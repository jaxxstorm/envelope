#!/usr/bin/env python3
"""Protected split-process controller acceptance entry point (live schema 3)."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import pathlib
import sys
import time
from typing import Any

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract
from controller_acceptance_io import AWS, Commands, Session, assume_oidc, publish_object, read_object, verify_phase_identity


def approved(run_id: str) -> None:
    contract.require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REF_PROTECTED") == "true" and os.environ.get("GITHUB_HEAD_REPO_FORK") == "false" and os.environ.get("ENVELOPE_E2E_APPROVED_RUN_ID") == run_id, "live phase lacks exact protected approval")


def output_reference(path: pathlib.Path, reference: dict[str, Any]) -> None:
    legacy.write_private_json(path, reference)
    print(json.dumps(reference, sort_keys=True, separators=(",", ":")))


def load_handoff(args: Any, phase: str, directory: pathlib.Path, *, cleanup_subject: bool = False) -> tuple[dict[str, Any], Session, AWS]:
    reference = contract.read_json(args.handoff_reference)
    contract.validate_reference(reference, "handoff reference")
    # The role ARN is a nonsecret, independently pinned workflow output. The
    # downloaded handoff must identify that exact role and workflow invocation.
    session = assume_oidc(args.role_arn, "cleanup" if cleanup_subject else phase, contract.execution_context(), directory / "home", 3600)
    session.phase = phase
    aws = AWS(Commands(session, directory / "home"))
    try:
        h = read_object(aws, reference, directory)
        contract.validate_handoff(h, now=dt.datetime.now(dt.timezone.utc), context=contract.execution_context())
        approved(h["run_id"])
        verify_phase_identity(aws, session, h, phase, directory)
    except BaseException:
        session.close()
        raise
    return h, session, aws


def bundle(h: dict[str, Any], live: Any, integration: Any, quiescence: Any, cleanup: Any) -> dict[str, Any]:
    from controller_acceptance_cleanup import validate_cleanup, validate_quiescence
    if integration is not None:
        contract.validate_integration(integration, h["context"]["revision"])
    validate_quiescence(quiescence, h)
    validate_cleanup(cleanup, h)
    if live is not None:
        contract.validate_live_evidence(live, h)
    passed = integration is not None and live is not None and live["status"] == "passed" and cleanup["status"] == "complete"
    result = {"schema": 1, "kind": "controller-acceptance-bundle", "run_id": h["run_id"], "invocation_id": h["invocation_id"], "handoff_sha256": contract.digest(h), "status": "passed" if passed else "failed", "live": live, "integration_only": integration, "quiescence": quiescence, "cleanup": cleanup}
    contract.require(not legacy.scan_evidence(result), "bundle contains unsafe evidence")
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-config")
    prepare.add_argument("--template", type=pathlib.Path, required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--output", type=pathlib.Path, required=True)
    deploy = commands.add_parser("deploy")
    deploy.add_argument("--config", type=pathlib.Path, required=True)
    deploy.add_argument("--directory", type=pathlib.Path, required=True)
    deploy.add_argument("--reference", type=pathlib.Path, required=True)
    for phase in ("observe", "quiesce", "cleanup"):
        command = commands.add_parser(phase)
        command.add_argument("--handoff-reference", type=pathlib.Path, required=True)
        command.add_argument("--role-arn", required=True)
        command.add_argument("--directory", type=pathlib.Path, required=True)
        command.add_argument("--reference", type=pathlib.Path, required=True)
        if phase == "cleanup":
            command.add_argument("--quiescence-reference", type=pathlib.Path, required=True)
            command.add_argument("--live-reference", type=pathlib.Path)
            command.add_argument("--integration", type=pathlib.Path, required=True)
    for name in ("validate-handoff", "validate-live", "verify-bundle"):
        command = commands.add_parser(name)
        command.add_argument("path", type=pathlib.Path)
        if name != "validate-handoff":
            command.add_argument("--handoff", type=pathlib.Path, required=True)
    integration = commands.add_parser("record-integration")
    integration.add_argument("--input", type=pathlib.Path, required=True)
    integration.add_argument("--revision", required=True)
    integration.add_argument("--output", type=pathlib.Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    session = None
    try:
        if args.command == "prepare-config":
            approved(args.run_id)
            raw = contract.read_json(args.template)
            raw["schema"], raw["context"] = 1, contract.execution_context()
            production = raw["production"]
            production["run_id"] = args.run_id
            production["expires_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=7)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            production["artifact_manifest"] = "build/manifest.json"
            production["backend"]["state_key"] = f"runs/{args.run_id}/appliance/terraform.tfstate"
            production["production_controller"]["state_key"] = f"runs/{args.run_id}/controller/terraform.tfstate"
            contract.require(production["tailnet"]["name"] == "_lbr_sandbox" and production["symmetric_topology"]["version"] == 3, "protected execution requires the reviewed sandbox/profile")
            legacy.write_private_json(args.output, raw)
            return 0
        if args.command == "record-integration":
            result = contract.record_integration(args.input.read_bytes(), args.revision)
            legacy.write_private_json(args.output, result)
            return 0
        if args.command == "validate-handoff":
            contract.validate_handoff(contract.read_json(args.path))
            return 0
        if args.command == "validate-live":
            contract.validate_live_evidence(contract.read_json(args.path), contract.read_json(args.handoff))
            return 0
        if args.command == "verify-bundle":
            value = contract.read_json(args.path)
            h = contract.read_json(args.handoff)
            expected = bundle(h, value["live"], value["integration_only"], value["quiescence"], value["cleanup"])
            contract.require(value == expected, "bundle schema or summary contradicts evidence")
            return 0 if value["status"] == "passed" else 1
        args.directory = args.directory.expanduser().resolve()
        args.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        if args.command == "deploy":
            from controller_acceptance_deploy import Deployment, load_config
            raw, config = load_config(args.config, args.directory)
            approved(config.run_id)
            session = assume_oidc(raw["deployment_role_arn"], "deploy", raw["context"], args.directory / "home", 21600)
            deployment = Deployment(raw, config, session, args.directory)
            try:
                reference = deployment.deploy()
            except BaseException:
                with contextlib.suppress(BaseException):
                    deployment.save()
                cleanup = None
                if deployment.backend_claim_version_id is not None:
                    from controller_acceptance_cleanup import cleanup_owned
                    with contextlib.suppress(BaseException):
                        cleanup = cleanup_owned(deployment, h=None, proof=None)
                legacy.write_private_json(args.directory / "failure.json", {"schema": 1, "kind": "deployment-failure", "run_id": config.run_id, "invocation_id": deployment.invocation_id, "claim_retained": deployment.backend_claim_version_id is not None, "private_recovery": deployment.private_reference, "cleanup": cleanup, "reason": "deployment did not hand off; recovery state retained"})
                raise
            output_reference(args.reference, reference)
            # Public role ARNs are emitted only after successful self-revocation.
            h = contract.read_json(args.directory / "handoff.json")
            legacy.write_private_json(args.directory / "phase-roles.json", {phase: role["arn"] for phase, role in h["roles"].items()})
            return 0
        from controller_acceptance_observer import LiveObserver, run_live
        h, session, aws = load_handoff(args, "quiesce" if args.command == "cleanup" else args.command, args.directory, cleanup_subject=args.command == "cleanup")
        if args.command == "observe":
            forbidden = [name for name in ("TS_OAUTH_CLIENT_ID", "TS_OAUTH_CLIENT_SECRET", legacy.CONTROLLER_TSNET_ENV, legacy.CONTROLLER_ADMIN_ENV, "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN") if os.environ.get(name)]
            contract.require(not forbidden, "measured process inherited non-observation credentials or credential sources")
            observer = LiveObserver(h, session, args.directory)
            with legacy.ProtectedLifecycleDeadline(3000, 300) as deadline:
                result = run_live(observer, deadline.start_cleanup)
            reference = publish_object(aws, result, bucket=h["evidence_store"]["bucket"], key=h["evidence_store"]["prefix"] + "live.json", region=h["evidence_store"]["region"], directory=args.directory)
            output_reference(args.reference, reference)
            return 0 if result["status"] == "passed" else 1
        from controller_acceptance_cleanup import quiesce, recheck_quiescence, validate_quiescence
        if args.command == "quiesce":
            # Do not keep short-lived credentials while waiting out the maximum
            # permitted observer session. Reacquire only the narrow identity.
            session.close()
            wait = (contract.timestamp(h["observer_sessions_until"]) - dt.datetime.now(dt.timezone.utc)).total_seconds()
            contract.require(wait <= 4500, "observer authority drain exceeded its bound")
            if wait > 0:
                time.sleep(wait + 5)
            session = assume_oidc(h["roles"]["quiesce"]["arn"], "quiesce", h["context"], args.directory / "home", 3600)
            aws = AWS(Commands(session, args.directory / "home"))
            verify_phase_identity(aws, session, h, "quiesce", args.directory)
            proof = quiesce(LiveObserver(h, session, args.directory))
            validate_quiescence(proof, h)
            legacy.write_private_json(args.directory / "quiescence.json", proof)
            reference = publish_object(aws, proof, bucket=h["evidence_store"]["bucket"], key=h["evidence_store"]["prefix"] + "quiescence.json", region=h["evidence_store"]["region"], directory=args.directory)
            output_reference(args.reference, reference)
            return 0
        proof = read_object(aws, contract.read_json(args.quiescence_reference), args.directory)
        recheck_quiescence(LiveObserver(h, session, args.directory), proof)
        session.close()
        # Deployment-capable cleanup credentials do not exist in this process
        # until an independently authenticated quiescence recheck succeeds.
        session = assume_oidc(h["roles"]["cleanup"]["arn"], "cleanup", h["context"], args.directory / "home", 10800)
        aws = AWS(Commands(session, args.directory / "home"))
        verify_phase_identity(aws, session, h, "cleanup", args.directory)
        state = read_object(aws, h["private_state"], args.directory)
        config_path = args.directory / "split-config.json"
        legacy.write_private_json(config_path, state["configuration"])
        from controller_acceptance_deploy import Deployment, load_config
        from controller_acceptance_cleanup import cleanup_owned
        raw, config = load_config(config_path, args.directory)
        deployment = Deployment(raw, config, session, args.directory)
        deployment.restore(state, h)
        deployment._build_artifacts()
        # Optional measurement evidence must never prevent owned cleanup.
        live = None
        if args.live_reference and args.live_reference.is_file():
            with contextlib.suppress(contract.Error, OSError):
                candidate = read_object(aws, contract.read_json(args.live_reference), args.directory)
                live = contract.validate_live_evidence(candidate, h)
        integration = None
        with contextlib.suppress(contract.Error, OSError):
            candidate = contract.read_json(args.integration)
            integration = contract.validate_integration(candidate, h["context"]["revision"])
        cleanup = cleanup_owned(deployment, h=h, proof=proof)
        result = bundle(h, live, integration, proof, cleanup)
        contract.require(not legacy.scan_evidence(result, deployment.protected_secrets), "bundle contains protected credentials")
        legacy.write_private_json(args.directory / "bundle.json", result)
        reference = publish_object(aws, result, bucket=h["evidence_store"]["bucket"], key=h["evidence_store"]["prefix"] + "bundle.json", region=h["evidence_store"]["region"], directory=args.directory)
        output_reference(args.reference, reference)
        return 0 if result["status"] == "passed" else 1
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        print(f"protected {args.command} failed closed; claims and forensic state are retained", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
