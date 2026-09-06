"""Quiescence proof and ordered cleanup; no authority from local booleans."""
from __future__ import annotations

import datetime as dt
import time
from collections.abc import Mapping
from typing import Any

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract
from controller_acceptance_io import APIError, verify_claim, revocation_policy
from controller_acceptance_observer import LiveObserver

CLEANUP_ORDER = ("restore-faults", "quiesce-controller", "destroy-controller", "destroy-attestor-enrollment", "delete-controller-material", "destroy-appliance", "cleanup-tailnet", "destroy-observer-roles", "audit-zero-residual", "release-deployment-freeze", "finalize-backend")


def journal_hashes(reader: LiveObserver) -> dict[str, str]:
    result = {}
    for domain in reader.topology["domains"]:
        payload = reader._dynamo_item(f"deployment#{reader.handoff['run_id']}", f"domain#{domain['id']}")
        contract.require(payload is not None, "handoff journal disappeared")
        # _durable_evidence validates the complete immutable authority too.
        reader._durable_evidence(payload, domain, {r["eni_id"]: r["id"] for r in reader.topology["routers"]})
        result[domain["id"]] = reader.items[domain["id"]]["hash"]
    return result


def actor_states(reader: LiveObserver, kind: str) -> dict[str, str]:
    result = {}
    for actor in reader.handoff["actors"]:
        if actor["actor_type"] == kind:
            _, result[actor["actor_id"]] = reader._describe_instance_actor(actor["instance_id"], actor["region"])
    return result


def quiesce(reader: LiveObserver) -> dict[str, Any]:
    h = reader.handoff
    contract.require(reader.session.phase == "quiesce", "quiescence requires the narrow identity")
    contract.require(dt.datetime.now(dt.timezone.utc) >= contract.timestamp(h["observer_sessions_until"]), "measured observer credentials may still restart controllers")
    verify_claim(reader.aws, h, reader.run_dir)
    # The observer role can no longer issue or use credentials. This identity
    # can start routers but cannot restart controllers, including via IAM/SSM.
    for kind, target in (("router", "running"), ("controller", "stopped")):
        deadline = time.monotonic() + 600
        stable = 0
        while time.monotonic() < deadline:
            states = actor_states(reader, kind)
            if states and all(state == target for state in states.values()):
                stable += 1
                if stable >= 2:
                    break
            else:
                stable = 0
                for actor in h["actors"]:
                    if actor["actor_type"] != kind:
                        continue
                    state = states[actor["actor_id"]]
                    if state == ("stopped" if kind == "router" else "running"):
                        verify_claim(reader.aws, h, reader.run_dir)
                        checked = reader._validate_instance_actor(actor["instance_id"], actor["region"], "ec2:StartInstances" if kind == "router" else "ec2:StopInstances")
                        reader._instance_fault("start" if kind == "router" else "stop", actor["instance_id"], actor["region"], validated_actor=checked)
            reader.sleep(5)
        else:
            raise contract.Error("exact actor quiescence/restoration did not settle")
    interval = sum(h["controller"]["policy_seconds"][name] for name in ("lease_duration", "api_timeout", "route_convergence_timeout"))
    contract.require(interval < 720, "quiescence drain exceeds supported bound")
    before = journal_hashes(reader)
    started = legacy.utc_now()
    reader.sleep(interval + 1)
    after = journal_hashes(reader)
    controllers = actor_states(reader, "controller")
    contract.require(before == after and all(state == "stopped" for state in controllers.values()), "controller state changed during drain; claim retained")
    for item in reader.items.values():
        lease = item["payload"].get("lease")
        contract.require(lease is None or contract.timestamp(lease["expires_at"]) <= dt.datetime.now(dt.timezone.utc), "a lease is still live")
    verify_claim(reader.aws, h, reader.run_dir)
    return {"schema": 1, "kind": "controller-quiescence", "run_id": h["run_id"], "invocation_id": h["invocation_id"], "handoff_sha256": contract.digest(h), "claim_sha256": h["claim"]["sha256"], "started_at": started, "completed_at": legacy.utc_now(), "drain_seconds": interval, "before": before, "after": after, "controllers": controllers, "routers": actor_states(reader, "router"), "credential": reader.session.receipt(), "method": "stopped-controllers-and-expired-observer-sessions"}


def validate_quiescence(proof: Any, h: Mapping[str, Any]) -> dict[str, Any]:
    p = contract.exact(proof, {"schema", "kind", "run_id", "invocation_id", "handoff_sha256", "claim_sha256", "started_at", "completed_at", "drain_seconds", "before", "after", "controllers", "routers", "credential", "method"}, "quiescence receipt")
    contract.require(p["schema"] == 1 and p["kind"] == "controller-quiescence" and p["method"] == "stopped-controllers-and-expired-observer-sessions" and p["run_id"] == h["run_id"] and p["invocation_id"] == h["invocation_id"] and p["handoff_sha256"] == contract.digest(h) and p["claim_sha256"] == h["claim"]["sha256"], "quiescence belongs to another owner")
    minimum = sum(h["controller"]["policy_seconds"][name] for name in ("lease_duration", "api_timeout", "route_convergence_timeout"))
    contract.require(p["drain_seconds"] >= minimum and (contract.timestamp(p["completed_at"]) - contract.timestamp(p["started_at"])).total_seconds() >= p["drain_seconds"] and contract.timestamp(p["started_at"]) >= contract.timestamp(h["observer_sessions_until"]), "quiescence did not drain every possible writer")
    contract.require(p["before"] == p["after"] and set(p["after"]) == {d["id"] for d in h["topology"]["domains"]} and all(contract.SHA.fullmatch(x) for x in p["after"].values()), "journal drain proof is incomplete")
    for kind in ("controller", "router"):
        states = p["controllers" if kind == "controller" else "routers"]
        contract.require(set(states) == {a["actor_id"] for a in h["actors"] if a["actor_type"] == kind} and all(s == ("stopped" if kind == "controller" else "running") for s in states.values()), "quiescence actor coverage differs")
    contract.require(p["credential"]["role_arn"] == h["roles"]["quiesce"]["arn"] and contract.timestamp(p["credential"]["expires_at"]) > contract.timestamp(p["completed_at"]), "quiescence identity was wrong or expired")
    return p


def recheck_quiescence(reader: LiveObserver, proof: Any) -> None:
    p = validate_quiescence(proof, reader.handoff)
    verify_claim(reader.aws, reader.handoff, reader.run_dir)
    contract.require(journal_hashes(reader) == p["after"] and actor_states(reader, "controller") == p["controllers"], "quiescence no longer holds; cleanup authority withheld")


def cleanup_owned(deployment: Any, *, h: Mapping[str, Any] | None, proof: Mapping[str, Any] | None) -> dict[str, Any]:
    d = deployment
    if h is not None:
        validate_quiescence(proof, h)
        d._require_backend_claim()
    else:
        # Unknown or active partial controller deployment requires inspected
        # recovery. Never infer safe cleanup from an incomplete Terraform output.
        contract.require(not d.workspaces["controller"].variables_path.exists() and not d.active_deployment_attempted, "partial controller deployment lacks a quiescence handoff; forensic state retained")
        observed = d.aws.json(["ec2", "describe-instances", "--filters", f"Name=tag:EnvelopeRun,Values={d.config.run_id}", f"Name=tag:EnvelopeInvocation,Values={d.invocation_id}", "Name=tag:Role,Values=envelope-controller"], region=d.config.controller.region)
        contract.require(not any(r.get("Instances") for r in observed.get("Reservations", [])), "partial controller instances require inspected quiescence")
        d._require_backend_claim()
    result = {"schema": 1, "kind": "controller-cleanup", "run_id": d.config.run_id, "invocation_id": d.invocation_id, "status": "failed", "sequence": [], "completed": {}, "audits": [], "errors": [], "backend_finalized": False, "retained_forensics": d.private_reference, "credential": d.session.receipt(), "started_at": legacy.utc_now(), "completed_at": legacy.utc_now()}
    operations = [
        ("restore-faults", lambda: True),
        ("quiesce-controller", lambda: True),
        ("destroy-controller", d.workspaces["controller"].destroy),
        ("destroy-attestor-enrollment", d.workspaces["attestor"].destroy),
        ("delete-controller-material", d.delete_controller_material),
        ("destroy-appliance", d.destroy_appliance),
        ("cleanup-tailnet", d.cleanup_tailnet),
        ("destroy-observer-roles", d.workspaces["sessions"].destroy),
    ]
    try:
        for name, operation in operations:
            d._require_backend_claim()
            result["sequence"].append(name)
            d.save()
            if name == "destroy-controller" and h is not None:
                d.aws.json(["iam", "delete-role-policy", "--role-name", h["revocation"]["lifecycle_role_arn"].split("/")[-1], "--policy-name", h["revocation"]["policy_name"]])
            operation()
            result["completed"][name] = True
        result["sequence"].append("audit-zero-residual")
        stable_absence = 0
        for attempt in range(12):
            audits = [dict(a) for a in d.audit_residuals()]
            public_residuals = 0
            for rid, receipt in d.seed_receipts.items():
                for name in (f"/envelope/attestor-bindings/{receipt['ed25519_public_key']}", f"/envelope/{d.config.run_id}/{rid}/{d.invocation_id}-enrollment"):
                    try:
                        d.aws.json(["ssm", "get-parameter", "--name", name], region=d.config.controller.region)
                        public_residuals += 1
                    except APIError as error:
                        if error.code != "ParameterNotFound":
                            raise
            roles_remaining = 0
            for phase in ("observe", "quiesce"):
                try:
                    d.aws.json(["iam", "get-role", "--role-name", f"{d.config.run_id}-{d.invocation_id[:12]}-{phase}"])
                    roles_remaining += 1
                except APIError as error:
                    if error.code != "NoSuchEntity":
                        raise
            audits += [{"hook": "attestor-enrollment-records", "residual_count": public_residuals}, {"hook": "acceptance-roles", "residual_count": roles_remaining}]
            stable_absence = stable_absence + 1 if all(a["residual_count"] == 0 for a in audits) else 0
            if stable_absence >= 2:
                result["audits"] = audits
                break
            d.sleep(5)
        else:
            raise contract.Error("authoritative residual audit did not settle to zero")
        result["completed"]["audit-zero-residual"] = True
        result["sequence"].append("release-deployment-freeze")
        if h is not None:
            import json
            import urllib.parse
            role = h["revocation"]["role_arn"].split("/")[-1]
            trust = d.aws.json(["iam", "get-role", "--role-name", role])["Role"]["AssumeRolePolicyDocument"]
            if isinstance(trust, str):
                trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
            contract.require(sum(s.get("Sid") == h["revocation"]["trust_sid"] for s in trust["Statement"]) == 1, "deployment freeze ownership changed")
            # Reopening the issuer must not reactivate previously frozen tokens.
            d.aws.json(["iam", "put-role-policy", "--role-name", role, "--policy-name", h["revocation"]["policy_name"], "--policy-document", json.dumps(revocation_policy(legacy.utc_now()))])
            trust["Statement"] = [s for s in trust["Statement"] if s.get("Sid") != h["revocation"]["trust_sid"]]
            d.aws.json(["iam", "update-assume-role-policy", "--role-name", role, "--policy-document", json.dumps(trust)])
        result["completed"]["release-deployment-freeze"] = True
        result["sequence"].append("finalize-backend")
        d.finalize_backend()
        result["completed"]["finalize-backend"] = True
        result["backend_finalized"] = True
        result["status"] = "complete"
    except BaseException as error:
        result["errors"].append({"category": type(error).__name__, "reason": "cleanup uncertain; claim and encrypted recovery journal retained"})
    result["completed_at"] = legacy.utc_now()
    # Encrypted recovery snapshots are retained audit evidence, not credentials
    # or a new cleanup claim. They are never handed to the observer identity.
    result["retained_forensics"] = d.private_reference
    legacy.write_private_json(d.run_dir / "cleanup.json", result)
    return result


def validate_cleanup(value: Any, h: Mapping[str, Any]) -> dict[str, Any]:
    c = contract.exact(value, {"schema", "kind", "run_id", "invocation_id", "status", "sequence", "completed", "audits", "errors", "backend_finalized", "retained_forensics", "credential", "started_at", "completed_at"}, "cleanup evidence")
    contract.require(c["schema"] == 1 and c["kind"] == "controller-cleanup" and c["run_id"] == h["run_id"] and c["invocation_id"] == h["invocation_id"], "cleanup owner mismatch")
    contract.require(c["credential"]["role_arn"] == h["roles"]["cleanup"]["arn"], "cleanup identity differs")
    if c["status"] == "complete":
        contract.require(c["sequence"] == list(CLEANUP_ORDER) and c["completed"] == {name: True for name in CLEANUP_ORDER} and c["backend_finalized"] is True and c["errors"] == [] and [a["hook"] for a in c["audits"]] == [*legacy.RESIDUAL_AUDIT_HOOKS, "attestor-enrollment-records", "acceptance-roles"] and all(a["residual_count"] == 0 for a in c["audits"]), "cleanup completion is contradicted by its evidence")
    else:
        contract.require(c["status"] == "failed" and bool(c["errors"]), "failed cleanup omitted uncertainty")
    return c
