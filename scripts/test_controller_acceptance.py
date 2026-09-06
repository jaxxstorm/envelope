from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract
from controller_acceptance_cleanup import CLEANUP_ORDER, cleanup_owned, validate_cleanup, validate_quiescence, recheck_quiescence
from controller_acceptance_io import APIError, Commands, Session, verify_claim, verify_revocation, revocation_policy
from controller_acceptance_policy import boundary_policy
import test_aws_production_controller_e2e as fixture


def make_handoff(directory: pathlib.Path) -> dict:
    config = fixture.make_config(directory)
    deployment = legacy.parse_appliance_output(fixture.appliance_output(), config)
    topology, nodes = legacy.build_controller_topology(deployment.seed, fixture.tailnet_devices(), config, "fixture-authority")
    canonical = json.dumps(topology, separators=(",", ":"), sort_keys=True).encode()
    context = {"repository": "example/envelope", "ref": "refs/heads/main", "revision": "d" * 40, "workflow_run_id": "1234", "attempt": "1"}
    identity = {"schema": 1, "component": "envelope-controller-topology", "version": "test.1", "revision": context["revision"], "go_version": "go1.26.2", "vcs_modified": False, "canonical_sha256": hashlib.sha256(canonical).hexdigest(), "canonical_json_base64": base64.b64encode(canonical).decode(), "policy_durations": {k: v for k, v in topology["policy"].items() if k not in {"replica_count", "observation_quorum"}}}
    base = dt.datetime(2026, 9, 5, 11, 59, tzinfo=dt.timezone.utc)
    def stamp(d: dt.datetime) -> str:
        return d.isoformat().replace("+00:00", "Z")
    invocation = "f" * 64
    deploy_role = f"arn:aws:iam::{fixture.ACCOUNT_ID}:role/deployment"
    principal = f"arn:aws:sts::{fixture.ACCOUNT_ID}:assumed-role/deployment/session"
    claim_body = {"schema": 1, "kind": "aws-production-controller-run-claim", "run_id": fixture.RUN_ID, "configuration_sha256": "a" * 64, "principal_arn_sha256": legacy.hash_identity(principal), "invocation_id_sha256": legacy.hash_identity(invocation), "created_at": stamp(base), "nonce_sha256": "b" * 64}
    actors = fixture.FakeAdapter(fixture.TickClock())._actors()["instances"]
    instances = {}
    for actor in actors:
        role = {"controller": "envelope-controller", "router": "transport-router"}.get(actor["actor_type"], actor["actor_id"].split("-", 1)[-1])
        actor["expected_tags"] = {"EnvelopeRun": fixture.RUN_ID, "EnvelopeInvocation": invocation, "Role": role, "Name": fixture.RUN_ID + "-" + actor["actor_id"]}
        if actor["actor_type"] == "controller":
            instances[actor["actor_id"]] = {k: actor[k] for k in ("instance_id", "private_ip", "subnet_id", "availability_zone")}
            instances[actor["actor_id"]]["observer_volume_id"] = "vol-00000001"
    h = {"schema": 1, "kind": "production-controller-handoff", "run_id": fixture.RUN_ID, "invocation_id": invocation, "context": context, "issued_at": stamp(base + dt.timedelta(seconds=1)), "expires_at": stamp(base + dt.timedelta(hours=6)), "observer_issuance_until": stamp(base + dt.timedelta(minutes=10)), "observer_sessions_until": stamp(base + dt.timedelta(minutes=70)),
         "claim": {"bucket": "fixture-backend", "key": f"runs/{fixture.RUN_ID}/production-controller-run.claim.json", "region": "us-west-2", "version_id": "claim-v1", "sha256": contract.digest(claim_body)}, "claim_body": claim_body, "configuration_sha256": "a" * 64, "authority_kms_key_arn": config.appliance.backend["kms_key_arn"], "topology": topology, "topology_identity": identity, "actors": actors, "workloads": deployment.workloads,
         "controller": {"region": config.controller.region, "vpc_id": config.controller.vpc_id, "controller_ids": list(config.controller.controller_ids), "metrics_port": config.controller.metrics_port, "policy_seconds": config.controller.policy_seconds, "timeouts": config.controller.timeouts, "instances": instances}, "router_nodes": nodes,
         "attestation_trust": {"schema_version": 1, "deployment_id": fixture.RUN_ID, "topology_hash": identity["canonical_sha256"], "routers": [{"router_id": rid, "ed25519_public_key": hashlib.sha256(rid.encode()).hexdigest(), "configuration_sha256": "c" * 64, "url": f"https://{rid}.example/attestation"} for rid in sorted(nodes)]},
         "dependencies": {"artifacts": [{"component": c, "revision": context["revision"], "source_dirty": False, "sha256": "e" * 64} for c in ("envelope", "envelope-controller", "envelope-controller-topology", "envelope-controller-deploy", "envelope-router-attestor")], "lifecycle": [{"operation": operation, "complete": True, "receipt_sha256": "e" * 64} for operation in ["initialize"] * 4 + ["rollout"] * 3 + ["activate"] * 4], "enrollment_verified": True},
         "roles": {phase: {"arn": f"arn:aws:iam::{fixture.ACCOUNT_ID}:role/" + ("cleanup" if phase == "cleanup" else f"{fixture.RUN_ID}-{invocation[:12]}-{phase}"), "subject": contract.subject(context, phase), "policy_sha256": "a" * 64} for phase in ("observe", "quiesce", "cleanup")},
         "revocation": {"role_arn": deploy_role, "lifecycle_role_arn": f"arn:aws:iam::{fixture.ACCOUNT_ID}:role/lifecycle", "subject": contract.subject(context, "deploy"), "cutoff": stamp(base + dt.timedelta(seconds=1)), "policy_name": "freeze", "trust_sid": "DenyRunFixture", "session_arn": principal, "session_expires_at": stamp(base + dt.timedelta(hours=6))},
         "private_state": {"bucket": "fixture-backend", "key": f"runs/{fixture.RUN_ID}/private/{invocation}/state-000001.json", "region": "us-west-2", "version_id": "private-v1", "sha256": "c" * 64}, "evidence_store": {"bucket": "fixture-evidence", "region": "us-west-2", "prefix": f"runs/{fixture.RUN_ID}/evidence/{invocation}/"}}
    for phase in ("observe", "quiesce"):
        h["roles"][phase]["policy_sha256"] = contract.digest(boundary_policy(h, phase))
    return contract.validate_handoff(h)


def make_live(h: dict) -> dict:
    clock = fixture.TickClock()
    adapter = fixture.FakeAdapter(clock)
    started = clock.now()
    adapter.router_fault_at = "2026-09-05T12:00:50Z"
    adapter.restored_at = "2026-09-05T12:02:30Z"
    rows = []
    domains = {d["id"]: d for d in h["topology"]["domains"]}
    stage_times = {}
    for index, stage in enumerate(contract.LIVE_STAGES):
        clock.value = dt.datetime(2026, 9, 5, 12, 0, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=10 + index * 30)
        for did in sorted(domains):
            observation = adapter._observation(stage, did)
            d = domains[did]
            table = observation["aws_route_table"]
            for key in ("route_table_id", "gwlbe_subnet_id", "route_table_association_id"):
                table[key] = d[key]
            table["snapshot_sha256"] = legacy.route_snapshot_sha256(table, observation["aws_routes"])
            owner = observation["tailnet"]["owner_router_id"]
            node_hash = legacy.hash_identity(h["router_nodes"][owner]["stable_node_id"])
            observation["tailnet"]["owner_node_sha256"] = node_hash
            observation["tailnet"]["failed_router_online"] = None
            for contributor in observation["tailnet"]["contributors"]:
                contributor["owner_node_sha256"] = node_hash
            states = {a["actor_id"]: "running" for a in h["actors"] if a["actor_type"] in {"router", "controller"}}
            if stage in {"router-failover", "leader-handoff", "durable-alternate"}:
                states["west-a"] = "stopped"
            if stage in {"leader-handoff", "durable-alternate"}:
                states["controller-a"] = "stopped"
            rows.append({"scope": "live", "activated": True, "item_sha256": "e" * 64, "instance_states": states, "observation": observation})
            if did == "west-a":
                stage_times[stage] = observation["captured_at"]
    selection = {"domain_id": "west-a", "router_id": "west-a", "alternate_router_id": "west-b"}
    fresh = []
    for stage in ("router-failover", "failback-stable"):
        clock.value = contract.timestamp(stage_times[stage]) + dt.timedelta(seconds=1)
        fresh.extend(adapter.probe_fresh_flows(stage, selection, {"event_at": adapter.router_fault_at if stage == "router-failover" else adapter.restored_at, "convergence_at": stage_times[stage]}))
    clock.value = contract.timestamp(stage_times["failback-stable"]) + dt.timedelta(seconds=10)
    established = adapter.finish_established_flows({"source_workload": "west-initiator", "destination_workload": "east-initiator", "source_instance_id": "i-00000015", "destination_instance_id": "i-0000001f", "sampled_at": "2026-09-05T12:00:45Z"}, {"fault_injected_at": adapter.router_fault_at, "convergence_at": stage_times["router-failover"]})
    principal = f"arn:aws:sts::{fixture.ACCOUNT_ID}:assumed-role/{h['roles']['observe']['arn'].split('/')[-1]}/envelope-observe-1234-1"
    credential = {"role_arn": h["roles"]["observe"]["arn"], "principal_arn_sha256": legacy.hash_identity(principal), "expires_at": "2026-09-05T13:00:00Z", "subject_sha256": legacy.hash_identity(h["roles"]["observe"]["subject"])}
    return {"schema": 3, "kind": contract.KIND, "run_id": h["run_id"], "invocation_id": h["invocation_id"], "handoff_sha256": contract.digest(h), "status": "passed", "started_at": started, "completed_at": clock.now(), "credential": credential, "selection": selection,
            "faults": {"router": {**selection, "instance_id": "i-00000001", "injected_at": "2026-09-05T12:00:50Z", "restored_at": adapter.restored_at, "method": "ec2-stop-instance"}, "leader": {"domain_id": "west-a", "previous_controller_id": "controller-a", "new_controller_id": "controller-b", "instance_id": "i-50000001", "previous_fence": 1, "new_fence": 2, "injected_at": "2026-09-05T12:01:25Z", "restored_at": "2026-09-05T12:02:00Z", "method": "ec2-stop-instance", "checkpoint_phase": "stable"}}, "observations": rows, "fresh_flows": fresh, "established_flows": established,
            "mutation_audit": adapter.ledger.evidence({"account_id": fixture.ACCOUNT_ID, "principal_arn": principal, "session_name": "envelope-observe-1234-1"}), "failure": None, "restoration": {"complete": True, "actors": {a["actor_id"]: "running" for a in h["actors"] if a["actor_type"] in {"router", "controller"}}}}


class AcceptanceContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.h = make_handoff(self.directory)

    def test_handoff_rejects_wrong_ownership_context_and_expiry(self) -> None:
        for mutation in (
            lambda h: h["claim_body"].update(invocation_id_sha256="0" * 64),
            lambda h: h["actors"][0]["expected_tags"].update(EnvelopeInvocation="0" * 64),
            lambda h: h["actors"][0].update(instance_id="i-ffffffff"),
            lambda h: h["roles"]["observe"].update(arn=h["revocation"]["role_arn"]),
            lambda h: h["roles"]["observe"].update(subject=h["roles"]["cleanup"]["subject"]),
            lambda h: h["dependencies"]["lifecycle"].pop(),
            lambda h: h["private_state"].update(key="foreign/state.json"),
        ):
            changed = copy.deepcopy(self.h)
            mutation(changed)
            with self.assertRaises(contract.Error):
                contract.validate_handoff(changed)
        with self.assertRaises(contract.Error):
            contract.validate_handoff(self.h, now=contract.timestamp(self.h["expires_at"]))
        with self.assertRaises(contract.Error):
            contract.validate_handoff(self.h, context={**self.h["context"], "attempt": "2"})

    def test_closed_role_policies_deny_routes_secrets_and_foreign_resources(self) -> None:
        for phase in ("observe", "quiesce"):
            policy = boundary_policy(self.h, phase)
            closed = policy["Statement"][0]
            self.assertEqual(closed["Effect"], "Deny")
            for api in ("ec2:ReplaceRoute", "ec2:CreateRoute", "sts:AssumeRole", "ssm:GetParameter", "iam:PutRolePolicy", "dynamodb:PutItem"):
                self.assertNotIn(api, closed["NotAction"])
            statements = {s["Sid"]: s for s in policy["Statement"]}
            self.assertEqual(statements["DenyPrivateDeploymentState"]["Effect"], "Deny")
            self.assertNotIn("/private/", json.dumps(statements["DenyPrivateDeploymentState"]["NotResource"]))
            if phase == "quiesce":
                self.assertNotIn("ssm:SendCommand", closed["NotAction"])
                self.assertNotIn("instance/i-50000001", json.dumps(statements["ExactStartActors"]))

    def test_expired_credentials_and_command_bypasses_fail_before_execution(self) -> None:
        session = Session(self.h["roles"]["observe"]["arn"], "principal", "ASIA" + "A" * 16, "opaque-secret", "opaque-token", dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1), self.h["roles"]["observe"]["subject"], "observe")
        commands = Commands(session, self.directory)
        with mock.patch("controller_acceptance_io._run") as run:
            for args in (["terraform", "apply"], ["aws", "ec2", "replace-route"], ["aws", "sts", "assume-role"], ["aws", "ssm", "get-parameter"], ["aws", "ec2", "describe-instances", "--endpoint-url", "https://other"], ["aws", "ec2", "describe-instances", "--endpoint-url=https://other"], ["aws", "ec2", "describe-instances", "--cli-input-yaml=other"]):
                with self.assertRaises(contract.Error):
                    commands.run(list(args))
            session.expires_at = dt.datetime.now(dt.timezone.utc)
            with self.assertRaises(contract.Error):
                commands.run(["aws", "ec2", "describe-instances"])
            run.assert_not_called()

    def test_claim_requires_exact_version_and_complete_body(self) -> None:
        with mock.patch("controller_acceptance_io.legacy.exact_object_versions", return_value=[{"version_id": "claim-v1", "kind": "version"}]), mock.patch("controller_acceptance_io.read_object", return_value=self.h["claim_body"]):
            verify_claim(mock.Mock(), self.h, self.directory)
        with mock.patch("controller_acceptance_io.legacy.exact_object_versions", return_value=[{"version_id": "other", "kind": "version"}]):
            with self.assertRaises(contract.Error):
                verify_claim(mock.Mock(), self.h, self.directory)
        with mock.patch("controller_acceptance_io.legacy.exact_object_versions", return_value=[{"version_id": "claim-v1", "kind": "version"}]), mock.patch("controller_acceptance_io.read_object", return_value={**self.h["claim_body"], "nonce_sha256": "0" * 64}):
            with self.assertRaises(contract.Error):
                verify_claim(mock.Mock(), self.h, self.directory)

    def test_deployment_issuer_and_all_prior_privileged_sessions_are_frozen(self) -> None:
        h = self.h
        principal = {"Federated": f"arn:aws:iam::{fixture.ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"}
        deploy_trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": principal, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": contract.subject(h["context"], "deploy", wildcard=True)}}},
            {"Sid": h["revocation"]["trust_sid"], "Effect": "Deny", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": principal},
        ]}
        cleanup_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": principal, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": h["roles"]["cleanup"]["subject"]}, "DateLessThan": {"aws:CurrentTime": h["expires_at"]}}}]}

        def response(args: list[str]) -> dict:
            role = args[args.index("--role-name") + 1]
            if args[1] == "get-role-policy":
                policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]} if role in {"lifecycle", "deployment"} else revocation_policy(h["observer_sessions_until"])
                return {"PolicyDocument": policy}
            return {"Role": {"AssumeRolePolicyDocument": deploy_trust if role == "deployment" else cleanup_trust}}

        api = mock.Mock()
        api.json.side_effect = response
        verify_revocation(api, h)
        deploy_trust["Statement"][1]["Condition"] = {"StringEquals": {"token.actions.githubusercontent.com:sub": "other-subject"}}
        with self.assertRaises(contract.Error):
            verify_revocation(api, h)

    def test_live_schema_never_accepts_simulated_receipts_or_unsupported_flags(self) -> None:
        live = make_live(self.h)
        contract.validate_live_evidence(live, self.h, passing=True)
        for mutation in (
            lambda e: e.update(control_plane={"stale_fence_rejection": True}),
            lambda e: e.update(capabilities={"ambiguous-settlement": True}),
            lambda e: e["observations"][0].update(scope="integration-only"),
            lambda e: e["observations"][0].update(activated=False),
            lambda e: e["credential"].update(expires_at=e["started_at"]),
            lambda e: e["faults"]["leader"].update(checkpoint_phase="routes-converging"),
            lambda e: e["faults"]["leader"].update(new_fence=1),
            lambda e: e["observations"][0]["observation"]["aws_routes"][0].update(target_eni_id="eni-ffffffff"),
            lambda e: e["fresh_flows"][0].update(source_instance_id="i-ffffffff"),
            lambda e: e["restoration"].update(complete=False),
        ):
            changed = copy.deepcopy(live)
            mutation(changed)
            with self.assertRaises(contract.Error):
                contract.validate_live_evidence(changed, self.h, passing=True)

    def test_integration_evidence_comes_from_completed_test_events(self) -> None:
        package = "github.com/jaxxstorm/envelope/internal/controller/integration"
        events = [{"Package": package, "Test": test, "Action": "pass"} for test in contract.INTEGRATION_TESTS.values()] + [{"Package": package, "Action": "pass"}]
        output = b"\n".join(json.dumps(e).encode() for e in events)
        report = contract.record_integration(output, self.h["context"]["revision"])
        contract.validate_integration(report, self.h["context"]["revision"])
        for bad in (events[:-1], events[1:], [*events, {"Action": "fail"}]):
            with self.assertRaises(contract.Error):
                contract.record_integration(b"\n".join(json.dumps(e).encode() for e in bad), self.h["context"]["revision"])
        report["results"]["observer-disagreement"]["scope"] = "live"
        with self.assertRaises(contract.Error):
            contract.validate_integration(report, self.h["context"]["revision"])

    def test_quiescence_cannot_be_claimed_before_observer_sessions_expire(self) -> None:
        started = contract.timestamp(self.h["observer_sessions_until"]) + dt.timedelta(seconds=1)
        ended = started + dt.timedelta(seconds=60)
        states = {d["id"]: "a" * 64 for d in self.h["topology"]["domains"]}
        proof = {"schema": 1, "kind": "controller-quiescence", "run_id": self.h["run_id"], "invocation_id": self.h["invocation_id"], "handoff_sha256": contract.digest(self.h), "claim_sha256": self.h["claim"]["sha256"], "started_at": started.isoformat().replace("+00:00", "Z"), "completed_at": ended.isoformat().replace("+00:00", "Z"), "drain_seconds": 45, "before": states, "after": dict(states), "controllers": {a["actor_id"]: "stopped" for a in self.h["actors"] if a["actor_type"] == "controller"}, "routers": {a["actor_id"]: "running" for a in self.h["actors"] if a["actor_type"] == "router"}, "credential": {"role_arn": self.h["roles"]["quiesce"]["arn"], "expires_at": self.h["expires_at"]}, "method": "stopped-controllers-and-expired-observer-sessions"}
        validate_quiescence(proof, self.h)
        for mutation in (lambda p: p.update(started_at=self.h["issued_at"]), lambda p: p["controllers"].update({"controller-a": "running"}), lambda p: p["after"].update({"west-a": "b" * 64}), lambda p: p.update(drain_seconds=1)):
            changed = copy.deepcopy(proof)
            mutation(changed)
            with self.assertRaises(contract.Error):
                validate_quiescence(changed, self.h)
        reader = mock.Mock(handoff=self.h)
        with mock.patch("controller_acceptance_cleanup.verify_claim"), mock.patch("controller_acceptance_cleanup.journal_hashes", return_value={"wrong": "a" * 64}):
            with self.assertRaises(contract.Error):
                recheck_quiescence(reader, proof)

    def test_cleanup_completion_requires_every_step_and_zero_residual(self) -> None:
        c = {"schema": 1, "kind": "controller-cleanup", "run_id": self.h["run_id"], "invocation_id": self.h["invocation_id"], "status": "complete", "sequence": list(CLEANUP_ORDER), "completed": {name: True for name in CLEANUP_ORDER}, "audits": [{"hook": name, "residual_count": 0} for name in [*legacy.RESIDUAL_AUDIT_HOOKS, "attestor-enrollment-records", "acceptance-roles"]], "errors": [], "backend_finalized": True, "retained_forensics": self.h["private_state"], "credential": {"role_arn": self.h["roles"]["cleanup"]["arn"]}, "started_at": self.h["issued_at"], "completed_at": self.h["expires_at"]}
        validate_cleanup(c, self.h)
        for mutation in (lambda x: x["sequence"].pop(), lambda x: x["completed"].update({"destroy-appliance": False}), lambda x: x["audits"][0].update(residual_count=1), lambda x: x.update(backend_finalized=False), lambda x: x.update(invocation_id="0" * 64)):
            changed = copy.deepcopy(c)
            mutation(changed)
            with self.assertRaises(contract.Error):
                validate_cleanup(changed, self.h)

    def test_cleanup_requires_consecutive_absence_and_retains_claim_on_failure(self) -> None:
        def deployment() -> mock.Mock:
            d = mock.Mock()
            d.config.run_id = self.h["run_id"]
            d.invocation_id = self.h["invocation_id"]
            temporary = tempfile.TemporaryDirectory(dir=self.directory)
            self.addCleanup(temporary.cleanup)
            d.run_dir = pathlib.Path(temporary.name)
            d.private_reference = self.h["private_state"]
            d.active_deployment_attempted = False
            d.workspaces = {name: mock.Mock() for name in ("controller", "attestor", "sessions")}
            d.workspaces["controller"].variables_path.exists.return_value = False
            d.seed_receipts = {}
            d.session.receipt.return_value = {"role_arn": self.h["roles"]["cleanup"]["arn"]}

            def response(args: list[str], **kwargs: object) -> dict:
                if args[:2] == ["ec2", "describe-instances"]:
                    return {"Reservations": []}
                raise APIError("NoSuchEntity")

            d.aws.json.side_effect = response
            return d

        for counts, expected_calls, complete in (
            ([1, 0, 1, 0, 0], 5, True),
            ([1, 0] * 6, 12, False),
        ):
            with self.subTest(counts=counts):
                d = deployment()
                d.audit_residuals.side_effect = [[{"hook": hook, "residual_count": count} for hook in legacy.RESIDUAL_AUDIT_HOOKS] for count in counts]
                result = cleanup_owned(d, h=None, proof=None)
                self.assertEqual(d.audit_residuals.call_count, expected_calls)
                self.assertEqual(result["status"], "complete" if complete else "failed")
                self.assertEqual(d.finalize_backend.call_count, int(complete))
                self.assertEqual(result["retained_forensics"], self.h["private_state"])
                if complete:
                    validate_cleanup(result, self.h)

        d = deployment()
        d.workspaces["attestor"].destroy.side_effect = KeyboardInterrupt()
        result = cleanup_owned(d, h=None, proof=None)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["errors"][0]["category"], "KeyboardInterrupt")
        d.destroy_appliance.assert_not_called()
        d.finalize_backend.assert_not_called()

        d = deployment()
        d.active_deployment_attempted = True
        with self.assertRaises(contract.Error):
            cleanup_owned(d, h=None, proof=None)
        d.aws.json.assert_not_called()
        d.workspaces["controller"].destroy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
