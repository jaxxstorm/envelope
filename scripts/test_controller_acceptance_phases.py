"""Offline phase integration. Only external I/O and production prerequisites are fake.

These tests never emit live evidence outside temporary directories. The real
handoff, IAM verification, fault sequencing, quiescence and cleanup code runs.
"""
from __future__ import annotations

import copy
import base64
import datetime as dt
import hashlib
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import aws_controller_acceptance as cli
import aws_production_controller_e2e as legacy
import controller_acceptance_cleanup as cleanup
import controller_acceptance_contract as contract
import controller_acceptance_deploy as deploy
import controller_acceptance_io as io
import controller_acceptance_observer as observer
from controller_acceptance_policy import boundary_policy
from test_controller_acceptance import make_handoff, make_live
import test_aws_production_controller_e2e as fixture


class Clock(dt.datetime):
    value = dt.datetime(2026, 9, 5, 12, 0, tzinfo=dt.timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.value if tz else cls.value.replace(tzinfo=None)


class Cloud:
    """Versioned object and IAM API boundary, rejecting unimplemented requests."""

    def __init__(self, h):
        self.h = h
        self.objects = {}
        self.roles = {}
        self.calls = []
        self.fail = None
        self.session = None
        self.states = {a["instance_id"]: "running" for a in h["actors"]}
        self.corrupt_item = False
        self.principal = {"Federated": f"arn:aws:iam::{fixture.ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"}
        for phase, role in h["roles"].items():
            subjects = [h["roles"]["quiesce"]["subject"], h["roles"]["cleanup"]["subject"]] if phase == "quiesce" else [role["subject"]]
            trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": self.principal, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": subjects}, "DateLessThan": {"aws:CurrentTime": h["observer_issuance_until"] if phase == "observe" else h["expires_at"]}}}]}
            policy = boundary_policy(h, phase) if phase != "cleanup" else {"Version": "2012-10-17", "Statement": []}
            self.roles[role["arn"].split("/")[-1]] = {"trust": trust, "duration": 3600, "policies": {"acceptance-boundary": policy}}
        for phase, arn in (("deploy", h["revocation"]["role_arn"]), ("cleanup", h["roles"]["cleanup"]["arn"])):
            self.roles[arn.split("/")[-1]] = {"duration": 21600 if phase == "deploy" else 10800, "policies": {"acceptance-boundary": {"Version": "2012-10-17", "Statement": []}}, "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": self.principal, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": contract.subject(h["context"], phase, wildcard=True)}}}]}}
        self.roles[h["revocation"]["lifecycle_role_arn"].split("/")[-1]] = {"policies": {}}
        h["roles"]["cleanup"]["policy_sha256"] = contract.digest(self.roles["cleanup"]["policies"]["acceptance-boundary"])
        self.put(h["claim"], h["claim_body"])

    def put(self, ref, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.objects[(ref["bucket"], ref["key"], ref["version_id"])] = data
        return data

    def run(self, args, environment, **kwargs):
        self.calls.append((list(args), dict(environment)))
        operation = tuple(args[1:3])
        if operation == self.fail:
            raise io.APIError("InjectedFailure")
        assert args[0] == "aws", args

        def arg(name):
            return args[args.index(name) + 1]

        result = {}
        if operation == ("sts", "get-caller-identity"):
            result = {"Arn": self.session.principal_arn}
        elif operation[0] == "iam":
            name = arg("--role-name")
            if name not in self.roles:
                raise io.APIError("NoSuchEntity")
            role = self.roles[name]
            if operation[1] == "get-role":
                result = {"Role": {"AssumeRolePolicyDocument": copy.deepcopy(role["trust"]), "MaxSessionDuration": role["duration"]}}
            elif operation[1] == "get-role-policy":
                result = {"PolicyDocument": copy.deepcopy(role["policies"][arg("--policy-name")])}
            elif operation[1] == "put-role-policy":
                role["policies"][arg("--policy-name")] = json.loads(arg("--policy-document"))
            elif operation[1] == "delete-role-policy":
                del role["policies"][arg("--policy-name")]
            elif operation[1] == "update-assume-role-policy":
                role["trust"] = json.loads(arg("--policy-document"))
            else:
                raise AssertionError(args)
        elif operation == ("s3api", "put-object"):
            bucket, key = arg("--bucket"), arg("--key")
            assert arg("--if-none-match") == "*"
            if any(b == bucket and k == key for b, k, _ in self.objects):
                raise io.APIError("PreconditionFailed")
            version = f"v{len(self.objects) + 1}"
            self.objects[bucket, key, version] = pathlib.Path(arg("--body")).read_bytes()
            result = {"VersionId": version}
        elif operation == ("s3api", "get-object"):
            key = (arg("--bucket"), arg("--key"), arg("--version-id"))
            if key not in self.objects:
                raise io.APIError("NoSuchVersion")
            pathlib.Path(args[args.index("--version-id") + 2]).write_bytes(self.objects[key])
            result = {"VersionId": key[2]}
        elif operation == ("s3api", "list-object-versions"):
            result = {"IsTruncated": False, "Versions": [{"Key": key, "VersionId": version} for bucket, key, version in self.objects if bucket == arg("--bucket") and key.startswith(arg("--prefix"))]}
        elif operation == ("s3api", "delete-object"):
            self.objects.pop((arg("--bucket"), arg("--key"), arg("--version-id")), None)
        elif operation == ("ec2", "describe-instances"):
            if self.session.phase == "deploy" and "envelope-deployment-session-revocation" in self.roles["deployment"]["policies"]:
                raise io.APIError("AccessDenied")
            rows = []
            for actor in self.h["actors"]:
                if actor["instance_id"] != arg("--instance-ids"):
                    continue
                rows.append({"InstanceId": actor["instance_id"], "VpcId": actor["vpc_id"], "SubnetId": actor["subnet_id"], "PrivateIpAddress": actor["private_ip"], "Placement": {"AvailabilityZone": actor["availability_zone"]}, "State": {"Name": self.states[actor["instance_id"]]}, "Tags": [{"Key": k, "Value": v} for k, v in actor["expected_tags"].items()]})
            result = {"Reservations": [{"Instances": rows}]}
        elif operation in (("ec2", "start-instances"), ("ec2", "stop-instances")):
            instance = arg("--instance-ids")
            self.states[instance] = "running" if operation[1] == "start-instances" else "stopped"
        elif operation == ("ec2", "describe-route-tables"):
            domain = next(d for d in self.h["topology"]["domains"] if d["route_table_id"] == arg("--route-table-ids"))
            site = next(s for s in self.h["topology"]["sites"] if s["id"] == domain["site_id"])
            router = next(r for r in self.h["topology"]["routers"] if r["id"] == domain["preferred_owner"])
            result = {"RouteTables": [{"RouteTableId": domain["route_table_id"], "VpcId": site["vpc_id"], "Associations": [{"Main": False, "AssociationState": {"State": "associated"}, "SubnetId": domain["gwlbe_subnet_id"], "RouteTableAssociationId": domain["route_table_association_id"], "RouteTableId": domain["route_table_id"]}], "Routes": [{"DestinationCidrBlock": prefix, "NetworkInterfaceId": router["eni_id"], "State": "active", "Origin": "CreateRoute"} for prefix in domain["remote_prefixes"]]}]}
        elif operation == ("dynamodb", "get-item"):
            keys = json.loads(arg("--key"))
            partition, sort = keys["pk"]["S"], keys["sk"]["S"]
            topology_hash = self.h["topology_identity"]["canonical_sha256"]
            item = {**keys, "topology_hash": {"S": "0" * 64 if self.corrupt_item else topology_hash}}
            def stamp(seconds):
                return (Clock.value + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
            sites = {s["id"]: s for s in self.h["topology"]["sites"]}
            if partition.startswith("observations#"):
                cid = sort.removeprefix("controller#")
                payload = {"controller_id": cid, "topology_hash": topology_hash, "sequence": 1, "captured_at": stamp(0), "expires_at": stamp(10), "backend_healthy": True, "domains": {d["id"]: {"stable_node_id": self.h["router_nodes"][d["preferred_owner"]]["stable_node_id"], "sole_primary": True, "online": True, "expired": False, "healthy": True, "advertised_prefixes": sites[d["site_id"]]["local_prefixes"], "enabled_prefixes": sites[d["site_id"]]["local_prefixes"], "owner_since": stamp(-60)} for d in self.h["topology"]["domains"]}}
                item.update(controller_id={"S": cid}, sequence={"N": "1"})
            else:
                domain = next(d for d in self.h["topology"]["domains"] if d["id"] == sort.removeprefix("domain#"))
                site = sites[domain["site_id"]]
                authority = {k: domain[k] for k in ("site_id", "source_prefix", "route_table_id", "gwlbe_subnet_id", "route_table_association_id", "remote_prefixes")}
                authority.update(topology_hash=topology_hash, deployment_id=self.h["run_id"], domain_id=domain["id"], region=site["region"], vpc_id=site["vpc_id"], preferred_owner=self.h["router_nodes"][domain["preferred_owner"]]["stable_node_id"], owners=[{**{k: r[k] for k in ("stable_node_id", "instance_id", "eni_id", "vpc_id", "subnet_id", "availability_zone", "region")}, "router_id": r["id"]} for r in self.h["topology"]["routers"] if r["site_id"] == site["id"]])
                payload = {"authority": authority, "activated": True, "phase": "stable", "revision": 1, "fence_term": 1, "stable_owner": authority["preferred_owner"], "lease": {"holder_id": "controller-a", "record_version": 1, "renewed_at": stamp(-1), "expires_at": stamp(30)}}
                item.update(record_type={"S": "domain"}, document_revision={"N": "1"}, fence_term={"N": "1"}, lease_holder={"S": "controller-a"}, lease_record_version={"N": "1"})
            item["payload"] = {"S": json.dumps(payload)}
            result = {"Item": item}
        else:
            raise AssertionError(args)
        return json.dumps(result)


class SplitPhaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.h = make_handoff(self.root)
        self.h["revocation"]["policy_name"] = "envelope-deployment-session-revocation"
        self.cloud = Cloud(self.h)
        Clock.value = dt.datetime(2026, 9, 5, 12, 0, tzinfo=dt.timezone.utc)
        for patch in (mock.patch.object(dt, "datetime", Clock), mock.patch.object(io, "_run", side_effect=self.cloud.run), mock.patch.object(contract, "execution_context", return_value=self.h["context"])):
            patch.start()
            self.addCleanup(patch.stop)

    def session(self, phase):
        arn = self.h["revocation"]["role_arn"] if phase == "deploy" else self.h["roles"][phase]["arn"]
        principal = f"arn:aws:sts::{fixture.ACCOUNT_ID}:assumed-role/{arn.split('/')[-1]}/envelope-{phase}-1234-1"
        s = io.Session(arn, principal, "ASIA" + "A" * 16, "temporary-secret", "temporary-token", Clock.value + dt.timedelta(hours=6 if phase == "deploy" else 1), contract.subject(self.h["context"], phase), phase)
        self.cloud.session = s
        return s

    def freeze(self):
        s = self.session("deploy")
        d = SimpleNamespace(raw={"oidc_provider_arn": self.cloud.principal["Federated"]}, raw_aws=io.AWS(io.Commands(s, self.root)), sleep=lambda _: None)
        deploy.Deployment.revoke(d, self.h)

    def test_versioned_handoff_revocation_identity_and_credential_isolation(self):
        self.freeze()
        for phase in ("observe", "quiesce", "cleanup"):
            with self.subTest(phase=phase):
                s = self.session(phase)
                api = io.AWS(io.Commands(s, self.root))
                io.verify_phase_identity(api, s, self.h, phase, self.root)
                s.close()
                with self.assertRaises(contract.Error):
                    api.json(["sts", "get-caller-identity"])
        for _, env in self.cloud.calls:
            self.assertEqual(env["AWS_CONFIG_FILE"], "/dev/null")
            self.assertEqual(env["AWS_SHARED_CREDENTIALS_FILE"], "/dev/null")
            self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")
            self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", env)
            self.assertNotIn("TS_OAUTH_CLIENT_SECRET", env)
        s = self.session("observe")
        api = io.AWS(io.Commands(s, self.root))
        self.cloud.roles[s.role_arn.split("/")[-1]]["trust"]["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = ["foreign"]
        with self.assertRaises(contract.Error):
            io.verify_phase_identity(api, s, self.h, "observe", self.root)

    def test_publication_is_exact_and_failure_never_hands_off(self):
        api = io.AWS(io.Commands(self.session("deploy"), self.root))
        ref = io.publish_object(api, self.h, bucket="fixture-backend", key="handoff.json", region="us-west-2", directory=self.root)
        self.assertEqual(io.read_object(api, ref, self.root), self.h)
        bad = dict(ref, sha256="0" * 64)
        with self.assertRaises(contract.Error):
            io.read_object(api, bad, self.root)
        with self.assertRaises(contract.Error):
            io.publish_object(api, self.h, bucket="fixture-backend", key="handoff.json", region="us-west-2", directory=self.root)
        self.freeze()
        self.cloud.fail = ("iam", "get-role-policy")
        api = io.AWS(io.Commands(self.session("observe"), self.root))
        with self.assertRaises(contract.Error):
            io.verify_phase_identity(api, self.cloud.session, self.h, "observe", self.root)
        self.assertFalse(any(args[1:3] == ["ec2", "stop-instances"] for args, _ in self.cloud.calls))

    def test_real_quiescence_stops_exact_controllers_and_drains_before_receipt(self):
        self.freeze()
        s = self.session("quiesce")
        reader = observer.LiveObserver(self.h, s, self.root)
        reader.sleep = lambda seconds: setattr(Clock, "value", Clock.value + dt.timedelta(seconds=seconds))
        with self.assertRaises(contract.Error):
            cleanup.quiesce(reader)
        Clock.value = contract.timestamp(self.h["observer_sessions_until"]) + dt.timedelta(seconds=1)
        s.expires_at = Clock.value + dt.timedelta(hours=1)
        hashes = {d["id"]: "a" * 64 for d in self.h["topology"]["domains"]}
        with mock.patch.object(cleanup, "journal_hashes", return_value=hashes):
            proof = cleanup.quiesce(reader)
            cleanup.validate_quiescence(proof, self.h)
            cleanup.recheck_quiescence(reader, proof)
            self.cloud.states[self.h["controller"]["instances"]["controller-a"]["instance_id"]] = "running"
            with self.assertRaises(contract.Error):
                cleanup.recheck_quiescence(reader, proof)
        stops = [args for args, _ in self.cloud.calls if args[1:3] == ["ec2", "stop-instances"]]
        self.assertEqual(len(stops), 3)
        self.assertEqual({args[args.index("--instance-ids") + 1] for args in stops}, {x["instance_id"] for x in self.h["controller"]["instances"].values()})

    def test_deploy_driver_runs_every_phase_and_stops_at_each_failure(self):
        names = ["claim", "prepare", "upload_bootstrap", "prepare_seeds", "deploy_appliance_native", "prepare_controller", "enroll_routers", "initialize_and_rollout", "make_handoff", "revoke"]
        for failure in [None, *names]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=self.root) as path:
                calls = []
                d = SimpleNamespace(run_dir=pathlib.Path(path), config=SimpleNamespace(run_id=self.h["run_id"], appliance=SimpleNamespace(backend={"bucket": "fixture-backend", "region": "us-west-2", "kms_key_arn": self.h["authority_kms_key_arn"]})), invocation_id=self.h["invocation_id"], raw_aws=io.AWS(io.Commands(self.session("deploy"), self.root)))
                for name in names:
                    def call(*args, name=name):
                        calls.append(name)
                        if name == failure:
                            raise KeyboardInterrupt()
                        return self.h if name == "make_handoff" else {}
                    setattr(d, name, call)
                # Publication/revocation themselves are tested above; this test
                # checks the driver's stop ordering across every prerequisite.
                with mock.patch.object(deploy, "publish_object", return_value=self.h["claim"]):
                    if failure:
                        with self.assertRaises(KeyboardInterrupt):
                            deploy.Deployment.deploy(d)
                        self.assertEqual(calls, names[:names.index(failure) + 1])
                    else:
                        self.assertEqual(deploy.Deployment.deploy(d), self.h["claim"])
                        self.assertEqual(calls, names)

    def test_lifecycle_receipts_and_workspace_are_bound_to_actual_request(self):
        identity = self.h["topology_identity"]["canonical_sha256"]
        d = SimpleNamespace(controller_output={"deployment_lifecycle_role_arn": {"value": self.h["revocation"]["lifecycle_role_arn"]}}, run_dir=self.root, invocation_id=self.h["invocation_id"], topology=self.h["topology"], topology_identity=self.h["topology_identity"], binary=lambda _: self.root / "envelope-controller-deploy", command=mock.Mock(), controller_workspace=SimpleNamespace(_environment=lambda: {"TF_DATA_DIR": str(self.root / "controller-data")}), lifecycle_receipts=[], save=mock.Mock())
        d.command.run.return_value = json.dumps({"initialized": True, "activated": False, "domain_id": "west-a", "topology_hash": identity, "revision": 1})
        deploy.Deployment.lifecycle(d, "initialize", "--domain", "west-a")
        self.assertEqual(d.command.run.call_args.kwargs["env"]["TF_DATA_DIR"], str(self.root / "controller-data"))
        self.assertIn(self.h["revocation"]["lifecycle_role_arn"], d.command.run.call_args.args[0])
        for response in ({"status": "complete"}, {"initialized": True, "activated": False, "domain_id": "east-a", "topology_hash": identity}, {"checked": True, "routers": 4, "topology_hash": "0" * 64}):
            d.command.run.return_value = json.dumps(response)
            with self.assertRaises(contract.Error):
                deploy.Deployment.lifecycle(d, "initialize", "--domain", "west-a")
        self.assertEqual(len(d.lifecycle_receipts), 1)

    def test_acceptance_fault_recovery_and_bundle_use_real_phase_orchestration(self):
        self.freeze()
        template = make_live(self.h)
        for failure in (None, *contract.LIVE_STAGES, "router-stop", "leader-stop"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=self.root) as path:
                Clock.value = contract.timestamp(template["started_at"])
                self.cloud.states = {a["instance_id"]: "running" for a in self.h["actors"]}
                s = self.session("observe")
                actor = observer.LiveObserver(self.h, s, pathlib.Path(path))
                actor.sleep = lambda seconds: setattr(Clock, "value", Clock.value + dt.timedelta(seconds=seconds))
                actor.monotonic = lambda: Clock.value.timestamp()

                def wait(stage, context):
                    if stage == failure:
                        raise KeyboardInterrupt()
                    rows = copy.deepcopy([r for r in template["observations"] if r["observation"]["stage"] == stage])
                    Clock.value = max(Clock.value, *(contract.timestamp(r["observation"]["captured_at"]) for r in rows))
                    return rows

                def start(selection):
                    Clock.value = contract.timestamp(template["faults"]["router"]["injected_at"])
                    return {"sampled_at": template["established_flows"][0]["sampled_at"]}

                def fresh(stage, selection, context):
                    if stage == "failback-stable":
                        Clock.value = max(Clock.value, contract.timestamp(template["completed_at"]))
                    rows = copy.deepcopy([r for r in template["fresh_flows"] if r["stage"] == stage])
                    for row in rows:
                        row.update(event_at=context["event_at"], convergence_at=context["convergence_at"], started_at=legacy.utc_now(), completed_at=legacy.utc_now(), recovery_milliseconds=int((Clock.value - contract.timestamp(context["event_at"])).total_seconds() * 1000))
                    return rows

                def finish(handle, context):
                    rows = copy.deepcopy(template["established_flows"])
                    for row in rows:
                        row.update(fault_injected_at=context["fault_injected_at"], convergence_at=context["convergence_at"])
                    return rows

                def durable(*args):
                    return {"activated": True, "phase": "stable", "fence_term": 1, "lease": {"holder_id": "controller-a", "expires_at": (Clock.value + dt.timedelta(seconds=30)).isoformat().replace("+00:00", "Z")}}

                original_fault = actor._instance_fault

                def fault(action, instance, region, **kwargs):
                    result = original_fault(action, instance, region, **kwargs)
                    if action == "stop" and failure == ("leader-stop" if instance.startswith("i-500") else "router-stop"):
                        raise KeyboardInterrupt()
                    return result

                with mock.patch.object(actor, "select_domain", side_effect=lambda rows: legacy.AwsProductionAdapter.select_domain(actor, [r for r in rows if r["domain_id"].startswith("west-")])), mock.patch.object(actor, "wait_live", side_effect=wait), mock.patch.object(actor, "start_established_flows", side_effect=start), mock.patch.object(actor, "probe_fresh_flows", side_effect=fresh), mock.patch.object(actor, "finish_established_flows", side_effect=finish), mock.patch.object(actor, "_dynamo_item", side_effect=durable), mock.patch.object(actor, "_instance_fault", side_effect=fault):
                    # Unique publications for each independent mocked invocation.
                    self.cloud.objects = {k: v for k, v in self.cloud.objects.items() if not k[1].endswith("fault-journal.json")}
                    result = observer.run_live(actor)
                self.assertEqual(result["status"], "passed" if failure is None else "failed", result["failure"])
                self.assertTrue(result["restoration"]["complete"])
                self.assertTrue(all(state == "running" for state in self.cloud.states.values()))
                self.assertTrue((pathlib.Path(path) / "live.json").is_file())
                self.assertEqual(result["mutation_audit"]["route_mutation_calls"], 0)
                if failure is None:
                    contract.validate_live_evidence(result, self.h, passing=True)
                    self.assertEqual(result["faults"]["leader"]["new_fence"], 2)
                    self.complete_cleanup(result, pathlib.Path(path))

    def complete_cleanup(self, live, path):
        Clock.value = contract.timestamp(self.h["observer_sessions_until"]) + dt.timedelta(seconds=1)
        reader = observer.LiveObserver(self.h, self.session("quiesce"), path)
        reader.sleep = lambda seconds: setattr(Clock, "value", Clock.value + dt.timedelta(seconds=seconds))
        hashes = {d["id"]: "a" * 64 for d in self.h["topology"]["domains"]}
        with mock.patch.object(cleanup, "journal_hashes", return_value=hashes):
            proof = cleanup.quiesce(reader)
            cleanup.recheck_quiescence(reader, proof)
        reader.session.close()
        for failed_step in ("destroy-controller", "destroy-attestor-enrollment", "delete-controller-material", "destroy-appliance", "cleanup-tailnet", "destroy-observer-roles", "audit-zero-residual", None):
            with self.subTest(cleanup_failure=failed_step), tempfile.TemporaryDirectory(dir=path) as directory:
                d = object.__new__(deploy.Deployment)
                d.config = SimpleNamespace(run_id=self.h["run_id"], appliance_state_key="runs/fixture/appliance/terraform.tfstate", controller=SimpleNamespace(region="us-west-2", state_key="runs/fixture/controller/terraform.tfstate"), appliance=SimpleNamespace(backend={"bucket": self.h["claim"]["bucket"], "region": self.h["claim"]["region"]}))
                d.run_dir = pathlib.Path(directory)
                d.invocation_id = self.h["invocation_id"]
                d.backend_claim_key = self.h["claim"]["key"]
                d.backend_claim_version_id = self.h["claim"]["version_id"]
                d.backend_state_cleanup_authorized = True
                d.private_reference = self.h["private_state"]
                d.session = self.session("cleanup")
                d.aws = io.AWS(io.Commands(d.session, self.root))
                d.seed_receipts = {}
                d.sleep = lambda _: None
                d.save = mock.Mock()
                called = []

                def operation(name):
                    called.append(name)
                    if name == failed_step:
                        raise KeyboardInterrupt()
                    if name == "destroy-observer-roles":
                        for phase in ("observe", "quiesce"):
                            self.cloud.roles.pop(self.h["roles"][phase]["arn"].split("/")[-1], None)

                # Resource creation/destroy is the Terraform boundary; the
                # cleanup driver, IAM unfreeze and S3 finalizer remain real.
                d.workspaces = {key: SimpleNamespace(destroy=lambda name=name: operation(name)) for key, name in (("controller", "destroy-controller"), ("attestor", "destroy-attestor-enrollment"), ("sessions", "destroy-observer-roles"))}
                d.delete_controller_material = lambda: operation("delete-controller-material")
                d.destroy_appliance = lambda: operation("destroy-appliance")
                d.cleanup_tailnet = lambda: operation("cleanup-tailnet")

                def audit():
                    operation("audit-zero-residual")
                    return [{"hook": name, "residual_count": 0} for name in legacy.RESIDUAL_AUDIT_HOOKS]

                d.audit_residuals = audit
                # A prior failed cleanup may already have removed this deny.
                self.cloud.roles["lifecycle"]["policies"][self.h["revocation"]["policy_name"]] = io.frozen_policy()
                outcome = cleanup.cleanup_owned(d, h=self.h, proof=proof)
                cleanup.validate_cleanup(outcome, self.h)
                if failed_step:
                    self.assertEqual(outcome["status"], "failed")
                    self.assertEqual(called[-1], failed_step)
                    self.assertEqual(d.backend_claim_version_id, self.h["claim"]["version_id"])
                    io.verify_claim(d.aws, self.h, self.root)
                else:
                    self.assertEqual(outcome["status"], "complete", outcome)
                    self.assertIsNone(d.backend_claim_version_id)
                    events = [{"Package": "github.com/jaxxstorm/envelope/internal/controller/integration", "Test": test, "Action": "pass"} for test in contract.INTEGRATION_TESTS.values()]
                    events.append({"Package": events[0]["Package"], "Action": "pass"})
                    integration = contract.record_integration(b"\n".join(json.dumps(e).encode() for e in events), self.h["context"]["revision"])
                    combined = cli.bundle(self.h, live, integration, proof, outcome)
                    self.assertEqual(combined["status"], "passed")
                    legacy.write_private_json(path / "bundle.json", combined)
        # Subsequent subtests model separate fresh invocations, not adoption.
        self.cloud.__dict__.update(Cloud(self.h).__dict__)
        self.freeze()

    def test_cleanup_cli_withholds_privileged_identity_when_recheck_fails(self):
        s = self.session("quiesce")
        args = ["cleanup", "--handoff-reference", str(self.root / "handoff-ref.json"), "--role-arn", s.role_arn, "--directory", str(self.root / "cleanup"), "--reference", str(self.root / "bundle-ref.json"), "--quiescence-reference", str(self.root / "quiescence-ref.json"), "--integration", str(self.root / "integration.json")]
        legacy.write_private_json(self.root / "quiescence-ref.json", self.h["claim"])
        with mock.patch.object(cli, "load_handoff", return_value=(self.h, s, mock.Mock())), mock.patch.object(cli, "read_object", return_value={}), mock.patch.object(cleanup, "recheck_quiescence", side_effect=contract.Error("changed journal")), mock.patch.object(cli, "assume_oidc") as assume:
            self.assertEqual(cli.main(args), 1)
            assume.assert_not_called()
        self.assertEqual(s.secrets(), ("", "", ""))

    def test_initialization_and_serialized_rollout_use_pinned_files_and_backend(self):
        directory = self.root / "deployment"
        directory.mkdir()
        config = fixture.make_config(directory)
        d = object.__new__(deploy.Deployment)
        d.config, d.run_dir = config, directory
        d.raw = {"context": self.h["context"]}
        d.invocation_id = self.h["invocation_id"]
        d.topology, d.topology_identity = self.h["topology"], self.h["topology_identity"]
        d.deployment = legacy.parse_appliance_output(fixture.appliance_output(), config)
        d.controller_output = {"deployment_lifecycle_role_arn": {"value": self.h["revocation"]["lifecycle_role_arn"]}}
        d.controller_variables = {"deployment_mode": "read-only"}
        d.lifecycle_receipts = []
        d.save = mock.Mock()
        d.monotonic = lambda: Clock.value.timestamp()
        d.sleep = lambda seconds: setattr(Clock, "value", Clock.value + dt.timedelta(seconds=seconds))
        d._tailnet_consensus = lambda did: {"owner_router_id": "west-b" if did == "west-a" else did}
        d._dynamo_item = lambda *args: None
        d.command = io.Commands(self.session("deploy"), directory)
        d.controller_workspace = deploy.DeploymentWorkspace(config, d.command, directory, self.root, "controller", config.controller.state_key)
        d.appliance_workspace = deploy.DeploymentWorkspace(config, d.command, directory, self.root, "appliance", config.appliance_state_key)
        legacy.write_private_json(d.appliance_workspace.variables_path, {"artifact_path": "fixture"})
        d.deploy_controller = lambda mode: d.controller_workspace.apply({"deployment_mode": mode}, mode)
        build = config.appliance.artifact_manifest.parent
        build.mkdir(parents=True, exist_ok=True)
        binary = build / "envelope-controller-deploy-linux-amd64"
        binary.write_bytes(b"mock executable: never executed")
        terraform = directory / "terraform"
        terraform.write_bytes(b"mock pinned terraform: never executed")
        d.controller_manifest = {"artifacts": [{"component": "envelope-controller-deploy", "architecture": "amd64", "file": binary.name, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "vcs_revision": self.h["context"]["revision"], "vcs_modified": False}]}
        calls = []

        def native(args, env, **kwargs):
            calls.append((args, env))
            if args[0] == "terraform":
                if args[1] == "plan":
                    plan = pathlib.Path(next(x.removeprefix("-out=") for x in args if x.startswith("-out=")))
                    plan.write_bytes(json.dumps({"request": args}).encode())
                return json.dumps(d.controller_output) if args[1] == "output" else "{}"
            self.assertEqual(pathlib.Path(args[0]), binary)
            self.assertEqual(env["TF_DATA_DIR"], str(d.controller_workspace.data_dir))
            operation = args[1]
            if operation == "initialize":
                return json.dumps({"initialized": True, "activated": False, "domain_id": args[args.index("--domain") + 1], "topology_hash": self.h["topology_identity"]["canonical_sha256"], "revision": 1})
            if operation == "check-routers":
                return json.dumps({"checked": True, "routers": len(d.topology["routers"]), "topology_hash": self.h["topology_identity"]["canonical_sha256"]})
            if operation == "rollout":
                for flag in ("--plan", "--terraform"):
                    file = pathlib.Path(args[args.index(flag) + 1])
                    self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), args[args.index(flag + "-sha256") + 1])
                self.assertIn("aws_volume_attachment.observer_state", pathlib.Path(args[args.index("--plan") + 1]).read_text())
            return json.dumps({"operation_id": "a" * 32, "operation": operation, "status": "starting"}) + "\n" + json.dumps({"operation_id": "a" * 32, "status": "complete"})

        with mock.patch.object(io, "_run", side_effect=native), mock.patch("shutil.which", return_value=str(terraform)):
            d.initialize_and_rollout()
        self.assertEqual([r["operation"] for r in d.lifecycle_receipts], ["initialize"] * 4 + ["rollout"] * 3 + ["activate"] * 4)
        commands = [args for args, _ in calls]
        self.assertEqual(sum("rollout" in args for args in commands), 3)
        self.assertTrue(any(any(x.startswith("-replace=aws_route.gwlbe_to_remote_west") for x in args) for args in commands))
        self.assertEqual(d.initial_owner_selection["west"]["a"], "b")
        self.assertEqual(d.controller_mode, "active")
        binary.write_bytes(b"tampered")
        with self.assertRaises(contract.Error):
            d.binary("envelope-controller-deploy")

    def test_failed_handoff_load_closes_issued_session(self):
        legacy.write_private_json(self.root / "ref.json", self.h["claim"])
        s = self.session("observe")
        args = SimpleNamespace(handoff_reference=self.root / "ref.json", role_arn=s.role_arn)
        with mock.patch.object(cli, "assume_oidc", return_value=s), mock.patch.object(cli, "read_object", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                cli.load_handoff(args, "observe", self.root)
        self.assertEqual(s.secrets(), ("", "", ""))

    def test_oidc_subject_sts_identity_and_private_token_lifetime(self):
        import os
        s = self.session("observe")
        claims = {"sub": s.subject, "aud": "sts.amazonaws.com", "iat": Clock.value.timestamp(), "exp": Clock.value.timestamp() + 300}
        token_paths = []

        def response():
            token = "header." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".signature"
            result = mock.MagicMock()
            result.__enter__.return_value.read.return_value = json.dumps({"value": token}).encode()
            return result

        def sts(args, env, **kwargs):
            self.assertEqual(args[1:3], ["sts", "assume-role-with-web-identity"])
            self.assertNotIn("AWS_ACCESS_KEY_ID", env)
            path = pathlib.Path(args[args.index("--web-identity-token") + 1].removeprefix("file://"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            token_paths.append(path)
            return json.dumps({"AssumedRoleUser": {"Arn": s.principal_arn}, "Credentials": {"AccessKeyId": s.access_key, "SecretAccessKey": s.secret_key, "SessionToken": s.token, "Expiration": s.receipt()["expires_at"]}})

        with mock.patch.dict(os.environ, {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://test.actions.githubusercontent.com/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "private-oidc-bearer", "AWS_ACCESS_KEY_ID": "ambient-must-not-be-used"}), mock.patch.object(io.urllib.request, "urlopen", side_effect=lambda *args, **kwargs: response()), mock.patch.object(io.time, "time", return_value=Clock.value.timestamp()), mock.patch.object(io, "_run", side_effect=sts) as run:
            issued = io.assume_oidc(s.role_arn, "observe", self.h["context"], self.root / "oidc", 3600)
            self.assertEqual(issued.role_arn, s.role_arn)
            self.assertTrue(all(not path.exists() for path in token_paths))
            claims["sub"] = self.h["roles"]["cleanup"]["subject"]
            with self.assertRaises(contract.Error):
                io.assume_oidc(s.role_arn, "observe", self.h["context"], self.root / "oidc", 3600)
            self.assertEqual(run.call_count, 1)

    def test_private_checkpoint_restore_rebases_only_local_artifact_authority(self):
        directory = self.root / "private"
        directory.mkdir()
        config = fixture.make_config(directory)
        raw = {"context": self.h["context"], "production": config.raw}
        with mock.patch.object(legacy, "build_tailscale", return_value=mock.Mock()):
            d = deploy.Deployment(raw, config, self.session("deploy"), directory)
        d.invocation_id = self.h["invocation_id"]
        d.backend_claim_version_id = self.h["claim"]["version_id"]
        d.backend_claim_key = self.h["claim"]["key"]
        d.runner_identity = None  # Local checkpoint, before publication authority.
        legacy.write_private_json(d.appliance_workspace.variables_path, {"artifact_path": "/old-host/build/envelope-linux-amd64"})
        d.save()
        saved = contract.read_json(directory / "private-state-000001.json")
        restored_dir = self.root / "restored"
        restored_dir.mkdir()
        restored_config = fixture.make_config(restored_dir)
        with mock.patch.object(legacy, "build_tailscale", return_value=mock.Mock()):
            restored = deploy.Deployment(raw, restored_config, self.session("cleanup"), restored_dir)
        # Config identity stays portable across hosts; no old absolute paths
        # establish cloud ownership. The real claim-version reader still runs.
        restored.config = SimpleNamespace(**{**restored_config.__dict__, "configuration_sha256": config.configuration_sha256})
        restored.restore(saved, self.h)
        variables = contract.read_json(restored.appliance_workspace.variables_path)
        self.assertEqual(variables, {"artifact_path": str(restored_config.appliance.artifact_manifest.parent / "envelope-linux-amd64")})
        bad = copy.deepcopy(saved)
        bad["values"]["invocation_id"] = "0" * 64
        with self.assertRaises(contract.Error):
            restored.restore(bad, self.h)

    def test_snapshot_and_wait_consume_raw_cloud_and_http_records(self):
        reader = observer.LiveObserver(self.h, self.session("observe"), self.root)
        reader.sleep = lambda _: None

        def http(url):
            if url.endswith("/readyz"):
                return 200, "ready"
            if url.endswith("/healthz"):
                return 200, "ok"
            metrics = []
            for domain in self.h["topology"]["domains"]:
                for metric, label, value in (("domain_mode", "mode", "active"), ("domain_role", "role", "leader"), ("domain_phase", "phase", "stable")):
                    metrics.append(f'envelope_controller_{metric}{{domain="{domain["id"]}",{label}="{value}"}} 1')
                metrics.append(f'envelope_controller_lease_fence_term{{domain="{domain["id"]}"}} 1')
            return 200, "\n".join(metrics)

        with mock.patch.object(reader, "_http_get", side_effect=http):
            rows = reader.wait_live("active-baseline", {})
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(r["activated"] and r["observation"]["route_agreement"] for r in rows))
            self.assertTrue(all(r["observation"]["tailnet"]["observer_quorum"] == 3 for r in rows))
            self.cloud.corrupt_item = True
            with self.assertRaises(contract.Error):
                reader.snapshot("active-baseline")

    def test_enrollment_binds_each_router_release_and_runtime_client_subnets(self):
        for wrong_identity in (False, True):
            with self.subTest(wrong_identity=wrong_identity), tempfile.TemporaryDirectory(dir=self.root) as path:
                directory = pathlib.Path(path)
                config = fixture.make_config(directory)
                d = object.__new__(deploy.Deployment)
                d.run_dir, d.config = directory, config
                d.raw = {"context": self.h["context"], "deployment_role_arn": self.h["revocation"]["role_arn"]}
                d.topology, d.topology_identity = self.h["topology"], self.h["topology_identity"]
                d.invocation_id = self.h["invocation_id"]
                d.controller_variables = {}
                d.seed_receipts = {r["router_id"]: {"ed25519_public_key": r["ed25519_public_key"], "parameter_arn": f"arn:aws:ssm:us-west-2:{fixture.ACCOUNT_ID}:parameter/envelope/fixture/{r['router_id']}"} for r in self.h["attestation_trust"]["routers"]}
                seed = {rid: {"configuration": {"router_id": rid}, "role_name": rid + "-role", "security_group_id": "sg-00000001"} for rid in d.seed_receipts}
                d.deployment = SimpleNamespace(raw={"router_attestor_enrollment_seed": {"value": seed}})
                d.binary = lambda _: directory / "attestor"
                d.command, d.aws, d.save = mock.Mock(), mock.Mock(), mock.Mock()

                def identity(args, **kwargs):
                    configuration = contract.read_json(pathlib.Path(args[-1]))
                    return json.dumps({"topology_sha256": self.h["topology_identity"]["canonical_sha256"], "source_modified": False, "revision": "0" * 40 if wrong_identity else self.h["context"]["revision"], "router_id": configuration["router_id"], "ed25519_public_key": configuration["ed25519_public_key"]})

                d.command.run.side_effect = identity
                d.aws.json.side_effect = lambda args, **kwargs: {"Subnets": [{"SubnetId": args[-1], "VpcId": config.controller.vpc_id, "CidrBlock": "10.30.0.0/24"}]}
                workspace = mock.Mock()
                d.workspaces = {"attestor": workspace}
                bindings = {r["router_id"]: {k: v for k, v in r.items() if k != "router_id"} for r in self.h["attestation_trust"]["routers"]}
                workspace.apply.return_value = {"router_attestations": {"value": bindings}}
                if wrong_identity:
                    with self.assertRaises(contract.Error):
                        d.enroll_routers()
                    workspace.apply.assert_not_called()
                else:
                    d.enroll_routers()
                    self.assertEqual(d.attestation_trust, self.h["attestation_trust"])
                    variables = workspace.apply.call_args.args[0]
                    self.assertIn("10.30.0.0/24", variables["controller_source_cidrs"])
                    self.assertEqual(set(variables["enrollments"]), set(d.seed_receipts))
                    self.assertEqual(d.controller_variables["deployment_lifecycle"]["external_id"], d.invocation_id)

    def test_handoff_is_constructed_from_exact_deployed_dependencies(self):
        directory = self.root / "handoff-build"
        directory.mkdir()
        config = fixture.make_config(directory)
        d = object.__new__(deploy.Deployment)
        d.config = SimpleNamespace(run_id=self.h["run_id"], expires_at=self.h["expires_at"], configuration_sha256=self.h["configuration_sha256"], appliance=config.appliance, controller=config.controller)
        d.run_dir, d.raw = directory, {"context": self.h["context"], "deployment_role_arn": self.h["revocation"]["role_arn"], "cleanup_role_arn": self.h["roles"]["cleanup"]["arn"], "oidc_provider_arn": self.cloud.principal["Federated"], "artifact_store": {k: self.h["evidence_store"][k] for k in ("bucket", "region")}}
        d.session = self.session("deploy")
        d.session.principal_arn = self.h["revocation"]["session_arn"]
        d.runner_identity = {"account_id": fixture.ACCOUNT_ID}
        d.invocation_id = self.h["invocation_id"]
        d.backend_claim_key, d.backend_claim_version_id = self.h["claim"]["key"], self.h["claim"]["version_id"]
        d.aws = d.raw_aws = io.AWS(io.Commands(d.session, directory))
        d.deployment = legacy.parse_appliance_output(fixture.appliance_output(), config)
        d.topology, d.topology_identity, d.router_nodes = self.h["topology"], self.h["topology_identity"], self.h["router_nodes"]
        d.controller_output = {"controller_instances": {"value": self.h["controller"]["instances"]}, "deployment_lifecycle_role_arn": {"value": self.h["revocation"]["lifecycle_role_arn"]}}
        d.controller_manifest = {"artifacts": [{"component": c, "architecture": "amd64", "vcs_revision": self.h["context"]["revision"], "vcs_modified": False, "sha256": "e" * 64} for c in ("envelope-controller", "envelope-controller-topology", "envelope-controller-deploy", "envelope-router-attestor")]}
        d.packet_artifact = {"sha256": "e" * 64}
        d.attestation_trust, d.lifecycle_receipts = self.h["attestation_trust"], self.h["dependencies"]["lifecycle"]
        d.private_reference = self.h["private_state"]
        d.save = mock.Mock()
        d.workspaces = {"sessions": mock.Mock()}
        actual = d.make_handoff()
        contract.validate_handoff(actual, now=Clock.value, context=self.h["context"])
        self.assertEqual(actual["claim"], self.h["claim"])
        self.assertEqual(actual["attestation_trust"], self.h["attestation_trust"])
        self.assertEqual(actual["dependencies"], self.h["dependencies"])
        policies = d.workspaces["sessions"].apply.call_args.args[0]["boundary_policies"]
        for phase in ("observe", "quiesce"):
            self.assertEqual(json.loads(policies[phase]), boundary_policy(actual, phase))
        d.controller_manifest["artifacts"][2]["vcs_revision"] = "0" * 40
        with self.assertRaises(contract.Error):
            d.make_handoff()


if __name__ == "__main__":
    unittest.main()
