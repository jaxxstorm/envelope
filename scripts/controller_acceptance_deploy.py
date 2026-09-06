"""Deployment/cleanup coordinator; never imported by the measured process."""
from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import fnmatch
import urllib.parse
from collections.abc import Mapping
from typing import Any

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract
from controller_acceptance_io import AWS, Commands, Session, APIError, publish_object, revocation_policy, frozen_policy
from controller_acceptance_policy import boundary_policy


def _private_json_value(value: Any) -> str:
    if isinstance(value, pathlib.Path):
        return str(value)
    raise contract.Error("private journal contains an unsupported value")


def load_config(path: pathlib.Path, directory: pathlib.Path) -> tuple[dict[str, Any], legacy.ProductionRunConfig]:
    raw = contract.exact(contract.read_json(path), {"schema", "production", "deployment_role_arn", "cleanup_role_arn", "oidc_provider_arn", "artifact_store", "context"}, "split deployment configuration")
    contract.require(raw["schema"] == 1 and raw["context"] == contract.execution_context(), "deployment configuration belongs to another invocation")
    for name in ("deployment_role_arn", "cleanup_role_arn"):
        contract.require(bool(contract.ROLE.fullmatch(raw[name])), "explicit deployment/cleanup roles are required")
    contract.require(raw["deployment_role_arn"] != raw["cleanup_role_arn"], "deployment and cleanup identities must be distinct")
    account = raw["deployment_role_arn"].split(":")[4]
    contract.require(raw["cleanup_role_arn"].split(":")[4] == account, "cleanup role belongs to another account")
    contract.require(raw["oidc_provider_arn"] == f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com", "OIDC provider differs from deployment account")
    artifact = contract.exact(raw["artifact_store"], {"bucket", "region"}, "artifact store")
    legacy._string(artifact["bucket"], "artifact bucket")
    legacy._string(artifact["region"], "artifact region", pattern=legacy._REGION_RE)
    production = copy.deepcopy(raw["production"])
    contract.require(production["artifact_manifest"] == "build/manifest.json", "artifact_manifest must be portable and run-local")
    nested = directory / "production-config.json"
    if not nested.exists():
        legacy.write_private_json(nested, production)
    else:
        contract.require(contract.read_json(nested) == production, "retained production config differs")
    config = legacy.ProductionRunConfig.load(nested, enforce_future_expiry=False)
    contract.require(config.controller.timeouts["transition_seconds"] <= 300, "split live transitions must fit the bounded one-hour observer session")
    return raw, dataclasses.replace(config, configuration_sha256=contract.digest(raw))


class DeploymentWorkspace(legacy.TerraformWorkspace):
    def apply_targets(self, variables: Mapping[str, Any], label: str, targets: list[str], replacements: list[str] | None = None, *, apply: bool = True) -> pathlib.Path | dict[str, Any]:
        self.initialize()
        self.variables_path.write_text(json.dumps(variables, sort_keys=True, separators=(",", ":")))
        os.chmod(self.variables_path, 0o600)
        plan = self.run_dir / f"{self.name}-{label}.tfplan"
        args = ["terraform", "plan", "-input=false", f"-out={plan}", f"-var-file={self.variables_path}"]
        args += [f"-target={target}" for target in targets]
        args += [f"-replace={target}" for target in replacements or []]
        self.runner.run(args, cwd=self.source_dir, env=self._environment(), timeout_seconds=1800)
        if not apply:
            return plan
        self.runner.run(["terraform", "apply", "-input=false", "-auto-approve", str(plan)], cwd=self.source_dir, env=self._environment(), timeout_seconds=3600)
        self.has_applied = True
        return self.output()

    def output(self) -> dict[str, Any]:
        return legacy._mapping(legacy.strict_json_loads(self.runner.run(["terraform", "output", "-json"], cwd=self.source_dir, env=self._environment(), timeout_seconds=300)), "deployment outputs")


class CheckpointTailnet:
    def __init__(self, delegate: Any, save: Any):
        self.delegate, self.save = delegate, save

    def __getattr__(self, name: str) -> Any:
        target = getattr(self.delegate, name)
        if name not in {"create_auth_key", "delete_device", "revoke_auth_key"}:
            return target
        def call(*args: Any, **kwargs: Any) -> Any:
            self.save()
            return target(*args, **kwargs)
        return call


class Deployment(legacy.AwsProductionAdapter):
    SAVED = (
        "invocation_id", "runner_identity", "packet_artifact", "controller_manifest", "router_key_id", "created_auth_key_ids", "router_parameters", "controller_parameters", "uploaded_objects",
        "tailnet_baseline_captured", "tailnet_device_baseline_ids", "tailnet_auth_key_baseline_ids", "tailnet_owned_device_ids", "router_auth_key_description", "topology", "topology_identity", "router_nodes", "controller_variables", "controller_output", "controller_mode", "appliance_deployment_started", "active_deployment_attempted", "backend_claim_key", "backend_claim_version_id", "backend_state_cleanup_authorized", "seed_receipts", "lifecycle_receipts", "attestation_trust", "initial_owner_selection", "claim_attempt_body",
    )

    def __init__(self, raw: dict[str, Any], config: legacy.ProductionRunConfig, session: Session, directory: pathlib.Path):
        root = pathlib.Path(__file__).resolve().parents[1]
        super().__init__(config, directory, root / "example/terraform", root / "deploy/terraform/envelope-controller")
        directory = self.run_dir
        self.raw, self.session = raw, session
        self.protected_secrets = (*self.protected_secrets, *session.secrets())
        self.command = Commands(session, directory / "home", self.before_command)
        self.aws = AWS(self.command)
        self.raw_aws = AWS(Commands(session, directory / "home"))
        self.tailnet = CheckpointTailnet(self.tailnet, self.save)
        self.workspaces = {
            "appliance": DeploymentWorkspace(config, self.command, directory, root / "example/terraform", "appliance", config.appliance_state_key),
            "controller": DeploymentWorkspace(config, self.command, directory, root / "deploy/terraform/envelope-controller", "controller", config.controller.state_key),
            "attestor": DeploymentWorkspace(config, self.command, directory, root / "deploy/terraform/router-attestor", "attestor", f"runs/{config.run_id}/attestor/terraform.tfstate"),
            "sessions": DeploymentWorkspace(config, self.command, directory, root / "deploy/terraform/controller-acceptance", "sessions", f"runs/{config.run_id}/sessions/terraform.tfstate"),
        }
        self.appliance_workspace = self.workspaces["appliance"]
        self.controller_workspace = self.workspaces["controller"]
        self.seed_receipts: dict[str, Any] = {}
        self.lifecycle_receipts: list[dict[str, Any]] = []
        self.attestation_trust: dict[str, Any] = {}
        self.initial_owner_selection: dict[str, Any] = {}
        self.claim_attempt_body = None
        self.sequence = 0
        self.private_reference: dict[str, str] | None = None
        self.saving = False

    def _backend_state_keys(self) -> tuple[str, ...]:
        keys = [self.config.appliance_state_key, self.config.controller.state_key, f"runs/{self.config.run_id}/attestor/terraform.tfstate", f"runs/{self.config.run_id}/sessions/terraform.tfstate"]
        return tuple(key for base in keys for key in (base, base + ".tflock"))

    def before_command(self, args: list[str]) -> None:
        if self.saving:
            return
        name = pathlib.Path(args[0]).name
        mutating = name.startswith("envelope-") or name == "terraform" and len(args) > 1 and args[1] == "apply"
        if name == "aws" and len(args) > 2:
            mutating = args[2].startswith(("put-", "delete-", "create-", "update-", "start-", "stop-"))
            if args[1:3] == ["s3api", "put-object"] and "--key" in args and args[args.index("--key") + 1] == self.backend_claim_key:
                self.claim_attempt_body = contract.read_json(pathlib.Path(args[args.index("--body") + 1]))
        if mutating:
            self.save()

    def save(self) -> None:
        if self.saving:
            return
        self.saving = True
        try:
            self.sequence += 1
            values = {}
            for name in self.SAVED:
                value = getattr(self, name)
                values[name] = sorted(value) if isinstance(value, set) else copy.deepcopy(value)
            workspaces = {name: {"variables": contract.read_json(w.variables_path) if w.variables_path.is_file() else None, "started": w.variables_path.is_file()} for name, w in self.workspaces.items()}
            state = {"schema": 1, "kind": "private-controller-deployment", "run_id": self.config.run_id, "context": self.raw["context"], "configuration": self.raw, "configuration_sha256": self.config.configuration_sha256, "sequence": self.sequence, "values": values, "workspaces": workspaces, "appliance_output": self.deployment.raw if self.deployment else None}
            state = json.loads(json.dumps(state, default=_private_json_value))
            legacy.write_private_json(self.run_dir / f"private-state-{self.sequence:06d}.json", state)
            if self.runner_identity is not None:
                if self.backend_claim_version_id is not None:
                    self._require_backend_claim()
                backend = self.config.appliance.backend
                self.private_reference = publish_object(self.raw_aws, state, bucket=backend["bucket"], key=f"runs/{self.config.run_id}/private/{self.invocation_id}/state-{self.sequence:06d}.json", region=backend["region"], kms=backend["kms_key_arn"], directory=self.run_dir)
        finally:
            self.saving = False

    def restore(self, state: Mapping[str, Any], h: Mapping[str, Any]) -> None:
        contract.require(state.get("schema") == 1 and state.get("kind") == "private-controller-deployment" and state.get("run_id") == self.config.run_id and state.get("context") == self.raw["context"] and state.get("configuration_sha256") == self.config.configuration_sha256, "private deployment state belongs to another invocation")
        contract.require(set(state["values"]) == set(self.SAVED), "private state fields differ")
        for name, value in state["values"].items():
            setattr(self, name, set(value) if name in {"tailnet_device_baseline_ids", "tailnet_auth_key_baseline_ids", "tailnet_owned_device_ids"} else copy.deepcopy(value))
        contract.require(self.invocation_id == h["invocation_id"] and self.backend_claim_version_id == h["claim"]["version_id"], "private state does not own handoff claim")
        self.sequence = state["sequence"]
        for name, record in state["workspaces"].items():
            workspace = self.workspaces[name]
            if record["variables"] is not None:
                variables = copy.deepcopy(record["variables"])
                if name == "appliance":
                    variables["artifact_path"] = str(self.config.appliance.artifact_manifest.parent / f"envelope-linux-{self.config.appliance.architecture}")
                workspace.variables_path.write_text(json.dumps(variables, sort_keys=True))
                os.chmod(workspace.variables_path, 0o600)
        if state["appliance_output"] is not None:
            self.deployment = legacy.parse_appliance_output(state["appliance_output"], self.config)
        self._require_backend_claim()

    def validate_static_trust(self, arn: str, phase: str) -> None:
        role = self.raw_aws.json(["iam", "get-role", "--role-name", arn.split("/")[-1]]).get("Role", {})
        contract.require(role.get("MaxSessionDuration", 0) >= (21600 if phase == "deploy" else 10800), "deployment/cleanup role duration cannot contain its phase")
        trust = role.get("AssumeRolePolicyDocument")
        if isinstance(trust, str):
            trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
        statements = trust.get("Statement", []) if isinstance(trust, Mapping) else []
        allows = [s for s in statements if s.get("Effect") == "Allow"]
        expected = contract.subject(self.raw["context"], phase, wildcard=True)
        condition = allows[0].get("Condition") if len(allows) == 1 else None
        permitted = condition == {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": expected}}
        if phase == "cleanup" and isinstance(condition, Mapping):
            equals = condition.get("StringEquals", {})
            actual_subject = equals.get("token.actions.githubusercontent.com:sub", "")
            permitted = permitted or (set(condition) == {"StringEquals", "DateLessThan"} and set(equals) == {"token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:sub"} and equals.get("token.actions.githubusercontent.com:aud") == "sts.amazonaws.com" and isinstance(actual_subject, str) and "*" not in actual_subject and fnmatch.fnmatchcase(actual_subject, expected))
        contract.require(len(allows) == 1 and allows[0].get("Action") == "sts:AssumeRoleWithWebIdentity" and allows[0].get("Principal") == {"Federated": self.raw["oidc_provider_arn"]} and permitted, "deployment-capable role has an unsafe OIDC trust boundary")

    def claim(self) -> None:
        contract.require(self.session.phase == "deploy" and self.session.role_arn == self.raw["deployment_role_arn"] and self.session.subject == contract.subject(self.raw["context"], "deploy"), "deployment identity mismatch")
        self.validate_static_trust(self.raw["deployment_role_arn"], "deploy")
        self.validate_static_trust(self.raw["cleanup_role_arn"], "cleanup")
        self._require_toolchain()
        self.runner_identity = {"account_id": self.session.role_arn.split(":")[4], "principal_arn": self.session.principal_arn, "session_name": self.session.principal_arn.rsplit("/", 1)[-1]}
        self._require_fresh_local_terraform()
        self._acquire_backend_claim()
        self.save()

    def artifact_entry(self, component: str) -> dict[str, Any]:
        matches = [e for e in self.controller_manifest["artifacts"] if e["component"] == component and e["architecture"] == self.config.appliance.architecture]
        contract.require(len(matches) == 1, "release dependency missing")
        contract.require(matches[0].get("vcs_revision") == self.raw["context"]["revision"] and matches[0].get("vcs_modified") is False, "dependency is not the exact clean workflow revision")
        return matches[0]

    def binary(self, component: str) -> pathlib.Path:
        entry = self.artifact_entry(component)
        path = self.config.appliance.artifact_manifest.parent / entry["file"]
        contract.require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], "production binary hash mismatch")
        return path

    def upload_bootstrap(self) -> dict[str, Any]:
        entry = self.artifact_entry("envelope-router-attestor")
        store = self.raw["artifact_store"]
        contract.require(self.aws.json(["s3api", "get-bucket-versioning", "--bucket", store["bucket"]], region=store["region"]).get("Status") == "Enabled", "bootstrap artifact bucket must be versioned")
        artifact = {"component": entry["component"], "bucket": store["bucket"], "region": store["region"], "key": f"runs/{self.config.run_id}/{self.invocation_id}/{entry['file']}", "version_id": None, "sha256": entry["sha256"], "baseline_versions": []}
        contract.require(not legacy.exact_object_versions(self.aws, bucket=artifact["bucket"], key=artifact["key"], region=artifact["region"]), "bootstrap artifact key already exists")
        self.uploaded_objects.append(artifact)
        result = self.aws.json(["s3api", "put-object", "--bucket", artifact["bucket"], "--key", artifact["key"], "--body", str(self.binary(entry["component"])), "--server-side-encryption", "AES256", "--if-none-match", "*", "--metadata", f"sha256={entry['sha256']},invocation={self.invocation_id}"], region=artifact["region"])
        artifact["version_id"] = legacy._string(result.get("VersionId"), "artifact version")
        contract.require(artifact["version_id"] != "null", "unversioned artifact")
        self.save()
        return artifact

    def prepare_seeds(self) -> None:
        account = self.runner_identity["account_id"]
        for site in ("west", "east"):
            for az in sorted(self.config.appliance.sites[site]["azs"]):
                rid = f"{site}-{az}"
                purpose = f"router-attestor-{rid}"
                name = f"/envelope/{self.config.run_id}/{rid}/{self.invocation_id}-seed"
                reference = {"purpose": purpose, "name": name, "arn": f"arn:aws:ssm:{self.config.controller.region}:{account}:parameter{name}", "kms_key_arn": self.config.controller.secret_kms_key_arn, "region": self.config.controller.region, "invocation_id": self.invocation_id, "put_outcome": "pending"}
                self.controller_parameters.append(reference)
                output = self.command.run([str(self.binary("envelope-router-attestor")), "provision-key", "--region", reference["region"], "--parameter", name, "--kms-key-arn", reference["kms_key_arn"], "--run-id", self.config.run_id, "--invocation-id", self.invocation_id, "--expires-at", self.config.expires_at, "--purpose", purpose], timeout_seconds=60)
                receipt = contract.exact(legacy.strict_json_loads(output), {"parameter_arn", "version", "ed25519_public_key"}, "seed receipt")
                contract.require(receipt["parameter_arn"] == reference["arn"] and receipt["version"] == 1 and bool(contract.SHA.fullmatch(receipt["ed25519_public_key"])), "seed receipt ownership differs")
                reference["version"], reference["put_outcome"] = "1", "confirmed"
                self.seed_receipts[rid] = receipt
                self._wait_parameter_resolution(reference, require_owned=True)
        self.save()

    def deploy_appliance_native(self, bootstrap: Mapping[str, Any]) -> None:
        parameters = [{"site": r["purpose"].removeprefix("router-"), "arn": r["arn"], "kms_key_arn": r["kms_key_arn"]} for r in self.router_parameters]
        variables = legacy.terraform_variables(self.config.appliance, self.packet_artifact, parameters)
        variables["symmetric_topology"] = copy.deepcopy(self.config.raw["symmetric_topology"])
        variables.setdefault("tags", {})["EnvelopeInvocation"] = self.invocation_id
        account = self.runner_identity["account_id"]
        variables["router_attestor_bootstrap"] = {"authority_region": self.config.controller.region, "artifact_manifest_json": json.dumps(self.controller_manifest), "artifact": {k: bootstrap[k] for k in ("region", "bucket", "key", "version_id", "sha256")}, "routers": {rid: {"ed25519_public_key": receipt["ed25519_public_key"], "configuration_parameter_arn": f"arn:aws:ssm:{self.config.controller.region}:{account}:parameter/envelope/{self.config.run_id}/{rid}/{self.invocation_id}-enrollment", "seed_parameter_arn": receipt["parameter_arn"], "seed_version": receipt["version"]} for rid, receipt in self.seed_receipts.items()}}
        self.appliance_deployment_started = True
        output = self.appliance_workspace.apply(variables, "native-create")
        self.deployment = legacy.parse_appliance_output(output, self.config)
        self.save()

    def enroll_routers(self) -> None:
        seed = legacy._output_value(self.deployment.raw, "router_attestor_enrollment_seed")
        contract.require(set(seed) == {r["id"] for r in self.topology["routers"]} == set(self.seed_receipts), "enrollment seed coverage differs from exact topology")
        enrollments = {}
        for rid, entry in seed.items():
            configuration = {**entry["configuration"], "topology": self.topology, "ed25519_public_key": self.seed_receipts[rid]["ed25519_public_key"]}
            path = self.run_dir / f"attestor-{rid}.json"
            legacy.write_private_json(path, configuration)
            identity = legacy.strict_json_loads(self.command.run([str(self.binary("envelope-router-attestor")), "identity", "--config", str(path)], timeout_seconds=60))
            contract.require(identity["topology_sha256"] == self.topology_identity["canonical_sha256"] and identity["source_modified"] is False and identity.get("revision") == self.raw["context"]["revision"] and identity.get("router_id") == rid and identity.get("ed25519_public_key") == self.seed_receipts[rid]["ed25519_public_key"], "attestor identity differs from production topology/release/router")
            enrollments[rid] = {"configuration_identity_json": json.dumps(identity), "configuration_parameter_name": f"/envelope/{self.config.run_id}/{rid}/{self.invocation_id}-enrollment", "seed_parameter_arn": self.seed_receipts[rid]["parameter_arn"], "seed_version": 1, "seed_kms_key_arn": self.config.controller.secret_kms_key_arn, "role_name": entry["role_name"], "security_group_id": entry["security_group_id"]}
        sources = set(self.config.controller.metrics_ingress_cidrs)
        # Metrics clients are not necessarily in the controller subnets. Both
        # the deployment check and the runtime replicas must reach attestors.
        for subnet_id in sorted({p["subnet_id"] for p in self.config.controller.placements.values()}):
            rows = self.aws.json(["ec2", "describe-subnets", "--subnet-ids", subnet_id], region=self.config.controller.region).get("Subnets", [])
            contract.require(len(rows) == 1 and rows[0].get("SubnetId") == subnet_id and rows[0].get("VpcId") == self.config.controller.vpc_id, "attestor client subnet differs from controller authority")
            sources.add(rows[0]["CidrBlock"])
        output = self.workspaces["attestor"].apply({"name": self.config.run_id, "authority_region": self.config.controller.region, "controller_source_cidrs": sorted(sources), "enrollments": enrollments, "protected_acceptance": True, "run_tags": {"EnvelopeRun": self.config.run_id, "EnvelopeInvocation": self.invocation_id, "ExpiresAt": self.config.expires_at}}, "enroll")
        routers = legacy._output_value(output, "router_attestations")
        self.controller_variables["router_attestations"] = routers
        self.controller_variables.setdefault("tags", {})["EnvelopeInvocation"] = self.invocation_id
        self.controller_variables["deployment_lifecycle"] = {"trusted_principal_arns": [self.raw["deployment_role_arn"]], "external_id": self.invocation_id, "rollout": {"state_bucket_arn": f"arn:aws:s3:::{self.config.appliance.backend['bucket']}", "state_key": self.config.controller.state_key, "kms_key_arns": [self.config.appliance.backend["kms_key_arn"], self.config.controller.secret_kms_key_arn]}}
        self.attestation_trust = {"schema_version": 1, "deployment_id": self.config.run_id, "topology_hash": self.topology_identity["canonical_sha256"], "routers": [{"router_id": rid, **routers[rid]} for rid in sorted(routers)]}
        legacy.write_private_json(self.run_dir / "router-trust.json", self.attestation_trust)
        self.save()

    def lifecycle(self, operation: str, *extra: str) -> None:
        role = legacy._output_value(self.controller_output, "deployment_lifecycle_role_arn")
        args = [str(self.binary("envelope-controller-deploy")), operation, "--topology", str(self.run_dir / "controller-topology.source.json"), "--router-trust", str(self.run_dir / "router-trust.json"), "--initialization-role-arn", role, "--external-id", self.invocation_id, *extra]
        output = self.command.run(args, env=self.controller_workspace._environment(), timeout_seconds=900)
        rows = [legacy.strict_json_loads(line) for line in output.splitlines() if line]
        if operation == "initialize":
            contract.require(len(rows) == 1 and rows[0].get("initialized") is True and rows[0].get("activated") is False and rows[0].get("domain_id") == extra[extra.index("--domain") + 1] and rows[0].get("topology_hash") == self.topology_identity["canonical_sha256"], "initialization receipt differs from requested authority")
        elif operation == "check-routers":
            contract.require(len(rows) == 1 and rows[0].get("checked") is True and rows[0].get("routers") == len(self.topology["routers"]) and rows[0].get("topology_hash") == self.topology_identity["canonical_sha256"], "router check receipt differs from enrolled authority")
        else:
            contract.require(len(rows) == 2 and rows[0].get("operation") == operation and rows[0].get("status") == "starting" and rows[-1].get("status") == "complete" and isinstance(rows[0].get("operation_id"), str) and len(rows[0]["operation_id"]) == 32 and rows[-1].get("operation_id") == rows[0]["operation_id"], "production lifecycle did not complete the exact started operation")
        if operation != "check-routers":
            self.lifecycle_receipts.append({"operation": operation, "complete": True, "receipt_sha256": hashlib.sha256(output.encode()).hexdigest()})
        self.save()

    def initialize_and_rollout(self) -> None:
        self.deploy_controller("read-only")
        self.save()
        # Production observers select the initial owner. Bootstrap graph changes
        # are Terraform deployment actions before any journal or measured fault.
        deadline = self.monotonic() + self.config.controller.timeouts["readiness_seconds"]
        owners = {}
        while self.monotonic() < deadline:
            owners = {d["id"]: self._tailnet_consensus(d["id"])["owner_router_id"] for d in self.deployment.seed.domains}
            if all(owners.values()):
                break
            self.sleep(2)
        contract.require(all(owners.values()), "initial production observer quorum unavailable")
        selection = {site: {} for site in ("west", "east")}
        replace = []
        for domain in self.deployment.seed.domains:
            contract.require(self._dynamo_item(f"deployment#{self.config.run_id}", f"domain#{domain['id']}") is None, "bootstrap cannot modify initialized authority")
            site = domain["site_id"]
            az = next(k for k, prefix in self.config.appliance.sites[site]["workload_subnet_cidrs"].items() if prefix == domain["source_prefix"])
            selected = owners[domain["id"]].removeprefix(site + "-")
            selection[site][az] = selected
            if selected != az:
                replace += [f'aws_route.gwlbe_to_remote_{site}[{json.dumps(az + ":" + prefix)}]' for prefix in domain["remote_prefixes"]]
        self.initial_owner_selection = selection
        if replace:
            variables = contract.read_json(self.appliance_workspace.variables_path)
            variables["production_initial_router_owners"] = selection
            self.appliance_workspace.apply_targets(variables, "initial-owner", replace, replace)
        check_deadline = self.monotonic() + self.config.controller.timeouts["readiness_seconds"]
        while True:
            try:
                self.lifecycle("check-routers")
                break
            except contract.Error:
                if self.monotonic() >= check_deadline:
                    raise
                self.sleep(5)
        for domain in self.topology["domains"]:
            self.lifecycle("initialize", "--domain", domain["id"])
        variables = copy.deepcopy(self.controller_variables)
        variables["deployment_mode"] = "active"
        self.active_deployment_attempted = True
        targets = ["aws_iam_role_policy.controller", "aws_ebs_volume.observer_state", "aws_security_group.controller", "aws_ssm_parameter.topology", "aws_ssm_parameter.router_trust", "aws_dynamodb_table.authority"]
        self.controller_workspace.apply_targets(variables, "stage-authority", targets)
        self.controller_variables = variables
        import shutil
        terraform = pathlib.Path(shutil.which("terraform") or "")
        terraform_hash = hashlib.sha256(terraform.read_bytes()).hexdigest()
        for cid in self.config.controller.controller_ids:
            target = f'aws_volume_attachment.observer_state[{json.dumps(cid)}]'
            plan = self.controller_workspace.apply_targets(variables, f"rollout-{cid}", [target], apply=False)
            self.lifecycle("rollout", "--replica", cid, "--terraform-dir", str(self.controller_workspace.source_dir), "--terraform", str(terraform), "--terraform-sha256", terraform_hash, "--plan", str(plan), "--plan-sha256", hashlib.sha256(plan.read_bytes()).hexdigest())
            self.controller_output = self.controller_workspace.output()
        self.controller_mode = "active"
        for domain in self.topology["domains"]:
            self.lifecycle("activate", "--domain", domain["id"])
        self.save()

    def make_handoff(self) -> dict[str, Any]:
        self.save()
        backend = self.config.appliance.backend
        claim_bytes = self._read_backend_claim_version(bucket=backend["bucket"], region=backend["region"], version_id=self.backend_claim_version_id)
        claim = legacy.strict_json_loads(claim_bytes)
        account = self.runner_identity["account_id"]
        roles = {phase: {"arn": f"arn:aws:iam::{account}:role/{self.config.run_id}-{self.invocation_id[:12]}-{phase}", "subject": contract.subject(self.raw["context"], phase), "policy_sha256": "0" * 64} for phase in ("observe", "quiesce")}
        cleanup_policy = self.raw_aws.json(["iam", "get-role-policy", "--role-name", self.raw["cleanup_role_arn"].split("/")[-1], "--policy-name", "acceptance-boundary"])["PolicyDocument"]
        if isinstance(cleanup_policy, str):
            cleanup_policy = legacy.strict_json_loads(urllib.parse.unquote(cleanup_policy))
        roles["cleanup"] = {"arn": self.raw["cleanup_role_arn"], "subject": contract.subject(self.raw["context"], "cleanup"), "policy_sha256": contract.digest(cleanup_policy)}
        actors = []
        for actor in self._instance_actors():
            expected = self._expected_instance_actor(actor["instance_id"], actor["region"])
            expected["expected_tags"]["EnvelopeInvocation"] = self.invocation_id
            actors.append(expected)
        artifacts = [{"component": "envelope", "revision": self.raw["context"]["revision"], "source_dirty": False, "sha256": self.packet_artifact["sha256"]}]
        artifacts += [{"component": component, "revision": self.artifact_entry(component)["vcs_revision"], "source_dirty": self.artifact_entry(component)["vcs_modified"], "sha256": self.artifact_entry(component)["sha256"]} for component in ("envelope-controller", "envelope-controller-topology", "envelope-controller-deploy", "envelope-router-attestor")]
        issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        h = {"schema": 1, "kind": "production-controller-handoff", "run_id": self.config.run_id, "invocation_id": self.invocation_id, "context": self.raw["context"], "issued_at": issued.isoformat().replace("+00:00", "Z"), "expires_at": self.config.expires_at,
             "observer_issuance_until": (issued + dt.timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
             "observer_sessions_until": (issued + dt.timedelta(minutes=75)).isoformat().replace("+00:00", "Z"),
             "claim": {"bucket": backend["bucket"], "key": self.backend_claim_key, "region": backend["region"], "version_id": self.backend_claim_version_id, "sha256": hashlib.sha256(claim_bytes).hexdigest()}, "claim_body": claim, "configuration_sha256": self.config.configuration_sha256, "authority_kms_key_arn": backend["kms_key_arn"],
             "topology": self.topology, "topology_identity": self.topology_identity, "actors": actors, "workloads": self.deployment.workloads,
             "controller": {"region": self.config.controller.region, "vpc_id": self.config.controller.vpc_id, "controller_ids": list(self.config.controller.controller_ids), "metrics_port": self.config.controller.metrics_port, "policy_seconds": self.config.controller.policy_seconds, "timeouts": self.config.controller.timeouts, "instances": legacy._output_value(self.controller_output, "controller_instances")},
             "router_nodes": self.router_nodes, "attestation_trust": self.attestation_trust, "dependencies": {"artifacts": artifacts, "lifecycle": self.lifecycle_receipts, "enrollment_verified": True}, "roles": roles,
             "revocation": {"role_arn": self.raw["deployment_role_arn"], "lifecycle_role_arn": legacy._output_value(self.controller_output, "deployment_lifecycle_role_arn"), "subject": self.session.subject, "cutoff": legacy.utc_now(), "policy_name": "envelope-deployment-session-revocation", "trust_sid": "DenyRun" + self.invocation_id[:24], "session_arn": self.session.principal_arn, "session_expires_at": self.session.receipt()["expires_at"]},
             "private_state": self.private_reference, "evidence_store": {**self.raw["artifact_store"], "prefix": f"runs/{self.config.run_id}/evidence/{self.invocation_id}/"}}
        policies = {phase: boundary_policy(h, phase) for phase in ("observe", "quiesce")}
        for phase, policy in policies.items():
            h["roles"][phase]["policy_sha256"] = contract.digest(policy)
        self.workspaces["sessions"].apply({"aws_region": self.config.controller.region, "oidc_provider_arn": self.raw["oidc_provider_arn"], "handoff_json": json.dumps(h), "boundary_policies": {phase: json.dumps(policy) for phase, policy in policies.items()}}, "phase-roles")
        self.save()
        h["private_state"] = self.private_reference
        return contract.validate_handoff(h, now=dt.datetime.now(dt.timezone.utc), context=self.raw["context"])

    def revoke(self, h: Mapping[str, Any]) -> None:
        rev = h["revocation"]
        cleanup_name = h["roles"]["cleanup"]["arn"].split("/")[-1]
        cleanup_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": self.raw["oidc_provider_arn"]}, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": h["roles"]["cleanup"]["subject"]}, "DateLessThan": {"aws:CurrentTime": h["expires_at"]}}}]}
        self.raw_aws.json(["iam", "update-assume-role-policy", "--role-name", cleanup_name, "--policy-document", json.dumps(cleanup_trust)])
        self.raw_aws.json(["iam", "put-role-policy", "--role-name", cleanup_name, "--policy-name", rev["policy_name"], "--policy-document", json.dumps(revocation_policy(h["observer_sessions_until"]))])
        self.raw_aws.json(["iam", "put-role-policy", "--role-name", rev["lifecycle_role_arn"].split("/")[-1], "--policy-name", rev["policy_name"], "--policy-document", json.dumps(frozen_policy())])
        name = rev["role_arn"].split("/")[-1]
        trust = self.raw_aws.json(["iam", "get-role", "--role-name", name])["Role"]["AssumeRolePolicyDocument"]
        if isinstance(trust, str):
            trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
        trust["Statement"].append({"Sid": rev["trust_sid"], "Effect": "Deny", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": self.raw["oidc_provider_arn"]}})
        self.raw_aws.json(["iam", "update-assume-role-policy", "--role-name", name, "--policy-document", json.dumps(trust)])
        self.raw_aws.json(["iam", "put-role-policy", "--role-name", name, "--policy-name", rev["policy_name"], "--policy-document", json.dumps(frozen_policy())])
        denied = 0
        for _ in range(60):
            try:
                self.raw_aws.json(["ec2", "describe-instances", "--instance-ids", h["actors"][0]["instance_id"]], region=h["actors"][0]["region"])
                denied = 0
            except APIError as error:
                if error.code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                    denied += 1
                else:
                    raise
            if denied >= 2:
                return
            self.sleep(1)
        raise contract.Error("deployment session revocation did not become authoritative")

    def deploy(self) -> dict[str, str]:
        self.claim()
        self.prepare()
        bootstrap = self.upload_bootstrap()
        self.prepare_seeds()
        self.deploy_appliance_native(bootstrap)
        self.prepare_controller()
        self.enroll_routers()
        self.initialize_and_rollout()
        h = self.make_handoff()
        legacy.write_private_json(self.run_dir / "handoff.json", h)
        backend = self.config.appliance.backend
        reference = publish_object(self.raw_aws, h, bucket=backend["bucket"], key=f"runs/{self.config.run_id}/handoff/{self.invocation_id}/handoff.json", region=backend["region"], kms=backend["kms_key_arn"], directory=self.run_dir)
        # No AWS publication follows revocation. Job outputs carry only this
        # already immutable reference after the source session is denied.
        self.revoke(h)
        return reference
