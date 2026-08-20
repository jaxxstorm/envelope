#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TF = ROOT / "example/terraform"
AZ_KEYS = {"west": {"a", "b"}, "east": {"a", "b"}}


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PLAN = load_module("validate_appliance_plan", ROOT / "scripts/validate_appliance_plan.py")
SCAN = load_module("secret_scan", ROOT / "scripts/secret_scan.py")


class TerraformStaticContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {path.name: path.read_text() for path in TF.glob("*.tf")}
        cls.all_tf = "\n".join(cls.files.values())

    def test_no_plaintext_key_dynamic_ami_or_dynamic_az_selection(self):
        self.assertNotIn("tailscale_auth_key", self.all_tf)
        self.assertNotIn("most_recent", self.all_tf)
        self.assertNotIn("aws_availability_zones", self.all_tf)
        self.assertNotIn("lbr-", self.all_tf)
        self.assertNotRegex(self.all_tf, r"for_each\s*=\s*data\.")
        self.assertNotRegex(self.all_tf, r"for_each\s*=\s*\{[^\n]*subnet_id")

    def test_versions_backend_and_lock_are_bounded(self):
        provider = self.files["provider.tf"]
        self.assertIn('required_version = ">= 1.10.1, < 1.11.0"', provider)
        self.assertIn('version = "= 6.33.0"', provider)
        self.assertIn('version = "= 2.3.7"', provider)
        self.assertIn('backend "s3" {}', provider)
        user_data = self.files["user_data.tf"]
        self.assertEqual(user_data.count('source = "./modules/tailscale-cloudinit"'), 2)
        provenance = (TF / "modules/tailscale-cloudinit/PROVENANCE.md").read_text()
        self.assertIn("tailscale/tailscale/cloudinit` release\n`0.0.11", provenance)
        self.assertTrue((TF / "modules/tailscale-cloudinit/SOURCE.sha256").is_file())
        lock = (TF / ".terraform.lock.hcl").read_text()
        self.assertIn('version     = "6.33.0"', lock)
        self.assertIn('version     = "2.3.7"', lock)
        self.assertGreaterEqual(lock.count('"h1:'), 6)
        self.assertIn("!example/terraform/.terraform.lock.hcl", (ROOT / ".gitignore").read_text())

    def test_target_attachments_use_direct_regional_instance_ids(self):
        gwlb = self.files["gwlb.tf"]
        self.assertEqual(gwlb.count("target_id        = aws_instance.envelope_west.id"), 1)
        self.assertEqual(gwlb.count("target_id        = aws_instance.envelope_east.id"), 1)
        self.assertNotRegex(gwlb, r"target_id\s*=\s*\".*aws_instance\.envelope_(west|east)\.id")

    def test_secret_resolver_and_exact_runtime_iam(self):
        user_data = self.files["user_data.tf"]
        self.assertEqual(user_data.count("command:AWS_PAGER="), 2)
        self.assertEqual(user_data.count("--with-decryption"), 2)
        self.assertIn("snat_subnet_routes = false", user_data)
        self.assertIn('netfilter_mode     = "off"', user_data)
        self.assertEqual(len(re.findall(r"\bgzip\s*=\s*true", user_data)), 2)
        module = (TF / "modules/tailscale-cloudinit/main.tf").read_text()
        self.assertRegex(module, r"gzip\s*=\s*var\.gzip")
        self.assertIn("ec2_user_data_raw_limit_bytes", user_data)
        self.assertIn("ec2_user_data_base64_limit_bytes", user_data)
        iam = self.files["iam.tf"]
        for action in ('"ssm:GetParameter"', '"kms:Decrypt"', '"s3:GetObject"'):
            self.assertIn(action, iam)
        self.assertIn("appliance_runtime_policy_west", iam)
        self.assertIn("appliance_runtime_policy_east", iam)
        self.assertIn('"kms:EncryptionContext:PARAMETER_ARN"', iam)
        self.assertIn('"kms:ViaService"', iam)
        self.assertEqual(iam.count('Action   = ["ssm:GetParameter"]'), 2)
        self.assertNotIn('"ssm:GetParameters"', iam)
        self.assertNotIn('"ssm:GetParametersByPath"', iam)
        ec2 = self.files["ec2.tf"]
        self.assertIn("aws_iam_instance_profile.appliance_west.name", ec2)
        self.assertIn("aws_iam_instance_profile.appliance_east.name", ec2)

    def test_static_graph_route_domains_single_owner_and_cost(self):
        gwlb = self.files["gwlb.tf"]
        self.assertIn("enable_cross_zone_load_balancing = true", gwlb)
        self.assertEqual(gwlb.count('resource "aws_lb_target_group_attachment"'), 2)
        self.assertIn("local.west_remote_workload_routes", gwlb)
        self.assertIn("destination_cidr_block = each.value.cidr", gwlb)
        self.assertNotIn("destination_cidr_block = var.east_vpc_cidr", gwlb)
        self.assertNotIn("destination_cidr_block = var.west_vpc_cidr", gwlb)
        vpc = self.files["vpc.tf"]
        for role in ("workload", "gwlbe", "gwlb", "appliance"):
            self.assertIn(f'aws_route_table" "{role}_west', vpc)
            self.assertIn(f'aws_route_table" "{role}_east', vpc)
        variables = self.files["variables.tf"]
        self.assertIn("appliance_target_count == 1", variables)
        ec2 = self.files["ec2.tf"]
        self.assertIn("nat_gateways", ec2)
        self.assertIn("estimated_fixed_hourly_usd", ec2)
        self.assertIn("ExpiresAt", variables)

    def test_service_preflight_and_pinned_tailscale_supply_chain(self):
        bootstrap = (TF / "cloud-init/bootstrap.sh.tftpl").read_text()
        preflight = bootstrap.split("<<'PREFLIGHT'", 1)[1].split("\nPREFLIGHT", 1)[0]
        self.assertNotIn("envelope-host-network\"", preflight)
        self.assertNotIn("sysctl -q -w", preflight)
        self.assertNotIn("sysctl --system", bootstrap)
        self.assertIn("'net.ipv4.ip_forward=1'", bootstrap)
        self.assertIn("'net.ipv4.conf.default.rp_filter=0'", bootstrap)
        self.assertNotIn("sysctl -p", bootstrap)
        self.assertIn("net.ipv4.conf.default.rp_filter = 0", bootstrap)
        self.assertIn("net.ipv4.conf.*.rp_filter = 0", bootstrap)
        self.assertIn('"net.ipv4.conf.$envelope.rp_filter=0"', bootstrap)
        self.assertIn("RuntimeDirectory=envelope-host-network", bootstrap)
        self.assertIn("RuntimeDirectoryMode=0700", bootstrap)
        self.assertIn("ReadWritePaths=/run/envelope-host-network", bootstrap)
        self.assertIn("ExecStartPre=!/usr/local/sbin/envelope-preflight", bootstrap)
        self.assertIn("ProtectKernelTunables=yes", bootstrap)
        self.assertIn("User=envelope", bootstrap)
        self.assertIn("User=root", bootstrap)
        self.assertIn("for table in raw mangle nat filter security", preflight)
        self.assertIn("raw|nat|security) return 0", preflight)
        self.assertIn("Table does not exist \\(do you need to insmod\\?\\)", preflight)
        self.assertIn('optional_legacy_table "$table"', preflight)
        self.assertIn("detail=%.256s", preflight)
        self.assertIn("unexpected table schema", preflight)
        module = "\n".join(path.read_text() for path in (TF / "modules/tailscale-cloudinit").rglob("*") if path.is_file())
        self.assertNotIn("tailscale.com/install.sh", module)
        self.assertNotIn("TRACK=", module)
        self.assertIn("rpm --checksig", module)
        self.assertIn("additional_parts", module)

    def test_artifact_is_checksum_addressed_encrypted_and_exact(self):
        artifact = self.files["artifact.tf"]
        self.assertIn("source_hash            = var.artifact_sha256", artifact)
        self.assertIn('checksum_algorithm     = "SHA256"', artifact)
        self.assertIn("filesha256(var.artifact_path) == var.artifact_sha256", artifact)
        self.assertIn('sse_algorithm = "AES256"', artifact)
        self.assertIn('blocked_encryption_types = ["SSE-C"]', artifact)
        self.assertIn("bucket_key_enabled       = false", artifact)
        self.assertIn('server_side_encryption = "AES256"', artifact)
        self.assertIn("force_destroy = true", artifact)
        self.assertIn("bucket       = local.artifact_bucket_name", artifact)
        self.assertIn("key          = local.artifact_object_key", artifact)
        iam = self.files["iam.tf"]
        self.assertEqual(iam.count("Resource = [local.artifact_object_arn]"), 2)
        self.assertNotIn("DecryptExactArtifactKey", iam)

    def test_runbook_uses_the_single_config_and_protected_lifecycle_commands(self):
        runbook = (ROOT / "docs/aws-appliance-runbook.md").read_text()
        self.assertNotIn("network.tfvars", runbook)
        self.assertNotIn("tskey-", runbook.lower())
        for command in (
            "metadata-preflight",
            "preflight",
            "prepare",
            "init",
            "plan",
            "apply",
            "verify-no-drift",
            "wait",
            "plan-replacement",
            "cleanup",
            "janitor",
        ):
            self.assertIn(command, runbook)
        self.assertNotIn("terraform -chdir=example/terraform plan", runbook)
        documents = [json.loads(value) for value in re.findall(r"```json\n(.*?)\n```", runbook, re.DOTALL)]
        document = next(value for value in documents if "run_id" in value)
        self.assertEqual(set(document["sites"]), {"west", "east"})
        for site in ("west", "east"):
            self.assertIn("workload_subnet_cidrs", document["sites"][site])
            self.assertIn("gwlb_return_cidrs", document["sites"][site])
        self.assertNotIn("lane_cidrs", document["tailnet"])


class PlanAndSecurityFixtureTest(unittest.TestCase):
    def setUp(self):
        self.plan_path = ROOT / "testdata/deployment/plan-shape.json"
        self.plan = json.loads(self.plan_path.read_text())

    def test_valid_plan_shape_fixture(self):
        self.assertEqual(PLAN.validate(self.plan, "envelope-plan", expected_az_keys=AZ_KEYS), [])

    def test_west_and_east_user_data_are_bounded_gzip_multipart_without_credentials(self):
        resources = self.plan["planned_values"]["root_module"]["resources"]
        for site in ("west", "east"):
            with self.subTest(site=site):
                encoded = next(
                    value
                    for value in resources
                    if value["address"] == f"aws_instance.envelope_{site}"
                )["values"]["user_data_base64"]
                compressed = base64.b64decode(encoded, validate=True)
                mime = gzip.decompress(compressed).decode("utf-8")
                self.assertLessEqual(len(encoded.encode("ascii")), PLAN.EC2_USER_DATA_BASE64_LIMIT_BYTES)
                self.assertLessEqual(len(compressed), PLAN.EC2_USER_DATA_RAW_LIMIT_BYTES)
                self.assertRegex(mime, r"(?im)^Content-Type:\s*multipart/")
                self.assertRegex(mime, r"(?im)^MIME-Version:\s*1\.0\s*$")
                self.assertIn(f"arn:aws:ssm:us-{'west-2' if site == 'west' else 'east-1'}", mime)
                self.assertIn('filename="20-setup-tailscale.sh"', mime)
                self.assertIsNone(PLAN.KEY_PATTERN.search(mime))
                self.assertNotIn("tailscale_auth_key", mime)

    def test_plan_shape_negative_matrix(self):
        cases = {}
        destructive = copy.deepcopy(self.plan)
        destructive["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        cases["destructive"] = destructive
        update = copy.deepcopy(self.plan)
        update["resource_changes"][0]["change"]["actions"] = ["update"]
        cases["unapproved update"] = update
        cross_zone = copy.deepcopy(self.plan)
        next(value for value in cross_zone["planned_values"]["root_module"]["resources"] if value["address"] == "aws_lb.west")["values"]["enable_cross_zone_load_balancing"] = False
        cases["cross zone"] = cross_zone
        secret = copy.deepcopy(self.plan)
        secret_resource = next(
            value
            for value in secret["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_instance.envelope_west"
        )
        mime = gzip.decompress(base64.b64decode(secret_resource["values"]["user_data_base64"])).decode()
        key_shaped_fixture = "tskey-" + "auth-fixture123456789"
        secret_resource["values"]["user_data_base64"] = base64.b64encode(
            gzip.compress((mime + f"\n{key_shaped_fixture}\n").encode(), mtime=0)
        ).decode()
        cases["secret"] = secret
        oversized = copy.deepcopy(self.plan)
        incompressible = b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(600))
        oversized_data = base64.b64encode(gzip.compress(incompressible, mtime=0)).decode()
        next(
            value
            for value in oversized["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_instance.envelope_west"
        )["values"]["user_data_base64"] = oversized_data
        cases["oversized user data"] = oversized
        incomplete = copy.deepcopy(self.plan)
        incomplete["planned_values"]["root_module"]["resources"] = [
            value
            for value in incomplete["planned_values"]["root_module"]["resources"]
            if value["address"] != 'aws_subnet.gwlb_west["b"]'
        ]
        cases["incomplete resource set"] = incomplete
        broad_route = copy.deepcopy(self.plan)
        next(
            value
            for value in broad_route["planned_values"]["root_module"]["resources"]
            if value["address"].startswith("aws_route.workload_to_remote_west")
        )["values"]["destination_cidr_block"] = "172.17.0.0/16"
        cases["entire remote VPC route"] = broad_route
        shared_resolver = copy.deepcopy(self.plan)
        west_data = next(
            value
            for value in shared_resolver["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_instance.envelope_west"
        )["values"]["user_data_base64"]
        next(
            value
            for value in shared_resolver["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_instance.envelope_east"
        )["values"]["user_data_base64"] = west_data
        cases["shared regional resolver"] = shared_resolver
        cross_site_iam = copy.deepcopy(self.plan)
        policy_resource = next(
            value
            for value in cross_site_iam["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_iam_role_policy.appliance_runtime_west"
        )
        policy_resource["values"]["policy"] += "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-plan/tailscale-auth"
        cases["cross-site IAM"] = cross_site_iam
        unknown_address = copy.deepcopy(self.plan)
        next(
            value
            for value in unknown_address["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_vpc.west"
        )["address"] = "aws_vpc.unreviewed"
        cases["unknown address with unchanged counts"] = unknown_address
        swapped_types = copy.deepcopy(self.plan)
        west_vpc = next(
            value
            for value in swapped_types["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_vpc.west"
        )
        west_igw = next(
            value
            for value in swapped_types["planned_values"]["root_module"]["resources"]
            if value["address"] == "aws_internet_gateway.west"
        )
        west_vpc["type"], west_igw["type"] = west_igw["type"], west_vpc["type"]
        cases["swapped address types with unchanged counts"] = swapped_types
        unknown_change = copy.deepcopy(self.plan)
        unknown_change["resource_changes"].append(
            {
                "address": "aws_kms_key.unreviewed",
                "type": "aws_kms_key",
                "change": {"actions": ["create"]},
            }
        )
        cases["unknown resource change"] = unknown_change
        for name, candidate in cases.items():
            with self.subTest(name=name):
                self.assertTrue(PLAN.validate(candidate, "envelope-plan", expected_az_keys=AZ_KEYS))
        secret_errors = PLAN.validate(secret, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("plaintext Tailscale credential" in error for error in secret_errors))
        oversized_errors = PLAN.validate(oversized, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("base64 user data" in error for error in oversized_errors))
        self.assertTrue(any("raw user data" in error for error in oversized_errors))
        self.assertTrue(PLAN.validate(destructive, "envelope-plan", {"aws_vpc.west"}, AZ_KEYS))
        replacement = copy.deepcopy(self.plan)
        target_group_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/fixture"
        next(
            resource
            for resource in replacement["planned_values"]["root_module"]["resources"]
            if resource["address"] == "aws_lb_target_group.west"
        )["values"] = {"arn": target_group_arn, "region": "us-west-2"}
        replacement["configuration"] = {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lb_target_group_attachment.west",
                        "mode": "managed",
                        "type": "aws_lb_target_group_attachment",
                        "expressions": {
                            "target_group_arn": {
                                "references": ["aws_lb_target_group.west.arn", "aws_lb_target_group.west"]
                            },
                            "target_id": {
                                "references": ["aws_instance.envelope_west.id", "aws_instance.envelope_west"]
                            },
                        },
                    }
                ]
            }
        }
        replacement["resource_changes"] = [
            {
                "address": "aws_instance.envelope_west",
                "type": "aws_instance",
                "action_reason": "replace_by_request",
                "change": {"actions": ["delete", "create"], "before": {"id": "i-old-west"}},
            },
            {
                "address": "aws_lb_target_group_attachment.west",
                "type": "aws_lb_target_group_attachment",
                "action_reason": "replace_because_cannot_update",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {
                        "availability_zone": None,
                        "id": "attachment-old",
                        "port": None,
                        "quic_server_id": None,
                        "region": "us-west-2",
                        "target_group_arn": target_group_arn,
                        "target_id": "i-old-west",
                    },
                    "after": {
                        "availability_zone": None,
                        "port": None,
                        "quic_server_id": None,
                        "region": "us-west-2",
                        "target_group_arn": target_group_arn,
                    },
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "after_unknown": {"id": True, "target_id": True},
                    "replace_paths": [["target_id"]],
                },
            },
        ]
        self.assertEqual(
            PLAN.validate(replacement, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS),
            [],
        )
        missing_dependency = copy.deepcopy(replacement)
        missing_dependency["resource_changes"] = missing_dependency["resource_changes"][:1]
        self.assertTrue(PLAN.validate(missing_dependency, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))
        mutated_dependency = copy.deepcopy(replacement)
        foreign_arn = target_group_arn.replace("targetgroup/west", "targetgroup/foreign")
        mutated_dependency["resource_changes"][1]["change"]["before"]["target_group_arn"] = foreign_arn
        mutated_dependency["resource_changes"][1]["change"]["after"]["target_group_arn"] = foreign_arn
        self.assertTrue(PLAN.validate(mutated_dependency, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))
        missing_identity = copy.deepcopy(replacement)
        del missing_identity["resource_changes"][0]["change"]["before"]["id"]
        del missing_identity["resource_changes"][1]["change"]["before"]["target_id"]
        self.assertTrue(PLAN.validate(missing_identity, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))
        create_before_destroy = copy.deepcopy(replacement)
        create_before_destroy["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
        create_before_destroy["resource_changes"][1]["change"]["actions"] = ["create", "delete"]
        self.assertTrue(PLAN.validate(create_before_destroy, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))
        wrong_reference = copy.deepcopy(replacement)
        wrong_reference["configuration"]["root_module"]["resources"][0]["expressions"]["target_id"]["references"] = [
            "aws_instance.envelope_west.private_ip",
            "aws_instance.envelope_west",
        ]
        self.assertTrue(PLAN.validate(wrong_reference, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))
        unrelated_create = copy.deepcopy(replacement)
        unrelated_create["resource_changes"].append(
            {
                "address": "aws_security_group.test_west",
                "type": "aws_security_group",
                "change": {"actions": ["create"]},
            }
        )
        self.assertTrue(PLAN.validate(unrelated_create, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS))

    def test_plan_and_state_fixtures_are_secret_free(self):
        paths = [self.plan_path, ROOT / "testdata/deployment/state-secret-reference.json"]
        self.assertEqual(SCAN.scan(paths), [])


if __name__ == "__main__":
    unittest.main()
