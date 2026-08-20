#!/usr/bin/env python3

from __future__ import annotations

import copy
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

    def test_secret_resolver_and_exact_runtime_iam(self):
        user_data = self.files["user_data.tf"]
        self.assertEqual(user_data.count("command:AWS_PAGER="), 2)
        self.assertEqual(user_data.count("--with-decryption"), 2)
        self.assertIn("snat_subnet_routes = false", user_data)
        self.assertIn('netfilter_mode     = "off"', user_data)
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
        self.assertIn("/usr/sbin/sysctl -p /etc/sysctl.d/90-envelope.conf", bootstrap)
        self.assertIn("ProtectKernelTunables=yes", bootstrap)
        self.assertIn("User=envelope", bootstrap)
        self.assertIn("User=root", bootstrap)
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
        self.assertIn('server_side_encryption = "AES256"', artifact)
        self.assertIn("force_destroy = true", artifact)
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
        encoded = "dHNrZXktYXV0aC1maXh0dXJlMTIzNDU2Nzg5"
        next(value for value in secret["planned_values"]["root_module"]["resources"] if value["address"] == "aws_instance.envelope_west")["values"]["user_data_base64"] = encoded
        cases["secret"] = secret
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
        self.assertTrue(PLAN.validate(destructive, "envelope-plan", {"aws_vpc.west"}, AZ_KEYS))
        replacement = copy.deepcopy(self.plan)
        replacement["resource_changes"] = [
            {
                "address": "aws_instance.envelope_west",
                "type": "aws_instance",
                "change": {"actions": ["delete", "create"]},
            }
        ]
        self.assertEqual(
            PLAN.validate(replacement, "envelope-plan", {"aws_instance.envelope_west"}, AZ_KEYS),
            [],
        )

    def test_plan_and_state_fixtures_are_secret_free(self):
        paths = [self.plan_path, ROOT / "testdata/deployment/state-secret-reference.json"]
        self.assertEqual(SCAN.scan(paths), [])


if __name__ == "__main__":
    unittest.main()
