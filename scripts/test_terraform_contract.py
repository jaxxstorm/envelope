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
        for site, other in (("west", "east"), ("east", "west")):
            self.assertEqual(gwlb.count(f'resource "aws_route" "initiator_to_responder_{site}"'), 1)
            self.assertEqual(gwlb.count(f'resource "aws_route" "responder_return_{site}"'), 1)
            self.assertIn(f"aws_route_table.workload_{site}[local.{site}_initiator_az_key].id", gwlb)
            self.assertIn(f"aws_vpc_endpoint.{site}[local.{site}_initiator_az_key].id", gwlb)
            self.assertIn(f"destination_cidr_block = local.{other}_responder_cidr", gwlb)
            self.assertIn(f"aws_route_table.workload_{site}[local.{site}_responder_az_key].id", gwlb)
            self.assertIn(f"destination_cidr_block = local.{other}_initiator_cidr", gwlb)
            self.assertIn(f"aws_instance.envelope_{site}.primary_network_interface_id", gwlb)
        self.assertEqual(gwlb.count('resource "aws_route"'), 4)
        self.assertIn("for_each = toset([local.west_initiator_az_key])", gwlb)
        self.assertIn("for_each = toset([local.east_initiator_az_key])", gwlb)
        self.assertNotIn("workload_to_remote", gwlb)
        self.assertNotIn("destination_cidr_block = var.east_vpc_cidr", gwlb)
        self.assertNotIn("destination_cidr_block = var.west_vpc_cidr", gwlb)
        vpc = self.files["vpc.tf"]
        for role in ("workload", "gwlbe", "gwlb", "appliance"):
            self.assertIn(f'aws_route_table" "{role}_west', vpc)
            self.assertIn(f'aws_route_table" "{role}_east', vpc)
        variables = self.files["variables.tf"]
        self.assertIn("appliance_target_count == 1", variables)
        ec2 = self.files["ec2.tf"]
        self.assertIn("for_each = local.west_workloads", ec2)
        self.assertIn("for_each = local.east_workloads", ec2)
        self.assertIn('output "workload_instances"', ec2)
        self.assertIn('profile                    = "directional-lane-acceptance"', ec2)
        self.assertIn("workload_instances     = 4", ec2)
        self.assertIn("nat_gateways", ec2)
        self.assertIn("estimated_fixed_hourly_usd", ec2)
        self.assertIn("ExpiresAt", variables)

    def test_flow_logs_nacls_and_workload_bootstrap_are_exact(self):
        vpc = self.files["vpc.tf"]
        self.assertEqual(vpc.count('resource "aws_network_acl" "appliance_'), 2)
        self.assertEqual(vpc.count('resource "aws_cloudwatch_log_group" "flow_'), 2)
        self.assertEqual(vpc.count('resource "aws_flow_log"'), 2)
        self.assertEqual(vpc.count("retention_in_days = 7"), 2)
        self.assertEqual(vpc.count('traffic_type             = "ALL"'), 2)
        self.assertEqual(vpc.count('log_destination_type     = "cloud-watch-logs"'), 2)
        self.assertEqual(vpc.count("max_aggregation_interval = 60"), 2)
        self.assertNotIn("kms_key_id", vpc)
        for field in PLAN.FLOW_LOG_FIELDS:
            self.assertIn(f'"$${{{field}}}"', vpc)
        for site in ("west", "east"):
            self.assertIn(f"subnet_ids = [aws_subnet.appliance_{site}.id]", vpc)
            self.assertIn(f"cidr_block = local.{site}_initiator_cidr", vpc)
            self.assertEqual(vpc.count(f"cidr_block = local.{site}_responder_cidr"), 2)
        self.assertEqual(vpc.count('rule_no    = 100'), 4)
        self.assertEqual(vpc.count('rule_no    = 110'), 2)
        self.assertEqual(vpc.count('rule_no    = 200'), 4)

        iam = self.files["iam.tf"]
        self.assertIn('Principal = { Service = "vpc-flow-logs.amazonaws.com" }', iam)
        self.assertIn('"aws:SourceArn" = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"', iam)
        self.assertIn('"aws:SourceAccount" = data.aws_caller_identity.current.account_id', iam)
        self.assertEqual(iam.count("aws_cloudwatch_log_group.flow_west.arn"), 2)
        self.assertEqual(iam.count("aws_cloudwatch_log_group.flow_east.arn"), 2)
        self.assertIn('Action = ["logs:CreateLogGroup"]', iam)
        self.assertIn('"logs:CreateLogStream"', iam)
        self.assertIn('"logs:PutLogEvents"', iam)

        ec2 = self.files["ec2.tf"]
        self.assertIn('workload_bootstrap = templatefile("${path.module}/cloud-init/workload.sh.tftpl"', ec2)
        self.assertIn('agent_base64 = base64encode(file("${path.module}/cloud-init/envelope-e2e-agent.py"))', ec2)
        self.assertIn("workload_user_data              = base64gzip(local.workload_bootstrap)", ec2)
        self.assertEqual(ec2.count("user_data_base64            = local.workload_user_data"), 2)
        self.assertEqual(ec2.count('each.key == "responder" ? local.workload_probe_ingress : {}'), 2)
        workload_bootstrap = (TF / "cloud-init/workload.sh.tftpl").read_text()
        for package in (
            "amazon-ssm-agent",
            "coreutils",
            "curl",
            "grep",
            "gzip",
            "iperf3",
            "iproute",
            "iputils",
            "jq",
            "procps-ng",
            "python3",
            "tcpdump",
        ):
            self.assertIn(package, workload_bootstrap)
        self.assertEqual(workload_bootstrap.count("KillMode=control-group"), 2)
        self.assertEqual(workload_bootstrap.count("KillSignal=SIGTERM"), 2)
        self.assertEqual(workload_bootstrap.count("TimeoutStopSec=5"), 2)
        self.assertNotIn("RefuseManualStop=true", workload_bootstrap)
        self.assertIn('output "e2e_load_profile"', ec2)
        self.assertIn("value       = var.e2e_load_profile", ec2)
        variables = self.files["variables.tf"]
        self.assertIn('variable "e2e_load_profile"', variables)
        self.assertIn("safe_inner_mtu == 1280", variables)
        self.assertIn("maximum_tcp_mss <= var.e2e_load_profile.safe_inner_mtu - 40", variables)
        for field in PLAN.E2E_LOAD_PROFILE_FIELDS:
            self.assertIn(field, variables)

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

    def resource(self, plan, address):
        return next(
            resource
            for resource in plan["planned_values"]["root_module"]["resources"]
            if resource["address"] == address
        )

    def configured_resource(self, plan, address):
        return next(
            resource
            for resource in plan["configuration"]["root_module"]["resources"]
            if resource["address"] == address
        )

    def workload_user_data(self, suffix=""):
        bootstrap = """#!/usr/bin/env bash
dnf install -y amazon-ssm-agent coreutils curl grep gzip iperf3 iproute iputils jq procps-ng python3 tcpdump
systemctl enable --now amazon-ssm-agent
mv -f "$agent_tmp" /opt/envelope/e2e-agent
envelope-e2e-agent-tcp.service
envelope-e2e-agent-udp.service
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=5
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=5
""" + suffix
        return base64.b64encode(gzip.compress(bootstrap.encode(), mtime=0)).decode()

    def replacement_plan(self, site="west", route_action=None):
        plan = copy.deepcopy(self.plan)
        profile_change = plan["output_changes"]["e2e_load_profile"]
        profile_change["actions"] = ["no-op"]
        profile_change["before"] = copy.deepcopy(profile_change["after"])
        region = "us-west-2" if site == "west" else "us-east-1"
        instance_id = f"i-envelope-{site}"
        eni_id = f"eni-envelope-{site}"
        target_group_arn = self.resource(plan, f"aws_lb_target_group.{site}")["values"]["arn"]
        changes = [
            {
                "address": f"aws_instance.envelope_{site}",
                "type": "aws_instance",
                "action_reason": "replace_by_request",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"id": instance_id, "primary_network_interface_id": eni_id},
                },
            },
            {
                "address": f"aws_lb_target_group_attachment.{site}",
                "type": "aws_lb_target_group_attachment",
                "action_reason": "replace_because_cannot_update",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {
                        "availability_zone": None,
                        "id": f"attachment-{site}-old",
                        "port": None,
                        "quic_server_id": None,
                        "region": region,
                        "target_group_arn": target_group_arn,
                        "target_id": instance_id,
                    },
                    "after": {
                        "availability_zone": None,
                        "port": None,
                        "quic_server_id": None,
                        "region": region,
                        "target_group_arn": target_group_arn,
                    },
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "after_unknown": {"id": True, "target_id": True},
                    "replace_paths": [["target_id"]],
                },
            },
        ]
        if route_action:
            route = self.resource(plan, f"aws_route.responder_return_{site}")["values"]
            before = {
                "id": route["id"],
                "region": route["region"],
                "route_table_id": route["route_table_id"],
                "destination_cidr_block": route["destination_cidr_block"],
                "network_interface_id": eni_id,
            }
            after = {key: value for key, value in before.items() if key != "network_interface_id"}
            change = {
                "actions": ["update"] if route_action == "update" else ["delete", "create"],
                "before": before,
                "after": after,
                "before_sensitive": {},
                "after_sensitive": {},
                "after_unknown": {"network_interface_id": True},
                "replace_paths": [],
            }
            route_change = {
                "address": f"aws_route.responder_return_{site}",
                "type": "aws_route",
                "change": change,
            }
            if route_action == "replace":
                route_change["action_reason"] = "replace_because_cannot_update"
                change["after"].pop("id")
                change["after_unknown"].update({"id": True, "origin": True, "state": True})
                change["replace_paths"] = [["network_interface_id"]]
            changes.append(route_change)
        plan["resource_changes"] = changes
        return plan

    def test_valid_plan_shape_fixture(self):
        self.assertEqual(PLAN.validate(self.plan, "envelope-plan", expected_az_keys=AZ_KEYS), [])

    def test_directional_fixture_has_exact_role_and_route_shape(self):
        resources = self.plan["planned_values"]["root_module"]["resources"]
        addresses = {resource["address"] for resource in resources}
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_instance"]), 6)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_security_group"]), 6)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_route"]), 12)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_vpc_endpoint"]), 2)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_network_acl"]), 2)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_flow_log"]), 2)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_cloudwatch_log_group"]), 2)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_iam_role"]), 5)
        self.assertEqual(len([resource for resource in resources if resource["type"] == "aws_iam_role_policy"]), 5)
        self.assertEqual(
            addresses
            & {
                f'aws_instance.workload_{site}["{role}"]'
                for site in ("west", "east")
                for role in ("initiator", "responder")
            },
            {
                f'aws_instance.workload_{site}["{role}"]'
                for site in ("west", "east")
                for role in ("initiator", "responder")
            },
        )
        self.assertEqual(
            {
                resource["address"]
                for resource in resources
                if resource["type"] == "aws_route"
                and resource["name"] in {
                    "initiator_to_responder_west",
                    "initiator_to_responder_east",
                    "responder_return_west",
                    "responder_return_east",
                }
            },
            {
                "aws_route.initiator_to_responder_west",
                "aws_route.initiator_to_responder_east",
                "aws_route.responder_return_west",
                "aws_route.responder_return_east",
            },
        )
        workloads = self.plan["planned_values"]["outputs"]["workload_instances"]["value"]
        self.assertEqual(set(workloads), {"west", "east"})
        self.assertTrue(all(set(workloads[site]) == {"initiator", "responder"} for site in workloads))
        cost = self.plan["planned_values"]["outputs"]["cost_profile"]["value"]
        self.assertEqual(cost["profile"], "directional-lane-acceptance")
        self.assertEqual(cost["resource_counts"]["workload_instances"], 4)
        self.assertEqual(cost["resource_counts"]["gwlbe_endpoints"], 2)
        self.assertEqual(cost["resource_counts"]["network_acls"], 2)
        self.assertEqual(cost["resource_counts"]["vpc_flow_logs"], 2)
        self.assertEqual(cost["resource_counts"]["cloudwatch_log_groups"], 2)
        self.assertEqual(cost["resource_counts"]["flow_log_iam_roles"], 1)
        self.assertEqual(
            set(cost["resource_counts"]),
            {
                "vpcs",
                "nat_gateways",
                "elastic_ips",
                "gateway_load_balancers",
                "gwlbe_endpoints",
                "semantic_lane_routes",
                "appliance_instances",
                "workload_instances",
                "artifact_buckets",
                "network_acls",
                "vpc_flow_logs",
                "cloudwatch_log_groups",
                "flow_log_iam_roles",
                "regional_targets",
            },
        )
        profile_output = self.plan["planned_values"]["outputs"]["e2e_load_profile"]
        profile = profile_output["value"]
        self.assertIs(profile_output["sensitive"], False)
        self.assertEqual(set(profile), PLAN.E2E_LOAD_PROFILE_FIELDS)
        self.assertEqual(profile, self.plan["variables"]["e2e_load_profile"]["value"])
        self.assertEqual(profile, self.plan["output_changes"]["e2e_load_profile"]["after"])

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

    def test_workload_user_data_is_computed_sensitive_and_scrubbed_before_retention(self):
        retained = copy.deepcopy(self.plan)
        for site in ("west", "east"):
            configuration = self.configured_resource(retained, f"aws_instance.workload_{site}")
            self.assertEqual(
                configuration["expressions"]["user_data_base64"]["references"],
                ["local.workload_user_data"],
            )
            for role in ("initiator", "responder"):
                resource = self.resource(retained, f'aws_instance.workload_{site}["{role}"]')
                self.assertNotIn("user_data_base64", resource["values"])
                self.assertIs(resource["sensitive_values"]["user_data_base64"], True)

        raw = copy.deepcopy(self.plan)
        user_data = self.workload_user_data()
        for site in ("west", "east"):
            for role in ("initiator", "responder"):
                self.resource(raw, f'aws_instance.workload_{site}["{role}"]')["values"][
                    "user_data_base64"
                ] = user_data
        raw["resource_changes"].append(
            {
                "address": 'aws_instance.workload_west["initiator"]',
                "type": "aws_instance",
                "change": {
                    "actions": ["no-op"],
                    "before": {"user_data_base64": user_data},
                    "after": {"user_data_base64": user_data},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        )
        self.assertEqual(PLAN.validate(raw, "envelope-plan", expected_az_keys=AZ_KEYS), [])
        for site in ("west", "east"):
            for role in ("initiator", "responder"):
                resource = self.resource(raw, f'aws_instance.workload_{site}["{role}"]')
                self.assertNotIn("user_data_base64", resource["values"])
                self.assertIs(resource["sensitive_values"]["user_data_base64"], True)
        workload_change = raw["resource_changes"][-1]["change"]
        self.assertNotIn("user_data_base64", workload_change["before"])
        self.assertNotIn("user_data_base64", workload_change["after"])
        self.assertIs(workload_change["before_sensitive"]["user_data_base64"], True)
        self.assertIs(workload_change["after_sensitive"]["user_data_base64"], True)

    def test_plan_shape_negative_matrix(self):
        cases = {}
        destructive = copy.deepcopy(self.plan)
        destructive["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        cases["destructive"] = destructive
        update = copy.deepcopy(self.plan)
        update["resource_changes"][0]["change"]["actions"] = ["update"]
        cases["unapproved update"] = update
        cross_zone = copy.deepcopy(self.plan)
        self.resource(cross_zone, "aws_lb.west")["values"]["enable_cross_zone_load_balancing"] = False
        cases["cross zone"] = cross_zone
        secret = copy.deepcopy(self.plan)
        secret_resource = self.resource(secret, "aws_instance.envelope_west")
        mime = gzip.decompress(base64.b64decode(secret_resource["values"]["user_data_base64"])).decode()
        key_shaped_fixture = "tskey-" + "auth-fixture123456789"
        secret_resource["values"]["user_data_base64"] = base64.b64encode(
            gzip.compress((mime + f"\n{key_shaped_fixture}\n").encode(), mtime=0)
        ).decode()
        cases["secret"] = secret
        oversized = copy.deepcopy(self.plan)
        incompressible = b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(600))
        oversized_data = base64.b64encode(gzip.compress(incompressible, mtime=0)).decode()
        self.resource(oversized, "aws_instance.envelope_west")["values"]["user_data_base64"] = oversized_data
        cases["oversized user data"] = oversized
        incomplete = copy.deepcopy(self.plan)
        incomplete["planned_values"]["root_module"]["resources"] = [
            value
            for value in incomplete["planned_values"]["root_module"]["resources"]
            if value["address"] != 'aws_subnet.gwlb_west["b"]'
        ]
        cases["incomplete resource set"] = incomplete
        broad_route = copy.deepcopy(self.plan)
        self.resource(broad_route, "aws_route.initiator_to_responder_west")["values"][
            "destination_cidr_block"
        ] = "172.17.0.0/16"
        cases["entire remote VPC route"] = broad_route
        extra_route = copy.deepcopy(self.plan)
        self.resource(extra_route, "aws_route.responder_return_east")["address"] = "aws_route.unreviewed_east"
        cases["extra route with unchanged count"] = extra_route
        inline_route = copy.deepcopy(self.plan)
        self.resource(inline_route, 'aws_route_table.workload_west["a"]')["values"]["route"] = [
            {"cidr_block": "0.0.0.0/0", "gateway_id": "igw-unreviewed"}
        ]
        cases["extra inline route"] = inline_route
        old_workload = copy.deepcopy(self.plan)
        self.resource(old_workload, 'aws_instance.workload_west["initiator"]')["address"] = "aws_instance.test_west"
        cases["old non-role workload address"] = old_workload
        wrong_route_table = copy.deepcopy(self.plan)
        self.resource(wrong_route_table, "aws_route.initiator_to_responder_west")["values"][
            "route_table_id"
        ] = "rtb-workload-west-b"
        cases["initiator route uses responder route table"] = wrong_route_table
        wrong_endpoint = copy.deepcopy(self.plan)
        self.resource(wrong_endpoint, "aws_route.initiator_to_responder_west")["values"][
            "vpc_endpoint_id"
        ] = "vpce-east-a"
        cases["initiator route uses cross-site endpoint"] = wrong_endpoint
        wrong_eni = copy.deepcopy(self.plan)
        self.resource(wrong_eni, "aws_route.responder_return_west")["values"][
            "network_interface_id"
        ] = "eni-envelope-east"
        cases["return route uses cross-site appliance ENI"] = wrong_eni
        extra_target = copy.deepcopy(self.plan)
        self.resource(extra_target, "aws_route.responder_return_west")["values"]["nat_gateway_id"] = "nat-extra"
        cases["semantic route has an extra target"] = extra_target
        wrong_endpoint_subnet = copy.deepcopy(self.plan)
        self.resource(wrong_endpoint_subnet, 'aws_vpc_endpoint.west["a"]')["values"]["subnet_ids"] = [
            "subnet-gwlbe-west-b"
        ]
        cases["endpoint uses a different AZ subnet"] = wrong_endpoint_subnet
        extra_responder_endpoint = copy.deepcopy(self.plan)
        endpoint = copy.deepcopy(self.resource(extra_responder_endpoint, 'aws_vpc_endpoint.west["a"]'))
        endpoint["address"] = 'aws_vpc_endpoint.west["b"]'
        endpoint["index"] = "b"
        endpoint["values"] = {"id": "vpce-west-b", "subnet_ids": ["subnet-gwlbe-west-b"]}
        extra_responder_endpoint["planned_values"]["root_module"]["resources"].append(endpoint)
        cases["extra responder-AZ endpoint"] = extra_responder_endpoint
        wrong_workload_subnet = copy.deepcopy(self.plan)
        self.resource(wrong_workload_subnet, 'aws_instance.workload_west["initiator"]')["values"][
            "subnet_id"
        ] = "subnet-workload-west-b"
        cases["workload uses a different role subnet"] = wrong_workload_subnet
        flat_output = copy.deepcopy(self.plan)
        flat_output["planned_values"]["outputs"]["workload_instances"]["value"] = {
            "west": flat_output["planned_values"]["outputs"]["workload_instances"]["value"]["west"]
        }
        cases["workload output is not nested by both sites"] = flat_output
        wrong_output_route_table = copy.deepcopy(self.plan)
        wrong_output_route_table["planned_values"]["outputs"]["workload_instances"]["value"]["east"][
            "initiator"
        ]["route_table_id"] = "rtb-workload-east-a"
        cases["workload output has wrong route table"] = wrong_output_route_table
        wrong_profile = copy.deepcopy(self.plan)
        wrong_profile["planned_values"]["outputs"]["cost_profile"]["value"]["profile"] = "legacy"
        cases["wrong cost profile"] = wrong_profile
        wrong_workload_cost = copy.deepcopy(self.plan)
        wrong_workload_cost["planned_values"]["outputs"]["cost_profile"]["value"]["resource_counts"][
            "workload_instances"
        ] = 2
        cases["wrong workload cost count"] = wrong_workload_cost
        broad_runtime = copy.deepcopy(self.plan)
        broad_runtime["planned_values"]["outputs"]["envelope_runtime_config"]["value"]["west"][
            "remote_tailnet_cidrs"
        ] = ["172.17.0.0/16", "172.17.1.0/24"]
        cases["runtime contains a broad remote role"] = broad_runtime
        wrong_route_reference = copy.deepcopy(self.plan)
        self.configured_resource(wrong_route_reference, "aws_route.responder_return_west")["expressions"][
            "network_interface_id"
        ]["references"] = ["aws_instance.envelope_east.primary_network_interface_id", "aws_instance.envelope_east"]
        cases["return route configuration has cross-site ENI references"] = wrong_route_reference
        indirect_target = copy.deepcopy(self.plan)
        self.configured_resource(indirect_target, "aws_lb_target_group_attachment.west")["expressions"][
            "target_id"
        ]["references"] = ["local.west_target_id"]
        cases["target attachment is not direct"] = indirect_target
        wrong_attachment = copy.deepcopy(self.plan)
        self.resource(wrong_attachment, "aws_lb_target_group_attachment.west")["values"][
            "target_id"
        ] = "i-envelope-east"
        cases["target attachment points cross-site"] = wrong_attachment
        shared_resolver = copy.deepcopy(self.plan)
        west_data = self.resource(shared_resolver, "aws_instance.envelope_west")["values"]["user_data_base64"]
        self.resource(shared_resolver, "aws_instance.envelope_east")["values"]["user_data_base64"] = west_data
        cases["shared regional resolver"] = shared_resolver
        cross_site_iam = copy.deepcopy(self.plan)
        policy_resource = self.resource(cross_site_iam, "aws_iam_role_policy.appliance_runtime_west")
        policy_resource["values"]["policy"] += "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-plan/tailscale-auth"
        cases["cross-site IAM"] = cross_site_iam
        unknown_address = copy.deepcopy(self.plan)
        self.resource(unknown_address, "aws_vpc.west")["address"] = "aws_vpc.unreviewed"
        cases["unknown address with unchanged counts"] = unknown_address
        swapped_types = copy.deepcopy(self.plan)
        west_vpc = self.resource(swapped_types, "aws_vpc.west")
        west_igw = self.resource(swapped_types, "aws_internet_gateway.west")
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
        broad_errors = PLAN.validate(broad_route, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("broad or incorrect directional destination" in error for error in broad_errors))
        eni_errors = PLAN.validate(wrong_eni, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("responder_return_west target" in error for error in eni_errors))
        self.assertTrue(PLAN.validate(destructive, "envelope-plan", {"aws_vpc.west"}, AZ_KEYS))

    def test_flow_log_nacl_sg_and_cost_negative_matrix(self):
        cases = {}
        wrong_flow_vpc = copy.deepcopy(self.plan)
        self.resource(wrong_flow_vpc, "aws_flow_log.west")["values"]["vpc_id"] = "vpc-east"
        cases["flow log wrong VPC"] = wrong_flow_vpc
        accepted_only = copy.deepcopy(self.plan)
        self.resource(accepted_only, "aws_flow_log.west")["values"]["traffic_type"] = "ACCEPT"
        cases["flow log not ALL"] = accepted_only
        wrong_destination_type = copy.deepcopy(self.plan)
        self.resource(wrong_destination_type, "aws_flow_log.east")["values"]["log_destination_type"] = "s3"
        cases["flow log not CloudWatch"] = wrong_destination_type
        wrong_aggregation = copy.deepcopy(self.plan)
        self.resource(wrong_aggregation, "aws_flow_log.west")["values"]["max_aggregation_interval"] = 600
        cases["flow log aggregation too broad"] = wrong_aggregation
        wrong_format = copy.deepcopy(self.plan)
        self.resource(wrong_format, "aws_flow_log.east")["values"]["log_format"] = PLAN.FLOW_LOG_FORMAT.replace(
            " ${pkt-dstaddr}", ""
        )
        cases["flow log omits packet destination"] = wrong_format
        wrong_flow_group = copy.deepcopy(self.plan)
        self.resource(wrong_flow_group, "aws_flow_log.west")["values"]["log_destination"] = self.resource(
            wrong_flow_group, "aws_cloudwatch_log_group.flow_east"
        )["values"]["arn"]
        cases["flow log uses cross-region group"] = wrong_flow_group
        wrong_flow_role = copy.deepcopy(self.plan)
        self.resource(wrong_flow_role, "aws_flow_log.west")["values"]["iam_role_arn"] = (
            "arn:aws:iam::123456789012:role/foreign"
        )
        cases["flow log uses foreign role"] = wrong_flow_role
        wrong_flow_reference = copy.deepcopy(self.plan)
        self.configured_resource(wrong_flow_reference, "aws_flow_log.west")["expressions"]["log_destination"][
            "references"
        ] = ["aws_cloudwatch_log_group.flow_east.arn", "aws_cloudwatch_log_group.flow_east"]
        cases["flow log group reference is cross-region"] = wrong_flow_reference

        wrong_group_name = copy.deepcopy(self.plan)
        self.resource(wrong_group_name, "aws_cloudwatch_log_group.flow_west")["values"]["name"] = "/aws/vpc-flow-logs/shared"
        cases["log group is not run-scoped"] = wrong_group_name
        wrong_group_region = copy.deepcopy(self.plan)
        self.resource(wrong_group_region, "aws_cloudwatch_log_group.flow_east")["values"]["region"] = "us-west-2"
        cases["log group is cross-region"] = wrong_group_region
        unbounded_retention = copy.deepcopy(self.plan)
        self.resource(unbounded_retention, "aws_cloudwatch_log_group.flow_west")["values"]["retention_in_days"] = 0
        cases["log group retention is unbounded"] = unbounded_retention
        unreviewed_encryption = copy.deepcopy(self.plan)
        self.resource(unreviewed_encryption, "aws_cloudwatch_log_group.flow_west")["values"]["kms_key_id"] = (
            "arn:aws:kms:us-west-2:123456789012:key/foreign"
        )
        cases["log group uses unreviewed encryption key"] = unreviewed_encryption

        wrong_trust = copy.deepcopy(self.plan)
        trust = json.loads(self.resource(wrong_trust, "aws_iam_role.flow_logs")["values"]["assume_role_policy"])
        trust["Statement"][0]["Principal"]["Service"] = "ec2.amazonaws.com"
        self.resource(wrong_trust, "aws_iam_role.flow_logs")["values"]["assume_role_policy"] = json.dumps(trust)
        cases["flow role trusts another service"] = wrong_trust
        broad_source_arn = copy.deepcopy(self.plan)
        trust = json.loads(self.resource(broad_source_arn, "aws_iam_role.flow_logs")["values"]["assume_role_policy"])
        trust["Statement"][0]["Condition"]["ArnLike"]["aws:SourceArn"] = "*"
        self.resource(broad_source_arn, "aws_iam_role.flow_logs")["values"]["assume_role_policy"] = json.dumps(trust)
        cases["flow role source ARN is broad"] = broad_source_arn
        wrong_source_account = copy.deepcopy(self.plan)
        trust = json.loads(self.resource(wrong_source_account, "aws_iam_role.flow_logs")["values"]["assume_role_policy"])
        trust["Statement"][0]["Condition"]["StringEquals"]["aws:SourceAccount"] = "999999999999"
        self.resource(wrong_source_account, "aws_iam_role.flow_logs")["values"]["assume_role_policy"] = json.dumps(trust)
        cases["flow role source account differs"] = wrong_source_account
        broad_delivery = copy.deepcopy(self.plan)
        delivery = json.loads(self.resource(broad_delivery, "aws_iam_role_policy.flow_logs")["values"]["policy"])
        delivery["Statement"][1]["Resource"] = ["*"]
        self.resource(broad_delivery, "aws_iam_role_policy.flow_logs")["values"]["policy"] = json.dumps(delivery)
        cases["flow delivery writes broadly"] = broad_delivery
        extra_delivery_action = copy.deepcopy(self.plan)
        delivery = json.loads(self.resource(extra_delivery_action, "aws_iam_role_policy.flow_logs")["values"]["policy"])
        delivery["Statement"][1]["Action"].append("logs:DeleteLogGroup")
        self.resource(extra_delivery_action, "aws_iam_role_policy.flow_logs")["values"]["policy"] = json.dumps(delivery)
        cases["flow delivery can delete groups"] = extra_delivery_action

        wrong_acl_subnet = copy.deepcopy(self.plan)
        self.resource(wrong_acl_subnet, "aws_network_acl.appliance_west")["values"]["subnet_ids"] = [
            "subnet-workload-west-a"
        ]
        cases["NACL attaches to workload subnet"] = wrong_acl_subnet
        wrong_acl_deny = copy.deepcopy(self.plan)
        self.resource(wrong_acl_deny, "aws_network_acl.appliance_east")["values"]["egress"][0][
            "cidr_block"
        ] = "172.17.0.0/16"
        cases["NACL deny is broad"] = wrong_acl_deny
        wrong_acl_order = copy.deepcopy(self.plan)
        self.resource(wrong_acl_order, "aws_network_acl.appliance_west")["values"]["egress"][0]["rule_no"] = 300
        cases["NACL deny follows allow"] = wrong_acl_order
        wrong_acl_responder = copy.deepcopy(self.plan)
        self.resource(wrong_acl_responder, "aws_network_acl.appliance_west")["values"]["ingress"][0][
            "cidr_block"
        ] = "172.16.0.0/24"
        cases["NACL ingress does not identify responder"] = wrong_acl_responder
        missing_responder_return = copy.deepcopy(self.plan)
        self.resource(missing_responder_return, "aws_network_acl.appliance_east")["values"]["egress"].pop(1)
        cases["NACL omits responder return allow"] = missing_responder_return
        extra_acl_rule = copy.deepcopy(self.plan)
        self.resource(extra_acl_rule, "aws_network_acl.appliance_east")["values"]["ingress"].append(
            {"rule_no": 200, "action": "allow", "protocol": "tcp", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}
        )
        cases["NACL has extra ingress"] = extra_acl_rule

        initiator_ingress = copy.deepcopy(self.plan)
        self.resource(initiator_ingress, 'aws_security_group.workload_west["initiator"]')["values"][
            "ingress"
        ] = copy.deepcopy(
            self.resource(initiator_ingress, 'aws_security_group.workload_west["responder"]')["values"]["ingress"]
        )
        cases["initiator allows application ingress"] = initiator_ingress
        broad_responder = copy.deepcopy(self.plan)
        self.resource(broad_responder, 'aws_security_group.workload_east["responder"]')["values"]["ingress"][0][
            "cidr_blocks"
        ] = ["172.16.0.0/16"]
        cases["responder allows broad CIDR"] = broad_responder
        missing_probe = copy.deepcopy(self.plan)
        self.resource(missing_probe, 'aws_security_group.workload_west["responder"]')["values"]["ingress"].pop()
        cases["responder omits UDP probe"] = missing_probe

        missing_sensitive_marker = copy.deepcopy(self.plan)
        del self.resource(missing_sensitive_marker, 'aws_instance.workload_west["initiator"]')["sensitive_values"]
        cases["workload user data is not marked sensitive"] = missing_sensitive_marker
        direct_workload_data = copy.deepcopy(self.plan)
        self.configured_resource(direct_workload_data, "aws_instance.workload_west")["expressions"][
            "user_data_base64"
        ]["references"] = ["var.workload_user_data"]
        cases["workload user data is not computed locally"] = direct_workload_data
        different_workload_data = copy.deepcopy(self.plan)
        for site in ("west", "east"):
            for role in ("initiator", "responder"):
                self.resource(different_workload_data, f'aws_instance.workload_{site}["{role}"]')["values"][
                    "user_data_base64"
                ] = self.workload_user_data(f"# {site}-{role}\n")
        cases["workload user data differs by role"] = different_workload_data

        for field in ("network_acls", "vpc_flow_logs", "cloudwatch_log_groups", "flow_log_iam_roles"):
            wrong_cost = copy.deepcopy(self.plan)
            wrong_cost["planned_values"]["outputs"]["cost_profile"]["value"]["resource_counts"][field] = 0
            cases[f"cost count {field}"] = wrong_cost
        extra_cost = copy.deepcopy(self.plan)
        extra_cost["planned_values"]["outputs"]["cost_profile"]["value"]["resource_counts"][
            "unreviewed"
        ] = 1
        cases["cost profile has extra count"] = extra_cost

        for name, candidate in cases.items():
            with self.subTest(name=name):
                self.assertTrue(PLAN.validate(candidate, "envelope-plan", expected_az_keys=AZ_KEYS))

        trust_errors = PLAN.validate(wrong_trust, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("Flow Log service ARN" in error for error in trust_errors))
        acl_errors = PLAN.validate(wrong_acl_order, "envelope-plan", expected_az_keys=AZ_KEYS)
        self.assertTrue(any("exact ordered directional rules" in error for error in acl_errors))

    def test_e2e_load_profile_saved_plan_negative_matrix(self):
        cases = {}

        def set_profile_value(plan, field, value):
            plan["planned_values"]["outputs"]["e2e_load_profile"]["value"][field] = value
            plan["variables"]["e2e_load_profile"]["value"][field] = value
            plan["output_changes"]["e2e_load_profile"]["after"][field] = value

        missing = copy.deepcopy(self.plan)
        for profile in (
            missing["planned_values"]["outputs"]["e2e_load_profile"]["value"],
            missing["variables"]["e2e_load_profile"]["value"],
            missing["output_changes"]["e2e_load_profile"]["after"],
        ):
            profile.pop("maximum_p99_latency_ms")
        cases["missing field"] = missing
        extra = copy.deepcopy(self.plan)
        for profile in (
            extra["planned_values"]["outputs"]["e2e_load_profile"]["value"],
            extra["variables"]["e2e_load_profile"]["value"],
            extra["output_changes"]["e2e_load_profile"]["after"],
        ):
            profile["unreviewed"] = 1
        cases["extra field"] = extra
        for field, value in (
            ("profile_id", "invalid profile"),
            ("approved_at", "2026-08-20T10:00:00+00:00"),
            ("approved_at", "2026-08-21T10:00:00Z"),
            ("safe_inner_mtu", 1279),
            ("maximum_tcp_mss", 1241),
            ("sustained_tcp_duration_seconds", 2),
            ("minimum_sustained_tcp_bytes", 0),
            ("iperf_duration_seconds", 121),
            ("concurrent_duration_seconds", 2),
            ("concurrent_tcp_flows", 33),
            ("concurrent_udp_flows", True),
            ("minimum_throughput_mbps", 0),
            ("maximum_udp_loss_percent", 101),
            ("maximum_p99_latency_ms", float("nan")),
        ):
            candidate = copy.deepcopy(self.plan)
            set_profile_value(candidate, field, value)
            cases[f"invalid {field} {value!r}"] = candidate
        sensitive = copy.deepcopy(self.plan)
        sensitive["planned_values"]["outputs"]["e2e_load_profile"]["sensitive"] = True
        cases["sensitive output"] = sensitive
        unknown = copy.deepcopy(self.plan)
        unknown["output_changes"]["e2e_load_profile"]["after_unknown"] = {
            "maximum_p99_latency_ms": True
        }
        cases["unknown output field"] = unknown
        sensitive_change = copy.deepcopy(self.plan)
        sensitive_change["output_changes"]["e2e_load_profile"]["after_sensitive"] = {
            "approved_at": True
        }
        cases["sensitive output change"] = sensitive_change
        mismatched_variable = copy.deepcopy(self.plan)
        mismatched_variable["variables"]["e2e_load_profile"]["value"]["concurrent_tcp_flows"] = 5
        cases["variable/output mismatch"] = mismatched_variable
        tampered_after = copy.deepcopy(self.plan)
        tampered_after["output_changes"]["e2e_load_profile"]["after"]["concurrent_udp_flows"] = 5
        cases["planned output change mismatch"] = tampered_after
        indirect_output = copy.deepcopy(self.plan)
        indirect_output["configuration"]["root_module"]["outputs"]["e2e_load_profile"]["expression"][
            "references"
        ] = ["local.e2e_load_profile"]
        cases["output is not direct variable"] = indirect_output
        for name, candidate in cases.items():
            with self.subTest(name=name):
                errors = PLAN.validate(candidate, "envelope-plan", expected_az_keys=AZ_KEYS)
                self.assertTrue(any("e2e_load_profile" in error for error in errors))

    def test_exactly_two_distinct_az_keys_are_required(self):
        for az_keys in (
            {"west": {"a"}, "east": {"a", "b"}},
            {"west": {"a", "b", "c"}, "east": {"a", "b"}},
            {"west": ["a", "a"], "east": ["a", "b"]},
        ):
            with self.subTest(az_keys=az_keys):
                errors = PLAN.validate(self.plan, "envelope-plan", expected_az_keys=az_keys)
                self.assertTrue(any("exactly two west/east AZ keys" in error for error in errors))

    def test_replacement_accepts_only_direct_attachment_and_optional_same_site_return_route(self):
        for site in ("west", "east"):
            allowed = {f"aws_instance.envelope_{site}"}
            for route_action in (None, "update", "replace"):
                with self.subTest(site=site, route_action=route_action):
                    replacement = self.replacement_plan(site, route_action)
                    self.assertEqual(PLAN.validate(replacement, "envelope-plan", allowed, AZ_KEYS), [])

    def test_replacement_negative_matrix(self):
        allowed = {"aws_instance.envelope_west"}
        replacement = self.replacement_plan("west", "update")
        cases = {}
        missing_attachment = copy.deepcopy(replacement)
        missing_attachment["resource_changes"] = [
            change
            for change in missing_attachment["resource_changes"]
            if change["address"] != "aws_lb_target_group_attachment.west"
        ]
        cases["missing target attachment"] = missing_attachment
        foreign_target_group = copy.deepcopy(replacement)
        foreign_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/foreign/fixture"
        foreign_target_group["resource_changes"][1]["change"]["before"]["target_group_arn"] = foreign_arn
        foreign_target_group["resource_changes"][1]["change"]["after"]["target_group_arn"] = foreign_arn
        cases["foreign target group"] = foreign_target_group
        missing_instance_identity = copy.deepcopy(replacement)
        del missing_instance_identity["resource_changes"][0]["change"]["before"]["id"]
        cases["missing old instance identity"] = missing_instance_identity
        create_before_destroy = copy.deepcopy(replacement)
        create_before_destroy["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
        cases["instance create before destroy"] = create_before_destroy
        wrong_target_reference = copy.deepcopy(replacement)
        self.configured_resource(wrong_target_reference, "aws_lb_target_group_attachment.west")["expressions"][
            "target_id"
        ]["references"] = ["aws_instance.envelope_west.private_ip", "aws_instance.envelope_west"]
        cases["indirect replacement target"] = wrong_target_reference
        unrelated_create = copy.deepcopy(replacement)
        unrelated_create["resource_changes"].append(
            {
                "address": 'aws_security_group.workload_west["initiator"]',
                "type": "aws_security_group",
                "change": {"actions": ["create"]},
            }
        )
        cases["unrelated managed create"] = unrelated_create
        wrong_old_eni = copy.deepcopy(replacement)
        wrong_old_eni["resource_changes"][2]["change"]["before"]["network_interface_id"] = "eni-envelope-east"
        cases["return route old target is not appliance ENI"] = wrong_old_eni
        changed_destination = copy.deepcopy(replacement)
        changed_destination["resource_changes"][2]["change"]["before"]["destination_cidr_block"] = "172.17.0.0/16"
        changed_destination["resource_changes"][2]["change"]["after"]["destination_cidr_block"] = "172.17.0.0/16"
        cases["return route changes destination"] = changed_destination
        missing_route_identity = copy.deepcopy(replacement)
        del missing_route_identity["resource_changes"][2]["change"]["before"]["route_table_id"]
        del missing_route_identity["resource_changes"][2]["change"]["after"]["route_table_id"]
        cases["return route omits route table identity"] = missing_route_identity
        route_extra_target = copy.deepcopy(replacement)
        route_extra_target["resource_changes"][2]["change"]["before"]["nat_gateway_id"] = "nat-extra"
        route_extra_target["resource_changes"][2]["change"]["after"]["nat_gateway_id"] = "nat-extra"
        cases["return route adds another target"] = route_extra_target
        wrong_route_reference = copy.deepcopy(replacement)
        self.configured_resource(wrong_route_reference, "aws_route.responder_return_west")["expressions"][
            "network_interface_id"
        ]["references"] = ["aws_instance.envelope_east.primary_network_interface_id", "aws_instance.envelope_east"]
        cases["return route references another appliance"] = wrong_route_reference
        unrelated_unknown = copy.deepcopy(replacement)
        unrelated_unknown["resource_changes"][2]["change"]["after_unknown"]["nat_gateway_id"] = True
        cases["return route has unrelated unknown target"] = unrelated_unknown
        wrong_replace_path = self.replacement_plan("west", "replace")
        wrong_replace_path["resource_changes"][2]["change"]["replace_paths"] = [["route_table_id"]]
        cases["return route replaces for another field"] = wrong_replace_path
        create_before_destroy_route = self.replacement_plan("west", "replace")
        create_before_destroy_route["resource_changes"][2]["change"]["actions"] = ["create", "delete"]
        cases["return route create before destroy"] = create_before_destroy_route
        opposite_route = self.replacement_plan("west")
        opposite_route["resource_changes"].append(self.replacement_plan("east", "update")["resource_changes"][2])
        cases["opposite-site return route changes"] = opposite_route
        initiator_route = copy.deepcopy(replacement)
        initiator_route["resource_changes"][2]["address"] = "aws_route.initiator_to_responder_west"
        cases["initiator route changes"] = initiator_route
        duplicate_change = copy.deepcopy(replacement)
        duplicate_change["resource_changes"].append(copy.deepcopy(duplicate_change["resource_changes"][1]))
        cases["duplicate dependency change"] = duplicate_change
        for address, resource_type in (
            ("aws_flow_log.west", "aws_flow_log"),
            ("aws_cloudwatch_log_group.flow_west", "aws_cloudwatch_log_group"),
            ("aws_network_acl.appliance_west", "aws_network_acl"),
            ("aws_iam_role.flow_logs", "aws_iam_role"),
            ('aws_security_group.workload_west["responder"]', "aws_security_group"),
        ):
            unrelated_update = copy.deepcopy(replacement)
            unrelated_update["resource_changes"].append(
                {"address": address, "type": resource_type, "change": {"actions": ["update"]}}
            )
            cases[f"replacement updates {address}"] = unrelated_update
        drifted_flow_log = copy.deepcopy(replacement)
        self.resource(drifted_flow_log, "aws_flow_log.west")["values"]["max_aggregation_interval"] = 600
        cases["replacement planned Flow Log drift"] = drifted_flow_log
        drifted_acl = copy.deepcopy(replacement)
        self.resource(drifted_acl, "aws_network_acl.appliance_west")["values"]["egress"][0][
            "action"
        ] = "allow"
        cases["replacement planned NACL drift"] = drifted_acl
        drifted_profile = copy.deepcopy(replacement)
        drifted_profile["output_changes"]["e2e_load_profile"]["after"][
            "concurrent_tcp_flows"
        ] = 5
        cases["replacement load profile drift"] = drifted_profile
        for name, candidate in cases.items():
            with self.subTest(name=name):
                self.assertTrue(PLAN.validate(candidate, "envelope-plan", allowed, AZ_KEYS))

        route_errors = PLAN.validate(wrong_old_eni, "envelope-plan", allowed, AZ_KEYS)
        self.assertTrue(any("responder-return route change" in error for error in route_errors))

    def test_plan_and_state_fixtures_are_secret_free(self):
        paths = [self.plan_path, ROOT / "testdata/deployment/state-secret-reference.json"]
        self.assertEqual(SCAN.scan(paths), [])


if __name__ == "__main__":
    unittest.main()
