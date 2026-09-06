#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TF = ROOT / "deploy" / "terraform" / "envelope-controller"


def braced_block(text: str, header: str) -> str:
    start = text.find(header)
    if start < 0:
        raise AssertionError(f"missing block: {header}")
    opening = text.find("{", start + len(header))
    if opening < 0:
        raise AssertionError(f"block has no opening brace: {header}")
    depth = 0
    quoted = False
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
        if escaped:
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"block has no closing brace: {header}")


def go_canonical_topology(path: pathlib.Path) -> bytes:
    helper = r"""package main

import (
	"fmt"
	"os"

	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
)

func main() {
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	topology, err := controllerconfig.Parse(file)
	if err != nil {
		panic(err)
	}
	canonical, err := topology.CanonicalJSON()
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(canonical); err != nil {
		panic(fmt.Errorf("write canonical topology: %w", err))
	}
}
"""
    with tempfile.TemporaryDirectory(prefix=".controller-canonical-", dir=ROOT) as tmp:
        helper_path = pathlib.Path(tmp) / "main.go"
        helper_path.write_text(helper)
        completed = subprocess.run(
            ["go", "run", helper_path, path],
            cwd=ROOT,
            capture_output=True,
        )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode(errors="replace"))
    return completed.stdout


class ControllerTerraformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.versions = (TF / "versions.tf").read_text()
        cls.variables = (TF / "variables.tf").read_text()
        cls.locals = (TF / "locals.tf").read_text()
        cls.contracts = (TF / "contracts.tf").read_text()
        cls.authority = (TF / "authority.tf").read_text()
        cls.iam = (TF / "iam.tf").read_text()
        cls.network = (TF / "network.tf").read_text()
        cls.compute = (TF / "compute.tf").read_text()
        cls.monitoring = (TF / "monitoring.tf").read_text()
        cls.outputs = (TF / "outputs.tf").read_text()
        cls.bootstrap = (TF / "cloud-init" / "controller.sh.tftpl").read_text()
        cls.topology_identity_tool = (
            TF / "tools" / "topology-identity" / "main.go"
        ).read_text()
        cls.native_test = (TF / "tests" / "controller.tftest.hcl").read_text()
        cls.readme = (TF / "README.md").read_text()
        cls.dynamodb_store = (
            ROOT / "internal" / "controller" / "store" / "dynamodb.go"
        ).read_text()
        cls.runtime_config = (
            ROOT / "internal" / "controller" / "config" / "runtime.go"
        ).read_text()
        cls.terraform = "\n".join(path.read_text() for path in sorted(TF.glob("*.tf")))

    def test_is_standalone_terraform_110_root(self) -> None:
        self.assertIn('required_version = ">= 1.10.1, < 1.11.0"', self.versions)
        self.assertIn('backend "s3" {}', self.versions)
        self.assertIn('version = "= 6.33.0"', self.versions)
        self.assertNotIn("example/terraform", self.terraform + self.bootstrap)
        self.assertNotRegex(
            self.terraform, r'resource\s+"aws_instance"\s+"(?:target|router|transport)'
        )
        self.assertEqual(
            re.findall(r'resource\s+"aws_instance"\s+"([^"]+)"', self.compute),
            ["controller"],
        )
        self.assertNotIn("CAP_NET_ADMIN", self.terraform + self.bootstrap)
        self.assertNotIn("CAP_NET_RAW", self.terraform + self.bootstrap)
        self.assertNotIn("ssm:SendCommand", self.iam)

    def test_exactly_three_private_unique_az_slots(self) -> None:
        for required in (
            "length(var.controller_ids) == 3",
            "length(var.controller_placements) == 3",
            "length(distinct([for placement in values(var.controller_placements) : placement.subnet_id])) == 3",
            "length(distinct([for placement in values(var.controller_placements) : placement.availability_zone])) == 3",
            "toset(keys(var.controller_placements)) == var.controller_ids",
            "data.aws_subnet.controller[id].map_public_ip_on_launch == false",
        ):
            self.assertIn(required, self.variables + self.contracts)
        instance = braced_block(self.compute, 'resource "aws_instance" "controller"')
        self.assertIn("for_each = var.controller_placements", instance)
        self.assertIn("associate_public_ip_address = false", instance)
        self.assertIn("source_dest_check           = true", instance)
        self.assertIn(
            "iam_instance_profile        = aws_iam_instance_profile.controller[each.key].name",
            instance,
        )

    def test_ami_and_release_manifest_are_architecture_bound(self) -> None:
        ami = braced_block(self.contracts, 'data "aws_ami" "controller"')
        for required in (
            "most_recent = false",
            "owners      = sort(tolist(var.controller_ami_trusted_owner_ids))",
            'name   = "image-id"',
            'name   = "architecture"',
            'name   = "root-device-type"',
            'values = ["ebs"]',
            'name   = "virtualization-type"',
            'values = ["hvm"]',
            'name   = "state"',
            'values = ["available"]',
        ):
            self.assertIn(required, ami)
        self.assertIn("ami                         = data.aws_ami.controller.id", self.compute)
        self.assertIn('data "aws_ec2_instance_type" "controller"', self.contracts)
        self.assertIn(
            "contains(data.aws_ec2_instance_type.controller.supported_architectures, local.ec2_architecture)",
            self.contracts,
        )
        for identity in (
            "entry.component",
            "entry.architecture",
            "entry.ec2_architecture",
            "entry.vcs_revision",
            "entry.vcs_modified == false",
            "entry.version",
            "entry.go_version == local.reviewed_go_toolchain",
            "local.controller_manifest_entry.file == basename(var.artifact.object_key)",
            "local.controller_manifest_entry.sha256 == var.artifact.sha256",
        ):
            self.assertIn(identity, self.contracts)
        self.assertIn("scripts/reviewed-go-toolchain.txt", self.locals)
        self.assertIn('run "reject_dirty_artifact_manifest"', self.native_test)
        self.assertIn('run "reject_empty_ami_owner_allowlist"', self.native_test)
        self.assertIn('run "reject_untrusted_live_ami"', self.native_test)
        self.assertIn('run "reject_manifest_artifact_hash_mismatch"', self.native_test)

    def test_every_replica_requires_independent_same_az_nat_egress(self) -> None:
        contract = braced_block(self.variables, 'variable "management_egress"')
        for required in (
            "route_table_id",
            "nat_gateway_id",
            "nat_subnet_id",
            "nat_route_table_id",
            "internet_gateway_id",
            "length(distinct([for contract in values(var.management_egress) : contract.route_table_id])) == 3",
            "length(distinct([for contract in values(var.management_egress) : contract.nat_gateway_id])) == 3",
        ):
            self.assertIn(required, contract)
        for required in (
            'data "aws_route_table" "management_egress"',
            'data "aws_nat_gateway" "management_egress"',
            'data "aws_subnet" "management_nat"',
            'data "aws_route_table" "management_nat"',
            'data "aws_internet_gateway" "management_egress"',
            'try(one(local.management_default_routes[id]).nat_gateway_id, "") == contract.nat_gateway_id',
            'try(one(local.management_nat_default_routes[id]).gateway_id, "") == contract.internet_gateway_id',
            'data.aws_nat_gateway.management_egress[id].connectivity_type == "public"',
            'data.aws_nat_gateway.management_egress[id].state == "available"',
            "data.aws_subnet.management_nat[id].availability_zone == var.controller_placements[id].availability_zone",
        ):
            self.assertIn(required, self.contracts)
        self.assertIn('run "reject_shared_management_nat"', self.native_test)
        self.assertIn('run "reject_cross_az_management_nat"', self.native_test)
        self.assertNotIn("0.0.0.0/0:22", self.network)

    def test_authority_table_is_protected_and_cmk_encrypted(self) -> None:
        table = braced_block(
            self.authority, 'resource "aws_dynamodb_table" "authority"'
        )
        for required in (
            'billing_mode = "PAY_PER_REQUEST"',
            'hash_key     = "pk"',
            'range_key    = "sk"',
            "deletion_protection_enabled = !var.protected_acceptance_mode",
            "point_in_time_recovery",
            "server_side_encryption",
            "enabled     = !var.protected_acceptance_mode",
            "kms_key_arn = local.controller_kms_key_arn",
            'attribute_name = "ttl"',
            "enabled        = true",
        ):
            self.assertIn(required, table)
        kms = braced_block(self.authority, 'resource "aws_kms_key" "controller"')
        self.assertIn("count = var.protected_acceptance_mode ? 0 : 1", kms)
        self.assertIn("enable_key_rotation     = true", kms)
        self.assertIn("deletion_window_in_days = 30", kms)

    def test_protected_acceptance_lifecycle_is_explicit_and_default_off(self) -> None:
        lifecycle = braced_block(
            self.variables, 'variable "protected_acceptance_mode"'
        )
        self.assertIn("default     = false", lifecycle)
        self.assertIn(
            "controller_kms_key_arn = var.protected_acceptance_mode ? null",
            self.locals,
        )
        self.assertIn(
            'encryption_key_mode         = var.protected_acceptance_mode ? "aws-owned" : "customer-managed"',
            self.outputs,
        )
        self.assertIn(
            "final_snapshot    = !var.protected_acceptance_mode", self.compute
        )
        self.assertIn(
            "protected_acceptance_mode requires exact EnvelopeRun and canonical ExpiresAt lifecycle tags",
            self.contracts,
        )
        output = braced_block(
            self.outputs, 'output "protected_acceptance_lifecycle"'
        )
        for field in (
            "dynamodb_deletion_protection",
            "observer_final_snapshots",
            "customer_managed_storage_key",
        ):
            self.assertIn(field, output)
        self.assertIn('run "protected_acceptance_cleanup_contract"', self.native_test)

    def test_mode_and_per_replica_iam_are_fail_closed(self) -> None:
        deployment_mode = braced_block(self.variables, 'variable "deployment_mode"')
        self.assertIn('default     = "read-only"', deployment_mode)
        self.assertIn(
            'contains(["read-only", "active"], var.deployment_mode)', deployment_mode
        )
        for action in (
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeRouteTables",
            "ec2:ReplaceRoute",
            "s3:GetObjectVersion",
            "ssm:GetParameter",
            "kms:Decrypt",
        ):
            self.assertIn(f'"{action}"', self.iam)
        self.assertNotIn('"dynamodb:Query"', self.iam)
        for prohibited in (
            "ec2:CreateRoute",
            "ec2:DeleteRoute",
            "ec2:AssociateRouteTable",
            "ec2:ModifyNetworkInterfaceAttribute",
            "cloudwatch:PutMetricData",
            's3:GetObject"',
        ):
            self.assertNotIn(prohibited, self.iam)
        self.assertIn("Resource = route_table_arns", self.iam)
        self.assertIn('StringEquals = { "aws:RequestedRegion" = region }', self.iam)
        self.assertIn('"dynamodb:LeadingKeys"', self.iam)
        self.assertIn('"s3:VersionId"', self.iam)
        self.assertGreaterEqual(
            self.iam.count('var.deployment_mode == "active" ? ['), 2
        )
        for resource in (
            "aws_iam_role",
            "aws_iam_role_policy",
            "aws_iam_instance_profile",
        ):
            block = braced_block(self.iam, f'resource "{resource}" "controller"')
            self.assertIn("for_each = var.controller_placements", block)
        self.assertIn("aws_iam_role.controller[each.key].id", self.iam)
        self.assertIn("aws_iam_role.controller[each.key].name", self.iam)
        self.assertIn("policy = local.controller_policies[each.key]", self.iam)
        self.assertIn('run "standalone_controller_contract"', self.native_test)
        self.assertIn('run "active_controller_contract"', self.native_test)
        self.assertIn("deployment_mode", self.compute)
        self.assertIn("= var.deployment_mode", self.compute)
        self.assertIn("readonly deployment_mode='${deployment_mode}'", self.bootstrap)
        self.assertIn("ENVELOPE_CONTROLLER_READ_ONLY=%s", self.bootstrap)
        self.assertIn('env:"ENVELOPE_CONTROLLER_READ_ONLY"', self.runtime_config)
        self.assertEqual(
            set(re.findall(r'resource "aws_iam_role" "([^"]+)"', self.terraform)),
            {"controller", "deployment_lifecycle"},
        )
        self.assertEqual(self.terraform.count('resource "aws_iam_instance_profile"'), 1)

    def test_dynamodb_cmk_decrypt_is_exact_and_mode_gated(self) -> None:
        dynamodb_start = self.iam.index(
            'var.protected_acceptance_mode ? [] : ['
        )
        dynamodb_end = self.iam.index(
            'var.deployment_mode == "active" ? [', dynamodb_start
        )
        dynamodb_kms = self.iam[dynamodb_start:dynamodb_end]
        for required in (
            'Sid      = "DecryptDynamoDBAuthorityTableOnly"',
            'Action   = ["kms:Decrypt"]',
            "Resource = [local.controller_kms_key_arn]",
            '"kms:CallerAccount"',
            '"kms:EncryptionContext:aws:dynamodb:subscriberId"',
            '"kms:EncryptionContext:aws:dynamodb:tableName"',
            '"kms:EncryptionContextKeys"',
            '"aws:dynamodb:subscriberId"',
            '"aws:dynamodb:tableName"',
            '"kms:ViaService"',
            '"dynamodb.${var.aws_region}.${data.aws_partition.current.dns_suffix}"',
            "var.authority_table_name",
            "var.aws_account_id",
        ):
            self.assertIn(required, dynamodb_kms)
        for prohibited in (
            '"kms:Encrypt"',
            '"kms:GenerateDataKey',
            '"kms:ReEncrypt',
            '"kms:CreateGrant"',
            '"kms:DescribeKey"',
            'Resource = [null]',
        ):
            self.assertNotIn(prohibited, dynamodb_kms)

        ssm_start = self.iam.index('for secret_name in ["tsnet", "admin"]')
        ssm_end = self.iam.index(
            'var.protected_acceptance_mode ? [] : [', ssm_start
        )
        ssm_kms = self.iam[ssm_start:ssm_end]
        self.assertIn('Sid      = "Decrypt${title(secret_name)}ParameterOnly"', ssm_kms)
        self.assertIn('Action   = ["kms:Decrypt"]', ssm_kms)
        self.assertIn(
            "Resource = [var.secret_parameters[secret_name].kms_key_arn]", ssm_kms
        )
        self.assertIn(
            '"kms:EncryptionContext:PARAMETER_ARN" = var.secret_parameters[secret_name].arn',
            ssm_kms,
        )
        self.assertIn(
            '"kms:ViaService"                      = "ssm.${var.aws_region}.${data.aws_partition.current.dns_suffix}"',
            ssm_kms,
        )
        self.assertIn('run "dynamodb_cmk_policy_contract"', self.native_test)
        self.assertIn(
            'run "protected_acceptance_cleanup_contract"', self.native_test
        )

    def test_observation_iam_matches_the_actual_dynamodb_key_layout(self) -> None:
        self.assertIn(
            'return "observations#" + deploymentID + "#" + topologyHash + "#" + controllerID',
            self.dynamodb_store,
        )
        self.assertIn('return "controller#" + controllerID', self.dynamodb_store)
        self.assertIn(
            'controller_id => "observations#${local.topology.deployment_id}#${local.topology_sha256}#${controller_id}"',
            self.iam,
        )
        self.assertIn("controller_policy_statements = {", self.iam)
        self.assertIn(
            "for controller_id in var.controller_ids : controller_id => concat(",
            self.iam,
        )
        publish_start = self.iam.index('Sid      = "PublishObservation"')
        publish_end = self.iam.index(
            'Sid    = "ReadControllerBootstrapParameters"', publish_start
        )
        publish = self.iam[publish_start:publish_end]
        self.assertIn('Action   = ["dynamodb:PutItem"]', publish)
        self.assertIn(
            '"dynamodb:LeadingKeys" = [local.observation_partition_keys[controller_id]]',
            publish,
        )
        quorum_start = self.iam.index('Sid      = "ReadObservationQuorum"')
        quorum_end = self.iam.index('Sid      = "PublishObservation"', quorum_start)
        quorum = self.iam[quorum_start:quorum_end]
        self.assertIn('Action   = ["dynamodb:GetItem"]', quorum)
        self.assertIn(
            '"dynamodb:LeadingKeys" = local.observation_partition_key_values',
            quorum,
        )
        self.assertNotIn("dynamodb:Query", self.iam)
        self.assertIn("a process using controller-a's AWS", self.readme)
        self.assertIn("credentials and claiming controller-b", self.readme)
        self.assertIn("denied by IAM", self.readme)

    def test_existing_routes_are_validated_but_never_managed(self) -> None:
        self.assertNotRegex(self.terraform, r'resource\s+"aws_route"')
        self.assertIn('data "aws_route_table" "managed"', self.contracts)
        self.assertIn('data "aws_subnet" "managed_gwlbe"', self.contracts)
        for required in (
            "route.cidr_block != cidr",
            "local.topology_prefix_bounds[cidr].first",
            "local.topology_prefix_bounds[cidr].last",
            "length(matches) == 1",
            "one(matches).network_interface_id",
            'try(route.destination_prefix_list_id, "") == ""',
            "contract.route_table_arn ==",
            "contract.destination_cidrs == toset(local.topology_domains_by_id[domain_id].remote_prefixes)",
            "contract.gwlbe_subnet_id == local.topology_domains_by_id[domain_id].gwlbe_subnet_id",
            "contract.route_table_association_id == local.topology_domains_by_id[domain_id].route_table_association_id",
        ):
            self.assertIn(required, self.contracts)
        ownership = braced_block(self.outputs, 'output "dynamic_route_ownership"')
        self.assertIn("terraform_manages_target = false", ownership)
        self.assertIn("observed_target_by_cidr", ownership)
        self.assertIn("eligible_eni_ids", ownership)
        self.assertIn("gwlbe_subnet_id", ownership)
        self.assertIn("route_table_association_id", ownership)
        self.assertNotIn("aws_route.", ownership)
        for run in (
            'run "allow_less_specific_ipv4_route"',
            'run "reject_more_specific_ipv4_route_shadow"',
            'run "reject_managed_route_prefix_list"',
        ):
            self.assertIn(run, self.native_test)

    def test_managed_route_authority_binds_exact_gwlbe_association(self) -> None:
        managed = braced_block(self.variables, 'variable "managed_route_tables"')
        for required in (
            "gwlbe_subnet_id",
            "route_table_association_id",
            "contract.gwlbe_subnet_id",
            "contract.route_table_association_id",
            'regex("^subnet-[0-9a-f]{8,17}$"',
            'regex("^rtbassoc-[0-9a-f]{8,17}$"',
        ):
            self.assertIn(required, managed)
        for required in (
            "data.aws_subnet.managed_gwlbe[each.key].vpc_id == each.value.vpc_id",
            "length(data.aws_route_table.managed[each.key].associations) == 1",
            "one(data.aws_route_table.managed[each.key].associations).main == false",
            "one(data.aws_route_table.managed[each.key].associations).subnet_id == each.value.gwlbe_subnet_id",
            "one(data.aws_route_table.managed[each.key].associations).route_table_association_id == each.value.route_table_association_id",
            "one(data.aws_route_table.managed[each.key].associations).route_table_id == each.value.route_table_id",
        ):
            self.assertIn(required, self.contracts)
        for run in (
            'run "reject_wrong_gwlbe_subnet_association"',
            'run "reject_wrong_gwlbe_route_table_association_id"',
            'run "reject_gwlbe_subnet_outside_site_vpc"',
            'run "reject_duplicate_managed_gwlbe_subnet"',
        ):
            self.assertIn(run, self.native_test)

        fixture = json.loads(
            (TF / "tests" / "fixtures" / "topology.json").read_text()
        )
        domains = fixture["domains"]
        self.assertEqual(
            len({domain["gwlbe_subnet_id"] for domain in domains}), len(domains)
        )
        self.assertEqual(
            len({domain["route_table_association_id"] for domain in domains}),
            len(domains),
        )

    def test_topology_requires_complete_overlapping_router_contract(self) -> None:
        transport = braced_block(self.variables, 'variable "transport_topology"')
        for field in (
            "expected_advertised_prefixes",
            "expected_enabled_prefixes",
            "expected_accepted_remote_prefixes",
            "expected_local_main_prefixes",
            "local_main_rule_priority_base",
            "tailscale_route_rule_priority",
        ):
            self.assertIn(field, transport)
        for equality in (
            "router.expected_advertised_prefixes == site.local_prefixes",
            "router.expected_enabled_prefixes == site.local_prefixes",
            "router.expected_local_main_prefixes == site.local_prefixes",
            "descriptor.local_prefixes == toset(local.topology_sites_by_id[site_id].local_prefixes)",
            "expectation.expected_accepted_remote_prefixes == local.topology_remote_prefixes_by_site[site_id]",
        ):
            self.assertIn(equality, self.variables + self.contracts)
        self.assertIn(
            "site.local_main_rule_priority_base + length(site.local_prefixes) - 1 < site.tailscale_route_rule_priority",
            transport,
        )

    def test_secrets_are_indirect_and_absent_from_state_and_user_data(self) -> None:
        secret_variable = braced_block(self.variables, 'variable "secret_parameters"')
        self.assertEqual(secret_variable.count("kms_key_arn = string"), 2)
        self.assertNotRegex(
            secret_variable, r"(?m)^\s*(?:value|secret|auth_key|api_key)\s*="
        )
        self.assertNotIn("topology_json", self.bootstrap)
        self.assertNotRegex(
            self.bootstrap + self.native_test,
            r"(?i)(tskey-[a-z]|nodekey:|machinekey:|privkey:|begin private key)",
        )
        self.assertIn("aws ssm get-parameter", self.bootstrap)
        self.assertIn("--with-decryption", self.bootstrap)
        self.assertIn(
            'tsnet_auth_key="$(fetch_secret "$tsnet_parameter")"', self.bootstrap
        )
        self.assertIn(
            'printf \'%s=%s\\n\' "$tsnet_env_name" "$tsnet_auth_key"', self.bootstrap
        )
        self.assertIn('/usr/bin/chmod 0400 "$environment_tmp"', self.bootstrap)
        self.assertIn("unset tsnet_auth_key admin_api_key", self.bootstrap)
        self.assertNotIn("export ", self.bootstrap)
        self.assertNotIn("/run/envelope-controller/tsnet-auth-key", self.bootstrap)
        self.assertNotIn("/run/envelope-controller/admin-api-key", self.bootstrap)
        self.assertNotIn("--auth-key", self.bootstrap)
        self.assertIn("/etc/envelope/controller.env", self.bootstrap)
        self.assertIn("/etc/envelope/controller-topology.json", self.bootstrap)
        self.assertIn('type        = "String"', self.authority)
        self.assertNotIn('type        = "SecureString"', self.authority)
        for condition in (
            '"kms:CallerAccount"',
            '"kms:EncryptionContext:PARAMETER_ARN"',
            '"kms:ViaService"',
        ):
            self.assertIn(condition, self.iam)

    def test_bootstrap_uses_immutable_artifact_and_private_state(self) -> None:
        for required in (
            "s3api get-object",
            '--version-id "$artifact_version"',
            "/usr/bin/sha256sum --check --status",
            "metadata_options",
            'http_tokens                 = "required"',
            "http_put_response_hop_limit = 1",
            "encrypted         = true",
            "aws_volume_attachment",
            "/var/lib/envelope-controller",
        ):
            self.assertIn(required, self.compute + self.bootstrap)
        self.assertIn("local.systemd_unit_path", self.locals)
        self.assertIn("../../systemd/envelope-controller.service", self.locals)
        self.assertIn(
            "controller_systemd_unit = file(local.systemd_unit_path)", self.locals
        )
        self.assertNotIn("fallback_systemd_unit", self.locals)
        self.assertNotIn("fileexists(local.systemd_unit_path)", self.locals)
        self.assertIn("ReadVersionedTopologyIdentityArtifact", self.iam)
        self.assertIn('"$topology_tool_tmp" verify', self.bootstrap)
        self.assertIn('--sha256 "$topology_document_sha256"', self.bootstrap)
        self.assertLess(
            self.bootstrap.index('"$topology_tool_tmp" verify'),
            self.bootstrap.index("/usr/bin/systemctl enable --now"),
        )
        for forbidden in (
            "envelope-controller-prepare",
            "envelope-controller-run",
            "ExecStartPre",
            "ExecStart=",
            "envelope-controller.service.d",
        ):
            self.assertNotIn(forbidden, self.bootstrap)

    def test_go_topology_identity_tool_normalizes_and_rejects_raw_aliases(self) -> None:
        fixture = TF / "tests" / "fixtures" / "topology.json"
        canonical = go_canonical_topology(fixture)
        noncanonical = canonical.replace(
            b'"observation_interval":"2s"',
            b'"observation_interval":"2000ms"',
            1,
        )
        self.assertNotEqual(noncanonical, canonical)

        with tempfile.TemporaryDirectory(prefix="controller-topology-tool-") as tmp:
            temporary = pathlib.Path(tmp)
            tool = temporary / "topology-identity"
            canonical_path = temporary / "canonical.json"
            noncanonical_path = temporary / "noncanonical.json"
            canonical_path.write_bytes(canonical)
            noncanonical_path.write_bytes(noncanonical)
            subprocess.run(
                [
                    "go",
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-ldflags",
                    "-X main.version=test.1 "
                    + "-X main.revision="
                    + "c" * 40
                    + " -X main.buildDate=2026-09-04T00:00:00Z "
                    + "-X main.sourceModified=false",
                    "-o",
                    tool,
                    TF / "tools" / "topology-identity",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            normalized = subprocess.run(
                [tool, "canonicalize", "--input", noncanonical_path],
                check=True,
                capture_output=True,
            ).stdout
            self.assertEqual(normalized, canonical)
            identity = json.loads(
                subprocess.run(
                    [tool, "identity", "--input", noncanonical_path],
                    check=True,
                    text=True,
                    capture_output=True,
                ).stdout
            )
            self.assertEqual(identity["canonical_sha256"], hashlib.sha256(canonical).hexdigest())
            self.assertEqual(identity["policy_durations"]["observation_interval"], "2s")
            self.assertFalse(identity["vcs_modified"])
            subprocess.run(
                [
                    tool,
                    "verify",
                    "--input",
                    canonical_path,
                    "--sha256",
                    hashlib.sha256(canonical).hexdigest(),
                ],
                check=True,
                capture_output=True,
            )
            rejected = subprocess.run(
                [
                    tool,
                    "verify",
                    "--input",
                    noncanonical_path,
                    "--sha256",
                    hashlib.sha256(noncanonical).hexdigest(),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not exact Go-canonical JSON", rejected.stderr)

    def test_rendered_bootstrap_is_valid_and_fits_ec2_user_data(self) -> None:
        systemd_path = ROOT / "deploy" / "systemd" / "envelope-controller.service"
        systemd_unit = systemd_path.read_bytes()
        values = {
            "topology_region": "us-west-2",
            "artifact_region": "us-west-2",
            "artifact_sha256": "a" * 64,
            "topology_document_sha256": "b" * 64,
            "router_trust_sha256": "d" * 64,
            "router_trust_parameter_b64": base64.b64encode(
                b"/deployment/router-trust/digest:1"
            ).decode(),
            "observer_volume_id": "vol-00000000000000000",
            "deployment_mode": "read-only",
            "metrics_port": "9091",
            "log_level": "info",
            "tsnet_env_name": "ENVELOPE_TSNET_AUTH_KEY",
            "admin_env_name": "ENVELOPE_TAILSCALE_ADMIN_API_KEY",
            "artifact_bucket_b64": base64.b64encode(b"artifact-bucket").decode(),
            "artifact_key_b64": base64.b64encode(b"controller/binary").decode(),
            "artifact_version_b64": base64.b64encode(b"version-id").decode(),
            "topology_tool_region": "us-west-2",
            "topology_tool_sha256": "c" * 64,
            "topology_tool_bucket_b64": base64.b64encode(
                b"artifact-bucket"
            ).decode(),
            "topology_tool_key_b64": base64.b64encode(
                b"controller/topology-tool"
            ).decode(),
            "topology_tool_version_b64": base64.b64encode(
                b"topology-version-id"
            ).decode(),
            "controller_id_b64": base64.b64encode(b"controller-a").decode(),
            "state_base_dir_b64": base64.b64encode(
                b"/var/lib/envelope-controller/tsnet"
            ).decode(),
            "topology_parameter_b64": base64.b64encode(
                b"/deployment/controller/topology"
            ).decode(),
            "tsnet_parameter_name_b64": base64.b64encode(
                b"/deployment/controller/tsnet"
            ).decode(),
            "admin_parameter_name_b64": base64.b64encode(
                b"/deployment/controller/admin"
            ).decode(),
            "systemd_unit_b64": base64.b64encode(systemd_unit).decode(),
        }
        escaped = "__TERRAFORM_LITERAL_INTERPOLATION__"
        rendered = self.bootstrap.replace("$${", escaped)
        rendered = re.sub(
            r"\$\{([a-z][a-z0-9_]*)\}",
            lambda match: values[match.group(1)],
            rendered,
        ).replace(escaped, "${")
        self.assertNotRegex(rendered, r"\$\{[a-z][a-z0-9_]*\}")
        self.assertLessEqual(len(rendered.encode()), 16 * 1024)
        completed = subprocess.run(
            ["bash", "-n"], input=rendered, text=True, capture_output=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("readonly deployment_mode='read-only'", rendered)
        self.assertIn("read-only) controller_read_only=true", rendered)
        self.assertIn("active) controller_read_only=false", rendered)
        for assignment in (
            "ENVELOPE_CONTROLLER_ID=%s",
            "ENVELOPE_CONTROLLER_TOPOLOGY_PATH=/etc/envelope/controller-topology.json",
            "ENVELOPE_CONTROLLER_METRICS_ADDR=%s:%s",
            "ENVELOPE_CONTROLLER_LOG_LEVEL=%s",
            "ENVELOPE_CONTROLLER_READ_ONLY=%s",
        ):
            self.assertIn(assignment, rendered)
        encoded_units = re.findall(
            r"/usr/bin/base64 --decode > /etc/systemd/system/envelope-controller.service <<'UNIT_BASE64'\n(?P<unit>.*?)\nUNIT_BASE64",
            rendered,
            re.DOTALL,
        )
        self.assertEqual(len(encoded_units), 1)
        self.assertEqual(base64.b64decode(encoded_units[0]), systemd_unit)

    def test_artifact_key_rejects_iam_wildcards_and_control_characters(self) -> None:
        artifact = braced_block(self.variables, 'variable "artifact"')
        self.assertIn('!can(regex("[*?\\\\p{Cc}]", var.artifact.object_key))', artifact)
        self.assertIn('run "reject_wildcard_artifact_key"', self.native_test)
        self.assertIn('run "reject_control_character_artifact_key"', self.native_test)

    def test_security_group_and_alarms_are_fail_closed(self) -> None:
        ingress_resources = re.findall(
            r'resource\s+"aws_vpc_security_group_ingress_rule"\s+"([^"]+)"',
            self.network,
        )
        self.assertEqual(ingress_resources, ["controller_metrics"])
        self.assertNotIn("from_port         = 22", self.network)
        self.assertIn("from_port         = var.metrics_port", self.network)
        self.assertIn('cidr_ipv4         = "169.254.169.254/32"', self.network)
        for metric in (
            'metric_name         = "StatusCheckFailed"',
            'read_throttles  = "ReadThrottleEvents"',
            'write_throttles = "WriteThrottleEvents"',
            'metric_name = "SystemErrors"',
            'Operation = "GetItem"',
            'Operation = "PutItem"',
            'expression  = "get_item_errors + put_item_errors"',
            'treat_missing_data  = "breaching"',
        ):
            self.assertIn(metric, self.monitoring)
        self.assertNotIn('Operation = "Query"', self.monitoring)
        self.assertIn("controller_can_publish = false", self.outputs)
        self.assertIn("data.aws_iam_role.readiness_publisher.arn", self.outputs)
        self.assertIn('PublisherId  = var.readiness_publisher.id', self.monitoring)
        self.assertIn("length(var.alarm_actions) > 0", self.variables)
        self.assertIn('run "reject_empty_alarm_actions"', self.native_test)
        self.assertIn('run "reject_ambiguous_readiness_publisher"', self.native_test)
        self.assertIn(
            'run "reject_readiness_publisher_identity_mismatch"', self.native_test
        )

    def test_fixture_hash_matches_canonical_contract(self) -> None:
        fixture = TF / "tests" / "fixtures" / "topology.json"
        source = fixture.read_bytes().strip()
        json.loads(source)
        canonical = go_canonical_topology(fixture)
        self.assertEqual(source, canonical)
        digest = hashlib.sha256(canonical).hexdigest()
        self.assertIn(
            'canonical_sha256      = sha256(trimspace(file("tests/fixtures/topology.json")))',
            self.native_test,
        )
        self.assertIn("topology_identity = jsondecode(var.topology_identity_json)", self.locals)
        self.assertIn(
            "topology_json     = base64decode(local.topology_identity.canonical_json_base64)",
            self.locals,
        )
        self.assertIn(
            "local.topology_sha256 == local.topology_document_sha256", self.contracts
        )
        self.assertIn('run "reject_noncanonical_duration_identity"', self.native_test)
        self.assertNotIn("canonical_policy_json", self.locals)

        semantic_source = source.replace(
            b'"observation_interval":"2s"',
            b'"observation_interval":"2000ms"',
            1,
        )
        with tempfile.TemporaryDirectory(prefix="controller-topology-") as tmp:
            semantic_path = pathlib.Path(tmp) / "topology.json"
            semantic_path.write_bytes(semantic_source)
            self.assertEqual(go_canonical_topology(semantic_path), canonical)
        self.assertNotEqual(hashlib.sha256(semantic_source).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
