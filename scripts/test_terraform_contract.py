#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TF = ROOT / "example" / "terraform"


def braced_block(text: str, header: str) -> str:
    start = text.find(header)
    if start < 0:
        raise AssertionError(f"missing block: {header}")
    opening = text.find("{", start + len(header))
    if opening < 0:
        raise AssertionError(f"block has no opening brace: {header}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"block has no closing brace: {header}")


def heredoc(text: str, path: str) -> str:
    match = re.search(
        rf"cat >{re.escape(path)} <<'(?P<marker>[A-Z_]+)'\n(?P<body>.*?)\n(?P=marker)",
        text,
        re.DOTALL,
    )
    if not match:
        raise AssertionError(f"missing heredoc: {path}")
    return match.group("body") + "\n"


def assigned_heredoc(text: str, name: str) -> str:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*<<-?(?P<marker>[A-Z_]+)\n(?P<body>.*?)\n\s*(?P=marker)",
        text,
        re.DOTALL,
    )
    if not match:
        raise AssertionError(f"missing assigned heredoc: {name}")
    return match.group("body") + "\n"


class SymmetricTerraformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.variables = (TF / "variables.tf").read_text()
        cls.topology = (TF / "topology.tf").read_text()
        cls.user_data = (TF / "user_data.tf").read_text()
        cls.iam = (TF / "iam.tf").read_text()
        cls.bootstrap = (TF / "cloud-init" / "bootstrap.sh.tftpl").read_text()
        cls.transport_router_path = (
            TF / "cloud-init" / "transport-router.sh.tftpl"
        )
        cls.transport_router = cls.transport_router_path.read_text()
        cls.tailscale_module = (
            TF / "modules" / "tailscale-cloudinit" / "main.tf"
        ).read_text()
        cls.tailscale_setup = (
            TF
            / "modules"
            / "tailscale-cloudinit"
            / "templates"
            / "setup_tailscale.sh.tftpl"
        ).read_text()
        cls.tests = (TF / "tests" / "appliance.tftest.hcl").read_text()

    def assert_literal_set(
        self, text: str, anchor: str, expected: set[str]
    ) -> None:
        start = text.find(anchor)
        self.assertGreaterEqual(start, 0, f"missing literal-set anchor: {anchor}")
        opening = text.find("[", start + len(anchor))
        closing = text.find("]", opening + 1)
        self.assertGreaterEqual(opening, 0, f"missing literal set after: {anchor}")
        self.assertGreaterEqual(closing, 0, f"unterminated literal set after: {anchor}")
        values = re.findall(r'"([a-z0-9_]+)"', text[opening : closing + 1])
        self.assertEqual(len(values), len(set(values)), f"duplicate key after: {anchor}")
        self.assertEqual(set(values), expected)

    def assert_assignment_set(
        self, text: str, indentation: int, expected: set[str]
    ) -> None:
        values = re.findall(
            rf"(?m)^ {{{indentation}}}([a-z][a-z0-9_]*)\s*=", text
        )
        self.assertEqual(len(values), len(set(values)), "duplicate assignment")
        self.assertEqual(set(values), expected)

    def test_versioned_schema_uses_exact_sets_and_transport_names(self) -> None:
        self.assertTrue(
            self.transport_router_path.is_file(),
            "current transport-router template is missing",
        )
        self.assertFalse(
            (TF / "cloud-init" / "ingress-router.sh.tftpl").exists(),
            "obsolete ingress-router template name must not coexist with transport naming",
        )
        self.assertIn('variable "symmetric_topology"', self.variables)
        self.assertIn("var.symmetric_topology.version == 2", self.variables)
        self.assert_literal_set(
            self.variables,
            "toset(keys(var.symmetric_topology)) == toset(",
            {"version", "sites", "route_failover"},
        )
        self.assert_literal_set(
            self.variables,
            "toset(keys(var.symmetric_topology.sites)) == toset(",
            {"west", "east"},
        )
        self.assert_literal_set(
            self.variables,
            "toset(keys(site)) == toset(",
            {
                "region",
                "ami_id",
                "ssm_kms_key_arn",
                "azs",
                "vpc_cidr",
                "local_site_cidrs",
                "remote_site_cidrs",
                "workload_subnet_cidrs",
                "transport_subnet_cidrs",
                "gwlbe_subnet_cidrs",
                "gwlb_subnet_cidrs",
                "target_subnet_cidrs",
                "management_subnet_cidr",
                "target_az_keys",
                "transport_router_az_keys",
            },
        )
        for exact_az_set in (
            "toset(site.target_az_keys) == toset(keys(site.azs))",
            "toset(site.transport_router_az_keys) == toset(keys(site.azs))",
            "toset(keys(site.workload_subnet_cidrs)) == toset(keys(site.azs))",
            "toset(keys(site.transport_subnet_cidrs)) == toset(keys(site.azs))",
            "toset(keys(site.gwlbe_subnet_cidrs)) == toset(keys(site.azs))",
            "toset(keys(site.gwlb_subnet_cidrs)) == toset(keys(site.azs))",
            "toset(keys(site.target_subnet_cidrs)) == toset(keys(site.azs))",
        ):
            self.assertIn(exact_az_set, self.variables)
        self.assertIn("length(site.azs) == 2", self.variables)
        self.assertIn("length(distinct(values(site.azs))) == 2", self.variables)
        self.assertRegex(
            self.variables,
            r"(?m)^\s*target_az_keys\s+= toset\(site\.target_az_keys\)$",
        )
        self.assertRegex(
            self.variables,
            r"(?m)^\s*transport_router_az_keys\s+= toset\(site\.transport_router_az_keys\)$",
        )
        self.assert_literal_set(
            self.variables,
            "toset(keys(var.symmetric_topology.route_failover)) == toset(",
            {
                "initial_transport_router_az_by_gwlbe_az",
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
            },
        )
        self.assert_literal_set(
            self.variables,
            "toset(keys(var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az)) == toset(",
            {"west", "east"},
        )
        for selection_expression in (
            "for site, selections in var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az",
            "toset(keys(selections)) == toset(keys(var.symmetric_topology.sites[site].gwlbe_subnet_cidrs))",
            "for gwlbe_az, transport_router_az in selections",
            "gwlbe_az == transport_router_az",
            "contains(var.symmetric_topology.sites[site].transport_router_az_keys, transport_router_az)",
        ):
            self.assertIn(selection_expression, self.variables)
        for timeout_field in (
            "mutation_timeout_seconds",
            "restoration_timeout_seconds",
            "recovery_timeout_seconds",
        ):
            self.assertIn(
                f"var.symmetric_topology.route_failover.{timeout_field}",
                self.variables,
            )
        self.assertIn(
            "seconds >= 1 && seconds <= 7200 && floor(seconds) == seconds",
            self.variables,
        )
        self.assertIn(
            "route_failover must map every GWLBE AZ to the same transport-router AZ and contain whole-second mutation, restoration, and recovery bounds from 1 through 7200.",
            self.variables,
        )

        current_contract = "\n".join(
            (self.variables, self.topology, self.user_data, self.tests)
        )
        for stale_name in (
            "ingress_subnet_cidrs",
            "ingress_router_az_keys",
            "ingress_router_fleet",
            "tailnet_ingress",
            "tailscale_ingress",
        ):
            self.assertNotIn(stale_name, current_contract)
        for obsolete_field in (
            "gwlb_return_cidrs",
            "local_delivery_cidrs",
            "remote_tailnet_cidrs",
            "appliance_target_count",
            "envelope_routing_mode",
            "envelope_tun_name",
            "envelope_routing_table_id",
            "envelope_routing_rule_priority",
        ):
            self.assertNotIn(obsolete_field, self.variables)

    def test_route_domains_and_post_inspection_routes_are_separate(self) -> None:
        for role in ("workload", "transport", "gwlbe", "target", "management"):
            self.assertIn(f'aws_route_table" "{role}_west', self.topology)
            self.assertIn(f'aws_route_table" "{role}_east', self.topology)
        for route in (
            "workload_to_remote_west",
            "workload_to_remote_east",
            "transport_to_local_west",
            "transport_to_local_east",
            "gwlbe_to_remote_west",
            "gwlbe_to_remote_east",
        ):
            self.assertIn(f'resource "aws_route" "{route}"', self.topology)
        self.assertNotIn('resource "aws_route" "gwlbe_to_local_', self.topology)
        self.assertNotIn('resource "aws_route" "target_to_', self.topology)
        self.assertGreaterEqual(self.topology.count("setproduct"), 6)

        for site in ("west", "east"):
            transport_route = braced_block(
                self.topology,
                f'resource "aws_route" "transport_to_local_{site}"',
            )
            self.assertIn(
                f"toset(keys(local.sites.{site}.workload_subnet_cidrs))",
                transport_route,
            )
            self.assertIn(
                f'"${{pair[0]}}:${{local.sites.{site}.workload_subnet_cidrs[pair[1]]}}"',
                transport_route,
            )
            self.assertIn(
                f"aws_route_table.transport_{site}[each.value.transport_az_key].id",
                transport_route,
            )
            self.assertIn(
                f"aws_vpc_endpoint.{site}[each.value.workload_az_key].id",
                transport_route,
            )
            self.assertIn(
                f"each.value.cidr == local.sites.{site}.workload_subnet_cidrs[each.value.workload_az_key]",
                transport_route,
            )
            self.assertIn(
                "transport routes must select the GWLBE in each destination workload prefix's AZ",
                transport_route,
            )
            self.assertNotIn(
                f"aws_vpc_endpoint.{site}[each.value.transport_az_key].id",
                transport_route,
            )

            route = braced_block(
                self.topology, f'resource "aws_route" "gwlbe_to_remote_{site}"'
            )
            selection = (
                "local.route_failover."
                f"initial_transport_router_az_by_gwlbe_az.{site}[each.value.az_key]"
            )
            self.assertIn(
                f"route_table_id         = aws_route_table.gwlbe_{site}[each.value.az_key].id",
                route,
            )
            self.assertIn(
                f"network_interface_id = aws_instance.transport_router_{site}[\n"
                f"    {selection}\n"
                "  ].primary_network_interface_id",
                route,
            )
            self.assertIn(
                f"contains(\n        local.sites.{site}.transport_router_az_keys,\n"
                f"        {selection},",
                route,
            )
            self.assertIn(f"{selection} == each.value.az_key", route)
            self.assertNotIn(
                f"aws_instance.transport_router_{site}[each.value.az_key]",
                route,
            )
            self.assertIn("toset(local.sites.", route)
            self.assertIn(".remote_site_cidrs)", route)
            self.assertIn(
                f"local.initial_transport_router_advertise_routes.{site}", route
            )
            self.assertIn(
                f"local.sites.{site}.workload_subnet_cidrs[each.value.az_key]",
                route,
            )

    def test_route_failover_and_readiness_outputs_are_exact(self) -> None:
        symmetric_output = braced_block(
            self.topology, 'output "symmetric_topology"'
        )
        self.assert_assignment_set(
            symmetric_output,
            4,
            {"config_version", "run_id", "route_failover", "sites"},
        )
        self.assertIn("route_failover = local.route_failover", symmetric_output)

        failover_output = braced_block(self.topology, 'output "route_failover"')
        self.assert_assignment_set(
            failover_output,
            4,
            {
                "config_version",
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
                "same_az_preferred",
                "sites",
            },
        )
        for site in ("west", "east"):
            selection = (
                "local.route_failover."
                f"initial_transport_router_az_by_gwlbe_az.{site}"
            )
            self.assertIn(
                f"for gwlbe_az, transport_az in {selection}", failover_output
            )
            self.assertIn(
                f"route_table_id                  = aws_route_table.gwlbe_{site}[gwlbe_az].id",
                failover_output,
            )
            self.assertIn(
                "initial_transport_router_az_key = transport_az",
                failover_output,
            )
            self.assertIn(
                f"initial_network_interface_id    = aws_instance.transport_router_{site}[transport_az].primary_network_interface_id",
                failover_output,
            )
            self.assertIn(
                f"source_workload_prefix          = local.sites.{site}.workload_subnet_cidrs[gwlbe_az]",
                failover_output,
            )
        self.assertIn(
            "site => alltrue([for gwlbe_az, transport_az in selections : gwlbe_az == transport_az])",
            failover_output,
        )

        readiness_output = braced_block(
            self.topology, 'output "transport_router_readiness_expectations"'
        )
        self.assert_assignment_set(
            readiness_output, 4, {"config_version", "sites"}
        )
        self.assertIn(
            "for site, contract in local.transport_router_contracts : site => merge(contract, {",
            readiness_output,
        )
        self.assertIn(
            "contract_sha256 = local.transport_router_contract_sha256[site]",
            readiness_output,
        )

        readiness_contract = braced_block(
            self.user_data, "transport_router_contracts ="
        )
        self.assert_assignment_set(
            readiness_contract,
            6,
            {
                "config_version",
                "local_site_cidrs",
                "remote_site_cidrs",
                "underlay_interface",
                "tailscale_interface",
                "approved_maximum_tcp_mss",
                "ipv4_forwarding",
                "ipv6_forwarding",
                "filter_forward_policy",
                "mangle_forward_policy",
                "filter_forward_rules",
                "mangle_forward_rules",
                "mss_terminal_rules",
                "nat_rules",
                "ipv6_filter_forward_policy",
                "ipv6_mangle_forward_policy",
                "ipv6_filter_forward_rules",
                "ipv6_forward_rules",
                "ipv6_mangle_forward_rules",
                "readiness_marker",
                "runtime_state",
                "recovery_marker",
                "mss_formula",
                "policy_rule_priority_base",
                "local_route_table",
                "remote_route_table",
                "local_policy_rules",
                "ipv4_policy_rules",
                "forward_rules",
                "mss_rules",
            },
        )
        self.assertIn(
            'mss_formula                = "min(min(underlay_mtu,tailscale_mtu)-40,approved_maximum_tcp_mss)"',
            readiness_contract,
        )

    def test_targets_and_transport_routers_have_distinct_ec2_contracts(self) -> None:
        for site in ("west", "east"):
            target = braced_block(
                self.topology,
                f'resource "aws_instance" "envelope_target_{site}"',
            )
            router = braced_block(
                self.topology,
                f'resource "aws_instance" "transport_router_{site}"',
            )
            self.assertIn("source_dest_check           = true", target)
            self.assertNotIn("source_dest_check           = false", target)
            self.assertIn("source_dest_check           = false", router)
            self.assertNotIn("source_dest_check           = true", router)
            self.assertIn(
                f"user_data_base64            = data.cloudinit_config.target_{site}.rendered",
                target,
            )
            self.assertIn(
                f"user_data_base64            = module.tailscale_transport_{site}[each.key].rendered",
                router,
            )
        self.assertEqual(self.topology.count("source_dest_check           = true"), 2)
        self.assertEqual(self.topology.count("source_dest_check           = false"), 2)
        self.assertIn("snat_subnet_routes = false", self.user_data)
        self.assertNotIn("advertise_routes   = []", self.user_data)
        for site in ("west", "east"):
            self.assertIn(
                f"advertise_routes   = local.initial_transport_router_advertise_routes.{site}[each.key]",
                self.user_data,
            )

    def test_transport_advertisement_mutation_is_generation_fenced(self) -> None:
        for value in (
            "/usr/local/sbin/envelope-transport-advertisements",
            "/usr/bin/flock -x 9",
            "transport-advertisements.state.json",
            "predecessors_json",
            "stale advertisement generation was fenced",
            "an existing advertisement generation has different desired state",
            "--accept-routes=true --snat-subnet-routes=false",
            "--accept-dns=false",
            ".CorpDNS == false",
            "systemctl kill --kill-who=main --signal=SIGKILL tailscaled.service",
            "transport-advertisements.epoch",
            "transport-advertisements.initialized",
            "advertisement state was lost after initialization",
            'readonly initial_generation="initial-$epoch"',
            "recorded advertisement state differs from the live service or preferences",
            "systemctl mask tailscaled.service",
            "systemctl unmask tailscaled.service",
        ):
            self.assertIn(value, self.transport_router)
        self.assertLess(
            self.transport_router.index(
                "stale advertisement generation was fenced"
            ),
            self.transport_router.index(
                "recorded advertisement predecessor differs from the live service or preferences"
            ),
        )
        self.assertLess(
            self.transport_router.index(
                "recorded advertisement predecessor differs from the live service or preferences"
            ),
            self.transport_router.index(
                "/usr/bin/tailscale set --accept-routes=true"
            ),
        )
        advertisements = heredoc(
            self.transport_router,
            "/usr/local/sbin/envelope-transport-advertisements",
        )
        self.assertIn("readonly requested_routes_json=$4", advertisements)
        self.assertNotIn("readonly routes_json=$4", advertisements)
        top_level_readonly = set(
            re.findall(r"^readonly ([a-z_][a-z0-9_]*)=", advertisements, re.MULTILINE)
        )
        function_locals = {
            token.split("=", 1)[0]
            for declaration in re.findall(
                r"^\s+local ([^\n]+)", advertisements, re.MULTILINE
            )
            for token in declaration.split()
            if re.fullmatch(r"[a-z_][a-z0-9_]*(?:=.*)?", token)
        }
        self.assertEqual(top_level_readonly & function_locals, set())
        subprocess.run(
            [
                "bash",
                "-c",
                """set -euo pipefail
readonly requested_generation=11111111-2222-4333-8444-555555555555
readonly requested_routes_json='["10.0.0.0/24"]'
validate_routes() { local routes_json=$1; [[ "$routes_json" == '["10.0.0.0/24"]' ]]; }
write_state() { local generation=$1 routes_json=$2; [[ "$generation" == "$requested_generation" && "$routes_json" == "$requested_routes_json" ]]; }
validate_routes "$requested_routes_json"
write_state "$requested_generation" "$requested_routes_json"
""",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        inspect_start = advertisements.index('if [[ "$operation" == inspect ]]')
        inspect_output = advertisements.index(
            "/usr/bin/jq -c '{success: true, payload: .}' \"$state\"",
            inspect_start,
        )
        verify_actual = advertisements[
            advertisements.index("verify_actual() {") : advertisements.index(
                "\n}\n\nexec 9>", advertisements.index("verify_actual() {")
            )
        ]
        for value in (
            ".CorpDNS == false",
            "] || return 1",
            "systemctl is-active --quiet tailscaled.service || return 1",
            "systemctl is-active --quiet envelope-transport-router-network.service || return 1",
        ):
            self.assertIn(value, verify_actual)
        self.assertLess(
            advertisements.index("verify_actual", inspect_start), inspect_output
        )
        abrupt_kill = advertisements.index(
            "systemctl kill --kill-who=main --signal=SIGKILL tailscaled.service"
        )
        abrupt_mask = advertisements.index(
            "systemctl mask tailscaled.service"
        )
        state_write = advertisements.rindex(
            'write_state "$requested_generation" "$desired_routes" "$desired_service" "$desired_mode"'
        )
        self.assertLess(abrupt_mask, abrupt_kill)
        self.assertLess(abrupt_kill, state_write)
        self.assertIn(
            '[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]', advertisements
        )
        self.assertIn(
            "abrupt transition did not terminate the original tailscaled process",
            advertisements,
        )
        self.assertIn(
            '[[ "$desired_service" == running && "$desired_mode" == normal ]] ||',
            advertisements,
        )
        self.assertIn(
            "an existing advertisement generation differs from live state",
            advertisements,
        )
        self.assertNotIn(
            "systemctl kill --kill-who=main --signal=SIGKILL tailscaled.service >/dev/null 2>&1 || true",
            advertisements,
        )

    @unittest.skipUnless(shutil.which("jq"), "jq is required for helper behavior coverage")
    def test_transport_advertisement_inspection_cannot_mask_dns_preference_failure(self) -> None:
        advertisements = heredoc(
            self.transport_router,
            "/usr/local/sbin/envelope-transport-advertisements",
        )
        start = advertisements.index("verify_actual() {")
        verify_actual = advertisements[start : advertisements.index("\n}\n\nexec 9>", start) + 2]
        verify_actual = verify_actual.replace("/usr/bin/tailscale", "tailscale").replace(
            "/usr/bin/jq", "jq"
        )
        completed = subprocess.run(
            [
                "bash",
                "-c",
                f'''set -euo pipefail
systemctl() {{
  if [[ "$1" == is-enabled ]]; then printf '%s\n' enabled; fi
  return 0
}}
tailscale() {{
  printf '{{"RouteAll":true,"NoSNAT":true,"CorpDNS":%s,"AdvertiseRoutes":["10.10.1.0/24"]}}\n' "$corp_dns"
}}
{verify_actual}
corp_dns=true
if verify_actual '["10.10.1.0/24"]' running normal; then exit 1; fi
corp_dns=false
verify_actual '["10.10.1.0/24"]' running normal
''',
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('[[ "$unit_state" == masked ]]', advertisements)
        self.assertIn(
            '.generation == $initial or (.generation | test(', advertisements
        )

    def test_ha_fleets_preserve_sources_and_expose_runner_route_inputs(self) -> None:
        self.assertEqual(
            self.topology.count("for_each = local.workload_probe_ingress"), 2
        )
        self.assertIn("values(local.workload_roles.east)", self.topology)
        self.assertIn("values(local.workload_roles.west)", self.topology)
        self.assertNotIn(
            'each.key == "responder" ? local.workload_probe_ingress', self.topology
        )
        for output in (
            "workload_instances",
            "gwlb_target_group_arns",
            "symmetric_topology",
            "cost_profile",
        ):
            self.assertIn(f'output "{output}"', self.topology)
        self.assertNotIn('output "instance_ids"', self.topology)
        self.assertEqual(self.topology.count("gwlbe_route_table_id"), 2)
        self.assertGreaterEqual(self.topology.count("network_interface_id"), 4)
        self.assertIn(
            "network_interface_id = aws_instance.transport_router_west[key].primary_network_interface_id",
            self.topology,
        )
        self.assertIn(
            "gwlbe_route_table_id = aws_route_table.gwlbe_west[key].id",
            self.topology,
        )
        self.assertNotIn(
            "aws_instance.envelope_target_west.primary_network_interface_id",
            self.topology,
        )
        self.assertNotIn(
            "aws_instance.envelope_target_east.primary_network_interface_id",
            self.topology,
        )

    def test_targets_use_exact_packet_return_runtime_without_tailnet(self) -> None:
        self.assertNotIn('module "tailscale_target_', self.user_data)
        self.assertEqual(
            self.user_data.count('source             = "./modules/tailscale-cloudinit"'),
            2,
        )
        for site in ("west", "east"):
            target_cloudinit = braced_block(
                self.user_data, f'data "cloudinit_config" "target_{site}"'
            )
            self.assertIn('filename     = "80-envelope-artifact.sh"', target_cloudinit)
            self.assertIn(
                'filename     = "90-envelope-packet-return.sh"', target_cloudinit
            )
            self.assertNotRegex(target_cloudinit, r"(?i)tailscale|\btun\b|forward")

        runtime = braced_block(self.user_data, "packet_return_runtime =")
        assignments = set(
            re.findall(r"(?m)^\s{4}([a-z][a-z0-9_]*)\s*=", runtime)
        )
        self.assertEqual(
            assignments,
            {
                "config_version",
                "mode",
                "udp_bind",
                "max_inner_packet_size",
                "artifact_sha256",
                "artifact_revision",
            },
        )
        self.assertIn('mode                  = "packet-return"', runtime)
        self.assertIn('udp_bind              = "0.0.0.0:6081"', runtime)
        self.assertIn("max_inner_packet_size = 1280", runtime)
        self.assertIn(
            "for site in keys(local.sites) : site => local.packet_return_runtime",
            self.topology,
        )

    def test_target_security_groups_and_routes_are_outer_only(self) -> None:
        for site in ("west", "east"):
            security_group = braced_block(
                self.topology,
                f'resource "aws_security_group" "target_{site}"',
            )
            self.assertIn("from_port   = 6081", security_group)
            self.assertIn("to_port     = 6081", security_group)
            self.assertIn('protocol    = "udp"', security_group)
            self.assertIn("from_port   = 9090", security_group)
            self.assertIn("to_port     = 9090", security_group)
            self.assertNotIn("local_site_cidrs", security_group)
            self.assertNotIn("remote_site_cidrs", security_group)
            target_routes = "\n".join(
                match.group(0)
                for match in re.finditer(
                    rf'(?s)resource "aws_route" "target_[^\"]*{site}".*?\n}}',
                    self.topology,
                )
            )
            self.assertIn('destination_cidr_block = "0.0.0.0/0"', target_routes)
            self.assertNotRegex(target_routes, r"(?:local|remote)_site_cidrs")

    def test_target_bootstrap_is_packet_return_only_and_raw_only(self) -> None:
        for required in (
            "ENVELOPE_CONFIG_VERSION=${config_version}",
            "ENVELOPE_MODE=${mode}",
            "ENVELOPE_UDP_BIND=${udp_bind}",
            "ENVELOPE_MAX_INNER_PACKET_SIZE=${max_inner_packet_size}",
            "After=network-online.target",
            "Wants=network-online.target",
            "AmbientCapabilities=CAP_NET_RAW",
            "CapabilityBoundingSet=CAP_NET_RAW",
            "PrivateDevices=yes",
        ):
            self.assertIn(required, self.bootstrap)
        for prohibited in (
            "CAP_NET_ADMIN",
            "tailscale",
            "ENVELOPE_TUN",
            "ENVELOPE_LOCAL_SITE_CIDRS",
            "ENVELOPE_REMOTE_SITE_CIDRS",
            "ENVELOPE_ROUTING",
            "sysctl",
            "iptables",
            "nft ",
            "TCPMSS",
            "host-network",
            "direct-forward",
        ):
            self.assertNotIn(prohibited, self.bootstrap)
        self.assertNotRegex(
            self.bootstrap,
            r"(?i)\b(?:tun|envelope0|tailscaled?|ip_forward|forward_chain|direct[- ]forward)\b",
        )
        self.assertNotRegex(self.bootstrap, r"(?m)^Requires=")
        self.assertEqual(self.bootstrap.count("CAP_NET_RAW"), 2)

        target_unit = heredoc(
            self.bootstrap, "/etc/systemd/system/envelope.service"
        )
        self.assertIn("User=envelope", target_unit)
        self.assertNotIn("User=root", target_unit)
        self.assertIn("ExecStartPre=/usr/local/sbin/envelope-preflight", target_unit)

        sections = (
            "[packet-return-metrics]",
            "[packet-return-routes]",
            "[packet-return-status]",
            "[bounded-logs]",
        )
        offsets = [self.bootstrap.index(section) for section in sections]
        self.assertEqual(offsets, sorted(offsets))
        allowed_metrics = re.findall(
            r'allowed\["([a-z0-9_]+)"\] = 1', self.bootstrap
        )
        self.assertEqual(len(allowed_metrics), len(set(allowed_metrics)))
        self.assertEqual(
            set(allowed_metrics),
            {
                "geneve_rx_packets",
                "geneve_rx_bytes",
                "geneve_tx_packets",
                "geneve_tx_bytes",
                "drops",
                "geneve_options_validation_errors",
                "gwlb_profile_rejections_total",
                "gwlb_receive_drops_total",
                "gwlb_return_build_failures_total",
                "gwlb_send_failures_total",
                "gwlb_inner_validation_failures_total",
                "gwlb_target_ready",
                "gwlb_target_component_ready",
                "gwlb_target_readiness_transitions_total",
                "gwlb_sender_reinitializations_total",
                "gwlb_mtu_drops_total",
            },
        )
        for obsolete_metric in (
            "decap_errors",
            "encap_errors",
            "gwlb_unsupported_inner_total",
            "datapath_component_healthy",
            "datapath_liveness_transitions_total",
        ):
            self.assertNotIn(f'allowed["{obsolete_metric}"]', self.bootstrap)
        self.assertIn("emitted < 128", self.bootstrap)

    def test_target_groups_use_the_exact_bounded_health_contract(self) -> None:
        expected = {
            "healthy_threshold": "5",
            "interval": "10",
            "path": '"/healthz"',
            "port": '"9090"',
            "protocol": '"HTTP"',
            "timeout": "5",
            "unhealthy_threshold": "2",
        }
        for site in ("west", "east"):
            with self.subTest(site=site):
                target_group = braced_block(
                    self.topology, f'resource "aws_lb_target_group" "{site}"'
                )
                health_check = braced_block(target_group, "health_check")
                assignments = dict(
                    re.findall(
                        r"(?m)^\s+([a-z_]+)\s*=\s*([^\n]+)$", health_check
                    )
                )
                self.assertEqual(assignments, expected)

    def test_transport_firewall_is_owned_fail_closed_and_activated_live(self) -> None:
        host_network = heredoc(
            self.transport_router,
            "/usr/local/sbin/envelope-transport-router-network",
        )
        for required in (
            "readonly forward_chain='ENVELOPE-TRANSPORT-FORWARD'",
            "readonly mss_chain='ENVELOPE-TRANSPORT-MSS'",
            "readonly firewall_state=/var/lib/envelope/transport-router-firewall.owner",
            "readonly policy_state=/var/lib/envelope/transport-router-policy-rules.owner",
            "unrelated $binary $table FORWARD state exists; refusing to flush it",
            "owned firewall state belongs to a different transport contract",
            "owned IPv4 policy rules belong to a different transport contract",
            "unclaimed transport firewall chains already exist",
            "unrelated or conflicting IPv4 policy rule state exists",
        ):
            self.assertIn(required, host_network)

        stage_firewall = braced_block(host_network, "stage_firewall()")
        for required in (
            "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=0",
            "/usr/sbin/sysctl -q -w net.ipv6.conf.all.forwarding=0",
            "/usr/sbin/sysctl -q -w net.ipv6.conf.default.forwarding=0",
            'assert_owned_hook /usr/sbin/iptables filter DROP "-A FORWARD -j $forward_chain"',
            'assert_owned_hook /usr/sbin/iptables mangle ACCEPT "-A FORWARD -j $mss_chain"',
            'assert_owned_hook /usr/sbin/ip6tables filter DROP "-A FORWARD -j $forward_chain"',
            'assert_owned_hook /usr/sbin/ip6tables mangle ACCEPT ""',
            "/usr/sbin/iptables --wait 10 -P FORWARD DROP",
            "/usr/sbin/iptables --wait 10 -t mangle -P FORWARD ACCEPT",
            "/usr/sbin/ip6tables --wait 10 -P FORWARD DROP",
            "/usr/sbin/ip6tables --wait 10 -t mangle -P FORWARD ACCEPT",
            'configure_chain /usr/sbin/iptables filter "$forward_chain"',
            'configure_chain /usr/sbin/iptables mangle "$mss_chain"',
            'configure_chain /usr/sbin/ip6tables filter "$forward_chain"',
            '/usr/sbin/iptables --wait 10 -A FORWARD -j "$forward_chain"',
            '/usr/sbin/iptables --wait 10 -t mangle -A FORWARD -j "$mss_chain"',
            '/usr/sbin/ip6tables --wait 10 -A FORWARD -j "$forward_chain"',
        ):
            self.assertIn(required, stage_firewall)
        self.assertEqual(
            stage_firewall.count("assert_no_nat /usr/sbin/iptables"), 2
        )
        self.assertEqual(
            stage_firewall.count("assert_no_nat /usr/sbin/ip6tables"), 2
        )
        self.assertLess(
            stage_firewall.index("claim_firewall_state"),
            stage_firewall.index("/usr/sbin/iptables --wait 10 -P FORWARD DROP"),
        )
        self.assertLess(
            stage_firewall.index("/usr/sbin/iptables --wait 10 -P FORWARD DROP"),
            stage_firewall.index(
                '/usr/sbin/iptables --wait 10 -A FORWARD -j "$forward_chain"'
            ),
        )

        policy_rule = braced_block(
            self.user_data,
            "for index, cidr in sort(topology.local_site_cidrs) :",
        )
        self.assert_assignment_set(
            policy_rule,
            10,
            {
                "priority",
                "input",
                "source",
                "destination",
                "fwmark",
                "table",
                "action",
            },
        )
        self.assertIn(
            '$cidrs | to_entries | map({priority: ($base + .key), input: $interface, source: "all", destination: .value, fwmark: 0, table: "main", action: "lookup"})',
            host_network,
        )
        for exact_selector in (
            '["priority", "src", "srclen", "dst", "dstlen", "fwmark", "fwmask", "iif", "table", "action", "protocol"] as $allowed',
            "if all(.[]; ((keys - $allowed) | length) == 0)",
            "([ $expected[] | select(. == $actual) ] | length) == 1",
            "([ $live[] | select(. == $wanted) ] | length) as $count",
            "if $require_all then $count == 1 else $count <= 1 end",
            "else $count == 1",
        ):
            self.assertIn(exact_selector, host_network)
        self.assertEqual(
            host_network.count("/usr/sbin/ip -4 rule add priority"), 1
        )
        self.assertIn(
            '/usr/sbin/ip -4 rule add priority "$priority" iif "$tailscale" \\\n'
            '        to "$${local_site_cidrs[$index]}" lookup main',
            host_network,
        )
        self.assertNotIn("from all lookup main", host_network)

        pair_start = host_network.index(
            'for local_cidr in "$${local_site_cidrs[@]}"; do'
        )
        pair_end = host_network.index(
            "\nassert_no_nat /usr/sbin/iptables", pair_start
        )
        pair_rules = host_network[pair_start:pair_end]
        self.assertIn(
            'for remote_cidr in "$${remote_site_cidrs[@]}"; do', pair_rules
        )
        accept_selectors = re.findall(
            r'(?m)^\s*/usr/sbin/iptables --wait 10 -A "\$forward_chain" \\\n\s+(.+ -j ACCEPT)$',
            pair_rules,
        )
        self.assertEqual(
            set(accept_selectors),
            {
                '-i "$underlay" -o "$tailscale" -s "$local_cidr" -d "$remote_cidr" -j ACCEPT',
                '-i "$tailscale" -o "$underlay" -s "$remote_cidr" -d "$local_cidr" -j ACCEPT',
            },
        )
        self.assertEqual(len(accept_selectors), 2)
        self.assertEqual(host_network.count("-j ACCEPT"), 2)
        for mss_rule in (
            '/usr/sbin/iptables --wait 10 -t mangle -A "$mss_chain" \\\n'
            '      -i "$underlay" -o "$tailscale" -s "$local_cidr" -d "$remote_cidr" \\\n'
            '      -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$ipv4_mss"',
            '/usr/sbin/iptables --wait 10 -t mangle -A "$mss_chain" \\\n'
            '      -i "$tailscale" -o "$underlay" -s "$remote_cidr" -d "$local_cidr" \\\n'
            '      -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$ipv4_mss"',
        ):
            self.assertIn(mss_rule, pair_rules)
        self.assertEqual(pair_rules.count("-j TCPMSS"), 2)
        self.assertEqual(host_network.count("-j TCPMSS"), 2)
        self.assertIn(
            '/usr/sbin/iptables --wait 10 -t mangle -A "$mss_chain" -j RETURN',
            pair_rules,
        )
        self.assertNotRegex(
            pair_rules,
            r'-i "\$(?:underlay|tailscale)" -o "\$(?:underlay|tailscale)" -j ACCEPT',
        )

        for mss_derivation in (
            'underlay_mtu=$(interface_mtu "$underlay")',
            'tailscale_mtu=$(interface_mtu "$tailscale")',
            "path_mtu=$underlay_mtu",
            "if (( tailscale_mtu < path_mtu )); then path_mtu=$tailscale_mtu; fi",
            "live_mtu_allowance=$((path_mtu - 40))",
            "ipv4_mss=$live_mtu_allowance",
            "if (( approved_maximum_tcp_mss < ipv4_mss )); then ipv4_mss=$approved_maximum_tcp_mss; fi",
            "(( ipv4_mss >= 536 && ipv4_mss <= approved_maximum_tcp_mss ))",
            "mss_rules: [$expectations.mss_rules[] + {mss: $tcp_mss}]",
            "approved_maximum_tcp_mss: $expectations.approved_maximum_tcp_mss",
        ):
            self.assertIn(mss_derivation, host_network)

        self.assertIn(".ipv6_forwarding == false", host_network)
        self.assertIn(".ipv6_filter_forward_policy == \"DROP\"", host_network)
        self.assertIn("ipv6_forwarding: false", host_network)
        self.assertNotIn("net.ipv6.conf.all.forwarding=1", host_network)
        self.assertNotIn("net.ipv6.conf.default.forwarding=1", host_network)
        self.assertIn("net.ipv6.conf.all.forwarding = 0", self.transport_router)
        self.assertIn(
            "net.ipv6.conf.default.forwarding = 0", self.transport_router
        )
        self.assertNotRegex(
            self.transport_router,
            r"net\.ipv6\.conf\.(?:all|default)\.forwarding\s*=\s*1",
        )
        self.assertNotRegex(
            host_network,
            r"(?m)^\s*/usr/sbin/ip6tables[^\n]*(?:\\\n\s+[^\n]*)*-j ACCEPT",
        )

        for prohibited in (
            "nft flush ruleset",
            "-j SNAT",
            "-j MASQUERADE",
            "--clamp-mss-to-pmtu",
            "ENVELOPE-INGRESS-FORWARD",
            "ENVELOPE-INGRESS-MSS",
        ):
            self.assertNotIn(prohibited, host_network)
        self.assertNotRegex(
            host_network,
            r"/usr/sbin/ip6?tables --wait 10 (?!-t mangle )-P FORWARD ACCEPT",
        )
        self.assertIn('"$binary" --wait 10 -t nat -S', host_network)
        self.assertIn("transport router must not contain NAT rules", host_network)
        self.assertIn("nat_rules: []", host_network)
        self.assertIn("no_nat: true", host_network)
        self.assertNotRegex(
            host_network,
            r"(?m)^\s*/usr/sbin/ip6?tables[^\n]* -t nat [^\n]* -(?:A|I|R)\b",
        )
        self.assertNotRegex(
            host_network,
            r'(?m)^\s*(?:"\$binary"|/usr/sbin/ip6?tables)[^\n]* -F(?:\s*$|\s+FORWARD(?:\s|$))',
        )
        self.assertNotRegex(
            host_network,
            r"(?im)^\s*/usr/sbin/nft\b[^\n]*\bflush\s+(?:ruleset|table)\b",
        )

        stage = host_network.index("\nstage_firewall\n")
        staged_exit = host_network.index('if [[ "$mode" == stage ]]', stage)
        wait_for_tailscale = host_network.index(
            "tailscale0 must be live before transport firewall setup"
        )
        reconcile_policy = host_network.index("\nreconcile_policy_rules\n")
        read_live_mtu = host_network.index(
            'tailscale_mtu=$(interface_mtu "$tailscale")'
        )
        install_prefix_rules = host_network.index(
            'for local_cidr in "$${local_site_cidrs[@]}"; do'
        )
        write_runtime_state = host_network.index("state_tmp=$(/usr/bin/mktemp")
        enable_forwarding = host_network.rindex(
            "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1"
        )
        self.assertLess(stage, staged_exit)
        self.assertLess(staged_exit, wait_for_tailscale)
        self.assertLess(wait_for_tailscale, reconcile_policy)
        self.assertLess(wait_for_tailscale, read_live_mtu)
        self.assertLess(read_live_mtu, install_prefix_rules)
        self.assertLess(install_prefix_rules, write_runtime_state)
        self.assertLess(write_runtime_state, enable_forwarding)
        self.assertEqual(
            host_network.count("/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1"),
            1,
        )

    def test_transport_capabilities_exist_only_in_transport_unit(self) -> None:
        unit_path = "/etc/systemd/system/envelope-transport-router-network.service"
        unit = heredoc(self.transport_router, unit_path)
        for required in (
            "After=network-online.target tailscaled.service",
            "Requires=tailscaled.service",
            "PartOf=tailscaled.service",
            "User=root",
            "ExecStart=/usr/local/sbin/envelope-transport-router-network",
            "ExecReload=/usr/local/sbin/envelope-transport-router-network",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
            "RemainAfterExit=yes",
            "ReadWritePaths=/run/envelope-transport-router-network",
        ):
            self.assertIn(required, unit)
        outside_unit = self.transport_router.replace(unit, "")
        self.assertNotIn("CAP_NET_ADMIN", outside_unit)
        self.assertNotIn("CAP_NET_RAW", outside_unit)
        self.assertEqual(self.transport_router.count("CAP_NET_ADMIN"), 2)
        self.assertEqual(self.transport_router.count("CAP_NET_RAW"), 2)

    def test_transport_activation_runs_after_tailscale_setup(self) -> None:
        pre_setup = self.tailscale_module.index('for_each = var.pre_setup_parts')
        setup = self.tailscale_module.index('filename     = "20-setup-tailscale.sh"')
        additional = self.tailscale_module.index('for_each = var.additional_parts')
        self.assertLess(pre_setup, setup)
        self.assertLess(setup, additional)
        self.assertEqual(
            self.user_data.count('filename = "15-transport-router.sh"'), 2
        )
        self.assertEqual(
            self.user_data.count(
                'pre_setup_gate = "/var/lib/envelope/transport-router-network.installed"'
            ),
            2,
        )
        self.assertEqual(
            self.user_data.count(
                'filename = "30-activate-transport-router.sh"'
            ),
            2,
        )
        activation = assigned_heredoc(self.user_data, "transport_router_activation")
        enabled = activation.index(
            "systemctl is-enabled --quiet envelope-transport-router-network.service"
        )
        tailscaled = activation.index(
            "systemctl is-active --quiet tailscaled.service"
        )
        stop = activation.index(
            "\n    systemctl stop envelope-transport-router-network.service"
        )
        reset = activation.index(
            "systemctl reset-failed envelope-transport-router-network.service"
        )
        start = activation.index(
            "systemctl start --no-block envelope-transport-router-network.service"
        )
        self.assertLess(enabled, tailscaled)
        self.assertLess(tailscaled, stop)
        self.assertLess(stop, reset)
        self.assertLess(reset, start)
        self.assertNotIn(
            "systemctl restart envelope-transport-router-network.service", activation
        )

        unit = heredoc(
            self.transport_router,
            "/etc/systemd/system/envelope-transport-router-network.service",
        )
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("RestartSec=10s", unit)

        stage = self.transport_router.rindex(
            "/usr/local/sbin/envelope-transport-router-network stage"
        )
        staged_gate = self.transport_router.rindex(
            "touch /var/lib/envelope/transport-router-network.installed"
        )
        self.assertLess(stage, staged_gate)
        self.assertNotRegex(
            self.transport_router, r"(?m)^\s*(?:/usr/bin/)?tailscale up\b"
        )
        self.assertNotIn("enable --now", self.transport_router)
        self.assertIn("required pre-setup gate did not complete", self.tailscale_setup)
        self.assertIn("--accept-dns=false", self.tailscale_setup)
        gate_check = self.tailscale_setup.index(
            'if [[ -n "$pre_setup_gate" && ! -f "$pre_setup_gate" ]]'
        )
        start_tailscaled = self.tailscale_setup.index(
            "/usr/bin/systemctl enable --now tailscaled.service"
        )
        tailscale_up = self.tailscale_setup.index("/usr/bin/tailscale up")
        self.assertLess(gate_check, start_tailscaled)
        self.assertLess(start_tailscaled, tailscale_up)

    def test_transport_security_groups_accept_only_exact_preserved_sources(self) -> None:
        self.assertIn(
            "local.ipv4_network_bounds[topology.vpc_cidr].first + 2",
            self.topology,
        )
        for site in ("west", "east"):
            security_group = braced_block(
                self.topology,
                f'resource "aws_security_group" "transport_{site}"',
            )
            self.assertIn(
                f"for_each = toset(local.sites.{site}.local_site_cidrs)",
                security_group,
            )
            self.assertIn(
                'description = "Preserved-source transit from ${ingress.value}"',
                security_group,
            )
            self.assertIn("cidr_blocks = [ingress.value]", security_group)
            self.assertNotIn("remote_site_cidrs", security_group)

    def test_iam_separates_target_workload_and_transport_authority(self) -> None:
        runtime_policy = braced_block(self.iam, "runtime_policy =")
        workload_policy = braced_block(self.iam, "workload_policy =")
        transport_policy = braced_block(self.iam, "transport_policy =")
        flow_policy = braced_block(self.iam, "flow_log_delivery_policy =")
        self.assertNotIn("ssm:GetParameter", runtime_policy)
        self.assertNotIn("kms:Decrypt", runtime_policy)
        self.assertEqual(runtime_policy.count("s3:GetObject"), 2)
        self.assertEqual(runtime_policy.count("local.ssm_core_actions"), 2)

        self.assertEqual(workload_policy.count("local.ssm_core_actions"), 1)
        for prohibited in (
            "s3:GetObject",
            "ssm:GetParameter",
            "kms:Decrypt",
            "ec2:ReplaceRoute",
        ):
            self.assertNotIn(prohibited, workload_policy)

        self.assertEqual(transport_policy.count("ssm:GetParameter"), 2)
        self.assertEqual(transport_policy.count("kms:Decrypt"), 2)
        self.assertEqual(transport_policy.count("local.ssm_core_actions"), 2)
        self.assertNotIn("s3:GetObject", transport_policy)
        self.assertNotIn("ec2:ReplaceRoute", self.iam)
        self.assertNotIn("aws_cloudwatch_log_group.flow_west.arn", flow_policy)
        self.assertNotIn("aws_cloudwatch_log_group.flow_east.arn", flow_policy)
        for site, region in (("west", "west"), ("east", "east")):
            self.assertIn(
                f"arn:aws:logs:${{var.{region}_region}}:${{data.aws_caller_identity.current.account_id}}:"
                f"log-group:${{aws_cloudwatch_log_group.flow_{site}.name}}:*",
                flow_policy,
            )

        actions_start = self.iam.index("ssm_core_actions = [")
        actions_end = self.iam.index("]", actions_start)
        actions_text = self.iam[actions_start:actions_end]
        ssm_core_actions = re.findall(
            r'"([A-Za-z0-9]+:[A-Za-z0-9]+)"',
            actions_text,
        )
        self.assertEqual(
            len(ssm_core_actions), len(re.findall(r'"[^"]+"', actions_text))
        )
        self.assertEqual(len(ssm_core_actions), len(set(ssm_core_actions)))
        self.assertEqual(
            set(ssm_core_actions),
            {
                "ec2messages:AcknowledgeMessage",
                "ec2messages:DeleteMessage",
                "ec2messages:FailMessage",
                "ec2messages:GetEndpoint",
                "ec2messages:GetMessages",
                "ec2messages:SendReply",
                "ssm:DescribeAssociation",
                "ssm:DescribeDocument",
                "ssm:GetDeployablePatchSnapshotForInstance",
                "ssm:GetDocument",
                "ssm:GetManifest",
                "ssm:ListAssociations",
                "ssm:ListInstanceAssociations",
                "ssm:PutComplianceItems",
                "ssm:PutConfigurePackageResult",
                "ssm:PutInventory",
                "ssm:UpdateAssociationStatus",
                "ssm:UpdateInstanceAssociationStatus",
                "ssm:UpdateInstanceInformation",
                "ssmmessages:CreateControlChannel",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel",
            },
        )

        for kind in (
            "aws_iam_role",
            "aws_iam_role_policy",
            "aws_iam_instance_profile",
        ):
            for profile in ("runtime", "workload", "transport"):
                for site in ("west", "east"):
                    self.assertEqual(
                        self.iam.count(f'resource "{kind}" "{profile}_{site}"'),
                        1,
                    )

        for site in ("west", "east"):
            workload = braced_block(
                self.topology, f'resource "aws_instance" "workload_{site}"'
            )
            self.assertIn(
                f"iam_instance_profile        = aws_iam_instance_profile.workload_{site}.name",
                workload,
            )
            self.assertIn(f"aws_iam_role_policy.workload_{site}", workload)
            self.assertNotIn("aws_iam_instance_profile.runtime_", workload)
            self.assertNotIn("aws_iam_instance_profile.transport_", workload)

    def test_mocked_tests_cover_exact_and_negative_contracts(self) -> None:
        runs = re.findall(r'(?m)^run "([a-z0-9_]+)" \{$', self.tests)
        self.assertEqual(len(runs), len(set(runs)))
        self.assertEqual(
            set(runs),
            {
                "symmetric_two_az_paths",
                "reject_incomplete_target_fleet",
                "reject_incomplete_transport_fleet",
                "reject_obsolete_target_routing_field",
                "reject_partial_site_cidr_overlap",
                "reject_vpc_resolver_overlap",
                "reject_route_domain_loop",
                "reject_unapproved_cost",
                "reject_unreviewed_tailscale_version",
                "reject_unsafe_shell_interpolation",
                "reject_unsafe_shell_name",
                "reject_unsafe_shell_tag",
                "reject_unsafe_shell_arn",
                "reject_foreign_route_failover_selection",
                "reject_cross_az_route_failover_selection",
                "reject_unbounded_route_failover",
                "reject_route_failover_compatibility_alias",
                "distinct_transport_enis_and_same_az_initial_routes",
                "reject_duplicate_target_fleet_az",
                "reject_duplicate_transport_fleet_az",
                "reject_too_short_restoration_timeout",
                "reject_recovery_not_exceeding_quiet_window",
                "reject_duplicate_transport_enis",
            },
        )

        negative_failures = {
            "reject_incomplete_target_fleet": "var.symmetric_topology",
            "reject_incomplete_transport_fleet": "var.symmetric_topology",
            "reject_obsolete_target_routing_field": "var.symmetric_topology",
            "reject_partial_site_cidr_overlap": "terraform_data.input_validation",
            "reject_vpc_resolver_overlap": "terraform_data.input_validation",
            "reject_route_domain_loop": "terraform_data.input_validation",
            "reject_unapproved_cost": "terraform_data.input_validation",
            "reject_unreviewed_tailscale_version": "var.tailscale_version",
            "reject_unsafe_shell_interpolation": "var.artifact_revision",
            "reject_unsafe_shell_name": "var.name",
            "reject_unsafe_shell_tag": "var.tailscale_tag",
            "reject_unsafe_shell_arn": "var.west_tailscale_secret_arn",
            "reject_foreign_route_failover_selection": "var.symmetric_topology",
            "reject_cross_az_route_failover_selection": "var.symmetric_topology",
            "reject_unbounded_route_failover": "var.symmetric_topology",
            "reject_route_failover_compatibility_alias": "var.symmetric_topology",
        }
        for run, expected_failure in negative_failures.items():
            run_block = braced_block(self.tests, f'run "{run}"')
            self.assertIn("command = plan", run_block)
            self.assertIn(
                f"expect_failures = [{expected_failure}]", run_block
            )

        for run, mutation in (
            ("reject_obsolete_target_routing_field", 'tun_name = "envelope0"'),
            ("reject_foreign_route_failover_selection", 'b = "east-a"'),
            ("reject_cross_az_route_failover_selection", 'west = { a = "b", b = "a" }'),
            ("reject_unbounded_route_failover", "restoration_timeout_seconds = 7201"),
            (
                "reject_route_failover_compatibility_alias",
                "initial_transport_router_az_keys =",
            ),
        ):
            self.assertIn(mutation, braced_block(self.tests, f'run "{run}"'))

        for expectation in (
            "raw own-IP packet-return targets must retain source/destination checks while transport routers disable them",
            "target runtime output must be the exact version-2 packet-return contract",
            "workloads must use separate SSM-core-only profiles with no artifact or Tailnet secret access",
            "only per-site transport profiles may resolve and decrypt Tailnet credentials",
            "post-inspection routes must cover every exact AZ and remote-prefix pair",
            "GWLBE route tables must route only exact remote-site prefixes after inspection",
            "every GWLBE AZ must have an explicit reviewed same-AZ initial transport-router selection",
            "transport bootstrap must own exact filter/mangle policies, audit complete protected policy and route paths, recover after tailscaled restarts, keep IPv6 disabled, avoid NAT, and cap live-MTU MSS",
            "transport readiness output must expose exact built-in policies, complete live IPv4 policy expectations, selected route tables, CIDRs, prefix-pair firewall selectors, MSS ceiling, recovery gate, and disabled IPv6/NAT state",
            "packet-return targets must have no Tailnet, firewall-transit, forwarding, or routing-manager bootstrap",
            "target diagnostics must allowlist every exact current Go metric and no obsolete datapath metric",
            "every GWLBE remote route must resolve its explicit same-AZ initial transport ENI",
        ):
            self.assertIn(expectation, self.tests)
        self.assertNotIn(
            "transport bootstrap must preserve unrelated firewall state, fail closed",
            self.tests,
        )
        self.assert_literal_set(
            self.tests,
            "toset(keys(runtime)) == toset(",
            {
                "config_version",
                "mode",
                "udp_bind",
                "max_inner_packet_size",
                "artifact_sha256",
                "artifact_revision",
            },
        )
        self.assert_literal_set(
            self.tests,
            "toset(keys(router)) == toset(",
            {
                "region",
                "az_key",
                "instance_id",
                "network_interface_id",
                "gwlbe_route_table_id",
                "advertised_prefix",
            },
        )
        self.assertIn("transport_router_fleet", self.tests)
        self.assertIn("transport_routers", self.tests)
        for site in ("west", "east"):
            self.assertIn(
                f"route.network_interface_id == aws_instance.transport_router_{site}[local.route_failover.initial_transport_router_az_by_gwlbe_az.{site}[split(\":\", key)[0]]].primary_network_interface_id",
                self.tests,
            )


if __name__ == "__main__":
    unittest.main()
