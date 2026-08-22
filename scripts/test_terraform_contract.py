#!/usr/bin/env python3

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TF = ROOT / "example" / "terraform"


class SymmetricTerraformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.variables = (TF / "variables.tf").read_text()
        cls.topology = (TF / "topology.tf").read_text()
        cls.user_data = (TF / "user_data.tf").read_text()
        cls.bootstrap = (TF / "cloud-init" / "bootstrap.sh.tftpl").read_text()
        cls.tests = (TF / "tests" / "appliance.tftest.hcl").read_text()

    def test_versioned_two_site_schema_requires_two_az_fleets(self):
        self.assertIn('variable "symmetric_topology"', self.variables)
        self.assertIn("version == 2", self.variables)
        self.assertIn("local_site_cidrs", self.variables)
        self.assertIn("remote_site_cidrs", self.variables)
        self.assertIn("target_az_keys", self.variables)
        self.assertIn("ingress_router_az_keys", self.variables)
        self.assertIn("length(site.azs) == 2", self.variables)
        self.assertIn("target_az_keys == toset(keys(site.azs))", self.variables)
        self.assertIn("ingress_router_az_keys == toset(keys(site.azs))", self.variables)
        self.assertNotIn("appliance_target_count", self.variables)
        self.assertNotIn("gwlb_return_cidrs", self.variables)

    def test_route_domains_and_exact_endpoint_routes_are_separate(self):
        for role in ("workload", "ingress", "gwlbe", "target", "management"):
            self.assertIn(f'aws_route_table" "{role}_west', self.topology)
            self.assertIn(f'aws_route_table" "{role}_east', self.topology)
        self.assertIn('resource "aws_route" "workload_to_remote_west"', self.topology)
        self.assertIn('resource "aws_route" "workload_default_west"', self.topology)
        self.assertIn('resource "aws_route" "workload_default_east"', self.topology)
        self.assertIn('resource "aws_route" "ingress_to_local_west"', self.topology)
        self.assertIn("setproduct", self.topology)
        self.assertNotIn("network_interface_id", self.topology)

    def test_ha_fleets_are_az_spread_and_preserve_sources(self):
        self.assertIn('resource "aws_vpc_endpoint" "west"', self.topology)
        self.assertIn('resource "aws_instance" "envelope_target_west"', self.topology)
        self.assertIn('resource "aws_instance" "tailnet_ingress_west"', self.topology)
        self.assertIn('resource "aws_instance" "workload_west"', self.topology)
        self.assertIn('resource "aws_security_group" "workload_west"', self.topology)
        self.assertIn('output "workload_instances"', self.topology)
        self.assertIn('output "gwlb_target_group_arns"', self.topology)
        self.assertIn('output "instance_ids"', self.topology)
        self.assertEqual(self.topology.count("source_dest_check           = false"), 4)
        self.assertIn("snat_subnet_routes = false", self.user_data)
        self.assertIn("advertise_routes   = []", self.user_data)
        self.assertIn("config_version        = var.symmetric_topology.version", self.topology)
        self.assertIn("local_site_cidrs      = join", self.topology)
        self.assertIn("remote_site_cidrs     = join", self.topology)
        self.assertIn("ENVELOPE_CONFIG_VERSION=${config_version}", self.bootstrap)
        self.assertIn("ENVELOPE_LOCAL_SITE_CIDRS=${local_site_cidrs}", self.bootstrap)
        self.assertIn("ENVELOPE_REMOTE_SITE_CIDRS=${remote_site_cidrs}", self.bootstrap)
        self.assertNotIn("aws_instance.envelope_target_west.primary_network_interface_id", self.topology)

    def test_mocked_fresh_and_negative_coverage_exists(self):
        self.assertIn('run "symmetric_two_az_paths"', self.tests)
        self.assertIn('run "reject_incomplete_target_fleet"', self.tests)
        self.assertIn("every enabled AZ must have a GWLBE", self.tests)
        self.assertIn("target route tables must not target a GWLBE", self.tests)


if __name__ == "__main__":
    unittest.main()
