#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_appliance as appliance  # noqa: E402
import aws_two_region_e2e as e2e  # noqa: E402


def topology_document() -> dict:
    def site(name: str, region: str, prefix: str, peer: str, serial: int) -> dict:
        target_group = f"arn:aws:elasticloadbalancing:{region}:123456789012:targetgroup/{name}/0123456789abcdef"
        return {
            "region": region,
            "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"],
            "remote_site_cidrs": [f"{peer}.1.0/24", f"{peer}.2.0/24"],
            "target_fleet": [
                {"region": region, "az_key": "a", "instance_id": f"i-0{serial}23456789abcdef", "target_group_arn": target_group},
                {"region": region, "az_key": "b", "instance_id": f"i-1{serial}23456789abcdef", "target_group_arn": target_group},
            ],
            "ingress_router_fleet": [
                {"region": region, "az_key": "a", "instance_id": f"i-2{serial}23456789abcdef"},
                {"region": region, "az_key": "b", "instance_id": f"i-3{serial}23456789abcdef"},
            ],
        }

    return {
        "config_version": 2,
        "run_id": "symmetric-fixture",
        "sites": {
            "west": site("west", "us-west-2", "10.10", "10.20", 1),
            "east": site("east", "us-east-1", "10.20", "10.10", 5),
        },
    }


def readiness_document(topology: e2e.SymmetricTopologyV2) -> dict:
    return {
        "tailnet_policy_valid": True,
        "sites": {
            site: {
                "route_domains": {"workload": True, "ingress_router": True, "target": True},
                "targets": {member.instance_id: True for member in topology.site(site).target_fleet},
                "ingress_routers": {member.instance_id: True for member in topology.site(site).ingress_router_fleet},
            }
            for site in e2e.SITES
        },
    }


def evidence_document() -> dict:
    topology = e2e.parse_symmetric_topology_v2(topology_document())
    return {
        "schema": 3,
        "kind": "aws-symmetric-gwlb-ha-v2",
        "run_id": topology.run_id,
        "generated_at": "2026-08-22T12:00:00Z",
        "topology": topology.as_dict(),
        "preflight": readiness_document(topology),
        "traversals": [
            {
                "source_site": "west", "destination_site": "east", "gwlbe_id": "vpce-0123456789abcdef0",
                "target_id": topology.west.target_fleet[0].instance_id,
                "ingress_router_id": topology.east.ingress_router_fleet[0].instance_id,
                "protocols": ["icmp", "tcp", "udp"], "source_preserved": True,
            },
            {
                "source_site": "east", "destination_site": "west", "gwlbe_id": "vpce-1123456789abcdef0",
                "target_id": topology.east.target_fleet[0].instance_id,
                "ingress_router_id": topology.west.ingress_router_fleet[0].instance_id,
                "protocols": ["icmp", "tcp", "udp"], "source_preserved": True,
            },
        ],
        "recoveries": [
            {"kind": "target", "site": "west", "failed_id": topology.west.target_fleet[0].instance_id, "alternate_id": topology.west.target_fleet[1].instance_id, "new_flow_succeeded": True, "recovery_duration_ms": 250},
            {"kind": "ingress-router", "site": "east", "failed_id": topology.east.ingress_router_fleet[0].instance_id, "alternate_id": topology.east.ingress_router_fleet[1].instance_id, "new_flow_succeeded": True, "recovery_duration_ms": 500},
        ],
        "transport": {"established_tcp_outcome": "interrupted", "udp_sent": 100, "udp_received": 95, "udp_loss_percent": 5.0},
        "health_transitions": [
            {"kind": "target", "member_id": topology.west.target_fleet[0].instance_id, "states": ["healthy", "unavailable", "healthy"]},
            {"kind": "ingress-router", "member_id": topology.east.ingress_router_fleet[0].instance_id, "states": ["healthy", "unavailable", "healthy"]},
        ],
        "residual_audit": {"passed": True, "owned_resources_remaining": 0},
    }


class Adapter:
    def __init__(self, replacement: bool = False) -> None:
        self.calls: list[str] = []
        self.replacement = replacement

    def owned(self, member: e2e.SymmetricFleetMember, run_id: str) -> bool:
        self.calls.append("owned")
        return run_id == "symmetric-fixture"

    def command(self, member: e2e.SymmetricFleetMember, command: str) -> dict:
        self.calls.append(command)
        return {}

    def deregister(self, member: e2e.SymmetricFleetMember) -> dict:
        self.calls.append("deregister")
        return {}

    def target_health(self, member: e2e.SymmetricFleetMember) -> str:
        self.calls.append("health")
        return "unhealthy" if self.replacement else "healthy"

    def replace(self, member: e2e.SymmetricFleetMember) -> e2e.SymmetricFleetMember:
        self.calls.append("replace")
        return e2e.SymmetricFleetMember(member.site, "target", member.region, member.az_key, "i-ff23456789abcdef", member.target_group_arn)


class SymmetricTopologyTest(unittest.TestCase):
    def test_topology_and_preflight_fail_closed(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        self.assertEqual(e2e.validate_symmetric_preflight(topology, readiness_document(topology))["config_version"], 2)
        invalid = readiness_document(topology)
        invalid["sites"]["west"]["route_domains"]["target"] = False
        with self.assertRaisesRegex(e2e.ReadinessError, "route-domain"):
            e2e.validate_symmetric_preflight(topology, invalid)
        invalid_topology = topology_document()
        invalid_topology["sites"]["west"]["remote_site_cidrs"] = ["10.10.1.0/24"]
        with self.assertRaisesRegex(e2e.DeploymentError, "overlap|peer"):
            e2e.parse_symmetric_topology_v2(invalid_topology)

    def test_dry_run_has_no_adapter_side_effects_and_failure_restarts_quiesced_target(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        target = topology.west.target_fleet[0]
        adapter = Adapter()
        dry = e2e.SymmetricLifecycle(topology, adapter, dry_run=True)
        self.assertTrue(dry.quiesce_target(target)["dry_run"])
        self.assertTrue(dry.fail_ingress_router(topology.east.ingress_router_fleet[0], graceful=True)["dry_run"])
        self.assertEqual(
            dry.probe_identities("west", target.instance_id, topology.east.ingress_router_fleet[0].instance_id)["destination_site"],
            "east",
        )
        self.assertEqual(dry.observe_new_flow_recovery(lambda: True, timeout_seconds=1), 1)
        self.assertEqual(adapter.calls, [])
        live = e2e.SymmetricLifecycle(topology, Adapter(replacement=True), dry_run=False)
        with self.assertRaisesRegex(e2e.ResilienceError, "distinct healthy"):
            live.replace_target_instance(target)
        self.assertIn("systemctl start envelope.service", live.adapter.calls)

    def test_evidence_requires_both_recovery_classes_and_redacts_unsafe_values(self) -> None:
        document = evidence_document()
        self.assertEqual(e2e.validate_evidence(document)["schema"], 3)
        missing = copy.deepcopy(document)
        missing["recoveries"] = missing["recoveries"][:1]
        with self.assertRaisesRegex(e2e.EvidenceError, "target and ingress-router"):
            e2e.validate_evidence(missing)
        unsafe = copy.deepcopy(document)
        unsafe["residual_audit"]["token"] = "tskey-secret-value"
        with self.assertRaisesRegex(e2e.EvidenceError, "unsupported|unsafe"):
            e2e.validate_evidence(unsafe)


class SymmetricConfigTest(unittest.TestCase):
    def test_run_config_requires_v2_symmetric_topology_and_rejects_directional_fields(self) -> None:
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        def site(region: str, prefix: str, peer: str) -> dict:
            azs = {"a": f"{region}a", "b": f"{region}b"}
            return {"region": region, "ami_id": "ami-0123456789abcdef0", "ssm_kms_key_arn": f"arn:aws:kms:{region}:123456789012:key/fixture", "azs": azs, "vpc_cidr": f"{prefix}.0.0/16", "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"], "remote_site_cidrs": [f"{peer}.1.0/24", f"{peer}.2.0/24"], "workload_subnet_cidrs": {"a": f"{prefix}.1.0/24", "b": f"{prefix}.2.0/24"}, "ingress_subnet_cidrs": {"a": f"{prefix}.3.0/24", "b": f"{prefix}.4.0/24"}, "gwlbe_subnet_cidrs": {"a": f"{prefix}.5.0/24", "b": f"{prefix}.6.0/24"}, "gwlb_subnet_cidrs": {"a": f"{prefix}.7.0/24", "b": f"{prefix}.8.0/24"}, "target_subnet_cidrs": {"a": f"{prefix}.9.0/24", "b": f"{prefix}.10.0/24"}, "management_subnet_cidr": f"{prefix}.11.0/24", "target_az_keys": ["a", "b"], "ingress_router_az_keys": ["a", "b"]}
        document = {"run_id": "symmetric-fixture", "expires_at": expiry, "architecture": "amd64", "artifact_manifest": "artifact.json", "instance_type": "t3.medium", "test_instance_type": "t3.micro", "e2e_load_profile": {"profile_id": "fixture", "approved_at": "2020-01-01T00:00:00Z", "safe_inner_mtu": 1280, "maximum_tcp_mss": 1240, "sustained_tcp_duration_seconds": 3, "minimum_sustained_tcp_bytes": 1, "iperf_duration_seconds": 3, "minimum_throughput_mbps": 1, "concurrent_duration_seconds": 3, "concurrent_tcp_flows": 1, "concurrent_udp_flows": 1, "maximum_udp_loss_percent": 1, "maximum_p99_latency_ms": 1}, "backend": {"bucket": "fixture", "region": "us-west-2", "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/backend", "state_key": "runs/symmetric-fixture/terraform.tfstate", "operator_principal_arns": ["arn:aws:iam::123456789012:role/fixture"]}, "symmetric_topology": {"version": 2, "sites": {"west": site("us-west-2", "10.10", "10.20"), "east": site("us-east-1", "10.20", "10.10")}}, "tailnet": {"name": "fixture.example", "tag": "tag:fixture", "tag_owners": ["group:infra"], "snat_subnet_routes": False}}
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "run.json"
            path.write_text(json.dumps(document))
            config = appliance.RunConfig.load(path)
            self.assertEqual(appliance.terraform_variables(config, {"path": path, "sha256": "a" * 64, "revision": "b" * 40, "version": "fixture"}, [{"site": "west", "arn": "west", "kms_key_arn": "west"}, {"site": "east", "arn": "east", "kms_key_arn": "east"}])["symmetric_topology"]["version"], 2)
            document["symmetric_topology"]["sites"]["west"]["gwlb_return_cidrs"] = ["10.10.1.0/24"]
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)


if __name__ == "__main__":
    unittest.main()
