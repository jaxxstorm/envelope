#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import pathlib
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_appliance as appliance  # noqa: E402
import aws_two_region_e2e as e2e  # noqa: E402
import test_aws_two_region_e2e as legacy_e2e_test  # noqa: E402


def packet_return_envelope() -> dict:
    return {
        "mode": "packet-return",
        "udp_bind": "0.0.0.0:6081",
        "max_inner_packet_size": 1280,
    }


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
            "transport_router_fleet": [
                {
                    "region": region,
                    "az_key": "a",
                    "instance_id": f"i-2{serial}23456789abcdef",
                    "network_interface_id": f"eni-4{serial}23456789abcdef",
                    "gwlbe_route_table_id": f"rtb-6{serial}23456789abcdef",
                    "advertised_prefix": f"{prefix}.1.0/24",
                },
                {
                    "region": region,
                    "az_key": "b",
                    "instance_id": f"i-3{serial}23456789abcdef",
                    "network_interface_id": f"eni-5{serial}23456789abcdef",
                    "gwlbe_route_table_id": f"rtb-7{serial}23456789abcdef",
                    "advertised_prefix": f"{prefix}.2.0/24",
                },
            ],
        }

    return {
        "config_version": 2,
        "run_id": "symmetric-fixture",
        "route_failover": {
            "mutation_timeout_seconds": 30,
            "restoration_timeout_seconds": 30,
            "recovery_timeout_seconds": 10,
            "initial_transport_router_az_by_gwlbe_az": {
                "west": {"a": "a", "b": "b"},
                "east": {"a": "a", "b": "b"},
            },
        },
        "sites": {
            "west": site("west", "us-west-2", "10.10", "10.20", 1),
            "east": site("east", "us-east-1", "10.20", "10.10", 5),
        },
    }


def readiness_document(topology: e2e.SymmetricTopologyV2) -> dict:
    expectations = legacy_e2e_test.terraform_transport_readiness_value(topology)
    return {
        "tailnet_policy_valid": True,
        "transport_router_contract_sha256": {
            site: expectations["sites"][site]["contract_sha256"]
            for site in e2e.SITES
        },
        "sites": {
            site: {
                "route_domains": {"workload": True, "transport": True, "target": True},
                "targets": {
                    member.instance_id: {
                        "ready": True,
                        "target_group_arn": member.target_group_arn,
                        "registration_port": 6081,
                        "process_generation_sha256": "7" * 64,
                    }
                    for member in topology.site(site).target_fleet
                },
                "transport_routers": {
                    member.instance_id: {
                        "ready": True,
                        "node_identity_ready": True,
                        "network_interface_id": member.network_interface_id,
                        "contract_sha256": expectations["sites"][site][
                            "contract_sha256"
                        ],
                        "tailnet_node_id_sha256": hashlib.sha256(
                            f"node-{member.site}-{member.az_key}".encode("utf-8")
                        ).hexdigest(),
                        "advertised_prefix": member.advertised_prefix,
                        "primary_route_ownership": {
                            "observed_at": "2026-08-28T12:00:00Z",
                            "remote": [
                                {
                                    "prefix": prefix,
                                    "owner_instance_id": topology.site(
                                        e2e._opposite(site)
                                    ).transport_router_for_prefix(prefix).instance_id,
                                    "online": True,
                                }
                                for index, prefix in enumerate(
                                    topology.site(site).remote_site_cidrs
                                )
                            ],
                            "local": [],
                        },
                    }
                    for member in topology.site(site).transport_router_fleet
                },
            }
            for site in e2e.SITES
        },
    }


def transport_runtime_state(contract: dict) -> dict:
    tcp_mss = 1240
    return {
        "ready": True,
        "contract_sha256": contract["contract_sha256"],
        "local_site_cidrs": contract["local_site_cidrs"],
        "remote_site_cidrs": contract["remote_site_cidrs"],
        "local_policy_rules": contract["local_policy_rules"],
        "ipv4_policy_rules": contract["ipv4_policy_rules"],
        "policy_rule_priority_base": contract["policy_rule_priority_base"],
        "local_route_table": contract["local_route_table"],
        "remote_route_table": contract["remote_route_table"],
        "recovery_marker": contract["recovery_marker"],
        "forward_rules": contract["forward_rules"],
        "mss_rules": [{**rule, "mss": tcp_mss} for rule in contract["mss_rules"]],
        "filter_forward_policy": contract["filter_forward_policy"],
        "mangle_forward_policy": contract["mangle_forward_policy"],
        "filter_forward_rules": contract["filter_forward_rules"],
        "mangle_forward_rules": contract["mangle_forward_rules"],
        "mss_terminal_rules": contract["mss_terminal_rules"],
        "underlay_mtu": 1500,
        "tailscale_mtu": 1280,
        "path_mtu": 1280,
        "live_mtu_allowance": 1240,
        "approved_maximum_tcp_mss": contract["approved_maximum_tcp_mss"],
        "tcp_mss": tcp_mss,
        "ipv4_forwarding": contract["ipv4_forwarding"],
        "ipv6_forwarding": contract["ipv6_forwarding"],
        "ipv6_filter_forward_policy": contract["ipv6_filter_forward_policy"],
        "ipv6_mangle_forward_policy": contract["ipv6_mangle_forward_policy"],
        "ipv6_filter_forward_rules": contract["ipv6_filter_forward_rules"],
        "ipv6_forward_rules": contract["ipv6_forward_rules"],
        "ipv6_mangle_forward_rules": contract["ipv6_mangle_forward_rules"],
        "nat_rules": contract["nat_rules"],
        "no_nat": True,
    }


def effective_transport_payload(
    contract: dict, advertised_prefix: str | None = None
) -> dict:
    advertised_prefix = advertised_prefix or contract["local_site_cidrs"][0]
    def table(name: str, chains: list[tuple[str, str]], rules: list[str]) -> str:
        declarations = "\n".join(
            f":{chain} {policy} [0:0]" for chain, policy in chains
        )
        body = "\n".join(rules)
        return (
            f"# Generated fixture\n*{name}\n{declarations}\n{body}\nCOMMIT\n"
            "# Completed fixture\n"
        )

    forward_rules = [
        "-A FORWARD -j ENVELOPE-TRANSPORT-FORWARD",
        *[
            " ".join(
                (
                    "-A ENVELOPE-TRANSPORT-FORWARD",
                    "-i",
                    rule["input"],
                    "-o",
                    rule["output"],
                    "-s",
                    rule["source"],
                    "-d",
                    rule["destination"],
                    "-j ACCEPT",
                )
            )
            for rule in contract["forward_rules"]
        ],
    ]
    mangle_rules = [
        "-A FORWARD -j ENVELOPE-TRANSPORT-MSS",
        *[
            " ".join(
                (
                    "-A ENVELOPE-TRANSPORT-MSS",
                    "-i",
                    rule["input"],
                    "-o",
                    rule["output"],
                    "-s",
                    rule["source"],
                    "-d",
                    rule["destination"],
                    "-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
                )
            )
            for rule in contract["mss_rules"]
        ],
        "-A ENVELOPE-TRANSPORT-MSS -j RETURN",
    ]
    policy_rules = []
    for rule in contract["ipv4_policy_rules"]:
        value = {
            "priority": rule["priority"],
            "table": rule["table"],
        }
        if rule["input"] != "all":
            value["iif"] = rule["input"]
        if rule["source"] != "all":
            value["src"] = rule["source"]
        if rule["destination"] != "all":
            value["dst"] = rule["destination"]
        if rule["fwmark"]:
            value["fwmark"] = rule["fwmark"]
        if rule["fwmask"]:
            value["fwmask"] = rule["fwmask"]
        if rule["action"] != "lookup":
            value["action"] = rule["action"]
        policy_rules.append(value)
    return {
        "runtime_state": transport_runtime_state(contract),
        "status": {
            "BackendState": "Running",
            "TUN": True,
            "Health": [],
            "CheckedAt": "2026-08-28T12:00:00Z",
            "Self": {
                "Online": True,
                "Expired": False,
                "KeyExpiry": "2027-08-28T12:00:00Z",
                "KeyExpiryDisabled": False,
                "AdvertisedRoutes": [advertised_prefix],
                "AcceptedRoutes": contract["remote_site_cidrs"],
                "NoSNAT": True,
                "RoutePeers": [
                    {
                        "Prefix": prefix,
                        "PeerID": f"peer-{index}",
                        "Online": True,
                        "Expired": False,
                        "KeyExpiry": "2027-08-28T12:00:00Z",
                        "KeyExpiryDisabled": False,
                        "Ping": {
                            "PeerID": f"peer-{index}",
                            "Succeeded": True,
                            "ObservedAt": "2026-08-28T11:59:59Z",
                            "LatencyMilliseconds": 10,
                        },
                    }
                    for index, prefix in enumerate(
                        contract["remote_site_cidrs"], start=1
                    )
                ],
            },
        },
        "firewall": {
            "iptables_filter": table(
                "filter",
                [
                    ("INPUT", "ACCEPT"),
                    ("FORWARD", "DROP"),
                    ("OUTPUT", "ACCEPT"),
                    ("ENVELOPE-TRANSPORT-FORWARD", "-"),
                ],
                forward_rules,
            ),
            "iptables_mangle": table(
                "mangle",
                [
                    ("PREROUTING", "ACCEPT"),
                    ("INPUT", "ACCEPT"),
                    ("FORWARD", "ACCEPT"),
                    ("OUTPUT", "ACCEPT"),
                    ("POSTROUTING", "ACCEPT"),
                    ("ENVELOPE-TRANSPORT-MSS", "-"),
                ],
                mangle_rules,
            ),
            "iptables_nat": table(
                "nat",
                [
                    ("PREROUTING", "ACCEPT"),
                    ("INPUT", "ACCEPT"),
                    ("OUTPUT", "ACCEPT"),
                    ("POSTROUTING", "ACCEPT"),
                ],
                [],
            ),
            "ip6tables_filter": table(
                "filter",
                [
                    ("INPUT", "ACCEPT"),
                    ("FORWARD", "DROP"),
                    ("OUTPUT", "ACCEPT"),
                    ("ENVELOPE-TRANSPORT-FORWARD", "-"),
                ],
                ["-A FORWARD -j ENVELOPE-TRANSPORT-FORWARD"],
            ),
            "ip6tables_mangle": table(
                "mangle",
                [
                    ("PREROUTING", "ACCEPT"),
                    ("INPUT", "ACCEPT"),
                    ("FORWARD", "ACCEPT"),
                    ("OUTPUT", "ACCEPT"),
                    ("POSTROUTING", "ACCEPT"),
                ],
                [],
            ),
            "ip6tables_nat": table(
                "nat",
                [
                    ("PREROUTING", "ACCEPT"),
                    ("INPUT", "ACCEPT"),
                    ("OUTPUT", "ACCEPT"),
                    ("POSTROUTING", "ACCEPT"),
                ],
                [],
            ),
            "nftables": {"nftables": [{"metainfo": {"json_schema_version": 1}}]},
        },
        "policy_rules": policy_rules,
        "table52_routes": [
            {"dst": prefix, "dev": contract["tailscale_interface"], "type": "unicast"}
            for prefix in contract["remote_site_cidrs"]
        ],
        "main_routes": [
            {"dst": "10.10.0.0/16", "dev": contract["underlay_interface"], "type": "unicast"}
        ],
        "sysctls": {
            "net.ipv4.ip_forward": 1,
            "net.ipv6.conf.all.forwarding": 0,
            "net.ipv6.conf.default.forwarding": 0,
            "net.ipv4.conf.all.rp_filter": 0,
            "net.ipv4.conf.default.rp_filter": 0,
            f"net.ipv4.conf.{contract['underlay_interface']}.rp_filter": 0,
            f"net.ipv4.conf.{contract['tailscale_interface']}.rp_filter": 0,
        },
        "underlay_mtu": 1500,
        "tailscale_mtu": 1280,
        "host_network_service": {
            "unit": "envelope-transport-router-network.service",
            "enabled": True,
            "active": True,
            "readiness_marker": contract["readiness_marker"],
            "runtime_state": contract["runtime_state"],
            "recovery_marker": contract["recovery_marker"],
        },
    }


def symmetric_protected_output() -> dict:
    document = legacy_e2e_test.protected_output()
    topology = topology_document()
    document["symmetric_topology"] = {"value": topology}
    document.pop("instance_ids")
    parsed_topology = e2e.parse_symmetric_topology_v2(topology)
    document["artifact_identity"] = {
        "value": legacy_e2e_test.terraform_artifact_identity_value(
            parsed_topology.run_id
        )
    }
    document["route_failover"] = {
        "value": legacy_e2e_test.terraform_route_failover_value(parsed_topology)
    }
    document["transport_router_readiness_expectations"] = {
        "value": legacy_e2e_test.terraform_transport_readiness_value(parsed_topology)
    }
    document["envelope_runtime_config"]["value"] = {
        site: {
            "config_version": 2,
            "mode": "packet-return",
            "udp_bind": "0.0.0.0:6081",
            "max_inner_packet_size": 1280,
            "artifact_sha256": "a" * 64,
            "artifact_revision": "b" * 40,
        }
        for site in e2e.SITES
    }
    document["gwlb_target_group_arns"]["value"] = {
        site: topology["sites"][site]["target_fleet"][0]["target_group_arn"] for site in e2e.SITES
    }
    document["cost_profile"]["value"] = legacy_e2e_test.terraform_symmetric_cost_value(
        parsed_topology
    )
    return document


def evidence_document() -> dict:
    return copy.deepcopy(legacy_e2e_test.symmetric_route_evidence())


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
        return "draining" if self.replacement and "deregister" in self.calls else "unhealthy" if self.replacement else "healthy"

    def replace(self, member: e2e.SymmetricFleetMember) -> e2e.SymmetricFleetMember:
        self.calls.append("replace")
        return e2e.SymmetricFleetMember(member.site, "target", member.region, member.az_key, "i-ff23456789abcdef", member.target_group_arn)


class SymmetricTopologyTest(unittest.TestCase):
    def replacement_adapter(
        self, temporary: str
    ) -> tuple[
        dict,
        e2e.SymmetricProtectedDeployment,
        legacy_e2e_test.DurableManifestStore,
        e2e.ProtectedLifecycleAdapter,
    ]:
        raw = symmetric_protected_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        config = SimpleNamespace(run_id="fixture-live", sites=legacy_e2e_test.lifecycle_sites())
        manifest = legacy_e2e_test.ready_lifecycle_manifest(raw)
        hostnames = e2e.expected_tailnet_hostnames(config)
        manifest["tailnet"]["expected_hostnames"] = hostnames
        manifest["tailnet"]["device_ids"] = {
            hostname: f"device-{index}"
            for index, hostname in enumerate(hostnames, start=1)
        }
        store = legacy_e2e_test.DurableManifestStore(manifest)
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = config
        adapter.aws = SimpleNamespace()
        adapter.runner = SimpleNamespace()
        adapter.run_dir = pathlib.Path(temporary).resolve()
        adapter.terraform_dir = ROOT / "example" / "terraform"
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"
        adapter.claim(raw, deployment)
        return raw, deployment, store, adapter

    def test_topology_and_preflight_fail_closed(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        expectations = legacy_e2e_test.terraform_transport_readiness_value(topology)[
            "sites"
        ]
        self.assertEqual(
            e2e.validate_symmetric_preflight(
                topology, readiness_document(topology), expectations
            )["config_version"],
            2,
        )
        invalid = readiness_document(topology)
        invalid["sites"]["west"]["route_domains"]["target"] = False
        with self.assertRaisesRegex(e2e.ReadinessError, "route-domain"):
            e2e.validate_symmetric_preflight(topology, invalid)
        wrong_contract = readiness_document(topology)
        wrong_contract["transport_router_contract_sha256"]["west"] = "f" * 64
        with self.assertRaisesRegex(e2e.ReadinessError, "Terraform contract SHA"):
            e2e.validate_symmetric_preflight(topology, wrong_contract, expectations)
        invalid_topology = topology_document()
        invalid_topology["sites"]["west"]["remote_site_cidrs"] = ["10.10.1.0/24"]
        with self.assertRaisesRegex(e2e.DeploymentError, "overlap|peer"):
            e2e.parse_symmetric_topology_v2(invalid_topology)

    def test_primary_route_ownership_requires_remote_owners_and_empty_local_selection(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        observer = topology.west.transport_router_fleet[0]
        sibling = topology.west.transport_router_fleet[1]
        remote_members = topology.east.transport_router_fleet
        expected_remote_owners = {
            member.advertised_prefix: member.instance_id
            for member in remote_members
        }
        expected_local_owners = {}
        bindings = {
            "node-west-b": {
                "hostname": "symmetric-fixture-west-transport-b",
                "instance_id": sibling.instance_id,
                "scope": "local",
            },
            **{
                f"node-east-{member.az_key}": {
                    "hostname": f"symmetric-fixture-east-transport-{member.az_key}",
                    "instance_id": member.instance_id,
                    "scope": "remote",
                }
                for member in remote_members
            },
        }

        def claim(prefix, peer_id, hostname):
            return {
                "Prefix": prefix,
                "PeerID": peer_id,
                "Hostname": hostname,
                "Online": True,
                "Expired": False,
                "KeyExpiry": "2027-08-28T12:00:00Z",
                "KeyExpiryDisabled": False,
                "Ping": {
                    "PeerID": peer_id,
                    "Succeeded": True,
                    "ObservedAt": "2026-08-28T11:59:59Z",
                    "LatencyMilliseconds": 10,
                },
            }

        ownership = {
            "ObservedAt": "2026-08-28T12:00:00Z",
            "Remote": [
                claim(
                    prefix,
                    "node-east-"
                    + topology.east.transport_router_for_prefix(prefix).az_key,
                    "symmetric-fixture-east-transport-"
                    + topology.east.transport_router_for_prefix(prefix).az_key,
                )
                for prefix in topology.west.remote_site_cidrs
            ],
            "Local": [],
        }
        validated = e2e._validated_primary_route_ownership(
            ownership,
            local_prefixes=topology.west.local_site_cidrs,
            remote_prefixes=topology.west.remote_site_cidrs,
            peer_bindings=bindings,
            selected_local_prefixes=set(),
            expected_remote_owner_instance_ids=expected_remote_owners,
            expected_local_owner_instance_ids=expected_local_owners,
        )
        self.assertEqual(
            {entry["owner_instance_id"] for entry in validated["remote"]},
            {member.instance_id for member in remote_members},
        )
        self.assertEqual(validated["local"], [])

        disabled_expiry = copy.deepcopy(ownership)
        for entry in disabled_expiry["Remote"] + disabled_expiry["Local"]:
            entry["KeyExpiry"] = disabled_expiry["ObservedAt"]
            entry["KeyExpiryDisabled"] = True
        e2e._validated_primary_route_ownership(
            disabled_expiry,
            local_prefixes=topology.west.local_site_cidrs,
            remote_prefixes=topology.west.remote_site_cidrs,
            peer_bindings=bindings,
            selected_local_prefixes=set(),
            expected_remote_owner_instance_ids=expected_remote_owners,
            expected_local_owner_instance_ids=expected_local_owners,
        )

        invalid_expiry_mode = copy.deepcopy(disabled_expiry)
        invalid_expiry_mode["Remote"][0]["KeyExpiryDisabled"] = "true"
        with self.assertRaisesRegex(e2e.ReadinessError, "expired"):
            e2e._validated_primary_route_ownership(
                invalid_expiry_mode,
                local_prefixes=topology.west.local_site_cidrs,
                remote_prefixes=topology.west.remote_site_cidrs,
                peer_bindings=bindings,
                selected_local_prefixes=set(),
                expected_remote_owner_instance_ids=expected_remote_owners,
                expected_local_owner_instance_ids=expected_local_owners,
            )

        for mutation in (
            "missing",
            "duplicate",
            "offline",
            "wrong-site",
            "swapped-owner",
            "local-owner",
            "local-table52-selection",
        ):
            invalid = copy.deepcopy(ownership)
            selected_local_prefixes: set[str] = set()
            if mutation == "missing":
                invalid["Remote"].pop()
            elif mutation == "duplicate":
                invalid["Remote"].append(copy.deepcopy(invalid["Remote"][0]))
            elif mutation == "offline":
                invalid["Remote"][0]["Online"] = False
            elif mutation == "wrong-site":
                invalid["Remote"][0] = claim(
                    invalid["Remote"][0]["Prefix"],
                    "node-west-b",
                    "symmetric-fixture-west-transport-b",
                )
            elif mutation == "swapped-owner":
                wrong = remote_members[1]
                invalid["Remote"][0] = claim(
                    invalid["Remote"][0]["Prefix"],
                    f"node-east-{wrong.az_key}",
                    f"symmetric-fixture-east-transport-{wrong.az_key}",
                )
            elif mutation == "local-owner":
                invalid["Local"] = [
                    claim(
                        sibling.advertised_prefix,
                        "node-west-b",
                        "symmetric-fixture-west-transport-b",
                    )
                ]
            else:
                selected_local_prefixes = {sibling.advertised_prefix}
            with self.subTest(mutation=mutation), self.assertRaises(e2e.ReadinessError):
                e2e._validated_primary_route_ownership(
                    invalid,
                    local_prefixes=topology.west.local_site_cidrs,
                    remote_prefixes=topology.west.remote_site_cidrs,
                    peer_bindings=bindings,
                    selected_local_prefixes=selected_local_prefixes,
                    expected_remote_owner_instance_ids=expected_remote_owners,
                    expected_local_owner_instance_ids=expected_local_owners,
                )

    def test_preflight_route_ownership_is_bound_to_prefixes_and_fleet(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        observer = topology.west.transport_router_fleet[0]
        for mutation in ("missing", "duplicate", "wrong-site", "offline", "local-self"):
            invalid = readiness_document(topology)
            ownership = invalid["sites"]["west"]["transport_routers"][
                observer.instance_id
            ]["primary_route_ownership"]
            if mutation == "missing":
                ownership["remote"].pop()
            elif mutation == "duplicate":
                ownership["remote"].append(copy.deepcopy(ownership["remote"][0]))
            elif mutation == "wrong-site":
                ownership["remote"][0]["owner_instance_id"] = (
                    topology.west.transport_router_fleet[1].instance_id
                )
            elif mutation == "offline":
                ownership["remote"][0]["online"] = False
            else:
                ownership["local"] = [
                    {
                        "prefix": topology.west.local_site_cidrs[0],
                        "owner_instance_id": observer.instance_id,
                        "online": True,
                    }
                ]
            with self.subTest(mutation=mutation), self.assertRaises(e2e.ReadinessError):
                e2e.validate_symmetric_preflight(topology, invalid)

    def test_ingress_era_symmetric_names_are_rejected_without_translation(self) -> None:
        legacy_topology = topology_document()
        west = legacy_topology["sites"]["west"]
        west["ingress_router_fleet"] = west.pop("transport_router_fleet")
        with self.assertRaisesRegex(e2e.DeploymentError, "unsupported|missing"):
            e2e.parse_symmetric_topology_v2(legacy_topology)

        with self.assertRaisesRegex(e2e.DeploymentError, "role is invalid"):
            e2e.SymmetricFleetMember(
                "west",
                "ingress-router",  # type: ignore[arg-type]
                "us-west-2",
                "a",
                "i-0123456789abcdef0",
            )

        topology = e2e.parse_symmetric_topology_v2(topology_document())
        legacy_readiness = readiness_document(topology)
        legacy_site = legacy_readiness["sites"]["west"]
        legacy_site["ingress_routers"] = legacy_site.pop("transport_routers")
        legacy_site["route_domains"]["ingress_router"] = legacy_site[
            "route_domains"
        ].pop("transport")
        with self.assertRaisesRegex(
            (e2e.DeploymentError, e2e.ReadinessError), "unsupported|missing"
        ):
            e2e.validate_symmetric_preflight(topology, legacy_readiness)

        legacy_evidence = evidence_document()
        probe = legacy_evidence["traversals"][0]["probes"][0]
        probe["ingress_router_id"] = probe.pop("destination_transport_router_id")
        with self.assertRaisesRegex(e2e.EvidenceError, "wrong shape"):
            e2e.validate_symmetric_evidence(legacy_evidence)

        self.assertFalse(hasattr(e2e.SymmetricLifecycle, "fail_ingress_router"))
        self.assertFalse(
            hasattr(e2e.AwsSymmetricLiveOperations, "_verify_ingress_router")
        )
        self.assertFalse(
            hasattr(e2e.AwsSymmetricLiveOperations, "_selected_ingress_router")
        )

    def test_symmetric_readiness_installs_wire_inspector_on_every_target(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        installed = []
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.base = SimpleNamespace(
            _install_wire_inspector=lambda target: installed.append(target)
        )

        operations._install_target_wire_inspectors(deployment)

        self.assertEqual(
            {target.instance_id for target in installed},
            {
                member.instance_id
                for site in e2e.SITES
                for member in deployment.topology.site(site).target_fleet
            },
        )
        self.assertEqual({target.role for target in installed}, {"target"})

    def test_capture_inspection_failure_retains_redacted_underlying_error(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        member = deployment.topology.west.target_fleet[0]
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations._geneve_capture_events = []
        cancelled = []

        class SSM:
            @staticmethod
            def wait(target, command_id, *, timeout_seconds):
                del timeout_seconds
                return e2e.SSMResult(target, command_id, "Success", 0)

            @staticmethod
            def cancel(_target, command_id, *, timeout_seconds):
                del timeout_seconds
                cancelled.append(command_id)

        operations.base = SimpleNamespace(
            ssm=SSM(),
            _inspect_capture_summary=mock.Mock(
                side_effect=e2e.SSMError("wire inspector is absent")
            ),
            _execute=lambda target, *_args, **_kwargs: e2e.SSMResult(
                target, "delete-capture", "Success", 0
            ),
        )
        handle = e2e._SymmetricGeneveCapture(
            member,
            "/run/envelope-e2e-capture/fixture.pcap",
            "capture-command",
            8,
        )

        with self.assertRaisesRegex(
            e2e.WireAssertionError, "wire inspector is absent"
        ):
            operations._finish_geneve_captures(
                {member.instance_id: handle}, inspect=True
            )

        self.assertEqual(
            operations._geneve_capture_events,
            [
                {
                    "target_id": member.instance_id,
                    "capture_method": "linux-af-packet",
                    "bounded": True,
                    "completed": True,
                    "inspected": False,
                    "raw_pcap_deleted": True,
                }
            ],
        )
        self.assertEqual(cancelled, ["capture-command"])

    def test_dry_run_has_no_adapter_side_effects_and_failure_restarts_quiesced_target(self) -> None:
        topology = e2e.parse_symmetric_topology_v2(topology_document())
        target = topology.west.target_fleet[0]
        adapter = Adapter()
        dry = e2e.SymmetricLifecycle(topology, adapter, dry_run=True)
        self.assertTrue(dry.quiesce_target(target)["dry_run"])
        self.assertTrue(
            dry.fail_transport_router(
                topology.east.transport_router_fleet[0], graceful=True
            )["dry_run"]
        )
        self.assertEqual(
            dry.probe_identities(
                "west",
                target.instance_id,
                topology.east.transport_router_fleet[0].instance_id,
            )["destination_site"],
            "east",
        )
        self.assertEqual(dry.observe_new_flow_recovery(lambda: True, timeout_seconds=1), 1)
        self.assertEqual(adapter.calls, [])
        quiesce_adapter = Adapter(replacement=True)
        quiesced = e2e.SymmetricLifecycle(
            topology, quiesce_adapter, dry_run=False
        ).quiesce_target(target)
        self.assertEqual(quiesced["health"], "unhealthy")
        quiesce_command = next(
            call for call in quiesce_adapter.calls if "systemctl stop" in call
        )
        self.assertIn("! systemctl is-active --quiet envelope.service", quiesce_command)
        self.assertIn("! curl --fail --silent --max-time 3", quiesce_command)
        live = e2e.SymmetricLifecycle(topology, Adapter(replacement=True), dry_run=False)
        with self.assertRaisesRegex(e2e.ResilienceError, "distinct healthy"):
            live.replace_target_instance(target)
        self.assertIn("systemctl start envelope.service", live.adapter.calls)

    def test_evidence_requires_both_recovery_classes_and_redacts_unsafe_values(self) -> None:
        document = evidence_document()
        self.assertEqual(e2e.validate_evidence(document)["schema"], 3)
        missing = copy.deepcopy(document)
        missing["recoveries"] = missing["recoveries"][:1]
        with self.assertRaisesRegex(e2e.EvidenceError, "process, instance, and transport-router"):
            e2e.validate_evidence(missing)
        unsafe = copy.deepcopy(document)
        unsafe["residual_audit"]["token"] = "tskey-secret-value"
        with self.assertRaisesRegex(e2e.EvidenceError, "unsupported|unsafe"):
            e2e.validate_evidence(unsafe)
        duplicate_role = copy.deepcopy(document)
        duplicate_role["cold_initiation"][3].update(
            {"source_role": "initiator", "destination_role": "responder"}
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "concurrently"):
            e2e.validate_evidence(duplicate_role)
        sequential = copy.deepcopy(document)
        sequential["cold_initiation"][3].update(
            {"dispatch_monotonic_ns": 1_000_000_106}
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "concurrently"):
            e2e.validate_evidence(sequential)
        missing_return = copy.deepcopy(document)
        del missing_return["traversals"][0]["probes"][0]["geneve_return_proof"]
        with self.assertRaisesRegex(e2e.EvidenceError, "wrong shape"):
            e2e.validate_evidence(missing_return)
        wrong_source_eni = copy.deepcopy(document)
        wrong_source_eni["traversals"][0]["probes"][0]["source_transport_eni_id"] = (
            topology_document()["sites"]["west"]["transport_router_fleet"][1][
                "network_interface_id"
            ]
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "same-AZ transport ENI"):
            e2e.validate_evidence(wrong_source_eni)

    def test_protected_parser_binds_fleets_workloads_endpoints_and_cost(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        self.assertEqual(deployment.topology.run_id, "symmetric-fixture")
        self.assertEqual(len(deployment.topology.west.target_fleet), 2)
        self.assertEqual(
            deployment.topology.west.transport_router_fleet[0].network_interface_id,
            "eni-4123456789abcdef",
        )
        self.assertEqual(deployment.runtime["west"]["mode"], "packet-return")
        self.assertEqual(deployment.cost_evidence()["within_approved_ceiling"], True)
        self.assertEqual(
            set(deployment.topology.route_failover.as_dict()),
            {
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
                "initial_transport_router_az_by_gwlbe_az",
            },
        )
        self.assertEqual(
            deployment.topology.route_failover.settlement_timeout_seconds,
            deployment.topology.route_failover.recovery_timeout_seconds,
        )
        self.assertEqual(deployment.topology.route_failover.quiet_window_seconds, 3)
        self.assertEqual(
            deployment.topology.route_failover.owner_lease_seconds,
            e2e.TRANSPORT_ROUTER_READINESS_RESERVATION_SECONDS
            + deployment.topology.route_failover.quiet_window_seconds
            + e2e.ROUTE_OWNER_LEASE_MARGIN_SECONDS,
        )
        self.assertEqual(
            deployment.route_failover_output["sites"]["west"]["a"]
            ["initial_network_interface_id"],
            deployment.topology.west.transport_router_fleet[0].network_interface_id,
        )
        self.assertEqual(
            deployment.cost_profile["resource_counts"]["nat_gateways"], 2
        )
        self.assertRegex(
            deployment.transport_router_readiness_expectations["west"][
                "contract_sha256"
            ],
            r"^[0-9a-f]{64}$",
        )
        directional = symmetric_protected_output()
        directional["cost_profile"]["value"]["profile"] = "directional-lane-acceptance"
        with self.assertRaisesRegex(e2e.DeploymentError, "cost profile|symmetric HA fleet"):
            e2e.parse_symmetric_protected_deployment_output(directional)
        obsolete_runtime = symmetric_protected_output()
        obsolete_runtime["envelope_runtime_config"]["value"]["west"]["tun_name"] = "envelope0"
        with self.assertRaisesRegex(e2e.DeploymentError, "unsupported"):
            e2e.parse_symmetric_protected_deployment_output(obsolete_runtime)
        wrong_mode = symmetric_protected_output()
        wrong_mode["envelope_runtime_config"]["value"]["west"]["mode"] = "direct-forward"
        with self.assertRaisesRegex(e2e.DeploymentError, "packet-return"):
            e2e.parse_symmetric_protected_deployment_output(wrong_mode)

    def test_protected_parser_requires_exact_terraform_contract_outputs(self) -> None:
        self.assertEqual(
            set(symmetric_protected_output()),
            {
                "artifact_identity",
                "cost_profile",
                "e2e_load_profile",
                "envelope_runtime_config",
                "flow_log_evidence",
                "gwlb_endpoint_ids",
                "gwlb_target_group_arns",
                "route_failover",
                "symmetric_topology",
                "transport_router_readiness_expectations",
                "vpc_ids",
                "workload_instances",
            },
        )
        missing_route = symmetric_protected_output()
        del missing_route["route_failover"]
        with self.assertRaisesRegex(e2e.DeploymentError, "route_failover"):
            e2e.parse_symmetric_protected_deployment_output(missing_route)

        for name, mutate in (
            (
                "bound",
                lambda value: value["route_failover"]["value"].update(
                    {"recovery_timeout_seconds": 11}
                ),
            ),
            (
                "selection",
                lambda value: value["route_failover"]["value"]["sites"]["west"][
                    "a"
                ].update({"initial_transport_router_az_key": "b"}),
            ),
            (
                "route table",
                lambda value: value["route_failover"]["value"]["sites"]["west"][
                    "a"
                ].update({"route_table_id": "rtb-fffffffffffffffff"}),
            ),
            (
                "ENI",
                lambda value: value["route_failover"]["value"]["sites"]["west"][
                    "a"
                ].update({"initial_network_interface_id": "eni-fffffffffffffffff"}),
            ),
        ):
            route_identity = symmetric_protected_output()
            mutate(route_identity)
            with self.subTest(name=name), self.assertRaisesRegex(
                e2e.DeploymentError, "bounds, selections, route tables, or ENIs"
            ):
                e2e.parse_symmetric_protected_deployment_output(route_identity)

        readiness_field = symmetric_protected_output()
        readiness_field["transport_router_readiness_expectations"]["value"][
            "sites"
        ]["west"]["ipv6_forwarding"] = True
        with self.assertRaisesRegex(e2e.DeploymentError, "topology, load, or SHA"):
            e2e.parse_symmetric_protected_deployment_output(readiness_field)

        readiness_sha = symmetric_protected_output()
        readiness_sha["transport_router_readiness_expectations"]["value"][
            "sites"
        ]["east"]["contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(e2e.DeploymentError, "topology, load, or SHA"):
            e2e.parse_symmetric_protected_deployment_output(readiness_sha)

        expanded_cost = symmetric_protected_output()
        del expanded_cost["cost_profile"]["value"]["resource_counts"][
            "elastic_ips"
        ]
        with self.assertRaisesRegex(e2e.DeploymentError, "expanded symmetric HA cost"):
            e2e.parse_symmetric_protected_deployment_output(expanded_cost)

    def test_transport_runtime_state_is_bound_to_the_terraform_contract(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        contract = deployment.transport_router_readiness_expectations["west"]
        state = transport_runtime_state(contract)
        self.assertTrue(
            e2e._validate_transport_router_runtime_state(contract, state)["ready"]
        )
        for field, value in (
            ("contract_sha256", "f" * 64),
            ("ipv6_forwarding", True),
            ("tcp_mss", 1239),
        ):
            invalid = copy.deepcopy(state)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                e2e.ReadinessError, "reviewed readiness contract"
            ):
                e2e._validate_transport_router_runtime_state(contract, invalid)

    def test_protected_deployment_cli_uses_the_symmetric_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "deployment.json"
            path.write_text(json.dumps(symmetric_protected_output()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = e2e.main(["parse-protected-deployment", str(path)])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["topology"]["config_version"], 2)

    def test_protected_replacement_reconciles_committed_manifest_write_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, deployment, store, adapter = self.replacement_adapter(temporary)
            member = deployment.topology.west.target_fleet[0]
            replacement = copy.deepcopy(raw)
            replacement["symmetric_topology"]["value"]["sites"]["west"]["target_fleet"][0][
                "instance_id"
            ] = "i-ff23456789abcdef"
            faulted: set[str] = set()

            def commit_then_error(target, value, if_match):
                target.commit(value, if_match)
                if value["phase"] in {"e2e_replacement_ready", "e2e_running"} and value["phase"] not in faulted:
                    faulted.add(value["phase"])
                    raise e2e.LifecycleError("injected response loss after durable replacement write")

            def advance(phase: str, *, output=None):
                value = copy.deepcopy(store.value)
                value["phase"] = phase
                if output is not None:
                    value["deployment"] = copy.deepcopy(output)
                store.commit(value, store.remote_etag)
                return value

            def plan(*_args, **_kwargs):
                advance("replacement_planned")
                return pathlib.Path(temporary) / "replace.tfplan"

            store.write_hook = commit_then_error
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "terraform_plan", side_effect=plan),
                mock.patch.object(
                    e2e,
                    "terraform_apply",
                    side_effect=lambda *_args, **_kwargs: advance("applied", output=replacement)["deployment"],
                ),
                mock.patch.object(
                    e2e,
                    "wait_and_record",
                    side_effect=lambda *_args, **_kwargs: advance("e2e_replacement_complete"),
                ),
            ):
                result = adapter.replace_target_instance(member)

            self.assertEqual(result, replacement)
            self.assertEqual(faulted, {"e2e_replacement_ready", "e2e_running"})
            self.assertEqual(store.value["phase"], "e2e_running")
            self.assertEqual(adapter.manifest, store.value)
            self.assertFalse(
                any(
                    str(value["phase"]).startswith("key_rotation")
                    or value["phase"] == "key_rotated"
                    for value, _etag in store.writes
                )
            )
            self.assertEqual(
                set(store.value["e2e"]["replacement"]),
                {"address", "old_instance_id", "started_at", "finished_at", "new_output_sha256"},
            )

    def test_interrupted_replacement_claim_remains_cleanup_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _raw, deployment, store, adapter = self.replacement_adapter(temporary)
            member = deployment.topology.west.target_fleet[0]

            def commit_then_interrupt(target, value, if_match):
                target.commit(value, if_match)
                raise KeyboardInterrupt("injected interrupt after durable replacement claim")

            store.write_hook = commit_then_interrupt
            with self.assertRaisesRegex(KeyboardInterrupt, "cleanup remains authorized"):
                adapter.replace_target_instance(member)
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                result = adapter.cleanup()

            cleanup.assert_called_once()
            self.assertTrue(result["e2e_claim_handoff"]["claim_identity_preserved"])
            self.assertEqual(store.value["phase"], "e2e_failed")
            self.assertIn("failed_at", store.value["e2e"]["replacement"])

    def test_protected_replacement_rejects_a_stale_member_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _raw, deployment, _store, adapter = self.replacement_adapter(temporary)
            member = deployment.topology.west.target_fleet[0]
            stale = e2e.SymmetricFleetMember(
                member.site,
                member.role,
                member.region,
                member.az_key,
                "i-ee23456789abcdef",
                member.target_group_arn,
            )
            with (
                mock.patch.object(e2e, "build_tailscale") as tailscale,
                self.assertRaisesRegex(e2e.ResilienceError, "exact current durable"),
            ):
                adapter.replace_target_instance(stale)
            tailscale.assert_not_called()

    def test_live_route_domain_rejects_a_more_specific_gwlbe_bypass(self) -> None:
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.base = SimpleNamespace(
            _route_selects_only_target=e2e.AwsLiveOperations._route_selects_only_target
        )
        routes = [
            {"DestinationCidrBlock": "10.20.1.0/24", "GatewayId": "vpce-0123456789abcdef0", "State": "active"},
            {"DestinationCidrBlock": "10.20.2.0/24", "GatewayId": "vpce-0123456789abcdef0", "State": "active"},
        ]
        operations._verify_gwlbe_route_domain(
            routes,
            ["10.20.1.0/24", "10.20.2.0/24"],
            "vpce-0123456789abcdef0",
            "fixture workload",
        )
        routes.append(
            {"DestinationCidrBlock": "10.20.1.128/25", "GatewayId": "local", "State": "active"}
        )
        with self.assertRaisesRegex(e2e.ReadinessError, "more-specific"):
            operations._verify_gwlbe_route_domain(
                routes,
                ["10.20.1.0/24", "10.20.2.0/24"],
                "vpce-0123456789abcdef0",
                "fixture workload",
            )

    def test_live_readiness_binds_gwlbes_to_the_expected_vpc_and_azs(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        endpoint_ids = deployment.endpoint_ids["west"]
        subnets = {"a": "subnet-0123456789abcdef0", "b": "subnet-1123456789abcdef0"}

        class AWS:
            def json(self, args, *, region=None):
                if args[1] == "describe-vpc-endpoints":
                    return {
                        "VpcEndpoints": [
                            {
                                "VpcEndpointId": endpoint_id,
                                "VpcEndpointType": "GatewayLoadBalancer",
                                "VpcId": deployment.vpc_ids["west"],
                                "State": "available",
                                "SubnetIds": [subnets[az_key]],
                                "CreationTimestamp": "2026-08-20T10:00:00Z",
                            }
                            for az_key, endpoint_id in endpoint_ids.items()
                        ]
                    }
                if args[1] == "describe-subnets":
                    return {
                        "Subnets": [
                            {
                                "SubnetId": subnet_id,
                                "VpcId": deployment.vpc_ids["west"],
                                "AvailabilityZone": f"us-west-2{az_key}",
                                "CidrBlock": f"10.10.{4 + int(az_key == 'b')}.0/24",
                                "State": "available",
                            }
                            for az_key, subnet_id in subnets.items()
                        ]
                    }
                raise AssertionError(args)

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.aws = AWS()
        operations.config = SimpleNamespace(
            sites={
                "west": {
                    "azs": {"a": "us-west-2a", "b": "us-west-2b"},
                    "gwlbe_subnet_cidrs": {
                        "a": "10.10.4.0/24",
                        "b": "10.10.5.0/24",
                    },
                }
            }
        )
        operations.base = SimpleNamespace(_wait_for_gwlbe_stability=mock.Mock(return_value=300))

        operations._verify_gwlbe_endpoints(deployment, "west", deadline=600.0)

        operations.base._wait_for_gwlbe_stability.assert_called_once()

    def test_live_readiness_binds_primary_eni_to_instance_subnet_vpc_and_az(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        member = deployment.topology.west.transport_router_fleet[0]
        identity = {
            "network_interface_id": member.network_interface_id,
            "subnet_id": "subnet-0123456789abcdef0",
            "availability_zone": "us-west-2a",
        }
        interface = {
            "NetworkInterfaceId": member.network_interface_id,
            "SubnetId": identity["subnet_id"],
            "VpcId": deployment.vpc_ids["west"],
            "AvailabilityZone": identity["availability_zone"],
            "Status": "in-use",
            "SourceDestCheck": False,
            "Attachment": {
                "InstanceId": member.instance_id,
                "DeviceIndex": 0,
                "Status": "attached",
            },
        }
        subnet = {
            "SubnetId": identity["subnet_id"],
            "VpcId": deployment.vpc_ids["west"],
            "AvailabilityZone": identity["availability_zone"],
            "CidrBlock": "10.10.3.0/24",
            "State": "available",
        }

        class AWS:
            def json(self, args, *, region=None):
                self.region = region
                if args[1] == "describe-network-interfaces":
                    return {"NetworkInterfaces": [copy.deepcopy(interface)]}
                if args[1] == "describe-subnets":
                    return {"Subnets": [copy.deepcopy(subnet)]}
                raise AssertionError(args)

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.aws = AWS()
        operations._verify_primary_network_binding(
            deployment,
            member,
            identity,
            expected_cidr="10.10.3.0/24",
            expected_source_dest_check=False,
        )
        self.assertEqual(operations.aws.region, "us-west-2")

        interface["Attachment"]["InstanceId"] = "i-1123456789abcdef0"
        with self.assertRaisesRegex(e2e.ReadinessError, "exact instance"):
            operations._verify_primary_network_binding(
                deployment,
                member,
                identity,
                expected_cidr="10.10.3.0/24",
                expected_source_dest_check=False,
            )

    def test_packet_return_target_readiness_requires_receive_send_and_isolation(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        member = deployment.topology.west.target_fleet[0]
        commands: list[str] = []
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(
            run_id="symmetric-fixture",
            sites={
                "west": {
                    "azs": {member.az_key: f"us-west-2{member.az_key}"},
                    "target_subnet_cidrs": {
                        member.az_key: "10.10.9.0/24"
                    },
                }
            },
        )
        operations._describe_instance = lambda _member: {
            "State": {"Name": "running"},
            "SourceDestCheck": True,
            "SubnetId": "subnet-0123456789abcdef0",
            "Placement": {"AvailabilityZone": f"us-west-2{member.az_key}"},
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-0123456789abcdef0",
                    "SubnetId": "subnet-0123456789abcdef0",
                    "Status": "in-use",
                    "SourceDestCheck": True,
                    "Attachment": {"DeviceIndex": 0, "Status": "attached"},
                }
            ],
            "Tags": [
                {"Key": "EnvelopeRun", "Value": "symmetric-fixture"},
                {"Key": "Role", "Value": "target"},
                {"Key": "Site", "Value": "west"},
                {"Key": "ZoneKey", "Value": member.az_key},
            ],
        }

        def execute_json(_target, command, **_kwargs):
            commands.append(command)
            return {
                "ready": True,
                "envelope_active": True,
                "health_ready": True,
                "geneve_receive_ready": True,
                "geneve_validation_ready": True,
                "geneve_send_ready": True,
                "metrics_ready": True,
                "target_isolated": True,
                "pid": 123,
                "process_generation_sha256": "9" * 64,
            }

        operations.base = SimpleNamespace(
            _tags=e2e.AwsLiveOperations._tags,
            _execute_json=execute_json,
        )
        operations._verify_primary_network_binding = mock.Mock()

        operations._verify_target(deployment, member, timeout_seconds=60)

        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertIn("ENVELOPE_MODE=packet-return", command)
        self.assertIn("ENVELOPE_UDP_BIND=0.0.0.0:6081", command)
        self.assertIn("gwlb_target_component_ready", command)
        for metric in (
            "geneve_rx_packets",
            "geneve_rx_bytes",
            "geneve_tx_packets",
            "geneve_tx_bytes",
            "geneve_options_validation_errors",
            "gwlb_profile_rejections_total",
            "gwlb_receive_drops_total",
            "gwlb_inner_validation_failures_total",
            "gwlb_return_build_failures_total",
            "gwlb_send_failures_total",
            "drops",
        ):
            self.assertIn(metric, command)
        self.assertNotIn("datapath_component_healthy", command)
        self.assertIn("! command -v tailscale", command)
        self.assertIn("! ip link show dev envelope0", command)
        self.assertIn('! systemctl is-enabled --quiet "$unit" 2>/dev/null', command)
        self.assertIn("tr '[:upper:]' '[:lower:]') == cap_net_raw", command)
        self.assertNotIn("grep -qw CAP_NET_RAW", command)
        self.assertIn('failed_check="component-readiness-$component"', command)
        self.assertNotIn("net.ipv4.ip_forward", command)
        self.assertNotIn("iptables", command)
        self.assertNotIn("systemctl is-active --quiet tailscaled.service envelope.service", command)
        subprocess.run(["bash", "-n", "-c", command], check=True, capture_output=True, text=True)
        component_check = next(
            line.strip()
            for line in command.splitlines()
            if "grep -Eq" in line and "gwlb_target_component_ready" in line
        )
        with tempfile.TemporaryDirectory() as directory:
            metrics = pathlib.Path(directory) / "metrics"
            metrics.write_text(
                'gwlb_target_component_ready{component="receiver"} 1\n',
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    f"set -euo pipefail\ncomponent=receiver\nmetrics={shlex.quote(str(metrics))}\n{component_check}",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_target_group_readiness_requires_exact_instance_ids_and_geneve_port(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        members = deployment.topology.west.target_fleet

        class AWS:
            values = [
                {
                    "Target": {"Id": member.instance_id, "Port": 6081},
                    "TargetHealth": {"State": "healthy"},
                }
                for member in members
            ]

            def json(self, _args, *, region=None):
                return {"TargetHealthDescriptions": copy.deepcopy(self.values)}

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.aws = AWS()

        registrations = operations._verify_target_group_registrations(
            deployment, "west"
        )

        self.assertEqual(set(registrations), {member.instance_id for member in members})
        operations.aws.values[0]["Target"]["Port"] = 6082
        with self.assertRaisesRegex(e2e.ReadinessError, "port"):
            operations._verify_target_group_registrations(deployment, "west")

    def test_gwlbe_post_inspection_routes_select_same_az_transport_eni(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        member = deployment.topology.west.transport_router_fleet[0]
        endpoint_subnet = "subnet-9123456789abcdef0"
        table = {
            "RouteTableId": member.gwlbe_route_table_id,
            "VpcId": deployment.vpc_ids["west"],
            "Associations": [
                {
                    "SubnetId": endpoint_subnet,
                    "Main": False,
                    "AssociationState": {"State": "associated"},
                }
            ],
            "Routes": [
                {
                    "DestinationCidrBlock": "10.10.0.0/16",
                    "GatewayId": "local",
                    "State": "active",
                },
                *[
                    {
                        "DestinationCidrBlock": cidr,
                        "NetworkInterfaceId": member.network_interface_id,
                        "State": "active",
                    }
                    for cidr in deployment.topology.west.remote_site_cidrs
                ],
            ],
        }

        class AWS:
            def json(self, args, *, region=None):
                self.args = args
                self.region = region
                return {"RouteTables": [table]}

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.aws = AWS()
        operations.base = SimpleNamespace(
            _route_selects_only_target=e2e.AwsLiveOperations._route_selects_only_target,
        )

        operations._verify_gwlbe_post_inspection_routes(deployment, member, endpoint_subnet)
        self.assertEqual(operations.aws.args[-1], member.gwlbe_route_table_id)

        table["Routes"][1]["NetworkInterfaceId"] = (
            deployment.topology.west.transport_router_fleet[1].network_interface_id
        )
        with self.assertRaisesRegex(e2e.ReadinessError, "protected next hop"):
            operations._verify_gwlbe_post_inspection_routes(deployment, member, endpoint_subnet)

    def test_target_selection_uses_geneve_receive_and_return_not_tun_tx(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        first, second = deployment.topology.west.target_fleet

        def snapshot(generation: str, rx: int, tx: int, tun_tx: int) -> e2e.MetricSnapshot:
            return e2e.parse_prometheus_metrics(
                f"geneve_rx_packets {rx}\ngeneve_tx_packets {tx}\ntun_tx_packets {tun_tx}\n",
                generation=generation,
            )

        before = {
            first.instance_id: snapshot("first", 10, 10, 10),
            second.instance_id: snapshot("second", 10, 10, 10),
        }
        after = {
            first.instance_id: snapshot("first", 11, 11, 10),
            second.instance_id: snapshot("second", 11, 10, 11),
        }
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)

        self.assertEqual(
            operations._selected_target(before, after, "west", deployment),
            first.instance_id,
        )

    def test_destination_router_discovery_runs_on_source_transport_router(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        source_router = deployment.topology.west.transport_router_fleet[0]
        destination_router = deployment.topology.east.transport_router_fleet[0]
        observed: list[object] = []

        def execute_json(target, command, **_kwargs):
            observed.extend([target, command])
            return {
                "peer_id": f"node-east-{destination_router.az_key}",
                "success": True,
            }

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(run_id="symmetric-fixture")
        operations.base = SimpleNamespace(_execute_json=execute_json)
        operations._tailnet_status_node_ids = lambda: {
            f"symmetric-fixture-east-transport-{member.az_key}": f"node-east-{member.az_key}"
            for member in deployment.topology.east.transport_router_fleet
        }

        selected = operations._selected_destination_transport_router(
            source_router,
            deployment.topology.east,
            "10.20.1.10",
        )

        self.assertEqual(selected, destination_router.instance_id)
        self.assertEqual(observed[0].instance_id, source_router.instance_id)
        self.assertEqual(observed[0].role, "transport-router")
        self.assertIn("10.20.1.0/24", observed[1])
        self.assertNotIn("10.20.2.0/24", observed[1])

        operations.base = SimpleNamespace(
            _execute_json=lambda *_args, **_kwargs: {
                "peer_id": "node-not-protected",
                "success": True,
            }
        )
        with self.assertRaisesRegex(e2e.ProbeError, "destination prefix owner"):
            operations._selected_destination_transport_router(
                source_router,
                deployment.topology.east,
                "10.20.1.10",
            )

    def test_ha25_live_transport_readiness_uses_remote_only_table52_and_status(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        member = deployment.topology.west.transport_router_fleet[0]
        commands: list[str] = []
        payloads: list[dict] = []
        mutation: list[str | None] = [None]

        class AWS:
            def json(self, args, *, region=None):
                self.assert_route_lookup(args, region)
                return {
                    "RouteTables": [
                        {
                            "RouteTableId": "rtb-8123456789abcdef0",
                            "VpcId": deployment.vpc_ids["west"],
                            "Associations": [
                                {
                                    "SubnetId": "subnet-0123456789abcdef0",
                                    "Main": False,
                                    "AssociationState": {"State": "associated"},
                                }
                            ],
                            "Routes": [
                                {
                                    "DestinationCidrBlock": cidr,
                                    "GatewayId": deployment.endpoint_ids["west"][member.az_key],
                                    "State": "active",
                                }
                                for cidr in deployment.topology.west.local_site_cidrs
                            ]
                        }
                    ]
                }

            @staticmethod
            def assert_route_lookup(args, region):
                if args[1] != "describe-route-tables" or region != "us-west-2":
                    raise AssertionError((args, region))

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(
            run_id="symmetric-fixture",
            raw={"envelope": packet_return_envelope()},
            sites={
                "west": {
                    "azs": {"a": "us-west-2a", "b": "us-west-2b"},
                    "transport_subnet_cidrs": {
                        "a": "10.10.6.0/24",
                        "b": "10.10.7.0/24",
                    },
                }
            },
        )
        operations.aws = AWS()
        operations.lifecycle = SimpleNamespace(
            manifest={
                "tailnet": {
                    "device_ids": {
                        "symmetric-fixture-east-transport-a": "peer-1",
                        "symmetric-fixture-east-transport-b": "peer-2",
                    }
                }
            }
        )
        operations._describe_instance = lambda _member: {
            "State": {"Name": "running"},
            "SourceDestCheck": False,
            "SubnetId": "subnet-0123456789abcdef0",
            "Placement": {"AvailabilityZone": f"us-west-2{member.az_key}"},
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": member.network_interface_id,
                    "SubnetId": "subnet-0123456789abcdef0",
                    "Status": "in-use",
                    "SourceDestCheck": False,
                    "Attachment": {"DeviceIndex": 0, "Status": "attached"},
                }
            ],
            "Tags": [
                {"Key": "EnvelopeRun", "Value": "symmetric-fixture"},
                {"Key": "Role", "Value": "transport-router"},
                {"Key": "Site", "Value": "west"},
                {"Key": "ZoneKey", "Value": member.az_key},
            ],
        }

        def execute_json(_target, command, **_kwargs):
            commands.append(command)
            payload = effective_transport_payload(
                deployment.transport_router_readiness_expectations["west"],
                member.advertised_prefix,
            )
            payload["primary_route_ownership"] = {
                "ObservedAt": payload["status"]["CheckedAt"],
                "Remote": [
                    {
                        **peer,
                        "Hostname": f"symmetric-fixture-east-transport-{az_key}",
                    }
                    for peer, az_key in zip(
                        payload["status"]["Self"]["RoutePeers"],
                        ("a", "b"),
                        strict=True,
                    )
                ],
                "Local": [],
            }
            if mutation[0] == "table52-local":
                payload["table52_routes"].append(
                    {
                        "dst": deployment.topology.west.transport_router_fleet[
                            1
                        ].advertised_prefix,
                        "dev": "tailscale0",
                        "type": "unicast",
                    }
                )
            elif mutation[0] == "status-local":
                payload["primary_route_ownership"]["Local"] = [
                    {
                        **payload["status"]["Self"]["RoutePeers"][0],
                        "Prefix": deployment.topology.west.transport_router_fleet[
                            1
                        ].advertised_prefix,
                        "PeerID": "node-west-b",
                        "Hostname": "symmetric-fixture-west-transport-b",
                        "Ping": {
                            **payload["status"]["Self"]["RoutePeers"][0][
                                "Ping"
                            ],
                            "PeerID": "node-west-b",
                        },
                    }
                ]
            payloads.append(copy.deepcopy(payload))
            return {
                "payload": payload,
                "success": True,
            }

        operations.base = SimpleNamespace(
            _tags=e2e.AwsLiveOperations._tags,
            _execute_json=execute_json,
            _route_selects_only_target=e2e.AwsLiveOperations._route_selects_only_target,
        )
        operations._remote = lambda _member: SimpleNamespace()
        operations._wait_transport_routes_enabled = mock.Mock(
            return_value="device-transport-a"
        )
        operations._tailnet_status_identities = lambda: {
            "symmetric-fixture-west-transport-a": {
                "node_id": "node-west-a",
                "key_expiry": "2025-01-01T00:00:00Z",
                "key_expiry_disabled": True,
                "authorized": True,
            },
            "symmetric-fixture-west-transport-b": {
                "node_id": "node-west-b",
                "key_expiry": "2025-01-01T00:00:00Z",
                "key_expiry_disabled": True,
                "authorized": True,
            },
            "symmetric-fixture-east-transport-a": {
                "node_id": "peer-1",
                "key_expiry": "2025-01-01T00:00:00Z",
                "key_expiry_disabled": True,
                "authorized": True,
            },
            "symmetric-fixture-east-transport-b": {
                "node_id": "peer-2",
                "key_expiry": "2025-01-01T00:00:00Z",
                "key_expiry_disabled": True,
                "authorized": True,
            },
        }
        operations._verify_primary_network_binding = mock.Mock()

        identity = operations._verify_transport_router(deployment, member)

        operations._wait_transport_routes_enabled.assert_called_once_with(
            member,
            [member.advertised_prefix],
            timeout_seconds=60,
        )
        self.assertEqual(len(commands), 1)
        self.assertLess(len(commands[0]), 16_384)
        self.assertIn("net.ipv4.ip_forward", commands[0])
        self.assertIn("ENVELOPE-TRANSPORT-FORWARD", commands[0])
        self.assertIn("ENVELOPE-TRANSPORT-MSS", commands[0])
        self.assertIn("iptables-save", commands[0])
        self.assertIn("ip6tables-save", commands[0])
        self.assertIn('["/usr/sbin/nft","-j","list","ruleset"]', commands[0])
        self.assertIn(
            '["/usr/sbin/ip","-j","-details","-4","route","show","table","52"]',
            commands[0],
        )
        self.assertIn("tailscale\",\"ping", commands[0])
        self.assertIn('"--until-direct=false"', commands[0])
        self.assertIn('binding.get("KeyExpiry")', commands[0])
        self.assertIn('binding.get("KeyExpiryDisabled")', commands[0])
        self.assertNotIn('peer.get("KeyExpiry")', commands[0])
        self.assertNotIn('self_value.get("KeyExpiry")', commands[0])
        self.assertNotIn('.get("Expired")', commands[0])
        self.assertIn(
            deployment.transport_router_readiness_expectations["west"][
                "contract_sha256"
            ],
            commands[0],
        )
        self.assertIn("transport-router-network.state.json", commands[0])
        self.assertIn("if selected_local:", commands[0])
        self.assertEqual(
            [route["dst"] for route in payloads[0]["table52_routes"]],
            list(deployment.topology.west.remote_site_cidrs),
        )
        self.assertEqual(
            payloads[0]["status"]["Self"]["AcceptedRoutes"],
            list(deployment.topology.west.remote_site_cidrs),
        )
        self.assertEqual(
            [
                route["Prefix"]
                for route in payloads[0]["status"]["Self"]["RoutePeers"]
            ],
            list(deployment.topology.west.remote_site_cidrs),
        )
        self.assertEqual(payloads[0]["primary_route_ownership"]["Local"], [])
        self.assertEqual(
            [entry["prefix"] for entry in identity["primary_route_ownership"]["remote"]],
            list(deployment.topology.west.remote_site_cidrs),
        )
        self.assertEqual(identity["primary_route_ownership"]["local"], [])
        shell_parts = shlex.split(commands[0])
        python_index = shell_parts.index("python3")
        self.assertEqual(shell_parts[python_index + 1], "-c")
        compile(shell_parts[python_index + 2], "<transport-readiness-collector>", "exec")
        subprocess.run(
            ["bash", "-n", "-c", commands[0]],
            check=True,
            capture_output=True,
            text=True,
        )
        mutation[0] = "table52-local"
        with self.assertRaisesRegex(e2e.ReadinessError, "table 52 contains a local-site route"):
            operations._verify_transport_router(deployment, member)
        mutation[0] = "status-local"
        with self.assertRaisesRegex(e2e.ReadinessError, "local primary-route ownership"):
            operations._verify_transport_router(deployment, member)

    def test_live_transport_readiness_waits_for_exact_enabled_tailnet_routes(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        member = deployment.topology.west.transport_router_fleet[0]
        routes = [member.advertised_prefix]
        device = {
            "id": "device-transport-a",
            "hostname": "symmetric-fixture-west-transport-a",
            "tags": ["tag:fixture"],
            "advertisedRoutes": routes,
            "enabledRoutes": routes,
        }
        api = SimpleNamespace(list_devices=lambda: [device])

        def wait(operation, predicate, **_kwargs):
            value = operation()
            if not predicate(value):
                raise e2e.ReadinessError("not enabled")
            return value

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(
            run_id="symmetric-fixture",
            tailnet={"tag": "tag:fixture"},
        )
        operations.lifecycle = SimpleNamespace(
            manifest={
                "tailnet": {
                    "device_ids": {
                        "symmetric-fixture-west-transport-a": "device-transport-a"
                    }
                }
            }
        )
        operations.base = SimpleNamespace(_wait_until=wait)
        with mock.patch.object(e2e, "build_tailscale", return_value=api):
            operations._wait_transport_routes_enabled(member, routes, timeout_seconds=60)
            device["enabledRoutes"] = []
            with self.assertRaisesRegex(e2e.ReadinessError, "not enabled"):
                operations._wait_transport_routes_enabled(member, routes, timeout_seconds=60)
            device["enabledRoutes"] = routes
            device["id"] = "device-wrong-node"
            with self.assertRaisesRegex(e2e.ReadinessError, "not enabled"):
                operations._wait_transport_routes_enabled(member, routes, timeout_seconds=60)

    def test_tailnet_status_identity_uses_stable_node_id_not_api_device_id(self) -> None:
        config = SimpleNamespace(
            run_id="symmetric-fixture",
            tailnet={"tag": "tag:fixture"},
            sites={
                site: {"transport_router_az_keys": ["a", "b"]}
                for site in e2e.SITES
            },
        )
        hostnames = e2e.expected_tailnet_hostnames(config)
        recorded = {
            hostname: f"device-{index}"
            for index, hostname in enumerate(hostnames, start=1)
        }
        devices = [
            {
                "id": recorded[hostname],
                "nodeId": f"node-{index}",
                "hostname": hostname,
                "tags": ["tag:fixture"],
                "expires": "2025-01-01T00:00:00Z",
                "keyExpiryDisabled": True,
                "authorized": True,
            }
            for index, hostname in enumerate(hostnames, start=1)
        ]
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = config
        operations.lifecycle = SimpleNamespace(
            manifest={"tailnet": {"device_ids": recorded}}
        )
        with mock.patch.object(
            e2e,
            "build_tailscale",
            return_value=SimpleNamespace(list_devices=lambda: devices),
        ):
            self.assertEqual(
                operations._tailnet_status_identities(),
                {
                    hostname: {
                        "node_id": f"node-{index}",
                        "key_expiry": "2025-01-01T00:00:00Z",
                        "key_expiry_disabled": True,
                        "authorized": True,
                    }
                    for index, hostname in enumerate(hostnames, start=1)
                },
            )
            self.assertEqual(
                operations._tailnet_status_node_ids(),
                {
                    hostname: f"node-{index}"
                    for index, hostname in enumerate(hostnames, start=1)
                },
            )

        del operations._tailnet_status_identity_cache
        devices[0].pop("nodeId")
        with mock.patch.object(
            e2e,
            "build_tailscale",
            return_value=SimpleNamespace(list_devices=lambda: devices),
        ), self.assertRaisesRegex(e2e.ReadinessError, "stable node ID"):
            operations._tailnet_status_identities()

        devices[0]["nodeId"] = "node-1"
        devices[0].pop("keyExpiryDisabled")
        with mock.patch.object(
            e2e,
            "build_tailscale",
            return_value=SimpleNamespace(list_devices=lambda: devices),
        ), self.assertRaisesRegex(e2e.ReadinessError, "key-expiry mode"):
            operations._tailnet_status_identities()

        devices[0]["keyExpiryDisabled"] = True
        devices[0]["authorized"] = False
        with mock.patch.object(
            e2e,
            "build_tailscale",
            return_value=SimpleNamespace(list_devices=lambda: devices),
        ), self.assertRaisesRegex(e2e.ReadinessError, "not authorized"):
            operations._tailnet_status_identities()

    def test_effective_firewall_and_policy_parsers_reject_live_drift(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        contract = deployment.transport_router_readiness_expectations["west"]
        payload = effective_transport_payload(contract)

        firewall = e2e._effective_transport_firewall(payload["firewall"], contract)
        policy = e2e._effective_local_policy_rules(payload["policy_rules"], contract)
        self.assertEqual(firewall["filter_forward_policy"], "DROP")
        self.assertEqual(firewall["mangle_forward_policy"], "ACCEPT")
        self.assertEqual(firewall["ipv6_mangle_forward_policy"], "ACCEPT")
        self.assertEqual(firewall["native_nft_rules"], [])
        self.assertEqual(policy, contract["local_policy_rules"])

        commented = copy.deepcopy(payload["firewall"])
        commented["iptables_filter"] = commented["iptables_filter"].replace(
            "-A FORWARD -j ENVELOPE-TRANSPORT-FORWARD",
            '-A FORWARD -m comment --comment "fixture hook" -j ENVELOPE-TRANSPORT-FORWARD',
        )
        e2e._effective_transport_firewall(commented, contract)

        saved_hex_flags = copy.deepcopy(payload["firewall"])
        saved_hex_flags["iptables_mangle"] = saved_hex_flags[
            "iptables_mangle"
        ].replace("--tcp-flags SYN,RST SYN", "--tcp-flags 0x06/0x02")
        e2e._effective_transport_firewall(saved_hex_flags, contract)

        extra_forward = copy.deepcopy(payload["firewall"])
        extra_forward["iptables_filter"] = extra_forward["iptables_filter"].replace(
            "COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT"
        )
        with self.assertRaisesRegex(e2e.ReadinessError, "unapproved append"):
            e2e._effective_transport_firewall(extra_forward, contract)

        native_nft = copy.deepcopy(payload["firewall"])
        native_nft["nftables"]["nftables"].append({"table": {"name": "unowned"}})
        with self.assertRaisesRegex(e2e.ReadinessError, "nftables"):
            e2e._effective_transport_firewall(native_nft, contract)

        conflicting_policy = copy.deepcopy(payload["policy_rules"])
        conflicting_policy.insert(
            1,
            {
                "priority": 50,
                "dst": contract["local_site_cidrs"][0],
                "table": "main",
            },
        )
        with self.assertRaisesRegex(e2e.ReadinessError, "complete effective"):
            e2e._effective_local_policy_rules(conflicting_policy, contract)

    def test_transport_restoration_reapplies_preferences_before_network_activation(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        member = deployment.topology.west.transport_router_fleet[0]
        commands: list[str] = []
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.adapter = SimpleNamespace(
            command=lambda _member, command: commands.append(command) or {}
        )
        operations._wait_transport_running = mock.Mock()
        operations._verify_transport_router = mock.Mock()

        operations._restore_transport_router(deployment, member)

        self.assertEqual(commands[0], "systemctl start tailscaled.service")
        self.assertIn("tailscale set --accept-routes=true", commands[1])
        self.assertIn("--snat-subnet-routes=false", commands[1])
        self.assertIn("--advertise-routes=10.10.1.0/24", commands[1])
        self.assertIn("transport-router-network.configured", commands[2])
        self.assertIn("systemctl enable envelope-transport-router-network.service", commands[2])
        self.assertIn("systemctl restart envelope-transport-router-network.service", commands[2])
        self.assertIn("systemctl is-enabled --quiet", commands[2])
        operations._wait_transport_running.assert_called_once_with(
            member, timeout_seconds=90
        )
        operations._verify_transport_router.assert_called_once_with(deployment, member)

    def test_transport_restoration_failure_disables_forwarding(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        member = deployment.topology.west.transport_router_fleet[0]
        commands: list[str] = []
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.adapter = SimpleNamespace(
            command=lambda _member, command: commands.append(command) or {}
        )
        operations._wait_transport_running = mock.Mock()
        operations._verify_transport_router = mock.Mock(
            side_effect=e2e.ReadinessError("injected effective drift")
        )

        with self.assertRaisesRegex(e2e.ReadinessError, "effective drift"):
            operations._restore_transport_router(deployment, member)

        self.assertIn("systemctl stop envelope-transport-router-network.service", commands[-1])
        self.assertIn("net.ipv4.ip_forward=0", commands[-1])
        self.assertIn("net.ipv6.conf.all.forwarding=0", commands[-1])

    def test_transport_restoration_does_not_swallow_protected_control_flow(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        member = deployment.topology.west.transport_router_fleet[0]
        control = e2e.ProtectedHardTimeout("restoration hard deadline")
        commands: list[str] = []

        def command(_member, value):
            commands.append(value)
            if value.startswith("tailscale set"):
                raise control
            return {}

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.adapter = SimpleNamespace(command=command)
        operations._wait_transport_running = mock.Mock()
        operations._verify_transport_router = mock.Mock()

        with self.assertRaises(e2e.ProtectedHardTimeout) as raised:
            operations._restore_transport_router(deployment, member)

        self.assertIs(raised.exception, control)
        self.assertEqual(len(commands), 2)
        self.assertFalse(any("systemctl stop" in value for value in commands))
        operations._verify_transport_router.assert_not_called()

    def test_established_target_attribution_is_exact_and_packet_correlated(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        first, second = deployment.topology.west.target_fleet
        ledger = e2e.FlowLedger("symmetric-fixture")
        flow = ledger.allocate(
            "tcp",
            deployment.workloads.target("west", "initiator"),
            deployment.workloads.target("east", "responder"),
            destination_port=5201,
            purpose="established-attribution",
            generation=ledger.begin_generation("established-attribution"),
        )
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations._start_geneve_captures = mock.Mock(return_value={"capture": object()})
        operations._finish_geneve_captures = mock.Mock(
            return_value={first.instance_id: {"selected": True}, second.instance_id: {}}
        )

        def correlate(capture, _flow, *, target_id, raw_deleted):
            self.assertTrue(raw_deleted)
            if capture.get("selected") is not True:
                raise e2e.WireAssertionError("no exact tuple")
            return {"target_id": target_id}

        with mock.patch.object(
            e2e, "correlate_geneve_turnaround_capture", side_effect=correlate
        ) as correlation:
            selected = operations._selected_established_target(
                deployment, flow, timeout_seconds=20
            )

        self.assertEqual(selected, first)
        self.assertEqual(correlation.call_count, 2)
        operations._finish_geneve_captures.assert_called_once_with(
            {"capture": mock.ANY}, inspect=True
        )

        operations._finish_geneve_captures.return_value = {
            first.instance_id: {"selected": True},
            second.instance_id: {"selected": True},
        }
        with mock.patch.object(
            e2e, "correlate_geneve_turnaround_capture", side_effect=correlate
        ), self.assertRaisesRegex(e2e.ResilienceError, "resolved to 2"):
            operations._selected_established_target(
                deployment, flow, timeout_seconds=20
            )

    def test_instance_replacement_refuses_different_packet_correlated_stream_targets(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(
            symmetric_protected_output()
        )
        first, second = deployment.topology.west.target_fleet
        ledger = e2e.FlowLedger("symmetric-fixture")

        def flow(protocol: str, purpose: str) -> e2e.FlowRecord:
            return ledger.allocate(
                protocol,
                deployment.workloads.target("west", "initiator"),
                deployment.workloads.target("east", "responder"),
                destination_port=5201,
                purpose=purpose,
                generation=ledger.begin_generation(purpose),
            )

        new_udp = flow("udp", "instance-new-udp")
        new_tcp = flow("tcp", "instance-new-tcp")
        established_tcp = flow("tcp", "instance-established-tcp")
        established_udp = flow("udp", "instance-established-udp")
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.base = SimpleNamespace(monotonic=lambda: 1.0)
        operations.adapter = SimpleNamespace(
            command=mock.Mock(),
            owned=lambda *_args: True,
        )
        operations._target_readiness_identities = {}
        operations._selected_established_target = mock.Mock(
            side_effect=(first, second)
        )
        operations._measure_tcp_udp_failure = lambda *_args, **kwargs: kwargs[
            "mutate_and_restore"
        ]()

        with self.assertRaisesRegex(e2e.ResilienceError, "did not select one"):
            operations.run_target_instance_recovery(
                deployment,
                first,
                new_udp,
                new_tcp,
                established_tcp,
                established_udp,
                timeout_seconds=30,
            )

        operations.adapter.command.assert_not_called()

    def test_live_cold_probe_uses_the_protocol_specific_sender(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)

        def probe(*_args, before_client, **_kwargs):
            before_client()
            return {"success": True}

        operations.base = SimpleNamespace(
            _run_icmp_probe=mock.Mock(side_effect=probe),
            _run_probe=mock.Mock(side_effect=probe),
        )
        ledger = e2e.FlowLedger("symmetric-fixture")
        with mock.patch.object(e2e, "_validate_probe_evidence"):
            for protocol in e2e.PROTOCOLS:
                flow = ledger.allocate(
                    protocol,
                    deployment.workloads.target("west", "initiator"),
                    deployment.workloads.target("east", "responder"),
                    destination_port=None if protocol == "icmp" else 5201,
                    purpose=f"cold-{protocol}",
                    generation=ledger.begin_generation(f"cold-{protocol}"),
                )
                result = operations.run_cold_probe(
                    deployment,
                    flow,
                    start_barrier=threading.Barrier(1),
                    timeout_seconds=60,
                )
                self.assertEqual(result["protocol"], protocol)

        operations.base._run_icmp_probe.assert_called_once()
        self.assertEqual(operations.base._run_probe.call_count, 2)

    def test_real_symmetric_runner_composition_emits_schema_three_after_cleanup(self) -> None:
        raw = symmetric_protected_output()
        parsed = e2e.parse_symmetric_protected_deployment_output(raw)

        class Lifecycle:
            def __init__(self, *, fail_cleanup: bool = False) -> None:
                self.calls: list[str] = []
                self.fail_cleanup = fail_cleanup

            def claim(self, raw_deployment, deployment):
                self.calls.append("claim")
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                self.calls.append(f"drift-{stage}")
                return {"clean": True}

            def replace_target_instance(self, member):
                raise AssertionError("fake operations own replacement")

            def finish(self, passed):
                self.calls.append(f"finish-{passed}")
                return {"acceptance": "passed" if passed else "failed"}

            def cleanup(self):
                self.calls.append("cleanup")
                if self.fail_cleanup:
                    raise e2e.LifecycleError("injected cleanup failure")
                return {"final_residual_count": 0}

        class Operations:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def verify_readiness(self, deployment, *, timeout_seconds):
                self.calls.append("readiness")
                return readiness_document(deployment.topology)

            def run_cold_probe(self, deployment, flow, *, start_barrier, timeout_seconds):
                self.calls.append(f"cold-{flow.source.site}")
                start_barrier.wait(timeout=1)
                dispatched = time.monotonic_ns()
                time.sleep(0.01)
                return {
                    "source_site": flow.source.site,
                    "destination_site": flow.destination.site,
                    "source_role": flow.source.role,
                    "destination_role": flow.destination.role,
                    "protocol": flow.protocol,
                    "source_az_key": flow.source.az_key,
                    "source_gwlbe_id": deployment.endpoint_ids[flow.source.site][flow.source.az_key],
                    "dispatch_monotonic_ns": dispatched,
                    "succeeded": True,
                }

            @staticmethod
            def turnaround(target_id):
                return {
                    "target_id": target_id,
                    "metrics": {
                        "geneve_rx_packets_delta": 1.0,
                        "geneve_tx_packets_delta": 1.0,
                        "geneve_options_validation_errors_delta": 0.0,
                        "gwlb_profile_rejections_total_delta": 0.0,
                        "gwlb_receive_drops_total_delta": 0.0,
                        "gwlb_inner_validation_failures_total_delta": 0.0,
                        "gwlb_return_build_failures_total_delta": 0.0,
                        "gwlb_send_failures_total_delta": 0.0,
                        "drops_delta": 0.0,
                        "gwlb_target_ready": 1.0,
                        "components_ready": {
                            "receiver": 1.0,
                            "validation": 1.0,
                            "sender": 1.0,
                        },
                    },
                    "fidelity": {
                        "observed": True,
                        "target_id": target_id,
                        "capture_sha256": "1" * 64,
                        "capture_frame_count": 2,
                        "raw_pcap_deleted": True,
                        "pairs": [{
                            "direction": "request",
                            "ingress_frame_sha256": "2" * 64,
                            "return_frame_sha256": "3" * 64,
                            "inner_packet_sha256": "4" * 64,
                            "ordered_options_sha256": "5" * 64,
                            "flow_cookie_sha256": "6" * 64,
                            "vni": 0,
                            "outer_tuple_swapped": True,
                            "return_source_port_preserved": True,
                        }],
                    },
                }

            def run_traversal(self, deployment, source_site, flows, *, timeout_seconds):
                self.calls.append(f"traversal-{source_site}")
                destination = e2e._opposite(source_site)
                source_target = deployment.topology.site(source_site).target_fleet[0]
                destination_target = deployment.topology.site(destination).target_fleet[0]
                destination_router = next(
                    member
                    for member in deployment.topology.site(
                        destination
                    ).transport_router_fleet
                    if member.az_key == flows[0].destination.az_key
                )
                return {
                    "source_site": source_site,
                    "destination_site": destination,
                    "probes": [
                        {
                            "protocol": flow.protocol,
                            "source_role": flow.source.role,
                            "destination_role": flow.destination.role,
                            "source_az_key": flow.source.az_key,
                            "destination_az_key": flow.destination.az_key,
                            "source_gwlbe_id": deployment.endpoint_ids[source_site][flow.source.az_key],
                            "destination_gwlbe_id": deployment.endpoint_ids[
                                destination
                            ][flow.destination.az_key],
                            "source_target_id": source_target.instance_id,
                            "destination_target_id": destination_target.instance_id,
                            "source_transport_router_id": next(
                                member.instance_id
                                for member in deployment.topology.site(
                                    source_site
                                ).transport_router_fleet
                                if member.az_key == flow.source.az_key
                            ),
                            "source_transport_eni_id": next(
                                member.network_interface_id
                                for member in deployment.topology.site(
                                    source_site
                                ).transport_router_fleet
                                if member.az_key == flow.source.az_key
                            ),
                            "destination_transport_router_id": next(
                                member.instance_id
                                for member in deployment.topology.site(
                                    destination
                                ).transport_router_fleet
                                if member.az_key == flow.destination.az_key
                            ),
                            "geneve_return_proof": {
                                "source": self.turnaround(source_target.instance_id),
                                "destination": self.turnaround(
                                    destination_target.instance_id
                                ),
                            },
                            "source_preserved": True,
                        }
                        for flow in flows
                    ],
                }

            def run_target_process_recovery(
                self, deployment, failed, new_flow, new_tcp_flow, tcp_flow, udp_flow, *, timeout_seconds
            ):
                self.calls.append("target-process")
                alternate = deployment.topology.site(failed.site).target_fleet[1]
                return {
                    "recovery": {"kind": "target-process", "site": failed.site, "failed_id": failed.instance_id, "alternate_id": alternate.instance_id, "new_flow_succeeded": True, "new_flows": legacy_e2e_test.new_flow_evidence(), "recovery_duration_ms": 10},
                    "health_transitions": [{"kind": "target-process", "member_id": failed.instance_id, "states": ["healthy", "unhealthy", "healthy"]}],
                    "transport": legacy_e2e_test.failure_transport_evidence(
                        failed.instance_id, "target-process"
                    ),
                }

            def run_target_instance_recovery(
                self, deployment, failed, new_flow, new_tcp_flow, tcp_flow, udp_flow, *, timeout_seconds
            ):
                self.calls.append("target-instance")
                alternate = deployment.topology.site(failed.site).target_fleet[1]
                return deployment, {
                    "recovery": {"kind": "target-instance", "site": failed.site, "failed_id": failed.instance_id, "alternate_id": alternate.instance_id, "replacement_id": "i-ff23456789abcdef", "replacement_ready": True, "old_process_generation_sha256": "7" * 64, "replacement_process_generation_sha256": "8" * 64, "target_group_arn": failed.target_group_arn, "registration_port": 6081, "drain_state": "draining", "drain_duration_ms": 5, "new_flow_succeeded": True, "new_flows": legacy_e2e_test.new_flow_evidence(), "recovery_duration_ms": 20},
                    "health_transition": {"kind": "target-instance", "member_id": failed.instance_id, "states": ["healthy", "draining", "replaced"]},
                    "transport": legacy_e2e_test.failure_transport_evidence(
                        failed.instance_id, "target-instance"
                    ),
                }

            def run_transport_router_recovery(
                self,
                deployment,
                graceful_failed,
                abrupt_failed,
                graceful_flow,
                abrupt_flow,
                graceful_new_tcp_flow,
                abrupt_new_tcp_flow,
                graceful_tcp_flow,
                graceful_udp_flow,
                abrupt_tcp_flow,
                abrupt_udp_flow,
                *,
                timeout_seconds,
            ):
                self.calls.append("transport-router")
                graceful_alternate = next(
                    member
                    for member in deployment.topology.site(
                        graceful_failed.site
                    ).transport_router_fleet
                    if member != graceful_failed
                )
                abrupt_alternate = next(
                    member
                    for member in deployment.topology.site(
                        abrupt_failed.site
                    ).transport_router_fleet
                    if member != abrupt_failed
                )
                assert abrupt_failed.gwlbe_route_table_id is not None
                assert abrupt_failed.network_interface_id is not None
                assert abrupt_alternate.network_interface_id is not None

                def snapshot(network_interface_id):
                    return {
                        "route_table_id": abrupt_failed.gwlbe_route_table_id,
                        "vpc_id": deployment.vpc_ids[abrupt_failed.site],
                        "ownership": {
                            "EnvelopeRun": deployment.topology.run_id,
                            "ManagedBy": "terraform",
                            "Profile": "symmetric-gwlb-ha-v2",
                            "Role": "gwlbe",
                            "ZoneKey": abrupt_failed.az_key,
                        },
                        "routes": [
                            {
                                "destination_cidr_block": prefix,
                                "network_interface_id": network_interface_id,
                                "origin": "CreateRoute",
                                "route_state": "active",
                            }
                            for prefix in deployment.topology.site(
                                abrupt_failed.site
                            ).remote_site_cidrs
                        ],
                    }

                abrupt_probe = {
                    "succeeded": True,
                    "source_transport_router_id": abrupt_alternate.instance_id,
                    "source_transport_eni_id": abrupt_alternate.network_interface_id,
                    "new_flows": legacy_e2e_test.new_flow_evidence(
                        source_transport_router_id=abrupt_alternate.instance_id,
                        source_transport_eni_id=abrupt_alternate.network_interface_id,
                    ),
                }
                prefixes = list(
                    deployment.topology.site(abrupt_failed.site).remote_site_cidrs
                )
                route_replacement = {
                    "route_table_id": abrupt_failed.gwlbe_route_table_id,
                    "gwlbe_az_key": abrupt_failed.az_key,
                    "prefixes": prefixes,
                    "current": {
                        "instance_id": abrupt_failed.instance_id,
                        "network_interface_id": abrupt_failed.network_interface_id,
                    },
                    "alternate": {
                        "instance_id": abrupt_alternate.instance_id,
                        "network_interface_id": abrupt_alternate.network_interface_id,
                    },
                    "bounds": {
                        "approved_inputs": deployment.topology.route_failover.approved_bounds(),
                        "effective": {
                            "mutation_timeout_seconds": 30,
                            "restoration_timeout_seconds": 30,
                            **deployment.topology.route_failover.derived_bounds(),
                        },
                        "derivation": {
                            "settlement_timeout_seconds": "recovery_timeout_seconds",
                            "quiet_window_seconds": (
                                "min(10,max(1,restoration_timeout_seconds//10))"
                            ),
                            "owner_lease_seconds": (
                                "max(mutation_timeout_seconds,restoration_timeout_seconds,"
                                "recovery_timeout_seconds)+quiet_window_seconds+5"
                            ),
                        },
                    },
                    "before": snapshot(abrupt_failed.network_interface_id),
                    "after": snapshot(abrupt_alternate.network_interface_id),
                    "probe": abrupt_probe,
                    "restoration": {
                        "status": "verified",
                        "attempted_prefixes": prefixes,
                        "api_failures": [],
                        "settled_prefixes": prefixes,
                        "quiet_window_seconds": deployment.topology.route_failover.quiet_window_seconds,
                        "routes": snapshot(abrupt_failed.network_interface_id),
                    },
                    "restored": True,
                }
                graceful_probe = {
                    "succeeded": True,
                    "destination_transport_router_id": graceful_alternate.instance_id,
                    "new_flows": legacy_e2e_test.new_flow_evidence(
                        destination_transport_router_id=graceful_alternate.instance_id
                    ),
                }
                graceful_route_replacement = (
                    legacy_e2e_test.coordinated_route_replacement_fixture(
                        deployment,
                        graceful_failed,
                        graceful_alternate,
                        graceful_probe,
                        "graceful",
                    )
                )
                route_replacement = (
                    legacy_e2e_test.coordinated_route_replacement_fixture(
                        deployment,
                        abrupt_failed,
                        abrupt_alternate,
                        abrupt_probe,
                        "abrupt",
                    )
                )
                return {
                    "recovery": {"kind": "transport-router", "site": abrupt_failed.site, "failed_id": abrupt_failed.instance_id, "alternate_id": abrupt_alternate.instance_id, "new_flow_succeeded": True, "new_flows": abrupt_probe["new_flows"], "recovery_duration_ms": 30},
                    "health_transition": {"kind": "transport-router", "member_id": abrupt_failed.instance_id, "states": ["healthy", "unavailable", "healthy"]},
                    "transport": {
                        "graceful": legacy_e2e_test.failure_transport_evidence(
                            graceful_failed.instance_id, "router-graceful"
                        ),
                        "abrupt": legacy_e2e_test.failure_transport_evidence(
                            abrupt_failed.instance_id, "router-abrupt"
                        ),
                    },
                    "graceful": {
                        "control_plane": "tailnet-and-gwlbe-route",
                        "failed_id": graceful_failed.instance_id,
                        "alternate_id": graceful_alternate.instance_id,
                        "probe": graceful_probe,
                        "new_flows": graceful_probe["new_flows"],
                        "new_flow_succeeded": True,
                        "recovery_duration_ms": 20,
                        "route_replacement": graceful_route_replacement,
                        "restored": True,
                    },
                    "abrupt": {
                        "control_plane": "tailnet-and-gwlbe-route",
                        "failed_id": abrupt_failed.instance_id,
                        "alternate_id": abrupt_alternate.instance_id,
                        "probe": abrupt_probe,
                        "new_flows": abrupt_probe["new_flows"],
                        "new_flow_succeeded": True,
                        "recovery_duration_ms": 30,
                        "route_replacement": route_replacement,
                        "restored": True,
                    },
                }

            def collect_diagnostics(self, deployment):
                self.calls.append("diagnostics")
                return {}

        lifecycle, operations = Lifecycle(), Operations()
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = pathlib.Path(temporary) / "evidence.json"
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=lifecycle,
                operations=operations,
                evidence_path=evidence_path,
            ).run()
            persisted = e2e.load_evidence(evidence_path)
        self.assertTrue(result.passed, result.error)
        self.assertEqual(persisted["schema"], 3)
        self.assertTrue(
            all(
                identity["primary_route_ownership"]["local"] == []
                for site in e2e.SITES
                for identity in persisted["preflight"]["sites"][site][
                    "transport_routers"
                ].values()
            )
        )
        self.assertEqual(lifecycle.calls, ["claim", "drift-before", "drift-after", "finish-True", "cleanup"])
        self.assertEqual(
            operations.calls[0],
            "readiness",
        )
        self.assertEqual(operations.calls[1:7].count("cold-west"), 3)
        self.assertEqual(operations.calls[1:7].count("cold-east"), 3)
        self.assertEqual(
            operations.calls[7:],
            ["traversal-west", "traversal-east", "target-process", "target-instance", "transport-router"],
        )

        failed_lifecycle, failed_operations = Lifecycle(fail_cleanup=True), Operations()
        with tempfile.TemporaryDirectory() as temporary:
            failed = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=failed_lifecycle,
                operations=failed_operations,
                evidence_path=pathlib.Path(temporary) / "cleanup-failure.json",
            ).run()
        self.assertEqual(failed.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(failed_lifecycle.calls.count("cleanup"), 1)
        self.assertNotIn("acceptance_failure_before_cleanup", failed.evidence["diagnostics"])

    def test_cold_failure_retains_all_six_bounded_redacted_outcomes(self) -> None:
        raw = symmetric_protected_output()
        calls: list[tuple[str, str]] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                return {"clean": True}

            def finish(self, passed):
                self.passed = passed
                return {"acceptance": "passed" if passed else "failed"}

            def cleanup(self):
                return {"final_residual_count": 0}

        class Operations:
            def verify_readiness(self, deployment, *, timeout_seconds):
                return readiness_document(deployment.topology)

            def run_cold_probe(
                self, deployment, flow, *, start_barrier, timeout_seconds
            ):
                start_barrier.wait(timeout=2)
                calls.append((flow.source.site, flow.protocol))
                if flow.source.site == "west" and flow.protocol == "tcp":
                    error = e2e.ProbeError("injected cold probe failure")
                    error.stdout = "token=fixture-sensitive-value\n" + "x" * 6000
                    error.stderr = "tskey-fixture-sensitive-value\n" + "y" * 6000
                    error.dispatch_monotonic_ns = 123
                    raise error
                return {
                    "source_site": flow.source.site,
                    "destination_site": flow.destination.site,
                    "source_role": flow.source.role,
                    "destination_role": flow.destination.role,
                    "protocol": flow.protocol,
                    "source_az_key": flow.source.az_key,
                    "source_gwlbe_id": deployment.endpoint_ids[flow.source.site][flow.source.az_key],
                    "dispatch_monotonic_ns": 100,
                    "succeeded": True,
                }

            def collect_diagnostics(self, deployment):
                return {"collection": "complete"}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "cold-failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(len(calls), 6)
        self.assertEqual(len(result.evidence["cold_initiation"]), 6)
        failed = [value for value in result.evidence["cold_initiation"] if not value["succeeded"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["dispatch_monotonic_ns"], 123)
        self.assertLessEqual(len(failed[0]["stdout"]), e2e._COLD_FAILURE_OUTPUT_LIMIT)
        self.assertLessEqual(len(failed[0]["stderr"]), e2e._COLD_FAILURE_OUTPUT_LIMIT)
        self.assertNotIn("fixture-sensitive-value", failed[0]["stdout"])
        self.assertNotIn("tskey-fixture-sensitive-value", failed[0]["stderr"])
        self.assertIn("[REDACTED", failed[0]["stdout"])
        self.assertIn("[REDACTED", failed[0]["stderr"])

    def test_symmetric_diagnostics_collect_metrics_routes_firewall_first_with_counters(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(symmetric_protected_output())
        commands: list[str] = []

        def execute(target, command, **_kwargs):
            commands.append(command)
            return e2e.SSMResult(
                target,
                f"diagnostic-{len(commands)}",
                "Success",
                0,
                stdout="token=fixture-sensitive-value\n" + "x" * 10_000,
                stderr="tskey-fixture-sensitive-value",
            )

        with tempfile.TemporaryDirectory() as temporary:
            operations = object.__new__(e2e.AwsSymmetricLiveOperations)
            operations.config = SimpleNamespace(
                raw={"envelope": packet_return_envelope()}
            )
            operations.base = SimpleNamespace(_execute=execute)
            operations.run_dir = pathlib.Path(temporary)
            operations._target_health = lambda _member: "healthy"

            diagnostics = operations.collect_diagnostics(deployment)

        self.assertEqual(
            diagnostics["counters"],
            {
                "hosts_attempted": 12,
                "hosts_completed": 12,
                "hosts_failed": 0,
                "target_health_attempted": 4,
                "target_health_completed": 4,
                "target_health_failed": 0,
            },
        )
        self.assertEqual(len(commands), 12)
        for command in commands:
            self.assertLess(command.index("[metrics]"), command.index("[routes]"))
            self.assertLess(command.index("[routes]"), command.index("[firewall]"))
        for host in diagnostics["hosts"].values():
            self.assertLessEqual(len(host["stdout"]), 8192)
            self.assertLessEqual(len(host["stderr"]), 8192)
            self.assertNotIn("fixture-sensitive-value", host["stdout"])
            self.assertNotIn("tskey-fixture-sensitive-value", host["stderr"])

    def test_symmetric_failure_collects_diagnostics_before_cleanup_and_stays_schema_three(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                calls.append("claim")
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                calls.append(f"drift-{stage}")
                return {"clean": True}

            def finish(self, passed):
                calls.append(f"finish-{passed}")
                return {"acceptance": "failed"}

            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        class Operations:
            def verify_readiness(self, deployment, *, timeout_seconds):
                calls.append("readiness")
                raise e2e.ReadinessError("injected readiness failure")

            def collect_diagnostics(self, deployment):
                calls.append("diagnostics")
                return {
                    "collection": "complete",
                    "measurement": float("nan"),
                    "AKIA" + "IOSFODNN7EXAMPLE": "credential-shaped key",
                    "access_token": "opaque-value-without-token-shape",
                }

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["schema"], 3)
        self.assertEqual(result.evidence["kind"], e2e.SYMMETRIC_EVIDENCE_KIND)
        self.assertEqual(
            result.evidence["diagnostics"],
            {
                "collection": "complete",
                "measurement": "[NON_FINITE_NUMBER]",
                "[REDACTED_KEY]": "credential-shaped key",
                "access_token": "[REDACTED]",
            },
        )
        with self.assertRaisesRegex(e2e.EvidenceVerificationError, "not passed"):
            e2e.verify_live_evidence(result.evidence)
        self.assertEqual(result.evidence["lifecycle"]["finish"], "persisted")
        self.assertEqual(
            calls,
            ["claim", "drift-before", "readiness", "diagnostics", "finish-False", "cleanup"],
        )

        ownership = copy.deepcopy(result.evidence)
        ownership["failure"]["category"] = e2e.ConcurrentRunError.__name__
        ownership["lifecycle"].update(
            {"ownership_resolution": "competing-claim", "cleanup": "skipped"}
        )
        self.assertTrue(
            e2e._is_inner_ownership_block(
                e2e.LiveRunResult(
                    e2e.EXIT_ACCEPTANCE_FAILED,
                    result.evidence_path,
                    ownership,
                    "competing claim",
                ),
                run_id="symmetric-fixture",
            )
        )

    def test_symmetric_cleanup_failure_retains_the_acceptance_failure(self) -> None:
        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                return {"clean": True}

            def finish(self, passed):
                return {"acceptance": "failed"}

            def cleanup(self):
                raise e2e.LifecycleError("injected cleanup failure")

        class Operations:
            def verify_readiness(self, deployment, *, timeout_seconds):
                raise e2e.ReadinessError("injected readiness failure")

            def collect_diagnostics(self, deployment):
                return {"collection": "complete"}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(result.evidence["failure"]["message"], "injected cleanup failure")
        self.assertEqual(
            result.evidence["diagnostics"]["acceptance_failure_before_cleanup"],
            {
                "phase": e2e.Phase.READINESS_TOPOLOGY.value,
                "category": "ReadinessError",
                "message": "injected readiness failure",
            },
        )

    def test_claim_noncommit_still_runs_authorized_cleanup(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                calls.append("claim")
                raise e2e.ClaimPersistenceError("claim not committed; cleanup remains authorized")

            def verify_no_drift(self, stage):
                raise AssertionError("claim failure must stop acceptance")

            def finish(self, passed):
                raise AssertionError("an uncommitted claim must not be finished")

            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        class Operations:
            def collect_diagnostics(self, deployment):
                raise AssertionError("unclaimed diagnostics are not authorized")

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(calls, ["claim", "cleanup"])
        self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], "not-committed")
        self.assertEqual(result.evidence["lifecycle"]["cleanup"], "passed")

    def test_interrupted_committed_claim_skips_diagnostics_and_runs_cleanup(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                calls.append("claim")
                raise TimeoutError("interrupted after committed claim reconciliation")

            def verify_no_drift(self, stage):
                raise AssertionError("interrupted claim must stop acceptance")

            def finish(self, passed):
                calls.append("finish")
                raise AssertionError("timeout must proceed directly to cleanup")

            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        class Operations:
            def collect_diagnostics(self, deployment):
                calls.append("diagnostics")
                raise AssertionError("timeout must preserve the cleanup reservation")

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(calls, ["claim", "cleanup"])
        self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")

    def test_parse_failure_still_runs_run_owned_cleanup(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment={},
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=SimpleNamespace(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(calls, ["cleanup"])
        self.assertEqual(result.evidence["lifecycle"]["cleanup"], "passed")

    def test_diagnostic_timeout_proceeds_directly_to_cleanup(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                calls.append("claim")
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                calls.append(f"drift-{stage}")
                return {"clean": True}

            def finish(self, passed):
                calls.append("finish")
                raise AssertionError("diagnostic timeout must skip finish")

            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        class Operations:
            def verify_readiness(self, deployment, *, timeout_seconds):
                calls.append("readiness")
                raise e2e.ReadinessError("primary readiness failure")

            def collect_diagnostics(self, deployment):
                calls.append("diagnostics")
                raise TimeoutError("diagnostic timeout")

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(calls, ["claim", "drift-before", "readiness", "diagnostics", "cleanup"])
        self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")

    def test_finish_ownership_block_preserves_acceptance_failure_and_suppresses_cleanup(self) -> None:
        calls: list[str] = []

        class Lifecycle:
            def claim(self, raw_deployment, deployment):
                calls.append("claim")
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                calls.append(f"drift-{stage}")
                return {"clean": True}

            def finish(self, passed):
                calls.append(f"finish-{passed}")
                raise e2e.ConcurrentRunError("competing durable claim")

            def cleanup(self):
                calls.append("cleanup")
                raise AssertionError("competing ownership must suppress cleanup")

        class Operations:
            def verify_readiness(self, deployment, *, timeout_seconds):
                calls.append("readiness")
                raise e2e.ReadinessError("original readiness failure")

            def collect_diagnostics(self, deployment):
                calls.append("diagnostics")
                return {"collection": "complete"}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="symmetric-fixture",
                raw_deployment=symmetric_protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "failure.json",
            ).run()

        self.assertEqual(result.evidence["failure"]["category"], "ReadinessError")
        self.assertEqual(result.evidence["failure"]["message"], "original readiness failure")
        self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], "competing-claim")
        self.assertEqual(result.evidence["lifecycle"]["cleanup"], "skipped")
        self.assertEqual(result.evidence["diagnostics"]["lifecycle_finish_failure"]["category"], "ConcurrentRunError")
        self.assertTrue(e2e._is_inner_ownership_block(result, run_id="symmetric-fixture"))
        self.assertNotIn("cleanup", calls)


class SymmetricConfigTest(unittest.TestCase):
    def test_run_config_requires_v2_symmetric_topology_and_rejects_directional_fields(self) -> None:
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        def site(region: str, prefix: str, peer: str) -> dict:
            azs = {"a": f"{region}a", "b": f"{region}b"}
            return {"region": region, "ami_id": "ami-0123456789abcdef0", "ssm_kms_key_arn": f"arn:aws:kms:{region}:123456789012:key/fixture", "azs": azs, "vpc_cidr": f"{prefix}.0.0/16", "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"], "remote_site_cidrs": [f"{peer}.1.0/24", f"{peer}.2.0/24"], "workload_subnet_cidrs": {"a": f"{prefix}.1.0/24", "b": f"{prefix}.2.0/24"}, "transport_subnet_cidrs": {"a": f"{prefix}.3.0/24", "b": f"{prefix}.4.0/24"}, "gwlbe_subnet_cidrs": {"a": f"{prefix}.5.0/24", "b": f"{prefix}.6.0/24"}, "gwlb_subnet_cidrs": {"a": f"{prefix}.7.0/24", "b": f"{prefix}.8.0/24"}, "target_subnet_cidrs": {"a": f"{prefix}.9.0/24", "b": f"{prefix}.10.0/24"}, "management_subnet_cidr": f"{prefix}.11.0/24", "target_az_keys": ["a", "b"], "transport_router_az_keys": ["a", "b"]}
        document = {"run_id": "symmetric-fixture", "expires_at": expiry, "architecture": "amd64", "artifact_manifest": "artifact.json", "instance_type": "t3.medium", "test_instance_type": "t3.micro", "e2e_load_profile": {"profile_id": "fixture", "approved_at": "2020-01-01T00:00:00Z", "safe_inner_mtu": 1280, "maximum_tcp_mss": 1240, "sustained_tcp_duration_seconds": 3, "minimum_sustained_tcp_bytes": 1, "iperf_duration_seconds": 3, "minimum_throughput_mbps": 1, "concurrent_duration_seconds": 3, "concurrent_tcp_flows": 1, "concurrent_udp_flows": 1, "maximum_udp_loss_percent": 1, "maximum_p99_latency_ms": 1}, "envelope": packet_return_envelope(), "backend": {"bucket": "fixture", "region": "us-west-2", "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/backend", "state_key": "runs/symmetric-fixture/terraform.tfstate", "operator_principal_arns": ["arn:aws:iam::123456789012:role/fixture"]}, "symmetric_topology": {"version": 2, "route_failover": {"mutation_timeout_seconds": 120, "restoration_timeout_seconds": 120, "recovery_timeout_seconds": 600, "initial_transport_router_az_by_gwlbe_az": {"west": {"a": "a", "b": "b"}, "east": {"a": "a", "b": "b"}}}, "sites": {"west": site("us-west-2", "10.10", "10.20"), "east": site("us-east-1", "10.20", "10.10")}}, "tailnet": {"name": "fixture.example", "tag": "tag:fixture", "tag_owners": ["group:infra"], "snat_subnet_routes": False}}
        document["cost"] = {
            "estimated_fixed_hourly_usd": 1.5,
            "approved_max_fixed_hourly_usd": 2.0,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "run.json"
            path.write_text(json.dumps(document))
            config = appliance.RunConfig.load(path)
            self.assertEqual(appliance.terraform_variables(config, {"path": path, "sha256": "a" * 64, "revision": "b" * 40, "version": "fixture"}, [{"site": "west", "arn": "west", "kms_key_arn": "west"}, {"site": "east", "arn": "east", "kms_key_arn": "east"}])["symmetric_topology"]["version"], 2)
            output_topology = topology_document()
            output_topology["route_failover"] = copy.deepcopy(config.route_failover)
            parsed_output_topology = e2e.parse_symmetric_topology_v2(output_topology)
            transport_fleets = {
                site_name: {
                    member.az_key: member.as_dict()
                    for member in parsed_output_topology.site(
                        site_name
                    ).transport_router_fleet
                }
                for site_name in e2e.SITES
            }
            readiness = legacy_e2e_test.terraform_transport_readiness_value(
                parsed_output_topology
            )
            self.assertEqual(
                readiness,
                appliance.expected_transport_router_readiness_expectations(config),
            )
            for site_name in e2e.SITES:
                contract = readiness["sites"][site_name]
                self.assertEqual(contract["policy_rule_priority_base"], 100)
                self.assertEqual(contract["local_route_table"], "main")
                self.assertEqual(contract["remote_route_table"], 52)
                self.assertEqual(contract["recovery_marker"], "/var/lib/envelope/transport-router-network.configured")
                self.assertEqual(
                    contract["contract_sha256"],
                    e2e._contract_sha256(
                        {key: value for key, value in contract.items() if key != "contract_sha256"}
                    ),
                )
            self.assertEqual(
                legacy_e2e_test.terraform_route_failover_value(
                    parsed_output_topology
                ),
                appliance.expected_route_failover_output(config, transport_fleets),
            )
            self.assertEqual(
                legacy_e2e_test.terraform_symmetric_cost_value(
                    parsed_output_topology
                ),
                appliance.expected_symmetric_cost_profile(config),
            )
            for current, obsolete in (
                ("transport_router_az_keys", "ingress_router_az_keys"),
                ("transport_subnet_cidrs", "ingress_subnet_cidrs"),
            ):
                legacy = copy.deepcopy(document)
                legacy_site = legacy["symmetric_topology"]["sites"]["west"]
                legacy_site[obsolete] = legacy_site.pop(current)
                path.write_text(json.dumps(legacy))
                with self.subTest(obsolete=obsolete), self.assertRaisesRegex(
                    appliance.LifecycleError, "unsupported fields"
                ):
                    appliance.RunConfig.load(path)
            document["symmetric_topology"]["sites"]["west"]["gwlb_return_cidrs"] = ["10.10.1.0/24"]
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)


if __name__ == "__main__":
    unittest.main()
