#!/usr/bin/env python3

from __future__ import annotations

import base64
import contextlib
import copy
import dataclasses
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import queue
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_two_region_e2e as e2e  # noqa: E402

AGENT_PATH = ROOT / "example" / "terraform" / "cloud-init" / "envelope-e2e-agent.py"
AGENT_SPEC = importlib.util.spec_from_file_location("envelope_e2e_agent", AGENT_PATH)
assert AGENT_SPEC and AGENT_SPEC.loader
AGENT = importlib.util.module_from_spec(AGENT_SPEC)
sys.modules[AGENT_SPEC.name] = AGENT
AGENT_SPEC.loader.exec_module(AGENT)


def deployment_value() -> dict[str, Any]:
    return {
        "west": {
            "region": "us-west-2",
            "initiator": {
                "instance_id": "i-0123456789abcdef0",
                "private_ip": "10.10.1.10",
            },
            "responder": {
                "instance_id": "i-1123456789abcdef0",
                "private_ip": "10.10.1.11",
            },
        },
        "east": {
            "region": "us-east-1",
            "initiator": {
                "instance_id": "i-2123456789abcdef0",
                "private_ip": "10.20.1.10",
            },
            "responder": {
                "instance_id": "i-3123456789abcdef0",
                "private_ip": "10.20.1.11",
            },
        },
    }


def terraform_output() -> dict[str, Any]:
    return {
        "workloads": {
            "sensitive": False,
            "type": ["object", {}],
            "value": deployment_value(),
        }
    }


def parsed_deployment() -> e2e.Deployment:
    return e2e.parse_deployment_output(terraform_output())


def protected_output() -> dict[str, Any]:
    value = deployment_value()
    identities = {
        ("west", "initiator"): (
            "a",
            "us-west-2a",
            "subnet-0123456789abcdef0",
            "10.10.1.0/24",
            "rtb-0123456789abcdef0",
        ),
        ("west", "responder"): (
            "b",
            "us-west-2b",
            "subnet-1123456789abcdef0",
            "10.10.2.0/24",
            "rtb-1123456789abcdef0",
        ),
        ("east", "initiator"): (
            "a",
            "us-east-1a",
            "subnet-2123456789abcdef0",
            "10.20.1.0/24",
            "rtb-2123456789abcdef0",
        ),
        ("east", "responder"): (
            "b",
            "us-east-1b",
            "subnet-3123456789abcdef0",
            "10.20.2.0/24",
            "rtb-3123456789abcdef0",
        ),
    }
    value["west"]["responder"]["private_ip"] = "10.10.2.11"
    value["east"]["responder"]["private_ip"] = "10.20.2.11"
    for site in ("west", "east"):
        value[site].pop("region")
        for role in ("initiator", "responder"):
            az_key, availability_zone, subnet_id, cidr, route_table_id = identities[(site, role)]
            value[site][role].update(
                {
                    "az_key": az_key,
                    "availability_zone": availability_zone,
                    "subnet_id": subnet_id,
                    "cidr": cidr,
                    "route_table_id": route_table_id,
                }
            )
    artifact_sha = "a" * 64
    revision = "b" * 40
    runtime = {}
    for site, peer in (("west", "east"), ("east", "west")):
        runtime[site] = {
            "routing_mode": "manage",
            "tun_name": "envelope0",
            "underlay_interface": "ens5",
            "tailscale_iface": "tailscale0",
            "gwlb_return_cidrs": [identities[(site, "initiator")][3]],
            "local_delivery_cidrs": [identities[(site, "responder")][3]],
            "remote_tailnet_cidrs": [
                identities[(peer, "initiator")][3],
                identities[(peer, "responder")][3],
            ],
            "routing_table_id": 100,
            "routing_rule_priority": 100,
            "artifact_sha256": artifact_sha,
            "artifact_revision": revision,
        }
    return {
        "instance_ids": {
            "value": {"west": "i-4123456789abcdef0", "east": "i-5123456789abcdef0"}
        },
        "workload_instances": {"value": value},
        "vpc_ids": {"value": {"west": "vpc-0123456789abcdef0", "east": "vpc-1123456789abcdef0"}},
        "gwlb_target_group_arns": {
            "value": {
                "west": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run-west/0123456789abcdef",
                "east": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/run-east/1123456789abcdef",
            }
        },
        "gwlb_endpoint_ids": {
            "value": {
                "west": {"a": "vpce-0123456789abcdef0", "b": "vpce-1123456789abcdef0"},
                "east": {"a": "vpce-2123456789abcdef0", "b": "vpce-3123456789abcdef0"},
            }
        },
        "flow_log_evidence": {
            "value": {
                "west": {
                    "flow_log_id": "fl-0123456789abcdef0",
                    "log_group_arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/fixture/west",
                    "region": "us-west-2",
                },
                "east": {
                    "flow_log_id": "fl-1123456789abcdef0",
                    "log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc-flow-logs/fixture/east",
                    "region": "us-east-1",
                },
            }
        },
        "envelope_runtime_config": {"value": runtime},
        "e2e_load_profile": {
            "value": {
                "profile_id": "fixture-load-v1",
                "approved_at": "2026-08-20T10:00:00Z",
                "safe_inner_mtu": 1280,
                "maximum_tcp_mss": 1240,
                "sustained_tcp_duration_seconds": 3,
                "minimum_sustained_tcp_bytes": 1024,
                "iperf_duration_seconds": 3,
                "minimum_throughput_mbps": 1.0,
                "concurrent_duration_seconds": 3,
                "concurrent_tcp_flows": 2,
                "concurrent_udp_flows": 2,
                "maximum_udp_loss_percent": 1.0,
                "maximum_p99_latency_ms": 100.0,
            }
        },
        "cost_profile": {
            "value": {
                "profile": "directional-lane-acceptance",
                "resource_counts": {
                    "appliance_instances": 2,
                    "workload_instances": 4,
                    "vpc_flow_logs": 2,
                    "cloudwatch_log_groups": 2,
                    "flow_log_iam_roles": 1,
                    "regional_targets": {"west": 1, "east": 1},
                },
            }
        },
    }


def fixture_live_tailnet_hostnames() -> list[str]:
    return [
        f"fixture-live-{site}-transport-{az_key}"
        for site in ("west", "east")
        for az_key in ("a", "b")
    ]


def lifecycle_sites() -> dict[str, dict[str, Any]]:
    return {
        "west": {
            "region": "us-west-2",
            "target_az_keys": ["a", "b"],
            "transport_router_az_keys": ["a", "b"],
        },
        "east": {
            "region": "us-east-1",
            "target_az_keys": ["a", "b"],
            "transport_router_az_keys": ["a", "b"],
        },
    }


def route_failover_topology() -> e2e.SymmetricTopologyV2:
    def site(
        name: str,
        region: str,
        local_prefix: str,
        remote_prefix: str,
        ids: tuple[str, str, str, str, str, str, str, str],
    ) -> dict[str, Any]:
        target_one, target_two, router_one, router_two, eni_one, eni_two, table_one, table_two = ids
        target_group = (
            f"arn:aws:elasticloadbalancing:{region}:123456789012:"
            f"targetgroup/{name}/0123456789abcdef"
        )
        return {
            "region": region,
            "local_site_cidrs": [f"{local_prefix}.1.0/24", f"{local_prefix}.2.0/24"],
            "remote_site_cidrs": [f"{remote_prefix}.1.0/24", f"{remote_prefix}.2.0/24"],
            "target_fleet": [
                {
                    "region": region,
                    "az_key": "a",
                    "instance_id": target_one,
                    "target_group_arn": target_group,
                },
                {
                    "region": region,
                    "az_key": "b",
                    "instance_id": target_two,
                    "target_group_arn": target_group,
                },
            ],
            "transport_router_fleet": [
                {
                    "region": region,
                    "az_key": "a",
                    "instance_id": router_one,
                    "network_interface_id": eni_one,
                    "gwlbe_route_table_id": table_one,
                    "advertised_prefix": f"{local_prefix}.1.0/24",
                },
                {
                    "region": region,
                    "az_key": "b",
                    "instance_id": router_two,
                    "network_interface_id": eni_two,
                    "gwlbe_route_table_id": table_two,
                    "advertised_prefix": f"{local_prefix}.2.0/24",
                },
            ],
        }

    return e2e.parse_symmetric_topology_v2(
        {
            "config_version": 2,
            "run_id": "fixture-live",
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
                "west": site(
                    "west",
                    "us-west-2",
                    "10.10",
                    "10.20",
                    (
                        "i-6123456789abcdef0",
                        "i-7123456789abcdef0",
                        "i-8123456789abcdef0",
                        "i-9123456789abcdef0",
                        "eni-8123456789abcdef0",
                        "eni-9123456789abcdef0",
                        "rtb-8123456789abcdef0",
                        "rtb-9123456789abcdef0",
                    ),
                ),
                "east": site(
                    "east",
                    "us-east-1",
                    "10.20",
                    "10.10",
                    (
                        "i-a123456789abcdef0",
                        "i-b123456789abcdef0",
                        "i-c123456789abcdef0",
                        "i-d123456789abcdef0",
                        "eni-c123456789abcdef0",
                        "eni-d123456789abcdef0",
                        "rtb-c123456789abcdef0",
                        "rtb-d123456789abcdef0",
                    ),
                ),
            },
        }
    )


def terraform_route_failover_value(topology: e2e.SymmetricTopologyV2) -> dict[str, Any]:
    return {
        "config_version": 2,
        **topology.route_failover.approved_bounds(),
        "same_az_preferred": {
            site: all(
                gwlbe_az == router_az
                for gwlbe_az, router_az in topology.route_failover.initial_transport_router_az_by_gwlbe_az[
                    site
                ].items()
            )
            for site in e2e.SITES
        },
        "sites": {
            site: {
                gwlbe_az: {
                    "route_table_id": next(
                        member.gwlbe_route_table_id
                        for member in topology.site(site).transport_router_fleet
                        if member.az_key == gwlbe_az
                    ),
                    "source_workload_prefix": next(
                        member.advertised_prefix
                        for member in topology.site(site).transport_router_fleet
                        if member.az_key == gwlbe_az
                    ),
                    "remote_site_cidrs": sorted(topology.site(site).remote_site_cidrs),
                    "initial_transport_router_az_key": router_az,
                    "initial_network_interface_id": next(
                        member.network_interface_id
                        for member in topology.site(site).transport_router_fleet
                        if member.az_key == router_az
                    ),
                }
                for gwlbe_az, router_az in topology.route_failover.initial_transport_router_az_by_gwlbe_az[
                    site
                ].items()
            }
            for site in e2e.SITES
        },
    }


def terraform_transport_readiness_value(
    topology: e2e.SymmetricTopologyV2, maximum_tcp_mss: int = 1240
) -> dict[str, Any]:
    load_profile = SimpleNamespace(maximum_tcp_mss=maximum_tcp_mss)
    sites: dict[str, Any] = {}
    for site in e2e.SITES:
        contract = e2e._transport_router_contract(topology, site, load_profile)
        sites[site] = {**contract, "contract_sha256": e2e._contract_sha256(contract)}
    return {"config_version": 2, "sites": sites}


def terraform_symmetric_cost_value(
    topology: e2e.SymmetricTopologyV2,
) -> dict[str, Any]:
    return {
        "profile": "symmetric-gwlb-ha-v2",
        "estimated_fixed_hourly_usd": 1.5,
        "approved_max_hourly_usd": 2.0,
        "resource_counts": {
            "gwlbe_endpoints": 4,
            "target_instances": {"west": 2, "east": 2},
            "transport_routers": {"west": 2, "east": 2},
            "workload_instances": 4,
            "nat_gateways": 2,
            "elastic_ips": 2,
            "gateway_load_balancers": 2,
            "vpc_flow_logs": 2,
            "cloudwatch_log_groups": 2,
            "flow_log_iam_roles": 1,
            "iam_roles": {
                "target": 2,
                "workload": 2,
                "transport": 2,
                "flow_log": 1,
            },
            "iam_instance_profiles": {
                "target": 2,
                "workload": 2,
                "transport": 2,
            },
        },
        "route_failover_bounds": topology.route_failover.approved_bounds(),
        "nat_topology_limit": {
            "gateways_per_site": 1,
            "expanded_for_ha": False,
            "placement": "one shared NAT gateway in each site's single management subnet",
            "limitation": (
                "private egress is not multi-AZ within a site and remains outside the protected data path"
            ),
        },
    }


def terraform_artifact_identity_value(run_id: str) -> dict[str, str]:
    return {
        "bucket": f"{run_id}-123456789012-us-west-2-artifact",
        "key": f"artifacts/{'b' * 40}/envelope-linux-amd64",
        "sha256": "a" * 64,
        "architecture": "amd64",
        "ec2_arch": "x86_64",
        "revision": "b" * 40,
        "version": "fixture",
    }


def route_failover_output() -> dict[str, Any]:
    document = protected_output()
    topology = route_failover_topology()
    document.pop("instance_ids")
    document["artifact_identity"] = {
        "value": terraform_artifact_identity_value(topology.run_id)
    }
    document["symmetric_topology"] = {"value": topology.as_dict()}
    document["route_failover"] = {"value": terraform_route_failover_value(topology)}
    document["transport_router_readiness_expectations"] = {
        "value": terraform_transport_readiness_value(topology)
    }
    document["gwlb_target_group_arns"]["value"] = {
        site: topology.site(site).target_fleet[0].target_group_arn for site in e2e.SITES
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
    document["cost_profile"]["value"] = terraform_symmetric_cost_value(topology)
    return document


def coordinated_route_replacement_fixture(
    deployment: e2e.SymmetricProtectedDeployment,
    failed: e2e.SymmetricFleetMember,
    selected_alternate: e2e.SymmetricFleetMember,
    probe: Mapping[str, Any],
    mode: str,
) -> dict[str, Any]:
    topology = deployment.topology
    site = topology.site(failed.site)
    prefixes = list(site.remote_site_cidrs)
    node_hashes = {
        member.instance_id: hashlib.sha256(
            f"node-{member.site}-{member.az_key}".encode()
        ).hexdigest()
        for topology_site in e2e.SITES
        for member in topology.site(topology_site).transport_router_fleet
    }

    def snapshot(target_eni: str) -> dict[str, Any]:
        return {
            "route_table_id": failed.gwlbe_route_table_id,
            "vpc_id": deployment.vpc_ids[failed.site],
            "ownership": {
                "EnvelopeRun": topology.run_id,
                "ManagedBy": "terraform",
                "Profile": "symmetric-gwlb-ha-v2",
                "Role": "gwlbe",
                "ZoneKey": failed.az_key,
            },
            "routes": [
                {
                    "destination_cidr_block": prefix,
                    "network_interface_id": target_eni,
                    "origin": "CreateRoute",
                    "route_state": "active",
                }
                for prefix in prefixes
            ],
        }

    def ownership_observation(owners: Mapping[str, str]) -> dict[str, Any]:
        return {
            "quiet_window_seconds": topology.route_failover.quiet_window_seconds,
            "observers": [
                {
                    "observer_instance_id": observer.instance_id,
                    "owners": [
                        {
                            "prefix": prefix,
                            "owner_instance_id": instance_id,
                            "owner_node_id_sha256": node_hashes[instance_id],
                        }
                        for prefix, instance_id in sorted(owners.items())
                    ],
                    "command": None,
                }
                for observer in topology.site(
                    e2e._opposite(failed.site)
                ).transport_router_fleet
            ],
        }

    def member_value(member: e2e.SymmetricFleetMember) -> dict[str, Any]:
        return {
            "instance_id": member.instance_id,
            "network_interface_id": member.network_interface_id,
            "baseline_advertisements": [member.advertised_prefix],
            "state_before": {
                "advertisements": {
                    "generation": f"initial-{member.site}-{member.az_key}",
                    "routes": [member.advertised_prefix],
                    "service": "running",
                    "mode": "normal",
                },
                "command": None,
            },
            "node_id_sha256": node_hashes[member.instance_id],
        }

    baseline_owners = {
        member.advertised_prefix: member.instance_id
        for member in site.transport_router_fleet
    }
    transferred_owners = dict(baseline_owners)
    transferred_owners[failed.advertised_prefix] = selected_alternate.instance_id
    forward_generation = "33333333-4444-4555-8666-777777777777"
    restore_generation = "44444444-5555-4666-8777-888888888888"

    def advertisement_record(member: e2e.SymmetricFleetMember) -> dict[str, Any]:
        return {
            "advertisements": {
                "generation": restore_generation,
                "routes": [member.advertised_prefix],
                "service": "running",
                "mode": "normal",
            },
            "command": None,
        }

    restored_current = advertisement_record(failed)
    restored_alternate = advertisement_record(selected_alternate)
    return {
        "route_table_id": failed.gwlbe_route_table_id,
        "gwlbe_az_key": failed.az_key,
        "source_prefix": failed.advertised_prefix,
        "prefixes": prefixes,
        "current": member_value(failed),
        "alternate": member_value(selected_alternate),
        "bounds": {
            "approved_inputs": topology.route_failover.approved_bounds(),
            "effective": {
                "mutation_timeout_seconds": topology.route_failover.mutation_timeout_seconds,
                "restoration_timeout_seconds": topology.route_failover.restoration_timeout_seconds,
                **topology.route_failover.derived_bounds(),
            },
            "derivation": {
                "settlement_timeout_seconds": "recovery_timeout_seconds",
                "quiet_window_seconds": "min(10,max(1,restoration_timeout_seconds//10))",
                "owner_lease_seconds": (
                    "max(mutation_timeout_seconds,restoration_timeout_seconds,"
                    "recovery_timeout_seconds,165,45)+quiet_window_seconds+15"
                ),
            },
        },
        "before": snapshot(failed.network_interface_id),
        "advertisements": {
            "forward_generation": forward_generation,
            "restore_generation": restore_generation,
            "failure_mode": mode,
            "alternate_expansion": {
                "advertisements": {
                    "generation": forward_generation,
                    "routes": sorted(
                        {
                            selected_alternate.advertised_prefix,
                            failed.advertised_prefix,
                        }
                    ),
                    "service": "running",
                    "mode": "normal",
                },
                "command": None,
            },
            "current_withdrawal": {
                "advertisements": {
                    "generation": forward_generation,
                    "routes": [],
                    "service": "stopped",
                    "mode": mode,
                },
                "command": None,
            },
        },
        "ownership": {
            "before": ownership_observation(baseline_owners),
            "transferred": ownership_observation(transferred_owners),
        },
        "after": snapshot(selected_alternate.network_interface_id),
        "probe": dict(probe),
        "restoration": {
            "status": "verified",
            "advertisements": {
                "status": "verified",
                "current": restored_current,
                "alternate": restored_alternate,
                "verification": {
                    "current": copy.deepcopy(restored_current),
                    "alternate": copy.deepcopy(restored_alternate),
                },
                "failures": [],
            },
            "ownership": {
                "status": "verified",
                "observation": ownership_observation(baseline_owners),
            },
            "routes": {
                "status": "verified",
                "attempted_prefixes": prefixes,
                "api_failures": [],
                "settled_prefixes": prefixes,
                "quiet_window_seconds": topology.route_failover.quiet_window_seconds,
                "snapshot": snapshot(failed.network_interface_id),
            },
        },
        "restored": True,
    }


def symmetric_route_evidence() -> dict[str, Any]:
    deployment = e2e.parse_symmetric_protected_deployment_output(route_failover_output())
    topology = deployment.topology
    endpoints = {site: dict(values) for site, values in deployment.endpoint_ids.items()}
    node_hashes = {
        member.instance_id: hashlib.sha256(
            f"node-{member.site}-{member.az_key}".encode()
        ).hexdigest()
        for site in e2e.SITES
        for member in topology.site(site).transport_router_fleet
    }

    def turnaround(target_id: str) -> dict[str, Any]:
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
                "components_ready": {"receiver": 1.0, "validation": 1.0, "sender": 1.0},
            },
            "fidelity": {
                "observed": True,
                "target_id": target_id,
                "capture_sha256": "1" * 64,
                "capture_frame_count": 2,
                "raw_pcap_deleted": True,
                "pairs": [
                    {
                        "direction": "request",
                        "ingress_frame_sha256": "2" * 64,
                        "return_frame_sha256": "3" * 64,
                        "inner_packet_sha256": "4" * 64,
                        "ordered_options_sha256": "5" * 64,
                        "flow_cookie_sha256": "6" * 64,
                        "vni": 0,
                        "outer_tuple_swapped": True,
                        "return_source_port_preserved": True,
                    }
                ],
            },
        }

    def traversal_probe(site: e2e.Site, role: e2e.WorkloadRole, protocol: str) -> dict[str, Any]:
        destination = e2e._opposite(site)
        source = topology.site(site)
        peer = topology.site(destination)
        az_key = "a" if role == "initiator" else "b"
        destination_az_key = "b" if role == "initiator" else "a"
        source_router = next(
            member
            for member in source.transport_router_fleet
            if member.az_key == az_key
        )
        destination_router = next(
            member
            for member in peer.transport_router_fleet
            if member.az_key == destination_az_key
        )
        source_target = source.target_fleet[0]
        destination_target = peer.target_fleet[0]
        return {
            "protocol": protocol,
            "source_role": role,
            "destination_role": e2e._opposite_workload_role(role),
            "source_az_key": az_key,
            "destination_az_key": destination_az_key,
            "source_gwlbe_id": endpoints[site][az_key],
            "destination_gwlbe_id": endpoints[destination][destination_router.az_key],
            "source_target_id": source_target.instance_id,
            "destination_target_id": destination_target.instance_id,
            "source_transport_router_id": source_router.instance_id,
            "source_transport_eni_id": source_router.network_interface_id,
            "destination_transport_router_id": destination_router.instance_id,
            "geneve_return_proof": {
                "source": turnaround(source_target.instance_id),
                "destination": turnaround(destination_target.instance_id),
            },
            "source_preserved": True,
        }

    def recovery_new_flows(
        site: e2e.Site,
        role: e2e.WorkloadRole,
        **path_overrides: Any,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for protocol in e2e.TRANSPORT_PROTOCOLS:
            path = traversal_probe(site, role, protocol)
            path.update(path_overrides)
            if "source_target_id" in path_overrides:
                path["geneve_return_proof"]["source"] = turnaround(
                    path_overrides["source_target_id"]
                )
            if "destination_target_id" in path_overrides:
                path["geneve_return_proof"]["destination"] = turnaround(
                    path_overrides["destination_target_id"]
                )
            result[protocol] = {"succeeded": True, "path": path}
        return result

    current, alternate = topology.west.transport_router_fleet
    graceful_failed, graceful_alternate = topology.east.transport_router_fleet
    assert current.gwlbe_route_table_id is not None
    assert current.network_interface_id is not None
    assert alternate.network_interface_id is not None

    def snapshot(
        owner: e2e.SymmetricFleetMember, target_eni: str
    ) -> dict[str, Any]:
        return {
            "route_table_id": owner.gwlbe_route_table_id,
            "vpc_id": deployment.vpc_ids[owner.site],
            "ownership": {
                "EnvelopeRun": topology.run_id,
                "ManagedBy": "terraform",
                "Profile": "symmetric-gwlb-ha-v2",
                "Role": "gwlbe",
                "ZoneKey": owner.az_key,
            },
            "routes": [
                {
                    "destination_cidr_block": prefix,
                    "network_interface_id": target_eni,
                    "origin": "CreateRoute",
                    "route_state": "active",
                }
                for prefix in topology.site(owner.site).remote_site_cidrs
            ],
        }

    graceful_new_flows = recovery_new_flows(
        "west",
        "responder",
        destination_transport_router_id=graceful_alternate.instance_id,
    )
    graceful_probe = {
        **graceful_new_flows["udp"]["path"],
        "succeeded": True,
        "new_flows": graceful_new_flows,
    }
    abrupt_new_flows = recovery_new_flows(
        "west",
        "initiator",
        source_transport_router_id=alternate.instance_id,
        source_transport_eni_id=alternate.network_interface_id,
    )
    abrupt_probe = {
        **abrupt_new_flows["udp"]["path"],
        "succeeded": True,
        "new_flows": abrupt_new_flows,
    }
    def owner_observation(
        owner_site: e2e.SymmetricSiteTopology,
        owners: Mapping[str, str],
    ) -> dict[str, Any]:
        return {
            "quiet_window_seconds": topology.route_failover.quiet_window_seconds,
            "observers": [
                {
                    "observer_instance_id": observer.instance_id,
                    "owners": [
                        {
                            "prefix": prefix,
                            "owner_instance_id": instance_id,
                            "owner_node_id_sha256": node_hashes[instance_id],
                        }
                        for prefix, instance_id in sorted(owners.items())
                    ],
                    "command": None,
                }
                for observer in topology.site(
                    e2e._opposite(owner_site.site)
                ).transport_router_fleet
            ],
        }

    def route_replacement(
        failed: e2e.SymmetricFleetMember,
        selected_alternate: e2e.SymmetricFleetMember,
        probe: Mapping[str, Any],
        mode: str,
    ) -> dict[str, Any]:
        site = topology.site(failed.site)
        prefixes = list(site.remote_site_cidrs)
        baseline_owners = {
            member.advertised_prefix: member.instance_id
            for member in site.transport_router_fleet
        }
        transferred_owners = dict(baseline_owners)
        transferred_owners[failed.advertised_prefix] = selected_alternate.instance_id
        forward_generation = "33333333-4444-4555-8666-777777777777"
        restore_generation = "44444444-5555-4666-8777-888888888888"

        def member_value(member: e2e.SymmetricFleetMember) -> dict[str, Any]:
            return {
                "instance_id": member.instance_id,
                "network_interface_id": member.network_interface_id,
                "baseline_advertisements": [member.advertised_prefix],
                "state_before": {
                    "advertisements": {
                        "generation": f"initial-{member.site}-{member.az_key}",
                        "routes": [member.advertised_prefix],
                        "service": "running",
                        "mode": "normal",
                    },
                    "command": None,
                },
                "node_id_sha256": node_hashes[member.instance_id],
            }

        def advertisement_record(member: e2e.SymmetricFleetMember) -> dict[str, Any]:
            return {
                "advertisements": {
                    "generation": restore_generation,
                    "routes": [member.advertised_prefix],
                    "service": "running",
                    "mode": "normal",
                },
                "command": None,
            }

        restored_current = advertisement_record(failed)
        restored_alternate = advertisement_record(selected_alternate)

        return {
            "route_table_id": failed.gwlbe_route_table_id,
            "gwlbe_az_key": failed.az_key,
            "source_prefix": failed.advertised_prefix,
            "prefixes": prefixes,
            "current": member_value(failed),
            "alternate": member_value(selected_alternate),
            "bounds": {
                "approved_inputs": topology.route_failover.approved_bounds(),
                "effective": {
                    "mutation_timeout_seconds": 30,
                    "restoration_timeout_seconds": 30,
                    **topology.route_failover.derived_bounds(),
                },
                "derivation": {
                    "settlement_timeout_seconds": "recovery_timeout_seconds",
                    "quiet_window_seconds": "min(10,max(1,restoration_timeout_seconds//10))",
                    "owner_lease_seconds": (
                        "max(mutation_timeout_seconds,restoration_timeout_seconds,"
                        "recovery_timeout_seconds,165,45)+quiet_window_seconds+15"
                    ),
                },
            },
            "before": snapshot(failed, failed.network_interface_id),
            "advertisements": {
                "forward_generation": forward_generation,
                "restore_generation": restore_generation,
                "failure_mode": mode,
                "alternate_expansion": {
                    "advertisements": {
                        "generation": forward_generation,
                        "routes": sorted(
                            {
                                selected_alternate.advertised_prefix,
                                failed.advertised_prefix,
                            }
                        ),
                        "service": "running",
                        "mode": "normal",
                    },
                    "command": None,
                },
                "current_withdrawal": {
                    "advertisements": {
                        "generation": forward_generation,
                        "routes": [],
                        "service": "stopped",
                        "mode": mode,
                    },
                    "command": None,
                },
            },
            "ownership": {
                "before": owner_observation(site, baseline_owners),
                "transferred": owner_observation(site, transferred_owners),
            },
            "after": snapshot(failed, selected_alternate.network_interface_id),
            "probe": dict(probe),
            "restoration": {
                "status": "verified",
                "advertisements": {
                    "status": "verified",
                    "current": restored_current,
                    "alternate": restored_alternate,
                    "verification": {
                        "current": copy.deepcopy(restored_current),
                        "alternate": copy.deepcopy(restored_alternate),
                    },
                    "failures": [],
                },
                "ownership": {
                    "status": "verified",
                    "observation": owner_observation(site, baseline_owners),
                },
                "routes": {
                    "status": "verified",
                    "attempted_prefixes": prefixes,
                    "api_failures": [],
                    "settled_prefixes": prefixes,
                    "quiet_window_seconds": topology.route_failover.quiet_window_seconds,
                    "snapshot": snapshot(failed, failed.network_interface_id),
                },
            },
            "restored": True,
        }

    graceful_route_replacement = route_replacement(
        graceful_failed, graceful_alternate, graceful_probe, "graceful"
    )
    abrupt_route_replacement = route_replacement(
        current, alternate, abrupt_probe, "abrupt"
    )
    target = topology.west.target_fleet[0]
    target_alternate = topology.west.target_fleet[1]
    readiness = {
        "config_version": 2,
        "tailnet_policy_valid": True,
        "transport_router_contract_sha256": {
            site: deployment.transport_router_readiness_expectations[site][
                "contract_sha256"
            ]
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
                        "contract_sha256": deployment.transport_router_readiness_expectations[
                            site
                        ]["contract_sha256"],
                        "tailnet_node_id_sha256": node_hashes[member.instance_id],
                        "advertised_prefix": member.advertised_prefix,
                        "local_gwlbes": {
                            candidate.advertised_prefix: endpoints[site][
                                candidate.az_key
                            ]
                            for candidate in topology.site(site).transport_router_fleet
                        },
                        "primary_route_ownership": {
                            "observed_at": "2026-08-20T11:59:59Z",
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
    document = {
        "schema": e2e.SYMMETRIC_EVIDENCE_SCHEMA,
        "kind": e2e.SYMMETRIC_EVIDENCE_KIND,
        "run_id": topology.run_id,
        "generated_at": "2026-08-20T12:00:00Z",
        "status": "passed",
        "topology": topology.as_dict(),
        "endpoint_ids": endpoints,
        "preflight": readiness,
        "cold_initiation": [
            {
                "source_site": site,
                "destination_site": e2e._opposite(site),
                "source_role": "initiator" if site == "west" else "responder",
                "destination_role": "responder" if site == "west" else "initiator",
                "protocol": protocol,
                "source_az_key": "a" if site == "west" else "b",
                "source_gwlbe_id": endpoints[site]["a" if site == "west" else "b"],
                "dispatch_monotonic_ns": 100 + index,
                "succeeded": True,
            }
            for index, (site, protocol) in enumerate(
                (site, protocol) for site in e2e.SITES for protocol in e2e.PROTOCOLS
            )
        ],
        "traversals": [
            {
                "source_site": site,
                "destination_site": e2e._opposite(site),
                "probes": [
                    traversal_probe(site, role, protocol)
                    for role in e2e.WORKLOAD_ROLES
                    for protocol in e2e.PROTOCOLS
                ],
            }
            for site in e2e.SITES
        ],
        "recoveries": [
            {
                "kind": "target-process",
                "site": "west",
                "failed_id": target.instance_id,
                "alternate_id": target_alternate.instance_id,
                "new_flow_succeeded": True,
                "new_flows": recovery_new_flows(
                    "west",
                    "initiator",
                    source_target_id=target_alternate.instance_id,
                ),
                "recovery_duration_ms": 10,
            },
            {
                "kind": "target-instance",
                "site": "west",
                "failed_id": target.instance_id,
                "alternate_id": target_alternate.instance_id,
                "replacement_id": "i-ff23456789abcdef",
                "replacement_ready": True,
                "old_process_generation_sha256": "7" * 64,
                "replacement_process_generation_sha256": "8" * 64,
                "target_group_arn": target.target_group_arn,
                "registration_port": 6081,
                "drain_state": "draining",
                "drain_duration_ms": 5,
                "new_flow_succeeded": True,
                "new_flows": recovery_new_flows(
                    "west",
                    "initiator",
                    source_target_id=target_alternate.instance_id,
                ),
                "recovery_duration_ms": 20,
            },
            {
                "kind": "transport-router",
                "site": "west",
                "failed_id": current.instance_id,
                "alternate_id": alternate.instance_id,
                "new_flow_succeeded": True,
                "new_flows": abrupt_probe["new_flows"],
                "recovery_duration_ms": 30,
            },
        ],
        "transport": {
            "target_process": failure_transport_evidence(
                target.instance_id, "target-process"
            ),
            "target_instance": failure_transport_evidence(
                target.instance_id, "target-instance"
            ),
            "transport_router": {
                "graceful": failure_transport_evidence(
                    graceful_failed.instance_id, "router-graceful"
                ),
                "abrupt": failure_transport_evidence(
                    current.instance_id, "router-abrupt"
                ),
            },
        },
        "transport_router": {
            "graceful": {
                "control_plane": "tailnet-and-gwlbe-route",
                "failed_id": graceful_failed.instance_id,
                "alternate_id": graceful_alternate.instance_id,
                "probe": graceful_probe,
                "new_flows": graceful_probe["new_flows"],
                "new_flow_succeeded": True,
                "recovery_duration_ms": 15,
                "route_replacement": graceful_route_replacement,
                "restored": True,
            },
            "abrupt": {
                "control_plane": "tailnet-and-gwlbe-route",
                "failed_id": current.instance_id,
                "alternate_id": alternate.instance_id,
                "probe": abrupt_probe,
                "new_flows": abrupt_probe["new_flows"],
                "new_flow_succeeded": True,
                "recovery_duration_ms": 30,
                "route_replacement": abrupt_route_replacement,
                "restored": True,
            },
        },
        "health_transitions": [
            {
                "kind": "target-process",
                "member_id": target.instance_id,
                "states": ["healthy", "unhealthy", "healthy"],
            },
            {
                "kind": "target-instance",
                "member_id": target.instance_id,
                "states": ["healthy", "draining", "replaced"],
            },
            {
                "kind": "transport-router",
                "member_id": current.instance_id,
                "states": ["healthy", "unavailable", "healthy"],
            },
        ],
        "cost": deployment.cost_evidence(),
        "lifecycle": {
            "claimed": True,
            "drift_precheck": "clean",
            "drift_postcheck": "clean",
            "finish": "passed",
            "cleanup": "complete",
        },
        "residual_audit": {"passed": True, "owned_resources_remaining": 0},
        "diagnostics": {},
        "failure": None,
    }
    return json.loads(json.dumps(document))


def failure_transport_evidence(failed_id: str, label: str) -> dict[str, Any]:
    def stream(protocol: str) -> dict[str, Any]:
        return {
            "protocol": protocol,
            "flow_id": f"fixture-{label}-{protocol}",
            "outcome": "resumed",
            "one_socket": True,
            "analysis_available": True,
            "sent_markers": 20,
            "received_markers": 19,
            "lost_markers": 1,
            "loss_percent": 5.0,
            "maximum_interruption_ms": 100,
            "threshold_ms": 30_000,
            "within_threshold": True,
            "observation_complete": True,
            "right_censored": False,
            "expected_markers": 20,
            "last_acknowledged_sequence": 19,
            "mutation_overlap_observed": True,
            "last_send_after_mutation": True,
        }

    return {
        "failed_ids": {"tcp": failed_id, "udp": failed_id},
        "tcp": stream("tcp"),
        "udp": stream("udp"),
        "receivers": {
            "tcp_sessions": 1,
            "tcp_duplicates": 0,
            "udp_sessions": 1,
            "udp_duplicates": 0,
        },
    }


def new_flow_evidence(**path_fields: Any) -> dict[str, Any]:
    return {
        protocol: {
            "succeeded": True,
            "path": {"protocol": protocol, **path_fields},
        }
        for protocol in e2e.TRANSPORT_PROTOCOLS
    }


def ready_lifecycle_manifest(deployment: Mapping[str, Any]) -> dict[str, Any]:
    source = {
        "revision": "b" * 40,
        "repository_path": str(ROOT),
        "sha256": "c" * 64,
    }
    return {
        "schema": 2,
        "run_id": "fixture-live",
        "phase": "ready",
        "terraform_source": {**source, "files": {"main.tf": "dGVycmFmb3JtIHt9Cg=="}},
        "saved_plan": {
            "path": "/protected-run/apply.tfplan",
            "sha256": "d" * 64,
            "replacement": None,
            "source": source,
            "apply_started": True,
            "applied": True,
            "applied_at": "2026-08-20T11:00:00Z",
        },
        "deployment": copy.deepcopy(deployment),
        "tailnet": {
            "name": "fixture.example",
            "tag": "tag:envelope-ci",
            "auth_key_description": "Envelope acceptance fixture-live",
            "auth_key_id": "key-id",
            "key_generation": 1,
            "pending_revoke_key_ids": [],
            "expected_hostnames": fixture_live_tailnet_hostnames(),
            "nodes_expected": True,
            "device_ids": {
                hostname: f"device-{index}"
                for index, hostname in enumerate(fixture_live_tailnet_hostnames(), start=1)
            },
            "device_roles": {
                hostname: "transport-router" for hostname in fixture_live_tailnet_hostnames()
            },
        },
    }


def transport_node_hashes(
    topology: e2e.SymmetricTopologyV2,
) -> dict[str, str]:
    return {
        member.instance_id: hashlib.sha256(
            f"node-{site}-{member.az_key}".encode("utf-8")
        ).hexdigest()
        for site in e2e.SITES
        for member in topology.site(site).transport_router_fleet
    }


class DurableManifestStore:
    def __init__(self, manifest: Mapping[str, Any]) -> None:
        self.value = copy.deepcopy(manifest)
        self.remote_etag: str | None = '"fixture-etag-0"'
        self.recover_count = 0
        self.recover_hook: Any = None
        self.write_hook: Any = None
        self.writes: list[tuple[dict[str, Any], str | None]] = []

    def recover(self) -> dict[str, Any]:
        self.recover_count += 1
        if self.recover_hook is not None:
            self.recover_hook(self)
        return copy.deepcopy(self.value)

    def commit(self, value: dict[str, Any], if_match: str | None) -> None:
        expected = self.remote_etag
        if if_match is not None and if_match != expected:
            raise e2e.LifecycleError("fixture durable manifest compare-and-swap rejected")
        self.value = copy.deepcopy(value)
        self.writes.append((copy.deepcopy(value), if_match))
        self.remote_etag = f'"fixture-etag-{len(self.writes)}"'

    def write(self, value: dict[str, Any], *, if_match: str | None = None) -> None:
        if self.write_hook is not None:
            self.write_hook(self, value, if_match)
            return
        self.commit(value, if_match)


class DurableRouteTransactions:
    def __init__(self, value: Mapping[str, Any] | None = None) -> None:
        self.value = copy.deepcopy(value)
        self.revision = '"route-etag-0"'
        self.writes: list[dict[str, Any]] = []
        self.finalized: list[dict[str, Any]] = []
        self.node_bindings: list[dict[str, str]] = []
        self.fail_next_update = False

    def bind_transport_node_identities(
        self, node_ids_by_instance: Mapping[str, str]
    ) -> Mapping[str, Any]:
        self.node_bindings.append(dict(node_ids_by_instance))
        return {"bound": True}

    def load_route_transaction(self) -> tuple[dict[str, Any], str] | None:
        if self.value is None:
            return None
        return copy.deepcopy(self.value), self.revision

    def create_route_transaction(self, value: Mapping[str, Any]) -> str:
        if self.value is not None:
            raise e2e.ConcurrentRunError("fixture route transaction already exists")
        self.value = copy.deepcopy(dict(value))
        return self._commit()

    def update_route_transaction(
        self, value: Mapping[str, Any], *, expected_revision: str
    ) -> str:
        if self.fail_next_update:
            self.fail_next_update = False
            raise e2e.ConcurrentRunError("fixture route transaction CAS collision")
        if self.value is None or expected_revision != self.revision:
            raise e2e.ConcurrentRunError("fixture route transaction CAS collision")
        self.value = copy.deepcopy(dict(value))
        return self._commit()

    def finalize_route_transaction(
        self,
        transaction_id: str,
        summary: Mapping[str, Any],
        *,
        expected_revision: str,
    ) -> str:
        if (
            self.value is None
            or self.value.get("transaction_id") != transaction_id
            or expected_revision != self.revision
        ):
            raise e2e.ConcurrentRunError("fixture route transaction finalization collision")
        self.finalized.append(copy.deepcopy(dict(summary)))
        self.value = None
        return self._commit()

    def _commit(self) -> str:
        if self.value is not None:
            self.writes.append(copy.deepcopy(self.value))
        self.revision = f'"route-etag-{len(self.writes) + len(self.finalized)}"'
        return self.revision


class ValidatingDurableRouteTransactions(DurableRouteTransactions):
    def __init__(
        self,
        topology: e2e.SymmetricTopologyV2,
        vpc_ids: Mapping[str, str],
        value: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(value)
        self.topology = topology
        self.vpc_ids = vpc_ids
        self.node_ids_by_instance = {
            member.instance_id: f"node-{member.site}-{member.az_key}"
            for site in e2e.SITES
            for member in topology.site(site).transport_router_fleet
        }

    def _validate(self, value: Mapping[str, Any]) -> None:
        e2e.GWLBERouteFailover.validate_durable_binding(
            value,
            self.topology,
            self.vpc_ids,
            node_ids_by_instance=self.node_ids_by_instance,
        )

    def create_route_transaction(self, value: Mapping[str, Any]) -> str:
        self._validate(value)
        return super().create_route_transaction(value)

    def update_route_transaction(
        self, value: Mapping[str, Any], *, expected_revision: str
    ) -> str:
        self._validate(value)
        return super().update_route_transaction(
            value, expected_revision=expected_revision
        )


class DeploymentParsingTest(unittest.TestCase):
    def test_parses_wrapped_role_aware_shape(self) -> None:
        deployment = parsed_deployment()

        self.assertEqual(deployment.target("west", "initiator").region, "us-west-2")
        self.assertEqual(deployment.target("east", "responder").private_ip, "10.20.1.11")
        self.assertEqual(
            [(target.site, target.role) for target in deployment.targets],
            [
                ("west", "initiator"),
                ("west", "responder"),
                ("east", "initiator"),
                ("east", "responder"),
            ],
        )
        self.assertEqual(e2e.parse_deployment_output(deployment.as_dict()), deployment)

    def test_accepts_role_regions_and_an_unambiguous_named_output(self) -> None:
        value = deployment_value()
        for site in ("west", "east"):
            region = value[site].pop("region")
            for role in ("initiator", "responder"):
                value[site][role]["region"] = region
        deployment = e2e.parse_deployment_output({"future_workload_output": {"value": value}})
        self.assertEqual(deployment.west.responder.region, "us-west-2")

    def test_parses_complete_workload_instances_network_identity(self) -> None:
        value = deployment_value()
        identity = {
            ("west", "initiator"): ("a", "us-west-2a", "subnet-0123456789abcdef0", "10.10.1.0/24", "rtb-0123456789abcdef0"),
            ("west", "responder"): ("b", "us-west-2b", "subnet-1123456789abcdef0", "10.10.1.0/24", "rtb-1123456789abcdef0"),
            ("east", "initiator"): ("a", "us-east-1a", "subnet-2123456789abcdef0", "10.20.1.0/24", "rtb-2123456789abcdef0"),
            ("east", "responder"): ("b", "us-east-1b", "subnet-3123456789abcdef0", "10.20.1.0/24", "rtb-3123456789abcdef0"),
        }
        for site in ("west", "east"):
            value[site].pop("region")
            for role in ("initiator", "responder"):
                az_key, availability_zone, subnet_id, cidr, route_table_id = identity[(site, role)]
                value[site][role].update(
                    {
                        "az_key": az_key,
                        "availability_zone": availability_zone,
                        "subnet_id": subnet_id,
                        "cidr": cidr,
                        "route_table_id": route_table_id,
                    }
                )

        deployment = e2e.parse_deployment_output({"workload_instances": {"value": value}})

        self.assertEqual(deployment.west.initiator.region, "us-west-2")
        self.assertEqual(deployment.east.responder.az_key, "b")
        self.assertEqual(deployment.east.responder.route_table_id, "rtb-3123456789abcdef0")
        self.assertEqual(e2e.parse_deployment_output(deployment.as_dict()), deployment)

    def test_rejects_missing_or_contradictory_roles_and_duplicate_targets(self) -> None:
        missing = terraform_output()
        del missing["workloads"]["value"]["west"]["responder"]
        with self.assertRaisesRegex(e2e.DeploymentError, "initiator and responder"):
            e2e.parse_deployment_output(missing)

        contradictory = terraform_output()
        contradictory["workloads"]["value"]["east"]["initiator"]["role"] = "responder"
        with self.assertRaisesRegex(e2e.DeploymentError, "contradicts"):
            e2e.parse_deployment_output(contradictory)

        duplicate = terraform_output()
        duplicate["workloads"]["value"]["east"]["responder"]["instance_id"] = "i-0123456789abcdef0"
        with self.assertRaisesRegex(e2e.DeploymentError, "unique instance_id"):
            e2e.parse_deployment_output(duplicate)


class ProtectedDeploymentParsingTest(unittest.TestCase):
    def test_parses_complete_exact_directional_topology(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())

        self.assertEqual(len(deployment.appliances), 2)
        self.assertEqual(len(deployment.workloads.targets), 4)
        self.assertEqual(deployment.west_runtime.gwlb_return_cidrs, ("10.10.1.0/24",))
        self.assertEqual(deployment.east_runtime.local_delivery_cidrs, ("10.20.2.0/24",))
        self.assertEqual(deployment.endpoint_ids["west"]["a"], "vpce-0123456789abcdef0")
        self.assertEqual(deployment.load_profile.safe_inner_mtu, 1280)
        self.assertRegex(deployment.load_profile.sha256, r"^[0-9a-f]{64}$")

    def test_accepts_v2_runtime_identity_and_ha_cost_profile(self) -> None:
        output = protected_output()
        for site, prefix in (("west", "10.10"), ("east", "10.20")):
            output["envelope_runtime_config"]["value"][site].update(
                {
                    "config_version": 2,
                    "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"],
                    "remote_site_cidrs": ["10.20.1.0/24", "10.20.2.0/24"]
                    if site == "west"
                    else ["10.10.1.0/24", "10.10.2.0/24"],
                }
            )
        output["cost_profile"]["value"] = {
            "profile": "symmetric-gwlb-ha-v2",
            "resource_counts": {
                "target_instances": {"west": 2, "east": 2},
                "transport_routers": {"west": 2, "east": 2},
                "workload_instances": 4,
                "vpc_flow_logs": 2,
                "cloudwatch_log_groups": 2,
                "flow_log_iam_roles": 1,
            },
        }

        self.assertEqual(e2e.parse_protected_deployment_output(output).west_runtime.site, "west")

    def test_load_profile_is_required_and_strictly_bounded(self) -> None:
        missing = protected_output()
        del missing["e2e_load_profile"]
        with self.assertRaisesRegex(e2e.DeploymentError, "e2e_load_profile"):
            e2e.parse_protected_deployment_output(missing)

        unsafe_mss = protected_output()
        unsafe_mss["e2e_load_profile"]["value"]["maximum_tcp_mss"] = 1241
        with self.assertRaisesRegex(e2e.LoadProfileError, "MSS"):
            e2e.parse_protected_deployment_output(unsafe_mss)

        unapproved_shape = protected_output()
        unapproved_shape["e2e_load_profile"]["value"]["invented_threshold"] = 1
        with self.assertRaisesRegex(e2e.DeploymentError, "unsupported"):
            e2e.parse_protected_deployment_output(unapproved_shape)

    def test_rejects_role_overlap_missing_endpoint_and_wrong_resource_count(self) -> None:
        overlap = protected_output()
        overlap["envelope_runtime_config"]["value"]["west"]["local_delivery_cidrs"] = ["10.10.1.0/24"]
        with self.assertRaisesRegex(e2e.DeploymentError, "local-delivery"):
            e2e.parse_protected_deployment_output(overlap)

        endpoint = protected_output()
        del endpoint["gwlb_endpoint_ids"]["value"]["west"]["a"]
        with self.assertRaisesRegex(e2e.DeploymentError, "same-AZ"):
            e2e.parse_protected_deployment_output(endpoint)

        count = protected_output()
        count["cost_profile"]["value"]["resource_counts"]["workload_instances"] = 3
        with self.assertRaisesRegex(e2e.DeploymentError, "two appliances, four workloads"):
            e2e.parse_protected_deployment_output(count)

        flow_log = protected_output()
        flow_log["flow_log_evidence"]["value"]["east"]["region"] = "us-west-2"
        with self.assertRaisesRegex(e2e.DeploymentError, "differs from the workload region"):
            e2e.parse_protected_deployment_output(flow_log)

    def test_managed_flow_log_capture_is_read_only_and_preserves_lifecycle_ownership(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())

        class FlowLogAWS:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], str | None]] = []

            def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
                self.calls.append((list(args), region))
                operation = args[1]
                site = "west" if region == "us-west-2" else "east"
                target = deployment.flow_logs[site]
                if operation == "describe-flow-logs":
                    return {
                        "FlowLogs": [
                            {
                                "FlowLogId": target.flow_log_id,
                                "ResourceId": deployment.appliance(site).vpc_id,
                                "FlowLogStatus": "ACTIVE",
                                "DeliverLogsStatus": "SUCCESS",
                                "LogDestinationType": "cloud-watch-logs",
                                "LogDestination": target.log_group_arn,
                            }
                        ]
                    }
                if operation == "describe-log-groups":
                    return {
                        "logGroups": [
                            {
                                "logGroupName": target.log_group_name,
                                "arn": target.log_group_arn + ":*",
                                "retentionInDays": 7,
                            }
                        ]
                    }
                raise AssertionError(f"unexpected operation {operation}")

        aws = FlowLogAWS()
        config = SimpleNamespace(run_id="fixture-live", sites={})
        with tempfile.TemporaryDirectory() as temporary:
            operations = e2e.AwsLiveOperations(config, aws, pathlib.Path(temporary))
            handle = operations.start_flow_logs(deployment, timeout_seconds=5)
            closed = operations.stop_flow_logs(handle, timeout_seconds=5)

        self.assertTrue(closed["ownership_preserved"])
        called_operations = [args[1] for args, _region in aws.calls]
        self.assertNotIn("create-flow-logs", called_operations)
        self.assertNotIn("delete-flow-logs", called_operations)
        self.assertNotIn("put-bucket-policy", called_operations)

    def test_target_health_selects_one_member_from_the_ha_target_group(self) -> None:
        target = e2e.ApplianceTarget(
            "west",
            "us-west-2",
            "i-0123456789abcdef0",
            "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/abcdef0123456789",
            "vpc-0123456789abcdef0",
        )

        class TargetHealthAWS:
            def json(self, args, *, region=None):
                return {
                    "TargetHealthDescriptions": [
                        {"Target": {"Id": "i-0123456789abcdef0"}, "TargetHealth": {"State": "healthy"}},
                        {"Target": {"Id": "i-0fedcba9876543210"}, "TargetHealth": {"State": "healthy"}},
                    ]
                }

        operations = e2e.AwsLiveOperations(
            SimpleNamespace(run_id="fixture-live", sites={}),
            TargetHealthAWS(),
            pathlib.Path("/tmp/not-used"),
        )
        self.assertEqual(
            operations._target_health(target),
            {"count": 2, "target_id": "i-0123456789abcdef0", "status": "healthy", "reason": None},
        )


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeAdvertisementControl:
    def __init__(
        self, topology: e2e.SymmetricTopologyV2, clock: FakeClock
    ) -> None:
        self.topology = topology
        self.clock = clock
        self.node_ids_by_instance = {
            member.instance_id: f"node-{member.site}-{member.az_key}"
            for site in e2e.SITES
            for member in topology.site(site).transport_router_fleet
        }
        self.states = {
            member.instance_id: {
                "generation": f"initial-{member.site}-{member.az_key}",
                "routes": [member.advertised_prefix],
                "service": "running",
                "mode": "normal",
            }
            for site in e2e.SITES
            for member in topology.site(site).transport_router_fleet
        }
        self.operations: list[dict[str, Any]] = []
        self.apply_count = 0
        self.fail_before_apply: int | None = None
        self.fail_after_apply: int | None = None

    def inspect(self, member: e2e.SymmetricFleetMember) -> dict[str, Any]:
        return {
            "advertisements": copy.deepcopy(self.states[member.instance_id]),
            "command": None,
        }

    def apply(
        self,
        member: e2e.SymmetricFleetMember,
        routes: Any,
        *,
        service: str,
        mode: str,
        generation: str,
        predecessors: Any,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        del timeout_seconds
        self.apply_count += 1
        if self.fail_before_apply == self.apply_count:
            raise RuntimeError("injected advertisement failure before mutation")
        current = self.states[member.instance_id]
        if current["generation"] != generation and current["generation"] not in predecessors:
            raise e2e.ResilienceError("fixture fenced a stale advertisement generation")
        state = {
            "generation": generation,
            "routes": sorted(routes),
            "service": service,
            "mode": mode,
        }
        self.states[member.instance_id] = state
        self.operations.append(
            {
                "instance_id": member.instance_id,
                "advertisements": copy.deepcopy(state),
            }
        )
        if self.fail_after_apply == self.apply_count:
            raise RuntimeError("injected ambiguous advertisement completion")
        return {"advertisements": copy.deepcopy(state), "command": None}

    def wait_ownership(
        self,
        site: str,
        expected_owner_instance_ids: Mapping[str, str],
        *,
        timeout_seconds: float,
        quiet_window_seconds: float,
    ) -> dict[str, Any]:
        if timeout_seconds < quiet_window_seconds:
            raise TimeoutError("fixture ownership deadline is too short")
        self.clock.sleep(quiet_window_seconds)
        return {
            "quiet_window_seconds": quiet_window_seconds,
            "observers": [
                {
                    "observer_instance_id": observer.instance_id,
                    "owners": [
                        {
                            "prefix": prefix,
                            "owner_instance_id": owner,
                            "owner_node_id_sha256": hashlib.sha256(
                                self.node_ids_by_instance[owner].encode()
                            ).hexdigest(),
                        }
                        for prefix, owner in sorted(
                            expected_owner_instance_ids.items()
                        )
                    ],
                    "command": None,
                }
                for observer in self.topology.site(
                    e2e._opposite(site)
                ).transport_router_fleet
            ],
        }


class RouteTableAWS:
    def __init__(self, topology: e2e.SymmetricTopologyV2) -> None:
        self.topology = topology
        self.current, self.alternate = topology.west.transport_router_fleet
        self.route_table_owner = self.current
        assert self.current.gwlbe_route_table_id is not None
        assert self.current.network_interface_id is not None
        assert self.alternate.network_interface_id is not None
        self.routes = {
            prefix: self.current.network_interface_id
            for prefix in topology.west.remote_site_cidrs
        }
        self.calls: list[tuple[list[str], str | None]] = []
        self.forward_calls = 0
        self.fail_forward_call: int | None = None
        self.fail_restore_prefix: str | None = None
        self.ambiguous_restore_prefix: str | None = None
        self.ignore_forward = False
        self.response_route_table_id = self.current.gwlbe_route_table_id
        self.run_tag = topology.run_id
        self.interface_instance_overrides: dict[str, str] = {}
        self.restore_visibility_failures: dict[str, int] = {}
        self.restoration_started = False

    def json(
        self,
        args: list[str],
        *,
        region: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        assert timeout_seconds is not None and timeout_seconds > 0
        self.calls.append((list(args), region))
        operation = args[1]
        if operation == "describe-route-tables":
            visible_routes = dict(self.routes)
            for prefix, failures in list(self.restore_visibility_failures.items()):
                if (
                    self.restoration_started
                    and failures > 0
                    and visible_routes.get(prefix) == self.current.network_interface_id
                ):
                    visible_routes[prefix] = self.alternate.network_interface_id
                    self.restore_visibility_failures[prefix] = failures - 1
            return {
                "RouteTables": [
                    {
                        "RouteTableId": self.response_route_table_id,
                        "VpcId": "vpc-0123456789abcdef0",
                        "Tags": [
                            {"Key": "EnvelopeRun", "Value": self.run_tag},
                            {"Key": "ManagedBy", "Value": "terraform"},
                            {"Key": "Profile", "Value": "symmetric-gwlb-ha-v2"},
                            {"Key": "Role", "Value": "gwlbe"},
                            {"Key": "ZoneKey", "Value": self.route_table_owner.az_key},
                        ],
                        "Associations": [
                            {
                                "SubnetId": "subnet-8123456789abcdef0",
                                "Main": False,
                                "AssociationState": {"State": "associated"},
                            }
                        ],
                        "Routes": [
                            {
                                "DestinationCidrBlock": prefix,
                                "NetworkInterfaceId": target,
                                "Origin": "CreateRoute",
                                "State": "active",
                            }
                            for prefix, target in visible_routes.items()
                        ],
                    }
                ]
            }
        if operation == "describe-network-interfaces":
            members = {
                member.network_interface_id: member
                for member in self.topology.west.transport_router_fleet
            }
            requested = args[args.index("--network-interface-ids") + 1 :]
            return {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": interface_id,
                        "VpcId": "vpc-0123456789abcdef0",
                        "Status": "in-use",
                        "Attachment": {
                            "InstanceId": self.interface_instance_overrides.get(
                                interface_id, members[interface_id].instance_id
                            ),
                            "DeviceIndex": 0,
                            "Status": "attached",
                        },
                    }
                    for interface_id in requested
                ]
            }
        if operation == "replace-route":
            prefix = args[args.index("--destination-cidr-block") + 1]
            target = args[args.index("--network-interface-id") + 1]
            if target == self.alternate.network_interface_id:
                self.forward_calls += 1
                if self.fail_forward_call == self.forward_calls:
                    raise RuntimeError("injected partial route replacement failure")
                if not self.ignore_forward:
                    self.routes[prefix] = target
                return {}
            if target == self.current.network_interface_id:
                self.restoration_started = True
                if self.fail_restore_prefix == prefix:
                    raise RuntimeError("injected route restoration failure")
                self.routes[prefix] = target
                if self.ambiguous_restore_prefix == prefix:
                    raise RuntimeError("injected ambiguous route restoration completion")
                return {}
            raise AssertionError(f"unexpected route target {target}")
        raise AssertionError(f"unexpected fake AWS operation {operation}")

    @property
    def mutation_calls(self) -> list[list[str]]:
        return [args for args, _region in self.calls if args[1] == "replace-route"]


class GWLBERouteFailoverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.topology = route_failover_topology()
        self.current, self.alternate = self.topology.west.transport_router_fleet
        self.vpc_ids = {
            "west": "vpc-0123456789abcdef0",
            "east": "vpc-1123456789abcdef0",
        }

    def test_route_runner_identity_requires_one_stable_boot_identity(self) -> None:
        with (
            mock.patch.object(e2e, "_ROUTE_BOOT_ID_CACHE", None),
            mock.patch.object(pathlib.Path, "read_text", side_effect=OSError("absent")),
            mock.patch.object(e2e.sys, "platform", "unsupported"),
        ):
            with self.assertRaisesRegex(e2e.LifecycleError, "boot identity"):
                e2e._route_runner_identity()

        with (
            mock.patch.object(e2e, "_ROUTE_BOOT_ID_CACHE", None),
            mock.patch.object(pathlib.Path, "read_text", side_effect=OSError("absent")),
            mock.patch.object(e2e.sys, "platform", "darwin"),
            mock.patch.object(
                e2e.subprocess,
                "run",
                return_value=SimpleNamespace(stdout="{ sec = 123456, usec = 0 }\n"),
            ),
        ):
            identity = e2e._route_runner_identity()

        self.assertRegex(identity["boot_id"], e2e._ROUTE_BOOT_ID_RE)

    @staticmethod
    def authority(
        current: e2e.SymmetricFleetMember,
        alternate: e2e.SymmetricFleetMember,
        prefixes: tuple[str, ...],
        route_table_owner: e2e.SymmetricFleetMember,
    ) -> dict[str, Any]:
        return {
            "authorized": True,
            "ownership_verified": True,
            "cleanup_authorized": True,
            "claim_id": "11111111-2222-4333-8444-555555555555",
            "route_table_id": route_table_owner.gwlbe_route_table_id,
            "prefixes": list(prefixes),
            "source_prefix": current.advertised_prefix,
            "current_network_interface_id": current.network_interface_id,
            "alternate_network_interface_id": alternate.network_interface_id,
        }

    def failover(
        self,
        temporary: str,
        aws: RouteTableAWS,
        *,
        authorize: Any = None,
        environment: Mapping[str, str] | None = None,
        durability: e2e.RouteTransactionDurability | None = None,
    ) -> tuple[e2e.GWLBERouteFailover, FakeClock, list[str], pathlib.Path]:
        clock = FakeClock()
        ready: list[str] = []
        evidence_path = pathlib.Path(temporary) / "gwlbe-route-replacement.json"
        transaction = e2e.GWLBERouteFailover(
            self.topology,
            self.vpc_ids,
            aws,
            authorize=authorize or self.authority,
            durability=durability
            or ValidatingDurableRouteTransactions(self.topology, self.vpc_ids),
            verify_ready=lambda member: ready.append(member.instance_id),
            advertisement_control=FakeAdvertisementControl(self.topology, clock),
            evidence_path=evidence_path,
            environment=environment
            if environment is not None
            else {
                "ENVELOPE_E2E_APPROVED_RUN_ID": self.topology.run_id,
                "GITHUB_EVENT_NAME": "workflow_dispatch",
            },
            monotonic=clock,
            sleep=clock.sleep,
            api_timeout_seconds=1,
        )
        return transaction, clock, ready, evidence_path

    def successful_probe(self, _remaining: float) -> Mapping[str, Any]:
        evidence = symmetric_route_evidence()
        west_traversal = next(
            item
            for item in evidence["traversals"]
            if item["source_site"] == "west"
        )
        paths = {
            item["protocol"]: copy.deepcopy(item)
            for item in west_traversal["probes"]
            if item["source_role"] == "responder"
            and item["protocol"] in e2e.TRANSPORT_PROTOCOLS
        }
        return {
            **paths["udp"],
            "succeeded": True,
            "new_flows": {
                protocol: {"succeeded": True, "path": path}
                for protocol, path in paths.items()
            },
        }

    def assert_original_routes(self, aws: RouteTableAWS) -> None:
        self.assertEqual(
            aws.routes,
            {
                prefix: self.current.network_interface_id
                for prefix in self.topology.west.remote_site_cidrs
            },
        )

    def test_lease_and_stream_reservations_cover_long_transaction_components(self) -> None:
        failover = self.topology.route_failover
        prefix_count = len(self.topology.west.remote_site_cidrs)

        self.assertGreaterEqual(
            failover.owner_lease_seconds,
            e2e.TRANSPORT_ROUTER_READINESS_RESERVATION_SECONDS
            + failover.quiet_window_seconds
            + e2e.ROUTE_OWNER_LEASE_MARGIN_SECONDS,
        )
        self.assertLessEqual(
            failover.restoration_reservation_seconds(prefix_count),
            e2e.DEFAULT_TIMEOUTS.cleanup,
        )
        self.assertLessEqual(
            2
            * (
                failover.transaction_reservation_seconds(prefix_count)
                + e2e.CONTROLLED_STREAM_COMPLETION_HEADROOM_SECONDS
            ),
            e2e.DEFAULT_TIMEOUTS.hard_timeout,
        )
        transaction_seconds = failover.transaction_reservation_seconds(prefix_count)
        controlled_duration = (
            transaction_seconds
            + e2e.CONTROLLED_STREAM_COMPLETION_HEADROOM_SECONDS
        )
        marker_interval = controlled_duration / 160.0
        marker_count = int((controlled_duration - 2) / marker_interval)
        final_stop_check = (marker_count - 1) * marker_interval
        self.assertGreaterEqual(final_stop_check - transaction_seconds, 500)
        self.assertLessEqual(controlled_duration + 30, 3600)

    def test_ha26_over_budget_configuration_is_rejected_before_resource_authority(self) -> None:
        selections = self.topology.route_failover.initial_transport_router_az_by_gwlbe_az
        over_budget = e2e.SymmetricRouteFailover(
            mutation_timeout_seconds=120,
            restoration_timeout_seconds=120,
            recovery_timeout_seconds=600,
            initial_transport_router_az_by_gwlbe_az=selections,
        )
        with self.assertRaisesRegex(
            e2e.DeploymentError, "active-run reservations"
        ):
            e2e._validate_route_failover_run_budget(
                over_budget,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=5400,
                cleanup_timeout_seconds=2400,
            )

        bounded = e2e.SymmetricRouteFailover(
            mutation_timeout_seconds=120,
            restoration_timeout_seconds=120,
            recovery_timeout_seconds=300,
            initial_transport_router_az_by_gwlbe_az=selections,
        )
        with self.assertRaisesRegex(e2e.DeploymentError, "active-run reservations"):
            e2e._validate_route_failover_run_budget(
                bounded,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=7000,
                cleanup_timeout_seconds=2400,
            )

        required_active_seconds = 10_330
        summary = e2e._validate_route_failover_run_budget(
            bounded,
            prefix_counts={"west": 2, "east": 2},
            observer_counts={"west": 2, "east": 2},
            hard_timeout_seconds=required_active_seconds,
            cleanup_timeout_seconds=2400,
        )
        self.assertEqual(bounded.restoration_reservation_seconds(2), 1555)
        self.assertEqual(bounded.reconciliation_reservation_seconds(2), 1415)
        self.assertEqual(
            summary["transaction_seconds_by_site"],
            {"west": 3335, "east": 3335},
        )
        self.assertEqual(summary["total_transaction_seconds"], 6670)
        self.assertEqual(summary["non_route_active_seconds"], 3660)
        self.assertEqual(summary["required_active_seconds"], required_active_seconds)
        self.assertEqual(summary["active_run_slack_seconds"], 0)
        self.assertEqual(
            summary["non_route_active_seconds_by_phase"]["target_process_recovery"],
            480,
        )
        self.assertEqual(
            summary["non_route_active_seconds_by_phase"]["target_instance_recovery"],
            1200,
        )
        self.assertEqual(
            summary["combined_cleanup_seconds_by_site"],
            {"west": 2315, "east": 2315},
        )
        self.assertEqual(summary["resource_cleanup_seconds"], 900)

        with self.assertRaisesRegex(e2e.DeploymentError, "resource cleanup"):
            e2e._validate_route_failover_run_budget(
                bounded,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=required_active_seconds,
                cleanup_timeout_seconds=2314,
            )

        with self.assertRaisesRegex(e2e.DeploymentError, "active-run reservations"):
            e2e._validate_route_failover_run_budget(
                bounded,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=required_active_seconds - 1,
                cleanup_timeout_seconds=2400,
            )

        with self.assertRaisesRegex(e2e.DeploymentError, "stream and active-run"):
            e2e._validate_route_failover_run_budget(
                bounded,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=10_800,
                cleanup_timeout_seconds=2400,
                active_budgets=dataclasses.replace(
                    e2e.DEFAULT_TIMEOUTS, route_mutation=3000
                ),
            )

        with self.assertRaisesRegex(e2e.DeploymentError, "bounded continuity command"):
            e2e._validate_route_failover_run_budget(
                bounded,
                prefix_counts={"west": 2, "east": 2},
                observer_counts={"west": 2, "east": 2},
                hard_timeout_seconds=10_800,
                cleanup_timeout_seconds=2400,
                active_budgets=dataclasses.replace(
                    e2e.DEFAULT_TIMEOUTS, ec2_reboot=3000
                ),
            )

    def pending_journal(
        self,
        aws: RouteTableAWS,
        *,
        claim_id: str = "11111111-2222-4333-8444-555555555555",
        owner: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        def snapshot(target: str) -> dict[str, Any]:
            return {
                "route_table_id": self.current.gwlbe_route_table_id,
                "vpc_id": self.vpc_ids["west"],
                "ownership": {
                    "EnvelopeRun": self.topology.run_id,
                    "ManagedBy": "terraform",
                    "Profile": "symmetric-gwlb-ha-v2",
                    "Role": "gwlbe",
                    "ZoneKey": self.current.az_key,
                },
                "routes": [
                    {
                        "destination_cidr_block": prefix,
                        "network_interface_id": target,
                        "origin": "CreateRoute",
                        "route_state": "active",
                    }
                    for prefix in self.topology.west.remote_site_cidrs
                ],
            }

        node_ids = {
            member.instance_id: f"node-{member.site}-{member.az_key}"
            for site in e2e.SITES
            for member in self.topology.site(site).transport_router_fleet
        }

        def ownership_observation(owners: Mapping[str, str]) -> dict[str, Any]:
            return {
                "quiet_window_seconds": self.topology.route_failover.quiet_window_seconds,
                "observers": [
                    {
                        "observer_instance_id": observer.instance_id,
                        "owners": [
                            {
                                "prefix": prefix,
                                "owner_instance_id": owner,
                                "owner_node_id_sha256": hashlib.sha256(
                                    node_ids[owner].encode("utf-8")
                                ).hexdigest(),
                            }
                            for prefix, owner in sorted(owners.items())
                        ],
                        "command": None,
                    }
                    for observer in self.topology.east.transport_router_fleet
                ],
            }

        baseline_owners = {
            member.advertised_prefix: member.instance_id
            for member in self.topology.west.transport_router_fleet
        }
        transferred_owners = dict(baseline_owners)
        transferred_owners[self.current.advertised_prefix] = self.alternate.instance_id

        identity = e2e._route_runner_identity()
        identity["pid"] = 99_999_999
        return {
            "schema": e2e.ROUTE_JOURNAL_SCHEMA,
            "kind": e2e.ROUTE_JOURNAL_KIND,
            "run_id": self.topology.run_id,
            "claim_id": claim_id,
            "transaction_id": "22222222-3333-4444-8555-666666666666",
            "owner": dict(owner or identity),
            "lease_expires_at": "2026-08-20T12:01:00Z",
            "site": "west",
            "gwlbe_az_key": self.current.az_key,
            "started_at": "2026-08-20T12:00:00Z",
            "status": "alternate-active",
            "route_table_id": self.current.gwlbe_route_table_id,
            "source_prefix": self.current.advertised_prefix,
            "prefixes": list(self.topology.west.remote_site_cidrs),
            "current": {
                "instance_id": self.current.instance_id,
                "network_interface_id": self.current.network_interface_id,
                "baseline_advertisements": [self.current.advertised_prefix],
                "state_before": {
                    "advertisements": {
                        "generation": "initial-west-a",
                        "routes": [self.current.advertised_prefix],
                        "service": "running",
                        "mode": "normal",
                    },
                    "command": None,
                },
                "node_id_sha256": hashlib.sha256(b"node-west-a").hexdigest(),
            },
            "alternate": {
                "instance_id": self.alternate.instance_id,
                "network_interface_id": self.alternate.network_interface_id,
                "baseline_advertisements": [self.alternate.advertised_prefix],
                "state_before": {
                    "advertisements": {
                        "generation": "initial-west-b",
                        "routes": [self.alternate.advertised_prefix],
                        "service": "running",
                        "mode": "normal",
                    },
                    "command": None,
                },
                "node_id_sha256": hashlib.sha256(b"node-west-b").hexdigest(),
            },
            "interfaces": [
                {
                    "instance_id": self.current.instance_id,
                    "network_interface_id": self.current.network_interface_id,
                },
                {
                    "instance_id": self.alternate.instance_id,
                    "network_interface_id": self.alternate.network_interface_id,
                },
            ],
            "before": snapshot(self.current.network_interface_id),
            "advertisements": {
                "forward_generation": "33333333-4444-4555-8666-777777777777",
                "restore_generation": "44444444-5555-4666-8777-888888888888",
                "failure_mode": "abrupt",
                "alternate_expansion": {
                    "advertisements": {
                        "generation": "33333333-4444-4555-8666-777777777777",
                        "routes": sorted(
                            {
                                self.current.advertised_prefix,
                                self.alternate.advertised_prefix,
                            }
                        ),
                        "service": "running",
                        "mode": "normal",
                    },
                    "command": None,
                },
                "current_withdrawal": {
                    "advertisements": {
                        "generation": "33333333-4444-4555-8666-777777777777",
                        "routes": [],
                        "service": "stopped",
                        "mode": "abrupt",
                    },
                    "command": None,
                },
            },
            "ownership": {
                "before": ownership_observation(baseline_owners),
                "transferred": ownership_observation(transferred_owners),
            },
            "mutation": {
                "attempted_prefixes": list(self.topology.west.remote_site_cidrs),
                "completed_prefixes": list(self.topology.west.remote_site_cidrs),
                "ambiguous_calls": [],
            },
            "after": snapshot(self.alternate.network_interface_id),
            "probe": None,
            "restoration": {
                "status": "not-started",
                "advertisements": {"status": "not-started"},
                "ownership": {"status": "not-started"},
                "routes": {"status": "not-started"},
            },
            "failure": None,
        }

    def cleanup_marker(
        self, journal: Mapping[str, Any]
    ) -> dict[str, Any]:
        owner = e2e._route_runner_identity()
        owner["pid"] = 99_999_999
        owner["host_sha256"] = "f" * 64
        return {
            "schema": e2e.ROUTE_RECOVERY_MARKER_SCHEMA,
            "kind": e2e.ROUTE_RECOVERY_MARKER_KIND,
            "run_id": self.topology.run_id,
            "claim_id": journal["claim_id"],
            "transaction_id": journal["transaction_id"],
            "owner": owner,
            "lease_expires_at": "2026-08-20T12:01:00Z",
            "restored_at": "2026-08-20T12:02:00Z",
            "restoration_status": "reconciled-after-crash",
            "status": "cleanup-pending",
        }

    def active_route_adapter(
        self,
    ) -> tuple[
        Mapping[str, Any],
        e2e.SymmetricProtectedDeployment,
        DurableManifestStore,
        e2e.ProtectedLifecycleAdapter,
        Mapping[str, Any],
    ]:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        store = DurableManifestStore(ready_lifecycle_manifest(raw))
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(
            run_id=self.topology.run_id,
            sites=lifecycle_sites(),
        )
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"
        adapter._route_only_recovery = False
        claim = adapter.claim(raw, deployment)
        adapter.bind_transport_node_identities(
            {
                member.instance_id: f"node-{site}-{member.az_key}"
                for site in e2e.SITES
                for member in self.topology.site(site).transport_router_fleet
            }
        )
        return raw, deployment, store, adapter, claim

    def test_authorized_replacement_records_before_after_and_verified_restoration(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, ready, evidence_path = self.failover(temporary, aws)
            result = transaction.replace(
                self.current,
                self.alternate,
                probe=self.successful_probe,
                timeout_seconds=10,
                restoration_timeout_seconds=10,
            )
            journal = json.loads(evidence_path.read_text())
            evidence_mode = stat.S_IMODE(evidence_path.stat().st_mode)
            durability = transaction.durability

        self.assertTrue(result["restored"])
        self.assertEqual(
            ready,
            [
                self.current.instance_id,
                self.alternate.instance_id,
                self.current.instance_id,
                self.alternate.instance_id,
            ],
        )
        self.assertEqual(len(aws.mutation_calls), 4)
        self.assert_original_routes(aws)
        self.assertEqual(journal["status"], "restored")
        self.assertEqual(
            {route["network_interface_id"] for route in journal["before"]["routes"]},
            {self.current.network_interface_id},
        )
        self.assertEqual(
            {route["network_interface_id"] for route in journal["after"]["routes"]},
            {self.alternate.network_interface_id},
        )
        self.assertEqual(journal["restoration"]["status"], "verified")
        self.assertEqual(
            [
                operation["advertisements"]["service"]
                for operation in transaction.advertisement_control.operations
            ],
            ["running", "stopped", "running", "running"],
        )
        self.assertEqual(
            transaction.advertisement_control.operations[0]["advertisements"][
                "routes"
            ],
            sorted(
                {
                    self.current.advertised_prefix,
                    self.alternate.advertised_prefix,
                }
            ),
        )
        self.assertEqual(evidence_mode, 0o600)
        self.assertIsInstance(durability, DurableRouteTransactions)
        self.assertIsNone(durability.value)
        self.assertEqual(len(durability.finalized), 1)
        self.assertTrue(
            all("lease_expires_at" in value for value in durability.writes)
        )
        for persisted in durability.writes:
            e2e.GWLBERouteFailover.validate_durable_binding(
                persisted,
                self.topology,
                self.vpc_ids,
                node_ids_by_instance=(
                    transaction.advertisement_control.node_ids_by_instance
                ),
            )

    def test_recovery_probe_uses_its_separate_reviewed_deadline(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, clock, _ready, _evidence_path = self.failover(
                temporary, aws
            )
            control = transaction.advertisement_control
            original_apply = control.apply

            def slow_apply(*args: Any, **kwargs: Any) -> dict[str, Any]:
                result = original_apply(*args, **kwargs)
                clock.sleep(10)
                return result

            control.apply = slow_apply
            observed_remaining: list[float] = []

            def probe(remaining: float) -> Mapping[str, Any]:
                observed_remaining.append(remaining)
                clock.sleep(9)
                return self.successful_probe(remaining)

            result = transaction.replace(
                self.current,
                self.alternate,
                probe=probe,
                timeout_seconds=self.topology.route_failover.mutation_timeout_seconds,
                restoration_timeout_seconds=(
                    self.topology.route_failover.restoration_timeout_seconds
                ),
            )

        self.assertTrue(result["restored"])
        self.assertEqual(
            observed_remaining,
            [float(self.topology.route_failover.recovery_timeout_seconds)],
        )
        self.assert_original_routes(aws)

    def test_lifecycle_proxies_delegate_complete_route_transaction_protocol(self) -> None:
        for proxy_name in ("run-all", "bounded-cleanup"):
            with self.subTest(proxy=proxy_name), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                durability = DurableRouteTransactions()
                proxy: e2e.RouteTransactionDurability
                if proxy_name == "run-all":
                    proxy = e2e._RunAllLifecycleProxy(
                        durability, lambda: {"complete": True}
                    )
                else:
                    proxy = e2e._BoundedCleanupLifecycleProxy(durability)
                self.assertTrue(
                    proxy.bind_transport_node_identities(
                        {"i-0123456789abcdef0": "node-fixture"}
                    )["bound"]
                )
                self.assertIsNone(proxy.load_route_transaction())
                transaction, _clock, _ready, _evidence_path = self.failover(
                    temporary, aws, durability=proxy
                )

                result = transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )

                self.assertTrue(result["restored"])
                self.assert_original_routes(aws)
                self.assertIsNone(durability.value)
                self.assertEqual(len(durability.finalized), 1)
                self.assertEqual(len(durability.node_bindings), 1)

    def test_ambiguous_advertisement_completion_restores_and_fences_late_forward(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, evidence_path = self.failover(
                temporary, aws
            )
            control = transaction.advertisement_control
            control.fail_after_apply = 1
            with self.assertRaisesRegex(
                RuntimeError, "ambiguous advertisement completion"
            ):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(evidence_path.read_text())

        self.assert_original_routes(aws)
        self.assertEqual(journal["restoration"]["status"], "verified")
        self.assertEqual(
            journal["restoration"]["advertisements"]["status"], "verified"
        )
        self.assertEqual(
            journal["restoration"]["ownership"]["status"], "verified"
        )
        self.assertEqual(journal["restoration"]["routes"]["status"], "verified")
        with self.assertRaisesRegex(e2e.ResilienceError, "stale"):
            control.apply(
                self.alternate,
                [
                    self.current.advertised_prefix,
                    self.alternate.advertised_prefix,
                ],
                service="running",
                mode="normal",
                generation=journal["advertisements"]["forward_generation"],
                predecessors=[
                    journal["alternate"]["state_before"]["advertisements"][
                        "generation"
                    ]
                ],
                timeout_seconds=10,
            )

    def test_restoration_keeps_alternate_coverage_and_routes_when_current_cannot_start(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, evidence_path = self.failover(
                temporary, aws
            )
            control = transaction.advertisement_control
            control.fail_before_apply = 3
            with self.assertRaisesRegex(
                e2e.RouteRestorationError,
                "advertisements and ownership before routes",
            ):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(evidence_path.read_text())

        self.assertEqual(
            set(aws.routes.values()), {self.alternate.network_interface_id}
        )
        self.assertEqual(len(aws.mutation_calls), 2)
        self.assertEqual(journal["status"], "restoration-failed")
        self.assertEqual(journal["restoration"]["routes"]["status"], "failed")
        self.assertEqual(
            [operation["advertisements"]["service"] for operation in control.operations],
            ["running", "stopped"],
        )
        self.assertEqual(
            control.states[self.alternate.instance_id]["routes"],
            sorted(
                {
                    self.current.advertised_prefix,
                    self.alternate.advertised_prefix,
                }
            ),
        )

    def test_initial_transport_router_selection_rejects_cross_az_routes(self) -> None:
        raw_topology = self.topology.as_dict()
        raw_topology["route_failover"]["initial_transport_router_az_by_gwlbe_az"][
            "west"
        ] = {"a": "b", "b": "a"}
        with self.assertRaisesRegex(e2e.DeploymentError, "same transport-router AZ"):
            e2e.parse_symmetric_topology_v2(raw_topology)

    def test_requires_protected_runner_and_exact_durable_authority(self) -> None:
        cases = {
            "unprotected": ({}, self.authority),
            "durable-denial": (
                {
                    "ENVELOPE_E2E_APPROVED_RUN_ID": self.topology.run_id,
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                },
                lambda *_args: {"authorized": False},
            ),
        }
        for name, (environment, authority) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                transaction, _clock, _ready, _path = self.failover(
                    temporary,
                    aws,
                    authorize=authority,
                    environment=environment,
                )
                with self.assertRaises(e2e.E2EError):
                    transaction.replace(
                        self.current,
                        self.alternate,
                        probe=self.successful_probe,
                        timeout_seconds=10,
                        restoration_timeout_seconds=10,
                    )
                self.assertEqual(aws.mutation_calls, [])

    def test_rejects_wrong_route_table_ownership_before_mutation(self) -> None:
        mutations = {
            "run ownership": lambda aws: setattr(aws, "run_tag", "another-run"),
            "route identity": lambda aws: setattr(
                aws, "response_route_table_id", "rtb-fffffffffffffffff"
            ),
            "ENI ownership": lambda aws: aws.interface_instance_overrides.update(
                {self.alternate.network_interface_id: "i-ff23456789abcdef"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                mutate(aws)
                transaction, _clock, _ready, _path = self.failover(temporary, aws)
                with self.assertRaises(e2e.ResilienceError):
                    transaction.replace(
                        self.current,
                        self.alternate,
                        probe=self.successful_probe,
                        timeout_seconds=10,
                        restoration_timeout_seconds=10,
                    )
                self.assertEqual(aws.mutation_calls, [])

    def test_rejects_wrong_prefix_current_target_and_alternate_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            aws = RouteTableAWS(self.topology)
            del aws.routes[self.topology.west.remote_site_cidrs[-1]]
            transaction, _clock, _ready, _path = self.failover(temporary, aws)
            with self.assertRaisesRegex(e2e.ResilienceError, "route"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            self.assertEqual(aws.mutation_calls, [])

        with tempfile.TemporaryDirectory() as temporary:
            aws = RouteTableAWS(self.topology)
            aws.routes[self.topology.west.remote_site_cidrs[0]] = "eni-fffffffffffffffff"
            transaction, _clock, _ready, _path = self.failover(temporary, aws)
            with self.assertRaisesRegex(e2e.ResilienceError, "current ENI"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            self.assertEqual(aws.mutation_calls, [])

        foreign = self.topology.east.transport_router_fleet[0]
        with tempfile.TemporaryDirectory() as temporary:
            aws = RouteTableAWS(self.topology)
            transaction, _clock, _ready, _path = self.failover(temporary, aws)
            with self.assertRaisesRegex(e2e.ResilienceError, "alternate"):
                transaction.replace(
                    self.current,
                    foreign,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            self.assertEqual(aws.mutation_calls, [])

    def test_partial_mutation_rolls_back_every_prefix(self) -> None:
        aws = RouteTableAWS(self.topology)
        aws.fail_forward_call = 2
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, evidence_path = self.failover(temporary, aws)
            with self.assertRaisesRegex(e2e.AmbiguousRouteMutationError, "ambiguous"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(evidence_path.read_text())

        self.assert_original_routes(aws)
        self.assertEqual(journal["status"], "restored-after-failure")
        self.assertEqual(
            journal["restoration"]["routes"]["attempted_prefixes"],
            list(self.topology.west.remote_site_cidrs),
        )

    def test_cas_collision_before_forward_call_never_selects_alternate(self) -> None:
        aws = RouteTableAWS(self.topology)
        durability = DurableRouteTransactions()
        durability.fail_next_update = True
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, _path = self.failover(
                temporary, aws, durability=durability
            )
            with self.assertRaisesRegex(e2e.ConcurrentRunError, "CAS collision"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )

        alternate_calls = [
            args
            for args in aws.mutation_calls
            if args[args.index("--network-interface-id") + 1]
            == self.alternate.network_interface_id
        ]
        self.assertEqual(alternate_calls, [])
        self.assert_original_routes(aws)

    def test_restoration_requires_a_repeated_quiet_visibility_window(self) -> None:
        aws = RouteTableAWS(self.topology)
        first_prefix = self.topology.west.remote_site_cidrs[0]
        aws.restore_visibility_failures[first_prefix] = 3
        with tempfile.TemporaryDirectory() as temporary:
            transaction, clock, _ready, path = self.failover(temporary, aws)
            result = transaction.replace(
                self.current,
                self.alternate,
                probe=self.successful_probe,
                timeout_seconds=10,
                restoration_timeout_seconds=10,
            )
            journal = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(result["restored"])
        self.assertGreaterEqual(clock.value, 5)
        self.assertEqual(
            journal["restoration"]["routes"]["settled_prefixes"],
            list(self.topology.west.remote_site_cidrs),
        )

    def test_reconcile_restores_each_persisted_mutation_phase(self) -> None:
        statuses = (
            "authorized",
            "alternate-advertising",
            "ownership-converging",
            "ownership-transferred",
            "failed-before-restoration",
            "ambiguous-forward-call",
            "alternate-active",
            "probe-passed",
            "recovery-claimed",
            "restoring",
            "restoration-failed",
            "restored",
            "restored-after-failure",
            "reconciled-after-crash",
        )

        templates: dict[str, dict[str, Any]] = {}

        def collect(transaction: e2e.GWLBERouteFailover) -> None:
            durability = transaction.durability
            self.assertIsInstance(durability, DurableRouteTransactions)
            for value in durability.writes:
                templates.setdefault(value["status"], copy.deepcopy(value))

        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, _path = self.failover(
                temporary, RouteTableAWS(self.topology)
            )
            transaction.replace(
                self.current,
                self.alternate,
                probe=self.successful_probe,
                timeout_seconds=10,
                restoration_timeout_seconds=10,
            )
            collect(transaction)

        with tempfile.TemporaryDirectory() as temporary:
            aws = RouteTableAWS(self.topology)
            aws.fail_forward_call = 1
            transaction, _clock, _ready, _path = self.failover(temporary, aws)
            with self.assertRaises(e2e.AmbiguousRouteMutationError):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            collect(transaction)

        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, _path = self.failover(
                temporary, RouteTableAWS(self.topology)
            )
            transaction.advertisement_control.fail_before_apply = 3
            with self.assertRaises(e2e.RouteRestorationError):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            collect(transaction)

        templates["recovery-claimed"] = copy.deepcopy(
            templates["ownership-transferred"]
        )
        templates["recovery-claimed"]["status"] = "recovery-claimed"
        templates["reconciled-after-crash"] = copy.deepcopy(templates["restored"])
        templates["reconciled-after-crash"]["status"] = "reconciled-after-crash"
        templates["reconciled-after-crash"]["reconciled_at"] = templates[
            "reconciled-after-crash"
        ]["finished_at"]
        self.assertEqual(set(templates).intersection(statuses), set(statuses))

        for status in statuses:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                if status not in {
                    "authorized",
                    "restored",
                    "restored-after-failure",
                    "reconciled-after-crash",
                }:
                    aws.routes = {
                        prefix: self.alternate.network_interface_id
                        for prefix in self.topology.west.remote_site_cidrs
                    }
                journal = copy.deepcopy(templates[status])
                journal["lease_expires_at"] = "2099-08-20T12:01:00Z"
                durability = ValidatingDurableRouteTransactions(
                    self.topology, self.vpc_ids, journal
                )
                transaction, _clock, _ready, _path = self.failover(
                    temporary, aws, durability=durability
                )

                result = transaction.reconcile(restoration_timeout_seconds=10)

                self.assertTrue(result["restored"])
                self.assertIsNone(durability.value)
                self.assert_original_routes(aws)

    def test_timeout_and_interruption_restore_original_routes(self) -> None:
        failures = (TimeoutError("probe deadline"), KeyboardInterrupt("runner interrupted"))
        for failure in failures:
            with self.subTest(category=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                transaction, _clock, _ready, evidence_path = self.failover(temporary, aws)

                def fail_probe(_remaining: float, error: BaseException = failure) -> Mapping[str, Any]:
                    raise error

                with self.assertRaises(type(failure)):
                    transaction.replace(
                        self.current,
                        self.alternate,
                        probe=fail_probe,
                        timeout_seconds=10,
                        restoration_timeout_seconds=10,
                    )
                journal = json.loads(evidence_path.read_text())
                self.assert_original_routes(aws)
                self.assertEqual(journal["status"], "restored-after-failure")
                self.assertEqual(journal["failure"]["category"], type(failure).__name__)

    def test_route_convergence_timeout_uses_fresh_restoration_deadline(self) -> None:
        aws = RouteTableAWS(self.topology)
        aws.ignore_forward = True
        probe = mock.Mock(side_effect=AssertionError("probe must wait for route convergence"))
        with tempfile.TemporaryDirectory() as temporary:
            transaction, clock, _ready, evidence_path = self.failover(temporary, aws)
            with self.assertRaisesRegex(TimeoutError, "converge"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=probe,
                    timeout_seconds=7,
                    restoration_timeout_seconds=7,
                )
            journal = json.loads(evidence_path.read_text())

        probe.assert_not_called()
        self.assertGreaterEqual(clock.value, 7)
        self.assert_original_routes(aws)
        self.assertEqual(journal["restoration"]["status"], "verified")
        self.assertEqual(journal["status"], "restored-after-failure")

    def test_restoration_failure_overrides_probe_failure_and_reports_residual_route(self) -> None:
        aws = RouteTableAWS(self.topology)
        failed_prefix = self.topology.west.remote_site_cidrs[0]
        aws.fail_restore_prefix = failed_prefix
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, evidence_path = self.failover(temporary, aws)

            def timeout_probe(_remaining: float) -> Mapping[str, Any]:
                raise TimeoutError("probe deadline")

            with self.assertRaises(e2e.RouteRestorationError) as raised:
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=timeout_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(evidence_path.read_text())

        self.assertIn("after TimeoutError", str(raised.exception))
        self.assertIsInstance(raised.exception.__cause__, TimeoutError)
        self.assertEqual(aws.routes[failed_prefix], self.alternate.network_interface_id)
        self.assertEqual(journal["status"], "restoration-failed")
        self.assertEqual(journal["restoration"]["status"], "failed")
        self.assertEqual(
            {
                value["prefix"]
                for value in journal["restoration"]["routes"]["api_failures"]
            },
            {failed_prefix},
        )

    def test_ambiguous_restoration_call_does_not_finalize_after_matching_observation(self) -> None:
        aws = RouteTableAWS(self.topology)
        failed_prefix = self.topology.west.remote_site_cidrs[0]
        aws.ambiguous_restore_prefix = failed_prefix
        durability = DurableRouteTransactions()
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, evidence_path = self.failover(
                temporary, aws, durability=durability
            )
            with self.assertRaises(e2e.RouteRestorationError):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(evidence_path.read_text())

        self.assert_original_routes(aws)
        self.assertEqual(journal["status"], "restoration-failed")
        self.assertEqual(journal["restoration"]["routes"]["status"], "failed")
        self.assertEqual(
            [failure["prefix"] for failure in journal["restoration"]["routes"]["api_failures"]],
            [failed_prefix],
        )
        self.assertIsNotNone(durability.value)
        self.assertEqual(durability.finalized, [])

    def test_restoration_aborts_before_mutation_when_initial_lease_cas_is_lost(self) -> None:
        class LoseInitialRestorationCAS(DurableRouteTransactions):
            def update_route_transaction(self, value, *, expected_revision):
                if value.get("status") == "restoring":
                    raise e2e.ConcurrentRunError("injected restoration ownership loss")
                return super().update_route_transaction(
                    value, expected_revision=expected_revision
                )

        aws = RouteTableAWS(self.topology)
        durability = LoseInitialRestorationCAS()
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, _path = self.failover(
                temporary, aws, durability=durability
            )
            with self.assertRaisesRegex(e2e.ConcurrentRunError, "ownership loss"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )

        self.assertEqual(len(transaction.advertisement_control.operations), 2)
        self.assertFalse(aws.restoration_started)
        self.assertTrue(
            all(target == self.alternate.network_interface_id for target in aws.routes.values())
        )

    def test_loss_after_first_restoration_mutation_stops_all_later_mutations(self) -> None:
        class LoseDuringRestoration(DurableRouteTransactions):
            def update_route_transaction(self, value, *, expected_revision):
                restoration = value.get("restoration")
                advertisements = (
                    restoration.get("advertisements")
                    if isinstance(restoration, Mapping)
                    else None
                )
                if (
                    isinstance(advertisements, Mapping)
                    and advertisements.get("current") is not None
                    and advertisements.get("alternate") is None
                ):
                    raise e2e.ConcurrentRunError("injected loss during restoration")
                return super().update_route_transaction(
                    value, expected_revision=expected_revision
                )

        aws = RouteTableAWS(self.topology)
        durability = LoseDuringRestoration()
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, _path = self.failover(
                temporary, aws, durability=durability
            )
            with self.assertRaisesRegex(e2e.ConcurrentRunError, "during restoration"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=self.successful_probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )

        self.assertEqual(len(transaction.advertisement_control.operations), 3)
        self.assertFalse(aws.restoration_started)
        self.assertTrue(
            all(target == self.alternate.network_interface_id for target in aws.routes.values())
        )

    def test_durable_claim_authorizer_rejects_wrong_ownership_and_allowlist(self) -> None:
        manifest = {
            "phase": "e2e_running",
            "deployment": {},
            "e2e": {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "a" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            },
        }
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.manifest = copy.deepcopy(manifest)
        adapter._ownership_state = "running-owned"
        adapter._claim_etag = '"etag"'
        adapter.config = SimpleNamespace(run_id=self.topology.run_id, sites=lifecycle_sites())
        adapter._authoritative_recover = lambda: (copy.deepcopy(manifest), '"etag"')
        deployment = SimpleNamespace(topology=self.topology, output_sha256="a" * 64)

        with mock.patch.object(e2e, "parse_symmetric_protected_deployment_output", return_value=deployment):
            authorized = adapter.authorize_gwlbe_route_replacement(
                self.current,
                self.alternate,
                self.topology.west.remote_site_cidrs,
                self.current,
            )
            self.assertTrue(authorized["cleanup_authorized"])
            with self.assertRaisesRegex(e2e.ResilienceError, "prefixes"):
                adapter.authorize_gwlbe_route_replacement(
                    self.current,
                    self.alternate,
                    self.topology.west.remote_site_cidrs[:-1],
                    self.current,
                )

        replacement_manifest = copy.deepcopy(manifest)
        replacement_manifest["e2e"]["replacement"] = {
            "address": 'aws_instance.envelope_target_west["a"]',
            "old_instance_id": "i-6123456789abcdef0",
            "started_at": "2026-08-20T12:01:00Z",
            "finished_at": "2026-08-20T12:02:00Z",
            "new_output_sha256": "b" * 64,
        }
        adapter.manifest = replacement_manifest
        adapter._authoritative_recover = lambda: (copy.deepcopy(replacement_manifest), '"etag"')
        replacement_deployment = SimpleNamespace(topology=self.topology, output_sha256="b" * 64)
        with mock.patch.object(
            e2e,
            "parse_symmetric_protected_deployment_output",
            return_value=replacement_deployment,
        ):
            self.assertTrue(
                adapter.authorize_gwlbe_route_replacement(
                    self.current,
                    self.alternate,
                    self.topology.west.remote_site_cidrs,
                    self.current,
                )["authorized"]
            )

        adapter._ownership_state = "unclaimed"
        with self.assertRaises(e2e.ClaimPersistenceError):
            adapter.authorize_gwlbe_route_replacement(
                self.current,
                self.alternate,
                self.topology.west.remote_site_cidrs,
                self.current,
            )

    def test_route_calls_delegate_timeout_to_native_aws_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            class NativeTimeoutAWS:
                timeout: float | None = None

                def json(self, _args, *, region=None, timeout_seconds=None):
                    self.timeout = timeout_seconds
                    raise TimeoutError("native child was killed and reaped")

            aws = NativeTimeoutAWS()
            transaction = e2e.GWLBERouteFailover(
                self.topology,
                self.vpc_ids,
                aws,
                authorize=self.authority,
                durability=DurableRouteTransactions(),
                verify_ready=lambda _member: None,
                advertisement_control=FakeAdvertisementControl(
                    self.topology, FakeClock()
                ),
                evidence_path=root / "journal.json",
                api_timeout_seconds=0.05,
            )
            with self.assertRaisesRegex(TimeoutError, "native"):
                transaction._aws_json(
                    ["ec2", "replace-route"],
                    region="us-west-2",
                    deadline=time.monotonic() + 1,
                    operation="injected native route mutation",
                )
            self.assertEqual(aws.timeout, 0.05)

    def test_native_route_timeout_kills_and_reaps_before_late_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            executable = root / "aws"
            marker = root / "late-route-mutation"
            executable.write_text(
                "#!/bin/sh\nsleep 0.3\nprintf late >\"$ROUTE_LATE_MARKER\"\nprintf '{}\\n'\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            transaction = e2e.GWLBERouteFailover(
                self.topology,
                self.vpc_ids,
                e2e.AwsCLI(e2e.SubprocessRunner()),
                authorize=self.authority,
                durability=DurableRouteTransactions(),
                verify_ready=lambda _member: None,
                advertisement_control=FakeAdvertisementControl(
                    self.topology, FakeClock()
                ),
                evidence_path=root / "journal.json",
                api_timeout_seconds=0.05,
            )
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "ROUTE_LATE_MARKER": str(marker),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(TimeoutError, "native"):
                    transaction._aws_json(
                        ["ec2", "replace-route"],
                        region="us-west-2",
                        deadline=time.monotonic() + 1,
                        operation="injected native route mutation",
                    )
                time.sleep(0.4)
            self.assertFalse(marker.exists())

    def test_restart_adopts_exact_dead_claim_and_restores_durable_journal(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        manifest = ready_lifecycle_manifest(raw)
        claim_id = "11111111-2222-4333-8444-555555555555"
        manifest["phase"] = "e2e_running"
        abandoned = self.pending_journal(RouteTableAWS(self.topology))
        abandoned["owner"]["host_sha256"] = "f" * 64
        manifest["e2e"] = {
            "claim_id": claim_id,
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_transaction": abandoned,
        }
        aws = RouteTableAWS(self.topology)
        aws.routes = {
            prefix: self.alternate.network_interface_id
            for prefix in self.topology.west.remote_site_cidrs
        }
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = pathlib.Path(temporary)
            journal_path = run_dir / "gwlbe-route-replacement.json"
            store = DurableManifestStore(manifest)
            adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
            adapter.store = store
            adapter.config = SimpleNamespace(run_id=self.topology.run_id, sites=lifecycle_sites())
            adapter.aws = aws
            adapter.runner = SimpleNamespace()
            adapter.run_dir = run_dir
            adapter.terraform_dir = ROOT / "example" / "terraform"
            adapter.manifest = None
            adapter._ownership_state = "unclaimed"
            adapter._claim_etag = None
            adapter._claim_original_manifest = None
            adapter._claim_original_etag = None
            adapter._last_persistence_resolution = "none"
            store.value["saved_plan"]["applied"] = False
            with self.assertRaisesRegex(
                e2e.DeploymentError, "one successful reviewed apply"
            ):
                adapter.claim(raw, deployment, require_route_recovery=True)
            self.assertEqual(store.writes, [])
            store.value["saved_plan"]["applied"] = True
            claim = adapter.claim(raw, deployment, require_route_recovery=True)
            self.assertTrue(claim["route_recovery_required"])
            with self.assertRaisesRegex(
                e2e.ClaimPersistenceError, "passing acceptance"
            ):
                adapter.finish(True)
            deferred = adapter.finish(False)
            self.assertEqual(deferred["finish"], "deferred-route-recovery")
            self.assertEqual(store.value["phase"], "e2e_running")
            with mock.patch.dict(
                os.environ,
                {
                    "ENVELOPE_E2E_APPROVED_RUN_ID": self.topology.run_id,
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                },
                clear=False,
            ), mock.patch.object(
                e2e, "build_tailscale", return_value=SimpleNamespace()
            ), mock.patch.object(
                e2e,
                "protected_cleanup",
                return_value={"final_residual_count": 0},
            ), mock.patch.object(
                e2e.AwsSymmetricLiveOperations,
                "_advertisement_control",
                return_value=FakeAdvertisementControl(self.topology, FakeClock()),
            ):
                result = adapter.cleanup()
            persisted = json.loads(journal_path.read_text(encoding="utf-8"))

        self.assertTrue(result["route_recovery_before_cleanup"]["restored"])
        self.assert_original_routes(aws)
        self.assertEqual(persisted["status"], "reconciled-after-crash")
        self.assertEqual(persisted["restoration"]["status"], "verified")
        self.assertEqual(store.value["phase"], "e2e_failed")
        self.assertNotIn("route_transaction", store.value["e2e"])
        self.assertEqual(
            store.value["e2e"]["route_recovery"]["status"],
            "cleanup-claimed",
        )

    def test_recovery_rejects_every_static_transaction_mismatch_before_cas(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)

        def output_hash(manifest, _journal):
            manifest["e2e"]["output_sha256"] = "b" * 64

        def route_table(_manifest, journal):
            journal["route_table_id"] = "rtb-f123456789abcdef0"

        def prefixes(_manifest, journal):
            journal["prefixes"][0] = "10.99.0.0/24"

        def router_eni(_manifest, journal):
            journal["current"]["network_interface_id"] = "eni-f123456789abcdef0"

        def topology_site(_manifest, journal):
            journal["site"] = "east"

        def generations(_manifest, journal):
            journal["advertisements"]["restore_generation"] = journal[
                "advertisements"
            ]["forward_generation"]

        def predecessor_generation(_manifest, journal):
            journal["current"]["state_before"]["advertisements"][
                "generation"
            ] = journal["advertisements"]["forward_generation"]

        def vpc(_manifest, journal):
            journal["before"]["vpc_id"] = "vpc-f123456789abcdef0"

        def uuid_version_one(_manifest, journal):
            journal["transaction_id"] = (
                "22222222-3333-1444-8555-666666666666"
            )

        def simultaneous_marker(manifest, journal):
            manifest["e2e"]["route_recovery"] = self.cleanup_marker(journal)

        def node_hash(_manifest, journal):
            journal["current"]["node_id_sha256"] = "a" * 64

        def ownership_progress(_manifest, journal):
            journal["ownership"].pop("transferred")

        def mutation_progress(_manifest, journal):
            journal["mutation"]["attempted_prefixes"].reverse()

        def restoration_progress(_manifest, journal):
            journal["restoration"]["routes"] = {"status": "unknown"}

        def restoration_extra_field(_manifest, journal):
            journal["restoration"]["advertisements"]["unexpected"] = {
                "forged": True
            }

        def restoration_missing_field(_manifest, journal):
            journal["restoration"]["ownership"].pop("status")

        def restoration_status_contradiction(_manifest, journal):
            journal["restoration"]["status"] = "verified"

        def ownership_observation_extra_field(_manifest, journal):
            journal["ownership"]["before"]["unexpected"] = {"forged": True}

        def status_progress_contradiction(_manifest, journal):
            journal["status"] = "authorized"

        def probe_extra_field(_manifest, journal):
            journal["status"] = "probe-passed"
            journal["probe"] = {
                **self.successful_probe(1),
                "unexpected": {"forged": True},
            }

        def ambiguous_settlement_target(_manifest, journal):
            prefix = journal["prefixes"][0]
            journal["status"] = "ambiguous-forward-call"
            journal["mutation"] = {
                "attempted_prefixes": [prefix],
                "completed_prefixes": [],
                "ambiguous_calls": [
                    {
                        "prefix": prefix,
                        "category": "TimeoutError",
                        "message": "ambiguous",
                        "settled_target": "eni-f123456789abcdef0",
                    }
                ],
            }
            journal["after"] = None

        def failure_transition(_manifest, journal):
            journal["failure_transition"] = {"forged": True}

        mutations = {
            "output-hash": output_hash,
            "route-table": route_table,
            "prefixes": prefixes,
            "router-eni": router_eni,
            "topology-site": topology_site,
            "generations": generations,
            "predecessor-generation": predecessor_generation,
            "vpc": vpc,
            "uuid-version-one": uuid_version_one,
            "simultaneous-marker": simultaneous_marker,
            "node-hash": node_hash,
            "ownership-progress": ownership_progress,
            "mutation-progress": mutation_progress,
            "restoration-progress": restoration_progress,
            "restoration-extra-field": restoration_extra_field,
            "restoration-missing-field": restoration_missing_field,
            "restoration-status-contradiction": restoration_status_contradiction,
            "ownership-observation-extra-field": ownership_observation_extra_field,
            "status-progress-contradiction": status_progress_contradiction,
            "probe-extra-field": probe_extra_field,
            "ambiguous-settlement-target": ambiguous_settlement_target,
            "failure-transition": failure_transition,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                manifest = ready_lifecycle_manifest(raw)
                journal = self.pending_journal(RouteTableAWS(self.topology))
                journal["owner"]["host_sha256"] = "f" * 64
                manifest["phase"] = "e2e_running"
                manifest["e2e"] = {
                    "claim_id": journal["claim_id"],
                    "output_sha256": deployment.output_sha256,
                    "started_at": "2026-08-20T12:00:00Z",
                    "transport_node_id_sha256": transport_node_hashes(
                        self.topology
                    ),
                    "route_transaction": journal,
                }
                mutate(manifest, journal)
                store = DurableManifestStore(manifest)

                class NoRemoteCalls:
                    calls: list[Any] = []

                    def json(self, *args, **kwargs):
                        self.calls.append((args, kwargs))
                        raise AssertionError("malformed transaction reached AWS")

                aws = NoRemoteCalls()
                adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
                adapter.store = store
                adapter.config = SimpleNamespace(
                    run_id=self.topology.run_id,
                    sites=lifecycle_sites(),
                )
                adapter.aws = aws
                adapter.manifest = None
                adapter._ownership_state = "unclaimed"
                adapter._claim_etag = None
                adapter._claim_original_manifest = None
                adapter._claim_original_etag = None
                adapter._last_persistence_resolution = "none"

                with self.assertRaises(e2e.E2EError):
                    adapter.claim(raw, deployment, require_route_recovery=True)

                self.assertEqual(store.writes, [])
                self.assertEqual(aws.calls, [])

    def test_transport_node_hashes_are_bound_in_a_separate_pretransaction_cas(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        store = DurableManifestStore(ready_lifecycle_manifest(raw))
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(
            run_id=self.topology.run_id,
            sites=lifecycle_sites(),
        )
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"
        adapter._route_only_recovery = False

        claim = adapter.claim(raw, deployment)
        node_ids = {
            member.instance_id: f"node-{site}-{member.az_key}"
            for site in e2e.SITES
            for member in self.topology.site(site).transport_router_fleet
        }
        binding = adapter.bind_transport_node_identities(node_ids)
        journal = self.pending_journal(
            RouteTableAWS(self.topology), claim_id=claim["claim_id"]
        )
        adapter.create_route_transaction(journal)

        self.assertTrue(binding["bound"])
        self.assertEqual(len(store.writes), 3)
        self.assertNotIn("route_transaction", store.writes[1][0]["e2e"])
        self.assertEqual(
            store.writes[1][0]["e2e"]["transport_node_id_sha256"],
            transport_node_hashes(self.topology),
        )
        self.assertEqual(
            store.writes[2][0]["e2e"]["route_transaction"]["transaction_id"],
            journal["transaction_id"],
        )

    def test_transaction_creation_rejects_an_invalid_envelope_before_cas(self) -> None:
        mutations = {
            "schema": lambda journal: journal.update(schema=999),
            "kind": lambda journal: journal.update(kind="forged-route-transaction"),
            "transaction": lambda journal: journal.update(transaction_id="not-a-uuid"),
            "lease": lambda journal: journal.update(lease_expires_at="not-a-timestamp"),
            "boot": lambda journal: journal["owner"].update(boot_id=""),
            "extra": lambda journal: journal.update(unexpected={"forged": True}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                _raw, _deployment, store, adapter, claim = (
                    self.active_route_adapter()
                )
                journal = self.pending_journal(
                    RouteTableAWS(self.topology), claim_id=claim["claim_id"]
                )
                mutate(journal)
                writes_before = len(store.writes)

                with self.assertRaises(e2e.AmbiguousOwnershipError):
                    adapter.create_route_transaction(journal)

                self.assertEqual(len(store.writes), writes_before)
                self.assertNotIn("route_transaction", store.value["e2e"])

    def test_transaction_update_preserves_authority_and_forward_progress(self) -> None:
        _raw, _deployment, store, adapter, claim = self.active_route_adapter()
        journal = self.pending_journal(
            RouteTableAWS(self.topology), claim_id=claim["claim_id"]
        )
        revision = adapter.create_route_transaction(journal)
        writes_before = len(store.writes)

        regressed = copy.deepcopy(journal)
        regressed["status"] = "authorized"
        regressed["advertisements"]["alternate_expansion"] = None
        regressed["advertisements"]["current_withdrawal"] = None
        regressed["ownership"]["transferred"] = None
        regressed["mutation"] = {
            "attempted_prefixes": [],
            "completed_prefixes": [],
            "ambiguous_calls": [],
        }
        regressed["after"] = None
        e2e.GWLBERouteFailover.validate_durable_binding(
            regressed,
            self.topology,
            self.vpc_ids,
            node_hashes_by_instance=transport_node_hashes(self.topology),
        )
        with self.assertRaisesRegex(e2e.ClaimPersistenceError, "regressed"):
            adapter.update_route_transaction(regressed, expected_revision=revision)

        new_owner = copy.deepcopy(journal)
        new_owner["owner"]["host_sha256"] = "f" * 64
        e2e.GWLBERouteFailover.validate_durable_binding(
            new_owner,
            self.topology,
            self.vpc_ids,
            node_hashes_by_instance=transport_node_hashes(self.topology),
        )
        with self.assertRaisesRegex(
            e2e.ClaimPersistenceError, "immutable durable authority"
        ):
            adapter.update_route_transaction(new_owner, expected_revision=revision)

        switched_site = copy.deepcopy(journal)
        switched_site["site"] = "east"
        with self.assertRaisesRegex(
            e2e.ClaimPersistenceError, "immutable durable authority"
        ):
            adapter._validate_route_transaction_successor(journal, switched_site)

        self.assertEqual(len(store.writes), writes_before)
        self.assertEqual(store.value["e2e"]["route_transaction"], journal)

    def test_transaction_retry_fences_restoration_before_resetting_progress(self) -> None:
        existing = self.pending_journal(RouteTableAWS(self.topology))
        route = symmetric_route_evidence()["transport_router"]["abrupt"][
            "route_replacement"
        ]
        existing["status"] = "restoring"
        existing["restoration"] = copy.deepcopy(route["restoration"])
        existing["restoration"]["status"] = "running"
        existing["restoration"]["routes"]["status"] = "running"
        existing["restoration"]["routes"]["snapshot"] = None
        command = {
            "site": "west",
            "role": "transport-router",
            "command_id": "fixture-restoration-command",
            "status": "Success",
            "response_code": 0,
        }
        existing["restoration"]["advertisements"]["current"][
            "command"
        ] = copy.deepcopy(command)
        existing["restoration"]["advertisements"]["verification"]["current"][
            "command"
        ] = copy.deepcopy(command)
        reset = copy.deepcopy(existing)
        reset["restoration"] = {
            "status": "running",
            "advertisements": {
                "status": "running",
                "current": None,
                "alternate": None,
                "verification": None,
                "failures": [],
            },
            "ownership": {"status": "not-started", "observation": None},
            "routes": {
                "status": "not-started",
                "attempted_prefixes": [],
                "api_failures": [],
                "settled_prefixes": [],
                "quiet_window_seconds": self.topology.route_failover.quiet_window_seconds,
                "snapshot": None,
            },
        }
        for journal in (existing, reset):
            e2e.GWLBERouteFailover.validate_durable_binding(
                journal,
                self.topology,
                self.vpc_ids,
                node_hashes_by_instance=transport_node_hashes(self.topology),
            )

        e2e.ProtectedLifecycleAdapter._validate_route_transaction_successor(
            existing, copy.deepcopy(existing)
        )

        with self.assertRaisesRegex(
            e2e.ClaimPersistenceError, "restoration progress"
        ):
            e2e.ProtectedLifecycleAdapter._validate_route_transaction_successor(
                existing, reset
            )

        claimed = copy.deepcopy(existing)
        claimed["status"] = "recovery-claimed"
        e2e.ProtectedLifecycleAdapter._validate_route_transaction_successor(
            existing, claimed
        )
        e2e.ProtectedLifecycleAdapter._validate_route_transaction_successor(
            claimed, reset
        )

    def test_transaction_finalization_requires_the_exact_terminal_summary(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        route = symmetric_route_evidence()["transport_router"]["abrupt"][
            "route_replacement"
        ]
        journal["probe"] = copy.deepcopy(self.successful_probe(1))
        journal["restoration"] = copy.deepcopy(route["restoration"])
        journal["failure"] = {
            "category": "RuntimeError",
            "message": "fixture forward failure",
        }
        journal["status"] = "restored-after-failure"
        journal["finished_at"] = "2026-08-20T12:03:00Z"
        e2e.GWLBERouteFailover.validate_durable_binding(
            journal,
            self.topology,
            self.vpc_ids,
            node_hashes_by_instance=transport_node_hashes(self.topology),
        )
        manifest = ready_lifecycle_manifest(raw)
        manifest["phase"] = "e2e_running"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_transaction": journal,
        }
        store = DurableManifestStore(manifest)
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(
            run_id=self.topology.run_id,
            sites=lifecycle_sites(),
        )
        adapter.manifest = copy.deepcopy(manifest)
        adapter._ownership_state = "running-owned"
        adapter._claim_etag = store.remote_etag
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"
        adapter._route_only_recovery = False
        exact_summary = {
            "transaction_id": journal["transaction_id"],
            "status": journal["status"],
            "finished_at": journal["finished_at"],
            "restored": True,
        }

        with self.assertRaisesRegex(
            e2e.ClaimPersistenceError, "cannot finalize"
        ):
            adapter.finalize_route_transaction(
                journal["transaction_id"],
                {**exact_summary, "status": "restored"},
                expected_revision=store.remote_etag,
            )

        self.assertEqual(store.writes, [])
        adapter.finalize_route_transaction(
            journal["transaction_id"],
            exact_summary,
            expected_revision=store.remote_etag,
        )
        marker = store.value["e2e"]["route_recovery"]
        self.assertEqual(marker["restoration_status"], "restored-after-failure")
        self.assertEqual(marker["restored_at"], journal["finished_at"])

    def test_route_only_recovery_resumes_cleanup_after_transaction_finalization(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        for phase in ("e2e_running", "e2e_failed", "cleanup_incomplete"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                run_dir = pathlib.Path(temporary)
                manifest = ready_lifecycle_manifest(raw)
                manifest["phase"] = phase
                manifest["e2e"] = {
                    "claim_id": journal["claim_id"],
                    "output_sha256": deployment.output_sha256,
                    "started_at": "2026-08-20T12:00:00Z",
                    "transport_node_id_sha256": transport_node_hashes(
                        self.topology
                    ),
                    "route_recovery": self.cleanup_marker(journal),
                }
                if phase != "e2e_running":
                    manifest["e2e"].update(
                        {
                            "finished_at": "2026-08-20T12:03:00Z",
                            "passed": False,
                        }
                    )
                if phase == "cleanup_incomplete":
                    manifest["cleanup_claim_id"] = (
                        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                    )
                    manifest["cleanup_claimed_at"] = "2026-08-20T12:04:00Z"
                store = DurableManifestStore(manifest)
                adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
                adapter.store = store
                adapter.config = SimpleNamespace(
                    run_id=self.topology.run_id,
                    config_identity="c" * 64,
                    sites=lifecycle_sites(),
                )
                adapter.aws = SimpleNamespace()
                adapter.runner = SimpleNamespace()
                adapter.run_dir = run_dir
                adapter.terraform_dir = ROOT / "example" / "terraform"
                adapter.manifest = None
                adapter._ownership_state = "unclaimed"
                adapter._claim_etag = None
                adapter._claim_original_manifest = None
                adapter._claim_original_etag = None
                adapter._last_persistence_resolution = "none"
                adapter._route_only_recovery = False

                def protected(*_args, **kwargs):
                    result = {"final_residual_count": 0}
                    self.assertEqual(
                        kwargs.get("timeout_seconds"),
                        e2e.PROTECTED_RESOURCE_CLEANUP_SECONDS,
                    )
                    checkpoint = kwargs.get("before_manifest_delete")
                    self.assertTrue(callable(checkpoint))
                    store.value["phase"] = "cleanup_started"
                    store.value["cleanup_claim_id"] = e2e.local_cleanup_claim_id(
                        run_dir
                    )
                    store.value["cleanup_claimed_at"] = (
                        dt.datetime.now(dt.timezone.utc)
                        .replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                    checkpoint(result)
                    return result

                claim = adapter.claim(
                    raw, deployment, require_route_recovery=True
                )
                with mock.patch.object(
                    e2e, "build_tailscale", return_value=SimpleNamespace()
                ), mock.patch.object(
                    e2e, "protected_cleanup", side_effect=protected
                ):
                    result = adapter.cleanup()

                receipt_path = run_dir / "route-recovery-cleanup-result.json"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertTrue(claim["route_recovery_required"])
                self.assertEqual(claim["manifest_phase"], phase)
                self.assertEqual(
                    claim["route_transaction_id"], journal["transaction_id"]
                )
                self.assertTrue(result["route_recovery_before_cleanup"]["restored"])
                self.assertEqual(
                    receipt["cleanup"], "backend-finalization-pending"
                )
                self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)

    def test_route_marker_cannot_take_over_a_fresh_foreign_cleanup_claim(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        manifest = ready_lifecycle_manifest(raw)
        manifest["phase"] = "cleanup_incomplete"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "finished_at": "2026-08-20T12:03:00Z",
            "passed": False,
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_recovery": self.cleanup_marker(journal),
        }
        manifest["cleanup_claim_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        manifest["cleanup_claimed_at"] = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        store = DurableManifestStore(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = pathlib.Path(temporary)
            adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
            adapter.store = store
            adapter.config = SimpleNamespace(
                run_id=self.topology.run_id,
                config_identity="c" * 64,
                sites=lifecycle_sites(),
            )
            adapter.aws = SimpleNamespace()
            adapter.runner = SimpleNamespace()
            adapter.run_dir = run_dir
            adapter.terraform_dir = ROOT / "example" / "terraform"
            adapter.manifest = None
            adapter._ownership_state = "unclaimed"
            adapter._claim_etag = None
            adapter._claim_original_manifest = None
            adapter._claim_original_etag = None
            adapter._last_persistence_resolution = "none"
            adapter._route_only_recovery = False

            with self.assertRaises(e2e.ConcurrentRunError):
                adapter.claim(raw, deployment, require_route_recovery=True)

        self.assertEqual(store.writes, [])
        self.assertEqual(store.value, manifest)

    def test_route_receipt_requires_the_same_durable_cleanup_owner(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        manifest = ready_lifecycle_manifest(raw)
        manifest["phase"] = "e2e_failed"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "finished_at": "2026-08-20T12:03:00Z",
            "passed": False,
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_recovery": self.cleanup_marker(journal),
        }
        store = DurableManifestStore(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = pathlib.Path(temporary)
            adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
            adapter.store = store
            adapter.config = SimpleNamespace(
                run_id=self.topology.run_id,
                config_identity="c" * 64,
                sites=lifecycle_sites(),
            )
            adapter.aws = SimpleNamespace()
            adapter.runner = SimpleNamespace()
            adapter.run_dir = run_dir
            adapter.terraform_dir = ROOT / "example" / "terraform"
            adapter.manifest = None
            adapter._ownership_state = "unclaimed"
            adapter._claim_etag = None
            adapter._claim_original_manifest = None
            adapter._claim_original_etag = None
            adapter._last_persistence_resolution = "none"
            adapter._route_only_recovery = False
            adapter.claim(raw, deployment, require_route_recovery=True)

            def protected(*_args, **kwargs):
                store.value["phase"] = "cleanup_started"
                store.value["cleanup_claim_id"] = e2e.local_cleanup_claim_id(
                    run_dir
                )
                store.value["cleanup_claimed_at"] = (
                    dt.datetime.now(dt.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                store.value["e2e"]["route_recovery"]["owner"][
                    "host_sha256"
                ] = "d" * 64
                kwargs["before_manifest_delete"](
                    {"final_residual_count": 0}
                )
                return {"final_residual_count": 0}

            with mock.patch.object(
                e2e, "build_tailscale", return_value=SimpleNamespace()
            ), mock.patch.object(
                e2e, "protected_cleanup", side_effect=protected
            ):
                with self.assertRaisesRegex(
                    e2e.AmbiguousOwnershipError, "lost durable ownership"
                ):
                    adapter.cleanup()

            self.assertFalse(
                (run_dir / "route-recovery-cleanup-result.json").exists()
            )

    def test_restart_rejects_unexpired_cross_host_lease_without_cas_write(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        manifest = ready_lifecycle_manifest(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        journal["owner"]["host_sha256"] = "f" * 64
        journal["lease_expires_at"] = "2099-08-20T12:01:00Z"
        manifest["phase"] = "e2e_running"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_transaction": journal,
        }
        store = DurableManifestStore(manifest)
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(run_id=self.topology.run_id, sites=lifecycle_sites())
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"

        with self.assertRaises(e2e.ConcurrentRunError):
            adapter.claim(raw, deployment)

        self.assertEqual(store.writes, [])
        self.assertEqual(store.value, manifest)

    def test_expired_lease_adoption_loses_safely_to_a_cas_rival(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        manifest = ready_lifecycle_manifest(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        journal["owner"]["host_sha256"] = "e" * 64
        manifest["phase"] = "e2e_running"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_transaction": journal,
        }
        store = DurableManifestStore(manifest)

        def rival(target, value, if_match):
            competing = copy.deepcopy(value)
            competing["e2e"]["route_transaction"]["owner"]["host_sha256"] = "d" * 64
            target.commit(competing, if_match)
            raise e2e.LifecycleError("injected CAS response race")

        store.write_hook = rival
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(run_id=self.topology.run_id, sites=lifecycle_sites())
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"

        with self.assertRaises(e2e.ConcurrentRunError):
            adapter.claim(raw, deployment)

        self.assertEqual(adapter._ownership_state, "competing")

    def test_expired_lease_adoption_distinguishes_an_uncommitted_cas(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        manifest = ready_lifecycle_manifest(raw)
        journal = self.pending_journal(RouteTableAWS(self.topology))
        journal["owner"]["host_sha256"] = "e" * 64
        manifest["phase"] = "e2e_running"
        manifest["e2e"] = {
            "claim_id": journal["claim_id"],
            "output_sha256": deployment.output_sha256,
            "started_at": "2026-08-20T12:00:00Z",
            "transport_node_id_sha256": transport_node_hashes(self.topology),
            "route_transaction": journal,
        }
        store = DurableManifestStore(manifest)

        def not_committed(_target, _value, _if_match):
            raise e2e.LifecycleError("injected uncommitted route claim")

        store.write_hook = not_committed
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(
            run_id=self.topology.run_id, sites=lifecycle_sites()
        )
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"

        with self.assertRaisesRegex(
            e2e.ClaimPersistenceError, "route-recovery claim was not committed"
        ):
            adapter.claim(raw, deployment, require_route_recovery=True)

        self.assertEqual(store.value, manifest)
        self.assertEqual(store.writes, [])
        self.assertEqual(adapter._ownership_state, "unclaimed")
        self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")

    def test_recovery_claim_acquisition_rethrows_protected_control_flow(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        for control in (
            e2e.ProtectedHardTimeout("recovery claim hard deadline"),
            e2e.ProtectedTermination("recovery claim termination"),
        ):
            with self.subTest(category=type(control).__name__):
                manifest = ready_lifecycle_manifest(raw)
                journal = self.pending_journal(RouteTableAWS(self.topology))
                journal["owner"]["host_sha256"] = "e" * 64
                manifest["phase"] = "e2e_running"
                manifest["e2e"] = {
                    "claim_id": journal["claim_id"],
                    "output_sha256": deployment.output_sha256,
                    "started_at": "2026-08-20T12:00:00Z",
                    "transport_node_id_sha256": transport_node_hashes(
                        self.topology
                    ),
                    "route_transaction": journal,
                }
                store = DurableManifestStore(manifest)

                def interrupt(_target, _value, _if_match, error=control):
                    raise error

                store.write_hook = interrupt
                adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
                adapter.store = store
                adapter.config = SimpleNamespace(
                    run_id=self.topology.run_id, sites=lifecycle_sites()
                )
                adapter.manifest = None
                adapter._ownership_state = "unclaimed"
                adapter._claim_etag = None
                adapter._claim_original_manifest = None
                adapter._claim_original_etag = None
                adapter._last_persistence_resolution = "none"

                with self.assertRaises(type(control)) as raised:
                    adapter.claim(raw, deployment)

                self.assertIs(raised.exception, control)
                self.assertEqual(store.recover_count, 1)
                self.assertEqual(store.value, manifest)

    def test_restart_rejects_ambiguous_journal_owner_without_mutation(self) -> None:
        aws = RouteTableAWS(self.topology)
        foreign_owner = e2e._route_runner_identity()
        foreign_owner["host_sha256"] = "f" * 64
        with tempfile.TemporaryDirectory() as temporary:
            durability = DurableRouteTransactions(
                self.pending_journal(aws, owner=foreign_owner)
            )
            transaction, _clock, _ready, _path = self.failover(
                temporary, aws, durability=durability
            )
            with self.assertRaises(e2e.AmbiguousOwnershipError):
                transaction.reconcile(restoration_timeout_seconds=10)
        self.assertEqual(aws.mutation_calls, [])

    def test_direct_reconcile_rejects_malformed_progress_before_any_write(self) -> None:
        def reversed_attempts(journal):
            journal["mutation"]["attempted_prefixes"].reverse()

        def restoration_extra_field(journal):
            journal["restoration"]["advertisements"]["unexpected"] = {
                "forged": True
            }

        def ownership_extra_field(journal):
            journal["ownership"]["before"]["unexpected"] = {"forged": True}

        def status_progress_contradiction(journal):
            journal["status"] = "authorized"

        def probe_extra_field(journal):
            journal["status"] = "probe-passed"
            journal["probe"] = {
                **self.successful_probe(1),
                "unexpected": {"forged": True},
            }

        def invalid_settlement_target(journal):
            prefix = journal["prefixes"][0]
            journal["status"] = "ambiguous-forward-call"
            journal["mutation"] = {
                "attempted_prefixes": [prefix],
                "completed_prefixes": [],
                "ambiguous_calls": [
                    {
                        "prefix": prefix,
                        "category": "TimeoutError",
                        "message": "ambiguous",
                        "settled_target": "eni-f123456789abcdef0",
                    }
                ],
            }
            journal["after"] = None

        mutations = {
            "reversed-attempts": reversed_attempts,
            "restoration-extra-field": restoration_extra_field,
            "ownership-extra-field": ownership_extra_field,
            "status-progress-contradiction": status_progress_contradiction,
            "probe-extra-field": probe_extra_field,
            "invalid-settlement-target": invalid_settlement_target,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                journal = self.pending_journal(
                    aws, owner=e2e._route_runner_identity()
                )
                mutate(journal)
                durability = DurableRouteTransactions(journal)
                transaction, _clock, _ready, evidence_path = self.failover(
                    temporary, aws, durability=durability
                )

                with self.assertRaisesRegex(
                    e2e.AmbiguousOwnershipError, "progress"
                ):
                    transaction.reconcile(restoration_timeout_seconds=10)

                self.assertFalse(evidence_path.exists())
                self.assertEqual(durability.writes, [])
                self.assertEqual(aws.mutation_calls, [])

    def test_durable_validator_accepts_exact_production_probe_shape(self) -> None:
        evidence = symmetric_route_evidence()
        west_traversal = next(
            item
            for item in evidence["traversals"]
            if item["source_site"] == "west"
        )
        paths = {
            item["protocol"]: copy.deepcopy(item)
            for item in west_traversal["probes"]
            if item["source_role"] == "responder"
            and item["protocol"] in e2e.TRANSPORT_PROTOCOLS
        }
        probe = {
            **paths["udp"],
            "succeeded": True,
            "new_flows": {
                protocol: {"succeeded": True, "path": path}
                for protocol, path in paths.items()
            },
        }
        journal = self.pending_journal(
            RouteTableAWS(self.topology), owner=e2e._route_runner_identity()
        )
        journal["status"] = "probe-passed"
        journal["probe"] = probe

        e2e.GWLBERouteFailover.validate_durable_binding(
            journal,
            self.topology,
            self.vpc_ids,
            node_ids_by_instance={
                member.instance_id: f"node-{member.site}-{member.az_key}"
                for site in e2e.SITES
                for member in self.topology.site(site).transport_router_fleet
            },
        )

    def test_durable_validator_rejects_compact_test_only_probe_shape(self) -> None:
        journal = self.pending_journal(RouteTableAWS(self.topology))
        journal["status"] = "probe-passed"
        journal["probe"] = {
            "source_transport_router_id": self.alternate.instance_id,
            "source_transport_eni_id": self.alternate.network_interface_id,
            "succeeded": True,
        }

        with self.assertRaisesRegex(
            e2e.AmbiguousOwnershipError, "progress"
        ):
            e2e.GWLBERouteFailover.validate_durable_binding(
                journal,
                self.topology,
                self.vpc_ids,
                node_hashes_by_instance=transport_node_hashes(self.topology),
            )

    def test_durable_validator_accepts_shared_restoration_predecessor(self) -> None:
        journal = self.pending_journal(RouteTableAWS(self.topology))
        shared_generation = journal["current"]["state_before"]["advertisements"][
            "generation"
        ]
        journal["alternate"]["state_before"]["advertisements"][
            "generation"
        ] = shared_generation

        e2e.GWLBERouteFailover.validate_durable_binding(
            journal,
            self.topology,
            self.vpc_ids,
            node_hashes_by_instance=transport_node_hashes(self.topology),
        )

    def test_local_journal_without_manifest_transaction_is_not_authority(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, path = self.failover(temporary, aws)
            path.write_text(
                json.dumps(self.pending_journal(aws)) + "\n", encoding="utf-8"
            )

            result = transaction.reconcile(restoration_timeout_seconds=10)

        self.assertEqual(result, {"required": False, "restored": True})
        self.assertEqual(aws.mutation_calls, [])

    def test_route_timeout_bounds_reject_invalid_values_before_mutation(self) -> None:
        for timeout, restoration in ((0, 1), (7201, 1), (1, 0), (1, 7201)):
            with self.subTest(timeout=timeout, restoration=restoration), tempfile.TemporaryDirectory() as temporary:
                aws = RouteTableAWS(self.topology)
                transaction, _clock, _ready, _path = self.failover(temporary, aws)
                with self.assertRaisesRegex(e2e.ResilienceError, "between 0 and 7200"):
                    transaction.replace(
                        self.current,
                        self.alternate,
                        probe=self.successful_probe,
                        timeout_seconds=timeout,
                        restoration_timeout_seconds=restoration,
                    )
                self.assertEqual(aws.mutation_calls, [])

    def test_unknown_probe_fields_fail_without_blocking_restoration(self) -> None:
        aws = RouteTableAWS(self.topology)
        with tempfile.TemporaryDirectory() as temporary:
            transaction, _clock, _ready, path = self.failover(temporary, aws)

            def probe(_remaining):
                return {
                    **self.successful_probe(1),
                    "token": "tskey-fixture-sensitive-value",
                }

            with self.assertRaisesRegex(e2e.EvidenceError, "durable shape"):
                transaction.replace(
                    self.current,
                    self.alternate,
                    probe=probe,
                    timeout_seconds=10,
                    restoration_timeout_seconds=10,
                )
            journal = json.loads(path.read_text(encoding="utf-8"))

        self.assert_original_routes(aws)
        self.assertIsNone(journal["probe"])
        self.assertEqual(journal["status"], "restored-after-failure")
        self.assertEqual(journal["failure"]["category"], "EvidenceError")
        self.assertEqual(e2e.scan_evidence(journal), [])


class RouteMutationAuthorityTest(unittest.TestCase):
    def test_transport_router_graceful_and_abrupt_failures_have_no_aws_route_command(self) -> None:
        topology = route_failover_topology()
        commands: list[str] = []

        class Adapter:
            @staticmethod
            def owned(member, run_id):
                return True

            @staticmethod
            def command(member, command):
                commands.append(command)
                return {}

        lifecycle = e2e.SymmetricLifecycle(topology, Adapter(), dry_run=False)
        member = topology.west.transport_router_fleet[0]
        lifecycle.fail_transport_router(member, graceful=True)
        lifecycle.fail_transport_router(member, graceful=False)

        self.assertIn("--advertise-routes=", commands[0])
        self.assertIn("systemctl stop tailscaled.service", commands[0])
        self.assertIn("--signal=SIGKILL", commands[1])
        self.assertIn("systemctl stop tailscaled.service", commands[1])
        self.assertFalse(any("aws " in command or "replace-route" in command for command in commands))

    def test_transport_control_uses_supported_ssm_arguments_and_host_fencing(self) -> None:
        topology = route_failover_topology()
        member = topology.west.transport_router_fleet[0]

        class Base:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def _execute(self, target, command, **kwargs):
                self.calls.append({"target": target, "command": command, **kwargs})
                return SimpleNamespace(
                    stdout='{"success":true,"payload":{}}\n',
                    summary=lambda: {"status": "Success"},
                )

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.base = Base()
        inspect = "/usr/local/sbin/envelope-transport-advertisements inspect"
        observe = "python3 -c 'observe ownership'"
        mutate = (
            "/usr/local/sbin/envelope-transport-advertisements apply "
            "11111111-2222-4333-8444-555555555555 '[\"initial\"]' '[\"10.0.0.0/24\"]' running normal"
        )
        for command in (inspect, inspect, observe, observe, mutate, mutate):
            operations._execute_transport_control(
                member,
                command,
                timeout_seconds=30,
                comment="fixture transport control",
            )

        self.assertTrue(all("client_token" not in call for call in operations.base.calls))
        self.assertEqual(
            [call["command"] for call in operations.base.calls[-2:]],
            [mutate, mutate],
        )

    def test_ownership_observers_require_running_online_nonexpired_stable_peers(self) -> None:
        topology = route_failover_topology()
        node_ids = {
            member.instance_id: f"node-{member.site}-{member.az_key}"
            for site in e2e.SITES
            for member in topology.site(site).transport_router_fleet
        }
        expected_owners = {
            member.advertised_prefix: member.instance_id
            for member in topology.west.transport_router_fleet
        }
        expected_nodes = {
            prefix: node_ids[instance_id]
            for prefix, instance_id in expected_owners.items()
        }
        commands: list[str] = []

        def execute(_member, command, **_kwargs):
            commands.append(command)
            return {
                "success": True,
                "payload": {"owners": dict(expected_nodes)},
            }

        control = e2e.TailnetAdvertisementControl(
            topology,
            execute,
            node_ids,
            monotonic=FakeClock(),
        )
        observations = control._observe_ownership_once(
            "west", expected_owners, timeout_seconds=30
        )

        self.assertEqual(len(observations), 2)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn('status.get("BackendState")!="Running"', command)
            self.assertIn('self_status.get("Online") is not True', command)
            self.assertIn('self_status.get("Expired",False) is not False', command)
            self.assertIn('by_id[expected_id].get("Online") is not True', command)
            self.assertIn(
                'by_id[expected_id].get("Expired",False) is not False', command
            )

        shell_parts = shlex.split(commands[0])
        self.assertEqual(shell_parts[:2], ["python3", "-c"])
        self.assertEqual(len(shell_parts), 4)
        self.assertEqual(json.loads(shell_parts[3]), expected_nodes)
        subprocess.run(
            ["bash", "-n", "-c", commands[0]],
            check=True,
            capture_output=True,
            text=True,
        )
        observer_script = compile(shell_parts[2], "<tailnet-ownership-observer>", "exec")
        status = {
            "BackendState": "Running",
            "Self": {"Online": True},
            "Peer": {
                node_id: {
                    "ID": node_id,
                    "Online": True,
                    "PrimaryRoutes": [prefix],
                }
                for prefix, node_id in expected_nodes.items()
            },
        }

        def run_observer(candidate: Mapping[str, Any]) -> dict[str, Any]:
            output = io.StringIO()
            with (
                mock.patch.object(
                    subprocess, "check_output", return_value=json.dumps(candidate)
                ) as check_output,
                mock.patch.object(sys, "argv", ["-c", shell_parts[3]]),
                contextlib.redirect_stdout(output),
            ):
                try:
                    exec(observer_script, {})
                finally:
                    check_output.assert_called_once_with(
                        ["/usr/bin/tailscale", "status", "--json"],
                        text=True,
                        timeout=20,
                    )
            return json.loads(output.getvalue())

        expected_result = {"success": True, "payload": {"owners": expected_nodes}}
        self.assertEqual(run_observer(status), expected_result)
        explicit_false = copy.deepcopy(status)
        explicit_false["Self"]["Expired"] = False
        for peer in explicit_false["Peer"].values():
            peer["Expired"] = False
        self.assertEqual(run_observer(explicit_false), expected_result)

        for invalid in (True, None, 0, "false", [], {}):
            with self.subTest(scope="self", expired=invalid):
                invalid_self = copy.deepcopy(status)
                invalid_self["Self"]["Expired"] = invalid
                with self.assertRaises(SystemExit) as raised:
                    run_observer(invalid_self)
                self.assertEqual(raised.exception.code, 2)

            with self.subTest(scope="peer", expired=invalid):
                invalid_peer = copy.deepcopy(status)
                next(iter(invalid_peer["Peer"].values()))["Expired"] = invalid
                with self.assertRaises(SystemExit) as raised:
                    run_observer(invalid_peer)
                self.assertEqual(raised.exception.code, 4)

    def test_target_and_router_roles_must_deny_runner_route_actions(self) -> None:
        topology = route_failover_topology()

        class IAM:
            def __init__(self, *, allowed: bool = False) -> None:
                self.allowed = allowed
                self.calls: list[list[str]] = []

            def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
                self.calls.append(list(args))
                if args[:2] == ["iam", "get-instance-profile"]:
                    name = args[-1]
                    return {
                        "InstanceProfile": {
                            "Arn": f"arn:aws:iam::123456789012:instance-profile/{name}",
                            "InstanceProfileName": name,
                            "Roles": [
                                {
                                    "Arn": f"arn:aws:iam::123456789012:role/{name}",
                                    "RoleName": name,
                                }
                            ],
                        }
                    }
                if args[:2] == ["iam", "simulate-principal-policy"]:
                    start = args.index("--action-names") + 1
                    finish = args.index("--resource-arns")
                    decision = "allowed" if self.allowed else "implicitDeny"
                    return {
                        "EvaluationResults": [
                            {"EvalActionName": action, "EvalDecision": decision}
                            for action in args[start:finish]
                        ]
                    }
                raise AssertionError(args)

        deployment = SimpleNamespace(topology=topology)
        denied = IAM()
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(run_id=topology.run_id)
        operations.aws = denied
        operations._route_mutation_denied_profiles = set()
        for member, role_name in (
            (topology.west.target_fleet[0], "runtime"),
            (topology.west.transport_router_fleet[0], "transport"),
        ):
            profile_name = f"{topology.run_id}-west-{role_name}"
            operations._verify_no_route_mutation_authority(
                deployment,
                member,
                {
                    "IamInstanceProfile": {
                        "Arn": f"arn:aws:iam::123456789012:instance-profile/{profile_name}"
                    }
                },
            )
        simulations = [args for args in denied.calls if args[:2] == ["iam", "simulate-principal-policy"]]
        self.assertEqual(len(simulations), 2)
        self.assertTrue(all(action in simulations[0] for action in e2e.ROUTE_MUTATION_ACTIONS))

        allowed = IAM(allowed=True)
        operations.aws = allowed
        operations._route_mutation_denied_profiles = set()
        member = topology.west.target_fleet[0]
        profile_name = f"{topology.run_id}-west-runtime"
        with self.assertRaisesRegex(e2e.ReadinessError, "unexpectedly permits"):
            operations._verify_no_route_mutation_authority(
                deployment,
                member,
                {
                    "IamInstanceProfile": {
                        "Arn": f"arn:aws:iam::123456789012:instance-profile/{profile_name}"
                    }
                },
            )

    def test_concrete_transport_recovery_orchestrates_tailnet_and_gwlbe_controls(self) -> None:
        deployment = e2e.parse_symmetric_protected_deployment_output(route_failover_output())
        topology = deployment.topology
        current, alternate = topology.west.transport_router_fleet
        graceful_alternate, graceful_failed = topology.east.transport_router_fleet
        aws = RouteTableAWS(topology)
        clock = FakeClock()
        commands: list[tuple[str, str]] = []

        class Adapter:
            @staticmethod
            def owned(_member, _run_id):
                return True

            @staticmethod
            def command(member, command):
                commands.append((member.instance_id, command))
                return {}

        class Lifecycle(DurableRouteTransactions):
            @staticmethod
            def authorize_gwlbe_route_replacement(
                route_current, route_alternate, prefixes, route_table_owner
            ):
                return GWLBERouteFailoverTest.authority(
                    route_current, route_alternate, prefixes, route_table_owner
                )

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(run_id=topology.run_id)
        operations.aws = aws
        operations.run_dir = pathlib.Path("/tmp/not-used")
        operations.lifecycle = Lifecycle()
        operations.base = SimpleNamespace(monotonic=clock, sleep=clock.sleep)
        operations.adapter = Adapter()
        operations._verify_transport_router = mock.Mock()
        operations._restore_transport_router = mock.Mock()
        operations._advertisement_control = mock.Mock(
            return_value=FakeAdvertisementControl(topology, clock)
        )
        operations._measure_tcp_udp_failure = lambda _tcp, _udp, **kwargs: (
            kwargs["mutate_and_restore"](),
            failure_transport_evidence(current.instance_id, "router-measurement"),
        )

        ledger = e2e.FlowLedger(topology.run_id)
        graceful_flow = ledger.allocate(
            "udp",
            deployment.workloads.target("west", "initiator"),
            deployment.workloads.target("east", "responder"),
            destination_port=5201,
            purpose="graceful-transport",
            generation=ledger.begin_generation("graceful-transport"),
        )
        abrupt_flow = ledger.allocate(
            "udp",
            deployment.workloads.target("west", "initiator"),
            deployment.workloads.target("east", "responder"),
            destination_port=5201,
            purpose="abrupt-transport",
            generation=ledger.begin_generation("abrupt-transport"),
        )
        graceful_tcp_flow = ledger.allocate(
            "tcp",
            deployment.workloads.target("west", "initiator"),
            deployment.workloads.target("east", "responder"),
            destination_port=5201,
            purpose="graceful-transport-tcp",
            generation=ledger.begin_generation("graceful-transport-tcp"),
        )
        abrupt_tcp_flow = ledger.allocate(
            "tcp",
            deployment.workloads.target("west", "initiator"),
            deployment.workloads.target("east", "responder"),
            destination_port=5201,
            purpose="abrupt-transport-tcp",
            generation=ledger.begin_generation("abrupt-transport-tcp"),
        )

        probe_timeouts: list[int] = []
        expected_router_calls: list[tuple[str | None, str | None]] = []

        def path(
            _deployment,
            flow,
            *,
            timeout_seconds,
            exclude_targets=None,
            expected_source_transport_router_id=None,
            expected_destination_transport_router_id=None,
        ):
            del exclude_targets
            probe_timeouts.append(timeout_seconds)
            expected_router_calls.append(
                (
                    expected_source_transport_router_id,
                    expected_destination_transport_router_id,
                )
            )
            clock.sleep(3)
            if flow.purpose.startswith("graceful-transport"):
                return {
                    "protocol": flow.protocol,
                    "source_transport_router_id": current.instance_id,
                    "source_transport_eni_id": current.network_interface_id,
                    "destination_transport_router_id": graceful_alternate.instance_id,
                }
            return {
                "protocol": flow.protocol,
                "source_transport_router_id": alternate.instance_id,
                "source_transport_eni_id": alternate.network_interface_id,
                "destination_transport_router_id": graceful_alternate.instance_id,
            }

        operations._wait_probe_path = path
        def coordinated_replace(
            _transaction,
            failed,
            selected_alternate,
            *,
            probe,
            failure_mode,
            **_kwargs,
        ):
            observed = probe(10)
            snapshot = {
                "routes": [
                    {
                        "destination_cidr_block": "10.0.0.0/24",
                        "network_interface_id": failed.network_interface_id,
                        "origin": "CreateRoute",
                        "route_state": "active",
                    }
                ]
            }
            return {
                "probe": observed,
                "restored": True,
                "before": snapshot,
                "after": {
                    "routes": [
                        {
                            **snapshot["routes"][0],
                            "network_interface_id": selected_alternate.network_interface_id,
                        }
                    ]
                },
                "restoration": {"status": "verified"},
                "failure_mode": failure_mode,
            }

        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {
                "ENVELOPE_E2E_APPROVED_RUN_ID": topology.run_id,
                "GITHUB_EVENT_NAME": "workflow_dispatch",
            },
            clear=False,
        ), mock.patch.object(
            e2e.GWLBERouteFailover,
            "replace",
            autospec=True,
            side_effect=coordinated_replace,
        ) as replace:
            operations.run_dir = pathlib.Path(temporary)
            result = operations.run_transport_router_recovery(
                deployment,
                graceful_failed,
                current,
                graceful_flow,
                abrupt_flow,
                graceful_tcp_flow,
                abrupt_tcp_flow,
                graceful_tcp_flow,
                graceful_flow,
                abrupt_tcp_flow,
                abrupt_flow,
                timeout_seconds=30,
            )

        self.assertEqual(
            result["graceful"]["control_plane"], "tailnet-and-gwlbe-route"
        )
        self.assertEqual(
            result["abrupt"]["control_plane"], "tailnet-and-gwlbe-route"
        )
        self.assertEqual(result["recovery"]["kind"], "transport-router")
        self.assertTrue(result["abrupt"]["route_replacement"]["restored"])
        self.assertEqual(result["abrupt"]["route_replacement"]["before"]["routes"][0]["route_state"], "active")
        self.assertEqual(result["abrupt"]["route_replacement"]["after"]["routes"][0]["route_state"], "active")
        self.assertEqual(
            result["abrupt"]["route_replacement"]["restoration"]["status"],
            "verified",
        )
        self.assertEqual(operations._restore_transport_router.call_count, 0)
        self.assertEqual(
            [call.kwargs["failure_mode"] for call in replace.call_args_list],
            ["graceful", "abrupt"],
        )
        self.assertEqual(probe_timeouts, [10, 7, 10, 7])
        self.assertEqual(
            expected_router_calls,
            [
                (None, graceful_alternate.instance_id),
                (None, graceful_alternate.instance_id),
                (alternate.instance_id, None),
                (alternate.instance_id, None),
            ],
        )
        self.assertFalse(any("aws " in command for _member, command in commands))


class SymmetricRouteEvidenceTest(unittest.TestCase):
    def test_detailed_route_and_packet_turnaround_evidence_strictly_verifies(self) -> None:
        document = symmetric_route_evidence()
        validated = e2e.validate_symmetric_evidence(document)
        self.assertEqual(validated, document)
        self.assertEqual(validated["schema"], 3)
        self.assertTrue(
            all(
                identity["primary_route_ownership"]["local"] == []
                for site in e2e.SITES
                for identity in validated["preflight"]["sites"][site][
                    "transport_routers"
                ].values()
            )
        )
        graceful_path = validated["transport_router"]["graceful"]["new_flows"][
            "tcp"
        ]["path"]
        topology = e2e.parse_symmetric_topology_v2(validated["topology"])
        destination_router = next(
            member
            for site in e2e.SITES
            for member in topology.site(site).transport_router_fleet
            if member.instance_id
            == graceful_path["destination_transport_router_id"]
        )
        self.assertNotEqual(
            destination_router.az_key, graceful_path["destination_az_key"]
        )
        self.assertEqual(
            graceful_path["destination_gwlbe_id"],
            validated["endpoint_ids"][destination_router.site][
                graceful_path["destination_az_key"]
            ],
        )
        self.assertEqual(e2e.verify_live_evidence(document), document)

    def test_transport_recovery_summary_exactly_matches_serialized_abrupt_exercise(
        self,
    ) -> None:
        def recovery(value: dict[str, Any]) -> dict[str, Any]:
            return next(
                item
                for item in value["recoveries"]
                if item["kind"] == "transport-router"
            )

        def swap_router_ids(value: dict[str, Any]) -> None:
            summary = recovery(value)
            summary["failed_id"], summary["alternate_id"] = (
                summary["alternate_id"],
                summary["failed_id"],
            )

        def change_new_flow(value: dict[str, Any]) -> None:
            topology = e2e.parse_symmetric_topology_v2(value["topology"])
            path = recovery(value)["new_flows"]["tcp"]["path"]
            replacement = next(
                member.instance_id
                for member in topology.west.target_fleet
                if member.instance_id != path["source_target_id"]
            )
            path["source_target_id"] = replacement
            proof = path["geneve_return_proof"]["source"]
            proof["target_id"] = replacement
            proof["fidelity"]["target_id"] = replacement

        def change_metric_number_type(value: dict[str, Any]) -> None:
            metrics = recovery(value)["new_flows"]["tcp"]["path"][
                "geneve_return_proof"
            ]["source"]["metrics"]
            metrics["geneve_rx_packets_delta"] = 1
            metrics["geneve_tx_packets_delta"] = 1

        mutations = {
            "alternate": swap_router_ids,
            "new flows": change_new_flow,
            "JSON number type": change_metric_number_type,
            "duration": lambda value: recovery(value).update(
                {"recovery_duration_ms": 31}
            ),
        }
        for name, mutate in mutations.items():
            document = json.loads(json.dumps(symmetric_route_evidence()))
            mutate(document)
            with self.subTest(name=name), self.assertRaisesRegex(
                e2e.EvidenceError, "summary differs"
            ):
                e2e.validate_symmetric_evidence(document)

    def test_recovery_paths_require_complete_typed_turnaround_proof(self) -> None:
        def source_proof(value: dict[str, Any]) -> dict[str, Any]:
            return value["recoveries"][0]["new_flows"]["tcp"]["path"][
                "geneve_return_proof"
            ]["source"]

        mutations = {
            "missing metrics": lambda value: source_proof(value)["metrics"].clear(),
            "boolean failure metric": lambda value: source_proof(value)[
                "metrics"
            ].update({"drops_delta": False}),
            "numeric capture hash": lambda value: source_proof(value)[
                "fidelity"
            ].update({"capture_sha256": int("1" * 64)}),
            "boolean VNI": lambda value: source_proof(value)["fidelity"]["pairs"][
                0
            ].update({"vni": False}),
            "float VNI": lambda value: source_proof(value)["fidelity"]["pairs"][
                0
            ].update({"vni": 0.0}),
            "array direction": lambda value: source_proof(value)["fidelity"][
                "pairs"
            ][0].update({"direction": []}),
            "array router ID": lambda value: value["recoveries"][0]["new_flows"][
                "tcp"
            ]["path"].update({"source_transport_router_id": []}),
            "array recovery ID": lambda value: value["recoveries"][0].update(
                {"failed_id": []}
            ),
            "array stream ID": lambda value: value["transport"][
                "target_process"
            ]["failed_ids"].update({"tcp": []}),
            "array exercise ID": lambda value: value["transport_router"][
                "abrupt"
            ].update({"failed_id": []}),
            "huge metric": lambda value: source_proof(value)["metrics"].update(
                {"geneve_rx_packets_delta": 10**10000}
            ),
        }
        for name, mutate in mutations.items():
            document = symmetric_route_evidence()
            mutate(document)
            with self.subTest(name=name), self.assertRaises(e2e.EvidenceError):
                e2e.validate_symmetric_evidence(document)

    def test_serialized_duplicate_probes_require_exact_json_types(self) -> None:
        mutations = {
            "exercise probe": lambda value: value["transport_router"]["abrupt"][
                "probe"
            ]["new_flows"]["tcp"]["path"]["geneve_return_proof"]["source"][
                "fidelity"
            ]["pairs"][0].update({"vni": False}),
            "route probe": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["probe"]["geneve_return_proof"]["source"]["fidelity"]["pairs"][
                0
            ].update({"vni": False}),
        }
        for name, mutate in mutations.items():
            document = json.loads(json.dumps(symmetric_route_evidence()))
            mutate(document)
            with self.subTest(name=name), self.assertRaises(e2e.EvidenceError):
                e2e.validate_symmetric_evidence(document)

    def test_target_instance_evidence_allows_distinct_tcp_control_target(self) -> None:
        document = symmetric_route_evidence()
        topology = e2e.parse_symmetric_topology_v2(document["topology"])
        failed_id = next(
            recovery["failed_id"]
            for recovery in document["recoveries"]
            if recovery["kind"] == "target-instance"
        )
        control_id = next(
            member.instance_id
            for member in topology.west.target_fleet
            if member.instance_id != failed_id
        )
        document["transport"]["target_instance"]["failed_ids"]["tcp"] = control_id

        self.assertEqual(e2e.validate_symmetric_evidence(document), document)
        document["transport"]["target_instance"]["failed_ids"]["udp"] = control_id
        with self.assertRaisesRegex(e2e.EvidenceError, "UDP stream"):
            e2e.validate_symmetric_evidence(document)

    def test_target_instance_evidence_records_right_censored_udp_loss(self) -> None:
        document = symmetric_route_evidence()
        stream = document["transport"]["target_instance"]["udp"]
        interrupted = {
            "outcome": "interrupted",
            "sent_markers": 159,
            "received_markers": 23,
            "lost_markers": 136,
            "loss_percent": 136 * 100.0 / 159,
            "maximum_interruption_ms": None,
            "within_threshold": None,
            "observation_complete": True,
            "right_censored": True,
            "expected_markers": 159,
            "last_acknowledged_sequence": 22,
            "mutation_overlap_observed": True,
            "last_send_after_mutation": True,
        }
        stream.update(interrupted)

        self.assertEqual(e2e.validate_symmetric_evidence(document), document)
        stream["observation_complete"] = False
        with self.assertRaisesRegex(e2e.EvidenceError, "interrupted UDP"):
            e2e.validate_symmetric_evidence(document)

        process_document = symmetric_route_evidence()
        process_document["transport"]["target_process"]["udp"].update(interrupted)
        with self.assertRaisesRegex(e2e.EvidenceError, "interrupted UDP"):
            e2e.validate_symmetric_evidence(process_document)

    def test_target_recovery_evidence_rejects_a_fresh_path_on_the_victim(self) -> None:
        for kind in ("target-process", "target-instance"):
            with self.subTest(kind=kind):
                document = symmetric_route_evidence()
                recovery = next(
                    item
                    for item in document["recoveries"]
                    if item["kind"] == kind
                )
                recovery["new_flows"]["tcp"]["path"][
                    "source_target_id"
                ] = recovery["failed_id"]
                proof = recovery["new_flows"]["tcp"]["path"][
                    "geneve_return_proof"
                ]["source"]
                proof["target_id"] = recovery["failed_id"]
                proof["fidelity"]["target_id"] = recovery["failed_id"]

                with self.assertRaisesRegex(e2e.EvidenceError, "victim exclusion"):
                    e2e.validate_symmetric_evidence(document)

    def test_target_process_evidence_rejects_a_different_measured_udp_victim(self) -> None:
        document = symmetric_route_evidence()
        topology = e2e.parse_symmetric_topology_v2(document["topology"])
        recovery = next(
            item
            for item in document["recoveries"]
            if item["kind"] == "target-process"
        )
        document["transport"]["target_process"]["failed_ids"]["udp"] = next(
            member.instance_id
            for member in topology.west.target_fleet
            if member.instance_id != recovery["failed_id"]
        )

        with self.assertRaisesRegex(e2e.EvidenceError, "target-process UDP stream"):
            e2e.validate_symmetric_evidence(document)

    def test_schema_rejects_route_identity_state_bounds_probe_and_fidelity_tampering(self) -> None:
        def duplicate_stable_hash(value: dict[str, Any]) -> None:
            west = list(value["preflight"]["sites"]["west"]["transport_routers"].values())
            west[1]["tailnet_node_id_sha256"] = west[0]["tailnet_node_id_sha256"]

        def add_local_owner(value: dict[str, Any]) -> None:
            topology = e2e.parse_symmetric_topology_v2(value["topology"])
            observer, sibling = topology.west.transport_router_fleet
            value["preflight"]["sites"]["west"]["transport_routers"][
                observer.instance_id
            ]["primary_route_ownership"]["local"] = [
                {
                    "prefix": sibling.advertised_prefix,
                    "owner_instance_id": sibling.instance_id,
                    "online": True,
                }
            ]

        def swap_preflight_destination_gwlbe(value: dict[str, Any]) -> None:
            topology = e2e.parse_symmetric_topology_v2(value["topology"])
            router = topology.west.transport_router_fleet[0]
            identity = value["preflight"]["sites"]["west"]["transport_routers"][
                router.instance_id
            ]
            identity["local_gwlbes"][router.advertised_prefix] = value[
                "endpoint_ids"
            ]["west"]["b"]

        def move_graceful_probe_to_unaffected_az(value: dict[str, Any]) -> None:
            topology = e2e.parse_symmetric_topology_v2(value["topology"])
            exercise = value["transport_router"]["graceful"]
            alternate = next(
                member
                for member in topology.east.transport_router_fleet
                if member.instance_id == exercise["alternate_id"]
            )
            endpoint = value["endpoint_ids"]["east"][alternate.az_key]
            route_probe = exercise["route_replacement"]["probe"]
            for probe in (exercise["probe"], route_probe):
                probe["destination_az_key"] = alternate.az_key
                probe["destination_gwlbe_id"] = endpoint
                for item in probe["new_flows"].values():
                    item["path"]["destination_az_key"] = alternate.az_key
                    item["path"]["destination_gwlbe_id"] = endpoint
            for item in exercise["new_flows"].values():
                item["path"]["destination_az_key"] = alternate.az_key
                item["path"]["destination_gwlbe_id"] = endpoint

        def transfer_target_recovery_destination_owner(value: dict[str, Any]) -> None:
            topology = e2e.parse_symmetric_topology_v2(value["topology"])
            path = value["recoveries"][0]["new_flows"]["tcp"]["path"]
            current = next(
                member
                for member in topology.east.transport_router_fleet
                if member.instance_id == path["destination_transport_router_id"]
            )
            path["destination_transport_router_id"] = next(
                member.instance_id
                for member in topology.east.transport_router_fleet
                if member != current
            )

        mutations = {
            "route table": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ].update({"route_table_id": "rtb-fffffffffffffffff"}),
            "prefix": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["prefixes"].pop(),
            "current ENI": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["current"].update({"network_interface_id": "eni-fffffffffffffffff"}),
            "alternate state": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["after"]["routes"][0].update({"route_state": "blackhole"}),
            "restoration": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["restoration"].update({"status": "failed"}),
            "advertisement transfer routes": lambda value: value["transport_router"][
                "abrupt"
            ]["route_replacement"]["advertisements"]["alternate_expansion"][
                "advertisements"
            ]["routes"].pop(),
            "generation identity": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["advertisements"].update(
                {
                    "restore_generation": value["transport_router"]["abrupt"][
                        "route_replacement"
                    ]["advertisements"]["forward_generation"]
                }
            ),
            "restored advertisement component": lambda value: value[
                "transport_router"
            ]["abrupt"]["route_replacement"]["restoration"]["advertisements"][
                "current"
            ]["advertisements"].update({"routes": []}),
            "ownership stable hash": lambda value: value["transport_router"][
                "abrupt"
            ]["route_replacement"]["ownership"]["transferred"]["observers"][0][
                "owners"
            ][0].update({"owner_node_id_sha256": "0" * 64}),
            "ownership observer binding": lambda value: value["transport_router"][
                "abrupt"
            ]["route_replacement"]["ownership"]["transferred"]["observers"][0].update(
                {"observer_instance_id": "i-ff23456789abcdef"}
            ),
            "local preflight owner": add_local_owner,
            "preflight destination GWLBE": swap_preflight_destination_gwlbe,
            "graceful unaffected destination AZ": move_graceful_probe_to_unaffected_az,
            "target recovery transferred owner": transfer_target_recovery_destination_owner,
            "duplicate stable node hash": duplicate_stable_hash,
            "bound": lambda value: value["transport_router"]["abrupt"][
                "route_replacement"
            ]["bounds"].update({"mutation_timeout_seconds": 0}),
            "GWLBE probe": lambda value: value["transport_router"]["abrupt"]["probe"].update(
                {"source_transport_eni_id": "eni-fffffffffffffffff"}
            ),
            "recovery destination GWLBE": lambda value: value["transport_router"][
                "graceful"
            ]["new_flows"]["tcp"]["path"].update(
                {
                    "destination_gwlbe_id": value["endpoint_ids"]["east"]["b"]
                }
            ),
            "control plane": lambda value: value["transport_router"]["graceful"].update(
                {"control_plane": "gwlbe-route"}
            ),
            "target metric": lambda value: value["traversals"][0]["probes"][0][
                "geneve_return_proof"
            ]["source"]["metrics"].update({"gwlb_target_ready": 0}),
            "packet fidelity": lambda value: value["traversals"][0]["probes"][0][
                "geneve_return_proof"
            ]["source"]["fidelity"].update({"observed": False}),
            "missing TCP new flow": lambda value: value["recoveries"][0][
                "new_flows"
            ].pop("tcp"),
            "UDP loss arithmetic": lambda value: value["transport"][
                "target_instance"
            ]["udp"].update({"loss_percent": 11.0}),
            "router stream identity": lambda value: value["transport"][
                "transport_router"
            ]["abrupt"]["failed_ids"].update({"tcp": "i-ff23456789abcdef"}),
            "residual audit": lambda value: value["residual_audit"].update(
                {"owned_resources_remaining": 1}
            ),
        }
        for name, mutate in mutations.items():
            candidate = copy.deepcopy(symmetric_route_evidence())
            mutate(candidate)
            with self.subTest(name=name), self.assertRaises(e2e.EvidenceError):
                e2e.validate_symmetric_evidence(candidate)

    def test_route_evidence_redacts_or_rejects_credentials(self) -> None:
        candidate = symmetric_route_evidence()
        candidate["transport_router"]["abrupt"]["probe"]["token"] = "tskey-secret-value"
        with self.assertRaisesRegex(e2e.EvidenceError, "unsafe evidence"):
            e2e.validate_symmetric_evidence(candidate)


class SymmetricRoleReadinessTest(unittest.TestCase):
    def test_packet_turnaround_proof_uses_current_metrics_and_fidelity_shape(self) -> None:
        def snapshot(rx: float, tx: float, failures: float) -> e2e.MetricSnapshot:
            return e2e.MetricSnapshot(
                "generation-1",
                (
                    e2e.MetricSeries("geneve_rx_packets", (), rx),
                    e2e.MetricSeries("geneve_tx_packets", (), tx),
                    e2e.MetricSeries(
                        "geneve_options_validation_errors",
                        (("reason", "structural"),),
                        0,
                    ),
                    e2e.MetricSeries(
                        "gwlb_profile_rejections_total",
                        (("reason", "decode"),),
                        0,
                    ),
                    e2e.MetricSeries(
                        "gwlb_receive_drops_total",
                        (("reason", "packet_info"),),
                        0,
                    ),
                    e2e.MetricSeries(
                        "gwlb_inner_validation_failures_total",
                        (("reason", "malformed"),),
                        0,
                    ),
                    e2e.MetricSeries("gwlb_return_build_failures_total", (), 0),
                    e2e.MetricSeries("gwlb_send_failures_total", (), failures),
                    e2e.MetricSeries("drops", (), 0),
                    e2e.MetricSeries("gwlb_target_ready", (), 1),
                    *(
                        e2e.MetricSeries(
                            "gwlb_target_component_ready",
                            (("component", component),),
                            1,
                        )
                        for component in ("receiver", "validation", "sender")
                    ),
                ),
            )

        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        before = {"i-6123456789abcdef0": snapshot(10, 10, 0)}
        after = {"i-6123456789abcdef0": snapshot(11, 11, 0)}
        fidelity = symmetric_route_evidence()["traversals"][0]["probes"][0][
            "geneve_return_proof"
        ]["source"]["fidelity"]
        proof = operations._geneve_return_proof(
            before,
            after,
            "i-6123456789abcdef0",
            fidelity,
        )
        self.assertEqual(
            proof["metrics"]["components_ready"],
            {"receiver": 1, "validation": 1, "sender": 1},
        )
        self.assertTrue(proof["fidelity"]["observed"])
        self.assertTrue(proof["fidelity"]["raw_pcap_deleted"])

        failed = {"i-6123456789abcdef0": snapshot(11, 11, 1)}
        with self.assertRaises(e2e.MetricAssertionError):
            operations._geneve_return_proof(
                before, failed, "i-6123456789abcdef0", fidelity
            )

        non_finite = {"i-6123456789abcdef0": snapshot(11, 11, float("inf"))}
        with self.assertRaisesRegex(e2e.MetricAssertionError, "non-finite"):
            operations._geneve_return_proof(
                before, non_finite, "i-6123456789abcdef0", fidelity
            )

    def test_target_requires_source_dest_check_and_current_packet_return_metrics(self) -> None:
        topology = route_failover_topology()
        member = topology.west.target_fleet[0]
        commands: list[str] = []
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(
            run_id=topology.run_id,
            sites={
                "west": {
                    "azs": {member.az_key: f"us-west-2{member.az_key}"},
                    "target_subnet_cidrs": {
                        member.az_key: "10.10.9.0/24"
                    },
                }
            },
        )
        instance = {
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
            "Tags": {
                "EnvelopeRun": topology.run_id,
                "Role": "target",
                "Site": member.site,
                "ZoneKey": member.az_key,
            },
        }
        operations._describe_instance = lambda _member: instance
        operations._verify_primary_network_binding = mock.Mock()

        def execute(_target, command, **_kwargs):
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
                "pid": 42,
                "process_generation_sha256": "9" * 64,
            }

        operations.base = SimpleNamespace(
            _tags=lambda value: value["Tags"],
            _execute_json=execute,
        )
        deployment = SimpleNamespace(
            runtime={
                "west": {
                    "artifact_sha256": "a" * 64,
                    "artifact_revision": "b" * 40,
                }
            }
        )
        operations._verify_target(deployment, member, timeout_seconds=30)
        self.assertIn("gwlb_target_ready", commands[0])
        self.assertIn("gwlb_target_component_ready", commands[0])
        self.assertIn("receiver validation sender", commands[0])
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
            self.assertIn(metric, commands[0])
        for obsolete in ("tun_", "routing_", "decap_errors", "encap_errors"):
            self.assertIn(obsolete, commands[0])
        self.assertNotIn("datapath_component_healthy", commands[0])

        instance["SourceDestCheck"] = False
        with self.assertRaisesRegex(e2e.ReadinessError, "source/destination checking"):
            operations._verify_target(deployment, member, timeout_seconds=30)

    def test_transport_requires_disabled_source_dest_check_and_explicit_role(self) -> None:
        topology = route_failover_topology()
        member = topology.west.transport_router_fleet[0]
        operations = object.__new__(e2e.AwsSymmetricLiveOperations)
        operations.config = SimpleNamespace(
            run_id=topology.run_id,
            sites={
                "west": {
                    "azs": {"a": "us-west-2a"},
                    "transport_subnet_cidrs": {"a": "10.10.3.0/24"},
                }
            },
        )
        instance = {
            "State": {"Name": "running"},
            "SourceDestCheck": True,
            "SubnetId": "subnet-8123456789abcdef0",
            "Placement": {"AvailabilityZone": "us-west-2a"},
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": member.network_interface_id,
                    "SubnetId": "subnet-8123456789abcdef0",
                    "Status": "in-use",
                    "SourceDestCheck": True,
                    "Attachment": {"DeviceIndex": 0, "Status": "attached"},
                }
            ],
            "Tags": {
                "EnvelopeRun": topology.run_id,
                "Role": "transport-router",
                "Site": member.site,
                "ZoneKey": member.az_key,
            },
        }
        operations._describe_instance = lambda _member: instance
        operations._verify_primary_network_binding = mock.Mock()
        operations.base = SimpleNamespace(_tags=lambda value: value["Tags"])
        with self.assertRaisesRegex(e2e.ReadinessError, "source/destination checking"):
            operations._verify_transport_router(SimpleNamespace(topology=topology), member)

        instance["SourceDestCheck"] = False
        instance["NetworkInterfaces"][0]["SourceDestCheck"] = False
        instance["Tags"]["Role"] = "tailnet-ingress"
        with self.assertRaisesRegex(e2e.ReadinessError, "transport-router EC2"):
            operations._verify_transport_router(SimpleNamespace(topology=topology), member)


class RouteRestorationCleanupPrecedenceTest(unittest.TestCase):
    def test_runner_requires_transport_recovery_contract_without_legacy_fallback(self) -> None:
        string_constants = {
            value
            for value in e2e.SymmetricTwoRegionE2ERunner.run.__code__.co_consts
            if isinstance(value, str)
        }
        self.assertIn("run_transport_router_recovery", string_constants)
        self.assertNotIn("run_ingress_router_recovery", string_constants)

    def test_startup_reconciliation_precedes_drift_and_stops_replay_before_cleanup(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)
        calls: list[str] = []

        class Lifecycle:
            def claim(self, _raw, _deployment):
                calls.append("claim")
                return {
                    "load_profile_approved_before_apply": True,
                    "route_recovery_required": True,
                }

            def reconcile_gwlbe_route_replacement(self, _deployment, *, timeout_seconds):
                calls.append(f"reconcile-{timeout_seconds}")
                return {"required": True, "restored": True}

            def verify_no_drift(self, _stage):
                raise AssertionError("drift must not run before an interrupted acceptance is terminated")

            def finish(self, passed):
                calls.append(f"finish-{passed}")
                return {"finish": "persisted", "acceptance": "failed"}

            def cleanup(self):
                calls.append("cleanup")
                return {"final_residual_count": 0}

        class Operations:
            @staticmethod
            def run_transport_router_recovery(*_args, **_kwargs):
                raise AssertionError("transport exercise must not run after startup reconciliation")

            @staticmethod
            def collect_diagnostics(_deployment):
                calls.append("diagnostics")
                return {"collection": "complete"}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["failure"]["category"], "ResilienceError")
        self.assertEqual(
            calls,
            [
                "claim",
                f"reconcile-{deployment.topology.route_failover.recovery_timeout_seconds}",
                "diagnostics",
                "finish-False",
                "cleanup",
            ],
        )

    def test_route_restoration_failure_still_cleans_up_and_cleanup_failure_wins(self) -> None:
        raw = route_failover_output()
        deployment = e2e.parse_symmetric_protected_deployment_output(raw)

        class Lifecycle:
            def __init__(self, cleanup_fails: bool) -> None:
                self.cleanup_fails = cleanup_fails
                self.cleanup_calls = 0

            def claim(self, _raw, _deployment):
                return {"load_profile_approved_before_apply": True}

            def verify_no_drift(self, stage):
                return {"clean": True, "stage": stage}

            def finish(self, passed):
                return {
                    "finish": "persisted",
                    "acceptance": "passed" if passed else "failed",
                }

            def cleanup(self):
                self.cleanup_calls += 1
                if self.cleanup_fails:
                    raise e2e.LifecycleError("injected protected cleanup failure")
                return {"final_residual_count": 0}

        class Operations:
            def verify_readiness(self, current, *, timeout_seconds):
                return {
                    "tailnet_policy_valid": True,
                    "transport_router_contract_sha256": {
                        site: current.transport_router_readiness_expectations[site][
                            "contract_sha256"
                        ]
                        for site in e2e.SITES
                    },
                    "sites": {
                        site: {
                            "route_domains": {
                                "workload": True,
                                "transport": True,
                                "target": True,
                            },
                            "targets": {
                                member.instance_id: {
                                    "ready": True,
                                    "target_group_arn": member.target_group_arn,
                                    "registration_port": 6081,
                                    "process_generation_sha256": "7" * 64,
                                }
                                for member in current.topology.site(site).target_fleet
                            },
                            "transport_routers": {
                                member.instance_id: {
                                    "ready": True,
                                    "node_identity_ready": True,
                                    "network_interface_id": member.network_interface_id,
                                    "contract_sha256": current.transport_router_readiness_expectations[
                                        site
                                    ]["contract_sha256"],
                                    "tailnet_node_id_sha256": "8" * 64,
                                    "advertised_prefix": member.advertised_prefix,
                                    "local_gwlbes": {
                                        candidate.advertised_prefix: current.endpoint_ids[
                                            site
                                        ][candidate.az_key]
                                        for candidate in current.topology.site(
                                            site
                                        ).transport_router_fleet
                                    },
                                    "primary_route_ownership": {
                                        "observed_at": "2026-08-20T11:59:59Z",
                                        "remote": [
                                            {
                                                "prefix": prefix,
                                                "owner_instance_id": current.topology.site(
                                                    e2e._opposite(site)
                                                ).transport_router_for_prefix(
                                                    prefix
                                                ).instance_id,
                                                "online": True,
                                            }
                                            for index, prefix in enumerate(
                                                current.topology.site(site).remote_site_cidrs
                                            )
                                        ],
                                        "local": [],
                                    },
                                }
                                for member in current.topology.site(site).transport_router_fleet
                            },
                        }
                        for site in e2e.SITES
                    },
                }

            def run_cold_probe(self, current, flow, *, start_barrier, timeout_seconds):
                assert flow.source.az_key is not None
                return {
                    "source_site": flow.source.site,
                    "destination_site": flow.destination.site,
                    "source_role": flow.source.role,
                    "destination_role": flow.destination.role,
                    "protocol": flow.protocol,
                    "source_az_key": flow.source.az_key,
                    "source_gwlbe_id": current.endpoint_ids[flow.source.site][flow.source.az_key],
                    "dispatch_monotonic_ns": time.monotonic_ns(),
                    "succeeded": True,
                }

            def run_traversal(self, current, source_site, flows, *, timeout_seconds):
                source = current.topology.site(source_site)
                destination = current.topology.site(e2e._opposite(source_site))
                source_router = source.transport_router_fleet[0]
                destination_router = destination.transport_router_fleet[0]
                return {
                    "source_site": source_site,
                    "destination_site": e2e._opposite(source_site),
                    "probes": [
                        {
                            "source_target_id": source.target_fleet[0].instance_id,
                            "source_az_key": source.target_fleet[0].az_key,
                            "source_transport_router_id": source_router.instance_id,
                            "source_transport_eni_id": source_router.network_interface_id,
                            "destination_transport_router_id": destination_router.instance_id,
                        }
                    ],
                }

            def run_target_process_recovery(
                self,
                current,
                failed,
                new_flow,
                new_tcp_flow,
                tcp_flow,
                udp_flow,
                *,
                timeout_seconds,
            ):
                alternate = current.topology.site(failed.site).target_fleet[1]
                return {
                    "recovery": {
                        "kind": "target-process",
                        "site": failed.site,
                        "failed_id": failed.instance_id,
                        "alternate_id": alternate.instance_id,
                        "new_flow_succeeded": True,
                        "new_flows": new_flow_evidence(
                            source_target_id=alternate.instance_id
                        ),
                        "recovery_duration_ms": 1,
                    },
                    "health_transitions": [
                        {
                            "kind": "target-process",
                            "member_id": failed.instance_id,
                            "states": ["healthy", "unhealthy", "healthy"],
                        }
                    ],
                    "transport": failure_transport_evidence(
                        failed.instance_id, "target-process"
                    ),
                }

            def run_target_instance_recovery(
                self,
                current,
                failed,
                new_flow,
                new_tcp_flow,
                tcp_flow,
                udp_flow,
                *,
                timeout_seconds,
            ):
                alternate = current.topology.site(failed.site).target_fleet[1]
                return current, {
                    "recovery": {
                        "kind": "target-instance",
                        "site": failed.site,
                        "failed_id": failed.instance_id,
                        "alternate_id": alternate.instance_id,
                        "replacement_id": "i-ff23456789abcdef",
                        "replacement_ready": True,
                        "drain_state": "draining",
                        "drain_duration_ms": 1,
                        "new_flow_succeeded": True,
                        "new_flows": new_flow_evidence(
                            source_target_id=alternate.instance_id
                        ),
                        "recovery_duration_ms": 1,
                    },
                    "health_transition": {
                        "kind": "target-instance",
                        "member_id": failed.instance_id,
                        "states": ["healthy", "draining", "replaced"],
                    },
                    "transport": failure_transport_evidence(
                        failed.instance_id, "target-instance"
                    ),
                }

            def run_transport_router_recovery(self, *_args, **_kwargs):
                raise e2e.RouteRestorationError("injected verified route restoration failure")

            def collect_diagnostics(self, current):
                return {"collection": "complete"}

        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as temporary:
                lifecycle = Lifecycle(cleanup_fails)
                result = e2e.SymmetricTwoRegionE2ERunner(
                    run_id=deployment.topology.run_id,
                    raw_deployment=raw,
                    site_regions={"west": "us-west-2", "east": "us-east-1"},
                    lifecycle=lifecycle,
                    operations=Operations(),
                    evidence_path=pathlib.Path(temporary) / "evidence.json",
                ).run()

                self.assertEqual(lifecycle.cleanup_calls, 1)
                if cleanup_fails:
                    self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
                    self.assertEqual(
                        result.evidence["failure"]["category"],
                        "LifecycleError",
                        result.evidence,
                    )

                    self.assertEqual(
                        result.evidence["diagnostics"]["acceptance_failure_before_cleanup"][
                            "category"
                        ],
                        "RouteRestorationError",
                    )
                else:
                    self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                    self.assertEqual(
                        result.evidence["failure"]["category"],
                        "RouteRestorationError",
                        result.evidence,
                    )

    def test_deferred_route_recovery_is_not_reported_as_a_terminal_finish(self) -> None:
        raw = route_failover_output()

        class Lifecycle:
            @staticmethod
            def claim(_raw, _deployment):
                return {"load_profile_approved_before_apply": True}

            @staticmethod
            def reconcile_gwlbe_route_replacement(_deployment, *, timeout_seconds):
                del timeout_seconds
                return {"required": False, "restored": True}

            @staticmethod
            def verify_no_drift(_stage):
                raise e2e.DriftError("injected precheck failure")

            @staticmethod
            def finish(_passed):
                return {
                    "finish": "deferred-route-recovery",
                    "acceptance": "failed",
                    "result_persistence": "active-route-transaction",
                }

            @staticmethod
            def cleanup():
                return {"final_residual_count": 0}

        class Operations:
            @staticmethod
            def collect_diagnostics(_deployment):
                return {"collection": "complete"}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=Operations(),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["lifecycle"]["finish"], "failed")
        self.assertEqual(
            result.evidence["diagnostics"]["lifecycle_finish_deferred"][
                "result_persistence"
            ],
            "active-route-transaction",
        )

    def test_unreservable_route_configuration_is_rejected_before_claim(self) -> None:
        raw = route_failover_output()
        for field in (
            "mutation_timeout_seconds",
            "restoration_timeout_seconds",
            "recovery_timeout_seconds",
        ):
            raw["symmetric_topology"]["value"]["route_failover"][field] = 1000
            raw["route_failover"]["value"][field] = 1000
            raw["cost_profile"]["value"]["route_failover_bounds"][field] = 1000

        class Lifecycle:
            claim_calls = 0

            @classmethod
            def claim(cls, _raw, _deployment):
                cls.claim_calls += 1
                raise AssertionError("an unreservable configuration must not be claimed")

            @staticmethod
            def cleanup():
                return {"final_residual_count": 0}

        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.SymmetricTwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=Lifecycle(),
                operations=SimpleNamespace(),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
            ).run()

        self.assertEqual(Lifecycle.claim_calls, 0)
        self.assertEqual(result.evidence["failure"]["category"], "DeploymentError")
        self.assertIn("reservation", result.evidence["failure"]["message"])


class InvocationMissing(Exception):
    def __init__(self) -> None:
        super().__init__("eventual consistency")
        self.response = {"Error": {"Code": "InvocationDoesNotExist"}}


class ScriptedAWS:
    def __init__(self, polls: list[object], *, cancellation_polls: list[object] | None = None) -> None:
        self.polls = list(polls)
        self.cancellation_polls = list(cancellation_polls or [])
        self.cancellation_requested = False
        self.calls: list[tuple[list[str], str | None]] = []
        self.timeouts: list[float | None] = []

    def json(
        self,
        args: list[str],
        *,
        region: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self.calls.append((list(args), region))
        self.timeouts.append(timeout_seconds)
        operation = args[1]
        if operation == "send-command":
            return {"Command": {"CommandId": "11111111-2222-3333-4444-555555555555"}}
        if operation == "get-command-invocation":
            selected = self.cancellation_polls if self.cancellation_requested else self.polls
            value = selected.pop(0) if selected else {"Status": "InProgress", "ResponseCode": -1}
            if isinstance(value, BaseException):
                raise value
            assert isinstance(value, dict)
            return value
        if operation == "cancel-command":
            self.cancellation_requested = True
            return {}
        raise AssertionError(f"unexpected fake operation: {operation}")


class SSMRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.target = parsed_deployment().west.initiator
        self.command = e2e.SSMCommand(self.target, ("/opt/envelope/e2e-agent probe",), timeout_seconds=2)

    def test_invocation_does_not_exist_is_retried_and_output_is_redacted(self) -> None:
        access_key = "ASIA" + "ABCDEFGHIJKLMNOP"
        aws = ScriptedAWS(
            [
                InvocationMissing(),
                {
                    "Status": "Success",
                    "ResponseCode": 0,
                    "StandardOutputContent": "token=very-secret-value",
                    "StandardErrorContent": access_key,
                },
            ]
        )
        clock = FakeClock()
        runner = e2e.SSMRunner(aws, clock=clock, sleep=clock.sleep, poll_interval_seconds=0.1)

        result = runner.execute(self.command, wait_timeout_seconds=1)

        self.assertTrue(result.succeeded)
        self.assertNotIn("very-secret-value", result.stdout)
        self.assertNotIn(access_key, result.stderr)
        self.assertNotIn("commands", repr(self.command))
        self.assertEqual([call[0][1] for call in aws.calls], ["send-command", "get-command-invocation", "get-command-invocation"])
        self.assertTrue(all(region == "us-west-2" for _args, region in aws.calls))

    def test_send_command_bounds_delivery_and_remote_execution_independently(self) -> None:
        aws = ScriptedAWS([])
        runner = e2e.SSMRunner(aws)

        command_id = runner.send(self.command, timeout_seconds=0.5)

        self.assertEqual(command_id, "11111111-2222-3333-4444-555555555555")
        send_args = aws.calls[0][0]
        timeout_index = send_args.index("--timeout-seconds")
        self.assertEqual(send_args[timeout_index + 1], "30")
        parameters = json.loads(send_args[send_args.index("--parameters") + 1])
        self.assertEqual(parameters["executionTimeout"], ["2"])
        self.assertEqual(parameters["commands"], list(self.command.commands))
        self.assertNotIn("--client-token", send_args)
        self.assertEqual(self.command.timeout_seconds, 2)
        self.assertEqual(aws.timeouts[0], 0.5)

        maximum = e2e.SSMCommand(self.target, ("true",), timeout_seconds=3600)
        runner.send(maximum, timeout_seconds=0.5)
        maximum_args = aws.calls[1][0]
        self.assertEqual(maximum_args[maximum_args.index("--timeout-seconds") + 1], "3600")
        maximum_parameters = json.loads(maximum_args[maximum_args.index("--parameters") + 1])
        self.assertEqual(maximum_parameters["executionTimeout"], ["3600"])

    def test_keyboard_interrupt_is_never_normalized_or_cancelled(self) -> None:
        for operation in ("send", "wait", "cancel"):
            with self.subTest(operation=operation):
                control = KeyboardInterrupt(f"fixture {operation} interrupt")
                aws = ScriptedAWS([control])
                runner = e2e.SSMRunner(
                    aws,
                    poll_interval_seconds=0.01,
                    api_timeout_seconds=0.5,
                )
                if operation == "send":
                    aws.json = mock.Mock(side_effect=control)
                    invoke = lambda: runner.send(self.command)
                elif operation == "wait":
                    invoke = lambda: runner.wait(
                        self.target,
                        "11111111-2222-3333-4444-555555555555",
                        timeout_seconds=0.5,
                    )
                else:
                    aws.json = mock.Mock(side_effect=control)
                    invoke = lambda: runner.cancel(
                        self.target,
                        "11111111-2222-3333-4444-555555555555",
                    )

                with self.assertRaises(KeyboardInterrupt) as raised:
                    invoke()

                self.assertIs(raised.exception, control)
                if operation == "wait":
                    self.assertFalse(aws.cancellation_requested)

    def test_wait_timeout_requests_bounded_cancellation(self) -> None:
        aws = ScriptedAWS(
            [InvocationMissing(), {"Status": "InProgress", "ResponseCode": -1}],
            cancellation_polls=[{"Status": "Cancelled", "ResponseCode": -1}],
        )
        clock = FakeClock()
        runner = e2e.SSMRunner(
            aws,
            clock=clock,
            sleep=clock.sleep,
            poll_interval_seconds=0.25,
            api_timeout_seconds=0.5,
        )

        with self.assertRaisesRegex(e2e.SSMTimeout, "terminal state Cancelled confirmed"):
            runner.execute(
                self.command,
                send_timeout_seconds=0.5,
                wait_timeout_seconds=1.0,
                cancel_timeout_seconds=0.5,
            )

        operations = [args[1] for args, _region in aws.calls]
        self.assertEqual(operations[0], "send-command")
        self.assertEqual(operations[-2:], ["cancel-command", "get-command-invocation"])
        self.assertGreaterEqual(operations.count("get-command-invocation"), 2)
        cancel_args = next(args for args, _region in aws.calls if args[1] == "cancel-command")
        self.assertIn(self.target.instance_id, cancel_args)

    def test_terminate_reports_confirmed_terminal_state_directly(self) -> None:
        aws = ScriptedAWS(
            [],
            cancellation_polls=[
                {"Status": "InProgress", "ResponseCode": -1},
                {"Status": "Cancelled", "ResponseCode": -1},
            ],
        )
        clock = FakeClock()
        runner = e2e.SSMRunner(
            aws,
            clock=clock,
            sleep=clock.sleep,
            poll_interval_seconds=0.1,
        )

        result = runner.terminate(
            self.target,
            "11111111-2222-3333-4444-555555555555",
            timeout_seconds=1,
        )

        self.assertEqual(result.status, "Cancelled")
        self.assertEqual(
            [args[1] for args, _region in aws.calls],
            ["cancel-command", "get-command-invocation", "get-command-invocation"],
        )

    def test_unknown_status_and_poll_api_error_cancel_and_confirm_terminal_state(self) -> None:
        cases = {
            "unknown": {"Status": "FutureStatus", "ResponseCode": -1},
            "api-error": RuntimeError("poll API unavailable"),
        }
        for name, failure in cases.items():
            with self.subTest(name=name):
                aws = ScriptedAWS(
                    [failure],
                    cancellation_polls=[{"Status": "Cancelled", "ResponseCode": -1}],
                )
                runner = e2e.SSMRunner(aws, poll_interval_seconds=0.01, api_timeout_seconds=0.5)

                with self.assertRaisesRegex(e2e.SSMError, "terminal state Cancelled confirmed"):
                    runner.execute(
                        self.command,
                        send_timeout_seconds=0.5,
                        wait_timeout_seconds=0.5,
                        cancel_timeout_seconds=0.5,
                    )

                self.assertEqual(
                    [args[1] for args, _region in aws.calls],
                    ["send-command", "get-command-invocation", "cancel-command", "get-command-invocation"],
                )

    def test_unconfirmed_cancellation_is_reported_after_a_bounded_poll(self) -> None:
        clock = FakeClock()
        aws = ScriptedAWS(
            [{"Status": "FutureStatus", "ResponseCode": -1}],
            cancellation_polls=[{"Status": "InProgress", "ResponseCode": -1}],
        )
        runner = e2e.SSMRunner(
            aws,
            clock=clock,
            sleep=clock.sleep,
            poll_interval_seconds=0.25,
            api_timeout_seconds=0.5,
        )

        with self.assertRaisesRegex(
            e2e.SSMTerminationError, "terminal state unconfirmed"
        ):
            runner.execute(
                self.command,
                send_timeout_seconds=0.5,
                wait_timeout_seconds=0.5,
                cancel_timeout_seconds=0.5,
            )

        self.assertEqual(clock.value, 0.5)

    def test_protected_control_flow_during_cancellation_is_rethrown_unchanged(self) -> None:
        for stage in ("cancel-command", "get-command-invocation"):
            with self.subTest(stage=stage):
                control = e2e.ProtectedHardTimeout(f"injected during {stage}")

                class ControlFlowAWS(ScriptedAWS):
                    def json(
                        inner,
                        args: list[str],
                        *,
                        region: str | None = None,
                        timeout_seconds: float | None = None,
                    ) -> dict[str, Any]:
                        operation = args[1]
                        if operation == stage and (
                            operation == "cancel-command" or inner.cancellation_requested
                        ):
                            raise control
                        return super().json(
                            args,
                            region=region,
                            timeout_seconds=timeout_seconds,
                        )

                aws = ControlFlowAWS(
                    [{"Status": "FutureStatus", "ResponseCode": -1}],
                    cancellation_polls=[{"Status": "InProgress", "ResponseCode": -1}],
                )
                runner = e2e.SSMRunner(aws, api_timeout_seconds=0.5)

                with self.assertRaises(e2e.ProtectedHardTimeout) as raised:
                    runner.execute(
                        self.command,
                        send_timeout_seconds=0.5,
                        wait_timeout_seconds=0.5,
                        cancel_timeout_seconds=0.5,
                    )
                self.assertIs(raised.exception, control)

    def test_send_call_itself_is_bounded(self) -> None:
        class HangingAWS:
            def json(
                inner,
                args: list[str],
                *,
                region: str | None = None,
                timeout_seconds: float | None = None,
            ) -> dict[str, Any]:
                inner.timeout = timeout_seconds
                raise TimeoutError("native child was killed and reaped")

        aws = HangingAWS()
        runner = e2e.SSMRunner(aws, api_timeout_seconds=0.02)
        started = time.monotonic()
        with self.assertRaisesRegex(e2e.SSMDispatchError, "send-command"):
            runner.send(self.command, timeout_seconds=0.02)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(aws.timeout, 0.02)

    def test_execute_failure_retains_only_bounded_redacted_invocation_streams(self) -> None:
        class FailedSSM:
            def execute(self, command, **_kwargs):
                return e2e.SSMResult(
                    command.target,
                    "failed-command",
                    "Failed",
                    17,
                    stdout="token=fixture-sensitive-value\n" + "x" * 30_000,
                    stderr="tskey-fixture-sensitive-value",
                )

        operations = e2e.AwsLiveOperations(
            SimpleNamespace(),
            SimpleNamespace(),
            pathlib.Path("/tmp/not-used"),
            ssm=FailedSSM(),
        )

        with self.assertRaises(e2e.SSMError) as raised:
            operations._execute(
                self.target,
                "false",
                timeout_seconds=10,
                comment="Envelope E2E retained failure output",
            )

        self.assertLessEqual(len(raised.exception.stdout), 24_000)
        self.assertLessEqual(len(raised.exception.stderr), 24_000)
        self.assertNotIn("fixture-sensitive-value", raised.exception.stdout)
        self.assertNotIn("tskey-fixture-sensitive-value", raised.exception.stderr)
        self.assertIn("[REDACTED", raised.exception.stdout)
        self.assertIn("[REDACTED", raised.exception.stderr)


class FlowLedgerTest(unittest.TestCase):
    def test_icmp_flow_uses_no_synthetic_ports_and_does_not_consume_one(self) -> None:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-icmp", first_source_port=41_000, last_source_port=41_001)
        generation = ledger.begin_generation("west-envelope")

        icmp = ledger.allocate(
            "icmp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=None,
            generation=generation,
        )
        tcp = ledger.allocate(
            "tcp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=5201,
            generation=generation,
        )

        self.assertIsNone(icmp.source_port)
        self.assertIsNone(icmp.destination_port)
        self.assertEqual(icmp.tuple_dict(), {
            "source_ip": "10.10.1.10",
            "destination_ip": "10.20.1.11",
            "protocol": "icmp",
        })
        self.assertEqual(tcp.source_port, 41_000)
        with self.assertRaisesRegex(e2e.E2EError, "synthetic transport ports"):
            e2e.FlowRecord(
                "fixture-icmp-bad",
                3,
                "icmp",
                deployment.west.initiator,
                deployment.east.responder,
                41_001,
                5201,
                generation.label,
            )

    def test_ports_flow_ids_and_generation_labels_are_unique_and_deterministic(self) -> None:
        deployment = parsed_deployment()

        def allocate() -> tuple[e2e.FlowLedger, list[e2e.FlowRecord]]:
            ledger = e2e.FlowLedger("fixture-e2e", first_source_port=41_000, last_source_port=41_010)
            generation_one = ledger.begin_generation("west-envelope")
            generation_two = ledger.begin_generation("west-envelope")
            records = [
                ledger.allocate(
                    "tcp",
                    deployment.west.initiator,
                    deployment.east.responder,
                    destination_port=5201,
                    generation=generation_one,
                ),
                ledger.allocate(
                    "udp",
                    deployment.east.initiator,
                    deployment.west.responder,
                    destination_port=5201,
                    generation=generation_two,
                ),
            ]
            return ledger, records

        first_ledger, first = allocate()
        second_ledger, second = allocate()

        self.assertEqual([record.source_port for record in first], [41_000, 41_001])
        self.assertEqual([record.flow_id for record in first], ["fixture-e2e-tcp-0001", "fixture-e2e-udp-0002"])
        self.assertEqual(
            [record.process_generation for record in first],
            ["west-envelope-g0001", "west-envelope-g0002"],
        )
        self.assertEqual([record.as_dict() for record in first], [record.as_dict() for record in second])
        self.assertEqual(first_ledger.records, tuple(first))
        self.assertEqual(second_ledger.records, tuple(second))

    def test_source_port_exhaustion_is_explicit(self) -> None:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-e2e", first_source_port=41_000, last_source_port=41_000)
        generation = ledger.begin_generation("west-envelope")
        ledger.allocate(
            "tcp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=5201,
            generation=generation,
        )
        with self.assertRaisesRegex(e2e.E2EError, "exhausted"):
            ledger.allocate(
                "udp",
                deployment.west.initiator,
                deployment.east.responder,
                destination_port=5201,
                generation=generation,
            )

    def test_vpc_flow_log_parser_filters_the_exact_forward_and_reverse_tuple(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-flow-log")
        flow = ledger.allocate(
            "udp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-envelope"),
        )
        operations = FakeLiveOperations()
        identities = {
            f"{site}-{role}": operations.workload_identity(deployment, site, role)
            for site in e2e.SITES
            for role in e2e.WORKLOAD_ROLES
        }

        def record(path: str, identity: Mapping[str, Any], direction: str, reverse: bool) -> dict[str, Any]:
            source = flow.destination.private_ip if reverse else flow.source.private_ip
            destination = flow.source.private_ip if reverse else flow.destination.private_ip
            source_port = flow.destination_port if reverse else flow.source_port
            destination_port = flow.source_port if reverse else flow.destination_port
            region = deployment.appliance(identity["site"]).region
            line = (
                f"2 123456789012 {identity['interface_id']} {source} {destination} {source_port} {destination_port} "
                f"17 3 300 100 105 ACCEPT OK {deployment.appliance(identity['site']).vpc_id} "
                f"{identity['subnet_id']} {identity['instance_id']} {region} fixture-az {direction} 2 {source} {destination}"
            )
            parsed = e2e.AwsLiveOperations._parse_cloudwatch_flow_log_text(line)[0]
            parsed["site"] = identity["site"]
            parsed["fixture_path"] = path
            return parsed

        records = [
            record("source-egress", identities["west-initiator"], "egress", False),
            record("destination-ingress", identities["east-responder"], "ingress", False),
            record("responder-egress", identities["east-responder"], "egress", True),
            record("initiator-ingress", identities["west-initiator"], "ingress", True),
        ]
        summary = e2e.AwsLiveOperations._flow_log_summary(
            flow,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["forward_matches"], 2)
        self.assertEqual(summary["reverse_matches"], 2)
        self.assertEqual(summary["packet_count"], 12)
        self.assertEqual(summary["byte_count"], 1200)
        self.assertEqual([value["path"] for value in summary["path_evidence"]], [
            "source-egress",
            "destination-ingress",
            "responder-egress",
            "initiator-ingress",
        ])

        too_early = copy.deepcopy(records)
        for value in too_early:
            value["start_epoch"] = 1
            value["end_epoch"] = 2
        self.assertIsNone(
            e2e.AwsLiveOperations._flow_log_summary(
                flow,
                too_early,
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities=identities,
            )
        )

        drop_flow = e2e.FlowRecord(
            flow.flow_id,
            flow.ordinal,
            flow.protocol,
            flow.source,
            flow.destination,
            flow.source_port,
            flow.destination_port,
            flow.process_generation,
            purpose="mtu-oversized",
            expected_result="mtu-drop",
        )
        drop_summary = e2e.AwsLiveOperations._flow_log_summary(
            drop_flow,
            [records[0]],
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )
        self.assertIsNotNone(drop_summary)
        assert drop_summary is not None
        self.assertEqual([value["path"] for value in drop_summary["path_evidence"]], ["source-egress"])
        self.assertEqual(drop_summary["reverse_matches"], 0)
        self.assertIsNone(
            e2e.AwsLiveOperations._flow_log_summary(
                drop_flow,
                [records[0], records[2]],
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities=identities,
            )
        )
        with self.assertRaisesRegex(e2e.FlowLogError, "all four"):
            e2e.AwsLiveOperations._flow_log_summary(
                flow,
                records,
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities={key: value for key, value in identities.items() if key != "east-responder"},
            )

    def test_vpc_flow_log_parser_matches_icmp_without_invented_ports(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-flow-log-icmp")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-envelope"),
        )
        operations = FakeLiveOperations()
        identities = {
            f"{site}-{role}": operations.workload_identity(deployment, site, role)
            for site in e2e.SITES
            for role in e2e.WORKLOAD_ROLES
        }

        def record(identity: Mapping[str, Any], direction: str, reverse: bool) -> dict[str, Any]:
            source = flow.destination.private_ip if reverse else flow.source.private_ip
            destination = flow.source.private_ip if reverse else flow.destination.private_ip
            region = deployment.appliance(identity["site"]).region
            line = (
                f"2 123456789012 {identity['interface_id']} {source} {destination} - - 1 1 84 100 105 ACCEPT OK "
                f"{deployment.appliance(identity['site']).vpc_id} {identity['subnet_id']} {identity['instance_id']} "
                f"{region} fixture-az {direction} 2 {source} {destination}"
            )
            parsed = e2e.AwsLiveOperations._parse_cloudwatch_flow_log_text(line)[0]
            parsed["site"] = identity["site"]
            return parsed

        records = [
            record(identities["west-initiator"], "egress", False),
            record(identities["east-responder"], "ingress", False),
            record(identities["east-responder"], "egress", True),
            record(identities["west-initiator"], "ingress", True),
        ]
        summary = e2e.AwsLiveOperations._flow_log_summary(
            flow,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["flow_tuple"], flow.tuple_dict())
        self.assertNotIn("source_port", summary["flow_tuple"])
        self.assertEqual(summary["reverse_matches"], 2)
        self.assertEqual(summary["correlation_mode"], "icmp-lane-window")
        self.assertFalse(summary["flow_logs_uniquely_identify_flow"])

        oversized = e2e.FlowRecord(
            flow.flow_id,
            flow.ordinal,
            flow.protocol,
            flow.source,
            flow.destination,
            flow.source_port,
            flow.destination_port,
            flow.process_generation,
            purpose="mtu-oversized-icmp",
            expected_result="mtu-drop",
        )
        oversized_summary = e2e.AwsLiveOperations._flow_log_summary(
            oversized,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )
        self.assertIsNotNone(oversized_summary)
        assert oversized_summary is not None
        self.assertEqual(
            [value["path"] for value in oversized_summary["path_evidence"]],
            ["source-egress"],
        )
        self.assertEqual(oversized_summary["forward_matches"], 1)
        self.assertEqual(oversized_summary["reverse_matches"], 0)
        self.assertEqual(oversized_summary["aggregation_overlap_path_matches"], 3)
        self.assertEqual(oversized_summary["unexpected_path_matches"], 0)
        self.assertFalse(oversized_summary["flow_logs_uniquely_identify_flow"])
        e2e._validate_flow_log_evidence(oversized.as_dict(), oversized_summary, identities)

    def test_table_52_route_validator_allows_peer_hosts_but_rejects_lane_ambiguity(self) -> None:
        expected = ["10.20.1.0/24"]

        def validate(routes: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-c", e2e.TAILSCALE_ROUTE_VALIDATOR_SOURCE, json.dumps(expected), "tailscale0"],
                input=json.dumps(routes),
                text=True,
                capture_output=True,
                check=False,
            )

        valid = [
            {"dst": "10.20.1.0/24", "dev": "tailscale0"},
            {"dst": "10.20.1.7/32", "dev": "tailscale0"},
            {"dst": "100.64.0.2/32", "dev": "tailscale0"},
        ]
        self.assertEqual(validate(valid).returncode, 0)
        invalid = {
            "missing": valid[1:],
            "wrong device": [{"dst": "10.20.1.0/24", "dev": "eth0"}],
            "ambiguous": [valid[0], dict(valid[0])],
            "broader overlap": [valid[0], {"dst": "10.20.0.0/16", "dev": "tailscale0"}],
        }
        for name, routes in invalid.items():
            with self.subTest(name=name):
                self.assertNotEqual(validate(routes).returncode, 0)

    def test_tailscale_routes_are_scoped_to_one_expected_appliance_peer(self) -> None:
        expected_hostname = "fixture-live-east"
        expected_routes = ["10.20.1.0/24", "10.20.2.0/24"]

        def validate(status: Mapping[str, Any]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    e2e.TAILSCALE_PEER_ROUTE_VALIDATOR_SOURCE,
                    expected_hostname,
                    json.dumps(expected_routes),
                ],
                input=json.dumps(status),
                text=True,
                capture_output=True,
                check=False,
            )

        valid = {
            "Peer": {
                "expected": {"HostName": expected_hostname, "PrimaryRoutes": list(reversed(expected_routes))},
                "sandbox": {"HostName": "unrelated-peer", "PrimaryRoutes": ["10.99.0.0/16"]},
            }
        }
        self.assertEqual(validate(valid).returncode, 0)

        invalid = {
            "missing": {"Peer": {"sandbox": valid["Peer"]["sandbox"]}},
            "ambiguous": {
                "Peer": {
                    "first": valid["Peer"]["expected"],
                    "second": dict(valid["Peer"]["expected"]),
                }
            },
            "wrong routes": {
                "Peer": {
                    "expected": {"HostName": expected_hostname, "PrimaryRoutes": [expected_routes[0]]},
                }
            },
        }
        for name, status in invalid.items():
            with self.subTest(name=name):
                self.assertNotEqual(validate(status).returncode, 0)

    def test_tcp_mss_capture_is_one_full_exact_outbound_syn(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-syn")
        flow = ledger.allocate(
            "tcp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-mss"),
        )

        command = e2e.AwsLiveOperations._tcp_syn_capture_command(
            flow,
            interface="tailscale0",
            capture_path="/run/envelope-e2e-capture/fixture-syn.pcap",
            duration_seconds=10,
        )

        self.assertIn("tcpdump -U -n", command)
        self.assertIn("-s 0 -c 1", command)
        self.assertIn(f"src host {flow.source.private_ip}", command)
        self.assertIn(f"dst host {flow.destination.private_ip}", command)
        self.assertIn(f"src port {flow.source_port}", command)
        self.assertIn(f"dst port {flow.destination_port}", command)
        self.assertIn("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn", command)
        self.assertNotIn("-c 8", command)
        subprocess.run(["bash", "-n", "-c", command], check=True, capture_output=True, text=True)

    def test_oversized_icmp_capture_is_one_exact_sized_request(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-icmp-capture")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-mtu"),
            purpose="mtu-oversized-icmp",
            expected_result="mtu-drop",
        )

        command = e2e.AwsLiveOperations._icmp_drop_capture_command(
            flow,
            interface="ens5",
            capture_path="/run/envelope-e2e-capture/fixture-icmp.pcap",
            timeout_seconds=20,
        )

        self.assertIn("tcpdump -U -n", command)
        self.assertIn("-s 0 -c 1", command)
        self.assertIn("udp and dst port 6081", command)
        subprocess.run(["bash", "-n", "-c", command], check=True, capture_output=True, text=True)

        client = e2e.AwsLiveOperations._icmp_client_command(
            flow,
            payload_bytes=1253,
            timeout_seconds=20,
            expect_timeout=True,
        )
        self.assertIn("e2e-live-observer icmp-client", client)
        self.assertIn("--payload-bytes 1253", client)
        self.assertIn("--expect-timeout", client)
        self.assertNotIn(" ping ", client)
        subprocess.run(["bash", "-n", "-c", client], check=True, capture_output=True, text=True)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum((data[index] << 8) | data[index + 1] for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_bytes(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)
    header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            7,
            0,
            64,
            protocol,
            0,
            source_bytes,
            destination_bytes,
        )
    )
    struct.pack_into("!H", header, 10, internet_checksum(bytes(header)))
    return bytes(header) + payload


def udp_bytes(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = bytearray(struct.pack("!HHHH", source_port, destination_port, length, 0))
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + b"\0\x11" + struct.pack("!H", length)
    checksum = internet_checksum(pseudo + bytes(header) + payload)
    struct.pack_into("!H", header, 6, checksum or 0xFFFF)
    return bytes(header) + payload


def ethernet_ipv4(packet: bytes) -> bytes:
    return bytes.fromhex("0200000000020200000000010800") + packet


def icmp_bytes(kind: int, identifier: int, sequence: int, payload: bytes = b"icmp-fixture") -> bytes:
    value = bytearray(struct.pack("!BBHHH", kind, 0, 0, identifier, sequence) + payload)
    struct.pack_into("!H", value, 2, internet_checksum(bytes(value)))
    return bytes(value)


def pcap_bytes(frames: list[bytes]) -> bytes:
    value = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        value.extend(struct.pack("<IIII", index + 1, 0, len(frame), len(frame)))
        value.extend(frame)
    return bytes(value)


def geneve_options(cookie: bytes = b"\xde\xad\xbe\xef") -> bytes:
    vpce = struct.pack("!HBB", 0x0108, 1, 2) + bytes.fromhex("1122334455667788")
    flow_cookie = struct.pack("!HBB", 0x0108, 3, 1) + cookie
    return vpce + flow_cookie


def geneve_packet(inner: bytes, *, options: bytes | None = None, vni: int = 0) -> bytes:
    selected = geneve_options() if options is None else options
    return bytes([len(selected) // 4, 0]) + struct.pack("!H", 0x0800) + vni.to_bytes(3, "big") + b"\0" + selected + inner


def directional_capture_fixture(
    flow: e2e.FlowRecord,
    *,
    return_source_port: int = 40_000,
    return_destination_port: int = 6081,
    return_cookie: bytes = b"\xde\xad\xbe\xef",
) -> dict[str, Any]:
    assert flow.source_port is not None and flow.destination_port is not None
    forward_inner_udp = udp_bytes(
        flow.source.private_ip,
        flow.destination.private_ip,
        flow.source_port,
        flow.destination_port,
        b"request",
    )
    reverse_inner_udp = udp_bytes(
        flow.destination.private_ip,
        flow.source.private_ip,
        flow.destination_port,
        flow.source_port,
        b"response",
    )
    forward_inner = ipv4_bytes(flow.source.private_ip, flow.destination.private_ip, 17, forward_inner_udp)
    reverse_inner = ipv4_bytes(flow.destination.private_ip, flow.source.private_ip, 17, reverse_inner_udp)
    forward_outer_payload = geneve_packet(forward_inner)
    return_outer_payload = geneve_packet(reverse_inner, options=geneve_options(return_cookie))
    forward_outer = ipv4_bytes(
        "192.0.2.10",
        "198.51.100.20",
        17,
        udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, forward_outer_payload),
    )
    return_outer = ipv4_bytes(
        "198.51.100.20",
        "192.0.2.10",
        17,
        udp_bytes(
            "198.51.100.20",
            "192.0.2.10",
            return_source_port,
            return_destination_port,
            return_outer_payload,
        ),
    )
    inner_capture = e2e.parse_packet_capture(
        pcap_bytes([ethernet_ipv4(forward_inner), ethernet_ipv4(reverse_inner)])
    )
    empty_capture = e2e.parse_packet_capture(pcap_bytes([]))
    source_underlay = e2e.parse_packet_capture(
        pcap_bytes([ethernet_ipv4(forward_outer), ethernet_ipv4(return_outer)])
    )
    source_site = flow.source.site
    destination_site = flow.destination.site
    return {
        source_site: {
            "underlay": source_underlay,
            "envelope0": copy.deepcopy(inner_capture),
            "tailscale0": copy.deepcopy(inner_capture),
        },
        destination_site: {
            "underlay": copy.deepcopy(empty_capture),
            "envelope0": copy.deepcopy(empty_capture),
            "tailscale0": copy.deepcopy(inner_capture),
        },
    }


def icmp_capture_fixture(flow: e2e.FlowRecord, *, return_identifier: int = 1234) -> dict[str, Any]:
    forward_inner = ipv4_bytes(
        flow.source.private_ip,
        flow.destination.private_ip,
        1,
        icmp_bytes(8, 1234, 1),
    )
    reverse_inner = ipv4_bytes(
        flow.destination.private_ip,
        flow.source.private_ip,
        1,
        icmp_bytes(0, return_identifier, 1),
    )
    forward_geneve = geneve_packet(forward_inner)
    reverse_geneve = geneve_packet(reverse_inner)
    forward_outer = ipv4_bytes(
        "192.0.2.10",
        "198.51.100.20",
        17,
        udp_bytes("192.0.2.10", "198.51.100.20", 40_001, 6081, forward_geneve),
    )
    reverse_outer = ipv4_bytes(
        "198.51.100.20",
        "192.0.2.10",
        17,
        udp_bytes("198.51.100.20", "192.0.2.10", 40_001, 6081, reverse_geneve),
    )
    inner = e2e.parse_packet_capture(pcap_bytes([ethernet_ipv4(forward_inner), ethernet_ipv4(reverse_inner)]))
    empty = e2e.parse_packet_capture(pcap_bytes([]))
    return {
        flow.source.site: {
            "underlay": e2e.parse_packet_capture(
                pcap_bytes([ethernet_ipv4(forward_outer), ethernet_ipv4(reverse_outer)])
            ),
            "envelope0": copy.deepcopy(inner),
            "tailscale0": copy.deepcopy(inner),
        },
        flow.destination.site: {
            "underlay": copy.deepcopy(empty),
            "envelope0": copy.deepcopy(empty),
            "tailscale0": copy.deepcopy(inner),
        },
    }


class PacketCaptureAssertionTest(unittest.TestCase):
    def setUp(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-wire")
        self.flow = ledger.allocate(
            "udp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-cold"),
            purpose="cold",
        )

    def test_binary_packet_fixture_proves_the_aws_return_contract(self) -> None:
        captures = directional_capture_fixture(self.flow)

        summary = e2e.assert_directional_wire_captures("west", [self.flow], captures, raw_deleted=True)

        self.assertTrue(summary["capture_bounded"])
        self.assertTrue(summary["raw_pcaps_deleted"])
        self.assertEqual(len(summary["interfaces"]), 6)
        self.assertEqual(summary["flows"][0]["return_udp_source_port"], 40_000)
        self.assertEqual(summary["flows"][0]["return_udp_destination_port"], 6081)
        self.assertEqual(e2e.scan_evidence(summary), [])

    def test_target_capture_correlates_identical_geneve_ingress_and_return(self) -> None:
        assert self.flow.source_port is not None and self.flow.destination_port is not None
        inner = ipv4_bytes(
            self.flow.source.private_ip,
            self.flow.destination.private_ip,
            17,
            udp_bytes(
                self.flow.source.private_ip,
                self.flow.destination.private_ip,
                self.flow.source_port,
                self.flow.destination_port,
                b"turnaround",
            ),
        )
        payload = geneve_packet(inner)
        ingress = ipv4_bytes(
            "192.0.2.10",
            "198.51.100.20",
            17,
            udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, payload),
        )
        returned = ipv4_bytes(
            "198.51.100.20",
            "192.0.2.10",
            17,
            udp_bytes("198.51.100.20", "192.0.2.10", 40_000, 6081, payload),
        )
        capture = e2e.parse_packet_capture(
            pcap_bytes([ethernet_ipv4(ingress), ethernet_ipv4(returned)])
        )

        evidence = e2e.correlate_geneve_turnaround_capture(
            capture,
            self.flow,
            target_id="i-6123456789abcdef0",
            raw_deleted=True,
        )

        self.assertTrue(evidence["observed"])
        self.assertEqual(evidence["pairs"][0]["inner_packet_sha256"], hashlib.sha256(inner).hexdigest())
        self.assertNotIn("ordered_options", evidence["pairs"][0])
        self.assertEqual(e2e.scan_evidence(evidence), [])

        changed = e2e.parse_packet_capture(
            pcap_bytes(
                [
                    ethernet_ipv4(ingress),
                    ethernet_ipv4(
                        ipv4_bytes(
                            "198.51.100.20",
                            "192.0.2.10",
                            17,
                            udp_bytes(
                                "198.51.100.20",
                                "192.0.2.10",
                                40_000,
                                6081,
                                geneve_packet(inner, options=geneve_options(b"\x00\x00\x00\x01")),
                            ),
                        )
                    ),
                ]
            )
        )
        with self.assertRaisesRegex(e2e.FlowNotObservedError, "no correlated"):
            e2e.correlate_geneve_turnaround_capture(
                changed,
                self.flow,
                target_id="i-6123456789abcdef0",
                raw_deleted=True,
            )

    def test_reversed_udp_ports_and_changed_ordered_options_fail(self) -> None:
        reversed_ports = directional_capture_fixture(
            self.flow,
            return_source_port=6081,
            return_destination_port=40_000,
        )
        with self.assertRaisesRegex(e2e.WireAssertionError, "orientation"):
            e2e.assert_directional_wire_captures("west", [self.flow], reversed_ports, raw_deleted=True)

        changed_options = directional_capture_fixture(self.flow, return_cookie=b"\x00\x00\x00\x01")
        with self.assertRaisesRegex(e2e.WireAssertionError, "options|cookie"):
            e2e.assert_directional_wire_captures("west", [self.flow], changed_options, raw_deleted=True)

    def test_icmp_binary_fixture_has_no_ports_and_requires_one_request_identity(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-wire-icmp")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-cold"),
            purpose="cold",
        )

        summary = e2e.assert_directional_wire_captures(
            "west", [flow], icmp_capture_fixture(flow), raw_deleted=True
        )
        self.assertTrue(summary["flows"][0]["inner_flow_identity_verified"])
        self.assertIsNone(flow.source_port)

        with self.assertRaisesRegex(e2e.WireAssertionError, "ICMP request/reply identity"):
            e2e.assert_directional_wire_captures(
                "west",
                [flow],
                icmp_capture_fixture(flow, return_identifier=999),
                raw_deleted=True,
            )

        source_capture = icmp_capture_fixture(flow)[flow.source.site]["envelope0"]
        source_summary = e2e.summarize_source_workload_capture(
            "west", [flow], source_capture, interface="ens5", raw_deleted=True
        )
        self.assertEqual(source_summary["request_packets"], 1)
        self.assertEqual(source_summary["reply_packets"], 1)
        self.assertTrue(source_summary["raw_pcap_deleted"])

        with self.assertRaisesRegex(e2e.WireAssertionError, "deletion"):
            e2e.summarize_source_workload_capture(
                "west", [flow], source_capture, interface="ens5", raw_deleted=False
            )

    def test_parser_rejects_bad_ipv4_udp_lengths_checksums_and_vni(self) -> None:
        captures = directional_capture_fixture(self.flow)
        # Reconstruct one valid outer frame from the fixture inputs for byte-level mutations.
        assert self.flow.source_port is not None and self.flow.destination_port is not None
        inner_udp = udp_bytes(
            self.flow.source.private_ip,
            self.flow.destination.private_ip,
            self.flow.source_port,
            self.flow.destination_port,
            b"request",
        )
        inner = ipv4_bytes(self.flow.source.private_ip, self.flow.destination.private_ip, 17, inner_udp)
        outer_payload = geneve_packet(inner)
        outer = ipv4_bytes(
            "192.0.2.10",
            "198.51.100.20",
            17,
            udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, outer_payload),
        )
        frame = bytearray(ethernet_ipv4(outer))

        bad_ip = bytearray(frame)
        bad_ip[24] ^= 0x01
        with self.assertRaisesRegex(e2e.WireAssertionError, "IPv4 checksum"):
            e2e.parse_packet_capture(pcap_bytes([bytes(bad_ip)]))

        bad_udp = bytearray(frame)
        bad_udp[40] ^= 0x01
        with self.assertRaisesRegex(e2e.WireAssertionError, "UDP checksum|UDP length"):
            e2e.parse_packet_capture(pcap_bytes([bytes(bad_udp)]))

        nonzero_vni_payload = geneve_packet(inner, vni=1)
        nonzero_vni = ipv4_bytes(
            "192.0.2.10",
            "198.51.100.20",
            17,
            udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, nonzero_vni_payload),
        )
        with self.assertRaisesRegex(e2e.WireAssertionError, "VNI"):
            e2e.parse_packet_capture(pcap_bytes([ethernet_ipv4(nonzero_vni)]))

        with self.assertRaisesRegex(e2e.WireAssertionError, "deletion"):
            e2e.assert_directional_wire_captures("west", [self.flow], captures, raw_deleted=False)


class CaptureControllerTest(unittest.TestCase):
    class FakeSSM:
        def __init__(
            self,
            *,
            fail_inspection: bool = False,
            malformed_summary: bool = False,
            inspection_timeouts: int = 0,
        ) -> None:
            self.fail_inspection = fail_inspection
            self.malformed_summary = malformed_summary
            self.inspection_timeouts = inspection_timeouts
            self.sent: list[e2e.SSMCommand] = []
            self.executed: list[e2e.SSMCommand] = []

        def send(self, command: e2e.SSMCommand, *, timeout_seconds: float = 10.0) -> str:
            self.sent.append(command)
            return f"capture-{len(self.sent)}"

        def wait(self, target: e2e.RemoteTarget, command_id: str, *, timeout_seconds: float) -> e2e.SSMResult:
            return e2e.SSMResult(target, command_id, "Success", 0)

        def cancel(self, target: e2e.RemoteTarget, command_id: str, *, timeout_seconds: float = 5.0) -> bool:
            return True

        def execute(
            self,
            command: e2e.SSMCommand,
            *,
            send_timeout_seconds: float = 10.0,
            wait_timeout_seconds: float | None = None,
            cancel_timeout_seconds: float = 5.0,
        ) -> e2e.SSMResult:
            self.executed.append(command)
            if command.comment == "Envelope E2E capture readiness":
                output = '{"capture_ready":true,"success":true}\n'
            elif command.comment == "Envelope E2E inspect sanitized capture":
                if self.inspection_timeouts > 0:
                    self.inspection_timeouts -= 1
                    raise e2e.SSMTimeout("fixture document-worker timeout")
                if self.fail_inspection:
                    return e2e.SSMResult(command.target, "inspect", "Failed", 2, stderr="fixture parse failure")
                payload = (
                    b"{not-json"
                    if self.malformed_summary
                    else json.dumps(
                        {
                            "file_sha256": "a" * 64,
                            "frame_count": 0,
                            "frames": [],
                            "link_type": 1,
                            "success": True,
                        }
                    ).encode()
                )
                output = base64.b64encode(gzip.compress(payload, mtime=0)).decode()
            elif command.comment == "Envelope E2E delete raw captures":
                output = '{"deleted":true,"success":true}\n'
            elif command.comment == "Envelope E2E explicit appliance readiness":
                output = '{"pid":123,"success":true}\n'
            elif command.comment == "Envelope E2E appliance readiness":
                output = '{"pid":123,"ready":true,"success":true}\n'
            elif command.comment == "Envelope E2E explicit workload readiness":
                output = '{"success":true}\n'
            else:
                output = ""
            return e2e.SSMResult(command.target, f"execute-{len(self.executed)}", "Success", 0, stdout=output)

    def fixture(self, fake: "CaptureControllerTest.FakeSSM") -> tuple[e2e.AwsLiveOperations, e2e.ProtectedDeployment, list[e2e.FlowRecord]]:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        operations = e2e.AwsLiveOperations(
            SimpleNamespace(run_id="fixture-live", sites={}),
            SimpleNamespace(),
            pathlib.Path("/tmp/not-used"),
            ssm=fake,
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        )
        ledger = e2e.FlowLedger("fixture-capture")
        generation = ledger.begin_generation("west-cold")
        flows = [
            ledger.allocate(
                protocol,
                deployment.workloads.west.initiator,
                deployment.workloads.east.responder,
                destination_port=None if protocol == "icmp" else 5201,
                generation=generation,
                purpose="cold",
            )
            for protocol in e2e.PROTOCOLS
        ]
        return operations, deployment, flows

    def test_controller_bounds_all_six_captures_and_deletes_raw_files(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)

        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)
        result = operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(result["raw_deleted"])
        self.assertIsNotNone(result["source_capture"])
        self.assertEqual(result["source_interface"], "ens5")
        self.assertEqual(len(fake.sent), 3)
        for site_paths in handle.paths.values():
            for path in site_paths.values():
                self.assertRegex(
                    path,
                    r"^/run/envelope-e2e-capture/[a-z0-9-]{1,80}-(west|east)-(underlay|envelope0|tailscale0)\.pcap$",
                )
                self.assertNotIn("..", pathlib.PurePosixPath(path).parts)
        self.assertRegex(
            str(handle.source_path),
            r"^/run/envelope-e2e-capture/[a-z0-9-]{1,80}-west-source-icmp\.pcap$",
        )
        for command in fake.sent:
            rendered = command.commands[0]
            expected_count = 1 if "source workload capture" in command.comment else 3
            self.assertEqual(rendered.count("tcpdump"), expected_count)
            self.assertEqual(rendered.count("-c 8"), 1 if expected_count == 1 else 0)
            self.assertEqual(rendered.count("-c 48"), 0 if expected_count == 1 else 3)
            self.assertEqual(
                rendered.count("timeout --signal=TERM --kill-after=2 60s tcpdump"), expected_count
            )
            self.assertNotIn("watchdog_pid", rendered)
            self.assertNotIn('kill -INT "$capture_pid"', rendered)
            self.assertLessEqual(command.timeout_seconds, 315)
        for command in [*fake.sent, *fake.executed]:
            for rendered in command.commands:
                subprocess.run(["bash", "-n", "-c", rendered], check=True, capture_output=True, text=True)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )

    def test_cold_failure_reports_source_workload_packet_counts(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)

        with (
            mock.patch.object(operations, "_restart_envelope", return_value={"west": 101, "east": 202}),
            mock.patch.object(operations, "_metric_snapshots", return_value={}),
            mock.patch.object(operations, "_run_icmp_probe", side_effect=e2e.ProbeError("fixture timeout")),
        ):
            with self.assertRaisesRegex(
                e2e.WireAssertionError,
                r"source workload capture observed 0 ICMP request packet\(s\) and 0 reply packet\(s\)",
            ):
                operations.run_cold_direction(deployment, "west", flows, timeout_seconds=60)

        self.assertEqual(len(operations.capture_diagnostic_events), 1)
        self.assertEqual(operations.capture_diagnostic_events[0]["interface"], "ens5")
        self.assertEqual(operations.capture_diagnostic_events[0]["request_packets"], 0)

    def test_wire_inspector_installer_creates_parent_directory_before_writing(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        operations._install_wire_inspector(deployment.appliance("west"))

        self.assertEqual(len(fake.executed), 1)
        command = fake.executed[0]
        self.assertEqual(command.comment, "Envelope E2E install bounded wire inspector")
        rendered = command.commands[0]
        directory_install = "install -d -o root -g root -m 0755 /opt/envelope"
        temporary_create = "temporary=$(mktemp /opt/envelope/e2e-wire-inspector.tmp.XXXXXX)"
        temporary_write = '> "$temporary"'
        self.assertIn(directory_install, rendered)
        self.assertIn(temporary_create, rendered)
        self.assertIn(temporary_write, rendered)
        self.assertLess(rendered.index(directory_install), rendered.index(temporary_create))
        self.assertLess(rendered.index(temporary_create), rendered.index(temporary_write))
        subprocess.run(["bash", "-n", "-c", rendered], check=True, capture_output=True, text=True)

    def test_appliance_readiness_command_has_balanced_shell_syntax(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        result = operations._appliance_readiness_details(deployment, "west", timeout_seconds=60)

        self.assertEqual(result["pid"], 123)
        command = fake.executed[-1]
        self.assertEqual(command.comment, "Envelope E2E explicit appliance readiness")
        self.assertIn("for unit in tailscaled.service envelope-host-network.service envelope.service", command.commands[0])
        self.assertIn("for tool in tcpdump timeout python3 sha256sum gzip base64", command.commands[0])
        subprocess.run(["bash", "-n", "-c", command.commands[0]], check=True, capture_output=True, text=True)

    def test_all_readiness_commands_require_each_managed_service(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        operations._wait_appliance_ready(deployment.appliance("west"), timeout_seconds=60)
        operations._workload_readiness_details(
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            interface="ens5",
            timeout_seconds=60,
        )

        appliance, workload = fake.executed[-2:]
        self.assertIn("for unit in tailscaled.service envelope-host-network.service envelope.service", appliance.commands[0])
        self.assertIn(
            "for unit in amazon-ssm-agent.service envelope-e2e-agent-tcp.service envelope-e2e-agent-udp.service",
            workload.commands[0],
        )
        self.assertIn("failed_check=source-route", workload.commands[0])
        self.assertIn(".[0].from // .[0].prefsrc // .[0].src", workload.commands[0])
        self.assertIn(".[0].dev == $interface", workload.commands[0])
        self.assertIn("tcpdump sha256sum gzip base64", workload.commands[0])
        for command in (appliance, workload):
            subprocess.run(["bash", "-n", "-c", command.commands[0]], check=True, capture_output=True, text=True)

    def test_workload_source_route_filter_accepts_al2023_from_field(self) -> None:
        route = json.dumps(
            [{"dst": "198.51.100.20", "from": "192.0.2.10", "gateway": "192.0.2.1", "dev": "ens5"}]
        )

        result = subprocess.run(
            [
                "jq",
                "-e",
                "--arg",
                "source",
                "192.0.2.10",
                "--arg",
                "interface",
                "ens5",
                e2e.WORKLOAD_SOURCE_ROUTE_JQ,
            ],
            input=route,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_gwlbe_stabilization_waits_from_the_newest_endpoint_creation(self) -> None:
        clock = {"monotonic": 100.0, "wall": 2_000_000_000.0}
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["monotonic"] += seconds
            clock["wall"] += seconds

        operations = e2e.AwsLiveOperations(
            SimpleNamespace(run_id="fixture-live", sites={}),
            SimpleNamespace(),
            pathlib.Path("/tmp/not-used"),
            ssm=self.FakeSSM(),
            sleep=sleep,
            monotonic=lambda: clock["monotonic"],
            wall_time=lambda: clock["wall"],
        )
        created = dt.datetime.fromtimestamp(clock["wall"] - 240, tz=dt.timezone.utc).isoformat()

        age = operations._wait_for_gwlbe_stability(
            "west",
            [{"CreationTimestamp": created}],
            deadline=clock["monotonic"] + 120,
        )

        self.assertEqual(sleeps, [60.0])
        self.assertEqual(age, e2e.GWLBE_STABILIZATION_SECONDS)

        with self.assertRaisesRegex(e2e.ReadinessError, "readiness deadline"):
            operations._wait_for_gwlbe_stability(
                "west",
                [{"CreationTimestamp": dt.datetime.fromtimestamp(clock["wall"], tz=dt.timezone.utc).isoformat()}],
                deadline=clock["monotonic"] + 30,
            )

    def test_emergency_return_rule_accepts_concurrent_reconciliation(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)
        restored = {"priority": 100, "protocol": "186", "table": "100"}

        with (
            mock.patch.object(operations, "_return_rule_snapshot", side_effect=[[], [restored]]),
            mock.patch.object(operations, "_execute", side_effect=e2e.SSMError("rule already exists")),
        ):
            operations._ensure_return_rule(deployment, "west")

    def test_inspector_failure_still_deletes_every_raw_capture(self) -> None:
        fake = self.FakeSSM(fail_inspection=True)
        operations, deployment, flows = self.fixture(fake)
        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)

        with self.assertRaises(e2e.WireAssertionError):
            operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(handle.stopped)
        self.assertTrue(handle.raw_deleted)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )
        self.assertEqual(
            sum(command.comment == "Envelope E2E inspect sanitized capture" for command in fake.executed),
            1,
        )

    def test_inspector_retries_only_one_ssm_timeout(self) -> None:
        fake = self.FakeSSM(inspection_timeouts=1)
        operations, deployment, _flows = self.fixture(fake)

        summary = operations._inspect_capture_summary(
            deployment.appliance("west"), "/run/envelope-e2e-capture/fixture.pcap"
        )

        self.assertTrue(summary["success"])
        self.assertEqual(
            sum(command.comment == "Envelope E2E inspect sanitized capture" for command in fake.executed),
            2,
        )

        exhausted = self.FakeSSM(inspection_timeouts=2)
        operations, deployment, _flows = self.fixture(exhausted)
        with self.assertRaisesRegex(e2e.SSMTimeout, "document-worker timeout"):
            operations._inspect_capture_summary(
                deployment.appliance("west"),
                "/run/envelope-e2e-capture/fixture.pcap",
            )
        self.assertEqual(
            sum(
                command.comment == "Envelope E2E inspect sanitized capture"
                for command in exhausted.executed
            ),
            2,
        )

    def test_inspector_retry_paths_delete_raw_captures(self) -> None:
        recovered = self.FakeSSM(inspection_timeouts=1)
        operations, deployment, flows = self.fixture(recovered)
        handle = operations._start_directional_captures(
            deployment, "west", flows, timeout_seconds=60
        )

        result = operations._finish_directional_captures(
            deployment, handle, inspect=True
        )

        self.assertTrue(result["raw_deleted"])
        self.assertTrue(handle.raw_deleted)

        exhausted = self.FakeSSM(inspection_timeouts=2)
        operations, deployment, flows = self.fixture(exhausted)
        handle = operations._start_directional_captures(
            deployment, "west", flows, timeout_seconds=60
        )
        with self.assertRaisesRegex(e2e.WireAssertionError, "document-worker timeout"):
            operations._finish_directional_captures(
                deployment, handle, inspect=True
            )
        self.assertTrue(handle.raw_deleted)
        self.assertEqual(
            sum(
                command.comment == "Envelope E2E inspect sanitized capture"
                for command in exhausted.executed
            ),
            2,
        )

    def test_capture_inspection_preserves_protected_control_flow(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)
        handle = operations._start_directional_captures(
            deployment, "west", flows, timeout_seconds=60
        )

        with (
            mock.patch.object(
                operations,
                "_inspect_capture_summary",
                side_effect=e2e.ProtectedHardTimeout("fixture hard deadline"),
            ),
            self.assertRaisesRegex(e2e.ProtectedHardTimeout, "hard deadline"),
        ):
            operations._finish_directional_captures(
                deployment, handle, inspect=True
            )

        self.assertTrue(handle.raw_deleted)

    def test_cold_direction_prioritizes_protected_capture_control_flow(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)
        handle = e2e.DirectionalCaptureHandle("west", {}, {}, {})

        with (
            mock.patch.object(
                operations,
                "_restart_envelope",
                return_value={"west": 101, "east": 202},
            ),
            mock.patch.object(
                operations,
                "_start_directional_captures",
                return_value=handle,
            ),
            mock.patch.object(
                operations,
                "_metric_snapshots",
                return_value={},
            ),
            mock.patch.object(
                operations,
                "_run_icmp_probe",
                side_effect=e2e.ProbeError("fixture probe failure"),
            ),
            mock.patch.object(
                operations,
                "_finish_directional_captures",
                side_effect=e2e.ProtectedHardTimeout("fixture hard deadline"),
            ),
            self.assertRaisesRegex(e2e.ProtectedHardTimeout, "hard deadline"),
        ):
            operations.run_cold_direction(
                deployment, "west", flows, timeout_seconds=60
            )

    def test_cold_direction_does_not_inspect_after_protected_primary_error(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)
        handle = e2e.DirectionalCaptureHandle("west", {}, {}, {})
        finish = mock.Mock(return_value={"raw_deleted": True})

        with (
            mock.patch.object(
                operations,
                "_restart_envelope",
                return_value={"west": 101, "east": 202},
            ),
            mock.patch.object(
                operations,
                "_start_directional_captures",
                return_value=handle,
            ),
            mock.patch.object(
                operations,
                "_metric_snapshots",
                return_value={},
            ),
            mock.patch.object(
                operations,
                "_run_icmp_probe",
                side_effect=e2e.ProtectedHardTimeout("fixture hard deadline"),
            ),
            mock.patch.object(
                operations,
                "_finish_directional_captures",
                finish,
            ),
            self.assertRaisesRegex(e2e.ProtectedHardTimeout, "hard deadline"),
        ):
            operations.run_cold_direction(
                deployment, "west", flows, timeout_seconds=60
            )

        finish.assert_called_once_with(deployment, handle, inspect=False)

    def test_capture_start_rollback_preserves_protected_control_flow(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)

        with (
            mock.patch.object(
                operations,
                "_execute_json",
                side_effect=e2e.SSMError("fixture readiness failure"),
            ),
            mock.patch.object(
                operations,
                "_finish_directional_captures",
                side_effect=e2e.ProtectedTermination("fixture termination"),
            ),
            self.assertRaisesRegex(e2e.ProtectedTermination, "termination"),
        ):
            operations._start_directional_captures(
                deployment, "west", flows, timeout_seconds=60
            )

    def test_summary_parse_failure_still_deletes_every_raw_capture(self) -> None:
        fake = self.FakeSSM(malformed_summary=True)
        operations, deployment, flows = self.fixture(fake)
        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)

        with self.assertRaisesRegex(e2e.WireAssertionError, "capture field summary is invalid"):
            operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(handle.stopped)
        self.assertTrue(handle.raw_deleted)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )
        self.assertEqual(
            sum(command.comment == "Envelope E2E inspect sanitized capture" for command in fake.executed),
            1,
        )

    def test_flow_id_cannot_escape_capture_directory(self) -> None:
        _operations, _deployment, flows = self.fixture(self.FakeSSM())
        flow = flows[0]

        with self.assertRaisesRegex(e2e.E2EError, "path-safe"):
            e2e.FlowRecord(
                flow_id="../../tmp/capture",
                ordinal=flow.ordinal,
                protocol=flow.protocol,
                source=flow.source,
                destination=flow.destination,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                process_generation=flow.process_generation,
                purpose=flow.purpose,
                expected_result=flow.expected_result,
            )


class PrometheusMetricTest(unittest.TestCase):
    def test_parser_and_delta_assertions(self) -> None:
        before = e2e.parse_prometheus_metrics(
            """
            # HELP envelope_packets_total Processed packets.
            envelope_packets_total{protocol="tcp",path="west\\\\east"} 2
            envelope_packets_total{protocol="udp",path="west\\\\east"} 4 1234
            """,
            generation="west-envelope-g0001",
        )
        after = e2e.parse_prometheus_metrics(
            """
            envelope_packets_total{path="west\\\\east",protocol="tcp"} 5
            envelope_packets_total{protocol="udp",path="west\\\\east"} 8
            """,
            generation="west-envelope-g0001",
        )

        self.assertEqual(
            e2e.assert_metric_delta(
                before,
                after,
                "envelope_packets_total",
                labels={"protocol": "tcp"},
                expected=3,
            ),
            3,
        )
        self.assertEqual(e2e.assert_metric_delta(before, after, "envelope_packets_total", minimum=7), 7)

    def test_process_generation_boundary_and_counter_reset_are_rejected(self) -> None:
        before = e2e.parse_prometheus("counter_total 10\n", generation="envelope-g0001")
        restarted = e2e.parse_prometheus("counter_total 1\n", generation="envelope-g0002")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "generation boundary"):
            e2e.metric_delta(before, restarted, "counter_total")

        reset = e2e.parse_prometheus("counter_total 1\n", generation="envelope-g0001")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "decreased"):
            e2e.metric_delta(before, reset, "counter_total")

    def test_duplicate_series_and_malformed_lines_are_rejected(self) -> None:
        with self.assertRaisesRegex(e2e.MetricError, "duplicate series"):
            e2e.parse_prometheus("counter 1\ncounter 2\n", generation="envelope-g0001")
        with self.assertRaisesRegex(e2e.MetricError, "label"):
            e2e.parse_prometheus('counter{bad="unterminated} 1\n', generation="envelope-g0001")

    @staticmethod
    def flow_metrics(
        packet_value: int,
        byte_value: int,
        *,
        drops: int = 0,
        mtu_drops: int = 0,
        mtu_direction: str = "ingress",
        mtu_family: str = "ipv4",
        overrides: dict[str, int] | None = None,
    ) -> str:
        values: dict[str, int] = {name: packet_value for name in e2e._PACKET_METRICS}
        values.update({name: byte_value for name in e2e._BYTE_METRICS})
        for name in e2e._UNEXPECTED_FLOW_METRICS:
            if name not in {
                "geneve_options_validation_errors",
                "gwlb_profile_rejections_total",
                "gwlb_receive_drops_total",
                "gwlb_unsupported_inner_total",
                "gwlb_mtu_drops_total",
            }:
                values.setdefault(name, 0)
        values["drops"] = drops
        values.update(overrides or {})
        lines = [f"{name} {value}" for name, value in sorted(values.items())]
        lines.extend(
            [
                'geneve_options_validation_errors{reason="structural"} 0',
                'gwlb_profile_rejections_total{reason="decode"} 0',
                'gwlb_receive_drops_total{reason="packet_info"} 0',
                'gwlb_unsupported_inner_total{reason="malformed"} 0',
                *[
                    f'gwlb_mtu_drops_total{{direction="{direction}",family="{family}"}} '
                    f'{mtu_drops if (direction, family) == (mtu_direction, mtu_family) else 0}'
                    for direction in ("ingress", "egress")
                    for family in ("ipv4", "ipv6")
                ],
            ]
        )
        return "\n".join(lines) + "\n"

    def test_complete_flow_metric_contract_and_unexpected_growth(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(self.flow_metrics(2, 256), generation="west-pid1"),
            "east": e2e.parse_prometheus(self.flow_metrics(0, 0), generation="east-pid1"),
        }

        summary = e2e.assert_flow_metric_contract(before, after, initiator_site="west", receiver_sessions=1)

        self.assertFalse(summary["unexpected_growth"])
        self.assertEqual(summary["session"]["receiver_sessions"], 1)
        self.assertEqual(summary["malformed_deltas"], {"west": 0, "east": 0})

        bad = dict(after)
        bad["west"] = e2e.parse_prometheus(self.flow_metrics(2, 256, drops=1), generation="west-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_flow_metric_contract(before, bad, initiator_site="west", receiver_sessions=1)

    def test_context_expiration_may_grow_but_eviction_remains_an_error(self) -> None:
        before = {
            site: e2e.parse_prometheus(
                self.flow_metrics(0, 0, overrides={"gwlb_context_expirations_total": 4}),
                generation=f"{site}-pid1",
            )
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(
                self.flow_metrics(2, 256, overrides={"gwlb_context_expirations_total": 5}),
                generation="west-pid1",
            ),
            "east": e2e.parse_prometheus(
                self.flow_metrics(0, 0, overrides={"gwlb_context_expirations_total": 4}),
                generation="east-pid1",
            ),
        }

        summary = e2e.assert_flow_metric_contract(before, after, initiator_site="west", receiver_sessions=1)

        self.assertFalse(summary["unexpected_growth"])
        self.assertNotIn("gwlb_context_expirations_total", summary["unexpected_deltas"]["west"])
        evicted = dict(after)
        evicted["west"] = e2e.parse_prometheus(
            self.flow_metrics(
                2,
                256,
                overrides={"gwlb_context_expirations_total": 5, "gwlb_context_evictions_total": 1},
            ),
            generation="west-pid1",
        )
        with self.assertRaisesRegex(e2e.MetricAssertionError, "evictions"):
            e2e.assert_flow_metric_contract(before, evicted, initiator_site="west", receiver_sessions=1)

    def test_approved_load_still_rejects_generic_drop_growth(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            site: e2e.parse_prometheus(self.flow_metrics(2, 256), generation=f"{site}-pid1")
            for site in e2e.SITES
        }

        summary = e2e.assert_bidirectional_metric_contract(before, after)

        self.assertFalse(summary["unexpected_growth"])
        bad = dict(after)
        bad["west"] = e2e.parse_prometheus(self.flow_metrics(2, 256, drops=1), generation="west-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_bidirectional_metric_contract(before, bad)

    def test_exact_generic_and_mtu_specific_pair_is_required_for_an_oversized_flow(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(
                self.flow_metrics(
                    0,
                    0,
                    drops=1,
                    mtu_drops=1,
                    overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128},
                ),
                generation="west-pid1",
            ),
            "east": e2e.parse_prometheus(self.flow_metrics(0, 0), generation="east-pid1"),
        }

        summary = e2e.assert_mtu_drop_metric_contract(before, after, initiator_site="west")

        self.assertEqual(
            summary["intentional_mtu_drop"],
            {
                "site": "west",
                "generic_drops_delta": 1,
                "mtu_specific": {
                    "metric": "gwlb_mtu_drops_total",
                    "delta": 1,
                    "direction": "ingress",
                    "family": "ipv4",
                },
            },
        )
        self.assertFalse(summary["unexpected_growth"])

        invalid_cases = {
            "missing generic drop": self.flow_metrics(
                0, 0, mtu_drops=1, overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128}
            ),
            "extra generic drop": self.flow_metrics(
                0, 0, drops=2, mtu_drops=1, overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128}
            ),
            "wrong MTU label": self.flow_metrics(
                0,
                0,
                drops=1,
                mtu_drops=1,
                mtu_direction="egress",
                overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128},
            ),
            "other error": self.flow_metrics(
                0,
                0,
                drops=1,
                mtu_drops=1,
                overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128, "gwlb_send_failures_total": 1},
            ),
        }
        for name, west_metrics in invalid_cases.items():
            candidate = {
                "west": e2e.parse_prometheus(west_metrics, generation="west-pid1"),
                "east": after["east"],
            }
            with self.subTest(name=name), self.assertRaises(e2e.MetricAssertionError):
                e2e.assert_mtu_drop_metric_contract(before, candidate, initiator_site="west")

        peer_growth = dict(after)
        peer_growth["east"] = e2e.parse_prometheus(self.flow_metrics(0, 0, drops=1), generation="east-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_mtu_drop_metric_contract(before, peer_growth, initiator_site="west")


def marker(sequence: int, sent: int, received: int, *, connection: str = "flow:c0001") -> e2e.StreamMarker:
    return e2e.StreamMarker(
        flow_id="flow-0001",
        connection_id=connection,
        sequence=sequence,
        sent_monotonic_ns=sent,
        received_monotonic_ns=received,
    )


class StreamAnalyzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mutation = e2e.MutationInterval(100, 200, "restart-west")

    def test_one_socket_with_bounded_mutation_loss_succeeds(self) -> None:
        markers = [
            marker(0, 40, 45),
            marker(1, 80, 90),
            marker(4, 205, 210),
            marker(5, 240, 245),
        ]

        analysis = e2e.analyze_stream_markers(
            markers,
            self.mutation,
            maximum_loss_ns=150,
            attempted_monotonic_ns=(40, 80, 120, 160, 205, 240),
            expected_first_sequence=0,
            expected_last_sequence=5,
        )

        self.assertEqual(analysis.missing_sequences, (2, 3))
        self.assertEqual(len(analysis.loss_windows), 1)
        self.assertEqual(analysis.loss_windows[0].duration_ns, 120)
        self.assertEqual(analysis.connection_id, "flow:c0001")

    def test_loss_outside_interval_or_over_bound_fails(self) -> None:
        outside = [
            marker(0, 40, 45),
            marker(1, 205, 210),
            marker(4, 240, 245),
            marker(5, 260, 265),
        ]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "outside"):
            e2e.analyze_stream_markers(
                outside,
                self.mutation,
                maximum_loss_ns=100,
                attempted_monotonic_ns=(40, 205, 220, 230, 240, 260),
            )

        over_bound = [
            marker(0, 40, 45),
            marker(1, 80, 90),
            marker(4, 205, 210),
            marker(5, 240, 245),
        ]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "exceeds"):
            e2e.analyze_stream_markers(
                over_bound,
                self.mutation,
                maximum_loss_ns=100,
                attempted_monotonic_ns=(40, 80, 120, 160, 205, 240),
            )

    def test_socket_change_is_rejected(self) -> None:
        markers = [marker(0, 40, 45), marker(1, 210, 215, connection="flow:c0002")]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "one long-lived socket"):
            e2e.analyze_stream_markers(
                markers,
                self.mutation,
                maximum_loss_ns=200,
                attempted_monotonic_ns=(40, 210),
            )

    def test_right_censored_interruption_retains_exact_observed_loss(self) -> None:
        markers = [marker(0, 40, 45), marker(1, 80, 90), marker(2, 120, 130)]
        attempts = (40, 80, 120, *range(160, 1720, 10))

        interruption = e2e.analyze_interrupted_stream_markers(
            markers,
            self.mutation,
            protocol="udp",
            expected_marker_count=159,
            sent_marker_count=159,
            attempted_monotonic_ns=attempts,
        )

        self.assertEqual(interruption.sent_marker_count, 159)
        self.assertEqual(interruption.marker_count, 3)
        self.assertTrue(interruption.observation_complete)
        self.assertTrue(interruption.right_censored)

        incomplete_attempts = (40, 80, 120, *range(121, 277))
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "right-censored"):
            e2e.analyze_interrupted_stream_markers(
                markers,
                e2e.MutationInterval(100, 1000, "restart-west"),
                protocol="udp",
                expected_marker_count=159,
                sent_marker_count=159,
                attempted_monotonic_ns=incomplete_attempts,
            )
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "contiguous"):
            e2e.analyze_interrupted_stream_markers(
                [markers[0], marker(2, 120, 130)],
                self.mutation,
                protocol="udp",
                expected_marker_count=159,
                sent_marker_count=159,
                attempted_monotonic_ns=attempts,
            )
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "acknowledgement during"):
            e2e.analyze_interrupted_stream_markers(
                [marker(0, 40, 45), marker(1, 70, 80)],
                self.mutation,
                protocol="udp",
                expected_marker_count=159,
                sent_marker_count=159,
                attempted_monotonic_ns=(40, 70, *range(120, 1690, 10)),
            )
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "bounds"):
            e2e.analyze_interrupted_stream_markers(
                markers,
                self.mutation,
                protocol="tcp",
                expected_marker_count=159,
                sent_marker_count=3,
                attempted_monotonic_ns=(40, 80, 120),
            )

        with self.assertRaisesRegex(e2e.StreamAnalysisError, "right-censored"):
            e2e.analyze_interrupted_stream_markers(
                markers,
                self.mutation,
                protocol="udp",
                expected_marker_count=159,
                sent_marker_count=159,
                attempted_monotonic_ns=(40, 80, 120, *range(210, 1770, 10)),
            )


def evidence_fixture() -> dict[str, Any]:
    deployment = parsed_deployment()
    ledger = e2e.FlowLedger("fixture-e2e", first_source_port=42_000, last_source_port=42_010)
    generation = ledger.begin_generation("west-envelope")
    ledger.allocate(
        "tcp",
        deployment.west.initiator,
        deployment.east.responder,
        destination_port=5201,
        generation=generation,
    )
    analysis = e2e.analyze_stream_markers(
        [marker(0, 40, 45), marker(1, 210, 215)],
        e2e.MutationInterval(100, 200, "restart-west"),
        maximum_loss_ns=200,
        attempted_monotonic_ns=(40, 210),
        expected_first_sequence=0,
        expected_last_sequence=1,
    )
    return e2e.evidence_document(
        "fixture-e2e",
        deployment,
        ledger.records,
        [{"name": "cross-region-tcp", "passed": True, "summary": "probe acknowledged"}],
        generated_at="2026-08-20T12:00:00Z",
        metrics=[{"delta": 2, "generation": generation.label, "name": "envelope_packets_total"}],
        streams=[analysis],
        metadata={"suite": "offline-core"},
    )


class EvidenceTest(unittest.TestCase):
    def test_atomic_writer_validator_and_cli(self) -> None:
        document = evidence_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "nested" / "evidence.json"
            returned = e2e.write_evidence(path, document)

            self.assertEqual(returned, path)
            self.assertEqual(e2e.load_evidence(path), document)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "aws_two_region_e2e.py"), "validate-evidence", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["valid"])

    def test_credentials_and_raw_material_are_rejected_without_overwriting(self) -> None:
        document = evidence_fixture()
        secret = "ASIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "evidence.json"
            e2e.write_evidence(path, document)
            original = path.read_bytes()

            credential = copy.deepcopy(document)
            credential["metadata"] = {"token": secret}
            with self.assertRaises(e2e.EvidenceError) as raised:
                e2e.write_evidence(path, credential)
            self.assertNotIn(secret, str(raised.exception))
            self.assertEqual(path.read_bytes(), original)

            for key in ("packet_payload", "terraform_state", "user-data"):
                unsafe = copy.deepcopy(document)
                unsafe["metadata"] = {key: {}}
                with self.subTest(key=key), self.assertRaisesRegex(e2e.EvidenceError, "raw packet/state/user-data"):
                    e2e.validate_evidence(unsafe)

    def test_scanner_reports_paths_but_not_secret_values(self) -> None:
        secret = "AKIA" + "ABCDEFGHIJKLMNOP"
        findings = e2e.scan_evidence(
            {"safe": [{"value": secret}], "payload": "bytes", "AWS_SECRET_ACCESS_KEY": "forty-character-value"}
        )
        rendered = " ".join(findings)
        self.assertIn("$.safe[0].value", rendered)
        self.assertIn("$.payload", rendered)
        self.assertIn("$.AWS_SECRET_ACCESS_KEY", rendered)
        self.assertNotIn(secret, rendered)


class FakeProtectedLifecycle:
    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.calls: list[str] = []
        self.cleanup_calls = 0

    def claim(
        self, raw_deployment: dict[str, Any], deployment: e2e.ProtectedDeployment
    ) -> dict[str, Any]:
        self.calls.append("claim")
        if self.failure == "claim":
            raise e2e.ConcurrentRunError("another durable E2E claim is active")
        if self.failure == "claim-persistence":
            raise e2e.ClaimPersistenceError(
                "durable E2E claim was not committed; deployment cleanup remains authorized"
            )
        if self.failure == "claim-ambiguous":
            raise e2e.AmbiguousOwnershipError(
                "durable E2E ownership is ambiguous after bounded recovery; cleanup is prohibited"
            )
        return {
            "manifest_phase": "ready",
            "saved_plan_applied_once": True,
            "load_profile_approved_before_apply": True,
        }

    def verify_no_drift(self, stage: str) -> dict[str, Any]:
        self.calls.append(f"drift-{stage}")
        if self.failure == f"drift-{stage}":
            raise e2e.DriftError(f"{stage} drift")
        return {"clean": True, "stage": stage}

    def finish(self, passed: bool) -> dict[str, Any]:
        self.calls.append(f"finish-{passed}")
        if self.failure == "finish":
            raise e2e.LifecycleError("durable finish rejected")
        if self.failure == "finish-persistence":
            raise e2e.ClaimPersistenceError(
                "durable E2E result was not committed; owned-claim cleanup handoff remains authorized"
            )
        if self.failure == "finish-ambiguous":
            raise e2e.AmbiguousOwnershipError(
                "durable E2E ownership is ambiguous after bounded recovery; cleanup is prohibited"
            )
        return {"finish": "persisted"}

    def cleanup(self) -> dict[str, Any]:
        self.calls.append("cleanup")
        self.cleanup_calls += 1
        if self.failure == "cleanup":
            raise e2e.LifecycleError("protected cleanup failed")
        return {"removed": True}


class FakeLiveOperations:
    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.calls: list[str] = []
        self.stop_calls = 0
        self.flow_windows: dict[str, dict[str, int]] = {}

    def record_flow_windows(self, flows: Sequence[e2e.FlowRecord]) -> None:
        now = int(time.time())
        for flow in flows:
            self.flow_windows[flow.flow_id] = {"start_epoch": now, "end_epoch": now}

    @staticmethod
    def workload_identity(deployment: e2e.ProtectedDeployment, site: str, role: str) -> dict[str, Any]:
        target = deployment.workloads.target(site, role)
        identity_index = e2e.SITES.index(site) * 2 + e2e.WORKLOAD_ROLES.index(role)
        return {
            "site": site,
            "role": role,
            "private_ip": target.private_ip,
            "instance_id": target.instance_id,
            "interface_id": f"eni-{identity_index}123456789abcdef0",
            "subnet_id": target.subnet_id,
            "flow_directions": ["egress", "ingress"],
        }

    @staticmethod
    def probe(flow: e2e.FlowRecord) -> dict[str, Any]:
        digest = hashlib.sha256(flow.flow_id.encode()).hexdigest()
        if flow.protocol == "icmp":
            return {
                "flow_id": flow.flow_id,
                "protocol": "icmp",
                "source_ip": flow.source.private_ip,
                "source_port": None,
                "destination_ip": flow.destination.private_ip,
                "destination_port": None,
                "payload_sha256": digest,
                "payload_bytes": 56,
                "icmp_request_type": 8,
                "icmp_reply_type": 0,
                "response_timeout_seconds": 30,
                "receiver": {
                    "reply_source_ip": flow.destination.private_ip,
                    "source_identity_verified": True,
                },
                "success": True,
            }
        return {
            "flow_id": flow.flow_id,
            "protocol": flow.protocol,
            "source_ip": flow.source.private_ip,
            "source_port": flow.source_port,
            "destination_ip": flow.destination.private_ip,
            "destination_port": flow.destination_port,
            "payload_sha256": digest,
            "payload_bytes": 64,
            "response_timeout_seconds": 30,
            "receiver": {
                "flow_id": flow.flow_id,
                "payload_sha256": digest,
                "source_ip": flow.source.private_ip,
                "source_port": flow.source_port,
                "receives": 1,
                "duplicates": 0,
                "sessions": 1,
            },
            "success": True,
        }

    @staticmethod
    def metrics(flow: e2e.FlowRecord, mode: str = "normal") -> dict[str, Any]:
        if mode == "bidirectional":
            return {
                "packet_deltas": {
                    site: {name: 20 for name in e2e._PACKET_METRICS} for site in e2e.SITES
                },
                "byte_deltas": {
                    site: {name: 4096 for name in e2e._BYTE_METRICS} for site in e2e.SITES
                },
                "unexpected_deltas": {
                    site: {name: 0 for name in e2e._UNEXPECTED_FLOW_METRICS} for site in e2e.SITES
                },
                "unexpected_growth": False,
            }
        packet = {name: 2 for name in e2e._PACKET_METRICS}
        byte = {name: 128 for name in e2e._BYTE_METRICS}
        unexpected = {
            site: {name: 0 for name in e2e._UNEXPECTED_FLOW_METRICS} for site in e2e.SITES
        }
        sessions: int | None = None if flow.protocol == "icmp" else 1
        intentional: dict[str, Any] = {}
        if mode == "mtu-drop":
            packet = {name: (2 if name == "geneve_rx_packets" else 0) for name in e2e._PACKET_METRICS}
            byte = {name: (128 if name == "geneve_rx_bytes" else 0) for name in e2e._BYTE_METRICS}
            sessions = 0
            unexpected[flow.source.site]["drops"] = 1
            unexpected[flow.source.site]["gwlb_mtu_drops_total"] = 1
            intentional = {
                "intentional_mtu_drop": {
                    "site": flow.source.site,
                    "generic_drops_delta": 1,
                    "mtu_specific": {
                        "metric": "gwlb_mtu_drops_total",
                        "delta": 1,
                        "direction": "ingress",
                        "family": "ipv4",
                    },
                }
            }
        return {
            "initiator_site": flow.source.site,
            "packet_deltas": packet,
            "byte_deltas": byte,
            "session": {
                "receiver_sessions": sessions,
                "receiver_identity_verified": True,
                "integrity_metric_deltas": {name: 0 for name in e2e._SESSION_INTEGRITY_METRICS},
            },
            "malformed_deltas": {"west": 0, "east": 0},
            "unexpected_deltas": unexpected,
            "unexpected_growth": False,
            **intentional,
        }

    def verify_readiness_and_topology(
        self, deployment: e2e.ProtectedDeployment, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append("readiness")
        appliance_checks: dict[str, dict[str, Any]] = {}
        workload_checks: dict[str, dict[str, Any]] = {}
        for site in e2e.SITES:
            runtime = deployment.runtime(site)
            appliance_checks[site] = {
                gate: True for gate in e2e._APPLIANCE_READINESS_GATES
            }
            appliance_checks[site].update(
                {
                    "advertised_routes": sorted((*runtime.gwlb_return_cidrs, *runtime.local_delivery_cidrs)),
                    "accepted_routes": sorted(runtime.remote_tailnet_cidrs),
                    "accepted_route_peer": f"fixture-live-{'east' if site == 'west' else 'west'}",
                    "links": [runtime.underlay_interface, runtime.tailscale_iface, runtime.tun_name],
                    "target_status": "healthy",
                    "gwlbe_endpoint_age_seconds": e2e.GWLBE_STABILIZATION_SECONDS,
                }
            )
            for role in e2e.WORKLOAD_ROLES:
                workload_checks[f"{site}-{role}"] = {
                    gate: True for gate in e2e._WORKLOAD_READINESS_GATES
                }
                workload_checks[f"{site}-{role}"].update(self.workload_identity(deployment, site, role))
        if self.failure == "readiness":
            appliance_checks["west"]["cloud_init_complete"] = False
        if self.failure and self.failure.startswith("readiness-appliance-"):
            appliance_checks["west"][self.failure.removeprefix("readiness-appliance-")] = False
        if self.failure and self.failure.startswith("readiness-workload-"):
            workload_checks["west-initiator"][self.failure.removeprefix("readiness-workload-")] = False
        return {
            "appliance_count": 2,
            "workload_count": 4,
            "all_hosts_ready": True,
            "directional_routes_exact": True,
            "lane_routes": [{"exact": True}] * 4,
            "appliance_checks": appliance_checks,
            "workload_checks": workload_checks,
        }

    def start_flow_logs(
        self, deployment: e2e.ProtectedDeployment, *, timeout_seconds: int
    ) -> object:
        self.calls.append("flow-start")
        if self.failure == "flow-start":
            raise e2e.FlowLogError("flow log startup rejected")
        return object()

    def run_cold_direction(
        self,
        deployment: e2e.ProtectedDeployment,
        source_site: str,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append(f"cold-{source_site}")
        self.record_flow_windows(flows)
        if self.failure == "interrupt":
            raise KeyboardInterrupt("simulated runner interruption")
        if self.failure == "acceptance-timeout":
            raise TimeoutError("simulated active acceptance timer")
        if self.failure == "active-interrupt":
            raise InterruptedError("simulated active acceptance interruption")
        results = []
        for flow in flows:
            probe = self.probe(flow)
            metrics = self.metrics(flow)
            if self.failure == "probe-duplicates" and flow.protocol == "udp":
                probe["receiver"]["duplicates"] = 1
                probe["receiver"]["receives"] = 2
            if self.failure == "icmp-identity" and flow.protocol == "icmp":
                probe["receiver"]["reply_source_ip"] = "10.0.0.1"
            if self.failure == "metrics":
                metrics["unexpected_growth"] = True
            results.append({"flow_id": flow.flow_id, "probe": probe, "metrics": metrics})
        wire_flows = [
            {
                "flow_id": flow.flow_id,
                "outer_ipv4_checksums": "valid",
                "outer_udp_checksums": ["valid", "valid"],
                "outer_ips_swapped": True,
                "original_gwlb_source_port": 40000 + flow.ordinal,
                "return_udp_source_port": 40000 + flow.ordinal,
                "return_udp_destination_port": 6081,
                "return_source_port_preserved": True,
                "inner_flow_identity_verified": True,
                "vni": 0,
                "ordered_options_sha256": "a" * 64,
                "flow_cookie_sha256": "b" * 64,
                "ordered_options_identical": True,
                "path_packet_counts": {
                    f"{source_site}:envelope0": 2,
                    f"{source_site}:tailscale0": 2,
                    f"{'east' if source_site == 'west' else 'west'}:envelope0": 0,
                    f"{'east' if source_site == 'west' else 'west'}:tailscale0": 2,
                },
                "responder_gwlb_matching_packets": 0,
            }
            for flow in flows
        ]
        if self.failure == "wire-port":
            wire_flows[0]["return_udp_destination_port"] = 40000
        if self.failure == "wire-options":
            wire_flows[0]["ordered_options_identical"] = False
        if self.failure == "wire-checksum":
            wire_flows[0]["outer_ipv4_checksums"] = "invalid"
        return {
            "context": {
                "both_processes_restarted": True,
                "matching_return_context_before_first_packet": self.failure == "cold-context",
                "matching_flow_ids_absent_before": [flow.flow_id for flow in flows],
                "allocation_unique_in_generation": True,
                "targets_healthy_before_first_packet": True,
                "process_ids": {"west": 101, "east": 202},
                "empty_context_proof": "new-process-generations-have-no-process-local-return-contexts",
            },
            "results": results,
            "wire": {
                "direction": f"{source_site}-to-{'east' if source_site == 'west' else 'west'}",
                "source_site": source_site,
                "destination_site": "east" if source_site == "west" else "west",
                "capture_bounded": True,
                "raw_pcaps_deleted": self.failure != "wire-cleanup",
                "raw_pcaps_retained": False,
                "interfaces": [
                    {"site": site, "interface": interface, "file_sha256": "c" * 64, "frame_count": 2}
                    for site in e2e.SITES
                    for interface in ("envelope0", "tailscale0", "underlay")
                ],
                "flows": wire_flows,
            },
        }

    def run_mtu_transport(
        self,
        deployment: e2e.ProtectedDeployment,
        profile: e2e.ApprovedLoadProfile,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append("mtu")
        self.record_flow_windows(flows)
        selected = flows[:-1] if self.failure == "mtu-missing" else flows
        results = []
        for flow in selected:
            mode = "mtu-drop" if flow.expected_result == "mtu-drop" else "normal"
            metrics = self.metrics(flow, mode)
            if self.failure == "mtu-drop-metric" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["gwlb_mtu_drops_total"] = 0
            if self.failure == "mtu-generic-drop-metric" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["drops"] = 0
            if self.failure == "mtu-extra-generic-drop" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["drops"] = 2
            if self.failure == "mtu-peer-drop" and mode == "mtu-drop":
                peer = "east" if flow.source.site == "west" else "west"
                metrics["unexpected_deltas"][peer]["drops"] = 1
            if self.failure == "mtu-other-error" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["gwlb_send_failures_total"] = 1
            value: dict[str, Any] = {"flow_id": flow.flow_id, "metrics": metrics}
            if flow.expected_result == "mtu-drop":
                value.update(
                    {
                        "reply_received": self.failure == "mtu-oversized-reply",
                        "pmtu_icmp_expected": False,
                    }
                )
                if flow.protocol == "icmp":
                    value["capture"] = {
                        "interface": deployment.runtime(flow.source.site).underlay_interface,
                        "file_sha256": "f" * 64,
                        "icmp_checksum": "valid",
                        "raw_pcap_deleted": True,
                        "request_count": 1,
                        "inner_bytes": profile.safe_inner_mtu + 1,
                        "payload_bytes": profile.safe_inner_mtu - 27,
                        "payload_sha256": "a" * 64,
                    }
                    if self.failure == "mtu-icmp-capture":
                        value["capture"]["request_count"] = 2
            elif flow.protocol in {"icmp", "udp"}:
                value["probe"] = self.probe(flow)
                value["probe"]["payload_bytes"] = profile.safe_inner_mtu - 28
            else:
                value["transport"] = {"completed": True}
            results.append(value)
        directions = [
            {
                "source_site": site,
                "destination_site": "east" if site == "west" else "west",
                "inner_mtu": 1280,
                "safe_icmp_inner_bytes": 1280,
                "safe_udp_inner_bytes": 1280,
                "oversized_icmp_inner_bytes": 1281,
                "oversized_udp_inner_bytes": 1281,
                "tcp_mss": 1300 if self.failure == "mtu-mss" else 1240,
                "tcp_mss_maximum": 1240,
                "tcp_syn_capture_sha256": "e" * 64,
                "tcp_syn_raw_pcap_deleted": True,
                "sustained_tcp_bytes": profile.minimum_sustained_tcp_bytes,
                "sustained_tcp_duration_seconds": profile.sustained_tcp_duration_seconds,
                "pmtu_icmp_expected": False,
                "flow_ids": [flow.flow_id for flow in flows if flow.source.site == site],
            }
            for site in e2e.SITES
        ]
        if self.failure == "mtu-safe":
            directions[0]["safe_udp_inner_bytes"] = 1279
        return {"results": results, "directions": directions}

    def run_approved_load(
        self,
        deployment: e2e.ProtectedDeployment,
        profile: e2e.ApprovedLoadProfile,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append("load")
        self.record_flow_windows(flows)
        iperf = [
            {
                "flow_id": flow.flow_id,
                "completed": True,
                "throughput_mbps": 0.5 if self.failure == "load-throughput" else profile.minimum_throughput_mbps,
                "duration_seconds": profile.iperf_duration_seconds,
                "bytes": profile.minimum_sustained_tcp_bytes,
                "syn_mss": profile.maximum_tcp_mss,
                "syn_capture_sha256": "d" * 64,
                "raw_pcap_deleted": True,
            }
            for flow in flows
            if flow.purpose == "iperf3"
        ]
        concurrent = [
            {
                "flow_id": flow.flow_id,
                "completed": True,
                "duration_seconds": profile.concurrent_duration_seconds,
                "loss_percent": 2.0 if self.failure == "load-loss" else 0.0,
                "p99_latency_ms": 200.0 if self.failure == "load-latency" else 1.0,
                "protocol": flow.protocol,
                "source_port": flow.source_port,
                "sent": 10,
                "received": 10 if self.failure != "load-loss" else 9,
            }
            for flow in flows
            if flow.purpose.startswith("concurrent-")
        ]
        metrics = self.metrics(flows[0], "bidirectional")
        if self.failure == "load-metrics":
            metrics["unexpected_deltas"]["west"]["drops"] = 1
        return {
            "profile_sha256": "0" * 64 if self.failure == "load-profile" else profile.sha256,
            "iperf3": iperf,
            "concurrent": concurrent,
            "metrics": metrics,
        }

    @staticmethod
    def continuity() -> dict[str, Any]:
        return {"bounded": True, "maximum_loss_ns": 1_000_000_000, "missing_markers": 0}

    def run_route_mutation(
        self,
        deployment: e2e.ProtectedDeployment,
        flow: e2e.FlowRecord,
        *,
        timeout_seconds: int,
        maximum_loss_ns: int,
    ) -> dict[str, Any]:
        self.calls.append("route")
        self.record_flow_windows((flow,))
        if self.failure == "route":
            raise e2e.ResilienceError("route restoration differs")
        observed = self.failure != "route-readiness"
        repair_delta = 0 if self.failure in {"route-readiness", "route-zero-repair"} else 1
        return {
            "passed": True,
            "restored": True,
            "continuity": self.continuity(),
            "stream": {"flow_id": flow.flow_id, "bounded": True},
            "readiness_during_drift": {
                "before_repair": True,
                "exact_rule_missing": True,
                "drift_observed": observed,
                "unhealthy": False,
                "host_preflight_failed": observed,
                "routing_drift_repairs_delta": repair_delta,
                "missing_cidr": deployment.workloads.west.initiator.cidr,
                "reason": "owned-return-rule-missing",
            },
            "repair_metric_delta": repair_delta,
            "metrics": self.metrics(flow),
        }

    def run_service_stop(
        self, deployment: e2e.ProtectedDeployment, flow: e2e.FlowRecord, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append("service")
        self.record_flow_windows((flow,))
        value = {
            "passed": True,
            "restored": True,
            "recovery": {"new_cold_flow": True},
            "probe": self.probe(flow),
            "metrics": self.metrics(flow),
            "target_transition": ["healthy", "unhealthy", "healthy"],
            "process_generation_changed": True,
        }
        if self.failure == "service":
            value["recovery"] = {"new_cold_flow": False}
        return value

    def run_ec2_reboot(
        self, deployment: e2e.ProtectedDeployment, site: str, flow: e2e.FlowRecord, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append(f"reboot-{site}")
        self.record_flow_windows((flow,))
        if self.failure in {"reboot", f"reboot-{site}"}:
            raise e2e.ResilienceError("boot generation unchanged")
        return {
            "passed": True,
            "restored": True,
            "recovery": {"new_cold_flow": True},
            "probe": self.probe(flow),
            "site": site,
            "metrics": self.metrics(flow),
            "boot_generation_changed": True,
            "process_generation_changed": True,
            "target_recovered_healthy": True,
            "persistent_configuration_recovered": True,
        }

    def run_tailscale_withdrawal(
        self,
        deployment: e2e.ProtectedDeployment,
        flow: e2e.FlowRecord,
        *,
        timeout_seconds: int,
        maximum_loss_ns: int,
    ) -> dict[str, Any]:
        self.calls.append("tailscale")
        self.record_flow_windows((flow,))
        return {
            "passed": True,
            "restored": True,
            "continuity": self.continuity(),
            "credential_rotation": self.failure == "tailscale-rotation",
            "exact_routes_withdrawn": self.failure != "tailscale-routes",
            "withdrawn_cidrs": sorted(deployment.runtime("west").remote_tailnet_cidrs),
            "restored_cidrs": sorted(deployment.runtime("west").remote_tailnet_cidrs),
            "stream": {"flow_id": flow.flow_id, "bounded": True},
            "metrics": self.metrics(flow),
        }

    def capture_flow_logs(
        self,
        handle: object,
        deployment: e2e.ProtectedDeployment,
        flows: tuple[e2e.FlowRecord, ...],
        *,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        self.calls.append("flow-capture")
        selected = flows[:-1] if self.failure == "flow-missing" else flows
        values: list[dict[str, Any]] = []
        for flow in selected:
            icmp_drop = flow.protocol == "icmp" and flow.expected_result == "mtu-drop"
            source = self.workload_identity(deployment, flow.source.site, flow.source.role)
            destination = self.workload_identity(deployment, flow.destination.site, flow.destination.role)
            specs = (
                [("source-egress", source, "egress")]
                if flow.expected_result == "mtu-drop"
                else [
                    ("source-egress", source, "egress"),
                    ("destination-ingress", destination, "ingress"),
                    ("responder-egress", destination, "egress"),
                    ("initiator-ingress", source, "ingress"),
                ]
            )
            paths = [
                {
                    "path": name,
                    "site": identity["site"],
                    "role": identity["role"],
                    "flow_direction": direction,
                    "instance_id": identity["instance_id"],
                    "interface_id": identity["interface_id"],
                    "subnet_id": identity["subnet_id"],
                    "matches": 1,
                    "packet_count": 1,
                    "byte_count": 64,
                }
                for name, identity, direction in specs
            ]
            values.append({
                "flow_id": flow.flow_id,
                "accepted": True,
                "flow_tuple": flow.tuple_dict(),
                "forward_matches": 1 if flow.expected_result == "mtu-drop" else 2,
                "reverse_matches": 0 if flow.expected_result == "mtu-drop" else 2,
                "reverse_required": flow.expected_result == "success",
                "packet_count": len(paths),
                "byte_count": 64 * len(paths),
                "phase": e2e._flow_phase(flow.as_dict()).value,
                "window": {
                    "start_epoch": self.flow_windows[flow.flow_id]["start_epoch"],
                    "end_epoch": self.flow_windows[flow.flow_id]["end_epoch"],
                    "aggregation_allowance_seconds": 60,
                },
                "path_evidence": paths,
                "unexpected_path_matches": 0,
                "aggregation_overlap_path_matches": 3 if icmp_drop else 0,
                "correlation_mode": "icmp-lane-window" if flow.protocol == "icmp" else "transport-5-tuple-window",
                "flow_logs_uniquely_identify_flow": flow.protocol != "icmp",
                "aws_aggregation_limitation": (
                    "icmp-records-omit-ports-and-may-aggregate-repeated-tuples"
                    if flow.protocol == "icmp"
                    else None
                ),
                "process_generation": flow.process_generation,
                "unique_identity_evidence": (
                    ["process-generation", "mtu-request-capture", "failed-application-reply", "mtu-drop-metrics"]
                    if icmp_drop
                    else ["process-generation", "application-reply"]
                    if flow.protocol == "icmp"
                    else ["transport-ports", "process-generation"]
                ),
            })
        if values and self.failure == "flow-wrong-eni":
            values[0]["path_evidence"][0]["interface_id"] = "eni-fffffffffffffffff"
        if values and self.failure == "flow-wrong-direction":
            values[0]["path_evidence"][0]["flow_direction"] = "ingress"
        if values and self.failure == "flow-window":
            values[0]["window"]["end_epoch"] = values[0]["window"]["start_epoch"] + 7201
        if self.failure == "flow-false-reverse":
            dropped = next(value for value in values if value["reverse_required"] is False)
            dropped["unexpected_path_matches"] = 1
        if self.failure == "flow-icmp-unique":
            icmp = next(
                value
                for value in values
                if value["correlation_mode"] == "icmp-lane-window"
            )
            icmp["flow_logs_uniquely_identify_flow"] = True
        return values

    def stop_flow_logs(self, handle: object, *, timeout_seconds: int) -> dict[str, Any]:
        self.calls.append("flow-stop")
        self.stop_calls += 1
        if self.failure == "flow-stop":
            raise e2e.FlowLogError("temporary flow log rollback failed")
        return {"stopped": True, "ownership_preserved": True}

    def collect_diagnostics(self, deployment: e2e.ProtectedDeployment | None) -> dict[str, Any]:
        self.calls.append("diagnostics")
        return {"collection": "complete", "hosts": 6}


class ReadinessGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.deployment = e2e.parse_protected_deployment_output(protected_output())
        self.operations = FakeLiveOperations()
        self.summary = self.operations.verify_readiness_and_topology(self.deployment, timeout_seconds=30)

    def test_every_appliance_and_workload_component_is_required(self) -> None:
        e2e._validate_readiness_summary(self.deployment, self.summary, run_id="fixture-live")
        for gate in e2e._APPLIANCE_READINESS_GATES:
            candidate = copy.deepcopy(self.summary)
            candidate["appliance_checks"]["west"][gate] = False
            with self.subTest(kind="appliance", gate=gate), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")
        for gate in e2e._WORKLOAD_READINESS_GATES:
            candidate = copy.deepcopy(self.summary)
            candidate["workload_checks"]["east-responder"][gate] = False
            with self.subTest(kind="workload", gate=gate), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")

    def test_exact_routes_links_target_and_source_identity_are_required(self) -> None:
        mutations = []
        advertised = copy.deepcopy(self.summary)
        advertised["appliance_checks"]["west"]["advertised_routes"].append("10.99.0.0/24")
        mutations.append(advertised)
        accepted = copy.deepcopy(self.summary)
        accepted["appliance_checks"]["east"]["accepted_routes"] = []
        mutations.append(accepted)
        peer = copy.deepcopy(self.summary)
        peer["appliance_checks"]["west"]["accepted_route_peer"] = "unrelated-peer"
        mutations.append(peer)
        links = copy.deepcopy(self.summary)
        links["appliance_checks"]["west"]["links"] = ["ens5", "tailscale0"]
        mutations.append(links)
        target = copy.deepcopy(self.summary)
        target["appliance_checks"]["east"]["target_status"] = "initial"
        mutations.append(target)
        source = copy.deepcopy(self.summary)
        source["workload_checks"]["west-initiator"]["private_ip"] = "10.10.1.99"
        mutations.append(source)
        missing_eni = copy.deepcopy(self.summary)
        missing_eni["workload_checks"]["east-responder"].pop("interface_id")
        mutations.append(missing_eni)
        duplicate_eni = copy.deepcopy(self.summary)
        duplicate_eni["workload_checks"]["east-responder"]["interface_id"] = duplicate_eni["workload_checks"]["west-initiator"]["interface_id"]
        mutations.append(duplicate_eni)
        young_endpoint = copy.deepcopy(self.summary)
        young_endpoint["appliance_checks"]["west"]["gwlbe_endpoint_age_seconds"] = (
            e2e.GWLBE_STABILIZATION_SECONDS - 1
        )
        mutations.append(young_endpoint)
        for index, candidate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")

    def test_ec2_route_response_uses_gateway_id_for_gwlbe_targets(self) -> None:
        endpoint_id = "vpce-0123456789abcdef0"
        endpoint_route = {
            "DestinationCidrBlock": "172.17.0.0/24",
            "GatewayId": endpoint_id,
            "Origin": "CreateRoute",
            "State": "active",
        }
        self.assertTrue(
            e2e.AwsLiveOperations._route_selects_only_target(
                endpoint_route, "GatewayId", endpoint_id
            )
        )
        wrong_field = {**endpoint_route, "GatewayId": None, "VpcEndpointId": endpoint_id}
        self.assertFalse(
            e2e.AwsLiveOperations._route_selects_only_target(wrong_field, "GatewayId", endpoint_id)
        )
        extra_target = {**endpoint_route, "NetworkInterfaceId": "eni-0123456789abcdef0"}
        self.assertFalse(
            e2e.AwsLiveOperations._route_selects_only_target(extra_target, "GatewayId", endpoint_id)
        )


class LiveRunnerTest(unittest.TestCase):
    def run_fixture(
        self, temporary: str, *, lifecycle_failure: str | None = None, operation_failure: str | None = None
    ) -> tuple[e2e.LiveRunResult, FakeProtectedLifecycle, FakeLiveOperations]:
        lifecycle = FakeProtectedLifecycle(lifecycle_failure)
        operations = FakeLiveOperations(operation_failure)
        result = e2e.TwoRegionE2ERunner(
            run_id="fixture-live",
            raw_deployment=protected_output(),
            site_regions={"west": "us-west-2", "east": "us-east-1"},
            lifecycle=lifecycle,
            operations=operations,
            evidence_path=pathlib.Path(temporary) / "evidence.json",
            monotonic=lambda: 0.0,
        ).run()
        return result, lifecycle, operations

    def test_preclaim_contract_failure_still_cleans_up_owned_run(self) -> None:
        raw = protected_output()
        del raw["e2e_load_profile"]
        lifecycle = FakeProtectedLifecycle()
        operations = FakeLiveOperations()
        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=lifecycle,
                operations=operations,
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CONTRACT_ERROR)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertNotIn("claim", lifecycle.calls)
        cleanup = next(phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value)
        self.assertEqual(cleanup["status"], "passed")

    def test_run_live_cleanup_has_one_separate_bounded_timer(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        with tempfile.TemporaryDirectory() as temporary:
            lifecycle = FakeProtectedLifecycle()
            bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations("acceptance-timeout"),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])
        bounded.cleanup()
        self.assertEqual(lifecycle.cleanup_calls, 1)

    def test_active_limit_skips_stuck_diagnostics_and_preserves_cleanup_reservation(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        class StuckDiagnosticOperations(FakeLiveOperations):
            def __init__(self, failure: str) -> None:
                super().__init__(failure)
                self.diagnostics_started = False

            def collect_diagnostics(self, deployment: e2e.ProtectedDeployment | None) -> dict[str, Any]:
                self.diagnostics_started = True
                threading.Event().wait(1)
                raise AssertionError("stuck diagnostics consumed the cleanup reservation")

        for failure, category in (("acceptance-timeout", "TimeoutError"), ("active-interrupt", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                lifecycle = FakeProtectedLifecycle()
                bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
                operations = StuckDiagnosticOperations(failure)
                result = e2e.TwoRegionE2ERunner(
                    run_id="fixture-live",
                    raw_deployment=protected_output(),
                    site_regions={"west": "us-west-2", "east": "us-east-1"},
                    lifecycle=bounded,
                    operations=operations,
                    evidence_path=pathlib.Path(temporary) / "evidence.json",
                    monotonic=lambda: 0.0,
                ).run()

                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")
                self.assertFalse(operations.diagnostics_started)
                self.assertEqual(lifecycle.cleanup_calls, 1)
                self.assertNotIn("finish", lifecycle.calls)

        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup] * 2)

    def test_run_live_cleanup_timeout_is_exit_three_without_retry(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield
            raise TimeoutError("cleanup reservation expired")

        with tempfile.TemporaryDirectory() as temporary:
            lifecycle = FakeProtectedLifecycle()
            bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations(),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertTrue(bounded.cleanup_attempted)

    def test_complete_success_bundle_strictly_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, lifecycle, operations = self.run_fixture(temporary)

            self.assertEqual(result.exit_code, e2e.EXIT_OK)
            self.assertTrue(result.passed)
            verified = e2e.verify_live_evidence(result.evidence)
            self.assertEqual(verified["status"], "passed")
            self.assertEqual([phase["name"] for phase in verified["phases"]], [phase.value for phase in e2e.LIVE_PHASES])
            self.assertEqual(len(verified["flows"]), 31)
            self.assertEqual(len(verified["flow_logs"]), 31)
            self.assertEqual(len(verified["probes"]), 13)
            self.assertEqual(len(verified["wire"]), 2)
            self.assertEqual(len(verified["transport"]), 2)
            self.assertEqual(len(verified["resilience"]), 5)
            self.assertEqual(lifecycle.cleanup_calls, 1)
            self.assertEqual(operations.stop_calls, 1)
            self.assertEqual(stat.S_IMODE(result.evidence_path.stat().st_mode), 0o600)

    def test_every_live_gate_fails_closed_and_claimed_runs_cleanup(self) -> None:
        cases = {
            "concurrent claim": ("claim", None, e2e.EXIT_ACCEPTANCE_FAILED, 0),
            "claim not committed": ("claim-persistence", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "claim ownership ambiguous": ("claim-ambiguous", None, e2e.EXIT_ACCEPTANCE_FAILED, 0),
            "pre-test drift": ("drift-before", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "readiness": (None, "readiness", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "appliance readiness component": (None, "readiness-appliance-firewall_mss_ready", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "workload readiness component": (None, "readiness-workload-tools_ready", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow log start": (None, "flow-start", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "cold context existed": (None, "cold-context", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "icmp identity": (None, "icmp-identity", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "receiver duplicate": (None, "probe-duplicates", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "runner interruption": (None, "interrupt", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "metric growth": (None, "metrics", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire UDP orientation": (None, "wire-port", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire options changed": (None, "wire-options", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire checksum": (None, "wire-checksum", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire cleanup": (None, "wire-cleanup", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU matrix missing": (None, "mtu-missing", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU safe boundary": (None, "mtu-safe", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU-specific drop missing": (None, "mtu-drop-metric", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "generic MTU drop missing": (None, "mtu-generic-drop-metric", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "generic MTU drop duplicated": (None, "mtu-extra-generic-drop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "peer MTU drop": (None, "mtu-peer-drop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "other MTU error": (None, "mtu-other-error", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU oversized reply": (None, "mtu-oversized-reply", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU ICMP capture": (None, "mtu-icmp-capture", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "TCP MSS": (None, "mtu-mss", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load profile binding": (None, "load-profile", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load throughput": (None, "load-throughput", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load loss": (None, "load-loss", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load latency": (None, "load-latency", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load metrics": (None, "load-metrics", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route restoration": (None, "route", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route readiness drift": (None, "route-readiness", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route repair metric": (None, "route-zero-repair", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "service recovery": (None, "service", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "west reboot recovery": (None, "reboot-west", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "east reboot recovery": (None, "reboot-east", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "credential rotation": (None, "tailscale-rotation", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route acceptance exactness": (None, "tailscale-routes", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow tuple missing": (None, "flow-missing", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow wrong ENI": (None, "flow-wrong-eni", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow wrong direction": (None, "flow-wrong-direction", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow window": (None, "flow-window", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow false reverse": (None, "flow-false-reverse", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "ICMP flow uniqueness": (None, "flow-icmp-unique", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow log rollback": (None, "flow-stop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "post-test drift": ("drift-after", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "durable finish": ("finish", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "cleanup": ("cleanup", None, e2e.EXIT_CLEANUP_FAILED, 1),
        }
        for name, (lifecycle_failure, operation_failure, exit_code, cleanup_calls) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                result, lifecycle, operations = self.run_fixture(
                    temporary,
                    lifecycle_failure=lifecycle_failure,
                    operation_failure=operation_failure,
                )
                self.assertEqual(result.exit_code, exit_code)
                self.assertEqual(result.evidence["status"], "failed")
                self.assertEqual(lifecycle.cleanup_calls, cleanup_calls)
                if lifecycle_failure in {"claim", "claim-persistence", "claim-ambiguous"}:
                    self.assertEqual(
                        result.evidence["lifecycle"]["ownership_resolution"],
                        {
                            "claim": "competing-claim",
                            "claim-persistence": "not-committed",
                            "claim-ambiguous": "ambiguous-ownership",
                        }[lifecycle_failure],
                    )
                self.assertEqual(e2e.validate_evidence(result.evidence), result.evidence)
                with self.assertRaises(e2e.EvidenceVerificationError):
                    e2e.verify_live_evidence(result.evidence)
                if operation_failure not in (
                    None,
                    "readiness",
                    "readiness-appliance-firewall_mss_ready",
                    "readiness-workload-tools_ready",
                    "flow-start",
                    "interrupt",
                ):
                    self.assertGreaterEqual(operations.stop_calls, 1)
                if operation_failure and operation_failure.startswith("readiness"):
                    self.assertFalse(any(call.startswith("cold-") for call in operations.calls))

    def test_finish_ownership_blocker_overrides_prior_failure_but_noncommit_does_not(self) -> None:
        cases = {
            "finish-persistence": ("MetricAssertionError", "not-committed", 1),
            "finish-ambiguous": ("AmbiguousOwnershipError", "ambiguous-ownership", 0),
        }
        for lifecycle_failure, (category, resolution, cleanup_calls) in cases.items():
            with self.subTest(failure=lifecycle_failure), tempfile.TemporaryDirectory() as temporary:
                result, lifecycle, _operations = self.run_fixture(
                    temporary,
                    lifecycle_failure=lifecycle_failure,
                    operation_failure="metrics",
                )

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], resolution)
                self.assertEqual(lifecycle.cleanup_calls, cleanup_calls)
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["status"], "passed" if cleanup_calls else "skipped")

    def test_strict_verifier_rejects_tampered_flow_and_cli_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _lifecycle, _operations = self.run_fixture(temporary)
            tampered = copy.deepcopy(result.evidence)
            tampered["flow_logs"].pop()
            path = pathlib.Path(temporary) / "tampered.json"
            e2e.write_evidence(path, tampered)

            with self.assertRaisesRegex(e2e.EvidenceVerificationError, "declared flow"):
                e2e.verify_live_evidence(tampered)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "aws_two_region_e2e.py"), "verify-evidence", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, e2e.EXIT_ACCEPTANCE_FAILED)

    def test_strict_verifier_rejects_each_new_evidence_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _lifecycle, _operations = self.run_fixture(temporary)
            baseline = result.evidence

            def cold_context(document: dict[str, Any]) -> None:
                phase = next(
                    value for value in document["phases"] if value["name"] == e2e.Phase.COLD_WEST_EAST.value
                )
                phase["summary"]["context"]["matching_return_context_before_first_packet"] = True

            def metric_collision(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "normal")
                metric["unexpected_deltas"]["west"]["gwlb_context_collisions_total"] = 1

            def metric_type(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "normal")
                metric["packet_deltas"]["geneve_rx_packets"] = "not-a-number"

            def mtu_generic_missing(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "mtu-drop")
                site = metric["intentional_mtu_drop"]["site"]
                metric["unexpected_deltas"][site]["drops"] = 0

            def mtu_label_changed(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "mtu-drop")
                metric["intentional_mtu_drop"]["mtu_specific"]["direction"] = "egress"

            def flow_log_eni_changed(document: dict[str, Any]) -> None:
                document["flow_logs"][0]["path_evidence"][0]["interface_id"] = "eni-fffffffffffffffff"

            def flow_log_window_changed(document: dict[str, Any]) -> None:
                document["flow_logs"][0]["window"]["end_epoch"] += 7201

            def icmp_flow_log_claims_uniqueness(document: dict[str, Any]) -> None:
                value = next(
                    item for item in document["flow_logs"] if item["correlation_mode"] == "icmp-lane-window"
                )
                value["flow_logs_uniquely_identify_flow"] = True

            def icmp_drop_capture_changed(document: dict[str, Any]) -> None:
                metric = next(
                    value
                    for value in document["metrics"]
                    if value["mode"] == "mtu-drop" and value["drop_proof"]["protocol"] == "icmp"
                )
                metric["drop_proof"]["capture"]["request_count"] = 2

            def udp_drop_allows_overlap(document: dict[str, Any]) -> None:
                flow_by_id = {flow["flow_id"]: flow for flow in document["flows"]}
                value = next(
                    item
                    for item in document["flow_logs"]
                    if flow_by_id[item["flow_id"]]["protocol"] == "udp"
                    and flow_by_id[item["flow_id"]]["expected_result"] == "mtu-drop"
                )
                value["aggregation_overlap_path_matches"] = 1

            def route_drift_hardcoded(document: dict[str, Any]) -> None:
                drill = next(
                    value for value in document["resilience"] if value["name"] == e2e.Phase.ROUTE_MUTATION.value
                )
                drill["repair_metric_delta"] = 0
                drill["readiness_during_drift"].update(
                    {
                        "host_preflight_failed": True,
                        "unhealthy": False,
                        "routing_drift_repairs_delta": 0,
                        "drift_observed": True,
                    }
                )

            mutations: dict[str, Any] = {
                "readiness": lambda value: value["topology"]["appliance_checks"]["west"].update(
                    {"tailscale_backend_running": False}
                ),
                "cold context": cold_context,
                "wire": lambda value: value["wire"][0]["flows"][0].update({"outer_ips_swapped": False}),
                "MTU": lambda value: value["transport"][0].update({"tcp_mss": 1241}),
                "load profile": lambda value: value["load_profile"].update({"immutable": False}),
                "load result": lambda value: value["load"]["iperf3"][0].update({"throughput_mbps": 0}),
                "unexpected metric": metric_collision,
                "metric type": metric_type,
                "MTU generic metric": mtu_generic_missing,
                "MTU label": mtu_label_changed,
                "Flow Log ENI": flow_log_eni_changed,
                "Flow Log window": flow_log_window_changed,
                "ICMP Flow Log uniqueness": icmp_flow_log_claims_uniqueness,
                "ICMP drop capture": icmp_drop_capture_changed,
                "UDP drop overlap": udp_drop_allows_overlap,
                "route drift observation": route_drift_hardcoded,
                "west/east reboot": lambda value: value["resilience"].pop(3),
                "flow log": lambda value: value["flow_logs"].pop(),
                "cleanup": lambda value: value["lifecycle"].update({"cleanup": "failed"}),
            }
            for name, mutate in mutations.items():
                candidate = copy.deepcopy(baseline)
                mutate(candidate)
                with self.subTest(name=name), self.assertRaises(e2e.E2EError):
                    e2e.verify_live_evidence(candidate)

            synthetic_port = copy.deepcopy(baseline)
            icmp = next(flow for flow in synthetic_port["flows"] if flow["protocol"] == "icmp")
            icmp["source_port"] = 40000
            with self.assertRaisesRegex(e2e.EvidenceError, "synthetic ports"):
                e2e.verify_live_evidence(synthetic_port)


class FakeRunAllLifecycle:
    def claim(self, raw_deployment: Mapping[str, Any], deployment: e2e.ProtectedDeployment) -> Mapping[str, Any]:
        return {"claimed": True}

    def verify_no_drift(self, stage: str) -> Mapping[str, Any]:
        return {"clean": True, "stage": stage}

    def finish(self, passed: bool) -> Mapping[str, Any]:
        return {
            "finish": "persisted",
            "acceptance": "passed" if passed else "failed",
        }

    def cleanup(self) -> Mapping[str, Any]:
        raise AssertionError("run-all must route cleanup through its one-attempt coordinator")


class FakeRunAllOperations:
    def __init__(self, root: pathlib.Path, failure: str | None = None) -> None:
        self.root = root
        self.failure = failure
        self.calls: list[str] = []
        self.cleanup_calls = 0

    def _stage(self, name: str) -> None:
        self.calls.append(name)
        if name != "e2e" and self.failure == f"{name}-concurrent":
            raise e2e.ConcurrentLifecycleError(f"another lifecycle writer owns {name}")
        if self.failure == name and name != "e2e":
            if name == "wait":
                diagnostics = self.root / "fixture-run" / "diagnostics.json"
                diagnostics.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                diagnostics.write_text('{"collection":"bounded","safe":true}\n')
                diagnostics.chmod(0o600)
            raise e2e.LifecycleError(f"injected {name} failure")
        if name == "prepare" and self.failure == "prepare-concurrent":
            raise e2e.ConcurrentLifecycleError("another lifecycle writer owns preparation")
        if name == "wait" and self.failure == "timeout":
            raise TimeoutError("injected whole-run timeout")
        if name == "wait" and self.failure == "signal":
            raise InterruptedError("injected SIGTERM")
        if name == "wait" and self.failure == "protected-timeout":
            raise e2e.ProtectedHardTimeout("injected protected hard timeout")

    def build(self) -> Mapping[str, Any]:
        self._stage("build")
        return {"architecture": "amd64", "allow_dirty": False}

    def preflight(self) -> Mapping[str, Any]:
        self._stage("preflight")
        return {"read_only": True}

    def prepare(self) -> Mapping[str, Any]:
        self._stage("prepare")
        return {"manifest_phase": "prepared", "published": True}

    def plan(self) -> pathlib.Path:
        self._stage("plan")
        return self.root / "apply.tfplan"

    def apply(self, plan_path: pathlib.Path) -> Mapping[str, Any]:
        self._stage("apply")
        self.asserted_plan = plan_path
        return protected_output()

    def wait_ready(self, deployment: Mapping[str, Any], *, timeout_seconds: int) -> Mapping[str, Any]:
        self._stage("wait")
        self.asserted_deployment = deployment
        self.asserted_wait_timeout = timeout_seconds
        return {"deployment_matches": True, "manifest_phase": "ready"}

    def run_e2e(
        self,
        deployment: Mapping[str, Any],
        lifecycle: e2e.ProtectedLifecycleAPI,
        evidence_path: pathlib.Path,
        budgets: e2e.TimeoutBudgets,
    ) -> e2e.LiveRunResult:
        self._stage("e2e")
        evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.failure in {"e2e-concurrent", "e2e-ambiguous", "e2e-concurrent-inexact"}:
            ambiguous = self.failure == "e2e-ambiguous"
            resolution = "ambiguous-ownership" if ambiguous else "competing-claim"
            evidence = {
                "schema": e2e.LIVE_EVIDENCE_SCHEMA,
                "kind": e2e.LIVE_EVIDENCE_KIND,
                "run_id": "fixture-run" if self.failure == "e2e-concurrent" else "other-run",
                "status": "failed",
                "failure": {
                    "phase": e2e.Phase.EVIDENCE.value if ambiguous else e2e.Phase.CONSUME_DEPLOYMENT.value,
                    "category": "AmbiguousOwnershipError" if ambiguous else "ConcurrentRunError",
                    "message": "durable E2E ownership blocks cleanup",
                },
                "lifecycle": {
                    "claimed": ambiguous,
                    "ownership_resolution": resolution,
                },
                "phases": [
                    {
                        "name": e2e.Phase.CLEANUP.value,
                        "status": "skipped",
                        "summary": {
                            "reason": "destructive cleanup suppressed by durable ownership resolution",
                            "ownership_resolution": resolution,
                        },
                    }
                ],
            }
            if ambiguous:
                evidence["run_id"] = "fixture-run"
            evidence_path.write_text(json.dumps(evidence) + "\n")
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                evidence,
                "durable E2E ownership blocks cleanup",
            )
        if self.failure == "e2e-persistence":
            evidence = {
                "schema": e2e.LIVE_EVIDENCE_SCHEMA,
                "kind": e2e.LIVE_EVIDENCE_KIND,
                "run_id": "fixture-run",
                "status": "failed",
                "failure": {
                    "phase": e2e.Phase.CONSUME_DEPLOYMENT.value,
                    "category": "ClaimPersistenceError",
                    "message": "durable E2E claim was not committed",
                },
                "lifecycle": {"ownership_resolution": "not-committed"},
                "phases": [
                    {
                        "name": e2e.Phase.CLEANUP.value,
                        "status": "skipped",
                        "summary": {"ownership_resolution": "not-committed"},
                    }
                ],
            }
            evidence_path.write_text(json.dumps(evidence) + "\n")
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                evidence,
                "durable E2E claim was not committed",
            )
        if self.failure in {"e2e-cleanup-primary", "e2e-cleanup-success"}:
            try:
                lifecycle.cleanup()
            except e2e.LifecycleError as cleanup_error:
                diagnostics = {}
                if self.failure == "e2e-cleanup-primary":
                    diagnostics["acceptance_failure_before_cleanup"] = {
                        "phase": "simultaneous-cold-initiation",
                        "category": "ProbeError",
                        "message": "injected cold probe failure",
                    }
                evidence = {
                    "schema": e2e.SYMMETRIC_EVIDENCE_SCHEMA,
                    "kind": e2e.SYMMETRIC_EVIDENCE_KIND,
                    "run_id": "fixture-run",
                    "status": "failed",
                    "failure": {
                        "phase": e2e.Phase.CLEANUP.value,
                        "category": "LifecycleError",
                        "message": str(cleanup_error),
                    },
                    "lifecycle": {"cleanup": "failed"},
                    "diagnostics": diagnostics,
                }
                evidence_path.write_text(json.dumps(evidence) + "\n")
                return e2e.LiveRunResult(
                    e2e.EXIT_CLEANUP_FAILED,
                    evidence_path,
                    evidence,
                    str(cleanup_error),
                )
            raise AssertionError("injected cleanup failure did not occur")
        lifecycle.cleanup()
        if self.failure == "e2e":
            evidence_path.write_text('{"status":"failed"}\n')
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                {"status": "failed"},
                "injected E2E failure",
            )
        evidence_path.write_text('{"status":"passed"}\n')
        return e2e.LiveRunResult(e2e.EXIT_OK, evidence_path, {"status": "passed"})

    def cleanup(self) -> Mapping[str, Any]:
        self.calls.append("cleanup")
        self.cleanup_calls += 1
        if self.failure in {"cleanup", "e2e-cleanup-primary", "e2e-cleanup-success"}:
            raise e2e.LifecycleError("injected cleanup failure")
        return {"destroyed": True, "residual_audit": "clean"}


class ProtectedControlFlowPropagationTest(unittest.TestCase):
    def test_retry_loops_rethrow_the_exact_control_flow_object(self) -> None:
        for control in (
            e2e.ProtectedHardTimeout("hard deadline"),
            e2e.ProtectedTermination("termination"),
        ):
            with self.subTest(control=type(control).__name__):
                base = object.__new__(e2e.AwsLiveOperations)
                base.monotonic = lambda: 0.0
                base.sleep = mock.Mock()
                with self.assertRaises(type(control)) as raised:
                    base._wait_until(
                        mock.Mock(side_effect=control),
                        lambda _value: False,
                        timeout_seconds=10,
                        description="protected retry",
                    )
                self.assertIs(raised.exception, control)
                base.sleep.assert_not_called()

                symmetric = object.__new__(e2e.AwsSymmetricLiveOperations)
                symmetric.base = SimpleNamespace(
                    monotonic=lambda: 0.0,
                    sleep=mock.Mock(),
                )
                symmetric._run_probe_with_path = mock.Mock(side_effect=control)
                with self.assertRaises(type(control)) as raised:
                    symmetric._wait_probe_path(
                        SimpleNamespace(),
                        SimpleNamespace(),
                        timeout_seconds=10,
                    )
                self.assertIs(raised.exception, control)
                symmetric.base.sleep.assert_not_called()

    def test_manifest_result_write_does_not_reconcile_protected_control_flow(self) -> None:
        control = e2e.ProtectedTermination("termination during manifest write")
        lifecycle = object.__new__(e2e.ProtectedLifecycleAdapter)
        lifecycle._ownership_state = "running-owned"
        lifecycle._claim_etag = "etag-running"
        lifecycle.manifest = {
            "phase": "e2e_running",
            "e2e": {"claim_id": "claim-fixture"},
        }
        lifecycle.store = SimpleNamespace(remote_etag="etag-running")
        lifecycle._write_manifest = mock.Mock(side_effect=control)
        lifecycle._reconcile_finish_write = mock.Mock()

        with self.assertRaises(e2e.ProtectedTermination) as raised:
            lifecycle.finish(False)

        self.assertIs(raised.exception, control)
        lifecycle._reconcile_finish_write.assert_not_called()

    def test_owned_recovery_preserves_the_distinct_control_flow_type(self) -> None:
        control = e2e.ProtectedHardTimeout("committed write interrupted")
        with self.assertRaises(e2e.ProtectedHardTimeout) as raised:
            e2e.ProtectedLifecycleAdapter._propagate_after_owned_recovery(control)
        self.assertIs(raised.exception, control)


class ProbeLifecycleTest(unittest.TestCase):
    def _tcp_flow(self) -> e2e.FlowRecord:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-probe")
        return ledger.allocate(
            "tcp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("fixture-probe"),
        )

    def _paired_flows(self) -> tuple[e2e.FlowRecord, e2e.FlowRecord]:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-paired-probe")
        return tuple(
            ledger.allocate(
                protocol,
                deployment.west.initiator,
                deployment.east.responder,
                destination_port=5201,
                generation=ledger.begin_generation(f"fixture-paired-{protocol}"),
            )
            for protocol in e2e.TRANSPORT_PROTOCOLS
        )

    def test_managed_responder_pause_is_reentrant(self) -> None:
        target = self._tcp_flow().destination
        operations = object.__new__(e2e.AwsLiveOperations)
        operations._responder_pause_depth = {}
        operations._execute = mock.Mock()
        operations._wait_listener = mock.Mock()

        operations._pause_managed_responder(target, "tcp")
        operations._pause_managed_responder(target, "tcp")
        self.assertEqual(operations._execute.call_count, 1)
        self.assertIn("systemctl stop", operations._execute.call_args.args[1])

        operations._resume_managed_responder(target, "tcp")
        self.assertEqual(operations._execute.call_count, 1)
        operations._resume_managed_responder(target, "tcp")

        self.assertEqual(operations._execute.call_count, 2)
        self.assertIn("systemctl start", operations._execute.call_args.args[1])
        operations._wait_listener.assert_called_once_with(
            target, "tcp", timeout_seconds=10
        )
        self.assertEqual(operations._responder_pause_depth, {})

    def test_managed_responder_lease_survives_ambiguous_pause_and_resume(self) -> None:
        target = self._tcp_flow().destination
        key = (target.instance_id, "tcp")
        operations = object.__new__(e2e.AwsLiveOperations)
        operations._responder_pause_depth = {}
        operations._execute = mock.Mock(
            side_effect=e2e.SSMDispatchError("fixture ambiguous pause")
        )
        operations._wait_listener = mock.Mock()

        with self.assertRaises(e2e.SSMDispatchError):
            operations._pause_managed_responder(target, "tcp")

        self.assertEqual(operations._responder_pause_depth, {key: 1})
        operations._execute.side_effect = None
        operations._resume_managed_responder(target, "tcp")
        self.assertEqual(operations._responder_pause_depth, {})

        operations._pause_managed_responder(target, "tcp")
        control = KeyboardInterrupt("fixture interrupted resume")
        operations._execute.side_effect = control
        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._resume_managed_responder(target, "tcp")

        self.assertIs(raised.exception, control)
        self.assertEqual(operations._responder_pause_depth, {key: 1})
        operations._execute.side_effect = None
        operations._resume_managed_responder(target, "tcp")
        self.assertEqual(operations._responder_pause_depth, {})

    def test_one_shot_probe_commands_reserve_agent_shutdown_headroom(self) -> None:
        flow = self._tcp_flow()
        payload = hashlib.sha512(
            f"{flow.flow_id}:receiver-observed-payload".encode()
        ).hexdigest()
        payload_sha256 = hashlib.sha256(payload.encode("ascii")).hexdigest()
        client = {
            "flow_id": flow.flow_id,
            "latency_ns": 1,
            "payload_sha256": payload_sha256,
            "protocol": "tcp",
            "source_ip": flow.source.private_ip,
            "source_port": flow.source_port,
            "success": True,
        }
        receiver_result = e2e.SSMResult(
            flow.destination,
            "fixture-server-command",
            "Success",
            0,
            stdout='{"success":true}\n',
        )
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(return_value="fixture-server-command"),
            wait=mock.Mock(return_value=receiver_result),
            cancel=mock.Mock(),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute_json = mock.Mock(return_value=client)

        result = operations._run_probe(flow, timeout_seconds=20)

        server_spec = operations.ssm.send.call_args.args[0]
        self.assertEqual(server_spec.timeout_seconds, 30)
        self.assertIn("--timeout 20", server_spec.commands[0])
        self.assertEqual(
            operations._execute_json.call_args.kwargs["timeout_seconds"], 30
        )
        self.assertEqual(operations.ssm.wait.call_args.kwargs["timeout_seconds"], 40)
        self.assertEqual(result["source_port"], flow.source_port)
        operations._resume_managed_responder.assert_called_once_with(
            flow.destination, "tcp"
        )

    def test_probe_client_dispatch_interrupt_keeps_nested_responder_paused(self) -> None:
        flow = self._tcp_flow()
        control = KeyboardInterrupt("fixture nested probe client dispatch")
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(return_value="fixture-server-command"),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute_json = mock.Mock(side_effect=control)

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_probe(flow, timeout_seconds=20)

        self.assertIs(raised.exception, control)
        self.assertTrue(e2e._ssm_ownership_unconfirmed(control))
        operations.ssm.terminate.assert_called_once_with(
            flow.destination,
            "fixture-server-command",
            timeout_seconds=5,
        )
        operations._resume_managed_responder.assert_not_called()

    def test_probe_listener_dispatch_interrupt_keeps_nested_responder_paused(self) -> None:
        flow = self._tcp_flow()
        control = KeyboardInterrupt("fixture nested probe listener dispatch")
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(return_value="fixture-server-command"),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock(side_effect=control)

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_probe(flow, timeout_seconds=20)

        self.assertIs(raised.exception, control)
        self.assertTrue(e2e._ssm_ownership_unconfirmed(control))
        operations.ssm.terminate.assert_called_once_with(
            flow.destination,
            "fixture-server-command",
            timeout_seconds=5,
        )
        operations._resume_managed_responder.assert_not_called()

    def test_stream_mutation_cooperatively_completes_with_actual_marker_count(self) -> None:
        flow = self._tcp_flow()
        attempts = [40 + sequence * 10 for sequence in range(20)]
        markers = [
            [sequence, 45 + sequence * 10]
            for sequence in range(20)
        ]
        client = {
            "attempts": attempts,
            "connection_id": f"{flow.flow_id}:c0001",
            "flow_id": flow.flow_id,
            "interrupted": False,
            "last_sent_monotonic_ns": attempts[-1],
            "markers": markers,
            "sent_markers": 20,
            "socket_count": 1,
            "source_port": flow.source_port,
            "stop_observed": True,
            "success": True,
        }
        receiver = {
            "duplicates": 0,
            "flow_id": flow.flow_id,
            "receives": 20,
            "sessions": 1,
            "stop_observed": True,
            "success": True,
        }
        results = {
            "fixture-client-command": e2e.SSMResult(
                flow.source,
                "fixture-client-command",
                "Success",
                0,
                stdout=json.dumps(client),
            ),
            "fixture-server-command": e2e.SSMResult(
                flow.destination,
                "fixture-server-command",
                "Success",
                0,
                stdout=json.dumps(receiver),
            ),
        }
        events: list[str] = []
        ambiguous_client_stop = True

        def wait(_target, command_id, **_kwargs):
            events.append(f"wait:{command_id}")
            return results[command_id]

        def execute(_target, _command, *, comment, **_kwargs):
            nonlocal ambiguous_client_stop
            events.append(comment)
            if (
                comment == "Envelope E2E complete continuity client"
                and ambiguous_client_stop
            ):
                ambiguous_client_stop = False
                raise e2e.SSMError("fixture lost committed stop response")

        clocks = iter((100, 200))

        def remote_monotonic(_target):
            value = next(clocks)
            events.append(f"clock:{value}")
            return value

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("fixture-server-command", "fixture-client-command")
            ),
            wait=mock.Mock(side_effect=wait),
            cancel=mock.Mock(),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._remote_monotonic_ns = mock.Mock(side_effect=remote_monotonic)

        def wait_until(observe, predicate, **_kwargs):
            observed = observe()
            self.assertTrue(predicate(observed))
            return observed

        operations._wait_until = wait_until
        analysis, observed_receiver, mutation = operations._run_stream_mutation(
            flow,
            timeout_seconds=90,
            maximum_loss_ns=1_000,
            label="fixture-controlled-stream",
            mutate_and_restore=lambda: events.append("mutation") or {"restored": True},
            allow_right_censored=True,
            stop_after_mutation=True,
        )

        self.assertIsInstance(analysis, e2e.StreamAnalysis)
        self.assertEqual(analysis.marker_count, 20)
        self.assertEqual(analysis.last_sequence, 19)
        self.assertEqual(observed_receiver, receiver)
        self.assertEqual(mutation, {"restored": True})
        server_spec = operations.ssm.send.call_args_list[0].args[0]
        client_spec = operations.ssm.send.call_args_list[1].args[0]
        self.assertIn("--stop-path", server_spec.commands[0])
        self.assertIn("--stop-path", client_spec.commands[0])
        self.assertIn("--stop-token", server_spec.commands[0])
        self.assertIn("--stop-token", client_spec.commands[0])
        self.assertIn("--minimum-count 20", client_spec.commands[0])
        comments = [call.kwargs.get("comment") for call in operations._execute.call_args_list]
        self.assertIn("Envelope E2E complete continuity client", comments)
        self.assertIn(
            "Envelope E2E complete continuity client reconciliation", comments
        )
        self.assertIn("Envelope E2E complete continuity receiver", comments)
        receiver_reset = next(
            call
            for call in operations._execute.call_args_list
            if call.kwargs.get("comment")
            == "Envelope E2E reset continuity receiver stop"
        )
        self.assertNotIn("rm -f", receiver_reset.args[1])
        self.assertIn("test ! -e", receiver_reset.args[1])
        stop_commands = [
            call.args[1]
            for call in operations._execute.call_args_list
            if "python3 -c" in call.args[1]
        ]
        self.assertGreaterEqual(len(stop_commands), 5)
        for command in stop_commands:
            arguments = shlex.split(command)
            compile(arguments[arguments.index("-c") + 1], "<stop-control>", "exec")
        create_call = next(
            call
            for call in operations._execute.call_args_list
            if call.kwargs.get("comment")
            == "Envelope E2E complete continuity receiver"
        )
        create_source = shlex.split(create_call.args[1])[
            shlex.split(create_call.args[1]).index("-c") + 1
        ]
        self.assertIn("if not valid", create_source)
        self.assertIn("os.unlink(sys.argv[1])", create_source)
        self.assertLess(events.index("mutation"), events.index("clock:200"))
        self.assertLess(
            events.index("clock:200"),
            events.index("Envelope E2E complete continuity client"),
        )
        self.assertLess(
            events.index("wait:fixture-client-command"),
            events.index("Envelope E2E complete continuity receiver"),
        )
        operations.ssm.cancel.assert_not_called()

        invalid_client = {**client, "stop_observed": False}
        results["fixture-client-command"] = e2e.SSMResult(
            flow.source,
            "fixture-client-command",
            "Success",
            0,
            stdout=json.dumps(invalid_client),
        )
        operations.ssm.send.side_effect = (
            "fixture-server-command",
            "fixture-client-command",
        )
        operations._remote_monotonic_ns.side_effect = (100, 200)
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "exact source socket"):
            operations._run_stream_mutation(
                flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-uncontrolled-completion",
                mutate_and_restore=lambda: {"restored": True},
                allow_right_censored=True,
                stop_after_mutation=True,
            )

    def test_paired_stream_mutation_uses_one_main_thread_controlled_lifecycle(self) -> None:
        tcp_flow, udp_flow = self._paired_flows()
        events: list[str] = []
        caller_thread = threading.get_ident()
        mutation_threads: list[int] = []

        def client(flow: e2e.FlowRecord) -> dict[str, Any]:
            attempts = [40 + sequence * 10 for sequence in range(20)]
            return {
                "attempts": attempts,
                "connection_id": f"{flow.flow_id}:c0001",
                "flow_id": flow.flow_id,
                "interrupted": False,
                "last_sent_monotonic_ns": attempts[-1],
                "markers": [
                    [sequence, 45 + sequence * 10]
                    for sequence in range(20)
                ],
                "sent_markers": 20,
                "socket_count": 1,
                "source_port": flow.source_port,
                "stop_observed": True,
                "success": True,
            }

        def receiver(flow: e2e.FlowRecord) -> dict[str, Any]:
            return {
                "duplicates": 0,
                "flow_id": flow.flow_id,
                "receives": 20,
                "sessions": 1,
                "stop_observed": True,
                "success": True,
            }

        results = {
            "tcp-client": e2e.SSMResult(
                tcp_flow.source,
                "tcp-client",
                "Success",
                0,
                stdout=json.dumps(client(tcp_flow)),
            ),
            "udp-client": e2e.SSMResult(
                udp_flow.source,
                "udp-client",
                "Success",
                0,
                stdout=json.dumps(client(udp_flow)),
            ),
            "tcp-server": e2e.SSMResult(
                tcp_flow.destination,
                "tcp-server",
                "Success",
                0,
                stdout=json.dumps(receiver(tcp_flow)),
            ),
            "udp-server": e2e.SSMResult(
                udp_flow.destination,
                "udp-server",
                "Success",
                0,
                stdout=json.dumps(receiver(udp_flow)),
            ),
        }

        def wait(_target, command_id, **_kwargs):
            events.append(f"wait:{command_id}")
            return results[command_id]

        def execute(_target, _command, *, comment, **_kwargs):
            events.append(comment)

        clocks = iter((100, 200))

        def remote_monotonic(_target):
            value = next(clocks)
            events.append(f"clock:{value}")
            return value

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("tcp-server", "udp-server", "tcp-client", "udp-client")
            ),
            wait=mock.Mock(side_effect=wait),
            cancel=mock.Mock(),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._remote_monotonic_ns = mock.Mock(side_effect=remote_monotonic)

        def wait_until(observe, predicate, **_kwargs):
            observed = observe()
            self.assertTrue(predicate(observed))
            return observed

        operations._wait_until = wait_until

        def mutate() -> Mapping[str, Any]:
            mutation_threads.append(threading.get_ident())
            events.append("mutation")
            return {"restored": True}

        observed, mutation = operations._run_paired_stream_mutation(
            tcp_flow,
            udp_flow,
            timeout_seconds=90,
            maximum_loss_ns=1_000,
            label="fixture-paired",
            mutate_and_restore=mutate,
        )

        self.assertEqual(mutation_threads, [caller_thread])
        self.assertEqual(mutation, {"restored": True})
        self.assertEqual(set(observed), {"tcp", "udp"})
        self.assertTrue(
            all(
                value[0].mutation.start_monotonic_ns == 100
                and value[0].mutation.end_monotonic_ns == 200
                for value in observed.values()
            )
        )
        client_stops = [
            index
            for index, event in enumerate(events)
            if event == "Envelope E2E complete continuity client"
        ]
        client_waits = [
            events.index("wait:tcp-client"),
            events.index("wait:udp-client"),
        ]
        receiver_stops = [
            index
            for index, event in enumerate(events)
            if event == "Envelope E2E complete continuity receiver"
        ]
        receiver_waits = [
            events.index("wait:tcp-server"),
            events.index("wait:udp-server"),
        ]
        self.assertLess(max(client_stops), min(client_waits))
        self.assertLess(max(client_waits), min(receiver_stops))
        self.assertLess(max(receiver_stops), min(receiver_waits))
        self.assertLess(events.index("mutation"), events.index("clock:200"))
        operations.ssm.cancel.assert_not_called()
        self.assertEqual(operations._resume_managed_responder.call_count, 2)
        for call in operations.ssm.send.call_args_list:
            command = call.args[0].commands[0]
            self.assertIn("--stop-path", command)
            self.assertIn("--stop-token", command)
        for call in operations._execute.call_args_list:
            command = call.args[1]
            if "python3 -c" not in command:
                continue
            arguments = shlex.split(command)
            compile(arguments[arguments.index("-c") + 1], "<stop-control>", "exec")

    def test_paired_stream_mutation_preserves_main_thread_interrupt(self) -> None:
        tcp_flow, udp_flow = self._paired_flows()
        control = KeyboardInterrupt("fixture paired mutation interrupt")
        mutation_threads: list[int] = []
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("tcp-server", "udp-server", "tcp-client", "udp-client")
            ),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock()
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(return_value=100)

        def interrupt() -> Mapping[str, Any]:
            mutation_threads.append(threading.get_ident())
            raise control

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_paired_stream_mutation(
                tcp_flow,
                udp_flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-paired-interrupt",
                mutate_and_restore=interrupt,
            )

        self.assertIs(raised.exception, control)
        self.assertEqual(mutation_threads, [threading.get_ident()])
        self.assertEqual(operations.ssm.terminate.call_count, 4)
        self.assertEqual(operations._resume_managed_responder.call_count, 2)

    def test_paired_stream_ambiguous_dispatch_fails_closed(self) -> None:
        tcp_flow, udp_flow = self._paired_flows()
        dispatch_error = e2e.SSMDispatchError(
            "fixture UDP client response omitted CommandId"
        )
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=(
                    "tcp-server",
                    "udp-server",
                    "tcp-client",
                    dispatch_error,
                )
            ),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock()

        with self.assertRaises(e2e.SSMDispatchError) as raised:
            operations._run_paired_stream_mutation(
                tcp_flow,
                udp_flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-paired-ambiguous",
                mutate_and_restore=lambda: {"restored": True},
            )

        self.assertIs(raised.exception, dispatch_error)
        self.assertEqual(operations.ssm.terminate.call_count, 3)
        operations._resume_managed_responder.assert_not_called()

    def test_stream_cleanup_preserves_protected_control_flow(self) -> None:
        flow = self._tcp_flow()
        for stage in ("cancel", "resume"):
            with self.subTest(stage=stage):
                control = e2e.ProtectedHardTimeout(f"protected {stage}")
                operations = object.__new__(e2e.AwsLiveOperations)
                operations.ssm = SimpleNamespace(
                    send=mock.Mock(
                        side_effect=("fixture-server-command", "fixture-client-command")
                    ),
                    wait=mock.Mock(return_value=SimpleNamespace()),
                    cancel=mock.Mock(
                        side_effect=control if stage == "cancel" else None
                    ),
                )
                operations._pause_managed_responder = mock.Mock()
                operations._resume_managed_responder = mock.Mock(
                    side_effect=control if stage == "resume" else None
                )
                operations._wait_listener = mock.Mock()
                operations._execute = mock.Mock()
                operations._execute_json = mock.Mock(return_value={"stream_ready": True})
                operations._wait_until = mock.Mock(
                    side_effect=e2e.StreamAnalysisError("fixture primary failure")
                )

                with self.assertRaises(e2e.ProtectedHardTimeout) as raised:
                    operations._run_stream_mutation(
                        flow,
                        timeout_seconds=90,
                        maximum_loss_ns=1_000,
                        label=f"fixture-protected-{stage}",
                        mutate_and_restore=lambda: {"restored": True},
                    )

                self.assertIs(raised.exception, control)
                if stage == "cancel":
                    operations._resume_managed_responder.assert_not_called()
                else:
                    operations._resume_managed_responder.assert_called_once()

    def test_ambiguous_stream_dispatch_suppresses_responder_restoration(self) -> None:
        flow = self._tcp_flow()
        for stage in ("server", "client"):
            with self.subTest(stage=stage):
                dispatch_error = e2e.SSMError(
                    f"fixture {stage} response omitted CommandId"
                )
                send_values = (
                    (dispatch_error,)
                    if stage == "server"
                    else ("fixture-server-command", dispatch_error)
                )
                operations = object.__new__(e2e.AwsLiveOperations)
                operations.ssm = SimpleNamespace(
                    send=mock.Mock(side_effect=send_values),
                    wait=mock.Mock(return_value=SimpleNamespace()),
                    cancel=mock.Mock(return_value=True),
                )
                operations._pause_managed_responder = mock.Mock()
                operations._resume_managed_responder = mock.Mock()
                operations._wait_listener = mock.Mock()
                operations._execute = mock.Mock()
                operations._wait_until = mock.Mock()

                with self.assertRaises(e2e.SSMError) as raised:
                    operations._run_stream_mutation(
                        flow,
                        timeout_seconds=90,
                        maximum_loss_ns=1_000,
                        label=f"fixture-ambiguous-{stage}",
                        mutate_and_restore=lambda: {"restored": True},
                    )

                self.assertIs(raised.exception, dispatch_error)
                operations._resume_managed_responder.assert_not_called()
                if stage == "server":
                    operations.ssm.cancel.assert_not_called()
                else:
                    operations.ssm.cancel.assert_called_once_with(
                        flow.destination,
                        "fixture-server-command",
                        timeout_seconds=5,
                    )

    def test_unconfirmed_stop_command_is_not_reconciled_as_safe(self) -> None:
        flow = self._tcp_flow()
        dispatch_error = e2e.SSMTerminationError(
            "fixture stop command terminal state unconfirmed"
        )

        def execute(_target, _command, *, comment, **_kwargs):
            if comment == "Envelope E2E complete continuity client":
                raise dispatch_error

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("fixture-server-command", "fixture-client-command")
            ),
            wait=mock.Mock(return_value=SimpleNamespace()),
            cancel=mock.Mock(return_value=True),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(side_effect=(100, 200))

        with self.assertRaises(e2e.SSMTerminationError) as raised:
            operations._run_stream_mutation(
                flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-ambiguous-stop",
                mutate_and_restore=lambda: {"restored": True},
                stop_after_mutation=True,
            )

        self.assertIs(raised.exception, dispatch_error)
        operations._resume_managed_responder.assert_not_called()
        comments = [
            call.kwargs.get("comment") for call in operations._execute.call_args_list
        ]
        self.assertNotIn(
            "Envelope E2E complete continuity client reconciliation", comments
        )
        self.assertEqual(operations.ssm.cancel.call_count, 2)

    def test_ambiguous_stop_cleanup_dispatch_suppresses_restoration(self) -> None:
        flow = self._tcp_flow()
        primary = e2e.StreamAnalysisError("fixture client wait failed")

        def execute(_target, _command, *, comment, **_kwargs):
            if comment == "Envelope E2E delete continuity client stop":
                raise e2e.SSMDispatchError(
                    "fixture stop cleanup response omitted CommandId"
                )

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("fixture-server-command", "fixture-client-command")
            ),
            wait=mock.Mock(side_effect=primary),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(side_effect=(100, 200))

        with self.assertRaises(e2e.StreamAnalysisError) as raised:
            operations._run_stream_mutation(
                flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-ambiguous-stop-cleanup",
                mutate_and_restore=lambda: {"restored": True},
                stop_after_mutation=True,
            )

        self.assertIs(raised.exception, primary)
        operations._resume_managed_responder.assert_not_called()
        self.assertEqual(operations.ssm.terminate.call_count, 2)
        self.assertTrue(
            any("cleanup dispatch was not confirmed" in note for note in primary.__notes__)
        )

    def test_keyboard_interrupt_during_success_cleanup_suppresses_restoration(self) -> None:
        flow = self._tcp_flow()
        control = KeyboardInterrupt("fixture successful cleanup interrupt")
        attempts = [40 + sequence * 10 for sequence in range(20)]
        client = {
            "attempts": attempts,
            "connection_id": f"{flow.flow_id}:c0001",
            "flow_id": flow.flow_id,
            "interrupted": False,
            "last_sent_monotonic_ns": attempts[-1],
            "markers": [
                [sequence, 45 + sequence * 10] for sequence in range(20)
            ],
            "sent_markers": 20,
            "socket_count": 1,
            "source_port": flow.source_port,
            "stop_observed": True,
            "success": True,
        }
        receiver = {
            "duplicates": 0,
            "flow_id": flow.flow_id,
            "receives": 20,
            "sessions": 1,
            "stop_observed": True,
            "success": True,
        }
        results = (
            e2e.SSMResult(
                flow.source,
                "fixture-client-command",
                "Success",
                0,
                stdout=json.dumps(client),
            ),
            e2e.SSMResult(
                flow.destination,
                "fixture-server-command",
                "Success",
                0,
                stdout=json.dumps(receiver),
            ),
        )

        def execute(_target, _command, *, comment, **_kwargs):
            if comment == "Envelope E2E delete continuity readiness":
                raise control

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("fixture-server-command", "fixture-client-command")
            ),
            wait=mock.Mock(side_effect=results),
            terminate=mock.Mock(),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(side_effect=(100, 200))

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_stream_mutation(
                flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-success-cleanup-interrupt",
                mutate_and_restore=lambda: {"restored": True},
                stop_after_mutation=True,
            )

        self.assertIs(raised.exception, control)
        operations._resume_managed_responder.assert_not_called()
        operations.ssm.terminate.assert_not_called()

    def test_keyboard_interrupt_during_stop_dispatch_fails_closed(self) -> None:
        flow = self._tcp_flow()
        for stop_role in ("client", "receiver"):
            with self.subTest(stop_role=stop_role):
                control = KeyboardInterrupt(
                    f"fixture {stop_role} stop dispatch interrupt"
                )
                target_comment = (
                    f"Envelope E2E complete continuity {stop_role}"
                )

                def execute(_target, _command, *, comment, **_kwargs):
                    if comment == target_comment:
                        raise control

                operations = object.__new__(e2e.AwsLiveOperations)
                operations.ssm = SimpleNamespace(
                    send=mock.Mock(
                        side_effect=(
                            "fixture-server-command",
                            "fixture-client-command",
                        )
                    ),
                    wait=mock.Mock(return_value=SimpleNamespace()),
                    terminate=mock.Mock(
                        return_value=SimpleNamespace(status="Cancelled")
                    ),
                )
                operations._pause_managed_responder = mock.Mock()
                operations._resume_managed_responder = mock.Mock()
                operations._wait_listener = mock.Mock()
                operations._execute = mock.Mock(side_effect=execute)
                operations._execute_json = mock.Mock(
                    return_value={"stream_ready": True}
                )
                operations._wait_until = mock.Mock()
                operations._remote_monotonic_ns = mock.Mock(
                    side_effect=(100, 200)
                )

                with self.assertRaises(KeyboardInterrupt) as raised:
                    operations._run_stream_mutation(
                        flow,
                        timeout_seconds=90,
                        maximum_loss_ns=1_000,
                        label=f"fixture-{stop_role}-stop-interrupt",
                        mutate_and_restore=lambda: {"restored": True},
                        stop_after_mutation=True,
                    )

                self.assertIs(raised.exception, control)
                operations._resume_managed_responder.assert_not_called()
                self.assertGreaterEqual(operations.ssm.terminate.call_count, 1)

    def test_paired_keyboard_interrupt_during_stop_dispatch_fails_closed(self) -> None:
        tcp_flow, udp_flow = self._paired_flows()
        control = KeyboardInterrupt("fixture paired stop dispatch interrupt")

        def execute(_target, _command, *, comment, **_kwargs):
            if comment == "Envelope E2E complete continuity client":
                raise control

        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("tcp-server", "udp-server", "tcp-client", "udp-client")
            ),
            terminate=mock.Mock(return_value=SimpleNamespace(status="Cancelled")),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock(side_effect=execute)
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(side_effect=(100, 200))

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_paired_stream_mutation(
                tcp_flow,
                udp_flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-paired-stop-interrupt",
                mutate_and_restore=lambda: {"restored": True},
            )

        self.assertIs(raised.exception, control)
        self.assertEqual(operations.ssm.terminate.call_count, 4)
        operations._resume_managed_responder.assert_not_called()

    def test_stream_mutation_preserves_keyboard_interrupt_after_termination(self) -> None:
        flow = self._tcp_flow()
        control = KeyboardInterrupt("fixture mutation interrupt")
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.ssm = SimpleNamespace(
            send=mock.Mock(
                side_effect=("fixture-server-command", "fixture-client-command")
            ),
            wait=mock.Mock(return_value=SimpleNamespace()),
            cancel=mock.Mock(return_value=True),
        )
        operations._pause_managed_responder = mock.Mock()
        operations._resume_managed_responder = mock.Mock()
        operations._wait_listener = mock.Mock()
        operations._execute = mock.Mock()
        operations._execute_json = mock.Mock(return_value={"stream_ready": True})
        operations._wait_until = mock.Mock()
        operations._remote_monotonic_ns = mock.Mock(return_value=100)

        with self.assertRaises(KeyboardInterrupt) as raised:
            operations._run_stream_mutation(
                flow,
                timeout_seconds=90,
                maximum_loss_ns=1_000,
                label="fixture-keyboard-interrupt",
                mutate_and_restore=lambda: (_ for _ in ()).throw(control),
            )

        self.assertIs(raised.exception, control)
        self.assertEqual(operations.ssm.cancel.call_count, 2)
        self.assertEqual(operations.ssm.wait.call_count, 2)
        operations._resume_managed_responder.assert_called_once_with(
            flow.destination, "tcp"
        )

    def test_dynamic_installers_wait_for_cloud_init_and_use_unique_temps(self) -> None:
        target = self._tcp_flow().destination
        operations = object.__new__(e2e.AwsLiveOperations)
        operations.agent_sha256 = "a" * 64
        operations.wire_inspector_sha256 = "b" * 64
        operations._execute = mock.Mock()

        operations._install_agent(target)
        operations._install_wire_inspector(target)

        self.assertEqual(operations._execute.call_count, 2)
        for call, template in zip(
            operations._execute.call_args_list,
            (
                f"{e2e.REMOTE_AGENT_PATH}.tmp.XXXXXX",
                f"{e2e.WIRE_INSPECTOR_PATH}.tmp.XXXXXX",
            ),
            strict=True,
        ):
            command = call.args[1]
            self.assertLess(
                command.index("cloud-init status --wait"), command.index("mktemp")
            )
            self.assertLess(command.index("mktemp"), command.index("base64 -d"))
            self.assertIn(f"mktemp {template}", command)
            self.assertIn("install -d -o root -g root -m 0755 /opt/envelope", command)
            self.assertIn("trap 'rm -f \"$temporary\"' EXIT", command)
            self.assertEqual(call.kwargs["timeout_seconds"], 150)


class RunAllCoordinatorTest(unittest.TestCase):
    class Contexts:
        class Deadline:
            def __init__(
                self,
                owner: "RunAllCoordinatorTest.Contexts",
                active_seconds: int,
                cleanup_seconds: int,
            ) -> None:
                self.owner = owner
                self.active_seconds = active_seconds
                self.cleanup_seconds = cleanup_seconds
                self.cleanup_started = False

            def __enter__(self) -> "RunAllCoordinatorTest.Contexts.Deadline":
                self.owner.active_timeouts.append(self.active_seconds)
                self.owner.events.append("active-enter")
                return self

            def start_cleanup(self) -> None:
                if self.cleanup_started:
                    return
                self.cleanup_started = True
                self.owner.cleanup_timeouts.append(self.cleanup_seconds)
                self.owner.events.extend(["active-exit", "cleanup-enter"])

            def __exit__(self, *_error: Any) -> None:
                self.owner.events.append(
                    "cleanup-exit" if self.cleanup_started else "active-exit"
                )
                if self.owner.deadline_exit_error is not None:
                    raise self.owner.deadline_exit_error

        def __init__(self) -> None:
            self.locks: list[pathlib.Path] = []
            self.active_timeouts: list[int] = []
            self.cleanup_timeouts: list[int] = []
            self.events: list[str] = []
            self.lock_active = False
            self.deadline_exit_error: BaseException | None = None

        @contextlib.contextmanager
        def lock(self, path: pathlib.Path) -> Any:
            self.locks.append(path)
            self.lock_active = True
            try:
                yield
            finally:
                self.lock_active = False

        def lifecycle_timeout(
            self, active_seconds: int, cleanup_seconds: int
        ) -> "RunAllCoordinatorTest.Contexts.Deadline":
            return self.Deadline(self, active_seconds, cleanup_seconds)

    @staticmethod
    def prepare_route_recovery_files(
        run_dir: pathlib.Path, raw: Mapping[str, Any]
    ) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "config.json").write_text("{}\n", encoding="utf-8")
        (run_dir / "deployment.json").write_text(
            json.dumps(raw) + "\n", encoding="utf-8"
        )

    def test_lifecycle_proxies_expose_the_live_durable_manifest(self) -> None:
        initial = {"phase": "ready", "tailnet": {"device_ids": {"node-a": "device-a"}}}
        delegate = SimpleNamespace(manifest=initial)
        run_all = e2e._RunAllLifecycleProxy(delegate, lambda: {"complete": True})
        bounded = e2e._BoundedCleanupLifecycleProxy(delegate)

        self.assertIs(run_all.manifest, initial)
        self.assertIs(bounded.manifest, initial)

        claimed = {"phase": "e2e_running", "tailnet": initial["tailnet"]}
        delegate.manifest = claimed
        self.assertIs(run_all.manifest, claimed)
        self.assertIs(bounded.manifest, claimed)

    def run_coordinator(
        self,
        temporary: str,
        failure: str | None = None,
        *,
        contexts: "RunAllCoordinatorTest.Contexts | None" = None,
        output: Callable[[e2e.RunAllResult], None] | None = None,
    ) -> tuple[e2e.RunAllResult, FakeRunAllOperations, "RunAllCoordinatorTest.Contexts"]:
        root = pathlib.Path(temporary).resolve()
        run_dir = root / "fixture-run"
        config = SimpleNamespace(
            run_id="fixture-run",
            architecture="amd64",
            artifact_manifest=(root / "artifacts" / "manifest.json").resolve(),
        )
        operations = FakeRunAllOperations(root, failure)
        contexts = contexts or self.Contexts()
        result = e2e.RunAllCoordinator(
            config=config,
            run_dir=run_dir,
            evidence_path=run_dir / "aws-two-region-e2e-evidence.json",
            lifecycle=FakeRunAllLifecycle(),
            operations=operations,
            hard_timeout_seconds=1200,
            readiness_timeout_seconds=300,
            lock_factory=contexts.lock,
            lifecycle_timeout_factory=contexts.lifecycle_timeout,
        ).run(output=output)
        return result, operations, contexts

    def test_nested_cleanup_timer_rearms_the_paused_active_timer(self) -> None:
        alarms: list[int] = []
        current_alarm = 0
        now = 0.0
        handlers: dict[int, Any] = {
            e2e.signal.SIGALRM: "original-alarm-handler",
            e2e.signal.SIGTERM: "original-term-handler",
        }

        def alarm(seconds: int) -> int:
            nonlocal current_alarm
            previous = current_alarm
            current_alarm = seconds
            alarms.append(seconds)
            return previous

        def install(signum: int, handler: Any) -> Any:
            previous = handlers[signum]
            handlers[signum] = handler
            return previous

        with (
            mock.patch.object(e2e.signal, "alarm", side_effect=alarm),
            mock.patch.object(e2e.signal, "getsignal", side_effect=lambda signum: handlers[signum]),
            mock.patch.object(e2e.signal, "signal", side_effect=install),
            mock.patch.object(e2e.time, "monotonic", side_effect=lambda: now),
            e2e.run_all_hard_timeout(120),
        ):
            self.assertEqual(current_alarm, 120)
            with e2e.cleanup_hard_timeout(30):
                self.assertEqual(current_alarm, 30)
                now = 7.0
            self.assertEqual(current_alarm, 113)

        self.assertEqual(current_alarm, 0)
        self.assertEqual(alarms, [0, 120, 0, 30, 0, 113, 0])

    def test_lifecycle_deadline_switches_to_cleanup_without_a_signal_handler_gap(self) -> None:
        alarms: list[int] = []
        current_alarm = 0
        handlers: dict[int, Any] = {
            e2e.signal.SIGALRM: "original-alarm-handler",
            e2e.signal.SIGTERM: "original-term-handler",
        }

        def alarm(seconds: int) -> int:
            nonlocal current_alarm
            previous = current_alarm
            current_alarm = seconds
            alarms.append(seconds)
            return previous

        def install(signum: int, handler: Any) -> Any:
            previous = handlers[signum]
            handlers[signum] = handler
            return previous

        with (
            mock.patch.object(e2e.signal, "alarm", side_effect=alarm),
            mock.patch.object(
                e2e.signal,
                "getsignal",
                side_effect=lambda signum: handlers[signum],
            ),
            mock.patch.object(e2e.signal, "signal", side_effect=install),
            mock.patch.object(e2e.time, "monotonic", return_value=0.0),
        ):
            with e2e.run_all_lifecycle_timeout(120, 30) as deadline:
                active_term_handler = handlers[e2e.signal.SIGTERM]
                self.assertNotEqual(active_term_handler, "original-term-handler")
                self.assertEqual(current_alarm, 120)

                deadline.start_cleanup()

                self.assertIs(handlers[e2e.signal.SIGTERM], active_term_handler)
                self.assertEqual(current_alarm, 30)

        self.assertEqual(handlers[e2e.signal.SIGTERM], "original-term-handler")
        self.assertEqual(handlers[e2e.signal.SIGALRM], "original-alarm-handler")
        self.assertEqual(alarms, [0, 120, 0, 30, 0])

    def test_signal_during_phase_switch_cannot_skip_cleanup(self) -> None:
        for signal_name in ("alarm", "term"):
            with self.subTest(signal=signal_name):
                cleanup_calls: list[str] = []
                deadline = e2e.run_all_lifecycle_timeout(120, 30)

                class Lifecycle:
                    def cleanup(self):
                        cleanup_calls.append("cleanup")
                        return {"complete": True}

                bounded = e2e._BoundedCleanupLifecycleProxy(
                    Lifecycle(),
                    timeout_factory=lambda _seconds: contextlib.nullcontext(),
                    before_cleanup=deadline.start_cleanup,
                )

                def run() -> None:
                    with deadline:
                        original_arm = deadline._arm
                        injected = False

                        def arm(seconds: int) -> None:
                            nonlocal injected
                            if seconds == 30 and not injected:
                                injected = True
                                if signal_name == "alarm":
                                    deadline._expired(e2e.signal.SIGALRM, None)
                                else:
                                    deadline._interrupted(e2e.signal.SIGTERM, None)
                            original_arm(seconds)

                        deadline._arm = arm
                        bounded.cleanup()

                if signal_name == "term":
                    with self.assertRaises(e2e.ProtectedTermination):
                        run()
                else:
                    run()

                self.assertEqual(cleanup_calls, ["cleanup"])
                self.assertTrue(bounded.cleanup_attempted)
                if signal_name == "alarm":
                    self.assertIsInstance(
                        bounded.deferred_active_error,
                        e2e.ProtectedHardTimeout,
                    )

    def test_control_before_signal_mask_remains_retryable(self) -> None:
        for control in (
            e2e.ProtectedHardTimeout("injected pre-mask alarm"),
            e2e.ProtectedTermination("injected pre-mask termination"),
        ):
            with self.subTest(control=type(control).__name__):
                entries = 0
                cleanup_calls: list[str] = []

                @contextlib.contextmanager
                def blocked():
                    nonlocal entries
                    entries += 1
                    if entries == 1:
                        raise control
                    yield

                bounded = e2e._BoundedCleanupLifecycleProxy(
                    SimpleNamespace(
                        cleanup=lambda: cleanup_calls.append("cleanup")
                        or {"complete": True}
                    ),
                    timeout_factory=lambda _seconds: contextlib.nullcontext(),
                )
                with mock.patch.object(
                    e2e,
                    "_blocked_protected_signals",
                    side_effect=blocked,
                ):
                    bounded.cleanup()

                self.assertEqual(entries, 2)
                self.assertEqual(cleanup_calls, ["cleanup"])
                self.assertTrue(bounded.cleanup_attempted)
                self.assertIs(bounded.deferred_active_error, control)

    def test_run_all_retries_control_before_cleanup_mask(self) -> None:
        for control in (
            e2e.ProtectedHardTimeout("injected run-all pre-mask alarm"),
            e2e.ProtectedTermination("injected run-all pre-mask termination"),
        ):
            with self.subTest(control=type(control).__name__):
                entries = 0

                @contextlib.contextmanager
                def blocked():
                    nonlocal entries
                    entries += 1
                    if entries == 1:
                        raise control
                    yield

                with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                    e2e,
                    "_blocked_protected_signals",
                    side_effect=blocked,
                ):
                    result, operations, _contexts = self.run_coordinator(temporary)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(operations.cleanup_calls, 1)
                self.assertEqual(entries, 2)

    def test_protected_timeout_reaches_the_outer_coordinator_and_runs_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(
                temporary, "protected-timeout"
            )

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(
            result.record["failure"]["category"], "ProtectedHardTimeout"
        )

    def test_success_uses_one_lock_ordered_stages_and_exactly_one_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, contexts = self.run_coordinator(temporary)

            self.assertEqual(result.exit_code, e2e.EXIT_OK)
            self.assertEqual(
                operations.calls,
                ["build", "preflight", "prepare", "plan", "apply", "wait", "e2e", "cleanup"],
            )
            self.assertEqual(operations.cleanup_calls, 1)
            self.assertEqual(contexts.locks, [pathlib.Path(temporary).resolve() / "fixture-run"])
            self.assertEqual(contexts.active_timeouts, [1200])
            self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])
            self.assertEqual(
                contexts.events,
                ["active-enter", "active-exit", "cleanup-enter", "cleanup-exit"],
            )
            self.assertNotIn("whole_timeout_seconds", result.record)
            self.assertEqual([record["name"] for record in result.record["stages"]], list(e2e.RUN_ALL_STAGES))
            self.assertTrue(all(record["status"] == "passed" for record in result.record["stages"]))
            self.assertEqual(result.record["cleanup"], {
                "authorized": True,
                "attempted": True,
                "attempts": 1,
                "status": "passed",
            })
            self.assertEqual(
                result.record["artifacts"],
                {
                    "run_all_result": {"path": str(result.record_path), "exists": True},
                    "evidence": {"path": str(result.evidence_path), "exists": True},
                    "diagnostics": {
                        "path": str(pathlib.Path(temporary).resolve() / "fixture-run" / "diagnostics.json"),
                        "exists": False,
                    },
                },
            )
            self.assertEqual(json.loads(result.record_path.read_text()), result.record)
            self.assertEqual(stat.S_IMODE(result.record_path.stat().st_mode), 0o600)

    def test_output_waits_for_cleanup_deadline_and_lock_release(self) -> None:
        contexts = self.Contexts()
        output_calls: list[int] = []

        def output(result: e2e.RunAllResult) -> None:
            self.assertFalse(contexts.lock_active)
            self.assertEqual(contexts.events[-1], "cleanup-exit")
            output_calls.append(result.exit_code)

        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(
                temporary,
                contexts=contexts,
                output=output,
            )

        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(output_calls, [e2e.EXIT_OK])
        self.assertEqual(
            contexts.events,
            ["active-enter", "active-exit", "cleanup-enter", "cleanup-exit"],
        )

    def test_output_timeout_after_cleanup_is_classified_as_cleanup_failure(self) -> None:
        def output(_result: e2e.RunAllResult) -> None:
            raise e2e.ProtectedHardTimeout("injected protected output timeout")

        with tempfile.TemporaryDirectory() as temporary:
            result, operations, contexts = self.run_coordinator(
                temporary,
                output=output,
            )

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[-1])
        self.assertEqual(result.record["failure"]["category"], "ProtectedHardTimeout")
        self.assertEqual(contexts.events[-1], "cleanup-exit")

    def test_cleanup_deadline_context_exit_failure_is_exit_three(self) -> None:
        contexts = self.Contexts()
        contexts.deadline_exit_error = e2e.ProtectedHardTimeout(
            "injected cleanup deadline exit failure"
        )
        output_calls: list[int] = []

        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(
                temporary,
                contexts=contexts,
                output=lambda value: output_calls.append(value.exit_code),
            )

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(result.record["failure"]["category"], "ProtectedHardTimeout")
        self.assertEqual(result.record["cleanup"]["status"], "failed")
        self.assertEqual(output_calls, [e2e.EXIT_CLEANUP_FAILED])

    def test_outer_teardown_cannot_revoke_committed_terminal_output(self) -> None:
        output_calls: list[int] = []

        @contextlib.contextmanager
        def outer_timeout(_seconds: int, **_kwargs: Any):
            yield
            raise e2e.ProtectedHardTimeout("injected outer teardown timeout")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            e2e,
            "hard_timeout",
            side_effect=outer_timeout,
        ):
            result, operations, _contexts = self.run_coordinator(
                temporary,
                output=lambda value: output_calls.append(value.exit_code),
            )

        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(output_calls, [e2e.EXIT_OK])

    def test_each_stage_failure_has_deterministic_exit_and_cleanup_authority(self) -> None:
        cases = {
            "build": (e2e.RUN_ALL_STAGES[0], e2e.EXIT_CONTRACT_ERROR, 0),
            "preflight": (e2e.RUN_ALL_STAGES[1], e2e.EXIT_CONTRACT_ERROR, 0),
            "prepare": (e2e.RUN_ALL_STAGES[2], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "plan": (e2e.RUN_ALL_STAGES[3], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "apply": (e2e.RUN_ALL_STAGES[4], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wait": (e2e.RUN_ALL_STAGES[5], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "e2e": (e2e.RUN_ALL_STAGES[6], e2e.EXIT_ACCEPTANCE_FAILED, 1),
        }
        operation_order = ["build", "preflight", "prepare", "plan", "apply", "wait", "e2e"]
        for failure, (stage, exit_code, cleanup_calls) in cases.items():
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, exit_code)
                self.assertEqual(result.record["failure"]["stage"], stage)
                self.assertEqual(next(value for value in result.record["stages"] if value["name"] == stage)["status"], "failed")
                self.assertEqual(operations.cleanup_calls, cleanup_calls)
                expected_calls = operation_order[: operation_order.index(failure) + 1]
                if cleanup_calls:
                    expected_calls.append("cleanup")
                self.assertEqual(operations.calls, expected_calls)
                self.assertEqual(result.record["cleanup"]["attempts"], cleanup_calls)
                self.assertEqual(
                    result.record["cleanup"]["status"],
                    "passed" if cleanup_calls else "skipped",
                )
                self.assertEqual(len(contexts.locks), 1)
                self.assertEqual(contexts.active_timeouts, [1200])
                self.assertEqual(
                    contexts.cleanup_timeouts,
                    [e2e.DEFAULT_TIMEOUTS.cleanup] if cleanup_calls else [],
                )
                diagnostics = result.record["artifacts"]["diagnostics"]
                self.assertEqual(diagnostics["exists"], failure == "wait")
                if failure == "wait":
                    self.assertIn(
                        {"kind": "diagnostics", **diagnostics},
                        result.record["failure"]["artifacts"],
                    )

    def test_timeout_and_signal_enter_reserved_cleanup_once(self) -> None:
        for failure, category in (("timeout", "TimeoutError"), ("signal", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[5])
                self.assertEqual(result.record["failure"]["category"], category)
                self.assertEqual(operations.cleanup_calls, 1)
                self.assertEqual(contexts.active_timeouts, [1200])
                self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])

    def test_concurrent_or_ambiguous_ownership_never_destroys_the_winner(self) -> None:
        cases = {
            "prepare-concurrent": (e2e.RUN_ALL_STAGES[2], "ConcurrentLifecycleError"),
            "e2e-concurrent": (e2e.RUN_ALL_STAGES[6], "ConcurrentRunError"),
            "e2e-ambiguous": (e2e.RUN_ALL_STAGES[6], "AmbiguousOwnershipError"),
        }
        for failure, (expected_stage, expected_category) in cases.items():
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.record["failure"]["stage"], expected_stage)
                self.assertEqual(result.record["failure"]["category"], expected_category)
                self.assertEqual(operations.cleanup_calls, 0)
                self.assertNotIn("cleanup", operations.calls)
                self.assertFalse(result.record["cleanup"]["authorized"])
                self.assertEqual(result.record["cleanup"]["attempts"], 0)
                self.assertEqual(result.record["cleanup"]["status"], "skipped")
                self.assertIn("ownership", result.record["cleanup"]["reason"])
                self.assertEqual(contexts.cleanup_timeouts, [])

    def test_late_lifecycle_conflict_never_destroys_the_winner(self) -> None:
        for failure in ("plan-concurrent", "apply-concurrent", "wait-concurrent"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.record["failure"]["category"], "ConcurrentLifecycleError")
                self.assertEqual(operations.cleanup_calls, 0)
                self.assertFalse(result.record["cleanup"]["authorized"])
                self.assertEqual(contexts.cleanup_timeouts, [])

    def test_ownership_suppression_survives_failure_checkpoint_error(self) -> None:
        persisted = e2e._write_private_json
        injected = False

        def checkpoint(path, value):
            nonlocal injected
            failure = value.get("failure")
            if (
                not injected
                and isinstance(failure, Mapping)
                and failure.get("category") == "ConcurrentRunError"
            ):
                injected = True
                raise OSError("injected checkpoint failure")
            persisted(path, value)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            e2e, "_write_private_json", side_effect=checkpoint
        ):
            result, operations, contexts = self.run_coordinator(temporary, "e2e-concurrent")

        self.assertTrue(injected)
        self.assertEqual(result.record["failure"]["category"], "ConcurrentRunError")
        self.assertEqual(operations.cleanup_calls, 0)
        self.assertEqual(contexts.cleanup_timeouts, [])

    def test_cleanup_runs_when_its_running_checkpoint_is_interrupted(self) -> None:
        persisted = e2e._write_private_json
        injected = False

        def checkpoint(path, value):
            nonlocal injected
            cleanup = value.get("cleanup")
            if not injected and isinstance(cleanup, Mapping) and cleanup.get("status") == "running":
                injected = True
                raise KeyboardInterrupt("injected cleanup checkpoint interrupt")
            persisted(path, value)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            e2e, "_write_private_json", side_effect=checkpoint
        ):
            result, operations, _contexts = self.run_coordinator(temporary)

        self.assertTrue(injected)
        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(result.record["cleanup"]["status"], "passed")

    def test_cleanup_checkpoint_protected_timeout_is_not_swallowed(self) -> None:
        persisted = e2e._write_private_json
        injected = False

        def checkpoint(path, value):
            nonlocal injected
            cleanup = value.get("cleanup")
            if (
                not injected
                and isinstance(cleanup, Mapping)
                and cleanup.get("status") == "running"
            ):
                injected = True
                raise e2e.ProtectedHardTimeout(
                    "injected cleanup checkpoint hard timeout"
                )
            persisted(path, value)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            e2e, "_write_private_json", side_effect=checkpoint
        ):
            result, operations, _contexts = self.run_coordinator(temporary)

        self.assertTrue(injected)
        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(operations.cleanup_calls, 0)
        self.assertEqual(result.record["failure"]["category"], "ProtectedHardTimeout")
        self.assertEqual(result.record["cleanup"]["status"], "failed")

    def test_nonblocking_or_inexact_inner_metadata_does_not_revoke_cleanup_authority(self) -> None:
        for failure in ("e2e-persistence", "e2e-concurrent-inexact"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(operations.cleanup_calls, 1)
                self.assertEqual(operations.calls[-1], "cleanup")
                self.assertTrue(result.record["cleanup"]["authorized"])
                self.assertEqual(result.record["cleanup"]["status"], "passed")
                self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])

    def test_cleanup_failure_is_not_retried_and_overrides_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(temporary, "cleanup")

            self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
            self.assertEqual(operations.cleanup_calls, 1)
            self.assertEqual(result.record["cleanup"]["attempts"], 1)
            self.assertEqual(result.record["cleanup"]["status"], "failed")
            self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[-1])

    def test_cleanup_failure_retains_inner_acceptance_as_primary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(temporary, "e2e-cleanup-primary")

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[-1])
        self.assertEqual(
            result.record["primary_failure"],
            {
                "stage": e2e.RUN_ALL_STAGES[6],
                "phase": "simultaneous-cold-initiation",
                "category": "ProbeError",
                "message": "injected cold probe failure",
                "exit_code": e2e.EXIT_ACCEPTANCE_FAILED,
                "artifacts": [
                    {
                        "kind": "evidence",
                        "path": str(result.evidence_path),
                        "exists": True,
                    }
                ],
            },
        )

    def test_cleanup_failure_after_passing_acceptance_has_no_primary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(temporary, "e2e-cleanup-success")

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(operations.cleanup_calls, 1)
        self.assertIsNone(result.record["primary_failure"])

    def test_build_command_uses_only_config_architecture_and_exact_manifest_parent(self) -> None:
        class RecordingRunner:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], pathlib.Path | None]] = []

            def run(
                self,
                args: list[str],
                *,
                env: dict[str, str] | None = None,
                cwd: pathlib.Path | None = None,
                input_text: str | None = None,
            ) -> str:
                self.calls.append((args, cwd))
                output = pathlib.Path(args[args.index("--output-dir") + 1])
                output.mkdir(parents=True)
                (output / "manifest.json").write_text("{}\n")
                (output / "envelope-linux-arm64").write_bytes(b"fixture")
                return "built fixture"

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            output = root / "artifacts"
            config = SimpleNamespace(architecture="arm64", artifact_manifest=output / "manifest.json")
            command_runner = RecordingRunner()
            operations = e2e.AwsRunAllOperations(
                config,
                SimpleNamespace(),
                command_runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )

            summary = operations.build()

            self.assertEqual(
                command_runner.calls,
                [
                    (
                        [
                            str(ROOT / "scripts" / "build_artifacts.sh"),
                            "--output-dir",
                            str(output),
                            "--architectures",
                            "arm64",
                        ],
                        ROOT,
                    )
                ],
            )
            self.assertNotIn("--allow-dirty", command_runner.calls[0][0])
            self.assertEqual(summary["manifest"], str(output / "manifest.json"))
            self.assertEqual(summary["architecture"], "arm64")

            bad_config = SimpleNamespace(architecture="arm64", artifact_manifest=output / "other.json")
            bad_operations = e2e.AwsRunAllOperations(
                bad_config,
                SimpleNamespace(),
                command_runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )
            with self.assertRaisesRegex(e2e.E2EError, "manifest.json"):
                bad_operations.build()
            self.assertEqual(len(command_runner.calls), 1)

    def test_preflight_rejects_an_unsupported_terraform_before_aws_preflight(self) -> None:
        class VersionRunner:
            def __init__(self, version: str) -> None:
                self.version = version
                self.calls: list[list[str]] = []

            def run(
                self,
                args: list[str],
                *,
                env: dict[str, str] | None = None,
                cwd: pathlib.Path | None = None,
                input_text: str | None = None,
            ) -> str:
                self.calls.append(args)
                if args != ["terraform", "version", "-json"]:
                    raise AssertionError(f"unexpected command: {args!r}")
                return json.dumps({"terraform_version": self.version})

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(architecture="amd64", artifact_manifest=root / "manifest.json")
            runner = VersionRunner("1.9.0")
            operations = e2e.AwsRunAllOperations(
                config,
                SimpleNamespace(),
                runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )

            with mock.patch.object(e2e, "run_preflight", side_effect=AssertionError("AWS preflight ran")):
                with self.assertRaisesRegex(e2e.E2EError, "requires Terraform 1.10.5; selected version is '1.9.0'"):
                    operations.preflight()

            self.assertEqual(runner.calls, [["terraform", "version", "-json"]])

    def test_run_all_preparation_reuses_the_successful_preflight_result(self) -> None:
        class VersionRunner:
            def run(self, args, *, env=None, cwd=None, input_text=None):
                if args != ["terraform", "version", "-json"]:
                    raise AssertionError(f"unexpected command: {args!r}")
                return json.dumps({"terraform_version": e2e.TERRAFORM_CORE_VERSION})

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(architecture="amd64", artifact_manifest=root / "manifest.json")
            operations = e2e.AwsRunAllOperations(
                config,
                SimpleNamespace(),
                VersionRunner(),
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )
            artifact = {"architecture": "amd64", "sha256": "a" * 64, "manifest_path": str(root / "manifest.json")}
            tailscale = object()
            operations._tailscale = tailscale

            with mock.patch.object(e2e, "run_preflight", return_value=(artifact, "123456789012")) as preflight, mock.patch.object(
                e2e, "protected_prepare", return_value={"phase": "prepared"}
            ) as prepare:
                operations.preflight()
                operations.prepare()

            preflight.assert_called_once_with(config, operations.aws, tailscale)
            prepare.assert_called_once_with(
                config,
                operations.aws,
                tailscale,
                operations.run_dir,
                validated_preflight=(artifact, "123456789012"),
            )
            with self.assertRaisesRegex(e2e.LifecycleError, "successful run-all preflight"):
                operations.prepare()

    def test_run_all_cli_defaults_preserve_run_live_as_separate_entry_point(self) -> None:
        args = e2e.build_parser().parse_args(["run-all", "--config", "config.json"])
        self.assertEqual(args.subcommand, "run-all")
        self.assertEqual(args.hard_timeout_seconds, 10800)
        self.assertEqual(args.readiness_timeout_seconds, 900)
        self.assertEqual(e2e.DEFAULT_TIMEOUTS.cleanup, 2400)
        self.assertEqual(e2e.PROTECTED_RESOURCE_CLEANUP_SECONDS, 900)
        self.assertEqual(e2e.MAX_PROTECTED_LIFECYCLE_SECONDS, 13200)
        live = e2e.build_parser().parse_args(
            ["run-live", "--config", "config.json", "--deployment", "deployment.json"]
        )
        self.assertEqual(live.subcommand, "run-live")
        recovery = e2e.build_parser().parse_args(
            [
                "recover-route-cleanup",
                "--config",
                "config.json",
                "--deployment",
                "deployment.json",
            ]
        )
        self.assertEqual(recovery.subcommand, "recover-route-cleanup")

    def test_route_recovery_cleanup_uses_only_abandoned_claim_and_cleanup(self) -> None:
        raw = route_failover_output()
        calls: list[object] = []

        class VersionRunner:
            def run(self, args, **_kwargs):
                calls.append(list(args))
                return json.dumps({"terraform_version": e2e.TERRAFORM_CORE_VERSION})

        class Lifecycle:
            def claim(self, claimed_raw, deployment, *, require_route_recovery=False):
                calls.append(
                    ("claim", claimed_raw, deployment.topology.run_id, require_route_recovery)
                )
                return {
                    "route_recovery_required": True,
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "route_transaction_id": "22222222-3333-4444-8555-666666666666",
                }

            def cleanup(self):
                calls.append("cleanup")
                return {
                    "final_residual_count": 0,
                    "route_recovery_before_cleanup": {"restored": True},
                }

        @contextlib.contextmanager
        def cleanup_envelope(seconds):
            calls.append(("cleanup-envelope-enter", seconds))
            yield
            calls.append("cleanup-envelope-exit")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            run_root = root / "runs"
            run_dir = run_root / "fixture-live"
            self.prepare_route_recovery_files(run_dir, raw)
            config = SimpleNamespace(
                run_id="fixture-live",
                config_identity="c" * 64,
                oauth_environment_names=(),
                backend={"bucket": "fixture-backend", "region": "us-west-2"},
                manifest_key="runs/fixture-live/manifest.json",
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "recover-route-cleanup",
                    "--config",
                    str(run_dir / "config.json"),
                    "--deployment",
                    str(run_dir / "deployment.json"),
                    "--run-root",
                    str(run_root),
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "_load_json", return_value=raw),
                mock.patch.object(e2e, "SubprocessRunner", return_value=VersionRunner()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(
                    e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()
                ),
                mock.patch.object(
                    e2e,
                    "lifecycle_lock",
                    side_effect=lambda _path: contextlib.nullcontext(),
                ),
                mock.patch.object(
                    e2e, "delete_exact_object_versions", return_value=[]
                ),
                mock.patch.object(
                    e2e, "cleanup_hard_timeout", side_effect=cleanup_envelope
                ),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                exit_code = e2e._route_recovery_cleanup_cli(args)

            retained = json.loads(
                (run_dir / "route-recovery-cleanup-result.json").read_text()
            )
            retained_mode = stat.S_IMODE(
                (run_dir / "route-recovery-cleanup-result.json").stat().st_mode
            )

        self.assertEqual(exit_code, e2e.EXIT_OK)
        self.assertEqual(
            calls[0], ("cleanup-envelope-enter", e2e.DEFAULT_TIMEOUTS.cleanup)
        )
        self.assertEqual(calls[1], ["terraform", "version", "-json"])
        self.assertEqual(calls[2][0], "claim")
        self.assertIs(calls[2][1], raw)
        self.assertTrue(calls[2][3])
        self.assertEqual(calls[3:], ["cleanup", "cleanup-envelope-exit"])
        self.assertEqual(retained["final_residual_count"], 0)
        self.assertEqual(retained["cleanup"], "complete")
        self.assertEqual(retained_mode, 0o600)
        self.assertEqual(json.loads(stdout.getvalue()), retained)

    def test_route_recovery_cleanup_failures_return_cleanup_exit_code(self) -> None:
        raw = route_failover_output()

        class VersionRunner:
            @staticmethod
            def run(_args, **_kwargs):
                return json.dumps({"terraform_version": e2e.TERRAFORM_CORE_VERSION})

        class Lifecycle:
            def __init__(self, cleanup):
                self.cleanup_result = cleanup

            @staticmethod
            def claim(_raw, _deployment, *, require_route_recovery=False):
                if not require_route_recovery:
                    raise AssertionError("route-only claim was not required")
                return {
                    "route_recovery_required": True,
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "route_transaction_id": "22222222-3333-4444-8555-666666666666",
                }

            def cleanup(self):
                if isinstance(self.cleanup_result, BaseException):
                    raise self.cleanup_result
                return self.cleanup_result

        cases = {
            "cleanup-error": RuntimeError("fixture cleanup failed"),
            "restoration-unverified": {
                "final_residual_count": 0,
                "route_recovery_before_cleanup": {"restored": False},
            },
            "residual": {
                "final_residual_count": 1,
                "route_recovery_before_cleanup": {"restored": True},
            },
            "missing-final-residual": {
                "route_recovery_before_cleanup": {"restored": True},
            },
            "legacy-residual-only": {
                "residual_count": 0,
                "route_recovery_before_cleanup": {"restored": True},
            },
            "boolean-residual": {
                "final_residual_count": False,
                "route_recovery_before_cleanup": {"restored": True},
            },
            "float-residual": {
                "final_residual_count": 0.0,
                "route_recovery_before_cleanup": {"restored": True},
            },
            "string-residual": {
                "final_residual_count": "0",
                "route_recovery_before_cleanup": {"restored": True},
            },
            "keyboard-interrupt": KeyboardInterrupt("fixture cleanup interrupt"),
            "system-exit": SystemExit("fixture cleanup exit"),
        }
        for name, cleanup in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "runs"
                run_dir = run_root / "fixture-live"
                self.prepare_route_recovery_files(run_dir, raw)
                config = SimpleNamespace(
                    run_id="fixture-live",
                    config_identity="c" * 64,
                    oauth_environment_names=(),
                    backend={
                        "bucket": "fixture-backend",
                        "region": "us-west-2",
                    },
                    manifest_key="runs/fixture-live/manifest.json",
                    sites={
                        "west": {"region": "us-west-2"},
                        "east": {"region": "us-east-1"},
                    },
                )
                args = e2e.build_parser().parse_args(
                    [
                        "recover-route-cleanup",
                        "--config",
                        str(run_dir / "config.json"),
                        "--deployment",
                        str(run_dir / "deployment.json"),
                        "--run-root",
                        str(run_root),
                    ]
                )
                with (
                    mock.patch.object(e2e.RunConfig, "load", return_value=config),
                    mock.patch.object(e2e, "validate_protected_execution"),
                    mock.patch.object(e2e, "_load_json", return_value=raw),
                    mock.patch.object(
                        e2e, "SubprocessRunner", return_value=VersionRunner()
                    ),
                    mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                    mock.patch.object(
                        e2e,
                        "ProtectedLifecycleAdapter",
                        return_value=Lifecycle(cleanup),
                    ),
                    mock.patch.object(
                        e2e,
                        "lifecycle_lock",
                        side_effect=lambda _path: contextlib.nullcontext(),
                    ),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e._route_recovery_cleanup_cli(args)

                self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
                self.assertFalse(
                    (run_dir / "route-recovery-cleanup-result.json").exists()
                )

    def test_route_recovery_post_claim_failures_run_cleanup_and_return_three(self) -> None:
        raw = route_failover_output()

        class VersionRunner:
            @staticmethod
            def run(_args, **_kwargs):
                return json.dumps(
                    {"terraform_version": e2e.TERRAFORM_CORE_VERSION}
                )

        valid_claim = {
            "route_recovery_required": True,
            "claim_id": "11111111-2222-4333-8444-555555555555",
            "route_transaction_id": "22222222-3333-4444-8555-666666666666",
        }
        for stage in ("invalid-claim-summary", "backend-delete", "result-write"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "runs"
                run_dir = run_root / "fixture-live"
                self.prepare_route_recovery_files(run_dir, raw)
                cleanup_calls: list[str] = []

                class Lifecycle:
                    @staticmethod
                    def claim(_raw, _deployment, *, require_route_recovery=False):
                        if not require_route_recovery:
                            raise AssertionError("route-only claim was not required")
                        if stage == "invalid-claim-summary":
                            return {
                                **valid_claim,
                                "route_recovery_required": False,
                            }
                        return valid_claim

                    @staticmethod
                    def cleanup():
                        cleanup_calls.append("cleanup")
                        return {
                            "final_residual_count": 0,
                            "route_recovery_before_cleanup": {"restored": True},
                        }

                config = SimpleNamespace(
                    run_id="fixture-live",
                    config_identity="c" * 64,
                    oauth_environment_names=(),
                    backend={
                        "bucket": "fixture-backend",
                        "region": "us-west-2",
                    },
                    manifest_key="runs/fixture-live/manifest.json",
                    sites={
                        "west": {"region": "us-west-2"},
                        "east": {"region": "us-east-1"},
                    },
                )
                args = e2e.build_parser().parse_args(
                    [
                        "recover-route-cleanup",
                        "--config",
                        str(run_dir / "config.json"),
                        "--deployment",
                        str(run_dir / "deployment.json"),
                        "--run-root",
                        str(run_root),
                    ]
                )
                delete = (
                    mock.patch.object(
                        e2e,
                        "delete_exact_object_versions",
                        side_effect=RuntimeError("fixture backend deletion failed"),
                    )
                    if stage == "backend-delete"
                    else mock.patch.object(
                        e2e, "delete_exact_object_versions", return_value=[]
                    )
                )
                write = (
                    mock.patch.object(
                        e2e,
                        "_write_private_json",
                        side_effect=OSError("fixture result persistence failed"),
                    )
                    if stage == "result-write"
                    else contextlib.nullcontext()
                )
                with (
                    mock.patch.object(e2e.RunConfig, "load", return_value=config),
                    mock.patch.object(e2e, "validate_protected_execution"),
                    mock.patch.object(e2e, "_load_json", return_value=raw),
                    mock.patch.object(
                        e2e, "SubprocessRunner", return_value=VersionRunner()
                    ),
                    mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                    mock.patch.object(
                        e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()
                    ),
                    mock.patch.object(
                        e2e,
                        "lifecycle_lock",
                        side_effect=lambda _path: contextlib.nullcontext(),
                    ),
                    delete,
                    write,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e._route_recovery_cleanup_cli(args)

                self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
                self.assertEqual(cleanup_calls, ["cleanup"])
                self.assertFalse(
                    (run_dir / "route-recovery-cleanup-result.json").exists()
                )

    def test_route_recovery_classifies_lock_exit_and_stdout_after_claim(self) -> None:
        raw = route_failover_output()

        class VersionRunner:
            @staticmethod
            def run(_args, **_kwargs):
                return json.dumps(
                    {"terraform_version": e2e.TERRAFORM_CORE_VERSION}
                )

        class Lifecycle:
            @staticmethod
            def claim(_raw, _deployment, *, require_route_recovery=False):
                return {
                    "route_recovery_required": require_route_recovery,
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "route_transaction_id": "22222222-3333-4444-8555-666666666666",
                }

            @staticmethod
            def cleanup():
                return {
                    "final_residual_count": 0,
                    "route_recovery_before_cleanup": {"restored": True},
                }

        failures = (
            ("lock", KeyboardInterrupt("lock exit interrupt")),
            ("lock", SystemExit("lock exit system exit")),
            ("lock", OSError("lock exit failure")),
            ("stdout", KeyboardInterrupt("stdout interrupt")),
            ("stdout", SystemExit("stdout system exit")),
            ("stdout", OSError("stdout failure")),
        )
        for boundary, failure in failures:
            with self.subTest(
                boundary=boundary, category=type(failure).__name__
            ), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "runs"
                run_dir = run_root / "fixture-live"
                self.prepare_route_recovery_files(run_dir, raw)
                config = SimpleNamespace(
                    run_id="fixture-live",
                    config_identity="c" * 64,
                    oauth_environment_names=(),
                    backend={
                        "bucket": "fixture-backend",
                        "region": "us-west-2",
                    },
                    manifest_key="runs/fixture-live/manifest.json",
                    sites={
                        "west": {"region": "us-west-2"},
                        "east": {"region": "us-east-1"},
                    },
                )
                args = e2e.build_parser().parse_args(
                    [
                        "recover-route-cleanup",
                        "--config",
                        str(run_dir / "config.json"),
                        "--deployment",
                        str(run_dir / "deployment.json"),
                        "--run-root",
                        str(run_root),
                    ]
                )

                @contextlib.contextmanager
                def lock(_path):
                    yield
                    if boundary == "lock":
                        raise failure

                output = (
                    mock.patch(
                        "builtins.print", side_effect=failure
                    )
                    if boundary == "stdout"
                    else contextlib.nullcontext()
                )
                with (
                    mock.patch.object(e2e.RunConfig, "load", return_value=config),
                    mock.patch.object(e2e, "validate_protected_execution"),
                    mock.patch.object(
                        e2e, "SubprocessRunner", return_value=VersionRunner()
                    ),
                    mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                    mock.patch.object(
                        e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()
                    ),
                    mock.patch.object(e2e, "lifecycle_lock", side_effect=lock),
                    mock.patch.object(
                        e2e, "delete_exact_object_versions", return_value=[]
                    ),
                    output,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e._route_recovery_cleanup_cli(args)

                self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
                if boundary == "lock":
                    self.assertFalse(
                        (run_dir / "route-recovery-cleanup-result.json").exists()
                    )

    def test_route_recovery_pending_receipt_resumes_only_backend_finalization(self) -> None:
        raw = route_failover_output()

        class VersionRunner:
            @staticmethod
            def run(_args, **_kwargs):
                raise AssertionError(
                    "receipt-only backend finalization invoked Terraform"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            run_root = root / "runs"
            run_dir = run_root / "fixture-live"
            self.prepare_route_recovery_files(run_dir, raw)
            config = SimpleNamespace(
                run_id="fixture-live",
                config_identity="c" * 64,
                oauth_environment_names=(),
                backend={
                    "bucket": "fixture-backend",
                    "region": "us-west-2",
                },
                manifest_key="runs/fixture-live/manifest.json",
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            receipt_path = run_dir / "route-recovery-cleanup-result.json"
            e2e._write_private_json(
                receipt_path,
                e2e._new_route_recovery_receipt(
                    config,
                    raw,
                    claim_id="11111111-2222-4333-8444-555555555555",
                    transaction_id="22222222-3333-4444-8555-666666666666",
                    cleanup_result={"final_residual_count": 0},
                    cleanup="backend-finalization-pending",
                ),
            )
            args = e2e.build_parser().parse_args(
                [
                    "recover-route-cleanup",
                    "--config",
                    str(run_dir / "config.json"),
                    "--deployment",
                    str(run_dir / "deployment.json"),
                    "--run-root",
                    str(run_root),
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(
                    e2e, "SubprocessRunner", return_value=VersionRunner()
                ),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(
                    e2e,
                    "ProtectedLifecycleAdapter",
                    side_effect=AssertionError("acceptance lifecycle was reconstructed"),
                ),
                mock.patch.object(
                    e2e,
                    "lifecycle_lock",
                    side_effect=lambda _path: contextlib.nullcontext(),
                ),
                mock.patch.object(
                    e2e, "delete_exact_object_versions", return_value=[]
                ) as delete,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                exit_code = e2e._route_recovery_cleanup_cli(args)

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_mode = stat.S_IMODE(receipt_path.stat().st_mode)

        self.assertEqual(exit_code, e2e.EXIT_OK)
        self.assertEqual(receipt["cleanup"], "complete")
        self.assertEqual(receipt_mode, 0o600)
        delete.assert_called_once_with(
            mock.ANY,
            bucket="fixture-backend",
            key="runs/fixture-live/manifest.json",
            region="us-west-2",
            dry_run=False,
        )

    def test_private_json_requires_parent_directory_fsync(self) -> None:
        real_fsync = os.fsync
        fsync_kinds: list[str] = []

        def fsync(descriptor):
            kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
            fsync_kinds.append(kind)
            if kind == "directory":
                raise OSError("fixture directory fsync failed")
            return real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "receipt.json"
            with mock.patch.object(e2e.os, "fsync", side_effect=fsync):
                with self.assertRaisesRegex(OSError, "directory fsync"):
                    e2e._write_private_json(path, {"safe": True})
            mode = stat.S_IMODE(path.stat().st_mode)

        self.assertEqual(fsync_kinds, ["file", "directory"])
        self.assertEqual(mode, 0o600)

    def test_route_recovery_rejects_symlinked_run_directory_before_tools(self) -> None:
        config = SimpleNamespace(run_id="fixture-live")
        for destination in ("sibling", "outside"):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "runs"
                run_root.mkdir()
                target = (
                    run_root / "another-run"
                    if destination == "sibling"
                    else root / "outside-run"
                )
                target.mkdir()
                alias = run_root / "fixture-live"
                alias.symlink_to(target, target_is_directory=True)
                args = e2e.build_parser().parse_args(
                    [
                        "recover-route-cleanup",
                        "--config",
                        str(alias / "config.json"),
                        "--deployment",
                        str(alias / "deployment.json"),
                        "--run-root",
                        str(run_root),
                    ]
                )
                with (
                    mock.patch.object(e2e.RunConfig, "load", return_value=config),
                    mock.patch.object(e2e, "validate_protected_execution"),
                    mock.patch.object(
                        e2e,
                        "SubprocessRunner",
                        side_effect=AssertionError("Terraform tool was constructed"),
                    ),
                ):
                    with self.assertRaisesRegex(e2e.E2EError, "symlinked path component"):
                        e2e._route_recovery_cleanup_cli(args)

    def test_route_recovery_rejects_all_path_and_lock_symlinks_before_tools(self) -> None:
        raw = route_failover_output()
        config = SimpleNamespace(
            run_id="fixture-live",
            sites={
                "west": {"region": "us-west-2"},
                "east": {"region": "us-east-1"},
            },
        )
        for kind in (
            "run-root",
            "config",
            "deployment",
            "receipt",
            "lifecycle-lock",
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                real_run_root = root / "runs"
                run_dir = real_run_root / "fixture-live"
                self.prepare_route_recovery_files(run_dir, raw)
                selected_run_root = real_run_root
                if kind == "run-root":
                    selected_run_root = root / "runs-alias"
                    selected_run_root.symlink_to(
                        real_run_root, target_is_directory=True
                    )
                elif kind == "config":
                    (run_dir / "config.json").unlink()
                    target = run_dir / "config-target.json"
                    target.write_text("{}\n", encoding="utf-8")
                    (run_dir / "config.json").symlink_to(target)
                elif kind == "deployment":
                    (run_dir / "deployment.json").unlink()
                    target = run_dir / "deployment-target.json"
                    target.write_text(json.dumps(raw) + "\n", encoding="utf-8")
                    (run_dir / "deployment.json").symlink_to(target)
                elif kind == "receipt":
                    target = run_dir / "receipt-target.json"
                    target.write_text("{}\n", encoding="utf-8")
                    (run_dir / "route-recovery-cleanup-result.json").symlink_to(
                        target
                    )
                else:
                    target = run_dir / "lock-target"
                    target.write_text("unchanged\n", encoding="utf-8")
                    (run_dir / "lifecycle.lock").symlink_to(target)
                args = e2e.build_parser().parse_args(
                    [
                        "recover-route-cleanup",
                        "--config",
                        str(selected_run_root / "fixture-live" / "config.json"),
                        "--deployment",
                        str(
                            selected_run_root
                            / "fixture-live"
                            / "deployment.json"
                        ),
                        "--run-root",
                        str(selected_run_root),
                    ]
                )
                with (
                    mock.patch.object(e2e.RunConfig, "load", return_value=config),
                    mock.patch.object(e2e, "validate_protected_execution"),
                    mock.patch.object(
                        e2e,
                        "SubprocessRunner",
                        side_effect=AssertionError("Terraform tool was constructed"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        (e2e.E2EError, e2e.LifecycleError),
                        "symlink|must not be a symlink",
                    ):
                        e2e._route_recovery_cleanup_cli(args)
                if kind == "lifecycle-lock":
                    self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")

    def test_run_live_malformed_deployment_still_cleans_up_and_writes_schema_three(self) -> None:
        cleanup_calls: list[str] = []

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                return self

            def start_cleanup(self):
                self.cleanup_started = True

            def __exit__(self, *_error):
                return None

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                return {"final_residual_count": 0}

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            run_root = root / "runs"
            deployment = root / "malformed.json"
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={"west": {"region": "us-west-2"}, "east": {"region": "us-east-1"}},
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(deployment),
                    "--run-root",
                    str(run_root),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "_load_json", side_effect=e2e.E2EError("malformed deployment JSON")),
                mock.patch.object(e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                exit_code = e2e._live_cli(args)

            evidence_path = run_root / "fixture-live" / "aws-two-region-e2e-evidence.json"
            evidence = json.loads(evidence_path.read_text())
        self.assertEqual(exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])
        self.assertEqual(evidence["schema"], e2e.SYMMETRIC_EVIDENCE_SCHEMA)
        self.assertEqual(evidence["failure"]["message"], "malformed deployment JSON")
        self.assertEqual(evidence["lifecycle"]["cleanup"], "passed")

    def test_run_live_control_flow_uses_the_separate_cleanup_reservation(self) -> None:
        cleanup_calls: list[str] = []
        timeout_events: list[str] = []
        control = e2e.ProtectedTermination("injected direct-live termination")

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                timeout_events.append("active-enter")
                return self

            def start_cleanup(self):
                if self.cleanup_started:
                    return
                self.cleanup_started = True
                timeout_events.extend(["active-exit", "cleanup-enter"])

            def __exit__(self, *_error):
                timeout_events.append(
                    "cleanup-exit" if self.cleanup_started else "active-exit"
                )

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                return {"final_residual_count": 0}

        class Runner:
            @staticmethod
            def run():
                raise control

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(root / "deployment.json"),
                    "--run-root",
                    str(root / "runs"),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "SymmetricTwoRegionE2ERunner", return_value=Runner()),
                mock.patch.object(e2e, "_load_json", return_value={}),
                mock.patch.object(
                    e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()
                ),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = e2e._live_cli(args)

        self.assertEqual(exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])
        self.assertEqual(
            timeout_events,
            ["active-enter", "active-exit", "cleanup-enter", "cleanup-exit"],
        )

    def test_run_live_cleanup_control_flow_is_exit_three(self) -> None:
        cleanup_calls: list[str] = []
        active_control = e2e.ProtectedTermination("injected direct-live termination")
        cleanup_control = e2e.ProtectedHardTimeout("injected direct-live cleanup timeout")

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                return self

            def start_cleanup(self):
                self.cleanup_started = True

            def __exit__(self, *_error):
                return None

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                raise cleanup_control

        class Runner:
            @staticmethod
            def run():
                raise active_control

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(root / "deployment.json"),
                    "--run-root",
                    str(root / "runs"),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "SymmetricTwoRegionE2ERunner", return_value=Runner()),
                mock.patch.object(e2e, "_load_json", return_value={}),
                mock.patch.object(
                    e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()
                ),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = e2e._live_cli(args)

        self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])

    def test_run_live_protected_error_after_cleanup_is_exit_three(self) -> None:
        cleanup_calls: list[str] = []
        post_cleanup_control = e2e.ProtectedHardTimeout(
            "injected post-cleanup evidence timeout"
        )

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                return self

            def start_cleanup(self):
                self.cleanup_started = True

            def __exit__(self, *_error):
                return None

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                return {"final_residual_count": 0}

        class Runner:
            def __init__(self, bounded_lifecycle):
                self.bounded_lifecycle = bounded_lifecycle

            def run(self):
                self.bounded_lifecycle.cleanup()
                raise post_cleanup_control

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(root / "deployment.json"),
                    "--run-root",
                    str(root / "runs"),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(
                    e2e,
                    "SymmetricTwoRegionE2ERunner",
                    side_effect=lambda **kwargs: Runner(kwargs["lifecycle"]),
                ),
                mock.patch.object(e2e, "_load_json", return_value={}),
                mock.patch.object(
                    e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()
                ),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = e2e._live_cli(args)

        self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])

    def test_run_live_cleanup_deadline_exit_failure_is_exit_three(self) -> None:
        cleanup_calls: list[str] = []
        active_control = e2e.ProtectedTermination("injected direct-live termination")

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                return self

            def start_cleanup(self):
                self.cleanup_started = True

            def __exit__(self, *_error):
                if self.cleanup_started:
                    raise e2e.ProtectedHardTimeout(
                        "injected direct-live deadline exit failure"
                    )
                return None

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                return {"final_residual_count": 0}

        class Runner:
            @staticmethod
            def run():
                raise active_control

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(root / "deployment.json"),
                    "--run-root",
                    str(root / "runs"),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "SymmetricTwoRegionE2ERunner", return_value=Runner()),
                mock.patch.object(e2e, "_load_json", return_value={}),
                mock.patch.object(
                    e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()
                ),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = e2e._live_cli(args)

        self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])

    def test_run_live_output_failure_quarantines_passing_evidence(self) -> None:
        cleanup_calls: list[str] = []

        class Deadline:
            cleanup_started = False

            def __enter__(self):
                return self

            def start_cleanup(self):
                self.cleanup_started = True

            def __exit__(self, *_error):
                return None

        class Lifecycle:
            def cleanup(self):
                cleanup_calls.append("cleanup")
                return {"final_residual_count": 0}

        class Runner:
            def __init__(self, bounded_lifecycle, evidence_path):
                self.bounded_lifecycle = bounded_lifecycle
                self.evidence_path = evidence_path

            def run(self):
                self.bounded_lifecycle.cleanup()
                self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
                evidence = {"status": "passed"}
                self.evidence_path.write_text(json.dumps(evidence) + "\n")
                return e2e.LiveRunResult(
                    e2e.EXIT_OK,
                    self.evidence_path,
                    evidence,
                )

        def terminal_output(*_args, **kwargs):
            if kwargs.get("file") is sys.stderr:
                return None
            raise OSError("injected terminal output failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            run_root = root / "runs"
            evidence_path = (
                run_root
                / "fixture-live"
                / "aws-two-region-e2e-evidence.json"
            )
            config = SimpleNamespace(
                run_id="fixture-live",
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                sites={
                    "west": {"region": "us-west-2"},
                    "east": {"region": "us-east-1"},
                },
            )
            args = e2e.build_parser().parse_args(
                [
                    "run-live",
                    "--config",
                    str(root / "config.json"),
                    "--deployment",
                    str(root / "deployment.json"),
                    "--run-root",
                    str(run_root),
                    "--hard-timeout-seconds",
                    "2400",
                ]
            )
            with (
                mock.patch.object(e2e.RunConfig, "load", return_value=config),
                mock.patch.object(e2e, "validate_protected_execution"),
                mock.patch.object(e2e, "SubprocessRunner", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "AwsCLI", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "ProtectedLifecycleAdapter", return_value=Lifecycle()),
                mock.patch.object(e2e, "AwsSymmetricLiveOperations", return_value=SimpleNamespace()),
                mock.patch.object(
                    e2e,
                    "SymmetricTwoRegionE2ERunner",
                    side_effect=lambda **kwargs: Runner(
                        kwargs["lifecycle"],
                        kwargs["evidence_path"],
                    ),
                ),
                mock.patch.object(e2e, "_load_json", return_value={}),
                mock.patch.object(
                    e2e, "lifecycle_lock", side_effect=lambda _path: contextlib.nullcontext()
                ),
                mock.patch.object(
                    e2e,
                    "live_lifecycle_timeout",
                    return_value=Deadline(),
                ),
                mock.patch.object(
                    e2e,
                    "_rewrite_symmetric_cleanup_failure",
                    side_effect=e2e.EvidenceError("injected evidence rewrite failure"),
                ),
                mock.patch("builtins.print", side_effect=terminal_output),
            ):
                exit_code = e2e._live_cli(args)

            quarantine = evidence_path.with_name(
                f".{evidence_path.name}.invalidated"
            )
            self.assertFalse(evidence_path.exists())
            self.assertTrue(quarantine.is_file())

        self.assertEqual(exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(cleanup_calls, ["cleanup"])

    def test_authorized_run_all_bootstrap_failures_write_only_a_minimal_private_record(self) -> None:
        approved = "fixture-run"
        trusted_environment = {
            "ENVELOPE_E2E_APPROVED_RUN_ID": approved,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
        }

        def config(
            run_id: str = approved,
            *,
            ttl_seconds: int = 20_000,
            recovery_timeout_seconds: int = 300,
        ) -> Any:
            return SimpleNamespace(
                run_id=run_id,
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl_seconds))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
                route_failover={
                    "initial_transport_router_az_by_gwlbe_az": {
                        "west": {"a": "a", "b": "b"},
                        "east": {"a": "a", "b": "b"},
                    },
                    "mutation_timeout_seconds": 120,
                    "restoration_timeout_seconds": 120,
                    "recovery_timeout_seconds": recovery_timeout_seconds,
                },
                sites={
                    site: {
                        "remote_site_cidrs": [
                            f"10.{index}.4.0/24",
                            f"10.{index}.5.0/24",
                        ],
                        "transport_router_az_keys": ["a", "b"],
                    }
                    for index, site in enumerate(e2e.SITES, start=10)
                },
            )

        cases = {
            "config-load": (e2e.LifecycleError("raw-user-payload-must-not-be-retained"), []),
            "run-id-match": (config("another-run"), []),
            "ttl": (config(ttl_seconds=60), []),
            "timeout-arguments": (config(), ["--hard-timeout-seconds", "0"]),
            "readiness-timeout": (config(), ["--readiness-timeout-seconds", "10801"]),
            "route-failover-budget": (
                config(recovery_timeout_seconds=2000),
                [],
            ),
            "evidence-path": (config(), ["--evidence", "OUTSIDE"]),
        }
        for expected_gate, (loaded, extra) in cases.items():
            with self.subTest(gate=expected_gate), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "ignored-runs"
                selected_extra = [str(root / "outside" / "evidence.json") if value == "OUTSIDE" else value for value in extra]
                argv = [
                    "run-all",
                    "--config",
                    str(root / "operator-private-config.json"),
                    "--run-root",
                    str(run_root),
                    *selected_extra,
                ]
                load = mock.Mock(side_effect=loaded) if isinstance(loaded, BaseException) else mock.Mock(return_value=loaded)
                with (
                    mock.patch.object(e2e.RunConfig, "load", load),
                    mock.patch.dict(e2e.os.environ, trusted_environment, clear=True),
                    mock.patch.object(e2e, "SubprocessRunner", side_effect=AssertionError("resource authority acquired")),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e.main(argv)

                self.assertEqual(exit_code, e2e.EXIT_CONTRACT_ERROR)
                load.assert_called_once_with(root / "operator-private-config.json", enforce_future_expiry=False)
                record_path = run_root / approved / "run-all-result.json"
                self.assertTrue(record_path.is_file())
                self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o600)
                record = json.loads(record_path.read_text())
                self.assertEqual(
                    set(record),
                    {
                        "schema",
                        "kind",
                        "run_id",
                        "status",
                        "exit_code",
                        "bootstrap",
                        "resource_authority",
                        "cleanup",
                        "failure",
                    },
                )
                self.assertEqual(record["run_id"], approved)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(record["exit_code"], e2e.EXIT_CONTRACT_ERROR)
                self.assertTrue(record["bootstrap"])
                self.assertFalse(record["resource_authority"])
                self.assertEqual(
                    record["cleanup"],
                    {
                        "authorized": False,
                        "attempted": False,
                        "attempts": 0,
                        "status": "skipped",
                    },
                )
                gate = "timeout-arguments" if expected_gate == "readiness-timeout" else expected_gate
                self.assertEqual(record["failure"]["gate"], gate)
                self.assertEqual(record["failure"]["exit_code"], e2e.EXIT_CONTRACT_ERROR)
                serialized = json.dumps(record, sort_keys=True)
                self.assertNotIn("raw-user-payload", serialized)
                self.assertNotIn("another-run", serialized)
                self.assertNotIn("operator-private-config", serialized)
                self.assertNotIn(str(root / "outside"), serialized)
                self.assertFalse((run_root / "another-run").exists())

    def test_invalid_or_untrusted_run_all_approval_writes_no_bootstrap_artifact(self) -> None:
        environments = {
            "missing": {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            "invalid": {
                "ENVELOPE_E2E_APPROVED_RUN_ID": "../escape",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
            },
            "untrusted": {
                "ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-run",
                "GITHUB_EVENT_NAME": "pull_request",
            },
        }
        for name, environment in environments.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                run_root = pathlib.Path(temporary).resolve() / "ignored-runs"
                with (
                    mock.patch.dict(e2e.os.environ, environment, clear=True),
                    mock.patch.object(e2e.RunConfig, "load", side_effect=AssertionError("config was read")),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e.main(
                        [
                            "run-all",
                            "--config",
                            "operator-private-config.json",
                            "--run-root",
                            str(run_root),
                        ]
                    )

                self.assertEqual(exit_code, e2e.EXIT_CONTRACT_ERROR)
                self.assertFalse(run_root.exists())

    def test_run_all_rejects_untrusted_context_before_credentials_or_build(self) -> None:
        args = e2e.build_parser().parse_args(["run-all", "--config", "config.json"])
        config = SimpleNamespace(run_id="fixture-run")
        environment = {
            "ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-run",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with (
            mock.patch.object(e2e.RunConfig, "load", return_value=config),
            mock.patch.dict(e2e.os.environ, environment, clear=True),
            mock.patch.object(e2e, "SubprocessRunner", side_effect=AssertionError("credentials constructed")),
            self.assertRaisesRegex(e2e.E2EError, "prohibited"),
        ):
            e2e._run_all_cli(args)


class ProtectedExecutionTest(unittest.TestCase):
    def protected_adapter(
        self, temporary: str
    ) -> tuple[dict[str, Any], DurableManifestStore, e2e.ProtectedLifecycleAdapter]:
        raw = protected_output()
        store = DurableManifestStore(ready_lifecycle_manifest(raw))
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(run_id="fixture-live", sites=lifecycle_sites())
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
        adapter.verify_no_drift = lambda stage: {"clean": True, "stage": stage}
        return raw, store, adapter

    def run_adapter_failure(
        self,
        temporary: str,
        failure: str,
        *,
        cleanup_timeout: Any,
        recover_hook: Any = None,
    ) -> tuple[e2e.LiveRunResult, DurableManifestStore, e2e.ProtectedLifecycleAdapter, list[str]]:
        raw, store, adapter = self.protected_adapter(temporary)
        store.recover_hook = recover_hook
        protected_calls: list[str] = []

        def protected(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
            protected_calls.append("cleanup")
            self.assertEqual(store.value["phase"], "e2e_failed")
            self.assertFalse(store.value["e2e"]["passed"])
            return {"destroyed": True}

        bounded = e2e._BoundedCleanupLifecycleProxy(adapter, cleanup_timeout)
        with (
            mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
            mock.patch.object(e2e, "protected_cleanup", side_effect=protected),
        ):
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations(failure),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()
        return result, store, adapter, protected_calls

    def test_requires_exact_approval_and_rejects_untrusted_ci(self) -> None:
        with self.assertRaisesRegex(e2e.E2EError, "exactly match"):
            e2e.validate_protected_execution("fixture-live", {})
        with self.assertRaisesRegex(e2e.E2EError, "prohibited"):
            e2e.validate_protected_execution(
                "fixture-live",
                {"ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-live", "GITHUB_EVENT_NAME": "pull_request"},
            )
        e2e.validate_protected_execution(
            "fixture-live", {"ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-live", "GITHUB_EVENT_NAME": "workflow_dispatch"}
        )

    def test_route_only_claim_rejects_ready_manifest_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)

            with self.assertRaisesRegex(e2e.ClaimPersistenceError, "active abandoned"):
                adapter.claim(raw, deployment, require_route_recovery=True)

        self.assertEqual(store.writes, [])

    def test_manifest_requires_exactly_four_explicit_transport_nodes_and_no_targets(self) -> None:
        expected = fixture_live_tailnet_hostnames()
        self.assertEqual(len(expected), 4)
        self.assertTrue(all("-transport-" in hostname for hostname in expected))
        self.assertFalse(any("-target-" in hostname for hostname in expected))

        for mutation in ("target-node", "wrong-role"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                if mutation == "target-node":
                    old = expected[0]
                    replacement = "fixture-live-west-target-a"
                    store.value["tailnet"]["expected_hostnames"][0] = replacement
                    store.value["tailnet"]["device_ids"][replacement] = store.value["tailnet"][
                        "device_ids"
                    ].pop(old)
                    store.value["tailnet"]["device_roles"][replacement] = store.value["tailnet"][
                        "device_roles"
                    ].pop(old)
                else:
                    store.value["tailnet"]["device_roles"][expected[0]] = "target"
                with self.assertRaisesRegex(e2e.DeploymentError, "exactly four role-separated"):
                    adapter.claim(raw, deployment)

    def test_timeout_and_sigterm_atomically_handoff_only_the_owned_claim(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        for failure, category in (("acceptance-timeout", "TimeoutError"), ("active-interrupt", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, store, adapter, protected_calls = self.run_adapter_failure(
                    temporary,
                    failure,
                    cleanup_timeout=cleanup_timeout,
                )

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(protected_calls, ["cleanup"])
                self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])
                self.assertEqual(store.writes[1][1], '"fixture-etag-1"')
                self.assertEqual(adapter.manifest, store.value)
                self.assertEqual(store.value["phase"], "e2e_failed")
                self.assertEqual(
                    set(store.value["e2e"]),
                    {"claim_id", "output_sha256", "started_at", "finished_at", "passed"},
                )
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["summary"]["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                self.assertTrue(cleanup["summary"]["e2e_claim_handoff"]["claim_identity_preserved"])

        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup] * 2)

    def test_keyboard_interrupt_after_committed_claim_reserves_cleanup_and_redacts_write_error(self) -> None:
        sensitive = "private-provider-response-must-not-reach-evidence"
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            protected_calls: list[str] = []

            def commit_then_interrupt(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                if value["phase"] == "e2e_running":
                    raise KeyboardInterrupt(sensitive)

            def protected(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
                protected_calls.append("cleanup")
                return {"destroyed": True}

            store.write_hook = commit_then_interrupt
            operations = FakeLiveOperations()
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", side_effect=protected),
            ):
                result = e2e.TwoRegionE2ERunner(
                    run_id="fixture-live",
                    raw_deployment=raw,
                    site_regions={"west": "us-west-2", "east": "us-east-1"},
                    lifecycle=adapter,
                    operations=operations,
                    evidence_path=pathlib.Path(temporary) / "evidence.json",
                    monotonic=lambda: 0.0,
                ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["failure"]["category"], "KeyboardInterrupt")
        self.assertNotIn(sensitive, json.dumps(result.evidence))
        self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")
        self.assertNotIn("diagnostics", operations.calls)
        self.assertEqual(protected_calls, ["cleanup"])
        self.assertEqual(store.value["phase"], "e2e_failed")

    def test_cleanup_handoff_rejects_changed_missing_claim_and_etag(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield

        def mutation(kind: str) -> Any:
            def mutate(store: DurableManifestStore) -> None:
                if store.recover_count != 2:
                    return
                if kind == "changed-claim":
                    store.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                elif kind == "missing-claim":
                    store.value.pop("e2e")
                else:
                    store.remote_etag = '"another-writer-etag"'

            return mutate

        for kind, category, resolution, message in (
            (
                "changed-claim",
                "ConcurrentRunError",
                "competing-claim",
                "owned by another runner",
            ),
            (
                "missing-claim",
                "AmbiguousOwnershipError",
                "ambiguous-ownership",
                "ownership is ambiguous",
            ),
            (
                "changed-etag",
                "AmbiguousOwnershipError",
                "ambiguous-ownership",
                "ownership is ambiguous",
            ),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                result, store, adapter, protected_calls = self.run_adapter_failure(
                    temporary,
                    "acceptance-timeout",
                    cleanup_timeout=cleanup_timeout,
                    recover_hook=mutation(kind),
                )

                self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
                self.assertEqual(protected_calls, [])
                self.assertEqual(len(store.writes), 1)
                self.assertEqual(adapter.manifest["phase"], "e2e_running")
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["status"], "failed")
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], resolution)
                self.assertIn(message, result.error or "")

    def test_cleanup_timeout_occurs_after_terminal_claim_handoff_without_retry(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield
            raise TimeoutError("cleanup reservation expired")

        with tempfile.TemporaryDirectory() as temporary:
            result, store, adapter, protected_calls = self.run_adapter_failure(
                temporary,
                "acceptance-timeout",
                cleanup_timeout=cleanup_timeout,
            )

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(protected_calls, ["cleanup"])
        self.assertEqual(store.value["phase"], "e2e_failed")
        self.assertEqual(adapter.manifest, store.value)
        self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

    def test_normal_finish_remains_the_only_terminal_write_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            adapter.finish(False)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}),
            ):
                cleanup = adapter.cleanup()

        self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])
        self.assertEqual(store.recover_count, 2)
        self.assertNotIn("e2e_claim_handoff", cleanup)

    def test_claim_write_reconciliation_distinguishes_durable_outcomes(self) -> None:
        sensitive = "raw-provider-error-with-private-request-body"

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            with self.assertRaises(e2e.ClaimPersistenceError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "unclaimed")
            self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)

            def commit_then_error(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                raise e2e.LifecycleError(sensitive)

            store.write_hook = commit_then_error
            summary = adapter.claim(raw, deployment)

            self.assertEqual(summary["claim_persistence"], "recovered-owned-claim")
            self.assertEqual(adapter._ownership_state, "running-owned")
            self.assertEqual(adapter.manifest, store.value)
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)

            def lose_compare_and_swap(
                target: DurableManifestStore, value: dict[str, Any], _if_match: str | None
            ) -> None:
                competitor = copy.deepcopy(value)
                competitor["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                target.value = competitor
                target.remote_etag = '"competitor-etag"'
                raise e2e.LifecycleError(sensitive)

            store.write_hook = lose_compare_and_swap
            with self.assertRaises(e2e.ConcurrentRunError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "competing")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            def fail_recovery(target: DurableManifestStore) -> None:
                if target.recover_count > 1:
                    raise e2e.LifecycleError(sensitive)

            store.recover_hook = fail_recovery
            with self.assertRaises(e2e.AmbiguousOwnershipError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "ambiguous")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.AmbiguousOwnershipError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

    def test_committed_claim_interrupts_propagate_with_cleanup_authority(self) -> None:
        sensitive = "private-provider-response-must-not-reach-evidence"
        for write_error in (TimeoutError(sensitive), KeyboardInterrupt(sensitive)):
            with self.subTest(category=type(write_error).__name__), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)

                def commit_then_interrupt(
                    target: DurableManifestStore,
                    value: dict[str, Any],
                    if_match: str | None,
                    error: BaseException = write_error,
                ) -> None:
                    target.commit(value, if_match)
                    raise error

                store.write_hook = commit_then_interrupt
                with self.assertRaises(type(write_error)) as raised:
                    adapter.claim(raw, deployment)

                self.assertNotIn(sensitive, str(raised.exception))
                self.assertEqual(adapter._ownership_state, "running-owned")
                self.assertEqual(adapter.manifest, store.value)
                store.write_hook = None
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    result = adapter.cleanup()

                cleanup.assert_called_once()
                self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                self.assertEqual(store.value["phase"], "e2e_failed")

    def test_interrupt_after_every_pending_claim_assignment_keeps_ready_cleanup_authorized(self) -> None:
        assignments = (
            "_claim_original_manifest",
            "_claim_original_etag",
            "_claim_etag",
            "_ownership_state",
            "manifest",
            "_last_persistence_resolution",
        )
        for index, field in enumerate(assignments):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
                store.write_hook = write_hook

                def interrupt_after_assignment(target: Any, name: str, value: Any) -> None:
                    object.__setattr__(target, name, value)
                    if target is adapter and name == field:
                        raise KeyboardInterrupt(f"interrupt after {field}")

                with (
                    mock.patch.object(
                        e2e.ProtectedLifecycleAdapter,
                        "__setattr__",
                        new=interrupt_after_assignment,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    adapter.claim(raw, deployment)

                write_hook.assert_not_called()
                self.assertEqual(
                    adapter._ownership_state,
                    "claim-pending" if index >= assignments.index("_ownership_state") else "unclaimed",
                )
                self.assertEqual(isinstance(adapter.manifest, dict), index >= assignments.index("manifest"))
                store.write_hook = None
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    result = adapter.cleanup()

                cleanup.assert_called_once()
                self.assertTrue(cleanup.call_args.kwargs["recover"])
                self.assertEqual(adapter._ownership_state, "unclaimed")
                self.assertIsNone(adapter.manifest)
                self.assertIsNone(adapter._claim_etag)
                self.assertIsNone(adapter._claim_original_manifest)
                self.assertIsNone(adapter._claim_original_etag)
                self.assertNotIn("e2e_claim_handoff", result)
                self.assertEqual(store.writes, [])
                if index >= assignments.index("_ownership_state"):
                    self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")

    def test_pending_claim_without_candidate_suppresses_a_competitor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
            store.write_hook = write_hook

            def interrupt_after_pending_state(target: Any, name: str, value: Any) -> None:
                object.__setattr__(target, name, value)
                if target is adapter and name == "_ownership_state":
                    raise KeyboardInterrupt("interrupt before pending candidate assignment")

            with (
                mock.patch.object(
                    e2e.ProtectedLifecycleAdapter,
                    "__setattr__",
                    new=interrupt_after_pending_state,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.claim(raw, deployment)

            write_hook.assert_not_called()
            self.assertEqual(adapter._ownership_state, "claim-pending")
            self.assertIsNone(adapter.manifest)
            competitor = copy.deepcopy(store.value)
            competitor["phase"] = "e2e_running"
            competitor["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "f" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            }
            store.value = competitor
            store.remote_etag = '"competitor-etag"'
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()

            cleanup.assert_not_called()
            self.assertEqual(adapter._ownership_state, "competing")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)

    def test_interrupt_after_pending_candidate_assignment_reconciles_before_cleanup(self) -> None:
        for outcome in ("not-committed", "competing", "own-commit", "ambiguous"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
                store.write_hook = write_hook

                def interrupt_after_candidate_assignment(target: Any, name: str, value: Any) -> None:
                    object.__setattr__(target, name, value)
                    if target is adapter and name == "manifest":
                        raise KeyboardInterrupt("interrupt after pending candidate assignment")

                with (
                    mock.patch.object(
                        e2e.ProtectedLifecycleAdapter,
                        "__setattr__",
                        new=interrupt_after_candidate_assignment,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    adapter.claim(raw, deployment)

                write_hook.assert_not_called()
                self.assertEqual(adapter._ownership_state, "claim-pending")
                self.assertEqual(adapter._claim_original_manifest, store.value)
                self.assertEqual(adapter._claim_original_etag, store.remote_etag)
                candidate = copy.deepcopy(adapter.manifest)
                original_etag = adapter._claim_original_etag
                self.assertIsInstance(candidate, dict)
                self.assertIsInstance(original_etag, str)
                store.write_hook = None

                if outcome == "competing":
                    store.value = copy.deepcopy(candidate)
                    store.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                    store.remote_etag = '"competitor-etag"'
                elif outcome == "own-commit":
                    store.commit(candidate, original_etag)
                elif outcome == "ambiguous":
                    store.remote_etag = '"unexplained-etag"'

                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    if outcome == "competing":
                        with self.assertRaises(e2e.ConcurrentRunError):
                            adapter.cleanup()
                    elif outcome == "ambiguous":
                        with self.assertRaises(e2e.AmbiguousOwnershipError):
                            adapter.cleanup()
                    else:
                        result = adapter.cleanup()

                self.assertIsNone(adapter._claim_original_manifest)
                self.assertIsNone(adapter._claim_original_etag)
                if outcome == "not-committed":
                    cleanup.assert_called_once()
                    self.assertTrue(cleanup.call_args.kwargs["recover"])
                    self.assertEqual(adapter._ownership_state, "unclaimed")
                    self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")
                    self.assertIsNone(adapter.manifest)
                    self.assertNotIn("e2e_claim_handoff", result)
                    self.assertEqual(store.writes, [])
                elif outcome == "own-commit":
                    cleanup.assert_called_once()
                    self.assertTrue(cleanup.call_args.kwargs["recover"])
                    self.assertEqual(adapter._ownership_state, "terminal-owned")
                    self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                    self.assertEqual(
                        [value[0]["phase"] for value in store.writes],
                        ["e2e_running", "e2e_failed"],
                    )
                else:
                    cleanup.assert_not_called()
                    self.assertEqual(
                        adapter._ownership_state,
                        "competing" if outcome == "competing" else "ambiguous",
                    )

    def test_interrupt_after_claim_write_return_keeps_pending_candidate_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            committed = adapter._set_owned

            def interrupt_before_assignment(
                _manifest: Mapping[str, Any], _etag: str, *, terminal: bool
            ) -> None:
                self.assertFalse(terminal)
                raise KeyboardInterrupt("interrupt after store.write returned")

            with (
                mock.patch.object(adapter, "_set_owned", side_effect=interrupt_before_assignment),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.claim(raw, deployment)

            self.assertEqual(adapter._ownership_state, "claim-pending")
            self.assertEqual(adapter.manifest, store.value)
            self.assertEqual(store.value["phase"], "e2e_running")
            self.assertIs(adapter._set_owned.__func__, committed.__func__)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                result = adapter.cleanup()

            cleanup.assert_called_once()
            self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
            self.assertEqual(adapter._ownership_state, "terminal-owned")

    def test_finish_write_reconciliation_handles_commit_noncommit_and_ownership_change(self) -> None:
        sensitive = "private-finish-provider-response"

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)

            def commit_then_error(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                raise e2e.LifecycleError(sensitive)

            store.write_hook = commit_then_error
            result = adapter.finish(False)
            self.assertEqual(result["result_persistence"], "recovered-owned-result")
            self.assertEqual(adapter._ownership_state, "terminal-owned")
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)

            def interrupt_before_terminal_assignment(
                _manifest: Mapping[str, Any], _etag: str, *, terminal: bool
            ) -> None:
                self.assertTrue(terminal)
                raise KeyboardInterrupt("interrupt after terminal write returned")

            with (
                mock.patch.object(adapter, "_set_owned", side_effect=interrupt_before_terminal_assignment),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.finish(False)

            self.assertEqual(adapter._ownership_state, "terminal-pending")
            self.assertEqual(adapter.manifest, store.value)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            with self.assertRaises(e2e.ClaimPersistenceError) as raised:
                adapter.finish(False)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "running-owned")
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                handoff = adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual(handoff["e2e_claim_handoff"]["persistence"], "conditional-write")

        for ownership_change, expected in (
            ("competing", e2e.ConcurrentRunError),
            ("ambiguous", e2e.AmbiguousOwnershipError),
        ):
            with self.subTest(ownership_change=ownership_change), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                adapter.claim(raw, deployment)

                def change_ownership(
                    target: DurableManifestStore,
                    _value: dict[str, Any],
                    _if_match: str | None,
                    mode: str = ownership_change,
                ) -> None:
                    if mode == "competing":
                        target.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                    else:
                        target.value["tailnet"]["key_generation"] = 2
                    target.remote_etag = '"changed-finish-etag"'
                    raise e2e.LifecycleError(sensitive)

                store.write_hook = change_ownership
                with self.assertRaises(expected) as raised:
                    adapter.finish(False)

                self.assertNotIn(sensitive, str(raised.exception))
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup") as cleanup,
                    self.assertRaises(expected),
                ):
                    adapter.cleanup()
                cleanup.assert_not_called()

    def test_late_competitor_is_still_rejected_by_protected_cleanup_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _raw, store, adapter = self.protected_adapter(temporary)
            store.value["phase"] = "e2e_running"
            store.value["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "f" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            }
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            _raw, store, adapter = self.protected_adapter(temporary)

            def guarded_cleanup(*_args: Any, **kwargs: Any) -> Mapping[str, Any]:
                self.assertEqual(store.recover_count, 1)
                self.assertTrue(kwargs["recover"])
                competitor = copy.deepcopy(store.value)
                competitor["phase"] = "e2e_running"
                competitor["e2e"] = {
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "output_sha256": "f" * 64,
                    "started_at": "2026-08-20T12:00:00Z",
                }
                store.value = competitor
                store.remote_etag = '"late-competitor-etag"'
                self.assertEqual(store.recover()["phase"], "e2e_running")
                self.assertEqual(store.recover_count, 2)
                raise e2e.ConcurrentLifecycleError("protected cleanup refused the active E2E claim")

            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", side_effect=guarded_cleanup) as cleanup,
                self.assertRaises(e2e.ConcurrentLifecycleError),
            ):
                adapter.cleanup()

            cleanup.assert_called_once()
            self.assertEqual(store.value["phase"], "e2e_running")
            self.assertEqual(store.writes, [])

    def test_embedded_remote_agent_is_valid_python_and_bounded_for_ssm(self) -> None:
        compile(e2e.REMOTE_AGENT_SOURCE, "<remote-agent>", "exec")
        self.assertIn('stream.add_argument("--ready-path", required=True)', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('stream.add_argument("--stop-path")', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('server.add_argument("--stop-path")', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('stream.add_argument("--stop-token")', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('server.add_argument("--stop-token")', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", e2e.REMOTE_AGENT_SOURCE)
        self.assertIn("attempts.append(sent)", e2e.REMOTE_AGENT_SOURCE)
        self.assertIn("markers.append([sequence, time.monotonic_ns()])", e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('"sent_markers": sent_markers', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn('"last_sent_monotonic_ns": last_sent_monotonic_ns', e2e.REMOTE_AGENT_SOURCE)
        compressed = gzip.compress(e2e.REMOTE_AGENT_SOURCE.encode("utf-8"), mtime=0)
        self.assertLess(len(base64.b64encode(compressed)), 12_000)
        compile(e2e.WIRE_INSPECTOR_SOURCE, "<wire-inspector>", "exec")
        wire_compressed = gzip.compress(e2e.WIRE_INSPECTOR_SOURCE.encode("utf-8"), mtime=0)
        self.assertLess(len(base64.b64encode(wire_compressed)), 12_000)

    def test_compact_stream_markers_fit_ssm_output_and_expand_strictly(self) -> None:
        flow_id = "fixture-tcp-0001"
        connection_id = f"{flow_id}:c0001"
        attempts = [10**18 + sequence * 2 for sequence in range(160)]
        markers = [
            [sequence, 10**18 + sequence * 2 + 1]
            for sequence in range(160)
        ]
        result = {
            "attempts": attempts,
            "connection_id": connection_id,
            "flow_id": flow_id,
            "interrupted": False,
            "last_sent_monotonic_ns": attempts[-1],
            "markers": markers,
            "sent_markers": len(markers),
            "socket_count": 1,
            "source_port": 30000,
            "stop_observed": False,
            "success": True,
        }

        self.assertLess(len(json.dumps(result, separators=(",", ":"))), 12_000)
        expanded = e2e._expand_compact_stream_markers(result)
        self.assertEqual([marker.sequence for marker in expanded], list(range(160)))
        self.assertEqual([marker.sent_monotonic_ns for marker in expanded], attempts)
        self.assertTrue(all(marker.flow_id == flow_id for marker in expanded))
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "wrong shape"):
            e2e._expand_compact_stream_markers({**result, "markers": [[0]]})

    def test_embedded_tcp_framing_retains_coalesced_trailing_bytes(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)
        first = {"flow_id": "fixture", "kind": "marker", "sequence": 1}
        second = {"flow_id": "fixture", "kind": "marker", "sequence": 2}

        class CoalescedSocket:
            def __init__(self) -> None:
                self.payload = namespace["encode"](first, True) + namespace["encode"](
                    second, True
                )

            def settimeout(self, _seconds: float) -> None:
                pass

            def recv(self, size: int) -> bytes:
                value, self.payload = self.payload[:size], self.payload[size:]
                return value

        connection = CoalescedSocket()
        frame, buffered = namespace["tcp_frame"](
            connection, time.monotonic() + 1
        )
        self.assertEqual(namespace["decode"](frame), first)
        frame, buffered = namespace["tcp_frame"](
            connection, time.monotonic() + 1, buffered
        )
        self.assertEqual(namespace["decode"](frame), second)
        self.assertEqual(buffered, b"")

        class PartialTimeoutSocket:
            def __init__(self) -> None:
                self.values: list[bytes | BaseException] = [
                    b'{"flow_id":"fixture",',
                    socket.timeout("fixture partial timeout"),
                    b'"kind":"ack","sequence":3}\n',
                ]

            def settimeout(self, _seconds: float) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                value = self.values.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value

        partial = PartialTimeoutSocket()
        retained = bytearray()
        with self.assertRaises(socket.timeout):
            namespace["tcp_frame"](
                partial,
                time.monotonic() + 1,
                retained,
            )
        self.assertEqual(retained, b'{"flow_id":"fixture",')
        frame, retained = namespace["tcp_frame"](
            partial,
            time.monotonic() + 1,
            retained,
        )
        self.assertEqual(
            namespace["decode"](frame),
            {"flow_id": "fixture", "kind": "ack", "sequence": 3},
        )
        self.assertEqual(retained, b"")

    def test_embedded_stream_server_releases_protocol_listener_identity(self) -> None:
        marker = {
            "connection_id": "fixture-stream:c0001",
            "flow_id": "fixture-stream",
            "kind": "marker",
            "sequence": 0,
        }
        peer = ("192.0.2.10", 41000)

        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
                exec(e2e.REMOTE_AGENT_SOURCE, namespace)
                events: list[object] = []
                emitted: list[dict[str, Any]] = []

                class Clock:
                    def __init__(self) -> None:
                        self.values = iter((0.0, 0.1, 0.2, 2.0))

                    def monotonic(self) -> float:
                        return next(self.values, 2.0)

                class Connection:
                    def settimeout(self, _seconds: float) -> None:
                        pass

                    def recv(self, _size: int) -> bytes:
                        events.append("connection-recv")
                        return namespace["encode"](marker, True)

                    def sendall(self, _payload: bytes) -> None:
                        events.append("connection-send")

                    def close(self) -> None:
                        events.append("connection-close")

                connection = Connection()

                class Listener:
                    def setsockopt(self, *_args: object) -> None:
                        pass

                    def bind(self, _address: tuple[str, int]) -> None:
                        pass

                    def listen(self, _backlog: int) -> None:
                        events.append("listener-listen")

                    def settimeout(self, _seconds: float) -> None:
                        pass

                    def accept(self) -> tuple[Connection, tuple[str, int]]:
                        events.append("listener-accept")
                        return connection, peer

                    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
                        events.append("udp-recvfrom")
                        return namespace["encode"](marker), peer

                    def connect(self, value: tuple[str, int]) -> None:
                        events.append(("udp-connect", value))

                    def send(self, payload: bytes) -> int:
                        events.append("udp-send")
                        return len(payload)

                    def sendto(self, _payload: bytes, _peer: tuple[str, int]) -> None:
                        events.append("udp-sendto")

                    def close(self) -> None:
                        events.append("listener-close")

                listener = Listener()
                namespace["socket"] = SimpleNamespace(
                    AF_INET=socket.AF_INET,
                    SOCK_STREAM=socket.SOCK_STREAM,
                    SOCK_DGRAM=socket.SOCK_DGRAM,
                    SOL_SOCKET=socket.SOL_SOCKET,
                    SO_REUSEADDR=socket.SO_REUSEADDR,
                    timeout=socket.timeout,
                    socket=lambda *_args: listener,
                )
                namespace["time"] = Clock()
                namespace["emit"] = emitted.append

                namespace["stream_server"](
                    SimpleNamespace(
                        bind="192.0.2.20",
                        duration=1.0,
                        flow_id="fixture-stream",
                        port=5201,
                        protocol=protocol,
                        stop_path=None,
                        stop_token=None,
                    )
                )

                self.assertEqual(emitted[-1]["receives"], 1)
                if protocol == "tcp":
                    self.assertLess(
                        events.index("listener-close"),
                        events.index("connection-recv"),
                    )
                    self.assertIn("connection-send", events)
                else:
                    self.assertIn(("udp-connect", peer), events)
                    self.assertIn("udp-send", events)
                    self.assertNotIn("udp-sendto", events)

    def test_controlled_tcp_receiver_waits_for_stop_after_client_eof(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)
        flow_id = "fixture-stream"
        stop_path = f"/run/envelope-e2e-stream-{flow_id}.server-stop"
        stop_token = "11111111-2222-4333-8444-555555555555"
        marker = {
            "connection_id": f"{flow_id}:c0001",
            "flow_id": flow_id,
            "kind": "marker",
            "sequence": 0,
        }
        events: list[str] = []
        emitted: list[dict[str, Any]] = []

        class Clock:
            def __init__(self) -> None:
                self.value = 0.0

            def monotonic(self) -> float:
                self.value += 0.01
                return self.value

            def sleep(self, seconds: float) -> None:
                self.value += seconds

        class Connection:
            def __init__(self) -> None:
                self.reads = 0

            def settimeout(self, _seconds: float) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                self.reads += 1
                events.append(f"recv:{self.reads}")
                return namespace["encode"](marker, True) if self.reads == 1 else b""

            def sendall(self, _payload: bytes) -> None:
                events.append("ack")

            def close(self) -> None:
                events.append("connection-close")

        connection = Connection()

        class Listener:
            def setsockopt(self, *_args: object) -> None:
                pass

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def listen(self, _backlog: int) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def accept(self):
                return connection, ("192.0.2.10", 41000)

            def close(self) -> None:
                events.append("listener-close")

        checks = 0

        def stop_requested(path: str, token: str) -> bool:
            nonlocal checks
            self.assertEqual((path, token), (stop_path, stop_token))
            checks += 1
            return checks >= 3

        namespace["socket"] = SimpleNamespace(
            AF_INET=socket.AF_INET,
            SOCK_STREAM=socket.SOCK_STREAM,
            SOCK_DGRAM=socket.SOCK_DGRAM,
            SOL_SOCKET=socket.SOL_SOCKET,
            SO_REUSEADDR=socket.SO_REUSEADDR,
            timeout=socket.timeout,
            socket=lambda *_args: Listener(),
        )
        namespace["time"] = Clock()
        namespace["emit"] = emitted.append
        namespace["private_stop_requested"] = stop_requested
        namespace["stream_server"](
            SimpleNamespace(
                bind="192.0.2.20",
                duration=10.0,
                flow_id=flow_id,
                port=5201,
                protocol="tcp",
                stop_path=stop_path,
                stop_token=stop_token,
            )
        )

        self.assertEqual(events.count("ack"), 1)
        self.assertIn("recv:2", events)
        self.assertTrue(emitted[-1]["stop_observed"])
        self.assertEqual(emitted[-1]["receives"], 1)

    def test_embedded_stream_client_stops_after_minimum_and_final_marker(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)
        flow_id = "fixture-stream"
        connection_id = f"{flow_id}:c0001"
        emitted: list[dict[str, Any]] = []
        events: list[str] = []

        class Clock:
            def __init__(self) -> None:
                self.value = 0.0

            def monotonic(self) -> float:
                self.value += 0.001
                return self.value

            def monotonic_ns(self) -> int:
                self.value += 0.001
                events.append("send-completion-clock")
                return int(self.value * 1_000_000_000)

            def sleep(self, seconds: float) -> None:
                self.value += max(0.0, seconds)

        class ClientSocket:
            def __init__(self) -> None:
                self.request: dict[str, Any] | None = None

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def connect(self, _address: tuple[str, int]) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def send(self, payload: bytes) -> int:
                self.request = namespace["decode"](payload)
                events.append("udp-send-returned")
                return len(payload)

            def recv(self, _size: int) -> bytes:
                assert self.request is not None
                return namespace["encode"](
                    {
                        "connection_id": connection_id,
                        "flow_id": flow_id,
                        "kind": "ack",
                        "sequence": self.request["sequence"],
                    }
                )

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as temporary:
            ready_path = pathlib.Path(temporary) / "ready"
            stop_path = f"/run/envelope-e2e-stream-{flow_id}.client-stop"
            stop_token = "11111111-2222-4333-8444-555555555555"
            namespace["socket"] = SimpleNamespace(
                AF_INET=socket.AF_INET,
                SOCK_STREAM=socket.SOCK_STREAM,
                SOCK_DGRAM=socket.SOCK_DGRAM,
                timeout=socket.timeout,
                socket=lambda *_args: ClientSocket(),
            )
            namespace["time"] = Clock()
            namespace["emit"] = emitted.append
            namespace["private_stop_requested"] = (
                lambda path, token: (path, token) == (stop_path, stop_token)
            )
            namespace["stream_client"](
                SimpleNamespace(
                    ack_timeout=0.1,
                    count=160,
                    flow_id=flow_id,
                    host="192.0.2.20",
                    interval=0.01,
                    minimum_count=20,
                    port=5201,
                    protocol="udp",
                    ready_path=str(ready_path),
                    source_ip="192.0.2.10",
                    source_port=41000,
                    stop_path=stop_path,
                    stop_token=stop_token,
                )
            )

        self.assertEqual(emitted[-1]["sent_markers"], 20)
        self.assertEqual(len(emitted[-1]["markers"]), 20)
        self.assertTrue(emitted[-1]["stop_observed"])
        self.assertEqual(events.count("udp-send-returned"), 20)
        self.assertEqual(events.count("send-completion-clock"), 40)
        self.assertLess(
            events.index("udp-send-returned"),
            events.index("send-completion-clock"),
        )

    def test_embedded_udp_short_sends_are_local_failures(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)
        flow_id = "fixture-stream"
        connection_id = f"{flow_id}:c0001"
        emitted: list[dict[str, Any]] = []

        class Clock:
            def __init__(self) -> None:
                self.value = 0.0

            def monotonic(self) -> float:
                self.value += 0.001
                return self.value

            def monotonic_ns(self) -> int:
                self.value += 0.001
                return int(self.value * 1_000_000_000)

            def sleep(self, seconds: float) -> None:
                self.value += max(0.0, seconds)

        class ShortClientSocket:
            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def connect(self, _address: tuple[str, int]) -> None:
                pass

            def send(self, payload: bytes) -> int:
                return len(payload) - 1

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as temporary:
            namespace["socket"] = SimpleNamespace(
                AF_INET=socket.AF_INET,
                SOCK_STREAM=socket.SOCK_STREAM,
                SOCK_DGRAM=socket.SOCK_DGRAM,
                socket=lambda *_args: ShortClientSocket(),
            )
            namespace["time"] = Clock()
            namespace["emit"] = emitted.append
            namespace["private_stop_requested"] = lambda *_args: False
            namespace["stream_client"](
                SimpleNamespace(
                    ack_timeout=0.1,
                    count=20,
                    flow_id=flow_id,
                    host="192.0.2.20",
                    interval=0.01,
                    minimum_count=20,
                    port=5201,
                    protocol="udp",
                    ready_path=str(pathlib.Path(temporary) / "ready"),
                    source_ip="192.0.2.10",
                    source_port=41000,
                    stop_path=None,
                    stop_token=None,
                )
            )

        self.assertTrue(emitted[-1]["interrupted"])
        self.assertEqual(emitted[-1]["sent_markers"], 0)
        self.assertEqual(emitted[-1]["attempts"], [])

        marker_value = {
            "connection_id": connection_id,
            "flow_id": flow_id,
            "kind": "marker",
            "sequence": 0,
        }

        class ShortServerSocket:
            def setsockopt(self, *_args: object) -> None:
                pass

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
                return namespace["encode"](marker_value), ("192.0.2.10", 41000)

            def connect(self, _peer: tuple[str, int]) -> None:
                pass

            def send(self, payload: bytes) -> int:
                return len(payload) - 1

            def close(self) -> None:
                pass

        namespace["socket"] = SimpleNamespace(
            AF_INET=socket.AF_INET,
            SOCK_STREAM=socket.SOCK_STREAM,
            SOCK_DGRAM=socket.SOCK_DGRAM,
            SOL_SOCKET=socket.SOL_SOCKET,
            SO_REUSEADDR=socket.SO_REUSEADDR,
            timeout=socket.timeout,
            socket=lambda *_args: ShortServerSocket(),
        )
        namespace["time"] = Clock()
        with self.assertRaisesRegex(RuntimeError, "not sent in full"):
            namespace["stream_server"](
                SimpleNamespace(
                    bind="192.0.2.20",
                    duration=1.0,
                    flow_id=flow_id,
                    port=5201,
                    protocol="udp",
                    stop_path=None,
                    stop_token=None,
                )
            )

    def test_embedded_icmp_sender_preserves_every_payload_byte(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)

        class FakeRawSocket:
            def __init__(self) -> None:
                self.packet = b""
                self.reply = b""

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def setsockopt(self, _level: int, _option: int, _value: int) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def sendto(self, packet: bytes, target: tuple[str, int]) -> None:
                self.packet = packet
                _request_type, _code, _checksum, identifier, sequence = struct.unpack("!BBHHH", packet[:8])
                payload = packet[8:]
                header = struct.pack("!BBHHH", 0, 0, 0, identifier, sequence)
                checksum = namespace["internet_checksum"](header + payload)
                response = struct.pack("!BBHHH", 0, 0, checksum, identifier, sequence) + payload
                ipv4 = bytearray(20)
                ipv4[0] = 0x45
                ipv4[9] = socket.IPPROTO_ICMP
                ipv4[12:16] = socket.inet_aton(target[0])
                ipv4[16:20] = socket.inet_aton("192.0.2.10")
                self.reply = bytes(ipv4) + response

            def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
                return self.reply, ("198.51.100.20", 0)

            def close(self) -> None:
                pass

        raw_socket = FakeRawSocket()
        namespace["socket"] = SimpleNamespace(
            AF_INET=socket.AF_INET,
            SOCK_RAW=socket.SOCK_RAW,
            IPPROTO_ICMP=socket.IPPROTO_ICMP,
            IPPROTO_IP=socket.IPPROTO_IP,
            timeout=socket.timeout,
            inet_ntoa=socket.inet_ntoa,
            socket=lambda *_args: raw_socket,
        )
        output = io.StringIO()
        args = SimpleNamespace(
            expect_timeout=False,
            flow_id="fixture-icmp",
            host="198.51.100.20",
            payload_bytes=1253,
            source_ip="192.0.2.10",
            timeout=1.0,
        )

        with contextlib.redirect_stdout(output):
            namespace["icmp_client"](args)

        result = json.loads(output.getvalue())
        self.assertTrue(result["reply_received"])
        self.assertEqual(raw_socket.packet[8:], b"\xa5" * 1253)
        self.assertEqual(namespace["internet_checksum"](raw_socket.packet), 0)

    def test_durable_claim_proves_load_thresholds_predate_apply(self) -> None:
        raw = protected_output()
        deployment = e2e.parse_protected_deployment_output(raw)

        class Store:
            remote_etag = "fixture-etag"

            def __init__(self, manifest: Mapping[str, Any]) -> None:
                self.value = copy.deepcopy(manifest)

            def recover(self) -> dict[str, Any]:
                return copy.deepcopy(self.value)

            def write(self, value: dict[str, Any], *, if_match: str | None = None) -> None:
                self.value = copy.deepcopy(value)

        def adapter(manifest: Mapping[str, Any]) -> e2e.ProtectedLifecycleAdapter:
            value = object.__new__(e2e.ProtectedLifecycleAdapter)
            value.store = Store(manifest)
            value.config = SimpleNamespace(run_id="fixture-live", sites=lifecycle_sites())
            value.manifest = None
            return value

        manifest = ready_lifecycle_manifest(raw)
        self.assertNotIn("apply_claimed_at", manifest)
        claim = adapter(manifest).claim(raw, deployment)
        self.assertTrue(claim["load_profile_approved_before_apply"])

        invalid_timestamps = {
            "missing": None,
            "malformed": "2026-13-20T11:00:00Z",
            "noncanonical": "2026-08-20T11:00:00+00:00",
        }
        for name, timestamp in invalid_timestamps.items():
            candidate = ready_lifecycle_manifest(raw)
            if timestamp is None:
                candidate["saved_plan"].pop("applied_at")
            else:
                candidate["saved_plan"]["applied_at"] = timestamp
            with self.subTest(name=name), self.assertRaisesRegex(e2e.LoadProfileError, "saved_plan.applied_at"):
                adapter(candidate).claim(raw, deployment)

        stale_claim = ready_lifecycle_manifest(raw)
        stale_claim["apply_claimed_at"] = "2026-08-20T11:00:00Z"
        with self.assertRaisesRegex(e2e.DeploymentError, "stale active apply claim"):
            adapter(stale_claim).claim(raw, deployment)

        post_apply_profile = protected_output()
        post_apply_profile["e2e_load_profile"]["value"]["approved_at"] = "2026-08-20T12:00:00Z"
        post_apply_deployment = e2e.parse_protected_deployment_output(post_apply_profile)
        with self.assertRaisesRegex(e2e.LoadProfileError, "before"):
            adapter(ready_lifecycle_manifest(post_apply_profile)).claim(post_apply_profile, post_apply_deployment)

        equal_profile = protected_output()
        equal_profile["e2e_load_profile"]["value"]["approved_at"] = "2026-08-20T11:00:00Z"
        equal_deployment = e2e.parse_protected_deployment_output(equal_profile)
        with self.assertRaisesRegex(e2e.LoadProfileError, "before"):
            adapter(ready_lifecycle_manifest(equal_profile)).claim(equal_profile, equal_deployment)


def unused_source_port(sock_type: int) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_agent_server(protocol: str, messages: int) -> tuple[threading.Thread, int, queue.Queue[object]]:
    ready: queue.Queue[int] = queue.Queue(maxsize=1)
    completed: queue.Queue[object] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            completed.put(
                AGENT.serve(
                    protocol,
                    "127.0.0.1",
                    0,
                    timeout=3,
                    max_messages=messages,
                    ready=ready.put,
                )
            )
        except BaseException as error:
            completed.put(error)

    thread = threading.Thread(target=run, name=f"test-agent-{protocol}", daemon=True)
    thread.start()
    return thread, ready.get(timeout=1), completed


class WorkloadAgentProtocolTest(unittest.TestCase):
    def test_agent_typing_is_compatible_with_al2023_python(self) -> None:
        self.assertNotIn("TypeAlias", AGENT_PATH.read_text())

    def _server_result(self, thread: threading.Thread, completed: queue.Queue[object]) -> dict[str, Any]:
        result = completed.get(timeout=4)
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        if isinstance(result, BaseException):
            raise result
        self.assertIsInstance(result, dict)
        return result

    def test_tcp_stream_uses_one_socket_and_monotonic_markers(self) -> None:
        thread, port, completed = start_agent_server("tcp", 4)
        source_port = unused_source_port(socket.SOCK_STREAM)

        result = AGENT.stream(
            "tcp",
            "127.0.0.1",
            port,
            source_ip="127.0.0.1",
            source_port=source_port,
            flow_id="fixture-tcp-0001",
            count=4,
            interval=0.002,
            timeout=2,
        )
        server = self._server_result(thread, completed)

        self.assertEqual(result["socket_count"], 1)
        self.assertEqual(result["source_port"], source_port)
        self.assertEqual([value["sequence"] for value in result["markers"]], [0, 1, 2, 3])
        self.assertEqual(len({value["connection_id"] for value in result["markers"]}), 1)
        self.assertEqual(server["connections"], 1)
        self.assertEqual(server["messages"], 4)
        e2e_markers = [e2e.StreamMarker.from_value(value) for value in result["markers"]]
        self.assertTrue(
            all(
                current.received_monotonic_ns < following.received_monotonic_ns
                for current, following in zip(e2e_markers, e2e_markers[1:])
            )
        )

    def test_udp_probe_honors_source_bind_and_flow_identity(self) -> None:
        thread, port, completed = start_agent_server("udp", 1)
        source_port = unused_source_port(socket.SOCK_DGRAM)

        result = AGENT.probe(
            "udp",
            "127.0.0.1",
            port,
            source_ip="127.0.0.1",
            source_port=source_port,
            flow_id="fixture-udp-0001",
            timeout=2,
        )
        server = self._server_result(thread, completed)

        self.assertTrue(result["success"])
        self.assertEqual(result["source_port"], source_port)
        self.assertEqual(result["flow_id"], "fixture-udp-0001")
        self.assertEqual(server["flow_ids"], ["fixture-udp-0001"])
        self.assertEqual(server["messages"], 1)

    def test_agent_rejects_invalid_flow_ids_without_opening_a_socket(self) -> None:
        with self.assertRaisesRegex(AGENT.AgentError, "flow_id"):
            AGENT.probe(
                "tcp",
                "127.0.0.1",
                1,
                source_ip="127.0.0.1",
                source_port=0,
                flow_id="not a valid flow",
                timeout=1,
            )


if __name__ == "__main__":
    unittest.main()
