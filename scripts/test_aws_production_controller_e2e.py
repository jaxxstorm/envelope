#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import queue
import socket
import sys
import tempfile
import threading
import unittest
from typing import Any, Mapping, Sequence
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_production_controller_e2e as e2e  # noqa: E402

AGENT_PATH = ROOT / "example" / "terraform" / "cloud-init" / "envelope-e2e-agent.py"
AGENT_SPEC = importlib.util.spec_from_file_location(
    "production_envelope_e2e_agent", AGENT_PATH
)
assert AGENT_SPEC and AGENT_SPEC.loader
AGENT = importlib.util.module_from_spec(AGENT_SPEC)
sys.modules[AGENT_SPEC.name] = AGENT
AGENT_SPEC.loader.exec_module(AGENT)


RUN_ID = "ctrl-fixture"
ACCOUNT_ID = "123456789012"


def config_document() -> dict[str, Any]:
    def site(region: str, number: int, prefix: str) -> dict[str, Any]:
        return {
            "region": region,
            "ami_id": f"ami-{number:08x}",
            "ssm_kms_key_arn": f"arn:aws:kms:{region}:{ACCOUNT_ID}:key/site-{number}",
            "azs": {"a": f"{region}a", "b": f"{region}b"},
            "vpc_cidr": f"{prefix}.0.0/16",
            "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"],
            "remote_site_cidrs": [],
            "workload_subnet_cidrs": {
                "a": f"{prefix}.1.0/24",
                "b": f"{prefix}.2.0/24",
            },
            "transport_subnet_cidrs": {
                "a": f"{prefix}.3.0/24",
                "b": f"{prefix}.4.0/24",
            },
            "gwlbe_subnet_cidrs": {
                "a": f"{prefix}.10.0/24",
                "b": f"{prefix}.11.0/24",
            },
            "gwlb_subnet_cidrs": {
                "a": f"{prefix}.20.0/24",
                "b": f"{prefix}.21.0/24",
            },
            "target_subnet_cidrs": {
                "a": f"{prefix}.30.0/24",
                "b": f"{prefix}.31.0/24",
            },
            "management_subnet_cidr": f"{prefix}.40.0/24",
            "target_az_keys": ["a", "b"],
            "transport_router_az_keys": ["a", "b"],
        }

    west = site("us-west-2", 1, "10.10")
    east = site("us-east-1", 2, "10.20")
    west["remote_site_cidrs"] = list(east["local_site_cidrs"])
    east["remote_site_cidrs"] = list(west["local_site_cidrs"])
    controller_ids = ["controller-a", "controller-b", "controller-c"]
    return {
        "run_id": RUN_ID,
        "expires_at": "2030-01-01T00:00:00Z",
        "architecture": "amd64",
        "artifact_manifest": "build/manifest.json",
        "instance_type": "t3.medium",
        "test_instance_type": "t3.micro",
        "backend": {
            "bucket": "fixture-backend",
            "region": "us-west-2",
            "kms_key_arn": f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:key/backend",
            "state_key": f"runs/{RUN_ID}/appliance/terraform.tfstate",
            "operator_principal_arns": [
                f"arn:aws:iam::{ACCOUNT_ID}:role/envelope-operator"
            ],
        },
        "symmetric_topology": {
            "version": 3,
            "sites": {"west": west, "east": east},
            "route_failover": {
                "initial_transport_router_az_by_gwlbe_az": {
                    "west": {"a": "a", "b": "b"},
                    "east": {"a": "a", "b": "b"},
                },
                "mutation_timeout_seconds": 120,
                "restoration_timeout_seconds": 120,
                "recovery_timeout_seconds": 600,
            },
        },
        "tailnet": {
            "name": "fixture.example",
            "tag": "tag:envelope-ci",
            "tag_owners": ["group:infra"],
            "snat_subnet_routes": False,
        },
        "envelope": {
            "mode": "packet-return",
            "udp_bind": "0.0.0.0:6081",
            "max_inner_packet_size": 1280,
        },
        "e2e_load_profile": {
            "profile_id": "fixture-load-v1",
            "approved_at": "2020-01-01T00:00:00Z",
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
        },
        "production_controller": {
            "region": "us-west-2",
            "state_key": f"runs/{RUN_ID}/controller/terraform.tfstate",
            "vpc_id": "vpc-30000001",
            "ami_id": "ami-30000001",
            "ami_trusted_owner_ids": [ACCOUNT_ID],
            "instance_type": "t3.small",
            "controller_ids": controller_ids,
            "placements": {
                controller_id: {
                    "subnet_id": f"subnet-3000000{index}",
                    "availability_zone": f"us-west-2{chr(96 + index)}",
                }
                for index, controller_id in enumerate(controller_ids, start=1)
            },
            "management_egress": {
                controller_id: {
                    "route_table_id": f"rtb-3000000{index}",
                    "nat_gateway_id": f"nat-3000000{index}",
                    "nat_subnet_id": f"subnet-4000000{index}",
                    "nat_route_table_id": f"rtb-4000000{index}",
                    "internet_gateway_id": "igw-30000001",
                }
                for index, controller_id in enumerate(controller_ids, start=1)
            },
            "secret_kms_key_arn": (
                f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000001"
            ),
            "metrics_ingress_cidrs": ["10.30.0.0/16"],
            "metrics_port": 9091,
            "readiness_publisher": {
                "id": "publisher-a",
                "role_name": "envelope-readiness-publisher",
                "role_arn": (
                    f"arn:aws:iam::{ACCOUNT_ID}:role/envelope-readiness-publisher"
                ),
                "source_cidrs": ["10.30.0.0/16"],
                "scrape_interval_seconds": 10,
            },
            "alarm_actions": [
                f"arn:aws:sns:us-west-2:{ACCOUNT_ID}:controller-alerts"
            ],
            "policy": {
                "replica_count": 3,
                "observation_quorum": 2,
                "observation_interval": "2s",
                "observation_freshness": "5s",
                "failover_stability": "3s",
                "failback_stability": "5s",
                "cooldown": "5s",
                "lease_duration": "30s",
                "lease_renew_interval": "5s",
                "lease_danger_window": "15s",
                "api_timeout": "5s",
                "route_convergence_timeout": "10s",
            },
            "state_base_dir": "/var/lib/envelope-controller/tsnet",
            "control_url": None,
            "artifact_version": "test.1",
            "timeouts": {
                "readiness_seconds": 30,
                "transition_seconds": 30,
                "cleanup_seconds": int(e2e.protected_cleanup_bound_seconds(30)) + 1,
            },
        },
    }


def make_config(directory: pathlib.Path) -> e2e.ProductionRunConfig:
    path = directory / "config.json"
    path.write_text(json.dumps(config_document()), encoding="utf-8")
    return e2e.ProductionRunConfig.load(path, enforce_future_expiry=False)


def topology_seed() -> dict[str, Any]:
    sites = {
        "west": {
            "vpc_id": "vpc-10000001",
            "region": "us-west-2",
            "local_prefixes": ["10.10.1.0/24", "10.10.2.0/24"],
            "local_main_rule_priority_base": 5200,
            "tailscale_route_rule_priority": 5270,
        },
        "east": {
            "vpc_id": "vpc-20000001",
            "region": "us-east-1",
            "local_prefixes": ["10.20.1.0/24", "10.20.2.0/24"],
            "local_main_rule_priority_base": 5200,
            "tailscale_route_rule_priority": 5270,
        },
    }
    routers: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    counter = 1
    for site_id, region, vpc_id, prefix, remote in (
        ("west", "us-west-2", "vpc-10000001", "10.10", "10.20"),
        ("east", "us-east-1", "vpc-20000001", "10.20", "10.10"),
    ):
        for az_index, az_key in enumerate(("a", "b"), start=1):
            routers.append(
                {
                    "id": f"{site_id}-{az_key}",
                    "expected_hostname": f"{RUN_ID}-{site_id}-transport-{az_key}",
                    "site_id": site_id,
                    "instance_id": f"i-{counter:08x}",
                    "eni_id": f"eni-{counter:08x}",
                    "vpc_id": vpc_id,
                    "subnet_id": f"subnet-{counter:08x}",
                    "availability_zone": f"{region}{az_key}",
                    "region": region,
                }
            )
            domains.append(
                {
                    "id": f"{site_id}-{az_key}",
                    "site_id": site_id,
                    "source_prefix": f"{prefix}.{az_index}.0/24",
                    "route_table_id": f"rtb-{counter:08x}",
                    "gwlbe_subnet_id": f"subnet-{counter + 10:08x}",
                    "route_table_association_id": f"rtbassoc-{counter:08x}",
                    "remote_prefixes": [
                        f"{remote}.1.0/24",
                        f"{remote}.2.0/24",
                    ],
                    "preferred_owner": f"{site_id}-{az_key}",
                }
            )
            counter += 1
    return {
        "config_version": 3,
        "deployment_id": RUN_ID,
        "sites": sites,
        "routers": routers,
        "domains": domains,
    }


def appliance_output() -> dict[str, Any]:
    workloads: dict[str, Any] = {}
    for site_id, region, prefix, offset in (
        ("west", "us-west-2", "10.10", 20),
        ("east", "us-east-1", "10.20", 30),
    ):
        workloads[site_id] = {}
        for index, role in enumerate(("initiator", "responder"), start=1):
            workloads[site_id][role] = {
                "instance_id": f"i-{offset + index:08x}",
                "private_ip": f"{prefix}.{index}.10",
                "az_key": chr(96 + index),
                "availability_zone": f"{region}{chr(96 + index)}",
                "subnet_id": f"subnet-{offset + index:08x}",
                "cidr": f"{prefix}.{index}.0/24",
                "route_table_id": f"rtb-{offset + index:08x}",
            }
    return {
        "production_controller_topology_seed": {"value": topology_seed()},
        "artifact_identity": {
            "value": {
                "bucket": "fixture-artifacts",
                "key": "artifacts/controller",
                "sha256": "a" * 64,
                "architecture": "amd64",
                "ec2_arch": "x86_64",
                "revision": "b" * 40,
                "version": "test.1",
            }
        },
        "workload_instances": {"value": workloads},
    }


def tailnet_devices() -> list[dict[str, Any]]:
    result = []
    for index, router in enumerate(topology_seed()["routers"], start=1):
        prefixes = topology_seed()["sites"][router["site_id"]]["local_prefixes"]
        result.append(
            {
                "id": f"device-{index}",
                "nodeId": f"node-{index}",
                "hostname": router["expected_hostname"],
                "authorized": True,
                "online": True,
                "tags": ["tag:envelope-ci"],
                "advertisedRoutes": prefixes,
                "enabledRoutes": prefixes,
            }
        )
    return result


def compact_stream_result(
    protocol: str,
    *,
    expected: int = 100,
    attempted: int | None = None,
    acknowledged: int | None = None,
    outcome: str = "survived",
    error_category: str | None = None,
    first_sent: int = 40,
    first_received: int = 50,
    last_sent: int = 250,
    last_received: int = 260,
) -> dict[str, Any]:
    attempted = expected if attempted is None else attempted
    acknowledged = expected if acknowledged is None else acknowledged
    flow_id = f"flow-{protocol}"
    last_acknowledged = acknowledged - 1
    last_attempted = attempted - 1
    attempted_sent = last_sent if attempted == acknowledged else last_received + 10
    return {
        "schema": e2e.ESTABLISHED_AGENT_SCHEMA,
        "operation": "stream",
        "protocol": protocol,
        "success": outcome == "survived",
        "outcome": outcome,
        "error_category": error_category,
        "flow_id": flow_id,
        "connection_id": f"{flow_id}:c0001",
        "local_ip": "10.10.1.10",
        "source_port": 60000 if protocol == "tcp" else 60001,
        "socket_count": 1,
        "expected_markers": expected,
        "sequences": {
            "attempted": {"count": attempted, "first": 0, "last": last_attempted},
            "acknowledged": {
                "count": acknowledged,
                "first": 0,
                "last": last_acknowledged,
            },
        },
        "timing": {
            "first_acknowledged": [0, first_sent, first_received],
            "last_acknowledged": [last_acknowledged, last_sent, last_received],
            "last_attempted": [last_attempted, attempted_sent],
        },
    }


class TickClock:
    def __init__(self) -> None:
        self.value = dt.datetime(2026, 9, 5, 12, 0, tzinfo=dt.timezone.utc)

    def now(self) -> str:
        self.value += dt.timedelta(seconds=1)
        return self.value.isoformat().replace("+00:00", "Z")

    def advance(self, seconds: float) -> None:
        self.value += dt.timedelta(seconds=seconds)


class PollClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeAdapter:
    def __init__(
        self,
        clock: TickClock,
        *,
        fail_quiesce: bool = False,
        fail_material_delete: bool = False,
        unsupported_capability: str | None = None,
    ):
        self.clock = clock
        self.fail_quiesce = fail_quiesce
        self.fail_material_delete = fail_material_delete
        self.unsupported_capability = unsupported_capability
        self.ledger = e2e.MutationLedger(session_deny=True)
        self.cleanup_calls: list[str] = []
        self.preferred = {
            "west-a": "west-a",
            "west-b": "west-b",
            "east-a": "east-a",
            "east-b": "east-b",
        }
        self.route_eni = {
            "west-a": "eni-00000001",
            "west-b": "eni-00000002",
            "east-a": "eni-00000003",
            "east-b": "eni-00000004",
        }
        self.router_fault_at: str | None = None
        self.restored_at: str | None = None

    @staticmethod
    def _timestamp(value: dt.datetime) -> str:
        return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def conformance_capabilities(self) -> Mapping[str, bool]:
        capabilities = {name: True for name in e2e.REQUIRED_SCENARIO_CAPABILITIES}
        if self.unsupported_capability is not None:
            capabilities[self.unsupported_capability] = False
        return capabilities

    def _authority(self, domain_id: str) -> dict[str, Any]:
        index = sorted(self.preferred).index(domain_id) + 1
        west = domain_id.startswith("west")
        site_id = "west" if west else "east"
        remote = ["10.20.1.0/24", "10.20.2.0/24"] if west else ["10.10.1.0/24", "10.10.2.0/24"]
        source_index = 1 if domain_id.endswith("a") else 2
        source_root = "10.10" if west else "10.20"
        routers = [router_id for router_id in sorted(self.preferred) if router_id.startswith(site_id)]
        return {
            "domain_id": domain_id,
            "site_id": site_id,
            "region": "us-west-2" if west else "us-east-1",
            "vpc_id": "vpc-10000001" if west else "vpc-20000001",
            "route_table_id": f"rtb-{index:08x}",
            "gwlbe_subnet_id": f"subnet-{index + 10:08x}",
            "route_table_association_id": f"rtbassoc-{index:08x}",
            "source_prefix": f"{source_root}.{source_index}.0/24",
            "remote_prefixes": remote,
            "preferred_owner": self.preferred[domain_id],
            "eligible_routers": [
                {
                    "router_id": router_id,
                    "instance_id": {
                        "west-a": "i-00000001",
                        "west-b": "i-00000002",
                        "east-a": "i-00000003",
                        "east-b": "i-00000004",
                    }[router_id],
                    "eni_id": self.route_eni[router_id],
                    "stable_node_sha256": hashlib.sha256(router_id.encode()).hexdigest(),
                }
                for router_id in routers
            ],
        }

    def acquire_backend_claim(self) -> Mapping[str, Any]:
        return {
            "runner_identity": {
                "account_id": ACCOUNT_ID,
                "principal_arn": (
                    f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/e2e/controller-session"
                ),
                "session_name": "controller-session",
            }
        }

    def prepare(self) -> Mapping[str, Any]:
        return {}

    def deploy_appliance(self) -> Mapping[str, Any]:
        return {"complete": True}

    def prepare_controller(self) -> Mapping[str, Any]:
        kms_hash = hashlib.sha256(b"kms").hexdigest()
        return {
            "topology": {
                "schema_version": 1,
                "sha256": "a" * 64,
                "source_output_sha256": "b" * 64,
                "controller_ids": ["controller-a", "controller-b", "controller-c"],
                "domain_ids": sorted(self.preferred),
                "policy": {
                    "observation_quorum": 2,
                    "observation_freshness_milliseconds": 5000,
                    "lease_renew_interval_milliseconds": 5000,
                    "failback_stability_milliseconds": 5000,
                    "cooldown_milliseconds": 5000,
                },
                "gwlbe_authority": [
                    self._authority(domain_id) for domain_id in sorted(self.preferred)
                ],
            },
            "artifacts": {
                "manifest_sha256": "c" * 64,
                "revision": "d" * 40,
                "version": "test.1",
                "architecture": "amd64",
                "objects": [
                    {
                        "component": component,
                        "key": f"runs/{RUN_ID}/controller/{'d' * 40}/{component}",
                        "version_id": f"version-{index}",
                        "sha256": chr(101 + index) * 64,
                    }
                    for index, component in enumerate(
                        ("envelope-controller", "envelope-controller-topology")
                    )
                ],
            },
            "secret_references": {
                "value_material_recorded": False,
                "parameters": [
                    {
                        "purpose": purpose,
                        "name": f"/{RUN_ID}/{purpose}",
                        "arn": (
                            f"arn:aws:ssm:us-west-2:{ACCOUNT_ID}:parameter/"
                            f"{RUN_ID}/{purpose}"
                        ),
                        "kms_key_arn_sha256": kms_hash,
                    }
                    for purpose in (
                        "controller-admin-readonly",
                        "controller-tsnet",
                        "router-east",
                        "router-west",
                    )
                ],
            },
        }

    def _actors(self) -> dict[str, Any]:
        instances: list[dict[str, Any]] = []
        for index, controller_id in enumerate(
            ("controller-a", "controller-b", "controller-c"), start=1
        ):
            instances.append(
                {
                    "actor_type": "controller",
                    "actor_id": controller_id,
                    "instance_id": f"i-{0x50000000 + index:08x}",
                    "region": "us-west-2",
                    "vpc_id": "vpc-30000001",
                    "subnet_id": f"subnet-3000000{index}",
                    "availability_zone": f"us-west-2{chr(96 + index)}",
                    "private_ip": f"10.30.0.{10 + index}",
                }
            )
        for router in topology_seed()["routers"]:
            instances.append(
                {
                    "actor_type": "router",
                    "actor_id": router["id"],
                    "instance_id": router["instance_id"],
                    "region": router["region"],
                    "vpc_id": router["vpc_id"],
                    "subnet_id": router["subnet_id"],
                    "availability_zone": router["availability_zone"],
                    "private_ip": None,
                }
            )
        output = appliance_output()["workload_instances"]["value"]
        for site in sorted(output):
            for role in sorted(output[site]):
                workload = output[site][role]
                instances.append(
                    {
                        "actor_type": "workload",
                        "actor_id": f"{site}-{role}",
                        "instance_id": workload["instance_id"],
                        "region": "us-west-2" if site == "west" else "us-east-1",
                        "vpc_id": "vpc-10000001" if site == "west" else "vpc-20000001",
                        "subnet_id": workload["subnet_id"],
                        "availability_zone": workload["availability_zone"],
                        "private_ip": workload["private_ip"],
                    }
                )
        return {
            "instances": sorted(
                instances,
                key=lambda actor: (actor["actor_type"], actor["actor_id"]),
            )
        }

    def _record_actor(self, operation: str, actor_type: str, actor_id: str) -> None:
        actor = next(
            actor
            for actor in self._actors()["instances"]
            if actor["actor_type"] == actor_type and actor["actor_id"] == actor_id
        )
        self.ledger.actor(
            operation=operation,
            actor_type=actor_type,
            actor_id=actor_id,
            instance_id=actor["instance_id"],
            region=actor["region"],
            identity_sha256=e2e.canonical_sha256(actor),
        )

    def deploy_controller(self, mode: str) -> Mapping[str, Any]:
        arns = (
            [
                f"arn:aws:ec2:us-west-2:{ACCOUNT_ID}:route-table/rtb-{index:08x}"
                for index in range(1, 5)
            ]
            if mode == "active"
            else []
        )
        return {
            "mode": mode,
            "exact_route_table_arns": arns,
            "actors": self._actors(),
        }

    def _observation(self, stage: str, domain_id: str) -> dict[str, Any]:
        captured_at = self.clock.now()
        captured = e2e.parse_timestamp(captured_at, "fixture capture")
        preferred = self.preferred[domain_id]
        selected = domain_id == "west-a"
        stable_owner = preferred
        tailnet_owner = preferred
        tailnet_agreement = True
        phase: str | None = "stable"
        present = stage != "read-only-cold"
        holder: str | None = "controller-a" if present else None
        fence = 1 if present else 0
        lease_record_version = 1 if present else 0
        revision = 1 if present else 0
        error_code: str | None = None
        error_ambiguous = False
        transaction: dict[str, Any] | None = None
        failed_online: bool | None = None
        if stage == "lease-renewal":
            lease_record_version = 2
            revision = 2
        if selected and stage == "observer-disagreement":
            phase = "degraded"
            tailnet_owner = None
            tailnet_agreement = False
            error_code = "observation-quorum"
            failed_online = False
            revision = 3
        if selected and stage == "route-progress":
            phase = "routes-converging"
            tailnet_owner = "west-b"
            failed_online = False
            revision = 4
        if selected and stage in {
            "router-failover",
            "leader-handoff",
            "durable-alternate",
        }:
            stable_owner = "west-b"
            tailnet_owner = "west-b"
            failed_online = False
        if stage in {"leader-handoff", "durable-alternate", "failback-gate", "failback-stable"}:
            holder = "controller-b"
            fence = 2
            lease_record_version = 1
            revision = 5
        if selected and stage == "failback-gate":
            stable_owner = "west-b"
            tailnet_owner = preferred
            phase = "owner-observed"
            failed_online = True
        if selected and stage == "failback-stable":
            failed_online = True
        if not present:
            phase = None
            stable_owner = None
        authority = self._authority(domain_id)
        route_owners = [stable_owner if stable_owner is not None else preferred] * len(
            authority["remote_prefixes"]
        )
        if selected and stage == "route-progress":
            route_owners = ["west-b", preferred]
            baseline_routes = [
                {
                    "destination_prefix": prefix,
                    "target_router_id": preferred,
                    "target_eni_id": self.route_eni[preferred],
                    "state": "active",
                    "origin": "CreateRoute",
                }
                for prefix in authority["remote_prefixes"]
            ]
            before_table = {
                "route_table_id": authority["route_table_id"],
                "vpc_id": authority["vpc_id"],
                "gwlbe_subnet_id": authority["gwlbe_subnet_id"],
                "route_table_association_id": authority["route_table_association_id"],
                "explicit_association_count": 1,
                "association_state": "associated",
            }
            transaction = {
                "transaction_id_sha256": hashlib.sha256(b"west-a-failover-transaction").hexdigest(),
                "fence_term": 1,
                "desired_owner": "west-b",
                "desired_eni_id": self.route_eni["west-b"],
                "before_sha256": e2e.route_snapshot_sha256(before_table, baseline_routes),
                "progress": [
                    {
                        "destination_prefix": prefix,
                        "attempted": index == 0,
                        "completed": index == 0,
                        "observed_eni_id": self.route_eni["west-b"] if index == 0 else None,
                        "ambiguous": False,
                    }
                    for index, prefix in enumerate(authority["remote_prefixes"])
                ],
            }
        if stage == "read-only-cold":
            endpoint_mode = endpoint_role = "read-only"
            ready_status = 503
            ready_reason = "domain-not-initialized"
        else:
            endpoint_mode = "active"
            endpoint_role = "follower"
            ready_status = 200
            ready_reason = "ok"
        endpoints = []
        actors = {
            actor["actor_id"]: actor
            for actor in self._actors()["instances"]
            if actor["actor_type"] == "controller"
        }
        for controller_id in ("controller-a", "controller-b", "controller-c"):
            role = endpoint_role
            if present and controller_id == holder:
                role = "leader"
            endpoints.append(
                {
                    "controller_id": controller_id,
                    "instance_id": actors[controller_id]["instance_id"],
                    "private_ip": actors[controller_id]["private_ip"],
                    "health_status": 200,
                    "ready_status": ready_status,
                    "ready_reason": ready_reason,
                    "mode": endpoint_mode,
                    "role": role,
                    "phase": phase or "stable",
                    "fence_term": fence,
                    "metrics_sha256": hashlib.sha256(
                        f"{stage}:{domain_id}:{controller_id}".encode()
                    ).hexdigest(),
                    }
                )
        report_owners = [tailnet_owner] * 3
        if selected and stage == "observer-disagreement":
            report_owners = [preferred, "west-b", "west-b"]
        owner_since = (
            self.restored_at
            if selected and stage in {"failback-gate", "failback-stable"}
            else self._timestamp(captured - dt.timedelta(seconds=10))
        )
        contributors = [
            {
                "controller_id": controller_id,
                "sequence": index + 1,
                "captured_at": captured_at,
                "expires_at": self._timestamp(captured + dt.timedelta(seconds=30)),
                "fresh": True,
                "backend_healthy": True,
                "sole_primary": report_owner is not None,
                "owner_healthy": report_owner is not None,
                "owner_node_sha256": (
                    hashlib.sha256(report_owner.encode()).hexdigest()
                    if report_owner is not None
                    else None
                ),
                "owner_since": owner_since if report_owner is not None else None,
            }
            for index, (controller_id, report_owner) in enumerate(
                zip(("controller-a", "controller-b", "controller-c"), report_owners)
            )
        ]
        routes = [
            {
                "destination_prefix": prefix,
                "target_router_id": route_owner,
                "target_eni_id": self.route_eni[route_owner],
                "state": "active",
                "origin": "CreateRoute",
            }
            for prefix, route_owner in zip(authority["remote_prefixes"], route_owners)
        ]
        route_table_base = {
            "route_table_id": authority["route_table_id"],
            "vpc_id": authority["vpc_id"],
            "gwlbe_subnet_id": authority["gwlbe_subnet_id"],
            "route_table_association_id": authority["route_table_association_id"],
            "explicit_association_count": 1,
            "association_state": "associated",
        }
        cooldown_until = None
        owner_observed_at = None
        if selected and stage == "failback-gate":
            assert self.restored_at is not None
            restored = e2e.parse_timestamp(self.restored_at, "fixture restoration")
            cooldown_until = self._timestamp(restored + dt.timedelta(seconds=5))
            owner_observed_at = self.restored_at
        lease_renewed_at = None
        lease_expires_at = None
        if present:
            renewal_offset = 0 if stage == "lease-renewal" else -5
            lease_renewed_at = self._timestamp(
                captured + dt.timedelta(seconds=renewal_offset)
            )
            lease_expires_at = self._timestamp(captured + dt.timedelta(seconds=30))
        return {
            "stage": stage,
            "captured_at": captured_at,
            "domain_id": domain_id,
            "preferred_owner": preferred,
            "dynamodb": {
                "present": present,
                "phase": phase,
                "stable_owner": stable_owner,
                "observed_owner": tailnet_owner if present else None,
                "lease_holder": holder,
                "fence_term": fence,
                "revision": revision,
                "cooldown_until": cooldown_until,
                "lease_record_version": lease_record_version,
                "lease_renewed_at": lease_renewed_at,
                "lease_expires_at": lease_expires_at,
                "owner_observed_at": owner_observed_at,
                "last_transition_at": captured_at if present else None,
                "error_code": error_code,
                "error_ambiguous": error_ambiguous,
                "transaction": transaction,
            },
            "controller_endpoints": endpoints,
            "tailnet": {
                "owner_router_id": tailnet_owner,
                "owner_node_sha256": (
                    hashlib.sha256(tailnet_owner.encode()).hexdigest()
                    if tailnet_owner is not None
                    else None
                ),
                "observer_quorum": 3 if tailnet_agreement else 0,
                "agreement": tailnet_agreement,
                "contributors": contributors,
                "failed_router_online": failed_online,
            },
            "aws_route_table": {
                **route_table_base,
                "stable_read_count": 2,
                "snapshot_sha256": e2e.route_snapshot_sha256(route_table_base, routes),
            },
            "aws_routes": routes,
            "route_agreement": tailnet_agreement
            and len(set(route_owners)) == 1
            and tailnet_owner == route_owners[0]
            and (not present or stable_owner == route_owners[0]),
        }

    def wait_observation(
        self, stage: str, context: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        if stage == "lease-renewal":
            self.clock.advance(5)
        if stage == "failback-stable":
            self.clock.advance(5)
        return [
            self._observation(stage, domain_id) for domain_id in sorted(self.preferred)
        ]

    def select_domain(
        self, observations: Sequence[Mapping[str, Any]]
    ) -> Mapping[str, str]:
        return {
            "domain_id": "west-a",
            "router_id": "west-a",
            "alternate_router_id": "west-b",
        }

    def start_established_flows(
        self, selection: Mapping[str, str]
    ) -> Mapping[str, Any]:
        for _index in range(3):
            self._record_actor("ssm:SendCommand", "workload", "west-initiator")
            self.ledger.remote("workload")
        return {
            "sampled_at": self.clock.now(),
            "source_workload": "west-initiator",
            "destination_workload": "east-initiator",
            "source_instance_id": "i-00000015",
            "destination_instance_id": "i-0000001f",
        }

    def inject_router_failure(
        self, selection: Mapping[str, str]
    ) -> Mapping[str, Any]:
        self._record_actor("ec2:StopInstances", "router", "west-a")
        self.ledger.aws("ec2:StopInstances")
        self.router_fault_at = self.clock.now()
        return {
            **selection,
            "instance_id": "i-00000001",
            "injected_at": self.router_fault_at,
            "restored_at": None,
            "method": "ec2-stop-instance",
        }

    def probe_fresh_flows(
        self,
        stage: str,
        selection: Mapping[str, str],
        context: Mapping[str, str],
    ) -> Sequence[Mapping[str, Any]]:
        result = []
        for protocol in ("tcp", "udp"):
            for _attempt in range(2):
                self._record_actor(
                    "ssm:SendCommand", "workload", "west-initiator"
                )
                self.ledger.remote("workload")
            started = self.clock.now()
            completed = self.clock.now()
            event_at = context["event_at"]
            flow_id = f"{stage}:{protocol}:2"
            result.append(
                {
                    "stage": stage,
                    "protocol": protocol,
                    "attempts": 2,
                    "success": True,
                    "flow_id_sha256": hashlib.sha256(flow_id.encode()).hexdigest(),
                    "connection_id_sha256": hashlib.sha256(
                        f"{flow_id}:c0001".encode()
                    ).hexdigest(),
                    "started_at": started,
                    "event_at": event_at,
                    "convergence_at": context["convergence_at"],
                    "completed_at": completed,
                    "recovery_milliseconds": int(
                        (
                            e2e.parse_timestamp(completed, "fixture completed")
                            - e2e.parse_timestamp(event_at, "fixture event")
                        ).total_seconds()
                        * 1000
                    ),
                    "source_workload": "west-initiator",
                    "destination_workload": "east-initiator",
                    "source_instance_id": "i-00000015",
                    "destination_instance_id": "i-0000001f",
                    "source_port": 61000 + len(result) + 1,
                    "responder_acknowledged": True,
                    "messages_sent": 1,
                    "messages_received": 1,
                    "loss_basis_points": 0,
                    "latency_milliseconds": 1,
                }
            )
        return result

    def inject_leader_failure(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self._record_actor("ec2:StopInstances", "controller", "controller-a")
        self.ledger.aws("ec2:StopInstances")
        transaction = observation["dynamodb"]["transaction"]
        return {
            "domain_id": selection["domain_id"],
            "previous_controller_id": "controller-a",
            "new_controller_id": None,
            "instance_id": "i-50000001",
            "previous_fence": 1,
            "new_fence": 0,
            "injected_at": self.clock.now(),
            "method": "ec2-stop-instance",
            "checkpoint_phase": observation["dynamodb"]["phase"],
            "transaction_id_sha256": transaction["transaction_id_sha256"],
            "journaled_progress_count": sum(
                item["attempted"] or item["completed"]
                for item in transaction["progress"]
            ),
        }

    def observe_stale_fence_rejection(
        self,
        selection: Mapping[str, str],
        leader_fault: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._record_actor("ec2:StartInstances", "controller", "controller-a")
        self.ledger.aws("ec2:StartInstances")
        snapshot = observation["aws_route_table"]["snapshot_sha256"]
        return {
            "domain_id": selection["domain_id"],
            "stale_controller_id": leader_fault["previous_controller_id"],
            "stale_fence": leader_fault["previous_fence"],
            "current_fence": observation["dynamodb"]["fence_term"],
            "observed_at": self.clock.now(),
            "state_revision_before": observation["dynamodb"]["revision"],
            "state_revision_after": observation["dynamodb"]["revision"],
            "route_snapshot_before_sha256": snapshot,
            "route_snapshot_after_sha256": snapshot,
            "stale_write_rejected": True,
            "stale_route_calls": 0,
        }

    def observe_ambiguous_settlement(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        observed_at = self.clock.now()
        settled_at = self.clock.now()
        authority = self._authority(selection["domain_id"])
        desired_eni = self.route_eni[selection["alternate_router_id"]]
        return {
            "domain_id": selection["domain_id"],
            "transaction_id_sha256": hashlib.sha256(
                b"west-a-failover-transaction"
            ).hexdigest(),
            "fence_term": observation["dynamodb"]["fence_term"],
            "destination_prefix": authority["remote_prefixes"][0],
            "desired_eni_id": desired_eni,
            "ambiguous_observed_at": observed_at,
            "settled_at": settled_at,
            "settled_eni_id": desired_eni,
            "authoritative_read_count": 2,
            "blind_retry_count": 0,
            "completed": True,
        }

    def restore_router(self, fault: Mapping[str, Any]) -> Mapping[str, Any]:
        self._record_actor("ec2:StartInstances", "router", "west-a")
        self.ledger.aws("ec2:StartInstances")
        self.restored_at = self.clock.now()
        return {"restored_at": self.restored_at}

    def finish_established_flows(
        self, handle: Mapping[str, Any], context: Mapping[str, str]
    ) -> Sequence[Mapping[str, Any]]:
        self._record_actor("ssm:SendCommand", "workload", "west-initiator")
        self.ledger.remote("workload")
        classified_at = self.clock.now()
        return [
            {
                "protocol": protocol,
                "outcome": "survived",
                "flow_id_sha256": hashlib.sha256(
                    f"established-{protocol}".encode()
                ).hexdigest(),
                "connection_id_sha256": hashlib.sha256(
                    f"established-{protocol}:c0001".encode()
                ).hexdigest(),
                "source_workload": handle["source_workload"],
                "destination_workload": handle["destination_workload"],
                "source_instance_id": handle["source_instance_id"],
                "destination_instance_id": handle["destination_instance_id"],
                "source_port": 60000 if protocol == "tcp" else 60001,
                "sampled_at": handle["sampled_at"],
                "fault_injected_at": context["fault_injected_at"],
                "convergence_at": context["convergence_at"],
                "classified_at": classified_at,
                "error_category": None,
                "expected_markers": 10,
                "attempted_markers": 10,
                "acknowledged_markers": 10,
                "loss_basis_points": 0,
                "pre_fault_acknowledged_sequence": 2,
                "post_convergence_acknowledged_sequence": 9,
                "one_socket": True,
                "agent_output_verified": True,
            }
            for protocol in ("tcp", "udp")
        ]

    def _cleanup(self, name: str) -> Mapping[str, Any]:
        self.cleanup_calls.append(name)
        return {"complete": True}

    def restore_faults_for_cleanup(self) -> Mapping[str, Any]:
        return self._cleanup("restore-faults")

    def quiesce_controller(
        self, _active_attempted: bool, _active_succeeded: bool
    ) -> Mapping[str, Any]:
        self.cleanup_calls.append("quiesce-controller")
        if self.fail_quiesce:
            raise e2e.ContractError("quiescence unavailable")
        return {"complete": True}

    def destroy_controller(self) -> Mapping[str, Any]:
        return self._cleanup("destroy-controller")

    def delete_controller_material(self) -> Mapping[str, Any]:
        if self.fail_material_delete:
            raise e2e.ContractError("material deletion unavailable")
        return self._cleanup("delete-controller-material")

    def destroy_appliance(self) -> Mapping[str, Any]:
        return self._cleanup("destroy-appliance")

    def cleanup_tailnet(self) -> Mapping[str, Any]:
        return self._cleanup("cleanup-tailnet")

    def finalize_backend(self) -> Mapping[str, Any]:
        return self._cleanup("finalize-backend")

    def audit_residuals(self) -> Sequence[Mapping[str, Any]]:
        self.cleanup_calls.append("audit-zero-residual")
        return [
            {"hook": "aws-tagged-resources", "residual_count": 0},
            {"hook": "ssm-secret-references", "residual_count": 0},
            {"hook": "controller-artifact-versions", "residual_count": 0},
            {"hook": "tailnet-devices", "residual_count": 0},
            {"hook": "tailscale-auth-keys", "residual_count": 0},
        ]


class CaptureCommandRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, args: list[str], **_kwargs: Any) -> str:
        self.calls.append(args)
        return "ok"


class VersionedBackendAws:
    def __init__(self) -> None:
        self.objects: dict[str, list[dict[str, Any]]] = {}
        self.bodies: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[list[str], str]] = []
        self.deletes: list[tuple[str, str]] = []
        self.puts = 0
        self.hide_claim_reads = False
        self.fail_claim_put_after_commit = False
        self.state_after_claim: tuple[str, str] | None = None

    @staticmethod
    def _argument(args: list[str], name: str) -> str:
        return args[args.index(name) + 1]

    def add_version(
        self,
        key: str,
        version_id: str,
        kind: str = "version",
        *,
        body: bytes | None = None,
    ) -> None:
        entry: dict[str, Any] = {"version_id": version_id, "kind": kind}
        if body is not None:
            self.bodies[(key, version_id)] = body
        self.objects.setdefault(key, []).append(entry)

    def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
        self.calls.append((list(args), region))
        operation = args[1] if len(args) > 1 else ""
        if operation == "get-bucket-versioning":
            return {"Status": "Enabled"}
        if args[0] == "sts" and operation == "get-caller-identity":
            return {
                "Account": ACCOUNT_ID,
                "Arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/e2e/controller-session",
            }
        if operation == "list-object-versions":
            key = self._argument(args, "--prefix")
            entries = self.objects.get(key, [])
            if self.hide_claim_reads and key.endswith(".claim.json"):
                entries = []
            return {
                "Versions": [
                    {"Key": key, "VersionId": item["version_id"]}
                    for item in entries
                    if item["kind"] == "version"
                ],
                "DeleteMarkers": [
                    {"Key": key, "VersionId": item["version_id"]}
                    for item in entries
                    if item["kind"] == "delete-marker"
                ],
            }
        key = self._argument(args, "--key")
        if operation == "put-object":
            self.assert_conditional_put(args)
            if self.objects.get(key):
                raise RuntimeError("PreconditionFailed")
            self.puts += 1
            version_id = f"claim-version-{self.puts}"
            body_path = pathlib.Path(self._argument(args, "--body"))
            self.add_version(key, version_id, body=body_path.read_bytes())
            if self.state_after_claim is not None:
                state_key, state_version = self.state_after_claim
                self.add_version(state_key, state_version)
                self.state_after_claim = None
            if self.fail_claim_put_after_commit:
                raise RuntimeError("response lost after conditional claim commit")
            return {"VersionId": version_id}
        if operation == "get-object":
            version_id = self._argument(args, "--version-id")
            matches = [
                item
                for item in self.objects.get(key, [])
                if item["version_id"] == version_id and item["kind"] == "version"
            ]
            body = self.bodies.get((key, version_id))
            if len(matches) != 1 or body is None:
                raise RuntimeError("NoSuchVersion")
            pathlib.Path(args[-1]).write_bytes(body)
            return {"VersionId": version_id}
        if operation == "delete-object":
            version_id = self._argument(args, "--version-id")
            entries = self.objects.get(key, [])
            remaining = [
                item for item in entries if item["version_id"] != version_id
            ]
            if len(remaining) == len(entries):
                raise RuntimeError("NoSuchVersion")
            self.objects[key] = remaining
            self.bodies.pop((key, version_id), None)
            self.deletes.append((key, version_id))
            return {"VersionId": version_id}
        raise AssertionError(f"unexpected backend operation: {args}")

    @staticmethod
    def assert_conditional_put(args: list[str]) -> None:
        if (
            "--if-none-match" not in args
            or args[args.index("--if-none-match") + 1] != "*"
        ):
            raise AssertionError("backend claim put was not conditional")


class ProductionControllerConfigTest(unittest.TestCase):
    def test_strict_json_rejects_duplicates_and_nonfinite_numbers(self) -> None:
        with self.assertRaisesRegex(e2e.ContractError, "duplicate JSON key"):
            e2e.strict_json_loads('{"a":1,"a":2}')
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaisesRegex(
                e2e.ContractError, "non-finite"
            ):
                e2e.strict_json_loads('{"value":' + value + "}")

    def test_config_is_version_three_and_uses_distinct_exact_state_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        self.assertEqual(config.raw["symmetric_topology"]["version"], 3)
        self.assertEqual(
            config.appliance_state_key,
            f"runs/{RUN_ID}/appliance/terraform.tfstate",
        )
        self.assertEqual(
            config.controller.state_key,
            f"runs/{RUN_ID}/controller/terraform.tfstate",
        )
        self.assertNotEqual(config.appliance_state_key, config.controller.state_key)

    def test_config_rejects_legacy_unknown_and_unsafe_controller_values(self) -> None:
        mutations = (
            lambda value: value["symmetric_topology"].update(version=2),
            lambda value: value.update(unreviewed=True),
            lambda value: value["production_controller"].update(
                state_key=f"runs/{RUN_ID}/appliance/terraform.tfstate"
            ),
            lambda value: value["production_controller"]["policy"].update(
                failback_stability="2s"
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                document = config_document()
                mutate(document)
                path = pathlib.Path(temporary) / "config.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(e2e.ContractError):
                    e2e.ProductionRunConfig.load(path, enforce_future_expiry=False)

    def test_config_and_runtime_budgets_are_coherent(self) -> None:
        self.assertEqual(e2e.protected_cleanup_bound_seconds(30), 6_630)
        mutations = (
            lambda value: value["production_controller"]["timeouts"].update(
                transition_seconds=10
            ),
            lambda value: value["production_controller"]["timeouts"].update(
                cleanup_seconds=90
            ),
            lambda value: value["production_controller"]["timeouts"].update(
                cleanup_seconds=int(e2e.protected_cleanup_bound_seconds(30))
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                document = config_document()
                mutate(document)
                path = pathlib.Path(temporary) / "config.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(e2e.ContractError):
                    e2e.ProductionRunConfig.load(path, enforce_future_expiry=False)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        e2e.validate_protected_budgets(
            config,
            hard_timeout_seconds=10_800,
            aws_role_duration_seconds=21_600,
            job_timeout_seconds=21_600,
        )
        reservation = (
            10_800
            + config.controller.timeouts["cleanup_seconds"]
            + e2e.PROTECTED_SETUP_SAFETY_MARGIN_SECONDS
        )
        for role_duration, job_timeout in (
            (reservation - 1, 21_600),
            (21_600, reservation - 1),
            (e2e.AWS_MAX_ROLE_DURATION_SECONDS + 1, 36_000),
        ):
            with self.subTest(
                role_duration=role_duration, job_timeout=job_timeout
            ), self.assertRaises(e2e.ContractError):
                e2e.validate_protected_budgets(
                    config,
                    hard_timeout_seconds=10_800,
                    aws_role_duration_seconds=role_duration,
                    job_timeout_seconds=job_timeout,
                )
        with self.assertRaisesRegex(e2e.ContractError, "established-flow"):
            e2e.validate_protected_budgets(
                config,
                hard_timeout_seconds=(
                    e2e.established_stream_duration_seconds(config)
                    + e2e.OBSERVATION_MARGIN_SECONDS
                ),
                aws_role_duration_seconds=36_000,
                job_timeout_seconds=36_000,
            )

    def test_appliance_output_and_tailnet_build_exact_controller_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        topology, identities = e2e.build_controller_topology(
            deployment.seed,
            tailnet_devices(),
            config,
            f"{RUN_ID}-controller-authority",
        )
        self.assertEqual(topology["schema_version"], 1)
        self.assertEqual(len(topology["domains"]), 4)
        self.assertEqual(len(identities), 4)
        self.assertEqual(
            {router["stable_node_id"] for router in topology["routers"]},
            {"node-1", "node-2", "node-3", "node-4"},
        )
        bad_devices = tailnet_devices()
        bad_devices[0]["enabledRoutes"] = ["10.10.1.0/24"]
        with self.assertRaisesRegex(e2e.ContractError, "complete exact site prefix"):
            e2e.build_controller_topology(
                deployment.seed,
                bad_devices,
                config,
                f"{RUN_ID}-controller-authority",
            )

    def test_topology_identity_binds_exact_canonical_bytes(self) -> None:
        topology = {"schema_version": 1, "policy": {"api_timeout": "5s"}}
        canonical = json.dumps(topology, sort_keys=True, separators=(",", ":")).encode()
        identity = {
            "schema": 1,
            "component": "envelope-controller-topology",
            "version": "test.1",
            "revision": "a" * 40,
            "go_version": "go1.26.2",
            "vcs_modified": False,
            "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
            "canonical_json_base64": base64.b64encode(canonical).decode(),
            "policy_durations": {"api_timeout": "5s"},
        }
        self.assertEqual(
            e2e.validate_topology_identity(identity, topology), identity
        )
        identity["canonical_sha256"] = "b" * 64
        with self.assertRaisesRegex(e2e.ContractError, "hash does not match"):
            e2e.validate_topology_identity(identity, topology)


class MutationBoundaryTest(unittest.TestCase):
    def test_guard_rejects_route_mutation_even_after_aws_global_options(self) -> None:
        capture = CaptureCommandRunner()
        ledger = e2e.MutationLedger(session_deny=True)
        runner = e2e.GuardedCommandRunner(capture, ledger)  # type: ignore[arg-type]
        with self.assertRaises(e2e.MutationDenied):
            runner.run(
                [
                    "aws",
                    "--region",
                    "us-west-2",
                    "ec2",
                    "replace-route",
                    "--route-table-id",
                    "rtb-00000001",
                ]
            )
        self.assertEqual(capture.calls, [])
        self.assertEqual(ledger.route_calls, 1)
        self.assertEqual(ledger.denied_attempts, ["ec2:ReplaceRoute"])

        for operation in (
            "associate-route-table",
            "create-route",
            "delete-route",
            "disassociate-route-table",
            "replace-route-table-association",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                e2e.MutationDenied
            ):
                runner.run(["aws", "ec2", operation])
        self.assertEqual(capture.calls, [])

    def test_guard_rejects_tailnet_advertisement_changes_but_allows_reads(self) -> None:
        capture = CaptureCommandRunner()
        ledger = e2e.MutationLedger(session_deny=True)
        runner = e2e.GuardedCommandRunner(capture, ledger)  # type: ignore[arg-type]
        with self.assertRaises(e2e.MutationDenied):
            runner.run(["tailscale", "set", "--advertise-routes=10.0.0.0/8"])
        self.assertEqual(ledger.advertisement_calls, 1)
        self.assertEqual(capture.calls, [])
        self.assertEqual(runner.run(["tailscale", "status", "--json"]), "ok")

    def test_private_evidence_writer_never_overwrites_an_existing_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "evidence.json"
            path.write_text("retained\n", encoding="utf-8")
            with self.assertRaisesRegex(e2e.ContractError, "new regular file"):
                e2e.write_private_json(path, {"replacement": True})
            self.assertEqual(path.read_text(encoding="utf-8"), "retained\n")

    def test_remote_execution_is_limited_to_workload_instances(self) -> None:
        ledger = e2e.MutationLedger(session_deny=True)
        ledger.remote("workload")
        for role in ("target", "router"):
            with self.subTest(role=role), self.assertRaises(e2e.MutationDenied):
                ledger.remote(role)
        self.assertEqual(ledger.workload_remote_calls, 1)
        self.assertEqual(ledger.target_remote_calls, 1)
        self.assertEqual(ledger.router_remote_calls, 1)

    def test_terraform_environment_retains_aws_identity(self) -> None:
        workspace = object.__new__(e2e.TerraformWorkspace)
        workspace.data_dir = pathlib.Path("/tmp/controller-terraform-data")
        with mock.patch.dict(
            os.environ,
            {"AWS_ACCESS_KEY_ID": "fixture-access", "AWS_SESSION_TOKEN": "fixture-token"},
            clear=True,
        ):
            environment = workspace._environment()
        self.assertEqual(environment["AWS_ACCESS_KEY_ID"], "fixture-access")
        self.assertEqual(environment["AWS_SESSION_TOKEN"], "fixture-token")
        self.assertEqual(environment["TF_IN_AUTOMATION"], "1")


class BackendOwnershipTest(unittest.TestCase):
    @staticmethod
    def _adapter(
        config: e2e.ProductionRunConfig,
        aws: VersionedBackendAws,
        run_dir: pathlib.Path,
    ) -> e2e.AwsProductionAdapter:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.aws = aws
        adapter.run_dir = run_dir
        adapter.runner_identity = {
            "account_id": ACCOUNT_ID,
            "principal_arn": (
                f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/e2e/controller-session"
            ),
            "session_name": "controller-session",
        }
        adapter.backend_claim_key = (
            f"runs/{config.run_id}/production-controller-run.claim.json"
        )
        adapter.backend_claim_version_id = None
        adapter.backend_state_cleanup_authorized = False
        adapter.invocation_id = "a" * 64
        return adapter

    @staticmethod
    def _zero_audits() -> list[dict[str, Any]]:
        return [
            {"hook": hook, "residual_count": 0}
            for hook in e2e.RESIDUAL_AUDIT_HOOKS
        ]

    def test_preexisting_backend_state_rejects_claim_without_arming_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            aws.add_version(config.controller.state_key, "preexisting-state")
            adapter = self._adapter(config, aws, directory)
            adapter.ledger = e2e.MutationLedger(session_deny=True)
            adapter.conformance_capabilities = lambda: {  # type: ignore[method-assign]
                name: True for name in e2e.REQUIRED_SCENARIO_CAPABILITIES
            }
            def acquire() -> Mapping[str, Any]:
                adapter._acquire_backend_claim()
                return {"runner_identity": dict(adapter.runner_identity or {})}

            adapter.acquire_backend_claim = acquire  # type: ignore[method-assign]
            adapter.restore_faults_for_cleanup = lambda: {"complete": True}  # type: ignore[method-assign]
            adapter.quiesce_controller = lambda *_args: {"complete": True}  # type: ignore[method-assign]
            adapter.destroy_controller = lambda: {"complete": True}  # type: ignore[method-assign]
            adapter.delete_controller_material = lambda: {"complete": True}  # type: ignore[method-assign]
            adapter.destroy_appliance = lambda: {"complete": True}  # type: ignore[method-assign]
            adapter.cleanup_tailnet = lambda: {"complete": True}  # type: ignore[method-assign]
            adapter.audit_residuals = self._zero_audits  # type: ignore[method-assign]
            begin_cleanup = mock.Mock()
            finish_cleanup = mock.Mock(
                return_value={
                    "termination_requested": False,
                    "acceptance_timed_out": False,
                    "cleanup_timed_out": False,
                }
            )
            result = e2e.ProductionControllerRunner(
                config,
                adapter,
                directory / "evidence.json",
                begin_cleanup=begin_cleanup,
                finish_cleanup=finish_cleanup,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["failure"]["stage"], "acquire-backend-claim")
        self.assertFalse(result.evidence["cleanup"]["attempted"])
        self.assertEqual(result.evidence["cleanup"]["status"], "not-required")
        self.assertFalse(result.evidence["cleanup"]["backend_finalized"])
        self.assertEqual(aws.puts, 0)
        self.assertEqual(aws.deletes, [])
        begin_cleanup.assert_not_called()
        finish_cleanup.assert_not_called()
        self.assertEqual(
            aws.objects[config.controller.state_key],
            [{"version_id": "preexisting-state", "kind": "version"}],
        )
        listed = [
            VersionedBackendAws._argument(args, "--prefix")
            for args, _region in aws.calls
            if args[1] == "list-object-versions"
        ]
        self.assertEqual(
            listed[:5],
            [*adapter._backend_state_keys(), adapter.backend_claim_key],
        )

    def test_conditional_claim_allows_only_one_owner_under_stale_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            first = self._adapter(config, aws, directory)
            second = self._adapter(config, aws, directory)
            first._acquire_backend_claim()
            first_version = first.backend_claim_version_id
            aws.hide_claim_reads = True
            with self.assertRaisesRegex(
                e2e.BackendClaimUncertain, "no provable exact version"
            ):
                second._acquire_backend_claim()
            aws.hide_claim_reads = False

        self.assertIsNotNone(first_version)
        self.assertIsNone(second.backend_claim_version_id)
        self.assertEqual(aws.puts, 1)
        self.assertEqual(
            aws.objects[first.backend_claim_key],
            [{"version_id": first_version, "kind": "version"}],
        )
        first._require_backend_claim()

    def test_ambiguous_claim_commit_reconciles_exact_body_and_requires_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            aws.fail_claim_put_after_commit = True
            adapter = self._adapter(config, aws, directory)
            with self.assertRaisesRegex(
                e2e.BackendClaimUncertain, "exact invocation claim requires cleanup"
            ):
                adapter._acquire_backend_claim()
            claim_version = adapter.backend_claim_version_id
            self.assertEqual(claim_version, "claim-version-1")
            self.assertTrue(adapter.backend_state_cleanup_authorized)
            adapter._require_backend_claim()
            adapter._release_backend_claim()

        self.assertIsNone(adapter.backend_claim_version_id)
        self.assertEqual(
            aws.deletes,
            [(adapter.backend_claim_key, claim_version)],
        )

    def test_ambiguous_claim_never_adopts_or_deletes_a_foreign_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            aws.add_version(
                adapter.backend_claim_key,
                "foreign-version",
                body=b'{"invocation":"foreign"}',
            )
            with self.assertRaisesRegex(
                e2e.ContractError, "belongs to another invocation"
            ):
                adapter._reconcile_backend_claim_write(
                    bucket=config.appliance.backend["bucket"],
                    region=config.appliance.backend["region"],
                    expected_body=b'{"invocation":"owned"}',
                )

        self.assertIsNone(adapter.backend_claim_version_id)
        self.assertEqual(aws.deletes, [])
        self.assertEqual(
            aws.objects[adapter.backend_claim_key],
            [{"version_id": "foreign-version", "kind": "version"}],
        )

    def test_ambiguous_claim_preserves_state_that_appears_during_acquisition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            state_key = adapter._backend_state_keys()[0]
            aws.state_after_claim = (state_key, "competing-state")
            aws.fail_claim_put_after_commit = True
            with self.assertRaisesRegex(e2e.ContractError, "TOCTOU"):
                adapter._acquire_backend_claim()

        self.assertIsNone(adapter.backend_claim_version_id)
        self.assertFalse(adapter.backend_state_cleanup_authorized)
        self.assertEqual(
            aws.objects[state_key],
            [{"version_id": "competing-state", "kind": "version"}],
        )
        self.assertEqual(
            aws.deletes,
            [(adapter.backend_claim_key, "claim-version-1")],
        )

    def test_post_claim_state_toctou_releases_only_the_exact_new_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            state_key = adapter._backend_state_keys()[0]
            aws.state_after_claim = (state_key, "competing-state")
            with self.assertRaisesRegex(e2e.ContractError, "TOCTOU"):
                adapter._acquire_backend_claim()

        self.assertIsNone(adapter.backend_claim_version_id)
        self.assertEqual(
            aws.objects[state_key],
            [{"version_id": "competing-state", "kind": "version"}],
        )
        self.assertEqual(
            aws.deletes,
            [(adapter.backend_claim_key, "claim-version-1")],
        )

    def test_stale_local_terraform_data_is_rejected_before_claim_put(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            appliance_variables = directory / "appliance.tfvars.json"
            appliance_variables.write_text("{}", encoding="utf-8")
            adapter.appliance_workspace = mock.Mock(
                variables_path=appliance_variables,
                data_dir=directory / "terraform-data-appliance",
            )
            adapter.controller_workspace = mock.Mock(
                variables_path=directory / "controller.tfvars.json",
                data_dir=directory / "terraform-data-controller",
            )
            adapter._require_authorized_environment = lambda: None  # type: ignore[method-assign]
            adapter._require_toolchain = lambda: None  # type: ignore[method-assign]
            with self.assertRaisesRegex(e2e.ContractError, "local Terraform"):
                adapter.acquire_backend_claim()

        self.assertEqual(aws.puts, 0)
        self.assertNotIn(adapter.backend_claim_key, aws.objects)

    def test_finalize_without_owned_claim_issues_no_backend_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            with self.assertRaisesRegex(e2e.ContractError, "exact run claim"):
                adapter.finalize_backend()
        self.assertEqual(aws.calls, [])
        self.assertEqual(aws.deletes, [])

    def test_changed_claim_blocks_state_and_foreign_claim_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            adapter._acquire_backend_claim()
            state_key = adapter._backend_state_keys()[0]
            aws.add_version(state_key, "owned-state")
            aws.add_version(adapter.backend_claim_key, "foreign-claim")
            aws.calls.clear()
            with self.assertRaisesRegex(e2e.ContractError, "exclusively"):
                adapter.finalize_backend()
        self.assertEqual(aws.deletes, [])
        self.assertEqual(
            aws.objects[state_key],
            [{"version_id": "owned-state", "kind": "version"}],
        )
        self.assertEqual(len(aws.objects[adapter.backend_claim_key]), 2)

    def test_successful_owner_deletes_state_versions_then_only_its_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            adapter._acquire_backend_claim()
            claim_version = adapter.backend_claim_version_id
            for index, key in enumerate(adapter._backend_state_keys(), start=1):
                aws.add_version(key, f"state-version-{index}")
            aws.calls.clear()
            self.assertEqual(adapter.finalize_backend(), {"complete": True})

        self.assertIsNone(adapter.backend_claim_version_id)
        self.assertEqual(
            [key for key, _version in aws.deletes],
            [*adapter._backend_state_keys(), adapter.backend_claim_key],
        )
        self.assertEqual(aws.deletes[-1], (adapter.backend_claim_key, claim_version))
        self.assertFalse(any(aws.objects.values()))

    def test_failed_prior_cleanup_preserves_claim_and_backend_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            aws = VersionedBackendAws()
            adapter = self._adapter(config, aws, directory)
            adapter._acquire_backend_claim()
            state_key = adapter._backend_state_keys()[0]
            aws.add_version(state_key, "recoverable-state")
            claim_version = adapter.backend_claim_version_id
            aws.calls.clear()
            adapter.ledger = e2e.MutationLedger(session_deny=True)
            adapter.restore_faults_for_cleanup = lambda: {"complete": True}  # type: ignore[method-assign]

            def fail_quiescence(*_args: Any) -> Mapping[str, Any]:
                raise e2e.ContractError("quiescence unavailable")

            adapter.quiesce_controller = fail_quiescence  # type: ignore[method-assign]
            adapter.audit_residuals = self._zero_audits  # type: ignore[method-assign]
            runner = e2e.ProductionControllerRunner(
                config, adapter, directory / "evidence.json"
            )
            cleanup = runner._cleanup(True, True)

        self.assertEqual(cleanup["status"], "failed")
        self.assertFalse(cleanup["backend_finalized"])
        self.assertEqual(aws.deletes, [])
        self.assertEqual(aws.calls, [])
        self.assertEqual(adapter.backend_claim_version_id, claim_version)
        self.assertEqual(
            aws.objects[state_key],
            [{"version_id": "recoverable-state", "kind": "version"}],
        )
        self.assertEqual(
            aws.objects[adapter.backend_claim_key],
            [{"version_id": claim_version, "kind": "version"}],
        )


class MutableResourceOwnershipTest(unittest.TestCase):
    def test_parameter_intent_is_journaled_before_an_ambiguous_put(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            adapter = object.__new__(e2e.AwsProductionAdapter)
            adapter.config = config
            adapter.run_dir = directory
            adapter.runner_identity = {
                "account_id": ACCOUNT_ID,
                "principal_arn": "fixture",
                "session_name": "fixture",
            }
            adapter.router_parameters = []
            adapter.controller_parameters = []
            adapter.invocation_id = "a" * 64

            class AmbiguousParameterAws:
                def json(
                    inner, args: list[str], *, region: str
                ) -> dict[str, Any]:
                    self.assertEqual(args[:2], ["ssm", "put-parameter"])
                    self.assertEqual(len(adapter.controller_parameters), 1)
                    self.assertEqual(
                        adapter.controller_parameters[0]["name"],
                        f"/{RUN_ID}/controller-tsnet",
                    )
                    payload_path = pathlib.Path(
                        args[args.index("--cli-input-json") + 1].removeprefix("file://")
                    )
                    payload = json.loads(payload_path.read_text(encoding="utf-8"))
                    self.assertIn(
                        {
                            "Key": "EnvelopeInvocation",
                            "Value": adapter.invocation_id,
                        },
                        payload["Tags"],
                    )
                    raise RuntimeError("transport failed after commit")

            adapter.aws = AmbiguousParameterAws()
            with self.assertRaisesRegex(RuntimeError, "after commit"):
                adapter._put_parameter(
                    purpose="controller-tsnet",
                    name=f"/{RUN_ID}/controller-tsnet",
                    region=config.controller.region,
                    kms_key_arn=config.controller.secret_kms_key_arn,
                    value="fixture-protected-value",
                )

        self.assertEqual(len(adapter.controller_parameters), 1)
        self.assertNotIn("value", adapter.controller_parameters[0])

    def test_parameter_cleanup_refuses_foreign_ownership_tags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        reference = {
            "purpose": "controller-tsnet",
            "name": f"/{RUN_ID}/controller-tsnet",
            "arn": (
                f"arn:aws:ssm:{config.controller.region}:{ACCOUNT_ID}:"
                f"parameter/{RUN_ID}/controller-tsnet"
            ),
            "kms_key_arn": config.controller.secret_kms_key_arn,
            "region": config.controller.region,
            "invocation_id": "a" * 64,
        }
        operations: list[str] = []

        class ForeignParameterAws:
            def json(
                inner,
                args: list[str],
                *,
                region: str,
                timeout_seconds: float | None = None,
            ) -> dict[str, Any]:
                self.assertIsNotNone(timeout_seconds)
                operations.append(args[1])
                if args[1] == "describe-parameters":
                    return {
                        "Parameters": [
                            {
                                "Name": reference["name"],
                                "Type": "SecureString",
                                "KeyId": reference["kms_key_arn"],
                                "ARN": reference["arn"],
                                "Version": 1,
                            }
                        ]
                    }
                if args[1] == "list-tags-for-resource":
                    return {
                        "TagList": [
                            {"Key": "EnvelopeRun", "Value": RUN_ID},
                            {"Key": "ExpiresAt", "Value": config.expires_at},
                            {"Key": "Purpose", "Value": reference["purpose"]},
                            {"Key": "EnvelopeInvocation", "Value": "b" * 64},
                        ]
                    }
                raise AssertionError("foreign parameter must not be deleted")

        adapter.aws = ForeignParameterAws()
        with self.assertRaisesRegex(e2e.ContractError, "ownership tags"):
            adapter._delete_parameter(reference)
        self.assertEqual(operations, ["describe-parameters", "list-tags-for-resource"])

    def test_ambiguous_parameter_put_and_delete_reconcile_stable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = PollClock()
            adapter = object.__new__(e2e.AwsProductionAdapter)
            adapter.config = config
            adapter.run_dir = directory
            adapter.runner_identity = {
                "account_id": ACCOUNT_ID,
                "principal_arn": "fixture",
                "session_name": "fixture",
            }
            adapter.router_parameters = []
            adapter.controller_parameters = []
            adapter.invocation_id = "a" * 64
            adapter.monotonic = clock.monotonic
            adapter.sleep = clock.sleep

            class EventuallyConsistentParameterAws:
                def __init__(inner) -> None:
                    inner.payload: dict[str, Any] | None = None
                    inner.created_at: float | None = None
                    inner.deleted_at: float | None = None
                    inner.delete_calls = 0

                def visible(inner) -> bool:
                    return bool(
                        inner.created_at is not None
                        and clock.value >= inner.created_at + 3
                        and (
                            inner.deleted_at is None
                            or clock.value < inner.deleted_at + 3
                        )
                    )

                def json(
                    inner,
                    args: list[str],
                    *,
                    region: str,
                    timeout_seconds: float | None = None,
                ) -> dict[str, Any]:
                    operation = args[1]
                    if operation == "put-parameter":
                        payload_path = pathlib.Path(
                            args[
                                args.index("--cli-input-json") + 1
                            ].removeprefix("file://")
                        )
                        inner.payload = json.loads(
                            payload_path.read_text(encoding="utf-8")
                        )
                        inner.created_at = clock.value
                        raise RuntimeError("put response lost after commit")
                    assert inner.payload is not None
                    if operation == "describe-parameters":
                        self.assertIsNotNone(timeout_seconds)
                        if not inner.visible():
                            return {"Parameters": []}
                        name = inner.payload["Name"]
                        return {
                            "Parameters": [
                                {
                                    "Name": name,
                                    "Type": "SecureString",
                                    "KeyId": inner.payload["KeyId"],
                                    "Version": 1,
                                    "ARN": (
                                        f"arn:aws:ssm:{region}:{ACCOUNT_ID}:"
                                        f"parameter{name}"
                                    ),
                                }
                            ]
                        }
                    if operation == "list-tags-for-resource":
                        self.assertIsNotNone(timeout_seconds)
                        return {"TagList": copy.deepcopy(inner.payload["Tags"])}
                    if operation == "delete-parameter":
                        self.assertEqual(
                            timeout_seconds,
                            e2e.SSM_PARAMETER_RECONCILE_TIMEOUT_SECONDS,
                        )
                        inner.delete_calls += 1
                        inner.deleted_at = clock.value
                        raise RuntimeError("delete response lost after commit")
                    raise AssertionError(f"unexpected SSM operation: {args}")

            aws = EventuallyConsistentParameterAws()
            adapter.aws = aws
            with self.assertRaisesRegex(RuntimeError, "put response lost"):
                adapter._put_parameter(
                    purpose="controller-tsnet",
                    name=f"/{RUN_ID}/controller-tsnet",
                    region=config.controller.region,
                    kms_key_arn=config.controller.secret_kms_key_arn,
                    value="fixture-protected-value",
                )
            reference = adapter.controller_parameters[0]
            self.assertEqual(reference["put_outcome"], "ambiguous")
            adapter._delete_parameter(reference)

        self.assertEqual(aws.delete_calls, 1)
        self.assertGreaterEqual(
            clock.value,
            3 + 1 + 3 + e2e.SSM_PARAMETER_STABLE_ABSENCE_SECONDS,
        )

    def test_parameter_delete_and_audit_fail_when_state_stays_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        reference = {
            "purpose": "controller-tsnet",
            "name": f"/{RUN_ID}/controller-tsnet",
            "arn": (
                f"arn:aws:ssm:{config.controller.region}:{ACCOUNT_ID}:"
                f"parameter/{RUN_ID}/controller-tsnet"
            ),
            "kms_key_arn": config.controller.secret_kms_key_arn,
            "region": config.controller.region,
            "invocation_id": "a" * 64,
            "put_outcome": "ambiguous",
        }

        for operation in ("delete", "audit"):
            with self.subTest(operation=operation):
                adapter = object.__new__(e2e.AwsProductionAdapter)
                adapter.config = config
                adapter.router_parameters = []
                adapter.controller_parameters = [reference]
                clock = PollClock()
                adapter.monotonic = clock.monotonic
                adapter.sleep = clock.sleep
                adapter.aws = mock.Mock()
                adapter.aws.json.side_effect = RuntimeError(
                    "parameter visibility unavailable"
                )
                with self.assertRaisesRegex(
                    e2e.ContractError, "could not prove stable SSM parameter"
                ):
                    if operation == "delete":
                        adapter._delete_parameter(reference)
                    else:
                        adapter._parameter_residual_count()
                self.assertEqual(
                    clock.value, e2e.SSM_PARAMETER_RECONCILE_TIMEOUT_SECONDS
                )

    def test_ambiguous_artifact_put_tracks_and_deletes_only_its_version_delta(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            deployment = e2e.parse_appliance_output(appliance_output(), config)
            output_dir = config.appliance.artifact_manifest.parent
            output_dir.mkdir(parents=True, exist_ok=True)
            artifact_path = output_dir / "envelope-controller"
            artifact_path.write_bytes(b"controller artifact")
            digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            revision = "d" * 40
            key = f"runs/{RUN_ID}/controller/{revision}/{artifact_path.name}"

            class AmbiguousArtifactAws:
                def __init__(inner) -> None:
                    inner.objects = {
                        key: [{"version_id": "baseline-version", "kind": "version"}]
                    }
                    inner.deletes: list[str] = []

                def json(
                    inner, args: list[str], *, region: str
                ) -> dict[str, Any]:
                    operation = args[1]
                    object_key = args[args.index("--prefix") + 1] if "--prefix" in args else args[args.index("--key") + 1]
                    if operation == "list-object-versions":
                        values = inner.objects.get(object_key, [])
                        return {
                            "Versions": [
                                {"Key": object_key, "VersionId": value["version_id"]}
                                for value in values
                                if value["kind"] == "version"
                            ],
                            "DeleteMarkers": [],
                        }
                    if operation == "put-object":
                        inner.objects.setdefault(object_key, []).append(
                            {"version_id": "run-version", "kind": "version"}
                        )
                        raise RuntimeError("artifact response lost after commit")
                    if operation == "delete-object":
                        version_id = args[args.index("--version-id") + 1]
                        inner.objects[object_key] = [
                            value
                            for value in inner.objects.get(object_key, [])
                            if value["version_id"] != version_id
                        ]
                        inner.deletes.append(version_id)
                        return {}
                    raise AssertionError(f"unexpected artifact operation {args}")

            aws = AmbiguousArtifactAws()
            adapter = object.__new__(e2e.AwsProductionAdapter)
            adapter.config = config
            adapter.deployment = deployment
            adapter.controller_manifest = {"revision": revision}
            adapter.uploaded_objects = []
            adapter.controller_parameters = []
            adapter.aws = aws
            with self.assertRaisesRegex(RuntimeError, "response lost"):
                adapter._upload_artifact(
                    {
                        "component": "envelope-controller",
                        "file": artifact_path.name,
                        "sha256": digest,
                    }
                )
            self.assertEqual(adapter.uploaded_objects[0]["version_id"], "run-version")
            self.assertEqual(adapter.uploaded_objects[0]["key"], key)
            self.assertEqual(adapter.delete_controller_material(), {"complete": True})

        self.assertEqual(aws.deletes, ["run-version"])
        self.assertEqual(
            aws.objects[key],
            [{"version_id": "baseline-version", "kind": "version"}],
        )

    def test_destroyed_artifact_bucket_has_no_residual_version_delta(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)

        class MissingBucketAws:
            def json(self, _args: list[str], **_kwargs: Any) -> dict[str, Any]:
                raise RuntimeError("An error occurred (NoSuchBucket)")

        adapter.aws = MissingBucketAws()
        self.assertEqual(
            adapter._artifact_version_delta(
                {
                    "bucket": "removed-bucket",
                    "key": "runs/fixture/controller",
                    "region": "us-west-2",
                    "baseline_versions": [],
                }
            ),
            [],
        )

    def test_tailnet_cleanup_requires_post_baseline_exact_name_and_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            expected_name = f"{RUN_ID}-west-transport-a"

            class TailnetFixture:
                def __init__(inner) -> None:
                    inner.devices = [
                        {
                            "id": "baseline-device",
                            "hostname": expected_name,
                            "tags": ["tag:envelope-ci"],
                        },
                        {
                            "id": "owned-device",
                            "hostname": expected_name,
                            "tags": ["tag:envelope-ci"],
                        },
                        {
                            "id": "foreign-device",
                            "hostname": expected_name,
                            "tags": ["tag:foreign"],
                        },
                    ]
                    inner.keys = [
                        {
                            "id": "owned-key",
                            "description": (
                                f"Envelope production controller acceptance {RUN_ID}"
                            ),
                            "capabilities": {
                                "devices": {
                                    "create": {
                                        "reusable": True,
                                        "ephemeral": True,
                                        "preauthorized": True,
                                        "tags": ["tag:envelope-ci"],
                                    }
                                }
                            },
                        }
                    ]
                    inner.deleted: list[str] = []
                    inner.revoked: list[str] = []

                def list_devices(inner) -> list[dict[str, Any]]:
                    return copy.deepcopy(inner.devices)

                def delete_device(inner, device_id: str) -> None:
                    inner.deleted.append(device_id)
                    inner.devices = [
                        device for device in inner.devices if device["id"] != device_id
                    ]

                def list_auth_keys(inner) -> list[dict[str, Any]]:
                    return copy.deepcopy(inner.keys)

                def revoke_auth_key(inner, key_id: str) -> None:
                    inner.revoked.append(key_id)
                    inner.keys = [key for key in inner.keys if key["id"] != key_id]

            tailnet = TailnetFixture()
            adapter = object.__new__(e2e.AwsProductionAdapter)
            adapter.config = config
            adapter.ledger = e2e.MutationLedger(session_deny=True)
            adapter.tailnet = tailnet
            adapter.appliance_deployment_started = True
            adapter.appliance_workspace = mock.Mock(
                variables_path=directory / "appliance.tfvars.json"
            )
            adapter.controller_workspace = mock.Mock(
                variables_path=directory / "controller.tfvars.json"
            )
            adapter.tailnet_baseline_captured = True
            adapter.tailnet_device_baseline_ids = {"baseline-device"}
            adapter.tailnet_auth_key_baseline_ids = set()
            adapter.tailnet_owned_device_ids = {"owned-device"}
            adapter.router_auth_key_description = (
                f"Envelope production controller acceptance {RUN_ID}"
            )
            adapter.created_auth_key_ids = ["owned-key"]
            adapter.router_key_id = "owned-key"
            adapter.router_parameters = []
            self.assertEqual(adapter.cleanup_tailnet(), {"complete": True})

        self.assertEqual(tailnet.deleted, ["owned-device"])
        self.assertEqual(tailnet.revoked, ["owned-key"])
        self.assertEqual(
            {device["id"] for device in tailnet.devices},
            {"baseline-device", "foreign-device"},
        )


class ProductionControllerRunnerTest(unittest.TestCase):
    def _passing_evidence(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            result = e2e.ProductionControllerRunner(
                config,
                FakeAdapter(clock),
                directory / "evidence.json",
                now=clock.now,
            ).run()
        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        return copy.deepcopy(result.evidence)

    def test_complete_fake_lifecycle_produces_verified_private_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)
            evidence_path = directory / "evidence.json"
            result = e2e.ProductionControllerRunner(
                config, adapter, evidence_path, now=clock.now
            ).run()
            persisted = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence_mode = evidence_path.stat().st_mode & 0o777
        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        self.assertEqual(result.evidence, persisted)
        self.assertEqual(e2e.verify_evidence(persisted)["status"], "passed")
        self.assertEqual(
            adapter.cleanup_calls,
            [
                "restore-faults",
                "quiesce-controller",
                "destroy-controller",
                "delete-controller-material",
                "destroy-appliance",
                "cleanup-tailnet",
                "audit-zero-residual",
                "finalize-backend",
            ],
        )
        self.assertEqual(evidence_mode, 0o600)

    def test_quiescence_failure_blocks_destructive_dependents_and_backend_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock, fail_quiesce=True)
            result = e2e.ProductionControllerRunner(
                config, adapter, directory / "evidence.json", now=clock.now
            ).run()
        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(result.evidence["cleanup"]["status"], "failed")
        self.assertNotIn("destroy-controller", adapter.cleanup_calls)
        self.assertNotIn("destroy-appliance", adapter.cleanup_calls)
        self.assertNotIn("finalize-backend", adapter.cleanup_calls)

    def test_verifier_rejects_runner_mutation_and_incomplete_stage_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            result = e2e.ProductionControllerRunner(
                config,
                FakeAdapter(clock),
                directory / "evidence.json",
                now=clock.now,
            ).run()
        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        mutated = copy.deepcopy(result.evidence)
        mutated["mutation_audit"]["route_mutation_calls"] = 1
        with self.assertRaisesRegex(e2e.EvidenceError, "mutation audit"):
            e2e.verify_evidence(mutated)
        incomplete = copy.deepcopy(result.evidence)
        incomplete["observations"] = [
            observation
            for observation in incomplete["observations"]
            if observation["stage"] != "durable-alternate"
        ]
        with self.assertRaisesRegex(e2e.EvidenceError, "does not cover every domain"):
            e2e.verify_evidence(incomplete)

    def test_verifier_rejects_zero_quorum_empty_audits_and_unbound_routes(self) -> None:
        evidence = self._passing_evidence()

        zero_quorum = copy.deepcopy(evidence)
        for observation in zero_quorum["observations"]:
            observation["tailnet"]["observer_quorum"] = 0
        with self.assertRaisesRegex(e2e.EvidenceError, "configured distinct quorum"):
            e2e.verify_evidence(zero_quorum)

        no_audits = copy.deepcopy(evidence)
        no_audits["cleanup"]["audits"] = []
        no_audits["cleanup"]["residual_count"] = 0
        with self.assertRaisesRegex(e2e.EvidenceError, "exact residual audit hook"):
            e2e.verify_evidence(no_audits)

        partial = copy.deepcopy(evidence)
        for observation in partial["observations"]:
            observation["aws_routes"] = observation["aws_routes"][:1]
            observation["aws_route_table"]["snapshot_sha256"] = e2e.route_snapshot_sha256(
                observation["aws_route_table"], observation["aws_routes"]
            )
        with self.assertRaisesRegex(e2e.EvidenceError, "every exact remote prefix"):
            e2e.verify_evidence(partial)

        unauthorized = copy.deepcopy(evidence)
        for observation in unauthorized["observations"]:
            observation["aws_routes"][0]["target_eni_id"] = "eni-deadbeef"
            observation["aws_route_table"]["snapshot_sha256"] = e2e.route_snapshot_sha256(
                observation["aws_route_table"], observation["aws_routes"]
            )
        with self.assertRaisesRegex(e2e.EvidenceError, "exact eligible ENI"):
            e2e.verify_evidence(unauthorized)

        wrong_authority = copy.deepcopy(evidence)
        observation = wrong_authority["observations"][0]
        observation["aws_route_table"]["vpc_id"] = "vpc-deadbeef"
        observation["aws_route_table"]["snapshot_sha256"] = e2e.route_snapshot_sha256(
            observation["aws_route_table"], observation["aws_routes"]
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "exact topology authority"):
            e2e.verify_evidence(wrong_authority)

        one_read = copy.deepcopy(evidence)
        one_read["observations"][0]["aws_route_table"]["stable_read_count"] = 1
        with self.assertRaisesRegex(e2e.EvidenceError, "exact topology authority"):
            e2e.verify_evidence(one_read)

    def test_validator_rejects_false_complete_cleanup_semantics(self) -> None:
        evidence = self._passing_evidence()
        mutations = {
            "false completion flag": lambda cleanup: cleanup.update(
                controller_destroyed=False
            ),
            "reordered sequence": lambda cleanup: cleanup["sequence"].reverse(),
            "nonzero residual": lambda cleanup: (
                cleanup["audits"][0].update(residual_count=1),
                cleanup.update(residual_count=1),
            ),
            "retained error": lambda cleanup: cleanup.update(
                errors=["material deletion uncertain"]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                malformed = copy.deepcopy(evidence)
                mutate(malformed["cleanup"])
                with self.assertRaisesRegex(
                    e2e.EvidenceError, "exact ordered zero-residual lifecycle"
                ):
                    e2e.validate_evidence(malformed)

    def test_verifier_rejects_short_failback_and_missing_safety_proofs(self) -> None:
        evidence = self._passing_evidence()
        selected_domain = evidence["faults"]["router"]["domain_id"]

        short_failback = copy.deepcopy(evidence)
        stable = next(
            item
            for item in short_failback["observations"]
            if item["stage"] == "failback-stable" and item["domain_id"] == selected_domain
        )
        gate = next(
            item
            for item in short_failback["observations"]
            if item["stage"] == "failback-gate" and item["domain_id"] == selected_domain
        )
        too_recent = (
            e2e.parse_timestamp(stable["captured_at"], "stable")
            - dt.timedelta(seconds=4)
        ).isoformat().replace("+00:00", "Z")
        gate["dynamodb"]["owner_observed_at"] = too_recent
        for contributor in stable["tailnet"]["contributors"]:
            contributor["owner_since"] = too_recent
        with self.assertRaisesRegex(e2e.EvidenceError, "continuous owner stability"):
            e2e.verify_evidence(short_failback)

        no_renewal = copy.deepcopy(evidence)
        baseline = next(
            item
            for item in no_renewal["observations"]
            if item["stage"] == "active-baseline" and item["domain_id"] == selected_domain
        )
        renewed = next(
            item
            for item in no_renewal["observations"]
            if item["stage"] == "lease-renewal" and item["domain_id"] == selected_domain
        )
        renewed["dynamodb"]["lease_record_version"] = baseline["dynamodb"][
            "lease_record_version"
        ]
        with self.assertRaisesRegex(e2e.EvidenceError, "actual same-fence lease renewal"):
            e2e.verify_evidence(no_renewal)

        no_disagreement_hold = copy.deepcopy(evidence)
        disagreement = next(
            item
            for item in no_disagreement_hold["observations"]
            if item["stage"] == "observer-disagreement"
            and item["domain_id"] == selected_domain
        )
        disagreement["aws_routes"][0]["target_router_id"] = "west-b"
        disagreement["aws_routes"][0]["target_eni_id"] = "eni-00000002"
        disagreement["aws_route_table"]["snapshot_sha256"] = e2e.route_snapshot_sha256(
            disagreement["aws_route_table"], disagreement["aws_routes"]
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "retain the prior route"):
            e2e.verify_evidence(no_disagreement_hold)

        completed_checkpoint = copy.deepcopy(evidence)
        progress = next(
            item
            for item in completed_checkpoint["observations"]
            if item["stage"] == "route-progress" and item["domain_id"] == selected_domain
        )
        for item in progress["dynamodb"]["transaction"]["progress"]:
            item["attempted"] = True
            item["completed"] = True
            item["observed_eni_id"] = "eni-00000002"
        completed_checkpoint["faults"]["leader"]["journaled_progress_count"] = len(
            progress["dynamodb"]["transaction"]["progress"]
        )
        with self.assertRaisesRegex(e2e.EvidenceError, "journaled in-progress"):
            e2e.verify_evidence(completed_checkpoint)

        stale_call = copy.deepcopy(evidence)
        stale_call["control_plane"]["stale_fence_rejection"]["stale_route_calls"] = 1
        with self.assertRaisesRegex(e2e.EvidenceError, "stale-fence rejection"):
            e2e.verify_evidence(stale_call)

        blind_retry = copy.deepcopy(evidence)
        blind_retry["control_plane"]["ambiguous_settlement"]["blind_retry_count"] = 1
        with self.assertRaisesRegex(e2e.EvidenceError, "ambiguous-call settlement"):
            e2e.verify_evidence(blind_retry)

    def test_verifier_rejects_unbound_flow_claims(self) -> None:
        evidence = self._passing_evidence()
        fresh = copy.deepcopy(evidence)
        fresh["fresh_flows"][0]["responder_acknowledged"] = False
        with self.assertRaisesRegex(e2e.EvidenceError, "fresh TCP and UDP retry"):
            e2e.verify_evidence(fresh)

        established = copy.deepcopy(evidence)
        established["established_flows"][0]["agent_output_verified"] = False
        with self.assertRaisesRegex(e2e.EvidenceError, "bounded and classified"):
            e2e.verify_evidence(established)

    def test_verifier_rejects_actor_endpoint_call_and_settlement_substitution(
        self,
    ) -> None:
        evidence = self._passing_evidence()

        actor_swap = copy.deepcopy(evidence)
        actor = next(
            actor
            for actor in actor_swap["actors"]["instances"]
            if actor["actor_type"] == "workload"
            and actor["actor_id"] == "west-initiator"
        )
        actor["instance_id"] = "i-deadbeef"
        with self.assertRaisesRegex(e2e.EvidenceError, "actor"):
            e2e.verify_evidence(actor_swap)

        dead_leader = copy.deepcopy(evidence)
        baseline = next(
            observation
            for observation in dead_leader["observations"]
            if observation["stage"] == "active-baseline"
            and observation["domain_id"] == "west-a"
        )
        leader = next(
            endpoint
            for endpoint in baseline["controller_endpoints"]
            if endpoint["controller_id"] == baseline["dynamodb"]["lease_holder"]
        )
        leader["health_status"] = 0
        leader["ready_status"] = 0
        with self.assertRaisesRegex(e2e.EvidenceError, "endpoint liveness"):
            e2e.verify_evidence(dead_leader)

        uncounted_remote = copy.deepcopy(evidence)
        uncounted_remote["mutation_audit"]["remote_execution"][
            "workload_calls"
        ] -= 1
        with self.assertRaisesRegex(e2e.EvidenceError, "mutation audit"):
            e2e.verify_evidence(uncounted_remote)

        wrong_transaction = copy.deepcopy(evidence)
        wrong_transaction["control_plane"]["ambiguous_settlement"][
            "transaction_id_sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(e2e.EvidenceError, "ambiguous-call settlement"):
            e2e.verify_evidence(wrong_transaction)

        wrong_fence = copy.deepcopy(evidence)
        wrong_fence["control_plane"]["ambiguous_settlement"]["fence_term"] += 1
        with self.assertRaisesRegex(e2e.EvidenceError, "ambiguous-call settlement"):
            e2e.verify_evidence(wrong_fence)

        stale_settlement = copy.deepcopy(evidence)
        handoff = next(
            observation
            for observation in stale_settlement["observations"]
            if observation["stage"] == "leader-handoff"
            and observation["domain_id"] == "west-a"
        )
        before_handoff = (
            e2e.parse_timestamp(handoff["captured_at"], "handoff")
            - dt.timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        settlement = stale_settlement["control_plane"]["ambiguous_settlement"]
        settlement["ambiguous_observed_at"] = before_handoff
        settlement["settled_at"] = before_handoff
        with self.assertRaisesRegex(e2e.EvidenceError, "ambiguous-call settlement"):
            e2e.verify_evidence(stale_settlement)

    def test_missing_live_scenario_capability_fails_before_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock, unsupported_capability="ambiguous-settlement")
            adapter.acquire_backend_claim = mock.Mock(  # type: ignore[method-assign]
                wraps=adapter.acquire_backend_claim
            )
            adapter.prepare = mock.Mock(wraps=adapter.prepare)  # type: ignore[method-assign]
            begin_cleanup = mock.Mock()
            finish_cleanup = mock.Mock()
            evidence_path = directory / "evidence.json"
            result = e2e.ProductionControllerRunner(
                config,
                adapter,
                evidence_path,
                now=clock.now,
                begin_cleanup=begin_cleanup,
                finish_cleanup=finish_cleanup,
            ).run()
            persisted = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence, persisted)
        self.assertEqual(result.evidence["failure"]["stage"], "prepare")
        self.assertIn("ambiguous-settlement", result.evidence["failure"]["message"])
        adapter.acquire_backend_claim.assert_not_called()
        adapter.prepare.assert_not_called()
        begin_cleanup.assert_not_called()
        finish_cleanup.assert_not_called()
        self.assertEqual(adapter.cleanup_calls, [])
        self.assertEqual(
            result.evidence["cleanup"],
            {
                "attempted": False,
                "status": "not-required",
                "sequence": [],
                "controller_quiesced": False,
                "controller_destroyed": False,
                "material_deleted": False,
                "appliance_destroyed": False,
                "tailnet_cleaned": False,
                "backend_finalized": False,
                "audits": [],
                "residual_count": 0,
                "errors": [],
            },
        )

        invalid = copy.deepcopy(result.evidence)
        invalid["cleanup"]["attempted"] = True
        with self.assertRaisesRegex(e2e.EvidenceError, "exact empty failed evidence"):
            e2e.validate_evidence(invalid)
        passing = self._passing_evidence()
        passing["cleanup"] = copy.deepcopy(result.evidence["cleanup"])
        with self.assertRaisesRegex(e2e.EvidenceError, "exact empty failed evidence"):
            e2e.validate_evidence(passing)

    def test_uncertain_backend_claim_arms_cleanup_and_never_emits_not_required(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)
            adapter.acquire_backend_claim = mock.Mock(  # type: ignore[method-assign]
                side_effect=e2e.BackendClaimUncertain(
                    "conditional claim response was ambiguous"
                )
            )
            adapter.finalize_backend = mock.Mock(  # type: ignore[method-assign]
                side_effect=e2e.ContractError(
                    "backend finalization requires an exact invocation claim"
                )
            )
            result = e2e.ProductionControllerRunner(
                config,
                adapter,
                directory / "evidence.json",
                now=clock.now,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertTrue(result.evidence["cleanup"]["attempted"])
        self.assertEqual(result.evidence["cleanup"]["status"], "failed")
        self.assertEqual(
            result.evidence["cleanup"]["sequence"],
            list(e2e.COMPLETE_CLEANUP_SEQUENCE),
        )
        self.assertFalse(result.evidence["cleanup"]["backend_finalized"])
        self.assertNotEqual(result.evidence["cleanup"]["status"], "not-required")

    def test_known_claim_version_arms_cleanup_when_acquisition_is_interrupted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)

            def acquire_then_interrupt() -> Mapping[str, Any]:
                adapter.backend_claim_version_id = "claim-version"
                raise e2e.TerminationRequested("signal after claim creation")

            adapter.acquire_backend_claim = acquire_then_interrupt  # type: ignore[method-assign]
            result = e2e.ProductionControllerRunner(
                config,
                adapter,
                directory / "evidence.json",
                now=clock.now,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertTrue(result.evidence["cleanup"]["attempted"])
        self.assertEqual(result.evidence["cleanup"]["status"], "complete")
        self.assertEqual(
            result.evidence["cleanup"]["sequence"],
            list(e2e.COMPLETE_CLEANUP_SEQUENCE),
        )

    def test_material_failure_preserves_backend_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock, fail_material_delete=True)
            result = e2e.ProductionControllerRunner(
                config, adapter, directory / "evidence.json", now=clock.now
            ).run()
        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertFalse(result.evidence["cleanup"]["backend_finalized"])
        self.assertNotIn("finalize-backend", adapter.cleanup_calls)

    def test_cleanup_callbacks_bracket_ordered_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)
            callback_states: list[tuple[str, list[str]]] = []

            def begin_cleanup() -> None:
                callback_states.append(("begin", list(adapter.cleanup_calls)))

            def finish_cleanup() -> Mapping[str, bool]:
                callback_states.append(("finish", list(adapter.cleanup_calls)))
                return {"termination_requested": False, "acceptance_timed_out": False}

            result = e2e.ProductionControllerRunner(
                config,
                adapter,
                directory / "evidence.json",
                now=clock.now,
                begin_cleanup=begin_cleanup,
                finish_cleanup=finish_cleanup,
            ).run()
        self.assertEqual(result.exit_code, e2e.EXIT_OK)
        self.assertEqual(callback_states[0], ("begin", []))
        self.assertEqual(callback_states[-1][0], "finish")
        self.assertEqual(callback_states[-1][1][-1], "finalize-backend")

    def test_runner_starts_cleanup_without_manipulating_process_signal_mask(self) -> None:
        runner = object.__new__(e2e.ProductionControllerRunner)
        events: list[str] = []
        cleanup_started = False

        def begin_cleanup() -> None:
            nonlocal cleanup_started
            events.append("begin")
            cleanup_started = True

        runner.begin_cleanup = begin_cleanup
        with mock.patch.object(e2e.signal, "pthread_sigmask") as signal_mask:
            runner._begin_cleanup_atomically()
        self.assertTrue(cleanup_started)
        self.assertEqual(events, ["begin"])
        signal_mask.assert_not_called()

    def test_signal_at_cleanup_boundary_retries_until_state_is_set(self) -> None:
        runner = object.__new__(e2e.ProductionControllerRunner)
        cleanup_started = False
        calls = 0

        def begin_cleanup() -> None:
            nonlocal cleanup_started, calls
            calls += 1
            if calls == 1:
                raise e2e.TerminationRequested("boundary signal")
            cleanup_started = True

        runner.begin_cleanup = begin_cleanup
        deferred = runner._begin_cleanup_atomically()
        self.assertTrue(cleanup_started)
        self.assertIsInstance(deferred, e2e.TerminationRequested)
        self.assertEqual(calls, 2)

    def test_repeated_cleanup_boundary_signals_preserve_the_first_interruption(self) -> None:
        runner = object.__new__(e2e.ProductionControllerRunner)
        calls = 0

        def begin_cleanup() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise e2e.TerminationRequested("boundary signal")
            if calls == 2:
                raise e2e.HardTimeout("boundary timeout")

        runner.begin_cleanup = begin_cleanup
        deferred = runner._begin_cleanup_atomically()
        self.assertIsInstance(deferred, e2e.TerminationRequested)
        self.assertEqual(calls, 3)

    def test_lifecycle_defers_sigterm_only_after_cleanup_starts(self) -> None:
        deadline = e2e.ProtectedLifecycleDeadline(60, 30)
        with self.assertRaises(e2e.TerminationRequested):
            deadline._terminate(0, None)
        deadline.cleanup_started = True
        deadline._terminate(0, None)
        self.assertTrue(deadline.termination_deferred)
        deadline.cleanup_finished = True
        deadline._handoff = True
        with self.assertRaises(e2e.TerminationRequested):
            deadline._terminate(0, None)

    def test_lifecycle_rearms_a_distinct_cleanup_deadline(self) -> None:
        with (
            mock.patch.object(e2e.signal, "getsignal", return_value=e2e.signal.SIG_DFL),
            mock.patch.object(e2e.signal, "getitimer", return_value=(0.0, 0.0)),
            mock.patch.object(e2e.signal, "signal"),
            mock.patch.object(e2e.signal, "setitimer") as setitimer,
            mock.patch.object(e2e.signal, "pthread_sigmask", return_value=set()),
            mock.patch.object(e2e.signal, "sigpending", return_value=set()),
        ):
            with e2e.ProtectedLifecycleDeadline(60, 30) as deadline:
                deadline.start_cleanup()
                deadline.finish_cleanup()
        active = mock.call(e2e.signal.ITIMER_REAL, 60)
        cleanup = mock.call(e2e.signal.ITIMER_REAL, 30)
        self.assertIn(active, setitimer.mock_calls)
        self.assertIn(cleanup, setitimer.mock_calls)
        self.assertLess(setitimer.mock_calls.index(active), setitimer.mock_calls.index(cleanup))

    def test_cleanup_timeout_stops_destructive_followups_and_backend_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)
            adapter.restore_faults_for_cleanup = mock.Mock(  # type: ignore[method-assign]
                side_effect=e2e.CleanupTimeout("fixture cleanup timeout")
            )
            evidence_path = directory / "evidence.json"
            with self.assertRaises(e2e.CleanupTimeout):
                e2e.ProductionControllerRunner(
                    config, adapter, evidence_path, now=clock.now
                ).run()
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(adapter.cleanup_calls, [])
        self.assertFalse(evidence["cleanup"]["backend_finalized"])

    def test_cleanup_never_swallows_lifecycle_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            for exception in (
                e2e.HardTimeout("hard"),
                e2e.CleanupTimeout("cleanup"),
                e2e.TerminationRequested("term"),
            ):
                with self.subTest(exception=type(exception).__name__):
                    adapter = FakeAdapter(TickClock())
                    adapter.restore_faults_for_cleanup = mock.Mock(  # type: ignore[method-assign]
                        side_effect=exception
                    )
                    runner = e2e.ProductionControllerRunner(
                        config, adapter, directory / "evidence.json"
                    )
                    with self.assertRaises(type(exception)):
                        runner._cleanup(False, False)

    def test_evidence_scanner_rejects_credentials_and_raw_stable_nodes(self) -> None:
        self.assertTrue(e2e.scan_evidence({"api_key": "fixture"}))
        self.assertTrue(e2e.scan_evidence({"value": "tskey-secret-material"}))
        self.assertTrue(e2e.scan_evidence({"stable_node_id": "node-1"}))
        opaque = "opaque-session-" + "x" * 256
        self.assertTrue(
            e2e.scan_evidence(
                {"ready_reason": opaque[:64]},
                [opaque],
            )
        )
        self.assertEqual(e2e.scan_evidence({"stable_node_sha256": "a" * 64}), [])

    def test_all_protected_environment_credentials_feed_the_final_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        environment_names = (
            *config.appliance.oauth_environment_names,
            e2e.CONTROLLER_TSNET_ENV,
            e2e.CONTROLLER_ADMIN_ENV,
            *e2e.AWS_CREDENTIAL_ENVIRONMENT_NAMES,
        )
        values = {
            name: f"opaque-{index}-" + chr(97 + index) * 64
            for index, name in enumerate(environment_names)
        }
        with mock.patch.dict(os.environ, values, clear=False):
            protected = e2e.protected_environment_secrets(config)
        self.assertEqual(set(protected), set(values.values()))
        for value in values.values():
            with self.subTest(value=value[:16]):
                self.assertTrue(
                    e2e.scan_evidence({"value": value[:40]}, protected)
                )

    def test_controller_readiness_body_is_redacted_and_allowlisted_before_truncation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        secret = "opaque-controller-secret-" + "z" * 256
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.controller_output = {}
        adapter.protected_secrets = (secret,)
        actors = [
            {
                "actor_id": controller_id,
                "instance_id": f"i-{0x50000000 + index:08x}",
                "private_ip": f"10.30.0.{10 + index}",
            }
            for index, controller_id in enumerate(
                config.controller.controller_ids, start=1
            )
        ]
        adapter._controller_actors = lambda _output: actors  # type: ignore[method-assign]

        def http_get(url: str) -> tuple[int, str]:
            if url.endswith("/healthz"):
                return 200, "ok\n"
            if url.endswith("/readyz"):
                return 503, secret + " trailing provider text"
            return 503, "unavailable"

        adapter._http_get = http_get  # type: ignore[method-assign]
        snapshots = adapter._controller_endpoint_snapshots()
        self.assertEqual(
            {snapshot["ready_reason"] for snapshot in snapshots.values()},
            {"unavailable"},
        )
        self.assertNotIn(secret[:32], json.dumps(snapshots, sort_keys=True))

    def test_top_level_run_failure_redacts_protected_environment_credentials(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            secret = "opaque-top-level-session-" + "q" * 128
            stderr = io.StringIO()
            with (
                mock.patch.dict(
                    os.environ,
                    {"AWS_SESSION_TOKEN": secret},
                    clear=False,
                ),
                mock.patch.object(
                    e2e.ProductionRunConfig,
                    "load",
                    return_value=config,
                ),
                mock.patch.object(
                    e2e,
                    "validate_protected_budgets",
                    side_effect=RuntimeError(f"provider failure: {secret}"),
                ),
                mock.patch.object(sys, "stderr", stderr),
            ):
                status = e2e.main(["run-all", "--config", str(config.path)])

        self.assertEqual(status, e2e.EXIT_CONTRACT_ERROR)
        self.assertNotIn(secret[:32], stderr.getvalue())
        self.assertIn("[REDACTED]", stderr.getvalue())

    def test_scanner_rejected_evidence_is_never_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            config = make_config(directory)
            clock = TickClock()
            adapter = FakeAdapter(clock)
            original_wait = adapter.wait_observation
            secret = "opaque-protected-admin-value"

            def unsafe_wait(
                stage: str, context: Mapping[str, Any]
            ) -> Sequence[Mapping[str, Any]]:
                observations = copy.deepcopy(original_wait(stage, context))
                if stage == "active-baseline":
                    observations[0]["controller_endpoints"][0]["ready_reason"] = secret
                return observations

            adapter.wait_observation = unsafe_wait  # type: ignore[method-assign]
            evidence_path = directory / "evidence.json"
            with mock.patch.dict(
                os.environ, {e2e.CONTROLLER_ADMIN_ENV: secret}, clear=False
            ), self.assertRaisesRegex(
                e2e.EvidenceError, "refusing to persist unsafe evidence"
            ):
                e2e.ProductionControllerRunner(
                    config, adapter, evidence_path, now=clock.now
                ).run()
        self.assertFalse(evidence_path.exists())
        self.assertEqual(adapter.cleanup_calls[-1], "finalize-backend")


class ConcreteObservationTest(unittest.TestCase):
    def test_live_adapter_declares_unavailable_scenarios_fail_closed(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        capabilities = adapter.conformance_capabilities()
        self.assertFalse(capabilities["observer-disagreement"])
        self.assertFalse(capabilities["stale-fence-rejection"])
        self.assertFalse(capabilities["ambiguous-settlement"])
        self.assertTrue(capabilities["lease-renewal"])
        self.assertFalse(capabilities["in-progress-leader-failure"])

    def test_ec2_actors_are_described_immediately_before_ssm_and_faults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.controller_output = {
            "controller_instances": {
                "value": {
                    controller_id: {
                        "instance_id": f"i-{0x50000000 + index:08x}",
                        "private_ip": f"10.30.0.{10 + index}",
                        "subnet_id": f"subnet-3000000{index}",
                        "availability_zone": f"us-west-2{chr(96 + index)}",
                        "observer_volume_id": f"vol-{index:08x}",
                    }
                    for index, controller_id in enumerate(
                        config.controller.controller_ids, start=1
                    )
                }
            }
        }
        actors = {
            str(actor["instance_id"]): adapter._expected_instance_actor(
                str(actor["instance_id"]), str(actor["region"])
            )
            for actor in adapter._instance_actors()
        }

        class ActorAws:
            def __init__(inner) -> None:
                inner.calls: list[tuple[str, str]] = []
                inner.bad_tags_for: str | None = None

            def json(
                inner, args: list[str], *, region: str
            ) -> dict[str, Any]:
                operation = args[1]
                inner.calls.append((operation, region))
                if operation == "describe-instances":
                    instance_id = args[args.index("--instance-ids") + 1]
                    actor = actors[instance_id]
                    tags = dict(actor["expected_tags"])
                    if inner.bad_tags_for == instance_id:
                        tags["EnvelopeRun"] = "foreign-run"
                    instance = {
                        "InstanceId": instance_id,
                        "VpcId": actor["vpc_id"],
                        "SubnetId": actor["subnet_id"],
                        "Placement": {
                            "AvailabilityZone": actor["availability_zone"]
                        },
                        "State": {"Name": "running"},
                        "Tags": [
                            {"Key": name, "Value": value}
                            for name, value in tags.items()
                        ],
                    }
                    if actor["private_ip"] is not None:
                        instance["PrivateIpAddress"] = actor["private_ip"]
                    return {"Reservations": [{"Instances": [instance]}]}
                if operation == "send-command":
                    return {
                        "Command": {
                            "CommandId": "11111111-2222-4333-8444-555555555555"
                        }
                    }
                if operation in {"stop-instances", "start-instances"}:
                    return {}
                raise AssertionError(f"unexpected actor operation: {args}")

        aws = ActorAws()
        adapter.aws = aws
        workload = deployment.workloads["west"]["initiator"]
        command_id = adapter._send_workload_command(
            workload["instance_id"],
            workload["region"],
            "true",
            timeout_seconds=30,
        )
        self.assertEqual(command_id, "11111111-2222-4333-8444-555555555555")
        router = deployment.seed.routers_by_id["west-a"]
        adapter._instance_fault("stop", router["instance_id"], router["region"])
        controller = actors["i-50000001"]
        adapter._instance_fault(
            "stop", controller["instance_id"], controller["region"]
        )
        self.assertEqual(
            [operation for operation, _region in aws.calls],
            [
                "describe-instances",
                "send-command",
                "describe-instances",
                "stop-instances",
                "describe-instances",
                "stop-instances",
            ],
        )
        self.assertEqual(len(adapter.ledger.actor_validations), 3)

        aws.calls.clear()
        aws.bad_tags_for = workload["instance_id"]
        with self.assertRaisesRegex(e2e.MutationDenied, "ownership tags"):
            adapter._send_workload_command(
                workload["instance_id"],
                workload["region"],
                "true",
                timeout_seconds=30,
            )
        self.assertEqual(aws.calls, [("describe-instances", workload["region"])])

    def test_fault_intent_is_tracked_before_an_ambiguous_stop_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.failed_router_id = None
        adapter.failed_router_instance = None
        adapter.router_restoration_phase = None
        adapter.failed_controller_id = None
        adapter.failed_controller_instance = None
        adapter.controller_restoration_phase = None
        adapter.established_commands = {}
        adapter.controller_output = {
            "controller_instances": {
                "value": {
                    controller_id: {
                        "instance_id": f"i-{0x50000000 + index:08x}"
                    }
                    for index, controller_id in enumerate(
                        config.controller.controller_ids, start=1
                    )
                }
            }
        }
        adapter._instance_fault = mock.Mock(  # type: ignore[method-assign]
            side_effect=RuntimeError("response lost after stop commit")
        )
        adapter._validate_instance_actor = mock.Mock(  # type: ignore[method-assign]
            side_effect=lambda instance_id, region, _operation: {
                "actor_type": "router" if instance_id == "i-00000001" else "controller",
                "actor_id": "west-a" if instance_id == "i-00000001" else "controller-a",
                "instance_id": instance_id,
                "region": region,
            }
        )
        selection = {
            "domain_id": "west-a",
            "router_id": "west-a",
            "alternate_router_id": "west-b",
        }
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            adapter.inject_router_failure(selection)
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_STOP_CALL_ARMED
        )
        self.assertEqual(adapter.failed_router_id, "west-a")
        self.assertEqual(adapter.failed_router_instance, "i-00000001")

        progress = {
            "dynamodb": {
                "lease_holder": "controller-a",
                "fence_term": 1,
                "phase": "routes-converging",
                "transaction": {
                    "transaction_id_sha256": "a" * 64,
                    "progress": [{"attempted": True, "completed": False}],
                },
            }
        }
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            adapter.inject_leader_failure(selection, progress)
        self.assertEqual(
            adapter.controller_restoration_phase, e2e.EC2_FAULT_STOP_CALL_ARMED
        )
        self.assertEqual(adapter.failed_controller_id, "controller-a")
        self.assertEqual(adapter.failed_controller_instance, "i-50000001")

    def test_pre_stop_validation_failure_leaves_no_restoration_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.failed_router_id = None
        adapter.failed_router_instance = None
        adapter.router_restoration_phase = None
        adapter.failed_controller_id = None
        adapter.failed_controller_instance = None
        adapter.controller_restoration_phase = None
        adapter.controller_output = {
            "controller_instances": {
                "value": {
                    controller_id: {
                        "instance_id": f"i-{0x50000000 + index:08x}"
                    }
                    for index, controller_id in enumerate(
                        config.controller.controller_ids, start=1
                    )
                }
            }
        }
        adapter._validate_instance_actor = mock.Mock(  # type: ignore[method-assign]
            side_effect=e2e.MutationDenied("definite actor validation failure")
        )
        adapter._instance_fault = mock.Mock()  # type: ignore[method-assign]
        selection = {
            "domain_id": "west-a",
            "router_id": "west-a",
            "alternate_router_id": "west-b",
        }

        with self.assertRaisesRegex(e2e.MutationDenied, "validation failure"):
            adapter.inject_router_failure(selection)
        self.assertIsNone(adapter.failed_router_id)
        self.assertIsNone(adapter.failed_router_instance)
        self.assertIsNone(adapter.router_restoration_phase)

        progress = {
            "dynamodb": {
                "lease_holder": "controller-a",
                "fence_term": 1,
                "phase": "routes-converging",
                "transaction": {
                    "transaction_id_sha256": "a" * 64,
                    "progress": [{"attempted": True, "completed": False}],
                },
            }
        }
        with self.assertRaisesRegex(e2e.MutationDenied, "validation failure"):
            adapter.inject_leader_failure(selection, progress)
        self.assertIsNone(adapter.failed_controller_id)
        self.assertIsNone(adapter.failed_controller_instance)
        self.assertIsNone(adapter.controller_restoration_phase)
        adapter._instance_fault.assert_not_called()

    def test_fault_restoration_waits_through_stale_running_delayed_stop_and_ambiguous_start(
        self,
    ) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        clock = PollClock()
        adapter.monotonic = clock.monotonic
        adapter.sleep = clock.sleep
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.failed_router_instance = "i-00000001"
        adapter.router_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        actor = {
            "actor_type": "router",
            "actor_id": "west-a",
            "instance_id": "i-00000001",
            "region": "us-west-2",
            "vpc_id": "vpc-10000001",
            "subnet_id": "subnet-00000001",
            "availability_zone": "us-west-2a",
            "private_ip": None,
        }
        states = iter(
            (
                "running",
                "running",
                "running",
                "running",
                "stopping",
                "stopped",
                "pending",
                "running",
                "running",
                "running",
                "running",
            )
        )
        observed_states: list[str] = []

        def describe(
            _instance_id: str,
            _region: str,
            *,
            timeout_seconds: float | None = None,
        ) -> tuple[dict[str, Any], str]:
            self.assertIsNotNone(timeout_seconds)
            state = next(states)
            observed_states.append(state)
            return actor, state

        adapter._describe_instance_actor = describe  # type: ignore[method-assign]
        adapter.aws = mock.Mock()
        adapter.aws.json.side_effect = RuntimeError(
            "start response lost after commit"
        )
        adapter._restore_instance_fault(
            actor["instance_id"], actor["region"], "router"
        )

        self.assertEqual(
            observed_states,
            [
                "running",
                "running",
                "running",
                "running",
                "stopping",
                "stopped",
                "pending",
                "running",
                "running",
                "running",
                "running",
            ],
        )
        adapter.aws.json.assert_called_once_with(
            ["ec2", "start-instances", "--instance-ids", actor["instance_id"]],
            region=actor["region"],
            timeout_seconds=mock.ANY,
        )
        self.assertEqual(adapter.ledger.allowed_fault_calls, ["ec2:StartInstances"])
        self.assertEqual(len(adapter.ledger.actor_validations), 1)
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_RUNNING_PROVED
        )

    def test_fault_restoration_starts_a_confirmed_stopped_instance(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        clock = PollClock()
        adapter.monotonic = clock.monotonic
        adapter.sleep = clock.sleep
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.failed_controller_instance = "i-50000001"
        adapter.controller_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        actor = {
            "actor_type": "controller",
            "actor_id": "controller-a",
            "instance_id": "i-50000001",
            "region": "us-west-2",
            "vpc_id": "vpc-30000001",
            "subnet_id": "subnet-30000001",
            "availability_zone": "us-west-2a",
            "private_ip": "10.30.0.11",
        }
        states = iter(("stopped", "pending", "running", "running", "running", "running"))
        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            side_effect=lambda *_args, **_kwargs: (actor, next(states))
        )
        adapter.aws = mock.Mock()

        adapter._restore_instance_fault(
            actor["instance_id"], actor["region"], "controller"
        )

        adapter.aws.json.assert_called_once_with(
            ["ec2", "start-instances", "--instance-ids", actor["instance_id"]],
            region=actor["region"],
            timeout_seconds=mock.ANY,
        )
        self.assertEqual(adapter.ledger.allowed_fault_calls, ["ec2:StartInstances"])
        self.assertEqual(
            adapter.controller_restoration_phase, e2e.EC2_FAULT_RUNNING_PROVED
        )

    def test_cleanup_reenters_after_interruption_at_start_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        clock = PollClock()
        adapter.config = config
        adapter.deployment = deployment
        adapter.monotonic = clock.monotonic
        adapter.sleep = clock.sleep
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.failed_router_id = "west-a"
        adapter.failed_router_instance = "i-00000001"
        adapter.router_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        adapter.failed_controller_instance = None
        adapter.controller_restoration_phase = None
        adapter.established_commands = {}
        adapter.protected_secrets = ()
        actor = {
            "actor_type": "router",
            "actor_id": "west-a",
            "instance_id": "i-00000001",
            "region": "us-west-2",
            "vpc_id": "vpc-10000001",
            "subnet_id": "subnet-00000001",
            "availability_zone": "us-west-2a",
            "private_ip": None,
        }
        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            return_value=(actor, "stopped")
        )
        adapter.aws = mock.Mock()
        adapter.aws.json.side_effect = e2e.TerminationRequested(
            "interrupted after start commit"
        )

        with self.assertRaisesRegex(e2e.TerminationRequested, "start commit"):
            adapter.restore_router({"router_id": "west-a"})
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_START_CALL_ARMED
        )
        adapter.aws.json.assert_called_once()

        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            return_value=(actor, "running")
        )
        adapter.aws.json.reset_mock()
        adapter.aws.json.side_effect = None
        self.assertEqual(adapter.restore_faults_for_cleanup(), {"complete": True})
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_RUNNING_PROVED
        )
        adapter.aws.json.assert_not_called()

    def test_cleanup_reenters_after_ambiguous_start_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        clock = PollClock()
        adapter.config = config
        adapter.deployment = deployment
        adapter.monotonic = clock.monotonic
        adapter.sleep = clock.sleep
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.failed_router_id = "west-a"
        adapter.failed_router_instance = "i-00000001"
        adapter.router_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        adapter.failed_controller_instance = None
        adapter.controller_restoration_phase = None
        adapter.established_commands = {}
        adapter.protected_secrets = ()
        actor = {
            "actor_type": "router",
            "actor_id": "west-a",
            "instance_id": "i-00000001",
            "region": "us-west-2",
            "vpc_id": "vpc-10000001",
            "subnet_id": "subnet-00000001",
            "availability_zone": "us-west-2a",
            "private_ip": None,
        }
        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            side_effect=(
                (actor, "stopped"),
                e2e.ContractError("normal restoration observation failed"),
            )
        )
        adapter.aws = mock.Mock()
        adapter.aws.json.side_effect = RuntimeError("start response lost after commit")

        with self.assertRaisesRegex(e2e.ContractError, "observation failed"):
            adapter.restore_router({"router_id": "west-a"})
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_START_CALL_ARMED
        )
        adapter.aws.json.assert_called_once()

        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            return_value=(actor, "running")
        )
        adapter.aws.json.reset_mock()
        adapter.aws.json.side_effect = None
        self.assertEqual(adapter.restore_faults_for_cleanup(), {"complete": True})
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_RUNNING_PROVED
        )
        adapter.aws.json.assert_not_called()

    def test_fault_restoration_fails_closed_when_stop_is_never_observed(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        clock = PollClock()
        adapter.monotonic = clock.monotonic
        adapter.sleep = clock.sleep
        adapter.ledger = e2e.MutationLedger(session_deny=True)
        adapter.failed_router_instance = "i-00000001"
        adapter.router_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        actor = {
            "actor_type": "router",
            "actor_id": "west-a",
            "instance_id": "i-00000001",
            "region": "us-west-2",
            "vpc_id": "vpc-10000001",
            "subnet_id": "subnet-00000001",
            "availability_zone": "us-west-2a",
            "private_ip": None,
        }
        adapter._describe_instance_actor = mock.Mock(  # type: ignore[method-assign]
            return_value=(actor, "running")
        )
        adapter.aws = mock.Mock()

        with self.assertRaisesRegex(e2e.ContractError, "bounded window"):
            adapter._restore_instance_fault(
                actor["instance_id"], actor["region"], "router"
            )

        adapter.aws.json.assert_not_called()
        self.assertEqual(clock.value, e2e.EC2_FAULT_RESTORE_TIMEOUT_SECONDS)

    def test_cleanup_keeps_fault_intent_armed_until_running_is_proved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.failed_router_id = "west-a"
        adapter.failed_router_instance = "i-00000001"
        adapter.router_restoration_phase = e2e.EC2_FAULT_STOP_CALL_ARMED
        adapter.failed_controller_instance = None
        adapter.controller_restoration_phase = None
        adapter.established_commands = {}
        adapter.protected_secrets = ()
        adapter._restore_instance_fault = mock.Mock(  # type: ignore[method-assign]
            side_effect=e2e.ContractError("running state remained unproved")
        )
        with self.assertRaisesRegex(e2e.ContractError, "running state remained unproved"):
            adapter.restore_faults_for_cleanup()
        self.assertEqual(
            adapter.router_restoration_phase, e2e.EC2_FAULT_STOP_CALL_ARMED
        )

    def test_route_readback_requires_repeated_exact_association_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        domain = deployment.seed.domains_by_id["west-a"]
        table = {
            "RouteTableId": domain["route_table_id"],
            "VpcId": deployment.seed.sites["west"]["vpc_id"],
            "Associations": [
                {
                    "Main": False,
                    "RouteTableAssociationId": domain["route_table_association_id"],
                    "RouteTableId": domain["route_table_id"],
                    "SubnetId": domain["gwlbe_subnet_id"],
                    "AssociationState": {"State": "associated"},
                }
            ],
            "Routes": [
                {
                    "DestinationCidrBlock": prefix,
                    "NetworkInterfaceId": "eni-00000001",
                    "State": "active",
                    "Origin": "CreateRoute",
                }
                for prefix in domain["remote_prefixes"]
            ],
        }

        class StaticAws:
            def __init__(self, route_table: Mapping[str, Any]):
                self.route_table = route_table
                self.calls = 0

            def json(self, _args: list[str], **_kwargs: Any) -> dict[str, Any]:
                self.calls += 1
                return {"RouteTables": [copy.deepcopy(self.route_table)]}

        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.sleep = lambda _seconds: None
        adapter.aws = StaticAws(table)
        route_table, routes = adapter._observe_route_table(
            domain, {"eni-00000001": "west-a"}
        )
        self.assertEqual(route_table["stable_read_count"], 2)
        self.assertEqual(adapter.aws.calls, 2)
        self.assertEqual(len(routes), 2)

        bad = copy.deepcopy(table)
        bad["Associations"][0]["Main"] = True
        adapter.aws = StaticAws(bad)
        with self.assertRaisesRegex(e2e.ContractError, "main association"):
            adapter._observe_route_table(domain, {"eni-00000001": "west-a"})

    def test_cleanup_router_identities_survive_output_parse_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            missing = pathlib.Path(temporary) / "missing.tfvars.json"
            adapter = object.__new__(e2e.AwsProductionAdapter)
            adapter.config = config
            adapter.appliance_deployment_started = True
            adapter.appliance_workspace = mock.Mock(variables_path=missing)
            adapter.controller_workspace = mock.Mock(variables_path=missing)
            names = adapter._expected_tailnet_device_names()
        self.assertEqual(
            names,
            {
                f"{RUN_ID}-west-transport-a",
                f"{RUN_ID}-west-transport-b",
                f"{RUN_ID}-east-transport-a",
                f"{RUN_ID}-east-transport-b",
            },
        )

    def test_established_commands_are_tracked_immediately_with_exact_region(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.established_commands = {}
        command_id = "11111111-2222-4333-8444-555555555555"
        calls: list[tuple[str, str, str]] = []

        def send(instance_id: str, region: str, command: str, **_kwargs: Any) -> str:
            calls.append((instance_id, region, command))
            if len(calls) == 1:
                return command_id
            raise e2e.ContractError("second dispatch failed")

        adapter._send_workload_command = send  # type: ignore[method-assign]
        with self.assertRaisesRegex(e2e.ContractError, "second dispatch"):
            adapter.start_established_flows(
                {
                    "domain_id": "west-a",
                    "router_id": "west-a",
                    "alternate_router_id": "west-b",
                }
            )
        self.assertEqual(
            adapter.established_commands,
            {command_id: ("i-00000015", "us-west-2")},
        )
        self.assertIn("--structured-result", calls[0][2])
        self.assertIn("--ack-barrier-path", calls[0][2])

    def test_cleanup_cancels_and_polls_every_command_in_its_exact_region(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.router_restoration_phase = None
        adapter.controller_restoration_phase = None
        adapter.failed_router_id = None
        adapter.failed_controller_instance = None
        adapter.deployment = None
        first = "11111111-2222-4333-8444-555555555555"
        second = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        adapter.established_commands = {
            first: ("i-00000015", "us-west-2"),
            second: ("i-0000001f", "us-east-1"),
        }
        cancellations: list[tuple[list[str], str]] = []

        class StaticAws:
            def json(self, args: list[str], *, region: str) -> dict[str, Any]:
                cancellations.append((args, region))
                return {}

        waits: list[tuple[str, str, str]] = []
        adapter.aws = StaticAws()
        adapter._wait_command = lambda command_id, instance_id, region, **_kwargs: (  # type: ignore[method-assign]
            waits.append((command_id, instance_id, region))
            or {"Status": "Cancelled"}
        )
        self.assertEqual(adapter.restore_faults_for_cleanup(), {"complete": True})
        self.assertEqual(
            [(args[args.index("--command-id") + 1], region) for args, region in cancellations],
            [(first, "us-west-2"), (second, "us-east-1")],
        )
        self.assertEqual(
            waits,
            [
                (first, "i-00000015", "us-west-2"),
                (second, "i-0000001f", "us-east-1"),
            ],
        )
        self.assertEqual(adapter.established_commands, {})

        adapter.established_commands = {
            first: ("i-00000015", "us-west-2")
        }
        adapter.aws = mock.Mock()
        adapter.aws.json.side_effect = e2e.HardTimeout("hard deadline")
        with self.assertRaises(e2e.HardTimeout):
            adapter.restore_faults_for_cleanup()

    def test_active_output_failure_still_forces_read_only_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        route_arn = f"arn:aws:ec2:us-west-2:{ACCOUNT_ID}:route-table/rtb-00000001"
        adapter.controller_variables = {
            "deployment_mode": "read-only",
            "managed_route_tables": {"west-a": {"route_table_arn": route_arn}},
        }
        adapter.controller_mode = "read-only"
        adapter.controller_output = None
        adapter.active_deployment_attempted = False
        adapter.deployment = None
        sleeps: list[float] = []
        adapter.sleep = sleeps.append

        class FailingOutputWorkspace:
            def __init__(self) -> None:
                self.calls: list[str] = []
                self.cleanup_calls: list[bool] = []
                self.has_applied = False

            def apply(
                self,
                _variables: Mapping[str, Any],
                label: str,
                *,
                cleanup: bool = False,
            ) -> dict[str, Any]:
                self.calls.append(label)
                self.cleanup_calls.append(cleanup)
                self.has_applied = True
                if label == "active":
                    self.assert_attempt_recorded()
                    raise RuntimeError("terraform output failed")
                return {
                    "dynamic_route_ownership": {
                        "value": {
                            "deployment_mode": "read-only",
                            "terraform_manages_target": False,
                        }
                    },
                    "controller_iam": {
                        "value": {
                            "deployment_mode": "read-only",
                            "exact_route_table_arns": [],
                        }
                    },
                    "protected_acceptance_lifecycle": {
                        "value": {
                            "enabled": True,
                            "dynamodb_deletion_protection": False,
                            "observer_final_snapshots": False,
                            "customer_managed_storage_key": False,
                        }
                    },
                    "controller_instances": {
                        "value": {
                            controller_id: {
                                "instance_id": f"i-{0x50000000 + index:08x}",
                                "private_ip": f"10.30.0.{10 + index}",
                                "subnet_id": f"subnet-3000000{index}",
                                "availability_zone": f"us-west-2{chr(96 + index)}",
                                "observer_volume_id": f"vol-{index:08x}",
                            }
                            for index, controller_id in enumerate(
                                config.controller.controller_ids, start=1
                            )
                        }
                    },
                }

            def assert_attempt_recorded(self) -> None:
                if not adapter.active_deployment_attempted:
                    raise AssertionError("active attempt was recorded after Terraform")

        workspace = FailingOutputWorkspace()
        adapter.controller_workspace = workspace
        with self.assertRaisesRegex(RuntimeError, "output failed"):
            adapter.deploy_controller("active")
        self.assertTrue(adapter.active_deployment_attempted)
        self.assertTrue(workspace.has_applied)
        self.assertEqual(adapter.controller_mode, "read-only")

        self.assertEqual(adapter.quiesce_controller(True, False), {"complete": True})
        self.assertEqual(workspace.calls, ["active", "read-only"])
        self.assertEqual(workspace.cleanup_calls, [False, True])
        self.assertEqual(adapter.controller_mode, "read-only")
        self.assertEqual(
            sleeps, [config.controller.policy_seconds["lease_duration"]]
        )

    def test_established_flow_failure_is_not_inferred_from_ssm_status(self) -> None:
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter._send_established_command = lambda *_args, **_kwargs: "sample-command"  # type: ignore[method-assign]
        reset = compact_stream_result(
            "tcp",
            attempted=6,
            acknowledged=5,
            outcome="reset",
            error_category="connection-reset",
            last_sent=150,
            last_received=160,
        )
        survived = compact_stream_result("udp")
        responses = iter(
            (
                {
                    "Status": "Success",
                    "StandardOutputContent": '{"monotonic_ns":200}',
                },
                {
                    "Status": "Failed",
                    "StandardOutputContent": json.dumps(reset, separators=(",", ":")),
                },
                {
                    "Status": "Success",
                    "StandardOutputContent": json.dumps(
                        survived, separators=(",", ":")
                    ),
                },
            )
        )
        adapter._wait_established_command = lambda *_args, **_kwargs: next(responses)  # type: ignore[method-assign]
        handle = {
            "sampled_at": "2020-09-05T12:00:00Z",
            "sampled_monotonic_ns": 100,
            "source_workload": "west-initiator",
            "destination_workload": "east-initiator",
            "source_instance_id": "i-00000001",
            "destination_instance_id": "i-00000002",
            "commands": {
                protocol: {
                    "command_id": f"command-{protocol}",
                    "instance_id": "i-00000001",
                    "region": "us-west-2",
                    "flow_id": f"flow-{protocol}",
                    "source_ip": "10.10.1.10",
                    "source_port": str(60000 + index),
                    "expected_markers": "100",
                    "timeout_seconds": "30",
                    "barrier_path": f"/run/envelope-e2e/flow-{protocol}.ack.json",
                }
                for index, protocol in enumerate(("tcp", "udp"))
            },
        }
        classified = adapter.finish_established_flows(
            handle,
            {
                "fault_injected_at": "2020-09-05T12:00:01Z",
                "convergence_at": "2020-09-05T12:00:02Z",
            },
        )
        self.assertEqual([flow["outcome"] for flow in classified], ["reset", "survived"])
        self.assertEqual(classified[0]["error_category"], "connection-reset")
        self.assertEqual(classified[0]["acknowledged_markers"], 5)

        malformed_responses = iter(
            (
                {
                    "Status": "Success",
                    "StandardOutputContent": '{"monotonic_ns":200}',
                },
                {"Status": "Failed", "StandardOutputContent": ""},
            )
        )
        adapter._wait_established_command = lambda *_args, **_kwargs: next(malformed_responses)  # type: ignore[method-assign]
        with self.assertRaisesRegex(e2e.ContractError, "refusing inferred classification"):
            adapter.finish_established_flows(
                handle,
                {
                    "fault_injected_at": "2020-09-05T12:00:01Z",
                    "convergence_at": "2020-09-05T12:00:02Z",
                },
            )

    def test_quorum_excludes_stale_expired_and_identity_mismatched_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = e2e.parse_appliance_output(appliance_output(), config)
        adapter = object.__new__(e2e.AwsProductionAdapter)
        adapter.config = config
        adapter.deployment = deployment
        adapter.topology_identity = {"canonical_sha256": "a" * 64}
        adapter.router_nodes = {
            "west-a": {"stable_node_id": "node-1"},
            "west-b": {"stable_node_id": "node-2"},
            "east-a": {"stable_node_id": "node-3"},
            "east-b": {"stable_node_id": "node-4"},
        }
        now = dt.datetime(2026, 9, 5, 12, 0, tzinfo=dt.timezone.utc)
        adapter.wall_clock = lambda: now

        def payload(controller_id: str) -> dict[str, Any]:
            return {
                "controller_id": controller_id,
                "topology_hash": "a" * 64,
                "sequence": 1,
                "captured_at": "2026-09-05T11:59:58.123456789Z",
                "expires_at": "2026-09-05T12:00:03.123456789Z",
                "backend_healthy": True,
                "domains": {
                    "west-a": {
                        "stable_node_id": "node-1",
                        "sole_primary": True,
                        "online": True,
                        "expired": False,
                        "healthy": True,
                        "advertised_prefixes": ["10.10.1.0/24", "10.10.2.0/24"],
                        "enabled_prefixes": ["10.10.1.0/24", "10.10.2.0/24"],
                    }
                },
            }

        records = {
            controller_id: payload(controller_id)
            for controller_id in config.controller.controller_ids
        }
        adapter._dynamo_item = lambda _partition, sort_key: records[  # type: ignore[method-assign]
            sort_key.removeprefix("controller#")
        ]
        consensus = adapter._tailnet_consensus("west-a")
        self.assertEqual(consensus["owner_router_id"], "west-a")
        self.assertEqual(
            consensus["owner_node_sha256"], hashlib.sha256(b"node-1").hexdigest()
        )
        self.assertEqual(consensus["observer_quorum"], 3)
        self.assertTrue(consensus["agreement"])
        self.assertEqual(
            [item["controller_id"] for item in consensus["contributors"]],
            ["controller-a", "controller-b", "controller-c"],
        )

        records["controller-c"]["domains"]["west-a"]["stable_node_id"] = "node-2"
        disagreement = adapter._tailnet_consensus("west-a")
        self.assertFalse(disagreement["agreement"])
        self.assertEqual(disagreement["observer_quorum"], 0)
        self.assertEqual(len(disagreement["contributors"]), 3)
        records["controller-c"] = payload("controller-c")

        records["controller-a"]["captured_at"] = "2026-09-05T11:00:00Z"
        records["controller-b"]["expires_at"] = "2026-09-05T11:59:59Z"
        records["controller-c"]["controller_id"] = "controller-a"
        absent = adapter._tailnet_consensus("west-a")
        self.assertFalse(absent["agreement"])
        self.assertEqual(absent["observer_quorum"], 0)
        self.assertEqual(absent["contributors"], [])


class EstablishedAgentCompatibilityTest(unittest.TestCase):
    @staticmethod
    def _unused_tcp_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def test_real_agent_compact_results_fit_ssm_and_parse_at_600_and_1000(self) -> None:
        for count in (600, e2e.ESTABLISHED_MAX_MARKERS):
            with self.subTest(count=count):
                ready: queue.Queue[int] = queue.Queue(maxsize=1)
                completed: queue.Queue[object] = queue.Queue(maxsize=1)

                def serve() -> None:
                    try:
                        completed.put(
                            AGENT.serve(
                                "tcp",
                                "127.0.0.1",
                                0,
                                timeout=10,
                                max_messages=count,
                                ready=ready.put_nowait,
                            )
                        )
                    except BaseException as error:
                        completed.put(error)

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                port = ready.get(timeout=2)
                source_port = self._unused_tcp_port()
                result = AGENT.stream(
                    "tcp",
                    "127.0.0.1",
                    port,
                    source_ip="127.0.0.1",
                    source_port=source_port,
                    flow_id="flow-tcp",
                    count=count,
                    interval=0,
                    timeout=8,
                    structured_result=True,
                )
                server_result = completed.get(timeout=10)
                thread.join(timeout=2)
                if isinstance(server_result, BaseException):
                    raise server_result
                self.assertFalse(thread.is_alive())
                serialized = json.dumps(
                    result, sort_keys=True, separators=(",", ":")
                ).encode("ascii")
                self.assertLess(len(serialized), e2e.SSM_STDOUT_MAX_BYTES)
                self.assertNotIn("markers", result)
                timing = result["timing"]
                parsed = e2e.parse_established_agent_output(
                    result,
                    protocol="tcp",
                    flow_id="flow-tcp",
                    source_ip="127.0.0.1",
                    source_port=source_port,
                    expected_markers=count,
                    sampled_monotonic_ns=timing["first_acknowledged"][2],
                    convergence_monotonic_ns=timing["last_acknowledged"][1],
                )
                self.assertEqual(parsed["outcome"], "survived")
                self.assertEqual(parsed["attempted_markers"], count)
                self.assertEqual(parsed["acknowledged_markers"], count)
                self.assertEqual(server_result["connections"], 1)
                self.assertEqual(server_result["messages"], count)

    def test_agent_emits_typed_partial_reset_and_timeout_but_legacy_raises(self) -> None:
        class InterruptedSocket:
            def __init__(self, mode: str):
                self.mode = mode
                self.response = b""
                self.sequence = -1

            def __enter__(self) -> "InterruptedSocket":
                return self

            def __exit__(self, *_args: Any) -> None:
                self.close()

            def bind(self, _address: Any) -> None:
                pass

            def connect(self, _address: Any) -> None:
                pass

            def close(self) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def getsockname(self) -> tuple[str, int]:
                return "127.0.0.1", 60000

            def sendall(self, data: bytes) -> None:
                request = json.loads(data.decode("ascii"))
                self.sequence = int(request["sequence"])
                if self.sequence == 1 and self.mode == "reset":
                    raise ConnectionResetError("fixture reset")
                self.response = AGENT._encode_frame(
                    AGENT._marker(
                        request["flow_id"],
                        request["connection_id"],
                        self.sequence,
                        "ack",
                    ),
                    newline=True,
                )

            def recv(self, _size: int) -> bytes:
                if self.sequence == 1 and self.mode == "timeout":
                    raise socket.timeout("fixture timeout")
                response, self.response = self.response, b""
                return response

        for mode, outcome, category in (
            ("reset", "reset", "connection-reset"),
            ("timeout", "timed-out", "socket-timeout"),
        ):
            with self.subTest(mode=mode), mock.patch.object(
                AGENT,
                "_client_socket",
                return_value=InterruptedSocket(mode),
            ):
                result = AGENT.stream(
                    "tcp",
                    "127.0.0.1",
                    5201,
                    source_ip="127.0.0.1",
                    source_port=60000,
                    flow_id="flow-tcp",
                    count=3,
                    interval=0,
                    timeout=2,
                    structured_result=True,
                )
            self.assertEqual(result["outcome"], outcome)
            self.assertEqual(result["error_category"], category)
            self.assertEqual(result["sequences"]["attempted"]["count"], 2)
            self.assertEqual(result["sequences"]["acknowledged"]["count"], 1)
            timing = result["timing"]
            parsed = e2e.parse_established_agent_output(
                result,
                protocol="tcp",
                flow_id="flow-tcp",
                source_ip="127.0.0.1",
                source_port=60000,
                expected_markers=3,
                sampled_monotonic_ns=timing["first_acknowledged"][2],
                convergence_monotonic_ns=timing["last_attempted"][1] + 1,
            )
            self.assertEqual(parsed["outcome"], outcome)

        with mock.patch.object(
            AGENT,
            "_client_socket",
            return_value=InterruptedSocket("reset"),
        ), self.assertRaises(AGENT.AgentError):
            AGENT.stream(
                "tcp",
                "127.0.0.1",
                5201,
                source_ip="127.0.0.1",
                source_port=60000,
                flow_id="flow-tcp",
                count=3,
                interval=0,
                timeout=2,
            )


class StaticWiringTest(unittest.TestCase):
    def test_controller_root_declares_its_own_s3_backend(self) -> None:
        versions = (
            ROOT / "deploy" / "terraform" / "envelope-controller" / "versions.tf"
        ).read_text(encoding="utf-8")
        self.assertIn('backend "s3" {}', versions)

    def test_runner_remains_independent_of_legacy_v2_orchestrator(self) -> None:
        source = (ROOT / "scripts" / "aws_production_controller_e2e.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import aws_two_region_e2e", source)
        self.assertNotIn("from aws_two_region_e2e", source)

    def test_protected_workflow_separates_credentials_and_retains_evidence(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "aws-two-region-e2e-live.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("scripts/aws_production_controller_e2e.py run-all", workflow)
        self.assertNotIn("scripts/aws_two_region_e2e.py run-all", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        for phase, environment in (("deploy", "deployment"), ("observe", "observation"), ("quiesce", "quiescence"), ("cleanup", "cleanup")):
            self.assertIn(f"scripts/aws_controller_acceptance.py {phase}", workflow)
            self.assertIn(f"environment: envelope-controller-{environment}", workflow)
        observer = workflow.split("\n  observe:\n", 1)[1].split("\n  quiesce:\n", 1)[0]
        self.assertIn("group: envelope-production-observation", observer)
        self.assertNotIn("group: envelope-production-deployment", observer)
        self.assertNotIn("secrets.", observer)
        self.assertNotIn("setup-terraform", observer)
        self.assertIn('mkdir ".run/$RUN_ID" || exit 1', observer)
        self.assertIn("--handoff-reference", observer)
        self.assertIn("needs: [deploy, observe]", workflow)
        self.assertIn("needs: [deploy, observe, quiesce]", workflow)
        self.assertIn("if: always() && needs.deploy.result == 'success'", workflow)
        self.assertIn("if: always() && needs.quiesce.result == 'success'", workflow)
        self.assertIn("--quiescence-reference", workflow)
        self.assertIn("scripts/aws_controller_acceptance.py record-integration", workflow)
        self.assertIn("go test -count=1 -json ./internal/controller/integration", workflow)
        self.assertIn("clean: false", workflow)
        self.assertNotIn("git clean -", workflow)
        self.assertNotIn("rm -rf", workflow)
        self.assertIn("if: always() && steps.scan.outputs.safe == 'true'", workflow)
        self.assertIn("scripts/secret_scan.py --root . --extra", workflow)
        self.assertIn("path: .run/${{ inputs.run_id }}/cleanup/bundle.json", workflow)


if __name__ == "__main__":
    unittest.main()
