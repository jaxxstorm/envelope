#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_appliance as appliance  # noqa: E402
import transport_router_readiness as transport_readiness  # noqa: E402


VALID_POLICY = {
    "tagOwners": {"tag:envelope-ci": ["group:infra"]},
    "autoApprovers": {
        "routes": {
            "10.10.1.0/24": ["tag:envelope-ci"],
            "10.10.2.0/24": ["tag:envelope-ci"],
            "10.20.1.0/24": ["tag:envelope-ci"],
            "10.20.2.0/24": ["tag:envelope-ci"],
        }
    },
    "grants": [
        {
            "src": ["10.10.1.0/24", "10.10.2.0/24"],
            "dst": ["10.20.1.0/24", "10.20.2.0/24"],
            "ip": ["*"],
        },
        {
            "src": ["10.20.1.0/24", "10.20.2.0/24"],
            "dst": ["10.10.1.0/24", "10.10.2.0/24"],
            "ip": ["*"],
        },
    ],
}


def e2e_load_profile_document() -> dict:
    return {
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
    }


def config_document(architecture: str = "amd64", *, expired: bool = False) -> dict:
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=-1 if expired else 2)

    def site(region, ami, key, vpc, prefix):
        return {
            "region": region,
            "ami_id": ami,
            "ssm_kms_key_arn": key,
            "azs": {"a": f"{region}a", "b": f"{region}b"},
            "vpc_cidr": vpc,
            "local_site_cidrs": [f"{prefix}.1.0/24", f"{prefix}.2.0/24"],
            "remote_site_cidrs": [],
            "workload_subnet_cidrs": {"a": f"{prefix}.1.0/24", "b": f"{prefix}.2.0/24"},
            "transport_subnet_cidrs": {"a": f"{prefix}.3.0/24", "b": f"{prefix}.4.0/24"},
            "gwlbe_subnet_cidrs": {"a": f"{prefix}.10.0/24", "b": f"{prefix}.11.0/24"},
            "gwlb_subnet_cidrs": {"a": f"{prefix}.20.0/24", "b": f"{prefix}.21.0/24"},
            "target_subnet_cidrs": {"a": f"{prefix}.30.0/24", "b": f"{prefix}.31.0/24"},
            "management_subnet_cidr": f"{prefix}.40.0/24",
            "target_az_keys": ["a", "b"],
            "transport_router_az_keys": ["a", "b"],
        }

    west = site(
        "us-west-2",
        "ami-0123456789abcdef0",
        "arn:aws:kms:us-west-2:123456789012:key/west",
        "10.10.0.0/16",
        "10.10",
    )
    east = site(
        "us-east-1",
        "ami-0fedcba9876543210",
        "arn:aws:kms:us-east-1:123456789012:key/east",
        "10.20.0.0/16",
        "10.20",
    )
    west["remote_site_cidrs"] = list(east["local_site_cidrs"])
    east["remote_site_cidrs"] = list(west["local_site_cidrs"])

    return {
        "run_id": "envelope-fixture",
        "expires_at": expiry.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "architecture": architecture,
        "artifact_manifest": "../../dist/manifest.json",
        "instance_type": "m7g.medium" if architecture == "arm64" else "t3.medium",
        "test_instance_type": "t4g.micro" if architecture == "arm64" else "t3.micro",
        "e2e_load_profile": e2e_load_profile_document(),
        "envelope": {
            "mode": "packet-return",
            "udp_bind": "0.0.0.0:6081",
            "max_inner_packet_size": 1280,
        },
        "backend": {
            "bucket": "operator-backend",
            "region": "us-west-2",
            "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/backend",
            "state_key": "runs/envelope-fixture/terraform.tfstate",
            "operator_principal_arns": ["arn:aws:iam::123456789012:role/envelope-operator"],
        },
        "symmetric_topology": {
            "version": 2,
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
    }


def make_config(tmp: pathlib.Path, architecture: str = "amd64", *, expired: bool = False) -> appliance.RunConfig:
    path = tmp / "config" / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config_document(architecture, expired=expired)))
    return appliance.RunConfig.load(path, enforce_future_expiry=not expired)


def fixture_tailnet_hostnames(run_id: str = "envelope-fixture") -> list[str]:
    return [
        f"{run_id}-{site}-transport-{az_key}"
        for site in ("west", "east")
        for az_key in ("a", "b")
    ]


def fixture_tailnet_roles(run_id: str = "envelope-fixture") -> dict[str, str]:
    return {hostname: "transport-router" for hostname in fixture_tailnet_hostnames(run_id)}


def fixture_tailnet_devices(run_id: str = "envelope-fixture") -> list[dict[str, object]]:
    devices = []
    for index, hostname in enumerate(fixture_tailnet_hostnames(run_id), start=1):
        site = "west" if f"{run_id}-west-" in hostname else "east"
        prefix = "10.10" if site == "west" else "10.20"
        az_index = 1 if hostname.endswith("-a") else 2
        routes = [f"{prefix}.{az_index}.0/24"]
        devices.append(
            {
                "id": f"device-{index}",
                "nodeId": f"node-{index}",
                "hostname": hostname,
                "tags": ["tag:envelope-ci"],
                "advertisedRoutes": routes,
                "enabledRoutes": routes,
            }
        )
    return devices


def fixture_target_groups() -> dict[str, str]:
    return {
        "west": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/fixture",
        "east": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/east/fixture",
    }


def fixture_symmetric_topology(config: appliance.RunConfig) -> dict:
    target_groups = fixture_target_groups()
    return {
        "config_version": 2,
        "run_id": config.run_id,
        "route_failover": copy.deepcopy(config.route_failover),
        "sites": {
            site: {
                "region": config.sites[site]["region"],
                "local_site_cidrs": sorted(config.sites[site]["local_site_cidrs"]),
                "remote_site_cidrs": sorted(config.sites[site]["remote_site_cidrs"]),
                "target_fleet": [
                    {
                        "region": config.sites[site]["region"],
                        "az_key": az_key,
                        "instance_id": f"i-target-{site}-{az_key}",
                        "target_group_arn": target_groups[site],
                    }
                    for az_key in config.sites[site]["target_az_keys"]
                ],
                "transport_router_fleet": [
                    {
                        "region": config.sites[site]["region"],
                        "az_key": az_key,
                        "instance_id": f"i-transport-{site}-{az_key}",
                        "network_interface_id": f"eni-transport-{site}-{az_key}",
                        "gwlbe_route_table_id": f"rtb-gwlbe-{site}-{az_key}",
                        "advertised_prefix": config.sites[site][
                            "workload_subnet_cidrs"
                        ][az_key],
                    }
                    for az_key in config.sites[site]["transport_router_az_keys"]
                ],
            }
            for site in ("west", "east")
        },
    }


def fixture_transport_router_readiness_expectations(
    config: appliance.RunConfig,
) -> dict:
    sites = {}
    for site in ("west", "east"):
        contract = transport_readiness.build_readiness_contract(
            config.sites[site]["local_site_cidrs"],
            config.sites[site]["remote_site_cidrs"],
            "ens5",
            "tailscale0",
            config.raw["e2e_load_profile"]["maximum_tcp_mss"],
        )
        contract_sha256 = hashlib.sha256(
            json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        sites[site] = {**contract, "contract_sha256": contract_sha256}
    return {"config_version": 2, "sites": sites}


def fixture_route_failover_output(config: appliance.RunConfig, topology: dict) -> dict:
    transport_fleets = {
        site: {
            member["az_key"]: member
            for member in topology["sites"][site]["transport_router_fleet"]
        }
        for site in ("west", "east")
    }
    selections = config.route_failover[
        "initial_transport_router_az_by_gwlbe_az"
    ]
    return {
        "config_version": 2,
        "mutation_timeout_seconds": config.route_failover[
            "mutation_timeout_seconds"
        ],
        "restoration_timeout_seconds": config.route_failover[
            "restoration_timeout_seconds"
        ],
        "recovery_timeout_seconds": config.route_failover[
            "recovery_timeout_seconds"
        ],
        "same_az_preferred": {
            site: all(gwlbe_az == selected for gwlbe_az, selected in selections[site].items())
            for site in ("west", "east")
        },
        "sites": {
            site: {
                gwlbe_az: {
                    "route_table_id": transport_fleets[site][gwlbe_az][
                        "gwlbe_route_table_id"
                    ],
                    "source_workload_prefix": config.sites[site][
                        "workload_subnet_cidrs"
                    ][gwlbe_az],
                    "remote_site_cidrs": sorted(
                        config.sites[site]["remote_site_cidrs"]
                    ),
                    "initial_transport_router_az_key": transport_az,
                    "initial_network_interface_id": transport_fleets[site][transport_az][
                        "network_interface_id"
                    ],
                }
                for gwlbe_az, transport_az in selections[site].items()
            }
            for site in ("west", "east")
        },
    }


def fixture_workload_instances(config: appliance.RunConfig) -> dict:
    result = {}
    for site in ("west", "east"):
        az_keys = sorted(config.sites[site]["azs"])
        result[site] = {}
        for role, az_key in zip(("initiator", "responder"), az_keys, strict=True):
            cidr = config.sites[site]["workload_subnet_cidrs"][az_key]
            result[site][role] = {
                "instance_id": f"i-workload-{site}-{role}",
                "private_ip": cidr.removesuffix("0/24") + "10",
                "az_key": az_key,
                "availability_zone": config.sites[site]["azs"][az_key],
                "subnet_id": f"subnet-{site}-{az_key}",
                "cidr": cidr,
                "route_table_id": f"rtb-workload-{site}-{az_key}",
            }
    return result


def symmetric_deployment_document(config: appliance.RunConfig) -> dict:
    topology = fixture_symmetric_topology(config)
    account_id = config.sites["west"]["ssm_kms_key_arn"].split(":", 5)[4]
    return {
        "envelope_runtime_config": {
            "value": {
                site: {
                    "config_version": 2,
                    **config.raw["envelope"],
                    "artifact_sha256": "a" * 64,
                    "artifact_revision": "b" * 40,
                }
                for site in ("west", "east")
            }
        },
        "cost_profile": {
            "value": {
                "profile": "symmetric-gwlb-ha-v2",
                "estimated_fixed_hourly_usd": config.raw["cost"]["estimated_fixed_hourly_usd"],
                "approved_max_hourly_usd": config.raw["cost"]["approved_max_fixed_hourly_usd"],
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
                "route_failover_bounds": {
                    field: config.route_failover[field]
                    for field in (
                        "mutation_timeout_seconds",
                        "restoration_timeout_seconds",
                        "recovery_timeout_seconds",
                    )
                },
                "nat_topology_limit": {
                    "gateways_per_site": 1,
                    "expanded_for_ha": False,
                    "placement": (
                        "one shared NAT gateway in each site's single management subnet"
                    ),
                    "limitation": (
                        "private egress is not multi-AZ within a site and remains outside "
                        "the protected data path"
                    ),
                },
            }
        },
        "artifact_identity": {
            "value": {
                "bucket": (
                    f"{config.run_id}-{account_id}-{config.sites['west']['region']}-artifact"
                ),
                "key": f"artifacts/{'b' * 40}/envelope-linux-{config.architecture}",
                "architecture": config.architecture,
                "ec2_arch": appliance.ARCHITECTURES[config.architecture],
                "sha256": "a" * 64,
                "revision": "b" * 40,
                "version": "fixture.1",
            }
        },
        "e2e_load_profile": {"value": copy.deepcopy(config.raw["e2e_load_profile"])},
        "flow_log_evidence": {
            "value": {
                site: {
                    "flow_log_id": f"fl-{site}-fixture",
                    "log_group_arn": (
                        f"arn:aws:logs:{config.sites[site]['region']}:{account_id}:"
                        f"log-group:/aws/vpc-flow-logs/{config.run_id}/{site}"
                    ),
                    "region": config.sites[site]["region"],
                }
                for site in ("west", "east")
            }
        },
        "gwlb_endpoint_ids": {
            "value": {
                site: {az_key: f"vpce-{site}-{az_key}" for az_key in ("a", "b")}
                for site in ("west", "east")
            }
        },
        "gwlb_target_group_arns": {"value": fixture_target_groups()},
        "route_failover": {
            "value": fixture_route_failover_output(config, topology)
        },
        "symmetric_topology": {"value": topology},
        "transport_router_readiness_expectations": {
            "value": fixture_transport_router_readiness_expectations(config)
        },
        "vpc_ids": {
            "value": {site: f"vpc-{site}-fixture" for site in ("west", "east")}
        },
        "workload_instances": {"value": fixture_workload_instances(config)},
    }


_PLAN_VALUE_MISSING = object()


def split_plan_unknowns(
    value: object, unknown_paths: set[tuple[object, ...]]
) -> tuple[object, object, bool]:
    if () in unknown_paths:
        return _PLAN_VALUE_MISSING, True, True
    if isinstance(value, dict):
        after = {}
        unknown = {}
        has_unknown = False
        for key, child in value.items():
            child_paths = {
                path[1:] for path in unknown_paths if path and path[0] == key
            }
            if not child_paths:
                after[key] = copy.deepcopy(child)
                continue
            child_after, child_unknown, child_has_unknown = split_plan_unknowns(
                child, child_paths
            )
            if child_after is not _PLAN_VALUE_MISSING:
                after[key] = child_after
            if child_has_unknown:
                unknown[key] = child_unknown
                has_unknown = True
        return after, unknown if has_unknown else False, has_unknown
    if isinstance(value, list):
        after = []
        unknown = []
        has_unknown = False
        for index, child in enumerate(value):
            child_paths = {
                path[1:] for path in unknown_paths if path and path[0] == index
            }
            if not child_paths:
                after.append(copy.deepcopy(child))
                unknown.append(False)
                continue
            child_after, child_unknown, child_has_unknown = split_plan_unknowns(
                child, child_paths
            )
            after.append(None if child_after is _PLAN_VALUE_MISSING else child_after)
            unknown.append(child_unknown if child_has_unknown else False)
            has_unknown = has_unknown or child_has_unknown
        return after, unknown if has_unknown else False, has_unknown
    raise AssertionError("fixture unknown path does not identify a value leaf")


def symmetric_output_references() -> dict[str, list[str]]:
    return {
        "artifact_identity": [
            "local.artifact_bucket_name",
            "local.artifact_object_key",
            "var.artifact_sha256",
            "var.architecture",
            "local.ec2_architecture",
            "var.artifact_revision",
            "var.artifact_version",
        ],
        "vpc_ids": [
            "aws_vpc.west.id",
            "aws_vpc.west",
            "aws_vpc.east.id",
            "aws_vpc.east",
        ],
        "gwlb_target_group_arns": [
            "aws_lb_target_group.west.arn",
            "aws_lb_target_group.west",
            "aws_lb_target_group.east.arn",
            "aws_lb_target_group.east",
        ],
        "gwlb_endpoint_ids": [
            "aws_vpc_endpoint.west",
            "aws_vpc_endpoint.east",
        ],
        "workload_instances": [
            "local.workload_roles.west",
            "local.workload_roles",
            "aws_instance.workload_west",
            "aws_instance.workload_west",
            "local.sites.west.azs",
            "local.sites",
            "aws_subnet.workload_west",
            "aws_route_table.workload_west",
            "local.workload_roles.east",
            "local.workload_roles",
            "aws_instance.workload_east",
            "aws_instance.workload_east",
            "local.sites.east.azs",
            "local.sites",
            "aws_subnet.workload_east",
            "aws_route_table.workload_east",
        ],
        "flow_log_evidence": [
            "aws_flow_log.west.id",
            "aws_flow_log.west",
            "aws_cloudwatch_log_group.flow_west.arn",
            "aws_cloudwatch_log_group.flow_west",
            "var.west_region",
            "aws_flow_log.east.id",
            "aws_flow_log.east",
            "aws_cloudwatch_log_group.flow_east.arn",
            "aws_cloudwatch_log_group.flow_east",
            "var.east_region",
        ],
        "e2e_load_profile": ["var.e2e_load_profile"],
        "symmetric_topology": [
            "var.symmetric_topology.version",
            "var.symmetric_topology",
            "var.name",
            "local.route_failover",
            "local.initial_transport_router_advertise_routes",
            "var.west_region",
            "local.sites.west.local_site_cidrs",
            "local.sites",
            "local.sites.west.remote_site_cidrs",
            "aws_instance.envelope_target_west",
            "aws_lb_target_group.west",
            "aws_instance.transport_router_west",
            "aws_route_table.gwlbe_west",
            "var.east_region",
            "local.sites.east.local_site_cidrs",
            "local.sites.east.remote_site_cidrs",
            "aws_instance.envelope_target_east",
            "aws_lb_target_group.east",
            "aws_instance.transport_router_east",
            "aws_route_table.gwlbe_east",
        ],
        "envelope_runtime_config": [
            "local.sites",
            "local.packet_return_runtime",
        ],
        "transport_router_readiness_expectations": [
            "local.transport_router_contracts",
            "local.transport_router_contract_sha256",
        ],
        "route_failover": [
            "local.route_failover",
            "aws_route_table.gwlbe_west",
            "local.sites.west.remote_site_cidrs",
            "local.sites",
            "aws_instance.transport_router_west",
            "aws_route_table.gwlbe_east",
            "local.sites.east.remote_site_cidrs",
            "aws_instance.transport_router_east",
        ],
        "cost_profile": [
            "var.estimated_fixed_hourly_usd",
            "var.approved_max_fixed_hourly_usd",
            "aws_vpc_endpoint.west",
            "aws_vpc_endpoint.east",
            "aws_instance.envelope_target_west",
            "aws_instance.envelope_target_east",
            "aws_instance.transport_router_west",
            "aws_instance.transport_router_east",
            "aws_instance.workload_west",
            "aws_instance.workload_east",
            "aws_nat_gateway.west",
            "aws_nat_gateway.east",
            "aws_eip.nat_west",
            "aws_eip.nat_east",
            "aws_lb.west",
            "aws_lb.east",
            "aws_flow_log.west",
            "aws_flow_log.east",
            "aws_cloudwatch_log_group.flow_west",
            "aws_cloudwatch_log_group.flow_east",
            "aws_iam_role.flow_logs",
            "aws_iam_role.runtime_west",
            "aws_iam_role.runtime_east",
            "aws_iam_role.workload_west",
            "aws_iam_role.workload_east",
            "aws_iam_role.transport_west",
            "aws_iam_role.transport_east",
            "aws_iam_instance_profile.runtime_west",
            "aws_iam_instance_profile.runtime_east",
            "aws_iam_instance_profile.workload_west",
            "aws_iam_instance_profile.workload_east",
            "aws_iam_instance_profile.transport_west",
            "aws_iam_instance_profile.transport_east",
            "local.route_failover",
        ],
    }


def fresh_output_unknown_paths(config: appliance.RunConfig) -> dict[str, set[tuple[object, ...]]]:
    paths: dict[str, set[tuple[object, ...]]] = {
        "vpc_ids": {(site,) for site in ("west", "east")},
        "gwlb_target_group_arns": {(site,) for site in ("west", "east")},
        "gwlb_endpoint_ids": {
            (site, az_key)
            for site in ("west", "east")
            for az_key in config.sites[site]["azs"]
        },
        "workload_instances": {
            (site, role, field)
            for site in ("west", "east")
            for role in ("initiator", "responder")
            for field in ("instance_id", "private_ip", "subnet_id", "route_table_id")
        },
        "flow_log_evidence": {
            (site, field)
            for site in ("west", "east")
            for field in ("flow_log_id", "log_group_arn")
        },
        "symmetric_topology": set(),
        "route_failover": set(),
    }
    for site in ("west", "east"):
        for index, _az_key in enumerate(sorted(config.sites[site]["target_az_keys"])):
            paths["symmetric_topology"].update(
                {
                    ("sites", site, "target_fleet", index, "instance_id"),
                    ("sites", site, "target_fleet", index, "target_group_arn"),
                }
            )
        for index, _az_key in enumerate(
            sorted(config.sites[site]["transport_router_az_keys"])
        ):
            paths["symmetric_topology"].update(
                {
                    ("sites", site, "transport_router_fleet", index, "instance_id"),
                    (
                        "sites",
                        site,
                        "transport_router_fleet",
                        index,
                        "network_interface_id",
                    ),
                    (
                        "sites",
                        site,
                        "transport_router_fleet",
                        index,
                        "gwlbe_route_table_id",
                    ),
                }
            )
        for az_key in config.sites[site]["azs"]:
            paths["route_failover"].update(
                {
                    ("sites", site, az_key, "route_table_id"),
                    ("sites", site, az_key, "initial_network_interface_id"),
                }
            )
    return paths


def symmetric_plan_output_documents(
    config: appliance.RunConfig,
) -> tuple[dict, dict, dict]:
    complete = {
        name: copy.deepcopy(wrapper["value"])
        for name, wrapper in symmetric_deployment_document(config).items()
    }
    unknown_paths = fresh_output_unknown_paths(config)
    planned_outputs = {}
    output_changes = {}
    for name, value in complete.items():
        after, after_unknown, has_unknown = split_plan_unknowns(
            value, unknown_paths.get(name, set())
        )
        planned_outputs[name] = {"sensitive": False}
        if not has_unknown:
            planned_outputs[name]["value"] = copy.deepcopy(after)
        output_changes[name] = {
            "actions": ["create"],
            "before": None,
            "after": after,
            "after_unknown": after_unknown,
            "before_sensitive": False,
            "after_sensitive": False,
        }
    configured_outputs = {
        name: {
            "sensitive": False,
            "expression": {"references": references},
        }
        for name, references in symmetric_output_references().items()
    }
    return planned_outputs, output_changes, configured_outputs


def symmetric_saved_plan_document(config: appliance.RunConfig) -> dict:
    addresses = {
        *(f'aws_vpc_endpoint.{site}["{az_key}"]' for site in ("west", "east") for az_key in ("a", "b")),
        *(f'aws_instance.envelope_target_{site}["{az_key}"]' for site in ("west", "east") for az_key in ("a", "b")),
        *(f'aws_instance.transport_router_{site}["{az_key}"]' for site in ("west", "east") for az_key in ("a", "b")),
        *(f'aws_instance.workload_{site}["{role}"]' for site in ("west", "east") for role in ("initiator", "responder")),
        *(f'aws_lb_target_group_attachment.{site}["{az_key}"]' for site in ("west", "east") for az_key in ("a", "b")),
        *(
            f'aws_{resource}.{domain}_{site}["{az_key}"]'
            for resource in ("subnet", "route_table", "route_table_association")
            for domain in ("workload", "transport", "gwlbe", "target")
            for site in ("west", "east")
            for az_key in ("a", "b")
        ),
        *(
            f'aws_route.target_default_{site}["{az_key}"]'
            for site in ("west", "east")
            for az_key in ("a", "b")
        ),
        *(
            f'aws_route.workload_to_remote_{site}[{json.dumps(f"{az_key}:{cidr}")}]'
            for site in ("west", "east")
            for az_key in config.sites[site]["azs"]
            for cidr in config.sites[site]["remote_site_cidrs"]
        ),
        *(
            f'aws_route.transport_to_local_{site}[{json.dumps(f"{az_key}:{cidr}")}]'
            for site in ("west", "east")
            for az_key in config.sites[site]["azs"]
            for cidr in config.sites[site]["local_site_cidrs"]
        ),
        *(
            f'aws_route.gwlbe_to_remote_{site}[{json.dumps(f"{az_key}:{cidr}")}]'
            for site in ("west", "east")
            for az_key in config.sites[site]["azs"]
            for cidr in config.sites[site]["remote_site_cidrs"]
        ),
    }
    approved = appliance.symmetric_managed_resource_addresses()
    represented = {re.sub(r"\[[^]]+\]", "", address) for address in addresses}
    addresses.update(approved - represented)

    transport_members = {
        site: {
            member["az_key"]: member
            for member in fixture_symmetric_topology(config)["sites"][site]["transport_router_fleet"]
        }
        for site in ("west", "east")
    }

    def route_identity(address: str) -> tuple[str, str, str, str] | None:
        match = re.fullmatch(
            r'aws_route\.(workload_to_remote|transport_to_local|gwlbe_to_remote)_(west|east)\["([^:]+):(.+)"\]',
            address,
        )
        return match.groups() if match is not None else None

    def policy_document(site: str, *, role: str) -> str:
        statements: list[dict] = []
        core = {
            "Effect": "Allow",
            "Action": sorted(appliance.INSTANCE_SSM_CORE_ACTIONS),
            "Resource": ["*"],
        }
        if role == "transport":
            kms_key_arn = config.sites[site]["ssm_kms_key_arn"]
            account_id = kms_key_arn.split(":", 5)[4]
            secret_arn = (
                f"arn:aws:ssm:{config.sites[site]['region']}:{account_id}:"
                f"parameter/{config.run_id}/tailscale-auth"
            )
            statements = [
                {
                    "Effect": "Allow",
                    "Action": ["ssm:GetParameter"],
                    "Resource": [secret_arn],
                },
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt"],
                    "Resource": [kms_key_arn],
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": account_id,
                            "kms:EncryptionContext:PARAMETER_ARN": secret_arn,
                            "kms:ViaService": (
                                f"ssm.{config.sites[site]['region']}.amazonaws.com"
                            ),
                        }
                    },
                },
                core,
            ]
        elif role == "runtime":
            account_id = config.sites[site]["ssm_kms_key_arn"].split(":", 5)[4]
            artifact_arn = (
                f"arn:aws:s3:::{config.run_id}-{account_id}-{config.sites['west']['region']}-artifact/"
                f"artifacts/{'b' * 40}/envelope-linux-{config.architecture}"
            )
            statements = [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [artifact_arn],
                },
                core,
            ]
        elif role == "workload":
            statements = [core]
        elif role == "flow":
            account_id = config.sites["west"]["ssm_kms_key_arn"].split(":", 5)[4]
            statements = [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogStream",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                    ],
                    "Resource": [
                        f"arn:aws:logs:{config.sites[owner]['region']}:{account_id}:"
                        f"log-group:/aws/vpc-flow-logs/{config.run_id}/{owner}:*"
                        for owner in ("west", "east")
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:DescribeLogGroups"],
                    "Resource": ["*"],
                },
            ]
        return json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":"))

    def planned_resource(address: str) -> dict:
        resource = {"address": address, "mode": "managed", "values": {}}
        target_group_match = re.fullmatch(r"aws_lb_target_group\.(west|east)", address)
        if target_group_match is not None:
            resource["values"] = {
                "health_check": [
                    {
                        "enabled": True,
                        "healthy_threshold": 5,
                        "interval": 10,
                        "path": "/healthz",
                        "port": "9090",
                        "protocol": "HTTP",
                        "timeout": 5,
                        "unhealthy_threshold": 2,
                    }
                ]
            }
        route = route_identity(address)
        if route is not None:
            family, site, az_key, cidr = route
            domain = {
                "workload_to_remote": "workload",
                "transport_to_local": "transport",
                "gwlbe_to_remote": "gwlbe",
            }[family]
            resource["index"] = f"{az_key}:{cidr}"
            resource["values"] = {
                "destination_cidr_block": cidr,
                "route_table_id": f"rtb-{domain}-{site}-{az_key}",
            }
            if family == "gwlbe_to_remote":
                selected_az = config.route_failover[
                    "initial_transport_router_az_by_gwlbe_az"
                ][site][az_key]
                resource["values"]["network_interface_id"] = transport_members[site][
                    selected_az
                ]["network_interface_id"]
            else:
                resource["values"]["vpc_endpoint_id"] = f"vpce-{site}-{az_key}"
        subnet_match = re.fullmatch(
            r'aws_subnet\.(workload|transport|gwlbe|target)_(west|east)\["([^\"]+)"\]',
            address,
        )
        if subnet_match is not None:
            domain, site, az_key = subnet_match.groups()
            resource["index"] = az_key
            resource["values"] = {"id": f"subnet-{domain}-{site}-{az_key}"}
            if domain == "transport":
                resource["values"]["tags"] = {"Role": "transport-router"}
        route_table_match = re.fullmatch(
            r'aws_route_table\.(workload|transport|gwlbe|target)_(west|east)\["([^\"]+)"\]',
            address,
        )
        if route_table_match is not None:
            domain, site, az_key = route_table_match.groups()
            resource["index"] = az_key
            resource["values"] = {"id": f"rtb-{domain}-{site}-{az_key}", "route": []}
            if domain == "transport":
                resource["values"]["tags"] = {"Role": "transport-router"}
        association_match = re.fullmatch(
            r'aws_route_table_association\.(workload|transport|gwlbe|target)_(west|east)\["([^\"]+)"\]',
            address,
        )
        if association_match is not None:
            domain, site, az_key = association_match.groups()
            resource["index"] = az_key
            resource["values"] = {
                "subnet_id": f"subnet-{domain}-{site}-{az_key}",
                "route_table_id": f"rtb-{domain}-{site}-{az_key}",
            }
        endpoint_match = re.fullmatch(r'aws_vpc_endpoint\.(west|east)\["([^\"]+)"\]', address)
        if endpoint_match is not None:
            site, az_key = endpoint_match.groups()
            resource["index"] = az_key
            resource["values"] = {"id": f"vpce-{site}-{az_key}"}
        target_default_match = re.fullmatch(
            r'aws_route\.target_default_(west|east)\["([^\"]+)"\]', address
        )
        if target_default_match is not None:
            site, az_key = target_default_match.groups()
            resource["index"] = az_key
            resource["values"] = {
                "route_table_id": f"rtb-target-{site}-{az_key}",
                "destination_cidr_block": "0.0.0.0/0",
                "nat_gateway_id": f"nat-{site}",
            }
        nat_gateway_match = re.fullmatch(r"aws_nat_gateway\.(west|east)", address)
        if nat_gateway_match is not None:
            resource["values"] = {"id": f"nat-{nat_gateway_match.group(1)}"}
        target_match = re.fullmatch(r'aws_instance\.envelope_target_(west|east)\["([^\"]+)"\]', address)
        if target_match is not None:
            site, az_key = target_match.groups()
            resource["index"] = az_key
            resource["values"] = {
                "id": f"i-target-{site}-{az_key}",
                "associate_public_ip_address": False,
                "source_dest_check": True,
                "subnet_id": f"subnet-target-{site}-{az_key}",
                "iam_instance_profile": f"{config.run_id}-{site}-runtime",
                "user_data_base64": f"packet-return-{site}-{az_key}",
            }
        transport_match = re.fullmatch(r'aws_instance\.transport_router_(west|east)\["([^\"]+)"\]', address)
        if transport_match is not None:
            site, az_key = transport_match.groups()
            resource["index"] = az_key
            resource["values"] = {
                "id": f"i-transport-{site}-{az_key}",
                "associate_public_ip_address": False,
                "source_dest_check": False,
                "subnet_id": f"subnet-transport-{site}-{az_key}",
                "primary_network_interface_id": f"eni-transport-{site}-{az_key}",
                "iam_instance_profile": f"{config.run_id}-{site}-transport",
                "tags": {"Role": "transport-router"},
                "volume_tags": {"Role": "transport-router"},
            }
        workload_match = re.fullmatch(
            r'aws_instance\.workload_(west|east)\["([^\"]+)"\]', address
        )
        if workload_match is not None:
            site, role = workload_match.groups()
            resource["index"] = role
            resource["values"] = {
                "id": f"i-workload-{site}-{role}",
                "associate_public_ip_address": False,
                "iam_instance_profile": f"{config.run_id}-{site}-workload",
            }
        if address in {
            "aws_iam_role.transport_west",
            "aws_iam_role.transport_east",
            "aws_security_group.transport_west",
            "aws_security_group.transport_east",
        }:
            resource["values"] = {"tags": {"Role": "transport-router"}}
        policy_match = re.fullmatch(
            r"aws_iam_role_policy\.(transport|runtime|workload)_(west|east)", address
        )
        if policy_match is not None:
            role, site = policy_match.groups()
            resource["values"] = {"policy": policy_document(site, role=role)}
        elif address == "aws_iam_role_policy.flow_logs":
            resource["values"] = {"policy": policy_document("west", role="flow")}
        return resource

    def configured_resource(address: str) -> dict:
        resource = {"address": address, "mode": "managed"}
        target_group_match = re.fullmatch(r"aws_lb_target_group\.(west|east)", address)
        if target_group_match is not None:
            resource["expressions"] = {
                "health_check": [
                    {
                        "healthy_threshold": {"constant_value": 5},
                        "interval": {"constant_value": 10},
                        "path": {"constant_value": "/healthz"},
                        "port": {"constant_value": "9090"},
                        "protocol": {"constant_value": "HTTP"},
                        "timeout": {"constant_value": 5},
                        "unhealthy_threshold": {"constant_value": 2},
                    }
                ]
            }
        association_match = re.fullmatch(
            r"aws_route_table_association\.(workload|transport|gwlbe|target)_(west|east)",
            address,
        )
        if association_match is not None:
            domain, site = association_match.groups()
            resource.update(
                {
                    "for_each_expression": {
                        "references": [
                            f"local.sites.{site}.azs",
                            f"local.sites.{site}",
                            "local.sites",
                        ]
                    },
                    "expressions": {
                        "subnet_id": {
                            "references": [f"aws_subnet.{domain}_{site}", "each.key"]
                        },
                        "route_table_id": {
                            "references": [f"aws_route_table.{domain}_{site}", "each.key"]
                        },
                    },
                }
            )
        endpoint_match = re.fullmatch(r"aws_vpc_endpoint\.(west|east)", address)
        if endpoint_match is not None:
            site = endpoint_match.group(1)
            resource.update(
                {
                    "for_each_expression": {
                        "references": [
                            f"local.sites.{site}.azs",
                            f"local.sites.{site}",
                            "local.sites",
                        ]
                    },
                    "expressions": {
                        "subnet_ids": {
                            "references": [f"aws_subnet.gwlbe_{site}", "each.key"]
                        }
                    },
                }
            )
        route_match = re.fullmatch(
            r"aws_route\.(workload_to_remote|transport_to_local|gwlbe_to_remote)_(west|east)",
            address,
        )
        if route_match is not None:
            family, site = route_match.groups()
            domain, cidr_field, target_field, target_base = {
                "workload_to_remote": (
                    "workload",
                    "remote_site_cidrs",
                    "vpc_endpoint_id",
                    f"aws_vpc_endpoint.{site}",
                ),
                "transport_to_local": (
                    "transport",
                    "local_site_cidrs",
                    "vpc_endpoint_id",
                    f"aws_vpc_endpoint.{site}",
                ),
                "gwlbe_to_remote": (
                    "gwlbe",
                    "remote_site_cidrs",
                    "network_interface_id",
                    f"aws_instance.transport_router_{site}",
                ),
            }[family]
            resource.update(
                {
                    "for_each_expression": {
                        "references": [
                            f"local.sites.{site}.azs",
                            f"local.sites.{site}.{cidr_field}",
                            f"local.sites.{site}",
                            "local.sites",
                        ]
                    },
                    "expressions": {
                        "route_table_id": {
                            "references": [
                                f"aws_route_table.{domain}_{site}",
                                "each.value.az_key",
                                "each.value",
                            ]
                        },
                        "destination_cidr_block": {
                            "references": ["each.value.cidr", "each.value"]
                        },
                        target_field: {
                            "references": (
                                [
                                    target_base,
                                    f"local.route_failover.initial_transport_router_az_by_gwlbe_az.{site}",
                                    "local.route_failover.initial_transport_router_az_by_gwlbe_az",
                                    "local.route_failover",
                                    "each.value.az_key",
                                    "each.value",
                                ]
                                if family == "gwlbe_to_remote"
                                else [target_base, "each.value.az_key", "each.value"]
                            )
                        },
                    },
                }
            )
        target_default_match = re.fullmatch(r"aws_route\.target_default_(west|east)", address)
        if target_default_match is not None:
            site = target_default_match.group(1)
            resource.update(
                {
                    "for_each_expression": {
                        "references": [
                            f"local.sites.{site}.azs",
                            f"local.sites.{site}",
                            "local.sites",
                        ]
                    },
                    "expressions": {
                        "route_table_id": {
                            "references": [f"aws_route_table.target_{site}", "each.key"]
                        },
                        "nat_gateway_id": {
                            "references": [
                                f"aws_nat_gateway.{site}.id",
                                f"aws_nat_gateway.{site}",
                            ]
                        },
                    },
                }
            )
        target_match = re.fullmatch(r"aws_instance\.envelope_target_(west|east)", address)
        if target_match is not None:
            site = target_match.group(1)
            resource["for_each_expression"] = {
                "references": [
                    f"local.sites.{site}.target_az_keys",
                    f"local.sites.{site}",
                    "local.sites",
                ]
            }
            resource["expressions"] = {
                "subnet_id": {
                    "references": [f"aws_subnet.target_{site}", "each.key"]
                },
                "vpc_security_group_ids": {
                    "references": [
                        f"aws_security_group.target_{site}.id",
                        f"aws_security_group.target_{site}",
                    ]
                },
                "iam_instance_profile": {
                    "references": [
                        f"aws_iam_instance_profile.runtime_{site}.name",
                        f"aws_iam_instance_profile.runtime_{site}",
                    ]
                },
                "user_data_base64": {
                    "references": [
                        f"data.cloudinit_config.target_{site}.rendered",
                        f"data.cloudinit_config.target_{site}",
                    ]
                },
            }
            resource["depends_on"] = [
                f"aws_iam_role_policy.runtime_{site}",
                f"aws_route_table_association.target_{site}",
                f"aws_route.target_default_{site}",
                "aws_s3_object.envelope",
            ]
        transport_match = re.fullmatch(r"aws_instance\.transport_router_(west|east)", address)
        if transport_match is not None:
            site = transport_match.group(1)
            resource["for_each_expression"] = {
                "references": [
                    f"local.sites.{site}.transport_router_az_keys",
                    f"local.sites.{site}",
                    "local.sites",
                ]
            }
            resource["expressions"] = {
                "subnet_id": {
                    "references": [f"aws_subnet.transport_{site}", "each.key"]
                },
                "vpc_security_group_ids": {
                    "references": [
                        f"aws_security_group.transport_{site}.id",
                        f"aws_security_group.transport_{site}",
                    ]
                },
                "iam_instance_profile": {
                    "references": [
                        f"aws_iam_instance_profile.transport_{site}.name",
                        f"aws_iam_instance_profile.transport_{site}",
                    ]
                },
                "user_data_base64": {
                    "references": [f"module.tailscale_transport_{site}", "each.key"]
                },
            }
            resource["depends_on"] = [
                f"aws_iam_role_policy.transport_{site}",
                f"aws_route_table_association.transport_{site}",
                f"aws_route.transport_default_{site}",
                f"aws_route.transport_to_local_{site}",
            ]
        workload_match = re.fullmatch(r"aws_instance\.workload_(west|east)", address)
        if workload_match is not None:
            site = workload_match.group(1)
            resource["for_each_expression"] = {
                "references": [f"local.workload_roles.{site}"]
            }
            resource["expressions"] = {
                "subnet_id": {
                    "references": [f"aws_subnet.workload_{site}", "each.value.az_key"]
                },
                "vpc_security_group_ids": {
                    "references": [f"aws_security_group.workload_{site}", "each.key"]
                },
                "iam_instance_profile": {
                    "references": [
                        f"aws_iam_instance_profile.workload_{site}.name",
                        f"aws_iam_instance_profile.workload_{site}",
                    ]
                },
            }
            resource["depends_on"] = [f"aws_iam_role_policy.workload_{site}"]
        policy_match = re.fullmatch(
            r"aws_iam_role_policy\.(transport|runtime|workload)_(west|east)", address
        )
        if policy_match is not None:
            role, site = policy_match.groups()
            resource["expressions"] = {
                "role": {
                    "references": [
                        f"aws_iam_role.{role}_{site}.id",
                        f"aws_iam_role.{role}_{site}",
                    ]
                },
                "policy": {
                    "references": [
                        "local.workload_policy"
                        if role == "workload"
                        else f"local.{role}_policy.{site}"
                    ]
                },
            }
        elif address == "aws_iam_role_policy.flow_logs":
            resource["expressions"] = {
                "role": {
                    "references": [
                        "aws_iam_role.flow_logs.id",
                        "aws_iam_role.flow_logs",
                    ]
                },
                "policy": {"references": ["local.flow_log_delivery_policy"]},
            }
        profile_match = re.fullmatch(
            r"aws_iam_instance_profile\.(transport|runtime|workload)_(west|east)", address
        )
        if profile_match is not None:
            role, site = profile_match.groups()
            resource["expressions"] = {
                "role": {
                    "references": [
                        f"aws_iam_role.{role}_{site}.name",
                        f"aws_iam_role.{role}_{site}",
                    ]
                }
            }
        return resource

    planned_resources = [planned_resource(address) for address in sorted(addresses)]
    configured_addresses = sorted({re.sub(r"\[[^]]+\]", "", address) for address in addresses})
    configured_resources = [configured_resource(address) for address in configured_addresses]
    configured_resources.extend(
        {
            "address": f"data.cloudinit_config.target_{site}",
            "mode": "data",
            "expressions": {
                "part": {
                    "references": [
                        f"local.{site}_artifact_installer",
                        f"local.{site}_target_bootstrap",
                    ]
                }
            },
        }
        for site in ("west", "east")
    )
    changes = [
        {"address": address, "mode": "managed", "change": {"actions": ["create"]}}
        for address in sorted(addresses)
    ]
    variable_values = appliance.terraform_variables(
        config,
        artifact_identity(config.path.parents[1], config.architecture),
        appliance.intended_ssm_parameters(config, "123456789012"),
    )
    variable_values.update(
        {
            "envelope_tailscale_iface": "tailscale0",
            "envelope_underlay_interface": "ens5",
        }
    )
    planned_outputs, output_changes, configured_outputs = (
        symmetric_plan_output_documents(config)
    )
    return {
        "variables": {
            name: {"value": value}
            for name, value in variable_values.items()
        },
        "applyable": True,
        "complete": True,
        "errored": False,
        "deferred_changes": [],
        "output_changes": output_changes,
        "planned_values": {
            "outputs": planned_outputs,
            "root_module": {"resources": planned_resources},
        },
        "configuration": {
            "root_module": {
                "resources": configured_resources,
                "outputs": configured_outputs,
                "module_calls": {
                    f"tailscale_transport_{site}": {
                        "expressions": {
                            "advertise_routes": {
                                "references": [
                                    "local.initial_transport_router_advertise_routes",
                                    f"local.initial_transport_router_advertise_routes.{site}",
                                    "each.key",
                                ]
                            },
                            "auth_key": {
                                "references": [f"local.{site}_transport_auth_resolver"]
                            },
                            "accept_routes": {"constant_value": True},
                            "snat_subnet_routes": {"constant_value": False},
                        },
                        "module": {"resources": [], "module_calls": {}},
                    }
                    for site in ("west", "east")
                },
            }
        },
        "resource_changes": changes,
    }


def symmetric_saved_plan_with_unknown_route_identities(
    config: appliance.RunConfig,
) -> dict:
    document = symmetric_saved_plan_document(config)
    unknown_fields: dict[str, set[str]] = {}
    for resource in document["planned_values"]["root_module"]["resources"]:
        address = resource["address"]
        fields: set[str] = set()
        if address.startswith("aws_instance."):
            fields.add("id")
        if address.startswith("aws_instance.transport_router_"):
            fields.add("primary_network_interface_id")
        if address.startswith("aws_route_table.gwlbe_"):
            fields.add("id")
        if address.startswith("aws_route.gwlbe_to_remote_"):
            fields.update({"route_table_id", "network_interface_id"})
        if not fields:
            continue
        values = resource["values"]
        present = {field for field in fields if field in values}
        for field in present:
            values.pop(field)
        if present:
            unknown_fields[address] = present

    for change in document["resource_changes"]:
        fields = unknown_fields.get(change["address"])
        if fields is None:
            continue
        resource = next(
            item
            for item in document["planned_values"]["root_module"]["resources"]
            if item["address"] == change["address"]
        )
        change["change"].update(
            {
                "before": None,
                "after": copy.deepcopy(resource["values"]),
                "after_unknown": {field: True for field in sorted(fields)},
                "before_sensitive": False,
                "after_sensitive": False,
                "replace_paths": [],
            }
        )
    return document


def symmetric_replacement_saved_plan_document(
    config: appliance.RunConfig,
    *,
    address: str,
    old_instance_id: str,
    target_group_arn: str,
) -> dict:
    document = symmetric_saved_plan_document(config)
    complete = {
        name: copy.deepcopy(wrapper["value"])
        for name, wrapper in symmetric_deployment_document(config).items()
    }
    match = appliance.TARGET_REPLACEMENT_ADDRESS_RE.fullmatch(address)
    if match is None:
        raise AssertionError(address)
    site, az_key = match.groups()
    target_index = sorted(config.sites[site]["target_az_keys"]).index(az_key)
    topology_before = complete["symmetric_topology"]
    topology_before["sites"][site]["target_fleet"][target_index].update(
        {
            "instance_id": old_instance_id,
            "target_group_arn": target_group_arn,
        }
    )

    for name, value in complete.items():
        document["planned_values"]["outputs"][name] = {
            "sensitive": False,
            "value": copy.deepcopy(value),
        }
        document["output_changes"][name] = {
            "actions": ["no-op"],
            "before": copy.deepcopy(value),
            "after": copy.deepcopy(value),
            "after_unknown": False,
            "before_sensitive": False,
            "after_sensitive": False,
        }

    topology_after, topology_unknown, has_unknown = split_plan_unknowns(
        topology_before,
        {("sites", site, "target_fleet", target_index, "instance_id")},
    )
    if not has_unknown:
        raise AssertionError("replacement topology fixture has no unknown target identity")
    document["planned_values"]["outputs"]["symmetric_topology"] = {
        "sensitive": False
    }
    document["output_changes"]["symmetric_topology"] = {
        "actions": ["update"],
        "before": copy.deepcopy(topology_before),
        "after": topology_after,
        "after_unknown": topology_unknown,
        "before_sensitive": False,
        "after_sensitive": False,
    }

    for change in document["resource_changes"]:
        change["change"]["actions"] = ["no-op"]
    target = next(
        change for change in document["resource_changes"] if change["address"] == address
    )
    target.update({"action_reason": "replace_by_request"})
    target["change"] = {
        "actions": ["delete", "create"],
        "before": {"id": old_instance_id},
    }
    attachment_address = f'aws_lb_target_group_attachment.{site}["{az_key}"]'
    attachment = next(
        change
        for change in document["resource_changes"]
        if change["address"] == attachment_address
    )
    attachment["change"] = {
        "actions": ["delete", "create"],
        "before": {
            "target_id": old_instance_id,
            "target_group_arn": target_group_arn,
        },
        "after": {"target_id": None, "target_group_arn": target_group_arn},
    }
    planned_target = next(
        resource
        for resource in document["planned_values"]["root_module"]["resources"]
        if resource["address"] == address
    )
    planned_target["values"].pop("id", None)
    return document


def aws_preflight_summary_document(architecture: str = "amd64") -> dict:
    instance_type = "m7g.medium" if architecture == "arm64" else "t3.medium"
    workload_type = "t4g.micro" if architecture == "arm64" else "t3.micro"
    regions = {}
    for site, region, zones in (
        ("west", "us-west-2", ("us-west-2a", "us-west-2b")),
        ("east", "us-east-1", ("us-east-1a", "us-east-1b")),
    ):
        instance_vcpus = {"target": 2, "transport_router": 2, "workload": 2}
        quotas = {}
        for gate, (service, quota_code, quota_name) in sorted(appliance.AWS_REGIONAL_QUOTA_CONTRACT.items()):
            required = 12 if gate == "standard-vcpus" else 1
            quotas[gate] = {
                "service": service,
                "quota_name": quota_name,
                "quota_code": quota_code,
                "source": "servicequotas:GetServiceQuota",
                "limit": 100,
                "used": 0,
                "required": required,
                "available": 100,
            }
        for gate, name in appliance.AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.items():
            quotas[gate] = {
                "service": "elasticloadbalancing",
                "quota_name": name,
                "quota_code": None,
                "source": "elbv2:DescribeAccountLimits",
                "limit": 100,
                "used": 0,
                "required": 1,
                "available": 100,
            }
        for gate, (service, name, limit, source) in appliance.AWS_STRUCTURAL_CAPACITY_CONTRACT.items():
            quotas[gate] = {
                "service": service,
                "quota_name": name,
                "quota_code": None,
                "source": source,
                "limit": limit,
                "used": 0,
                "required": 1,
                "available": limit,
            }
        offerings = {
            *(f"{instance_type}@{zone}" for zone in zones),
            *(f"{workload_type}@{zone}" for zone in zones),
        }
        regions[region] = {
            "site": site,
            "planned_instances": 6,
            "instance_vcpus": instance_vcpus,
            "instance_offerings": sorted(offerings),
            "ssm_kms_key_sha256": hashlib.sha256(
                f"arn:aws:kms:{region}:123456789012:key/{site}".encode()
            ).hexdigest(),
            "excluded_regional_nat_gateways": 0,
            "quotas": quotas,
        }
    return {
        "schema": 1,
        "account_id": "123456789012",
        "principal": {"kind": "assumed-role", "policy_source_sha256": "d" * 64},
        "actions": {
            "operator": list(appliance.AWS_OPERATOR_ACTIONS),
            "operator_simulated": [
                action
                for action in appliance.AWS_OPERATOR_ACTIONS
                if action != "ec2:RunInstances"
            ],
            "operator_decision": "allowed",
            "run_instances_dry_run": {
                "west": {"target": instance_type, "transport_router": instance_type, "workload": workload_type},
                "east": {"target": instance_type, "transport_router": instance_type, "workload": workload_type},
            },
            "flow_log_delivery_role": list(appliance.AWS_FLOW_LOG_DELIVERY_ACTIONS),
        },
        "regions": regions,
        "global_quotas": {
            "s3-artifact-buckets": {
                "service": "s3",
                "quota_name": "General purpose buckets",
                "quota_code": "L-DC2B2D3D",
                "source": "servicequotas:GetServiceQuota",
                "limit": 100,
                "used": 0,
                "required": 1,
                "available": 100,
            }
        },
        "iam_capacity": {
            gate: {
                "source": "iam:GetAccountSummary",
                "limit": 100,
                "used": 0,
                "required": required,
                "available": 100,
            }
            for gate, (_, _, required) in appliance.AWS_IAM_CAPACITY_CONTRACT.items()
        },
    }


def artifact_identity(root: pathlib.Path, architecture: str = "amd64") -> dict:
    return {
        "architecture": architecture,
        "ec2_architecture": appliance.ARCHITECTURES[architecture],
        "sha256": "a" * 64,
        "revision": "b" * 40,
        "version": "fixture.1",
        "go_version": "go1.26.2",
        "manifest_sha256": "c" * 64,
        "manifest_path": str((root / "artifact-manifest.json").resolve()),
        "path": str((root / f"envelope-linux-{architecture}").resolve()),
        "aws_preflight": aws_preflight_summary_document(architecture),
    }


def mark_manifest_applied(manifest: dict) -> None:
    manifest["saved_plan"] = {
        "apply_started": True,
        "applied": True,
        "applied_at": "2026-08-20T12:00:00Z",
    }


def mark_manifest_apply_started(manifest: dict) -> None:
    manifest["saved_plan"] = {"apply_started": True, "applied": False}
    manifest["apply_claimed_at"] = "2026-08-20T12:00:00Z"
    manifest["apply_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"


def live_gwlbe_route_tables(
    config: appliance.RunConfig,
    deployment: dict,
) -> dict[str, dict]:
    topology = deployment["symmetric_topology"]["value"]
    vpc_ids = deployment["vpc_ids"]["value"]
    result = {}
    for site in ("west", "east"):
        result[config.sites[site]["region"]] = {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": member["network_interface_id"],
                    "VpcId": vpc_ids[site],
                    "Status": "in-use",
                    "Attachment": {
                        "InstanceId": member["instance_id"],
                        "DeviceIndex": 0,
                        "Status": "attached",
                    },
                }
                for member in sorted(
                    topology["sites"][site]["transport_router_fleet"],
                    key=lambda value: value["az_key"],
                )
            ],
            "RouteTables": [
                {
                    "RouteTableId": member["gwlbe_route_table_id"],
                    "VpcId": vpc_ids[site],
                    "Routes": [
                        {
                            "DestinationCidrBlock": config.sites[site]["vpc_cidr"],
                            "GatewayId": "local",
                            "Origin": "CreateRouteTable",
                            "State": "active",
                        },
                        *[
                            {
                                "DestinationCidrBlock": prefix,
                                "NetworkInterfaceId": member[
                                    "network_interface_id"
                                ],
                                "Origin": "CreateRoute",
                                "State": "active",
                            }
                            for prefix in sorted(
                                config.sites[site]["remote_site_cidrs"]
                            )
                        ],
                    ],
                }
                for member in sorted(
                    topology["sites"][site]["transport_router_fleet"],
                    key=lambda value: value["az_key"],
                )
            ]
        }
    return result


def deployment_document() -> dict:
    def workload(site, instance_id, private_ip, az_key, availability_zone, cidr):
        return {
            "route_table_id": f"rtb-{site}-{az_key}",
            "cidr": cidr,
            "subnet_id": f"subnet-{site}-{az_key}",
            "availability_zone": availability_zone,
            "az_key": az_key,
            "private_ip": private_ip,
            "instance_id": instance_id,
        }

    target_groups = {
        "east": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/east/fixture",
        "west": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/fixture",
    }

    def site_topology(site, region, local_cidrs, remote_cidrs):
        return {
            "region": region,
            "local_site_cidrs": local_cidrs,
            "remote_site_cidrs": remote_cidrs,
            "target_fleet": [
                {
                    "region": region,
                    "az_key": az_key,
                    "instance_id": f"i-appliance-{site}" + ("-b" if az_key == "b" else ""),
                    "target_group_arn": target_groups[site],
                }
                for az_key in ("a", "b")
            ],
            "transport_router_fleet": [
                {
                    "region": region,
                    "az_key": az_key,
                    "instance_id": f"i-transport-{site}-{az_key}",
                    "network_interface_id": f"eni-transport-{site}-{az_key}",
                    "gwlbe_route_table_id": f"rtb-gwlbe-{site}-{az_key}",
                    "advertised_prefix": local_cidrs[index],
                }
                for index, az_key in enumerate(("a", "b"))
            ],
        }

    return {
        "gwlb_target_group_arns": {
            "sensitive": False,
            "type": ["map", "string"],
            "value": target_groups,
        },
        "workload_instances": {
            "sensitive": False,
            "type": ["object", {}],
            "value": {
                "east": {
                    "responder": workload(
                        "east",
                        "i-workload-east-responder",
                        "10.20.2.10",
                        "b",
                        "us-east-1b",
                        "10.20.2.0/24",
                    ),
                    "initiator": workload(
                        "east",
                        "i-workload-east-initiator",
                        "10.20.1.10",
                        "a",
                        "us-east-1a",
                        "10.20.1.0/24",
                    ),
                },
                "west": {
                    "responder": workload(
                        "west",
                        "i-workload-west-responder",
                        "10.10.2.10",
                        "b",
                        "us-west-2b",
                        "10.10.2.0/24",
                    ),
                    "initiator": workload(
                        "west",
                        "i-workload-west-initiator",
                        "10.10.1.10",
                        "a",
                        "us-west-2a",
                        "10.10.1.0/24",
                    ),
                },
            },
        },
        "symmetric_topology": {
            "sensitive": False,
            "type": ["object", {}],
            "value": {
                "config_version": 2,
                "run_id": "envelope-fixture",
                "route_failover": {
                    "initial_transport_router_az_by_gwlbe_az": {
                        "west": {"a": "a", "b": "b"},
                        "east": {"a": "a", "b": "b"},
                    },
                    "mutation_timeout_seconds": 120,
                    "restoration_timeout_seconds": 120,
                    "recovery_timeout_seconds": 600,
                },
                "sites": {
                    "west": site_topology(
                        "west",
                        "us-west-2",
                        ["10.10.1.0/24", "10.10.2.0/24"],
                        ["10.20.1.0/24", "10.20.2.0/24"],
                    ),
                    "east": site_topology(
                        "east",
                        "us-east-1",
                        ["10.20.1.0/24", "10.20.2.0/24"],
                        ["10.10.1.0/24", "10.10.2.0/24"],
                    ),
                },
            },
        },
    }


def owned_residual(config: appliance.RunConfig, arn: str) -> dict[str, str]:
    return {
        "arn": arn,
        "region": arn.split(":", 5)[3],
        "run_id": config.run_id,
        "expires_at": config.expires_at,
    }


def owned_tag_list(config: appliance.RunConfig) -> list[dict[str, str]]:
    return [
        {"Key": "EnvelopeRun", "Value": config.run_id},
        {"Key": "ExpiresAt", "Value": config.expires_at},
    ]


class ConfigAndPathTest(unittest.TestCase):
    def test_lifecycle_lock_rejects_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            target = root / "outside-lock"
            target.write_text("unchanged\n", encoding="utf-8")
            target.chmod(0o644)
            (run_dir / "lifecycle.lock").symlink_to(target)

            with self.assertRaisesRegex(
                appliance.LifecycleError, "private regular file|symlink"
            ):
                with appliance.lifecycle_lock(run_dir):
                    self.fail("symlinked lock was acquired")

            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_manifest_transition_reconciles_commit_response_loss_and_collisions(self):
        original = {"phase": "original"}
        candidate = {"phase": "candidate"}

        class Store:
            def __init__(self, mode):
                self.mode = mode
                self.value = copy.deepcopy(original)
                self.remote_etag = '"etag-0"'

            def write(self, value, *, if_match=None):
                self.assert_etag = if_match
                if self.mode in {"committed", "interrupted"}:
                    self.value = copy.deepcopy(value)
                    self.remote_etag = '"etag-1"'
                elif self.mode == "competing":
                    self.value = {"phase": "competitor"}
                    self.remote_etag = '"etag-competitor"'
                if self.mode == "interrupted":
                    raise KeyboardInterrupt("injected interrupt")
                raise appliance.LifecycleError("injected response loss")

            def recover(self):
                return copy.deepcopy(self.value)

        committed = Store("committed")
        self.assertEqual(
            appliance.persist_manifest_transition(
                committed, original, candidate, description="fixture transition"
            ),
            "recovered-committed",
        )
        self.assertEqual(committed.assert_etag, '"etag-0"')
        with self.assertRaisesRegex(appliance.LifecycleError, "response loss"):
            appliance.persist_manifest_transition(
                Store("uncommitted"), original, candidate, description="fixture transition"
            )
        with self.assertRaises(appliance.ConcurrentLifecycleError):
            appliance.persist_manifest_transition(
                Store("competing"), original, candidate, description="fixture transition"
            )
        with self.assertRaisesRegex(KeyboardInterrupt, "injected interrupt"):
            appliance.persist_manifest_transition(
                Store("interrupted"), original, candidate, description="fixture transition"
            )

    def test_approved_saved_plan_graph_matches_every_terraform_resource_block(self):
        actual = {
            f"{resource_type}.{name}"
            for path in (ROOT / "example" / "terraform").glob("*.tf")
            for resource_type, name in re.findall(
                r'^resource\s+"([^"]+)"\s+"([^"]+)"',
                path.read_text(),
                flags=re.MULTILINE,
            )
        }
        self.assertEqual(appliance.symmetric_managed_resource_addresses(), actual)

    def test_complete_output_fixture_matches_every_terraform_output_block(self):
        actual = {
            name
            for path in (ROOT / "example" / "terraform").glob("*.tf")
            for name in re.findall(
                r'^output\s+"([^"]+)"',
                path.read_text(),
                flags=re.MULTILINE,
            )
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            fixture = symmetric_deployment_document(config)
        self.assertEqual(actual, set(appliance.SYMMETRIC_DEPLOYMENT_OUTPUT_FIELDS))
        self.assertEqual(set(fixture), actual)

    def test_manifest_accepts_only_exact_replacement_journal_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "e2e_replacement_ready"
            manifest["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "d" * 64,
                "started_at": "2026-08-20T12:00:00Z",
                "replacement": {
                    "address": 'aws_instance.envelope_target_west["a"]',
                    "old_instance_id": "i-0123456789abcdef0",
                    "started_at": "2026-08-20T12:01:00Z",
                },
            }
            appliance.validate_manifest(manifest, config)

            completed = copy.deepcopy(manifest)
            completed["phase"] = "e2e_running"
            completed["e2e"]["replacement"].update(
                {"finished_at": "2026-08-20T12:02:00Z", "new_output_sha256": "e" * 64}
            )
            appliance.validate_manifest(completed, config)
            failed = copy.deepcopy(manifest)
            failed["phase"] = "e2e_running"
            failed["e2e"]["replacement"]["failed_at"] = "2026-08-20T12:02:00Z"
            appliance.validate_manifest(failed, config)

            active = copy.deepcopy(manifest)
            active["e2e"].update(
                {"finished_at": "2026-08-20T12:02:00Z", "passed": False}
            )
            for replacement_state in (active, completed, failed):
                cleanup = copy.deepcopy(replacement_state)
                cleanup["phase"] = "cleanup_started"
                cleanup["cleanup_claimed_at"] = "2026-08-20T12:03:00Z"
                cleanup["cleanup_claim_id"] = (
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                )
                appliance.validate_manifest(cleanup, config)

            ambiguous = copy.deepcopy(completed)
            ambiguous["e2e"]["replacement"]["failed_at"] = "2026-08-20T12:03:00Z"
            with self.assertRaisesRegex(appliance.LifecycleError, "replacement journal"):
                appliance.validate_manifest(ambiguous, config)

    def test_manifest_accepts_only_exact_route_recovery_cleanup_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "e2e_running"
            manifest["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "d" * 64,
                "started_at": "2026-08-20T12:00:00Z",
                "route_recovery": {
                    "schema": 1,
                    "kind": "transport-prefix-and-gwlbe-route-cleanup",
                    "run_id": config.run_id,
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "transaction_id": "22222222-3333-4444-8555-666666666666",
                    "owner": {
                        "pid": 1234,
                        "host_sha256": "e" * 64,
                        "boot_id": "33333333-4444-4555-8666-777777777777",
                    },
                    "lease_expires_at": "2026-08-20T12:02:00Z",
                    "restored_at": "2026-08-20T12:01:00Z",
                    "restoration_status": "reconciled-after-crash",
                    "status": "cleanup-pending",
                },
            }
            appliance.validate_manifest(manifest, config)

            terminal = copy.deepcopy(manifest)
            terminal["phase"] = "e2e_failed"
            terminal["e2e"].update(
                {"finished_at": "2026-08-20T12:03:00Z", "passed": False}
            )
            appliance.validate_manifest(terminal, config)

            incomplete = copy.deepcopy(terminal)
            incomplete["phase"] = "cleanup_incomplete"
            incomplete["cleanup_claimed_at"] = "2026-08-20T12:04:00Z"
            incomplete["cleanup_claim_id"] = (
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            )
            appliance.validate_manifest(incomplete, config)

            for field, value in (
                ("status", "complete"),
                ("transaction_id", "not-a-transaction"),
                ("restoration_status", "restored"),
            ):
                with self.subTest(field=field):
                    invalid = copy.deepcopy(manifest)
                    invalid["e2e"]["route_recovery"][field] = value
                    with self.assertRaisesRegex(
                        appliance.LifecycleError, "route-recovery marker"
                    ):
                        appliance.validate_manifest(invalid, config)

            invalid_owner = copy.deepcopy(manifest)
            invalid_owner["e2e"]["route_recovery"]["owner"]["boot_id"] = ""
            with self.assertRaisesRegex(
                appliance.LifecycleError, "route-recovery marker"
            ):
                appliance.validate_manifest(invalid_owner, config)

    def test_saved_plan_requires_the_exact_symmetric_fleet_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_saved_plan_document(config)
            self.assertEqual(appliance.validate_symmetric_saved_plan(document, config), [])
            computed_outputs = {
                "vpc_ids",
                "gwlb_target_group_arns",
                "gwlb_endpoint_ids",
                "workload_instances",
                "flow_log_evidence",
                "symmetric_topology",
                "route_failover",
            }
            self.assertEqual(
                set(document["configuration"]["root_module"]["outputs"]),
                set(appliance.SYMMETRIC_DEPLOYMENT_OUTPUT_FIELDS),
            )
            self.assertEqual(
                set(document["output_changes"]),
                set(appliance.SYMMETRIC_DEPLOYMENT_OUTPUT_FIELDS),
            )
            for output_name in computed_outputs:
                with self.subTest(plan_time_unknown=output_name):
                    self.assertNotIn(
                        "value", document["planned_values"]["outputs"][output_name]
                    )
                    self.assertTrue(
                        appliance.output_has_unknown(
                            document["output_changes"][output_name]["after_unknown"]
                        )
                    )
            workload_after = document["output_changes"]["workload_instances"][
                "after"
            ]["west"]["initiator"]
            self.assertEqual(workload_after["az_key"], "a")
            self.assertNotIn("instance_id", workload_after)
            self.assertIs(
                document["output_changes"]["route_failover"]["after_unknown"][
                    "sites"
                ]["west"]["a"]["route_table_id"],
                True,
            )

            for field, invalid in (
                ("healthy_threshold", 3),
                ("interval", 30),
                ("timeout", 6),
                ("unhealthy_threshold", 3),
            ):
                with self.subTest(target_health_field=field):
                    wrong_health = copy.deepcopy(document)
                    target_group = next(
                        resource
                        for resource in wrong_health["planned_values"]["root_module"][
                            "resources"
                        ]
                        if resource["address"] == "aws_lb_target_group.west"
                    )
                    target_group["values"]["health_check"][0][field] = invalid
                    self.assertTrue(
                        any(
                            "bounded health transition contract" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                wrong_health, config
                            )
                        )
                    )

            missing_health_expression = copy.deepcopy(document)
            configured_target_group = next(
                resource
                for resource in missing_health_expression["configuration"][
                    "root_module"
                ]["resources"]
                if resource["address"] == "aws_lb_target_group.east"
            )
            configured_target_group["expressions"]["health_check"][0].pop(
                "interval"
            )
            self.assertTrue(
                any(
                    "bounded health transition contract" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        missing_health_expression, config
                    )
                )
            )

            missing = copy.deepcopy(document)
            missing["resource_changes"] = [
                change
                for change in missing["resource_changes"]
                if change["address"] != 'aws_instance.envelope_target_west["a"]'
            ]
            self.assertTrue(
                any("omits required fleet resources" in failure for failure in appliance.validate_symmetric_saved_plan(missing, config))
            )

            collateral = copy.deepcopy(document)
            collateral["resource_changes"].append(
                {
                    "address": "aws_vpc.unrelated",
                    "mode": "managed",
                    "change": {"actions": ["update"]},
                }
            )
            self.assertTrue(
                any("update or destroy" in failure for failure in appliance.validate_symmetric_saved_plan(collateral, config))
            )
            deferred = copy.deepcopy(document)
            deferred["deferred_changes"] = [{"reason": "provider deferred fixture"}]
            self.assertTrue(
                any("deferred" in failure for failure in appliance.validate_symmetric_saved_plan(deferred, config))
            )
            incomplete = copy.deepcopy(document)
            incomplete["complete"] = False
            self.assertTrue(
                any("complete, applyable" in failure for failure in appliance.validate_symmetric_saved_plan(incomplete, config))
            )
            coherent_extra = copy.deepcopy(document)
            extra = {"address": "aws_iam_role.unreviewed", "mode": "managed"}
            coherent_extra["configuration"]["root_module"]["resources"].append(extra)
            coherent_extra["planned_values"]["root_module"]["resources"].append(extra)
            coherent_extra["resource_changes"].append(
                {**extra, "change": {"actions": ["create"]}}
            )
            self.assertTrue(
                any("approved symmetric resource graph" in failure for failure in appliance.validate_symmetric_saved_plan(coherent_extra, config))
            )
            coherent_missing = copy.deepcopy(document)
            omitted = "aws_route.workload_to_remote_west"
            coherent_missing["configuration"]["root_module"]["resources"] = [
                resource
                for resource in coherent_missing["configuration"]["root_module"]["resources"]
                if resource["address"] != omitted
            ]
            coherent_missing["planned_values"]["root_module"]["resources"] = [
                resource
                for resource in coherent_missing["planned_values"]["root_module"]["resources"]
                if resource["address"] != omitted
            ]
            coherent_missing["resource_changes"] = [
                change for change in coherent_missing["resource_changes"] if change["address"] != omitted
            ]
            self.assertTrue(
                any("approved symmetric resource graph" in failure for failure in appliance.validate_symmetric_saved_plan(coherent_missing, config))
            )

    def test_saved_plan_unknown_route_identities_still_require_exact_resource_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_saved_plan_with_unknown_route_identities(config)
            route = next(
                resource
                for resource in document["planned_values"]["root_module"]["resources"]
                if resource["address"]
                == 'aws_route.gwlbe_to_remote_west["a:10.20.1.0/24"]'
            )
            self.assertNotIn("route_table_id", route["values"])
            self.assertNotIn("network_interface_id", route["values"])
            transport = next(
                resource
                for resource in document["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_instance.transport_router_west["a"]'
            )
            route_table = next(
                resource
                for resource in document["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_route_table.gwlbe_west["a"]'
            )
            self.assertNotIn("id", transport["values"])
            self.assertNotIn("primary_network_interface_id", transport["values"])
            self.assertNotIn("id", route_table["values"])
            self.assertEqual(
                next(
                    change
                    for change in document["resource_changes"]
                    if change["address"] == route["address"]
                )["change"]["after_unknown"],
                {"network_interface_id": True, "route_table_id": True},
            )
            self.assertEqual(
                appliance.validate_symmetric_saved_plan(document, config), []
            )

            unanchored = copy.deepcopy(document)
            configured_route = next(
                resource
                for resource in unanchored["configuration"]["root_module"]["resources"]
                if resource["address"] == "aws_route.gwlbe_to_remote_west"
            )
            configured_route["expressions"]["network_interface_id"]["references"][
                0
            ] = "aws_instance.transport_router_east"
            self.assertTrue(
                any(
                    "reviewed same-site transport ENI" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        unanchored, config
                    )
                )
            )

    def test_saved_plan_rejects_mutated_current_output_contracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_saved_plan_document(config)

            for output_name in (
                "transport_router_readiness_expectations",
                "route_failover",
            ):
                with self.subTest(missing_output=output_name):
                    missing = copy.deepcopy(document)
                    missing["planned_values"]["outputs"].pop(output_name)
                    self.assertTrue(
                        any(
                            "complete symmetric deployment output contract" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                missing, config
                            )
                        )
                    )

            for section, remove in (
                (
                    "configured",
                    lambda value: value["configuration"]["root_module"][
                        "outputs"
                    ].pop("vpc_ids"),
                ),
                (
                    "change",
                    lambda value: value["output_changes"].pop("vpc_ids"),
                ),
            ):
                with self.subTest(missing_declaration=section):
                    missing = copy.deepcopy(document)
                    remove(missing)
                    self.assertTrue(
                        any(
                            "complete symmetric deployment output contract" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                missing, config
                            )
                        )
                    )

            for output_name in (
                "symmetric_topology",
                "transport_router_readiness_expectations",
                "route_failover",
            ):
                with self.subTest(wrong_output_reference=output_name):
                    wrong_reference = copy.deepcopy(document)
                    wrong_reference["configuration"]["root_module"]["outputs"][
                        output_name
                    ]["expression"]["references"].append(
                        "aws_instance.unreviewed.id"
                    )
                    self.assertTrue(
                        any(
                            "exact authorized references" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                wrong_reference, config
                            )
                        )
                    )

            missing_unknown = copy.deepcopy(document)
            missing_unknown["output_changes"]["route_failover"]["after_unknown"][
                "sites"
            ]["west"]["a"].pop("route_table_id")
            self.assertTrue(
                any(
                    "route_failover output change has an invalid known/unknown shape"
                    in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        missing_unknown, config
                    )
                )
            )

            wrong_known_shape = copy.deepcopy(document)
            wrong_known_shape["output_changes"]["workload_instances"]["after"][
                "west"
            ]["initiator"]["az_key"] = "b"
            self.assertTrue(
                any(
                    "workload_instances output change has an invalid known/unknown shape"
                    in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_known_shape, config
                    )
                )
            )

            wrong_runtime = copy.deepcopy(document)
            wrong_runtime["output_changes"]["envelope_runtime_config"]["after"][
                "west"
            ]["mode"] = "forward"
            self.assertTrue(
                any(
                    "runtime is not the canonical packet-return configuration" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_runtime, config
                    )
                )
            )

            wrong_load_profile = copy.deepcopy(document)
            wrong_load_profile["output_changes"]["e2e_load_profile"]["after"][
                "safe_inner_mtu"
            ] = 1279
            self.assertTrue(
                any(
                    "load profile differs" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_load_profile, config
                    )
                )
            )

            def readiness(document_value):
                return document_value["output_changes"][
                    "transport_router_readiness_expectations"
                ]["after"]

            readiness_mutations = {
                "schema": lambda value: value.update({"config_version": 3}),
                "schema type": lambda value: value.update({"config_version": 2.0}),
                "extra field": lambda value: value["sites"]["west"].update(
                    {"legacy": True}
                ),
                "local CIDR": lambda value: value["sites"]["west"][
                    "local_site_cidrs"
                ].append("10.99.0.0/24"),
                "policy rule": lambda value: value["sites"]["west"][
                    "local_policy_rules"
                ][0].update({"priority": 99}),
                "policy rule type": lambda value: value["sites"]["west"][
                    "local_policy_rules"
                ][0].update({"priority": 100.0}),
                "firewall": lambda value: value["sites"]["west"][
                    "forward_rules"
                ][0].update({"action": "DROP"}),
                "forwarding type": lambda value: value["sites"]["west"].update(
                    {"ipv4_forwarding": 1}
                ),
                "MSS": lambda value: value["sites"]["west"]["mss_rules"][0].update(
                    {"action": "ACCEPT"}
                ),
                "MSS ceiling": lambda value: value["sites"]["west"].update(
                    {"approved_maximum_tcp_mss": 1239}
                ),
                "mangle policy": lambda value: value["sites"]["west"].update(
                    {"mangle_forward_policy": "DROP"}
                ),
                "recovery marker": lambda value: value["sites"]["west"].update(
                    {"recovery_marker": "/tmp/stale"}
                ),
                "full policy rules": lambda value: value["sites"]["west"][
                    "ipv4_policy_rules"
                ][0].update({"table": "main"}),
                "remote route table": lambda value: value["sites"]["west"].update(
                    {"remote_route_table": 53}
                ),
                "contract SHA": lambda value: value["sites"]["west"].update(
                    {"contract_sha256": "0" * 64}
                ),
            }
            for name, mutate in readiness_mutations.items():
                with self.subTest(readiness=name):
                    changed = copy.deepcopy(document)
                    mutate(readiness(changed))
                    self.assertTrue(
                        any(
                            "transport-router readiness expectations" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                changed, config
                            )
                        )
                    )

            def failover(document_value):
                return document_value["output_changes"]["route_failover"]["after"]

            failover_mutations = {
                "schema": lambda value: value.update({"config_version": 3}),
                "extra field": lambda value: value.update({"legacy": True}),
                "route table": lambda value: value["sites"]["west"]["a"].update(
                    {"route_table_id": "rtb-wrong"}
                ),
                "initial ENI": lambda value: value["sites"]["west"]["a"].update(
                    {"initial_network_interface_id": "eni-transport-west-b"}
                ),
                "initial AZ": lambda value: value["sites"]["west"]["a"].update(
                    {"initial_transport_router_az_key": "b"}
                ),
                "remote CIDRs": lambda value: value["sites"]["west"]["a"].update(
                    {"remote_site_cidrs": ["10.99.0.0/24"]}
                ),
                "bound type": lambda value: value.update(
                    {"mutation_timeout_seconds": 120.0}
                ),
                "preference type": lambda value: value["same_az_preferred"].update(
                    {"west": 1}
                ),
            }
            for field in (
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
            ):
                failover_mutations[field] = lambda value, field=field: value.update(
                    {field: value[field] + 1}
                )
            for name, mutate in failover_mutations.items():
                with self.subTest(route_failover=name):
                    changed = copy.deepcopy(document)
                    mutate(failover(changed))
                    self.assertTrue(
                        any(
                            "route_failover output" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                changed, config
                            )
                        )
                    )

            topology_mismatch = copy.deepcopy(document)
            topology_mismatch["output_changes"]["symmetric_topology"]["after"][
                "route_failover"
            ]["mutation_timeout_seconds"] += 1
            self.assertTrue(
                any(
                    "symmetric_topology output change" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        topology_mismatch, config
                    )
                )
            )

            cost_paths = (
                ("resource_counts", "nat_gateways"),
                ("resource_counts", "elastic_ips"),
                ("resource_counts", "gateway_load_balancers"),
                ("resource_counts", "iam_roles", "target"),
                ("resource_counts", "iam_roles", "workload"),
                ("resource_counts", "iam_roles", "transport"),
                ("resource_counts", "iam_roles", "flow_log"),
                ("resource_counts", "iam_instance_profiles", "target"),
                ("resource_counts", "iam_instance_profiles", "workload"),
                ("resource_counts", "iam_instance_profiles", "transport"),
                ("route_failover_bounds", "mutation_timeout_seconds"),
                ("route_failover_bounds", "restoration_timeout_seconds"),
                ("route_failover_bounds", "recovery_timeout_seconds"),
                ("nat_topology_limit", "gateways_per_site"),
                ("nat_topology_limit", "expanded_for_ha"),
                ("nat_topology_limit", "placement"),
                ("nat_topology_limit", "limitation"),
            )
            for path in cost_paths:
                with self.subTest(cost_path=".".join(path)):
                    changed = copy.deepcopy(document)
                    target = changed["output_changes"]["cost_profile"]["after"]
                    for field in path[:-1]:
                        target = target[field]
                    current = target[path[-1]]
                    target[path[-1]] = not current if isinstance(current, bool) else 99
                    self.assertTrue(
                        any(
                            "symmetric HA cost profile" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                changed, config
                            )
                        )
                    )

    def test_saved_plan_rejects_every_ingress_era_schema_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_saved_plan_document(config)

            obsolete_input = copy.deepcopy(document)
            topology = obsolete_input["variables"]["symmetric_topology"]["value"]["sites"]["west"]
            topology["ingress_subnet_cidrs"] = topology.pop("transport_subnet_cidrs")
            topology["ingress_router_az_keys"] = topology.pop("transport_router_az_keys")
            self.assertTrue(
                any(
                    "variables differ" in failure
                    for failure in appliance.validate_symmetric_saved_plan(obsolete_input, config)
                )
            )

            obsolete_output = copy.deepcopy(document)
            site_output = obsolete_output["output_changes"]["symmetric_topology"][
                "after"
            ]["sites"]["west"]
            site_output["ingress_router_fleet"] = site_output.pop("transport_router_fleet")
            self.assertTrue(appliance.validate_symmetric_saved_plan(obsolete_output, config))

            obsolete_count = copy.deepcopy(document)
            counts = obsolete_count["output_changes"]["cost_profile"]["after"][
                "resource_counts"
            ]
            counts["ingress_routers"] = counts.pop("transport_routers")
            self.assertTrue(
                any(
                    "symmetric HA cost profile" in failure
                    for failure in appliance.validate_symmetric_saved_plan(obsolete_count, config)
                )
            )

            aliases = (
                ("aws_instance.transport_router_west", "aws_instance.tailnet_ingress_west"),
                ("aws_subnet.transport_west", "aws_subnet.ingress_west"),
                ("aws_route_table.transport_west", "aws_route_table.ingress_west"),
                (
                    "aws_route_table_association.transport_west",
                    "aws_route_table_association.ingress_west",
                ),
                ("aws_security_group.transport_west", "aws_security_group.ingress_west"),
                ("aws_route.transport_default_west", "aws_route.ingress_default_west"),
                ("aws_route.transport_to_local_west", "aws_route.ingress_to_local_west"),
            )
            for current, obsolete in aliases:
                with self.subTest(resource=obsolete):
                    obsolete_resource = copy.deepcopy(document)
                    for resource in obsolete_resource["configuration"]["root_module"]["resources"]:
                        if resource["address"] == current:
                            resource["address"] = obsolete
                    for resource in obsolete_resource["planned_values"]["root_module"]["resources"]:
                        if resource["address"].startswith(current):
                            resource["address"] = obsolete + resource["address"][len(current) :]
                    for change in obsolete_resource["resource_changes"]:
                        if change["address"].startswith(current):
                            change["address"] = obsolete + change["address"][len(current) :]
                    self.assertTrue(
                        any(
                            "approved symmetric resource graph" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                obsolete_resource, config
                            )
                        )
                    )

    def test_saved_plan_binds_packet_return_routes_targets_and_transport_secret_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_saved_plan_document(config)

            wrong_eni = copy.deepcopy(document)
            next(
                resource
                for resource in wrong_eni["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_route.gwlbe_to_remote_west["a:10.20.1.0/24"]'
            )["values"]["network_interface_id"] = "eni-transport-west-b"
            self.assertTrue(
                any(
                    "reviewed same-site transport ENI" in failure
                    for failure in appliance.validate_symmetric_saved_plan(wrong_eni, config)
                )
            )

            wrong_route_reference = copy.deepcopy(document)
            next(
                resource
                for resource in wrong_route_reference["configuration"]["root_module"]["resources"]
                if resource["address"] == "aws_route.gwlbe_to_remote_west"
            )["expressions"]["network_interface_id"]["references"][0] = (
                "aws_instance.transport_router_east"
            )
            self.assertTrue(
                any(
                    "reviewed same-site transport ENI" in failure
                    for failure in appliance.validate_symmetric_saved_plan(wrong_route_reference, config)
                )
            )

            crossed_domain = copy.deepcopy(document)
            next(
                resource
                for resource in crossed_domain["configuration"]["root_module"]["resources"]
                if resource["address"] == "aws_route_table_association.workload_west"
            )["expressions"]["route_table_id"]["references"][0] = "aws_route_table.gwlbe_west"
            self.assertTrue(
                any(
                    "route domains are not distinct" in failure
                    for failure in appliance.validate_symmetric_saved_plan(crossed_domain, config)
                )
            )

            wrong_preinspection_endpoint = copy.deepcopy(document)
            next(
                resource
                for resource in wrong_preinspection_endpoint["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_route.workload_to_remote_west["a:10.20.1.0/24"]'
            )["values"]["vpc_endpoint_id"] = "vpce-west-b"
            self.assertTrue(
                any(
                    "same-AZ GWLBE" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_preinspection_endpoint, config
                    )
                )
            )

            source_dest_check = copy.deepcopy(document)
            next(
                resource
                for resource in source_dest_check["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_instance.envelope_target_west["a"]'
            )["values"]["source_dest_check"] = False
            self.assertTrue(
                any(
                    "packet-return source-dest-check enforcement" in failure
                    for failure in appliance.validate_symmetric_saved_plan(source_dest_check, config)
                )
            )

            obsolete_role_tag = copy.deepcopy(document)
            next(
                resource
                for resource in obsolete_role_tag["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_instance.transport_router_west["a"]'
            )["values"]["tags"]["Role"] = "tailnet-ingress"
            self.assertTrue(
                any(
                    "same-AZ eligible ENI" in failure
                    for failure in appliance.validate_symmetric_saved_plan(obsolete_role_tag, config)
                )
            )

            missing_bootstrap_dependency = copy.deepcopy(document)
            next(
                resource
                for resource in missing_bootstrap_dependency["configuration"]["root_module"]["resources"]
                if resource["address"] == "aws_instance.envelope_target_west"
            )["depends_on"].remove("aws_s3_object.envelope")
            self.assertTrue(
                any(
                    "incomplete bootstrap dependency" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        missing_bootstrap_dependency, config
                    )
                )
            )

            broad_runtime = copy.deepcopy(document)
            runtime = next(
                resource
                for resource in broad_runtime["planned_values"]["root_module"]["resources"]
                if resource["address"] == "aws_iam_role_policy.runtime_west"
            )
            policy = json.loads(runtime["values"]["policy"])
            policy["Statement"][0]["Action"] = ["s3:*"]
            runtime["values"]["policy"] = json.dumps(policy)
            self.assertTrue(
                any(
                    "exact least-privilege" in failure
                    for failure in appliance.validate_symmetric_saved_plan(broad_runtime, config)
                )
            )

            wrong_cost = copy.deepcopy(document)
            wrong_cost["output_changes"]["cost_profile"]["after"][
                "estimated_fixed_hourly_usd"
            ] = 1.5
            self.assertTrue(
                any(
                    "symmetric HA cost profile" in failure
                    for failure in appliance.validate_symmetric_saved_plan(wrong_cost, config)
                )
            )

            obsolete_variable = copy.deepcopy(document)
            obsolete_variable["variables"]["envelope_tun_name"] = {"value": "envelope0"}
            self.assertTrue(
                any(
                    "variable schema contains obsolete" in failure
                    for failure in appliance.validate_symmetric_saved_plan(obsolete_variable, config)
                )
            )

            target_tailscale = copy.deepcopy(document)
            next(
                resource
                for resource in target_tailscale["configuration"]["root_module"]["resources"]
                if resource["address"] == "aws_instance.envelope_target_west"
            )["expressions"]["user_data_base64"]["references"] = [
                "module.tailscale_target_west.rendered"
            ]
            self.assertTrue(
                any(
                    "Tailscale user-data" in failure
                    for failure in appliance.validate_symmetric_saved_plan(target_tailscale, config)
                )
            )

            target_inner_route = copy.deepcopy(document)
            next(
                resource
                for resource in target_inner_route["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_route_table.target_east["a"]'
            )["values"]["route"] = [{"cidr_block": "10.10.1.0/24"}]
            self.assertTrue(
                any(
                    "target route tables contain an inner route" in failure
                    for failure in appliance.validate_symmetric_saved_plan(target_inner_route, config)
                )
            )

            reflected_target_default = copy.deepcopy(document)
            target_table = next(
                resource
                for resource in reflected_target_default["planned_values"]["root_module"]["resources"]
                if resource["address"] == 'aws_route_table.target_east["a"]'
            )
            target_table["values"]["route"] = [
                {
                    "carrier_gateway_id": "",
                    "cidr_block": "0.0.0.0/0",
                    "core_network_arn": "",
                    "destination_prefix_list_id": "",
                    "egress_only_gateway_id": "",
                    "gateway_id": "",
                    "ipv6_cidr_block": "",
                    "local_gateway_id": "",
                    "nat_gateway_id": "nat-east",
                    "network_interface_id": "",
                    "transit_gateway_id": "",
                    "vpc_endpoint_id": "",
                    "vpc_peering_connection_id": "",
                }
            ]
            self.assertTrue(
                any(
                    "target route tables contain an inner route" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        reflected_target_default, config
                    )
                )
            )

            leaked_secret = copy.deepcopy(document)
            runtime_policy = next(
                resource
                for resource in leaked_secret["planned_values"]["root_module"]["resources"]
                if resource["address"] == "aws_iam_role_policy.runtime_west"
            )
            runtime_policy["values"]["policy"] = next(
                resource
                for resource in leaked_secret["planned_values"]["root_module"]["resources"]
                if resource["address"] == "aws_iam_role_policy.transport_west"
            )["values"]["policy"]
            self.assertTrue(
                any(
                    "outside its exact transport role" in failure
                    for failure in appliance.validate_symmetric_saved_plan(leaked_secret, config)
                )
            )

            wrong_transport_secret = copy.deepcopy(document)
            transport_policy = next(
                resource
                for resource in wrong_transport_secret["planned_values"]["root_module"]["resources"]
                if resource["address"] == "aws_iam_role_policy.transport_east"
            )
            policy = json.loads(transport_policy["values"]["policy"])
            policy["Statement"][0]["Resource"] = [
                "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-fixture/tailscale-auth"
            ]
            transport_policy["values"]["policy"] = json.dumps(policy)
            self.assertTrue(
                any(
                    "does not own exact secret access" in failure
                    for failure in appliance.validate_symmetric_saved_plan(wrong_transport_secret, config)
                )
            )

            def mutate_transport_policy(document, mutation):
                resource = next(
                    item
                    for item in document["planned_values"]["root_module"]["resources"]
                    if item["address"] == "aws_iam_role_policy.transport_west"
                )
                value = json.loads(resource["values"]["policy"])
                mutation(value["Statement"])
                resource["values"]["policy"] = json.dumps(value)

            def kms_statement(statements):
                return next(statement for statement in statements if statement["Action"] == ["kms:Decrypt"])

            condition_mutations = {
                "missing condition": lambda statements: kms_statement(statements).pop("Condition"),
                "wrong caller": lambda statements: kms_statement(statements)["Condition"]["StringEquals"].update(
                    {"kms:CallerAccount": "210987654321"}
                ),
                "wrong service": lambda statements: kms_statement(statements)["Condition"]["StringEquals"].update(
                    {"kms:ViaService": "ssm.us-east-1.amazonaws.com"}
                ),
                "wrong parameter": lambda statements: kms_statement(statements)["Condition"]["StringEquals"].update(
                    {
                        "kms:EncryptionContext:PARAMETER_ARN": (
                            "arn:aws:ssm:us-west-2:123456789012:parameter/other/tailscale-auth"
                        )
                    }
                ),
                "extra condition": lambda statements: kms_statement(statements)["Condition"].update(
                    {"ArnLike": {"kms:EncryptionContext:PARAMETER_ARN": "*"}}
                ),
                "condition on SSM": lambda statements: statements[0].update(
                    {"Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"}}}
                ),
                "condition on core": lambda statements: statements[2].update(
                    {"Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"}}}
                ),
            }
            for name, mutation in condition_mutations.items():
                with self.subTest(transport_condition=name):
                    weakened = copy.deepcopy(document)
                    mutate_transport_policy(weakened, mutation)
                    self.assertTrue(
                        any(
                            "reviewed KMS context" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                weakened, config
                            )
                        )
                    )

            broad_workload = copy.deepcopy(document)
            workload_policy = next(
                item
                for item in broad_workload["planned_values"]["root_module"]["resources"]
                if item["address"] == "aws_iam_role_policy.workload_west"
            )
            workload_document = json.loads(workload_policy["values"]["policy"])
            workload_document["Statement"][0]["Action"].append("ssm:GetParameter")
            workload_policy["values"]["policy"] = json.dumps(workload_document)
            self.assertTrue(
                any(
                    "SSM-core-only" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        broad_workload, config
                    )
                )
            )

            artifact_arn = (
                "arn:aws:s3:::envelope-fixture-123456789012-us-west-2-artifact/"
                f"artifacts/{'b' * 40}/envelope-linux-{config.architecture}"
            )
            workload_permissions = {
                "artifact": ("s3:GetObject", artifact_arn),
                "secret": (
                    "ssm:GetParameter",
                    "arn:aws:ssm:us-west-2:123456789012:"
                    "parameter/envelope-fixture/tailscale-auth",
                ),
                "route mutation": ("ec2:ReplaceRoute", "*"),
            }
            for name, (action, resource) in workload_permissions.items():
                with self.subTest(workload_permission=name):
                    changed = copy.deepcopy(document)
                    workload_policy = next(
                        item
                        for item in changed["planned_values"]["root_module"][
                            "resources"
                        ]
                        if item["address"] == "aws_iam_role_policy.workload_west"
                    )
                    workload_document = json.loads(workload_policy["values"]["policy"])
                    workload_document["Statement"].append(
                        {
                            "Effect": "Allow",
                            "Action": [action],
                            "Resource": [resource],
                        }
                    )
                    workload_policy["values"]["policy"] = json.dumps(
                        workload_document
                    )
                    self.assertTrue(
                        any(
                            "SSM-core-only" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                changed, config
                            )
                        )
                    )

            duplicate_core = copy.deepcopy(document)
            duplicate_policy = next(
                item
                for item in duplicate_core["planned_values"]["root_module"][
                    "resources"
                ]
                if item["address"] == "aws_iam_role_policy.workload_west"
            )
            duplicate_document = json.loads(duplicate_policy["values"]["policy"])
            duplicate_document["Statement"][0]["Action"].append(
                duplicate_document["Statement"][0]["Action"][0]
            )
            duplicate_policy["values"]["policy"] = json.dumps(duplicate_document)
            self.assertTrue(
                any(
                    "SSM-core-only" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        duplicate_core, config
                    )
                )
            )

            crossed_workload_role = copy.deepcopy(document)
            workload_configuration = next(
                item
                for item in crossed_workload_role["configuration"]["root_module"][
                    "resources"
                ]
                if item["address"] == "aws_iam_role_policy.workload_west"
            )
            workload_configuration["expressions"]["role"]["references"] = [
                "aws_iam_role.workload_east.id",
                "aws_iam_role.workload_east",
            ]
            self.assertTrue(
                any(
                    "SSM-core-only" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        crossed_workload_role, config
                    )
                )
            )

            for name, mutate in {
                "wildcard action": lambda policy: policy["Statement"][0].update(
                    {"Action": ["logs:*"]}
                ),
                "wildcard resource": lambda policy: policy["Statement"][0].update(
                    {"Resource": ["*"]}
                ),
                "wrong region": lambda policy: policy["Statement"][0]["Resource"].__setitem__(
                    0, policy["Statement"][0]["Resource"][0].replace("us-west-2", "us-east-2")
                ),
                "extra statement": lambda policy: policy["Statement"].append(
                    {"Effect": "Allow", "Action": ["logs:GetLogEvents"], "Resource": ["*"]}
                ),
            }.items():
                with self.subTest(flow_log_policy=name):
                    changed = copy.deepcopy(document)
                    flow_policy = next(
                        item
                        for item in changed["planned_values"]["root_module"][
                            "resources"
                        ]
                        if item["address"] == "aws_iam_role_policy.flow_logs"
                    )
                    flow_document = json.loads(flow_policy["values"]["policy"])
                    mutate(flow_document)
                    flow_policy["values"]["policy"] = json.dumps(flow_document)
                    self.assertTrue(
                        any(
                            "exact regional CloudWatch delivery role" in failure
                            for failure in appliance.validate_symmetric_saved_plan(
                                changed, config
                            )
                        )
                    )

            unknown_flow_policy = copy.deepcopy(document)
            next(
                item
                for item in unknown_flow_policy["planned_values"]["root_module"][
                    "resources"
                ]
                if item["address"] == "aws_iam_role_policy.flow_logs"
            )["values"].pop("policy")
            unknown_failures = appliance.validate_symmetric_saved_plan(
                unknown_flow_policy, config
            )
            self.assertTrue(
                any("IAM policies do not expose" in failure for failure in unknown_failures)
            )
            self.assertTrue(
                any(
                    "exact regional CloudWatch delivery role" in failure
                    for failure in unknown_failures
                )
            )

            flow_artifact = copy.deepcopy(document)
            flow_policy = next(
                item
                for item in flow_artifact["planned_values"]["root_module"][
                    "resources"
                ]
                if item["address"] == "aws_iam_role_policy.flow_logs"
            )
            flow_document = json.loads(flow_policy["values"]["policy"])
            flow_document["Statement"].append(
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [artifact_arn],
                }
            )
            flow_policy["values"]["policy"] = json.dumps(flow_document)
            self.assertTrue(
                any(
                    "artifact access outside the exact target runtime roles" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        flow_artifact, config
                    )
                )
            )

    def test_replacement_plan_is_bound_to_one_current_target_and_attachment(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            address = 'aws_instance.envelope_target_west["a"]'
            old_instance_id = "i-0123456789abcdef0"
            target_group_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/fixture"
            document = symmetric_replacement_saved_plan_document(
                config,
                address=address,
                old_instance_id=old_instance_id,
                target_group_arn=target_group_arn,
            )
            self.assertNotIn(
                "value",
                document["planned_values"]["outputs"]["symmetric_topology"],
            )
            self.assertIs(
                document["output_changes"]["symmetric_topology"]["after_unknown"][
                    "sites"
                ]["west"]["target_fleet"][0]["instance_id"],
                True,
            )
            self.assertEqual(
                document["output_changes"]["cost_profile"]["actions"], ["no-op"]
            )

            self.assertEqual(
                appliance.validate_symmetric_saved_plan(
                    document,
                    config,
                    replace_address=address,
                    replace_instance_id=old_instance_id,
                    replace_target_group_arn=target_group_arn,
                ),
                [],
            )

            def reflected_default(nat_gateway_id):
                return {
                    "carrier_gateway_id": "",
                    "cidr_block": "0.0.0.0/0",
                    "core_network_arn": "",
                    "destination_prefix_list_id": "",
                    "egress_only_gateway_id": "",
                    "gateway_id": "",
                    "ipv6_cidr_block": "",
                    "local_gateway_id": "",
                    "nat_gateway_id": nat_gateway_id,
                    "network_interface_id": "",
                    "transit_gateway_id": "",
                    "vpc_endpoint_id": "",
                    "vpc_peering_connection_id": "",
                }

            reflected = copy.deepcopy(document)
            for site in ("west", "east"):
                for az_key in ("a", "b"):
                    next(
                        resource
                        for resource in reflected["planned_values"]["root_module"][
                            "resources"
                        ]
                        if resource["address"]
                        == f'aws_route_table.target_{site}["{az_key}"]'
                    )["values"]["route"] = [reflected_default(f"nat-{site}")]
            self.assertEqual(
                appliance.validate_symmetric_saved_plan(
                    reflected,
                    config,
                    replace_address=address,
                    replace_instance_id=old_instance_id,
                    replace_target_group_arn=target_group_arn,
                ),
                [],
            )

            configured_inline = copy.deepcopy(reflected)
            next(
                resource
                for resource in configured_inline["configuration"]["root_module"][
                    "resources"
                ]
                if resource["address"] == "aws_route_table.target_east"
            ).setdefault("expressions", {})["route"] = [{}]
            self.assertTrue(
                any(
                    "target route tables contain an inner route" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        configured_inline,
                        config,
                        replace_address=address,
                        replace_instance_id=old_instance_id,
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )

            unbound_nat = copy.deepcopy(reflected)
            next(
                resource
                for resource in unbound_nat["planned_values"]["root_module"][
                    "resources"
                ]
                if resource["address"] == 'aws_route_table.target_east["a"]'
            )["values"]["route"][0]["nat_gateway_id"] = "nat-other"
            next(
                resource
                for resource in unbound_nat["planned_values"]["root_module"][
                    "resources"
                ]
                if resource["address"] == 'aws_route.target_default_east["a"]'
            )["values"]["nat_gateway_id"] = "nat-other"
            self.assertTrue(
                any(
                    "target route tables contain an inner route" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        unbound_nat,
                        config,
                        replace_address=address,
                        replace_instance_id=old_instance_id,
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )

            multiple_reflections = copy.deepcopy(reflected)
            route_table = next(
                resource
                for resource in multiple_reflections["planned_values"]["root_module"][
                    "resources"
                ]
                if resource["address"] == 'aws_route_table.target_east["a"]'
            )
            route_table["values"]["route"].append(
                copy.deepcopy(route_table["values"]["route"][0])
            )
            self.assertTrue(
                any(
                    "target route tables contain an inner route" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        multiple_reflections,
                        config,
                        replace_address=address,
                        replace_instance_id=old_instance_id,
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )

            wrong_attachment = copy.deepcopy(document)
            next(
                change
                for change in wrong_attachment["resource_changes"]
                if change["address"] == 'aws_lb_target_group_attachment.west["a"]'
            )["change"]["before"]["target_id"] = "i-1123456789abcdef0"
            self.assertTrue(
                any(
                    "attachment is not bound" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_attachment,
                        config,
                        replace_address=address,
                        replace_instance_id=old_instance_id,
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )

            wrong_identity = copy.deepcopy(document)
            self.assertTrue(
                any(
                    "exact authorized current target" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        wrong_identity,
                        config,
                        replace_address=address,
                        replace_instance_id="i-1123456789abcdef0",
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )
            collateral = copy.deepcopy(document)
            collateral["resource_changes"].append(
                {
                    "address": "aws_vpc.west",
                    "mode": "managed",
                    "change": {"actions": ["update"]},
                }
            )
            self.assertTrue(
                any(
                    "outside the authorized target" in failure
                    for failure in appliance.validate_symmetric_saved_plan(
                        collateral,
                        config,
                        replace_address=address,
                        replace_instance_id=old_instance_id,
                        replace_target_group_arn=target_group_arn,
                    )
                )
            )

    def test_expired_config_loads_only_for_recovery_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root, expired=True)
            self.assertLess(
                dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00")),
                dt.datetime.now(dt.timezone.utc),
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "new run"):
                appliance.RunConfig.load(config.path)

    def test_one_config_generates_tailnet_and_all_terraform_network_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            parameters = appliance.intended_ssm_parameters(config, "123456789012")
            values = appliance.terraform_variables(config, artifact, parameters)
            self.assertEqual(set(values), appliance.TERRAFORM_VARIABLE_FIELDS)
            self.assertEqual(values["symmetric_topology"]["sites"]["west"]["azs"], config.sites["west"]["azs"])
            self.assertEqual(config.raw["e2e_load_profile"], e2e_load_profile_document())
            self.assertEqual(values["e2e_load_profile"], config.raw["e2e_load_profile"])
            self.assertIsNot(values["e2e_load_profile"], config.raw["e2e_load_profile"])
            self.assertEqual(values["symmetric_topology"]["version"], 2)
            self.assertEqual(
                values["symmetric_topology"]["route_failover"],
                config_document()["symmetric_topology"]["route_failover"],
            )
            self.assertIsNot(
                values["symmetric_topology"]["route_failover"], config.route_failover
            )
            for site in ("west", "east"):
                topology = values["symmetric_topology"]["sites"][site]
                self.assertIn("transport_subnet_cidrs", topology)
                self.assertIn("transport_router_az_keys", topology)
                self.assertNotIn("ingress_subnet_cidrs", topology)
                self.assertNotIn("ingress_router_az_keys", topology)
            self.assertEqual(config.site_cidrs["west"], ["10.10.1.0/24", "10.10.2.0/24"])
            self.assertEqual(
                config.raw["cost"],
                {
                    "estimated_fixed_hourly_usd": 4.0,
                    "approved_max_fixed_hourly_usd": 5.0,
                },
            )
            self.assertEqual(
                config.raw["envelope"],
                {
                    "mode": "packet-return",
                    "udp_bind": "0.0.0.0:6081",
                    "max_inner_packet_size": 1280,
                },
            )
            self.assertFalse(
                {
                    "envelope_mode",
                    "envelope_udp_bind",
                    "envelope_max_inner_packet_size",
                    "envelope_routing_mode",
                    "envelope_tun_name",
                    "envelope_tailscale_iface",
                    "envelope_underlay_interface",
                    "envelope_routing_table_id",
                    "envelope_routing_rule_priority",
                    "ebs_root_volume_size",
                }.intersection(values)
            )

            document = config_document()
            document["tailnet"]["lane_cidrs"] = {"west": ["10.99.0.0/24"], "east": ["10.98.0.0/24"]}
            path = root / "duplicate.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)
            document = config_document()
            document["network_tfvars"] = "second-source.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)
            document = config_document()
            document["ebs_root_volume_size"] = 20
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)

    def test_route_failover_input_is_exact_bounded_and_same_az(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            valid = config_document()
            path = root / "route-failover.json"
            path.write_text(json.dumps(valid))
            config = appliance.RunConfig.load(path)
            self.assertEqual(
                appliance.terraform_variables(
                    config,
                    artifact_identity(root),
                    appliance.intended_ssm_parameters(config, "123456789012"),
                )["symmetric_topology"]["route_failover"],
                valid["symmetric_topology"]["route_failover"],
            )

            whole_number = config_document()
            whole_number["symmetric_topology"]["route_failover"][
                "mutation_timeout_seconds"
            ] = 1.0
            whole_number_path = root / "route-failover-whole-number.json"
            whole_number_path.write_text(json.dumps(whole_number))
            self.assertEqual(
                appliance.RunConfig.load(whole_number_path).route_failover[
                    "mutation_timeout_seconds"
                ],
                1,
            )

            cases = []
            missing = config_document()
            missing["symmetric_topology"].pop("route_failover")
            cases.append(("missing", missing))
            extra = config_document()
            extra["symmetric_topology"]["route_failover"]["legacy_timeout"] = 1
            cases.append(("extra", extra))
            missing_az = config_document()
            missing_az["symmetric_topology"]["route_failover"][
                "initial_transport_router_az_by_gwlbe_az"
            ]["west"].pop("b")
            cases.append(("missing AZ", missing_az))
            cross_site = config_document()
            cross_site["symmetric_topology"]["route_failover"][
                "initial_transport_router_az_by_gwlbe_az"
            ]["west"]["a"] = "east-a"
            cases.append(("cross-site AZ", cross_site))
            cross_az = config_document()
            cross_az["symmetric_topology"]["route_failover"][
                "initial_transport_router_az_by_gwlbe_az"
            ]["west"] = {"a": "b", "b": "a"}
            cases.append(("cross-AZ selection", cross_az))
            short_restoration = config_document()
            short_restoration["symmetric_topology"]["route_failover"][
                "restoration_timeout_seconds"
            ] = 1
            cases.append(("restoration quiet window", short_restoration))
            short_recovery = config_document()
            short_recovery["symmetric_topology"]["route_failover"][
                "recovery_timeout_seconds"
            ] = 10
            cases.append(("recovery quiet window", short_recovery))
            for field in (
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
            ):
                for value in (True, 0, 1.5, 7201):
                    invalid = config_document()
                    invalid["symmetric_topology"]["route_failover"][field] = value
                    cases.append((f"{field}={value!r}", invalid))

            for index, (name, document) in enumerate(cases):
                with self.subTest(name=name):
                    candidate = root / f"route-failover-{index}.json"
                    candidate.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, "route_failover"):
                        appliance.RunConfig.load(candidate)

    def test_config_rejects_ingress_era_topology_fields_without_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for current, obsolete in (
                ("transport_subnet_cidrs", "ingress_subnet_cidrs"),
                ("transport_router_az_keys", "ingress_router_az_keys"),
            ):
                with self.subTest(field=obsolete):
                    document = config_document()
                    site = document["symmetric_topology"]["sites"]["west"]
                    site[obsolete] = site.pop(current)
                    path = root / f"obsolete-{obsolete}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                        appliance.RunConfig.load(path)

    def test_cost_defaults_match_approved_ha_profile_and_reject_non_finite_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            self.assertEqual(config.raw["cost"]["estimated_fixed_hourly_usd"], 4.0)
            self.assertEqual(config.raw["cost"]["approved_max_fixed_hourly_usd"], 5.0)

            for index, value in enumerate((True, "4", float("nan"), float("inf"))):
                with self.subTest(value=value):
                    document = config_document()
                    document["cost"] = {
                        "estimated_fixed_hourly_usd": value,
                        "approved_max_fixed_hourly_usd": 5,
                    }
                    path = root / f"cost-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, "cost"):
                        appliance.RunConfig.load(path)

    def test_config_rejects_collapsed_route_domains_and_duplicate_fleet_azs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            collapsed = config_document()
            collapsed["symmetric_topology"]["sites"]["west"]["target_subnet_cidrs"]["a"] = (
                collapsed["symmetric_topology"]["sites"]["west"]["workload_subnet_cidrs"]["a"]
            )
            path = root / "collapsed.json"
            path.write_text(json.dumps(collapsed))
            with self.assertRaisesRegex(appliance.LifecycleError, "subnet role CIDRs must not overlap"):
                appliance.RunConfig.load(path)

            resolver_overlap = config_document()
            west = resolver_overlap["symmetric_topology"]["sites"]["west"]
            west["local_site_cidrs"][0] = "10.10.0.0/24"
            west["workload_subnet_cidrs"]["a"] = "10.10.0.0/24"
            path = root / "resolver-overlap.json"
            path.write_text(json.dumps(resolver_overlap))
            with self.assertRaisesRegex(appliance.LifecycleError, "VPC DNS resolver"):
                appliance.RunConfig.load(path)

            for field in ("target_az_keys", "transport_router_az_keys"):
                with self.subTest(field=field):
                    duplicate_az = config_document()
                    duplicate_az["symmetric_topology"]["sites"]["west"][field] = [
                        "a",
                        "a",
                        "b",
                    ]
                    path = root / f"duplicate-{field}.json"
                    path.write_text(json.dumps(duplicate_az))
                    with self.assertRaisesRegex(
                        appliance.LifecycleError, "fleets must cover every AZ"
                    ):
                        appliance.RunConfig.load(path)

    def test_packet_return_envelope_is_required_exact_and_has_no_legacy_v2_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            cases = []
            missing_object = config_document()
            missing_object.pop("envelope")
            cases.append(("missing object", missing_object, "required version-2 packet-return object"))
            missing_field = config_document()
            missing_field["envelope"].pop("udp_bind")
            cases.append(("missing field", missing_field, "contain exactly"))
            for field in (
                "routing_mode",
                "tun_name",
                "tailscale_iface",
                "underlay_interface",
                "routing_table_id",
                "routing_rule_priority",
                "local_site_cidrs",
                "remote_site_cidrs",
            ):
                legacy = config_document()
                legacy["envelope"][field] = "obsolete"
                cases.append((field, legacy, "unsupported fields"))
            for field, value in (
                ("mode", "manage"),
                ("udp_bind", "127.0.0.1:6081"),
                ("max_inner_packet_size", 1279),
                ("max_inner_packet_size", True),
            ):
                wrong_value = config_document()
                wrong_value["envelope"][field] = value
                cases.append((f"{field}={value}", wrong_value, re.escape(f"envelope.{field}")))

            for index, (name, document, message) in enumerate(cases):
                with self.subTest(name=name):
                    path = root / f"envelope-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, message):
                        appliance.RunConfig.load(path)

    def test_e2e_load_profile_is_required_and_has_an_exact_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            cases = []
            missing_object = config_document()
            missing_object.pop("e2e_load_profile")
            cases.append(("missing object", missing_object, "required object"))
            missing_field = config_document()
            missing_field["e2e_load_profile"].pop("maximum_p99_latency_ms")
            cases.append(("missing field", missing_field, "every required"))
            unsupported = config_document()
            unsupported["e2e_load_profile"]["invented_threshold"] = 1
            cases.append(("unsupported field", unsupported, "unsupported fields"))
            invalid_id = config_document()
            invalid_id["e2e_load_profile"]["profile_id"] = "invalid profile"
            cases.append(("invalid profile id", invalid_id, "profile_id"))

            for index, (name, document, message) in enumerate(cases):
                with self.subTest(name=name):
                    path = root / f"shape-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, message):
                        appliance.RunConfig.load(path)

    def test_e2e_load_profile_rejects_bool_nonfinite_and_out_of_bounds_values(self):
        invalid_values = (
            ("safe_inner_mtu", True),
            ("safe_inner_mtu", 1279),
            ("maximum_tcp_mss", 535),
            ("maximum_tcp_mss", 1241),
            ("sustained_tcp_duration_seconds", 2),
            ("sustained_tcp_duration_seconds", 121),
            ("minimum_sustained_tcp_bytes", 0),
            ("minimum_sustained_tcp_bytes", 1_000_000_001),
            ("iperf_duration_seconds", 2),
            ("iperf_duration_seconds", 121),
            ("concurrent_duration_seconds", 2),
            ("concurrent_duration_seconds", 121),
            ("concurrent_tcp_flows", 0),
            ("concurrent_tcp_flows", 33),
            ("concurrent_udp_flows", 0),
            ("concurrent_udp_flows", 33),
            ("minimum_throughput_mbps", True),
            ("minimum_throughput_mbps", float("nan")),
            ("minimum_throughput_mbps", 0.0009),
            ("minimum_throughput_mbps", 100_000.1),
            ("maximum_udp_loss_percent", float("inf")),
            ("maximum_udp_loss_percent", -0.1),
            ("maximum_udp_loss_percent", 100.1),
            ("maximum_p99_latency_ms", float("-inf")),
            ("maximum_p99_latency_ms", 0.0),
            ("maximum_p99_latency_ms", 60_000.1),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, (field, value) in enumerate(invalid_values):
                with self.subTest(field=field, value=value):
                    document = config_document()
                    document["e2e_load_profile"][field] = value
                    path = root / f"bound-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, re.escape(f"e2e_load_profile.{field}")):
                        appliance.RunConfig.load(path)

    def test_e2e_load_profile_accepts_inclusive_minimum_and_maximum_bounds(self):
        profiles = []
        minimums = e2e_load_profile_document()
        minimums.update(
            {
                "maximum_tcp_mss": 536,
                "minimum_sustained_tcp_bytes": 1,
                "minimum_throughput_mbps": 0.001,
                "concurrent_tcp_flows": 1,
                "concurrent_udp_flows": 1,
                "maximum_udp_loss_percent": 0.0,
                "maximum_p99_latency_ms": 0.001,
            }
        )
        profiles.append(minimums)
        maximums = e2e_load_profile_document()
        maximums.update(
            {
                "sustained_tcp_duration_seconds": 120,
                "minimum_sustained_tcp_bytes": 1_000_000_000,
                "iperf_duration_seconds": 120,
                "minimum_throughput_mbps": 100_000.0,
                "concurrent_duration_seconds": 120,
                "concurrent_tcp_flows": 32,
                "concurrent_udp_flows": 32,
                "maximum_udp_loss_percent": 100.0,
                "maximum_p99_latency_ms": 60_000.0,
            }
        )
        profiles.append(maximums)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, profile in enumerate(profiles):
                with self.subTest(index=index):
                    document = config_document()
                    document["e2e_load_profile"] = profile
                    path = root / f"inclusive-{index}.json"
                    path.write_text(json.dumps(document))
                    loaded = appliance.RunConfig.load(path)
                    self.assertEqual(loaded.raw["e2e_load_profile"], profile)

    def test_e2e_load_profile_approval_is_canonical_and_precedes_new_run_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, approved_at in enumerate(
                (
                    "2020-01-01T00:00:00+00:00",
                    "2020-01-01 00:00:00Z",
                    "2020-01-01T00:00:00.000Z",
                )
            ):
                with self.subTest(approved_at=approved_at):
                    document = config_document()
                    document["e2e_load_profile"]["approved_at"] = approved_at
                    path = root / f"timestamp-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, "canonical UTC RFC3339 ending Z"):
                        appliance.RunConfig.load(path)

            future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
            document = config_document()
            document["e2e_load_profile"]["approved_at"] = future
            path = root / "future.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "must not be later"):
                appliance.RunConfig.load(path)
            recovered = appliance.RunConfig.load(path, enforce_future_expiry=False)
            self.assertEqual(recovered.raw["e2e_load_profile"]["approved_at"], future)

    def test_e2e_load_profile_is_bound_to_config_manifest_and_runtime_variables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            original_document = config_document()
            original_path = root / "original.json"
            original_path.write_text(json.dumps(original_document))
            original = appliance.RunConfig.load(original_path)

            changed_document = copy.deepcopy(original_document)
            changed_document["e2e_load_profile"]["profile_id"] = "fixture-load-v2"
            changed_path = root / "changed.json"
            changed_path.write_text(json.dumps(changed_document))
            changed = appliance.RunConfig.load(changed_path)
            self.assertNotEqual(original.config_identity, changed.config_identity)

            artifact = artifact_identity(root)
            manifest = appliance.new_manifest(original, artifact, "123456789012")
            with self.assertRaisesRegex(appliance.LifecycleError, "configuration identity"):
                appliance.validate_manifest(manifest, changed)

            tampered = copy.deepcopy(manifest)
            tampered["terraform_variables"]["e2e_load_profile"]["concurrent_tcp_flows"] = 3
            with self.assertRaisesRegex(appliance.LifecycleError, "load profile differs"):
                appliance.validate_manifest(tampered, original)
            self.assertEqual(original.raw["e2e_load_profile"]["concurrent_tcp_flows"], 2)
            store = appliance.ManifestStore(original, BackendAWS(original), root / "run")
            with self.assertRaisesRegex(appliance.LifecycleError, "durable Terraform variable set"):
                appliance.write_runtime_variables(original, store, tampered, artifact)

    def test_relative_artifact_is_resolved_before_cwd_changes(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as other:
            root = pathlib.Path(temporary)
            document = config_document()
            document["artifact_manifest"] = "../artifacts/manifest.json"
            config_path = root / "config" / "run.json"
            config_path.parent.mkdir()
            config_path.write_text(json.dumps(document))
            artifact_dir = root / "artifacts"
            artifact_dir.mkdir()
            binary = artifact_dir / "envelope-linux-amd64"
            binary.write_bytes(b"fixture-go-elf")
            manifest = {
                "schema": 1,
                "version": "fixture.1",
                "revision": "b" * 40,
                "source_dirty": False,
                "go_version": "go1.26.2",
                "artifacts": [
                    {
                        "architecture": "amd64",
                        "ec2_architecture": "x86_64",
                        "file": binary.name,
                        "goos": "linux",
                        "goarch": "amd64",
                        "go_version": "go1.26.2",
                        "vcs_revision": "b" * 40,
                        "vcs_modified": False,
                        "version": "fixture.1",
                        "sha256": "a" * 64,
                    }
                ],
            }
            (artifact_dir / "manifest.json").write_text(json.dumps(manifest))
            config = appliance.RunConfig.load(config_path)
            old_cwd = pathlib.Path.cwd()
            try:
                os.chdir(other)
                with mock.patch.object(
                    appliance,
                    "inspect_artifact",
                    return_value={
                        "architecture": "amd64",
                        "sha256": "a" * 64,
                        "go_version": "go1.26.2",
                        "goos": "linux",
                        "goarch": "amd64",
                        "vcs_revision": "b" * 40,
                        "vcs_modified": False,
                    },
                ):
                    selected = appliance.validate_artifact(config)
                    variables = appliance.terraform_variables(
                        config,
                        selected,
                        appliance.intended_ssm_parameters(config, "123456789012"),
                    )
            finally:
                os.chdir(old_cwd)
            self.assertTrue(pathlib.Path(selected["path"]).is_absolute())
            self.assertEqual(pathlib.Path(selected["path"]), binary.resolve())
            self.assertEqual(pathlib.Path(variables["artifact_path"]), binary.resolve())

    def test_relative_runner_paths_and_oauth_environment_are_normalized(self):
        class CaptureRunner:
            def __init__(self):
                self.calls = []

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            run_dir = root / "relative-run"
            terraform_dir = root / "relative-terraform"
            terraform_dir.mkdir()
            run_dir.mkdir()
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            appliance.ManifestStore(config, BackendAWS(config), run_dir).write(manifest, upload=False)
            runner = CaptureRunner()
            old_cwd = pathlib.Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.dict(
                    os.environ,
                    {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
                ):
                    backend_file = appliance.terraform_init(
                        config,
                        BackendAWS(config),
                        runner,
                        pathlib.Path("relative-run"),
                        pathlib.Path("relative-terraform"),
                    )
            finally:
                os.chdir(old_cwd)
            args, env, cwd = runner.calls[0]
            self.assertTrue(backend_file.is_absolute())
            self.assertTrue(pathlib.Path(env["TF_DATA_DIR"]).is_absolute())
            self.assertTrue(cwd.is_absolute())
            self.assertIn(f"-backend-config={backend_file}", args)
            self.assertNotIn("TS_OAUTH_CLIENT_ID", env)
            self.assertNotIn("TS_OAUTH_CLIENT_SECRET", env)
            with mock.patch.dict(
                os.environ,
                {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
            ):
                appliance.AwsCLI(runner, config.oauth_environment_names).call(["sts", "get-caller-identity"])
            aws_env = runner.calls[-1][1]
            self.assertNotIn("TS_OAUTH_CLIENT_ID", aws_env)
            self.assertNotIn("TS_OAUTH_CLIENT_SECRET", aws_env)

    def test_subprocess_runner_strips_configured_oauth_names_defensively(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = ("", "")
        with mock.patch.dict(os.environ, {"CUSTOM_TS_ID": "id", "CUSTOM_TS_SECRET": "secret"}), mock.patch(
            "subprocess.Popen", return_value=process
        ) as popen:
            appliance.SubprocessRunner(("CUSTOM_TS_ID", "CUSTOM_TS_SECRET")).run(["fixture"])
        child_env = popen.call_args.kwargs["env"]
        self.assertNotIn("CUSTOM_TS_ID", child_env)
        self.assertNotIn("CUSTOM_TS_SECRET", child_env)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_subprocess_timeout_kills_the_process_group_and_reaps_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "orphan-ran"
            child = (
                "import pathlib,time; time.sleep(.3); "
                f"pathlib.Path({str(marker)!r}).write_text('orphan')"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(30)"
            )
            started = time.monotonic()
            with self.assertRaises(appliance.CommandTimeoutError):
                appliance.SubprocessRunner().run(
                    [sys.executable, "-c", parent], timeout_seconds=0.05
                )
            self.assertLess(time.monotonic() - started, 2)
            time.sleep(0.4)
            self.assertFalse(marker.exists())

    def test_aws_text_and_json_timeouts_are_native_with_explicit_fake_adapter(self):
        class TimeoutRunner:
            def __init__(self):
                self.timeouts = []

            def run(
                self,
                args,
                *,
                env=None,
                cwd=None,
                input_text=None,
                timeout_seconds=None,
            ):
                self.timeouts.append(timeout_seconds)
                return '{"Account":"123456789012"}'

        native = TimeoutRunner()
        aws = appliance.AwsCLI(native)
        self.assertEqual(
            aws.json(["sts", "get-caller-identity"], timeout_seconds=2)["Account"],
            "123456789012",
        )
        self.assertEqual(
            json.loads(aws.text(["sts", "get-caller-identity"], timeout=2))["Account"],
            "123456789012",
        )
        self.assertEqual(len(native.timeouts), 2)
        self.assertTrue(all(0 < value <= 2 for value in native.timeouts))

        class ImmediateFake:
            def __init__(self):
                self.calls = 0

            def run(self, args, *, env=None, cwd=None, input_text=None):
                self.calls += 1
                return '{"Account":"123456789012"}'

        immediate = ImmediateFake()
        adapted = appliance.AwsCLI(appliance.ImmediateCommandRunnerAdapter(immediate))
        self.assertEqual(
            adapted.json(["sts", "get-caller-identity"], timeout_seconds=1)["Account"],
            "123456789012",
        )
        self.assertEqual(immediate.calls, 1)

    def test_aws_cli_retries_only_explicit_signature_expiry_once(self):
        class ExpiredOnceRunner:
            def __init__(self):
                self.calls = 0

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls += 1
                if inner.calls == 1:
                    raise appliance.CommandError(
                        args,
                        254,
                        "An error occurred (InvalidSignatureException): Signature expired: fixture",
                    )
                return '{"Account":"123456789012"}'

        runner = ExpiredOnceRunner()
        self.assertEqual(appliance.AwsCLI(runner).json(["sts", "get-caller-identity"])["Account"], "123456789012")
        self.assertEqual(runner.calls, 2)

        class OtherFailureRunner:
            def __init__(self):
                self.calls = 0

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls += 1
                raise appliance.CommandError(args, 254, "An error occurred (AccessDeniedException): denied")

        runner = OtherFailureRunner()
        with self.assertRaises(appliance.CommandError):
            appliance.AwsCLI(runner).call(["sts", "get-caller-identity"])
        self.assertEqual(runner.calls, 1)

    def test_terraform_source_snapshot_is_exactly_materialized_from_artifact_revision(self):
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = pathlib.Path(temporary) / "run"
            snapshot, identity = appliance.materialize_reviewed_terraform_source(
                appliance.SubprocessRunner(), ROOT / "example/terraform", run_dir, revision
            )
            expected = subprocess.run(
                ["git", "show", f"{revision}:example/terraform/topology.tf"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            self.assertEqual((snapshot / "topology.tf").read_text(), expected)
            self.assertEqual(
                stat.S_IMODE((snapshot / "cloud-init" / "envelope-e2e-agent.py").stat().st_mode),
                0o700,
            )
            self.assertFalse((snapshot / ".terraform").exists())
            self.assertEqual(identity["revision"], revision)
            self.assertEqual(identity["repository_path"], "example/terraform")
            self.assertEqual(identity["sha256"], appliance.terraform_source_digest(snapshot))
            baseline = identity["sha256"]
            source_record = appliance.terraform_source_record(snapshot, identity)
            restored, restored_identity = appliance.materialize_durable_terraform_source(source_record, run_dir)
            self.assertEqual(restored_identity, identity)
            self.assertEqual(appliance.terraform_source_digest(restored), baseline)
            topology = restored / "topology.tf"
            original = topology.read_text()
            topology.write_text(
                original.replace(
                    "target_id        = each.value.id",
                    'target_id        = format("%s-unexpected", each.value.id)',
                    1,
                )
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "direct regional target"):
                appliance.validate_terraform_source_contract(restored)
            west_block = '''resource "aws_lb_target_group_attachment" "west" {
  for_each         = aws_instance.envelope_target_west
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = each.value.id
}'''
            commented_bypass = original.replace(
                west_block,
                f'''/*
{west_block}
*/
resource /* separator */ "aws_lb_target_group_attachment" "west" {{
  for_each         = aws_instance.envelope_target_west
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = format("%s-unexpected", each.value.id)
}}''',
            )
            topology.write_text(commented_bypass)
            with self.assertRaisesRegex(appliance.LifecycleError, "direct regional target"):
                appliance.validate_terraform_source_contract(restored)
            topology.write_text("locals { fixture = <<-EOT\n" + west_block + "\nEOT\n}\n" + original)
            with self.assertRaisesRegex(appliance.LifecycleError, "heredoc"):
                appliance.validate_terraform_source_contract(restored)
            topology.write_text(original)
            (restored / "override.tf").write_text('resource "terraform_data" "unexpected" {}\n')
            self.assertNotEqual(appliance.terraform_source_digest(restored), baseline)
            with self.assertRaisesRegex(appliance.LifecycleError, "override"):
                appliance.validate_terraform_source_contract(restored)
            (restored / "override.tf").unlink()
            (restored / "unsafe.tf").symlink_to(restored / "topology.tf")
            with self.assertRaisesRegex(appliance.LifecycleError, "symlink"):
                appliance.terraform_source_digest(restored)

    def test_apply_boundary_is_durable_before_the_terraform_child_runs(self):
        class ManifestAWS:
            def __init__(self):
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0
                self.manifests = []
                self.fail_after_phases = set()

            def json(self, args, *, region=None):
                if args[1] == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != self.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    payload = json.loads(self.remote)
                    self.manifests.append(payload)
                    self.version += 1
                    self.etag = f'"manifest-{self.version}"'
                    if payload.get("phase") in self.fail_after_phases:
                        self.fail_after_phases.remove(payload.get("phase"))
                        raise appliance.LifecycleError("injected response loss after durable manifest write")
                    return {"ETag": self.etag}
                if args[1] == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                raise AssertionError(args)

        class FailingRunner:
            def __init__(self):
                self.calls = []

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                if len(args) > 1 and args[1] == "apply":
                    raise appliance.LifecycleError("injected runner loss after apply boundary")
                return ""

        class SuccessRunner:
            def __init__(self):
                self.calls = []

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                if len(args) > 1 and args[1] == "output":
                    return json.dumps(symmetric_deployment_document(config))
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            terraform_dir = root / "terraform"
            terraform_dir.mkdir()
            config = make_config(root)
            aws = ManifestAWS()
            store = appliance.ManifestStore(config, aws, root / "run")
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            plan = store.run_dir / "apply.tfplan"
            store.run_dir.mkdir(parents=True)
            plan.write_bytes(b"reviewed-plan")
            source_identity = {
                "revision": manifest["artifact"]["revision"],
                "repository_path": "example/terraform",
                "sha256": "b" * 64,
            }
            manifest["saved_plan"] = {
                "path": str(plan.resolve()),
                "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                "replacement": None,
                "source": source_identity,
                "apply_started": False,
                "applied": False,
            }
            manifest["terraform_source"] = source_identity
            manifest["phase"] = "planned"
            store.write(manifest)
            runner = FailingRunner()
            with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.object(
                appliance,
                "materialize_durable_terraform_source",
                return_value=(terraform_dir, source_identity),
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "runner loss"):
                    appliance.terraform_apply(config, aws, runner, store.run_dir, terraform_dir, plan)
            persisted = store.load_local()
            self.assertEqual(persisted["phase"], "apply_failed")
            self.assertTrue(persisted["tailnet"]["nodes_expected"])
            self.assertTrue(persisted["saved_plan"]["apply_started"])
            self.assertNotIn("apply_claimed_at", persisted)
            self.assertNotIn("applied_at", persisted["saved_plan"])
            with mock.patch.object(
                appliance,
                "materialize_durable_terraform_source",
                return_value=(terraform_dir, source_identity),
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "exactly once"):
                    appliance.terraform_apply(config, aws, runner, store.run_dir, terraform_dir, plan)

            success_aws = ManifestAWS()
            success_aws.fail_after_phases = {"apply_claimed", "applied"}
            success_store = appliance.ManifestStore(config, success_aws, root / "success-run")
            success_plan = success_store.run_dir / "apply.tfplan"
            success_store.run_dir.mkdir(parents=True)
            success_plan.write_bytes(b"reviewed-plan")
            success_manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            success_manifest["saved_plan"] = {
                "path": str(success_plan.resolve()),
                "sha256": hashlib.sha256(success_plan.read_bytes()).hexdigest(),
                "replacement": None,
                "source": source_identity,
                "apply_started": False,
                "applied": False,
            }
            success_manifest["terraform_source"] = source_identity
            success_manifest["phase"] = "planned"
            success_store.write(success_manifest)
            with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.object(
                appliance,
                "materialize_durable_terraform_source",
                return_value=(terraform_dir, source_identity),
            ):
                appliance.terraform_apply(
                    config,
                    success_aws,
                    SuccessRunner(),
                    success_store.run_dir,
                    terraform_dir,
                    success_plan,
                )
            successful = success_store.load_local()
            claimed = next(value for value in success_aws.manifests if value["phase"] == "apply_claimed")
            self.assertRegex(claimed["apply_claim_id"], appliance.OPERATION_CLAIM_ID_RE)
            self.assertEqual(successful["phase"], "applied")
            self.assertTrue(successful["saved_plan"]["applied"])
            self.assertEqual(successful["saved_plan"]["applied_at"], claimed["apply_claimed_at"])
            self.assertNotIn("apply_claimed_at", successful)
            self.assertNotIn("apply_claim_id", successful)

            replacement_aws = ManifestAWS()
            replacement_store = appliance.ManifestStore(config, replacement_aws, root / "replacement-run")
            replacement_plan = replacement_store.run_dir / "replace.tfplan"
            replacement_store.run_dir.mkdir(parents=True)
            replacement_plan.write_bytes(b"reviewed-replacement-plan")
            replacement_manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            transport_ids = {
                str(device["hostname"]): str(device["id"])
                for device in fixture_tailnet_devices()
            }
            replacement_manifest["tailnet"]["nodes_expected"] = True
            replacement_manifest["tailnet"]["device_ids"] = transport_ids
            replacement_manifest["saved_plan"] = {
                "path": str(replacement_plan.resolve()),
                "sha256": hashlib.sha256(replacement_plan.read_bytes()).hexdigest(),
                "replacement": 'aws_instance.envelope_target_west["a"]',
                "replacement_instance_id": "i-0123456789abcdef0",
                "source": source_identity,
                "apply_started": False,
                "applied": False,
            }
            replacement_manifest["terraform_source"] = source_identity
            replacement_manifest["phase"] = "replacement_planned"
            replacement_store.write(replacement_manifest)
            target_tailnet_factory = mock.Mock(
                side_effect=AssertionError("target replacement touched Tailnet lifecycle")
            )
            with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.object(
                appliance,
                "materialize_durable_terraform_source",
                return_value=(terraform_dir, source_identity),
            ):
                appliance.terraform_apply(
                    config,
                    replacement_aws,
                    SuccessRunner(),
                    replacement_store.run_dir,
                    terraform_dir,
                    replacement_plan,
                    tailscale_factory=target_tailnet_factory,
                )
            replaced = replacement_store.load_local()
            target_tailnet_factory.assert_not_called()
            self.assertEqual(replaced["tailnet"]["device_ids"], transport_ids)
            self.assertFalse(
                any(
                    "replacement_device" in str(value.get("phase", ""))
                    for value in replacement_aws.manifests
                )
            )

    def test_no_drift_runner_uses_durable_inputs_and_maps_exit_two_to_drift(self):
        class CaptureRunner:
            def __init__(self, drift=False):
                self.calls = []
                self.drift = drift

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                if len(args) > 1 and args[1] == "plan" and inner.drift:
                    raise appliance.CommandError(args, 2, "fixture drift")
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            terraform_dir = root / "terraform"
            terraform_dir.mkdir()
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            source_identity = {
                "revision": manifest["artifact"]["revision"],
                "repository_path": "example/terraform",
                "sha256": "b" * 64,
            }
            manifest["terraform_source"] = source_identity
            store.write(manifest, upload=False)
            for drift in (False, True):
                with self.subTest(drift=drift):
                    runner = CaptureRunner(drift)
                    with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.object(
                        appliance, "artifact_for_recovery", return_value=artifact_identity(root)
                    ), mock.patch.object(
                        appliance,
                        "materialize_durable_terraform_source",
                        return_value=(terraform_dir, source_identity),
                    ), mock.patch.dict(
                        os.environ,
                        {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
                    ):
                        if drift:
                            with self.assertRaisesRegex(appliance.LifecycleError, "detected Terraform changes"):
                                appliance.terraform_verify_no_drift(
                                    config, BackendAWS(config), runner, store.run_dir, terraform_dir
                                )
                        else:
                            appliance.terraform_verify_no_drift(
                                config, BackendAWS(config), runner, store.run_dir, terraform_dir
                            )
                    plan_args, plan_env, plan_cwd = next(
                        call for call in runner.calls if len(call[0]) > 1 and call[0][1] == "plan"
                    )
                    self.assertIn("-detailed-exitcode", plan_args)
                    variable_arg = next(value for value in plan_args if value.startswith("-var-file="))
                    self.assertTrue(pathlib.Path(variable_arg.split("=", 1)[1]).is_absolute())
                    self.assertTrue(plan_cwd.is_absolute())
                    self.assertNotIn("TS_OAUTH_CLIENT_ID", plan_env)
                    self.assertNotIn("TS_OAUTH_CLIENT_SECRET", plan_env)


class FakeHTTP:
    def __init__(self, policy: dict | None = None):
        self.policy = policy or VALID_POLICY
        self.requests: list[tuple[str, str, bytes | None]] = []
        self.devices = {"devices": []}
        self.urls: list[str] = []

    def request(self, method: str, url: str, *, headers=None, body=None):
        self.urls.append(url)
        path = urllib.parse.urlparse(url).path
        self.requests.append((method, path, body))
        if path.endswith("/oauth/token"):
            return 200, json.dumps({"access_token": "fixture-bearer", "expires_in": 3600}).encode()
        if path.endswith("/acl"):
            return 200, json.dumps(self.policy).encode()
        if path.endswith("/devices") and method == "GET":
            return 200, json.dumps(self.devices).encode()
        if path.endswith("/keys") and method == "POST":
            return 200, json.dumps({"id": "key-fixture-id", "key": "fixture-auth-material"}).encode()
        if path.endswith("/keys") and method == "GET":
            return 200, b'{"keys":[]}'
        if method == "DELETE":
            return 200, b"{}"
        return 404, b'{"message":"fixture route missing"}'


class BackendAWS:
    def __init__(self, config: appliance.RunConfig):
        self.config = config
        self.versioning = "Enabled"
        self.algorithm = "aws:kms"
        self.key = config.backend["kms_key_arn"]
        self.bucket_key_enabled = True
        self.public = True
        self.existing: set[str] = set()
        self.versions: dict[str, list[dict[str, str]]] = {}
        self.policy_public = False
        self.key_enabled = True
        self.key_manager = "CUSTOMER"
        principal = config.backend["operator_principal_arns"][0]
        bucket_arn = f"arn:aws:s3:::{config.backend['bucket']}"
        object_actions = {
            f"{bucket_arn}/{config.backend['state_key']}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObjectVersion",
            ],
            f"{bucket_arn}/{config.lock_key}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
            ],
            f"{bucket_arn}/{config.manifest_key}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectTagging",
                "s3:DeleteObjectVersion",
            ],
        }
        self.bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": list(appliance.BACKEND_BUCKET_ACTIONS),
                    "Resource": bucket_arn,
                },
                *[
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": principal},
                        "Action": actions,
                        "Resource": object_arn,
                    }
                    for object_arn, actions in object_actions.items()
                ],
            ],
        }
        self.key_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": list(appliance.BACKEND_KMS_ACTIONS),
                    "Resource": "*",
                }
            ],
        }

    def json(self, args, *, region=None):
        operation = args[1]
        if operation == "head-bucket":
            return {}
        if operation == "get-bucket-location":
            return {"LocationConstraint": self.config.backend["region"]}
        if operation == "get-bucket-versioning":
            return {"Status": self.versioning}
        if operation == "get-bucket-encryption":
            rule = {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": self.algorithm,
                    "KMSMasterKeyID": self.key,
                },
            }
            if hasattr(self, "bucket_key_enabled"):
                rule["BucketKeyEnabled"] = self.bucket_key_enabled
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [rule]
                }
            }
        if operation == "get-public-access-block":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": self.public,
                    "IgnorePublicAcls": self.public,
                    "BlockPublicPolicy": self.public,
                    "RestrictPublicBuckets": self.public,
                }
            }
        if operation == "get-bucket-policy-status":
            return {"PolicyStatus": {"IsPublic": self.policy_public}}
        if operation == "get-bucket-policy":
            return {"Policy": json.dumps(self.bucket_policy)}
        if operation == "describe-key":
            return {
                "KeyMetadata": {
                    "Arn": self.key,
                    "Enabled": self.key_enabled,
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyManager": self.key_manager,
                }
            }
        if operation == "get-key-policy":
            return {"Policy": json.dumps(self.key_policy)}
        if operation == "list-object-versions":
            key = args[args.index("--prefix") + 1]
            return {"Versions": self.versions.get(key, []), "DeleteMarkers": []}
        if operation == "put-object":
            return {"VersionId": "manifest-version"}
        raise AssertionError(args)

    def object_exists(self, bucket, key, region):
        return key in self.existing


class MetadataAWS:
    def __init__(self, config: appliance.RunConfig):
        self.config = config
        self.expected = appliance.ARCHITECTURES[config.architecture]
        self.image_overrides: dict[str, object] = {}
        self.type_architectures = [self.expected]

    def json(self, args, *, region=None):
        operation = args[1]
        if operation == "describe-images":
            image_id = args[3]
            image = {
                "ImageId": image_id,
                "Architecture": self.expected,
                "State": "available",
                "RootDeviceType": "ebs",
                "VirtualizationType": "hvm",
                "Name": "al2023-ami-2023.8.20260818.0-kernel-6.1-x86_64",
            }
            image.update(self.image_overrides)
            return {"Images": [image]}
        if operation == "describe-instance-types":
            return {
                "InstanceTypes": [
                    {
                        "InstanceType": selected,
                        "ProcessorInfo": {"SupportedArchitectures": self.type_architectures},
                        "VCpuInfo": {"DefaultVCpus": 2},
                    }
                    for selected in args[3:]
                ]
            }
        raise AssertionError(args)


class CapabilityAWS:
    def __init__(self, config: appliance.RunConfig):
        self.config = config
        self.denied_action: str | None = None
        self.denied_decision = "implicitDeny"
        self.denied_resource: str | None = None
        self.low_quota_gate: str | None = None
        self.low_account_limit_gate: str | None = None
        self.omitted_quota_gate: str | None = None
        self.malformed_quota_schema = False
        self.runtime_kms_decision = "allowed"
        self.calls: list[tuple[list[str], str | None]] = []
        self.role_name = "AWSReservedSSO_Envelope_fixture"
        self.role_arn = (
            "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/"
            + self.role_name
        )

    def json(self, args, *, region=None):
        self.calls.append((list(args), region))
        service, operation = args[:2]
        if service == "sts" and operation == "get-caller-identity":
            return {
                "Account": "123456789012",
                "Arn": f"arn:aws:sts::123456789012:assumed-role/{self.role_name}/fixture-session",
                "UserId": "AROAEXAMPLE:fixture-session",
            }
        if service == "iam" and operation == "get-role":
            return {"Role": {"RoleName": self.role_name, "Arn": self.role_arn}}
        if service == "iam" and operation == "simulate-custom-policy":
            action = args[args.index("--action-names") + 1]
            resource = args[args.index("--resource-arns") + 1]
            return {
                "EvaluationResults": [
                    {
                        "EvalActionName": action,
                        "EvalDecision": self.runtime_kms_decision,
                        "ResourceSpecificResults": [
                            {
                                "EvalResourceName": resource,
                                "EvalResourceDecision": self.runtime_kms_decision,
                            }
                        ],
                    }
                ],
                "IsTruncated": False,
            }
        if service == "iam" and operation == "simulate-principal-policy":
            start = args.index("--action-names") + 1
            end = args.index("--resource-arns")
            resource_start = end + 1
            resource_end = args.index("--context-entries") if "--context-entries" in args else len(args)
            resources = args[resource_start:resource_end]
            return {
                "EvaluationResults": [
                    {
                        "EvalActionName": action,
                        "EvalDecision": (
                            self.denied_decision
                            if action == self.denied_action and self.denied_resource is None
                            else "allowed"
                        ),
                        "ResourceSpecificResults": [
                            {
                                "EvalResourceName": resource,
                                "EvalResourceDecision": (
                                    self.denied_decision
                                    if action == self.denied_action
                                    and (self.denied_resource is None or resource == self.denied_resource)
                                    else "allowed"
                                ),
                            }
                            for resource in resources
                        ],
                    }
                    for action in args[start:end]
                ],
                "IsTruncated": False,
            }
        if service == "iam" and operation == "get-account-summary":
            return {
                "SummaryMap": {
                    "Roles": 10,
                    "RolesQuota": 100,
                    "InstanceProfiles": 8,
                    "InstanceProfilesQuota": 100,
                }
            }
        if service == "service-quotas" and operation == "get-service-quota":
            if self.malformed_quota_schema:
                return {"Quota": []}
            requested_service = args[args.index("--service-code") + 1]
            requested_code = args[args.index("--quota-code") + 1]
            contracts = {
                **appliance.AWS_REGIONAL_QUOTA_CONTRACT,
                **appliance.AWS_GLOBAL_QUOTA_CONTRACT,
            }
            matches = [
                (gate, quota_service, code, name)
                for gate, (quota_service, code, name) in contracts.items()
                if quota_service == requested_service and code == requested_code
            ]
            if len(matches) != 1:
                raise AssertionError((args, matches))
            gate, quota_service, code, name = matches[0]
            if gate == self.omitted_quota_gate:
                return {}
            global_quota = gate in appliance.AWS_GLOBAL_QUOTA_CONTRACT
            quota_arn_region = "" if global_quota else region
            return {
                "Quota": {
                    "ServiceCode": quota_service,
                    "QuotaName": name,
                    "QuotaCode": code,
                    "QuotaArn": (
                        f"arn:{self.role_arn.split(':', 2)[1]}:servicequotas:{quota_arn_region}:"
                        f"123456789012:{quota_service}/{code}"
                    ),
                    "Value": 0 if gate == self.low_quota_gate else 100,
                    "GlobalQuota": global_quota,
                }
            }
        if service == "ec2" and operation in {
            "describe-vpcs",
            "describe-subnets",
            "describe-security-groups",
            "run-instances",
        }:
            site = next(
                site
                for site in ("west", "east")
                if self.config.sites[site]["region"] == region
            )
            identities = {
                "west": {
                    "vpc": "vpc-11111111111111111",
                    "subnet": "subnet-22222222222222222",
                    "security_group": "sg-33333333333333333",
                },
                "east": {
                    "vpc": "vpc-aaaaaaaaaaaaaaaaa",
                    "subnet": "subnet-bbbbbbbbbbbbbbbbb",
                    "security_group": "sg-ccccccccccccccccc",
                },
            }[site]
            if operation == "describe-vpcs" and "Name=is-default,Values=true" in args:
                return {"Vpcs": [{"VpcId": identities["vpc"], "IsDefault": True}]}
            if operation == "describe-subnets":
                zone = next(iter(self.config.sites[site]["azs"].values()))
                return {
                    "Subnets": [
                        {
                            "SubnetId": identities["subnet"],
                            "VpcId": identities["vpc"],
                            "AvailabilityZone": zone,
                            "DefaultForAz": True,
                        }
                    ]
                }
            if operation == "describe-security-groups":
                return {
                    "SecurityGroups": [
                        {
                            "GroupId": identities["security_group"],
                            "VpcId": identities["vpc"],
                            "GroupName": "default",
                        }
                    ]
                }
            if operation == "run-instances":
                raise appliance.CommandError(
                    args,
                    255,
                    "An error occurred (DryRunOperation) when calling the RunInstances operation: "
                    "Request would have succeeded, but DryRun flag is set.\n",
                )
        if service == "ec2" and operation == "describe-instance-type-offerings":
            site = next(site for site in ("west", "east") if self.config.sites[site]["region"] == region)
            return {
                "InstanceTypeOfferings": [
                    {"InstanceType": instance_type, "Location": zone}
                    for instance_type in (
                        self.config.raw["instance_type"],
                        self.config.raw["test_instance_type"],
                    )
                    for zone in self.config.sites[site]["azs"].values()
                ]
            }
        if service == "elbv2" and operation == "describe-account-limits":
            return {
                "Limits": [
                    {
                        "Name": name,
                        "Max": "0" if gate == self.low_account_limit_gate else "100",
                    }
                    for gate, name in appliance.AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.items()
                ]
            }
        if service == "kms" and operation == "describe-key":
            key_arn = args[args.index("--key-id") + 1]
            return {
                "KeyMetadata": {
                    "Arn": key_arn,
                    "Enabled": True,
                    "KeyState": "Enabled",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyManager": "CUSTOMER",
                }
            }
        if service == "kms" and operation == "get-key-policy":
            partition = self.role_arn.split(":", 2)[1]
            root = f"arn:{partition}:iam::123456789012:root"
            return {
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": root},
                                "Action": "kms:*",
                                "Resource": "*",
                            }
                        ],
                    }
                )
            }
        empty_responses = {
            ("ec2", "describe-vpcs"): {"Vpcs": []},
            ("ec2", "describe-addresses"): {"Addresses": []},
            ("ec2", "describe-nat-gateways"): {"NatGateways": []},
            ("ec2", "describe-vpc-endpoint-service-configurations"): {"ServiceConfigurations": []},
            ("ec2", "describe-instances"): {"Reservations": []},
            ("elbv2", "describe-load-balancers"): {"LoadBalancers": []},
            ("elbv2", "describe-target-groups"): {"TargetGroups": []},
            ("logs", "describe-log-groups"): {"logGroups": []},
            ("s3api", "list-buckets"): {"Buckets": []},
        }
        if (service, operation) in empty_responses:
            return copy.deepcopy(empty_responses[(service, operation)])
        raise AssertionError((args, region))


def fixture_instance_vcpus(config: appliance.RunConfig) -> dict[str, dict[str, int]]:
    return {
        config.sites[site]["region"]: {
            config.raw["instance_type"]: 2,
            config.raw["test_instance_type"]: 2,
        }
        for site in ("west", "east")
    }


class AWSCapabilityQuotaPreflightTest(unittest.TestCase):
    def test_success_is_read_only_redacted_deterministic_and_resolves_sso_role_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = CapabilityAWS(config)
            account_id, summary = appliance.aws_capability_quota_preflight(
                config, aws, fixture_instance_vcpus(config), artifact_identity(pathlib.Path(temporary))
            )
            appliance.validate_aws_preflight_summary(summary, config, account_id)

        self.assertEqual(account_id, "123456789012")
        self.assertEqual(summary["actions"]["operator"], list(appliance.AWS_OPERATOR_ACTIONS))
        self.assertEqual(
            summary["actions"]["operator_simulated"],
            [
                action
                for action in appliance.AWS_OPERATOR_ACTIONS
                if action != "ec2:RunInstances"
            ],
        )
        self.assertEqual(
            summary["actions"]["run_instances_dry_run"],
            {
                "west": {
                    "target": config.raw["instance_type"],
                    "transport_router": config.raw["instance_type"],
                    "workload": config.raw["test_instance_type"],
                },
                "east": {
                    "target": config.raw["instance_type"],
                    "transport_router": config.raw["instance_type"],
                    "workload": config.raw["test_instance_type"],
                },
            },
        )
        self.assertEqual(
            summary["actions"]["flow_log_delivery_role"],
            list(appliance.AWS_FLOW_LOG_DELIVERY_ACTIONS),
        )
        self.assertEqual(set(summary["regions"]), {"us-west-2", "us-east-1"})
        self.assertEqual(summary["regions"]["us-west-2"]["planned_instances"], 6)
        self.assertEqual(summary["regions"]["us-west-2"]["excluded_regional_nat_gateways"], 0)
        self.assertEqual(summary["regions"]["us-west-2"]["quotas"]["standard-vcpus"]["required"], 12)
        self.assertEqual(
            summary["regions"]["us-west-2"]["quotas"]["standard-vcpus"]["quota_code"],
            "L-1216C47A",
        )
        self.assertEqual(summary["regions"]["us-west-2"]["quotas"]["target-groups"]["required"], 1)
        west_quotas = summary["regions"]["us-west-2"]["quotas"]
        self.assertEqual(
            west_quotas["gateway-load-balancers"],
            {
                "service": "elasticloadbalancing",
                "quota_name": "gateway-load-balancers",
                "quota_code": None,
                "source": "elbv2:DescribeAccountLimits",
                "limit": 100,
                "used": 0,
                "required": 1,
                "available": 100,
            },
        )
        self.assertEqual(
            (west_quotas["listeners-per-gateway-load-balancer"]["limit"],
             west_quotas["listeners-per-gateway-load-balancer"]["required"]),
            (1, 1),
        )
        self.assertEqual(
            (west_quotas["targets-per-gateway-load-balancer"]["limit"],
             west_quotas["targets-per-gateway-load-balancer"]["required"]),
            (300, 1),
        )
        self.assertEqual(
            (west_quotas["flow-logs-per-resource"]["limit"],
             west_quotas["flow-logs-per-resource"]["used"],
             west_quotas["flow-logs-per-resource"]["required"]),
            (10, 0, 1),
        )
        self.assertEqual(
            (west_quotas["vpc-endpoint-services"]["limit"],
             west_quotas["vpc-endpoint-services"]["used"],
             west_quotas["vpc-endpoint-services"]["required"]),
            (50, 0, 1),
        )
        self.assertEqual(summary["global_quotas"]["s3-artifact-buckets"]["required"], 1)
        self.assertEqual(
            summary["global_quotas"]["s3-artifact-buckets"]["quota_code"],
            "L-DC2B2D3D",
        )
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn(aws.role_arn, serialized)
        self.assertNotIn("fixture-session", serialized)
        for selected_default_id in (
            "vpc-11111111111111111",
            "subnet-22222222222222222",
            "sg-33333333333333333",
            "vpc-aaaaaaaaaaaaaaaaa",
            "subnet-bbbbbbbbbbbbbbbbb",
            "sg-ccccccccccccccccc",
        ):
            self.assertNotIn(selected_default_id, serialized)
        self.assertEqual(appliance.redact(serialized), serialized)
        get_role = next(args for args, _ in aws.calls if args[:2] == ["iam", "get-role"])
        self.assertEqual(get_role[-1], aws.role_name)
        pass_role_calls = [
            args
            for args, _ in aws.calls
            if args[:2] == ["iam", "simulate-principal-policy"]
            and args[args.index("--action-names") + 1 : args.index("--resource-arns")] == ["iam:PassRole"]
        ]
        self.assertEqual(len(pass_role_calls), 2)
        expected_roles = appliance.simulation_pass_role_arns(config, account_id)
        observed = {}
        for call in pass_role_calls:
            context_index = call.index("--context-entries")
            resources = call[call.index("--resource-arns") + 1 : context_index]
            context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in json.loads(call[context_index + 1])
            }
            observed[context["iam:PassedToService"][0]] = resources
        self.assertEqual(observed["ec2.amazonaws.com"], sorted(expected_roles[:4]))
        self.assertEqual(observed["vpc-flow-logs.amazonaws.com"], expected_roles[4:])
        mutating_verbs = {
            "create",
            "delete",
            "put",
            "update",
            "modify",
            "attach",
            "detach",
            "associate",
            "disassociate",
            "run",
            "terminate",
            "reboot",
            "send",
            "cancel",
        }
        dry_run_calls = [
            (args, region)
            for args, region in aws.calls
            if args[:2] == ["ec2", "run-instances"]
        ]
        self.assertEqual(len(dry_run_calls), 6)
        self.assertTrue(all("--dry-run" in args for args, _region in dry_run_calls))
        non_dry_mutations = [
            args
            for args, _region in aws.calls
            if args[1].split("-", 1)[0] in mutating_verbs
            and not (args[:2] == ["ec2", "run-instances"] and "--dry-run" in args)
        ]
        self.assertEqual(non_dry_mutations, [])
        self.assertIn("servicequotas:GetServiceQuota", appliance.AWS_OPERATOR_ACTIONS)
        self.assertNotIn("servicequotas:ListServiceQuotas", appliance.AWS_OPERATOR_ACTIONS)
        self.assertFalse(any(args[:2] == ["service-quotas", "list-service-quotas"] for args, _ in aws.calls))
        global_reads = [
            (args, region)
            for args, region in aws.calls
            if args[:2] == ["service-quotas", "get-service-quota"]
            and args[args.index("--quota-code") + 1] == "L-DC2B2D3D"
        ]
        self.assertEqual([region for _args, region in global_reads], ["us-east-1"])
        self.assertEqual(
            [region for args, region in aws.calls if args[:2] == ["s3api", "list-buckets"]],
            ["us-east-1"],
        )
        self.assertEqual(
            [region for args, region in aws.calls if args[:2] == ["elbv2", "describe-account-limits"]],
            ["us-west-2", "us-east-1"],
        )
        runtime_simulations = [
            args for args, _region in aws.calls if args[:2] == ["iam", "simulate-custom-policy"]
        ]
        self.assertEqual(len(runtime_simulations), 2)
        for args in runtime_simulations:
            policy = json.loads(args[args.index("--policy-input-list") + 1])
            statement = policy["Statement"][0]
            key_arn = args[args.index("--resource-arns") + 1]
            context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in json.loads(args[args.index("--context-entries") + 1])
            }
            self.assertEqual(statement["Action"], "kms:Decrypt")
            self.assertEqual(statement["Resource"], key_arn)
            self.assertEqual(
                statement["Condition"]["StringEquals"]["kms:ViaService"],
                context["kms:ViaService"][0],
            )
            self.assertEqual(
                statement["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"],
                context["kms:EncryptionContext:PARAMETER_ARN"][0],
            )

    def test_run_instances_dry_run_uses_exact_six_safe_probe_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = CapabilityAWS(config)
            summary = appliance.run_instances_dry_run_preflight(config, aws)

        expected_summary = {
            "west": {
                "target": config.raw["instance_type"],
                "transport_router": config.raw["instance_type"],
                "workload": config.raw["test_instance_type"],
            },
            "east": {
                "target": config.raw["instance_type"],
                "transport_router": config.raw["instance_type"],
                "workload": config.raw["test_instance_type"],
            },
        }
        self.assertEqual(summary, expected_summary)
        serialized_summary = json.dumps(summary, sort_keys=True)
        for resource_prefix in ("vpc-", "subnet-", "sg-"):
            self.assertNotIn(resource_prefix, serialized_summary)

        expected_resources = {
            "west": {
                "vpc": "vpc-11111111111111111",
                "subnet": "subnet-22222222222222222",
                "security_group": "sg-33333333333333333",
            },
            "east": {
                "vpc": "vpc-aaaaaaaaaaaaaaaaa",
                "subnet": "subnet-bbbbbbbbbbbbbbbbb",
                "security_group": "sg-ccccccccccccccccc",
            },
        }
        expected_tags = {
            "EnvelopeRun": config.run_id,
            "ExpiresAt": config.expires_at,
            "ManagedBy": "terraform",
            "Profile": "envelope-aws-appliance",
        }
        run_calls = [
            (args, region)
            for args, region in aws.calls
            if args[:2] == ["ec2", "run-instances"]
        ]
        self.assertEqual(len(run_calls), 6)
        observed = set()
        for args, region in run_calls:
            site = next(
                site
                for site in ("west", "east")
                if config.sites[site]["region"] == region
            )
            instance_type = args[args.index("--instance-type") + 1]
            observed.add((site, instance_type))
            self.assertEqual(args.count("--dry-run"), 1)
            self.assertEqual(args[args.index("--image-id") + 1], config.sites[site]["ami_id"])
            self.assertEqual(args[args.index("--count") + 1], "1")
            self.assertEqual(
                args[args.index("--subnet-id") + 1],
                expected_resources[site]["subnet"],
            )
            self.assertEqual(
                args[args.index("--security-group-ids") + 1],
                expected_resources[site]["security_group"],
            )
            self.assertEqual(
                args[args.index("--metadata-options") + 1],
                "HttpTokens=required,HttpEndpoint=enabled",
            )
            self.assertNotIn("--iam-instance-profile", args)
            tag_specifications = json.loads(args[args.index("--tag-specifications") + 1])
            self.assertEqual(len(tag_specifications), 2)
            self.assertEqual(
                {value["ResourceType"] for value in tag_specifications},
                {"instance", "volume"},
            )
            for value in tag_specifications:
                self.assertEqual(set(value), {"ResourceType", "Tags"})
                self.assertEqual(len(value["Tags"]), len(expected_tags))
                self.assertEqual(
                    {tag["Key"]: tag["Value"] for tag in value["Tags"]},
                    expected_tags,
                )
        self.assertEqual(
            observed,
            {
                (site, instance_type)
                for site in ("west", "east")
                for instance_type in (
                    config.raw["instance_type"],
                    config.raw["test_instance_type"],
                )
            },
        )
        for site in ("west", "east"):
            region = config.sites[site]["region"]
            zone = next(iter(config.sites[site]["azs"].values()))
            regional_calls = [args for args, called_region in aws.calls if called_region == region]
            self.assertIn(
                ["ec2", "describe-vpcs", "--filters", "Name=is-default,Values=true"],
                regional_calls,
            )
            self.assertIn(
                [
                    "ec2",
                    "describe-subnets",
                    "--filters",
                    f"Name=vpc-id,Values={expected_resources[site]['vpc']}",
                    f"Name=availability-zone,Values={zone}",
                    "Name=default-for-az,Values=true",
                ],
                regional_calls,
            )
            self.assertIn(
                [
                    "ec2",
                    "describe-security-groups",
                    "--filters",
                    f"Name=vpc-id,Values={expected_resources[site]['vpc']}",
                    "Name=group-name,Values=default",
                ],
                regional_calls,
            )

    def test_run_instances_dry_run_rejects_missing_ambiguous_and_malformed_defaults(self):
        class InvalidDefaultAWS(CapabilityAWS):
            def __init__(self, config, mode):
                super().__init__(config)
                self.mode = mode

            def json(self, args, *, region=None):
                response = super().json(args, region=region)
                operation = args[1]
                target = self.mode.split("-", 1)[0]
                operation_by_target = {
                    "vpc": "describe-vpcs",
                    "subnet": "describe-subnets",
                    "sg": "describe-security-groups",
                }
                if operation != operation_by_target[target]:
                    return response
                field = {
                    "vpc": "Vpcs",
                    "subnet": "Subnets",
                    "sg": "SecurityGroups",
                }[target]
                mutation = self.mode.split("-", 1)[1]
                if mutation == "missing":
                    response[field] = []
                elif mutation == "ambiguous":
                    response[field].append(copy.deepcopy(response[field][0]))
                elif mutation == "malformed":
                    identity_field = {
                        "vpc": "VpcId",
                        "subnet": "SubnetId",
                        "sg": "GroupId",
                    }[target]
                    response[field][0][identity_field] = "malformed"
                else:
                    raise AssertionError(self.mode)
                return response

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for resource, gate in (
                ("vpc", "default-vpc"),
                ("subnet", "default-subnet"),
                ("sg", "default-security-group"),
            ):
                for mutation in ("missing", "ambiguous", "malformed"):
                    with self.subTest(resource=resource, mutation=mutation):
                        with self.assertRaisesRegex(
                            appliance.LifecycleError,
                            rf"RunInstances dry-run gate west/{gate}",
                        ):
                            appliance.run_instances_dry_run_preflight(
                                config,
                                InvalidDefaultAWS(config, f"{resource}-{mutation}"),
                            )

    def test_run_instances_dry_run_fails_closed_for_every_non_success_status(self):
        class DryRunStatusAWS(CapabilityAWS):
            def __init__(self, config, mode):
                super().__init__(config)
                self.mode = mode

            def json(self, args, *, region=None):
                if args[:2] != ["ec2", "run-instances"]:
                    return super().json(args, region=region)
                self.calls.append((list(args), region))
                if "--dry-run" not in args:
                    raise AssertionError("non-dry RunInstances command")
                exact_success = (
                    "An error occurred (DryRunOperation) when calling the RunInstances operation: "
                    "Request would have succeeded, but DryRun flag is set."
                )
                errors = {
                    "unauthorized": "An error occurred (UnauthorizedOperation): You are not authorized.",
                    "explicit-deny": "An error occurred (UnauthorizedOperation): explicit deny in a service control policy.",
                    "invalid-ami": "An error occurred (InvalidAMIID.NotFound): The image id does not exist.",
                    "invalid-type": "An error occurred (InvalidParameterValue): Invalid instance type.",
                    "invalid-subnet": "An error occurred (InvalidSubnetID.NotFound): The subnet does not exist.",
                    "other": "An error occurred (RequestLimitExceeded): Retry later.",
                    "wrong-message": exact_success + " unexpected",
                }
                if self.mode == "normal-response":
                    return {}
                if self.mode == "non-command-error":
                    raise appliance.LifecycleError("unexpected fixture failure with subnet-sensitive")
                returncode = 0 if self.mode == "zero-returncode" else 255
                stderr = exact_success if self.mode == "zero-returncode" else errors[self.mode]
                raise appliance.CommandError(args, returncode, stderr)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for mode in (
                "unauthorized",
                "explicit-deny",
                "invalid-ami",
                "invalid-type",
                "invalid-subnet",
                "normal-response",
                "other",
                "wrong-message",
                "zero-returncode",
                "non-command-error",
            ):
                with self.subTest(mode=mode):
                    with self.assertRaises(appliance.LifecycleError) as raised:
                        appliance.run_instances_dry_run_preflight(
                            config,
                            DryRunStatusAWS(config, mode),
                        )
                    message = str(raised.exception)
                    self.assertIn("RunInstances dry-run gate west/target", message)
                    self.assertNotIn("UnauthorizedOperation", message)
                    self.assertNotIn("subnet-sensitive", message)

    def test_quota_codes_account_limit_names_and_structural_defaults_are_independent_literals(self):
        expected_regional = {
            "cloudwatch-log-groups": ("logs", "L-C7B9AAAB"),
            "elastic-ips": ("ec2", "L-0263D0A3"),
            "gateway-load-balancer-endpoints-per-vpc": ("vpc", "L-29B6F2EB"),
            "nat-gateways-per-availability-zone": ("vpc", "L-FE5A380F"),
            "standard-vcpus": ("ec2", "L-1216C47A"),
            "target-groups": ("elasticloadbalancing", "L-B22855CB"),
            "vpcs": ("vpc", "L-F678F1CE"),
        }
        expected_global = {"s3-artifact-buckets": ("s3", "L-DC2B2D3D")}
        self.assertEqual(
            {gate: values[:2] for gate, values in appliance.AWS_REGIONAL_QUOTA_CONTRACT.items()},
            expected_regional,
        )
        self.assertEqual(
            {gate: values[:2] for gate, values in appliance.AWS_GLOBAL_QUOTA_CONTRACT.items()},
            expected_global,
        )
        self.assertEqual(
            appliance.AWS_REGIONAL_QUOTA_CONTRACT["gateway-load-balancer-endpoints-per-vpc"][2],
            "Interface VPC endpoints per VPC",
        )
        self.assertEqual(
            appliance.AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT,
            {
                "gateway-load-balancers": "gateway-load-balancers",
                "gateway-load-balancers-per-vpc": "gateway-load-balancers-per-vpc",
                "geneve-target-groups": "geneve-target-groups",
                "targets-per-availability-zone-per-gateway-load-balancer": (
                    "targets-per-availability-zone-per-gateway-load-balancer"
                ),
            },
        )
        self.assertEqual(
            appliance.AWS_STRUCTURAL_CAPACITY_CONTRACT,
            {
                "flow-logs-per-resource": (
                    "ec2",
                    "Flow logs per resource",
                    10,
                    "documented-default-lower-bound",
                ),
                "listeners-per-gateway-load-balancer": (
                    "elasticloadbalancing",
                    "Listeners per Gateway Load Balancer",
                    1,
                    "documented-structural-limit",
                ),
                "targets-per-gateway-load-balancer": (
                    "elasticloadbalancing",
                    "Targets per Gateway Load Balancer",
                    300,
                    "documented-structural-limit",
                ),
                "vpc-endpoint-services": (
                    "ec2",
                    "VPC endpoint services per Region",
                    50,
                    "documented-default-lower-bound",
                ),
            },
        )

    def test_elbv2_account_limits_require_each_exact_name_once_with_numeric_max(self):
        names = (
            "gateway-load-balancers",
            "gateway-load-balancers-per-vpc",
            "geneve-target-groups",
            "targets-per-availability-zone-per-gateway-load-balancer",
        )
        baseline = {"Limits": [{"Name": name, "Max": str(index + 1)} for index, name in enumerate(names)]}

        class LimitsAWS:
            def __init__(self, response):
                self.response = response
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                return copy.deepcopy(self.response)

        aws = LimitsAWS(baseline)
        self.assertEqual(
            appliance.regional_elbv2_account_limits(aws, "us-west-2"),
            {
                "gateway-load-balancers": 1,
                "gateway-load-balancers-per-vpc": 2,
                "geneve-target-groups": 3,
                "targets-per-availability-zone-per-gateway-load-balancer": 4,
            },
        )
        self.assertEqual(aws.calls, [(["elbv2", "describe-account-limits"], "us-west-2")])

        malformed = (
            [],
            {"Limits": {}},
            {"Limits": baseline["Limits"][:-1]},
            {"Limits": [*baseline["Limits"], copy.deepcopy(baseline["Limits"][0])]},
            {"Limits": [{**value, "Max": 1} if index == 0 else value for index, value in enumerate(baseline["Limits"])]},
            {"Limits": [{**value, "Max": "1.0"} if index == 0 else value for index, value in enumerate(baseline["Limits"])]},
            {"Limits": [{**value, "Name": None} if index == 0 else value for index, value in enumerate(baseline["Limits"])]},
        )
        for response in malformed:
            with self.subTest(response=response):
                with self.assertRaises(appliance.LifecycleError):
                    appliance.regional_elbv2_account_limits(LimitsAWS(response), "us-west-2")

    def test_code_based_quota_reads_reject_mismatched_metadata_and_name_api_failures(self):
        contract = {
            "fixture-gate": ("ec2", "L-1216C47A", "Running On-Demand Standard instances")
        }
        baseline = {
            "ServiceCode": "ec2",
            "QuotaCode": "L-1216C47A",
            "QuotaArn": "arn:aws:servicequotas:us-west-2:123456789012:ec2/L-1216C47A",
            "QuotaName": "Current AWS display name",
            "Value": 100.0,
            "GlobalQuota": False,
        }

        class QuotaAWS:
            def __init__(self, quota):
                self.quota = quota
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                return {"Quota": copy.deepcopy(self.quota)}

        aws = QuotaAWS(baseline)
        values = appliance.service_quota_values(
            aws,
            "us-west-2",
            contract,
            "arn:aws:iam::123456789012:role/operator",
            global_quotas=False,
        )
        self.assertEqual(values["fixture-gate"]["QuotaName"], "Current AWS display name")
        self.assertEqual(
            aws.calls,
            [
                (
                    [
                        "service-quotas",
                        "get-service-quota",
                        "--service-code",
                        "ec2",
                        "--quota-code",
                        "L-1216C47A",
                    ],
                    "us-west-2",
                )
            ],
        )
        mutations = (
            {**baseline, "ServiceCode": "vpc"},
            {**baseline, "QuotaCode": "L-WRONG"},
            {**baseline, "QuotaArn": "arn:aws:servicequotas:us-east-1:123456789012:ec2/L-1216C47A"},
            {**baseline, "QuotaArn": "arn:aws:servicequotas::123456789012:ec2/L-1216C47A"},
            {**baseline, "QuotaName": ""},
            {**baseline, "Value": True},
            {**baseline, "Value": float("nan")},
            {**baseline, "GlobalQuota": True},
            {key: value for key, value in baseline.items() if key != "GlobalQuota"},
            [],
        )
        for quota in mutations:
            with self.subTest(quota=quota):
                with self.assertRaisesRegex(appliance.LifecycleError, "fixture-gate.*L-1216C47A"):
                    appliance.service_quota_values(
                        QuotaAWS(quota),
                        "us-west-2",
                        contract,
                        "arn:aws:iam::123456789012:role/operator",
                        global_quotas=False,
                    )

        class FailedQuotaAWS:
            def json(self, args, *, region=None):
                raise appliance.CommandError(args, 255, "NoSuchResourceException")

        with self.assertRaisesRegex(appliance.LifecycleError, "fixture-gate.*L-1216C47A"):
            appliance.service_quota_values(
                FailedQuotaAWS(),
                "us-west-2",
                contract,
                "arn:aws:iam::123456789012:role/operator",
                global_quotas=False,
            )

    def test_global_quota_requires_literal_empty_region_arn(self):
        baseline = {
            "ServiceCode": "s3",
            "QuotaCode": "L-DC2B2D3D",
            "QuotaArn": "arn:aws:servicequotas::123456789012:s3/L-DC2B2D3D",
            "QuotaName": "General purpose buckets",
            "Value": 100.0,
            "GlobalQuota": True,
        }

        class LiteralQuotaAWS:
            def __init__(self, quota):
                self.quota = quota
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                return {"Quota": copy.deepcopy(self.quota)}

        identity_arn = "arn:aws:iam::123456789012:role/operator"
        aws = LiteralQuotaAWS(baseline)
        values = appliance.global_service_quota_values(aws, identity_arn)
        self.assertEqual(
            values["s3-artifact-buckets"]["QuotaArn"],
            "arn:aws:servicequotas::123456789012:s3/L-DC2B2D3D",
        )
        self.assertEqual(
            aws.calls,
            [
                (
                    [
                        "service-quotas",
                        "get-service-quota",
                        "--service-code",
                        "s3",
                        "--quota-code",
                        "L-DC2B2D3D",
                    ],
                    "us-east-1",
                )
            ],
        )

        invalid_arns = (
            "arn:aws:servicequotas:us-east-1:123456789012:s3/L-DC2B2D3D",
            "arn:aws-us-gov:servicequotas::123456789012:s3/L-DC2B2D3D",
            "arn:aws:servicequotas::000000000000:s3/L-DC2B2D3D",
            "arn:aws:servicequotas::123456789012:ec2/L-DC2B2D3D",
            "arn:aws:servicequotas::123456789012:s3/L-WRONG",
        )
        for quota_arn in invalid_arns:
            with self.subTest(quota_arn=quota_arn):
                with self.assertRaisesRegex(
                    appliance.LifecycleError,
                    "s3-artifact-buckets.*L-DC2B2D3D",
                ):
                    appliance.global_service_quota_values(
                        LiteralQuotaAWS({**baseline, "QuotaArn": quota_arn}),
                        identity_arn,
                    )

    def test_global_quota_and_bucket_inventory_use_commercial_control_region(self):
        class PartitionAWS:
            def __init__(self):
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                if args[:2] == ["service-quotas", "get-service-quota"]:
                    service, code, name = appliance.AWS_GLOBAL_QUOTA_CONTRACT["s3-artifact-buckets"]
                    return {
                        "Quota": {
                            "ServiceCode": service,
                            "QuotaCode": code,
                            "QuotaArn": "arn:aws:servicequotas::123456789012:s3/L-DC2B2D3D",
                            "QuotaName": name,
                            "Value": 100,
                            "GlobalQuota": True,
                        }
                    }
                if args[:2] == ["s3api", "list-buckets"]:
                    return {"Buckets": []}
                raise AssertionError(args)

        aws = PartitionAWS()
        identity_arn = "arn:aws:iam::123456789012:role/operator"
        appliance.global_service_quota_values(aws, identity_arn)
        self.assertEqual(appliance.s3_general_purpose_bucket_count(aws, identity_arn), 0)
        self.assertEqual([called_region for _args, called_region in aws.calls], ["us-east-1", "us-east-1"])
        self.assertEqual(appliance.AWS_GLOBAL_QUOTA_CONTROL_REGIONS, {"aws": "us-east-1"})
        self.assertEqual(appliance.AWS_PARTITION_DNS_SUFFIXES, {"aws": "amazonaws.com"})
        for partition in ("aws-us-gov", "aws-cn"):
            with self.subTest(partition=partition):
                with self.assertRaisesRegex(appliance.LifecycleError, "commercial aws ARN partition"):
                    appliance.aws_partition(
                        f"arn:{partition}:iam::123456789012:role/operator"
                    )

    def test_run_config_rejects_every_noncommercial_aws_partition(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            cases = []
            backend = config_document()
            backend["backend"]["kms_key_arn"] = (
                "arn:aws-cn:kms:us-west-2:123456789012:key/backend"
            )
            cases.append(backend)
            operator = config_document()
            operator["backend"]["operator_principal_arns"] = [
                "arn:aws-us-gov:iam::123456789012:role/operator"
            ]
            cases.append(operator)
            site = config_document()
            site["symmetric_topology"]["sites"]["east"]["ssm_kms_key_arn"] = (
                "arn:aws-cn:kms:us-east-1:123456789012:key/east"
            )
            cases.append(site)
            for index, document in enumerate(cases):
                with self.subTest(index=index):
                    path = root / f"noncommercial-{index}.json"
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(appliance.LifecycleError, "commercial-partition"):
                        appliance.RunConfig.load(path)

            config = make_config(root / "commercial")

            class NonCommercialCaller(CapabilityAWS):
                def json(self, args, *, region=None):
                    if args[:2] == ["sts", "get-caller-identity"]:
                        return {
                            "Account": "123456789012",
                            "Arn": "arn:aws-cn:sts::123456789012:assumed-role/operator/session",
                            "UserId": "fixture",
                        }
                    return super().json(args, region=region)

            with self.assertRaisesRegex(appliance.LifecycleError, "commercial aws ARN partition"):
                appliance.aws_capability_quota_preflight(
                    config,
                    NonCommercialCaller(config),
                    fixture_instance_vcpus(config),
                    artifact_identity(root),
                )

    def test_s3_bucket_inventory_paginates_and_rejects_malformed_or_repeated_pages(self):
        class PagedAWS:
            def __init__(self, pages):
                self.pages = pages
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                return copy.deepcopy(self.pages[len(self.calls) - 1])

        identity_arn = "arn:aws:iam::123456789012:role/operator"
        aws = PagedAWS(
            [
                {"Buckets": [{"Name": "one"}], "NextToken": "opaque+token/="},
                {"Buckets": [{"Name": "two"}]},
            ]
        )
        self.assertEqual(appliance.s3_general_purpose_bucket_count(aws, identity_arn), 2)
        self.assertEqual(aws.calls[0][1], "us-east-1")
        self.assertIn("--page-size", aws.calls[0][0])
        self.assertIn("--max-items", aws.calls[0][0])
        self.assertNotIn("--starting-token", aws.calls[0][0])
        self.assertEqual(aws.calls[1][0][-2:], ["--starting-token", "opaque+token/="])

        malformed_pages = (
            [{"Buckets": [], "NextToken": ""}],
            [{"Buckets": [], "ContinuationToken": "raw-service-token"}],
            [{"Buckets": [{"Name": "one"}], "NextToken": "again"}, {"Buckets": [], "NextToken": "again"}],
            [{"Buckets": [{"Name": "one"}], "NextToken": "next"}, {"Buckets": [{"Name": "one"}]}],
            [{"Buckets": {}}],
        )
        for pages in malformed_pages:
            with self.subTest(pages=pages):
                with self.assertRaises(appliance.LifecycleError):
                    appliance.s3_general_purpose_bucket_count(PagedAWS(pages), identity_arn)

    def test_reviewed_action_resource_contract_groups_only_applicable_mandatory_resources(self):
        self.assertEqual(
            set(appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT),
            set(appliance.AWS_OPERATOR_ACTIONS),
        )
        self.assertEqual(len(appliance.AWS_OPERATOR_ACTIONS), 202)
        self.assertEqual(
            appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT["elasticloadbalancing:CreateTargetGroup"],
            ("target-group",),
        )
        self.assertEqual(
            appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT["elasticloadbalancing:CreateListener"],
            ("load-balancer",),
        )
        self.assertEqual(
            appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT["elasticloadbalancing:AddTags"],
            ("*",),
        )
        self.assertNotIn("elasticloadbalancing:RemoveTags", appliance.AWS_OPERATOR_ACTIONS)
        self.assertIn("elasticloadbalancing:DescribeTags", appliance.AWS_OPERATOR_ACTIONS)
        self.assertEqual(
            appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT["ec2:RunInstances"],
            ("image", "subnet", "security-group", "instance", "volume", "network-interface"),
        )
        for action in (
            "iam:AddRoleToInstanceProfile",
            "iam:RemoveRoleFromInstanceProfile",
        ):
            self.assertEqual(
                appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT[action],
                ("instance-profile",),
            )
        self.assertEqual(
            appliance.AWS_OPERATOR_ACTION_RESOURCE_CONTRACT["iam:SimulatePrincipalPolicy"],
            ("policy-source",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            batches = appliance.build_operator_simulation_batches(
                config,
                "123456789012",
                artifact,
                policy_source_arn="arn:aws:iam::123456789012:role/operator",
            )
            simulated_actions = {
                action
                for batch in batches
                for action in batch["actions"]
            }
            expected_simulated_actions = set(appliance.AWS_OPERATOR_ACTIONS)
            expected_simulated_actions.remove("ec2:RunInstances")
            self.assertEqual(simulated_actions, expected_simulated_actions)
            self.assertEqual(len(simulated_actions), 201)
            self.assertNotIn("ec2:RunInstances", simulated_actions)

            def west_batches(action):
                matches = [
                    batch
                    for batch in batches
                    if action in batch["actions"] and "west" in batch["name"]
                ]
                self.assertTrue(matches, action)
                return matches

            def west_batch(action):
                matches = west_batches(action)
                self.assertEqual(len(matches), 1, action)
                return matches[0]

            def west_resource_batch(action, expected_resources):
                matches = [
                    batch
                    for batch in west_batches(action)
                    if set(batch["resources"]) == set(expected_resources)
                ]
                self.assertEqual(len(matches), 1, (action, expected_resources))
                return matches[0]

            def context(batch):
                return {
                    entry["ContextKeyName"]: entry["ContextKeyValues"]
                    for entry in batch["context"]
                }

            def assert_context_mode(batch, mode, extra_context=None):
                values = context(batch)
                expected_tags = {
                    "EnvelopeRun": config.run_id,
                    "ExpiresAt": config.expires_at,
                    "ManagedBy": "terraform",
                    "Profile": "envelope-aws-appliance",
                }
                if mode not in {
                    "regional",
                    "request",
                    "resource",
                    "request-resource",
                    "tag-keys",
                    "resource-tag-keys",
                }:
                    self.fail(f"unknown context mode {mode}")
                expected_keys = {"aws:RequestedRegion"}
                if mode in {"request", "request-resource", "tag-keys", "resource-tag-keys"}:
                    expected_keys.add("aws:TagKeys")
                if mode in {"request", "request-resource"}:
                    expected_keys.update(f"aws:RequestTag/{key}" for key in expected_tags)
                if mode in {"resource", "request-resource", "resource-tag-keys"}:
                    expected_keys.update(f"aws:ResourceTag/{key}" for key in expected_tags)
                expected_keys.update((extra_context or {}).keys())
                self.assertEqual(set(values), expected_keys)
                self.assertEqual(values["aws:RequestedRegion"], ["us-west-2"])
                if mode in {"request", "request-resource", "tag-keys", "resource-tag-keys"}:
                    self.assertEqual(values["aws:TagKeys"], sorted(expected_tags))
                if mode in {"request", "request-resource"}:
                    for key, value in expected_tags.items():
                        self.assertEqual(values[f"aws:RequestTag/{key}"], [value])
                if mode in {"resource", "request-resource", "resource-tag-keys"}:
                    for key, value in expected_tags.items():
                        self.assertEqual(values[f"aws:ResourceTag/{key}"], [value])
                for key, value in (extra_context or {}).items():
                    self.assertEqual(values[key], value)

            load_balancer_arn = (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:"
                "loadbalancer/gwy/envelope-fixture-west-gwlb/*"
            )
            target_group_batch = west_batch("elasticloadbalancing:CreateTargetGroup")
            self.assertEqual(
                target_group_batch["resources"],
                (
                    "arn:aws:elasticloadbalancing:us-west-2:123456789012:"
                    "targetgroup/envelope-fixture-west-gwlb-tg/*",
                ),
            )
            self.assertFalse(
                any("loadbalancer/" in resource or "listener/" in resource for resource in target_group_batch["resources"])
            )
            assert_context_mode(target_group_batch, "request")
            create_load_balancer_batch = west_batch("elasticloadbalancing:CreateLoadBalancer")
            self.assertEqual(create_load_balancer_batch["resources"], (load_balancer_arn,))
            assert_context_mode(create_load_balancer_batch, "request")

            subnet_arn = "arn:aws:ec2:us-west-2:123456789012:subnet/*"
            vpc_arn = "arn:aws:ec2:us-west-2:123456789012:vpc/*"
            self.assertEqual(len(west_batches("ec2:CreateSubnet")), 2)
            assert_context_mode(
                west_resource_batch("ec2:CreateSubnet", (subnet_arn,)),
                "request",
            )
            assert_context_mode(
                west_resource_batch("ec2:CreateSubnet", (vpc_arn,)),
                "resource",
            )

            self.assertEqual(len(west_batches("elasticloadbalancing:CreateListener")), 1)
            assert_context_mode(
                west_resource_batch(
                    "elasticloadbalancing:CreateListener",
                    (load_balancer_arn,),
                ),
                "request-resource",
            )
            self.assertEqual(
                {resource.split(":", 5)[5].split("/", 1)[0] for resource in west_batch("ec2:AttachVolume")["resources"]},
                {"instance", "volume"},
            )
            self.assertEqual(
                {resource.split(":", 5)[5].split("/", 1)[0] for resource in west_batch("ec2:AssociateRouteTable")["resources"]},
                {"route-table", "subnet"},
            )
            assert_context_mode(west_batch("ec2:CreateVpc"), "request")
            assert_context_mode(west_batch("ec2:DeleteVpc"), "resource")
            assert_context_mode(west_batch("ec2:CreateNetworkAclEntry"), "regional")
            assert_context_mode(west_batch("ec2:CreateRoute"), "regional")

            create_tag_paths = {
                batch["name"].rsplit("-", 1)[1]: batch
                for batch in batches
                if batch["name"].startswith("ec2-west-create-tags-")
            }
            expected_create_tag_resources = {
                "AllocateAddress": {"elastic-ip"},
                "CreateFlowLogs": {"vpc-flow-log"},
                "CreateInternetGateway": {"internet-gateway"},
                "CreateNatGateway": {"natgateway"},
                "CreateNetworkAcl": {"network-acl"},
                "CreateNetworkInterface": {"network-interface"},
                "CreateRouteTable": {"route-table"},
                "CreateSecurityGroup": {"security-group"},
                "CreateSubnet": {"subnet"},
                "CreateVolume": {"volume"},
                "CreateVpc": {"vpc"},
                "CreateVpcEndpoint": {"vpc-endpoint"},
                "CreateVpcEndpointServiceConfiguration": {"vpc-endpoint-service"},
                "RunInstances": {"instance", "volume"},
            }
            self.assertEqual(set(create_tag_paths), set(expected_create_tag_resources))
            for create_action, batch in create_tag_paths.items():
                with self.subTest(create_action=create_action):
                    values = context(batch)
                    self.assertEqual(values["ec2:CreateAction"], [create_action])
                    self.assertIn("aws:RequestTag/EnvelopeRun", values)
                    self.assertNotIn("aws:ResourceTag/EnvelopeRun", values)
                    self.assertEqual(
                        {
                            resource.split(":", 5)[5].split("/", 1)[0]
                            for resource in batch["resources"]
                        },
                        expected_create_tag_resources[create_action],
                    )
            existing_ec2_tag_context = context(
                next(batch for batch in batches if batch["name"] == "ec2-west-tag-existing")
            )
            self.assertIn("aws:RequestTag/EnvelopeRun", existing_ec2_tag_context)
            self.assertIn("aws:ResourceTag/EnvelopeRun", existing_ec2_tag_context)
            self.assertNotIn("ec2:CreateAction", existing_ec2_tag_context)
            delete_tag_context = context(
                next(batch for batch in batches if batch["name"] == "ec2-west-delete-tags")
            )
            self.assertIn("aws:ResourceTag/EnvelopeRun", delete_tag_context)
            self.assertIn("aws:TagKeys", delete_tag_context)
            self.assertNotIn("aws:RequestTag/EnvelopeRun", delete_tag_context)

            expected_elb_create_tag_resources = {
                "CreateListener": ("*",),
                "CreateLoadBalancer": ("*",),
                "CreateTargetGroup": ("*",),
            }
            for create_action, expected_resources in expected_elb_create_tag_resources.items():
                with self.subTest(elbv2_create_action=create_action):
                    tag_batch = next(
                        batch
                        for batch in batches
                        if batch["name"] == f"elbv2-west-add-tags-{create_action}"
                    )
                    self.assertEqual(tag_batch["resources"], expected_resources)
                    assert_context_mode(
                        tag_batch,
                        "request",
                        {
                            "elasticloadbalancing:CreateAction": [create_action],
                        },
                    )

            west_elb_tag_batches = [
                batch
                for batch in batches
                if "west" in batch["name"]
                and "elasticloadbalancing:AddTags" in batch["actions"]
            ]
            self.assertEqual(
                {batch["name"] for batch in west_elb_tag_batches},
                {
                    "elbv2-west-add-tags-CreateListener",
                    "elbv2-west-add-tags-CreateLoadBalancer",
                    "elbv2-west-add-tags-CreateTargetGroup",
                },
            )
            self.assertTrue(all(batch["resources"] == ("*",) for batch in west_elb_tag_batches))
            self.assertFalse(any("tag-existing" in batch["name"] for batch in west_elb_tag_batches))

            self_simulation = next(batch for batch in batches if batch["name"] == "iam-policy-source")
            self.assertEqual(self_simulation["actions"], ("iam:SimulatePrincipalPolicy",))
            self.assertEqual(
                self_simulation["resources"],
                ("arn:aws:iam::123456789012:role/operator",),
            )
            profile_links = next(
                batch
                for batch in batches
                if "iam:AddRoleToInstanceProfile" in batch["actions"]
            )
            self.assertIn("iam:RemoveRoleFromInstanceProfile", profile_links["actions"])
            self.assertTrue(
                all(":instance-profile/" in resource for resource in profile_links["resources"])
            )
            self.assertFalse(any(":role/" in resource for resource in profile_links["resources"]))

            self.assertEqual(len(batches), 208)
            self.assertLess(len(batches), 225)

            class LeastPrivilegeAWS(CapabilityAWS):
                def json(self, args, *, region=None):
                    response = super().json(args, region=region)
                    if args[:2] == ["iam", "simulate-principal-policy"]:
                        for result in response["EvaluationResults"]:
                            if result["EvalActionName"] == "elasticloadbalancing:CreateTargetGroup":
                                for resource in result["ResourceSpecificResults"]:
                                    resource["EvalResourceDecision"] = (
                                        "allowed"
                                        if ":targetgroup/" in resource["EvalResourceName"]
                                        else "implicitDeny"
                                    )
                                result["EvalDecision"] = (
                                    "allowed"
                                    if all(
                                        resource["EvalResourceDecision"] == "allowed"
                                        for resource in result["ResourceSpecificResults"]
                                    )
                                    else "implicitDeny"
                                )
                    return response

            appliance.simulate_operator_actions(
                LeastPrivilegeAWS(config),
                "arn:aws:iam::123456789012:role/operator",
                config,
                "123456789012",
                artifact,
            )

    def test_mixed_create_rejects_policy_that_only_allows_fabricated_all_request_context(self):
        class FabricatedAllRequestPolicyAWS(CapabilityAWS):
            def json(self, args, *, region=None):
                response = super().json(args, region=region)
                if args[:2] != ["iam", "simulate-principal-policy"]:
                    return response
                resource_start = args.index("--resource-arns") + 1
                context_start = (
                    args.index("--context-entries")
                    if "--context-entries" in args
                    else len(args)
                )
                resources = args[resource_start:context_start]
                resource_kinds = {
                    resource.split(":", 5)[5].split("/", 1)[0]
                    if resource.startswith("arn:")
                    else resource
                    for resource in resources
                }
                context = (
                    {
                        entry["ContextKeyName"]: entry["ContextKeyValues"]
                        for entry in json.loads(args[context_start + 1])
                    }
                    if context_start < len(args)
                    else {}
                )
                request_tags = {
                    key for key in context if key.startswith("aws:RequestTag/")
                }
                resource_tags = {
                    key for key in context if key.startswith("aws:ResourceTag/")
                }
                for result in response["EvaluationResults"]:
                    if result["EvalActionName"] != "ec2:CreateSubnet":
                        continue
                    allowed = (
                        resource_kinds == {"subnet", "vpc"}
                        and bool(request_tags)
                        and not resource_tags
                    )
                    decision = "allowed" if allowed else "implicitDeny"
                    result["EvalDecision"] = decision
                    for resource_result in result["ResourceSpecificResults"]:
                        resource_result["EvalResourceDecision"] = decision
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            with self.assertRaisesRegex(appliance.LifecycleError, "CreateSubnet"):
                appliance.simulate_operator_actions(
                    FabricatedAllRequestPolicyAWS(config),
                    "arn:aws:iam::123456789012:role/operator",
                    config,
                    "123456789012",
                    artifact_identity(root),
                )

    def test_operator_batch_builder_requires_an_exact_policy_source_arn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            for policy_source_arn in (
                "arn:aws:iam::123456789012:role/operator*",
                "arn:aws:iam::210987654321:role/operator",
                "arn:aws:sts::123456789012:assumed-role/operator/session",
                "arn:aws:iam::123456789012:group/operators",
            ):
                with self.subTest(policy_source_arn=policy_source_arn):
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "exact resolved commercial policy source ARN",
                    ):
                        appliance.build_operator_simulation_batches(
                            config,
                            "123456789012",
                            artifact,
                            policy_source_arn=policy_source_arn,
                        )

    def test_exact_run_arn_region_tag_and_service_condition_policies_pass(self):
        self.assertTrue(
            {
                "s3:GetBucketAcl",
                "s3:GetBucketCORS",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketWebsite",
                "s3:GetObjectAttributes",
                "ec2:DescribeInstanceCreditSpecifications",
                "ec2:DescribeIamInstanceProfileAssociations",
                "ec2:DescribeSecurityGroupRules",
                "ec2:DescribeVolumeAttribute",
                "ec2:DescribeVolumesModifications",
                "ec2:DescribeVpcEndpointServicePermissions",
                "elasticloadbalancing:DescribeListenerAttributes",
                "iam:ListRoleTags",
                "iam:ListInstanceProfileTags",
            }.issubset(appliance.AWS_OPERATOR_ACTIONS)
        )

        class ExactPolicyAWS:
            def __init__(self, config, artifact):
                self.config = config
                self.artifact = artifact
                self.calls = []

            @staticmethod
            def parsed(args):
                action_start = args.index("--action-names") + 1
                resource_start = args.index("--resource-arns")
                context_start = args.index("--context-entries") if "--context-entries" in args else len(args)
                actions = args[action_start:resource_start]
                resources = args[resource_start + 1 : context_start]
                entries = json.loads(args[context_start + 1]) if context_start < len(args) else []
                context = {
                    entry["ContextKeyName"]: entry["ContextKeyValues"]
                    for entry in entries
                }
                return actions, resources, context

            def json(self, args, *, region=None):
                self.calls.append(list(args))
                actions, resources, context = self.parsed(args)
                resource_kinds = frozenset(
                    resource.split(":", 5)[5].split("/", 1)[0]
                    if resource.startswith("arn:")
                    else resource
                    for resource in resources
                )
                mixed_creation_contexts = {
                    "ec2:CreateFlowLogs": {
                        frozenset({"vpc-flow-log"}): "request",
                        frozenset({"vpc"}): "resource",
                    },
                    "ec2:CreateNatGateway": {
                        frozenset({"natgateway"}): "request",
                        frozenset({"subnet", "elastic-ip"}): "resource",
                    },
                    "ec2:CreateNetworkAcl": {
                        frozenset({"network-acl"}): "request",
                        frozenset({"vpc"}): "resource",
                    },
                    "ec2:CreateNetworkInterface": {
                        frozenset({"network-interface"}): "request",
                        frozenset({"subnet", "security-group"}): "resource",
                    },
                    "ec2:CreateRouteTable": {
                        frozenset({"route-table"}): "request",
                        frozenset({"vpc"}): "resource",
                    },
                    "ec2:CreateSecurityGroup": {
                        frozenset({"security-group"}): "request",
                        frozenset({"vpc"}): "resource",
                    },
                    "ec2:CreateSubnet": {
                        frozenset({"subnet"}): "request",
                        frozenset({"vpc"}): "resource",
                    },
                    "ec2:CreateVpcEndpoint": {
                        frozenset({"vpc-endpoint"}): "request",
                        frozenset({"vpc", "subnet"}): "resource",
                    },
                    "elasticloadbalancing:CreateListener": {
                        frozenset({"loadbalancer"}): "request-resource",
                    },
                }
                results = []
                for action in actions:
                    allowed = True
                    request_tag_keys = {
                        key for key in context if key.startswith("aws:RequestTag/")
                    }
                    resource_tag_keys = {
                        key for key in context if key.startswith("aws:ResourceTag/")
                    }
                    if action in mixed_creation_contexts:
                        expected_mode = mixed_creation_contexts[action].get(resource_kinds)
                        if expected_mode == "request":
                            allowed = (
                                bool(request_tag_keys)
                                and not resource_tag_keys
                                and "aws:TagKeys" in context
                            )
                        elif expected_mode == "resource":
                            allowed = (
                                bool(resource_tag_keys)
                                and not request_tag_keys
                                and "aws:TagKeys" not in context
                            )
                        elif expected_mode == "request-resource":
                            allowed = (
                                bool(request_tag_keys)
                                and bool(resource_tag_keys)
                                and "aws:TagKeys" in context
                            )
                        elif expected_mode == "regional":
                            allowed = (
                                not request_tag_keys
                                and not resource_tag_keys
                                and "aws:TagKeys" not in context
                            )
                        else:
                            allowed = False
                    elif action == "s3:PutObject":
                        allowed = all(resource.startswith("arn:aws:s3:::") for resource in resources)
                        if resources[0].startswith("arn:aws:s3:::operator-backend/"):
                            allowed = allowed and context.get("s3:x-amz-server-side-encryption") == ["aws:kms"]
                            allowed = allowed and context.get(
                                "s3:x-amz-server-side-encryption-aws-kms-key-id"
                            ) == [self.config.backend["kms_key_arn"]]
                            if resources[0].endswith(f"/{self.config.manifest_key}"):
                                allowed = allowed and context.get("s3:RequestObjectTag/EnvelopeRun") == [
                                    self.config.run_id
                                ]
                                allowed = allowed and context.get("s3:RequestObjectTag/ExpiresAt") == [
                                    self.config.expires_at
                                ]
                            else:
                                allowed = allowed and "s3:RequestObjectTag/EnvelopeRun" not in context
                    elif action in {"s3:ListBucket", "s3:ListBucketVersions"} and resources == [
                        "arn:aws:s3:::operator-backend"
                    ]:
                        allowed = context.get("s3:prefix") in [
                            [self.config.backend["state_key"]],
                            [self.config.lock_key],
                            [self.config.manifest_key],
                        ]
                    elif action == "s3:GetBucketAcl":
                        allowed = resources == [
                            "arn:aws:s3:::envelope-fixture-123456789012-us-west-2-artifact"
                        ]
                    elif action == "s3:CreateBucket":
                        allowed = resources == [
                            "arn:aws:s3:::envelope-fixture-123456789012-us-west-2-artifact"
                        ] and context.get("s3:LocationConstraint") == ["us-west-2"]
                    elif action == "ssm:PutParameter":
                        requested_region = context.get("aws:RequestedRegion", [None])[0]
                        allowed = resources == [
                            f"arn:aws:ssm:{requested_region}:123456789012:parameter/envelope-fixture/tailscale-auth"
                        ]
                        if request_tag_keys:
                            allowed = (
                                allowed
                                and not resource_tag_keys
                                and context.get("aws:RequestTag/EnvelopeRun") == ["envelope-fixture"]
                                and context.get("aws:RequestTag/ExpiresAt") == [self.config.expires_at]
                            )
                        else:
                            allowed = allowed and bool(resource_tag_keys)
                    elif action == "iam:PassRole":
                        service = context.get("iam:PassedToService", [None])[0]
                        allowed = service in {"ec2.amazonaws.com", "vpc-flow-logs.amazonaws.com"} and all(
                            resource.startswith("arn:aws:iam::123456789012:role/envelope-fixture-")
                            for resource in resources
                        )
                    elif action in {"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"}:
                        via_service = context.get("kms:ViaService", [None])[0]
                        allowed = isinstance(via_service, str) and (
                            via_service.startswith("s3.")
                            and context.get("kms:EncryptionContextKeys") == ["aws:s3:arn"]
                            and context.get("kms:EncryptionContext:aws:s3:arn")
                            == ["arn:aws:s3:::operator-backend"]
                            or via_service.startswith("ssm.")
                            and context.get("kms:EncryptionContextKeys") == ["PARAMETER_ARN"]
                            and context.get("kms:EncryptionContext:PARAMETER_ARN", [""])[0].endswith(
                                ":parameter/envelope-fixture/tailscale-auth"
                            )
                        )
                    elif action == "logs:CreateLogGroup":
                        requested_region = context.get("aws:RequestedRegion", [None])[0]
                        allowed = resources == [
                            f"arn:aws:logs:{requested_region}:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/"
                            + ("west" if requested_region == "us-west-2" else "east")
                        ]
                    elif action == "ec2:CreateVpc":
                        tagged = (
                            context.get("aws:RequestTag/EnvelopeRun") == ["envelope-fixture"]
                            and context.get("aws:RequestTag/ExpiresAt") == [self.config.expires_at]
                            and set(context.get("aws:TagKeys", [])) >= {"EnvelopeRun", "ExpiresAt"}
                        )
                        allowed = tagged
                    elif action == "ec2:CreateTags":
                        create_action = context.get("ec2:CreateAction")
                        if create_action:
                            allowed = (
                                len(create_action) == 1
                                and bool(request_tag_keys)
                                and not resource_tag_keys
                            )
                        else:
                            allowed = bool(request_tag_keys) and bool(resource_tag_keys)
                    elif action == "ec2:DeleteTags":
                        allowed = (
                            bool(resource_tag_keys)
                            and not request_tag_keys
                            and "ec2:CreateAction" not in context
                        )
                    elif action == "elasticloadbalancing:AddTags":
                        create_action = context.get("elasticloadbalancing:CreateAction")
                        allowed = (
                            create_action
                            in (["CreateListener"], ["CreateLoadBalancer"], ["CreateTargetGroup"])
                            and resources == ["*"]
                            and bool(request_tag_keys)
                            and not resource_tag_keys
                        )
                    elif action == "iam:SimulatePrincipalPolicy":
                        allowed = resources == ["arn:aws:iam::123456789012:role/operator"]
                    elif action in {
                        "iam:AddRoleToInstanceProfile",
                        "iam:RemoveRoleFromInstanceProfile",
                    }:
                        allowed = all(":instance-profile/" in resource for resource in resources)
                    creation_actions = {
                        "ec2:AllocateAddress",
                        "ec2:CreateInternetGateway",
                        "ec2:CreateNetworkAclEntry",
                        "ec2:CreateRoute",
                        "ec2:CreateVolume",
                        "ec2:CreateVpc",
                        "ec2:CreateVpcEndpointServiceConfiguration",
                        "elasticloadbalancing:CreateLoadBalancer",
                        "elasticloadbalancing:CreateTargetGroup",
                        "iam:CreateInstanceProfile",
                        "iam:CreateRole",
                        "logs:CreateLogGroup",
                        "s3:CreateBucket",
                    }
                    existing_resource_actions = {
                        "ec2:DeleteVpc",
                        "ec2:ModifyVpcAttribute",
                        "elasticloadbalancing:DeleteListener",
                        "elasticloadbalancing:ModifyListenerAttributes",
                        "iam:DeleteRole",
                        "logs:DeleteLogGroup",
                        "s3:DeleteBucket",
                        "ssm:DeleteParameter",
                    }
                    if action in creation_actions:
                        allowed = allowed and not resource_tag_keys
                    if action in existing_resource_actions:
                        allowed = (
                            allowed
                            and bool(resource_tag_keys)
                            and not request_tag_keys
                        )
                    if action != "ec2:CreateTags":
                        allowed = allowed and "ec2:CreateAction" not in context
                    if action != "elasticloadbalancing:AddTags":
                        allowed = (
                            allowed
                            and "elasticloadbalancing:CreateAction" not in context
                        )
                    if action in {
                        "ec2:CreateVpc",
                        "iam:CreateRole",
                        "logs:CreateLogGroup",
                    }:
                        allowed = allowed and context.get("aws:RequestTag/EnvelopeRun") == ["envelope-fixture"]
                        allowed = allowed and context.get("aws:RequestTag/ExpiresAt") == [self.config.expires_at]
                        allowed = allowed and set(context.get("aws:TagKeys", [])) >= {
                            "EnvelopeRun",
                            "ExpiresAt",
                        }
                    results.append(
                        {
                            "EvalActionName": action,
                            "EvalDecision": "allowed" if allowed else "implicitDeny",
                            "ResourceSpecificResults": [
                                {
                                    "EvalResourceName": resource,
                                    "EvalResourceDecision": "allowed" if allowed else "implicitDeny",
                                }
                                for resource in resources
                            ],
                        }
                    )
                return {"EvaluationResults": results, "IsTruncated": False}

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            batches = appliance.build_operator_simulation_batches(
                config,
                "123456789012",
                artifact,
                policy_source_arn="arn:aws:iam::123456789012:role/operator",
            )
            by_name = {batch["name"]: batch for batch in batches}
            artifact_object = by_name["s3-artifact-object"]
            self.assertEqual(
                artifact_object["resources"],
                (
                    "arn:aws:s3:::envelope-fixture-123456789012-us-west-2-artifact/"
                    + f"artifacts/{artifact['revision']}/envelope-linux-amd64",
                ),
            )
            west_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["ssm-west-parameter"]["context"]
            }
            self.assertEqual(west_context["aws:RequestedRegion"], ["us-west-2"])
            self.assertEqual(west_context["aws:ResourceTag/EnvelopeRun"], [config.run_id])
            self.assertEqual(west_context["aws:ResourceTag/ExpiresAt"], [config.expires_at])
            self.assertNotIn("aws:RequestTag/EnvelopeRun", west_context)
            self.assertEqual(
                by_name["ssm-west-parameter"]["resources"],
                ("arn:aws:ssm:us-west-2:123456789012:parameter/envelope-fixture/tailscale-auth",),
            )
            create_parameter_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["ssm-west-parameter-create"]["context"]
            }
            self.assertIn("aws:RequestTag/EnvelopeRun", create_parameter_context)
            self.assertNotIn("aws:ResourceTag/EnvelopeRun", create_parameter_context)
            update_parameter_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["ssm-west-parameter-update"]["context"]
            }
            self.assertIn("aws:ResourceTag/EnvelopeRun", update_parameter_context)
            self.assertNotIn("aws:RequestTag/EnvelopeRun", update_parameter_context)
            backend_list_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["s3-backend-list-state"]["context"]
            }
            self.assertEqual(backend_list_context["s3:prefix"], [config.backend["state_key"]])
            state_put_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["s3-backend-state-put"]["context"]
            }
            self.assertEqual(state_put_context["s3:x-amz-server-side-encryption"], ["aws:kms"])
            self.assertEqual(
                state_put_context["s3:x-amz-server-side-encryption-aws-kms-key-id"],
                [config.backend["kms_key_arn"]],
            )
            self.assertNotIn("s3:RequestObjectTag/EnvelopeRun", state_put_context)
            manifest_put_context = {
                entry["ContextKeyName"]: entry["ContextKeyValues"]
                for entry in by_name["s3-backend-manifest-put"]["context"]
            }
            self.assertEqual(manifest_put_context["s3:RequestObjectTag/EnvelopeRun"], [config.run_id])
            self.assertEqual(manifest_put_context["s3:RequestObjectTag/ExpiresAt"], [config.expires_at])
            kms_contexts = {
                name: {
                    entry["ContextKeyName"]: entry["ContextKeyValues"]
                    for entry in by_name[name]["context"]
                }
                for name in ("kms-backend-s3-state", "kms-backend-s3-lock", "kms-backend-s3-manifest")
            }
            self.assertEqual(
                {
                    values["kms:EncryptionContext:aws:s3:arn"][0]
                    for values in kms_contexts.values()
                },
                {f"arn:aws:s3:::{config.backend['bucket']}"},
            )
            self.assertTrue(
                all(values["kms:EncryptionContextKeys"] == ["aws:s3:arn"] for values in kms_contexts.values())
            )
            self.assertTrue(
                all(
                    by_name[name]["resources"] == (config.backend["kms_key_arn"],)
                    for name in kms_contexts
                )
            )
            backend_object_resources = {
                "s3-backend-state-read-delete": config.backend["state_key"],
                "s3-backend-state-put": config.backend["state_key"],
                "s3-backend-lock-read-delete": config.lock_key,
                "s3-backend-lock-put": config.lock_key,
                "s3-backend-manifest-get": config.manifest_key,
                "s3-backend-manifest-read-delete": config.manifest_key,
                "s3-backend-manifest-put": config.manifest_key,
                "s3-backend-manifest-put-tags": config.manifest_key,
            }
            for name, key in backend_object_resources.items():
                self.assertEqual(
                    by_name[name]["resources"],
                    (f"arn:aws:s3:::{config.backend['bucket']}/{key}",),
                )
            for site in ("west", "east"):
                ssm_kms_context = {
                    entry["ContextKeyName"]: entry["ContextKeyValues"]
                    for entry in by_name[f"kms-{site}-ssm"]["context"]
                }
                self.assertEqual(ssm_kms_context["kms:EncryptionContextKeys"], ["PARAMETER_ARN"])
                self.assertIn("kms:EncryptionContext:PARAMETER_ARN", ssm_kms_context)
                self.assertNotIn("kms:EncryptionContext:aws:s3:arn", ssm_kms_context)
            quota_batches = [batch for name, batch in by_name.items() if name.startswith("service-quota-")]
            self.assertEqual(
                len(quota_batches),
                2 * len(appliance.AWS_REGIONAL_QUOTA_CONTRACT) + len(appliance.AWS_GLOBAL_QUOTA_CONTRACT),
            )
            self.assertTrue(
                all(
                    len(batch["resources"]) == 1
                    and batch["resources"][0].startswith("arn:aws:servicequotas:")
                    and batch["resources"][0] != "*"
                    for batch in quota_batches
                )
            )
            api = ExactPolicyAWS(config, artifact)
            appliance.simulate_operator_actions(
                api,
                "arn:aws:iam::123456789012:role/operator",
                config,
                "123456789012",
                artifact,
            )
            self.assertEqual(len(api.calls), len(batches))
            self.assertTrue(
                all(
                    call[call.index("--policy-source-arn") + 1]
                    == "arn:aws:iam::123456789012:role/operator"
                    for call in api.calls
                )
            )

    def test_backend_kms_identity_policy_rejects_object_only_and_wrong_bucket_contexts(self):
        class ContextRestrictedAWS(CapabilityAWS):
            def __init__(self, config, mode):
                super().__init__(config)
                self.mode = mode

            def json(self, args, *, region=None):
                response = super().json(args, region=region)
                if args[:2] != ["iam", "simulate-principal-policy"]:
                    return response
                context_start = (
                    args.index("--context-entries")
                    if "--context-entries" in args
                    else len(args)
                )
                context = (
                    {
                        entry["ContextKeyName"]: entry["ContextKeyValues"]
                        for entry in json.loads(args[context_start + 1])
                    }
                    if context_start < len(args)
                    else {}
                )
                encryption_context = context.get("kms:EncryptionContext:aws:s3:arn")
                if encryption_context is None:
                    return response
                bucket_arn = f"arn:aws:s3:::{self.config.backend['bucket']}"
                if self.mode == "object-only":
                    allowed = (
                        len(encryption_context) == 1
                        and encryption_context[0].startswith(f"{bucket_arn}/")
                    )
                elif self.mode == "wrong-bucket":
                    allowed = encryption_context == ["arn:aws:s3:::other-backend"]
                else:
                    raise AssertionError(self.mode)
                decision = "allowed" if allowed else "implicitDeny"
                for result in response["EvaluationResults"]:
                    if result["EvalActionName"] not in {
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                    }:
                        continue
                    result["EvalDecision"] = decision
                    for resource_result in result["ResourceSpecificResults"]:
                        resource_result["EvalResourceDecision"] = decision
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            for mode in ("object-only", "wrong-bucket"):
                with self.subTest(mode=mode):
                    with self.assertRaisesRegex(appliance.LifecycleError, "kms:"):
                        appliance.simulate_operator_actions(
                            ContextRestrictedAWS(config, mode),
                            "arn:aws:iam::123456789012:role/operator",
                            config,
                            "123456789012",
                            artifact,
                        )

    def test_missing_operator_action_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for decision in ("implicitDeny", "explicitDeny"):
                with self.subTest(decision=decision):
                    aws = CapabilityAWS(config)
                    aws.denied_action = "ssm:SendCommand"
                    aws.denied_decision = decision
                    with self.assertRaisesRegex(appliance.LifecycleError, "ssm:SendCommand"):
                        appliance.aws_capability_quota_preflight(
                            config, aws, fixture_instance_vcpus(config), artifact_identity(pathlib.Path(temporary))
                        )

    def test_each_mandatory_simulation_resource_must_have_an_allowed_decision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            send_batch = next(
                batch
                for batch in appliance.build_operator_simulation_batches(
                    config,
                    "123456789012",
                    artifact,
                    policy_source_arn="arn:aws:iam::123456789012:role/operator",
                )
                if batch["name"] == "ssm-west-send-command"
            )
            for decision in ("implicitDeny", "explicitDeny"):
                with self.subTest(decision=decision):
                    aws = CapabilityAWS(config)
                    aws.denied_action = "ssm:SendCommand"
                    aws.denied_decision = decision
                    aws.denied_resource = send_batch["resources"][1]
                    expected = (
                        "explicitly denied ssm:SendCommand"
                        if decision == "explicitDeny"
                        else rf"ssm:SendCommand.*{re.escape(aws.denied_resource)}"
                    )
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        expected,
                    ):
                        appliance.aws_capability_quota_preflight(
                            config,
                            aws,
                            fixture_instance_vcpus(config),
                            artifact,
                        )

            class OmittedResourceAWS(CapabilityAWS):
                def json(self, args, *, region=None):
                    response = super().json(args, region=region)
                    if args[:2] == ["iam", "simulate-principal-policy"]:
                        for result in response["EvaluationResults"]:
                            if result["EvalActionName"] == "ssm:SendCommand":
                                result["ResourceSpecificResults"].pop()
                    return response

            with self.assertRaisesRegex(appliance.LifecycleError, "omitted mandatory resource"):
                appliance.aws_capability_quota_preflight(
                    config,
                    OmittedResourceAWS(config),
                    fixture_instance_vcpus(config),
                    artifact,
                )

    def test_unresolved_policy_context_reports_the_exact_actionable_key(self):
        class MissingContextAWS(CapabilityAWS):
            def json(self, args, *, region=None):
                response = super().json(args, region=region)
                if args[:2] == ["iam", "simulate-principal-policy"]:
                    for result in response["EvaluationResults"]:
                        if result["EvalActionName"] == "ssm:SendCommand":
                            result["EvalDecision"] = "implicitDeny"
                            result["MissingContextValues"] = ["ssm:ResourceTag/Environment"]
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            with self.assertRaisesRegex(
                appliance.LifecycleError,
                "ssm:SendCommand.*ssm:ResourceTag/Environment",
            ):
                appliance.aws_capability_quota_preflight(
                    config,
                    MissingContextAWS(config),
                    fixture_instance_vcpus(config),
                    artifact_identity(root),
                )

    def test_ssm_kms_key_policy_requires_effective_exact_operator_and_ssm_context_authorization(self):
        class KeyPolicyAWS(CapabilityAWS):
            def __init__(self, config, *, principal_mode="root", mutation=None):
                super().__init__(config)
                self.principal_mode = principal_mode
                self.mutation = mutation

            def json(self, args, *, region=None):
                if args[:2] != ["kms", "get-key-policy"]:
                    return super().json(args, region=region)
                partition = self.role_arn.split(":", 2)[1]
                principal = (
                    self.role_arn
                    if self.principal_mode == "direct"
                    else f"arn:{partition}:iam::123456789012:root"
                )
                parameter_arn = (
                    f"arn:{partition}:ssm:{region}:123456789012:"
                    "parameter/envelope-fixture/tailscale-auth"
                )
                site = "west" if region == self.config.sites["west"]["region"] else "east"
                runtime_role = f"arn:aws:iam::123456789012:role/envelope-fixture-{site}-appliance"
                condition: dict = {
                    "StringEquals": {
                        "kms:ViaService": f"ssm.{region}.amazonaws.com",
                        "kms:EncryptionContext:PARAMETER_ARN": parameter_arn,
                    },
                    "ForAllValues:StringEquals": {
                        "kms:EncryptionContextKeys": ["PARAMETER_ARN"]
                    },
                }
                if self.mutation == "wrong-via-service":
                    condition["StringEquals"]["kms:ViaService"] = "ssm.eu-west-1.amazonaws.com"
                elif self.mutation == "wrong-parameter":
                    condition["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"] = parameter_arn + "/other"
                elif self.mutation == "unsupported-condition":
                    condition = {"NumericEquals": {"kms:EncryptionContext:PARAMETER_ARN": "1"}}
                operator_allow = {
                    "Effect": "Allow",
                    "Principal": {"AWS": self.role_arn},
                    "Action": ["kms:Encrypt", "kms:Decrypt"],
                    "Resource": "*",
                    "Condition": copy.deepcopy(condition),
                }
                if self.principal_mode == "root":
                    statements = [
                        {
                            **operator_allow,
                            "Principal": {"AWS": principal},
                        }
                    ]
                elif self.principal_mode == "operator-only":
                    statements = [operator_allow]
                elif self.principal_mode == "wildcard-runtime":
                    runtime_condition = copy.deepcopy(condition)
                    runtime_condition["ArnEquals"] = {"aws:PrincipalArn": runtime_role}
                    if self.mutation == "arnlike-runtime":
                        runtime_condition["ArnLike"] = runtime_condition.pop("ArnEquals")
                    elif self.mutation == "wrong-runtime-role":
                        runtime_condition["ArnEquals"]["aws:PrincipalArn"] = runtime_role.replace(
                            f"-{site}-", "-wrong-"
                        )
                    elif self.mutation == "wrong-runtime-site":
                        runtime_condition["StringEquals"]["kms:ViaService"] = (
                            "ssm.us-east-2.amazonaws.com"
                        )
                    elif self.mutation == "wrong-runtime-parameter":
                        runtime_condition["StringEquals"][
                            "kms:EncryptionContext:PARAMETER_ARN"
                        ] = parameter_arn + "/wrong"
                    elif self.mutation == "broad-runtime-wildcard":
                        runtime_condition.pop("ArnEquals")
                    statements = [
                        operator_allow,
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:Decrypt",
                            "Resource": "*",
                            "Condition": runtime_condition,
                        },
                    ]
                else:
                    raise AssertionError(self.principal_mode)
                if self.mutation == "explicit-deny":
                    statements.append({**copy.deepcopy(statements[0]), "Effect": "Deny"})
                elif self.mutation == "runtime-explicit-deny":
                    statements.append({**copy.deepcopy(statements[-1]), "Effect": "Deny"})
                return {"Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            for principal_mode, mutation in (
                ("root", None),
                ("wildcard-runtime", None),
                ("wildcard-runtime", "arnlike-runtime"),
            ):
                with self.subTest(principal_mode=principal_mode, mutation=mutation):
                    appliance.aws_capability_quota_preflight(
                        config,
                        KeyPolicyAWS(
                            config,
                            principal_mode=principal_mode,
                            mutation=mutation,
                        ),
                        fixture_instance_vcpus(config),
                        artifact_identity(root),
                    )
            with self.assertRaisesRegex(appliance.LifecycleError, "future regional appliance role"):
                appliance.aws_capability_quota_preflight(
                    config,
                    KeyPolicyAWS(config, principal_mode="operator-only"),
                    fixture_instance_vcpus(config),
                    artifact_identity(root),
                )
            for mutation, message in (
                ("wrong-via-service", "ViaService"),
                ("wrong-parameter", "PARAMETER_ARN"),
                ("explicit-deny", "explicitly denies"),
                ("unsupported-condition", "unsupported condition operator"),
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaisesRegex(appliance.LifecycleError, message):
                        appliance.aws_capability_quota_preflight(
                            config,
                            KeyPolicyAWS(config, mutation=mutation),
                            fixture_instance_vcpus(config),
                            artifact_identity(root),
                        )
            for mutation in (
                "wrong-runtime-role",
                "wrong-runtime-site",
                "wrong-runtime-parameter",
                "broad-runtime-wildcard",
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaisesRegex(appliance.LifecycleError, "future regional appliance role"):
                        appliance.aws_capability_quota_preflight(
                            config,
                            KeyPolicyAWS(
                                config,
                                principal_mode="wildcard-runtime",
                                mutation=mutation,
                            ),
                            fixture_instance_vcpus(config),
                            artifact_identity(root),
                        )

            with self.assertRaisesRegex(appliance.LifecycleError, "explicitly denies.*future"):
                appliance.aws_capability_quota_preflight(
                    config,
                    KeyPolicyAWS(
                        config,
                        principal_mode="wildcard-runtime",
                        mutation="runtime-explicit-deny",
                    ),
                    fixture_instance_vcpus(config),
                    artifact_identity(root),
                )

            denied_runtime = KeyPolicyAWS(config)
            denied_runtime.runtime_kms_decision = "implicitDeny"
            with self.assertRaisesRegex(appliance.LifecycleError, "appliance-runtime-kms"):
                appliance.aws_capability_quota_preflight(
                    config,
                    denied_runtime,
                    fixture_instance_vcpus(config),
                    artifact_identity(root),
                )

    def test_low_service_quota_account_limit_and_endpoint_service_headroom_fail_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for gate, message in (("standard-vcpus", "too low"), ("s3-artifact-buckets", "too low")):
                with self.subTest(gate=gate):
                    aws = CapabilityAWS(config)
                    aws.low_quota_gate = gate
                    with self.assertRaisesRegex(appliance.LifecycleError, f"{gate}.*{message}"):
                        appliance.aws_capability_quota_preflight(
                            config, aws, fixture_instance_vcpus(config), artifact_identity(pathlib.Path(temporary))
                        )
            aws = CapabilityAWS(config)
            aws.omitted_quota_gate = "target-groups"
            with self.assertRaisesRegex(appliance.LifecycleError, "target-groups.*L-B22855CB"):
                appliance.aws_capability_quota_preflight(
                    config, aws, fixture_instance_vcpus(config), artifact_identity(pathlib.Path(temporary))
                )
            for gate in appliance.AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT:
                with self.subTest(account_limit=gate):
                    aws = CapabilityAWS(config)
                    aws.low_account_limit_gate = gate
                    with self.assertRaisesRegex(appliance.LifecycleError, rf"{re.escape(gate)}.*too low"):
                        appliance.aws_capability_quota_preflight(
                            config,
                            aws,
                            fixture_instance_vcpus(config),
                            artifact_identity(pathlib.Path(temporary)),
                        )

            class FullEndpointServiceAWS(CapabilityAWS):
                def json(self, args, *, region=None):
                    if args[:2] == ["ec2", "describe-vpc-endpoint-service-configurations"]:
                        return {
                            "ServiceConfigurations": [
                                {"ServiceId": f"vpce-svc-{index:03d}", "ServiceState": "Available"}
                                for index in range(50)
                            ]
                        }
                    return super().json(args, region=region)

            with self.assertRaisesRegex(appliance.LifecycleError, "vpc-endpoint-services.*too low"):
                appliance.aws_capability_quota_preflight(
                    config,
                    FullEndpointServiceAWS(config),
                    fixture_instance_vcpus(config),
                    artifact_identity(pathlib.Path(temporary)),
                )

    def test_nat_per_az_headroom_counts_literal_zonal_schema_and_excludes_regional(self):
        class NatUsageAWS(CapabilityAWS):
            def json(self, args, *, region=None):
                if args[:2] == ["ec2", "describe-nat-gateways"]:
                    self.calls.append((list(args), region))
                    if region != "us-west-2":
                        return {"NatGateways": []}
                    return {
                        "NatGateways": [
                            {
                                "NatGatewayId": "nat-00000000000000001",
                                "State": "available",
                                "AvailabilityMode": "zonal",
                                "SubnetId": "subnet-00000000000000001",
                                "VpcId": "vpc-00000000000000001",
                                "NatGatewayAddresses": [{"PrivateIp": "10.0.0.10"}],
                            },
                            {
                                "NatGatewayId": "nat-00000000000000002",
                                "State": "pending",
                                "AvailabilityMode": "zonal",
                                "SubnetId": "subnet-00000000000000002",
                                "VpcId": "vpc-00000000000000001",
                                "NatGatewayAddresses": [{"PrivateIp": "10.0.0.11"}],
                            },
                            {
                                "NatGatewayId": "nat-00000000000000003",
                                "State": "deleting",
                                "AvailabilityMode": "zonal",
                                "SubnetId": "subnet-00000000000000003",
                                "VpcId": "vpc-00000000000000001",
                                "NatGatewayAddresses": [{"PrivateIp": "10.0.0.12"}],
                            },
                            {
                                "NatGatewayId": "nat-00000000000000004",
                                "State": "available",
                                "AvailabilityMode": "zonal",
                                "SubnetId": "subnet-00000000000000004",
                                "VpcId": "vpc-00000000000000001",
                                "NatGatewayAddresses": [{"PrivateIp": "10.0.1.10"}],
                            },
                            {
                                "NatGatewayId": "nat-10000000000000001",
                                "State": "available",
                                "AvailabilityMode": "regional",
                                "VpcId": "vpc-10000000000000001",
                                "RouteTableId": "rtb-10000000000000001",
                                "NatGatewayAddresses": [
                                    {"AvailabilityZone": "us-west-2a", "PrivateIp": "10.1.0.10"},
                                    {"AvailabilityZone": "us-west-2b", "PrivateIp": "10.1.1.10"},
                                ],
                            },
                        ]
                    }
                if args[:2] == ["ec2", "describe-subnets"] and "--subnet-ids" in args:
                    self.calls.append((list(args), region))
                    zones = {
                        "subnet-00000000000000001": "us-west-2a",
                        "subnet-00000000000000002": "us-west-2a",
                        "subnet-00000000000000003": "us-west-2a",
                        "subnet-00000000000000004": "us-west-2b",
                    }
                    requested = args[args.index("--subnet-ids") + 1 :]
                    if set(requested) != set(zones):
                        raise AssertionError(requested)
                    return {
                        "Subnets": [
                            {"SubnetId": subnet_id, "AvailabilityZone": zones[subnet_id]}
                            for subnet_id in requested
                        ]
                    }
                response = super().json(args, region=region)
                if (
                    args[:2] == ["service-quotas", "get-service-quota"]
                    and args[args.index("--quota-code") + 1] == "L-FE5A380F"
                ):
                    response["Quota"]["Value"] = 4.0
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = NatUsageAWS(config)
            _, summary = appliance.aws_capability_quota_preflight(
                config,
                aws,
                fixture_instance_vcpus(config),
                artifact_identity(root),
            )

        west = summary["regions"]["us-west-2"]
        nat_quota = west["quotas"]["nat-gateways-per-availability-zone"]
        self.assertEqual(
            (nat_quota["limit"], nat_quota["used"], nat_quota["required"], nat_quota["available"]),
            (4, 3, 1, 1),
        )
        self.assertEqual(west["quotas"]["elastic-ips"]["used"], 0)
        self.assertEqual(west["excluded_regional_nat_gateways"], 1)
        self.assertEqual(summary["regions"]["us-east-1"]["excluded_regional_nat_gateways"], 0)
        subnet_calls = [
            (args, region)
            for args, region in aws.calls
            if args[:2] == ["ec2", "describe-subnets"] and "--subnet-ids" in args
        ]
        self.assertEqual(len(subnet_calls), 1)
        self.assertEqual(subnet_calls[0][1], "us-west-2")
        self.assertEqual(
            set(subnet_calls[0][0][subnet_calls[0][0].index("--subnet-ids") + 1 :]),
            {
                "subnet-00000000000000001",
                "subnet-00000000000000002",
                "subnet-00000000000000003",
                "subnet-00000000000000004",
            },
        )
        serialized = json.dumps(summary, sort_keys=True)
        for identifier in (
            "nat-00000000000000001",
            "nat-10000000000000001",
            "subnet-00000000000000001",
            "vpc-10000000000000001",
            "rtb-10000000000000001",
        ):
            self.assertNotIn(identifier, serialized)

    def test_nat_usage_rejects_unknown_modes_and_malformed_literal_schemas(self):
        zonal = {
            "NatGatewayId": "nat-20000000000000001",
            "State": "available",
            "AvailabilityMode": "zonal",
            "SubnetId": "subnet-20000000000000001",
            "VpcId": "vpc-20000000000000001",
            "NatGatewayAddresses": [{"PrivateIp": "10.2.0.10"}],
        }
        regional = {
            "NatGatewayId": "nat-30000000000000001",
            "State": "available",
            "AvailabilityMode": "regional",
            "VpcId": "vpc-30000000000000001",
            "RouteTableId": "rtb-30000000000000001",
            "NatGatewayAddresses": [
                {"AvailabilityZone": "us-west-2a", "PrivateIp": "10.3.0.10"}
            ],
        }
        malformed = (
            ("missing-mode", {key: value for key, value in zonal.items() if key != "AvailabilityMode"}),
            ("unknown-mode", {**zonal, "AvailabilityMode": "multi-az"}),
            ("unknown-state", {**zonal, "State": "active"}),
            ("zonal-missing-subnet", {key: value for key, value in zonal.items() if key != "SubnetId"}),
            ("zonal-malformed-subnet", {**zonal, "SubnetId": "subnet-not-an-id"}),
            ("regional-with-subnet", {**regional, "SubnetId": "subnet-30000000000000001"}),
            ("regional-missing-vpc", {key: value for key, value in regional.items() if key != "VpcId"}),
            (
                "regional-missing-route-table",
                {key: value for key, value in regional.items() if key != "RouteTableId"},
            ),
            ("regional-empty-addresses", {**regional, "NatGatewayAddresses": []}),
            (
                "regional-invalid-address-zone",
                {**regional, "NatGatewayAddresses": [{"AvailabilityZone": "us-east-1a"}]},
            ),
        )

        class LiteralNatAWS(CapabilityAWS):
            def __init__(self, config, gateway, subnets=None):
                super().__init__(config)
                self.gateway = gateway
                self.subnets = (
                    [
                        {
                            "SubnetId": "subnet-20000000000000001",
                            "AvailabilityZone": "us-west-2a",
                        }
                    ]
                    if subnets is None
                    else subnets
                )

            def json(self, args, *, region=None):
                if args[:2] == ["ec2", "describe-nat-gateways"]:
                    self.calls.append((list(args), region))
                    return {"NatGateways": [copy.deepcopy(self.gateway)]}
                if args[:2] == ["ec2", "describe-subnets"] and "--subnet-ids" in args:
                    self.calls.append((list(args), region))
                    return {"Subnets": copy.deepcopy(self.subnets)}
                return super().json(args, region=region)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for name, gateway in malformed:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(appliance.LifecycleError, "NAT current usage"):
                        appliance.regional_quota_usage(
                            config,
                            LiteralNatAWS(config, gateway),
                            "west",
                        )
            malformed_subnet_responses = (
                ("missing", []),
                (
                    "wrong-region",
                    [
                        {
                            "SubnetId": "subnet-20000000000000001",
                            "AvailabilityZone": "us-east-1a",
                        }
                    ],
                ),
            )
            for name, subnets in malformed_subnet_responses:
                with self.subTest(zonal_subnet_resolution=name):
                    with self.assertRaisesRegex(appliance.LifecycleError, "NAT current usage"):
                        appliance.regional_quota_usage(
                            config,
                            LiteralNatAWS(config, zonal, subnets),
                            "west",
                        )

    def test_standard_vcpu_quota_subtracts_default_weight_of_current_on_demand_instances(self):
        class UsageAWS(CapabilityAWS):
            def json(self, args, *, region=None):
                if args[:2] == ["ec2", "describe-instances"]:
                    return {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "State": {"Name": "running"},
                                        "InstanceType": "t3.medium",
                                        "Placement": {"Tenancy": "default"},
                                    },
                                    {
                                        "State": {"Name": "pending"},
                                        "InstanceType": "c7g.large",
                                        "Placement": {"Tenancy": "default"},
                                    },
                                    {
                                        "State": {"Name": "running"},
                                        "InstanceType": "t3.medium",
                                        "InstanceLifecycle": "spot",
                                        "Placement": {"Tenancy": "default"},
                                    },
                                    {
                                        "State": {"Name": "running"},
                                        "InstanceType": "p5.48xlarge",
                                        "Placement": {"Tenancy": "default"},
                                    },
                                ]
                            }
                        ]
                    }
                if args[:2] == ["ec2", "describe-instance-types"]:
                    defaults = {"t3.medium": 2, "c7g.large": 4}
                    return {
                        "InstanceTypes": [
                            {"InstanceType": name, "VCpuInfo": {"DefaultVCpus": defaults[name]}}
                            for name in args[args.index("--instance-types") + 1 :]
                        ]
                    }
                if args[:2] == ["ec2", "describe-vpc-endpoint-service-configurations"]:
                    return {
                        "ServiceConfigurations": [
                            {"ServiceId": "vpce-svc-one", "ServiceState": "Available"},
                            {"ServiceId": "vpce-svc-two", "ServiceState": "Pending"},
                            {"ServiceId": "vpce-svc-old", "ServiceState": "Deleted"},
                        ]
                    }
                if args[:2] == ["elbv2", "describe-load-balancers"]:
                    return {
                        "LoadBalancers": [
                            {"LoadBalancerArn": "arn:aws:elasticloadbalancing:fixture:gwlb-one", "Type": "gateway"},
                            {"LoadBalancerArn": "arn:aws:elasticloadbalancing:fixture:gwlb-two", "Type": "gateway"},
                            {"LoadBalancerArn": "arn:aws:elasticloadbalancing:fixture:alb", "Type": "application"},
                        ]
                    }
                if args[:2] == ["elbv2", "describe-target-groups"]:
                    return {
                        "TargetGroups": [
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:fixture:geneve-one",
                                "Protocol": "GENEVE",
                                "TargetType": "instance",
                            },
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:fixture:geneve-two",
                                "Protocol": "GENEVE",
                                "TargetType": "ip",
                            },
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:fixture:tcp",
                                "Protocol": "TCP",
                                "TargetType": "instance",
                            },
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:fixture:lambda",
                                "TargetType": "lambda",
                            },
                        ]
                    }
                if args[:2] == ["s3api", "list-buckets"]:
                    return {"Buckets": [{"Name": "one"}, {"Name": "two"}]}
                return super().json(args, region=region)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            _, summary = appliance.aws_capability_quota_preflight(
                config,
                UsageAWS(config),
                fixture_instance_vcpus(config),
                artifact_identity(pathlib.Path(temporary)),
            )
        for value in summary["regions"].values():
            self.assertEqual(value["quotas"]["standard-vcpus"]["used"], 6)
            self.assertEqual(value["quotas"]["standard-vcpus"]["available"], 94)
            self.assertEqual(value["quotas"]["gateway-load-balancers"]["used"], 2)
            self.assertEqual(value["quotas"]["gateway-load-balancers"]["available"], 98)
            self.assertEqual(value["quotas"]["geneve-target-groups"]["used"], 2)
            self.assertEqual(value["quotas"]["target-groups"]["used"], 4)
            self.assertEqual(value["quotas"]["vpc-endpoint-services"]["used"], 3)
            self.assertEqual(value["quotas"]["vpc-endpoint-services"]["available"], 47)
        self.assertEqual(summary["global_quotas"]["s3-artifact-buckets"]["used"], 2)

    def test_malformed_or_duplicate_gwlb_geneve_and_endpoint_service_usage_fails_closed(self):
        class MalformedUsageAWS(CapabilityAWS):
            def __init__(self, config, mode):
                super().__init__(config)
                self.mode = mode

            def json(self, args, *, region=None):
                if args[:2] == ["elbv2", "describe-load-balancers"] and self.mode == "load-balancer":
                    value = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:fixture:duplicate", "Type": "gateway"}
                    return {"LoadBalancers": [value, copy.deepcopy(value)]}
                if args[:2] == ["elbv2", "describe-target-groups"] and self.mode == "target-group":
                    return {
                        "TargetGroups": [
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:fixture:missing-protocol",
                                "TargetType": "instance",
                            }
                        ]
                    }
                if args[:2] == ["ec2", "describe-vpc-endpoint-service-configurations"] and self.mode == "endpoint-service":
                    return {
                        "ServiceConfigurations": [
                            {"ServiceId": "vpce-svc-fixture", "ServiceState": "Unknown"}
                        ]
                    }
                return super().json(args, region=region)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            for mode, message in (
                ("load-balancer", "gateway-load-balancers/current-usage"),
                ("target-group", "target-groups/current-usage"),
                ("endpoint-service", "vpc-endpoint-services/current-usage"),
            ):
                with self.subTest(mode=mode):
                    with self.assertRaisesRegex(appliance.LifecycleError, message):
                        appliance.aws_capability_quota_preflight(
                            config,
                            MalformedUsageAWS(config, mode),
                            fixture_instance_vcpus(config),
                            artifact_identity(root),
                        )

    def test_malformed_iam_and_quota_response_schemas_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            malformed_quota = CapabilityAWS(config)
            malformed_quota.malformed_quota_schema = True
            with self.assertRaisesRegex(appliance.LifecycleError, "mismatched or malformed quota"):
                appliance.aws_capability_quota_preflight(
                    config,
                    malformed_quota,
                    fixture_instance_vcpus(config),
                    artifact_identity(pathlib.Path(temporary)),
                )

            malformed_simulation = CapabilityAWS(config)
            original_json = malformed_simulation.json

            def malformed(args, *, region=None):
                if args[:2] == ["iam", "simulate-principal-policy"]:
                    return {"EvaluationResults": {}}
                return original_json(args, region=region)

            malformed_simulation.json = malformed
            with self.assertRaisesRegex(appliance.LifecycleError, "malformed result schema"):
                appliance.aws_capability_quota_preflight(
                    config,
                    malformed_simulation,
                    fixture_instance_vcpus(config),
                    artifact_identity(pathlib.Path(temporary)),
                )

    def test_run_preflight_retains_summary_without_changing_two_value_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            summary = artifact.pop("aws_preflight")
            with mock.patch.object(appliance, "validate_artifact", return_value=artifact), mock.patch.object(
                appliance.BackendValidator, "validate"
            ), mock.patch.object(
                appliance, "validate_aws_metadata", return_value=fixture_instance_vcpus(config)
            ), mock.patch.object(
                appliance,
                "aws_capability_quota_preflight",
                return_value=("123456789012", summary),
            ), mock.patch.object(appliance, "tailnet_preflight"):
                selected, account_id = appliance.run_preflight(config, object(), object())
            manifest = appliance.new_manifest(config, selected, account_id)
            self.assertEqual(selected["aws_preflight"], summary)
            self.assertEqual(manifest["aws_preflight"], summary)
            self.assertIsNot(selected["aws_preflight"], manifest["aws_preflight"])


class PolicyAndAdapterTest(unittest.TestCase):
    def test_hujson_comments_unquoted_keys_and_trailing_commas(self):
        policy = appliance.parse_hujson(
            """
            {
              // fixture comment
              tagOwners: {"tag:envelope-ci": ["group:infra",],},
              autoApprovers: {routes: {"10.10.0.0/16": ["tag:envelope-ci"]}},
              grants: [],
            }
            """
        )
        self.assertEqual(policy["tagOwners"]["tag:envelope-ci"], ["group:infra"])

    def test_policy_contract_and_failure_matrix(self):
        arguments = {
            "tag": "tag:envelope-ci",
            "tag_owners": ["group:infra"],
            "advertised_routes": [
                "10.10.1.0/24",
                "10.10.2.0/24",
                "10.20.1.0/24",
                "10.20.2.0/24",
            ],
            "site_cidrs": {
                "west": ["10.10.1.0/24", "10.10.2.0/24"],
                "east": ["10.20.1.0/24", "10.20.2.0/24"],
            },
            "snat_subnet_routes": False,
        }
        appliance.validate_tailnet_policy(copy.deepcopy(VALID_POLICY), **arguments)
        policy_with_disjoint_extras = copy.deepcopy(VALID_POLICY)
        policy_with_disjoint_extras["autoApprovers"]["routes"].update(
            {
                "10.30.1.0/24": ["tag:envelope-ci"],
                "10.40.1.0/24": ["tag:envelope-ci"],
            }
        )
        policy_with_disjoint_extras["grants"].extend(
            [
                {"src": ["10.30.1.0/24"], "dst": ["10.40.1.0/24"], "ip": ["*"]},
                {"src": ["10.40.1.0/24"], "dst": ["10.30.1.0/24"], "ip": ["*"]},
            ]
        )
        appliance.validate_tailnet_policy(policy_with_disjoint_extras, **arguments)
        cases = {
            "tag owner": lambda value: value["tagOwners"].clear(),
            "auto approval": lambda value: value["autoApprovers"]["routes"].pop("10.20.2.0/24"),
            "grant": lambda value: value["grants"].pop(),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                policy = copy.deepcopy(VALID_POLICY)
                mutate(policy)
                with self.assertRaises(appliance.LifecycleError):
                    appliance.validate_tailnet_policy(policy, **arguments)
        with self.assertRaisesRegex(appliance.LifecycleError, "SNAT"):
            appliance.validate_tailnet_policy(copy.deepcopy(VALID_POLICY), **{**arguments, "snat_subnet_routes": True})

        broad_policies = {}
        route_supernet = copy.deepcopy(VALID_POLICY)
        route_supernet["autoApprovers"]["routes"]["10.10.0.0/16"] = ["tag:envelope-ci"]
        broad_policies["route supernet"] = route_supernet
        route_subnet = copy.deepcopy(VALID_POLICY)
        route_subnet["autoApprovers"]["routes"]["10.10.1.0/25"] = ["tag:envelope-ci"]
        broad_policies["route subnet"] = route_subnet
        wildcard_source = copy.deepcopy(VALID_POLICY)
        wildcard_source["grants"].append(
            {"src": ["*"], "dst": ["10.20.1.0/24"], "ip": ["*"]}
        )
        broad_policies["wildcard source"] = wildcard_source
        wildcard_tcp_source = copy.deepcopy(VALID_POLICY)
        wildcard_tcp_source["grants"].append(
            {"src": ["*"], "dst": ["10.20.1.0/24"], "ip": ["tcp"]}
        )
        broad_policies["wildcard TCP source"] = wildcard_tcp_source
        wildcard_destination = copy.deepcopy(VALID_POLICY)
        wildcard_destination["grants"].append(
            {"src": ["10.10.1.0/24"], "dst": ["*"], "ip": ["*"]}
        )
        broad_policies["wildcard destination"] = wildcard_destination
        wildcard_port_destination = copy.deepcopy(VALID_POLICY)
        wildcard_port_destination["grants"].append(
            {"src": ["10.10.1.0/24"], "dst": ["*:*"], "ip": ["*"]}
        )
        broad_policies["wildcard port destination"] = wildcard_port_destination
        grant_supernet = copy.deepcopy(VALID_POLICY)
        grant_supernet["grants"].append(
            {"src": ["10.10.0.0/16"], "dst": ["10.20.0.0/16"], "ip": ["*"]}
        )
        broad_policies["grant supernet"] = grant_supernet
        extra_owner = copy.deepcopy(VALID_POLICY)
        extra_owner["tagOwners"]["tag:envelope-ci"].append("*")
        broad_policies["unreviewed tag owner"] = extra_owner
        for name, policy in broad_policies.items():
            with self.subTest(name=name), self.assertRaises(appliance.LifecycleError):
                appliance.validate_tailnet_policy(policy, **arguments)

    def test_oauth_key_shape_and_lifecycle_are_fixture_testable(self):
        transport = FakeHTTP()
        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", transport)
        self.assertEqual(api.list_devices(), [])
        self.assertTrue(any(urllib.parse.urlparse(url).query == "fields=all" for url in transport.urls))
        key_id, key = api.create_auth_key("tag:envelope-ci", "fixture", 1800)
        self.assertEqual((key_id, key), ("key-fixture-id", "fixture-auth-material"))
        api.revoke_auth_key(key_id)
        create = next(json.loads(body) for method, path, body in transport.requests if method == "POST" and path.endswith("/keys"))
        capabilities = create["capabilities"]["devices"]["create"]
        self.assertEqual(
            capabilities,
            {"reusable": True, "ephemeral": True, "preauthorized": True, "tags": ["tag:envelope-ci"]},
        )
        self.assertEqual(create["expirySeconds"], 1800)

    def test_oauth_token_expiry_uses_injected_monotonic_clock_and_refresh_margin(self):
        class Clock:
            value = 0.0

            def __call__(self):
                return self.value

        class RefreshHTTP:
            def __init__(self):
                self.token_requests = 0
                self.authorizations = []

            def request(self, method, url, *, headers=None, body=None):
                path = urllib.parse.urlparse(url).path
                if path.endswith("/oauth/token"):
                    self.token_requests += 1
                    return 200, json.dumps(
                        {"access_token": f"bearer-{self.token_requests}", "expires_in": "100"}
                    ).encode()
                self.authorizations.append(headers["Authorization"])
                return 200, b'{"devices":[]}'

        clock = Clock()
        transport = RefreshHTTP()
        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", transport, clock=clock)
        api.list_devices()
        clock.value = 89
        api.list_devices()
        clock.value = 90
        api.list_devices()
        self.assertEqual(transport.token_requests, 2)
        self.assertEqual(
            transport.authorizations,
            ["Bearer bearer-1", "Bearer bearer-1", "Bearer bearer-2"],
        )
        self.assertEqual(api._token_expires_at, 190)

    def test_oauth_401_refreshes_and_retries_once_but_other_failures_do_not_retry_or_leak(self):
        class RetryHTTP:
            def __init__(self, statuses):
                self.statuses = list(statuses)
                self.token_requests = 0
                self.api_requests = 0
                self.authorizations = []
                self.sensitive_body = "sensitive-response-body"

            def request(self, method, url, *, headers=None, body=None):
                if urllib.parse.urlparse(url).path.endswith("/oauth/token"):
                    self.token_requests += 1
                    return 200, json.dumps(
                        {"access_token": f"private-bearer-{self.token_requests}", "expires_in": 3600}
                    ).encode()
                self.api_requests += 1
                self.authorizations.append(headers["Authorization"])
                status = self.statuses.pop(0)
                return status, (
                    b'{"devices":[]}'
                    if status == 200
                    else json.dumps({"message": self.sensitive_body}).encode()
                )

        recovered = RetryHTTP([401, 200])
        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", recovered, clock=lambda: 0)
        self.assertEqual(api.list_devices(), [])
        self.assertEqual((recovered.token_requests, recovered.api_requests), (2, 2))
        self.assertEqual(
            recovered.authorizations,
            ["Bearer private-bearer-1", "Bearer private-bearer-2"],
        )

        for statuses, expected_tokens, expected_api_calls in (([403], 1, 1), ([401, 401], 2, 2)):
            with self.subTest(statuses=statuses):
                failed = RetryHTTP(statuses)
                candidate = appliance.TailscaleAPI(
                    "fixture.example", "client", "fixture-secret", failed, clock=lambda: 0
                )
                with self.assertRaises(appliance.LifecycleError) as raised:
                    candidate.list_devices()
                rendered = str(raised.exception)
                self.assertEqual((failed.token_requests, failed.api_requests), (expected_tokens, expected_api_calls))
                self.assertNotIn(failed.sensitive_body, rendered)
                self.assertNotIn("private-bearer", rendered)

    def test_oauth_expiry_and_token_failure_schemas_fail_closed_without_response_body(self):
        class TokenHTTP:
            def __init__(self, status, payload):
                self.status = status
                self.payload = payload
                self.requests = 0

            def request(self, method, url, *, headers=None, body=None):
                self.requests += 1
                if not urllib.parse.urlparse(url).path.endswith("/oauth/token"):
                    raise AssertionError("malformed OAuth metadata must fail before an API request")
                return self.status, json.dumps(self.payload).encode()

        for expires_in in (None, 0, -1, True, 1.5, "0", "1.5", 86401, "9999999999"):
            with self.subTest(expires_in=expires_in):
                transport = TokenHTTP(200, {"access_token": "private-bearer", "expires_in": expires_in})
                api = appliance.TailscaleAPI(
                    "fixture.example", "client", "fixture-secret", transport, clock=lambda: 0
                )
                with self.assertRaisesRegex(appliance.LifecycleError, "expires_in"):
                    api.list_devices()
                self.assertEqual(transport.requests, 1)

        failed = TokenHTTP(500, {"message": "sensitive-token-response-body"})
        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", failed, clock=lambda: 0)
        with self.assertRaises(appliance.LifecycleError) as raised:
            api.list_devices()
        self.assertNotIn("sensitive-token-response-body", str(raised.exception))

    def test_delete_accepts_every_success_body_shape_and_bounds_failures(self):
        class DeleteHTTP:
            def __init__(self, status, body):
                self.status = status
                self.body = body

            def request(self, method, url, *, headers=None, body=None):
                if urllib.parse.urlparse(url).path.endswith("/oauth/token"):
                    return 200, b'{"access_token":"fixture-bearer","expires_in":3600}'
                if method == "DELETE":
                    return self.status, self.body
                raise AssertionError((method, url))

        responses = (
            (200, b""),
            (200, b"{}"),
            (200, b"[]"),
            (202, b"null"),
            (202, b"plain text"),
            (204, b""),
            (404, b"[]"),
        )
        for operation in ("key", "device"):
            for status, body in responses:
                with self.subTest(operation=operation, status=status, body=body):
                    api = appliance.TailscaleAPI(
                        "fixture.example", "client", "fixture-secret", DeleteHTTP(status, body)
                    )
                    if operation == "key":
                        api.revoke_auth_key("key-fixture")
                    else:
                        api.delete_device("device-fixture")

        secret = "ts" + "key-" + "auth-fixture123456789"
        api = appliance.TailscaleAPI(
            "fixture.example",
            "client",
            "fixture-secret",
            DeleteHTTP(500, (f'{{"message":"auth_key={secret}"}}' + "x" * 2048).encode()),
        )
        with self.assertRaises(appliance.LifecycleError) as raised:
            api.revoke_auth_key("key-fixture")
        self.assertNotIn(secret, str(raised.exception))
        self.assertLess(len(str(raised.exception)), 700)

    def test_non_object_delete_success_is_followed_by_confirmed_absence(self):
        class StatefulHTTP:
            def __init__(self):
                self.keys = [{"id": "key-fixture", "description": "fixture"}]
                self.devices = [{"id": "device-fixture", "hostname": "fixture"}]

            def request(self, method, url, *, headers=None, body=None):
                path = urllib.parse.urlparse(url).path
                if path.endswith("/oauth/token"):
                    return 200, b'{"access_token":"fixture-bearer","expires_in":3600}'
                if path.endswith("/keys") and method == "GET":
                    return 200, json.dumps({"keys": self.keys}).encode()
                if path.endswith("/devices") and method == "GET":
                    return 200, json.dumps({"devices": self.devices}).encode()
                if "/keys/" in path and method == "DELETE":
                    self.keys = []
                    return 200, b"[]"
                if path.endswith("/device-fixture") and method == "DELETE":
                    self.devices = []
                    return 200, b"null"
                raise AssertionError((method, url))

        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", StatefulHTTP())
        self.assertEqual(len(api.list_auth_keys()), 1)
        self.assertEqual(len(api.list_devices()), 1)
        api.revoke_auth_key("key-fixture")
        api.delete_device("device-fixture")
        self.assertEqual(api.list_auth_keys(), [])
        self.assertEqual(api.list_devices(), [])


class SecurityAndBackendTest(unittest.TestCase):
    def test_redaction(self):
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        tailscale_key = "ts" + "key-auth-abc123"
        value = f"auth_key=fixture-value token: bearer-value access key {aws_key} {tailscale_key}"
        result = appliance.redact(value)
        for prohibited in ("fixture-value", "bearer-value", aws_key, tailscale_key):
            self.assertNotIn(prohibited, result)

    def test_backend_requires_versioning_kms_public_block_and_unique_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = BackendAWS(config)
            validator = appliance.BackendValidator(aws)
            validator.validate(config, require_empty=True)
            mutations = (
                ("versioning", "Suspended"),
                ("algorithm", "AES256"),
                ("key", "arn:aws:kms:us-west-2:123456789012:key/wrong"),
                ("public", False),
                ("policy_public", True),
                ("key_enabled", False),
            )
            for field, value in mutations:
                with self.subTest(field=field):
                    candidate = BackendAWS(config)
                    setattr(candidate, field, value)
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)
            disabled_bucket_key = BackendAWS(config)
            disabled_bucket_key.bucket_key_enabled = False
            with self.assertRaisesRegex(appliance.LifecycleError, "must enable S3 Bucket Keys"):
                appliance.BackendValidator(disabled_bucket_key).validate(config, require_empty=True)
            missing_bucket_key = BackendAWS(config)
            del missing_bucket_key.bucket_key_enabled
            with self.assertRaisesRegex(appliance.LifecycleError, "malformed default encryption metadata"):
                appliance.BackendValidator(missing_bucket_key).validate(config, require_empty=True)
            for malformed in (None, "true", 1, [], {}):
                with self.subTest(bucket_key_enabled=malformed):
                    candidate = BackendAWS(config)
                    candidate.bucket_key_enabled = malformed
                    with self.assertRaisesRegex(appliance.LifecycleError, "malformed default encryption metadata"):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)
            aws.versions[config.backend["state_key"]] = [
                {"Key": config.backend["state_key"], "VersionId": "historical"}
            ]
            with self.assertRaisesRegex(appliance.LifecycleError, "historical"):
                validator.validate(config, require_empty=True)
            denied = BackendAWS(config)
            denied.bucket_policy["Statement"] = denied.bucket_policy["Statement"][:1]
            with self.assertRaisesRegex(appliance.LifecycleError, "backend policy omits"):
                appliance.BackendValidator(denied).validate(config, require_empty=True)

    def test_backend_policy_rejects_each_omitted_lifecycle_action(self):
        def omit_action(policy, action):
            removed = False
            for statement in policy["Statement"]:
                actions = statement.get("Action")
                if isinstance(actions, list) and action in actions:
                    statement["Action"] = [value for value in actions if value != action]
                    removed = True
            self.assertTrue(removed, action)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            baseline = BackendAWS(config)
            s3_actions = {
                str(action)
                for statement in baseline.bucket_policy["Statement"]
                for action in (statement.get("Action") if isinstance(statement.get("Action"), list) else [])
                if str(action).startswith("s3:") and action != "s3:*"
            }
            for action in sorted(s3_actions):
                with self.subTest(action=action):
                    candidate = BackendAWS(config)
                    omit_action(candidate.bucket_policy, action)
                    with self.assertRaisesRegex(appliance.LifecycleError, re.escape(action)):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)
            for action in appliance.BACKEND_KMS_ACTIONS:
                with self.subTest(action=action):
                    candidate = BackendAWS(config)
                    omit_action(candidate.key_policy, action)
                    with self.assertRaisesRegex(appliance.LifecycleError, re.escape(action)):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)

    def test_backend_policy_accepts_kms_bucket_key_context_with_root_delegation(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            candidate = BackendAWS(config)
            principal = config.backend["operator_principal_arns"][0]
            partition, account_id = principal.split(":", 5)[1], principal.split(":", 5)[4]
            root = f"arn:{partition}:iam::{account_id}:root"
            bucket_arn = f"arn:{partition}:s3:::{config.backend['bucket']}"
            object_arns = [
                f"{bucket_arn}/{key}"
                for key in (config.backend["state_key"], config.lock_key, config.manifest_key)
            ]

            bucket_allow = candidate.bucket_policy["Statement"][1]
            bucket_allow["Principal"] = {"AWS": root}
            conditional_s3_actions = {"s3:ListBucket", "s3:ListBucketVersions", "s3:PutObject", "s3:PutObjectTagging"}
            bucket_allow["Action"] = [
                action for action in bucket_allow["Action"] if action not in conditional_s3_actions
            ]
            candidate.bucket_policy["Statement"].extend(
                [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": root},
                        "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                        "Resource": bucket_arn,
                        "Condition": {
                            "StringEquals": {
                                "s3:prefix": [
                                    config.backend["state_key"],
                                    config.lock_key,
                                    config.manifest_key,
                                ]
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": root},
                        "Action": "s3:PutObject",
                        "Resource": object_arns,
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-server-side-encryption": "aws:kms",
                                "s3:x-amz-server-side-encryption-aws-kms-key-id": config.backend["kms_key_arn"],
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": root},
                        "Action": "s3:PutObjectTagging",
                        "Resource": f"{bucket_arn}/{config.manifest_key}",
                        "Condition": {
                            "StringEquals": {
                                "s3:RequestObjectTag/EnvelopeRun": config.run_id,
                                "s3:RequestObjectTag/ExpiresAt": config.expires_at,
                            }
                        },
                    },
                ]
            )

            key_allow = candidate.key_policy["Statement"][0]
            key_allow["Principal"] = {"AWS": root}
            key_allow["Action"] = ["kms:DescribeKey", "kms:GetKeyPolicy"]
            candidate.key_policy["Statement"].append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": root},
                    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"s3.{config.backend['region']}.amazonaws.com",
                            "kms:EncryptionContext:aws:s3:arn": bucket_arn,
                        },
                        "ForAllValues:StringEquals": {
                            "kms:EncryptionContextKeys": ["aws:s3:arn"]
                        },
                    },
                }
            )
            appliance.BackendValidator(candidate).validate(config, require_empty=True)

    def test_backend_policy_explicit_denies_override_matching_allows(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            principal = config.backend["operator_principal_arns"][0]
            bucket_arn = f"arn:aws:s3:::{config.backend['bucket']}"
            state_arn = f"{bucket_arn}/{config.backend['state_key']}"

            denied_s3 = BackendAWS(config)
            denied_s3.bucket_policy["Statement"].append(
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": principal},
                    "Action": "s3:PutObject",
                    "Resource": state_arn,
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms",
                            "s3:x-amz-server-side-encryption-aws-kms-key-id": config.backend["kms_key_arn"],
                        }
                    },
                }
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "explicitly denies"):
                appliance.BackendValidator(denied_s3).validate(config, require_empty=True)

            denied_kms = BackendAWS(config)
            denied_kms.key_policy["Statement"].append(
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": principal},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"s3.{config.backend['region']}.amazonaws.com",
                            "kms:EncryptionContext:aws:s3:arn": bucket_arn,
                        }
                    },
                }
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "explicitly denies"):
                appliance.BackendValidator(denied_kms).validate(config, require_empty=True)

    def test_backend_insecure_transport_deny_must_cover_each_real_operator_without_exemption(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            principal = config.backend["operator_principal_arns"][0]
            exempted = BackendAWS(config)
            exempted.bucket_policy["Statement"][0]["Condition"]["StringNotEquals"] = {
                "aws:PrincipalArn": principal
            }
            with self.assertRaisesRegex(
                appliance.LifecycleError,
                rf"insecure transport.*{re.escape(principal)}",
            ):
                appliance.BackendValidator(exempted).validate(config, require_empty=True)

    def test_backend_policy_rejects_wrong_or_unsupported_request_conditions(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            principal = config.backend["operator_principal_arns"][0]
            bucket_arn = f"arn:aws:s3:::{config.backend['bucket']}"

            wrong_prefix = BackendAWS(config)
            allow = wrong_prefix.bucket_policy["Statement"][1]
            allow["Action"].remove("s3:ListBucket")
            wrong_prefix.bucket_policy["Statement"].append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "s3:ListBucket",
                    "Resource": bucket_arn,
                    "Condition": {"StringEquals": {"s3:prefix": "unrelated/"}},
                }
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "s3:ListBucket"):
                appliance.BackendValidator(wrong_prefix).validate(config, require_empty=True)

            for label, via_service, encryption_context in (
                (
                    "object-only",
                    f"s3.{config.backend['region']}.amazonaws.com",
                    f"{bucket_arn}/{config.backend['state_key']}",
                ),
                (
                    "wrong-bucket",
                    f"s3.{config.backend['region']}.amazonaws.com",
                    "arn:aws:s3:::other-backend",
                ),
                (
                    "wrong-service",
                    "s3.us-east-2.amazonaws.com",
                    bucket_arn,
                ),
            ):
                with self.subTest(kms_context=label):
                    wrong_kms_context = BackendAWS(config)
                    key_allow = wrong_kms_context.key_policy["Statement"][0]
                    key_allow["Action"].remove("kms:GenerateDataKey")
                    wrong_kms_context.key_policy["Statement"].append(
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": principal},
                            "Action": "kms:GenerateDataKey",
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {
                                    "kms:ViaService": via_service,
                                    "kms:EncryptionContext:aws:s3:arn": encryption_context,
                                }
                            },
                        }
                    )
                    with self.assertRaisesRegex(appliance.LifecycleError, "kms:GenerateDataKey"):
                        appliance.BackendValidator(wrong_kms_context).validate(config, require_empty=True)

            invalid_key_policy_resource = BackendAWS(config)
            invalid_key_policy_resource.key_policy["Statement"][0]["Resource"] = config.backend["kms_key_arn"]
            with self.assertRaisesRegex(appliance.LifecycleError, "backend KMS key policy omits"):
                appliance.BackendValidator(invalid_key_policy_resource).validate(config, require_empty=True)

            unsupported = BackendAWS(config)
            unsupported.bucket_policy["Statement"].append(
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": principal},
                    "Action": "s3:GetObject",
                    "Resource": f"{bucket_arn}/{config.backend['state_key']}",
                    "Condition": {"NumericEquals": {"s3:object-lock-remaining-retention-days": "1"}},
                }
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported condition operator"):
                appliance.BackendValidator(unsupported).validate(config, require_empty=True)

    def test_backend_configuration_requires_encryption_and_lockfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            text = appliance.backend_config_text(make_config(pathlib.Path(temporary)))
        self.assertIn('key = "runs/envelope-fixture/terraform.tfstate"', text)
        self.assertIn("encrypt = true", text)
        self.assertIn("use_lockfile = true", text)
        self.assertNotIn("access_key", text)
        self.assertNotIn("secret_key", text)

    def test_manifest_is_secret_free_protected_and_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = BackendAWS(config)
            artifact = artifact_identity(root)
            manifest = appliance.new_manifest(config, artifact, "123456789012")
            store = appliance.ManifestStore(config, aws, root / "run")
            store.write(manifest)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            serialized = store.path.read_text()
            self.assertNotIn("auth-material", serialized)
            self.assertNotIn("oauth", serialized.lower())
            appliance.validate_manifest(json.loads(serialized), config)
            self.assertEqual(set(manifest["terraform_variables"]), set(appliance.terraform_variables(config, artifact, manifest["ssm_parameters"])))
            self.assertEqual([value["created"] for value in manifest["ssm_parameters"]], [False, False])
            self.assertEqual(manifest["tailnet"]["device_roles"], fixture_tailnet_roles())
            self.assertEqual(manifest["tailnet"]["expected_hostnames"], fixture_tailnet_hostnames())
            self.assertFalse(
                any("-target-" in hostname for hostname in manifest["tailnet"]["expected_hostnames"])
            )
            fabricated_target = copy.deepcopy(manifest)
            fabricated_target["tailnet"]["expected_hostnames"].append(
                "envelope-fixture-west-target-a"
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "Tailnet identity"):
                appliance.validate_manifest(fabricated_target, config)

            legacy_role = copy.deepcopy(manifest)
            legacy_role["tailnet"].pop("device_roles")
            legacy_role["tailnet"]["device_role"] = "transport-router"
            with self.assertRaisesRegex(appliance.LifecycleError, "Tailnet identity"):
                appliance.validate_manifest(legacy_role, config)

            ingress_hostname = copy.deepcopy(manifest)
            current_hostname = ingress_hostname["tailnet"]["expected_hostnames"][0]
            obsolete_hostname = current_hostname.replace("-transport-", "-ingress-")
            ingress_hostname["tailnet"]["expected_hostnames"][0] = obsolete_hostname
            ingress_hostname["tailnet"]["device_roles"] = {
                obsolete_hostname if hostname == current_hostname else hostname: role
                for hostname, role in ingress_hostname["tailnet"]["device_roles"].items()
            }
            with self.assertRaisesRegex(appliance.LifecycleError, "Tailnet identity"):
                appliance.validate_manifest(ingress_hostname, config)

            target_role = copy.deepcopy(manifest)
            target_role["tailnet"]["device_roles"][fixture_tailnet_hostnames()[0]] = "target"
            with self.assertRaisesRegex(appliance.LifecycleError, "Tailnet identity"):
                appliance.validate_manifest(target_role, config)

    def test_manifest_apply_timestamp_contract_rejects_missing_or_stale_claim_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            base = appliance.new_manifest(config, artifact_identity(root), "123456789012")

            active = copy.deepcopy(base)
            mark_manifest_apply_started(active)
            active["phase"] = "apply_started"
            appliance.validate_manifest(active, config)

            applied = copy.deepcopy(base)
            mark_manifest_applied(applied)
            applied["phase"] = "ready"
            appliance.validate_manifest(applied, config)

            cases = {}
            missing_applied_at = copy.deepcopy(applied)
            missing_applied_at["saved_plan"].pop("applied_at")
            cases["saved_plan.applied_at"] = missing_applied_at
            stale_claim = copy.deepcopy(applied)
            stale_claim["apply_claimed_at"] = "2026-08-20T12:00:00Z"
            cases["stale active apply claim"] = stale_claim
            misplaced = copy.deepcopy(applied)
            misplaced["applied_at"] = misplaced["saved_plan"]["applied_at"]
            cases["only under saved_plan"] = misplaced
            active_without_claim = copy.deepcopy(active)
            active_without_claim.pop("apply_claimed_at")
            cases["apply_claimed_at"] = active_without_claim
            active_without_id = copy.deepcopy(active)
            active_without_id.pop("apply_claim_id")
            cases["unique claim ID"] = active_without_id
            invalid_timestamp = copy.deepcopy(applied)
            invalid_timestamp["saved_plan"]["applied_at"] = "2026-08-20T12:00:00+00:00"
            cases["canonical UTC"] = invalid_timestamp
            for message, candidate in cases.items():
                with self.subTest(message=message), self.assertRaisesRegex(appliance.LifecycleError, message):
                    appliance.validate_manifest(candidate, config)

    def test_manifest_compare_and_swap_rejects_a_stale_lifecycle_writer(self):
        class AWS:
            def __init__(self):
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != self.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.version += 1
                    self.etag = f'"manifest-{self.version}"'
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = AWS()
            initial = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            appliance.ManifestStore(config, aws, root / "initial").write(initial)
            first = appliance.ManifestStore(config, aws, root / "first")
            second = appliance.ManifestStore(config, aws, root / "second")
            first_manifest = first.recover()
            second_manifest = second.recover()
            first_manifest["phase"] = "first-claim"
            first.write(first_manifest)
            second_manifest["phase"] = "stale-claim"
            with self.assertRaisesRegex(appliance.CommandError, "PreconditionFailed"):
                second.write(second_manifest)
            self.assertEqual(second.load_local()["phase"], "preflight_complete")

    def test_residual_allowlist_never_accepts_shared_backend_and_enforces_janitor_ttl(self):
        class UnusedAWS:
            def json(self, *args, **kwargs):
                raise AssertionError("validation must fail before AWS deletion")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            backend = [{"arn": "arn:aws:s3:::operator-backend", "region": "us-west-2"}]
            with self.assertRaisesRegex(appliance.LifecycleError, "shared backend"):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    backend,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )
            with self.assertRaisesRegex(appliance.LifecycleError, "TTL"):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    [],
                    dry_run=False,
                    allow_unexpired=False,
                    sleep=lambda _: None,
                )
            expired = make_config(root / "expired", expired=True)
            self.assertEqual(
                appliance.remove_owned_residuals(
                    expired,
                    UnusedAWS(),
                    [],
                    dry_run=False,
                    allow_unexpired=False,
                    sleep=lambda _: None,
                ),
                [],
            )

    def test_allowlisted_owned_residual_is_removed_and_reaudited(self):
        class ResidualAWS:
            def __init__(self):
                self.terminated = []

            def json(self, args, *, region=None):
                if args[1] == "terminate-instances":
                    self.terminated.append(args[-1])
                    return {}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = ResidualAWS()
            resource = {
                "arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-ownedfixture",
                "region": "us-west-2",
            }
            removed = appliance.remove_owned_residuals(
                config,
                aws,
                [resource],
                dry_run=False,
                allow_unexpired=True,
                sleep=lambda _: None,
            )
            self.assertEqual(removed, [resource["arn"]])
            self.assertEqual(aws.terminated, ["i-ownedfixture"])
            with self.assertRaisesRegex(appliance.LifecycleError, "allowlist"):
                appliance.remove_owned_residuals(
                    config,
                    aws,
                    [{"arn": "arn:aws:kms:us-west-2:123456789012:key/shared", "region": "us-west-2"}],
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )

    def test_residual_recovery_uses_dependency_order_and_bounded_async_window(self):
        class UnusedAWS:
            pass

        order = []
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            resources = [
                {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-fixture", "region": "us-west-2"},
                {"arn": "arn:aws:s3:::run-artifact-fixture", "region": "us-west-2"},
                {"arn": "arn:aws:iam::123456789012:role/run-role", "region": "us-west-2"},
                {"arn": "arn:aws:ec2:us-west-2:123456789012:subnet/subnet-fixture", "region": "us-west-2"},
                {
                    "arn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id",
                    "region": "us-west-2",
                },
                {
                    "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                    "region": "us-west-2",
                },
                {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-fixture", "region": "us-west-2"},
                owned_residual(
                    config,
                    "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-fixture",
                ),
                owned_residual(
                    config,
                    "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west:*",
                ),
                owned_residual(
                    config,
                    "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-fixture",
                ),
            ]
            with mock.patch.object(
                appliance,
                "delete_owned_resource",
                side_effect=lambda aws, resource: order.append(appliance.owned_resource_kind(resource["arn"])[0]),
            ), mock.patch.object(appliance, "audit_run_resources", return_value=[]):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    resources,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )
        self.assertEqual(
            order,
            [
                "instance",
                "flow-log",
                "vpc-endpoint",
                "log-group",
                "load-balancer",
                "subnet",
                "network-acl",
                "role",
                "s3-bucket",
                "vpc",
            ],
        )
        self.assertEqual(appliance.RESIDUAL_CLEANUP_TIMEOUT_SECONDS, 15 * 60)
        self.assertLessEqual(
            appliance.RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS,
            appliance.RESIDUAL_CLEANUP_MAX_BACKOFF_SECONDS,
        )

    def test_authoritative_liveness_covers_every_allowlisted_resource_kind(self):
        cases = (
            ("arn:aws:s3:::run-artifact", "head-bucket", {}),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id",
                "describe-load-balancers",
                {"LoadBalancers": [{"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id"}]},
            ),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/gwy/run/id/listener",
                "describe-listeners",
                {"Listeners": [{"ListenerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/gwy/run/id/listener"}]},
            ),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run/id",
                "describe-target-groups",
                {"TargetGroups": [{"TargetGroupArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run/id"}]},
            ),
            (
                "arn:aws:iam::123456789012:instance-profile/run-profile",
                "get-instance-profile",
                {"InstanceProfile": {"InstanceProfileName": "run-profile"}},
            ),
            ("arn:aws:iam::123456789012:role/run-role", "get-role", {"Role": {"RoleName": "run-role"}}),
            (
                "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-fixture/tailscale-auth",
                "describe-parameters",
                {"Parameters": [{"Name": "/envelope-fixture/tailscale-auth"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-live",
                "describe-network-acls",
                {
                    "NetworkAcls": [
                        {
                            "NetworkAclId": "acl-live",
                            "VpcId": "vpc-live",
                            "IsDefault": False,
                            "Associations": [],
                            "Tags": [],
                        }
                    ]
                },
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-live",
                "describe-flow-logs",
                {"FlowLogs": [{"FlowLogId": "fl-live", "FlowLogStatus": "ACTIVE", "Tags": []}]},
            ),
            (
                "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west:*",
                "list-tags-for-resource",
                {},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:instance/i-live",
                "describe-instances",
                {"Reservations": [{"Instances": [{"InstanceId": "i-live", "State": {"Name": "running"}}]}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:volume/vol-live",
                "describe-volumes",
                {"Volumes": [{"VolumeId": "vol-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-live",
                "describe-vpc-endpoints",
                {"VpcEndpoints": [{"VpcEndpointId": "vpce-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-live",
                "describe-vpc-endpoint-service-configurations",
                {"ServiceConfigurations": [{"ServiceId": "vpce-svc-live", "ServiceState": "Available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-live",
                "describe-nat-gateways",
                {"NatGateways": [{"NatGatewayId": "nat-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-live",
                "describe-addresses",
                {"Addresses": [{"AllocationId": "eipalloc-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:internet-gateway/igw-live",
                "describe-internet-gateways",
                {"InternetGateways": [{"InternetGatewayId": "igw-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:route-table/rtb-live",
                "describe-route-tables",
                {"RouteTables": [{"RouteTableId": "rtb-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:subnet/subnet-live",
                "describe-subnets",
                {"Subnets": [{"SubnetId": "subnet-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:security-group/sg-live",
                "describe-security-groups",
                {"SecurityGroups": [{"GroupId": "sg-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:network-interface/eni-live",
                "describe-network-interfaces",
                {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-live",
                "describe-vpcs",
                {"Vpcs": [{"VpcId": "vpc-live"}]},
            ),
        )

        class DescribeAWS:
            def __init__(self, operation, response, tags=None):
                self.operation = operation
                self.response = response
                self.tags = tags
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                if args[1] == "list-tags-for-resource" and self.tags is not None:
                    return {"tags": self.tags}
                self.assert_operation(args[1])
                return self.response

            def assert_operation(self, operation):
                if operation != self.operation:
                    raise AssertionError((operation, self.operation))

        self.assertEqual(len(cases), len(appliance.RESIDUAL_DELETE_PRIORITY))
        self.assertEqual(
            set(appliance.RESIDUAL_DELETE_PRIORITY),
            set(appliance.OWNED_RESOURCE_ABSENT_MARKERS),
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for arn, operation, original_response in cases:
                with self.subTest(arn=arn):
                    kind, identifier = appliance.owned_resource_kind(arn)
                    response = copy.deepcopy(original_response)
                    resource = {"arn": arn, "region": "us-west-2"}
                    tags = None
                    if kind in appliance.OWNERSHIP_VERIFIED_RESOURCE_KINDS:
                        resource = owned_residual(config, arn)
                        if kind == "network-acl":
                            response["NetworkAcls"][0]["Tags"] = owned_tag_list(config)
                        elif kind == "flow-log":
                            response["FlowLogs"][0]["Tags"] = owned_tag_list(config)
                        else:
                            tags = {tag["Key"]: tag["Value"] for tag in owned_tag_list(config)}
                    aws = DescribeAWS(operation, response, tags)
                    self.assertTrue(appliance.owned_resource_is_live(aws, resource))
                    self.assertIn(identifier, " ".join(aws.calls[0][0]))

        volume = {"arn": "arn:aws:ec2:us-west-2:123456789012:volume/vol-live", "region": "us-west-2"}
        with self.assertRaisesRegex(appliance.LifecycleError, "exact requested identity"):
            appliance.owned_resource_is_live(
                DescribeAWS("describe-volumes", {"Volumes": [{"VolumeId": "vol-other", "State": "available"}]}),
                volume,
            )
        denied = mock.Mock()
        denied.json.side_effect = appliance.CommandError(["aws", "describe-volumes"], 255, "AccessDenied")
        with self.assertRaises(appliance.CommandError):
            appliance.owned_resource_is_live(denied, volume)

    def test_new_residual_arn_parsing_is_exact_and_log_group_variants_are_equivalent(self):
        valid = {
            "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-fixture": ("network-acl", "acl-fixture"),
            "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-fixture": ("flow-log", "fl-fixture"),
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/run/west": (
                "log-group",
                "/aws/vpc-flow-logs/run/west",
            ),
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/run/west:*": (
                "log-group",
                "/aws/vpc-flow-logs/run/west",
            ),
        }
        for arn, expected in valid.items():
            with self.subTest(arn=arn):
                self.assertEqual(appliance.owned_resource_kind(arn), expected)

        invalid = (
            "arn:aws:ec2::123456789012:network-acl/acl-fixture",
            "arn:aws:ec2:us-west-2:account:network-acl/acl-fixture",
            "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-fixture/extra",
            "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/flow-fixture",
            "arn:aws:ec2:us-west-2:123456789012:flow-log/fl-fixture",
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/run/*/west",
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/run/west:*:extra",
            "arn:aws:logs:us-west-2:123456789012:log-stream:/aws/vpc-flow-logs/run/west",
            "arn:aws:ec2:us-west-2:123456789012:network-firewall/unknown",
        )
        for arn in invalid:
            with self.subTest(arn=arn), self.assertRaises(appliance.LifecycleError):
                appliance.owned_resource_kind(arn)

    def test_network_acl_cleanup_rejects_default_nonowned_conflicting_and_malformed_state(self):
        class ACLAWS:
            def __init__(self, response):
                self.response = response
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                if args[1] == "describe-network-acls":
                    return self.response
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            resource = owned_residual(
                config,
                "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-owned",
            )
            base = {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-owned",
                        "VpcId": "vpc-owned",
                        "IsDefault": False,
                        "Associations": [],
                        "Tags": owned_tag_list(config),
                    }
                ]
            }
            cases = {}
            default = copy.deepcopy(base)
            default["NetworkAcls"][0]["IsDefault"] = True
            cases["default"] = default
            nonowned = copy.deepcopy(base)
            nonowned["NetworkAcls"][0]["Tags"][0]["Value"] = "another-run"
            cases["non-owned"] = nonowned
            conflicting = copy.deepcopy(base)
            conflicting["NetworkAcls"][0]["NetworkAclId"] = "acl-other"
            cases["conflicting identity"] = conflicting
            malformed = copy.deepcopy(base)
            malformed["NetworkAcls"][0]["Associations"] = "invalid"
            cases["malformed associations"] = malformed

            for name, response in cases.items():
                with self.subTest(name=name):
                    aws = ACLAWS(response)
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.delete_owned_resource(aws, resource)
                    self.assertEqual([call[0][1] for call in aws.calls], ["describe-network-acls"])

            wrong_region = dict(resource)
            wrong_region["region"] = "us-east-1"
            aws = ACLAWS(base)
            with self.assertRaisesRegex(appliance.LifecycleError, "audit region"):
                appliance.owned_resource_is_live(aws, wrong_region)
            self.assertEqual(aws.calls, [])

    def test_network_acl_cleanup_restores_exact_associations_before_deletion(self):
        class ACLAWS:
            def __init__(self, config):
                self.config = config
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                operation = args[1]
                if operation == "describe-network-acls" and "--network-acl-ids" in args:
                    return {
                        "NetworkAcls": [
                            {
                                "NetworkAclId": "acl-owned",
                                "VpcId": "vpc-owned",
                                "IsDefault": False,
                                "Associations": [
                                    {
                                        "NetworkAclAssociationId": "aclassoc-owned",
                                        "NetworkAclId": "acl-owned",
                                        "SubnetId": "subnet-owned",
                                    }
                                ],
                                "Tags": owned_tag_list(self.config),
                            }
                        ]
                    }
                if operation == "describe-network-acls" and "--filters" in args:
                    return {
                        "NetworkAcls": [
                            {"NetworkAclId": "acl-default", "VpcId": "vpc-owned", "IsDefault": True}
                        ]
                    }
                if operation == "replace-network-acl-association":
                    return {"NewAssociationId": "aclassoc-defaulted"}
                if operation == "delete-network-acl":
                    return {}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = ACLAWS(config)
            resource = owned_residual(
                config,
                "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-owned",
            )
            appliance.delete_owned_resource(aws, resource)

        operations = [args[1] for args, _ in aws.calls]
        self.assertEqual(
            operations,
            [
                "describe-network-acls",
                "describe-network-acls",
                "replace-network-acl-association",
                "delete-network-acl",
            ],
        )
        replacement = aws.calls[2][0]
        self.assertEqual(replacement[replacement.index("--association-id") + 1], "aclassoc-owned")
        self.assertEqual(replacement[replacement.index("--network-acl-id") + 1], "acl-default")

    def test_flow_log_and_log_group_deletion_use_exact_id_name_and_valid_schemas(self):
        class FlowAWS:
            def __init__(self, config, unsuccessful=None):
                self.config = config
                self.unsuccessful = [] if unsuccessful is None else unsuccessful
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                if args[1] == "describe-flow-logs":
                    return {
                        "FlowLogs": [
                            {
                                "FlowLogId": "fl-owned",
                                "FlowLogStatus": "ACTIVE",
                                "Tags": owned_tag_list(self.config),
                            }
                        ]
                    }
                if args[1] == "delete-flow-logs":
                    return {"Unsuccessful": self.unsuccessful}
                raise AssertionError(args)

        class LogsAWS:
            def __init__(self, config, arn):
                self.config = config
                self.arn = arn
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                if args[1] == "describe-log-groups":
                    return {
                        "logGroups": [
                            {
                                "logGroupName": "/aws/vpc-flow-logs/envelope-fixture/west",
                                "arn": self.arn,
                            },
                            {"logGroupName": "/aws/vpc-flow-logs/envelope-fixture/west-prefix"},
                        ]
                    }
                if args[1] == "list-tags-for-resource":
                    return {"tags": {tag["Key"]: tag["Value"] for tag in owned_tag_list(self.config)}}
                if args[1] == "delete-log-group":
                    return {}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            flow = owned_residual(
                config,
                "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-owned",
            )
            flow_aws = FlowAWS(config)
            appliance.delete_owned_resource(flow_aws, flow)
            self.assertEqual([args[1] for args, _ in flow_aws.calls], ["describe-flow-logs", "delete-flow-logs"])
            self.assertEqual(flow_aws.calls[1][0][-1], "fl-owned")

            failed_flow = FlowAWS(
                config,
                [{"ResourceId": "fl-owned", "Error": {"Code": "InternalError"}}],
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "unsuccessful exact ID"):
                appliance.delete_owned_resource(failed_flow, flow)
            absent_flow = FlowAWS(
                config,
                [
                    {
                        "ResourceId": "fl-owned",
                        "Error": {"Code": "InvalidFlowLogId.NotFound"},
                    }
                ],
            )
            appliance.delete_owned_resource(absent_flow, flow)

            for suffix in ("", ":*"):
                arn = (
                    "arn:aws:logs:us-west-2:123456789012:"
                    f"log-group:/aws/vpc-flow-logs/envelope-fixture/west{suffix}"
                )
                with self.subTest(suffix=suffix):
                    logs_aws = LogsAWS(config, arn)
                    log_group = owned_residual(config, arn)
                    appliance.delete_owned_resource(logs_aws, log_group)
                    self.assertEqual(
                        [args[1] for args, _ in logs_aws.calls],
                        ["list-tags-for-resource", "delete-log-group"],
                    )
                    delete_args = logs_aws.calls[-1][0]
                    self.assertEqual(delete_args[1], "delete-log-group")
                    self.assertEqual(
                        delete_args[delete_args.index("--log-group-name") + 1],
                        "/aws/vpc-flow-logs/envelope-fixture/west",
                    )
                    tag_args = next(args for args, _ in logs_aws.calls if args[1] == "list-tags-for-resource")
                    self.assertEqual(
                        tag_args[-1],
                        "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west",
                    )

    def test_log_group_liveness_uses_only_the_exact_canonical_arn_and_tags(self):
        class LogsAWS:
            def __init__(self, tags):
                self.tags = tags
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append(args)
                if args[1] != "list-tags-for-resource":
                    raise AssertionError(args)
                return {"tags": self.tags}

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            resource = owned_residual(
                config,
                "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west:*",
            )
            exact_tags = {tag["Key"]: tag["Value"] for tag in owned_tag_list(config)}
            exact = LogsAWS(exact_tags)
            self.assertTrue(appliance.owned_resource_is_live(exact, resource))
            self.assertEqual(
                exact.calls,
                [
                    [
                        "logs",
                        "list-tags-for-resource",
                        "--resource-arn",
                        "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west",
                    ]
                ],
            )
            conflicting_tags = dict(exact_tags)
            conflicting_tags["EnvelopeRun"] = "another-run"
            with self.assertRaisesRegex(appliance.LifecycleError, "exact run/TTL identity"):
                appliance.owned_resource_is_live(LogsAWS(conflicting_tags), resource)
            with self.assertRaisesRegex(appliance.LifecycleError, "invalid tag schema"):
                appliance.owned_resource_is_live(LogsAWS([]), resource)

    def test_tag_tombstones_are_filtered_before_cleanup_without_delete_retries(self):
        tombstones = [
            {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-terminated", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-deleted", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:volume/vol-absent", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-empty", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-absent", "region": "us-west-2"},
            {
                "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-absent",
                "region": "us-west-2",
            },
            {
                "arn": "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-absent",
                "region": "us-west-2",
            },
            {
                "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-absent",
                "region": "us-west-2",
            },
            {
                "arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/absent:*",
                "region": "us-west-2",
            },
        ]

        class TombstoneAWS:
            def __init__(self, config):
                self.config = config
                self.delete_calls = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "get-resources":
                    if region != self.config.sites["west"]["region"]:
                        return {"ResourceTagMappingList": []}
                    return {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": resource["arn"],
                                "Tags": [
                                    {"Key": "EnvelopeRun", "Value": self.config.run_id},
                                    {"Key": "ExpiresAt", "Value": self.config.expires_at},
                                ],
                            }
                            for resource in tombstones
                        ]
                    }
                if operation == "describe-instances":
                    return {
                        "Reservations": [
                            {"Instances": [{"InstanceId": "i-terminated", "State": {"Name": "terminated"}}]}
                        ]
                    }
                if operation == "describe-nat-gateways":
                    return {"NatGateways": [{"NatGatewayId": "nat-deleted", "State": "deleted"}]}
                if operation == "describe-volumes":
                    raise appliance.CommandError(args, 255, "InvalidVolume.NotFound: fixture tombstone")
                if operation == "describe-vpc-endpoints":
                    endpoint_id = args[-1]
                    if endpoint_id == "vpce-empty":
                        return {"VpcEndpoints": []}
                    raise appliance.CommandError(args, 255, "InvalidVpcEndpointId.NotFound: fixture tombstone")
                if operation == "describe-vpc-endpoint-service-configurations":
                    raise appliance.CommandError(
                        args, 255, "InvalidVpcEndpointServiceId.NotFound: fixture tombstone"
                    )
                if operation == "describe-network-acls":
                    raise appliance.CommandError(args, 255, "InvalidNetworkAclID.NotFound: fixture tombstone")
                if operation == "describe-flow-logs":
                    return {"FlowLogs": []}
                if operation == "describe-log-groups":
                    return {"logGroups": []}
                if operation == "list-tags-for-resource":
                    raise appliance.CommandError(args, 255, "ResourceNotFoundException: fixture tombstone")
                if operation.startswith(("delete", "terminate", "release")):
                    self.delete_calls.append(operation)
                    return {}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = TombstoneAWS(config)
            residuals = appliance.audit_run_resources(config, aws)
            self.assertEqual(residuals, [])
            self.assertEqual(
                appliance.remove_owned_residuals(
                    config,
                    aws,
                    residuals,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: self.fail("filtered tombstones must not retry"),
                ),
                [],
            )
            self.assertEqual(aws.delete_calls, [])
            for state in ("deleted", "failed"):
                with self.subTest(nat_state=state):
                    response = {"NatGateways": [{"NatGatewayId": "nat-deleted", "State": state}]}
                    with mock.patch.object(aws, "json", return_value=response):
                        self.assertFalse(appliance.owned_resource_is_live(aws, tombstones[1]))

    def test_residual_dependencies_are_reaudited_retried_and_eventually_absent(self):
        class Clock:
            def __init__(self):
                self.now = 0.0
                self.sleeps = []

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.sleeps.append(seconds)
                self.now += seconds

        class DependencyAWS:
            def __init__(self, config, operations):
                self.config = config
                self.operations = operations
                self.remaining = {value[0]: value[1] for value in operations.values()}
                self.calls = {operation: 0 for operation in operations}

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "get-resources":
                    if region != self.config.sites["west"]["region"]:
                        return {"ResourceTagMappingList": []}
                    return {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": resource["arn"],
                                "Tags": [
                                    {"Key": "EnvelopeRun", "Value": self.config.run_id},
                                    {"Key": "ExpiresAt", "Value": self.config.expires_at},
                                ],
                            }
                            for resource in self.remaining.values()
                        ]
                    }
                describes = {
                    "describe-vpc-endpoints": (
                        "delete-vpc-endpoints",
                        "VpcEndpoints",
                        "VpcEndpointId",
                        "State",
                        "available",
                    ),
                    "describe-vpc-endpoint-service-configurations": (
                        "delete-vpc-endpoint-service-configurations",
                        "ServiceConfigurations",
                        "ServiceId",
                        "ServiceState",
                        "Available",
                    ),
                    "describe-nat-gateways": (
                        "delete-nat-gateway",
                        "NatGateways",
                        "NatGatewayId",
                        "State",
                        "available",
                    ),
                    "describe-addresses": ("release-address", "Addresses", "AllocationId", None, None),
                }
                if operation in describes:
                    delete_operation, collection, identity_field, state_field, state = describes[operation]
                    arn = self.operations[delete_operation][0]
                    if arn not in self.remaining:
                        return {collection: []}
                    value = {identity_field: arn.rsplit("/", 1)[1]}
                    if state_field is not None:
                        value[state_field] = state
                    return {collection: [value]}
                arn, resource, error_code = self.operations[operation]
                self.calls[operation] += 1
                if self.calls[operation] == 1:
                    raise appliance.CommandError(
                        ["aws", operation],
                        255,
                        f"An error occurred ({error_code}) while deleting an exact run resource",
                    )
                self.remaining.pop(arn)
                return {}

        cases = {
            "gwlbe and endpoint service": {
                "delete-vpc-endpoints": (
                    "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                        "region": "us-west-2",
                    },
                    "OperationNotPermitted",
                ),
                "delete-vpc-endpoint-service-configurations": (
                    "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-fixture",
                        "region": "us-west-2",
                    },
                    "ExistingVpcEndpointConnections",
                ),
            },
            "nat and eip": {
                "delete-nat-gateway": (
                    "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-fixture",
                        "region": "us-west-2",
                    },
                    "DependencyViolation",
                ),
                "release-address": (
                    "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-fixture",
                        "region": "us-west-2",
                    },
                    "InvalidIPAddress.InUse",
                ),
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for name, operations in cases.items():
                with self.subTest(name=name):
                    clock = Clock()
                    aws = DependencyAWS(config, operations)
                    resources = [value[1] for value in operations.values()]
                    removed = appliance.remove_owned_residuals(
                        config,
                        aws,
                        resources,
                        dry_run=False,
                        allow_unexpired=True,
                        sleep=clock.sleep,
                        monotonic=clock.monotonic,
                    )
                    self.assertEqual(set(removed), {resource["arn"] for resource in resources})
                    self.assertEqual(aws.calls, {operation: 2 for operation in operations})
                    self.assertEqual(aws.remaining, {})
                    self.assertEqual(appliance.audit_run_resources(config, aws), [])
                    self.assertEqual(clock.sleeps, [appliance.RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS])

    def test_terminal_auth_failure_does_not_block_independent_residual_cleanup(self):
        resources = [
            {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-denied", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-removed", "region": "us-west-2"},
        ]
        attempted = []

        def delete(_aws, resource):
            attempted.append(resource["arn"])
            if resource["arn"].endswith("i-denied"):
                raise appliance.CommandError(["aws", "delete"], 255, "AccessDenied: fixture terminal denial")

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            with mock.patch.object(appliance, "delete_owned_resource", side_effect=delete), mock.patch.object(
                appliance, "audit_run_resources", return_value=[resources[0]]
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "AccessDenied"):
                    appliance.remove_owned_residuals(
                        config,
                        object(),
                        resources,
                        dry_run=False,
                        allow_unexpired=True,
                        sleep=lambda _: self.fail("terminal-only residual must not back off"),
                    )
        self.assertEqual(attempted, [resource["arn"] for resource in resources])


class MetadataTest(unittest.TestCase):
    def test_amd64_and_arm64_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            for architecture in ("amd64", "arm64"):
                with self.subTest(architecture=architecture):
                    config = make_config(pathlib.Path(temporary), architecture)
                    appliance.validate_aws_metadata(config, MetadataAWS(config))

    def test_metadata_failure_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            cases = {
                "architecture": {"Architecture": "arm64"},
                "state": {"State": "pending"},
                "root": {"RootDeviceType": "instance-store"},
                "virtualization": {"VirtualizationType": "paravirtual"},
                "image family": {"Name": "ubuntu-fixture"},
            }
            for name, overrides in cases.items():
                with self.subTest(name=name):
                    aws = MetadataAWS(config)
                    aws.image_overrides = overrides
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.validate_aws_metadata(config, aws)
            aws = MetadataAWS(config)
            aws.type_architectures = ["arm64"]
            with self.assertRaisesRegex(appliance.LifecycleError, "does not support"):
                appliance.validate_aws_metadata(config, aws)


class SSMAndCleanupTest(unittest.TestCase):
    @staticmethod
    def interrupt_cleanup_aws():
        class CleanupAWS:
            def __init__(self):
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.version += 1
                    self.etag = f'"manifest-{self.version}"'
                    return {"ETag": self.etag}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                if operation == "describe-parameters":
                    return {"Parameters": []}
                if operation == "get-resources":
                    return {"ResourceTagMappingList": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return False

        return CleanupAWS()

    def test_cleanup_hard_timeout_is_not_swallowed_or_allowed_to_continue(self):
        if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
            self.skipTest("POSIX interval timers are required")
        self.assertFalse(issubclass(appliance.CleanupDeadlineExceeded, Exception))

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("state-free cleanup must not invoke Terraform")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = self.interrupt_cleanup_aws()
            store = appliance.ManifestStore(config, aws, root / "timeout")
            store.write(appliance.new_manifest(config, artifact_identity(root), "123456789012"))
            later_cleanup = mock.Mock()

            def block_forever(*_args, **_kwargs):
                while True:
                    time.sleep(0.01)

            started = time.monotonic()
            with mock.patch.object(
                appliance, "cleanup_tailnet_devices", side_effect=block_forever
            ), mock.patch.object(appliance, "delete_ssm_parameter", later_cleanup):
                with self.assertRaises(appliance.CleanupDeadlineExceeded):
                    appliance.cleanup(
                        config,
                        appliance.ImmediateAwsCLIAdapter(aws),
                        object(),
                        appliance.ImmediateCommandRunnerAdapter(UnusedRunner()),
                        store.run_dir,
                        root / "terraform",
                        recover=False,
                        dry_run=False,
                        skip_destroy=True,
                        timeout_seconds=0.05,
                    )
            self.assertLess(time.monotonic() - started, 1)
            later_cleanup.assert_not_called()

    def test_keyboard_interrupt_and_sigterm_do_not_skip_independent_cleanup(self):
        if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
            self.skipTest("POSIX interval timers are required")

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("state-free cleanup must not invoke Terraform")

        for name, interruption, expected in (
            (
                "keyboard",
                lambda: (_ for _ in ()).throw(KeyboardInterrupt("injected interrupt")),
                KeyboardInterrupt,
            ),
            ("sigterm", lambda: signal.raise_signal(signal.SIGTERM), appliance.CleanupInterrupted),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                config = make_config(root)
                aws = self.interrupt_cleanup_aws()
                store = appliance.ManifestStore(config, aws, root / name)
                store.write(
                    appliance.new_manifest(config, artifact_identity(root), "123456789012")
                )
                calls = []

                def interrupt_devices(*_args, **_kwargs):
                    calls.append("devices")
                    interruption()
                    return []

                def delete_parameter(_aws, parameter):
                    calls.append(f"parameter-{parameter['site']}")

                def audit(*_args, **_kwargs):
                    calls.append("residual-audit")
                    return []

                with mock.patch.object(
                    appliance, "cleanup_tailnet_devices", side_effect=interrupt_devices
                ), mock.patch.object(
                    appliance, "delete_ssm_parameter", side_effect=delete_parameter
                ), mock.patch.object(
                    appliance, "recover_auth_key_ids", return_value=[]
                ), mock.patch.object(appliance, "audit_run_resources", side_effect=audit):
                    with self.assertRaises(expected):
                        appliance.cleanup(
                            config,
                            appliance.ImmediateAwsCLIAdapter(aws),
                            object(),
                            appliance.ImmediateCommandRunnerAdapter(UnusedRunner()),
                            store.run_dir,
                            root / "terraform",
                            recover=False,
                            dry_run=False,
                            skip_destroy=True,
                            timeout_seconds=2,
                        )

                self.assertEqual(
                    calls,
                    ["devices", "parameter-west", "parameter-east", "residual-audit"],
                )
                self.assertEqual(store.load_local()["phase"], "cleanup_incomplete")

    def test_ssm_secret_uses_protected_cli_input_file_not_argv(self):
        class FakeAWS:
            def __init__(self):
                self.payload = None
                self.command = None

            def json(inner, args, *, region=None):
                if args[1] == "put-parameter":
                    inner.command = list(args)
                    path = pathlib.Path(args[3].removeprefix("file://"))
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    inner.payload = json.loads(path.read_text())
                    return {"Version": 1}
                return {"Parameters": [{"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}]}

        with tempfile.TemporaryDirectory() as temporary:
            aws = FakeAWS()
            parameter = appliance.put_ssm_parameter(
                aws,
                run_dir=pathlib.Path(temporary),
                run_id="envelope-fixture",
                expires_at="2026-08-20T00:00:00Z",
                site="west",
                region="us-west-2",
                kms_key_arn="arn:aws:kms:us-west-2:123456789012:key/west",
                secret="fixture-auth-material",
            )
        self.assertEqual(aws.payload["Type"], "SecureString")
        self.assertFalse(aws.payload["Overwrite"])
        self.assertNotIn("fixture-auth-material", " ".join(aws.command))
        self.assertEqual(parameter["site"], "west")

    def test_device_cleanup_is_name_and_tag_scoped(self):
        class FakeAPI:
            def __init__(self):
                self.deleted = []
                self.devices = fixture_tailnet_devices()
                self.devices[1]["hostname"] = f"{self.devices[1]['hostname']}.fixture"
                self.devices.extend(
                    [
                        {
                            "id": "wrong-tag",
                            "hostname": fixture_tailnet_hostnames()[0],
                            "tags": ["tag:other"],
                        },
                        {"id": "wrong-name", "hostname": "other-west", "tags": ["tag:envelope-ci"]},
                    ]
                )

            def list_devices(inner):
                return inner.devices

            def delete_device(inner, device_id):
                inner.deleted.append(device_id)
                inner.devices = [device for device in inner.devices if device["id"] != device_id]

        api = FakeAPI()
        manifest = {
            "tailnet": {
                "expected_hostnames": fixture_tailnet_hostnames(),
                "device_roles": fixture_tailnet_roles(),
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        selected = appliance.cleanup_tailnet_devices(api, manifest, dry_run=False)
        expected_ids = {str(device["id"]) for device in fixture_tailnet_devices()}
        self.assertEqual(set(selected), expected_ids)
        self.assertEqual(set(api.deleted), expected_ids)
        self.assertEqual([device["id"] for device in api.devices], ["wrong-tag", "wrong-name"])

    def test_partial_recovery_accepts_zero_to_four_transport_node_subsets(self):
        class API:
            def __init__(self, devices):
                self.devices = devices
                self.deleted = []

            def list_devices(self):
                return self.devices

            def delete_device(self, device_id):
                self.deleted.append(device_id)
                self.devices = [device for device in self.devices if device["id"] != device_id]

        manifest = {
            "tailnet": {
                "expected_hostnames": fixture_tailnet_hostnames(),
                "device_roles": fixture_tailnet_roles(),
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        candidates = fixture_tailnet_devices()
        for count in (0, 1, 2, 4):
            with self.subTest(count=count):
                api = API(copy.deepcopy(candidates[:count]))
                selected = appliance.cleanup_tailnet_devices(api, manifest, dry_run=False)
                self.assertEqual(selected, sorted(device["id"] for device in candidates[:count]))
                self.assertEqual(api.deleted, selected)

    def test_partial_recovery_deletes_exact_and_numeric_retry_nodes(self):
        class API:
            def __init__(self):
                self.deleted = []
                self.devices = [
                    {
                        "id": "transport-exact",
                        "hostname": "envelope-fixture-west-transport-a",
                        "tags": ["tag:envelope-ci"],
                    },
                    {
                        "id": "transport-retry",
                        "hostname": "envelope-fixture-west-transport-a-1",
                        "tags": ["tag:envelope-ci"],
                    },
                ]

            def list_devices(self):
                return self.devices

            def delete_device(self, device_id):
                self.deleted.append(device_id)
                self.devices = [device for device in self.devices if device["id"] != device_id]

        manifest = {
            "tailnet": {
                "expected_hostnames": fixture_tailnet_hostnames(),
                "device_roles": fixture_tailnet_roles(),
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        api = API()
        selected = appliance.cleanup_tailnet_devices(api, manifest, dry_run=False)
        self.assertEqual(selected, ["transport-exact", "transport-retry"])
        self.assertEqual(api.deleted, selected)

    def test_readiness_records_exact_full_field_node_ids_durably(self):
        class API:
            def list_devices(self):
                return fixture_tailnet_devices()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with mock.patch.object(
                appliance,
                "persist_manifest_transition",
                side_effect=lambda target, _original, candidate, **_kwargs: target.write(
                    candidate, upload=False
                ),
            ):
                identifiers = appliance.record_ready_devices(API(), store, manifest)
            self.assertEqual(
                identifiers,
                {str(device["hostname"]): str(device["id"]) for device in fixture_tailnet_devices()},
            )
            persisted = json.loads(store.path.read_text())
            self.assertEqual(persisted["tailnet"]["device_ids"], identifiers)
            self.assertEqual(persisted["phase"], "ready")

    def test_readiness_discovers_numeric_aliases_and_selects_the_only_enabled_advertiser(self):
        class API:
            def list_devices(self):
                devices = fixture_tailnet_devices()
                exact = devices[0]
                exact["enabledRoutes"] = []
                alias = copy.deepcopy(exact)
                alias.update(
                    {
                        "id": "device-alias",
                        "nodeId": "node-alias",
                        "hostname": f"{exact['hostname']}-1",
                        "enabledRoutes": list(exact["advertisedRoutes"]),
                    }
                )
                return [alias, *reversed(devices)]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with mock.patch.object(
                appliance,
                "persist_manifest_transition",
                side_effect=lambda target, _original, candidate, **_kwargs: target.write(
                    candidate, upload=False
                ),
            ):
                identifiers = appliance.record_ready_devices(API(), store, manifest)

        self.assertEqual(
            identifiers["envelope-fixture-west-transport-a"], "device-alias"
        )
        self.assertEqual(set(identifiers), set(fixture_tailnet_hostnames()))

    def test_readiness_fails_closed_on_duplicate_enabled_numeric_aliases(self):
        class API:
            def list_devices(self):
                devices = fixture_tailnet_devices()
                alias = copy.deepcopy(devices[0])
                alias.update(
                    {
                        "id": "device-alias",
                        "nodeId": "node-alias",
                        "hostname": f"{devices[0]['hostname']}-2",
                    }
                )
                return [*devices, alias]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with self.assertRaisesRegex(
                appliance.LifecycleError, "exactly one enabled Tailnet advertiser"
            ):
                appliance.record_ready_devices(API(), store, manifest)
            self.assertEqual(store.load_local()["phase"], "readiness_started")

    def test_readiness_inspects_disabled_numeric_alias_route_fields(self):
        class API:
            def list_devices(self):
                devices = fixture_tailnet_devices()
                alias = copy.deepcopy(devices[0])
                alias.update(
                    {
                        "id": "device-alias",
                        "nodeId": "node-alias",
                        "hostname": f"{devices[0]['hostname']}-3",
                        "advertisedRoutes": ["10.99.0.0/24"],
                        "enabledRoutes": [],
                    }
                )
                return [alias, *devices]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with self.assertRaisesRegex(
                appliance.LifecycleError, "exact approved symmetric prefixes"
            ):
                appliance.record_ready_devices(API(), store, manifest)

    def test_readiness_rejects_unapproved_transport_route_advertisements(self):
        class API:
            def list_devices(self):
                devices = fixture_tailnet_devices()
                devices[2]["enabledRoutes"] = ["10.10.1.0/24"]
                return devices

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with self.assertRaisesRegex(appliance.LifecycleError, "exact approved symmetric prefixes"):
                appliance.record_ready_devices(API(), store, manifest)

    def test_readiness_rejects_any_run_scoped_target_tailnet_device(self):
        class API:
            def list_devices(self):
                return [
                    *fixture_tailnet_devices(),
                    {
                        "id": "fabricated-target",
                        "hostname": "envelope-fixture-west-target-a",
                        "tags": ["tag:envelope-ci"],
                        "advertisedRoutes": [],
                        "enabledRoutes": [],
                    },
                ]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "readiness_started"
            manifest["readiness_started_at"] = "2026-08-20T12:00:00Z"
            manifest["readiness_claim_id"] = "123e4567-e89b-42d3-a456-426614174000"
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            with self.assertRaisesRegex(appliance.LifecycleError, "targets must not be Tailnet devices"):
                appliance.record_ready_devices(API(), store, manifest)

    def test_numeric_retry_matching_never_shadows_an_exact_az_hostname(self):
        manifest = {
            "tailnet": {
                "expected_hostnames": [
                    "envelope-fixture-west-transport-a",
                    "envelope-fixture-west-transport-a-1",
                ],
                "device_roles": {
                    "envelope-fixture-west-transport-a": "transport-router",
                    "envelope-fixture-west-transport-a-1": "transport-router",
                },
                "tag": "tag:envelope-ci",
            }
        }
        devices = [
            {
                "id": "exact-a-1",
                "hostname": "envelope-fixture-west-transport-a-1",
                "tags": ["tag:envelope-ci"],
            },
            {
                "id": "retry-a-1",
                "hostname": "envelope-fixture-west-transport-a-1-1",
                "tags": ["tag:envelope-ci"],
            },
        ]

        scoped = appliance.scoped_run_devices(devices, manifest, include_numeric_suffixes=True)

        self.assertEqual(
            [device["id"] for device in scoped["envelope-fixture-west-transport-a"]],
            [],
        )
        self.assertEqual(
            [device["id"] for device in scoped["envelope-fixture-west-transport-a-1"]],
            ["exact-a-1", "retry-a-1"],
        )

    def test_backend_cleanup_deletes_only_exact_run_key_versions(self):
        class FakeAWS:
            def __init__(self):
                self.deleted = []
                self.present = True

            def json(inner, args, *, region=None):
                if args[1] == "list-object-versions":
                    if not inner.present:
                        return {"Versions": [], "DeleteMarkers": []}
                    return {
                        "Versions": [
                            {"Key": "runs/run/state", "VersionId": "v1"},
                            {"Key": "runs/run/state-other", "VersionId": "foreign"},
                        ],
                        "DeleteMarkers": [{"Key": "runs/run/state", "VersionId": "d1"}],
                    }
                inner.deleted.append((args[args.index("--key") + 1], args[args.index("--version-id") + 1]))
                if len(inner.deleted) == 2:
                    inner.present = False
                return {}

        aws = FakeAWS()
        versions = appliance.delete_exact_object_versions(
            aws, bucket="operator-backend", key="runs/run/state", region="us-west-2", dry_run=False
        )
        self.assertEqual(versions, ["v1", "d1"])
        self.assertEqual(aws.deleted, [("runs/run/state", "v1"), ("runs/run/state", "d1")])

    def test_prepare_creates_two_references_and_never_persists_key_material(self):
        class FakeAWS:
            def __init__(self):
                self.sites = []
                self.phases = []
                self.version = 0
                self.etag = '"manifest-0"'

            def json(inner, args, *, region=None):
                if args[1] == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != inner.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    body = pathlib.Path(args[args.index("--body") + 1])
                    inner.phases.append(json.loads(body.read_text())["phase"])
                    inner.version += 1
                    inner.etag = f'"manifest-{inner.version}"'
                    return {"VersionId": "manifest", "ETag": inner.etag}
                if args[1] == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    self.assertEqual(payload["Value"], "fixture-auth-material")
                    inner.sites.append(region)
                    return {"Version": 1}
                if args[1] == "describe-parameters":
                    return {"Parameters": [{"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}]}
                raise AssertionError(args)

        class FakeTailscale:
            def create_auth_key(self, tag, description, expiry):
                return "key-fixture-id", "fixture-auth-material"

            def revoke_auth_key(self, key_id):
                raise AssertionError("unexpected rollback")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = artifact_identity(root)
            config = make_config(root)
            aws = FakeAWS()
            with mock.patch.object(appliance, "run_preflight", return_value=(artifact, "123456789012")):
                manifest = appliance.prepare(config, aws, FakeTailscale(), root / "run")
            self.assertEqual(aws.sites, ["us-west-2", "us-east-1"])
            self.assertEqual(len(manifest["ssm_parameters"]), 2)
            for phase in (
                "preflight_complete",
                "auth_key_create_started",
                "auth_key_created",
                "west_secret_create_started",
                "west_secret_created",
                "east_secret_create_started",
                "east_secret_created",
                "prepared",
            ):
                self.assertIn(phase, aws.phases)
            for path in (root / "run").iterdir():
                if path.is_file():
                    self.assertNotIn("fixture-auth-material", path.read_text())

            validated_aws = FakeAWS()
            with mock.patch.object(
                appliance, "run_preflight", side_effect=AssertionError("duplicate preflight")
            ), mock.patch.object(appliance, "validate_artifact", return_value=artifact):
                validated_manifest = appliance.prepare(
                    config,
                    validated_aws,
                    FakeTailscale(),
                    root / "validated-run",
                    validated_preflight=(artifact, "123456789012"),
                )
            self.assertEqual(validated_manifest["phase"], "prepared")
            self.assertEqual(validated_aws.sites, ["us-west-2", "us-east-1"])

    def test_prepare_distinguishes_only_exact_manifest_create_collisions(self):
        class FailingAWS:
            def __init__(self, stderr):
                self.stderr = stderr
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                raise appliance.CommandError(args, 255, self.stderr)

        class UnusedTailscale:
            def create_auth_key(self, *args):
                raise AssertionError("manifest collision must fail before Tailnet mutation")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            collision = FailingAWS("PreconditionFailed: conditional request returned status code: 412")
            with mock.patch.object(appliance, "run_preflight", return_value=(artifact, "123456789012")):
                with self.assertRaises(appliance.ConcurrentLifecycleError):
                    appliance.prepare(config, collision, UnusedTailscale(), root / "collision")
            self.assertEqual(len(collision.calls), 1)
            self.assertIn("--if-none-match", collision.calls[0][0])
            collision.calls.clear()
            with self.assertRaisesRegex(appliance.ConcurrentLifecycleError, "cleanup is not authorized"):
                appliance.cleanup(
                    config,
                    appliance.ImmediateAwsCLIAdapter(collision),
                    object(),
                    object(),
                    root / "collision",
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=False,
                )
            self.assertEqual(collision.calls, [])

            unrelated = FailingAWS("AccessDenied: fixture policy failure")
            with mock.patch.object(appliance, "run_preflight", return_value=(artifact, "123456789012")):
                with self.assertRaises(appliance.CommandError) as raised:
                    appliance.prepare(config, unrelated, UnusedTailscale(), root / "unrelated")
            self.assertNotIsInstance(raised.exception, appliance.ConcurrentLifecycleError)

    def test_cross_host_cleanup_cannot_take_over_a_fresh_e2e_claim(self):
        class SharedAWS:
            def __init__(self):
                self.remote = b""
                self.etag = '"manifest-0"'
                self.writes = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    if "--if-none-match" in args and self.remote:
                        raise appliance.CommandError(args, 255, "PreconditionFailed: status code: 412")
                    if "--if-match" in args and args[args.index("--if-match") + 1] != self.etag:
                        raise appliance.CommandError(args, 255, "PreconditionFailed: status code: 412")
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.writes.append(json.loads(self.remote))
                    self.etag = f'"manifest-{len(self.writes)}"'
                    return {"ETag": self.etag}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag}
                raise AssertionError(args)

            def object_exists(self, *args):
                raise AssertionError("loser must stop before inspecting or destroying state")

        class Unused:
            def __getattr__(self, name):
                raise AssertionError(f"loser must not call {name}")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "e2e_running"
            manifest["e2e"] = {
                "claim_id": "123e4567-e89b-42d3-a456-426614174000",
                "output_sha256": "e" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            }
            aws = SharedAWS()
            winner = appliance.ManifestStore(config, aws, root / "winner")
            winner.write(manifest, if_none_match=True)
            winner_payload = bytes(aws.remote)
            aws.writes.clear()

            with self.assertRaisesRegex(appliance.LifecycleError, "active E2E claim"):
                appliance.cleanup(
                    config,
                    appliance.ImmediateAwsCLIAdapter(aws),
                    Unused(),
                    Unused(),
                    root / "loser",
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=False,
                )
            self.assertEqual(aws.writes, [])
            self.assertEqual(aws.remote, winner_payload)
            self.assertEqual(json.loads(aws.remote)["phase"], "e2e_running")

            replacement = copy.deepcopy(manifest)
            replacement["phase"] = "e2e_replacement_ready"
            replacement["e2e"]["replacement"] = {
                "address": 'aws_instance.envelope_target_west["a"]',
                "old_instance_id": "i-0123456789abcdef0",
                "started_at": "2026-08-20T12:01:00Z",
            }
            winner.write(replacement, if_match=aws.etag)
            replacement_payload = bytes(aws.remote)
            aws.writes.clear()
            with self.assertRaisesRegex(appliance.LifecycleError, "active E2E claim"):
                appliance.cleanup(
                    config,
                    appliance.ImmediateAwsCLIAdapter(aws),
                    Unused(),
                    Unused(),
                    root / "replacement-loser",
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=False,
                )
            self.assertEqual(aws.writes, [])
            self.assertEqual(aws.remote, replacement_payload)

            terminal = copy.deepcopy(manifest)
            terminal["phase"] = "cleanup_started"
            terminal["e2e"].update(
                {
                    "finished_at": "2026-08-20T12:05:00Z",
                    "passed": False,
                }
            )
            terminal["cleanup_claim_id"] = "223e4567-e89b-42d3-a456-426614174000"
            terminal["cleanup_claimed_at"] = (
                dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            )
            winner.write(terminal, if_match=aws.etag)
            cleanup_payload = bytes(aws.remote)
            aws.writes.clear()
            with self.assertRaisesRegex(appliance.ConcurrentLifecycleError, "another cleanup owner"):
                appliance.cleanup(
                    config,
                    appliance.ImmediateAwsCLIAdapter(aws),
                    Unused(),
                    Unused(),
                    root / "cleanup-loser",
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=False,
                )
            self.assertEqual(aws.writes, [])
            self.assertEqual(aws.remote, cleanup_payload)

    def test_expired_e2e_orphan_is_cleanable_only_by_janitor_recovery(self):
        class JanitorAWS:
            def __init__(self, payload):
                self.remote = payload
                self.etag = '"manifest-0"'
                self.phases = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag}
                if operation == "put-object":
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.phases.append(json.loads(self.remote)["phase"])
                    self.etag = f'"manifest-{len(self.phases)}"'
                    return {"ETag": self.etag}
                if operation == "delete-parameter":
                    return {}
                if operation == "describe-parameters":
                    return {"Parameters": []}
                raise AssertionError(args)

            def object_exists(self, *args):
                return False

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("state-free janitor must not invoke Terraform")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root, expired=True)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            mark_manifest_applied(manifest)
            manifest["phase"] = "e2e_running"
            manifest["e2e"] = {
                "claim_id": "123e4567-e89b-42d3-a456-426614174000",
                "output_sha256": "e" * 64,
                "started_at": "2026-08-19T12:00:00Z",
            }
            aws = JanitorAWS((json.dumps(manifest, separators=(",", ":")) + "\n").encode())
            with mock.patch.object(appliance, "cleanup_tailnet_devices", return_value=[]), mock.patch.object(
                appliance, "recover_auth_key_ids", return_value=[]
            ), mock.patch.object(appliance, "audit_run_resources", return_value=[]):
                result = appliance.cleanup(
                    config,
                    appliance.ImmediateAwsCLIAdapter(aws),
                    object(),
                    UnusedRunner(),
                    root / "janitor",
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=True,
                    janitor=True,
                )
            self.assertEqual(aws.phases, ["cleanup_started", "secrets_only_cleanup_complete"])
            self.assertFalse(result["state_exists"])

    def test_runner_loss_recovery_dry_run_preserves_shared_backend(self):
        class RecoveryAWS:
            def __init__(self, remote):
                self.remote = remote
                self.calls = []

            def json(inner, args, *, region=None):
                inner.calls.append(args[1])
                if args[1] == "get-object":
                    pathlib.Path(args[-1]).write_bytes(inner.remote)
                    return {"VersionId": "manifest"}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                if args[1] == "list-object-versions":
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return False

        class FakeTailscale:
            def list_devices(self):
                return []

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("dry-run recovery must not invoke Terraform")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            manifest = appliance.new_manifest(config, artifact, "123456789012")
            manifest["tailnet"]["auth_key_id"] = "key-fixture-id"
            remote = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            run_dir = root / "recovered"
            run_dir.mkdir()
            (run_dir / "runtime.tfvars.json").write_text("{}\n")
            aws = RecoveryAWS(remote)
            result = appliance.cleanup(
                config,
                appliance.ImmediateAwsCLIAdapter(aws),
                FakeTailscale(),
                UnusedRunner(),
                run_dir,
                root / "terraform",
                recover=True,
                dry_run=True,
                skip_destroy=True,
            )
            self.assertTrue(result["dry_run"])
            self.assertEqual(aws.calls.count("get-object"), 1)
            self.assertEqual(aws.calls.count("get-resources"), 2)
            self.assertEqual(config.backend["bucket"], "operator-backend")

    def test_cleanup_continues_after_destroy_exception_and_preserves_backend(self):
        class CleanupAWS:
            def __init__(self, config):
                self.config = config
                self.terminated = False
                self.deleted_new_residuals = set()
                self.deleted_parameters = []
                self.backend_version_reads = 0
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0

            def json(inner, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != inner.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    inner.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    inner.version += 1
                    inner.etag = f'"manifest-{inner.version}"'
                    return {"ETag": inner.etag}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(inner.remote)
                    return {"ETag": inner.etag, "VersionId": str(inner.version)}
                if operation == "delete-parameter":
                    inner.deleted_parameters.append((region, args[-1]))
                    return {}
                if operation == "describe-parameters":
                    return {"Parameters": []}
                if operation == "describe-instances":
                    return {
                        "Reservations": [
                            {"Instances": [{"InstanceId": "i-residual", "State": {"Name": "running"}}]}
                        ]
                    }
                if operation == "describe-network-acls":
                    return {
                        "NetworkAcls": [
                            {
                                "NetworkAclId": "acl-residual",
                                "VpcId": "vpc-residual",
                                "IsDefault": False,
                                "Associations": [],
                                "Tags": owned_tag_list(inner.config),
                            }
                        ]
                    }
                if operation == "describe-flow-logs":
                    return {
                        "FlowLogs": [
                            {
                                "FlowLogId": "fl-residual",
                                "FlowLogStatus": "ACTIVE",
                                "Tags": owned_tag_list(inner.config),
                            }
                        ]
                    }
                if operation == "describe-log-groups":
                    return {
                        "logGroups": [
                            {
                                "logGroupName": "/aws/vpc-flow-logs/envelope-fixture/west",
                                "arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west:*",
                            }
                        ]
                    }
                if operation == "list-tags-for-resource":
                    return {"tags": {tag["Key"]: tag["Value"] for tag in owned_tag_list(inner.config)}}
                if operation == "terminate-instances":
                    inner.terminated = True
                    return {}
                if operation == "delete-network-acl":
                    inner.deleted_new_residuals.add("network-acl")
                    return {}
                if operation == "delete-flow-logs":
                    inner.deleted_new_residuals.add("flow-log")
                    return {"Unsuccessful": []}
                if operation == "delete-log-group":
                    inner.deleted_new_residuals.add("log-group")
                    return {}
                if operation == "get-resources":
                    if region == inner.config.sites["west"]["region"]:
                        resources = []
                        if not inner.terminated:
                            resources.append(
                                "arn:aws:ec2:us-west-2:123456789012:instance/i-residual"
                            )
                        if "network-acl" not in inner.deleted_new_residuals:
                            resources.append(
                                "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-residual"
                            )
                        if "flow-log" not in inner.deleted_new_residuals:
                            resources.append(
                                "arn:aws:ec2:us-west-2:123456789012:vpc-flow-log/fl-residual"
                            )
                        if "log-group" not in inner.deleted_new_residuals:
                            resources.append(
                                "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-fixture/west:*"
                            )
                        return {
                            "ResourceTagMappingList": [
                                {
                                    "ResourceARN": arn,
                                    "Tags": [
                                        {"Key": "EnvelopeRun", "Value": inner.config.run_id},
                                        {"Key": "ExpiresAt", "Value": inner.config.expires_at},
                                    ],
                                }
                                for arn in resources
                            ]
                        }
                    return {"ResourceTagMappingList": []}
                if operation == "list-object-versions":
                    inner.backend_version_reads += 1
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return True

        class API:
            def __init__(self):
                self.devices = [
                    {
                        "id": "west-node",
                        "hostname": "envelope-fixture-west-transport-a",
                        "tags": ["tag:envelope-ci"],
                    }
                ]
                self.deleted = []
                self.revoked = []

            def list_devices(self):
                return self.devices

            def delete_device(self, device_id):
                self.deleted.append(device_id)
                self.devices = [device for device in self.devices if device["id"] != device_id]

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

            def list_auth_keys(self):
                return []

        class UnusedRunner:
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = CleanupAWS(config)
            api = API()
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "run-key"
            manifest["tailnet"]["nodes_expected"] = True
            mark_manifest_apply_started(manifest)
            manifest.pop("apply_claimed_at")
            manifest.pop("apply_claim_id")
            manifest["phase"] = "apply_failed"
            store = appliance.ManifestStore(config, aws, root / "run")
            store.write(manifest)
            with mock.patch.object(
                appliance, "terraform_destroy", side_effect=appliance.LifecycleError("injected destroy failure")
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "Terraform destroy.*injected destroy failure"):
                    appliance.cleanup(
                        config,
                        appliance.ImmediateAwsCLIAdapter(aws),
                        api,
                        UnusedRunner(),
                        store.run_dir,
                        root / "terraform",
                        recover=False,
                        dry_run=False,
                        skip_destroy=False,
                    )
            self.assertEqual(api.deleted, ["west-node"])
            self.assertEqual(api.revoked, ["run-key"])
            self.assertEqual(len(aws.deleted_parameters), 2)
            self.assertTrue(aws.terminated)
            self.assertEqual(
                aws.deleted_new_residuals,
                {"network-acl", "flow-log", "log-group"},
            )
            self.assertEqual(aws.backend_version_reads, 0)
            self.assertTrue(store.path.exists())
            self.assertEqual(store.load_local()["phase"], "cleanup_incomplete")

    def test_runner_loss_manifest_recovers_every_prepare_boundary_and_post_apply(self):
        class RecoveryAWS:
            def __init__(self, payload):
                self.payload = payload

            def json(self, args, *, region=None):
                if args[1] == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.payload)
                    return {}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                if args[1] == "list-object-versions":
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return False

        class API:
            def __init__(self, nodes_expected):
                self.nodes_expected = nodes_expected

            def list_devices(self):
                if not self.nodes_expected:
                    return []
                return fixture_tailnet_devices()

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("state-free recovery must not invoke Terraform")

        phases = (
            "preflight_complete",
            "auth_key_create_started",
            "auth_key_created",
            "west_secret_create_started",
            "west_secret_created",
            "east_secret_create_started",
            "east_secret_created",
            "prepared",
            "apply_started",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            for phase in phases:
                with self.subTest(phase=phase):
                    manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
                    manifest["phase"] = phase
                    if phase != "preflight_complete":
                        manifest["tailnet"]["auth_key_id"] = "key-fixture-id"
                    if phase == "apply_started":
                        mark_manifest_apply_started(manifest)
                        manifest["tailnet"]["nodes_expected"] = True
                    payload = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
                    run_dir = root / f"recover-{phase}"
                    result = appliance.cleanup(
                        config,
                        appliance.ImmediateAwsCLIAdapter(RecoveryAWS(payload)),
                        API(phase == "apply_started"),
                        UnusedRunner(),
                        run_dir,
                        root / "terraform",
                        recover=True,
                        dry_run=True,
                        skip_destroy=True,
                    )
                    self.assertTrue(result["dry_run"])

    def test_key_rotation_rolls_back_regional_partial_failure_before_revoking_old_key(self):
        class RotationAWS:
            def __init__(self, fail_east):
                self.values = {"us-west-2": "old-west", "us-east-1": "old-east"}
                self.fail_east = fail_east
                self.failed = False
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != self.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.version += 1
                    self.etag = f'"manifest-{self.version}"'
                    return {"ETag": self.etag}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                if operation == "get-parameter":
                    return {"Parameter": {"Value": self.values[region]}}
                if operation == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    if self.fail_east and region == "us-east-1" and payload["Value"] == "new-material" and not self.failed:
                        self.failed = True
                        raise appliance.LifecycleError("injected east update failure")
                    self.values[region] = payload["Value"]
                    return {"Version": 2}
                if operation == "describe-parameters":
                    return {
                        "Parameters": [
                            {"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}
                        ]
                    }
                raise AssertionError(args)

        class RotationAPI:
            def __init__(self):
                self.revoked = []

            def create_auth_key(self, tag, description, expiry):
                return "new-key-id", "new-material"

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key-id"
            mark_manifest_applied(manifest)
            manifest["phase"] = "ready"

            failing_aws = RotationAWS(True)
            failing_api = RotationAPI()
            failing_store = appliance.ManifestStore(config, failing_aws, root / "failed")
            failing_store.write(copy.deepcopy(manifest))
            with self.assertRaisesRegex(appliance.LifecycleError, "injected"):
                appliance.rotate_auth_key(config, failing_aws, failing_api, failing_store.run_dir)
            self.assertEqual(failing_aws.values, {"us-west-2": "old-west", "us-east-1": "old-east"})
            self.assertEqual(failing_api.revoked, ["new-key-id"])
            self.assertEqual(failing_store.load_local()["tailnet"]["auth_key_id"], "old-key-id")

            success_aws = RotationAWS(False)
            success_api = RotationAPI()
            success_store = appliance.ManifestStore(config, success_aws, root / "success")
            success_store.write(copy.deepcopy(manifest))
            rotated = appliance.rotate_auth_key(config, success_aws, success_api, success_store.run_dir)
            self.assertEqual(success_aws.values, {"us-west-2": "new-material", "us-east-1": "new-material"})
            self.assertEqual(success_api.revoked, ["old-key-id"])
            self.assertEqual(rotated["tailnet"]["auth_key_id"], "new-key-id")
            self.assertEqual(rotated["tailnet"]["pending_revoke_key_ids"], [])
            self.assertNotIn("rotation", rotated["tailnet"])

            replacement_manifest = copy.deepcopy(manifest)
            replacement_manifest["phase"] = "e2e_replacement_ready"
            replacement_manifest["e2e"] = {
                "claim_id": "123e4567-e89b-42d3-a456-426614174000",
                "output_sha256": "d" * 64,
                "started_at": "2026-08-20T12:00:00Z",
                "replacement": {
                    "address": 'aws_instance.envelope_target_west["a"]',
                    "old_instance_id": "i-0123456789abcdef0",
                    "started_at": "2026-08-20T12:01:00Z",
                },
            }
            replacement_aws = RotationAWS(False)
            replacement_store = appliance.ManifestStore(
                config, replacement_aws, root / "replacement"
            )
            replacement_store.write(replacement_manifest)
            with self.assertRaisesRegex(appliance.LifecycleError, "fully ready deployment"):
                appliance.rotate_auth_key(
                    config, replacement_aws, RotationAPI(), replacement_store.run_dir
                )

    def test_key_rotation_rolls_back_write_when_post_write_verification_fails(self):
        class VerificationFailureAWS:
            def __init__(self, failing_region):
                self.values = {"us-west-2": "old-west", "us-east-1": "old-east"}
                self.failing_region = failing_region
                self.verification_failed = False
                self.remote = b""
                self.etag = '"manifest-0"'
                self.version = 0

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    if "--if-match" in args and args[args.index("--if-match") + 1] != self.etag:
                        raise appliance.CommandError(args, 412, "PreconditionFailed")
                    self.remote = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                    self.version += 1
                    self.etag = f'"manifest-{self.version}"'
                    return {"ETag": self.etag}
                if operation == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.remote)
                    return {"ETag": self.etag, "VersionId": str(self.version)}
                if operation == "get-parameter":
                    return {"Parameter": {"Value": self.values[region]}}
                if operation == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    self.values[region] = payload["Value"]
                    return {"Version": 2}
                if operation == "describe-parameters":
                    if (
                        region == self.failing_region
                        and self.values[region] == "new-material"
                        and not self.verification_failed
                    ):
                        self.verification_failed = True
                        raise appliance.LifecycleError("injected post-write describe failure")
                    return {
                        "Parameters": [
                            {"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}
                        ]
                    }
                raise AssertionError(args)

        class API:
            def __init__(self):
                self.revoked = []

            def create_auth_key(self, tag, description, expiry):
                return "new-key-id", "new-material"

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key-id"
            mark_manifest_applied(manifest)
            manifest["phase"] = "ready"
            for region in ("us-west-2", "us-east-1"):
                with self.subTest(region=region):
                    aws = VerificationFailureAWS(region)
                    api = API()
                    store = appliance.ManifestStore(config, aws, root / f"failure-{region}")
                    store.write(copy.deepcopy(manifest))
                    with self.assertRaisesRegex(appliance.LifecycleError, "post-write describe"):
                        appliance.rotate_auth_key(config, aws, api, store.run_dir)
                    self.assertEqual(aws.values, {"us-west-2": "old-west", "us-east-1": "old-east"})
                    self.assertEqual(api.revoked, ["new-key-id"])
                    persisted = store.load_local()
                    self.assertEqual(persisted["tailnet"]["auth_key_id"], "old-key-id")
                    self.assertNotIn("rotation", persisted["tailnet"])

    def test_cleanup_discovers_key_created_after_durable_rotation_intent(self):
        class API:
            def list_auth_keys(self):
                return [{"id": "unrecorded-new-key", "description": "Envelope acceptance envelope-fixture rotation-1"}]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key"
            manifest["tailnet"]["rotation"] = {
                "claim_id": "123e4567-e89b-42d3-a456-426614174000",
                "description": "Envelope acceptance envelope-fixture rotation-1",
                "new_key_id": None,
                "updated_sites": [],
            }
            manifest["phase"] = "key_rotation_create_started"
            self.assertEqual(appliance.recover_auth_key_ids(API(), manifest), ["old-key", "unrecorded-new-key"])

    def test_cleanup_checkpoints_after_zero_audit_before_manifest_deletion(self):
        class AWS:
            @staticmethod
            def object_exists(_bucket, _key, _region, **_kwargs):
                return False

            @staticmethod
            def json(args, *, region=None, timeout_seconds=None):
                if args[1] == "describe-parameters":
                    return {"Parameters": []}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            config = make_config(root)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "e2e_failed"
            manifest["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "d" * 64,
                "started_at": "2026-08-20T12:00:00Z",
                "finished_at": "2026-08-20T12:01:00Z",
                "passed": False,
            }

            class Store:
                def __init__(self):
                    self.value = copy.deepcopy(manifest)
                    self.remote_etag = '"fixture-etag"'
                    self.path = run_dir / "manifest.json"

                def recover(self):
                    return copy.deepcopy(self.value)

                def write(self, value, *, if_match=None):
                    self.value = copy.deepcopy(value)
                    self.remote_etag = '"fixture-next-etag"'

            store = Store()
            order: list[str] = []

            def delete_versions(_aws, *, bucket, key, region, dry_run):
                order.append(key)
                return []

            def checkpoint(result):
                self.assertEqual(result["final_residual_count"], 0)
                self.assertNotIn(config.manifest_key, order)
                order.append("checkpoint")

            with (
                mock.patch.object(appliance, "ManifestStore", return_value=store),
                mock.patch.object(
                    appliance, "cleanup_tailnet_devices", return_value=[]
                ),
                mock.patch.object(appliance, "recover_auth_key_ids", return_value=[]),
                mock.patch.object(appliance, "audit_run_resources", return_value=[]),
                mock.patch.object(appliance, "delete_ssm_parameter"),
                mock.patch.object(
                    appliance,
                    "delete_exact_object_versions",
                    side_effect=delete_versions,
                ),
            ):
                result = appliance.cleanup(
                    config,
                    AWS(),
                    object(),
                    object(),
                    run_dir,
                    root / "terraform",
                    recover=True,
                    dry_run=False,
                    skip_destroy=False,
                    before_manifest_delete=checkpoint,
                )

            self.assertEqual(result["final_residual_count"], 0)
            self.assertEqual(
                order,
                [
                    config.backend["state_key"],
                    config.lock_key,
                    "checkpoint",
                    config.manifest_key,
                ],
            )

            failed_store = Store()
            failed_order: list[str] = []

            def failed_delete_versions(
                _aws, *, bucket, key, region, dry_run
            ):
                failed_order.append(key)
                return []

            def failed_checkpoint(_result):
                failed_order.append("checkpoint")
                raise OSError("fixture durable receipt fsync failed")

            with (
                mock.patch.object(
                    appliance, "ManifestStore", return_value=failed_store
                ),
                mock.patch.object(
                    appliance, "cleanup_tailnet_devices", return_value=[]
                ),
                mock.patch.object(appliance, "recover_auth_key_ids", return_value=[]),
                mock.patch.object(appliance, "audit_run_resources", return_value=[]),
                mock.patch.object(appliance, "delete_ssm_parameter"),
                mock.patch.object(
                    appliance,
                    "delete_exact_object_versions",
                    side_effect=failed_delete_versions,
                ),
            ):
                with self.assertRaisesRegex(
                    appliance.LifecycleError, "durable receipt fsync"
                ):
                    appliance.cleanup(
                        config,
                        AWS(),
                        object(),
                        object(),
                        run_dir,
                        root / "terraform",
                        recover=True,
                        dry_run=False,
                        skip_destroy=False,
                        before_manifest_delete=failed_checkpoint,
                    )

            self.assertNotIn(config.manifest_key, failed_order)
            self.assertEqual(failed_store.value["phase"], "cleanup_incomplete")


def render_template(path: pathlib.Path, values: dict[str, str]) -> str:
    text = path.read_text()
    pattern = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

    def replace(match):
        name = match.group(1)
        if name not in values:
            raise AssertionError(f"missing template value {name}")
        return values[name]

    return pattern.sub(replace, text).replace("$${", "${")


class CloudInitSandboxTest(unittest.TestCase):
    def template_values(self, digest: str) -> dict[str, str]:
        return {
            "site": "west",
            "run_name": "envelope-fixture",
            "artifact_region": "us-west-2",
            "artifact_bucket": "fixture-artifact",
            "artifact_key": "artifacts/revision/envelope-linux-amd64",
            "artifact_sha256": digest,
            "artifact_revision": "a" * 40,
            "artifact_version": "fixture.1",
            "artifact_architecture": "amd64",
            "config_version": "2",
            "mode": "packet-return",
            "udp_bind": "0.0.0.0:6081",
            "max_inner_packet_size": "1280",
        }

    def test_rendered_scripts_and_embedded_assets_have_valid_shell_syntax(self):
        digest = "a" * 64
        templates = [
            ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl",
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl",
        ]
        for template in templates:
            with self.subTest(template=template.name):
                rendered = render_template(template, self.template_values(digest))
                self.assertIsNone(appliance.SECRET_PATTERNS[0].search(rendered))
                self.assertNotIn("tailscale_auth_key", rendered)
                subprocess.run(["bash", "-n"], input=rendered, text=True, check=True, capture_output=True)
                for body in re.findall(r"<<'([A-Z_]+)'\n(.*?)\n\1", rendered, flags=re.DOTALL):
                    if body[1].startswith("#!/usr/bin/env bash"):
                        subprocess.run(["bash", "-n"], input=body[1], text=True, check=True, capture_output=True)
        bootstrap = render_template(templates[1], self.template_values(digest))
        self.assertIn("ENVELOPE_CONFIG_VERSION=2", bootstrap)
        self.assertIn("ENVELOPE_MODE=packet-return", bootstrap)
        self.assertIn("ENVELOPE_UDP_BIND=0.0.0.0:6081", bootstrap)
        self.assertIn("ENVELOPE_MAX_INNER_PACKET_SIZE=1280", bootstrap)
        for obsolete in (
            "ENVELOPE_TUN_NAME",
            "ENVELOPE_TAILSCALE_IFACE",
            "ENVELOPE_LOCAL_SITE_CIDRS",
            "ENVELOPE_REMOTE_SITE_CIDRS",
            "ENVELOPE_ROUTING_MODE",
            "ENVELOPE_ROUTING_TABLE_ID",
            "ENVELOPE_ROUTING_RULE_PRIORITY",
            "tailscaled.service",
            "envelope-host-network",
            "ENVELOPE-MSS",
        ):
            self.assertNotIn(obsolete, bootstrap)
        self.assertIn("After=network-online.target", bootstrap)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW", bootstrap)
        self.assertNotIn("CAP_NET_ADMIN", bootstrap)

    def test_packet_return_service_preflight_is_read_only_and_target_has_no_host_routing(self):
        rendered = render_template(
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl", self.template_values("a" * 64)
        )
        preflight = re.search(
            r"cat >/usr/local/sbin/envelope-preflight <<'PREFLIGHT'\n(.*?)\nPREFLIGHT",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        service_unit = re.search(
            r"cat >/etc/systemd/system/envelope.service <<'ENVELOPE_UNIT'\n(.*?)\nENVELOPE_UNIT",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        self.assertIn("grep -Fqx", preflight)
        self.assertIn('"$sha256_bin" -c -', preflight)
        for prohibited in (
            "tailscale",
            "sysctl",
            "iptables",
            "nft ",
            " route ",
            "envelope0",
            "FORWARD",
            "TCPMSS",
        ):
            self.assertNotIn(prohibited, preflight)
        self.assertIn("User=envelope", service_unit)
        self.assertIn("Group=envelope", service_unit)
        self.assertNotRegex(service_unit, r"(?m)^User=root$")
        self.assertIn("ExecStartPre=/usr/local/sbin/envelope-preflight", service_unit)
        self.assertIn("ExecStart=/usr/local/bin/envelope", service_unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW", service_unit)
        self.assertIn("AmbientCapabilities=CAP_NET_RAW", service_unit)
        self.assertNotIn("CAP_NET_ADMIN", service_unit)
        self.assertIn("ProtectKernelTunables=yes", service_unit)

    def test_vendored_tailscale_module_has_only_exact_package_installation_before_auth(self):
        module = ROOT / "example/terraform/modules/tailscale-cloudinit"
        texts = [path.read_text() for path in module.rglob("*") if path.is_file()]
        combined = "\n".join(texts)
        self.assertNotIn("tailscale.com/install.sh", combined)
        self.assertNotIn("TRACK=", combined)
        self.assertIn("additional_parts", combined)
        self.assertIn("rpm --checksig", combined)
        self.assertIn("key ID 957f5868: OK", combined)
        self.assertIn("-----BEGIN PGP PUBLIC KEY BLOCK-----", combined)
        main = (module / "main.tf").read_text()
        self.assertLess(main.index("10-install-pinned-tailscale.sh"), main.index("20-setup-tailscale.sh"))
        user_data = (ROOT / "example/terraform/user_data.tf").read_text()
        self.assertNotIn('source  = "tailscale/tailscale/cloudinit"', user_data)
        self.assertIn("tailscale_1.80.3_x86_64.rpm", user_data)
        self.assertIn("aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2", user_data)
        self.assertIn("84ea51f9200a2c93362208f9617948fc8dbae06f3ed7faddf08eebc8a5371c32", user_data)
        self.assertIn(
            "53c6f7dfbd774839d9f37e6c5022ba952108aba9a0e556a56f292a9eb605d7cf  files/repo.gpg",
            (module / "SOURCE.sha256").read_text(),
        )
        for line in (module / "SOURCE.sha256").read_text().splitlines():
            digest, relative = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((module / relative).read_bytes()).hexdigest(), digest)
        rendered_install = render_template(
            module / "templates/install_tailscale.sh.tftpl",
            {
                "package_version": "1.80.3",
                "package_url": "https://fixture.invalid/tailscale_1.80.3_x86_64.rpm",
                "package_sha256": "a" * 64,
                "signing_key": "Zml4dHVyZQ==",
                "max_retries": "3",
                "retry_delay": "1",
            },
        )
        rendered_setup = render_template(
            module / "templates/setup_tailscale.sh.tftpl",
            {
                "auth_key": "command:/fixture/resolver",
                "package_version": "1.80.3",
                "max_retries": "3",
                "retry_delay": "1",
                "hostname": "fixture-west",
                "advertise_tags": "tag:fixture",
                "advertise_routes": "10.0.0.0/24",
                "accept_routes": "true",
                "snat_subnet_routes": "false",
                "netfilter_mode": "off",
                "timeout": "2m",
                "pre_setup_gate": "",
            },
        )
        for rendered in (rendered_install, rendered_setup):
            subprocess.run(["bash", "-n"], input=rendered, text=True, check=True, capture_output=True)
        self.assertIn('if /usr/bin/dnf install -y "$package_path" &&', rendered_install)
        self.assertIn("/usr/bin/dnf clean packages >/dev/null 2>&1 || true", rendered_install)
        self.assertIn("reviewed Tailscale package installation exhausted retries", rendered_install)

    def test_checksum_verified_atomic_install_and_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            source.write_bytes(b"fixture-static-linux-artifact")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            fake_aws = root / "aws"
            fake_systemctl = root / "systemctl"
            service_log = root / "service.log"
            fake_aws.write_text("#!/usr/bin/env bash\nset -euo pipefail\ncp \"$FAKE_ARTIFACT\" \"${@: -1}\"\n")
            fake_systemctl.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\"$SERVICE_LOG\"\n")
            fake_aws.chmod(0o755)
            fake_systemctl.chmod(0o755)
            installer = render_template(
                ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl", self.template_values(digest)
            )
            env = {
                **os.environ,
                "ENVELOPE_INSTALL_ROOT": str(root / "target"),
                "AWS_BIN": str(fake_aws),
                "SYSTEMCTL_BIN": str(fake_systemctl),
                "FAKE_ARTIFACT": str(source),
                "SERVICE_LOG": str(service_log),
                "SHA256_BIN": "/usr/bin/shasum" if pathlib.Path("/usr/bin/shasum").exists() else "/usr/bin/sha256sum",
                "INSTALL_BIN": "/usr/bin/install",
                "MV_BIN": "/bin/mv",
            }
            if env["SHA256_BIN"].endswith("shasum"):
                wrapper = root / "sha256"
                wrapper.write_text("#!/usr/bin/env bash\nexec /usr/bin/shasum -a 256 \"$@\"\n")
                wrapper.chmod(0o755)
                env["SHA256_BIN"] = str(wrapper)
            subprocess.run(["bash"], input=installer, text=True, env=env, check=True, capture_output=True)
            target = root / "target/usr/local/bin/envelope"
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertTrue(target.stat().st_mode & stat.S_IXUSR)
            self.assertIn(digest, (root / "target/etc/envelope/artifact.env").read_text())

            target.write_bytes(b"known-good-old-artifact")
            bad_installer = render_template(
                ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl", self.template_values("0" * 64)
            )
            result = subprocess.run(["bash"], input=bad_installer, text=True, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"known-good-old-artifact")
            self.assertIn("disable --now envelope.service", service_log.read_text())

    def test_packet_return_preflight_requires_exact_runtime_and_artifact_identity(self):
        rendered = render_template(
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl", self.template_values("a" * 64)
        )
        match = re.search(
            r"cat >/usr/local/sbin/envelope-preflight <<'PREFLIGHT'\n(.*?)\nPREFLIGHT",
            rendered,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        preflight = match.group(1)
        for expected in (
            "ENVELOPE_CONFIG_VERSION=2",
            "ENVELOPE_MODE=packet-return",
            "ENVELOPE_UDP_BIND=0.0.0.0:6081",
            "ENVELOPE_MAX_INNER_PACKET_SIZE=1280",
            "ENVELOPE_DEPLOYED_ARTIFACT_SHA256=" + "a" * 64,
            "ENVELOPE_DEPLOYED_ARTIFACT_REVISION=" + "a" * 40,
        ):
            self.assertIn(expected, preflight)
        self.assertIn("sha256sum", rendered)
        self.assertNotIn("tailscale", preflight)
        self.assertNotIn("route", preflight)
        self.assertNotIn("iptables", preflight)


class DeploymentOutputTest(unittest.TestCase):
    def test_complete_output_rejects_plan_time_unknowns_and_partial_id_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))

            missing_value = symmetric_deployment_document(config)
            missing_value["symmetric_topology"].pop("value")
            with self.assertRaisesRegex(
                appliance.LifecycleError,
                "complete symmetric deployment output contract",
            ):
                appliance.validate_symmetric_deployment_output(missing_value, config)

            for output_name, mutate in (
                (
                    "vpc_ids",
                    lambda value: value.pop("east"),
                ),
                (
                    "gwlb_endpoint_ids",
                    lambda value: value["west"].pop("b"),
                ),
                (
                    "flow_log_evidence",
                    lambda value: value["west"].pop("flow_log_id"),
                ),
            ):
                with self.subTest(partial_output=output_name):
                    changed = symmetric_deployment_document(config)
                    mutate(changed[output_name]["value"])
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        f"{output_name} does not contain a complete concrete output value",
                    ):
                        appliance.validate_symmetric_deployment_output(changed, config)

    def test_complete_output_requires_packet_return_and_exact_transport_member_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_deployment_document(config)
            appliance.validate_symmetric_deployment_output(document, config)

            obsolete_runtime = copy.deepcopy(document)
            obsolete_runtime["envelope_runtime_config"]["value"]["west"]["tun_name"] = "envelope0"
            with self.assertRaisesRegex(appliance.LifecycleError, "canonical packet-return"):
                appliance.validate_symmetric_deployment_output(obsolete_runtime, config)

            missing_eni = copy.deepcopy(document)
            missing_eni["symmetric_topology"]["value"]["sites"]["west"][
                "transport_router_fleet"
            ][0].pop("network_interface_id")
            with self.assertRaisesRegex(appliance.LifecycleError, "transport_router_fleet has an invalid member"):
                appliance.validate_symmetric_deployment_output(missing_eni, config)

            duplicate_route_table = copy.deepcopy(document)
            west_routers = duplicate_route_table["symmetric_topology"]["value"]["sites"]["west"][
                "transport_router_fleet"
            ]
            west_routers[1]["gwlbe_route_table_id"] = west_routers[0]["gwlbe_route_table_id"]
            with self.assertRaisesRegex(appliance.LifecycleError, "transport fleets contain duplicate identities"):
                appliance.validate_symmetric_deployment_output(duplicate_route_table, config)

    def test_complete_output_requires_all_instance_roles_to_be_globally_disjoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            cases = {
                "secondary target": "i-target-east-b",
                "transport router": "i-transport-west-b",
            }
            for name, duplicate_id in cases.items():
                with self.subTest(name=name):
                    document = symmetric_deployment_document(config)
                    document["workload_instances"]["value"]["west"]["initiator"][
                        "instance_id"
                    ] = duplicate_id
                    with self.assertRaisesRegex(
                        appliance.LifecycleError, "globally disjoint"
                    ):
                        appliance.validate_symmetric_deployment_output(
                            document, config
                        )

    def test_complete_output_rejects_new_contract_mutations_after_apply(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            document = symmetric_deployment_document(config)

            for output_name in (
                "transport_router_readiness_expectations",
                "route_failover",
            ):
                with self.subTest(missing=output_name):
                    changed = copy.deepcopy(document)
                    changed.pop(output_name)
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "complete symmetric deployment output contract",
                    ):
                        appliance.validate_symmetric_deployment_output(changed, config)

            readiness_mutations = {
                "schema": lambda site: site.update({"config_version": 3}),
                "schema type": lambda site: site.update({"config_version": 2.0}),
                "CIDR": lambda site: site["local_site_cidrs"].append(
                    "10.99.0.0/24"
                ),
                "policy": lambda site: site["local_policy_rules"][0].update(
                    {"table": "52"}
                ),
                "firewall": lambda site: site["filter_forward_rules"][0].update(
                    {"target": "ACCEPT"}
                ),
                "MSS": lambda site: site["mss_rules"][0].update(
                    {"tcp_flags": "SYN SYN"}
                ),
                "mangle policy": lambda site: site.update(
                    {"mangle_forward_policy": "DROP"}
                ),
                "recovery marker": lambda site: site.update(
                    {"recovery_marker": "/tmp/stale"}
                ),
                "full policy rules": lambda site: site["ipv4_policy_rules"][0].update(
                    {"table": "main"}
                ),
                "remote route table": lambda site: site.update(
                    {"remote_route_table": 53}
                ),
                "contract SHA": lambda site: site.update(
                    {"contract_sha256": "f" * 64}
                ),
            }
            for name, mutate in readiness_mutations.items():
                with self.subTest(readiness=name):
                    changed = copy.deepcopy(document)
                    mutate(
                        changed["transport_router_readiness_expectations"]["value"][
                            "sites"
                        ]["west"]
                    )
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "transport-router readiness expectations",
                    ):
                        appliance.validate_symmetric_deployment_output(changed, config)

            for field in (
                "mutation_timeout_seconds",
                "restoration_timeout_seconds",
                "recovery_timeout_seconds",
            ):
                with self.subTest(bound=field):
                    changed = copy.deepcopy(document)
                    changed["route_failover"]["value"][field] += 1
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "route_failover output",
                    ):
                        appliance.validate_symmetric_deployment_output(changed, config)

            changed = copy.deepcopy(document)
            changed["route_failover"]["value"]["mutation_timeout_seconds"] = 120.0
            with self.assertRaisesRegex(
                appliance.LifecycleError, "route_failover output"
            ):
                appliance.validate_symmetric_deployment_output(changed, config)

            for field, value in (
                ("route_table_id", "rtb-wrong"),
                ("initial_network_interface_id", "eni-transport-west-b"),
            ):
                with self.subTest(route_identity=field):
                    changed = copy.deepcopy(document)
                    changed["route_failover"]["value"]["sites"]["west"]["a"][
                        field
                    ] = value
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "route_failover output",
                    ):
                        appliance.validate_symmetric_deployment_output(changed, config)

            changed = copy.deepcopy(document)
            changed["cost_profile"]["value"]["nat_topology_limit"][
                "expanded_for_ha"
            ] = True
            with self.assertRaisesRegex(
                appliance.LifecycleError, "symmetric HA cost profile"
            ):
                appliance.validate_symmetric_deployment_output(changed, config)

            changed = copy.deepcopy(document)
            changed["cost_profile"]["value"]["resource_counts"]["flow_log_iam_roles"] = True
            with self.assertRaisesRegex(
                appliance.LifecycleError, "symmetric HA cost profile"
            ):
                appliance.validate_symmetric_deployment_output(changed, config)

    def test_parses_deterministic_role_aware_workloads_and_preserves_existing_maps(self):
        document = deployment_document()
        instances, target_groups, workloads = appliance.deployment_values(document)

        self.assertEqual(instances, {"west": "i-appliance-west", "east": "i-appliance-east"})
        self.assertEqual(
            target_groups,
            {
                "west": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/west/fixture",
                "east": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/east/fixture",
            },
        )
        self.assertEqual(list(workloads), ["west", "east"])
        self.assertEqual(list(workloads["west"]), ["initiator", "responder"])
        self.assertEqual(workloads["west"]["initiator"]["region"], "us-west-2")
        self.assertEqual(workloads["east"]["responder"]["availability_zone"], "us-east-1b")
        self.assertEqual(workloads["east"]["responder"]["private_ip"], "10.20.2.10")
        self.assertEqual(workloads["east"]["responder"]["instance_id"], "i-workload-east-responder")

        bare = {
            name: value["value"]
            for name, value in document.items()
        }
        self.assertEqual(appliance.deployment_values(bare), (instances, target_groups, workloads))

    def test_explicit_regions_and_configured_az_identity_must_agree(self):
        document = deployment_document()
        for site, region in (("west", "us-west-2"), ("east", "us-east-1")):
            document["workload_instances"]["value"][site]["region"] = region
            for role in ("initiator", "responder"):
                document["workload_instances"]["value"][site][role]["region"] = region

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            _, _, workloads = appliance.deployment_values(document, expected_sites=config.sites)
            self.assertEqual(workloads["west"]["responder"]["region"], "us-west-2")

            document["workload_instances"]["value"]["west"]["initiator"][
                "availability_zone"
            ] = "us-west-2c"
            with self.assertRaisesRegex(appliance.LifecycleError, "unexpected AZ identity"):
                appliance.deployment_values(document, expected_sites=config.sites)

            swapped = deployment_document()
            west = swapped["workload_instances"]["value"]["west"]
            west["initiator"]["cidr"] = "10.10.2.0/24"
            with self.assertRaisesRegex(appliance.LifecycleError, "inconsistent IPv4 metadata"):
                appliance.deployment_values(swapped, expected_sites=config.sites)

    def test_malformed_missing_and_duplicate_workload_output_fails_closed(self):
        def missing_output(document):
            document.pop("workload_instances")

        def missing_site(document):
            document["workload_instances"]["value"].pop("east")

        def missing_role(document):
            document["workload_instances"]["value"]["west"].pop("responder")

        def missing_identity_field(document):
            document["workload_instances"]["value"]["west"]["initiator"].pop("private_ip")

        def unsupported_identity_field(document):
            document["workload_instances"]["value"]["west"]["initiator"]["credential"] = "prohibited"

        def contradictory_region(document):
            document["workload_instances"]["value"]["west"]["initiator"]["region"] = "us-east-1"

        def duplicate_instance(document):
            document["workload_instances"]["value"]["east"]["responder"][
                "instance_id"
            ] = "i-workload-west-initiator"

        def duplicate_private_ip(document):
            initiator = document["workload_instances"]["value"]["east"]["initiator"]
            responder = document["workload_instances"]["value"]["east"]["responder"]
            responder["private_ip"] = initiator["private_ip"]
            responder["cidr"] = initiator["cidr"]

        def duplicate_role_az(document):
            initiator = document["workload_instances"]["value"]["west"]["initiator"]
            responder = document["workload_instances"]["value"]["west"]["responder"]
            responder["az_key"] = initiator["az_key"]
            responder["availability_zone"] = initiator["availability_zone"]

        def duplicate_site_region(document):
            for role, suffix in (("initiator", "a"), ("responder", "b")):
                document["workload_instances"]["value"]["east"][role][
                    "availability_zone"
                ] = f"us-west-2{suffix}"

        cases = {
            "missing output": missing_output,
            "missing site": missing_site,
            "missing role": missing_role,
            "missing identity field": missing_identity_field,
            "unsupported identity field": unsupported_identity_field,
            "contradictory region": contradictory_region,
            "duplicate instance": duplicate_instance,
            "duplicate private IP": duplicate_private_ip,
            "duplicate role AZ": duplicate_role_az,
            "duplicate site region": duplicate_site_region,
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                document = deployment_document()
                mutate(document)
                with self.assertRaises(appliance.LifecycleError):
                    appliance.deployment_values(document)

    def test_duplicate_json_roles_and_secret_bearing_values_are_not_exposed(self):
        duplicate = '{"west":{"initiator":{},"initiator":{}}}'
        with self.assertRaisesRegex(appliance.LifecycleError, "duplicate object key"):
            appliance.parse_deployment_json(duplicate)

        secret = "ts" + "key-auth-fixture-sensitive"
        document = deployment_document()
        document["workload_instances"]["value"]["west"]["initiator"]["availability_zone"] = secret
        with self.assertRaises(appliance.LifecycleError) as raised:
            appliance.deployment_values(document)
        self.assertNotIn(secret, str(raised.exception))


class ReadinessTest(unittest.TestCase):
    def test_live_gwlbe_routes_match_config_bound_source_owners_and_output_allowlist(self):
        class RouteAWS:
            def __init__(self, responses):
                self.responses = responses
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((list(args), region))
                if args[:2] == ["ec2", "describe-network-interfaces"]:
                    return {
                        "NetworkInterfaces": copy.deepcopy(
                            self.responses[region]["NetworkInterfaces"]
                        )
                    }
                if args[:2] == ["ec2", "describe-route-tables"]:
                    return {
                        "RouteTables": copy.deepcopy(
                            self.responses[region]["RouteTables"]
                        )
                    }
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = symmetric_deployment_document(config)
            aws = RouteAWS(live_gwlbe_route_tables(config, deployment))
            appliance.validate_live_gwlbe_routes(config, aws, deployment)

        self.assertEqual(
            aws.calls,
            [
                (
                    [
                        "ec2",
                        "describe-network-interfaces",
                        "--network-interface-ids",
                        "eni-transport-west-a",
                        "eni-transport-west-b",
                    ],
                    "us-west-2",
                ),
                (
                    [
                        "ec2",
                        "describe-route-tables",
                        "--route-table-ids",
                        "rtb-gwlbe-west-a",
                        "rtb-gwlbe-west-b",
                    ],
                    "us-west-2",
                ),
                (
                    [
                        "ec2",
                        "describe-network-interfaces",
                        "--network-interface-ids",
                        "eni-transport-east-a",
                        "eni-transport-east-b",
                    ],
                    "us-east-1",
                ),
                (
                    [
                        "ec2",
                        "describe-route-tables",
                        "--route-table-ids",
                        "rtb-gwlbe-east-a",
                        "rtb-gwlbe-east-b",
                    ],
                    "us-east-1",
                ),
            ],
        )

    def test_live_gwlbe_routes_fail_closed_on_route_or_owner_drift(self):
        class RouteAWS:
            def __init__(self, responses):
                self.responses = responses

            def json(self, args, *, region=None):
                if args[:2] == ["ec2", "describe-network-interfaces"]:
                    return {
                        "NetworkInterfaces": copy.deepcopy(
                            self.responses[region]["NetworkInterfaces"]
                        )
                    }
                if args[:2] == ["ec2", "describe-route-tables"]:
                    return {
                        "RouteTables": copy.deepcopy(
                            self.responses[region]["RouteTables"]
                        )
                    }
                raise AssertionError(args)

        def first_west_remote(responses):
            return responses["us-west-2"]["RouteTables"][0]["Routes"][1]

        mutations = {
            "wrong allowlisted ENI": lambda responses: first_west_remote(
                responses
            ).update({"NetworkInterfaceId": "eni-transport-west-b"}),
            "missing prefix": lambda responses: responses["us-west-2"][
                "RouteTables"
            ][0]["Routes"].pop(),
            "duplicate prefix": lambda responses: responses["us-west-2"][
                "RouteTables"
            ][0]["Routes"].append(copy.deepcopy(first_west_remote(responses))),
            "intersecting supernet": lambda responses: responses["us-west-2"][
                "RouteTables"
            ][0]["Routes"].append(
                {
                    "DestinationCidrBlock": "10.20.0.0/16",
                    "NetworkInterfaceId": "eni-transport-west-a",
                    "Origin": "CreateRoute",
                    "State": "active",
                }
            ),
            "wrong VPC": lambda responses: responses["us-west-2"][
                "RouteTables"
            ][0].update({"VpcId": "vpc-east-fixture"}),
            "foreign route table": lambda responses: responses["us-west-2"][
                "RouteTables"
            ][0].update({"RouteTableId": "rtb-gwlbe-foreign"}),
            "ENI attached to wrong owner": lambda responses: responses["us-west-2"][
                "NetworkInterfaces"
            ][0]["Attachment"].update({"InstanceId": "i-transport-west-b"}),
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            deployment = symmetric_deployment_document(config)
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    responses = live_gwlbe_route_tables(config, deployment)
                    mutate(responses)
                    with self.assertRaisesRegex(
                        appliance.LifecycleError, "live (?:GWLBE route|transport ENI)"
                    ):
                        appliance.validate_live_gwlbe_routes(
                            config, RouteAWS(responses), deployment
                        )

    def test_wait_and_record_checks_live_routes_before_ready_persistence(self):
        class Store:
            remote_etag = '"fixture-etag"'

            def __init__(self, manifest):
                self.manifest = copy.deepcopy(manifest)

            def recover(self):
                return copy.deepcopy(self.manifest)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            deployment = symmetric_deployment_document(config)
            manifest = appliance.new_manifest(
                config, artifact_identity(root), "123456789012"
            )
            mark_manifest_applied(manifest)
            manifest["phase"] = "applied"
            manifest["deployment"] = copy.deepcopy(deployment)
            store = Store(manifest)
            phases = []

            def persist(target, _original, candidate, **_kwargs):
                phases.append(candidate["phase"])
                target.manifest = copy.deepcopy(candidate)
                return "written"

            ready = mock.Mock()
            with mock.patch.object(
                appliance, "ManifestStore", return_value=store
            ), mock.patch.object(
                appliance, "persist_manifest_transition", side_effect=persist
            ), mock.patch.object(
                appliance, "wait_deployment"
            ), mock.patch.object(
                appliance,
                "validate_live_gwlbe_routes",
                side_effect=appliance.LifecycleError("injected live route drift"),
            ), mock.patch.object(appliance, "record_ready_devices", ready):
                with self.assertRaisesRegex(
                    appliance.LifecycleError, "injected live route drift"
                ):
                    appliance.wait_and_record(
                        config,
                        object(),
                        object(),
                        root / "run",
                        deployment,
                        timeout_seconds=5,
                    )

        ready.assert_not_called()
        self.assertEqual(phases, ["readiness_started", "readiness_failed"])

    def test_deployment_wait_requires_complete_current_outputs(self):
        class UnusedAWS:
            def json(self, args, *, region=None):
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for output_name in (
                "transport_router_readiness_expectations",
                "route_failover",
            ):
                with self.subTest(output=output_name):
                    document = symmetric_deployment_document(config)
                    document.pop(output_name)
                    with self.assertRaisesRegex(
                        appliance.LifecycleError,
                        "complete symmetric deployment output contract",
                    ):
                        appliance.wait_deployment(
                            config,
                            UnusedAWS(),
                            document,
                            timeout_seconds=5,
                            sleep=lambda _: None,
                        )

    def test_symmetric_target_fleets_must_match_configured_azs_and_target_groups(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for name, mutate in (
                (
                    "duplicate identity",
                    lambda document: document["symmetric_topology"]["value"]["sites"]["west"]["target_fleet"][1].update(
                        {"instance_id": "i-appliance-west"}
                    ),
                ),
                (
                    "wrong AZ",
                    lambda document: document["symmetric_topology"]["value"]["sites"]["west"]["target_fleet"][1].update(
                        {"az_key": "a"}
                    ),
                ),
                (
                    "wrong target group",
                    lambda document: document["symmetric_topology"]["value"]["sites"]["west"]["target_fleet"][1].update(
                        {"target_group_arn": "arn:fixture:wrong"}
                    ),
                ),
            ):
                with self.subTest(name=name):
                    document = deployment_document()
                    mutate(document)
                    _instances, target_groups, _workloads = appliance.deployment_values(
                        document, expected_sites=config.sites
                    )
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.deployment_target_fleets(document, config, target_groups)

    def test_deployment_wait_separates_four_targets_four_transports_and_four_workloads(self):
        class FakeAWS:
            def __init__(self):
                self.online = []
                self.readiness_commands = []
                self.targets = []

            def json(inner, args, *, region=None):
                operation = args[1]
                if operation == "describe-instance-information":
                    instance_id = args[-1].rsplit("=", 1)[1]
                    inner.online.append((region, instance_id))
                    return {"InstanceInformationList": [{"PingStatus": "Online"}]}
                if operation == "send-command":
                    instance_id = args[args.index("--instance-ids") + 1]
                    payload = json.loads(args[args.index("--parameters") + 1])
                    inner.readiness_commands.append((region, instance_id, payload["commands"]))
                    return {"Command": {"CommandId": f"command-{instance_id}"}}
                if operation == "get-command-invocation":
                    return {"Status": "Success"}
                if operation == "describe-target-health":
                    inner.targets.append((region, args[-1]))
                    site = "west" if region == "us-west-2" else "east"
                    return {
                        "TargetHealthDescriptions": [
                            {
                                "Target": {"Id": f"i-target-{site}-{az_key}"},
                                "TargetHealth": {"State": "healthy"},
                            }
                            for az_key in ("a", "b")
                        ]
                    }
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = FakeAWS()
            appliance.wait_deployment(
                config,
                aws,
                symmetric_deployment_document(config),
                timeout_seconds=5,
                sleep=lambda _: None,
            )

        self.assertEqual(
            aws.online,
            [
                ("us-west-2", "i-target-west-a"),
                ("us-west-2", "i-target-west-b"),
                ("us-east-1", "i-target-east-a"),
                ("us-east-1", "i-target-east-b"),
                ("us-west-2", "i-transport-west-a"),
                ("us-west-2", "i-transport-west-b"),
                ("us-east-1", "i-transport-east-a"),
                ("us-east-1", "i-transport-east-b"),
                ("us-west-2", "i-workload-west-initiator"),
                ("us-west-2", "i-workload-west-responder"),
                ("us-east-1", "i-workload-east-initiator"),
                ("us-east-1", "i-workload-east-responder"),
            ],
        )
        self.assertEqual(
            [(region, instance_id) for region, instance_id, _commands in aws.readiness_commands],
            [
                ("us-west-2", "i-target-west-a"),
                ("us-west-2", "i-target-west-b"),
                ("us-east-1", "i-target-east-a"),
                ("us-east-1", "i-target-east-b"),
                ("us-west-2", "i-transport-west-a"),
                ("us-west-2", "i-transport-west-b"),
                ("us-east-1", "i-transport-east-a"),
                ("us-east-1", "i-transport-east-b"),
            ],
        )
        self.assertTrue(
            all(commands == appliance.READINESS_COMMANDS for _, _, commands in aws.readiness_commands[:4])
        )
        self.assertTrue(
            all("PrimaryRoutes" in "\n".join(commands) for _, _, commands in aws.readiness_commands[4:])
        )
        self.assertEqual([region for region, _ in aws.targets], ["us-west-2", "us-east-1"])

    def test_failure_collects_nested_bounded_diagnostics_for_targets_transport_and_workloads(self):
        secret = "fixture-readiness-secret"

        class FakeAWS:
            def json(self, args, *, region=None):
                if args[1] == "describe-target-health":
                    return {
                        "TargetHealthDescriptions": [
                            {
                                "Target": {"Id": "i-target"},
                                "TargetHealth": {
                                    "State": "unhealthy",
                                    "Description": f"token: {secret}",
                                },
                            }
                        ]
                    }
                raise AssertionError(args)

        collected = []

        def diagnostics(_aws, site, instance_id, *, commands=None, sleep=time.sleep):
            collected.append((site["region"], instance_id, commands))
            return {
                "command_id": f"diagnostic-{len(collected)}",
                "status": "Success",
                "stdout": "",
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            evidence = root / "diagnostics.json"
            with mock.patch.object(
                appliance,
                "wait_for_instance",
                side_effect=appliance.LifecycleError(f"auth_key={secret}"),
            ), mock.patch.object(appliance, "collect_diagnostics", side_effect=diagnostics):
                with self.assertRaises(appliance.LifecycleError) as raised:
                    appliance.wait_deployment(
                        config,
                        FakeAWS(),
                        symmetric_deployment_document(config),
                        timeout_seconds=5,
                        evidence_path=evidence,
                        sleep=lambda _: None,
                    )

            serialized = evidence.read_text()
            payload = json.loads(serialized)
            self.assertEqual(len(collected), 10)
            self.assertTrue(all(commands is None for _, _, commands in collected[:2]))
            self.assertTrue(
                all(
                    commands == appliance.TRANSPORT_DIAGNOSTIC_COMMANDS
                    for _, _, commands in collected[2:6]
                )
            )
            self.assertTrue(
                all(
                    commands == appliance.WORKLOAD_DIAGNOSTIC_COMMANDS
                    for _, _, commands in collected[6:]
                )
            )
            self.assertEqual(set(payload["transport"]), {"west", "east"})
            self.assertEqual(set(payload["transport"]["west"]), {"a", "b"})
            self.assertEqual(set(payload["workloads"]), {"west", "east"})
            self.assertEqual(set(payload["workloads"]["west"]), {"initiator", "responder"})
            self.assertEqual(payload["target_health"]["west"][0]["target_state"], "unhealthy")
            self.assertNotIn("state", payload["target_health"]["west"][0])
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, str(raised.exception))

    def test_ssm_and_target_waits_require_success_and_the_exact_healthy_fleet(self):
        class FakeAWS:
            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "describe-instance-information":
                    return {"InstanceInformationList": [{"PingStatus": "Online"}]}
                if operation == "send-command":
                    return {"Command": {"CommandId": "command-fixture"}}
                if operation == "get-command-invocation":
                    return {"Status": "Success"}
                if operation == "describe-target-health":
                    return {
                        "TargetHealthDescriptions": [
                            {"Target": {"Id": target_id}, "TargetHealth": {"State": "healthy"}}
                            for target_id in ("i-fixture-a", "i-fixture-b")
                        ]
                    }
                raise AssertionError(args)

        aws = FakeAWS()
        deadline = time.monotonic() + 1
        appliance.wait_for_instance(aws, region="us-west-2", instance_id="i-fixture", deadline=deadline, sleep=lambda _: None)
        appliance.wait_for_target(
            aws,
            region="us-west-2",
            target_group_arn="arn:fixture",
            expected_target_ids=("i-fixture-a", "i-fixture-b"),
            deadline=deadline,
            sleep=lambda _: None,
        )
        commands = "\n".join(appliance.READINESS_COMMANDS)
        self.assertIn("600s cloud-init status --wait", commands)
        self.assertIn("envelope-preflight", commands)
        self.assertIn("signal=KILL 120s", commands)
        self.assertIn("sleep 2", commands)
        self.assertIn("curl --fail --silent --show-error", commands)
        self.assertIn("systemctl is-active envelope.service", commands)
        self.assertNotIn("tailscale", commands.lower())
        self.assertNotIn("host-network", commands)
        subprocess.run(["bash", "-n"], input=commands, text=True, capture_output=True, check=True)
        inner = appliance.READINESS_COMMANDS[2].split("'ENVELOPE_READINESS'\n", 1)[1].split(
            "\nENVELOPE_READINESS\n", 1
        )[0]
        subprocess.run(["bash", "-n"], input=inner, text=True, capture_output=True, check=True)
        self.assertNotIn("get-parameter", commands)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            transport_commands = appliance.transport_readiness_commands(config, "west", "a")
        transport = "\n".join(transport_commands)
        self.assertIn("tailscaled.service", transport)
        self.assertIn("envelope-transport-router-network.service", transport)
        self.assertNotIn("envelope-ingress-router-network.service", transport)
        self.assertIn("PrimaryRoutes", transport)
        self.assertIn("tailscale debug prefs", transport)
        self.assertIn("10.20.1.0/24", transport)
        self.assertIn("10.20.2.0/24", transport)
        self.assertIn("10.10.1.0/24", transport)
        self.assertIn("10.10.2.0/24", transport)
        self.assertIn("envelope-fixture-west-transport-a", transport)
        self.assertNotIn("envelope-fixture-west-transport-b", transport)
        self.assertIn("envelope-fixture-east-transport-a", transport)
        self.assertIn("envelope-fixture-east-transport-b", transport)
        self.assertNotIn("expected_local_owners", transport)
        self.assertNotIn("-ingress-", transport)
        self.assertNotIn("envelope.service", transport)
        self.assertNotIn("get-parameter", transport)
        self.assertIn("signal=KILL 700s", transport)
        self.assertIn("600s cloud-init status --wait", transport)
        subprocess.run(["bash", "-n"], input=transport, text=True, capture_output=True, check=True)
        transport_inner = transport_commands[-1].split("'TRANSPORT_READINESS'\n", 1)[1].split(
            "\nTRANSPORT_READINESS\n", 1
        )[0]
        subprocess.run(["bash", "-n"], input=transport_inner, text=True, capture_output=True, check=True)

    @unittest.skipUnless(shutil.which("jq"), "jq is required for embedded readiness-filter coverage")
    def test_transport_readiness_requires_remote_owners_and_rejects_local_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            command = appliance.transport_readiness_commands(config, "west", "a")[-1]
        match = re.search(r"/usr/bin/jq .*? '\n(.*?)\n    ' <<<", command, re.DOTALL)
        self.assertIsNotNone(match)
        jq_filter = match.group(1)
        expected_self = "envelope-fixture-west-transport-a"
        expected_local = ["10.10.1.0/24", "10.10.2.0/24"]
        expected_remote = ["10.20.1.0/24", "10.20.2.0/24"]
        expected_self_prefix = expected_local[0]
        expected_remote_owners = {
            expected_remote[0]: "envelope-fixture-east-transport-a",
            expected_remote[1]: "envelope-fixture-east-transport-b",
        }
        prefs = {
            "RouteAll": True,
            "NoSNAT": True,
            "AdvertiseRoutes": [expected_self_prefix],
        }

        def accepted(status, observed_prefs=None):
            completed = subprocess.run(
                [
                    shutil.which("jq"),
                    "-e",
                    "--arg",
                    "expected_self",
                    expected_self,
                    "--arg",
                    "expected_self_prefix",
                    expected_self_prefix,
                    "--argjson",
                    "expected_local",
                    json.dumps(expected_local),
                    "--argjson",
                    "expected_remote",
                    json.dumps(expected_remote),
                    "--argjson",
                    "expected_remote_owners",
                    json.dumps(expected_remote_owners),
                    "--argjson",
                    "prefs",
                    json.dumps(prefs if observed_prefs is None else observed_prefs),
                    jq_filter,
                ],
                input=json.dumps(status),
                text=True,
                capture_output=True,
                check=False,
            )
            return completed.returncode == 0

        status = {
            "BackendState": "Running",
            "Self": {"Online": True, "HostName": expected_self},
            "Peer": {
                "east-a": {
                    "Online": True,
                    "HostName": expected_remote_owners[expected_remote[0]],
                    "PrimaryRoutes": [expected_remote[0]],
                },
                "east-b": {
                    "Online": True,
                    "HostName": expected_remote_owners[expected_remote[1]],
                    "PrimaryRoutes": [expected_remote[1]],
                },
                "west-b": {
                    "Online": True,
                    "HostName": "envelope-fixture-west-transport-b",
                    "PrimaryRoutes": [],
                },
            },
        }
        self.assertTrue(accepted(status))
        unrelated = copy.deepcopy(status)
        unrelated["Peer"]["east-a"]["PrimaryRoutes"].append("10.99.0.0/24")
        self.assertTrue(accepted(unrelated))
        selected_sibling = copy.deepcopy(status)
        selected_sibling["Peer"]["west-b"]["PrimaryRoutes"] = [expected_local[1]]
        self.assertFalse(accepted(selected_sibling))

        for advertised_routes in (
            [],
            [expected_self_prefix, expected_self_prefix],
            [expected_self_prefix, expected_local[1]],
        ):
            invalid_prefs = {**prefs, "AdvertiseRoutes": advertised_routes}
            with self.subTest(advertised_routes=advertised_routes):
                self.assertFalse(accepted(status, invalid_prefs))

        for mutation in (
            "missing",
            "duplicate",
            "offline",
            "wrong-site",
            "swapped-owner",
            "local-sibling",
            "local-self",
        ):
            invalid = copy.deepcopy(status)
            if mutation == "missing":
                invalid["Peer"]["east-b"]["PrimaryRoutes"] = []
            elif mutation == "duplicate":
                invalid["Peer"]["east-b"]["PrimaryRoutes"].append(expected_remote[0])
            elif mutation == "offline":
                invalid["Peer"]["east-a"]["Online"] = False
            elif mutation == "wrong-site":
                invalid["Peer"]["east-a"]["HostName"] = (
                    "envelope-fixture-west-transport-b"
                )
            elif mutation == "swapped-owner":
                east_a = invalid["Peer"]["east-a"]
                east_b = invalid["Peer"]["east-b"]
                east_a["HostName"], east_b["HostName"] = (
                    east_b["HostName"],
                    east_a["HostName"],
                )
            elif mutation == "local-sibling":
                invalid["Peer"]["west-b"]["PrimaryRoutes"] = [expected_local[1]]
            elif mutation == "local-self":
                invalid["Peer"]["west-a"] = {
                    "Online": True,
                    "HostName": expected_self,
                    "PrimaryRoutes": [expected_local[0]],
                }
            with self.subTest(mutation=mutation):
                self.assertFalse(accepted(invalid))

    def test_readiness_payload_has_remote_execution_timeout_and_cancels_on_local_deadline(self):
        class FakeAWS:
            def __init__(self):
                self.payload = None
                self.cancelled = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "describe-instance-information":
                    return {"InstanceInformationList": [{"PingStatus": "Online"}]}
                if operation == "send-command":
                    self.payload = json.loads(args[args.index("--parameters") + 1])
                    return {"Command": {"CommandId": "command-fixture"}}
                if operation == "get-command-invocation":
                    return {"Status": "Cancelled" if self.cancelled else "InProgress"}
                if operation == "cancel-command":
                    self.cancelled.append(args[args.index("--command-id") + 1])
                    return {}
                raise AssertionError(args)

        aws = FakeAWS()
        with mock.patch.object(appliance.time, "monotonic", side_effect=[0, 0, 2, 2, 2]):
            with self.assertRaisesRegex(appliance.LifecycleError, "timed out"):
                appliance.wait_for_instance(
                    aws, region="us-west-2", instance_id="i-fixture", deadline=1, sleep=lambda _: None
                )
        self.assertEqual(aws.payload["executionTimeout"], ["750"])
        self.assertEqual(aws.payload["commands"], appliance.READINESS_COMMANDS)
        self.assertEqual(aws.cancelled, ["command-fixture"])

    def test_readiness_retries_eventually_consistent_ssm_invocation(self):
        class FakeAWS:
            def __init__(self):
                self.invocations = 0

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "describe-instance-information":
                    return {"InstanceInformationList": [{"PingStatus": "Online"}]}
                if operation == "send-command":
                    return {"Command": {"CommandId": "command-fixture"}}
                if operation == "get-command-invocation":
                    self.invocations += 1
                    if self.invocations == 1:
                        raise appliance.CommandError(args, 255, "InvocationDoesNotExist")
                    return {"Status": "Success"}
                raise AssertionError(args)

        aws = FakeAWS()
        appliance.wait_for_instance(
            aws,
            region="us-west-2",
            instance_id="i-fixture",
            deadline=time.monotonic() + 1,
            sleep=lambda _: None,
        )
        self.assertEqual(aws.invocations, 2)

    def test_diagnostics_are_bounded_and_redacted(self):
        class FakeAWS:
            def __init__(self):
                self.payload = None

            def json(self, args, *, region=None):
                if args[1] == "send-command":
                    self.payload = json.loads(args[args.index("--parameters") + 1])
                    return {"Command": {"CommandId": "diagnostic-fixture"}}
                return {
                    "Status": "Success",
                    "StandardOutputContent": "auth_key=fixture-sensitive-value",
                    "StandardErrorContent": "",
                }

        aws = FakeAWS()
        result = appliance.collect_diagnostics(aws, {"region": "us-west-2"}, "i-fixture", sleep=lambda _: None)
        self.assertEqual(result["status"], "Success")
        self.assertEqual(aws.payload["executionTimeout"], ["90"])
        self.assertNotIn("fixture-sensitive-value", result["stdout"])
        self.assertIn("[REDACTED]", result["stdout"])

    def test_workload_diagnostics_cancel_and_confirm_stop_after_local_timeout(self):
        class FakeAWS:
            def __init__(self):
                self.payload = None
                self.cancelled = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "send-command":
                    self.payload = json.loads(args[args.index("--parameters") + 1])
                    return {"Command": {"CommandId": "diagnostic-workload"}}
                if operation == "cancel-command":
                    self.cancelled.append(args[args.index("--command-id") + 1])
                    return {}
                if operation == "get-command-invocation":
                    return {"Status": "Cancelled"}
                raise AssertionError(args)

        aws = FakeAWS()
        with mock.patch.object(appliance.time, "monotonic", side_effect=[0, 121, 121, 121]):
            result = appliance.collect_diagnostics(
                aws,
                {"region": "us-west-2"},
                "i-workload-west-initiator",
                commands=appliance.WORKLOAD_DIAGNOSTIC_COMMANDS,
                sleep=lambda _: None,
            )

        self.assertEqual(aws.payload["commands"], appliance.WORKLOAD_DIAGNOSTIC_COMMANDS)
        self.assertEqual(aws.payload["executionTimeout"], ["90"])
        self.assertEqual(aws.cancelled, ["diagnostic-workload"])
        self.assertEqual(result["status"], "TimedOut")
        self.assertIn("stopped with Cancelled", result["stderr"])


if __name__ == "__main__":
    unittest.main()
