#!/usr/bin/env python3
"""Fail closed when a saved Terraform plan diverges from the acceptance shape."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import json
import math
import pathlib
import re
import sys
from typing import Any


KEY_PATTERN = re.compile("tskey-" + r"(?:auth|client|api)-[A-Za-z0-9_-]{8,}", re.IGNORECASE)
EC2_USER_DATA_RAW_LIMIT_BYTES = 16 * 1024
EC2_USER_DATA_BASE64_LIMIT_BYTES = 4 * ((EC2_USER_DATA_RAW_LIMIT_BYTES + 2) // 3)
SITES = ("west", "east")
WORKLOAD_ROLES = ("initiator", "responder")
WORKLOAD_ADDRESS_PATTERN = re.compile(r'aws_instance\.workload_(?:west|east)\["(?:initiator|responder)"\]')
WORKLOAD_OUTPUT_FIELDS = {
    "instance_id",
    "private_ip",
    "az_key",
    "availability_zone",
    "subnet_id",
    "cidr",
    "route_table_id",
}
ROUTE_TARGET_FIELDS = {
    "carrier_gateway_id",
    "core_network_arn",
    "egress_only_gateway_id",
    "gateway_id",
    "local_gateway_id",
    "nat_gateway_id",
    "network_interface_id",
    "transit_gateway_id",
    "vpc_endpoint_id",
    "vpc_peering_connection_id",
}
FLOW_LOG_FIELDS = (
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
    "vpc-id",
    "subnet-id",
    "instance-id",
    "region",
    "az-id",
    "flow-direction",
    "traffic-path",
    "pkt-srcaddr",
    "pkt-dstaddr",
)
FLOW_LOG_FORMAT = " ".join(f"${{{field}}}" for field in FLOW_LOG_FIELDS)
E2E_LOAD_PROFILE_FIELDS = {
    "profile_id",
    "approved_at",
    "safe_inner_mtu",
    "maximum_tcp_mss",
    "sustained_tcp_duration_seconds",
    "minimum_sustained_tcp_bytes",
    "iperf_duration_seconds",
    "minimum_throughput_mbps",
    "concurrent_duration_seconds",
    "concurrent_tcp_flows",
    "concurrent_udp_flows",
    "maximum_udp_loss_percent",
    "maximum_p99_latency_ms",
}
E2E_LOAD_PROFILE_INTEGER_BOUNDS = {
    "safe_inner_mtu": (576, 1500),
    "maximum_tcp_mss": (536, 1460),
    "sustained_tcp_duration_seconds": (3, 120),
    "minimum_sustained_tcp_bytes": (1, 1_000_000_000),
    "iperf_duration_seconds": (3, 120),
    "concurrent_duration_seconds": (3, 120),
    "concurrent_tcp_flows": (1, 32),
    "concurrent_udp_flows": (1, 32),
}
E2E_LOAD_PROFILE_NUMBER_BOUNDS = {
    "minimum_throughput_mbps": (0.001, 100_000.0),
    "maximum_udp_loss_percent": (0.0, 100.0),
    "maximum_p99_latency_ms": (0.001, 60_000.0),
}
APPROVED_DATA_RESOURCES = {
    "data.aws_caller_identity.current": "aws_caller_identity",
    "data.aws_iam_policy_document.artifact_bucket": "aws_iam_policy_document",
    "data.aws_ami.west": "aws_ami",
    "data.aws_ami.east": "aws_ami",
    "data.aws_ec2_instance_type.west_appliance": "aws_ec2_instance_type",
    "data.aws_ec2_instance_type.east_appliance": "aws_ec2_instance_type",
    "data.aws_ec2_instance_type.west_test": "aws_ec2_instance_type",
    "data.aws_ec2_instance_type.east_test": "aws_ec2_instance_type",
    "module.tailscale_client_west.data.cloudinit_config.main": "cloudinit_config",
    "module.tailscale_client_east.data.cloudinit_config.main": "cloudinit_config",
}


def resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    result = [value for value in module.get("resources", []) if isinstance(value, dict)]
    for child in module.get("child_modules", []):
        if isinstance(child, dict):
            result.extend(resources(child))
    return result


def configured_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    result = [value for value in module.get("resources", []) if isinstance(value, dict)]
    for call in module.get("module_calls", {}).values():
        child = call.get("module") if isinstance(call, dict) else None
        if isinstance(child, dict):
            result.extend(configured_resources(child))
    return result


def output_value(plan: dict[str, Any], name: str) -> Any:
    value = plan.get("planned_values", {}).get("outputs", {}).get(name)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return None


def indexed_address(prefix: str, key: str) -> str:
    return f"{prefix}[{json.dumps(key, separators=(',', ':'))}]"


def approved_managed_resources(
    az_keys: dict[str, set[str]], initiator_az_keys: dict[str, str]
) -> dict[str, str]:
    result = {"terraform_data.input_validation": "terraform_data"}
    per_site = (
        ("aws_vpc", "aws_vpc.{site}"),
        ("aws_internet_gateway", "aws_internet_gateway.{site}"),
        ("aws_subnet", "aws_subnet.public_{site}"),
        ("aws_subnet", "aws_subnet.appliance_{site}"),
        ("aws_eip", "aws_eip.nat_{site}"),
        ("aws_nat_gateway", "aws_nat_gateway.{site}"),
        ("aws_route_table", "aws_route_table.public_{site}"),
        ("aws_route_table", "aws_route_table.appliance_{site}"),
        ("aws_route", "aws_route.public_default_{site}"),
        ("aws_route", "aws_route.appliance_default_{site}"),
        ("aws_route_table_association", "aws_route_table_association.public_{site}"),
        ("aws_route_table_association", "aws_route_table_association.appliance_{site}"),
        ("aws_lb", "aws_lb.{site}"),
        ("aws_lb_target_group", "aws_lb_target_group.{site}"),
        ("aws_lb_listener", "aws_lb_listener.{site}"),
        ("aws_lb_target_group_attachment", "aws_lb_target_group_attachment.{site}"),
        ("aws_vpc_endpoint_service", "aws_vpc_endpoint_service.{site}"),
        ("aws_security_group", "aws_security_group.envelope_{site}"),
        ("aws_instance", "aws_instance.envelope_{site}"),
        ("aws_network_acl", "aws_network_acl.appliance_{site}"),
        ("aws_cloudwatch_log_group", "aws_cloudwatch_log_group.flow_{site}"),
        ("aws_flow_log", "aws_flow_log.{site}"),
        ("aws_iam_role", "aws_iam_role.appliance_{site}"),
        ("aws_iam_role", "aws_iam_role.workload_{site}"),
        ("aws_iam_instance_profile", "aws_iam_instance_profile.appliance_{site}"),
        ("aws_iam_instance_profile", "aws_iam_instance_profile.workload_{site}"),
        ("aws_iam_role_policy", "aws_iam_role_policy.appliance_runtime_{site}"),
        ("aws_iam_role_policy", "aws_iam_role_policy.workload_runtime_{site}"),
    )
    indexed_per_az = (
        ("aws_subnet", "aws_subnet.workload_{site}"),
        ("aws_subnet", "aws_subnet.gwlbe_{site}"),
        ("aws_subnet", "aws_subnet.gwlb_{site}"),
        ("aws_route_table", "aws_route_table.workload_{site}"),
        ("aws_route_table", "aws_route_table.gwlbe_{site}"),
        ("aws_route_table", "aws_route_table.gwlb_{site}"),
        ("aws_route_table_association", "aws_route_table_association.workload_{site}"),
        ("aws_route_table_association", "aws_route_table_association.gwlbe_{site}"),
        ("aws_route_table_association", "aws_route_table_association.gwlb_{site}"),
        ("aws_route", "aws_route.workload_default_{site}"),
    )
    for site in SITES:
        for resource_type, address in per_site:
            result[address.format(site=site)] = resource_type
        for az_key in az_keys[site]:
            for resource_type, prefix in indexed_per_az:
                result[indexed_address(prefix.format(site=site), az_key)] = resource_type
        for role in WORKLOAD_ROLES:
            result[indexed_address(f"aws_security_group.workload_{site}", role)] = "aws_security_group"
            result[indexed_address(f"aws_instance.workload_{site}", role)] = "aws_instance"
        if initiator_az_keys.get(site) in az_keys[site]:
            result[indexed_address(f"aws_vpc_endpoint.{site}", initiator_az_keys[site])] = "aws_vpc_endpoint"
        result[f"aws_route.initiator_to_responder_{site}"] = "aws_route"
        result[f"aws_route.responder_return_{site}"] = "aws_route"
    result.update(
        {
            "aws_s3_bucket.artifact": "aws_s3_bucket",
            "aws_s3_bucket_public_access_block.artifact": "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_ownership_controls.artifact": "aws_s3_bucket_ownership_controls",
            "aws_s3_bucket_versioning.artifact": "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration.artifact": "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_policy.artifact": "aws_s3_bucket_policy",
            "aws_s3_object.envelope": "aws_s3_object",
            "aws_iam_role.flow_logs": "aws_iam_role",
            "aws_iam_role_policy.flow_logs": "aws_iam_role_policy",
        }
    )
    return result


def validate(
    plan: dict[str, Any],
    run_name: str,
    allowed_replacements: set[str] | None = None,
    expected_az_keys: dict[str, set[str]] | None = None,
    expected_initiator_az_keys: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    allowed_replacements = allowed_replacements or set()
    root = plan.get("planned_values", {}).get("root_module", {})
    values = resources(root) if isinstance(root, dict) else []
    runtime = output_value(plan, "envelope_runtime_config")
    normalized_az_keys: dict[str, set[str]] = {"west": set(), "east": set()}
    if (
        not isinstance(expected_az_keys, dict)
        or set(expected_az_keys) != {"west", "east"}
        or any(
            not isinstance(expected_az_keys[site], (set, list, tuple))
            or len(expected_az_keys[site]) != 2
            or not all(isinstance(key, str) and key for key in expected_az_keys[site])
            or len(set(expected_az_keys[site])) != 2
            for site in SITES
        )
    ):
        errors.append("exactly two west/east AZ keys are required for protected address validation")
    else:
        normalized_az_keys = {site: set(expected_az_keys[site]) for site in SITES}
    runtime_valid = (
        isinstance(runtime, dict)
        and set(runtime) == {"west", "east"}
        and all(
            isinstance(runtime[site], dict)
            and isinstance(runtime[site].get("gwlb_return_cidrs"), list)
            and len(runtime[site]["gwlb_return_cidrs"]) == 1
            and all(isinstance(cidr, str) and cidr for cidr in runtime[site]["gwlb_return_cidrs"])
            and isinstance(runtime[site].get("local_delivery_cidrs"), list)
            and len(runtime[site]["local_delivery_cidrs"]) == 1
            and all(isinstance(cidr, str) and cidr for cidr in runtime[site]["local_delivery_cidrs"])
            and isinstance(runtime[site].get("remote_tailnet_cidrs"), list)
            and all(isinstance(cidr, str) and cidr for cidr in runtime[site]["remote_tailnet_cidrs"])
            for site in SITES
        )
    )
    initiator_az_keys: dict[str, str] = {}
    if (
        not isinstance(expected_initiator_az_keys, dict)
        or set(expected_initiator_az_keys) != set(SITES)
        or any(
            not isinstance(expected_initiator_az_keys[site], str)
            or expected_initiator_az_keys[site] not in normalized_az_keys[site]
            for site in SITES
        )
    ):
        errors.append("exact reviewed west/east initiator AZ keys are required for protected address validation")
    else:
        initiator_az_keys = dict(expected_initiator_az_keys)
    expected_resources = (
        approved_managed_resources(normalized_az_keys, initiator_az_keys)
        if all(normalized_az_keys.values())
        else {}
    )
    actual_resources: dict[str, str] = {}
    for resource in values:
        address = resource.get("address")
        resource_type = resource.get("type")
        mode = resource.get("mode", "managed")
        if not isinstance(address, str) or not address or not isinstance(resource_type, str) or not resource_type:
            errors.append("planned resource has no exact address/type identity")
            continue
        if address in actual_resources:
            errors.append(f"planned resource address is duplicated: {address}")
            continue
        actual_resources[address] = resource_type
        expected_type = APPROVED_DATA_RESOURCES.get(address) if mode == "data" else expected_resources.get(address)
        if expected_type is None:
            errors.append(f"planned resource address is outside the approved set: {address}")
        elif resource_type != expected_type:
            errors.append(f"planned resource type for {address} is {resource_type}, expected {expected_type}")
    for address in sorted(set(expected_resources) - set(actual_resources)):
        errors.append(f"approved planned resource is missing: {address}")

    replacement_dependencies = {
        "aws_instance.envelope_west": "aws_lb_target_group_attachment.west",
        "aws_instance.envelope_east": "aws_lb_target_group_attachment.east",
    }
    dependency_owners = {dependency: instance for instance, dependency in replacement_dependencies.items()}
    replacement_routes = {
        "aws_instance.envelope_west": "aws_route.responder_return_west",
        "aws_instance.envelope_east": "aws_route.responder_return_east",
    }
    replacement_route_owners = {route: instance for instance, route in replacement_routes.items()}
    approved_replacements = set(replacement_dependencies)
    if not allowed_replacements.issubset(approved_replacements):
        errors.append("replacement allowlist contains an address other than an exact regional Envelope instance")
    changes = plan.get("resource_changes")
    seen_replacements: set[str] = set()
    seen_replacement_dependencies: set[str] = set()
    if not isinstance(changes, list):
        errors.append("resource_changes must be a list")
        changes = []
    replacement_instance_ids: dict[str, str] = {}
    replacement_instance_enis: dict[str, str] = {}
    for change in changes:
        if not isinstance(change, dict) or change.get("address") not in allowed_replacements:
            continue
        change_body = change.get("change")
        before = change_body.get("before") if isinstance(change_body, dict) else None
        instance_id = before.get("id") if isinstance(before, dict) else None
        if isinstance(instance_id, str) and instance_id:
            replacement_instance_ids[str(change["address"])] = instance_id
        primary_eni = before.get("primary_network_interface_id") if isinstance(before, dict) else None
        if isinstance(primary_eni, str) and primary_eni:
            replacement_instance_enis[str(change["address"])] = primary_eni
    configured_root = plan.get("configuration", {}).get("root_module", {})
    configured = configured_resources(configured_root) if isinstance(configured_root, dict) else []
    configured_by_address = {
        str(resource.get("address")): resource
        for resource in configured
        if isinstance(resource.get("address"), str)
    }
    planned_by_address = {
        str(resource.get("address")): resource
        for resource in values
        if isinstance(resource.get("address"), str)
    }
    semantic_route_references: dict[str, dict[str, set[str]]] = {}
    for site, other in (("west", "east"), ("east", "west")):
        semantic_route_references[f"aws_route.initiator_to_responder_{site}"] = {
            "route_table_id": {f"aws_route_table.workload_{site}", f"local.{site}_initiator_az_key"},
            "destination_cidr_block": {f"local.{other}_responder_cidr"},
            "vpc_endpoint_id": {f"aws_vpc_endpoint.{site}", f"local.{site}_initiator_az_key"},
        }
        semantic_route_references[f"aws_route.responder_return_{site}"] = {
            "route_table_id": {f"aws_route_table.workload_{site}", f"local.{site}_responder_az_key"},
            "destination_cidr_block": {f"local.{other}_initiator_cidr"},
            "network_interface_id": {
                f"aws_instance.envelope_{site}.primary_network_interface_id",
                f"aws_instance.envelope_{site}",
            },
        }

    def exact_configuration_references(
        address: str, resource_type: str, expected: dict[str, set[str]]
    ) -> bool:
        configuration = configured_by_address.get(address)
        expressions = configuration.get("expressions") if isinstance(configuration, dict) else None
        if (
            not isinstance(expressions, dict)
            or set(expressions) != set(expected)
            or configuration.get("mode", "managed") != "managed"
            or configuration.get("type") != resource_type
        ):
            return False
        for attribute, wanted in expected.items():
            expression = expressions.get(attribute)
            references = expression.get("references") if isinstance(expression, dict) else None
            if not isinstance(references, list) or len(references) != len(wanted) or set(references) != wanted:
                return False
        return True

    def required_configuration_references(
        address: str, resource_type: str, expected: dict[str, set[str]]
    ) -> bool:
        configuration = configured_by_address.get(address)
        expressions = configuration.get("expressions") if isinstance(configuration, dict) else None
        if (
            not isinstance(expressions, dict)
            or configuration.get("mode", "managed") != "managed"
            or configuration.get("type") != resource_type
        ):
            return False
        for attribute, wanted in expected.items():
            expression = expressions.get(attribute)
            references = expression.get("references") if isinstance(expression, dict) else None
            if not isinstance(references, list) or len(references) != len(wanted) or set(references) != wanted:
                return False
        return True

    profile_entry = plan.get("planned_values", {}).get("outputs", {}).get("e2e_load_profile")
    profile = profile_entry.get("value") if isinstance(profile_entry, dict) else None
    variable_entry = plan.get("variables", {}).get("e2e_load_profile")
    variable_profile = variable_entry.get("value") if isinstance(variable_entry, dict) else None
    configured_outputs = configured_root.get("outputs") if isinstance(configured_root, dict) else None
    configured_profile = configured_outputs.get("e2e_load_profile") if isinstance(configured_outputs, dict) else None
    configured_expression = configured_profile.get("expression") if isinstance(configured_profile, dict) else None
    configured_references = (
        configured_expression.get("references") if isinstance(configured_expression, dict) else None
    )
    profile_change = plan.get("output_changes", {}).get("e2e_load_profile")
    profile_change_body = profile_change if isinstance(profile_change, dict) else None

    def has_true_marker(value: Any) -> bool:
        if value is True:
            return True
        if isinstance(value, dict):
            return any(has_true_marker(child) for child in value.values())
        if isinstance(value, list):
            return any(has_true_marker(child) for child in value)
        return False

    def validated_computed_output(
        name: str,
        expected_references: list[str],
        expected_unknown: dict[str, Any],
    ) -> Any:
        outputs = plan.get("planned_values", {}).get("outputs", {})
        entry = outputs.get(name) if isinstance(outputs, dict) else None
        configured_output = configured_outputs.get(name) if isinstance(configured_outputs, dict) else None
        configured_output_expression = (
            configured_output.get("expression") if isinstance(configured_output, dict) else None
        )
        references = (
            configured_output_expression.get("references")
            if isinstance(configured_output_expression, dict)
            else None
        )
        change = plan.get("output_changes", {}).get(name)
        actions = change.get("actions") if isinstance(change, dict) else None
        base_change_valid = (
            isinstance(change, dict)
            and set(change)
            == {
                "actions",
                "before",
                "after",
                "after_unknown",
                "before_sensitive",
                "after_sensitive",
            }
            and actions in (["create"], ["no-op"])
            and change.get("before_sensitive") is False
            and change.get("after_sensitive") is False
            and isinstance(configured_output, dict)
            and set(configured_output) == {"expression"}
            and isinstance(configured_output_expression, dict)
            and set(configured_output_expression) == {"references"}
            and references == expected_references
        )
        if not isinstance(entry, dict) or entry.get("sensitive") is not False:
            errors.append(f"{name} output must be explicitly non-sensitive")
            return None
        if "value" in entry:
            value = entry["value"]
            if (
                not {"sensitive", "value"}.issubset(entry)
                or not set(entry).issubset({"sensitive", "type", "value"})
                or not base_change_valid
                or change.get("after") != value
                or change.get("after_unknown") is not False
                or actions == ["create"] and change.get("before") is not None
                or actions == ["no-op"] and change.get("before") != value
            ):
                errors.append(f"{name} known output change does not match its configured planned value")
            return value

        partial = change.get("after") if isinstance(change, dict) else None
        partial_valid = isinstance(partial, dict) and set(partial) == set(SITES)
        if partial_valid and name == "workload_instances":
            partial_valid = all(
                isinstance(partial[site], dict)
                and set(partial[site]) == set(WORKLOAD_ROLES)
                and all(
                    isinstance(partial[site][role], dict)
                    and set(partial[site][role]) == {"availability_zone", "az_key", "cidr"}
                    for role in WORKLOAD_ROLES
                )
                for site in SITES
            )
        elif partial_valid and name == "flow_log_evidence":
            partial_valid = all(
                isinstance(partial[site], dict) and set(partial[site]) == {"region"}
                for site in SITES
            )
        if (
            set(entry) != {"sensitive"}
            or not base_change_valid
            or actions != ["create"]
            or change.get("before") is not None
            or change.get("after_unknown") != expected_unknown
            or not partial_valid
        ):
            errors.append(f"{name} unknown output does not have the exact protected plan-time shape")
        return partial

    workload_output = validated_computed_output(
        "workload_instances",
        [
            "local.west_workloads",
            "aws_instance.workload_west",
            "aws_instance.workload_west",
            "var.west_azs",
            "aws_subnet.workload_west",
            "aws_route_table.workload_west",
            "local.east_workloads",
            "aws_instance.workload_east",
            "aws_instance.workload_east",
            "var.east_azs",
            "aws_subnet.workload_east",
            "aws_route_table.workload_east",
        ],
        {
            site: {
                role: {
                    "instance_id": True,
                    "private_ip": True,
                    "route_table_id": True,
                    "subnet_id": True,
                }
                for role in WORKLOAD_ROLES
            }
            for site in SITES
        },
    )
    flow_log_evidence = validated_computed_output(
        "flow_log_evidence",
        [
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
        {
            site: {"flow_log_id": True, "log_group_arn": True}
            for site in SITES
        },
    )

    profile_valid = isinstance(profile, dict) and set(profile) == E2E_LOAD_PROFILE_FIELDS
    if profile_valid:
        profile_id = profile.get("profile_id")
        approved_at = profile.get("approved_at")
        profile_valid = (
            isinstance(profile_id, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", profile_id) is not None
            and isinstance(approved_at, str)
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", approved_at)
            is not None
        )
        for name, (minimum, maximum) in E2E_LOAD_PROFILE_INTEGER_BOUNDS.items():
            candidate = profile.get(name)
            profile_valid = profile_valid and (
                not isinstance(candidate, bool)
                and isinstance(candidate, int)
                and minimum <= candidate <= maximum
            )
        for name, (minimum, maximum) in E2E_LOAD_PROFILE_NUMBER_BOUNDS.items():
            candidate = profile.get(name)
            profile_valid = profile_valid and (
                not isinstance(candidate, bool)
                and isinstance(candidate, (int, float))
                and minimum <= candidate <= maximum
                and math.isfinite(float(candidate))
            )
        profile_valid = profile_valid and profile.get("safe_inner_mtu") == 1280
        maximum_mss = profile.get("maximum_tcp_mss")
        profile_valid = profile_valid and isinstance(maximum_mss, int) and maximum_mss <= 1240
        try:
            approved_time = dt.datetime.fromisoformat(str(approved_at).removesuffix("Z") + "+00:00")
            plan_time = dt.datetime.fromisoformat(str(plan.get("timestamp", "")).replace("Z", "+00:00"))
        except ValueError:
            profile_valid = False
        else:
            profile_valid = (
                profile_valid
                and approved_time.tzinfo == dt.timezone.utc
                and plan_time.tzinfo == dt.timezone.utc
                and approved_time <= plan_time
            )
    change_actions = (
        tuple(profile_change_body.get("actions", [])) if isinstance(profile_change_body, dict) else ()
    )
    if (
        not profile_valid
        or not isinstance(profile_entry, dict)
        or profile_entry.get("sensitive") is not False
        or variable_profile != profile
        or configured_references != ["var.e2e_load_profile"]
        or not isinstance(profile_change_body, dict)
        or change_actions not in {("create",), ("no-op",)}
        or change_actions == ("create",) and profile_change_body.get("before") is not None
        or change_actions == ("no-op",) and profile_change_body.get("before") != profile
        or profile_change_body.get("after") != profile
        or "after_unknown" not in profile_change_body
        or has_true_marker(profile_change_body.get("after_unknown"))
        or "after_sensitive" not in profile_change_body
        or has_true_marker(profile_change_body.get("after_sensitive"))
    ):
        errors.append(
            "e2e_load_profile is not an exact known non-sensitive pre-plan variable/output contract"
        )

    seen_change_addresses: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            errors.append("resource_changes contains a non-object entry")
            continue
        address = change.get("address")
        if isinstance(address, str):
            if address in seen_change_addresses:
                errors.append(f"resource-change address is duplicated: {address}")
                continue
            seen_change_addresses.add(address)
        resource_type = change.get("type")
        mode = change.get("mode", "managed")
        expected_type = APPROVED_DATA_RESOURCES.get(address) if mode == "data" else expected_resources.get(address)
        if not isinstance(address, str) or expected_type is None:
            errors.append(f"resource-change address is outside the approved set: {address}")
        if not isinstance(resource_type, str) or resource_type != expected_type:
            errors.append(f"resource-change type for {address} is not the approved type")
        change_body = change.get("change")
        actions = change_body.get("actions") if isinstance(change_body, dict) else None
        action_tuple = tuple(actions) if isinstance(actions, list) and all(isinstance(action, str) for action in actions) else ()
        if action_tuple == ("no-op",):
            continue
        if action_tuple == ("create",) and mode != "data":
            if not allowed_replacements:
                continue
            errors.append(f"replacement plan contains an unrelated managed create on {address}")
            continue
        if action_tuple == ("read",) and mode == "data":
            continue
        if address in allowed_replacements and action_tuple == ("delete", "create"):
            if change.get("action_reason") != "replace_by_request" or address not in replacement_instance_ids:
                errors.append(f"requested replacement identity is incomplete for {address}")
            else:
                seen_replacements.add(address)
            continue
        dependency_owner = dependency_owners.get(address)
        if dependency_owner in allowed_replacements and action_tuple == ("delete", "create"):
            before = change_body.get("before") if isinstance(change_body, dict) else None
            after = change_body.get("after") if isinstance(change_body, dict) else None
            site = dependency_owner.rsplit("_", 1)[-1]
            target_group_address = f"aws_lb_target_group.{site}"
            target_group = planned_by_address.get(target_group_address, {})
            target_group_values = target_group.get("values") if isinstance(target_group, dict) else None
            target_group_arn = target_group_values.get("arn") if isinstance(target_group_values, dict) else None
            target_group_region = target_group_values.get("region") if isinstance(target_group_values, dict) else None
            expected_target_references = {f"{dependency_owner}.id", dependency_owner}
            expected_group_references = {f"{target_group_address}.arn", target_group_address}
            dependency_valid = (
                isinstance(before, dict)
                and isinstance(after, dict)
                and set(before) == {"availability_zone", "id", "port", "quic_server_id", "region", "target_group_arn", "target_id"}
                and set(after) == {"availability_zone", "port", "quic_server_id", "region", "target_group_arn"}
                and isinstance(before.get("id"), str)
                and bool(before["id"])
                and isinstance(before.get("target_group_arn"), str)
                and bool(before["target_group_arn"])
                and isinstance(target_group_arn, str)
                and bool(target_group_arn)
                and isinstance(target_group_region, str)
                and bool(target_group_region)
                and before.get("target_id") == replacement_instance_ids.get(dependency_owner)
                and before.get("target_group_arn") == after.get("target_group_arn") == target_group_arn
                and before.get("region") == after.get("region") == target_group_region
                and target_group_arn.split(":")[3:4] == [target_group_region]
                and all(before.get(field) is None and after.get(field) is None for field in ("availability_zone", "port", "quic_server_id"))
                and exact_configuration_references(
                    str(address),
                    "aws_lb_target_group_attachment",
                    {"target_group_arn": expected_group_references, "target_id": expected_target_references},
                )
                and change.get("action_reason") == "replace_because_cannot_update"
                and change_body.get("before_sensitive") == {}
                and change_body.get("after_sensitive") == {}
                and change_body.get("replace_paths") == [["target_id"]]
                and change_body.get("after_unknown") == {"id": True, "target_id": True}
            )
            if dependency_valid:
                seen_replacement_dependencies.add(address)
                continue
            errors.append(f"dependent target attachment replacement is not limited to {dependency_owner}'s target_id: {address}")
            continue
        route_owner = replacement_route_owners.get(address)
        if route_owner in allowed_replacements and action_tuple in {("update",), ("delete", "create")}:
            before = change_body.get("before") if isinstance(change_body, dict) else None
            after = change_body.get("after") if isinstance(change_body, dict) else None
            after_unknown = change_body.get("after_unknown") if isinstance(change_body, dict) else None
            route_configuration = semantic_route_references.get(str(address), {})
            planned_route_values = planned_by_address.get(str(address), {}).get("values", {})
            if not isinstance(planned_route_values, dict):
                planned_route_values = {}
            required_route_fields = {"destination_cidr_block", "region", "route_table_id"}
            unchanged_fields = (
                set(before) | set(after)
                if isinstance(before, dict) and isinstance(after, dict)
                else set()
            ) - {"id", "network_interface_id", "origin", "state"}
            route_valid = (
                isinstance(before, dict)
                and isinstance(after, dict)
                and isinstance(after_unknown, dict)
                and isinstance(before.get("id"), str)
                and bool(before["id"])
                and route_owner in replacement_instance_enis
                and before.get("network_interface_id") == replacement_instance_enis.get(route_owner)
                and after.get("network_interface_id") is None
                and after_unknown.get("network_interface_id") is True
                and all(
                    isinstance(before.get(field), str)
                    and bool(before[field])
                    and before.get(field) == after.get(field) == planned_route_values.get(field)
                    for field in required_route_fields
                )
                and set(after_unknown).issubset({"id", "network_interface_id", "origin", "state"})
                and all(before.get(field) == after.get(field) for field in unchanged_fields)
                and all(
                    planned_route_values.get(field) is None
                    or before.get(field) == after.get(field) == planned_route_values.get(field)
                    for field in unchanged_fields
                )
                and all(before.get(field) in (None, "") and after.get(field) in (None, "") for field in ROUTE_TARGET_FIELDS - {"network_interface_id"})
                and exact_configuration_references(str(address), "aws_route", route_configuration)
                and change_body.get("before_sensitive") == {}
                and change_body.get("after_sensitive") == {}
            )
            if action_tuple == ("update",):
                route_valid = (
                    route_valid
                    and change.get("action_reason") is None
                    and change_body.get("replace_paths") == []
                    and all(
                        after.get(field) == before.get(field)
                        or after.get(field) is None and after_unknown.get(field) is True
                        for field in ("id", "origin", "state")
                    )
                )
            else:
                route_valid = (
                    route_valid
                    and change.get("action_reason") == "replace_because_cannot_update"
                    and change_body.get("replace_paths") == [["network_interface_id"]]
                    and after.get("id") is None
                    and after_unknown.get("id") is True
                )
            if route_valid:
                continue
            errors.append(
                f"dependent responder-return route change is not limited to {route_owner}'s network_interface_id: {address}"
            )
            continue
        errors.append(f"resource-change actions are outside the approved set on {address}: {list(action_tuple)}")
    for address in sorted(allowed_replacements - seen_replacements):
        errors.append(f"requested replacement action is absent for {address}")
    for address in sorted(allowed_replacements & approved_replacements):
        dependency = replacement_dependencies[address]
        if dependency not in seen_replacement_dependencies:
            errors.append(f"requested replacement dependency action is absent for {dependency}")

    by_type: dict[str, list[dict[str, Any]]] = {}
    for resource in values:
        if resource.get("mode", "managed") != "data":
            by_type.setdefault(str(resource.get("type")), []).append(resource)

    az_count = sum(len(normalized_az_keys[site]) for site in SITES)
    endpoint_count = len(initiator_az_keys)
    expected_counts = {
        "terraform_data": 1,
        "aws_vpc": 2,
        "aws_internet_gateway": 2,
        "aws_subnet": 4 + 3 * az_count,
        "aws_nat_gateway": 2,
        "aws_eip": 2,
        "aws_route_table": 4 + 3 * az_count,
        "aws_route_table_association": 4 + 3 * az_count,
        "aws_route": 8 + len(SITES) * 2,
        "aws_lb": 2,
        "aws_lb_target_group": 2,
        "aws_lb_listener": 2,
        "aws_lb_target_group_attachment": 2,
        "aws_vpc_endpoint_service": 2,
        "aws_vpc_endpoint": endpoint_count,
        "aws_security_group": 6,
        "aws_instance": 6,
        "aws_network_acl": 2,
        "aws_cloudwatch_log_group": 2,
        "aws_flow_log": 2,
        "aws_iam_role": 5,
        "aws_iam_instance_profile": 4,
        "aws_iam_role_policy": 5,
        "aws_s3_bucket": 1,
        "aws_s3_bucket_public_access_block": 1,
        "aws_s3_bucket_ownership_controls": 1,
        "aws_s3_bucket_versioning": 1,
        "aws_s3_bucket_server_side_encryption_configuration": 1,
        "aws_s3_bucket_policy": 1,
        "aws_s3_object": 1,
    }
    for resource_type, expected in expected_counts.items():
        actual = len(by_type.get(resource_type, []))
        if actual != expected:
            errors.append(f"{resource_type} count is {actual}, expected {expected}")
    gateway_lbs = [
        resource for resource in by_type.get("aws_lb", []) if resource.get("values", {}).get("load_balancer_type") == "gateway"
    ]
    if len(gateway_lbs) != 2:
        errors.append(f"gateway load balancer count is {len(gateway_lbs)}, expected 2")
    for resource in gateway_lbs:
        if resource.get("values", {}).get("enable_cross_zone_load_balancing") is not True:
            errors.append(f"GWLB cross-zone load balancing is not explicit on {resource.get('address')}")

    cost = output_value(plan, "cost_profile")
    if not isinstance(cost, dict):
        errors.append("cost_profile output is missing")
    else:
        counts = cost.get("resource_counts", {})
        if not isinstance(counts, dict):
            errors.append("cost_profile resource_counts is missing")
            counts = {}
        reviewed_endpoint_count = counts.get("gwlbe_endpoints")
        if len(by_type.get("aws_vpc_endpoint", [])) != reviewed_endpoint_count:
            errors.append("GWLBE count does not match reviewed cost_profile")
        reviewed_counts = {
            "vpcs": 2,
            "nat_gateways": 2,
            "elastic_ips": 2,
            "gateway_load_balancers": 2,
            "gwlbe_endpoints": 2,
            "semantic_lane_routes": 4,
            "appliance_instances": 2,
            "workload_instances": 4,
            "artifact_buckets": 1,
            "network_acls": 2,
            "vpc_flow_logs": 2,
            "cloudwatch_log_groups": 2,
            "flow_log_iam_roles": 1,
            "regional_targets": {"west": 1, "east": 1},
        }
        if (
            cost.get("profile") != "directional-lane-acceptance"
            or counts != reviewed_counts
        ):
            errors.append("cost_profile does not declare the exact directional evidence topology")
        if cost.get("estimated_fixed_hourly_usd", 1e9) > cost.get("approved_max_hourly_usd", -1):
            errors.append("estimated fixed hourly cost exceeds approved ceiling")

    appliances = [resource for resource in by_type.get("aws_instance", []) if resource.get("name") in {"envelope_west", "envelope_east"}]
    resolver_arns: dict[str, str] = {}
    if len(appliances) != 2:
        errors.append("planned appliance instances are not exactly west and east")
    for resource in appliances:
        instance = resource.get("values", {})
        if instance.get("associate_public_ip_address") is not False or instance.get("source_dest_check") is not False:
            errors.append(f"appliance public-IP/source-destination contract failed on {resource.get('address')}")
        user_data = instance.get("user_data_base64")
        if isinstance(user_data, str):
            if not user_data.isascii():
                errors.append(f"appliance user_data_base64 is not ASCII on {resource.get('address')}")
                continue
            encoded = user_data.encode("ascii")
            if len(encoded) > EC2_USER_DATA_BASE64_LIMIT_BYTES:
                errors.append(
                    f"appliance base64 user data is {len(encoded)} bytes, exceeds EC2 limit "
                    f"{EC2_USER_DATA_BASE64_LIMIT_BYTES} on {resource.get('address')}"
                )
            try:
                compressed = base64.b64decode(encoded, validate=True)
            except ValueError:
                errors.append(f"invalid appliance user_data_base64 on {resource.get('address')}")
                continue
            if len(compressed) > EC2_USER_DATA_RAW_LIMIT_BYTES:
                errors.append(
                    f"appliance raw user data is {len(compressed)} bytes, exceeds EC2 limit "
                    f"{EC2_USER_DATA_RAW_LIMIT_BYTES} on {resource.get('address')}"
                )
            try:
                mime_bytes = gzip.decompress(compressed)
            except (EOFError, OSError):
                errors.append(f"appliance user data is not valid gzip on {resource.get('address')}")
                continue
            try:
                decoded = mime_bytes.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"appliance gzip user data is not UTF-8 MIME on {resource.get('address')}")
                continue
            if not re.search(r"(?im)^Content-Type:\s*multipart/", decoded) or not re.search(
                r"(?im)^MIME-Version:\s*1\.0\s*$", decoded
            ):
                errors.append(f"appliance gzip user data is not multipart cloud-init MIME on {resource.get('address')}")
            if KEY_PATTERN.search(decoded) or "tailscale_auth_key" in decoded:
                errors.append(f"plaintext Tailscale credential material appears in {resource.get('address')}")
            if "command:" not in decoded or ":ssm:" not in decoded or "--with-decryption" not in decoded:
                errors.append(f"boot-time SSM auth resolver is missing from {resource.get('address')}")
            site = "west" if resource.get("name") == "envelope_west" else "east"
            arns = set(re.findall(r"arn:[^:\s]+:ssm:[^:\s]+:[0-9]{12}:parameter/[^\s'\"]+", decoded))
            if len(arns) != 1:
                errors.append(f"appliance resolver is not isolated to its own region on {resource.get('address')}")
            else:
                resolver_arns[site] = arns.pop()
    if len(resolver_arns) == 2 and resolver_arns["west"] == resolver_arns["east"]:
        errors.append("west and east appliance resolvers reference the same regional SSM parameter")

    artifact = output_value(plan, "artifact_identity")
    objects = by_type.get("aws_s3_object", [])
    if not isinstance(artifact, dict) or len(objects) != 1:
        errors.append("artifact identity or object is missing")
    elif objects[0].get("values", {}).get("source_hash") != artifact.get("sha256"):
        errors.append("artifact object source hash differs from reviewed output")

    required_route_domains = {"workload_west", "workload_east", "gwlbe_west", "gwlbe_east", "gwlb_west", "gwlb_east", "appliance_west", "appliance_east"}
    route_names = {str(resource.get("name")) for resource in by_type.get("aws_route_table", [])}
    if not required_route_domains.issubset(route_names):
        errors.append("workload, GWLBE, GWLB, and appliance route domains are not all distinct")
    for route_table in by_type.get("aws_route_table", []):
        inline_routes = route_table.get("values", {}).get("route")
        if inline_routes not in (None, []):
            errors.append(f"inline or extra routes are prohibited on {route_table.get('address')}")

    def planned_resource_values(address: str) -> dict[str, Any]:
        resource = planned_by_address.get(address)
        resource_values = resource.get("values") if isinstance(resource, dict) else None
        return resource_values if isinstance(resource_values, dict) else {}

    def require_known_equal(label: str, *candidates: Any) -> None:
        known = [candidate for candidate in candidates if candidate is not None]
        if any(not isinstance(candidate, str) or not candidate for candidate in known):
            errors.append(f"{label} contains a non-string or empty planned identity")
        elif len(set(known)) > 1:
            errors.append(f"{label} does not resolve to one exact planned identity")

    def require_output_equal(label: str, output_candidate: Any, *sources: Any) -> None:
        if output_candidate is None and any(source is not None for source in sources):
            errors.append(f"{label} omits an identity known elsewhere in the plan")
        require_known_equal(label, output_candidate, *sources)

    workload_details: dict[str, dict[str, dict[str, Any]]] = {}
    workload_user_data_digests: list[str] = []
    workload_user_data_present = 0
    if not isinstance(workload_output, dict) or set(workload_output) != set(SITES):
        errors.append("workload_instances output must be nested exactly by west/east and role")
    else:
        for site in SITES:
            other = "east" if site == "west" else "west"
            site_output = workload_output.get(site)
            if not isinstance(site_output, dict) or set(site_output) != set(WORKLOAD_ROLES):
                errors.append(f"workload_instances.{site} must contain exactly initiator and responder")
                continue
            if not required_configuration_references(
                f"aws_instance.workload_{site}",
                "aws_instance",
                {"user_data_base64": {"local.workload_user_data"}},
            ):
                errors.append(f"{site} workload user data is not computed from local.workload_user_data")
            workload_details[site] = {}
            role_az_keys: list[str] = []
            for role in WORKLOAD_ROLES:
                details = site_output.get(role)
                if (
                    not isinstance(details, dict)
                    or not {"az_key", "availability_zone", "cidr"}.issubset(details)
                    or not set(details).issubset(WORKLOAD_OUTPUT_FIELDS)
                ):
                    errors.append(f"workload_instances.{site}.{role} has an invalid field shape")
                    continue
                workload_details[site][role] = details
                az_key = details.get("az_key")
                if not isinstance(az_key, str) or az_key not in normalized_az_keys[site]:
                    errors.append(f"workload_instances.{site}.{role} has an unreviewed AZ key")
                    continue
                if role == "initiator" and az_key != initiator_az_keys.get(site):
                    errors.append(f"workload_instances.{site}.initiator differs from the reviewed initiator AZ key")
                role_az_keys.append(az_key)
                instance_address = indexed_address(f"aws_instance.workload_{site}", role)
                security_group_address = indexed_address(f"aws_security_group.workload_{site}", role)
                subnet_address = indexed_address(f"aws_subnet.workload_{site}", az_key)
                route_table_address = indexed_address(f"aws_route_table.workload_{site}", az_key)
                association_address = indexed_address(f"aws_route_table_association.workload_{site}", az_key)
                instance_resource = planned_by_address.get(instance_address, {})
                security_group_resource = planned_by_address.get(security_group_address, {})
                if instance_resource.get("index") != role or security_group_resource.get("index") != role:
                    errors.append(f"{site} {role} workload instance/security group is not role-keyed")
                instance_values = planned_resource_values(instance_address)
                security_group_values = planned_resource_values(security_group_address)
                subnet_values = planned_resource_values(subnet_address)
                route_table_values = planned_resource_values(route_table_address)
                association_values = planned_resource_values(association_address)
                require_output_equal(
                    f"{site} {role} workload instance",
                    details.get("instance_id"),
                    instance_values.get("id"),
                )
                require_output_equal(
                    f"{site} {role} workload private IP",
                    details.get("private_ip"),
                    instance_values.get("private_ip"),
                )
                require_output_equal(
                    f"{site} {role} workload subnet",
                    details.get("subnet_id"),
                    instance_values.get("subnet_id"),
                    subnet_values.get("id"),
                    association_values.get("subnet_id"),
                )
                require_output_equal(
                    f"{site} {role} workload availability zone",
                    details.get("availability_zone"),
                    instance_values.get("availability_zone"),
                    subnet_values.get("availability_zone"),
                )
                require_output_equal(
                    f"{site} {role} workload route table",
                    details.get("route_table_id"),
                    route_table_values.get("id"),
                    association_values.get("route_table_id"),
                )
                require_output_equal(
                    f"{site} {role} workload CIDR",
                    details.get("cidr"),
                    subnet_values.get("cidr_block"),
                )
                security_group_ids = instance_values.get("vpc_security_group_ids")
                security_group_id = security_group_values.get("id")
                if (
                    (security_group_id is not None and security_group_ids is None)
                    or (
                        security_group_ids is not None
                        and (
                            not isinstance(security_group_ids, list)
                            or len(security_group_ids) != 1
                            or security_group_id is not None and security_group_ids != [security_group_id]
                        )
                    )
                ):
                    errors.append(f"{site} {role} workload does not use only its role-keyed security group")
                ingress = security_group_values.get("ingress")
                expected_ingress = (
                    set()
                    if role == "initiator"
                    else {
                        ("icmp", -1, -1, runtime[other]["gwlb_return_cidrs"][0]),
                        ("tcp", 5201, 5201, runtime[other]["gwlb_return_cidrs"][0]),
                        ("udp", 5201, 5201, runtime[other]["gwlb_return_cidrs"][0]),
                    }
                    if runtime_valid
                    else set()
                )
                actual_ingress: set[tuple[Any, Any, Any, Any]] = set()
                ingress_valid = (ingress is None and role == "initiator") or isinstance(ingress, list)
                if isinstance(ingress, list):
                    for rule in ingress:
                        cidrs = rule.get("cidr_blocks") if isinstance(rule, dict) else None
                        if (
                            not isinstance(rule, dict)
                            or not isinstance(cidrs, list)
                            or len(cidrs) != 1
                            or any(
                                rule.get(field) not in (None, [], False)
                                for field in ("ipv6_cidr_blocks", "prefix_list_ids", "security_groups", "self")
                            )
                        ):
                            ingress_valid = False
                            continue
                        actual_ingress.add(
                            (rule.get("protocol"), rule.get("from_port"), rule.get("to_port"), cidrs[0])
                        )
                if ingress is None and role == "initiator":
                    ingress_count = 0
                else:
                    ingress_count = len(ingress) if isinstance(ingress, list) else -1
                if not ingress_valid or actual_ingress != expected_ingress or ingress_count != len(expected_ingress):
                    errors.append(f"{site} {role} workload application ingress is not the exact paired probe set")
                sensitive_values = instance_resource.get("sensitive_values")
                user_data = instance_values.get("user_data_base64")
                if user_data is None:
                    if not isinstance(sensitive_values, dict) or sensitive_values.get("user_data_base64") is not True:
                        errors.append(f"{site} {role} omitted workload user data is not marked sensitive")
                else:
                    workload_user_data_present += 1
                    try:
                        encoded = user_data.encode("ascii") if isinstance(user_data, str) else b""
                        compressed = base64.b64decode(encoded, validate=True)
                        bootstrap = gzip.decompress(compressed).decode("utf-8")
                    except (EOFError, OSError, UnicodeDecodeError, UnicodeEncodeError, ValueError):
                        errors.append(f"{site} {role} workload user data is not bounded base64 gzip text")
                    else:
                        if (
                            not encoded
                            or len(encoded) > EC2_USER_DATA_BASE64_LIMIT_BYTES
                            or len(compressed) > EC2_USER_DATA_RAW_LIMIT_BYTES
                            or not bootstrap.startswith("#!/usr/bin/env bash\n")
                            or any(
                                package not in bootstrap
                                for package in (
                                    "amazon-ssm-agent",
                                    "coreutils",
                                    "grep",
                                    "gzip",
                                    "iperf3",
                                    "iproute",
                                    "iputils",
                                    "jq",
                                    "procps-ng",
                                    "python3",
                                    "tcpdump",
                                )
                            )
                            or 'mv -f "$agent_tmp" /opt/envelope/e2e-agent' not in bootstrap
                            or "envelope-e2e-agent-tcp.service" not in bootstrap
                            or "envelope-e2e-agent-udp.service" not in bootstrap
                            or bootstrap.count("KillMode=control-group") != 2
                            or bootstrap.count("KillSignal=SIGTERM") != 2
                            or bootstrap.count("TimeoutStopSec=5") != 2
                            or "RefuseManualStop=true" in bootstrap
                            or KEY_PATTERN.search(bootstrap)
                            or "tailscale_auth_key" in bootstrap
                        ):
                            errors.append(f"{site} {role} workload bootstrap contract failed")
                        workload_user_data_digests.append(hashlib.sha256(encoded).hexdigest())
                if runtime_valid:
                    runtime_field = "gwlb_return_cidrs" if role == "initiator" else "local_delivery_cidrs"
                    if details.get("cidr") != runtime[site][runtime_field][0]:
                        errors.append(f"workload_instances.{site}.{role} CIDR differs from its runtime role")
            if set(role_az_keys) != normalized_az_keys[site] or len(role_az_keys) != 2:
                errors.append(f"{site} initiator and responder workloads must occupy the two reviewed AZs exactly once")
    if workload_user_data_present not in (0, len(SITES) * len(WORKLOAD_ROLES)):
        errors.append("workload user data is only partially retained")
    if len(set(workload_user_data_digests)) > 1:
        errors.append("workload user data differs across role-keyed instances")

    if not runtime_valid:
        errors.append("site-specific directional runtime configuration output is missing")
    else:
        for site, other in (("west", "east"), ("east", "west")):
            local_roles = runtime[site]["gwlb_return_cidrs"] + runtime[site]["local_delivery_cidrs"]
            remote_roles = runtime[site]["remote_tailnet_cidrs"]
            expected_remote_roles = runtime[other]["gwlb_return_cidrs"] + runtime[other]["local_delivery_cidrs"]
            if len(set(local_roles)) != 2:
                errors.append(f"{site} runtime initiator and responder CIDRs are not distinct")
            if len(remote_roles) != 2 or sorted(remote_roles) != sorted(expected_remote_roles):
                errors.append(f"{site} runtime remote CIDRs are not exactly the opposite directional roles")

    for site in SITES:
        attachment_address = f"aws_lb_target_group_attachment.{site}"
        target_group_address = f"aws_lb_target_group.{site}"
        instance_address = f"aws_instance.envelope_{site}"
        if not exact_configuration_references(
            attachment_address,
            "aws_lb_target_group_attachment",
            {
                "target_group_arn": {f"{target_group_address}.arn", target_group_address},
                "target_id": {f"{instance_address}.id", instance_address},
            },
        ):
            errors.append(f"{attachment_address} does not use the exact direct regional appliance target")
        attachment_values = planned_resource_values(attachment_address)
        require_output_equal(
            f"{site} direct target attachment",
            attachment_values.get("target_id"),
            planned_resource_values(instance_address).get("id"),
        )
        require_output_equal(
            f"{site} target group attachment",
            attachment_values.get("target_group_arn"),
            planned_resource_values(target_group_address).get("arn"),
        )

    for site, other in (("west", "east"), ("east", "west")):
        endpoint_az_keys = [initiator_az_keys[site]] if site in initiator_az_keys else []
        for az_key in endpoint_az_keys:
            endpoint_address = indexed_address(f"aws_vpc_endpoint.{site}", az_key)
            endpoint_resource = planned_by_address.get(endpoint_address, {})
            endpoint_values = planned_resource_values(endpoint_address)
            gwlbe_subnet_values = planned_resource_values(indexed_address(f"aws_subnet.gwlbe_{site}", az_key))
            if endpoint_resource.get("index") != az_key:
                errors.append(f"{endpoint_address} is not keyed by its reviewed AZ")
            subnet_ids = endpoint_values.get("subnet_ids")
            gwlbe_subnet_id = gwlbe_subnet_values.get("id")
            if (
                (gwlbe_subnet_id is not None and subnet_ids is None)
                or (
                    subnet_ids is not None
                    and (
                        not isinstance(subnet_ids, list)
                        or len(subnet_ids) != 1
                        or gwlbe_subnet_id is not None and subnet_ids != [gwlbe_subnet_id]
                    )
                )
            ):
                errors.append(f"{endpoint_address} is not attached only to its same-AZ GWLBE subnet")

        route_contracts = (
            (
                f"aws_route.initiator_to_responder_{site}",
                "initiator",
                runtime[other]["local_delivery_cidrs"][0] if runtime_valid else None,
                "vpc_endpoint_id",
            ),
            (
                f"aws_route.responder_return_{site}",
                "responder",
                runtime[other]["gwlb_return_cidrs"][0] if runtime_valid else None,
                "network_interface_id",
            ),
        )
        for route_address, role, expected_destination, target_field in route_contracts:
            route_values = planned_resource_values(route_address)
            if not exact_configuration_references(
                route_address, "aws_route", semantic_route_references[route_address]
            ):
                errors.append(f"{route_address} does not have the exact directional configuration references")
            if route_values.get("destination_cidr_block") != expected_destination:
                errors.append(f"{route_address} has a broad or incorrect directional destination")
            opposite_role = "responder" if role == "initiator" else "initiator"
            require_known_equal(
                f"{route_address} directional destination",
                route_values.get("destination_cidr_block"),
                expected_destination,
                workload_details.get(other, {}).get(opposite_role, {}).get("cidr"),
            )
            if any(route_values.get(field) not in (None, "") for field in ("destination_ipv6_cidr_block", "destination_prefix_list_id")):
                errors.append(f"{route_address} uses an unapproved non-IPv4 destination")
            details = workload_details.get(site, {}).get(role, {})
            role_az_key = details.get("az_key")
            route_table_id = (
                planned_resource_values(indexed_address(f"aws_route_table.workload_{site}", role_az_key)).get("id")
                if isinstance(role_az_key, str)
                else None
            )
            require_output_equal(
                f"{route_address} workload route table",
                route_values.get("route_table_id"),
                details.get("route_table_id"),
                route_table_id,
            )
            expected_target: Any = None
            if target_field == "vpc_endpoint_id":
                if isinstance(role_az_key, str):
                    expected_target = planned_resource_values(
                        indexed_address(f"aws_vpc_endpoint.{site}", role_az_key)
                    ).get("id")
            else:
                expected_target = planned_resource_values(f"aws_instance.envelope_{site}").get(
                    "primary_network_interface_id"
                )
            target_value = route_values.get(target_field)
            require_output_equal(f"{route_address} target", target_value, expected_target)
            if any(
                route_values.get(field) not in (None, "")
                for field in ROUTE_TARGET_FIELDS - {target_field}
            ):
                errors.append(f"{route_address} has an extra or wrong target type")

    flow_evidence_details: dict[str, dict[str, Any]] = {}
    site_regions: dict[str, str] = {}
    if not isinstance(flow_log_evidence, dict) or set(flow_log_evidence) != set(SITES):
        errors.append("flow_log_evidence output must contain exactly west and east")
    else:
        for site in SITES:
            evidence = flow_log_evidence.get(site)
            if (
                not isinstance(evidence, dict)
                or "region" not in evidence
                or not set(evidence).issubset({"flow_log_id", "log_group_arn", "region"})
                or not isinstance(evidence.get("region"), str)
                or not evidence["region"]
            ):
                errors.append(f"flow_log_evidence.{site} has an invalid field shape")
                continue
            flow_evidence_details[site] = evidence
            site_regions[site] = evidence["region"]

    flow_role_values = planned_resource_values("aws_iam_role.flow_logs")
    flow_policy_values = planned_resource_values("aws_iam_role_policy.flow_logs")
    flow_role_arn = flow_role_values.get("arn")
    flow_role_id = flow_role_values.get("id")
    if flow_role_values.get("name") != f"{run_name}-flow-logs":
        errors.append("flow-log IAM role name is not exactly run-scoped")
    if not required_configuration_references(
        "aws_iam_role.flow_logs",
        "aws_iam_role",
        {"assume_role_policy": {"local.flow_log_assume_policy"}},
    ):
        errors.append("flow-log IAM role does not use the reviewed assume policy")
    if not required_configuration_references(
        "aws_iam_role_policy.flow_logs",
        "aws_iam_role_policy",
        {
            "role": {"aws_iam_role.flow_logs.id", "aws_iam_role.flow_logs"},
            "policy": {"local.flow_log_delivery_policy"},
        },
    ):
        errors.append("flow-log IAM policy does not use the exact role and delivery policy references")
    require_output_equal("flow-log IAM policy role", flow_policy_values.get("role"), flow_role_id)

    trust_policy: dict[str, Any] = {}
    try:
        candidate_trust = json.loads(flow_role_values.get("assume_role_policy", ""))
        if isinstance(candidate_trust, dict):
            trust_policy = candidate_trust
    except (json.JSONDecodeError, TypeError):
        pass
    trust_statements = trust_policy.get("Statement")
    trust_statement = trust_statements[0] if isinstance(trust_statements, list) and len(trust_statements) == 1 else None
    trust_condition = trust_statement.get("Condition") if isinstance(trust_statement, dict) else None
    source_account = (
        trust_condition.get("StringEquals", {}).get("aws:SourceAccount")
        if isinstance(trust_condition, dict)
        and isinstance(trust_condition.get("StringEquals"), dict)
        else None
    )
    expected_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:ec2:*:{source_account}:vpc-flow-log/*"
                    },
                    "StringEquals": {"aws:SourceAccount": source_account},
                },
            }
        ],
    }
    if not isinstance(source_account, str) or not re.fullmatch(r"[0-9]{12}", source_account) or trust_policy != expected_trust:
        errors.append("flow-log IAM trust is not limited to the source account and VPC Flow Log service ARN")
    if flow_role_arn is not None and flow_role_arn != f"arn:aws:iam::{source_account}:role/{run_name}-flow-logs":
        errors.append("flow-log IAM role ARN is not the exact run-scoped role")

    log_group_arns: dict[str, str] = {}
    for site in SITES:
        region = site_regions.get(site)
        vpc_values = planned_resource_values(f"aws_vpc.{site}")
        subnet_values = planned_resource_values(f"aws_subnet.appliance_{site}")
        group_address = f"aws_cloudwatch_log_group.flow_{site}"
        group_values = planned_resource_values(group_address)
        group_name = f"/aws/vpc-flow-logs/{run_name}/{site}"
        group_arn = group_values.get("arn")
        if (
            group_values.get("name") != group_name
            or group_values.get("retention_in_days") != 7
            or group_values.get("kms_key_id") not in (None, "")
        ):
            errors.append(f"{site} Flow Log group is not the exact seven-day repository-policy shape")
        if region is not None and group_values.get("region") not in (None, region):
            errors.append(f"{site} Flow Log group is not in its workload region")
        if group_arn is not None:
            expected_group_arn = f"arn:aws:logs:{region}:{source_account}:log-group:{group_name}"
            if group_arn != expected_group_arn:
                errors.append(f"{site} Flow Log group ARN is not exact and regional")
            elif isinstance(group_arn, str):
                log_group_arns[site] = group_arn
        require_output_equal(
            f"{site} Flow Log evidence group",
            flow_evidence_details.get(site, {}).get("log_group_arn"),
            group_arn,
        )

        flow_address = f"aws_flow_log.{site}"
        flow_values = planned_resource_values(flow_address)
        if (
            flow_values.get("traffic_type") != "ALL"
            or flow_values.get("log_destination_type") != "cloud-watch-logs"
            or flow_values.get("max_aggregation_interval") != 60
            or flow_values.get("log_format") != FLOW_LOG_FORMAT
            or any(
                flow_values.get(field) not in (None, "")
                for field in ("eni_id", "subnet_id", "transit_gateway_id", "transit_gateway_attachment_id")
            )
        ):
            errors.append(f"{site} Flow Log is not the exact VPC ALL CloudWatch packet-address shape")
        require_output_equal(f"{site} Flow Log VPC scope", flow_values.get("vpc_id"), vpc_values.get("id"))
        require_output_equal(f"{site} Flow Log destination", flow_values.get("log_destination"), group_arn)
        require_output_equal(f"{site} Flow Log role", flow_values.get("iam_role_arn"), flow_role_arn)
        require_output_equal(
            f"{site} Flow Log evidence identity",
            flow_evidence_details.get(site, {}).get("flow_log_id"),
            flow_values.get("id"),
        )
        if region is not None and flow_values.get("region") not in (None, region):
            errors.append(f"{site} Flow Log is not in its workload region")
        if not required_configuration_references(
            flow_address,
            "aws_flow_log",
            {
                "vpc_id": {f"aws_vpc.{site}.id", f"aws_vpc.{site}"},
                "log_destination": {f"{group_address}.arn", group_address},
                "iam_role_arn": {"aws_iam_role.flow_logs.arn", "aws_iam_role.flow_logs"},
                "log_format": {"local.flow_log_format"},
            },
        ):
            errors.append(f"{site} Flow Log does not use exact VPC, group, role, and format references")
        flow_configuration = configured_by_address.get(flow_address, {})
        if flow_configuration.get("depends_on") != ["aws_iam_role_policy.flow_logs"]:
            errors.append(f"{site} Flow Log does not depend exactly on its delivery policy")

        acl_address = f"aws_network_acl.appliance_{site}"
        acl_values = planned_resource_values(acl_address)
        require_output_equal(f"{site} appliance NACL VPC", acl_values.get("vpc_id"), vpc_values.get("id"))
        subnet_ids = acl_values.get("subnet_ids")
        appliance_subnet_id = subnet_values.get("id")
        if (
            (appliance_subnet_id is not None and subnet_ids is None)
            or (
                subnet_ids is not None
                and (
                    not isinstance(subnet_ids, list)
                    or len(subnet_ids) != 1
                    or appliance_subnet_id is not None and subnet_ids != [appliance_subnet_id]
                )
            )
        ):
            errors.append(f"{site} appliance NACL is not attached only to its appliance subnet")
        expected_ingress = [
            {
                "rule_no": 100,
                "action": "allow",
                "protocol": "-1",
                "cidr_block": runtime[site]["local_delivery_cidrs"][0] if runtime_valid else None,
                "from_port": 0,
                "to_port": 0,
            },
            {"rule_no": 200, "action": "allow", "protocol": "-1", "cidr_block": "0.0.0.0/0", "from_port": 0, "to_port": 0},
        ]
        expected_egress = [
            {
                "rule_no": 100,
                "action": "deny",
                "protocol": "-1",
                "cidr_block": runtime[site]["gwlb_return_cidrs"][0] if runtime_valid else None,
                "from_port": 0,
                "to_port": 0,
            },
            {
                "rule_no": 110,
                "action": "allow",
                "protocol": "-1",
                "cidr_block": runtime[site]["local_delivery_cidrs"][0] if runtime_valid else None,
                "from_port": 0,
                "to_port": 0,
            },
            {"rule_no": 200, "action": "allow", "protocol": "-1", "cidr_block": "0.0.0.0/0", "from_port": 0, "to_port": 0},
        ]

        def normalized_acl_rules(candidate: Any) -> list[dict[str, Any]] | None:
            if not isinstance(candidate, list) or not all(isinstance(rule, dict) for rule in candidate):
                return None
            if any(rule.get("ipv6_cidr_block") not in (None, "") for rule in candidate):
                return None
            return sorted(
                [
                    {
                        key: rule.get(key)
                        for key in ("rule_no", "action", "protocol", "cidr_block", "from_port", "to_port")
                    }
                    for rule in candidate
                ],
                key=lambda rule: str(rule["rule_no"]),
            )

        if normalized_acl_rules(acl_values.get("ingress")) != expected_ingress or normalized_acl_rules(
            acl_values.get("egress")
        ) != expected_egress:
            errors.append(f"{site} appliance NACL does not have the exact ordered directional rules")
        if region is not None and acl_values.get("region") not in (None, region):
            errors.append(f"{site} appliance NACL is not in its workload region")
        if not required_configuration_references(
            acl_address,
            "aws_network_acl",
            {
                "vpc_id": {f"aws_vpc.{site}.id", f"aws_vpc.{site}"},
                "subnet_ids": {f"aws_subnet.appliance_{site}.id", f"aws_subnet.appliance_{site}"},
            },
        ):
            errors.append(f"{site} appliance NACL does not use exact VPC and appliance subnet references")

    delivery_policy: dict[str, Any] = {}
    policy_text = flow_policy_values.get("policy")
    if policy_text is not None:
        try:
            candidate_policy = json.loads(policy_text)
            if isinstance(candidate_policy, dict):
                delivery_policy = candidate_policy
        except (json.JSONDecodeError, TypeError):
            pass
        statements = delivery_policy.get("Statement")
        by_sid = {
            statement.get("Sid"): statement
            for statement in statements
            if isinstance(statement, dict) and isinstance(statement.get("Sid"), str)
        } if isinstance(statements, list) else {}
        expected_groups = set(log_group_arns.values())
        expected_streams = {f"{arn}:*" for arn in expected_groups}
        create = by_sid.get("CreateExactRegionalFlowLogGroups")
        write = by_sid.get("WriteExactRegionalFlowLogGroups")
        discover = by_sid.get("DiscoverFlowLogGroups")
        delivery_valid = (
            delivery_policy.get("Version") == "2012-10-17"
            and isinstance(statements, list)
            and len(statements) == 3
            and set(by_sid) == {
                "CreateExactRegionalFlowLogGroups",
                "WriteExactRegionalFlowLogGroups",
                "DiscoverFlowLogGroups",
            }
            and len(expected_groups) == 2
            and isinstance(create, dict)
            and set(create) == {"Sid", "Effect", "Action", "Resource"}
            and create.get("Effect") == "Allow"
            and create.get("Action") == ["logs:CreateLogGroup"]
            and set(create.get("Resource", [])) == expected_groups
            and isinstance(write, dict)
            and set(write) == {"Sid", "Effect", "Action", "Resource"}
            and write.get("Effect") == "Allow"
            and set(write.get("Action", [])) == {
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
            }
            and set(write.get("Resource", [])) == expected_streams
            and isinstance(discover, dict)
            and set(discover) == {"Sid", "Effect", "Action", "Resource"}
            and discover.get("Effect") == "Allow"
            and discover.get("Action") == ["logs:DescribeLogGroups"]
            and discover.get("Resource") == ["*"]
        )
        if not delivery_valid:
            errors.append("flow-log delivery IAM is not limited to exact regional log groups and required writes")

    artifact_identity = output_value(plan, "artifact_identity")
    if isinstance(artifact_identity, dict):
        artifact_arn = f"arn:aws:s3:::{artifact_identity.get('bucket')}/{artifact_identity.get('key')}"
    else:
        artifact_arn = ""
    policy_resources = {resource.get("name"): resource for resource in by_type.get("aws_iam_role_policy", [])}
    for site, other in (("west", "east"), ("east", "west")):
        resource = policy_resources.get(f"appliance_runtime_{site}")
        try:
            policy = json.loads(resource.get("values", {}).get("policy", "")) if resource else {}
        except json.JSONDecodeError:
            policy = {}
        serialized_policy = json.dumps(policy, sort_keys=True)
        expected_parameter = resolver_arns.get(site, "missing-resolver")
        other_parameter = resolver_arns.get(other, "missing-other-resolver")
        if (
            expected_parameter not in serialized_policy
            or other_parameter in serialized_policy
            or artifact_arn not in serialized_policy
            or "kms:EncryptionContext:PARAMETER_ARN" not in serialized_policy
            or "kms:ViaService" not in serialized_policy
            or "aws:RequestedRegion" not in serialized_policy
        ):
            errors.append(f"{site} appliance IAM is not isolated to its exact artifact/SSM/KMS/regional core contract")

    for resource in values:
        tags = resource.get("values", {}).get("tags_all")
        if isinstance(tags, dict):
            if tags.get("EnvelopeRun") != run_name or not tags.get("ExpiresAt"):
                errors.append(f"run ownership/TTL tags missing on {resource.get('address')}")
            name = tags.get("Name")
            if isinstance(name, str) and not name.startswith(run_name):
                errors.append(f"resource name is not derived from run name on {resource.get('address')}")
    if not errors:
        def scrub_module_user_data(module: Any) -> None:
            if not isinstance(module, dict):
                return
            for resource in module.get("resources", []):
                if not isinstance(resource, dict) or not WORKLOAD_ADDRESS_PATTERN.fullmatch(
                    str(resource.get("address", ""))
                ):
                    continue
                resource_values = resource.get("values")
                if isinstance(resource_values, dict):
                    resource_values.pop("user_data_base64", None)
                sensitive = resource.get("sensitive_values")
                if not isinstance(sensitive, dict):
                    sensitive = {}
                    resource["sensitive_values"] = sensitive
                sensitive["user_data_base64"] = True
            for child in module.get("child_modules", []):
                scrub_module_user_data(child)

        scrub_module_user_data(plan.get("planned_values", {}).get("root_module"))
        scrub_module_user_data(plan.get("prior_state", {}).get("values", {}).get("root_module"))
        for collection_name in ("resource_changes", "resource_drift"):
            for change in plan.get(collection_name, []):
                if not isinstance(change, dict) or not WORKLOAD_ADDRESS_PATTERN.fullmatch(
                    str(change.get("address", ""))
                ):
                    continue
                change_body = change.get("change")
                if not isinstance(change_body, dict):
                    continue
                for phase in ("before", "after"):
                    phase_values = change_body.get(phase)
                    if isinstance(phase_values, dict):
                        phase_values.pop("user_data_base64", None)
                    sensitive_name = f"{phase}_sensitive"
                    sensitive = change_body.get(sensitive_name)
                    if not isinstance(sensitive, dict):
                        sensitive = {}
                        change_body[sensitive_name] = sensitive
                    sensitive["user_data_base64"] = True
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=pathlib.Path)
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--allow-replace", action="append", default=[])
    parser.add_argument("--west-az-key", action="append", required=True)
    parser.add_argument("--east-az-key", action="append", required=True)
    parser.add_argument("--west-initiator-az-key", required=True)
    parser.add_argument("--east-initiator-az-key", required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"plan validation failed: cannot read plan JSON: {error}", file=sys.stderr)
        return 1
    failures = validate(
        plan,
        args.run_name,
        set(args.allow_replace),
        {"west": set(args.west_az_key), "east": set(args.east_az_key)},
        {"west": args.west_initiator_az_key, "east": args.east_initiator_az_key},
    )
    if failures:
        for failure in failures:
            print(f"plan validation failed: {failure}", file=sys.stderr)
        return 1
    print("appliance plan shape passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
