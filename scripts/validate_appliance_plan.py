#!/usr/bin/env python3
"""Fail closed when a saved Terraform plan diverges from the acceptance shape."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import pathlib
import re
import sys
from typing import Any


KEY_PATTERN = re.compile("tskey-" + r"(?:auth|client|api)-[A-Za-z0-9_-]{8,}", re.IGNORECASE)
EC2_USER_DATA_RAW_LIMIT_BYTES = 16 * 1024
EC2_USER_DATA_BASE64_LIMIT_BYTES = 4 * ((EC2_USER_DATA_RAW_LIMIT_BYTES + 2) // 3)
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


def output_value(plan: dict[str, Any], name: str) -> Any:
    value = plan.get("planned_values", {}).get("outputs", {}).get(name)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def indexed_address(prefix: str, key: str) -> str:
    return f"{prefix}[{json.dumps(key, separators=(',', ':'))}]"


def approved_managed_resources(runtime: dict[str, Any], az_keys: dict[str, set[str]]) -> dict[str, str]:
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
        ("aws_security_group", "aws_security_group.test_{site}"),
        ("aws_instance", "aws_instance.envelope_{site}"),
        ("aws_instance", "aws_instance.test_{site}"),
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
        ("aws_vpc_endpoint", "aws_vpc_endpoint.{site}"),
    )
    for site in ("west", "east"):
        for resource_type, address in per_site:
            result[address.format(site=site)] = resource_type
        remotes = runtime[site]["remote_tailnet_cidrs"]
        for az_key in az_keys[site]:
            for resource_type, prefix in indexed_per_az:
                result[indexed_address(prefix.format(site=site), az_key)] = resource_type
            for cidr in remotes:
                result[indexed_address(f"aws_route.workload_to_remote_{site}", f"{az_key}:{cidr}")] = "aws_route"
    result.update(
        {
            "aws_s3_bucket.artifact": "aws_s3_bucket",
            "aws_s3_bucket_public_access_block.artifact": "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_ownership_controls.artifact": "aws_s3_bucket_ownership_controls",
            "aws_s3_bucket_versioning.artifact": "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration.artifact": "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_policy.artifact": "aws_s3_bucket_policy",
            "aws_s3_object.envelope": "aws_s3_object",
        }
    )
    return result


def validate(
    plan: dict[str, Any],
    run_name: str,
    allowed_replacements: set[str] | None = None,
    expected_az_keys: dict[str, set[str]] | None = None,
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
            or not 1 <= len(expected_az_keys[site]) <= 3
            or not all(isinstance(key, str) and key for key in expected_az_keys[site])
            for site in ("west", "east")
        )
    ):
        errors.append("exact west/east AZ keys are required for protected address validation")
    else:
        normalized_az_keys = {site: set(expected_az_keys[site]) for site in ("west", "east")}
    runtime_valid = (
        isinstance(runtime, dict)
        and set(runtime) == {"west", "east"}
        and all(
            isinstance(runtime[site], dict)
            and isinstance(runtime[site].get("remote_tailnet_cidrs"), list)
            and all(isinstance(cidr, str) for cidr in runtime[site]["remote_tailnet_cidrs"])
            for site in ("west", "east")
        )
    )
    expected_resources = (
        approved_managed_resources(runtime, normalized_az_keys)
        if runtime_valid and all(normalized_az_keys.values())
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

    approved_replacements = {"aws_instance.envelope_west", "aws_instance.envelope_east"}
    if not allowed_replacements.issubset(approved_replacements):
        errors.append("replacement allowlist contains an address other than an exact regional Envelope instance")
    changes = plan.get("resource_changes")
    seen_replacements: set[str] = set()
    if not isinstance(changes, list):
        errors.append("resource_changes must be a list")
        changes = []
    for change in changes:
        if not isinstance(change, dict):
            errors.append("resource_changes contains a non-object entry")
            continue
        address = change.get("address")
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
            continue
        if action_tuple == ("read",) and mode == "data":
            continue
        if address in allowed_replacements and action_tuple in {("create", "delete"), ("delete", "create")}:
            seen_replacements.add(address)
            continue
        errors.append(f"resource-change actions are outside the approved set on {address}: {list(action_tuple)}")
    for address in sorted(allowed_replacements - seen_replacements):
        errors.append(f"requested replacement action is absent for {address}")

    by_type: dict[str, list[dict[str, Any]]] = {}
    for resource in values:
        if resource.get("mode", "managed") != "data":
            by_type.setdefault(str(resource.get("type")), []).append(resource)

    endpoint_count = sum(len(normalized_az_keys[site]) for site in ("west", "east"))
    remote_route_count = 0
    configured_endpoint_count = endpoint_count
    if isinstance(runtime, dict):
        for site in ("west", "east"):
            site_runtime = runtime.get(site, {})
            remotes = site_runtime.get("remote_tailnet_cidrs", []) if isinstance(site_runtime, dict) else []
            remote_route_count += len(normalized_az_keys[site]) * len(remotes)
    expected_counts = {
        "terraform_data": 1,
        "aws_vpc": 2,
        "aws_internet_gateway": 2,
        "aws_subnet": 4 + 3 * endpoint_count,
        "aws_nat_gateway": 2,
        "aws_eip": 2,
        "aws_route_table": 4 + 3 * endpoint_count,
        "aws_route_table_association": 4 + 3 * endpoint_count,
        "aws_route": 4 + endpoint_count + remote_route_count,
        "aws_lb": 2,
        "aws_lb_target_group": 2,
        "aws_lb_listener": 2,
        "aws_lb_target_group_attachment": 2,
        "aws_vpc_endpoint_service": 2,
        "aws_vpc_endpoint": configured_endpoint_count,
        "aws_security_group": 4,
        "aws_instance": 4,
        "aws_iam_role": 4,
        "aws_iam_instance_profile": 4,
        "aws_iam_role_policy": 4,
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
        endpoint_count = counts.get("gwlbe_endpoints")
        if len(by_type.get("aws_vpc_endpoint", [])) != endpoint_count:
            errors.append("GWLBE count does not match reviewed cost_profile")
        if counts.get("nat_gateways") != 2 or counts.get("regional_targets") != {"west": 1, "east": 1}:
            errors.append("cost_profile does not declare one NAT and one target per region")
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

    if not runtime_valid:
        errors.append("site-specific runtime configuration output is missing")
    else:
        for site in ("west", "east"):
            expected = runtime[site].get("remote_tailnet_cidrs", [])
            endpoints = len([resource for resource in by_type.get("aws_vpc_endpoint", []) if resource.get("name") == site])
            actual = [
                resource.get("values", {}).get("destination_cidr_block")
                for resource in by_type.get("aws_route", [])
                if resource.get("name") == f"workload_to_remote_{site}"
            ]
            wanted = [cidr for cidr in expected for _ in range(endpoints)]
            if sorted(actual, key=str) != sorted(wanted):
                errors.append(f"{site} inspection routes do not enumerate only configured remote workload CIDRs per AZ")

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
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=pathlib.Path)
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--allow-replace", action="append", default=[])
    parser.add_argument("--west-az-key", action="append", required=True)
    parser.add_argument("--east-az-key", action="append", required=True)
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
    )
    if failures:
        for failure in failures:
            print(f"plan validation failed: {failure}", file=sys.stderr)
        return 1
    print("appliance plan shape passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
