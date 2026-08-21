#!/usr/bin/env python3
"""Protected, AWS-free-testable orchestration for the two-region appliance E2E."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import copy
import dataclasses
import datetime as dt
import enum
import gzip
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import queue
import re
import shlex
import signal
import struct
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Literal, Protocol, TypeAlias, cast

from aws_appliance import (
    AwsCLI,
    ConcurrentLifecycleError,
    LifecycleError,
    ManifestStore,
    RunConfig,
    SubprocessRunner,
    build_tailscale,
    cleanup as protected_cleanup,
    collect_diagnostics as collect_appliance_diagnostics,
    lifecycle_lock,
    prepare as protected_prepare,
    run_preflight,
    run_directory,
    terraform_apply,
    terraform_plan,
    terraform_verify_no_drift,
    redact,
    validate_canonical_utc_timestamp,
    wait_and_record,
)


Site: TypeAlias = Literal["west", "east"]
WorkloadRole: TypeAlias = Literal["initiator", "responder"]
ProtocolName: TypeAlias = Literal["icmp", "tcp", "udp"]

SITES: tuple[Site, ...] = ("west", "east")
WORKLOAD_ROLES: tuple[WorkloadRole, ...] = ("initiator", "responder")
PROTOCOLS: tuple[ProtocolName, ...] = ("icmp", "tcp", "udp")
TRANSPORT_PROTOCOLS: tuple[Literal["tcp", "udp"], ...] = ("tcp", "udp")
EVIDENCE_SCHEMA = 1
LIVE_EVIDENCE_SCHEMA = 2
LIVE_EVIDENCE_KIND = "aws-two-region-live"

EXIT_OK = 0
EXIT_ACCEPTANCE_FAILED = 1
EXIT_CONTRACT_ERROR = 2
EXIT_CLEANUP_FAILED = 3
RUN_ALL_HARD_TIMEOUT_SECONDS = 5400

_VPC_ID_RE = re.compile(r"vpc-[0-9a-f]{8,17}")
_VPCE_ID_RE = re.compile(r"vpce-[0-9a-f]{8,17}")
_ENI_ID_RE = re.compile(r"eni-[0-9a-f]{8,17}")
_FLOW_LOG_ID_RE = re.compile(r"fl-[0-9a-f]{8,17}")
_TARGET_GROUP_ARN_RE = re.compile(
    r"arn:aws(?:-[a-z]+)?:elasticloadbalancing:([a-z]{2}(?:-[a-z]+)+-[0-9]+):[0-9]{12}:targetgroup/[A-Za-z0-9-]+/[0-9a-f]+"
)
_LOG_GROUP_ARN_RE = re.compile(
    r"arn:aws(?:-[a-z]+)?:logs:([a-z]{2}(?:-[a-z]+)+-[0-9]+):[0-9]{12}:log-group:([^:*][^:]*)"
)

_INSTANCE_ID_RE = re.compile(r"i-[0-9a-f]{8,17}")
_SUBNET_ID_RE = re.compile(r"subnet-[0-9a-f]{8,17}")
_ROUTE_TABLE_ID_RE = re.compile(r"rtb-[0-9a-f]{8,17}")
_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+")
_RUN_ID_RE = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]")
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PROCESS_RE = re.compile(r"[a-z][a-z0-9-]{0,47}")
_METRIC_NAME_RE = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
_LABEL_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ROUTE_TARGET_FIELDS = {
    "CarrierGatewayId",
    "CoreNetworkArn",
    "EgressOnlyInternetGatewayId",
    "GatewayId",
    "IpAddress",
    "LocalGatewayId",
    "NatGatewayId",
    "NetworkInterfaceId",
    "OdbNetworkArn",
    "TransitGatewayId",
    "VpcEndpointId",
    "VpcPeeringConnectionId",
}


class E2EError(LifecycleError):
    """Base error for an invalid E2E contract or operation."""


class DeploymentError(E2EError):
    pass


class SSMError(E2EError):
    pass


class SSMTimeout(SSMError):
    pass


class MetricError(E2EError):
    pass


class MetricAssertionError(MetricError):
    pass


class StreamAnalysisError(E2EError):
    pass


class EvidenceError(E2EError):
    pass


class AcceptanceError(E2EError):
    """A valid live run failed one acceptance gate."""


class ConcurrentRunError(AcceptanceError):
    pass


class ClaimPersistenceError(AcceptanceError):
    """A conditional claim/result write provably did not commit."""


class AmbiguousOwnershipError(AcceptanceError):
    """Durable claim ownership could not be reconciled safely."""


class DriftError(AcceptanceError):
    pass


class ReadinessError(AcceptanceError):
    pass


class ProbeError(AcceptanceError):
    pass


class FlowLogError(AcceptanceError):
    pass


class WireAssertionError(AcceptanceError):
    pass


class TransportError(AcceptanceError):
    pass


class LoadProfileError(AcceptanceError):
    pass


class ResilienceError(AcceptanceError):
    pass


class EvidenceVerificationError(EvidenceError):
    pass


def _ownership_resolution(error: BaseException | None) -> str | None:
    if isinstance(error, ConcurrentRunError):
        return "competing-claim"
    if isinstance(error, AmbiguousOwnershipError):
        return "ambiguous-ownership"
    if isinstance(error, ClaimPersistenceError):
        return "not-committed"
    return None


class Phase(str, enum.Enum):
    CONSUME_DEPLOYMENT = "consume-protected-deployment"
    DRIFT_PRECHECK = "terraform-drift-precheck"
    READINESS_TOPOLOGY = "readiness-and-topology"
    FLOW_LOG_START = "vpc-flow-log-start"
    COLD_WEST_EAST = "cold-flow-and-wire-west-to-east"
    COLD_EAST_WEST = "cold-flow-and-wire-east-to-west"
    MTU_TRANSPORT = "mtu-and-transport"
    APPROVED_LOAD = "approved-load"
    ROUTE_MUTATION = "route-mutation"
    SERVICE_STOP = "appliance-service-stop"
    EC2_REBOOT_WEST = "appliance-ec2-reboot-west"
    EC2_REBOOT_EAST = "appliance-ec2-reboot-east"
    TAILSCALE_WITHDRAWAL = "tailscale-route-withdrawal"
    FLOW_LOG_CAPTURE = "vpc-flow-log-capture"
    DRIFT_POSTCHECK = "terraform-drift-postcheck"
    EVIDENCE = "evidence"
    CLEANUP = "protected-cleanup"


LIVE_PHASES: tuple[Phase, ...] = (
    Phase.CONSUME_DEPLOYMENT,
    Phase.DRIFT_PRECHECK,
    Phase.READINESS_TOPOLOGY,
    Phase.FLOW_LOG_START,
    Phase.COLD_WEST_EAST,
    Phase.COLD_EAST_WEST,
    Phase.MTU_TRANSPORT,
    Phase.APPROVED_LOAD,
    Phase.ROUTE_MUTATION,
    Phase.SERVICE_STOP,
    Phase.EC2_REBOOT_WEST,
    Phase.EC2_REBOOT_EAST,
    Phase.TAILSCALE_WITHDRAWAL,
    Phase.FLOW_LOG_CAPTURE,
    Phase.DRIFT_POSTCHECK,
    Phase.EVIDENCE,
    Phase.CLEANUP,
)


@dataclasses.dataclass(frozen=True)
class TimeoutBudgets:
    """Wall-clock budgets for every live gate, including recovery and cleanup."""

    consume_deployment: int = 30
    drift_check: int = 300
    readiness_topology: int = 600
    flow_log_start: int = 120
    cold_direction: int = 240
    mtu_transport: int = 600
    approved_load: int = 900
    route_mutation: int = 120
    service_stop: int = 180
    ec2_reboot: int = 600
    tailscale_withdrawal: int = 180
    flow_log_capture: int = 420
    evidence: int = 30
    cleanup: int = 900
    hard_timeout: int = 5400
    probe_response: int = 30
    continuity_loss: int = 90

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 7200:
                raise E2EError(f"timeout budget {field.name} must be an integer between 1 and 7200")
        minimum = (
            self.consume_deployment
            + 2 * self.drift_check
            + self.readiness_topology
            + self.flow_log_start
            + 2 * self.cold_direction
            + self.mtu_transport
            + self.approved_load
            + self.route_mutation
            + self.service_stop
            + 2 * self.ec2_reboot
            + self.tailscale_withdrawal
            + self.flow_log_capture
            + self.evidence
        )
        if self.hard_timeout > minimum + self.cleanup:
            return
        # Individual budgets are upper bounds and normally overlap waits, but the
        # hard limit must still leave cleanup a deterministic reservation.
        if self.hard_timeout <= self.cleanup:
            raise E2EError("hard_timeout must exceed the protected cleanup budget")

    def as_dict(self) -> dict[str, int]:
        return {field.name: int(getattr(self, field.name)) for field in dataclasses.fields(self)}


DEFAULT_TIMEOUTS = TimeoutBudgets()


_EXTRA_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
        "[REDACTED_PRIVATE_KEY]",
    ),
)


def redact_runtime_text(value: str) -> str:
    """Apply the appliance redactor plus E2E-specific credential redaction."""

    result = redact(value)
    for pattern, replacement in _EXTRA_SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise DeploymentError(f"{path} must be an object with string keys")
    return cast(Mapping[str, Any], value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"unsupported {extra}")
        raise DeploymentError(f"{path} has the wrong shape: {', '.join(details)}")


@dataclasses.dataclass(frozen=True)
class SSMTarget:
    """One role-bearing workload addressable through regional SSM."""

    site: Site
    role: WorkloadRole
    region: str
    instance_id: str
    private_ip: str
    az_key: str | None = None
    availability_zone: str | None = None
    subnet_id: str | None = None
    cidr: str | None = None
    route_table_id: str | None = None

    def __post_init__(self) -> None:
        if self.site not in SITES:
            raise DeploymentError(f"invalid workload site: {self.site!r}")
        if self.role not in WORKLOAD_ROLES:
            raise DeploymentError(f"invalid workload role: {self.role!r}")
        if not _REGION_RE.fullmatch(self.region):
            raise DeploymentError(f"{self.site}.{self.role}.region is invalid")
        if not _INSTANCE_ID_RE.fullmatch(self.instance_id):
            raise DeploymentError(f"{self.site}.{self.role}.instance_id is invalid")
        try:
            address = ipaddress.ip_address(self.private_ip)
        except ValueError as error:
            raise DeploymentError(f"{self.site}.{self.role}.private_ip is invalid") from error
        if address.version != 4 or address.is_unspecified or address.is_multicast:
            raise DeploymentError(f"{self.site}.{self.role}.private_ip must be a usable IPv4 address")
        object.__setattr__(self, "private_ip", str(address))

        network_values = (self.az_key, self.availability_zone, self.subnet_id, self.cidr, self.route_table_id)
        if any(value is not None for value in network_values) and not all(
            isinstance(value, str) and value for value in network_values
        ):
            raise DeploymentError(f"{self.site}.{self.role} network identity must be complete or omitted")
        if all(value is not None for value in network_values):
            assert self.az_key is not None
            assert self.availability_zone is not None
            assert self.subnet_id is not None
            assert self.cidr is not None
            assert self.route_table_id is not None
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", self.az_key):
                raise DeploymentError(f"{self.site}.{self.role}.az_key is invalid")
            if not self.availability_zone.startswith(self.region) or self.availability_zone == self.region:
                raise DeploymentError(f"{self.site}.{self.role}.availability_zone is outside its region")
            if not _SUBNET_ID_RE.fullmatch(self.subnet_id):
                raise DeploymentError(f"{self.site}.{self.role}.subnet_id is invalid")
            if not _ROUTE_TABLE_ID_RE.fullmatch(self.route_table_id):
                raise DeploymentError(f"{self.site}.{self.role}.route_table_id is invalid")
            try:
                network = ipaddress.ip_network(self.cidr, strict=True)
            except ValueError as error:
                raise DeploymentError(f"{self.site}.{self.role}.cidr is invalid") from error
            if network.version != 4 or address not in network:
                raise DeploymentError(f"{self.site}.{self.role}.private_ip is not contained by its cidr")
            object.__setattr__(self, "cidr", str(network))

    def as_dict(self) -> dict[str, str]:
        result = {
            "region": self.region,
            "instance_id": self.instance_id,
            "private_ip": self.private_ip,
        }
        if self.az_key is not None:
            assert self.availability_zone is not None
            assert self.subnet_id is not None
            assert self.cidr is not None
            assert self.route_table_id is not None
            result.update(
                {
                    "az_key": self.az_key,
                    "availability_zone": self.availability_zone,
                    "subnet_id": self.subnet_id,
                    "cidr": self.cidr,
                    "route_table_id": self.route_table_id,
                }
            )
        return result


@dataclasses.dataclass(frozen=True)
class SiteWorkloads:
    initiator: SSMTarget
    responder: SSMTarget

    def __post_init__(self) -> None:
        if self.initiator.site != self.responder.site:
            raise DeploymentError("site workloads cannot mix west and east targets")
        if self.initiator.role != "initiator" or self.responder.role != "responder":
            raise DeploymentError("site workloads have incorrect role identities")
        if self.initiator.region != self.responder.region:
            raise DeploymentError(f"{self.initiator.site} workloads must share one region")

    def target(self, role: WorkloadRole) -> SSMTarget:
        if role == "initiator":
            return self.initiator
        if role == "responder":
            return self.responder
        raise DeploymentError(f"invalid workload role: {role!r}")

    def as_dict(self) -> dict[str, dict[str, str]]:
        return {
            "initiator": self.initiator.as_dict(),
            "responder": self.responder.as_dict(),
        }


@dataclasses.dataclass(frozen=True)
class Deployment:
    west: SiteWorkloads
    east: SiteWorkloads

    def __post_init__(self) -> None:
        if self.west.initiator.site != "west" or self.east.initiator.site != "east":
            raise DeploymentError("deployment site identities do not match west/east nesting")
        targets = self.targets
        if len({target.instance_id for target in targets}) != len(targets):
            raise DeploymentError("every workload role must have a unique instance_id")
        if len({target.private_ip for target in targets}) != len(targets):
            raise DeploymentError("every workload role must have a unique private_ip")
        if self.west.initiator.region == self.east.initiator.region:
            raise DeploymentError("west and east workloads must be in distinct regions")

    @property
    def targets(self) -> tuple[SSMTarget, ...]:
        return (
            self.west.initiator,
            self.west.responder,
            self.east.initiator,
            self.east.responder,
        )

    def target(self, site: Site, role: WorkloadRole) -> SSMTarget:
        if site == "west":
            return self.west.target(role)
        if site == "east":
            return self.east.target(role)
        raise DeploymentError(f"invalid workload site: {site!r}")

    def as_dict(self) -> dict[str, dict[str, dict[str, str]]]:
        return {"west": self.west.as_dict(), "east": self.east.as_dict()}


def _unwrap_terraform_value(value: Any) -> Any:
    if isinstance(value, Mapping) and "value" in value and set(value).issubset({"value", "type", "sensitive"}):
        return value["value"]
    return value


def _deployment_candidate(document: Mapping[str, Any], output_name: str) -> Any:
    unwrapped = _unwrap_terraform_value(document)
    if isinstance(unwrapped, Mapping) and set(unwrapped) == set(SITES):
        return unwrapped
    if output_name in document:
        return _unwrap_terraform_value(document[output_name])

    candidates: list[Any] = []
    for value in document.values():
        candidate = _unwrap_terraform_value(value)
        if isinstance(candidate, Mapping) and set(candidate) == set(SITES):
            candidates.append(candidate)
    if len(candidates) == 1:
        return candidates[0]
    raise DeploymentError(f"Terraform output does not contain one unambiguous {output_name!r} value")


def parse_deployment_output(
    document: Mapping[str, Any] | str,
    *,
    output_name: str = "workload_instances",
    site_regions: Mapping[str, str] | None = None,
) -> Deployment:
    """Parse Terraform's nested role-aware workload output.

    The accepted value is ``west/east -> initiator/responder -> identity``.
    A region can be carried by each identity, once at its site node, or supplied
    through ``site_regions``.  Terraform's usual ``value/type/sensitive``
    wrapper is accepted, as is the already-unwrapped value.
    """

    if isinstance(document, str):
        try:
            decoded = json.loads(document)
        except json.JSONDecodeError as error:
            raise DeploymentError("Terraform output is not valid JSON") from error
        document = _mapping(decoded, "Terraform output")
    else:
        document = _mapping(document, "Terraform output")

    if not output_name or not isinstance(output_name, str):
        raise DeploymentError("output_name must be a non-empty string")
    if site_regions is not None:
        regions = _mapping(site_regions, "site_regions")
        _exact_keys(regions, set(SITES), "site_regions")
    else:
        regions = {}

    value = _mapping(_deployment_candidate(document, output_name), f"{output_name}.value")
    _exact_keys(value, set(SITES), f"{output_name}.value")
    parsed_sites: dict[Site, SiteWorkloads] = {}

    for site in SITES:
        site_value = _mapping(value[site], f"{output_name}.value.{site}")
        allowed_site_keys = set(WORKLOAD_ROLES) | {"region"}
        if set(site_value) not in (set(WORKLOAD_ROLES), allowed_site_keys):
            missing = sorted(set(WORKLOAD_ROLES) - set(site_value))
            extra = sorted(set(site_value) - allowed_site_keys)
            raise DeploymentError(
                f"{output_name}.value.{site} must contain initiator and responder"
                + (f"; missing {missing}" if missing else "")
                + (f"; unsupported {extra}" if extra else "")
            )
        site_region = site_value.get("region", regions.get(site))
        targets: dict[WorkloadRole, SSMTarget] = {}
        for role in WORKLOAD_ROLES:
            role_value = _mapping(site_value[role], f"{output_name}.value.{site}.{role}")
            network_role_keys = {"az_key", "availability_zone", "subnet_id", "cidr", "route_table_id"}
            allowed_role_keys = {
                "instance_id",
                "private_ip",
                "region",
                "site",
                "role",
            } | network_role_keys
            required_role_keys = {"instance_id", "private_ip"}
            network_keys_present = set(role_value).intersection(network_role_keys)
            if (
                not required_role_keys.issubset(role_value)
                or set(role_value) - allowed_role_keys
                or network_keys_present not in (set(), network_role_keys)
            ):
                missing = sorted(required_role_keys - set(role_value))
                extra = sorted(set(role_value) - allowed_role_keys)
                partial_network = sorted(network_role_keys - network_keys_present) if network_keys_present else []
                raise DeploymentError(
                    f"{output_name}.value.{site}.{role} has the wrong identity shape"
                    + (f"; missing {missing}" if missing else "")
                    + (f"; unsupported {extra}" if extra else "")
                    + (f"; incomplete network identity {partial_network}" if partial_network else "")
                )
            if "site" in role_value and role_value["site"] != site:
                raise DeploymentError(f"{site}.{role}.site contradicts its parent key")
            if "role" in role_value and role_value["role"] != role:
                raise DeploymentError(f"{site}.{role}.role contradicts its parent key")
            role_region = role_value.get("region", site_region)
            if role_region is None and isinstance(role_value.get("availability_zone"), str):
                az_match = re.fullmatch(r"([a-z]{2}(?:-[a-z]+)+-[0-9]+)[a-z]", role_value["availability_zone"])
                if az_match is not None:
                    role_region = az_match.group(1)
            if not isinstance(role_region, str) or not role_region:
                raise DeploymentError(f"{site}.{role}.region is required")
            targets[role] = SSMTarget(
                site=site,
                role=role,
                region=role_region,
                instance_id=str(role_value["instance_id"]),
                private_ip=str(role_value["private_ip"]),
                az_key=str(role_value["az_key"]) if "az_key" in role_value else None,
                availability_zone=(
                    str(role_value["availability_zone"]) if "availability_zone" in role_value else None
                ),
                subnet_id=str(role_value["subnet_id"]) if "subnet_id" in role_value else None,
                cidr=str(role_value["cidr"]) if "cidr" in role_value else None,
                route_table_id=str(role_value["route_table_id"]) if "route_table_id" in role_value else None,
            )
        parsed_sites[site] = SiteWorkloads(targets["initiator"], targets["responder"])

    return Deployment(parsed_sites["west"], parsed_sites["east"])


@dataclasses.dataclass(frozen=True)
class ApplianceTarget:
    site: Site
    region: str
    instance_id: str
    target_group_arn: str
    vpc_id: str

    @property
    def role(self) -> Literal["appliance"]:
        return "appliance"

    def __post_init__(self) -> None:
        if self.site not in SITES or not _REGION_RE.fullmatch(self.region):
            raise DeploymentError("appliance site or region is invalid")
        if not _INSTANCE_ID_RE.fullmatch(self.instance_id):
            raise DeploymentError(f"{self.site} appliance instance_id is invalid")
        target_match = _TARGET_GROUP_ARN_RE.fullmatch(self.target_group_arn)
        if target_match is None or target_match.group(1) != self.region:
            raise DeploymentError(f"{self.site} target group ARN is invalid or regionalized incorrectly")
        if not _VPC_ID_RE.fullmatch(self.vpc_id):
            raise DeploymentError(f"{self.site} VPC ID is invalid")

    def as_dict(self) -> dict[str, str]:
        return {
            "region": self.region,
            "instance_id": self.instance_id,
            "target_group_arn": self.target_group_arn,
            "vpc_id": self.vpc_id,
        }


@dataclasses.dataclass(frozen=True)
class ManagedFlowLog:
    site: Site
    region: str
    flow_log_id: str
    log_group_arn: str

    def __post_init__(self) -> None:
        if self.site not in SITES or not _REGION_RE.fullmatch(self.region):
            raise DeploymentError("managed Flow Log site or region is invalid")
        if not _FLOW_LOG_ID_RE.fullmatch(self.flow_log_id):
            raise DeploymentError(f"{self.site} managed Flow Log ID is invalid")
        match = _LOG_GROUP_ARN_RE.fullmatch(self.log_group_arn)
        if match is None or match.group(1) != self.region:
            raise DeploymentError(f"{self.site} managed Flow Log group ARN is invalid or in the wrong region")

    @property
    def log_group_name(self) -> str:
        match = _LOG_GROUP_ARN_RE.fullmatch(self.log_group_arn)
        assert match is not None
        return match.group(2)

    def as_dict(self) -> dict[str, str]:
        return {
            "region": self.region,
            "flow_log_id": self.flow_log_id,
            "log_group_arn": self.log_group_arn,
        }


@dataclasses.dataclass(frozen=True)
class ApprovedLoadProfile:
    """Immutable thresholds that must be carried by the reviewed saved plan."""

    profile_id: str
    approved_at: str
    safe_inner_mtu: int
    maximum_tcp_mss: int
    sustained_tcp_duration_seconds: int
    minimum_sustained_tcp_bytes: int
    iperf_duration_seconds: int
    minimum_throughput_mbps: float
    concurrent_duration_seconds: int
    concurrent_tcp_flows: int
    concurrent_udp_flows: int
    maximum_udp_loss_percent: float
    maximum_p99_latency_ms: float

    def __post_init__(self) -> None:
        if not _LABEL_RE.fullmatch(self.profile_id):
            raise LoadProfileError("e2e_load_profile.profile_id is invalid")
        try:
            approved = dt.datetime.fromisoformat(self.approved_at.removesuffix("Z") + "+00:00")
        except ValueError as error:
            raise LoadProfileError("e2e_load_profile.approved_at must be UTC RFC3339") from error
        if not self.approved_at.endswith("Z") or approved.tzinfo != dt.timezone.utc:
            raise LoadProfileError("e2e_load_profile.approved_at must be UTC RFC3339")
        integer_bounds = {
            "safe_inner_mtu": (self.safe_inner_mtu, 576, 1500),
            "maximum_tcp_mss": (self.maximum_tcp_mss, 536, 1460),
            "sustained_tcp_duration_seconds": (self.sustained_tcp_duration_seconds, 3, 120),
            "minimum_sustained_tcp_bytes": (self.minimum_sustained_tcp_bytes, 1, 1_000_000_000),
            "iperf_duration_seconds": (self.iperf_duration_seconds, 3, 120),
            "concurrent_duration_seconds": (self.concurrent_duration_seconds, 3, 120),
            "concurrent_tcp_flows": (self.concurrent_tcp_flows, 1, 32),
            "concurrent_udp_flows": (self.concurrent_udp_flows, 1, 32),
        }
        for name, (value, minimum, maximum) in integer_bounds.items():
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise LoadProfileError(f"e2e_load_profile.{name} must be between {minimum} and {maximum}")
        if self.safe_inner_mtu != 1280 or self.maximum_tcp_mss > self.safe_inner_mtu - 40:
            raise LoadProfileError("the reviewed IPv4 path must use MTU 1280 and an MSS no greater than 1240")
        numeric_bounds = {
            "minimum_throughput_mbps": (self.minimum_throughput_mbps, 0.001, 100_000.0),
            "maximum_udp_loss_percent": (self.maximum_udp_loss_percent, 0.0, 100.0),
            "maximum_p99_latency_ms": (self.maximum_p99_latency_ms, 0.001, 60_000.0),
        }
        for name, (value, minimum, maximum) in numeric_bounds.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise LoadProfileError(f"e2e_load_profile.{name} must be finite")
            if not minimum <= float(value) <= maximum:
                raise LoadProfileError(f"e2e_load_profile.{name} must be between {minimum:g} and {maximum:g}")

    def as_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in dataclasses.fields(self)}

    @property
    def sha256(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _parse_load_profile(value: Any) -> ApprovedLoadProfile:
    mapping = _mapping(value, "e2e_load_profile")
    expected = {field.name for field in dataclasses.fields(ApprovedLoadProfile)}
    _exact_keys(mapping, expected, "e2e_load_profile")
    try:
        return ApprovedLoadProfile(**{name: mapping[name] for name in expected})
    except TypeError as error:
        raise LoadProfileError(f"e2e_load_profile has invalid value types: {error}") from None


RemoteTarget: TypeAlias = SSMTarget | ApplianceTarget


@dataclasses.dataclass(frozen=True)
class RuntimeTopology:
    site: Site
    routing_mode: str
    tun_name: str
    underlay_interface: str
    tailscale_iface: str
    gwlb_return_cidrs: tuple[str, ...]
    local_delivery_cidrs: tuple[str, ...]
    remote_tailnet_cidrs: tuple[str, ...]
    routing_table_id: int
    routing_rule_priority: int
    artifact_sha256: str
    artifact_revision: str

    def __post_init__(self) -> None:
        if self.site not in SITES or self.routing_mode != "manage":
            raise DeploymentError(f"{self.site} runtime must use managed routing")
        interfaces = (self.tun_name, self.underlay_interface, self.tailscale_iface)
        if any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value) for value in interfaces):
            raise DeploymentError(f"{self.site} runtime interface identity is invalid")
        if len(set(interfaces)) != 3:
            raise DeploymentError(f"{self.site} runtime interfaces must be distinct")
        if not 1 <= self.routing_table_id <= 252 or self.routing_table_id == 52:
            raise DeploymentError(f"{self.site} runtime routing table is invalid")
        if not 1 <= self.routing_rule_priority <= 32765:
            raise DeploymentError(f"{self.site} runtime routing rule priority is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
            raise DeploymentError(f"{self.site} runtime artifact SHA-256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", self.artifact_revision):
            raise DeploymentError(f"{self.site} runtime artifact revision is invalid")
        for field_name in ("gwlb_return_cidrs", "local_delivery_cidrs", "remote_tailnet_cidrs"):
            values = getattr(self, field_name)
            if not values or len(set(values)) != len(values):
                raise DeploymentError(f"{self.site} runtime {field_name} must be non-empty and unique")
            try:
                networks = tuple(ipaddress.ip_network(value, strict=True) for value in values)
            except ValueError as error:
                raise DeploymentError(f"{self.site} runtime {field_name} contains an invalid CIDR") from error
            if any(network.version != 4 for network in networks):
                raise DeploymentError(f"{self.site} runtime {field_name} must contain IPv4 CIDRs")

    def as_dict(self) -> dict[str, Any]:
        return {
            "routing_mode": self.routing_mode,
            "tun_name": self.tun_name,
            "underlay_interface": self.underlay_interface,
            "tailscale_iface": self.tailscale_iface,
            "gwlb_return_cidrs": list(self.gwlb_return_cidrs),
            "local_delivery_cidrs": list(self.local_delivery_cidrs),
            "remote_tailnet_cidrs": list(self.remote_tailnet_cidrs),
            "routing_table_id": self.routing_table_id,
            "routing_rule_priority": self.routing_rule_priority,
            "artifact_sha256": self.artifact_sha256,
            "artifact_revision": self.artifact_revision,
        }


@dataclasses.dataclass(frozen=True)
class ProtectedDeployment:
    workloads: Deployment
    west_appliance: ApplianceTarget
    east_appliance: ApplianceTarget
    west_runtime: RuntimeTopology
    east_runtime: RuntimeTopology
    endpoint_ids: Mapping[Site, Mapping[str, str]]
    flow_logs: Mapping[Site, ManagedFlowLog]
    load_profile: ApprovedLoadProfile
    output_sha256: str

    def __post_init__(self) -> None:
        appliance_ids = {self.west_appliance.instance_id, self.east_appliance.instance_id}
        workload_ids = {target.instance_id for target in self.workloads.targets}
        if len(appliance_ids) != 2 or appliance_ids.intersection(workload_ids):
            raise DeploymentError("the two appliances and four workloads must have six distinct instance IDs")
        if self.west_appliance.site != "west" or self.east_appliance.site != "east":
            raise DeploymentError("appliance identities do not match west/east nesting")
        if self.west_runtime.site != "west" or self.east_runtime.site != "east":
            raise DeploymentError("runtime identities do not match west/east nesting")
        if self.west_appliance.vpc_id == self.east_appliance.vpc_id:
            raise DeploymentError("west and east appliances must belong to distinct VPCs")
        if self.west_appliance.target_group_arn == self.east_appliance.target_group_arn:
            raise DeploymentError("west and east appliances must use distinct target groups")
        if set(self.flow_logs) != set(SITES) or any(self.flow_logs[site].site != site for site in SITES):
            raise DeploymentError("managed Flow Log identities must contain exactly west and east")
        if len({self.flow_logs[site].flow_log_id for site in SITES}) != 2 or len(
            {self.flow_logs[site].log_group_arn for site in SITES}
        ) != 2:
            raise DeploymentError("managed regional Flow Log IDs and groups must be distinct")
        all_endpoint_ids: list[str] = []
        for site in SITES:
            endpoints = self.endpoint_ids.get(site)
            if not isinstance(endpoints, Mapping) or not endpoints:
                raise DeploymentError(f"{site} endpoint identities are absent")
            if len(set(endpoints.values())) != len(endpoints) or any(
                not isinstance(key, str) or not _VPCE_ID_RE.fullmatch(str(value))
                for key, value in endpoints.items()
            ):
                raise DeploymentError(f"{site} endpoint identities are invalid or duplicated")
            all_endpoint_ids.extend(str(value) for value in endpoints.values())
            initiator = self.workloads.target(site, "initiator")
            if initiator.az_key not in endpoints:
                raise DeploymentError(f"{site} initiator has no same-AZ GWLB endpoint")
        if len(set(all_endpoint_ids)) != len(all_endpoint_ids):
            raise DeploymentError("GWLB endpoint identities must be globally unique")
        if not re.fullmatch(r"[0-9a-f]{64}", self.output_sha256):
            raise DeploymentError("protected deployment output digest is invalid")
        self._validate_directional_roles()

    @property
    def appliances(self) -> tuple[ApplianceTarget, ApplianceTarget]:
        return (self.west_appliance, self.east_appliance)

    def appliance(self, site: Site) -> ApplianceTarget:
        if site == "west":
            return self.west_appliance
        if site == "east":
            return self.east_appliance
        raise DeploymentError(f"invalid appliance site: {site!r}")

    def runtime(self, site: Site) -> RuntimeTopology:
        if site == "west":
            return self.west_runtime
        if site == "east":
            return self.east_runtime
        raise DeploymentError(f"invalid runtime site: {site!r}")

    def _validate_directional_roles(self) -> None:
        cidrs = [target.cidr for target in self.workloads.targets]
        if any(cidr is None for cidr in cidrs) or len(set(cidrs)) != 4:
            raise DeploymentError("live workloads must expose four distinct complete subnet identities")
        networks = [ipaddress.ip_network(cast(str, cidr)) for cidr in cidrs]
        if any(left.overlaps(right) for index, left in enumerate(networks) for right in networks[index + 1 :]):
            raise DeploymentError("directional workload subnet CIDRs must not overlap")
        for site, peer in (("west", "east"), ("east", "west")):
            runtime = self.runtime(cast(Site, site))
            initiator = self.workloads.target(cast(Site, site), "initiator")
            responder = self.workloads.target(cast(Site, site), "responder")
            remote = self.workloads.target(cast(Site, peer), "initiator"), self.workloads.target(
                cast(Site, peer), "responder"
            )
            if runtime.gwlb_return_cidrs != (initiator.cidr,):
                raise DeploymentError(f"{site} GWLB-return role is not exactly its initiator CIDR")
            if runtime.local_delivery_cidrs != (responder.cidr,):
                raise DeploymentError(f"{site} local-delivery role is not exactly its responder CIDR")
            if set(runtime.remote_tailnet_cidrs) != {cast(str, target.cidr) for target in remote}:
                raise DeploymentError(f"{site} remote Tailnet routes do not exactly cover the peer lanes")
        if self.west_runtime.artifact_sha256 != self.east_runtime.artifact_sha256 or (
            self.west_runtime.artifact_revision != self.east_runtime.artifact_revision
        ):
            raise DeploymentError("regional appliances do not use one reviewed artifact identity")

    def as_dict(self) -> dict[str, Any]:
        return {
            "workloads": self.workloads.as_dict(),
            "appliances": {
                "west": self.west_appliance.as_dict(),
                "east": self.east_appliance.as_dict(),
            },
            "runtime": {
                "west": self.west_runtime.as_dict(),
                "east": self.east_runtime.as_dict(),
            },
            "gwlb_endpoint_ids": {
                site: dict(sorted(self.endpoint_ids[site].items())) for site in SITES
            },
            "flow_logs": {site: self.flow_logs[site].as_dict() for site in SITES},
            "load_profile": {**self.load_profile.as_dict(), "sha256": self.load_profile.sha256},
            "output_sha256": self.output_sha256,
        }


def _required_output(document: Mapping[str, Any], name: str) -> Any:
    if name not in document:
        raise DeploymentError(f"protected deployment output is missing {name!r}")
    return _unwrap_terraform_value(document[name])


def _site_string_map(value: Any, path: str, pattern: re.Pattern[str]) -> dict[Site, str]:
    mapping = _mapping(value, path)
    _exact_keys(mapping, set(SITES), path)
    result: dict[Site, str] = {}
    for site in SITES:
        candidate = mapping[site]
        if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
            raise DeploymentError(f"{path}.{site} is invalid")
        result[site] = candidate
    return result


def _parse_runtime(site: Site, value: Any) -> RuntimeTopology:
    mapping = _mapping(value, f"envelope_runtime_config.{site}")
    expected = {
        "routing_mode",
        "tun_name",
        "underlay_interface",
        "tailscale_iface",
        "gwlb_return_cidrs",
        "local_delivery_cidrs",
        "remote_tailnet_cidrs",
        "routing_table_id",
        "routing_rule_priority",
        "artifact_sha256",
        "artifact_revision",
    }
    _exact_keys(mapping, expected, f"envelope_runtime_config.{site}")

    def cidrs(name: str) -> tuple[str, ...]:
        candidate = mapping[name]
        if not isinstance(candidate, list) or not all(isinstance(item, str) for item in candidate):
            raise DeploymentError(f"envelope_runtime_config.{site}.{name} must be a string list")
        return tuple(candidate)

    integer_values = (mapping["routing_table_id"], mapping["routing_rule_priority"])
    if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
        raise DeploymentError(f"envelope_runtime_config.{site} routing identifiers must be integers")
    return RuntimeTopology(
        site=site,
        routing_mode=str(mapping["routing_mode"]),
        tun_name=str(mapping["tun_name"]),
        underlay_interface=str(mapping["underlay_interface"]),
        tailscale_iface=str(mapping["tailscale_iface"]),
        gwlb_return_cidrs=cidrs("gwlb_return_cidrs"),
        local_delivery_cidrs=cidrs("local_delivery_cidrs"),
        remote_tailnet_cidrs=cidrs("remote_tailnet_cidrs"),
        routing_table_id=cast(int, mapping["routing_table_id"]),
        routing_rule_priority=cast(int, mapping["routing_rule_priority"]),
        artifact_sha256=str(mapping["artifact_sha256"]),
        artifact_revision=str(mapping["artifact_revision"]),
    )


def parse_protected_deployment_output(
    document: Mapping[str, Any] | str,
    *,
    site_regions: Mapping[str, str] | None = None,
) -> ProtectedDeployment:
    """Fail closed on the complete output emitted by one protected successful apply."""

    if isinstance(document, str):
        try:
            decoded = json.loads(document)
        except json.JSONDecodeError as error:
            raise DeploymentError("protected deployment output is not valid JSON") from error
        document = _mapping(decoded, "protected deployment output")
    else:
        document = _mapping(document, "protected deployment output")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
    workloads = parse_deployment_output(document, output_name="workload_instances", site_regions=site_regions)
    regions: dict[Site, str] = {
        "west": workloads.west.initiator.region,
        "east": workloads.east.initiator.region,
    }
    instances = _site_string_map(_required_output(document, "instance_ids"), "instance_ids", _INSTANCE_ID_RE)
    vpcs = _site_string_map(_required_output(document, "vpc_ids"), "vpc_ids", _VPC_ID_RE)
    target_groups = _site_string_map(
        _required_output(document, "gwlb_target_group_arns"), "gwlb_target_group_arns", _TARGET_GROUP_ARN_RE
    )
    raw_endpoints = _mapping(_required_output(document, "gwlb_endpoint_ids"), "gwlb_endpoint_ids")
    _exact_keys(raw_endpoints, set(SITES), "gwlb_endpoint_ids")
    endpoints: dict[Site, dict[str, str]] = {}
    for site in SITES:
        site_endpoints = _mapping(raw_endpoints[site], f"gwlb_endpoint_ids.{site}")
        endpoints[site] = {}
        for az_key, endpoint_id in site_endpoints.items():
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", az_key) or not isinstance(
                endpoint_id, str
            ) or not _VPCE_ID_RE.fullmatch(endpoint_id):
                raise DeploymentError(f"gwlb_endpoint_ids.{site} contains an invalid identity")
            endpoints[site][az_key] = endpoint_id
    raw_runtime = _mapping(_required_output(document, "envelope_runtime_config"), "envelope_runtime_config")
    _exact_keys(raw_runtime, set(SITES), "envelope_runtime_config")
    raw_flow_logs = _mapping(_required_output(document, "flow_log_evidence"), "flow_log_evidence")
    _exact_keys(raw_flow_logs, set(SITES), "flow_log_evidence")
    flow_logs: dict[Site, ManagedFlowLog] = {}
    for site in SITES:
        flow_value = _mapping(raw_flow_logs[site], f"flow_log_evidence.{site}")
        _exact_keys(flow_value, {"flow_log_id", "log_group_arn", "region"}, f"flow_log_evidence.{site}")
        if flow_value["region"] != regions[site]:
            raise DeploymentError(f"flow_log_evidence.{site}.region differs from the workload region")
        flow_logs[site] = ManagedFlowLog(
            site,
            str(flow_value["region"]),
            str(flow_value["flow_log_id"]),
            str(flow_value["log_group_arn"]),
        )

    cost = _mapping(_required_output(document, "cost_profile"), "cost_profile")
    counts = _mapping(cost.get("resource_counts"), "cost_profile.resource_counts")
    regional_targets = counts.get("regional_targets")
    if (
        cost.get("profile") != "directional-lane-acceptance"
        or counts.get("appliance_instances") != 2
        or counts.get("workload_instances") != 4
        or counts.get("vpc_flow_logs") != 2
        or counts.get("cloudwatch_log_groups") != 2
        or counts.get("flow_log_iam_roles") != 1
        or regional_targets != {"west": 1, "east": 1}
    ):
        raise DeploymentError(
            "cost profile does not declare exactly two appliances, four workloads, two managed Flow Logs, and one target per site"
        )

    appliances = {
        site: ApplianceTarget(site, regions[site], instances[site], target_groups[site], vpcs[site])
        for site in SITES
    }
    return ProtectedDeployment(
        workloads=workloads,
        west_appliance=appliances["west"],
        east_appliance=appliances["east"],
        west_runtime=_parse_runtime("west", raw_runtime["west"]),
        east_runtime=_parse_runtime("east", raw_runtime["east"]),
        endpoint_ids=endpoints,
        flow_logs=flow_logs,
        load_profile=_parse_load_profile(_required_output(document, "e2e_load_profile")),
        output_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


@dataclasses.dataclass(frozen=True)
class SSMCommand:
    target: RemoteTarget
    commands: tuple[str, ...] = dataclasses.field(repr=False)
    timeout_seconds: int = 60
    comment: str = "Envelope two-region E2E"

    def __post_init__(self) -> None:
        commands = tuple(self.commands)
        if not commands or not all(isinstance(command, str) and command.strip() for command in commands):
            raise SSMError("SSM commands must be a non-empty sequence of non-empty strings")
        if len(commands) > 32 or sum(len(command) for command in commands) > 16_384:
            raise SSMError("SSM command payload exceeds the E2E bound")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= 3600
        ):
            raise SSMError("SSM command timeout_seconds must be between 1 and 3600")
        if not self.comment or len(self.comment) > 100 or any(ord(char) < 32 for char in self.comment):
            raise SSMError("SSM command comment must be 1-100 printable characters")
        if redact_runtime_text(self.comment) != self.comment:
            raise SSMError("SSM command comment must not contain credentials")
        object.__setattr__(self, "commands", commands)


@dataclasses.dataclass(frozen=True)
class SSMResult:
    target: RemoteTarget
    command_id: str
    status: str
    response_code: int
    stdout: str = dataclasses.field(default="", repr=False)
    stderr: str = dataclasses.field(default="", repr=False)

    def __post_init__(self) -> None:
        if not self.command_id or len(self.command_id) > 128:
            raise SSMError("SSM result has an invalid command_id")
        if not self.status or len(self.status) > 64:
            raise SSMError("SSM result has an invalid status")
        if isinstance(self.response_code, bool) or not isinstance(self.response_code, int):
            raise SSMError("SSM result response_code must be an integer")
        object.__setattr__(self, "stdout", redact_runtime_text(str(self.stdout))[:24_000])
        object.__setattr__(self, "stderr", redact_runtime_text(str(self.stderr))[:24_000])

    @property
    def succeeded(self) -> bool:
        return self.status == "Success" and self.response_code == 0

    def summary(self) -> dict[str, Any]:
        return {
            "site": self.target.site,
            "role": self.target.role,
            "command_id": self.command_id,
            "status": self.status,
            "response_code": self.response_code,
        }


class AWSJSON(Protocol):
    def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]: ...


_SSM_PENDING_STATUSES = {"Pending", "InProgress", "Delayed", "Cancelling"}
_SSM_TERMINAL_STATUSES = {
    "Success",
    "Cancelled",
    "TimedOut",
    "Failed",
    "Delivery Timed Out",
    "Execution Timed Out",
    "Undeliverable",
    "Terminated",
    "InvalidPlatform",
    "AccessDenied",
}


def _invocation_does_not_exist(error: BaseException) -> bool:
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        error_value = response.get("Error")
        if isinstance(error_value, Mapping) and error_value.get("Code") == "InvocationDoesNotExist":
            return True
    raw_stderr = getattr(error, "raw_stderr", "")
    text = f"{type(error).__name__} {error} {raw_stderr}".lower()
    return "invocationdoesnotexist" in text or "invocation does not exist" in text


def _bounded_call(call: Callable[[], dict[str, Any]], timeout_seconds: float, operation: str) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise SSMTimeout(f"{operation} has no time remaining")
    outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            outcome.put((True, call()))
        except BaseException as error:  # The caller re-raises only on its controlling thread.
            outcome.put((False, error))

    thread = threading.Thread(target=invoke, name="envelope-e2e-aws-call", daemon=True)
    thread.start()
    try:
        ok, value = outcome.get(timeout=timeout_seconds)
    except queue.Empty as error:
        raise SSMTimeout(f"{operation} exceeded {timeout_seconds:g} seconds") from error
    if not ok:
        assert isinstance(value, BaseException)
        raise value
    if not isinstance(value, dict):
        raise SSMError(f"{operation} returned a non-object response")
    return value


class SSMRunner:
    """Bounded SSM send/poll/cancel operations over a fakeable AWSJSON API."""

    def __init__(
        self,
        aws: AWSJSON | AwsCLI,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = 0.5,
        api_timeout_seconds: float = 10.0,
    ):
        if poll_interval_seconds <= 0 or api_timeout_seconds <= 0:
            raise SSMError("SSM polling and API timeouts must be positive")
        self.aws = aws
        self.clock = clock
        self.sleep = sleep
        self.poll_interval_seconds = poll_interval_seconds
        self.api_timeout_seconds = api_timeout_seconds

    def send(self, command: SSMCommand, *, timeout_seconds: float = 10.0) -> str:
        execution_timeout = max(1, min(command.timeout_seconds, 3600))
        parameters = json.dumps(
            {"commands": list(command.commands), "executionTimeout": [str(execution_timeout)]},
            sort_keys=True,
            separators=(",", ":"),
        )
        args = [
            "ssm",
            "send-command",
            "--document-name",
            "AWS-RunShellScript",
            "--instance-ids",
            command.target.instance_id,
            "--timeout-seconds",
            str(max(30, min(command.timeout_seconds, 3600))),
            "--comment",
            command.comment,
            "--parameters",
            parameters,
        ]
        try:
            response = _bounded_call(
                lambda: self.aws.json(args, region=command.target.region),
                min(timeout_seconds, self.api_timeout_seconds),
                "SSM send-command",
            )
        except SSMTimeout:
            raise
        except BaseException as error:
            raise SSMError(redact_runtime_text(f"SSM send-command failed: {error}")) from None
        command_value = response.get("Command")
        command_id = command_value.get("CommandId") if isinstance(command_value, Mapping) else None
        if not isinstance(command_id, str) or not command_id or len(command_id) > 128:
            raise SSMError("SSM send-command response omitted a valid CommandId")
        return command_id

    def _poll(self, target: RemoteTarget, command_id: str, *, timeout_seconds: float) -> SSMResult:
        if timeout_seconds <= 0:
            raise SSMTimeout("SSM wait timeout must be positive")
        deadline = self.clock() + timeout_seconds
        args = [
            "ssm",
            "get-command-invocation",
            "--command-id",
            command_id,
            "--instance-id",
            target.instance_id,
        ]
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise SSMTimeout(f"SSM command {command_id} did not finish within {timeout_seconds:g} seconds")
            try:
                response = _bounded_call(
                    lambda: self.aws.json(args, region=target.region),
                    min(remaining, self.api_timeout_seconds),
                    "SSM get-command-invocation",
                )
            except SSMTimeout:
                raise
            except BaseException as error:
                if not _invocation_does_not_exist(error):
                    raise SSMError(redact_runtime_text(f"SSM invocation polling failed: {error}")) from None
            else:
                status = response.get("Status")
                if not isinstance(status, str):
                    raise SSMError("SSM invocation response omitted Status")
                if status in _SSM_TERMINAL_STATUSES:
                    response_code = response.get("ResponseCode", -1)
                    if isinstance(response_code, bool) or not isinstance(response_code, int):
                        raise SSMError("SSM invocation response has a non-integer ResponseCode")
                    return SSMResult(
                        target=target,
                        command_id=command_id,
                        status=status,
                        response_code=response_code,
                        stdout=str(response.get("StandardOutputContent", "")),
                        stderr=str(response.get("StandardErrorContent", "")),
                    )
                if status not in _SSM_PENDING_STATUSES:
                    raise SSMError(f"SSM invocation returned unknown status {redact_runtime_text(status)!r}")
            remaining = deadline - self.clock()
            if remaining <= 0:
                continue
            self.sleep(min(self.poll_interval_seconds, remaining))

    def wait(
        self,
        target: RemoteTarget,
        command_id: str,
        *,
        timeout_seconds: float,
        cancel_timeout_seconds: float = 5.0,
    ) -> SSMResult:
        try:
            return self._poll(target, command_id, timeout_seconds=timeout_seconds)
        except BaseException as wait_error:
            cancellation_request = "requested"
            try:
                if not self.cancel(target, command_id, timeout_seconds=cancel_timeout_seconds):
                    cancellation_request = "not accepted"
            except BaseException as cancel_error:
                cancellation_request = redact_runtime_text(f"request failed: {cancel_error}")
            try:
                terminal = self._poll(target, command_id, timeout_seconds=cancel_timeout_seconds)
                cancellation = (
                    f"cancellation {cancellation_request}; terminal state {terminal.status} confirmed for {command_id}"
                )
            except BaseException as confirmation_error:
                cancellation = redact_runtime_text(
                    f"cancellation {cancellation_request}; terminal state unconfirmed for {command_id}: "
                    f"{confirmation_error}"
                )
            message = f"{redact_runtime_text(str(wait_error))}; {cancellation}"
            if isinstance(wait_error, SSMTimeout):
                raise SSMTimeout(message) from None
            if isinstance(wait_error, SSMError):
                raise SSMError(message) from None
            if hasattr(wait_error, "add_note"):
                wait_error.add_note(cancellation)
            raise

    def cancel(self, target: RemoteTarget, command_id: str, *, timeout_seconds: float = 5.0) -> bool:
        args = ["ssm", "cancel-command", "--command-id", command_id, "--instance-ids", target.instance_id]
        try:
            _bounded_call(
                lambda: self.aws.json(args, region=target.region),
                min(timeout_seconds, self.api_timeout_seconds),
                "SSM cancel-command",
            )
        except SSMTimeout:
            raise
        except BaseException as error:
            if _invocation_does_not_exist(error):
                return False
            raise SSMError(redact_runtime_text(f"SSM cancel-command failed: {error}")) from None
        return True

    def execute(
        self,
        command: SSMCommand,
        *,
        send_timeout_seconds: float = 10.0,
        wait_timeout_seconds: float | None = None,
        cancel_timeout_seconds: float = 5.0,
    ) -> SSMResult:
        command_id = self.send(command, timeout_seconds=send_timeout_seconds)
        wait_timeout = wait_timeout_seconds if wait_timeout_seconds is not None else command.timeout_seconds + 15.0
        return self.wait(
            command.target,
            command_id,
            timeout_seconds=wait_timeout,
            cancel_timeout_seconds=cancel_timeout_seconds,
        )

    run = execute


@dataclasses.dataclass(frozen=True)
class ProcessGeneration:
    process: str
    ordinal: int

    def __post_init__(self) -> None:
        if not _PROCESS_RE.fullmatch(self.process):
            raise E2EError("process generation name must be a lowercase slug")
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or not 1 <= self.ordinal <= 9999:
            raise E2EError("process generation ordinal must be between 1 and 9999")

    @property
    def label(self) -> str:
        return f"{self.process}-g{self.ordinal:04d}"


@dataclasses.dataclass(frozen=True)
class FlowRecord:
    flow_id: str
    ordinal: int
    protocol: ProtocolName
    source: SSMTarget
    destination: SSMTarget
    source_port: int | None
    destination_port: int | None
    process_generation: str
    purpose: str = "probe"
    expected_result: Literal["success", "mtu-drop"] = "success"

    def __post_init__(self) -> None:
        if not isinstance(self.flow_id, str) or not _LABEL_RE.fullmatch(self.flow_id):
            raise E2EError("flow_id must be a bounded path-safe label")
        if self.protocol not in PROTOCOLS:
            raise E2EError(f"unsupported flow protocol: {self.protocol!r}")
        if self.protocol == "icmp":
            if self.source_port is not None or self.destination_port is not None:
                raise E2EError("ICMP flows cannot carry synthetic transport ports")
        elif (
            isinstance(self.source_port, bool)
            or not isinstance(self.source_port, int)
            or not 1024 <= self.source_port <= 65_535
            or isinstance(self.destination_port, bool)
            or not isinstance(self.destination_port, int)
            or not 1 <= self.destination_port <= 65_535
        ):
            raise E2EError("TCP/UDP flows require valid source and destination ports")
        if not _LABEL_RE.fullmatch(self.purpose):
            raise E2EError("flow purpose must be a bounded label")
        if self.expected_result not in {"success", "mtu-drop"}:
            raise E2EError("flow expected_result is invalid")

    def tuple_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "source_ip": self.source.private_ip,
            "destination_ip": self.destination.private_ip,
            "protocol": self.protocol,
        }
        if self.protocol != "icmp":
            value["source_port"] = self.source_port
            value["destination_port"] = self.destination_port
        return value

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "source": {
                "site": self.source.site,
                "role": self.source.role,
                "private_ip": self.source.private_ip,
            },
            "destination": {
                "site": self.destination.site,
                "role": self.destination.role,
                "private_ip": self.destination.private_ip,
            },
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "process_generation": self.process_generation,
            "purpose": self.purpose,
            "expected_result": self.expected_result,
        }


class FlowLedger:
    """Allocate deterministic flow IDs, source ports, and generation labels."""

    def __init__(self, run_id: str, *, first_source_port: int = 30_000, last_source_port: int = 60_999):
        if not _RUN_ID_RE.fullmatch(run_id):
            raise E2EError("flow ledger run_id must be a lowercase deployment slug")
        if not 1024 <= first_source_port <= last_source_port <= 65_535:
            raise E2EError("flow ledger source-port range is invalid")
        self.run_id = run_id
        self.first_source_port = first_source_port
        self.last_source_port = last_source_port
        self._generation_counts: dict[str, int] = {}
        self._records: list[FlowRecord] = []
        self._next_source_port = first_source_port

    @property
    def records(self) -> tuple[FlowRecord, ...]:
        return tuple(self._records)

    def begin_generation(self, process: str) -> ProcessGeneration:
        ordinal = self._generation_counts.get(process, 0) + 1
        generation = ProcessGeneration(process, ordinal)
        self._generation_counts[process] = ordinal
        return generation

    def allocate(
        self,
        protocol: ProtocolName,
        source: SSMTarget,
        destination: SSMTarget,
        *,
        destination_port: int | None,
        generation: ProcessGeneration | str,
        purpose: str = "probe",
        expected_result: Literal["success", "mtu-drop"] = "success",
    ) -> FlowRecord:
        if protocol not in PROTOCOLS:
            raise E2EError(f"unsupported flow protocol: {protocol!r}")
        if source == destination:
            raise E2EError("flow source and destination must differ")
        if protocol == "icmp":
            if destination_port is not None:
                raise E2EError("ICMP flow allocation cannot specify a destination port")
            source_port: int | None = None
        else:
            if isinstance(destination_port, bool) or not isinstance(destination_port, int) or not 1 <= destination_port <= 65_535:
                raise E2EError("transport flow destination_port must be between 1 and 65535")
            source_port = self._next_source_port
            if source_port > self.last_source_port:
                raise E2EError("flow ledger exhausted its source-port range")
            self._next_source_port += 1
        generation_label = generation.label if isinstance(generation, ProcessGeneration) else generation
        if not isinstance(generation_label, str) or not _LABEL_RE.fullmatch(generation_label):
            raise E2EError("flow process_generation label is invalid")
        ordinal = len(self._records) + 1
        record = FlowRecord(
            flow_id=f"{self.run_id}-{protocol}-{ordinal:04d}",
            ordinal=ordinal,
            protocol=protocol,
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            process_generation=generation_label,
            purpose=purpose,
            expected_result=expected_result,
        )
        self._records.append(record)
        return record

    allocate_flow = allocate


WIRE_INSPECTOR_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import ipaddress
import json
import pathlib
import struct
import sys

AWS_CLASS = 0x0108

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def transport_summary(protocol, payload, source, destination):
    if protocol == 1:
        if len(payload) < 8:
            raise RuntimeError("truncated ICMP header")
        if checksum(payload) != 0:
            raise RuntimeError("invalid ICMP checksum")
        return {"protocol": "icmp", "type": payload[0], "code": payload[1],
                "identifier": struct.unpack("!H", payload[4:6])[0],
                "sequence": struct.unpack("!H", payload[6:8])[0],
                "checksum": "valid",
                "payload_bytes": len(payload) - 8,
                "payload_sha256": hashlib.sha256(payload[8:]).hexdigest()}
    if protocol == 6:
        if len(payload) < 20:
            raise RuntimeError("truncated TCP header")
        source_port, destination_port = struct.unpack("!HH", payload[:4])
        header_length = (payload[12] >> 4) * 4
        if header_length < 20 or header_length > len(payload):
            raise RuntimeError("invalid TCP header length")
        flags = payload[13]
        mss = None
        offset = 20
        while offset < header_length:
            kind = payload[offset]
            if kind == 0:
                break
            if kind == 1:
                offset += 1
                continue
            if offset + 2 > header_length:
                raise RuntimeError("truncated TCP option")
            length = payload[offset + 1]
            if length < 2 or offset + length > header_length:
                raise RuntimeError("invalid TCP option length")
            if kind == 2:
                if length != 4 or mss is not None:
                    raise RuntimeError("invalid TCP MSS option")
                mss = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += length
        return {"protocol": "tcp", "source_port": source_port,
                "destination_port": destination_port, "flags": flags, "mss": mss}
    if protocol == 17:
        if len(payload) < 8:
            raise RuntimeError("truncated UDP header")
        source_port, destination_port, length, observed = struct.unpack("!HHHH", payload[:8])
        if length != len(payload) or length < 8:
            raise RuntimeError("invalid UDP length")
        pseudo = source + destination + b"\0\x11" + struct.pack("!H", length)
        if observed == 0:
            status = "not-present"
        elif checksum(pseudo + payload) == 0:
            status = "valid"
        else:
            raise RuntimeError("invalid UDP checksum")
        return {"protocol": "udp", "source_port": source_port,
                "destination_port": destination_port, "length": length,
                "checksum": status}
    return {"protocol": str(protocol)}

def ipv4(data, require_checksum=True):
    if len(data) < 20 or data[0] >> 4 != 4:
        raise RuntimeError("invalid IPv4 header")
    header_length = (data[0] & 15) * 4
    if header_length < 20 or header_length > len(data):
        raise RuntimeError("invalid IPv4 header length")
    total_length = struct.unpack("!H", data[2:4])[0]
    if total_length < header_length or total_length > len(data):
        raise RuntimeError("invalid IPv4 total length")
    header = data[:header_length]
    if require_checksum and checksum(header) != 0:
        raise RuntimeError("invalid IPv4 checksum")
    fragment = struct.unpack("!H", data[6:8])[0]
    if fragment & 0x3fff:
        raise RuntimeError("fragmented IPv4 packet")
    source = data[12:16]
    destination = data[16:20]
    protocol = data[9]
    payload = data[header_length:total_length]
    return ({"source_ip": str(ipaddress.ip_address(source)),
             "destination_ip": str(ipaddress.ip_address(destination)),
             "header_length": header_length, "total_length": total_length,
             "checksum": "valid", "transport": transport_summary(protocol, payload, source, destination)},
            payload)

def geneve(payload):
    if len(payload) < 8 or payload[0] >> 6 != 0:
        raise RuntimeError("invalid GENEVE base header")
    options_length = (payload[0] & 0x3f) * 4
    header_length = 8 + options_length
    if header_length > len(payload) or payload[7] != 0:
        raise RuntimeError("invalid GENEVE header length or reserved byte")
    if payload[1] & 0x3f:
        raise RuntimeError("invalid GENEVE reserved flags")
    protocol = struct.unpack("!H", payload[2:4])[0]
    vni = int.from_bytes(payload[4:7], "big")
    if protocol != 0x0800 or vni != 0 or payload[1] & 0x80:
        raise RuntimeError("invalid AWS GENEVE protocol, VNI, or OAM bit")
    options = payload[8:header_length]
    values = []
    cookie = None
    critical = False
    counts = {1: 0, 2: 0, 3: 0}
    offset = 0
    while offset < len(options):
        if len(options) - offset < 4:
            raise RuntimeError("truncated GENEVE option")
        option_class = struct.unpack("!H", options[offset:offset + 2])[0]
        raw_type = options[offset + 2]
        length_byte = options[offset + 3]
        length = (length_byte & 0x1f) * 4
        end = offset + 4 + length
        if length_byte >> 5 or end > len(options):
            raise RuntimeError("invalid GENEVE option reserved bits or length")
        option_type = raw_type & 0x7f
        is_critical = bool(raw_type & 0x80)
        critical = critical or is_critical
        data = options[offset + 4:end]
        if is_critical and not (option_class == AWS_CLASS and option_type in counts):
            raise RuntimeError("unknown critical GENEVE option")
        if option_class == AWS_CLASS and option_type in counts:
            counts[option_type] += 1
            expected = {1: 8, 2: 8, 3: 4}[option_type]
            if length != expected:
                raise RuntimeError("invalid AWS GENEVE option length")
            if option_type == 3:
                cookie = data
        values.append({"class": option_class, "type": option_type,
                       "critical": is_critical, "length": length,
                       "data_sha256": hashlib.sha256(data).hexdigest()})
        offset = end
    if bool(payload[1] & 0x40) != critical or counts[3] != 1 or counts[1] > 1 or counts[2] > 1:
        raise RuntimeError("invalid AWS GENEVE option criticality or cardinality")
    inner, _ = ipv4(payload[header_length:])
    return {"vni": vni, "protocol": "ipv4", "oam": False,
            "options_length": options_length,
            "options_sha256": hashlib.sha256(options).hexdigest(),
            "flow_cookie_sha256": hashlib.sha256(cookie).hexdigest(),
            "ordered_options": values, "inner": inner}

def frame_payload(frame, link_type):
    if link_type == 1:
        if len(frame) < 14:
            raise RuntimeError("truncated Ethernet frame")
        offset = 14
        protocol = struct.unpack("!H", frame[12:14])[0]
        while protocol in (0x8100, 0x88a8):
            if len(frame) < offset + 4:
                raise RuntimeError("truncated VLAN header")
            protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if protocol != 0x0800:
            return None
        return frame[offset:]
    if link_type == 101:
        return frame
    if link_type == 113:
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        return frame[16:]
    if link_type == 276:
        if len(frame) < 20 or struct.unpack("!H", frame[:2])[0] != 0x0800:
            return None
        return frame[20:]
    raise RuntimeError("unsupported pcap link type")

def inspect_frame(frame, link_type):
    payload = frame_payload(frame, link_type)
    if payload is None:
        return None
    outer, transport_payload = ipv4(payload)
    summary = {"frame_sha256": hashlib.sha256(frame).hexdigest(),
               "captured_length": len(frame), "inner": outer}
    transport = outer["transport"]
    if transport.get("protocol") == "udp" and (transport.get("source_port") == 6081 or transport.get("destination_port") == 6081):
        summary = {"frame_sha256": summary["frame_sha256"],
                   "captured_length": len(frame), "outer": outer,
                   "geneve": geneve(transport_payload[8:])}
    return summary

def parse_pcap_bytes(data):
    if len(data) < 24:
        raise RuntimeError("truncated pcap header")
    magics = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    endian = magics.get(data[:4])
    if endian is None:
        raise RuntimeError("unsupported pcap magic")
    _magic, major, minor, _zone, _sig, snaplen, link_type = struct.unpack(endian + "IHHIIII", data[:24])
    if (major, minor) != (2, 4) or not 64 <= snaplen <= 262144:
        raise RuntimeError("invalid pcap global header")
    frames = []
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise RuntimeError("truncated pcap record header")
        _sec, _fraction, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if captured > snaplen or captured > original or offset + captured > len(data):
            raise RuntimeError("invalid pcap record length")
        value = inspect_frame(data[offset:offset + captured], link_type)
        if value is not None:
            frames.append(value)
        offset += captured
        if len(frames) > 512:
            raise RuntimeError("pcap frame bound exceeded")
    return {"file_sha256": hashlib.sha256(data).hexdigest(), "frame_count": len(frames),
            "link_type": link_type, "frames": frames, "success": True}

def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: inspector PCAP")
    data = pathlib.Path(sys.argv[1]).read_bytes()
    if len(data) > 8 * 1024 * 1024:
        raise RuntimeError("pcap size bound exceeded")
    print(json.dumps(parse_pcap_bytes(data), sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"error": str(error), "success": False}, sort_keys=True))
        raise SystemExit(2)
'''

_WIRE_INSPECTOR_NAMESPACE: dict[str, Any] = {"__name__": "envelope_e2e_wire_inspector"}
exec(compile(WIRE_INSPECTOR_SOURCE, "<wire-inspector>", "exec"), _WIRE_INSPECTOR_NAMESPACE)


def parse_packet_capture(data: bytes) -> dict[str, Any]:
    """Parse bounded pcap bytes into hashes and protocol field summaries only."""

    if not isinstance(data, bytes):
        raise WireAssertionError("packet capture input must be bytes")
    try:
        value = _WIRE_INSPECTOR_NAMESPACE["parse_pcap_bytes"](data)
    except (KeyError, RuntimeError, ValueError, struct.error) as error:
        raise WireAssertionError(f"packet capture validation failed: {error}") from None
    if not isinstance(value, dict):
        raise WireAssertionError("packet capture parser returned an invalid summary")
    return value


def _captured_inner(frame: Mapping[str, Any]) -> Mapping[str, Any] | None:
    geneve_value = frame.get("geneve")
    if isinstance(geneve_value, Mapping) and isinstance(geneve_value.get("inner"), Mapping):
        return cast(Mapping[str, Any], geneve_value["inner"])
    inner = frame.get("inner")
    return cast(Mapping[str, Any], inner) if isinstance(inner, Mapping) else None


def _capture_matches_flow(frame: Mapping[str, Any], flow: FlowRecord, *, reverse: bool) -> bool:
    inner = _captured_inner(frame)
    if inner is None or not isinstance(inner.get("transport"), Mapping):
        return False
    source_ip = flow.destination.private_ip if reverse else flow.source.private_ip
    destination_ip = flow.source.private_ip if reverse else flow.destination.private_ip
    transport = cast(Mapping[str, Any], inner["transport"])
    if (
        inner.get("source_ip") != source_ip
        or inner.get("destination_ip") != destination_ip
        or transport.get("protocol") != flow.protocol
    ):
        return False
    if flow.protocol == "icmp":
        return transport.get("type") == (0 if reverse else 8) and transport.get("code") == 0
    expected_source = flow.destination_port if reverse else flow.source_port
    expected_destination = flow.source_port if reverse else flow.destination_port
    return (
        transport.get("source_port") == expected_source
        and transport.get("destination_port") == expected_destination
    )


def assert_directional_wire_captures(
    source_site: Site,
    flows: Sequence[FlowRecord],
    captures: Mapping[str, Any],
    *,
    raw_deleted: bool,
) -> dict[str, Any]:
    """Assert the directional GWLB return wire contract from sanitized captures."""

    destination_site = _opposite(source_site)
    if set(captures) != set(SITES) or not raw_deleted:
        raise WireAssertionError("directional capture set is incomplete or raw capture deletion was not proven")
    expected_interfaces = {"underlay", "envelope0", "tailscale0"}
    normalized: dict[Site, dict[str, Mapping[str, Any]]] = {}
    interface_evidence: list[dict[str, Any]] = []
    for site in SITES:
        site_value = captures.get(site)
        if not isinstance(site_value, Mapping) or set(site_value) != expected_interfaces:
            raise WireAssertionError(f"{site} capture does not cover underlay, envelope0, and tailscale0")
        normalized[site] = {}
        for interface in sorted(expected_interfaces):
            value = site_value[interface]
            if (
                not isinstance(value, Mapping)
                or value.get("success") is not True
                or not isinstance(value.get("file_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", str(value.get("file_sha256"))) is None
                or not isinstance(value.get("frames"), list)
                or value.get("frame_count") != len(value["frames"])
            ):
                raise WireAssertionError(f"{site} {interface} capture summary is invalid")
            normalized[site][interface] = cast(Mapping[str, Any], value)
            interface_evidence.append(
                {
                    "site": site,
                    "interface": interface,
                    "file_sha256": value["file_sha256"],
                    "frame_count": value["frame_count"],
                }
            )

    flow_evidence: list[dict[str, Any]] = []
    for flow in flows:
        if flow.source.site != source_site or flow.destination.site != destination_site:
            raise WireAssertionError("directional capture flow has the wrong lane identity")
        source_underlay = cast(list[Any], normalized[source_site]["underlay"]["frames"])
        peer_underlay = cast(list[Any], normalized[destination_site]["underlay"]["frames"])
        forwards = [
            value
            for value in source_underlay
            if isinstance(value, Mapping)
            and isinstance(value.get("geneve"), Mapping)
            and _capture_matches_flow(value, flow, reverse=False)
        ]
        returns = [
            value
            for value in source_underlay
            if isinstance(value, Mapping)
            and isinstance(value.get("geneve"), Mapping)
            and _capture_matches_flow(value, flow, reverse=True)
        ]
        peer_geneve = [
            value
            for value in peer_underlay
            if isinstance(value, Mapping)
            and isinstance(value.get("geneve"), Mapping)
            and (_capture_matches_flow(value, flow, reverse=False) or _capture_matches_flow(value, flow, reverse=True))
        ]
        if not forwards or not returns or peer_geneve:
            raise WireAssertionError(
                f"flow {flow.flow_id} lacks initiating-region GENEVE request/return or crossed the responder GWLB"
            )
        selected: tuple[Mapping[str, Any], Mapping[str, Any]] | None = None
        for forward in forwards:
            for returned in returns:
                forward_geneve = cast(Mapping[str, Any], forward["geneve"])
                return_geneve = cast(Mapping[str, Any], returned["geneve"])
                if (
                    forward_geneve.get("options_sha256") == return_geneve.get("options_sha256")
                    and forward_geneve.get("flow_cookie_sha256") == return_geneve.get("flow_cookie_sha256")
                    and forward_geneve.get("ordered_options") == return_geneve.get("ordered_options")
                ):
                    selected = (forward, returned)
                    break
            if selected is not None:
                break
        if selected is None:
            raise WireAssertionError(f"flow {flow.flow_id} changed ordered AWS options or its flow cookie")
        forward, returned = selected
        forward_outer = forward.get("outer")
        return_outer = returned.get("outer")
        forward_geneve = forward.get("geneve")
        return_geneve = returned.get("geneve")
        if not all(isinstance(value, Mapping) for value in (forward_outer, return_outer, forward_geneve, return_geneve)):
            raise WireAssertionError(f"flow {flow.flow_id} has an incomplete outer packet summary")
        forward_outer = cast(Mapping[str, Any], forward_outer)
        return_outer = cast(Mapping[str, Any], return_outer)
        forward_udp = forward_outer.get("transport")
        return_udp = return_outer.get("transport")
        forward_inner = _captured_inner(forward)
        return_inner = _captured_inner(returned)
        if flow.protocol == "icmp" and (
            not isinstance(forward_inner, Mapping)
            or not isinstance(return_inner, Mapping)
            or not isinstance(forward_inner.get("transport"), Mapping)
            or not isinstance(return_inner.get("transport"), Mapping)
            or forward_inner["transport"].get("identifier") != return_inner["transport"].get("identifier")
            or forward_inner["transport"].get("sequence") != return_inner["transport"].get("sequence")
        ):
            raise WireAssertionError(f"flow {flow.flow_id} changed its ICMP request/reply identity")
        if not isinstance(forward_udp, Mapping) or not isinstance(return_udp, Mapping):
            raise WireAssertionError(f"flow {flow.flow_id} has no independently parsed outer UDP headers")
        if (
            forward_outer.get("checksum") != "valid"
            or return_outer.get("checksum") != "valid"
            or forward_udp.get("checksum") not in {"valid", "not-present"}
            or return_udp.get("checksum") not in {"valid", "not-present"}
            or forward_udp.get("destination_port") != 6081
            or return_udp.get("source_port") != forward_udp.get("source_port")
            or return_udp.get("destination_port") != 6081
            or return_outer.get("source_ip") != forward_outer.get("destination_ip")
            or return_outer.get("destination_ip") != forward_outer.get("source_ip")
            or cast(Mapping[str, Any], forward_geneve).get("vni") != 0
            or cast(Mapping[str, Any], return_geneve).get("vni") != 0
        ):
            raise WireAssertionError(f"flow {flow.flow_id} violates outer IPv4/UDP/GENEVE return orientation")
        path_counts: dict[str, int] = {}
        for site in SITES:
            for interface in ("envelope0", "tailscale0"):
                frames = cast(list[Any], normalized[site][interface]["frames"])
                path_counts[f"{site}:{interface}"] = sum(
                    1
                    for frame in frames
                    if isinstance(frame, Mapping)
                    and (
                        _capture_matches_flow(frame, flow, reverse=False)
                        or _capture_matches_flow(frame, flow, reverse=True)
                    )
                )
        if (
            path_counts[f"{source_site}:envelope0"] < 2
            or path_counts[f"{source_site}:tailscale0"] < 2
            or path_counts[f"{destination_site}:tailscale0"] < 2
            or path_counts[f"{destination_site}:envelope0"] != 0
        ):
            raise WireAssertionError(f"flow {flow.flow_id} does not prove the exact TUN/Tailscale bypass path")
        flow_evidence.append(
            {
                "flow_id": flow.flow_id,
                "outer_ipv4_checksums": "valid",
                "outer_udp_checksums": [forward_udp["checksum"], return_udp["checksum"]],
                "outer_ips_swapped": True,
                "original_gwlb_source_port": forward_udp["source_port"],
                "return_udp_source_port": return_udp["source_port"],
                "return_udp_destination_port": 6081,
                "return_source_port_preserved": True,
                "inner_flow_identity_verified": True,
                "vni": 0,
                "ordered_options_sha256": cast(Mapping[str, Any], forward_geneve)["options_sha256"],
                "flow_cookie_sha256": cast(Mapping[str, Any], forward_geneve)["flow_cookie_sha256"],
                "ordered_options_identical": True,
                "path_packet_counts": path_counts,
                "responder_gwlb_matching_packets": 0,
            }
        )
    return {
        "direction": f"{source_site}-to-{destination_site}",
        "source_site": source_site,
        "destination_site": destination_site,
        "capture_bounded": True,
        "raw_pcaps_deleted": True,
        "raw_pcaps_retained": False,
        "interfaces": interface_evidence,
        "flows": flow_evidence,
    }


@dataclasses.dataclass(frozen=True, order=True)
class MetricSeries:
    name: str
    labels: tuple[tuple[str, str], ...]
    value: float = dataclasses.field(compare=False)

    def label_dict(self) -> dict[str, str]:
        return dict(self.labels)


@dataclasses.dataclass(frozen=True)
class MetricSnapshot:
    generation: str
    samples: tuple[MetricSeries, ...]

    def __post_init__(self) -> None:
        if not _LABEL_RE.fullmatch(self.generation):
            raise MetricError("metric snapshot generation label is invalid")
        identities = [(sample.name, sample.labels) for sample in self.samples]
        if len(set(identities)) != len(identities):
            raise MetricError("metric snapshot contains a duplicate series")

    def select(self, name: str, labels: Mapping[str, str] | None = None) -> tuple[MetricSeries, ...]:
        wanted = dict(labels or {})
        selected = tuple(
            sample
            for sample in self.samples
            if sample.name == name and all(sample.label_dict().get(key) == value for key, value in wanted.items())
        )
        if not selected:
            selector = ",".join(f"{key}={value!r}" for key, value in sorted(wanted.items()))
            raise MetricAssertionError(f"metric {name}{{{selector}}} is absent")
        return selected


def _parse_label_set(value: str, line_number: int) -> tuple[tuple[str, str], ...]:
    labels: dict[str, str] = {}
    index = 0
    while index < len(value):
        match = _LABEL_NAME_RE.match(value, index)
        if match is None:
            raise MetricError(f"invalid Prometheus label name on line {line_number}")
        name = match.group(0)
        index = match.end()
        if index >= len(value) or value[index] != "=":
            raise MetricError(f"missing Prometheus label '=' on line {line_number}")
        index += 1
        if index >= len(value) or value[index] != '"':
            raise MetricError(f"Prometheus label value is not quoted on line {line_number}")
        index += 1
        decoded: list[str] = []
        while index < len(value) and value[index] != '"':
            char = value[index]
            if char == "\\":
                index += 1
                if index >= len(value) or value[index] not in ('\\', '"', "n"):
                    raise MetricError(f"invalid Prometheus label escape on line {line_number}")
                decoded.append("\n" if value[index] == "n" else value[index])
            else:
                decoded.append(char)
            index += 1
        if index >= len(value):
            raise MetricError(f"unterminated Prometheus label on line {line_number}")
        index += 1
        if name in labels:
            raise MetricError(f"duplicate Prometheus label {name!r} on line {line_number}")
        labels[name] = "".join(decoded)
        if index == len(value):
            break
        if value[index] != ",":
            raise MetricError(f"invalid Prometheus label separator on line {line_number}")
        index += 1
        if index == len(value):
            raise MetricError(f"trailing Prometheus label comma on line {line_number}")
    return tuple(sorted(labels.items()))


def _split_sample_line(line: str, line_number: int) -> tuple[str, str, str]:
    name_match = _METRIC_NAME_RE.match(line)
    if name_match is None:
        raise MetricError(f"invalid Prometheus metric name on line {line_number}")
    name = name_match.group(0)
    index = name_match.end()
    labels = ""
    if index < len(line) and line[index] == "{":
        index += 1
        start = index
        quoted = False
        escaped = False
        while index < len(line):
            char = line[index]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "}":
                break
            index += 1
        if index >= len(line) or quoted:
            raise MetricError(f"unterminated Prometheus label set on line {line_number}")
        labels = line[start:index]
        index += 1
    if index >= len(line) or not line[index].isspace():
        raise MetricError(f"Prometheus sample has no value separator on line {line_number}")
    rest = line[index:].strip()
    if not rest:
        raise MetricError(f"Prometheus sample has no value on line {line_number}")
    fields = rest.split()
    if len(fields) > 1 and not (len(fields) == 2 and re.fullmatch(r"[-+]?\d+", fields[1])):
        if "#" not in fields:
            raise MetricError(f"invalid Prometheus sample suffix on line {line_number}")
        fields = fields[: fields.index("#")]
        if len(fields) not in (1, 2) or (len(fields) == 2 and not re.fullmatch(r"[-+]?\d+", fields[1])):
            raise MetricError(f"invalid Prometheus sample suffix on line {line_number}")
    return name, labels, fields[0]


def parse_prometheus_metrics(text: str, *, generation: str) -> MetricSnapshot:
    """Parse Prometheus text exposition into one generation-bound snapshot."""

    samples: list[MetricSeries] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, label_text, value_text = _split_sample_line(line, line_number)
        try:
            value = float(value_text)
        except ValueError as error:
            raise MetricError(f"invalid Prometheus value on line {line_number}") from error
        samples.append(MetricSeries(name, _parse_label_set(label_text, line_number), value))
    return MetricSnapshot(generation, tuple(samples))


parse_prometheus = parse_prometheus_metrics


def metric_delta(
    before: MetricSnapshot,
    after: MetricSnapshot,
    name: str,
    *,
    labels: Mapping[str, str] | None = None,
    allow_decrease: bool = False,
) -> float:
    if before.generation != after.generation:
        raise MetricAssertionError(
            f"metric delta crosses process generation boundary {before.generation!r} -> {after.generation!r}"
        )
    before_values = {(sample.name, sample.labels): sample.value for sample in before.select(name, labels)}
    after_values = {(sample.name, sample.labels): sample.value for sample in after.select(name, labels)}
    if set(before_values) != set(after_values):
        raise MetricAssertionError("metric delta series membership changed between snapshots")
    if not all(math.isfinite(value) for value in (*before_values.values(), *after_values.values())):
        raise MetricAssertionError("metric delta cannot use a non-finite sample")
    differences = {key: after_values[key] - before_values[key] for key in before_values}
    if not allow_decrease and any(value < 0 for value in differences.values()):
        raise MetricAssertionError(f"metric {name} decreased within one process generation")
    delta = sum(differences.values())
    return delta


def assert_metric_delta(
    before: MetricSnapshot,
    after: MetricSnapshot,
    name: str,
    *,
    labels: Mapping[str, str] | None = None,
    expected: float | None = None,
    minimum: float | None = None,
    maximum: float | None = None,
    tolerance: float = 0.0,
    allow_decrease: bool = False,
) -> float:
    if tolerance < 0:
        raise MetricAssertionError("metric delta tolerance cannot be negative")
    delta = metric_delta(before, after, name, labels=labels, allow_decrease=allow_decrease)
    if expected is not None and not math.isclose(delta, expected, rel_tol=0.0, abs_tol=tolerance):
        raise MetricAssertionError(f"metric {name} delta {delta:g} does not equal {expected:g}")
    if minimum is not None and delta + tolerance < minimum:
        raise MetricAssertionError(f"metric {name} delta {delta:g} is below {minimum:g}")
    if maximum is not None and delta - tolerance > maximum:
        raise MetricAssertionError(f"metric {name} delta {delta:g} is above {maximum:g}")
    return delta


_PACKET_METRICS = ("geneve_rx_packets", "geneve_tx_packets", "tun_rx_packets", "tun_tx_packets")
_BYTE_METRICS = ("geneve_rx_bytes", "geneve_tx_bytes")
_SESSION_INTEGRITY_METRICS = (
    "gwlb_missing_contexts_total",
    "gwlb_conflicted_contexts_total",
    "gwlb_context_collisions_total",
    "gwlb_context_evictions_total",
)
_UNEXPECTED_FLOW_METRICS = (
    "decap_errors",
    "encap_errors",
    "drops",
    "geneve_options_validation_errors",
    "gwlb_profile_rejections_total",
    "gwlb_receive_drops_total",
    "gwlb_send_failures_total",
    "gwlb_missing_contexts_total",
    "gwlb_conflicted_contexts_total",
    "gwlb_possible_loops_total",
    "gwlb_unsupported_inner_total",
    "gwlb_context_evictions_total",
    "gwlb_context_collisions_total",
    "gwlb_mtu_drops_total",
)


def assert_flow_metric_contract(
    before: Mapping[Site, MetricSnapshot],
    after: Mapping[Site, MetricSnapshot],
    *,
    initiator_site: Site,
    receiver_sessions: int | None,
    receiver_identity_verified: bool = True,
) -> dict[str, Any]:
    """Assert one lane's packet, byte, session-integrity, and malformed deltas."""

    if set(before) != set(SITES) or set(after) != set(SITES):
        raise MetricAssertionError("flow metrics must contain exactly west and east appliance snapshots")
    if receiver_sessions is not None and receiver_sessions != 1:
        raise MetricAssertionError(f"receiver observed {receiver_sessions} sessions, want exactly one")
    if receiver_identity_verified is not True:
        raise MetricAssertionError("flow did not prove the applicable endpoint/source identity")
    peer_site: Site = "east" if initiator_site == "west" else "west"
    packet_deltas: dict[str, float] = {}
    byte_deltas: dict[str, float] = {}
    for name in _PACKET_METRICS:
        packet_deltas[name] = assert_metric_delta(before[initiator_site], after[initiator_site], name, minimum=1)
        assert_metric_delta(before[peer_site], after[peer_site], name, expected=0)
    for name in _BYTE_METRICS:
        byte_deltas[name] = assert_metric_delta(before[initiator_site], after[initiator_site], name, minimum=1)
        assert_metric_delta(before[peer_site], after[peer_site], name, expected=0)

    unexpected: dict[str, dict[str, float]] = {site: {} for site in SITES}
    for site in SITES:
        for name in _UNEXPECTED_FLOW_METRICS:
            delta = assert_metric_delta(before[site], after[site], name, expected=0)
            unexpected[site][name] = delta
    malformed = {
        site: assert_metric_delta(
            before[site],
            after[site],
            "gwlb_unsupported_inner_total",
            labels={"reason": "malformed"},
            expected=0,
        )
        for site in SITES
    }
    session_metrics = {
        name: assert_metric_delta(before[initiator_site], after[initiator_site], name, expected=0)
        for name in _SESSION_INTEGRITY_METRICS
    }
    return {
        "initiator_site": initiator_site,
        "packet_deltas": packet_deltas,
        "byte_deltas": byte_deltas,
        "session": {
            "receiver_sessions": receiver_sessions,
            "receiver_identity_verified": True,
            "integrity_metric_deltas": session_metrics,
        },
        "malformed_deltas": malformed,
        "unexpected_deltas": unexpected,
        "unexpected_growth": False,
    }


def assert_mtu_drop_metric_contract(
    before: Mapping[Site, MetricSnapshot],
    after: Mapping[Site, MetricSnapshot],
    *,
    initiator_site: Site,
) -> dict[str, Any]:
    """Require the exact generic+specific metric pair for one intentional MTU drop."""

    if set(before) != set(SITES) or set(after) != set(SITES):
        raise MetricAssertionError("MTU metrics must contain exactly west and east snapshots")
    peer_site = _opposite(initiator_site)
    packet_deltas: dict[str, float] = {}
    byte_deltas: dict[str, float] = {}
    for name in _PACKET_METRICS:
        expected = None if name == "geneve_rx_packets" else 0
        packet_deltas[name] = assert_metric_delta(
            before[initiator_site],
            after[initiator_site],
            name,
            minimum=1 if expected is None else None,
            expected=expected,
        )
        assert_metric_delta(before[peer_site], after[peer_site], name, expected=0)
    for name in _BYTE_METRICS:
        expected = None if name == "geneve_rx_bytes" else 0
        byte_deltas[name] = assert_metric_delta(
            before[initiator_site],
            after[initiator_site],
            name,
            minimum=1 if expected is None else None,
            expected=expected,
        )
        assert_metric_delta(before[peer_site], after[peer_site], name, expected=0)
    unexpected: dict[str, dict[str, float]] = {site: {} for site in SITES}
    for site in SITES:
        for name in _UNEXPECTED_FLOW_METRICS:
            expected = 1 if site == initiator_site and name in {"drops", "gwlb_mtu_drops_total"} else 0
            unexpected[site][name] = assert_metric_delta(before[site], after[site], name, expected=expected)
    mtu_specific_delta = assert_metric_delta(
        before[initiator_site],
        after[initiator_site],
        "gwlb_mtu_drops_total",
        labels={"direction": "ingress", "family": "ipv4"},
        expected=1,
    )
    return {
        "initiator_site": initiator_site,
        "packet_deltas": packet_deltas,
        "byte_deltas": byte_deltas,
        "session": {
            "receiver_sessions": 0,
            "receiver_identity_verified": True,
            "integrity_metric_deltas": {
                name: unexpected[initiator_site][name] for name in _SESSION_INTEGRITY_METRICS
            },
        },
        "malformed_deltas": {site: 0 for site in SITES},
        "unexpected_deltas": unexpected,
        "intentional_mtu_drop": {
            "site": initiator_site,
            "generic_drops_delta": unexpected[initiator_site]["drops"],
            "mtu_specific": {
                "metric": "gwlb_mtu_drops_total",
                "delta": mtu_specific_delta,
                "direction": "ingress",
                "family": "ipv4",
            },
        },
        "unexpected_growth": False,
    }


def assert_bidirectional_metric_contract(
    before: Mapping[Site, MetricSnapshot],
    after: Mapping[Site, MetricSnapshot],
) -> dict[str, Any]:
    """Assert expected traffic in both lanes with no integrity/error growth."""

    if set(before) != set(SITES) or set(after) != set(SITES):
        raise MetricAssertionError("bidirectional metrics must contain exactly west and east snapshots")
    packet_deltas = {
        site: {name: assert_metric_delta(before[site], after[site], name, minimum=1) for name in _PACKET_METRICS}
        for site in SITES
    }
    byte_deltas = {
        site: {name: assert_metric_delta(before[site], after[site], name, minimum=1) for name in _BYTE_METRICS}
        for site in SITES
    }
    unexpected = {
        site: {
            name: assert_metric_delta(before[site], after[site], name, expected=0)
            for name in _UNEXPECTED_FLOW_METRICS
        }
        for site in SITES
    }
    return {
        "packet_deltas": packet_deltas,
        "byte_deltas": byte_deltas,
        "unexpected_deltas": unexpected,
        "unexpected_growth": False,
    }


@dataclasses.dataclass(frozen=True)
class MutationInterval:
    start_monotonic_ns: int
    end_monotonic_ns: int
    label: str = "mutation"

    def __post_init__(self) -> None:
        if (
            isinstance(self.start_monotonic_ns, bool)
            or not isinstance(self.start_monotonic_ns, int)
            or isinstance(self.end_monotonic_ns, bool)
            or not isinstance(self.end_monotonic_ns, int)
        ):
            raise StreamAnalysisError("mutation monotonic timestamps must be integers")
        if self.start_monotonic_ns < 0 or self.end_monotonic_ns < self.start_monotonic_ns:
            raise StreamAnalysisError("mutation interval is invalid")
        if not _LABEL_RE.fullmatch(self.label):
            raise StreamAnalysisError("mutation label is invalid")


@dataclasses.dataclass(frozen=True)
class StreamMarker:
    flow_id: str
    connection_id: str
    sequence: int
    sent_monotonic_ns: int
    received_monotonic_ns: int

    @classmethod
    def from_value(cls, value: "StreamMarker | Mapping[str, Any]") -> "StreamMarker":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise StreamAnalysisError("stream marker must be an object")
        required = {
            "flow_id",
            "connection_id",
            "sequence",
            "sent_monotonic_ns",
            "received_monotonic_ns",
        }
        if set(value) != required:
            raise StreamAnalysisError("stream marker has the wrong shape")
        integer_fields = ("sequence", "sent_monotonic_ns", "received_monotonic_ns")
        if any(isinstance(value[field], bool) or not isinstance(value[field], int) for field in integer_fields):
            raise StreamAnalysisError("stream marker has a non-integer sequence or timestamp")
        if not isinstance(value["flow_id"], str) or not isinstance(value["connection_id"], str):
            raise StreamAnalysisError("stream marker identifiers must be strings")
        return cls(
            flow_id=value["flow_id"],
            connection_id=value["connection_id"],
            sequence=value["sequence"],
            sent_monotonic_ns=value["sent_monotonic_ns"],
            received_monotonic_ns=value["received_monotonic_ns"],
        )

    def __post_init__(self) -> None:
        if not _LABEL_RE.fullmatch(self.flow_id) or not _LABEL_RE.fullmatch(self.connection_id):
            raise StreamAnalysisError("stream marker flow_id or connection_id is invalid")
        values = (self.sequence, self.sent_monotonic_ns, self.received_monotonic_ns)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise StreamAnalysisError("stream marker sequence and timestamps must be non-negative integers")
        if self.received_monotonic_ns < self.sent_monotonic_ns:
            raise StreamAnalysisError("stream marker was received before it was sent")


@dataclasses.dataclass(frozen=True)
class LossWindow:
    first_missing_sequence: int
    last_missing_sequence: int
    start_monotonic_ns: int
    end_monotonic_ns: int

    @property
    def duration_ns(self) -> int:
        return self.end_monotonic_ns - self.start_monotonic_ns

    def as_dict(self) -> dict[str, int]:
        return {
            "first_missing_sequence": self.first_missing_sequence,
            "last_missing_sequence": self.last_missing_sequence,
            "start_monotonic_ns": self.start_monotonic_ns,
            "end_monotonic_ns": self.end_monotonic_ns,
            "duration_ns": self.duration_ns,
        }


@dataclasses.dataclass(frozen=True)
class StreamAnalysis:
    flow_id: str
    connection_id: str
    marker_count: int
    first_sequence: int
    last_sequence: int
    missing_sequences: tuple[int, ...]
    loss_windows: tuple[LossWindow, ...]
    mutation: MutationInterval
    maximum_loss_ns: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "connection_id": self.connection_id,
            "marker_count": self.marker_count,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "missing_sequences": list(self.missing_sequences),
            "loss_windows": [window.as_dict() for window in self.loss_windows],
            "mutation": {
                "label": self.mutation.label,
                "start_monotonic_ns": self.mutation.start_monotonic_ns,
                "end_monotonic_ns": self.mutation.end_monotonic_ns,
            },
            "maximum_loss_ns": self.maximum_loss_ns,
        }


def analyze_stream_markers(
    markers: Sequence[StreamMarker | Mapping[str, Any]],
    mutation: MutationInterval,
    *,
    maximum_loss_ns: int,
    expected_first_sequence: int | None = None,
    expected_last_sequence: int | None = None,
) -> StreamAnalysis:
    """Validate continuity on one socket and bound mutation-adjacent loss."""

    if isinstance(maximum_loss_ns, bool) or not isinstance(maximum_loss_ns, int) or maximum_loss_ns < 0:
        raise StreamAnalysisError("maximum_loss_ns must be a non-negative integer")
    parsed = tuple(StreamMarker.from_value(marker) for marker in markers)
    if len(parsed) < 2:
        raise StreamAnalysisError("stream analysis needs at least two markers")
    if len({marker.flow_id for marker in parsed}) != 1:
        raise StreamAnalysisError("stream markers mix flow IDs")
    if len({marker.connection_id for marker in parsed}) != 1:
        raise StreamAnalysisError("stream markers do not use one long-lived socket")
    if expected_first_sequence is not None and parsed[0].sequence != expected_first_sequence:
        raise StreamAnalysisError("stream is missing an unbounded leading sequence")
    if expected_last_sequence is not None and parsed[-1].sequence != expected_last_sequence:
        raise StreamAnalysisError("stream is missing an unbounded trailing sequence")
    if parsed[0].sent_monotonic_ns > mutation.start_monotonic_ns:
        raise StreamAnalysisError("stream has no marker before the mutation interval")
    if parsed[-1].received_monotonic_ns < mutation.end_monotonic_ns:
        raise StreamAnalysisError("stream has no marker after the mutation interval")

    missing: list[int] = []
    windows: list[LossWindow] = []
    for previous, current in zip(parsed, parsed[1:]):
        if current.sequence <= previous.sequence:
            raise StreamAnalysisError("stream marker sequences are not strictly increasing")
        if current.sent_monotonic_ns <= previous.sent_monotonic_ns:
            raise StreamAnalysisError("stream marker send timestamps are not strictly increasing")
        if current.received_monotonic_ns <= previous.received_monotonic_ns:
            raise StreamAnalysisError("stream marker receive timestamps are not strictly increasing")
        if current.sequence == previous.sequence + 1:
            continue
        if current.sequence - previous.sequence > 100_001:
            raise StreamAnalysisError("stream sequence gap exceeds the analysis bound")
        window = LossWindow(
            first_missing_sequence=previous.sequence + 1,
            last_missing_sequence=current.sequence - 1,
            start_monotonic_ns=previous.received_monotonic_ns,
            end_monotonic_ns=current.received_monotonic_ns,
        )
        overlaps_mutation = (
            window.start_monotonic_ns <= mutation.end_monotonic_ns
            and window.end_monotonic_ns >= mutation.start_monotonic_ns
        )
        inside_expanded_interval = (
            window.start_monotonic_ns >= mutation.start_monotonic_ns - maximum_loss_ns
            and window.end_monotonic_ns <= mutation.end_monotonic_ns + maximum_loss_ns
        )
        if not overlaps_mutation or not inside_expanded_interval:
            raise StreamAnalysisError("stream loss occurred outside the declared mutation interval")
        if window.duration_ns > maximum_loss_ns:
            raise StreamAnalysisError(
                f"stream loss window {window.duration_ns}ns exceeds {maximum_loss_ns}ns"
            )
        windows.append(window)
        missing.extend(range(window.first_missing_sequence, window.last_missing_sequence + 1))

    return StreamAnalysis(
        flow_id=parsed[0].flow_id,
        connection_id=parsed[0].connection_id,
        marker_count=len(parsed),
        first_sequence=parsed[0].sequence,
        last_sequence=parsed[-1].sequence,
        missing_sequences=tuple(missing),
        loss_windows=tuple(windows),
        mutation=mutation,
        maximum_loss_ns=maximum_loss_ns,
    )


_RAW_MATERIAL_KEYS = {
    "packet",
    "packets",
    "payload",
    "packet_payload",
    "raw_packet",
    "raw_packet_payload",
    "raw_payload",
    "packet_bytes",
    "pcap",
    "packet_capture",
    "state",
    "terraform_state",
    "tfstate",
    "user_data",
    "userdata",
    "user_data_base64",
}
_CREDENTIAL_KEYS = {
    "access_key",
    "access_key_id",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "secret_access_key",
    "session_token",
    "token",
    "api_token",
    "auth_token",
    "auth_key",
    "authorization",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "oauth_client_secret",
    "tailscale_auth_key",
    "credential",
    "credentials",
    "private_key",
}
_CREDENTIAL_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"(?i)\btskey-[A-Za-z0-9_-]{8,}\b"), "Tailscale key"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), "bearer credential"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "JWT"),
    (re.compile(r"(?i)https?://[^\s/:]+:[^\s/@]+@"), "URL credential"),
    (
        re.compile(
            r"(?i)\b(?:access[_-]?key|secret[_-]?access[_-]?key|client[_-]?secret|session[_-]?token|auth[_-]?key|password)\b\s*[=:]\s*[^\s,;]+"
        ),
        "assigned credential",
    ),
)


def _normalized_key(value: str) -> str:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).replace("-", "_")
    return re.sub(r"_+", "_", snake).lower()


def _is_redacted(value: Any) -> bool:
    return value is None or value == "" or (isinstance(value, str) and value.startswith("[REDACTED"))


def scan_evidence(document: Any) -> list[str]:
    """Return value-free findings for unsafe evidence material."""

    findings: list[str] = []

    def visit(value: Any, path: str, depth: int) -> None:
        if depth > 32:
            findings.append(f"{path}: nesting exceeds 32 levels")
            return
        if isinstance(value, Mapping):
            for key, child in value.items():
                if not isinstance(key, str):
                    findings.append(f"{path}: non-string object key")
                    continue
                normalized = _normalized_key(key)
                child_path = f"{path}.{key}"
                if normalized in _RAW_MATERIAL_KEYS:
                    findings.append(f"{child_path}: raw packet/state/user-data material key is prohibited")
                if normalized in _CREDENTIAL_KEYS and not _is_redacted(child):
                    findings.append(f"{child_path}: credential-bearing key is not redacted")
                visit(child, child_path, depth + 1)
            return
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]", depth + 1)
            return
        if isinstance(value, str) and not _is_redacted(value):
            for pattern, description in _CREDENTIAL_VALUE_PATTERNS:
                if pattern.search(value):
                    findings.append(f"{path}: contains a {description}")
                    break

    visit(document, "$", 0)
    return findings


_EVIDENCE_KEYS = {
    "schema",
    "run_id",
    "generated_at",
    "deployment",
    "flows",
    "assertions",
    "metrics",
    "streams",
    "metadata",
}
_EVIDENCE_REQUIRED_KEYS = {"schema", "run_id", "generated_at", "deployment", "flows", "assertions"}
_LIVE_EVIDENCE_KEYS = {
    "schema",
    "kind",
    "run_id",
    "generated_at",
    "status",
    "deployment",
    "phases",
    "flows",
    "assertions",
    "metrics",
    "streams",
    "topology",
    "probes",
    "wire",
    "transport",
    "load_profile",
    "load",
    "flow_logs",
    "resilience",
    "diagnostics",
    "lifecycle",
    "timeout_budgets",
    "failure",
}


def _validate_generated_at(value: Any) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError("evidence.generated_at must be a UTC RFC3339 timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError("evidence.generated_at must be a UTC RFC3339 timestamp") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise EvidenceError("evidence.generated_at must use UTC")


def _validate_flow_evidence(flows: Any, deployment: Deployment) -> None:
    if not isinstance(flows, list):
        raise EvidenceError("evidence.flows must be a list")
    expected_keys = {
        "flow_id",
        "protocol",
        "source",
        "destination",
        "source_port",
        "destination_port",
        "process_generation",
        "purpose",
        "expected_result",
    }
    flow_ids: set[str] = set()
    source_ports: set[int] = set()
    target_lookup = {(target.site, target.role): target for target in deployment.targets}
    for index, value in enumerate(flows):
        if not isinstance(value, Mapping) or set(value) != expected_keys:
            raise EvidenceError(f"evidence.flows[{index}] has the wrong shape")
        flow_id = value["flow_id"]
        generation = value["process_generation"]
        if not isinstance(flow_id, str) or not _LABEL_RE.fullmatch(flow_id) or flow_id in flow_ids:
            raise EvidenceError(f"evidence.flows[{index}].flow_id is invalid or duplicated")
        if not isinstance(generation, str) or not _LABEL_RE.fullmatch(generation):
            raise EvidenceError(f"evidence.flows[{index}].process_generation is invalid")
        if value["protocol"] not in PROTOCOLS:
            raise EvidenceError(f"evidence.flows[{index}].protocol is invalid")
        protocol = value["protocol"]
        source_port = value["source_port"]
        destination_port = value["destination_port"]
        if protocol == "icmp":
            if source_port is not None or destination_port is not None:
                raise EvidenceError(f"evidence.flows[{index}] gives ICMP synthetic ports")
        else:
            if (
                isinstance(source_port, bool)
                or not isinstance(source_port, int)
                or not 1024 <= source_port <= 65_535
                or source_port in source_ports
            ):
                raise EvidenceError(f"evidence.flows[{index}].source_port is invalid or duplicated")
            if (
                isinstance(destination_port, bool)
                or not isinstance(destination_port, int)
                or not 1 <= destination_port <= 65_535
            ):
                raise EvidenceError(f"evidence.flows[{index}].destination_port is invalid")
            source_ports.add(source_port)
        if not isinstance(value["purpose"], str) or not _LABEL_RE.fullmatch(value["purpose"]):
            raise EvidenceError(f"evidence.flows[{index}].purpose is invalid")
        if value["expected_result"] not in {"success", "mtu-drop"}:
            raise EvidenceError(f"evidence.flows[{index}].expected_result is invalid")
        for endpoint_name in ("source", "destination"):
            endpoint = value[endpoint_name]
            if not isinstance(endpoint, Mapping) or set(endpoint) != {"site", "role", "private_ip"}:
                raise EvidenceError(f"evidence.flows[{index}].{endpoint_name} has the wrong shape")
            target = target_lookup.get((endpoint["site"], endpoint["role"]))
            if target is None or endpoint["private_ip"] != target.private_ip:
                raise EvidenceError(f"evidence.flows[{index}].{endpoint_name} is not a deployment target")
        flow_ids.add(flow_id)


def _validate_assertions(value: Any) -> None:
    if not isinstance(value, list):
        raise EvidenceError("evidence.assertions must be a list")
    names: set[str] = set()
    for index, assertion in enumerate(value):
        if not isinstance(assertion, Mapping) or not {"name", "passed"}.issubset(assertion):
            raise EvidenceError(f"evidence.assertions[{index}] must contain name and passed")
        if set(assertion) - {"name", "passed", "summary"}:
            raise EvidenceError(f"evidence.assertions[{index}] has unsupported keys")
        name = assertion["name"]
        if not isinstance(name, str) or not _LABEL_RE.fullmatch(name) or name in names:
            raise EvidenceError(f"evidence.assertions[{index}].name is invalid or duplicated")
        if not isinstance(assertion["passed"], bool):
            raise EvidenceError(f"evidence.assertions[{index}].passed must be boolean")
        if "summary" in assertion and not isinstance(assertion["summary"], str):
            raise EvidenceError(f"evidence.assertions[{index}].summary must be a string")
        names.add(name)


def _validate_live_evidence(document: Mapping[str, Any]) -> None:
    if set(document) != _LIVE_EVIDENCE_KEYS:
        raise EvidenceError("live evidence has missing or unsupported top-level keys")
    if document.get("schema") != LIVE_EVIDENCE_SCHEMA or document.get("kind") != LIVE_EVIDENCE_KIND:
        raise EvidenceError("live evidence schema or kind is invalid")
    run_id = document.get("run_id")
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("live evidence run_id is invalid")
    _validate_generated_at(document.get("generated_at"))
    if document.get("status") not in {"running", "passed", "failed"}:
        raise EvidenceError("live evidence status is invalid")
    deployment_value = document.get("deployment")
    deployment: Deployment | None = None
    if deployment_value is not None:
        expected_deployment_keys = {
            "workloads",
            "appliances",
            "runtime",
            "gwlb_endpoint_ids",
            "flow_logs",
            "load_profile",
            "output_sha256",
        }
        if not isinstance(deployment_value, Mapping) or set(deployment_value) != expected_deployment_keys:
            raise EvidenceError("live evidence deployment has the wrong shape")
        try:
            deployment = parse_deployment_output(cast(Mapping[str, Any], deployment_value["workloads"]))
        except DeploymentError as error:
            raise EvidenceError(f"live evidence deployment is invalid: {error}") from None
        appliances = deployment_value.get("appliances")
        if not isinstance(appliances, Mapping) or set(appliances) != set(SITES):
            raise EvidenceError("live evidence must identify exactly two appliances")
        parsed_appliances: dict[Site, ApplianceTarget] = {}
        try:
            for site in SITES:
                appliance = _mapping(appliances[site], f"live evidence appliances.{site}")
                _exact_keys(
                    appliance,
                    {"region", "instance_id", "target_group_arn", "vpc_id"},
                    f"live evidence appliances.{site}",
                )
                parsed_appliances[site] = ApplianceTarget(
                    site,
                    str(appliance.get("region", "")),
                    str(appliance.get("instance_id", "")),
                    str(appliance.get("target_group_arn", "")),
                    str(appliance.get("vpc_id", "")),
                )
        except DeploymentError as error:
            raise EvidenceError(f"live evidence appliance identity is invalid: {error}") from None
        appliance_ids = [parsed_appliances[site].instance_id for site in SITES]
        if len(set(appliance_ids + [target.instance_id for target in deployment.targets])) != 6:
            raise EvidenceError("live evidence does not contain six distinct instance identities")
        flow_logs = deployment_value.get("flow_logs")
        if not isinstance(flow_logs, Mapping) or set(flow_logs) != set(SITES):
            raise EvidenceError("live evidence must identify both managed VPC Flow Logs")
        parsed_flow_logs: dict[Site, ManagedFlowLog] = {}
        try:
            for site in SITES:
                value = _mapping(flow_logs[site], f"live evidence flow_logs.{site}")
                _exact_keys(
                    value,
                    {"region", "flow_log_id", "log_group_arn"},
                    f"live evidence flow_logs.{site}",
                )
                parsed_flow_logs[site] = ManagedFlowLog(
                    site,
                    str(value.get("region", "")),
                    str(value.get("flow_log_id", "")),
                    str(value.get("log_group_arn", "")),
                )
        except DeploymentError as error:
            raise EvidenceError(f"live evidence managed Flow Log identity is invalid: {error}") from None
        load_profile = deployment_value.get("load_profile")
        if not isinstance(load_profile, Mapping) or set(load_profile) != {
            *(field.name for field in dataclasses.fields(ApprovedLoadProfile)),
            "sha256",
        }:
            raise EvidenceError("live evidence protected load profile has the wrong shape")
        try:
            parsed_profile = _parse_load_profile(
                {field.name: load_profile[field.name] for field in dataclasses.fields(ApprovedLoadProfile)}
            )
        except (DeploymentError, LoadProfileError) as error:
            raise EvidenceError(f"live evidence protected load profile is invalid: {error}") from None
        if load_profile.get("sha256") != parsed_profile.sha256:
            raise EvidenceError("live evidence protected load profile digest is invalid")
        runtime = deployment_value.get("runtime")
        endpoints = deployment_value.get("gwlb_endpoint_ids")
        if not isinstance(runtime, Mapping) or set(runtime) != set(SITES):
            raise EvidenceError("live evidence runtime identities are incomplete")
        if not isinstance(endpoints, Mapping) or set(endpoints) != set(SITES):
            raise EvidenceError("live evidence GWLB endpoint identities are incomplete")
        try:
            parsed_endpoints = {
                site: dict(_mapping(endpoints[site], f"live evidence gwlb_endpoint_ids.{site}"))
                for site in SITES
            }
            ProtectedDeployment(
                workloads=deployment,
                west_appliance=parsed_appliances["west"],
                east_appliance=parsed_appliances["east"],
                west_runtime=_parse_runtime("west", runtime["west"]),
                east_runtime=_parse_runtime("east", runtime["east"]),
                endpoint_ids=parsed_endpoints,
                flow_logs=parsed_flow_logs,
                load_profile=parsed_profile,
                output_sha256=str(deployment_value.get("output_sha256", "")),
            )
        except (DeploymentError, LoadProfileError) as error:
            raise EvidenceError(f"live evidence protected deployment contract is invalid: {error}") from None
    elif document.get("status") != "failed":
        raise EvidenceError("non-failed live evidence requires a deployment")

    phases = document.get("phases")
    if not isinstance(phases, list):
        raise EvidenceError("live evidence phases must be a list")
    phase_names: set[str] = set()
    for index, phase in enumerate(phases):
        if not isinstance(phase, Mapping) or set(phase) != {
            "name",
            "status",
            "budget_seconds",
            "started_at",
            "finished_at",
            "summary",
        }:
            raise EvidenceError(f"live evidence phases[{index}] has the wrong shape")
        name = phase["name"]
        if name not in {value.value for value in LIVE_PHASES} or name in phase_names:
            raise EvidenceError(f"live evidence phases[{index}] has an invalid or duplicate name")
        if phase["status"] not in {"running", "passed", "failed", "skipped"}:
            raise EvidenceError(f"live evidence phases[{index}] status is invalid")
        budget = phase["budget_seconds"]
        if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 7200:
            raise EvidenceError(f"live evidence phases[{index}] budget is invalid")
        _validate_generated_at(phase["started_at"])
        if phase["finished_at"] is not None:
            _validate_generated_at(phase["finished_at"])
        if not isinstance(phase["summary"], Mapping):
            raise EvidenceError(f"live evidence phases[{index}] summary must be an object")
        phase_names.add(cast(str, name))

    if deployment is not None:
        _validate_flow_evidence(document.get("flows"), deployment)
    elif document.get("flows") != []:
        raise EvidenceError("failed live evidence without deployment cannot contain flows")
    _validate_assertions(document.get("assertions"))
    for key in ("metrics", "streams", "probes", "wire", "transport", "flow_logs", "resilience"):
        if not isinstance(document.get(key), list):
            raise EvidenceError(f"live evidence {key} must be a list")
    for key in ("topology", "load_profile", "load", "diagnostics", "lifecycle", "timeout_budgets"):
        if not isinstance(document.get(key), Mapping):
            raise EvidenceError(f"live evidence {key} must be an object")
    timeout_values = document["timeout_budgets"]
    expected_timeout_keys = {field.name for field in dataclasses.fields(TimeoutBudgets)}
    if set(timeout_values) != expected_timeout_keys:
        raise EvidenceError("live evidence timeout_budgets has the wrong shape")
    try:
        TimeoutBudgets(**{key: timeout_values[key] for key in expected_timeout_keys})
    except (TypeError, E2EError) as error:
        raise EvidenceError(f"live evidence timeout_budgets is invalid: {error}") from None
    failure = document.get("failure")
    if failure is not None and (
        not isinstance(failure, Mapping)
        or set(failure) != {"phase", "category", "message"}
        or not all(isinstance(failure[key], str) for key in failure)
    ):
        raise EvidenceError("live evidence failure has the wrong shape")
    if document.get("status") == "failed" and failure is None:
        raise EvidenceError("failed live evidence requires a redacted failure summary")
    if document.get("status") == "passed" and failure is not None:
        raise EvidenceError("passed live evidence cannot contain a failure")


def _normalize_safe_evidence(document: Mapping[str, Any]) -> dict[str, Any]:
    findings = scan_evidence(document)
    if findings:
        raise EvidenceError("unsafe evidence rejected: " + "; ".join(findings))
    try:
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise EvidenceError("evidence must contain only finite JSON values") from error
    if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
        raise EvidenceError("evidence exceeds the 4 MiB bound")
    return cast(dict[str, Any], normalized)


def validate_evidence(document: Any) -> dict[str, Any]:
    """Validate and return a detached schema-1 core or schema-2 live document."""

    if not isinstance(document, Mapping) or not all(isinstance(key, str) for key in document):
        raise EvidenceError("evidence must be a JSON object")
    if document.get("kind") == LIVE_EVIDENCE_KIND or document.get("schema") == LIVE_EVIDENCE_SCHEMA:
        _validate_live_evidence(document)
        return _normalize_safe_evidence(document)
    actual_keys = set(document)
    if not _EVIDENCE_REQUIRED_KEYS.issubset(actual_keys) or actual_keys - _EVIDENCE_KEYS:
        raise EvidenceError("evidence has missing or unsupported top-level keys")
    if document.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceError(f"evidence.schema must be {EVIDENCE_SCHEMA}")
    run_id = document.get("run_id")
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("evidence.run_id is invalid")
    _validate_generated_at(document.get("generated_at"))
    try:
        deployment = parse_deployment_output(cast(Mapping[str, Any], document["deployment"]))
    except DeploymentError as error:
        raise EvidenceError(f"evidence.deployment is invalid: {error}") from None
    _validate_flow_evidence(document["flows"], deployment)
    _validate_assertions(document["assertions"])
    for key in ("metrics", "streams"):
        if key in document and not isinstance(document[key], list):
            raise EvidenceError(f"evidence.{key} must be a list")
    if "metadata" in document and not isinstance(document["metadata"], Mapping):
        raise EvidenceError("evidence.metadata must be an object")
    return _normalize_safe_evidence(document)


def evidence_document(
    run_id: str,
    deployment: Deployment,
    flows: Iterable[FlowRecord],
    assertions: Iterable[Mapping[str, Any]],
    *,
    generated_at: str | None = None,
    metrics: Iterable[Mapping[str, Any]] = (),
    streams: Iterable[StreamAnalysis | Mapping[str, Any]] = (),
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    stream_values = [stream.as_dict() if isinstance(stream, StreamAnalysis) else dict(stream) for stream in streams]
    document: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "generated_at": timestamp,
        "deployment": deployment.as_dict(),
        "flows": [flow.as_dict() for flow in flows],
        "assertions": [dict(assertion) for assertion in assertions],
        "metrics": [dict(metric) for metric in metrics],
        "streams": stream_values,
    }
    if metadata is not None:
        document["metadata"] = dict(metadata)
    return validate_evidence(document)


def write_evidence(path: pathlib.Path | str, document: Any) -> pathlib.Path:
    """Validate and atomically replace a mode-0600 evidence JSON file."""

    normalized = validate_evidence(document)
    destination = pathlib.Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(normalized, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            directory_fd = -1
        if directory_fd >= 0:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def load_evidence(path: pathlib.Path | str) -> dict[str, Any]:
    source = pathlib.Path(path).expanduser()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read evidence {source}: {error}") from error
    return validate_evidence(document)


def verify_live_evidence(document: Any) -> dict[str, Any]:
    """Strictly verify that a schema-2 bundle proves a complete passing run."""

    normalized = validate_evidence(document)
    if normalized.get("kind") != LIVE_EVIDENCE_KIND:
        raise EvidenceVerificationError("evidence is not an AWS two-region live bundle")
    failures: list[str] = []
    def positive_number(value: Any) -> bool:
        return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value > 0

    def at_least(value: Any, minimum: Any) -> bool:
        return positive_number(value) and isinstance(minimum, (int, float)) and value >= minimum

    def at_most(value: Any, maximum: Any) -> bool:
        return positive_number(value) and isinstance(maximum, (int, float)) and value <= maximum

    def timestamp_epoch(value: str) -> int:
        return int(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())

    if normalized["status"] != "passed":
        failures.append("run status is not passed")
    phases = normalized["phases"]
    actual_phase_names = [phase["name"] for phase in phases]
    expected_phase_names = [phase.value for phase in LIVE_PHASES]
    if actual_phase_names != expected_phase_names:
        failures.append("phase sequence is incomplete or out of order")
    if any(phase["status"] != "passed" or phase["finished_at"] is None for phase in phases):
        failures.append("one or more phases did not pass")
    recorded_budgets = TimeoutBudgets(**normalized["timeout_budgets"])
    if any(
        phase["budget_seconds"] != _phase_budget(Phase(phase["name"]), recorded_budgets)
        for phase in phases
    ):
        failures.append("phase timeout budgets differ from the documented schema")
    if any(assertion["passed"] is not True for assertion in normalized["assertions"]):
        failures.append("one or more acceptance assertions failed")

    deployment_value = normalized.get("deployment")
    topology = normalized["topology"]
    appliance_checks = topology.get("appliance_checks")
    workload_checks = topology.get("workload_checks")
    if (
        topology.get("appliance_count") != 2
        or topology.get("workload_count") != 4
        or topology.get("directional_routes_exact") is not True
        or topology.get("all_hosts_ready") is not True
        or not isinstance(appliance_checks, Mapping)
        or set(appliance_checks) != set(SITES)
        or any(
            not isinstance(appliance_checks[site], Mapping)
            or any(appliance_checks[site].get(gate) is not True for gate in _APPLIANCE_READINESS_GATES)
            for site in SITES
        )
        or not isinstance(workload_checks, Mapping)
        or set(workload_checks) != {f"{site}-{role}" for site in SITES for role in WORKLOAD_ROLES}
        or any(
            not isinstance(value, Mapping)
            or any(value.get(gate) is not True for gate in _WORKLOAD_READINESS_GATES)
            for value in workload_checks.values()
        )
    ):
        failures.append("field-level readiness gate proof is incomplete")
    if isinstance(appliance_checks, Mapping) and isinstance(workload_checks, Mapping) and isinstance(deployment_value, Mapping):
        runtime_values = deployment_value.get("runtime")
        workload_values = deployment_value.get("workloads")
        if not isinstance(runtime_values, Mapping) or not isinstance(workload_values, Mapping):
            failures.append("readiness cannot be bound to deployment runtime identities")
        else:
            readiness_interface_ids: list[str] = []
            for site in SITES:
                checks = appliance_checks.get(site)
                runtime = runtime_values.get(site)
                if not isinstance(checks, Mapping) or not isinstance(runtime, Mapping):
                    failures.append(f"{site} readiness/runtime identity is absent")
                    continue
                if (
                    checks.get("advertised_routes")
                    != sorted((*runtime.get("gwlb_return_cidrs", []), *runtime.get("local_delivery_cidrs", [])))
                    or checks.get("accepted_routes") != sorted(runtime.get("remote_tailnet_cidrs", []))
                    or checks.get("accepted_route_peer") != f"{normalized['run_id']}-{_opposite(site)}"
                    or checks.get("links")
                    != [runtime.get("underlay_interface"), runtime.get("tailscale_iface"), runtime.get("tun_name")]
                    or checks.get("target_status") != "healthy"
                ):
                    failures.append(f"{site} readiness route, link, or target identity is not exact")
                site_workloads = workload_values.get(site)
                if not isinstance(site_workloads, Mapping):
                    failures.append(f"{site} readiness workload identities are absent")
                    continue
                for role in WORKLOAD_ROLES:
                    expected = site_workloads.get(role)
                    observed = workload_checks.get(f"{site}-{role}")
                    if (
                        not isinstance(expected, Mapping)
                        or not isinstance(observed, Mapping)
                        or observed.get("private_ip") != expected.get("private_ip")
                        or observed.get("instance_id") != expected.get("instance_id")
                        or observed.get("subnet_id") != expected.get("subnet_id")
                        or not isinstance(observed.get("interface_id"), str)
                        or not _ENI_ID_RE.fullmatch(cast(str, observed["interface_id"]))
                        or observed.get("flow_directions") != ["egress", "ingress"]
                    ):
                        failures.append(f"{site}-{role} readiness Flow Log identity is not exact")
                    elif isinstance(observed.get("interface_id"), str):
                        readiness_interface_ids.append(cast(str, observed["interface_id"]))
            if len(readiness_interface_ids) != 4 or len(set(readiness_interface_ids)) != 4:
                failures.append("readiness workload Flow Log ENI identities are missing or duplicated")

    profile = normalized["load_profile"]
    deployment_profile = deployment_value.get("load_profile", {}) if isinstance(deployment_value, Mapping) else {}
    profile_fields = {field.name for field in dataclasses.fields(ApprovedLoadProfile)}
    if (
        set(profile) != profile_fields | {"sha256", "source", "immutable"}
        or profile.get("source") != "protected-saved-plan-output"
        or profile.get("immutable") is not True
        or profile.get("sha256") != deployment_profile.get("sha256")
        or any(profile.get(name) != deployment_profile.get(name) for name in profile_fields)
    ):
        failures.append("load thresholds are not immutable protected saved-plan inputs")

    flow_by_id = {flow["flow_id"]: flow for flow in normalized["flows"]}
    if len(flow_by_id) != len(normalized["flows"]):
        failures.append("flow IDs are duplicated")
    cold_flows = [flow for flow in flow_by_id.values() if flow.get("purpose") == "cold"]
    expected_cold_matrix = {(source, _opposite(cast(Site, source)), protocol) for source in SITES for protocol in PROTOCOLS}
    observed_cold_matrix = {
        (flow["source"]["site"], flow["destination"]["site"], flow["protocol"])
        for flow in cold_flows
    }
    cold_ids = {flow["flow_id"] for flow in cold_flows}
    if observed_cold_matrix != expected_cold_matrix:
        failures.append("cold ICMP/TCP/UDP directional matrix is incomplete")
    expected_mtu = {
        (site, "icmp", "mtu-safe-icmp", "success") for site in SITES
    } | {
        (site, "udp", "mtu-safe-udp", "success") for site in SITES
    } | {
        (site, "icmp", "mtu-oversized-icmp", "mtu-drop") for site in SITES
    } | {
        (site, "udp", "mtu-oversized-udp", "mtu-drop") for site in SITES
    } | {
        (site, "tcp", "tcp-mss-sustained", "success") for site in SITES
    }
    actual_mtu = {
        (flow["source"]["site"], flow["protocol"], flow["purpose"], flow["expected_result"])
        for flow in flow_by_id.values()
        if flow["purpose"].startswith("mtu-") or flow["purpose"] == "tcp-mss-sustained"
    }
    if actual_mtu != expected_mtu:
        failures.append("MTU flow declaration matrix is incomplete")
    expected_load = {
        (site, "tcp", "iperf3") for site in SITES
    } | {
        (site, protocol, f"concurrent-{protocol}-{index:02d}")
        for site in SITES
        for protocol, count in (
            ("tcp", int(profile.get("concurrent_tcp_flows", 0))),
            ("udp", int(profile.get("concurrent_udp_flows", 0))),
        )
        for index in range(1, count + 1)
    }
    actual_load = {
        (flow["source"]["site"], flow["protocol"], flow["purpose"])
        for flow in flow_by_id.values()
        if flow["purpose"] == "iperf3" or flow["purpose"].startswith("concurrent-")
    }
    if actual_load != expected_load:
        failures.append("approved load flow counts or identities differ from the protected profile")
    expected_resilience = {
        ("west", "udp", "route-drift"),
        ("west", "tcp", "service-recovery"),
        ("west", "udp", "reboot-west-recovery"),
        ("east", "udp", "reboot-east-recovery"),
        ("west", "udp", "route-acceptance-withdrawal"),
    }
    actual_resilience = {
        (flow["source"]["site"], flow["protocol"], flow["purpose"])
        for flow in flow_by_id.values()
        if flow["purpose"]
        in {
            "route-drift",
            "service-recovery",
            "reboot-west-recovery",
            "reboot-east-recovery",
            "route-acceptance-withdrawal",
        }
    }
    expected_purposes = {"cold", *(value[2] for value in expected_mtu), *(value[2] for value in expected_load), *(value[2] for value in expected_resilience)}
    if actual_resilience != expected_resilience or {flow["purpose"] for flow in flow_by_id.values()} != expected_purposes:
        failures.append("resilience flow declarations are incomplete or unsupported flows were added")

    cold_phase_names = {Phase.COLD_WEST_EAST.value, Phase.COLD_EAST_WEST.value}
    for phase in phases:
        if phase["name"] not in cold_phase_names:
            continue
        context = phase["summary"].get("context")
        if (
            not isinstance(context, Mapping)
            or context.get("both_processes_restarted") is not True
            or context.get("matching_return_context_before_first_packet") is not False
            or not isinstance(context.get("matching_flow_ids_absent_before"), list)
            or len(context.get("matching_flow_ids_absent_before", [])) != 3
            or context.get("matching_flow_ids_absent_before") != phase["summary"].get("flow_ids")
            or context.get("allocation_unique_in_generation") is not True
            or context.get("targets_healthy_before_first_packet") is not True
        ):
            failures.append("cold phase lacks pre-first-packet empty-context proof")

    probe_ids: set[str] = set()
    for probe in normalized["probes"]:
        if not isinstance(probe, Mapping):
            failures.append("probe evidence contains a non-object entry")
            continue
        flow_id = probe.get("flow_id")
        flow = flow_by_id.get(flow_id)
        receiver = probe.get("receiver")
        if flow is None or not isinstance(receiver, Mapping):
            failures.append("probe does not reference one recorded flow and receiver")
            continue
        probe_ids.add(cast(str, flow_id))
        expected_kind = (
            "cold"
            if flow["purpose"] == "cold"
            else "mtu-safe"
            if flow["purpose"] in {"mtu-safe-icmp", "mtu-safe-udp"}
            else "recovery"
        )
        common_invalid = (
            probe.get("success") is not True
            or isinstance(probe.get("response_timeout_seconds"), bool)
            or not isinstance(probe.get("response_timeout_seconds"), (int, float))
            or not 0 < probe.get("response_timeout_seconds", 0) <= 30
            or probe.get("kind") != expected_kind
            or probe.get("protocol") != flow["protocol"]
            or probe.get("source_ip") != flow["source"]["private_ip"]
            or probe.get("destination_ip") != flow["destination"]["private_ip"]
            or isinstance(probe.get("payload_bytes"), bool)
            or not isinstance(probe.get("payload_bytes"), int)
            or probe.get("payload_bytes", 0) <= 0
            or not isinstance(probe.get("payload_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", probe["payload_sha256"]) is None
        )
        if flow["protocol"] == "icmp":
            protocol_invalid = (
                flow["source_port"] is not None
                or flow["destination_port"] is not None
                or probe.get("source_port") is not None
                or probe.get("destination_port") is not None
                or probe.get("icmp_request_type") != 8
                or probe.get("icmp_reply_type") != 0
                or receiver.get("reply_source_ip") != flow["destination"]["private_ip"]
                or receiver.get("source_identity_verified") is not True
            )
        else:
            protocol_invalid = (
                probe.get("source_port") != flow["source_port"]
                or probe.get("destination_port") != flow["destination_port"]
                or receiver.get("flow_id") != flow_id
                or receiver.get("payload_sha256") != probe.get("payload_sha256")
                or receiver.get("receives") != 1
                or receiver.get("duplicates") != 0
                or receiver.get("sessions") != 1
                or receiver.get("source_ip") != flow["source"]["private_ip"]
                or receiver.get("source_port") != flow["source_port"]
            )
        if common_invalid or protocol_invalid:
            failures.append("probe protocol-specific identity, payload, session, or duplicate assertion failed")
        if flow["purpose"] in {"mtu-safe-icmp", "mtu-safe-udp"} and probe.get("payload_bytes") != profile.get("safe_inner_mtu", 0) - 28:
            failures.append("safe MTU probe payload size is not exact")
    if not cold_ids.issubset(probe_ids):
        failures.append("one or more cold ICMP/TCP/UDP flows has no probe proof")
    expected_probe_ids = {
        flow_id
        for flow_id, flow in flow_by_id.items()
        if flow["purpose"]
        in {
            "cold",
            "mtu-safe-icmp",
            "mtu-safe-udp",
            "service-recovery",
            "reboot-west-recovery",
            "reboot-east-recovery",
        }
    }
    if probe_ids != expected_probe_ids or len(normalized["probes"]) != len(expected_probe_ids):
        failures.append("probe evidence does not cover exactly cold, safe-MTU, service, and both reboot flows")

    wire_ids: set[str] = set()
    if [value.get("direction") for value in normalized["wire"] if isinstance(value, Mapping)] != [
        "west-to-east",
        "east-to-west",
    ]:
        failures.append("directional wire capture order is incomplete")
    for value in normalized["wire"]:
        wire_flows = value.get("flows") if isinstance(value, Mapping) else None
        if (
            not isinstance(value, Mapping)
            or value.get("capture_bounded") is not True
            or value.get("raw_pcaps_deleted") is not True
            or value.get("raw_pcaps_retained") is not False
            or not isinstance(value.get("interfaces"), list)
            or len(value["interfaces"]) != 6
            or {
                (item.get("site"), item.get("interface"))
                for item in value.get("interfaces", [])
                if isinstance(item, Mapping)
            }
            != {(site, interface) for site in SITES for interface in ("underlay", "envelope0", "tailscale0")}
            or any(
                not isinstance(item, Mapping)
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("file_sha256", "")))
                or not isinstance(item.get("frame_count"), int)
                or item.get("frame_count", -1) < 0
                for item in value.get("interfaces", [])
            )
            or not isinstance(wire_flows, list)
        ):
            failures.append("wire capture controller lifecycle proof is incomplete")
            continue
        for wire_flow in wire_flows:
            if not isinstance(wire_flow, Mapping):
                failures.append("wire flow summary is invalid")
                continue
            wire_ids.add(str(wire_flow.get("flow_id", "")))
            path_counts = wire_flow.get("path_packet_counts")
            source_site = value.get("source_site")
            destination_site = value.get("destination_site")
            if (
                wire_flow.get("outer_ipv4_checksums") != "valid"
                or wire_flow.get("outer_ips_swapped") is not True
                or wire_flow.get("return_source_port_preserved") is not True
                or wire_flow.get("inner_flow_identity_verified") is not True
                or wire_flow.get("return_udp_source_port") != wire_flow.get("original_gwlb_source_port")
                or not isinstance(wire_flow.get("original_gwlb_source_port"), int)
                or not 1 <= wire_flow.get("original_gwlb_source_port", 0) <= 65_535
                or wire_flow.get("return_udp_destination_port") != 6081
                or not isinstance(wire_flow.get("outer_udp_checksums"), list)
                or len(wire_flow.get("outer_udp_checksums", [])) != 2
                or any(status not in {"valid", "not-present"} for status in wire_flow.get("outer_udp_checksums", []))
                or wire_flow.get("vni") != 0
                or wire_flow.get("ordered_options_identical") is not True
                or not re.fullmatch(r"[0-9a-f]{64}", str(wire_flow.get("ordered_options_sha256", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(wire_flow.get("flow_cookie_sha256", "")))
                or wire_flow.get("responder_gwlb_matching_packets") != 0
                or not isinstance(path_counts, Mapping)
                or set(path_counts)
                != {
                    f"{source_site}:envelope0",
                    f"{source_site}:tailscale0",
                    f"{destination_site}:envelope0",
                    f"{destination_site}:tailscale0",
                }
                or any(isinstance(count, bool) or not isinstance(count, int) for count in path_counts.values())
                or path_counts.get(f"{source_site}:envelope0", 0) < 2
                or path_counts.get(f"{source_site}:tailscale0", 0) < 2
                or path_counts.get(f"{destination_site}:tailscale0", 0) < 2
                or path_counts.get(f"{destination_site}:envelope0") != 0
            ):
                failures.append("outer IPv4/UDP/GENEVE wire assertion failed")
    if wire_ids != cold_ids:
        failures.append("wire evidence does not cover exactly every cold flow")
    if sum(len(value.get("flows", [])) for value in normalized["wire"] if isinstance(value, Mapping)) != len(cold_ids):
        failures.append("wire evidence duplicates a cold flow")

    metric_flow_ids: set[str] = set()
    metric_by_flow_id: dict[str, Mapping[str, Any]] = {}
    for metric in normalized["metrics"]:
        if not isinstance(metric, Mapping):
            failures.append("metric evidence contains a non-object entry")
            continue
        scope = metric.get("scope_flow_ids")
        if (
            not isinstance(scope, list)
            or not scope
            or len(set(scope)) != len(scope)
            or not all(isinstance(flow_id, str) and flow_id in flow_by_id for flow_id in scope)
            or metric_flow_ids.intersection(scope)
        ):
            failures.append("metric scope is invalid, duplicated, or references an unknown flow")
            continue
        metric_flow_ids.update(scope)
        metric_by_flow_id.update({flow_id: metric for flow_id in scope})
        unexpected = metric.get("unexpected_deltas")
        if (
            metric.get("unexpected_growth") is not False
            or not isinstance(unexpected, Mapping)
            or set(unexpected) != set(SITES)
            or any(
                not isinstance(unexpected[site], Mapping)
                or set(unexpected[site]) != set(_UNEXPECTED_FLOW_METRICS)
                or any(isinstance(delta, bool) or not isinstance(delta, (int, float)) for delta in unexpected[site].values())
                for site in SITES
            )
        ):
            failures.append("metric evidence omitted complete unexpected-counter deltas")
            continue
        mode = metric.get("mode")
        nonzero = [
            (site, name, delta)
            for site, site_values in unexpected.items()
            if isinstance(site_values, Mapping)
            for name, delta in site_values.items()
            if delta != 0
        ]
        expected_modes = {flow_by_id[flow_id]["expected_result"] for flow_id in scope}
        if mode == "mtu-drop":
            intentional = metric.get("intentional_mtu_drop")
            expected_site = flow_by_id[scope[0]]["source"]["site"]
            expected_protocol = flow_by_id[scope[0]]["protocol"]
            packet = metric.get("packet_deltas")
            byte = metric.get("byte_deltas")
            session = metric.get("session")
            malformed = metric.get("malformed_deltas")
            drop_proof = metric.get("drop_proof")
            capture = drop_proof.get("capture") if isinstance(drop_proof, Mapping) else None
            capture_valid = (
                isinstance(capture, Mapping)
                and set(capture)
                == {
                    "interface",
                    "file_sha256",
                    "icmp_checksum",
                    "raw_pcap_deleted",
                    "request_count",
                    "inner_bytes",
                    "payload_bytes",
                    "payload_sha256",
                }
                and capture.get("interface") == deployment_value["runtime"][expected_site]["underlay_interface"]
                and re.fullmatch(r"[0-9a-f]{64}", str(capture.get("file_sha256", ""))) is not None
                and capture.get("icmp_checksum") == "valid"
                and capture.get("raw_pcap_deleted") is True
                and not isinstance(capture.get("request_count"), bool)
                and capture.get("request_count") == 1
                and not isinstance(capture.get("inner_bytes"), bool)
                and capture.get("inner_bytes") == profile.get("safe_inner_mtu", 0) + 1
                and not isinstance(capture.get("payload_bytes"), bool)
                and capture.get("payload_bytes") == profile.get("safe_inner_mtu", 0) - 27
                and re.fullmatch(r"[0-9a-f]{64}", str(capture.get("payload_sha256", ""))) is not None
            )
            if (
                expected_modes != {"mtu-drop"}
                or len(scope) != 1
                or metric.get("initiator_site") != expected_site
                or not isinstance(intentional, Mapping)
                or intentional
                != {
                    "site": expected_site,
                    "generic_drops_delta": 1,
                    "mtu_specific": {
                        "metric": "gwlb_mtu_drops_total",
                        "delta": 1,
                        "direction": "ingress",
                        "family": "ipv4",
                    },
                }
                or set(nonzero)
                != {
                    (expected_site, "drops", 1),
                    (expected_site, "gwlb_mtu_drops_total", 1),
                }
                or not isinstance(packet, Mapping)
                or set(packet) != set(_PACKET_METRICS)
                or not positive_number(packet.get("geneve_rx_packets"))
                or any(packet.get(name) != 0 for name in _PACKET_METRICS if name != "geneve_rx_packets")
                or not isinstance(byte, Mapping)
                or set(byte) != set(_BYTE_METRICS)
                or not positive_number(byte.get("geneve_rx_bytes"))
                or any(byte.get(name) != 0 for name in _BYTE_METRICS if name != "geneve_rx_bytes")
                or not isinstance(session, Mapping)
                or session.get("receiver_sessions") != 0
                or session.get("receiver_identity_verified") is not True
                or not isinstance(session.get("integrity_metric_deltas"), Mapping)
                or set(session["integrity_metric_deltas"]) != set(_SESSION_INTEGRITY_METRICS)
                or any(delta != 0 for delta in session["integrity_metric_deltas"].values())
                or not isinstance(malformed, Mapping)
                or set(malformed) != set(SITES)
                or any(delta != 0 for delta in malformed.values())
                or not isinstance(drop_proof, Mapping)
                or set(drop_proof)
                != {
                    "protocol",
                    "application_reply_received",
                    "pmtu_icmp_expected",
                    "process_generation",
                    "capture",
                }
                or drop_proof.get("protocol") != expected_protocol
                or drop_proof.get("application_reply_received") is not False
                or drop_proof.get("pmtu_icmp_expected") is not False
                or drop_proof.get("process_generation") != flow_by_id[scope[0]]["process_generation"]
                or (expected_protocol == "icmp" and not capture_valid)
                or (expected_protocol == "udp" and capture is not None)
            ):
                failures.append("intentional MTU drop metrics are not exact")
        elif mode == "bidirectional":
            packet = metric.get("packet_deltas")
            byte = metric.get("byte_deltas")
            if (
                metric.get("drop_proof") is not None
                or nonzero
                or any(
                    flow_by_id[flow_id]["purpose"] != "iperf3"
                    and not flow_by_id[flow_id]["purpose"].startswith("concurrent-")
                    for flow_id in scope
                )
                or set(scope)
                != {
                    flow_id
                    for flow_id, flow in flow_by_id.items()
                    if flow["purpose"] == "iperf3" or flow["purpose"].startswith("concurrent-")
                }
                or not isinstance(packet, Mapping)
                or set(packet) != set(SITES)
                or not isinstance(byte, Mapping)
                or set(byte) != set(SITES)
                or any(
                    not isinstance(packet[site], Mapping)
                    or set(packet[site]) != set(_PACKET_METRICS)
                    or any(not positive_number(delta) for delta in packet[site].values())
                    or not isinstance(byte[site], Mapping)
                    or set(byte[site]) != set(_BYTE_METRICS)
                    or any(not positive_number(delta) for delta in byte[site].values())
                    for site in SITES
                )
            ):
                failures.append("load metric scope or zero-error proof is invalid")
        else:
            packet = metric.get("packet_deltas")
            byte = metric.get("byte_deltas")
            session = metric.get("session")
            malformed = metric.get("malformed_deltas")
            expected_sessions = None if flow_by_id[scope[0]]["protocol"] == "icmp" else 1
            expected_site = flow_by_id[scope[0]]["source"]["site"]
            if (
                mode != "normal"
                or metric.get("drop_proof") is not None
                or nonzero
                or expected_modes != {"success"}
                or len(scope) != 1
                or metric.get("initiator_site") != expected_site
                or not isinstance(packet, Mapping)
                or set(packet) != set(_PACKET_METRICS)
                or any(not positive_number(delta) for delta in packet.values())
                or not isinstance(byte, Mapping)
                or set(byte) != set(_BYTE_METRICS)
                or any(not positive_number(delta) for delta in byte.values())
                or not isinstance(session, Mapping)
                or session.get("receiver_sessions") != expected_sessions
                or session.get("receiver_identity_verified") is not True
                or not isinstance(session.get("integrity_metric_deltas"), Mapping)
                or set(session["integrity_metric_deltas"]) != set(_SESSION_INTEGRITY_METRICS)
                or any(delta != 0 for delta in session["integrity_metric_deltas"].values())
                or not isinstance(malformed, Mapping)
                or set(malformed) != set(SITES)
                or any(delta != 0 for delta in malformed.values())
            ):
                failures.append("normal flow metrics contain unexpected growth or incomplete traffic deltas")
    if metric_flow_ids != set(flow_by_id):
        failures.append("metric evidence does not cover every declared flow exactly once")

    transport_by_site: dict[str, Mapping[str, Any]] = {}
    transport_shape_invalid = False
    for value in normalized["transport"]:
        site = value.get("source_site") if isinstance(value, Mapping) else None
        if not isinstance(value, Mapping) or site not in SITES or site in transport_by_site:
            transport_shape_invalid = True
            continue
        transport_by_site[cast(str, site)] = value
    if transport_shape_invalid or set(transport_by_site) != set(SITES):
        failures.append("MTU/transport evidence does not cover both lanes")
    else:
        for site in SITES:
            value = transport_by_site[site]
            expected_transport_ids = {
                flow_id
                for flow_id, flow in flow_by_id.items()
                if flow["source"]["site"] == site
                and flow["purpose"]
                in {
                    "mtu-safe-icmp",
                    "mtu-safe-udp",
                    "mtu-oversized-icmp",
                    "mtu-oversized-udp",
                    "tcp-mss-sustained",
                }
            }
            if (
                value.get("destination_site") != _opposite(site)
                or not isinstance(value.get("flow_ids"), list)
                or set(value.get("flow_ids", [])) != expected_transport_ids
                or value.get("inner_mtu") != profile.get("safe_inner_mtu")
                or value.get("safe_icmp_inner_bytes") != profile.get("safe_inner_mtu")
                or value.get("safe_udp_inner_bytes") != profile.get("safe_inner_mtu")
                or value.get("oversized_icmp_inner_bytes") != profile.get("safe_inner_mtu", 0) + 1
                or value.get("oversized_udp_inner_bytes") != profile.get("safe_inner_mtu", 0) + 1
                or not at_most(value.get("tcp_mss"), profile.get("maximum_tcp_mss"))
                or value.get("tcp_mss_maximum") != profile.get("maximum_tcp_mss")
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("tcp_syn_capture_sha256", "")))
                or value.get("tcp_syn_raw_pcap_deleted") is not True
                or not at_least(value.get("sustained_tcp_bytes"), profile.get("minimum_sustained_tcp_bytes"))
                or not at_least(value.get("sustained_tcp_duration_seconds"), profile.get("sustained_tcp_duration_seconds"))
                or value.get("pmtu_icmp_expected") is not False
            ):
                failures.append("exact MTU sizes, MSS, sustained TCP, or no-PMTU-response proof failed")

    load = normalized["load"]
    iperf = load.get("iperf3")
    concurrent = load.get("concurrent")
    load_flow_ids = {
        flow_id
        for flow_id, flow in flow_by_id.items()
        if flow["purpose"] == "iperf3" or flow["purpose"].startswith("concurrent-")
    }
    load_outcomes = [*iperf, *concurrent] if isinstance(iperf, list) and isinstance(concurrent, list) else []
    load_outcomes_valid = all(
        isinstance(value, Mapping) and isinstance(value.get("flow_id"), str) for value in load_outcomes
    )
    if (
        set(load)
        != {
            "profile_sha256",
            "iperf3",
            "concurrent",
            "thresholds",
            "flow_count",
            "collision_eviction_error_growth",
        }
        or load.get("profile_sha256") != profile.get("sha256")
        or load.get("thresholds") != {name: profile.get(name) for name in profile_fields}
        or load.get("flow_count") != len(load_flow_ids)
        or load.get("collision_eviction_error_growth") is not False
        or not load_outcomes_valid
        or {value.get("flow_id") for value in load_outcomes if isinstance(value, Mapping)} != load_flow_ids
        or len(load_outcomes) != len(load_flow_ids)
        or any(
            not isinstance(value, Mapping)
            or value.get("completed") is not True
            or not at_least(value.get("throughput_mbps"), profile.get("minimum_throughput_mbps"))
            or not at_least(value.get("duration_seconds"), profile.get("iperf_duration_seconds"))
            or not positive_number(value.get("bytes"))
            or not at_most(value.get("syn_mss"), profile.get("maximum_tcp_mss"))
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("syn_capture_sha256", "")))
            or value.get("raw_pcap_deleted") is not True
            for value in (iperf if isinstance(iperf, list) else [])
        )
        or any(
            not isinstance(value, Mapping)
            or flow_by_id.get(value.get("flow_id"), {}).get("protocol") != value.get("protocol")
            or flow_by_id.get(value.get("flow_id"), {}).get("source_port") != value.get("source_port")
            or value.get("completed") is not True
            or isinstance(value.get("sent"), bool)
            or not isinstance(value.get("sent"), int)
            or value.get("sent", 0) <= 0
            or isinstance(value.get("received"), bool)
            or not isinstance(value.get("received"), int)
            or not 0 <= value.get("received", -1) <= value.get("sent", -1)
            or isinstance(value.get("loss_percent"), bool)
            or not isinstance(value.get("loss_percent"), (int, float))
            or not math.isfinite(value["loss_percent"])
            or value["loss_percent"] < 0
            or not math.isclose(
                value["loss_percent"],
                (value["sent"] - value["received"]) * 100.0 / value["sent"],
                rel_tol=0.0,
                abs_tol=1e-9,
            )
            or value["loss_percent"] > profile.get("maximum_udp_loss_percent", -1)
            or not at_most(value.get("p99_latency_ms"), profile.get("maximum_p99_latency_ms"))
            or not at_least(value.get("duration_seconds"), profile.get("concurrent_duration_seconds"))
            for value in (concurrent if isinstance(concurrent, list) else [])
        )
    ):
        failures.append("protected throughput/concurrency profile did not pass exactly")

    flow_log_ids: set[str] = set()
    for record in normalized["flow_logs"]:
        if not isinstance(record, Mapping):
            failures.append("flow-log evidence contains a non-object entry")
            continue
        flow_log_ids.add(str(record.get("flow_id", "")))
        flow = flow_by_id.get(record.get("flow_id"))
        try:
            if flow is None or not isinstance(workload_checks, Mapping):
                raise FlowLogError("flow or readiness identity is absent")
            _validate_flow_log_evidence(flow, record, workload_checks)
            phase = next((value for value in phases if value["name"] == record["phase"]), None)
            window = record["window"]
            if (
                not isinstance(phase, Mapping)
                or not isinstance(phase.get("started_at"), str)
                or not isinstance(phase.get("finished_at"), str)
                or window["start_epoch"] < timestamp_epoch(phase["started_at"]) - 1
                or window["end_epoch"] > timestamp_epoch(phase["finished_at"]) + 1
            ):
                raise FlowLogError("flow window is outside its recorded execution phase")
            if flow["protocol"] == "icmp":
                if flow["expected_result"] == "mtu-drop":
                    metric = metric_by_flow_id.get(cast(str, record.get("flow_id")))
                    proof = metric.get("drop_proof") if isinstance(metric, Mapping) else None
                    if not isinstance(proof, Mapping) or not isinstance(proof.get("capture"), Mapping):
                        raise FlowLogError("oversized ICMP lane has no exact capture and MTU drop proof")
                elif record.get("flow_id") not in probe_ids:
                    raise FlowLogError("successful ICMP lane has no failed/successful application reply proof")
        except FlowLogError:
            failures.append("a declared protocol tuple has no expected VPC Flow Log proof")
    if set(flow_by_id) != flow_log_ids:
        failures.append("VPC Flow Log evidence does not cover every declared flow")
    if len(normalized["flow_logs"]) != len(flow_by_id):
        failures.append("VPC Flow Log evidence duplicates a declared flow")

    expected_drills = [
        Phase.ROUTE_MUTATION.value,
        Phase.SERVICE_STOP.value,
        Phase.EC2_REBOOT_WEST.value,
        Phase.EC2_REBOOT_EAST.value,
        Phase.TAILSCALE_WITHDRAWAL.value,
    ]
    if [drill.get("name") for drill in normalized["resilience"] if isinstance(drill, Mapping)] != expected_drills:
        failures.append("resilience drill sequence is incomplete or concurrent")
    for drill in normalized["resilience"]:
        if not isinstance(drill, Mapping):
            continue
        if drill.get("passed") is not True or drill.get("restored") is not True:
            failures.append("a resilience drill did not pass and restore exact state")
        if drill.get("name") in {
            Phase.SERVICE_STOP.value,
            Phase.EC2_REBOOT_WEST.value,
            Phase.EC2_REBOOT_EAST.value,
        } and (
            not isinstance(drill.get("recovery"), Mapping)
            or drill["recovery"].get("new_cold_flow") is not True
        ):
            failures.append("service stop or reboot lacks new-cold-flow recovery proof")
        if drill.get("name") == Phase.SERVICE_STOP.value and (
            drill.get("target_transition") != ["healthy", "unhealthy", "healthy"]
            or drill.get("process_generation_changed") is not True
        ):
            failures.append("service stop lacks exact target-health/process-generation transitions")
        if drill.get("name") in {Phase.EC2_REBOOT_WEST.value, Phase.EC2_REBOOT_EAST.value}:
            expected_site = "west" if drill.get("name") == Phase.EC2_REBOOT_WEST.value else "east"
            if (
                drill.get("site") != expected_site
                or drill.get("boot_generation_changed") is not True
                or drill.get("process_generation_changed") is not True
                or drill.get("target_recovered_healthy") is not True
                or drill.get("persistent_configuration_recovered") is not True
            ):
                failures.append("regional reboot recovery identity or persistent readiness proof is incomplete")
        if drill.get("name") in {Phase.ROUTE_MUTATION.value, Phase.TAILSCALE_WITHDRAWAL.value} and (
            not isinstance(drill.get("continuity"), Mapping)
            or drill["continuity"].get("bounded") is not True
        ):
            failures.append("route mutation or route withdrawal lacks bounded continuity proof")
        if drill.get("name") == Phase.ROUTE_MUTATION.value:
            readiness = drill.get("readiness_during_drift")
            expected_cidr = deployment_value["workloads"]["west"]["initiator"]["cidr"]
            repair_delta = drill.get("repair_metric_delta")
            if (
                not isinstance(readiness, Mapping)
                or readiness.get("before_repair") is not True
                or readiness.get("exact_rule_missing") is not True
                or isinstance(repair_delta, bool)
                or not isinstance(repair_delta, (int, float))
                or repair_delta < 1
                or readiness.get("routing_drift_repairs_delta") != repair_delta
                or readiness.get("drift_observed")
                is not (
                    readiness.get("exact_rule_missing") is True
                    and (
                        readiness.get("host_preflight_failed") is True
                        or readiness.get("unhealthy") is True
                        or repair_delta > 0
                    )
                )
                or readiness.get("drift_observed") is not True
                or readiness.get("missing_cidr") != expected_cidr
                or readiness.get("reason") != "owned-return-rule-missing"
            ):
                failures.append("route drift was not reported/unhealthy before repair")
    withdrawal = next(
        (
            drill
            for drill in normalized["resilience"]
            if isinstance(drill, Mapping) and drill.get("name") == Phase.TAILSCALE_WITHDRAWAL.value
        ),
        {},
    )
    if withdrawal.get("credential_rotation") is not False:
        failures.append("Tailscale route reacceptance did not prove zero credential rotation")
    if withdrawal.get("exact_routes_withdrawn") is not True:
        failures.append("Tailscale route withdrawal did not prove exact accepted prefixes absent")
    expected_withdrawn = sorted(deployment_value["runtime"]["west"]["remote_tailnet_cidrs"])
    if withdrawal.get("withdrawn_cidrs") != expected_withdrawn or withdrawal.get("restored_cidrs") != expected_withdrawn:
        failures.append("Tailscale route withdrawal/restoration prefix evidence is not exact")

    lifecycle = normalized["lifecycle"]
    if (
        lifecycle.get("claimed") is not True
        or lifecycle.get("load_profile_approved_before_apply") is not True
        or lifecycle.get("drift_precheck") != "clean"
        or lifecycle.get("drift_postcheck") != "clean"
        or lifecycle.get("cleanup") != "complete"
    ):
        failures.append("protected claim, drift, or cleanup proof is incomplete")
    if failures:
        raise EvidenceVerificationError("live evidence did not verify: " + "; ".join(sorted(set(failures))))
    return normalized


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sanitize_string(value: str) -> str:
    safe = redact_runtime_text(value)
    for pattern, _description in _CREDENTIAL_VALUE_PATTERNS:
        safe = pattern.sub("[REDACTED]", safe)
    return safe[:32_768]


def sanitize_evidence_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 24:
        return "[TRUNCATED_NESTING]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                continue
            normalized = _normalized_key(key)
            if normalized in _RAW_MATERIAL_KEYS:
                result[f"{normalized}_omitted"] = True
            elif normalized in _CREDENTIAL_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = sanitize_evidence_value(child, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence_value(child, depth=depth + 1) for child in value[:10_000]]
    if isinstance(value, str):
        return _sanitize_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize_string(str(value))


def new_live_evidence(run_id: str, budgets: TimeoutBudgets) -> dict[str, Any]:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("live evidence run_id is invalid")
    return {
        "schema": LIVE_EVIDENCE_SCHEMA,
        "kind": LIVE_EVIDENCE_KIND,
        "run_id": run_id,
        "generated_at": _utc_now(),
        "status": "running",
        "deployment": None,
        "phases": [],
        "flows": [],
        "assertions": [],
        "metrics": [],
        "streams": [],
        "topology": {},
        "probes": [],
        "wire": [],
        "transport": [],
        "load_profile": {},
        "load": {},
        "flow_logs": [],
        "resilience": [],
        "diagnostics": {},
        "lifecycle": {},
        "timeout_budgets": budgets.as_dict(),
        "failure": None,
    }


class ProtectedLifecycleAPI(Protocol):
    def claim(self, raw_deployment: Mapping[str, Any], deployment: ProtectedDeployment) -> Mapping[str, Any]: ...

    def verify_no_drift(self, stage: Literal["before", "after"]) -> Mapping[str, Any]: ...

    def finish(self, passed: bool) -> Mapping[str, Any]: ...

    def cleanup(self) -> Mapping[str, Any]: ...


class LiveOperations(Protocol):
    def verify_readiness_and_topology(
        self, deployment: ProtectedDeployment, *, timeout_seconds: int
    ) -> Mapping[str, Any]: ...

    def start_flow_logs(self, deployment: ProtectedDeployment, *, timeout_seconds: int) -> object: ...

    def run_cold_direction(
        self,
        deployment: ProtectedDeployment,
        source_site: Site,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]: ...

    def run_mtu_transport(
        self,
        deployment: ProtectedDeployment,
        profile: ApprovedLoadProfile,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]: ...

    def run_approved_load(
        self,
        deployment: ProtectedDeployment,
        profile: ApprovedLoadProfile,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]: ...

    def run_route_mutation(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int, maximum_loss_ns: int
    ) -> Mapping[str, Any]: ...

    def run_service_stop(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int
    ) -> Mapping[str, Any]: ...

    def run_ec2_reboot(
        self, deployment: ProtectedDeployment, site: Site, flow: FlowRecord, *, timeout_seconds: int
    ) -> Mapping[str, Any]: ...

    def run_tailscale_withdrawal(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int, maximum_loss_ns: int
    ) -> Mapping[str, Any]: ...

    def capture_flow_logs(
        self,
        handle: object,
        deployment: ProtectedDeployment,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Sequence[Mapping[str, Any]]: ...

    def stop_flow_logs(self, handle: object, *, timeout_seconds: int) -> Mapping[str, Any]: ...

    def collect_diagnostics(self, deployment: ProtectedDeployment | None) -> Mapping[str, Any]: ...


@dataclasses.dataclass(frozen=True)
class LiveRunResult:
    exit_code: int
    evidence_path: pathlib.Path
    evidence: Mapping[str, Any]
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.exit_code == EXIT_OK


def _opposite(site: Site) -> Site:
    return "east" if site == "west" else "west"


def _opposite_workload_role(role: WorkloadRole) -> WorkloadRole:
    return "responder" if role == "initiator" else "initiator"


def _phase_budget(phase: Phase, budgets: TimeoutBudgets) -> int:
    return {
        Phase.CONSUME_DEPLOYMENT: budgets.consume_deployment,
        Phase.DRIFT_PRECHECK: budgets.drift_check,
        Phase.READINESS_TOPOLOGY: budgets.readiness_topology,
        Phase.FLOW_LOG_START: budgets.flow_log_start,
        Phase.COLD_WEST_EAST: budgets.cold_direction,
        Phase.COLD_EAST_WEST: budgets.cold_direction,
        Phase.MTU_TRANSPORT: budgets.mtu_transport,
        Phase.APPROVED_LOAD: budgets.approved_load,
        Phase.ROUTE_MUTATION: budgets.route_mutation,
        Phase.SERVICE_STOP: budgets.service_stop,
        Phase.EC2_REBOOT_WEST: budgets.ec2_reboot,
        Phase.EC2_REBOOT_EAST: budgets.ec2_reboot,
        Phase.TAILSCALE_WITHDRAWAL: budgets.tailscale_withdrawal,
        Phase.FLOW_LOG_CAPTURE: budgets.flow_log_capture,
        Phase.DRIFT_POSTCHECK: budgets.drift_check,
        Phase.EVIDENCE: budgets.evidence,
        Phase.CLEANUP: budgets.cleanup,
    }[phase]


def _flow_phase(flow: Mapping[str, Any]) -> Phase:
    purpose = flow.get("purpose")
    source = flow.get("source")
    source_site = source.get("site") if isinstance(source, Mapping) else None
    if purpose == "cold":
        return Phase.COLD_WEST_EAST if source_site == "west" else Phase.COLD_EAST_WEST
    if isinstance(purpose, str) and (purpose.startswith("mtu-") or purpose == "tcp-mss-sustained"):
        return Phase.MTU_TRANSPORT
    if purpose == "iperf3" or isinstance(purpose, str) and purpose.startswith("concurrent-"):
        return Phase.APPROVED_LOAD
    return {
        "route-drift": Phase.ROUTE_MUTATION,
        "service-recovery": Phase.SERVICE_STOP,
        "reboot-west-recovery": Phase.EC2_REBOOT_WEST,
        "reboot-east-recovery": Phase.EC2_REBOOT_EAST,
        "route-acceptance-withdrawal": Phase.TAILSCALE_WITHDRAWAL,
    }.get(cast(str, purpose), Phase.EVIDENCE)


def _validate_probe_evidence(flow: FlowRecord, value: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    receiver = value.get("receiver")
    payload_sha256 = value.get("payload_sha256")
    common_invalid = (
        value.get("flow_id") != flow.flow_id
        or value.get("protocol") != flow.protocol
        or value.get("source_ip") != flow.source.private_ip
        or value.get("destination_ip") != flow.destination.private_ip
        or value.get("success") is not True
        or isinstance(value.get("response_timeout_seconds"), bool)
        or not isinstance(value.get("response_timeout_seconds"), (int, float))
        or not 0 < value.get("response_timeout_seconds", 0) <= 30
        or not isinstance(payload_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", payload_sha256) is None
        or not isinstance(receiver, Mapping)
    )
    if common_invalid:
        raise ProbeError(f"probe {flow.flow_id} did not prove its exact endpoint identities and payload digest")
    if flow.protocol == "icmp":
        if (
            value.get("source_port") is not None
            or value.get("destination_port") is not None
            or value.get("icmp_request_type") != 8
            or value.get("icmp_reply_type") != 0
            or receiver.get("reply_source_ip") != flow.destination.private_ip
            or receiver.get("source_identity_verified") is not True
        ):
            raise ProbeError(f"ICMP probe {flow.flow_id} failed source/reply identity without-port proof")
    elif (
        value.get("source_port") != flow.source_port
        or value.get("destination_port") != flow.destination_port
        or receiver.get("flow_id") != flow.flow_id
        or receiver.get("payload_sha256") != payload_sha256
        or receiver.get("source_ip") != flow.source.private_ip
        or receiver.get("source_port") != flow.source_port
        or receiver.get("receives") != 1
        or receiver.get("duplicates") != 0
        or receiver.get("sessions") != 1
    ):
        raise ProbeError(f"probe {flow.flow_id} failed receiver identity, payload, or zero-duplicate proof")
    return cast(
        dict[str, Any],
        sanitize_evidence_value(
            {
                **dict(value),
                "kind": kind,
                "process_generation": flow.process_generation,
            }
        ),
    )


def _validate_metric_evidence(
    flows: Sequence[FlowRecord],
    value: Mapping[str, Any],
    *,
    mode: Literal["normal", "mtu-drop", "bidirectional"] = "normal",
    drop_proof: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not flows or len({flow.flow_id for flow in flows}) != len(flows):
        raise MetricAssertionError("metric evidence scope must contain unique declared flows")
    packet = value.get("packet_deltas")
    byte = value.get("byte_deltas")
    session = value.get("session")
    malformed = value.get("malformed_deltas")
    integrity = session.get("integrity_metric_deltas") if isinstance(session, Mapping) else None
    unexpected = value.get("unexpected_deltas")
    if value.get("unexpected_growth") is not False or not isinstance(packet, Mapping) or not isinstance(byte, Mapping):
        raise MetricAssertionError("metric evidence is incomplete or reports unexpected growth")
    if mode == "bidirectional":
        if (
            set(packet) != set(SITES)
            or set(byte) != set(SITES)
            or any(
                not isinstance(packet[site], Mapping)
                or set(packet[site]) != set(_PACKET_METRICS)
                or any(not isinstance(delta, (int, float)) or delta <= 0 for delta in packet[site].values())
                or not isinstance(byte[site], Mapping)
                or set(byte[site]) != set(_BYTE_METRICS)
                or any(not isinstance(delta, (int, float)) or delta <= 0 for delta in byte[site].values())
                for site in SITES
            )
            or not isinstance(unexpected, Mapping)
            or set(unexpected) != set(SITES)
            or any(
                not isinstance(unexpected[site], Mapping)
                or set(unexpected[site]) != set(_UNEXPECTED_FLOW_METRICS)
                or any(delta != 0 for delta in unexpected[site].values())
                for site in SITES
            )
        ):
            raise MetricAssertionError("bidirectional load metrics do not prove both lanes and zero errors")
    else:
        expected_sessions = 0 if mode == "mtu-drop" else (None if flows[0].protocol == "icmp" else 1)
        if (
            set(packet) != set(_PACKET_METRICS)
            or set(byte) != set(_BYTE_METRICS)
            or value.get("initiator_site") != flows[0].source.site
            or not isinstance(session, Mapping)
            or session.get("receiver_sessions") != expected_sessions
            or session.get("receiver_identity_verified") is not True
            or not isinstance(integrity, Mapping)
            or set(integrity) != set(_SESSION_INTEGRITY_METRICS)
            or any(delta != 0 for delta in integrity.values())
            or not isinstance(malformed, Mapping)
            or set(malformed) != set(SITES)
            or any(delta != 0 for delta in malformed.values())
            or not isinstance(unexpected, Mapping)
            or set(unexpected) != set(SITES)
            or any(
                not isinstance(site_values, Mapping) or set(site_values) != set(_UNEXPECTED_FLOW_METRICS)
                for site_values in unexpected.values()
            )
        ):
            raise MetricAssertionError("flow metric evidence has an invalid protocol-specific shape")
        if mode == "normal":
            if (
                any(not isinstance(delta, (int, float)) or delta <= 0 for delta in packet.values())
                or any(not isinstance(delta, (int, float)) or delta <= 0 for delta in byte.values())
                or any(delta != 0 for site_values in unexpected.values() for delta in site_values.values())
            ):
                raise MetricAssertionError("normal flow metrics did not grow expected counters exclusively")
        else:
            intentional = value.get("intentional_mtu_drop")
            initiator_site = flows[0].source.site
            capture = drop_proof.get("capture") if isinstance(drop_proof, Mapping) else None
            expected_drop_proof = {
                "protocol",
                "application_reply_received",
                "pmtu_icmp_expected",
                "process_generation",
                "capture",
            }
            capture_valid = (
                isinstance(capture, Mapping)
                and set(capture)
                == {
                    "interface",
                    "file_sha256",
                    "icmp_checksum",
                    "raw_pcap_deleted",
                    "request_count",
                    "inner_bytes",
                    "payload_bytes",
                    "payload_sha256",
                }
                and isinstance(capture.get("interface"), str)
                and bool(capture["interface"])
                and re.fullmatch(r"[0-9a-f]{64}", str(capture.get("file_sha256", ""))) is not None
                and capture.get("icmp_checksum") == "valid"
                and capture.get("raw_pcap_deleted") is True
                and not isinstance(capture.get("request_count"), bool)
                and capture.get("request_count") == 1
                and not isinstance(capture.get("inner_bytes"), bool)
                and isinstance(capture.get("inner_bytes"), int)
                and not isinstance(capture.get("payload_bytes"), bool)
                and isinstance(capture.get("payload_bytes"), int)
                and capture["inner_bytes"] == capture["payload_bytes"] + 28
                and re.fullmatch(r"[0-9a-f]{64}", str(capture.get("payload_sha256", ""))) is not None
            )
            if (
                not isinstance(intentional, Mapping)
                or intentional
                != {
                    "site": initiator_site,
                    "generic_drops_delta": 1,
                    "mtu_specific": {
                        "metric": "gwlb_mtu_drops_total",
                        "delta": 1,
                        "direction": "ingress",
                        "family": "ipv4",
                    },
                }
                or unexpected[initiator_site].get("drops") != 1
                or unexpected[initiator_site].get("gwlb_mtu_drops_total") != 1
                or any(
                    delta != 0
                    for site, site_values in unexpected.items()
                    for name, delta in site_values.items()
                    if not (site == initiator_site and name in {"drops", "gwlb_mtu_drops_total"})
                )
                or not isinstance(drop_proof, Mapping)
                or set(drop_proof) != expected_drop_proof
                or drop_proof.get("protocol") != flows[0].protocol
                or drop_proof.get("application_reply_received") is not False
                or drop_proof.get("pmtu_icmp_expected") is not False
                or drop_proof.get("process_generation") != flows[0].process_generation
                or (flows[0].protocol == "icmp" and not capture_valid)
                or (flows[0].protocol == "udp" and capture is not None)
            ):
                raise MetricAssertionError(
                    "oversized flow did not prove its failed reply, process/capture identity, and exact MTU drop pair"
                )
    document = {
        "flow_id": flows[0].flow_id,
        "scope_flow_ids": [flow.flow_id for flow in flows],
        "mode": mode,
        **dict(value),
    }
    if drop_proof is not None:
        document["drop_proof"] = dict(drop_proof)
    return cast(
        dict[str, Any],
        sanitize_evidence_value(document),
    )


def _validate_flow_log_evidence(
    flow: Mapping[str, Any],
    value: Mapping[str, Any],
    workload_checks: Mapping[str, Any],
) -> dict[str, Any]:
    expected_keys = {
        "flow_id",
        "flow_tuple",
        "accepted",
        "reverse_required",
        "forward_matches",
        "reverse_matches",
        "packet_count",
        "byte_count",
        "phase",
        "window",
        "path_evidence",
        "unexpected_path_matches",
        "aggregation_overlap_path_matches",
        "correlation_mode",
        "flow_logs_uniquely_identify_flow",
        "aws_aggregation_limitation",
        "process_generation",
        "unique_identity_evidence",
    }
    source = flow.get("source")
    destination = flow.get("destination")
    if (
        set(value) != expected_keys
        or not isinstance(source, Mapping)
        or not isinstance(destination, Mapping)
        or value.get("flow_id") != flow.get("flow_id")
        or value.get("accepted") is not True
        or value.get("reverse_required") is not (flow.get("expected_result") == "success")
        or value.get("process_generation") != flow.get("process_generation")
        or value.get("phase") != _flow_phase(flow).value
    ):
        raise FlowLogError("Flow Log evidence is not bound to its declared flow and process generation")
    expected_tuple = {
        "source_ip": source.get("private_ip"),
        "destination_ip": destination.get("private_ip"),
        "protocol": flow.get("protocol"),
    }
    if flow.get("protocol") != "icmp":
        expected_tuple.update(
            {"source_port": flow.get("source_port"), "destination_port": flow.get("destination_port")}
        )
    window = value.get("window")
    if (
        value.get("flow_tuple") != expected_tuple
        or not isinstance(window, Mapping)
        or set(window) != {"start_epoch", "end_epoch", "aggregation_allowance_seconds"}
        or isinstance(window.get("start_epoch"), bool)
        or not isinstance(window.get("start_epoch"), int)
        or isinstance(window.get("end_epoch"), bool)
        or not isinstance(window.get("end_epoch"), int)
        or not 0 <= window["start_epoch"] <= window["end_epoch"]
        or window["end_epoch"] - window["start_epoch"] > 7200
        or window.get("aggregation_allowance_seconds") != 60
    ):
        raise FlowLogError("Flow Log evidence has an invalid tuple or bounded aggregation window")
    source_key = f"{source.get('site')}-{source.get('role')}"
    destination_key = f"{destination.get('site')}-{destination.get('role')}"
    source_identity = workload_checks.get(source_key)
    destination_identity = workload_checks.get(destination_key)
    if not isinstance(source_identity, Mapping) or not isinstance(destination_identity, Mapping):
        raise FlowLogError("Flow Log evidence has no readiness workload identity")
    expected_specs = (
        [("source-egress", source_identity, "egress")]
        if flow.get("expected_result") == "mtu-drop"
        else [
            ("source-egress", source_identity, "egress"),
            ("destination-ingress", destination_identity, "ingress"),
            ("responder-egress", destination_identity, "egress"),
            ("initiator-ingress", source_identity, "ingress"),
        ]
    )
    paths = value.get("path_evidence")
    if not isinstance(paths, list) or len(paths) != len(expected_specs):
        raise FlowLogError("Flow Log evidence does not contain the exact required workload paths")
    for path, (name, identity, direction) in zip(paths, expected_specs, strict=True):
        if (
            not isinstance(path, Mapping)
            or set(path)
            != {
                "path",
                "site",
                "role",
                "flow_direction",
                "instance_id",
                "interface_id",
                "subnet_id",
                "matches",
                "packet_count",
                "byte_count",
            }
            or path.get("path") != name
            or path.get("site") != identity.get("site")
            or path.get("role") != identity.get("role")
            or path.get("flow_direction") != direction
            or path.get("instance_id") != identity.get("instance_id")
            or path.get("interface_id") != identity.get("interface_id")
            or path.get("subnet_id") != identity.get("subnet_id")
            or isinstance(path.get("matches"), bool)
            or not isinstance(path.get("matches"), int)
            or path["matches"] < 1
            or isinstance(path.get("packet_count"), bool)
            or not isinstance(path.get("packet_count"), int)
            or path["packet_count"] < 1
            or isinstance(path.get("byte_count"), bool)
            or not isinstance(path.get("byte_count"), int)
            or path["byte_count"] < 1
        ):
            raise FlowLogError("Flow Log evidence contains a missing or mismatched ENI path")
    forward_matches = sum(cast(int, path["matches"]) for path in paths if path["flow_direction"] in {"egress", "ingress"} and path["path"] in {"source-egress", "destination-ingress"})
    reverse_matches = sum(cast(int, path["matches"]) for path in paths if path["path"] in {"responder-egress", "initiator-ingress"})
    aggregation_overlap = value.get("aggregation_overlap_path_matches")
    icmp_drop = flow.get("protocol") == "icmp" and flow.get("expected_result") == "mtu-drop"
    if (
        value.get("forward_matches") != forward_matches
        or value.get("reverse_matches") != reverse_matches
        or value.get("unexpected_path_matches") != 0
        or isinstance(aggregation_overlap, bool)
        or not isinstance(aggregation_overlap, int)
        or aggregation_overlap < 0
        or (not icmp_drop and aggregation_overlap != 0)
        or value.get("packet_count") != sum(cast(int, path["packet_count"]) for path in paths)
        or value.get("byte_count") != sum(cast(int, path["byte_count"]) for path in paths)
        or (flow.get("expected_result") == "mtu-drop" and reverse_matches != 0)
    ):
        raise FlowLogError("Flow Log aggregate counts differ from exact workload-path evidence")
    if flow.get("protocol") == "icmp":
        if (
            value.get("correlation_mode") != "icmp-lane-window"
            or value.get("flow_logs_uniquely_identify_flow") is not False
            or value.get("aws_aggregation_limitation")
            != "icmp-records-omit-ports-and-may-aggregate-repeated-tuples"
            or value.get("unique_identity_evidence")
            != (
                ["process-generation", "mtu-request-capture", "failed-application-reply", "mtu-drop-metrics"]
                if icmp_drop
                else ["process-generation", "application-reply"]
            )
        ):
            raise FlowLogError("ICMP Flow Logs must be explicitly non-unique lane-window evidence")
    elif (
        value.get("correlation_mode") != "transport-5-tuple-window"
        or value.get("flow_logs_uniquely_identify_flow") is not True
        or value.get("aws_aggregation_limitation") is not None
        or value.get("unique_identity_evidence") != ["transport-ports", "process-generation"]
    ):
        raise FlowLogError("transport Flow Log evidence does not prove its exact windowed tuple")
    return cast(dict[str, Any], sanitize_evidence_value(value))


def _validate_drill_result(name: Phase, value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("passed") is not True or value.get("restored") is not True:
        raise ResilienceError(f"{name.value} did not pass and restore exact pre-mutation state")
    if name in {Phase.ROUTE_MUTATION, Phase.TAILSCALE_WITHDRAWAL}:
        continuity = value.get("continuity")
        if not isinstance(continuity, Mapping) or continuity.get("bounded") is not True:
            raise ResilienceError(f"{name.value} did not prove bounded one-socket continuity")
    if name == Phase.ROUTE_MUTATION:
        readiness = value.get("readiness_during_drift")
        repair_delta = value.get("repair_metric_delta")
        if (
            not isinstance(readiness, Mapping)
            or readiness.get("before_repair") is not True
            or readiness.get("exact_rule_missing") is not True
            or not isinstance(repair_delta, (int, float))
            or isinstance(repair_delta, bool)
            or repair_delta < 1
            or readiness.get("routing_drift_repairs_delta") != repair_delta
            or readiness.get("drift_observed")
            is not (
                readiness.get("exact_rule_missing") is True
                and (
                    readiness.get("host_preflight_failed") is True
                    or readiness.get("unhealthy") is True
                    or repair_delta > 0
                )
            )
            or readiness.get("drift_observed") is not True
            or not isinstance(readiness.get("missing_cidr"), str)
            or not isinstance(readiness.get("reason"), str)
        ):
            raise ResilienceError("route drift did not become unready/report exact drift before repair")
    if name in {Phase.SERVICE_STOP, Phase.EC2_REBOOT_WEST, Phase.EC2_REBOOT_EAST}:
        recovery = value.get("recovery")
        if not isinstance(recovery, Mapping) or recovery.get("new_cold_flow") is not True:
            raise ResilienceError(f"{name.value} did not prove new-cold-flow recovery")
    if name == Phase.SERVICE_STOP and (
        value.get("target_transition") != ["healthy", "unhealthy", "healthy"]
        or value.get("process_generation_changed") is not True
    ):
        raise ResilienceError("service stop did not prove exact target and process transitions")
    if name in {Phase.EC2_REBOOT_WEST, Phase.EC2_REBOOT_EAST}:
        expected_site: Site = "west" if name == Phase.EC2_REBOOT_WEST else "east"
        if (
            value.get("site") != expected_site
            or value.get("boot_generation_changed") is not True
            or value.get("process_generation_changed") is not True
            or value.get("target_recovered_healthy") is not True
            or value.get("persistent_configuration_recovered") is not True
        ):
            raise ResilienceError(f"{name.value} did not prove persistent regional recovery")
    if name == Phase.TAILSCALE_WITHDRAWAL and value.get("credential_rotation") is not False:
        raise ResilienceError("Tailscale route reacceptance changed the bootstrap credential identity")
    if name == Phase.TAILSCALE_WITHDRAWAL and value.get("exact_routes_withdrawn") is not True:
        raise ResilienceError("Tailscale withdrawal did not prove the exact accepted route set was absent")
    if name == Phase.TAILSCALE_WITHDRAWAL and (
        not isinstance(value.get("withdrawn_cidrs"), list)
        or value.get("withdrawn_cidrs") != value.get("restored_cidrs")
    ):
        raise ResilienceError("Tailscale withdrawal/restoration did not retain one exact prefix set")
    return cast(
        dict[str, Any],
        sanitize_evidence_value(
            {"name": name.value, **{key: child for key, child in value.items() if key not in {"probe", "metrics", "stream"}}}
        ),
    )


_APPLIANCE_READINESS_GATES = (
    "cloud_init_complete",
    "tailscaled_active",
    "envelope_active",
    "host_network_active",
    "tailscale_backend_running",
    "advertised_routes_exact",
    "accepted_routes_exact",
    "host_network_preflight",
    "links_ready",
    "sysctls_ready",
    "firewall_mss_ready",
    "envelope_health",
    "metrics_ready",
    "capture_tools_ready",
    "target_healthy",
)
_WORKLOAD_READINESS_GATES = (
    "cloud_init_complete",
    "ssm_active",
    "host_network_preflight",
    "links_ready",
    "tools_ready",
    "tcp_listener_ready",
    "udp_listener_ready",
)


def _validate_readiness_summary(
    deployment: ProtectedDeployment, value: Mapping[str, Any], *, run_id: str
) -> dict[str, Any]:
    appliances = value.get("appliance_checks")
    workloads = value.get("workload_checks")
    if (
        value.get("appliance_count") != 2
        or value.get("workload_count") != 4
        or value.get("all_hosts_ready") is not True
        or value.get("directional_routes_exact") is not True
        or not isinstance(appliances, Mapping)
        or set(appliances) != set(SITES)
        or not isinstance(workloads, Mapping)
        or set(workloads) != {f"{site}-{role}" for site in SITES for role in WORKLOAD_ROLES}
    ):
        raise ReadinessError("readiness did not prove the exact six-host directional topology")
    for site in SITES:
        checks = appliances[site]
        runtime = deployment.runtime(site)
        if not isinstance(checks, Mapping) or any(checks.get(gate) is not True for gate in _APPLIANCE_READINESS_GATES):
            raise ReadinessError(f"{site} appliance omitted a required readiness gate")
        if (
            checks.get("advertised_routes")
            != sorted((*runtime.gwlb_return_cidrs, *runtime.local_delivery_cidrs))
            or checks.get("accepted_routes") != sorted(runtime.remote_tailnet_cidrs)
            or checks.get("accepted_route_peer") != f"{run_id}-{_opposite(site)}"
            or checks.get("links")
            != [runtime.underlay_interface, runtime.tailscale_iface, runtime.tun_name]
            or checks.get("target_status") != "healthy"
        ):
            raise ReadinessError(f"{site} appliance route, link, or target identity is not exact")
    workload_interface_ids: list[str] = []
    for site in SITES:
        for role in WORKLOAD_ROLES:
            key = f"{site}-{role}"
            checks = workloads[key]
            target = deployment.workloads.target(site, role)
            if not isinstance(checks, Mapping) or any(checks.get(gate) is not True for gate in _WORKLOAD_READINESS_GATES):
                raise ReadinessError(f"{key} omitted a required readiness gate")
            if (
                checks.get("private_ip") != target.private_ip
                or checks.get("instance_id") != target.instance_id
                or checks.get("subnet_id") != target.subnet_id
                or not isinstance(checks.get("interface_id"), str)
                or not _ENI_ID_RE.fullmatch(cast(str, checks["interface_id"]))
                or checks.get("flow_directions") != ["egress", "ingress"]
            ):
                raise ReadinessError(f"{key} Flow Log/host-network identity is not exact")
            workload_interface_ids.append(cast(str, checks["interface_id"]))
    if len(set(workload_interface_ids)) != len(workload_interface_ids):
        raise ReadinessError("readiness workload Flow Log ENI identities are not unique")
    return cast(dict[str, Any], sanitize_evidence_value(value))


class TwoRegionE2ERunner:
    """One serialized, fail-closed post-deployment acceptance transaction."""

    def __init__(
        self,
        *,
        run_id: str,
        raw_deployment: Mapping[str, Any],
        site_regions: Mapping[str, str],
        lifecycle: ProtectedLifecycleAPI,
        operations: LiveOperations,
        evidence_path: pathlib.Path,
        budgets: TimeoutBudgets = DEFAULT_TIMEOUTS,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not _RUN_ID_RE.fullmatch(run_id):
            raise E2EError("live run_id must be a lowercase deployment slug")
        self.run_id = run_id
        self.raw_deployment = dict(raw_deployment)
        self.site_regions = dict(site_regions)
        self.lifecycle = lifecycle
        self.operations = operations
        self.evidence_path = evidence_path.expanduser().resolve()
        self.budgets = budgets
        self.monotonic = monotonic
        self.started_monotonic = monotonic()
        self.document = new_live_evidence(run_id, budgets)
        self.deployment: ProtectedDeployment | None = None
        self.ledger = FlowLedger(run_id)
        self.claimed = False
        self.flow_log_handle: object | None = None
        self.flow_logs_stopped = False
        self.current_phase: Phase = Phase.CONSUME_DEPLOYMENT

    def _checkpoint(self) -> None:
        self.document["generated_at"] = _utc_now()
        write_evidence(self.evidence_path, self.document)

    def _phase(self, phase: Phase, operation: Callable[[], Mapping[str, Any] | None]) -> Mapping[str, Any]:
        self.current_phase = phase
        budget = _phase_budget(phase, self.budgets)
        record: dict[str, Any] = {
            "name": phase.value,
            "status": "running",
            "budget_seconds": budget,
            "started_at": _utc_now(),
            "finished_at": None,
            "summary": {},
        }
        self.document["phases"].append(record)
        started = self.monotonic()
        try:
            if phase not in {Phase.EVIDENCE, Phase.CLEANUP} and started - self.started_monotonic >= self.budgets.hard_timeout:
                raise TimeoutError(f"live E2E exceeded its {self.budgets.hard_timeout}-second acceptance timeout")
            summary = dict(operation() or {})
            elapsed = self.monotonic() - started
            if elapsed > budget:
                raise AcceptanceError(f"{phase.value} exceeded its {budget}-second timeout budget")
            if phase not in {Phase.EVIDENCE, Phase.CLEANUP} and self.monotonic() - self.started_monotonic > self.budgets.hard_timeout:
                raise TimeoutError(f"live E2E exceeded its {self.budgets.hard_timeout}-second acceptance timeout")
            record["status"] = "passed"
            record["summary"] = sanitize_evidence_value(summary)
            self.document["assertions"].append(
                {"name": phase.value, "passed": True, "summary": f"completed within {budget}s"}
            )
            return summary
        except BaseException as error:
            record["status"] = "failed"
            record["summary"] = {
                "category": type(error).__name__,
                "message": _sanitize_string(str(error)),
            }
            self.document["assertions"].append(
                {"name": phase.value, "passed": False, "summary": _sanitize_string(str(error))}
            )
            raise
        finally:
            record["finished_at"] = _utc_now()
            if self.deployment is not None:
                self._checkpoint()

    def _allocate(
        self,
        protocol: ProtocolName,
        source_site: Site,
        generation_name: str,
        *,
        purpose: str,
        expected_result: Literal["success", "mtu-drop"] = "success",
        generation: ProcessGeneration | None = None,
    ) -> FlowRecord:
        selected_generation = generation or self.ledger.begin_generation(generation_name)
        destination_site = _opposite(source_site)
        assert self.deployment is not None
        return self.ledger.allocate(
            protocol,
            self.deployment.workloads.target(source_site, "initiator"),
            self.deployment.workloads.target(destination_site, "responder"),
            destination_port=None if protocol == "icmp" else 5201,
            generation=selected_generation,
            purpose=purpose,
            expected_result=expected_result,
        )

    def _record_probe_result(self, flow: FlowRecord, result: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
        probe_value = result.get("probe")
        if not isinstance(probe_value, Mapping):
            raise ProbeError(f"flow {flow.flow_id} returned no receiver-observed probe evidence")
        probe = _validate_probe_evidence(flow, probe_value, kind=kind)
        self.document["probes"].append(probe)
        metric_value = result.get("metrics")
        if metric_value is not None:
            if not isinstance(metric_value, Mapping):
                raise MetricAssertionError(f"flow {flow.flow_id} metric evidence is not an object")
            self.document["metrics"].append(_validate_metric_evidence((flow,), metric_value))
        return probe

    def _record_drill(self, phase: Phase, flow: FlowRecord, result: Mapping[str, Any]) -> dict[str, Any]:
        drill = _validate_drill_result(phase, result)
        probe_value = result.get("probe")
        if probe_value is not None:
            if not isinstance(probe_value, Mapping):
                raise ProbeError(f"{phase.value} recovery probe evidence is invalid")
            self.document["probes"].append(_validate_probe_evidence(flow, probe_value, kind="recovery"))
        stream_value = result.get("stream")
        if stream_value is not None:
            if not isinstance(stream_value, Mapping):
                raise StreamAnalysisError(f"{phase.value} stream evidence is invalid")
            self.document["streams"].append(sanitize_evidence_value(stream_value))
        metric_value = result.get("metrics")
        if not isinstance(metric_value, Mapping):
            raise MetricAssertionError(f"{phase.value} did not return metric evidence for its declared flow")
        self.document["metrics"].append(_validate_metric_evidence((flow,), metric_value))
        self.document["resilience"].append(drill)
        return drill

    def _skip_to_evidence(self) -> None:
        present = {record["name"] for record in self.document["phases"]}
        for phase in LIVE_PHASES:
            if phase in {Phase.EVIDENCE, Phase.CLEANUP}:
                break
            if phase.value in present:
                continue
            self.document["phases"].append(
                {
                    "name": phase.value,
                    "status": "skipped",
                    "budget_seconds": _phase_budget(phase, self.budgets),
                    "started_at": _utc_now(),
                    "finished_at": _utc_now(),
                    "summary": {"reason": "prior phase failed closed"},
                }
            )
            self.document["assertions"].append(
                {"name": phase.value, "passed": False, "summary": "skipped after fail-closed gate"}
            )

    def _stop_flow_logs(self) -> Mapping[str, Any]:
        if self.flow_log_handle is None or self.flow_logs_stopped:
            return {"stopped": True, "created": False}
        result = self.operations.stop_flow_logs(
            self.flow_log_handle,
            timeout_seconds=self.budgets.flow_log_start,
        )
        self.flow_logs_stopped = result.get("stopped") is True and result.get("ownership_preserved") is True
        return result

    def _collect_failure_diagnostics(self) -> bool:
        try:
            self.document["diagnostics"] = sanitize_evidence_value(
                self.operations.collect_diagnostics(self.deployment)
            )
            return True
        except (TimeoutError, InterruptedError, KeyboardInterrupt):
            self._skip_failure_diagnostics("active run limit exhausted during diagnostics; cleanup reservation preserved")
            return False
        except Exception as diagnostic_error:
            self.document["diagnostics"] = {
                "collection": "failed",
                "error": _sanitize_string(str(diagnostic_error)),
            }
            return True

    def _skip_failure_diagnostics(self, reason: str) -> None:
        self.document["diagnostics"] = {
            "collection": "skipped",
            "reason": reason,
        }

    def run(self) -> LiveRunResult:
        primary_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        ownership_blocker: BaseException | None = None
        acceptance_passed = False
        active_limit_exhausted = False
        try:
            def consume() -> Mapping[str, Any]:
                deployment = parse_protected_deployment_output(
                    self.raw_deployment,
                    site_regions=self.site_regions,
                )
                self.deployment = deployment
                self.document["deployment"] = deployment.as_dict()
                self.document["load_profile"] = {
                    **deployment.load_profile.as_dict(),
                    "sha256": deployment.load_profile.sha256,
                    "source": "protected-saved-plan-output",
                    "immutable": True,
                }
                claim = dict(self.lifecycle.claim(self.raw_deployment, deployment))
                self.claimed = True
                self.document["lifecycle"].update(sanitize_evidence_value(claim))
                self.document["lifecycle"]["claimed"] = True
                return {
                    "output_sha256": deployment.output_sha256,
                    "load_profile_sha256": deployment.load_profile.sha256,
                    "manifest_phase": claim.get("manifest_phase", "claimed"),
                }

            self._phase(Phase.CONSUME_DEPLOYMENT, consume)

            def drift_before() -> Mapping[str, Any]:
                result = dict(self.lifecycle.verify_no_drift("before"))
                if result.get("clean") is not True:
                    raise DriftError("protected Terraform pre-test plan is not empty")
                self.document["lifecycle"]["drift_precheck"] = "clean"
                return result

            self._phase(Phase.DRIFT_PRECHECK, drift_before)
            assert self.deployment is not None

            def readiness() -> Mapping[str, Any]:
                topology = dict(
                    self.operations.verify_readiness_and_topology(
                        self.deployment,
                        timeout_seconds=self.budgets.readiness_topology,
                    )
                )
                self.document["topology"] = _validate_readiness_summary(
                    self.deployment, topology, run_id=self.run_id
                )
                return topology

            self._phase(Phase.READINESS_TOPOLOGY, readiness)

            def flow_log_start() -> Mapping[str, Any]:
                self.flow_log_handle = self.operations.start_flow_logs(
                    self.deployment,
                    timeout_seconds=self.budgets.flow_log_start,
                )
                return {"active": True, "scope": "both-vpcs", "aggregation_seconds": 60, "managed": True}

            self._phase(Phase.FLOW_LOG_START, flow_log_start)

            def run_cold_direction(source_site: Site) -> Mapping[str, Any]:
                generation = self.ledger.begin_generation(f"{source_site}-cold")
                flows = [
                    self._allocate(
                        protocol,
                        source_site,
                        f"{source_site}-cold",
                        purpose="cold",
                        generation=generation,
                    )
                    for protocol in PROTOCOLS
                ]
                result = dict(
                    self.operations.run_cold_direction(
                        self.deployment,
                        source_site,
                        flows,
                        timeout_seconds=self.budgets.cold_direction,
                    )
                )
                context = result.get("context")
                if (
                    not isinstance(context, Mapping)
                    or context.get("both_processes_restarted") is not True
                    or context.get("matching_return_context_before_first_packet") is not False
                    or context.get("matching_flow_ids_absent_before") != [flow.flow_id for flow in flows]
                    or context.get("allocation_unique_in_generation") is not True
                    or context.get("targets_healthy_before_first_packet") is not True
                    or set(context.get("process_ids", {})) != set(SITES)
                ):
                    raise ProbeError(f"{source_site} cold direction did not prove empty matching return context")
                values = result.get("results")
                if not isinstance(values, list):
                    raise ProbeError(f"{source_site} cold direction returned no protocol matrix")
                by_id = {
                    str(value.get("flow_id")): value
                    for value in values
                    if isinstance(value, Mapping) and isinstance(value.get("flow_id"), str)
                }
                if set(by_id) != {flow.flow_id for flow in flows}:
                    raise ProbeError(f"{source_site} cold direction did not cover ICMP, TCP, and UDP exactly")
                for flow in flows:
                    self._record_probe_result(flow, cast(Mapping[str, Any], by_id[flow.flow_id]), kind="cold")
                wire = result.get("wire")
                wire_flows = wire.get("flows") if isinstance(wire, Mapping) else None
                if (
                    not isinstance(wire, Mapping)
                    or wire.get("direction") != f"{source_site}-to-{_opposite(source_site)}"
                    or wire.get("capture_bounded") is not True
                    or wire.get("raw_pcaps_deleted") is not True
                    or wire.get("raw_pcaps_retained") is not False
                    or not isinstance(wire_flows, list)
                    or {item.get("flow_id") for item in wire_flows if isinstance(item, Mapping)}
                    != {flow.flow_id for flow in flows}
                    or any(
                        not isinstance(item, Mapping)
                        or item.get("outer_ipv4_checksums") != "valid"
                        or item.get("outer_ips_swapped") is not True
                        or item.get("return_source_port_preserved") is not True
                        or item.get("inner_flow_identity_verified") is not True
                        or item.get("return_udp_source_port") != item.get("original_gwlb_source_port")
                        or item.get("return_udp_destination_port") != 6081
                        or item.get("vni") != 0
                        or item.get("ordered_options_identical") is not True
                        for item in wire_flows
                    )
                ):
                    raise WireAssertionError(f"{source_site} directional wire evidence is incomplete")
                self.document["wire"].append(sanitize_evidence_value(wire))
                return {
                    "direction": f"{source_site}-to-{_opposite(source_site)}",
                    "protocols": list(PROTOCOLS),
                    "flow_ids": [flow.flow_id for flow in flows],
                    "context": context,
                    "wire_asserted": True,
                }

            self._phase(Phase.COLD_WEST_EAST, lambda: run_cold_direction("west"))
            self._phase(Phase.COLD_EAST_WEST, lambda: run_cold_direction("east"))

            def mtu_transport() -> Mapping[str, Any]:
                flows: list[FlowRecord] = []
                for source_site in SITES:
                    generation = self.ledger.begin_generation(f"{source_site}-mtu")
                    for protocol, purpose, expected in (
                        ("icmp", "mtu-safe-icmp", "success"),
                        ("udp", "mtu-safe-udp", "success"),
                        ("icmp", "mtu-oversized-icmp", "mtu-drop"),
                        ("udp", "mtu-oversized-udp", "mtu-drop"),
                        ("tcp", "tcp-mss-sustained", "success"),
                    ):
                        flows.append(
                            self._allocate(
                                cast(ProtocolName, protocol),
                                source_site,
                                f"{source_site}-mtu",
                                purpose=purpose,
                                expected_result=cast(Literal["success", "mtu-drop"], expected),
                                generation=generation,
                            )
                        )
                result = dict(
                    self.operations.run_mtu_transport(
                        self.deployment,
                        self.deployment.load_profile,
                        flows,
                        timeout_seconds=self.budgets.mtu_transport,
                    )
                )
                values = result.get("results")
                directions = result.get("directions")
                if not isinstance(values, list) or not isinstance(directions, list):
                    raise TransportError("MTU/transport operation returned an invalid result")
                by_id = {
                    str(value.get("flow_id")): value
                    for value in values
                    if isinstance(value, Mapping) and isinstance(value.get("flow_id"), str)
                }
                if set(by_id) != {flow.flow_id for flow in flows}:
                    raise TransportError("MTU/transport evidence does not cover every declared flow")
                for flow in flows:
                    value = cast(Mapping[str, Any], by_id[flow.flow_id])
                    metric = value.get("metrics")
                    if not isinstance(metric, Mapping):
                        raise MetricAssertionError(f"MTU flow {flow.flow_id} omitted metric evidence")
                    mode: Literal["normal", "mtu-drop"] = "mtu-drop" if flow.expected_result == "mtu-drop" else "normal"
                    drop_proof = None
                    if flow.expected_result == "mtu-drop":
                        drop_proof = {
                            "protocol": flow.protocol,
                            "application_reply_received": value.get("reply_received"),
                            "pmtu_icmp_expected": value.get("pmtu_icmp_expected"),
                            "process_generation": flow.process_generation,
                            "capture": value.get("capture") if flow.protocol == "icmp" else None,
                        }
                    self.document["metrics"].append(
                        _validate_metric_evidence((flow,), metric, mode=mode, drop_proof=drop_proof)
                    )
                    if flow.expected_result == "success" and flow.protocol in {"icmp", "udp"}:
                        probe = value.get("probe")
                        if not isinstance(probe, Mapping):
                            raise ProbeError(f"safe MTU flow {flow.flow_id} omitted its probe")
                        self.document["probes"].append(_validate_probe_evidence(flow, probe, kind="mtu-safe"))
                    if flow.expected_result == "mtu-drop" and (
                        value.get("reply_received") is not False or value.get("pmtu_icmp_expected") is not False
                    ):
                        raise TransportError(f"oversized flow {flow.flow_id} did not fail only at the MTU gate")
                if len(directions) != 2 or {value.get("source_site") for value in directions if isinstance(value, Mapping)} != set(SITES):
                    raise TransportError("MTU/transport evidence does not cover both directional lanes")
                for value in directions:
                    if (
                        not isinstance(value, Mapping)
                        or value.get("inner_mtu") != self.deployment.load_profile.safe_inner_mtu
                        or value.get("safe_icmp_inner_bytes") != self.deployment.load_profile.safe_inner_mtu
                        or value.get("safe_udp_inner_bytes") != self.deployment.load_profile.safe_inner_mtu
                        or value.get("oversized_icmp_inner_bytes") != self.deployment.load_profile.safe_inner_mtu + 1
                        or value.get("oversized_udp_inner_bytes") != self.deployment.load_profile.safe_inner_mtu + 1
                        or not isinstance(value.get("tcp_mss"), int)
                        or value.get("tcp_mss", 65_536) > self.deployment.load_profile.maximum_tcp_mss
                        or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("tcp_syn_capture_sha256", "")))
                        or value.get("tcp_syn_raw_pcap_deleted") is not True
                        or value.get("sustained_tcp_bytes", 0) < self.deployment.load_profile.minimum_sustained_tcp_bytes
                        or value.get("sustained_tcp_duration_seconds", 0)
                        < self.deployment.load_profile.sustained_tcp_duration_seconds
                        or value.get("pmtu_icmp_expected") is not False
                    ):
                        raise TransportError("MTU sizes, TCP MSS, or sustained transfer threshold failed")
                self.document["transport"] = sanitize_evidence_value(directions)
                return {"flow_count": len(flows), "directions": len(directions), "inner_mtu": self.deployment.load_profile.safe_inner_mtu}

            self._phase(Phase.MTU_TRANSPORT, mtu_transport)

            def approved_load() -> Mapping[str, Any]:
                profile = self.deployment.load_profile
                flows: list[FlowRecord] = []
                for source_site in SITES:
                    generation = self.ledger.begin_generation(f"{source_site}-load")
                    flows.append(
                        self._allocate("tcp", source_site, f"{source_site}-load", purpose="iperf3", generation=generation)
                    )
                    for protocol, count in (
                        ("tcp", profile.concurrent_tcp_flows),
                        ("udp", profile.concurrent_udp_flows),
                    ):
                        for index in range(1, count + 1):
                            flows.append(
                                self._allocate(
                                    cast(ProtocolName, protocol),
                                    source_site,
                                    f"{source_site}-load",
                                    purpose=f"concurrent-{protocol}-{index:02d}",
                                    generation=generation,
                                )
                            )
                result = dict(
                    self.operations.run_approved_load(
                        self.deployment,
                        profile,
                        flows,
                        timeout_seconds=self.budgets.approved_load,
                    )
                )
                iperf = result.get("iperf3")
                concurrent = result.get("concurrent")
                if result.get("profile_sha256") != profile.sha256 or not isinstance(iperf, list) or not isinstance(concurrent, list):
                    raise LoadProfileError("load result is not bound to the protected immutable profile")
                outcomes = [*iperf, *concurrent]
                if {value.get("flow_id") for value in outcomes if isinstance(value, Mapping)} != {
                    flow.flow_id for flow in flows
                } or len(outcomes) != len(flows):
                    raise LoadProfileError("load result does not cover every approved flow exactly")
                flow_lookup = {flow.flow_id: flow for flow in flows}
                for value in iperf:
                    if (
                        not isinstance(value, Mapping)
                        or value.get("completed") is not True
                        or not isinstance(value.get("throughput_mbps"), (int, float))
                        or value.get("throughput_mbps", 0) < profile.minimum_throughput_mbps
                        or not isinstance(value.get("duration_seconds"), (int, float))
                        or value.get("duration_seconds", 0) < profile.iperf_duration_seconds
                        or not isinstance(value.get("bytes"), int)
                        or value.get("bytes", 0) <= 0
                        or not isinstance(value.get("syn_mss"), int)
                        or value.get("syn_mss", 65_536) > profile.maximum_tcp_mss
                        or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("syn_capture_sha256", "")))
                        or value.get("raw_pcap_deleted") is not True
                    ):
                        raise LoadProfileError("bounded iperf3 throughput, duration, MSS, or capture cleanup failed")
                for value in concurrent:
                    flow = flow_lookup.get(str(value.get("flow_id", ""))) if isinstance(value, Mapping) else None
                    sent = value.get("sent") if isinstance(value, Mapping) else None
                    received = value.get("received") if isinstance(value, Mapping) else None
                    loss = value.get("loss_percent") if isinstance(value, Mapping) else None
                    if (
                        not isinstance(value, Mapping)
                        or flow is None
                        or value.get("completed") is not True
                        or value.get("protocol") != flow.protocol
                        or value.get("source_port") != flow.source_port
                        or isinstance(sent, bool)
                        or not isinstance(sent, int)
                        or sent <= 0
                        or isinstance(received, bool)
                        or not isinstance(received, int)
                        or not 0 <= received <= sent
                        or isinstance(loss, bool)
                        or not isinstance(loss, (int, float))
                        or not math.isclose(loss, (sent - received) * 100.0 / sent, rel_tol=0.0, abs_tol=1e-9)
                        or not isinstance(value.get("duration_seconds"), (int, float))
                        or value.get("duration_seconds", 0) < profile.concurrent_duration_seconds
                        or loss > profile.maximum_udp_loss_percent
                        or not isinstance(value.get("p99_latency_ms"), (int, float))
                        or value.get("p99_latency_ms", float("inf")) > profile.maximum_p99_latency_ms
                    ):
                        raise LoadProfileError("approved concurrent flow loss, latency, or duration threshold failed")
                metrics = result.get("metrics")
                if not isinstance(metrics, Mapping):
                    raise MetricAssertionError("approved load omitted bidirectional aggregate metrics")
                self.document["metrics"].append(_validate_metric_evidence(flows, metrics, mode="bidirectional"))
                self.document["load"] = sanitize_evidence_value(
                    {
                        **{key: value for key, value in result.items() if key != "metrics"},
                        "thresholds": profile.as_dict(),
                        "flow_count": len(flows),
                        "collision_eviction_error_growth": False,
                    }
                )
                return {"profile_sha256": profile.sha256, "flow_count": len(flows), "directions": 2}

            self._phase(Phase.APPROVED_LOAD, approved_load)

            def route_mutation() -> Mapping[str, Any]:
                flow = self._allocate("udp", "west", "west-envelope-route-drill", purpose="route-drift")
                result = self.operations.run_route_mutation(
                    self.deployment,
                    flow,
                    timeout_seconds=self.budgets.route_mutation,
                    maximum_loss_ns=self.budgets.continuity_loss * 1_000_000_000,
                )
                return self._record_drill(Phase.ROUTE_MUTATION, flow, result)

            self._phase(Phase.ROUTE_MUTATION, route_mutation)

            def service_stop() -> Mapping[str, Any]:
                flow = self._allocate("tcp", "west", "west-envelope-service-recovery", purpose="service-recovery")
                result = self.operations.run_service_stop(
                    self.deployment,
                    flow,
                    timeout_seconds=self.budgets.service_stop,
                )
                return self._record_drill(Phase.SERVICE_STOP, flow, result)

            self._phase(Phase.SERVICE_STOP, service_stop)

            def ec2_reboot(site: Site, phase: Phase) -> Mapping[str, Any]:
                flow = self._allocate("udp", site, f"{site}-envelope-reboot-recovery", purpose=f"reboot-{site}-recovery")
                result = self.operations.run_ec2_reboot(
                    self.deployment,
                    site,
                    flow,
                    timeout_seconds=self.budgets.ec2_reboot,
                )
                return self._record_drill(phase, flow, result)

            self._phase(Phase.EC2_REBOOT_WEST, lambda: ec2_reboot("west", Phase.EC2_REBOOT_WEST))
            self._phase(Phase.EC2_REBOOT_EAST, lambda: ec2_reboot("east", Phase.EC2_REBOOT_EAST))

            def tailscale_withdrawal() -> Mapping[str, Any]:
                flow = self._allocate("udp", "west", "west-tailscale-withdrawal", purpose="route-acceptance-withdrawal")
                result = self.operations.run_tailscale_withdrawal(
                    self.deployment,
                    flow,
                    timeout_seconds=self.budgets.tailscale_withdrawal,
                    maximum_loss_ns=self.budgets.continuity_loss * 1_000_000_000,
                )
                return self._record_drill(Phase.TAILSCALE_WITHDRAWAL, flow, result)

            self._phase(Phase.TAILSCALE_WITHDRAWAL, tailscale_withdrawal)

            def flow_log_capture() -> Mapping[str, Any]:
                assert self.flow_log_handle is not None
                values = list(
                    self.operations.capture_flow_logs(
                        self.flow_log_handle,
                        self.deployment,
                        self.ledger.records,
                        timeout_seconds=self.budgets.flow_log_capture,
                    )
                )
                by_id = {
                    str(value.get("flow_id")): value
                    for value in values
                    if isinstance(value, Mapping) and isinstance(value.get("flow_id"), str)
                }
                if set(by_id) != {flow.flow_id for flow in self.ledger.records}:
                    raise FlowLogError("VPC Flow Logs do not cover every declared protocol tuple")
                workload_checks = self.document.get("topology", {}).get("workload_checks", {})
                if not isinstance(workload_checks, Mapping):
                    raise FlowLogError("VPC Flow Log evidence has no readiness workload identities")
                for flow in self.ledger.records:
                    value = by_id[flow.flow_id]
                    _validate_flow_log_evidence(flow.as_dict(), value, workload_checks)
                self.document["flow_logs"] = [
                    _validate_flow_log_evidence(flow.as_dict(), by_id[flow.flow_id], workload_checks)
                    for flow in self.ledger.records
                ]
                stopped = dict(self._stop_flow_logs())
                if stopped.get("stopped") is not True or stopped.get("ownership_preserved") is not True:
                    raise FlowLogError("managed VPC Flow Log ownership changed during capture")
                return {"flow_count": len(values), "stopped": True, "ownership_preserved": True}

            self._phase(Phase.FLOW_LOG_CAPTURE, flow_log_capture)

            def drift_after() -> Mapping[str, Any]:
                result = dict(self.lifecycle.verify_no_drift("after"))
                if result.get("clean") is not True:
                    raise DriftError("protected Terraform post-test plan is not empty")
                self.document["lifecycle"]["drift_postcheck"] = "clean"
                return result

            self._phase(Phase.DRIFT_POSTCHECK, drift_after)

            def evidence_phase() -> Mapping[str, Any]:
                self.document["flows"] = [flow.as_dict() for flow in self.ledger.records]
                self._checkpoint()
                return {"atomic": True, "mode": "0600", "schema": LIVE_EVIDENCE_SCHEMA}

            self._phase(Phase.EVIDENCE, evidence_phase)
            acceptance_passed = True
        except BaseException as error:
            primary_error = error
            resolution = _ownership_resolution(error)
            if resolution is not None:
                self.document["lifecycle"]["ownership_resolution"] = resolution
            if isinstance(error, (ConcurrentRunError, AmbiguousOwnershipError)):
                ownership_blocker = error
            active_limit_exhausted = isinstance(error, (TimeoutError, InterruptedError, KeyboardInterrupt))
            self.document["status"] = "failed"
            self.document["failure"] = {
                "phase": self.current_phase.value,
                "category": type(error).__name__,
                "message": _sanitize_string(str(error)),
            }
            if self.deployment is not None:
                self.document["flows"] = [flow.as_dict() for flow in self.ledger.records]
            try:
                if not active_limit_exhausted and self.flow_log_handle is not None and not self.flow_logs_stopped:
                    stop_result = dict(self._stop_flow_logs())
                    self.document["lifecycle"]["flow_log_rollback"] = sanitize_evidence_value(stop_result)
                elif active_limit_exhausted and self.flow_log_handle is not None and not self.flow_logs_stopped:
                    self.document["lifecycle"]["flow_log_rollback"] = {
                        "complete": False,
                        "reason": "skipped after active run limit; protected cleanup owns teardown",
                    }
            except BaseException as stop_error:
                active_limit_exhausted = active_limit_exhausted or isinstance(
                    stop_error, (TimeoutError, InterruptedError, KeyboardInterrupt)
                )
                self.document["lifecycle"]["flow_log_rollback"] = {
                    "complete": False,
                    "error": _sanitize_string(str(stop_error)),
                }
            if active_limit_exhausted:
                self._skip_failure_diagnostics("active run limit exhausted; cleanup reservation preserved")
            else:
                active_limit_exhausted = not self._collect_failure_diagnostics()
            self._skip_to_evidence()
            if Phase.EVIDENCE.value not in {record["name"] for record in self.document["phases"]}:
                try:
                    self._phase(
                        Phase.EVIDENCE,
                        lambda: {"atomic": True, "failure_bundle": True, "schema": LIVE_EVIDENCE_SCHEMA},
                    )
                except BaseException as evidence_error:
                    active_limit_exhausted = active_limit_exhausted or isinstance(
                        evidence_error, (TimeoutError, InterruptedError, KeyboardInterrupt)
                    )
                    if primary_error is None:
                        primary_error = evidence_error
        finally:
            if self.claimed and active_limit_exhausted:
                self.document["lifecycle"]["finish"] = "skipped"
                self.document["lifecycle"]["finish_reason"] = (
                    "active run limit exhausted; proceed directly to protected cleanup"
                )
            elif self.claimed:
                try:
                    finish = dict(self.lifecycle.finish(acceptance_passed and primary_error is None))
                    self.document["lifecycle"].update(sanitize_evidence_value(finish))
                except BaseException as finish_error:
                    active_limit_exhausted = active_limit_exhausted or isinstance(
                        finish_error, (TimeoutError, InterruptedError, KeyboardInterrupt)
                    )
                    resolution = _ownership_resolution(finish_error)
                    if resolution is not None:
                        self.document["lifecycle"]["ownership_resolution"] = resolution
                    if isinstance(finish_error, (ConcurrentRunError, AmbiguousOwnershipError)):
                        ownership_blocker = finish_error
                        primary_error = finish_error
                        self.document["failure"] = {
                            "phase": self.current_phase.value,
                            "category": type(finish_error).__name__,
                            "message": _sanitize_string(str(finish_error)),
                        }
                    elif primary_error is None:
                        primary_error = finish_error
                    self.document["lifecycle"]["finish"] = "failed"
                    self.document["lifecycle"]["finish_error"] = _sanitize_string(str(finish_error))
                    if not self.document["diagnostics"]:
                        if isinstance(finish_error, (TimeoutError, InterruptedError, KeyboardInterrupt)):
                            self._skip_failure_diagnostics(
                                "active run limit exhausted during lifecycle finish; cleanup reservation preserved"
                            )
                        else:
                            active_limit_exhausted = not self._collect_failure_diagnostics()
            cleanup_authorized = ownership_blocker is None
            if cleanup_authorized:
                try:
                    def cleanup_operation() -> Mapping[str, Any]:
                        result = dict(self.lifecycle.cleanup())
                        self.document["lifecycle"]["cleanup"] = "complete"
                        return {"complete": True, **result}

                    self._phase(Phase.CLEANUP, cleanup_operation)
                except BaseException as error:
                    cleanup_error = error
                    self.document["lifecycle"]["cleanup"] = "failed"
                    resolution = _ownership_resolution(error)
                    if resolution is not None:
                        self.document["lifecycle"]["ownership_resolution"] = resolution
                    if not self.document["diagnostics"]:
                        if isinstance(error, (TimeoutError, InterruptedError, KeyboardInterrupt)):
                            self._skip_failure_diagnostics(
                                "cleanup reservation exhausted; post-cleanup diagnostics prohibited"
                            )
                        else:
                            self._collect_failure_diagnostics()
            else:
                resolution = _ownership_resolution(ownership_blocker) or "unknown"
                self.document["phases"].append(
                    {
                        "name": Phase.CLEANUP.value,
                        "status": "skipped",
                        "budget_seconds": self.budgets.cleanup,
                        "started_at": _utc_now(),
                        "finished_at": _utc_now(),
                        "summary": {
                            "reason": "destructive cleanup suppressed by durable ownership resolution",
                            "ownership_resolution": resolution,
                        },
                    }
                )
                self.document["assertions"].append(
                    {
                        "name": Phase.CLEANUP.value,
                        "passed": False,
                        "summary": f"not authorized after {resolution}",
                    }
                )

        if cleanup_error is not None:
            self.document["status"] = "failed"
            self.document["failure"] = {
                "phase": Phase.CLEANUP.value,
                "category": type(cleanup_error).__name__,
                "message": _sanitize_string(str(cleanup_error)),
            }
        elif acceptance_passed and primary_error is None:
            self.document["status"] = "passed"
            self.document["failure"] = None
        else:
            self.document["status"] = "failed"
            if self.document["failure"] is None and primary_error is not None:
                self.document["failure"] = {
                    "phase": self.current_phase.value,
                    "category": type(primary_error).__name__,
                    "message": _sanitize_string(str(primary_error)),
                }
        self.document["flows"] = [flow.as_dict() for flow in self.ledger.records]
        self._checkpoint()
        if self.document["status"] == "passed":
            try:
                verify_live_evidence(self.document)
            except EvidenceVerificationError as error:
                primary_error = error
                self.document["status"] = "failed"
                self.document["failure"] = {
                    "phase": Phase.EVIDENCE.value,
                    "category": type(error).__name__,
                    "message": _sanitize_string(str(error)),
                }
                for phase_record in self.document["phases"]:
                    if phase_record["name"] == Phase.EVIDENCE.value:
                        phase_record["status"] = "failed"
                        phase_record["summary"] = {"verification": "failed"}
                for assertion in self.document["assertions"]:
                    if assertion["name"] == Phase.EVIDENCE.value:
                        assertion["passed"] = False
                        assertion["summary"] = "strict live evidence verification failed"
                self._checkpoint()
                exit_code = EXIT_ACCEPTANCE_FAILED
            else:
                exit_code = EXIT_OK
        elif cleanup_error is not None:
            exit_code = EXIT_CLEANUP_FAILED
        elif not self.claimed and isinstance(primary_error, (DeploymentError, LoadProfileError)):
            exit_code = EXIT_CONTRACT_ERROR
        else:
            exit_code = EXIT_ACCEPTANCE_FAILED
        rendered_error = None
        if cleanup_error is not None:
            rendered_error = _sanitize_string(str(cleanup_error))
        elif primary_error is not None:
            rendered_error = _sanitize_string(str(primary_error))
        return LiveRunResult(exit_code, self.evidence_path, validate_evidence(self.document), rendered_error)


class ProtectedLifecycleAdapter:
    """Thin adapter over aws_appliance's durable lifecycle and cleanup APIs."""

    def __init__(
        self,
        config: RunConfig,
        aws: AwsCLI,
        runner: SubprocessRunner,
        run_dir: pathlib.Path,
        terraform_dir: pathlib.Path,
    ):
        self.config = config
        self.aws = aws
        self.runner = runner
        self.run_dir = run_dir.expanduser().resolve()
        self.terraform_dir = terraform_dir.expanduser().resolve()
        self.store = ManifestStore(config, aws, self.run_dir)
        self.manifest: dict[str, Any] | None = None
        self._ownership_state = "unclaimed"
        self._claim_etag: str | None = None
        self._claim_original_manifest: dict[str, Any] | None = None
        self._claim_original_etag: str | None = None
        self._last_persistence_resolution = "none"

    @staticmethod
    def _manifest_claim_id(manifest: Mapping[str, Any] | None) -> str | None:
        e2e = manifest.get("e2e") if isinstance(manifest, Mapping) else None
        claim_id = e2e.get("claim_id") if isinstance(e2e, Mapping) else None
        return claim_id if isinstance(claim_id, str) and claim_id else None

    @staticmethod
    def _propagate_after_owned_recovery(error: BaseException) -> None:
        message = "durable persistence was interrupted after its write committed; cleanup remains authorized"
        if isinstance(error, KeyboardInterrupt):
            raise KeyboardInterrupt(message) from None
        if isinstance(error, InterruptedError):
            raise InterruptedError(message) from None
        if isinstance(error, TimeoutError):
            raise TimeoutError(message) from None
        if not isinstance(error, Exception):
            raise error

    def _clear_claim_original(self) -> None:
        self._claim_original_manifest = None
        self._claim_original_etag = None

    def _install_pending_claim(
        self,
        original: Mapping[str, Any],
        original_etag: str,
        candidate: Mapping[str, Any],
    ) -> None:
        self._claim_original_manifest = copy.deepcopy(dict(original))
        self._claim_original_etag = original_etag
        self._claim_etag = original_etag
        self._ownership_state = "claim-pending"
        self.manifest = copy.deepcopy(dict(candidate))
        self._last_persistence_resolution = "conditional-write"

    def _set_owned(self, manifest: Mapping[str, Any], etag: str, *, terminal: bool) -> None:
        self.manifest = copy.deepcopy(dict(manifest))
        self._claim_etag = etag
        self._ownership_state = "terminal-owned" if terminal else "running-owned"
        self._clear_claim_original()

    def _raise_competing(self) -> None:
        self._ownership_state = "competing"
        self._last_persistence_resolution = "competing-claim"
        self._clear_claim_original()
        raise ConcurrentRunError("durable E2E claim is owned by another runner; cleanup is prohibited")

    def _raise_ambiguous(self) -> None:
        self._ownership_state = "ambiguous"
        self._last_persistence_resolution = "ambiguous-ownership"
        self._clear_claim_original()
        raise AmbiguousOwnershipError(
            "durable E2E ownership is ambiguous after bounded recovery; cleanup is prohibited"
        )

    def _authoritative_recover(self) -> tuple[dict[str, Any], str]:
        def recover() -> dict[str, Any]:
            manifest = self.store.recover()
            return {"manifest": manifest, "etag": self.store.remote_etag}

        try:
            recovered = _bounded_call(recover, 10.0, "durable E2E ownership recovery")
        except BaseException:
            self._raise_ambiguous()
        manifest = recovered.get("manifest")
        etag = recovered.get("etag")
        if not isinstance(manifest, dict) or not isinstance(etag, str) or not etag:
            self._raise_ambiguous()
        return manifest, etag

    def _reconcile_claim_write(
        self,
        original: Mapping[str, Any],
        original_etag: str,
        candidate: Mapping[str, Any],
        error: BaseException,
    ) -> str:
        durable, etag = self._authoritative_recover()
        claim_id = self._manifest_claim_id(candidate)
        if durable == candidate and durable.get("phase") == "e2e_running":
            self._set_owned(durable, etag, terminal=False)
            self._last_persistence_resolution = "recovered-owned-claim"
            self._propagate_after_owned_recovery(error)
            return self._last_persistence_resolution
        if durable == original and etag == original_etag:
            self.manifest = None
            self._claim_etag = None
            self._ownership_state = "unclaimed"
            self._last_persistence_resolution = "claim-not-committed"
            self._clear_claim_original()
            raise ClaimPersistenceError(
                "durable E2E claim was not committed; deployment cleanup remains authorized"
            )
        durable_claim_id = self._manifest_claim_id(durable)
        if durable.get("phase") == "e2e_running" and durable_claim_id is not None and durable_claim_id != claim_id:
            self._raise_competing()
        self._raise_ambiguous()

    def _claim_summary(
        self,
        candidate: Mapping[str, Any],
        deployment: ProtectedDeployment,
        device_ids: Mapping[str, Any],
        persistence: str,
    ) -> Mapping[str, Any]:
        claim_id = self._manifest_claim_id(candidate)
        assert claim_id is not None
        key_generation = candidate.get("tailnet", {}).get("key_generation")
        auth_key_id = str(candidate.get("tailnet", {}).get("auth_key_id", ""))
        return {
            "manifest_phase": "ready",
            "claim_id": claim_id,
            "claim_persistence": persistence,
            "saved_plan_applied_once": True,
            "load_profile_sha256": deployment.load_profile.sha256,
            "load_profile_approved_before_apply": True,
            "tailnet_device_count": len(device_ids),
            "bootstrap_generation": key_generation,
            "bootstrap_identity_sha256": hashlib.sha256(auth_key_id.encode()).hexdigest() if auth_key_id else "absent",
        }

    def claim(self, raw_deployment: Mapping[str, Any], deployment: ProtectedDeployment) -> Mapping[str, Any]:
        manifest = self.store.recover()
        if self.store.remote_etag is None:
            self._raise_ambiguous()
        if manifest.get("phase") != "ready":
            if manifest.get("phase") == "e2e_running" and self._manifest_claim_id(manifest) is not None:
                self._raise_competing()
            self._raise_ambiguous()
        if manifest.get("deployment") != raw_deployment:
            raise DeploymentError("deployment output differs from the durable applied output")
        if "apply_claimed_at" in manifest:
            raise DeploymentError("ready durable manifest retains a stale active apply claim")
        saved_plan = manifest.get("saved_plan")
        if not isinstance(saved_plan, Mapping) or saved_plan.get("apply_started") is not True or saved_plan.get(
            "applied"
        ) is not True:
            raise DeploymentError("durable manifest does not prove one successful reviewed apply")
        try:
            applied_at = validate_canonical_utc_timestamp(saved_plan.get("applied_at"), "saved_plan.applied_at")
        except LifecycleError as error:
            raise LoadProfileError(f"durable {error}") from None
        applied_after = dt.datetime.fromisoformat(applied_at.removesuffix("Z") + "+00:00")
        approved_at = dt.datetime.fromisoformat(deployment.load_profile.approved_at.removesuffix("Z") + "+00:00")
        if approved_at >= applied_after:
            raise LoadProfileError("load thresholds were not approved before the protected apply")
        device_ids = manifest.get("tailnet", {}).get("device_ids")
        if not isinstance(device_ids, Mapping) or set(device_ids) != set(SITES) or len(set(device_ids.values())) != 2:
            raise DeploymentError("durable manifest does not identify exactly two ready Tailnet appliances")
        if any(self.config.sites[site]["region"] != deployment.appliance(site).region for site in SITES):
            raise DeploymentError("deployment regions differ from protected run configuration")
        candidate = copy.deepcopy(manifest)
        claim_id = str(uuid.uuid4())
        candidate["phase"] = "e2e_running"
        candidate["e2e"] = {
            "claim_id": claim_id,
            "output_sha256": deployment.output_sha256,
            "started_at": _utc_now(),
        }
        original_etag = cast(str, self.store.remote_etag)
        self._install_pending_claim(manifest, original_etag, candidate)
        try:
            self.store.write(candidate, if_match=original_etag)
        except BaseException as error:
            persistence = self._reconcile_claim_write(manifest, original_etag, candidate, error)
        else:
            committed_etag = self.store.remote_etag
            if not isinstance(committed_etag, str) or not committed_etag:
                persistence = self._reconcile_claim_write(
                    manifest,
                    original_etag,
                    candidate,
                    LifecycleError("conditional claim write returned no ETag"),
                )
            else:
                self._set_owned(candidate, committed_etag, terminal=False)
                persistence = "conditional-write"
        return self._claim_summary(candidate, deployment, cast(Mapping[str, Any], device_ids), persistence)

    def verify_no_drift(self, stage: Literal["before", "after"]) -> Mapping[str, Any]:
        try:
            terraform_verify_no_drift(
                self.config,
                self.aws,
                self.runner,
                self.run_dir,
                self.terraform_dir,
            )
        except LifecycleError as error:
            raise DriftError(f"{stage} protected Terraform no-drift gate failed: {error}") from None
        return {"clean": True, "stage": stage, "source": "protected-lifecycle"}

    def finish(self, passed: bool) -> Mapping[str, Any]:
        if getattr(self, "_ownership_state", "unclaimed") == "competing":
            self._raise_competing()
        if getattr(self, "_ownership_state", "unclaimed") == "ambiguous":
            self._raise_ambiguous()
        original = self.manifest
        if not isinstance(original, dict) or original.get("phase") != "e2e_running":
            raise ClaimPersistenceError("cannot persist an E2E result without this runner's running claim")
        original_etag = getattr(self, "_claim_etag", None) or self.store.remote_etag
        if not isinstance(original_etag, str) or not original_etag:
            self._raise_ambiguous()
        candidate = copy.deepcopy(original)
        candidate["phase"] = "e2e_passed" if passed else "e2e_failed"
        candidate["e2e"]["finished_at"] = _utc_now()
        candidate["e2e"]["passed"] = passed
        self.manifest = candidate
        self._ownership_state = "terminal-pending"
        self._last_persistence_resolution = "conditional-write"
        try:
            self.store.write(candidate, if_match=original_etag)
        except BaseException as error:
            persistence = self._reconcile_finish_write(original, original_etag, candidate, error)
        else:
            committed_etag = self.store.remote_etag
            if not isinstance(committed_etag, str) or not committed_etag:
                persistence = self._reconcile_finish_write(
                    original,
                    original_etag,
                    candidate,
                    LifecycleError("conditional result write returned no ETag"),
                )
            else:
                self._set_owned(candidate, committed_etag, terminal=True)
                persistence = "conditional-write"
        return {
            "finish": "persisted",
            "acceptance": "passed" if passed else "failed",
            "result_persistence": persistence,
        }

    def _reconcile_finish_write(
        self,
        original: Mapping[str, Any],
        original_etag: str,
        candidate: Mapping[str, Any],
        error: BaseException,
    ) -> str:
        durable, etag = self._authoritative_recover()
        claim_id = self._manifest_claim_id(candidate)
        if durable == candidate and durable.get("phase") in {"e2e_passed", "e2e_failed"}:
            self._set_owned(durable, etag, terminal=True)
            self._last_persistence_resolution = "recovered-owned-result"
            self._propagate_after_owned_recovery(error)
            return self._last_persistence_resolution
        if durable == original and etag == original_etag:
            self._set_owned(original, etag, terminal=False)
            self._last_persistence_resolution = "result-not-committed"
            raise ClaimPersistenceError(
                "durable E2E result was not committed; owned-claim cleanup handoff remains authorized"
            )
        durable_claim_id = self._manifest_claim_id(durable)
        if durable.get("phase") == "e2e_running" and durable_claim_id is not None and durable_claim_id != claim_id:
            self._raise_competing()
        self._raise_ambiguous()

    def _handoff_active_claim_for_cleanup(self) -> Mapping[str, Any] | None:
        state = getattr(self, "_ownership_state", "unclaimed")
        if state == "competing":
            self._raise_competing()
        if state == "ambiguous":
            self._raise_ambiguous()
        durable, etag = self._authoritative_recover()
        in_memory = self.manifest
        if state == "claim-pending":
            original = getattr(self, "_claim_original_manifest", None)
            original_etag = getattr(self, "_claim_original_etag", None)
            if (
                not isinstance(original, dict)
                or original.get("phase") != "ready"
                or not isinstance(original_etag, str)
                or not original_etag
                or getattr(self, "_claim_etag", None) != original_etag
            ):
                self._raise_ambiguous()
            if in_memory is None:
                if durable == original and etag == original_etag:
                    self._claim_etag = None
                    self._ownership_state = "unclaimed"
                    self._last_persistence_resolution = "claim-not-committed"
                    self._clear_claim_original()
                    return None
                if durable.get("phase") == "e2e_running" and self._manifest_claim_id(durable) is not None:
                    self._raise_competing()
                self._raise_ambiguous()
            if (
                not isinstance(in_memory, dict)
                or in_memory.get("phase") != "e2e_running"
                or self._manifest_claim_id(in_memory) is None
            ):
                self._raise_ambiguous()
            if durable == in_memory:
                self._set_owned(durable, etag, terminal=False)
                in_memory = self.manifest
                state = self._ownership_state
            elif durable == original and etag == original_etag:
                self.manifest = None
                self._claim_etag = None
                self._ownership_state = "unclaimed"
                self._last_persistence_resolution = "claim-not-committed"
                self._clear_claim_original()
                return None
            else:
                claim_id = self._manifest_claim_id(in_memory)
                durable_claim_id = self._manifest_claim_id(durable)
                if (
                    durable.get("phase") == "e2e_running"
                    and durable_claim_id is not None
                    and durable_claim_id != claim_id
                ):
                    self._raise_competing()
                self._raise_ambiguous()
        if not isinstance(in_memory, dict):
            if state == "unclaimed":
                self._claim_etag = None
            self._clear_claim_original()
            if durable.get("phase") == "e2e_running":
                if self._manifest_claim_id(durable) is not None:
                    self._raise_competing()
                self._raise_ambiguous()
            return None
        claim_id = self._manifest_claim_id(in_memory)
        if claim_id is None:
            self._raise_ambiguous()
        if in_memory.get("phase") in {"e2e_passed", "e2e_failed"}:
            if durable == in_memory:
                if state == "terminal-owned" and getattr(self, "_claim_etag", None) != etag:
                    self._raise_ambiguous()
                self._set_owned(durable, etag, terminal=True)
                return None
            running = copy.deepcopy(in_memory)
            running["phase"] = "e2e_running"
            running["e2e"].pop("finished_at", None)
            running["e2e"].pop("passed", None)
            if durable == running and etag == getattr(self, "_claim_etag", None):
                self._set_owned(durable, etag, terminal=False)
                in_memory = self.manifest
            else:
                durable_claim_id = self._manifest_claim_id(durable)
                if (
                    durable.get("phase") == "e2e_running"
                    and durable_claim_id is not None
                    and durable_claim_id != claim_id
                ):
                    self._raise_competing()
                self._raise_ambiguous()
        elif in_memory.get("phase") == "e2e_running" and durable == in_memory:
            if state == "running-owned" and getattr(self, "_claim_etag", None) != etag:
                self._raise_ambiguous()
            self._set_owned(durable, etag, terminal=False)
            in_memory = self.manifest
        else:
            durable_claim_id = self._manifest_claim_id(durable)
            if (
                durable.get("phase") == "e2e_running"
                and durable_claim_id is not None
                and durable_claim_id != claim_id
            ):
                self._raise_competing()
            self._raise_ambiguous()
        assert isinstance(in_memory, dict)
        candidate = copy.deepcopy(in_memory)
        candidate["phase"] = "e2e_failed"
        candidate["e2e"]["finished_at"] = _utc_now()
        candidate["e2e"]["passed"] = False
        self.manifest = candidate
        self._ownership_state = "terminal-pending"
        try:
            self.store.write(candidate, if_match=etag)
        except BaseException as error:
            persistence = self._reconcile_finish_write(in_memory, etag, candidate, error)
        else:
            committed_etag = self.store.remote_etag
            if not isinstance(committed_etag, str) or not committed_etag:
                persistence = self._reconcile_finish_write(
                    in_memory,
                    etag,
                    candidate,
                    LifecycleError("conditional cleanup handoff returned no ETag"),
                )
            else:
                self._set_owned(candidate, committed_etag, terminal=True)
                persistence = "conditional-write"
        return {
            "claim_identity_preserved": True,
            "manifest_phase": "e2e_failed",
            "persistence": persistence,
        }

    def cleanup(self) -> Mapping[str, Any]:
        handoff = self._handoff_active_claim_for_cleanup()
        tailscale = build_tailscale(self.config)
        result = protected_cleanup(
            self.config,
            self.aws,
            tailscale,
            self.runner,
            self.run_dir,
            self.terraform_dir,
            recover=True,
            dry_run=False,
            skip_destroy=False,
        )
        if handoff is None:
            return result
        return {**result, "e2e_claim_handoff": dict(handoff)}


def validate_protected_execution(run_id: str, environment: Mapping[str, str]) -> None:
    if environment.get("ENVELOPE_E2E_APPROVED_RUN_ID") != run_id:
        raise E2EError("live execution requires ENVELOPE_E2E_APPROVED_RUN_ID to exactly match the run")
    github_event = environment.get("GITHUB_EVENT_NAME", "").lower()
    untrusted = (
        github_event in {"pull_request", "pull_request_target"}
        or environment.get("GITHUB_HEAD_REPO_FORK", "").lower() == "true"
        or environment.get("CI_EXTERNAL_PULL_REQUEST", "").lower() in {"1", "true"}
        or environment.get("BUILDKITE_PULL_REQUEST", "false").lower() != "false"
    )
    if untrusted:
        raise E2EError("live AWS/Tailscale execution is prohibited for pull-request or fork context")


@contextlib.contextmanager
def hard_timeout(seconds: int, *, operation: str = "live E2E") -> Iterable[None]:
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 7200:
        raise E2EError("hard timeout must be between 1 and 7200 seconds")
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_term_handler = signal.getsignal(signal.SIGTERM)
    previous_alarm_seconds = signal.alarm(0)

    def expired(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"{operation} exceeded its {seconds}-second hard timeout")

    def interrupted(_signum: int, _frame: Any) -> None:
        raise InterruptedError(f"{operation} received SIGTERM and entered protected cleanup")

    signal.signal(signal.SIGALRM, expired)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        signal.signal(signal.SIGTERM, previous_term_handler)
        if previous_alarm_seconds > 0:
            signal.alarm(previous_alarm_seconds)


def run_all_hard_timeout(seconds: int) -> Any:
    return hard_timeout(seconds, operation="protected run-all")


def cleanup_hard_timeout(seconds: int) -> Any:
    return hard_timeout(seconds, operation="protected cleanup")


REMOTE_AGENT_SOURCE = r'''#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import math
import os
import socket
import struct
import sys
import time

MAX_FRAME = 4096

def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)

def encode(value, tcp=False):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if tcp:
        data += b"\n"
    if len(data) > MAX_FRAME:
        raise RuntimeError("frame too large")
    return data

def decode(data):
    if not data or len(data) > MAX_FRAME:
        raise RuntimeError("invalid frame size")
    value = json.loads(data.decode("ascii").strip())
    if not isinstance(value, dict):
        raise RuntimeError("frame is not an object")
    return value

def internet_checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum((data[offset] << 8) | data[offset + 1] for offset in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def icmp_client(args):
    if not 1 <= args.payload_bytes <= 65507:
        raise RuntimeError("ICMP payload size is invalid")
    payload = b"\xa5" * args.payload_bytes
    digest = hashlib.sha256(payload).hexdigest()
    identifier = int.from_bytes(hashlib.sha256(args.flow_id.encode("ascii")).digest()[:2], "big") or 1
    sequence = 1
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    packet = struct.pack("!BBHHH", 8, 0, internet_checksum(header + payload), identifier, sequence) + payload
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    reply_source = None
    try:
        sock.bind((args.source_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, 10, 2)
        sock.sendto(packet, (args.host, 0))
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                received, _peer = sock.recvfrom(65535)
            except socket.timeout:
                break
            if len(received) < 28 or received[0] >> 4 != 4 or received[9] != socket.IPPROTO_ICMP:
                continue
            header_length = (received[0] & 15) * 4
            if header_length < 20 or len(received) < header_length + 8:
                continue
            response = received[header_length:]
            response_type, code, _checksum, response_id, response_sequence = struct.unpack("!BBHHH", response[:8])
            if (response_type, code, response_id, response_sequence) != (0, 0, identifier, sequence):
                continue
            source_ip = socket.inet_ntoa(received[12:16])
            destination_ip = socket.inet_ntoa(received[16:20])
            if source_ip != args.host or destination_ip != args.source_ip:
                raise RuntimeError("ICMP reply identity mismatch")
            if internet_checksum(response) != 0 or response[8:] != payload:
                raise RuntimeError("ICMP reply checksum or payload mismatch")
            reply_source = source_ip
            break
    finally:
        sock.close()
    if args.expect_timeout:
        if reply_source is not None:
            raise RuntimeError("oversized ICMP unexpectedly received a reply")
    elif reply_source is None:
        raise RuntimeError("ICMP reply timed out")
    emit({"destination_ip": args.host, "flow_id": args.flow_id, "payload_bytes": args.payload_bytes,
          "payload_sha256": digest, "reply_received": reply_source is not None,
          "reply_source_ip": reply_source, "source_ip": args.source_ip, "success": True})

def tcp_frame(conn, deadline):
    data = bytearray()
    while b"\n" not in data:
        conn.settimeout(max(0.01, deadline - time.monotonic()))
        chunk = conn.recv(MAX_FRAME + 1 - len(data))
        if not chunk:
            raise RuntimeError("TCP frame ended early")
        data.extend(chunk)
        if len(data) > MAX_FRAME:
            raise RuntimeError("TCP frame too large")
    return bytes(data.split(b"\n", 1)[0])

def serve_probe(args):
    tcp = args.protocol == "tcp"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    if tcp:
        sock.listen(8)
    deadline = time.monotonic() + args.timeout
    settle = None
    first = None
    receives = duplicates = sessions = 0
    try:
        while time.monotonic() < (settle if settle is not None else deadline):
            until = settle if settle is not None else deadline
            sock.settimeout(max(0.01, until - time.monotonic()))
            try:
                if tcp:
                    conn, peer = sock.accept()
                    sessions += 1
                    request = decode(tcp_frame(conn, until))
                else:
                    data, peer = sock.recvfrom(MAX_FRAME + 1)
                    request = decode(data)
                    sessions = len({(str(peer[0]), int(peer[1]))} if first is None else {(first[0], first[1]), (str(peer[0]), int(peer[1]))})
            except socket.timeout:
                break
            if set(request) != {"flow_id", "kind", "payload", "sequence"} or request["kind"] != "probe" or request["sequence"] != 0:
                raise RuntimeError("probe frame shape mismatch")
            digest = hashlib.sha256(request["payload"].encode("ascii")).hexdigest()
            if request["flow_id"] != args.flow_id or digest != args.payload_sha256:
                raise RuntimeError("probe identity or payload mismatch")
            receives += 1
            if first is None:
                first = (str(peer[0]), int(peer[1]))
                settle = time.monotonic() + args.settle
            else:
                duplicates += 1
            ack = {"flow_id": args.flow_id, "kind": "ack", "payload_sha256": digest, "sequence": 0}
            if tcp:
                conn.sendall(encode(ack, True))
                conn.close()
            else:
                sock.sendto(encode(ack), peer)
    finally:
        sock.close()
    if first is None:
        raise RuntimeError("no probe received")
    emit({"duplicates": duplicates, "flow_id": args.flow_id, "payload_sha256": args.payload_sha256,
          "receives": receives, "sessions": sessions, "source_ip": first[0], "source_port": first[1], "success": duplicates == 0 and receives == 1})

def probe(args):
    tcp = args.protocol == "tcp"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    deadline = time.monotonic() + args.timeout
    try:
        sock.bind((args.source_ip, args.source_port))
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port))
        request = {"flow_id": args.flow_id, "kind": "probe", "payload": args.payload, "sequence": 0}
        started = time.monotonic_ns()
        if tcp:
            sock.sendall(encode(request, True))
            response = decode(tcp_frame(sock, deadline))
        else:
            sock.send(encode(request))
            response = decode(sock.recv(MAX_FRAME + 1))
        received = time.monotonic_ns()
        digest = hashlib.sha256(args.payload.encode("ascii")).hexdigest()
        if response != {"flow_id": args.flow_id, "kind": "ack", "payload_sha256": digest, "sequence": 0}:
            raise RuntimeError("ack mismatch")
        local = sock.getsockname()
    finally:
        sock.close()
    emit({"flow_id": args.flow_id, "latency_ns": received - started, "payload_sha256": digest,
          "protocol": args.protocol, "source_ip": str(local[0]), "source_port": int(local[1]), "success": True})

def stream_server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    deadline = time.monotonic() + args.duration
    seen = set()
    duplicates = 0
    sources = set()
    try:
        while time.monotonic() < deadline:
            sock.settimeout(min(1.0, max(0.01, deadline - time.monotonic())))
            try:
                data, peer = sock.recvfrom(MAX_FRAME + 1)
            except socket.timeout:
                continue
            request = decode(data)
            if set(request) != {"connection_id", "flow_id", "kind", "sequence"} or request["kind"] != "marker" or request["flow_id"] != args.flow_id:
                raise RuntimeError("stream marker mismatch")
            sequence = request["sequence"]
            if not isinstance(sequence, int) or sequence < 0:
                raise RuntimeError("stream sequence invalid")
            if sequence in seen:
                duplicates += 1
            seen.add(sequence)
            sources.add((str(peer[0]), int(peer[1]), str(request["connection_id"])))
            ack = {"connection_id": request["connection_id"], "flow_id": args.flow_id, "kind": "ack", "sequence": sequence}
            sock.sendto(encode(ack), peer)
    finally:
        sock.close()
    emit({"duplicates": duplicates, "flow_id": args.flow_id, "receives": len(seen), "sessions": len(sources), "success": duplicates == 0 and len(sources) == 1})

def stream_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection_id = args.flow_id + ":c0001"
    markers = []
    try:
        try:
            os.unlink(args.ready_path)
        except FileNotFoundError:
            pass
        sock.bind((args.source_ip, args.source_port))
        sock.connect((args.host, args.port))
        started = time.monotonic()
        for sequence in range(args.count):
            target = started + sequence * args.interval
            if target > time.monotonic():
                time.sleep(target - time.monotonic())
            sent = time.monotonic_ns()
            request = {"connection_id": connection_id, "flow_id": args.flow_id, "kind": "marker", "sequence": sequence}
            sock.send(encode(request))
            ack_deadline = time.monotonic() + args.ack_timeout
            while time.monotonic() < ack_deadline:
                sock.settimeout(max(0.01, ack_deadline - time.monotonic()))
                try:
                    response = decode(sock.recv(MAX_FRAME + 1))
                except socket.timeout:
                    break
                if response == {"connection_id": connection_id, "flow_id": args.flow_id, "kind": "ack", "sequence": sequence}:
                    markers.append({"connection_id": connection_id, "flow_id": args.flow_id,
                                    "received_monotonic_ns": time.monotonic_ns(), "sent_monotonic_ns": sent, "sequence": sequence})
                    if sequence == 0:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        if hasattr(os, "O_NOFOLLOW"):
                            flags |= os.O_NOFOLLOW
                        descriptor = os.open(args.ready_path, flags, 0o600)
                        try:
                            os.write(descriptor, b"ready\n")
                        finally:
                            os.close(descriptor)
                    break
    finally:
        sock.close()
    emit({"connection_id": connection_id, "flow_id": args.flow_id, "markers": markers,
          "socket_count": 1, "source_port": args.source_port, "success": True})

def sized_udp_server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(args.timeout)
    received = None
    peer = None
    try:
        try:
            received, peer = sock.recvfrom(8192)
        except socket.timeout:
            if not args.expect_none:
                raise RuntimeError("sized UDP payload was not received")
        if args.expect_none:
            if received is not None:
                raise RuntimeError("oversized UDP payload unexpectedly reached the receiver")
            emit({"flow_id": args.flow_id, "receives": 0, "success": True})
            return
        digest = hashlib.sha256(received).hexdigest()
        if len(received) != args.payload_bytes or digest != args.payload_sha256:
            raise RuntimeError("sized UDP payload length or digest mismatch")
        sock.sendto((args.flow_id + ":ack").encode("ascii"), peer)
        emit({"flow_id": args.flow_id, "payload_sha256": digest, "receives": 1,
              "source_ip": str(peer[0]), "source_port": int(peer[1]), "success": True})
    finally:
        sock.close()

def sized_udp_client(args):
    seed = hashlib.sha256(args.flow_id.encode("ascii")).digest()
    payload = (seed * ((args.payload_bytes + len(seed) - 1) // len(seed)))[:args.payload_bytes]
    digest = hashlib.sha256(payload).hexdigest()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.source_ip, args.source_port))
    sock.connect((args.host, args.port))
    sock.settimeout(args.timeout)
    reply = None
    try:
        sock.send(payload)
        try:
            reply = sock.recv(4096)
        except socket.timeout:
            if not args.expect_timeout:
                raise RuntimeError("sized UDP acknowledgement timed out")
        if args.expect_timeout:
            if reply is not None:
                raise RuntimeError("oversized UDP unexpectedly received a reply")
        elif reply != (args.flow_id + ":ack").encode("ascii"):
            raise RuntimeError("sized UDP acknowledgement mismatch")
    finally:
        sock.close()
    emit({"flow_id": args.flow_id, "payload_bytes": args.payload_bytes,
          "payload_sha256": digest, "reply_received": reply is not None,
          "source_ip": args.source_ip, "source_port": args.source_port, "success": True})

def batch_worker(spec, args):
    protocol = spec["protocol"]
    tcp = protocol == "tcp"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.bind((args.source_ip, int(spec["source_port"])))
    sock.settimeout(args.ack_timeout)
    sock.connect((args.host, args.port))
    connection_id = spec["flow_id"] + ":c0001"
    count = max(2, int(args.duration / args.interval))
    received = 0
    latencies = []
    started = time.monotonic()
    buffer = b""
    try:
        for sequence in range(count):
            target = started + sequence * args.interval
            if target > time.monotonic():
                time.sleep(target - time.monotonic())
            frame = {"connection_id": connection_id, "flow_id": spec["flow_id"],
                     "kind": "marker", "sequence": sequence}
            encoded = encode(frame, tcp)
            sent = time.monotonic_ns()
            if tcp:
                sock.sendall(encoded)
                deadline = time.monotonic() + args.ack_timeout
                while b"\n" not in buffer:
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                    buffer += sock.recv(MAX_FRAME + 1 - len(buffer))
                raw, buffer = buffer.split(b"\n", 1)
            else:
                sock.send(encoded)
                try:
                    raw = sock.recv(MAX_FRAME + 1)
                except socket.timeout:
                    continue
            ack = decode(raw)
            if ack != {"connection_id": connection_id, "flow_id": spec["flow_id"],
                       "kind": "ack", "sequence": sequence}:
                raise RuntimeError("batch acknowledgement mismatch")
            received += 1
            latencies.append((time.monotonic_ns() - sent) / 1000000.0)
        remaining = started + args.duration - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        elapsed = time.monotonic() - started
    finally:
        sock.close()
    if not latencies:
        raise RuntimeError("batch flow received no acknowledgements")
    ordered = sorted(latencies)
    p99 = ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * 0.99) - 1))]
    return {"completed": True, "duration_seconds": elapsed, "flow_id": spec["flow_id"],
            "loss_percent": (count - received) * 100.0 / count, "p99_latency_ms": p99,
            "protocol": protocol, "sent": count, "received": received,
            "source_port": int(spec["source_port"])}

def batch_client(args):
    specs = json.loads(gzip.decompress(base64.b64decode(args.flows_b64, validate=True)).decode("ascii"))
    if not isinstance(specs, list) or not specs or len(specs) > 64:
        raise RuntimeError("batch flow specification is invalid")
    ids = set()
    ports = set()
    for spec in specs:
        if set(spec) != {"flow_id", "protocol", "source_port"} or spec["protocol"] not in ("tcp", "udp"):
            raise RuntimeError("batch flow entry is invalid")
        if spec["flow_id"] in ids or spec["source_port"] in ports:
            raise RuntimeError("batch flow identities are duplicated")
        ids.add(spec["flow_id"]); ports.add(spec["source_port"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(specs)) as pool:
        results = list(pool.map(lambda spec: batch_worker(spec, args), specs))
    emit({"results": sorted(results, key=lambda value: value["flow_id"]), "success": True})

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="op", required=True)
    serve = sub.add_parser("serve-probe")
    serve.add_argument("--protocol", choices=("tcp", "udp"), required=True); serve.add_argument("--bind", required=True)
    serve.add_argument("--port", type=int, required=True); serve.add_argument("--flow-id", required=True)
    serve.add_argument("--payload-sha256", required=True); serve.add_argument("--timeout", type=float, default=40)
    serve.add_argument("--settle", type=float, default=2)
    client = sub.add_parser("probe")
    client.add_argument("--protocol", choices=("tcp", "udp"), required=True); client.add_argument("--host", required=True)
    client.add_argument("--port", type=int, required=True); client.add_argument("--source-ip", required=True)
    client.add_argument("--source-port", type=int, required=True); client.add_argument("--flow-id", required=True)
    client.add_argument("--payload", required=True); client.add_argument("--timeout", type=float, default=30)
    server = sub.add_parser("stream-server")
    server.add_argument("--bind", required=True); server.add_argument("--port", type=int, required=True)
    server.add_argument("--flow-id", required=True); server.add_argument("--duration", type=float, required=True)
    stream = sub.add_parser("stream-client")
    stream.add_argument("--host", required=True); stream.add_argument("--port", type=int, required=True)
    stream.add_argument("--source-ip", required=True); stream.add_argument("--source-port", type=int, required=True)
    stream.add_argument("--flow-id", required=True); stream.add_argument("--count", type=int, required=True)
    stream.add_argument("--interval", type=float, required=True); stream.add_argument("--ack-timeout", type=float, required=True)
    stream.add_argument("--ready-path", required=True)
    icmp = sub.add_parser("icmp-client")
    icmp.add_argument("--host", required=True); icmp.add_argument("--source-ip", required=True)
    icmp.add_argument("--flow-id", required=True); icmp.add_argument("--payload-bytes", type=int, required=True)
    icmp.add_argument("--timeout", type=float, required=True); icmp.add_argument("--expect-timeout", action="store_true")
    sized_server = sub.add_parser("sized-udp-server")
    sized_server.add_argument("--bind", required=True); sized_server.add_argument("--port", type=int, required=True)
    sized_server.add_argument("--flow-id", required=True); sized_server.add_argument("--payload-bytes", type=int, required=True)
    sized_server.add_argument("--payload-sha256", required=True); sized_server.add_argument("--timeout", type=float, required=True)
    sized_server.add_argument("--expect-none", action="store_true")
    sized_client = sub.add_parser("sized-udp-client")
    sized_client.add_argument("--host", required=True); sized_client.add_argument("--port", type=int, required=True)
    sized_client.add_argument("--source-ip", required=True); sized_client.add_argument("--source-port", type=int, required=True)
    sized_client.add_argument("--flow-id", required=True); sized_client.add_argument("--payload-bytes", type=int, required=True)
    sized_client.add_argument("--timeout", type=float, required=True); sized_client.add_argument("--expect-timeout", action="store_true")
    batch = sub.add_parser("batch-client")
    batch.add_argument("--host", required=True); batch.add_argument("--port", type=int, required=True)
    batch.add_argument("--source-ip", required=True); batch.add_argument("--flows-b64", required=True)
    batch.add_argument("--duration", type=float, required=True); batch.add_argument("--interval", type=float, default=0.25)
    batch.add_argument("--ack-timeout", type=float, default=1.0)
    args = parser.parse_args()
    {"serve-probe": serve_probe, "probe": probe, "stream-server": stream_server, "stream-client": stream_client,
     "icmp-client": icmp_client,
     "sized-udp-server": sized_udp_server, "sized-udp-client": sized_udp_client,
     "batch-client": batch_client}[args.op](args)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"error": str(error), "success": False})
        sys.exit(2)
'''

REMOTE_AGENT_PATH = "/opt/envelope/e2e-live-observer"
WIRE_INSPECTOR_PATH = "/opt/envelope/e2e-wire-inspector"
TAILSCALE_ROUTE_VALIDATOR_SOURCE = r'''import ipaddress
import json
import sys

expected = [ipaddress.ip_network(value, strict=True) for value in json.loads(sys.argv[1])]
interface = sys.argv[2]
routes = json.load(sys.stdin)
if not isinstance(routes, list):
    raise SystemExit(2)
for network in expected:
    matches = [route for route in routes if route.get("dst") == str(network)]
    if len(matches) != 1 or matches[0].get("dev") != interface:
        raise SystemExit(3)
for route in routes:
    destination = route.get("dst")
    if destination == "default":
        destination = "0.0.0.0/0"
    if not isinstance(destination, str):
        continue
    try:
        network = ipaddress.ip_network(destination, strict=True)
    except ValueError:
        continue
    if any(network.version == value.version and network != value and network.supernet_of(value) for value in expected):
        raise SystemExit(4)
'''
TAILSCALE_PEER_ROUTE_VALIDATOR_SOURCE = r'''import json
import sys

expected_hostname = sys.argv[1]
expected_routes = json.loads(sys.argv[2])
status = json.load(sys.stdin)
peers = status.get("Peer", {}) if isinstance(status, dict) else {}
values = list(peers.values()) if isinstance(peers, dict) else peers if isinstance(peers, list) else []
matching = [peer for peer in values if isinstance(peer, dict) and peer.get("HostName") == expected_hostname]
if len(matching) != 1:
    raise SystemExit(2)
routes = matching[0].get("PrimaryRoutes", [])
if (
    not isinstance(expected_routes, list)
    or not all(isinstance(route, str) for route in expected_routes)
    or not isinstance(routes, list)
    or not all(isinstance(route, str) for route in routes)
    or sorted(routes) != sorted(expected_routes)
):
    raise SystemExit(3)
'''
WORKLOAD_SOURCE_ROUTE_JQ = 'length == 1 and ((.[0].from // .[0].prefsrc // .[0].src) == $source)'


@dataclasses.dataclass
class FlowLogHandle:
    flow_logs: dict[Site, ManagedFlowLog]
    started_milliseconds: int


@dataclasses.dataclass
class DirectionalCaptureHandle:
    source_site: Site
    command_ids: dict[Site, str]
    paths: dict[Site, dict[str, str]]
    pid_paths: dict[Site, dict[str, str]]
    stopped: bool = False
    raw_deleted: bool = False


class AwsLiveOperations:
    """Concrete AWS/SSM operations; every dependency is injectable for tests."""

    def __init__(
        self,
        config: RunConfig,
        aws: AWSJSON | AwsCLI,
        run_dir: pathlib.Path,
        *,
        ssm: SSMRunner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ):
        self.config = config
        self.aws = aws
        self.run_dir = run_dir.expanduser().resolve()
        self.ssm = ssm or SSMRunner(aws, sleep=sleep, clock=monotonic)
        self.sleep = sleep
        self.monotonic = monotonic
        self.wall_time = wall_time
        self.appliance_hosts: dict[Site, ApplianceTarget] = {}
        self.appliance_private_ips: dict[Site, str] = {}
        self.appliance_enis: dict[Site, str] = {}
        self.workload_flow_identities: dict[str, dict[str, Any]] = {}
        self.flow_windows: dict[str, dict[str, int]] = {}
        self.capture_cleanup_events: list[dict[str, Any]] = []
        self.capture_assertion_events: list[dict[str, Any]] = []
        self.agent_sha256 = hashlib.sha256(REMOTE_AGENT_SOURCE.encode("utf-8")).hexdigest()
        self.wire_inspector_sha256 = hashlib.sha256(WIRE_INSPECTOR_SOURCE.encode("utf-8")).hexdigest()

    def _begin_flow_window(self, flow: FlowRecord) -> None:
        if flow.flow_id in self.flow_windows:
            raise FlowLogError(f"flow {flow.flow_id} already has a wall-clock window")
        self.flow_windows[flow.flow_id] = {"start_epoch": max(0, int(math.floor(self.wall_time())))}

    def _end_flow_window(self, flow: FlowRecord) -> None:
        window = self.flow_windows.get(flow.flow_id)
        if window is None or "end_epoch" in window:
            raise FlowLogError(f"flow {flow.flow_id} has no open wall-clock window")
        end_epoch = max(window["start_epoch"], int(math.ceil(self.wall_time())))
        if end_epoch - window["start_epoch"] > 7200:
            raise FlowLogError(f"flow {flow.flow_id} wall-clock window exceeds the bounded run")
        window["end_epoch"] = end_epoch

    def _run_with_flow_window(self, flow: FlowRecord, operation: Callable[[], Any]) -> Any:
        self._begin_flow_window(flow)
        try:
            return operation()
        finally:
            self._end_flow_window(flow)

    def _run_with_flow_windows(self, flows: Sequence[FlowRecord], operation: Callable[[], Any]) -> Any:
        for flow in flows:
            self._begin_flow_window(flow)
        try:
            return operation()
        finally:
            for flow in flows:
                self._end_flow_window(flow)

    def _execute(
        self,
        target: RemoteTarget,
        command: str,
        *,
        timeout_seconds: int,
        comment: str,
    ) -> SSMResult:
        bounded = max(1, min(int(timeout_seconds), 3600))
        result = self.ssm.execute(
            SSMCommand(target, (command,), timeout_seconds=bounded, comment=comment),
            wait_timeout_seconds=bounded + 15,
        )
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip() or result.status
            raise SSMError(
                f"{target.site} {target.role} command failed ({result.response_code}): {_sanitize_string(detail)}"
            )
        return result

    def _execute_json(
        self,
        target: RemoteTarget,
        command: str,
        *,
        timeout_seconds: int,
        comment: str,
    ) -> dict[str, Any]:
        result = self._execute(target, command, timeout_seconds=timeout_seconds, comment=comment)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            raise SSMError(f"{target.site} {target.role} command returned no JSON")
        try:
            value = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            raise SSMError(f"{target.site} {target.role} command returned invalid JSON") from error
        if not isinstance(value, dict):
            raise SSMError(f"{target.site} {target.role} command returned non-object JSON")
        if value.get("success") is False:
            raise SSMError(f"{target.site} {target.role} agent failed: {_sanitize_string(str(value.get('error', 'unknown')))}")
        return value

    def _wait_until(
        self,
        operation: Callable[[], Any],
        predicate: Callable[[Any], bool],
        *,
        timeout_seconds: float,
        description: str,
        interval_seconds: float = 3.0,
    ) -> Any:
        deadline = self.monotonic() + timeout_seconds
        last: Any = None
        last_error: Exception | None = None
        while self.monotonic() < deadline:
            try:
                last = operation()
                if predicate(last):
                    return last
            except Exception as error:
                last_error = error
            remaining = deadline - self.monotonic()
            if remaining > 0:
                self.sleep(min(interval_seconds, remaining))
        detail = f"; last error={_sanitize_string(str(last_error))}" if last_error is not None else ""
        if last is not None:
            detail += "; last value=" + _sanitize_string(
                json.dumps(sanitize_evidence_value(last), sort_keys=True, separators=(",", ":"), default=str)
            )
        raise ReadinessError(f"timed out waiting for {description}{detail}")

    @staticmethod
    def _instances(response: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        reservations = response.get("Reservations")
        if not isinstance(reservations, list):
            raise ReadinessError("EC2 describe-instances response omitted Reservations")
        values: dict[str, dict[str, Any]] = {}
        for reservation in reservations:
            if not isinstance(reservation, Mapping) or not isinstance(reservation.get("Instances"), list):
                raise ReadinessError("EC2 describe-instances response has an invalid reservation")
            for instance in reservation["Instances"]:
                if not isinstance(instance, dict) or not isinstance(instance.get("InstanceId"), str):
                    raise ReadinessError("EC2 describe-instances returned an invalid instance")
                identifier = instance["InstanceId"]
                if identifier in values:
                    raise ReadinessError("EC2 describe-instances duplicated an instance")
                values[identifier] = instance
        return values

    @staticmethod
    def _tags(instance: Mapping[str, Any]) -> dict[str, str]:
        tags = instance.get("Tags")
        if not isinstance(tags, list) or not all(
            isinstance(tag, Mapping) and isinstance(tag.get("Key"), str) and isinstance(tag.get("Value"), str)
            for tag in tags
        ):
            raise ReadinessError("EC2 instance tags have an invalid schema")
        return {str(tag["Key"]): str(tag["Value"]) for tag in tags}

    def _install_agent(self, target: SSMTarget) -> None:
        encoded = base64.b64encode(gzip.compress(REMOTE_AGENT_SOURCE.encode("utf-8"), mtime=0)).decode("ascii")
        temporary = REMOTE_AGENT_PATH + ".tmp"
        command = (
            "set -euo pipefail; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d | gzip -d > {shlex.quote(temporary)}; "
            f"printf '%s  %s\\n' {shlex.quote(self.agent_sha256)} {shlex.quote(temporary)} | sha256sum -c - >/dev/null; "
            f"install -m 0700 {shlex.quote(temporary)} {shlex.quote(REMOTE_AGENT_PATH)}; rm -f {shlex.quote(temporary)}"
        )
        self._execute(target, command, timeout_seconds=60, comment="Envelope E2E install bounded agent")

    def _install_wire_inspector(self, target: ApplianceTarget) -> None:
        encoded = base64.b64encode(gzip.compress(WIRE_INSPECTOR_SOURCE.encode("utf-8"), mtime=0)).decode("ascii")
        temporary = WIRE_INSPECTOR_PATH + ".tmp"
        command = (
            "set -euo pipefail; umask 077; install -d -o root -g root -m 0755 /opt/envelope; "
            f"printf %s {shlex.quote(encoded)} | base64 -d | gzip -d > {shlex.quote(temporary)}; "
            f"printf '%s  %s\\n' {shlex.quote(self.wire_inspector_sha256)} {shlex.quote(temporary)} | sha256sum -c - >/dev/null; "
            f"install -m 0700 {shlex.quote(temporary)} {shlex.quote(WIRE_INSPECTOR_PATH)}; rm -f {shlex.quote(temporary)}"
        )
        self._execute(target, command, timeout_seconds=60, comment="Envelope E2E install bounded wire inspector")

    def _target_health(self, target: ApplianceTarget) -> dict[str, Any]:
        response = self.aws.json(
            ["elbv2", "describe-target-health", "--target-group-arn", target.target_group_arn],
            region=target.region,
        )
        descriptions = response.get("TargetHealthDescriptions")
        if not isinstance(descriptions, list) or len(descriptions) != 1:
            return {"count": len(descriptions) if isinstance(descriptions, list) else -1, "status": "invalid"}
        value = descriptions[0]
        if not isinstance(value, Mapping):
            return {"count": 1, "status": "invalid"}
        return {
            "count": 1,
            "target_id": value.get("Target", {}).get("Id") if isinstance(value.get("Target"), Mapping) else None,
            "status": value.get("TargetHealth", {}).get("State")
            if isinstance(value.get("TargetHealth"), Mapping)
            else None,
            "reason": value.get("TargetHealth", {}).get("Reason")
            if isinstance(value.get("TargetHealth"), Mapping)
            else None,
        }

    def _wait_target_status(self, target: ApplianceTarget, status: str, *, timeout_seconds: float) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._wait_until(
                lambda: self._target_health(target),
                lambda value: value.get("count") == 1
                and value.get("target_id") == target.instance_id
                and value.get("status") == status,
                timeout_seconds=timeout_seconds,
                description=f"{target.site} GWLB target status {status}",
                interval_seconds=5,
            ),
        )

    def _wait_appliance_ready(self, target: ApplianceTarget, *, timeout_seconds: float) -> dict[str, Any]:
        command = """set -euo pipefail
deadline=$((SECONDS+%d))
while (( SECONDS < deadline )); do
  units_ready=true
  for unit in tailscaled.service envelope-host-network.service envelope.service; do
    systemctl is-active --quiet "$unit" || units_ready=false
  done
  if [[ "$units_ready" == true ]] &&
     PREFLIGHT_MAX_ATTEMPTS=1 PREFLIGHT_RETRY_SECONDS=0 timeout 20 /usr/local/sbin/envelope-preflight >/dev/null 2>&1 &&
     curl --fail --silent --max-time 3 http://127.0.0.1:9090/healthz >/dev/null; then
    pid=$(systemctl show -p MainPID --value envelope.service)
    printf '{"pid":%%s,"ready":true,"success":true}\n' "$pid"
    exit 0
  fi
  sleep 2
done
exit 1""" % max(5, int(timeout_seconds) - 15)
        result = self._execute_json(
            target,
            command,
            timeout_seconds=max(15, int(timeout_seconds)),
            comment="Envelope E2E appliance readiness",
        )
        if result.get("ready") is not True or not isinstance(result.get("pid"), int) or result["pid"] <= 1:
            raise ReadinessError(f"{target.site} appliance readiness omitted a live Envelope PID")
        return result

    def _appliance_readiness_details(
        self,
        deployment: ProtectedDeployment,
        site: Site,
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        target = deployment.appliance(site)
        runtime = deployment.runtime(site)
        advertised = sorted((*runtime.gwlb_return_cidrs, *runtime.local_delivery_cidrs))
        accepted = sorted(runtime.remote_tailnet_cidrs)
        expected_peer = f"{self.config.run_id}-{_opposite(site)}"
        advertised_json = json.dumps(advertised, separators=(",", ":"))
        accepted_json = json.dumps(accepted, separators=(",", ":"))
        route_checks = (
            "ip -j route show table 52 | python3 -c "
            f"{shlex.quote(TAILSCALE_ROUTE_VALIDATOR_SOURCE)} {shlex.quote(accepted_json)} "
            f"{shlex.quote(runtime.tailscale_iface)}"
        )
        peer_route_checks = (
            "python3 -c "
            f"{shlex.quote(TAILSCALE_PEER_ROUTE_VALIDATOR_SOURCE)} {shlex.quote(expected_peer)} "
            f"{shlex.quote(accepted_json)} <\"$status\""
        )
        command = f"""set -euo pipefail
status=$(mktemp /run/envelope-e2e-tailscale.XXXXXX)
trap 'rm -f "$status"' EXIT
timeout 120 cloud-init status --wait >/dev/null
for unit in tailscaled.service envelope-host-network.service envelope.service; do
  systemctl is-active --quiet "$unit"
done
timeout 10 tailscale status --json >"$status"
jq -e --argjson advertised {shlex.quote(advertised_json)} '
  (.Self.TailscaleIPs // .TailscaleIPs // []) as $self_ips |
  .BackendState == "Running" and .TUN == true and ((.Health // []) | length == 0) and
  (([.Self.AllowedIPs[] | select((split("/")[0]) as $address | ($self_ips | index($address) | not))] | unique | sort) == ($advertised | sort))
' "$status" >/dev/null
{peer_route_checks}
{route_checks}
for iface in {shlex.quote(runtime.underlay_interface)} {shlex.quote(runtime.tailscale_iface)} {shlex.quote(runtime.tun_name)}; do
  ip -j link show dev "$iface" | jq -e 'length == 1 and .[0].operstate != "DOWN" and .[0].mtu >= 1280' >/dev/null
done
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
[[ $(sysctl -n net.ipv6.conf.all.forwarding) == 1 ]]
for iface in {shlex.quote(runtime.underlay_interface)} {shlex.quote(runtime.tailscale_iface)} {shlex.quote(runtime.tun_name)}; do
  [[ $(sysctl -n "net.ipv4.conf.$iface.rp_filter") == 0 ]]
done
PREFLIGHT_MAX_ATTEMPTS=1 PREFLIGHT_RETRY_SECONDS=0 timeout 20 /usr/local/sbin/envelope-preflight >/dev/null
iptables-save -t filter | grep -F -- '-A FORWARD -j ENVELOPE-FORWARD' >/dev/null
iptables-save -t mangle | grep -F -- '-A FORWARD -j ENVELOPE-MSS' >/dev/null
curl --fail --silent --max-time 3 http://127.0.0.1:9090/healthz >/dev/null
curl --fail --silent --max-time 3 http://127.0.0.1:9090/metrics | grep -E '^routing_ready 1(\\.0)?$' >/dev/null
for tool in tcpdump timeout python3 sha256sum gzip base64; do
  command -v "$tool" >/dev/null
done
printf '%s  %s\\n' {shlex.quote(self.wire_inspector_sha256)} {shlex.quote(WIRE_INSPECTOR_PATH)} | sha256sum -c - >/dev/null
pid=$(systemctl show -p MainPID --value envelope.service)
printf '{{"accepted_route_peer":{json.dumps(expected_peer)},"accepted_routes":{accepted_json},"accepted_routes_exact":true,"advertised_routes":{advertised_json},"advertised_routes_exact":true,"capture_tools_ready":true,"cloud_init_complete":true,"envelope_active":true,"envelope_health":true,"firewall_mss_ready":true,"host_network_active":true,"host_network_preflight":true,"links":["{runtime.underlay_interface}","{runtime.tailscale_iface}","{runtime.tun_name}"],"links_ready":true,"metrics_ready":true,"pid":%s,"success":true,"sysctls_ready":true,"tailscale_backend_running":true,"tailscaled_active":true}}\\n' "$pid"
"""
        value = self._execute_json(
            target,
            command,
            timeout_seconds=max(30, timeout_seconds),
            comment="Envelope E2E explicit appliance readiness",
        )
        if not isinstance(value.get("pid"), int) or value["pid"] <= 1:
            raise ReadinessError(f"{site} explicit readiness omitted a live Envelope PID")
        return value

    def _workload_readiness_details(
        self,
        target: SSMTarget,
        peer: SSMTarget,
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        command = f"""set -euo pipefail
failed_check=unknown
report_failure() {{
  status=$?
  trap - EXIT
  if (( status != 0 )); then
    printf '{{"exit_code":%d,"failed_check":"%s","success":false}}\\n' "$status" "$failed_check" >&2
  fi
  exit "$status"
}}
trap report_failure EXIT
failed_check=cloud-init
timeout 120 cloud-init status --wait >/dev/null
failed_check=services-active
for unit in amazon-ssm-agent.service envelope-e2e-agent-tcp.service envelope-e2e-agent-udp.service; do
  systemctl is-active --quiet "$unit"
done
failed_check=tools-present
for tool in ping iperf3 python3 ip ss timeout jq; do command -v "$tool" >/dev/null; done
failed_check=source-address
ip -j address show | jq -e --arg source {shlex.quote(target.private_ip)} 'any(.[]?.addr_info[]?; .local == $source)' >/dev/null
failed_check=source-route
ip -j route get {shlex.quote(peer.private_ip)} from {shlex.quote(target.private_ip)} | jq -e --arg source {shlex.quote(target.private_ip)} {shlex.quote(WORKLOAD_SOURCE_ROUTE_JQ)} >/dev/null
failed_check=tcp-listener
ss -H -ltn 'sport = :5201' | grep -q .
failed_check=udp-listener
ss -H -lun 'sport = :5201' | grep -q .
failed_check=complete
printf '{{"cloud_init_complete":true,"host_network_preflight":true,"links_ready":true,"private_ip":"{target.private_ip}","ssm_active":true,"success":true,"tcp_listener_ready":true,"tools_ready":true,"udp_listener_ready":true}}\\n'"""
        return self._execute_json(
            target,
            command,
            timeout_seconds=max(30, timeout_seconds),
            comment="Envelope E2E explicit workload readiness",
        )

    @staticmethod
    def _exact_route(routes: Any, destination: str) -> dict[str, Any]:
        if not isinstance(routes, list):
            raise ReadinessError("route table response omitted Routes")
        matches = [route for route in routes if isinstance(route, dict) and route.get("DestinationCidrBlock") == destination]
        if len(matches) != 1 or matches[0].get("State") != "active":
            raise ReadinessError(f"route table does not contain one active exact route for {destination}")
        return matches[0]

    @staticmethod
    def _route_selects_only_target(route: Mapping[str, Any], field: str, target_id: str) -> bool:
        return route.get(field) == target_id and all(
            route.get(other) in (None, "") for other in _ROUTE_TARGET_FIELDS - {field}
        )

    def verify_readiness_and_topology(
        self, deployment: ProtectedDeployment, *, timeout_seconds: int
    ) -> Mapping[str, Any]:
        deadline = self.monotonic() + timeout_seconds
        host_summaries: list[dict[str, Any]] = []
        lane_routes: list[dict[str, Any]] = []
        appliance_checks: dict[Site, dict[str, Any]] = {}
        workload_checks: dict[str, dict[str, Any]] = {}
        for site in SITES:
            appliance = deployment.appliance(site)
            workload_targets = [deployment.workloads.target(site, role) for role in WORKLOAD_ROLES]
            requested_ids = [appliance.instance_id, *(target.instance_id for target in workload_targets)]
            response = self.aws.json(
                ["ec2", "describe-instances", "--instance-ids", *requested_ids],
                region=appliance.region,
            )
            instances = self._instances(response)
            if set(instances) != set(requested_ids):
                raise ReadinessError(f"{site} did not return exactly one appliance and two workloads")
            appliance_value = instances[appliance.instance_id]
            appliance_tags = self._tags(appliance_value)
            if (
                appliance_value.get("State", {}).get("Name") != "running"
                or appliance_value.get("SourceDestCheck") is not False
                or appliance_tags.get("EnvelopeRun") != self.config.run_id
                or appliance_tags.get("Site") != site
                or appliance_tags.get("Role") != "appliance"
            ):
                raise ReadinessError(f"{site} appliance runtime identity is not exact")
            private_ip = appliance_value.get("PrivateIpAddress")
            interfaces = appliance_value.get("NetworkInterfaces")
            primary = [
                interface
                for interface in interfaces or []
                if isinstance(interface, Mapping) and interface.get("Attachment", {}).get("DeviceIndex") == 0
            ]
            if not isinstance(private_ip, str) or len(primary) != 1 or not _ENI_ID_RE.fullmatch(
                str(primary[0].get("NetworkInterfaceId", ""))
            ):
                raise ReadinessError(f"{site} appliance primary address/ENI identity is invalid")
            self.appliance_hosts[site] = appliance
            self.appliance_private_ips[site] = private_ip
            self.appliance_enis[site] = str(primary[0]["NetworkInterfaceId"])
            for target in workload_targets:
                value = instances[target.instance_id]
                tags = self._tags(value)
                workload_interfaces = value.get("NetworkInterfaces")
                workload_primary = [
                    interface
                    for interface in workload_interfaces or []
                    if isinstance(interface, Mapping) and interface.get("Attachment", {}).get("DeviceIndex") == 0
                ]
                if (
                    value.get("State", {}).get("Name") != "running"
                    or value.get("PrivateIpAddress") != target.private_ip
                    or value.get("SubnetId") != target.subnet_id
                    or len(workload_primary) != 1
                    or workload_primary[0].get("PrivateIpAddress") != target.private_ip
                    or workload_primary[0].get("SubnetId") != target.subnet_id
                    or not _ENI_ID_RE.fullmatch(str(workload_primary[0].get("NetworkInterfaceId", "")))
                    or tags.get("EnvelopeRun") != self.config.run_id
                    or tags.get("Site") != site
                    or tags.get("Role") != target.role
                ):
                    raise ReadinessError(f"{site} {target.role} workload identity is not exact")
                self.workload_flow_identities[f"{site}-{target.role}"] = {
                    "site": site,
                    "role": target.role,
                    "private_ip": target.private_ip,
                    "instance_id": target.instance_id,
                    "interface_id": str(workload_primary[0]["NetworkInterfaceId"]),
                    "subnet_id": target.subnet_id,
                    "flow_directions": ["egress", "ingress"],
                }

            ssm_response = self.aws.json(
                [
                    "ssm",
                    "describe-instance-information",
                    "--filters",
                    "Key=InstanceIds,Values=" + ",".join(requested_ids),
                ],
                region=appliance.region,
            )
            information = ssm_response.get("InstanceInformationList")
            if not isinstance(information, list):
                raise ReadinessError(f"{site} SSM readiness response is invalid")
            online = {
                value.get("InstanceId")
                for value in information
                if isinstance(value, Mapping) and value.get("PingStatus") == "Online"
            }
            if online != set(requested_ids):
                raise ReadinessError(f"{site} does not have exactly three online SSM instances")

            initiator = deployment.workloads.target(site, "initiator")
            responder = deployment.workloads.target(site, "responder")
            endpoint_values = deployment.endpoint_ids[site]
            endpoint_response = self.aws.json(
                ["ec2", "describe-vpc-endpoints", "--vpc-endpoint-ids", *endpoint_values.values()],
                region=appliance.region,
            )
            described_endpoints = endpoint_response.get("VpcEndpoints")
            if not isinstance(described_endpoints, list) or {
                value.get("VpcEndpointId")
                for value in described_endpoints
                if isinstance(value, Mapping)
                and value.get("State") == "available"
                and value.get("VpcId") == appliance.vpc_id
                and value.get("VpcEndpointType") == "GatewayLoadBalancer"
            } != set(endpoint_values.values()):
                raise ReadinessError(f"{site} GWLB endpoints are not exactly available in the expected VPC")
            endpoints_by_id = {
                str(value["VpcEndpointId"]): value
                for value in described_endpoints
                if isinstance(value, Mapping) and isinstance(value.get("VpcEndpointId"), str)
            }
            endpoint_subnets: dict[str, str] = {}
            for az_key, endpoint_id in endpoint_values.items():
                subnet_ids = endpoints_by_id[endpoint_id].get("SubnetIds")
                if not isinstance(subnet_ids, list) or len(subnet_ids) != 1 or not _SUBNET_ID_RE.fullmatch(
                    str(subnet_ids[0])
                ):
                    raise ReadinessError(f"{site} GWLB endpoint {az_key} does not have one exact subnet")
                endpoint_subnets[az_key] = str(subnet_ids[0])
            subnet_response = self.aws.json(
                ["ec2", "describe-subnets", "--subnet-ids", *endpoint_subnets.values()],
                region=appliance.region,
            )
            subnet_values = subnet_response.get("Subnets")
            if not isinstance(subnet_values, list):
                raise ReadinessError(f"{site} GWLB endpoint subnet response is invalid")
            subnet_azs = {
                value.get("SubnetId"): value.get("AvailabilityZone")
                for value in subnet_values
                if isinstance(value, Mapping) and value.get("VpcId") == appliance.vpc_id
            }
            if any(
                subnet_azs.get(subnet_id) != self.config.sites[site]["azs"].get(az_key)
                for az_key, subnet_id in endpoint_subnets.items()
            ):
                raise ReadinessError(f"{site} GWLB endpoint map does not preserve exact AZ identities")

            route_ids = [cast(str, target.route_table_id) for target in workload_targets]
            route_response = self.aws.json(
                ["ec2", "describe-route-tables", "--route-table-ids", *route_ids],
                region=appliance.region,
            )
            route_tables = route_response.get("RouteTables")
            if not isinstance(route_tables, list) or len(route_tables) != len(set(route_ids)):
                raise ReadinessError(f"{site} workload route-table response is incomplete")
            by_id = {
                value.get("RouteTableId"): value
                for value in route_tables
                if isinstance(value, Mapping) and isinstance(value.get("RouteTableId"), str)
            }
            if set(by_id) != set(route_ids):
                raise ReadinessError(f"{site} workload route-table identities are not exact")
            for target in workload_targets:
                table = by_id[target.route_table_id]
                associations = table.get("Associations")
                matching = [
                    association
                    for association in associations or []
                    if isinstance(association, Mapping)
                    and association.get("SubnetId") == target.subnet_id
                    and association.get("Main") is False
                    and association.get("AssociationState", {}).get("State") == "associated"
                ]
                if table.get("VpcId") != appliance.vpc_id or len(matching) != 1:
                    raise ReadinessError(f"{site} {target.role} route table is not exactly associated to its subnet")
            peer = _opposite(site)
            peer_responder = deployment.workloads.target(peer, "responder")
            peer_initiator = deployment.workloads.target(peer, "initiator")
            initiator_route = self._exact_route(
                by_id[initiator.route_table_id].get("Routes"), cast(str, peer_responder.cidr)
            )
            expected_endpoint = endpoint_values[cast(str, initiator.az_key)]
            if not self._route_selects_only_target(initiator_route, "GatewayId", expected_endpoint):
                raise ReadinessError(f"{site} initiator route does not select only its same-AZ GWLB endpoint")
            responder_route = self._exact_route(
                by_id[responder.route_table_id].get("Routes"), cast(str, peer_initiator.cidr)
            )
            if not self._route_selects_only_target(
                responder_route, "NetworkInterfaceId", self.appliance_enis[site]
            ):
                raise ReadinessError(f"{site} responder route does not select only its local appliance ENI")
            lane_routes.extend(
                [
                    {
                        "site": site,
                        "role": "initiator",
                        "destination_cidr": peer_responder.cidr,
                        "route_table_id": initiator.route_table_id,
                        "target_type": "gwlb-endpoint",
                        "target_id": expected_endpoint,
                    },
                    {
                        "site": site,
                        "role": "responder",
                        "destination_cidr": peer_initiator.cidr,
                        "route_table_id": responder.route_table_id,
                        "target_type": "appliance-eni",
                        "target_id": self.appliance_enis[site],
                    },
                ]
            )

            remaining = max(30, int(deadline - self.monotonic()))
            self._wait_appliance_ready(appliance, timeout_seconds=remaining)
            self._install_wire_inspector(appliance)
            appliance_ready = self._appliance_readiness_details(
                deployment,
                site,
                timeout_seconds=max(30, int(deadline - self.monotonic())),
            )
            target_health = self._wait_target_status(
                appliance,
                "healthy",
                timeout_seconds=max(15, deadline - self.monotonic()),
            )
            appliance_ready["target_healthy"] = True
            appliance_ready["target_status"] = target_health["status"]
            appliance_checks[site] = appliance_ready
            host_summaries.append(
                {"site": site, "role": "appliance", "instance_id": appliance.instance_id, "ready": True, "pid": appliance_ready["pid"]}
            )
            for target in workload_targets:
                self._install_agent(target)
                peer_target = deployment.workloads.target(_opposite(site), _opposite_workload_role(target.role))
                result = self._workload_readiness_details(
                    target,
                    peer_target,
                    timeout_seconds=min(180, max(30, int(deadline - self.monotonic()))),
                )
                result.update(self.workload_flow_identities[f"{site}-{target.role}"])
                workload_checks[f"{site}-{target.role}"] = result
                host_summaries.append(
                    {"site": site, "role": target.role, "instance_id": target.instance_id, "ready": True}
                )
        return {
            "appliance_count": 2,
            "workload_count": 4,
            "all_hosts_ready": len(host_summaries) == 6 and all(value["ready"] for value in host_summaries),
            "directional_routes_exact": len(lane_routes) == 4,
            "hosts": host_summaries,
            "appliance_checks": appliance_checks,
            "workload_checks": workload_checks,
            "lane_routes": lane_routes,
            "regional_target_counts": {"west": 1, "east": 1},
        }

    @staticmethod
    def _json_from_result(result: SSMResult) -> dict[str, Any]:
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            raise SSMError("remote agent returned no JSON")
        try:
            value = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            raise SSMError("remote agent returned invalid JSON") from error
        if not isinstance(value, dict) or value.get("success") is not True:
            detail = value.get("error") if isinstance(value, dict) else "non-object result"
            raise SSMError(f"remote agent failed: {_sanitize_string(str(detail))}")
        return value

    def _pid(self, target: ApplianceTarget) -> int:
        result = self._execute_json(
            target,
            "set -euo pipefail; pid=$(systemctl show -p MainPID --value envelope.service); "
            "printf '{\"pid\":%s,\"success\":true}\\n' \"$pid\"",
            timeout_seconds=20,
            comment="Envelope E2E process generation",
        )
        pid = result.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise ReadinessError(f"{target.site} Envelope service has no live process generation")
        return pid

    def _restart_envelope(self, deployment: ProtectedDeployment, *, timeout_seconds: int) -> dict[Site, int]:
        before = {site: self._pid(deployment.appliance(site)) for site in SITES}
        for site in SITES:
            self._execute(
                deployment.appliance(site),
                "set -euo pipefail; systemctl restart envelope.service",
                timeout_seconds=45,
                comment="Envelope E2E clear flow context",
            )
        deadline = self.monotonic() + timeout_seconds
        after: dict[Site, int] = {}
        for site in SITES:
            target = deployment.appliance(site)
            ready = self._wait_appliance_ready(target, timeout_seconds=max(20, deadline - self.monotonic()))
            after[site] = cast(int, ready["pid"])
            if after[site] == before[site]:
                raise ProbeError(f"{site} cold-flow reset did not create a new Envelope process generation")
            self._wait_target_status(target, "healthy", timeout_seconds=max(15, deadline - self.monotonic()))
        return after

    def _metric_snapshot(self, target: ApplianceTarget) -> MetricSnapshot:
        result = self._execute(
            target,
            "set -euo pipefail; pid=$(systemctl show -p MainPID --value envelope.service); "
            "printf 'ENVELOPE_PID=%s\\n' \"$pid\"; curl --fail --silent --max-time 5 http://127.0.0.1:9090/metrics",
            timeout_seconds=20,
            comment="Envelope E2E management metrics",
        )
        lines = result.stdout.splitlines()
        if not lines or not re.fullmatch(r"ENVELOPE_PID=[1-9][0-9]*", lines[0].strip()):
            raise MetricError(f"{target.site} metric scrape omitted the process generation")
        pid = int(lines[0].split("=", 1)[1])
        return parse_prometheus_metrics("\n".join(lines[1:]), generation=f"{target.site}-envelope-pid{pid}")

    def _metric_snapshots(self, deployment: ProtectedDeployment) -> dict[Site, MetricSnapshot]:
        return {site: self._metric_snapshot(deployment.appliance(site)) for site in SITES}

    def _wait_listener(self, target: SSMTarget, protocol: ProtocolName, *, timeout_seconds: int) -> None:
        selector = "-ltn" if protocol == "tcp" else "-lun"
        command = f"""set -euo pipefail
deadline=$((SECONDS+{max(5, timeout_seconds)}))
while (( SECONDS < deadline )); do
  if ss -H {selector} 'sport = :5201' | grep -q .; then
    printf '{{"listening":true,"success":true}}\\n'
    exit 0
  fi
  sleep 1
done
exit 1"""
        value = self._execute_json(
            target,
            command,
            timeout_seconds=max(10, timeout_seconds + 5),
            comment="Envelope E2E receiver listener",
        )
        if value.get("listening") is not True:
            raise ProbeError(f"{target.site} responder did not open the {protocol} probe listener")

    @staticmethod
    def _responder_unit(protocol: ProtocolName) -> str:
        return f"envelope-e2e-agent-{protocol}.service"

    def _pause_managed_responder(self, target: SSMTarget, protocol: ProtocolName) -> None:
        unit = self._responder_unit(protocol)
        self._execute(
            target,
            f"set -euo pipefail; systemctl stop {shlex.quote(unit)}; ! systemctl is-active --quiet {shlex.quote(unit)}",
            timeout_seconds=20,
            comment="Envelope E2E pause managed receiver",
        )

    def _resume_managed_responder(self, target: SSMTarget, protocol: ProtocolName) -> None:
        if protocol == "icmp":
            return
        unit = self._responder_unit(protocol)
        selector = "-ltn" if protocol == "tcp" else "-lun"
        self._execute(
            target,
            "set -euo pipefail; "
            f"for attempt in $(seq 1 20); do ss -H {selector} 'sport = :5201' | grep -q . || break; sleep 0.25; done; "
            f"! ss -H {selector} 'sport = :5201' | grep -q .; "
            f"systemctl start {shlex.quote(unit)}; systemctl is-active --quiet {shlex.quote(unit)}",
            timeout_seconds=30,
            comment="Envelope E2E restore managed receiver",
        )
        self._wait_listener(target, protocol, timeout_seconds=10)

    def _start_directional_captures(
        self,
        deployment: ProtectedDeployment,
        source_site: Site,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> DirectionalCaptureHandle:
        if {flow.source.site for flow in flows} != {source_site}:
            raise WireAssertionError("capture flows do not belong to one direction")
        command_ids: dict[Site, str] = {}
        paths: dict[Site, dict[str, str]] = {}
        pid_paths: dict[Site, dict[str, str]] = {}
        handle = DirectionalCaptureHandle(source_site, command_ids, paths, pid_paths)
        tag = re.sub(r"[^a-z0-9-]", "-", flows[0].flow_id.lower())[:80]
        hosts = sorted({flow.source.private_ip for flow in flows} | {flow.destination.private_ip for flow in flows})
        host_filter = "(" + " or ".join(f"host {address}" for address in hosts) + ")"
        inner_filter = f"{host_filter} and (icmp or tcp port 5201 or udp port 5201)"
        duration = max(30, min(timeout_seconds, 300))
        try:
            for site in SITES:
                target = deployment.appliance(site)
                runtime = deployment.runtime(site)
                interfaces = {
                    "underlay": runtime.underlay_interface,
                    "envelope0": runtime.tun_name,
                    "tailscale0": runtime.tailscale_iface,
                }
                paths[site] = {
                    logical: f"/run/envelope-e2e-capture/{tag}-{site}-{logical}.pcap"
                    for logical in interfaces
                }
                pid_paths[site] = {logical: path + ".pid" for logical, path in paths[site].items()}
                commands = ["set -euo pipefail", "install -d -m 0700 /run/envelope-e2e-capture"]
                for logical, interface in interfaces.items():
                    path = paths[site][logical]
                    pid_path = pid_paths[site][logical]
                    capture_filter = "udp port 6081" if logical == "underlay" else inner_filter
                    commands.extend(
                        [
                            f"rm -f {shlex.quote(path)} {shlex.quote(pid_path)}",
                            f"tcpdump -U -n -i {shlex.quote(interface)} "
                            f"-s 512 -c 48 -w {shlex.quote(path)} {shlex.quote(capture_filter)} >/dev/null 2>&1 &",
                            "capture_pid=$!",
                            f"( sleep {duration}; kill -TERM \"$capture_pid\" 2>/dev/null || true ) &",
                            "watchdog_pid=$!",
                            f"printf '%s %s\\n' \"$capture_pid\" \"$watchdog_pid\" > {shlex.quote(pid_path)}",
                        ]
                    )
                commands.extend(
                    [
                        "status=0",
                        *[
                            f"read -r capture_pid watchdog_pid < {shlex.quote(pid_path)}; "
                            "wait \"$capture_pid\" || status=$?; "
                            "kill -TERM \"$watchdog_pid\" 2>/dev/null || true; "
                            "wait \"$watchdog_pid\" 2>/dev/null || true"
                            for pid_path in pid_paths[site].values()
                        ],
                        "exit \"$status\"",
                    ]
                )
                command_id = self.ssm.send(
                    SSMCommand(
                        target,
                        ("\n".join(commands),),
                        timeout_seconds=duration + 15,
                        comment=f"Envelope E2E {source_site} bounded captures",
                    ),
                    timeout_seconds=10,
                )
                command_ids[site] = command_id
            for site in SITES:
                checks = " ".join(
                    f"test -f {shlex.quote(paths[site][logical])}; "
                    f"test -s {shlex.quote(pid_paths[site][logical])}; "
                    f"read -r capture_pid watchdog_pid < {shlex.quote(pid_paths[site][logical])}; "
                    "kill -0 \"$capture_pid\"; kill -0 \"$watchdog_pid\";"
                    for logical in sorted(paths[site])
                )
                ready = self._execute_json(
                    deployment.appliance(site),
                    f"set -euo pipefail; {checks} printf '{{\"capture_ready\":true,\"success\":true}}\\n'",
                    timeout_seconds=max(10, min(30, timeout_seconds // 4)),
                    comment="Envelope E2E capture readiness",
                )
                if ready.get("capture_ready") is not True:
                    raise WireAssertionError(f"{site} capture controller did not become ready")
            return handle
        except BaseException:
            try:
                self._finish_directional_captures(deployment, handle, inspect=False)
            except Exception:
                pass
            raise

    def _finish_directional_captures(
        self,
        deployment: ProtectedDeployment,
        handle: DirectionalCaptureHandle,
        *,
        inspect: bool,
    ) -> dict[str, Any]:
        if handle.stopped:
            raise WireAssertionError("directional capture handle was already stopped")
        summaries: dict[Site, dict[str, Any]] = {site: {} for site in SITES}
        errors: list[str] = []
        try:
            for site in SITES:
                if site not in handle.paths:
                    continue
                target = deployment.appliance(site)
                stop_commands = ["set -u"]
                for pid_path in handle.pid_paths[site].values():
                    stop_commands.append(
                        f"if test -s {shlex.quote(pid_path)}; then read -r capture_pid watchdog_pid < {shlex.quote(pid_path)}; "
                        "kill -TERM \"$capture_pid\" 2>/dev/null || true; "
                        "kill -TERM \"$watchdog_pid\" 2>/dev/null || true; fi"
                    )
                self._execute(
                    target,
                    "; ".join(stop_commands),
                    timeout_seconds=20,
                    comment="Envelope E2E stop bounded captures",
                )
            for site, command_id in handle.command_ids.items():
                try:
                    result = self.ssm.wait(deployment.appliance(site), command_id, timeout_seconds=30)
                    if not result.succeeded:
                        errors.append(f"{site} capture command ended {result.status}")
                except Exception as error:
                    errors.append(f"{site} capture wait failed: {_sanitize_string(str(error))}")
            if inspect and not errors:
                for site in SITES:
                    if errors:
                        break
                    target = deployment.appliance(site)
                    for logical, path in handle.paths[site].items():
                        try:
                            summaries[site][logical] = self._inspect_capture_summary(target, path)
                        except Exception as error:
                            errors.append(
                                f"{site} {logical} capture inspection failed: {_sanitize_string(str(error))}"
                            )
                            break
        finally:
            for site in SITES:
                if site not in handle.paths:
                    continue
                target = deployment.appliance(site)
                all_paths = [*handle.paths[site].values(), *handle.pid_paths[site].values()]
                try:
                    deleted = self._execute_json(
                        target,
                        "set -euo pipefail; rm -f "
                        + " ".join(shlex.quote(path) for path in all_paths)
                        + "; ! test -e "
                        + " && ! test -e ".join(shlex.quote(path) for path in all_paths)
                        + "; printf '{\"deleted\":true,\"success\":true}\\n'",
                        timeout_seconds=30,
                        comment="Envelope E2E delete raw captures",
                    )
                    if deleted.get("deleted") is not True:
                        errors.append(f"{site} did not prove raw capture deletion")
                except Exception as error:
                    errors.append(f"{site} raw capture deletion failed: {_sanitize_string(str(error))}")
            handle.stopped = True
            handle.raw_deleted = not any("delet" in error for error in errors)
            self.capture_cleanup_events.append(
                {
                    "source_site": handle.source_site,
                    "stopped": True,
                    "raw_pcaps_deleted": handle.raw_deleted,
                    "error_count": len(errors),
                }
            )
        if errors:
            raise WireAssertionError("; ".join(errors))
        return {"captures": summaries, "raw_deleted": handle.raw_deleted}

    def _inspect_capture_summary(self, target: ApplianceTarget, path: str) -> dict[str, Any]:
        result = self._execute(
            target,
            f"set -euo pipefail; {shlex.quote(WIRE_INSPECTOR_PATH)} {shlex.quote(path)} | gzip -n -9 | base64 -w0",
            timeout_seconds=30,
            comment="Envelope E2E inspect sanitized capture",
        )
        encoded = result.stdout.strip()
        if not encoded or len(encoded) > 20_000:
            raise WireAssertionError("compressed capture summary is absent or exceeds the SSM evidence bound")
        try:
            compressed = base64.b64decode(encoded, validate=True)
            decoded = gzip.decompress(compressed)
            if len(decoded) > 1_000_000:
                raise WireAssertionError("capture field summary exceeds the decompressed bound")
            value = json.loads(decoded)
        except (ValueError, binascii.Error, EOFError, gzip.BadGzipFile, json.JSONDecodeError) as error:
            raise WireAssertionError(f"capture field summary is invalid: {error}") from None
        if not isinstance(value, dict) or value.get("success") is not True:
            raise WireAssertionError("capture inspector rejected the bounded pcap")
        return value

    @staticmethod
    def _icmp_client_command(
        flow: FlowRecord, *, payload_bytes: int, timeout_seconds: int, expect_timeout: bool = False
    ) -> str:
        if flow.protocol != "icmp" or flow.source_port is not None or flow.destination_port is not None:
            raise ProbeError("ICMP probe flow carries an invalid transport identity")
        parts = [
            "set -euo pipefail; exec",
            shlex.quote(REMOTE_AGENT_PATH),
            "icmp-client",
            "--host",
            shlex.quote(flow.destination.private_ip),
            "--source-ip",
            shlex.quote(flow.source.private_ip),
            "--flow-id",
            shlex.quote(flow.flow_id),
            "--payload-bytes",
            str(payload_bytes),
            "--timeout",
            str(max(1, min(30, timeout_seconds))),
        ]
        if expect_timeout:
            parts.append("--expect-timeout")
        return " ".join(parts)

    def _run_icmp_probe(self, flow: FlowRecord, *, payload_bytes: int, timeout_seconds: int) -> dict[str, Any]:
        payload = bytes([0xA5]) * payload_bytes
        digest = hashlib.sha256(payload).hexdigest()
        value = self._execute_json(
            flow.source,
            self._icmp_client_command(flow, payload_bytes=payload_bytes, timeout_seconds=timeout_seconds),
            timeout_seconds=max(5, min(40, timeout_seconds)),
            comment="Envelope E2E bound ICMP probe",
        )
        if (
            value.get("reply_source_ip") != flow.destination.private_ip
            or value.get("source_ip") != flow.source.private_ip
            or value.get("payload_bytes") != payload_bytes
            or value.get("payload_sha256") != digest
            or value.get("reply_received") is not True
        ):
            raise ProbeError(f"ICMP probe {flow.flow_id} did not preserve source/reply identity")
        return {
            "flow_id": flow.flow_id,
            "protocol": "icmp",
            "source_ip": flow.source.private_ip,
            "source_port": None,
            "destination_ip": flow.destination.private_ip,
            "destination_port": None,
            "payload_sha256": digest,
            "payload_bytes": payload_bytes,
            "icmp_request_type": 8,
            "icmp_reply_type": 0,
            "response_timeout_seconds": min(30, timeout_seconds),
            "receiver": {
                "reply_source_ip": flow.destination.private_ip,
                "source_identity_verified": True,
            },
            "success": True,
        }

    def _run_probe(self, flow: FlowRecord, *, timeout_seconds: int) -> dict[str, Any]:
        payload = hashlib.sha512(f"{flow.flow_id}:receiver-observed-payload".encode()).hexdigest()
        payload_sha256 = hashlib.sha256(payload.encode("ascii")).hexdigest()
        server_command = " ".join(
            [
                "set -euo pipefail; exec",
                shlex.quote(REMOTE_AGENT_PATH),
                "serve-probe",
                "--protocol",
                flow.protocol,
                "--bind",
                shlex.quote(flow.destination.private_ip),
                "--port",
                str(flow.destination_port),
                "--flow-id",
                shlex.quote(flow.flow_id),
                "--payload-sha256",
                payload_sha256,
                "--timeout",
                str(min(45, timeout_seconds)),
                "--settle",
                "2",
            ]
        )
        server_spec = SSMCommand(
            flow.destination,
            (server_command,),
            timeout_seconds=min(60, timeout_seconds),
            comment="Envelope E2E receiver-observed probe",
        )
        server_id: str | None = None
        pause_attempted = False
        try:
            pause_attempted = True
            self._pause_managed_responder(flow.destination, flow.protocol)
            server_id = self.ssm.send(server_spec, timeout_seconds=10)
            self._wait_listener(flow.destination, flow.protocol, timeout_seconds=min(20, timeout_seconds))
            client_command = " ".join(
                [
                    "set -euo pipefail; exec",
                    shlex.quote(REMOTE_AGENT_PATH),
                    "probe",
                    "--protocol",
                    flow.protocol,
                    "--host",
                    flow.destination.private_ip,
                    "--port",
                    str(flow.destination_port),
                    "--source-ip",
                    flow.source.private_ip,
                    "--source-port",
                    str(flow.source_port),
                    "--flow-id",
                    flow.flow_id,
                    "--payload",
                    payload,
                    "--timeout",
                    str(min(30, timeout_seconds)),
                ]
            )
            client = self._execute_json(
                flow.source,
                client_command,
                timeout_seconds=min(45, timeout_seconds),
                comment="Envelope E2E unique cold probe",
            )
            server_result = self.ssm.wait(
                flow.destination,
                cast(str, server_id),
                timeout_seconds=min(60, timeout_seconds),
            )
            if not server_result.succeeded:
                raise ProbeError(f"receiver command for {flow.flow_id} failed with {server_result.status}")
            receiver = self._json_from_result(server_result)
        except Exception:
            if server_id is not None:
                try:
                    self.ssm.cancel(flow.destination, server_id, timeout_seconds=5)
                except E2EError:
                    pass
            raise
        finally:
            if pause_attempted:
                self._resume_managed_responder(flow.destination, flow.protocol)
        if (
            client.get("flow_id") != flow.flow_id
            or client.get("payload_sha256") != payload_sha256
            or client.get("source_ip") != flow.source.private_ip
            or client.get("source_port") != flow.source_port
            or client.get("protocol") != flow.protocol
        ):
            raise ProbeError(f"client result for {flow.flow_id} changed its bound identity or payload")
        return {
            "flow_id": flow.flow_id,
            "protocol": flow.protocol,
            "source_ip": flow.source.private_ip,
            "source_port": flow.source_port,
            "destination_ip": flow.destination.private_ip,
            "destination_port": flow.destination_port,
            "payload_sha256": payload_sha256,
            "payload_bytes": len(payload),
            "latency_ns": client.get("latency_ns"),
            "response_timeout_seconds": min(30, timeout_seconds),
            "receiver": receiver,
            "success": True,
        }

    def run_cold_direction(
        self,
        deployment: ProtectedDeployment,
        source_site: Site,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        deadline = self.monotonic() + timeout_seconds
        if [flow.protocol for flow in flows] != list(PROTOCOLS) or any(flow.source.site != source_site for flow in flows):
            raise ProbeError("cold direction must contain ordered ICMP, TCP, and UDP flows from one lane")
        pids = self._restart_envelope(deployment, timeout_seconds=max(45, int(timeout_seconds * 0.45)))
        context = {
            "both_processes_restarted": True,
            "matching_return_context_before_first_packet": False,
            "matching_flow_ids_absent_before": [flow.flow_id for flow in flows],
            "allocation_unique_in_generation": True,
            "empty_context_proof": "new-process-generations-have-no-process-local-return-contexts",
            "process_ids": pids,
            "targets_healthy_before_first_packet": True,
        }
        handle: DirectionalCaptureHandle | None = None
        results: list[dict[str, Any]] = []
        primary_error: BaseException | None = None
        capture_result: dict[str, Any] | None = None
        capture_error: BaseException | None = None
        try:
            handle = self._start_directional_captures(
                deployment,
                source_site,
                flows,
                timeout_seconds=max(30, int(deadline - self.monotonic())),
            )
            for flow in flows:
                def run_flow(flow: FlowRecord = flow) -> dict[str, Any]:
                    before = self._metric_snapshots(deployment)
                    remaining = max(10, int(deadline - self.monotonic()))
                    probe = (
                        self._run_icmp_probe(flow, payload_bytes=56, timeout_seconds=remaining)
                        if flow.protocol == "icmp"
                        else self._run_probe(flow, timeout_seconds=remaining)
                    )
                    after = self._metric_snapshots(deployment)
                    sessions = None if flow.protocol == "icmp" else cast(int, probe["receiver"]["sessions"])
                    metrics = assert_flow_metric_contract(
                        before,
                        after,
                        initiator_site=flow.source.site,
                        receiver_sessions=sessions,
                        receiver_identity_verified=True,
                    )
                    metrics["process_ids"] = pids
                    return {"flow_id": flow.flow_id, "probe": probe, "metrics": metrics}

                results.append(cast(dict[str, Any], self._run_with_flow_window(flow, run_flow)))
        except BaseException as error:
            primary_error = error
        finally:
            if handle is not None:
                try:
                    capture_result = self._finish_directional_captures(deployment, handle, inspect=True)
                except BaseException as error:
                    capture_error = error
        wire: dict[str, Any] | None = None
        if capture_result is not None and capture_error is None:
            try:
                wire = assert_directional_wire_captures(
                    source_site,
                    flows,
                    cast(Mapping[str, Any], capture_result["captures"]),
                    raw_deleted=capture_result.get("raw_deleted") is True,
                )
                self.capture_assertion_events.append(wire)
            except BaseException as error:
                capture_error = error
        if primary_error is not None:
            if capture_error is not None:
                raise WireAssertionError(
                    f"cold direction failed and capture cleanup/assertion also failed: {_sanitize_string(str(capture_error))}"
                ) from primary_error
            raise primary_error
        if capture_error is not None:
            raise capture_error
        if capture_result is None or wire is None:
            raise WireAssertionError("cold direction produced no bounded capture result")
        return {"context": context, "results": results, "wire": wire}

    def _run_sized_udp(
        self,
        flow: FlowRecord,
        *,
        payload_bytes: int,
        expect_drop: bool,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        if flow.protocol != "udp" or flow.source_port is None or flow.destination_port is None:
            raise TransportError("sized UDP flow has no exact transport tuple")
        seed = hashlib.sha256(flow.flow_id.encode("ascii")).digest()
        payload = (seed * ((payload_bytes + len(seed) - 1) // len(seed)))[:payload_bytes]
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        server_parts = [
            "set -euo pipefail; exec",
            shlex.quote(REMOTE_AGENT_PATH),
            "sized-udp-server --bind",
            flow.destination.private_ip,
            "--port",
            str(flow.destination_port),
            "--flow-id",
            flow.flow_id,
            "--payload-bytes",
            str(payload_bytes),
            "--payload-sha256",
            payload_sha256,
            "--timeout",
            str(max(3, min(15, timeout_seconds))),
        ]
        if expect_drop:
            server_parts.append("--expect-none")
        server_spec = SSMCommand(
            flow.destination,
            (" ".join(server_parts),),
            timeout_seconds=max(10, min(30, timeout_seconds)),
            comment="Envelope E2E sized UDP receiver",
        )
        server_id: str | None = None
        pause_attempted = False
        try:
            pause_attempted = True
            self._pause_managed_responder(flow.destination, "udp")
            server_id = self.ssm.send(server_spec, timeout_seconds=10)
            self._wait_listener(flow.destination, "udp", timeout_seconds=min(15, timeout_seconds))
            client_parts = [
                "set -euo pipefail; exec",
                shlex.quote(REMOTE_AGENT_PATH),
                "sized-udp-client --host",
                flow.destination.private_ip,
                "--port",
                str(flow.destination_port),
                "--source-ip",
                flow.source.private_ip,
                "--source-port",
                str(flow.source_port),
                "--flow-id",
                flow.flow_id,
                "--payload-bytes",
                str(payload_bytes),
                "--timeout",
                str(max(2, min(10, timeout_seconds))),
            ]
            if expect_drop:
                client_parts.append("--expect-timeout")
            client = self._execute_json(
                flow.source,
                " ".join(client_parts),
                timeout_seconds=max(10, min(30, timeout_seconds)),
                comment="Envelope E2E sized UDP sender",
            )
            server_result = self.ssm.wait(
                flow.destination,
                cast(str, server_id),
                timeout_seconds=max(10, min(30, timeout_seconds)),
            )
            if not server_result.succeeded:
                raise TransportError(f"sized UDP receiver for {flow.flow_id} failed")
            receiver = self._json_from_result(server_result)
        except Exception:
            if server_id is not None:
                try:
                    self.ssm.cancel(flow.destination, server_id, timeout_seconds=5)
                except E2EError:
                    pass
            raise
        finally:
            if pause_attempted:
                self._resume_managed_responder(flow.destination, "udp")
        if client.get("payload_sha256") != payload_sha256 or client.get("payload_bytes") != payload_bytes:
            raise TransportError(f"sized UDP client {flow.flow_id} changed its exact payload")
        if expect_drop:
            if client.get("reply_received") is not False or receiver.get("receives") != 0:
                raise TransportError(f"oversized UDP flow {flow.flow_id} unexpectedly reached or returned")
            return {
                "flow_id": flow.flow_id,
                "payload_bytes": payload_bytes,
                "payload_sha256": payload_sha256,
                "reply_received": False,
                "pmtu_icmp_expected": False,
            }
        return {
            "flow_id": flow.flow_id,
            "protocol": "udp",
            "source_ip": flow.source.private_ip,
            "source_port": flow.source_port,
            "destination_ip": flow.destination.private_ip,
            "destination_port": flow.destination_port,
            "payload_sha256": payload_sha256,
            "payload_bytes": payload_bytes,
            "response_timeout_seconds": max(2, min(10, timeout_seconds)),
            "receiver": {
                "flow_id": flow.flow_id,
                "payload_sha256": payload_sha256,
                "source_ip": receiver.get("source_ip"),
                "source_port": receiver.get("source_port"),
                "receives": receiver.get("receives"),
                "duplicates": 0,
                "sessions": 1,
            },
            "success": True,
        }

    @staticmethod
    def _icmp_drop_capture_command(
        flow: FlowRecord,
        *,
        interface: str,
        capture_path: str,
        timeout_seconds: int,
    ) -> str:
        if flow.protocol != "icmp" or flow.source_port is not None or flow.destination_port is not None:
            raise TransportError("oversized ICMP capture requires an exact port-free ICMP flow")
        capture_filter = "udp and dst port 6081"
        return (
            "set -euo pipefail; install -d -m 0700 /run/envelope-e2e-capture; "
            f"rm -f {shlex.quote(capture_path)}; exec timeout --signal=INT --kill-after=2 "
            f"{max(5, min(timeout_seconds, 30))}s tcpdump -n -i {shlex.quote(interface)} -s 0 -c 1 "
            f"-w {shlex.quote(capture_path)} {shlex.quote(capture_filter)} >/dev/null 2>&1"
        )

    def _run_oversized_icmp(
        self,
        deployment: ProtectedDeployment,
        flow: FlowRecord,
        *,
        payload_bytes: int,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        payload_sha256 = hashlib.sha256(bytes([0xA5]) * payload_bytes).hexdigest()
        source_appliance = deployment.appliance(flow.source.site)
        interface = deployment.runtime(flow.source.site).underlay_interface
        capture_path = f"/run/envelope-e2e-capture/{flow.flow_id}-oversized-icmp.pcap"
        capture_id: str | None = None
        capture_done = False
        raw_capture_deleted = False
        try:
            capture_id = self.ssm.send(
                SSMCommand(
                    source_appliance,
                    (
                        self._icmp_drop_capture_command(
                            flow,
                            interface=interface,
                            capture_path=capture_path,
                            timeout_seconds=timeout_seconds,
                        ),
                    ),
                    timeout_seconds=max(10, min(timeout_seconds + 5, 35)),
                    comment="Envelope E2E oversized ICMP request capture",
                ),
                timeout_seconds=10,
            )
            ready = self._execute_json(
                source_appliance,
                "set -euo pipefail; "
                f"for attempt in $(seq 1 30); do if test -s {shlex.quote(capture_path)}; then "
                "printf '{\"capture_ready\":true,\"success\":true}\\n'; exit 0; fi; sleep 0.25; done; exit 1",
                timeout_seconds=15,
                comment="Envelope E2E oversized ICMP capture readiness",
            )
            if ready.get("capture_ready") is not True:
                raise TransportError("oversized ICMP capture did not become ready")
            value = self._execute_json(
                flow.source,
                self._icmp_client_command(
                    flow,
                    payload_bytes=payload_bytes,
                    timeout_seconds=max(2, min(15, timeout_seconds)),
                    expect_timeout=True,
                ),
                timeout_seconds=max(5, min(25, timeout_seconds)),
                comment="Envelope E2E expected oversized ICMP drop",
            )
            if value.get("payload_bytes") != payload_bytes or value.get("payload_sha256") != payload_sha256:
                raise TransportError("oversized ICMP sender changed the exact request payload")
            capture_result = self.ssm.wait(
                source_appliance,
                capture_id,
                timeout_seconds=max(10, min(timeout_seconds + 5, 35)),
            )
            if not capture_result.succeeded:
                raise TransportError("oversized ICMP request capture did not complete")
            capture_done = True
            summary = self._inspect_capture_summary(source_appliance, capture_path)
            frames = summary.get("frames")
            if not isinstance(frames, list) or len(frames) != 1 or not isinstance(frames[0], Mapping):
                raise TransportError("oversized ICMP capture did not contain exactly one request")
            inner = _captured_inner(cast(Mapping[str, Any], frames[0]))
            transport = inner.get("transport") if isinstance(inner, Mapping) else None
            if (
                not isinstance(inner, Mapping)
                or inner.get("source_ip") != flow.source.private_ip
                or inner.get("destination_ip") != flow.destination.private_ip
                or inner.get("total_length") != payload_bytes + 28
                or not isinstance(transport, Mapping)
                or transport.get("protocol") != "icmp"
                or transport.get("type") != 8
                or transport.get("code") != 0
                or transport.get("checksum") != "valid"
                or transport.get("payload_bytes") != payload_bytes
                or transport.get("payload_sha256") != payload_sha256
            ):
                raise TransportError("oversized ICMP capture changed the exact request identity or size")
        finally:
            if capture_id is not None and not capture_done:
                try:
                    self.ssm.cancel(source_appliance, capture_id, timeout_seconds=5)
                except E2EError:
                    pass
            try:
                self._execute(
                    source_appliance,
                    f"set -u; rm -f {shlex.quote(capture_path)}; ! test -e {shlex.quote(capture_path)}",
                    timeout_seconds=20,
                    comment="Envelope E2E delete oversized ICMP capture",
                )
                raw_capture_deleted = True
            finally:
                self.capture_cleanup_events.append(
                    {
                        "source_site": flow.source.site,
                        "purpose": "oversized-icmp",
                        "stopped": capture_done,
                        "raw_pcaps_deleted": raw_capture_deleted,
                        "error_count": 0 if raw_capture_deleted else 1,
                    }
                )
        if value.get("reply_received") is not False:
            raise TransportError(f"oversized ICMP flow {flow.flow_id} unexpectedly returned")
        return {
            "flow_id": flow.flow_id,
            "payload_bytes": payload_bytes,
            "payload_sha256": payload_sha256,
            "reply_received": False,
            "pmtu_icmp_expected": False,
            "capture": {
                "interface": interface,
                "file_sha256": summary["file_sha256"],
                "icmp_checksum": "valid",
                "raw_pcap_deleted": raw_capture_deleted,
                "request_count": 1,
                "inner_bytes": payload_bytes + 28,
                "payload_bytes": payload_bytes,
                "payload_sha256": payload_sha256,
            },
        }

    @staticmethod
    def _tcp_syn_capture_command(
        flow: FlowRecord,
        *,
        interface: str,
        capture_path: str,
        duration_seconds: int,
    ) -> str:
        if flow.protocol != "tcp" or flow.source_port is None or flow.destination_port is None:
            raise TransportError("TCP SYN capture requires an exact transport tuple")
        capture_filter = (
            f"tcp and src host {flow.source.private_ip} and dst host {flow.destination.private_ip} "
            f"and src port {flow.source_port} and dst port {flow.destination_port} "
            "and (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
        )
        return (
            "set -euo pipefail; install -d -m 0700 /run/envelope-e2e-capture; "
            f"rm -f {shlex.quote(capture_path)}; exec timeout --signal=INT --kill-after=2 "
            f"{duration_seconds + 15}s tcpdump -n -i {shlex.quote(interface)} -s 0 -c 1 "
            f"-w {shlex.quote(capture_path)} {shlex.quote(capture_filter)} >/dev/null 2>&1"
        )

    def _run_iperf3(
        self,
        deployment: ProtectedDeployment,
        flow: FlowRecord,
        *,
        duration_seconds: int,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        if flow.protocol != "tcp" or flow.source_port is None or flow.destination_port is None:
            raise TransportError("iperf3 flow requires an exact TCP tuple")
        server_id: str | None = None
        capture_id: str | None = None
        server_done = False
        capture_done = False
        raw_capture_deleted = False
        capture_path = f"/run/envelope-e2e-capture/{flow.flow_id}-syn.pcap"
        pause_attempted = False
        try:
            pause_attempted = True
            self._pause_managed_responder(flow.destination, "tcp")
            server_id = self.ssm.send(
                SSMCommand(
                    flow.destination,
                    (
                        f"set -euo pipefail; exec timeout {duration_seconds + 30}s iperf3 --server --one-off "
                        f"--port {flow.destination_port} --json",
                    ),
                    timeout_seconds=duration_seconds + 35,
                    comment="Envelope E2E bounded iperf3 receiver",
                ),
                timeout_seconds=10,
            )
            self._wait_listener(flow.destination, "tcp", timeout_seconds=15)
            source_appliance = deployment.appliance(flow.source.site)
            interface = deployment.runtime(flow.source.site).tailscale_iface
            capture_id = self.ssm.send(
                SSMCommand(
                    source_appliance,
                    (
                        self._tcp_syn_capture_command(
                            flow,
                            interface=interface,
                            capture_path=capture_path,
                            duration_seconds=duration_seconds,
                        ),
                    ),
                    timeout_seconds=duration_seconds + 20,
                    comment="Envelope E2E bounded TCP SYN capture",
                ),
                timeout_seconds=10,
            )
            capture_ready = self._execute_json(
                source_appliance,
                "set -euo pipefail; "
                f"for attempt in $(seq 1 30); do if test -s {shlex.quote(capture_path)}; then "
                "printf '{\"ready\":true,\"success\":true}\\n'; exit 0; fi; sleep 0.25; done; exit 1",
                timeout_seconds=15,
                comment="Envelope E2E TCP SYN capture readiness",
            )
            if capture_ready.get("ready") is not True:
                raise TransportError("TCP SYN capture did not become ready before the connection")
            client_result = self._execute(
                flow.source,
                f"set -euo pipefail; exec timeout {duration_seconds + 20}s iperf3 --client {shlex.quote(flow.destination.private_ip)} "
                f"--port {flow.destination_port} --cport {flow.source_port} --time {duration_seconds} --omit 1 --json",
                timeout_seconds=duration_seconds + 25,
                comment="Envelope E2E bounded iperf3 sender",
            )
            try:
                client = json.loads(client_result.stdout)
            except json.JSONDecodeError as error:
                raise TransportError("iperf3 client returned invalid JSON") from error
            if not isinstance(client, Mapping):
                raise TransportError("iperf3 client returned a non-object result")
            server_result = self.ssm.wait(
                flow.destination,
                cast(str, server_id),
                timeout_seconds=duration_seconds + 25,
            )
            if not server_result.succeeded:
                raise TransportError("iperf3 receiver did not complete")
            server_done = True
            capture_result = self.ssm.wait(
                source_appliance,
                cast(str, capture_id),
                timeout_seconds=duration_seconds + 20,
            )
            if not capture_result.succeeded:
                raise TransportError("bounded TCP SYN capture did not complete")
            capture_done = True
            summary = self._inspect_capture_summary(source_appliance, capture_path)
            frames = summary.get("frames")
            mss_values = [
                cast(Mapping[str, Any], _captured_inner(frame)["transport"]).get("mss")
                for frame in frames or []
                if isinstance(frame, Mapping)
                and _capture_matches_flow(frame, flow, reverse=False)
                and isinstance(_captured_inner(frame), Mapping)
                and isinstance(_captured_inner(frame).get("transport"), Mapping)
                and cast(Mapping[str, Any], _captured_inner(frame)["transport"]).get("flags", 0) & 0x12 == 0x02
            ]
            mss_values = [value for value in mss_values if isinstance(value, int)]
            if not mss_values:
                raise TransportError("TCP SYN capture omitted a negotiated MSS option")
        finally:
            source_appliance = deployment.appliance(flow.source.site)
            if capture_id is not None and not capture_done:
                try:
                    self.ssm.cancel(source_appliance, capture_id, timeout_seconds=5)
                except E2EError:
                    pass
            if server_id is not None and not server_done:
                try:
                    self.ssm.cancel(flow.destination, server_id, timeout_seconds=5)
                except E2EError:
                    pass
            try:
                self._execute(
                    source_appliance,
                    f"set -u; rm -f {shlex.quote(capture_path)}; ! test -e {shlex.quote(capture_path)}",
                    timeout_seconds=20,
                    comment="Envelope E2E delete TCP SYN capture",
                )
                raw_capture_deleted = True
            finally:
                self.capture_cleanup_events.append(
                    {
                        "source_site": flow.source.site,
                        "purpose": "tcp-syn-mss",
                        "stopped": capture_done,
                        "raw_pcaps_deleted": raw_capture_deleted,
                        "error_count": 0 if raw_capture_deleted else 1,
                    }
                )
                if pause_attempted:
                    self._resume_managed_responder(flow.destination, "tcp")
        connected = client.get("start", {}).get("connected") if isinstance(client.get("start"), Mapping) else None
        received = client.get("end", {}).get("sum_received") if isinstance(client.get("end"), Mapping) else None
        if not isinstance(connected, list) or len(connected) != 1 or not isinstance(received, Mapping):
            raise TransportError("iperf3 result omitted exact connection or receive summary")
        if connected[0].get("local_port") != flow.source_port or connected[0].get("remote_port") != flow.destination_port:
            raise TransportError("iperf3 changed the declared TCP tuple")
        bits_per_second = received.get("bits_per_second")
        transferred = received.get("bytes")
        seconds = received.get("seconds")
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 for value in (bits_per_second, transferred, seconds)):
            raise TransportError("iperf3 result contains invalid throughput, bytes, or duration")
        return {
            "flow_id": flow.flow_id,
            "completed": True,
            "throughput_mbps": float(bits_per_second) / 1_000_000.0,
            "bytes": int(transferred),
            "duration_seconds": float(seconds),
            "syn_mss": min(cast(list[int], mss_values)),
            "syn_capture_sha256": summary["file_sha256"],
            "raw_pcap_deleted": True,
        }

    def run_mtu_transport(
        self,
        deployment: ProtectedDeployment,
        profile: ApprovedLoadProfile,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        deadline = self.monotonic() + timeout_seconds
        by_site = {site: [flow for flow in flows if flow.source.site == site] for site in SITES}
        expected_purposes = [
            "mtu-safe-icmp",
            "mtu-safe-udp",
            "mtu-oversized-icmp",
            "mtu-oversized-udp",
            "tcp-mss-sustained",
        ]
        if any([flow.purpose for flow in by_site[site]] != expected_purposes for site in SITES):
            raise TransportError("MTU flow matrix is incomplete or out of order")
        results: list[dict[str, Any]] = []
        directions: list[dict[str, Any]] = []
        safe_icmp_payload = profile.safe_inner_mtu - 28
        safe_udp_payload = profile.safe_inner_mtu - 28
        for site in SITES:
            self._restart_envelope(deployment, timeout_seconds=max(45, int((deadline - self.monotonic()) * 0.25)))
            site_results: dict[str, Mapping[str, Any]] = {}
            for flow in by_site[site]:
                self._begin_flow_window(flow)
                before = self._metric_snapshots(deployment)
                remaining = max(15, int(deadline - self.monotonic()))
                if flow.purpose == "mtu-safe-icmp":
                    value: dict[str, Any] = {"probe": self._run_icmp_probe(flow, payload_bytes=safe_icmp_payload, timeout_seconds=remaining)}
                elif flow.purpose == "mtu-safe-udp":
                    value = {"probe": self._run_sized_udp(flow, payload_bytes=safe_udp_payload, expect_drop=False, timeout_seconds=remaining)}
                elif flow.purpose == "mtu-oversized-icmp":
                    value = self._run_oversized_icmp(
                        deployment,
                        flow,
                        payload_bytes=safe_icmp_payload + 1,
                        timeout_seconds=remaining,
                    )
                elif flow.purpose == "mtu-oversized-udp":
                    value = self._run_sized_udp(flow, payload_bytes=safe_udp_payload + 1, expect_drop=True, timeout_seconds=remaining)
                else:
                    iperf = self._run_iperf3(
                        deployment,
                        flow,
                        duration_seconds=profile.sustained_tcp_duration_seconds,
                        timeout_seconds=remaining,
                    )
                    value = {"transport": iperf}
                after = self._metric_snapshots(deployment)
                if flow.expected_result == "mtu-drop":
                    metrics = assert_mtu_drop_metric_contract(before, after, initiator_site=site)
                else:
                    probe = value.get("probe")
                    sessions = None if flow.protocol == "icmp" else 1
                    metrics = assert_flow_metric_contract(
                        before,
                        after,
                        initiator_site=site,
                        receiver_sessions=sessions,
                        receiver_identity_verified=True,
                    )
                item = {"flow_id": flow.flow_id, **value, "metrics": metrics}
                results.append(item)
                site_results[flow.purpose] = item
                self._end_flow_window(flow)
            tcp = cast(Mapping[str, Any], site_results["tcp-mss-sustained"]["transport"])
            directions.append(
                {
                    "source_site": site,
                    "destination_site": _opposite(site),
                    "inner_mtu": profile.safe_inner_mtu,
                    "safe_icmp_inner_bytes": safe_icmp_payload + 28,
                    "safe_udp_inner_bytes": safe_udp_payload + 28,
                    "oversized_icmp_inner_bytes": safe_icmp_payload + 29,
                    "oversized_udp_inner_bytes": safe_udp_payload + 29,
                    "tcp_mss": tcp["syn_mss"],
                    "tcp_mss_maximum": profile.maximum_tcp_mss,
                    "tcp_syn_capture_sha256": tcp["syn_capture_sha256"],
                    "tcp_syn_raw_pcap_deleted": tcp["raw_pcap_deleted"],
                    "sustained_tcp_bytes": tcp["bytes"],
                    "sustained_tcp_duration_seconds": tcp["duration_seconds"],
                    "pmtu_icmp_expected": False,
                    "flow_ids": [flow.flow_id for flow in by_site[site]],
                }
            )
        return {"results": results, "directions": directions}

    def _run_concurrent_load(
        self,
        flows: Sequence[FlowRecord],
        profile: ApprovedLoadProfile,
        *,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        command_ids: dict[Site, str] = {}
        try:
            for site in SITES:
                selected = [flow for flow in flows if flow.source.site == site]
                specs = [
                    {"flow_id": flow.flow_id, "protocol": flow.protocol, "source_port": flow.source_port}
                    for flow in selected
                ]
                encoded = base64.b64encode(
                    gzip.compress(
                        json.dumps(specs, sort_keys=True, separators=(",", ":")).encode("ascii"),
                        mtime=0,
                    )
                ).decode("ascii")
                target = selected[0].source
                destination = selected[0].destination
                command = " ".join(
                    [
                        "set -euo pipefail; exec",
                        shlex.quote(REMOTE_AGENT_PATH),
                        "batch-client --host",
                        destination.private_ip,
                        "--port 5201 --source-ip",
                        target.private_ip,
                        "--flows-b64",
                        encoded,
                        "--duration",
                        str(profile.concurrent_duration_seconds),
                        "--interval 0.25 --ack-timeout 1.0",
                    ]
                )
                command_ids[site] = self.ssm.send(
                    SSMCommand(
                        target,
                        (command,),
                        timeout_seconds=profile.concurrent_duration_seconds + 30,
                        comment="Envelope E2E approved concurrent TCP UDP load",
                    ),
                    timeout_seconds=10,
                )
            results: list[dict[str, Any]] = []
            for site in SITES:
                target = next(flow.source for flow in flows if flow.source.site == site)
                result = self.ssm.wait(
                    target,
                    command_ids[site],
                    timeout_seconds=min(timeout_seconds, profile.concurrent_duration_seconds + 45),
                )
                if not result.succeeded:
                    raise LoadProfileError(f"{site} concurrent load command did not complete")
                value = self._json_from_result(result)
                site_results = value.get("results")
                if not isinstance(site_results, list):
                    raise LoadProfileError(f"{site} concurrent load returned no flow results")
                results.extend(cast(list[dict[str, Any]], site_results))
            expected = {flow.flow_id: flow for flow in flows}
            if {value.get("flow_id") for value in results} != set(expected):
                raise LoadProfileError("concurrent load result changed its exact flow set")
            for value in results:
                flow = expected[cast(str, value["flow_id"])]
                if (
                    value.get("protocol") != flow.protocol
                    or value.get("source_port") != flow.source_port
                    or value.get("completed") is not True
                ):
                    raise LoadProfileError(f"concurrent flow {flow.flow_id} changed its socket identity")
            return results
        except Exception:
            for site, command_id in command_ids.items():
                target = next((flow.source for flow in flows if flow.source.site == site), None)
                if target is None:
                    continue
                try:
                    self.ssm.cancel(target, command_id, timeout_seconds=5)
                except E2EError:
                    pass
            raise

    def run_approved_load(
        self,
        deployment: ProtectedDeployment,
        profile: ApprovedLoadProfile,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        deadline = self.monotonic() + timeout_seconds
        iperf_flows = [flow for flow in flows if flow.purpose == "iperf3"]
        concurrent_flows = [flow for flow in flows if flow.purpose.startswith("concurrent-")]
        expected_concurrent = 2 * (profile.concurrent_tcp_flows + profile.concurrent_udp_flows)
        if (
            len(iperf_flows) != 2
            or {flow.source.site for flow in iperf_flows} != set(SITES)
            or len(concurrent_flows) != expected_concurrent
            or any(flow.protocol not in TRANSPORT_PROTOCOLS for flow in flows)
        ):
            raise LoadProfileError("approved load flow matrix is incomplete")
        before = self._metric_snapshots(deployment)
        iperf_results = [
            self._run_with_flow_window(
                flow,
                lambda flow=flow: self._run_iperf3(
                    deployment,
                    flow,
                    duration_seconds=profile.iperf_duration_seconds,
                    timeout_seconds=max(30, int(deadline - self.monotonic())),
                ),
            )
            for flow in iperf_flows
        ]
        concurrent_results = self._run_with_flow_windows(
            concurrent_flows,
            lambda: self._run_concurrent_load(
                concurrent_flows,
                profile,
                timeout_seconds=max(30, int(deadline - self.monotonic())),
            ),
        )
        after = self._metric_snapshots(deployment)
        metrics = assert_bidirectional_metric_contract(before, after)
        return {
            "profile_sha256": profile.sha256,
            "iperf3": iperf_results,
            "concurrent": concurrent_results,
            "metrics": metrics,
        }

    def _remote_monotonic_ns(self, target: SSMTarget) -> int:
        value = self._execute_json(
            target,
            "python3 -c 'import json,time; print(json.dumps({\"monotonic_ns\":time.monotonic_ns(),\"success\":True}))'",
            timeout_seconds=15,
            comment="Envelope E2E continuity clock",
        ).get("monotonic_ns")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise StreamAnalysisError("remote continuity clock returned an invalid value")
        return value

    def _run_stream_mutation(
        self,
        flow: FlowRecord,
        *,
        timeout_seconds: int,
        maximum_loss_ns: int,
        label: str,
        mutate_and_restore: Callable[[], Mapping[str, Any]],
    ) -> tuple[StreamAnalysis, dict[str, Any], Mapping[str, Any]]:
        duration = max(35, min(140, timeout_seconds - 30))
        interval = 0.5
        count = max(20, int((duration - 2) / interval))
        ready_path = f"/run/envelope-e2e-stream-{flow.flow_id}.ready"
        server_command = " ".join(
            [
                "set -euo pipefail; exec",
                shlex.quote(REMOTE_AGENT_PATH),
                "stream-server",
                "--bind",
                flow.destination.private_ip,
                "--port",
                str(flow.destination_port),
                "--flow-id",
                flow.flow_id,
                "--duration",
                str(duration),
            ]
        )
        client_command = " ".join(
            [
                "set -euo pipefail; exec",
                shlex.quote(REMOTE_AGENT_PATH),
                "stream-client",
                "--host",
                flow.destination.private_ip,
                "--port",
                str(flow.destination_port),
                "--source-ip",
                flow.source.private_ip,
                "--source-port",
                str(flow.source_port),
                "--flow-id",
                flow.flow_id,
                "--count",
                str(count),
                "--interval",
                str(interval),
                "--ack-timeout",
                "0.3",
                "--ready-path",
                shlex.quote(ready_path),
            ]
        )
        server_spec = SSMCommand(
            flow.destination,
            (server_command,),
            timeout_seconds=duration + 10,
            comment="Envelope E2E continuity receiver",
        )
        client_spec = SSMCommand(
            flow.source,
            (client_command,),
            timeout_seconds=duration + 5,
            comment="Envelope E2E one-socket continuity stream",
        )
        server_id: str | None = None
        client_id: str | None = None
        pause_attempted = False
        try:
            pause_attempted = True
            self._pause_managed_responder(flow.destination, "udp")
            server_id = self.ssm.send(server_spec, timeout_seconds=10)
            self._wait_listener(flow.destination, "udp", timeout_seconds=15)
            self._execute(
                flow.source,
                f"set -euo pipefail; rm -f {shlex.quote(ready_path)}; ! test -e {shlex.quote(ready_path)}",
                timeout_seconds=15,
                comment="Envelope E2E reset continuity readiness",
            )
            client_id = self.ssm.send(client_spec, timeout_seconds=10)
            self._wait_until(
                lambda: self._execute_json(
                    flow.source,
                    f"set -euo pipefail; test -s {shlex.quote(ready_path)}; "
                    "printf '{\"stream_ready\":true,\"success\":true}\\n'",
                    timeout_seconds=10,
                    comment="Envelope E2E continuity stream readiness",
                ),
                lambda value: value.get("stream_ready") is True,
                timeout_seconds=20,
                description=f"{label} first acknowledged continuity marker",
                interval_seconds=1,
            )
            mutation_start = self._remote_monotonic_ns(flow.source)
            mutation_summary = mutate_and_restore()
            mutation_end = self._remote_monotonic_ns(flow.source)
            client_result = self.ssm.wait(
                flow.source,
                client_id,
                timeout_seconds=max(20, duration + 10),
            )
            server_result = self.ssm.wait(
                flow.destination,
                cast(str, server_id),
                timeout_seconds=max(20, duration + 10),
            )
            if not client_result.succeeded or not server_result.succeeded:
                raise StreamAnalysisError(f"{label} continuity commands did not both complete")
            client = self._json_from_result(client_result)
            receiver = self._json_from_result(server_result)
            self._execute(
                flow.source,
                f"set -u; rm -f {shlex.quote(ready_path)}; ! test -e {shlex.quote(ready_path)}",
                timeout_seconds=15,
                comment="Envelope E2E delete continuity readiness",
            )
        except Exception:
            for target, command_id in ((flow.source, client_id), (flow.destination, server_id)):
                if command_id is None:
                    continue
                try:
                    self.ssm.cancel(target, command_id, timeout_seconds=5)
                except E2EError:
                    pass
            try:
                self._execute(
                    flow.source,
                    f"set -u; rm -f {shlex.quote(ready_path)}",
                    timeout_seconds=15,
                    comment="Envelope E2E delete continuity readiness",
                )
            except E2EError:
                pass
            raise
        finally:
            if pause_attempted:
                self._resume_managed_responder(flow.destination, "udp")
        markers_value = client.get("markers")
        if not isinstance(markers_value, list) or client.get("socket_count") != 1 or client.get(
            "source_port"
        ) != flow.source_port:
            raise StreamAnalysisError(f"{label} did not retain one exact source socket")
        analysis = analyze_stream_markers(
            cast(Sequence[Mapping[str, Any]], markers_value),
            MutationInterval(mutation_start, mutation_end, label),
            maximum_loss_ns=maximum_loss_ns,
            expected_first_sequence=0,
            expected_last_sequence=count - 1,
        )
        if receiver.get("duplicates") != 0 or receiver.get("sessions") != 1:
            raise StreamAnalysisError(f"{label} receiver observed duplicate markers or multiple sockets")
        return analysis, receiver, mutation_summary

    def _return_rule_snapshot(self, deployment: ProtectedDeployment, site: Site) -> list[dict[str, Any]]:
        target = deployment.appliance(site)
        runtime = deployment.runtime(site)
        cidr = cast(str, deployment.workloads.target(site, "initiator").cidr)
        command = (
            "set -euo pipefail; ip -j -details -N -4 rule show | "
            f"jq -c '[.[] | select(.priority == {runtime.routing_rule_priority} and .iif == "
            f"{json.dumps(runtime.tailscale_iface)} and .dst == {json.dumps(cidr)} and "
            f"((.table|tostring) == {json.dumps(str(runtime.routing_table_id))}) and ((.protocol|tostring) == \"186\"))]'"
        )
        result = self._execute(target, command, timeout_seconds=20, comment="Envelope E2E exact route rule")
        try:
            value = json.loads(result.stdout.strip())
        except json.JSONDecodeError as error:
            raise ResilienceError("managed return-rule inspection returned invalid JSON") from error
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ResilienceError("managed return-rule inspection returned an invalid schema")
        return cast(list[dict[str, Any]], value)

    def _ensure_return_rule(self, deployment: ProtectedDeployment, site: Site) -> None:
        current = self._return_rule_snapshot(deployment, site)
        if len(current) == 1:
            return
        if current:
            raise ResilienceError("managed return-rule restoration found ambiguous exact objects")
        target = deployment.appliance(site)
        runtime = deployment.runtime(site)
        cidr = cast(str, deployment.workloads.target(site, "initiator").cidr)
        command = " ".join(
            [
                "set -euo pipefail; ip -4 rule add priority",
                str(runtime.routing_rule_priority),
                "iif",
                shlex.quote(runtime.tailscale_iface),
                "to",
                shlex.quote(cidr),
                "table",
                str(runtime.routing_table_id),
                "protocol 186",
            ]
        )
        try:
            self._execute(
                target,
                command,
                timeout_seconds=20,
                comment="Envelope E2E emergency exact route restore",
            )
        except SSMError:
            if len(self._return_rule_snapshot(deployment, site)) == 1:
                return
            raise
        if len(self._return_rule_snapshot(deployment, site)) != 1:
            raise ResilienceError("managed return-rule restoration did not create one exact object")

    def run_route_mutation(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int, maximum_loss_ns: int
    ) -> Mapping[str, Any]:
        self._begin_flow_window(flow)
        site: Site = "west"
        target = deployment.appliance(site)
        runtime = deployment.runtime(site)
        cidr = cast(str, deployment.workloads.target(site, "initiator").cidr)
        before_rule = self._return_rule_snapshot(deployment, site)
        if len(before_rule) != 1:
            raise ResilienceError("route drill requires exactly one owned managed return rule")
        before_digest = hashlib.sha256(
            json.dumps(before_rule, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        before_metrics = self._metric_snapshot(target)
        before_flow_metrics = self._metric_snapshots(deployment)

        def mutate() -> Mapping[str, Any]:
            try:
                self._execute(
                    target,
                    " ".join(
                        [
                            "set -euo pipefail; ip -4 rule del priority",
                            str(runtime.routing_rule_priority),
                            "iif",
                            shlex.quote(runtime.tailscale_iface),
                            "to",
                            shlex.quote(cidr),
                            "table",
                            str(runtime.routing_table_id),
                            "protocol 186",
                        ]
                    ),
                    timeout_seconds=20,
                    comment="Envelope E2E managed route mutation",
                )
                post_delete = self._return_rule_snapshot(deployment, site)
                if len(post_delete) > 1:
                    raise ResilienceError("managed return-rule reconciliation produced ambiguous exact objects")
                exact_rule_missing = True
                readiness = self._execute_json(
                    target,
                    "set +e; PREFLIGHT_MAX_ATTEMPTS=1 PREFLIGHT_RETRY_SECONDS=0 timeout 20 "
                    "/usr/local/sbin/envelope-preflight >/dev/null 2>&1; preflight=$?; "
                    "health=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 "
                    "http://127.0.0.1:9090/healthz || true); "
                    "printf '{\"health_code\":\"%s\",\"preflight_failed\":%s,"
                    "\"success\":true}\\n' \"$health\" \"$([[ $preflight -ne 0 ]] && printf true || printf false)\"",
                    timeout_seconds=30,
                    comment="Envelope E2E observe route drift readiness",
                )
                readiness_during_drift = {
                    "before_repair": True,
                    "exact_rule_missing": exact_rule_missing,
                    "unhealthy": readiness.get("health_code") != "200",
                    "host_preflight_failed": readiness.get("preflight_failed") is True,
                    "missing_cidr": cidr,
                    "reason": "owned-return-rule-missing",
                }
                self._wait_until(
                    lambda: self._return_rule_snapshot(deployment, site),
                    lambda value: len(value) == 1,
                    timeout_seconds=max(35, timeout_seconds - 35),
                    description="Envelope managed return-rule reconciliation",
                    interval_seconds=3,
                )
            finally:
                self._ensure_return_rule(deployment, site)
            restored = self._return_rule_snapshot(deployment, site)
            restored_digest = hashlib.sha256(
                json.dumps(restored, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if restored_digest != before_digest:
                raise ResilienceError("managed return rule was not restored byte-for-byte in normalized form")
            return {
                "before_sha256": before_digest,
                "after_sha256": restored_digest,
                "exact": True,
                "readiness_during_drift": readiness_during_drift,
            }

        analysis, receiver, mutation = self._run_stream_mutation(
            flow,
            timeout_seconds=timeout_seconds,
            maximum_loss_ns=maximum_loss_ns,
            label=Phase.ROUTE_MUTATION.value,
            mutate_and_restore=mutate,
        )
        after_metrics = self._metric_snapshot(target)
        repair_delta = assert_metric_delta(
            before_metrics,
            after_metrics,
            "routing_drift_repairs",
            minimum=1,
        )
        readiness_during_drift = cast(dict[str, Any], mutation["readiness_during_drift"])
        readiness_during_drift["routing_drift_repairs_delta"] = repair_delta
        readiness_during_drift["drift_observed"] = readiness_during_drift["exact_rule_missing"] is True and (
            readiness_during_drift["host_preflight_failed"] is True
            or readiness_during_drift["unhealthy"] is True
            or repair_delta > 0
        )
        if readiness_during_drift["drift_observed"] is not True:
            raise ResilienceError("route mutation produced no observed preflight, health, or repair signal")
        after_flow_metrics = self._metric_snapshots(deployment)
        flow_metrics = assert_flow_metric_contract(
            before_flow_metrics,
            after_flow_metrics,
            initiator_site=flow.source.site,
            receiver_sessions=1,
        )
        self._end_flow_window(flow)
        return {
            "passed": True,
            "restored": True,
            "continuity": {
                "bounded": True,
                "maximum_loss_ns": maximum_loss_ns,
                "missing_markers": len(analysis.missing_sequences),
                "receiver_duplicates": receiver["duplicates"],
            },
            "mutation": mutation,
            "readiness_during_drift": readiness_during_drift,
            "repair_metric_delta": repair_delta,
            "stream": analysis.as_dict(),
            "metrics": flow_metrics,
        }

    @staticmethod
    def _flow_log_summary(
        flow: FlowRecord,
        records: Sequence[Mapping[str, Any]],
        *,
        window: Mapping[str, int],
        workload_identities: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any] | None:
        if (
            set(window) != {"start_epoch", "end_epoch"}
            or isinstance(window.get("start_epoch"), bool)
            or not isinstance(window.get("start_epoch"), int)
            or isinstance(window.get("end_epoch"), bool)
            or not isinstance(window.get("end_epoch"), int)
            or not 0 <= window["start_epoch"] <= window["end_epoch"]
            or window["end_epoch"] - window["start_epoch"] > 7200
        ):
            raise FlowLogError(f"flow {flow.flow_id} has an invalid bounded wall-clock window")
        required_identity_keys = {
            "site",
            "role",
            "private_ip",
            "instance_id",
            "interface_id",
            "subnet_id",
            "flow_directions",
        }
        source_key = f"{flow.source.site}-{flow.source.role}"
        destination_key = f"{flow.destination.site}-{flow.destination.role}"
        if set(workload_identities) != {f"{site}-{role}" for site in SITES for role in WORKLOAD_ROLES}:
            raise FlowLogError("Flow Log correlation requires all four readiness workload identities")
        if any(
            set(identity) != required_identity_keys
            or identity.get("flow_directions") != ["egress", "ingress"]
            or not _ENI_ID_RE.fullmatch(str(identity.get("interface_id", "")))
            for identity in workload_identities.values()
        ):
            raise FlowLogError("Flow Log readiness identity is incomplete or invalid")
        source_identity = workload_identities[source_key]
        destination_identity = workload_identities[destination_key]
        if (
            source_identity.get("private_ip") != flow.source.private_ip
            or source_identity.get("instance_id") != flow.source.instance_id
            or source_identity.get("subnet_id") != flow.source.subnet_id
            or destination_identity.get("private_ip") != flow.destination.private_ip
            or destination_identity.get("instance_id") != flow.destination.instance_id
            or destination_identity.get("subnet_id") != flow.destination.subnet_id
        ):
            raise FlowLogError(f"flow {flow.flow_id} differs from its readiness workload identities")
        protocol_number = {"icmp": 1, "tcp": 6, "udp": 17}[flow.protocol]

        def ports_match(record: Mapping[str, Any], *, reverse: bool) -> bool:
            if flow.protocol == "icmp":
                return record.get("srcport") is None and record.get("dstport") is None
            return (
                record.get("srcport") == (flow.destination_port if reverse else flow.source_port)
                and record.get("dstport") == (flow.source_port if reverse else flow.destination_port)
            )

        def tuple_matches(record: Mapping[str, Any], *, reverse: bool) -> bool:
            source = flow.destination.private_ip if reverse else flow.source.private_ip
            destination = flow.source.private_ip if reverse else flow.destination.private_ip
            return (
                record.get("srcaddr") == source
                and record.get("dstaddr") == destination
                and record.get("packet_source_address") == source
                and record.get("packet_destination_address") == destination
                and ports_match(record, reverse=reverse)
                and record.get("protocol_number") == protocol_number
                and record.get("action") == "ACCEPT"
                and record.get("log_status") == "OK"
                and isinstance(record.get("start_epoch"), int)
                and isinstance(record.get("end_epoch"), int)
                and record["start_epoch"] <= record["end_epoch"]
                and record["end_epoch"] >= window["start_epoch"] - 60
                and record["start_epoch"] <= window["end_epoch"] + 60
            )

        def identity_matches(record: Mapping[str, Any], identity: Mapping[str, Any], direction: str) -> bool:
            return (
                record.get("site") == identity["site"]
                and record.get("instance_id") == identity["instance_id"]
                and record.get("interface_id") == identity["interface_id"]
                and record.get("subnet_id") == identity["subnet_id"]
                and record.get("flow_direction") == direction
            )

        path_specs = [
            ("source-egress", source_identity, "egress", False),
            ("destination-ingress", destination_identity, "ingress", False),
            ("responder-egress", destination_identity, "egress", True),
            ("initiator-ingress", source_identity, "ingress", True),
        ]
        paths: list[dict[str, Any]] = []
        for name, identity, direction, reverse in path_specs:
            matches = [
                record
                for record in records
                if tuple_matches(record, reverse=reverse) and identity_matches(record, identity, direction)
            ]
            paths.append(
                {
                    "path": name,
                    "site": identity["site"],
                    "role": identity["role"],
                    "flow_direction": direction,
                    "instance_id": identity["instance_id"],
                    "interface_id": identity["interface_id"],
                    "subnet_id": identity["subnet_id"],
                    "matches": len(matches),
                    "packet_count": sum(cast(int, record["packets"]) for record in matches),
                    "byte_count": sum(cast(int, record["bytes"]) for record in matches),
                }
            )
        path_by_name = {path["path"]: path for path in paths}
        required_names = (
            ["source-egress"]
            if flow.expected_result == "mtu-drop"
            else ["source-egress", "destination-ingress", "responder-egress", "initiator-ingress"]
        )
        if any(path_by_name[name]["matches"] < 1 for name in required_names):
            return None
        if flow.expected_result == "mtu-drop" and flow.protocol != "icmp" and any(
            path_by_name[name]["matches"] != 0
            for name in ("destination-ingress", "responder-egress", "initiator-ingress")
        ):
            return None
        selected_paths = [path_by_name[name] for name in required_names]
        forward = [path for path in selected_paths if path["path"] in {"source-egress", "destination-ingress"}]
        reverse = [path for path in selected_paths if path["path"] in {"responder-egress", "initiator-ingress"}]
        omitted_matches = sum(
            cast(int, path_by_name[name]["matches"])
            for name in path_by_name
            if name not in required_names
        )
        icmp_drop = flow.protocol == "icmp" and flow.expected_result == "mtu-drop"
        return {
            "flow_id": flow.flow_id,
            "flow_tuple": flow.tuple_dict(),
            "accepted": True,
            "reverse_required": flow.expected_result == "success",
            "forward_matches": sum(cast(int, path["matches"]) for path in forward),
            "reverse_matches": sum(cast(int, path["matches"]) for path in reverse),
            "packet_count": sum(cast(int, path["packet_count"]) for path in selected_paths),
            "byte_count": sum(cast(int, path["byte_count"]) for path in selected_paths),
            "phase": _flow_phase(flow.as_dict()).value,
            "window": {
                "start_epoch": window["start_epoch"],
                "end_epoch": window["end_epoch"],
                "aggregation_allowance_seconds": 60,
            },
            "path_evidence": selected_paths,
            "unexpected_path_matches": 0,
            "aggregation_overlap_path_matches": omitted_matches if icmp_drop else 0,
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
        }

    def _managed_flow_log_status(
        self, deployment: ProtectedDeployment, site: Site
    ) -> dict[str, Any]:
        expected = deployment.flow_logs[site]
        response = self.aws.json(
            ["ec2", "describe-flow-logs", "--flow-log-ids", expected.flow_log_id],
            region=expected.region,
        )
        values = response.get("FlowLogs")
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], Mapping):
            raise FlowLogError(f"{site} managed VPC Flow Log lookup was not exact")
        value = values[0]
        return {
            "flow_log_id": value.get("FlowLogId"),
            "resource_id": value.get("ResourceId"),
            "flow_log_status": value.get("FlowLogStatus"),
            "delivery_status": value.get("DeliverLogsStatus"),
            "destination_type": value.get("LogDestinationType"),
            "destination": value.get("LogDestination"),
        }

    def start_flow_logs(self, deployment: ProtectedDeployment, *, timeout_seconds: int) -> object:
        for site in SITES:
            expected = deployment.flow_logs[site]
            status = self._wait_until(
                lambda site=site: self._managed_flow_log_status(deployment, site),
                lambda value, site=site: value.get("flow_log_id") == deployment.flow_logs[site].flow_log_id
                and value.get("resource_id") == deployment.appliance(site).vpc_id
                and value.get("flow_log_status") == "ACTIVE"
                and value.get("delivery_status") == "SUCCESS"
                and value.get("destination_type") == "cloud-watch-logs"
                and value.get("destination") == deployment.flow_logs[site].log_group_arn,
                timeout_seconds=timeout_seconds,
                description=f"{site} managed VPC Flow Log delivery readiness",
                interval_seconds=3,
            )
            if status.get("delivery_status") != "SUCCESS":
                raise FlowLogError(f"{site} managed VPC Flow Log delivery is not successful")
            groups = self.aws.json(
                [
                    "logs",
                    "describe-log-groups",
                    "--log-group-name-prefix",
                    expected.log_group_name,
                ],
                region=expected.region,
            ).get("logGroups")
            exact = [
                group
                for group in groups or []
                if isinstance(group, Mapping) and group.get("logGroupName") == expected.log_group_name
            ]
            if (
                not isinstance(groups, list)
                or len(exact) != 1
                or str(exact[0].get("arn", "")).removesuffix(":*") != expected.log_group_arn
                or exact[0].get("retentionInDays") != 7
            ):
                raise FlowLogError(f"{site} managed Flow Log group identity or retention is invalid")
        return FlowLogHandle(
            flow_logs={site: deployment.flow_logs[site] for site in SITES},
            started_milliseconds=int(time.time() * 1000),
        )

    @staticmethod
    def _parse_cloudwatch_flow_log_text(text: str) -> list[dict[str, Any]]:
        fields = (
            "version",
            "account_id",
            "interface_id",
            "srcaddr",
            "dstaddr",
            "srcport",
            "dstport",
            "protocol_number",
            "packets",
            "bytes",
            "start_epoch",
            "end_epoch",
            "action",
            "log_status",
            "vpc_id",
            "subnet_id",
            "instance_id",
            "region",
            "az_id",
            "flow_direction",
            "traffic_path",
            "packet_source_address",
            "packet_destination_address",
        )
        values = text.strip().split()
        if len(values) != len(fields) or not values[0].isdigit():
            return []
        record: dict[str, Any] = dict(zip(fields, values, strict=True))
        try:
            for name in (
                "protocol_number",
                "packets",
                "bytes",
                "start_epoch",
                "end_epoch",
            ):
                record[name] = int(record[name])
            for name in ("srcport", "dstport"):
                record[name] = (
                    None
                    if record[name] == "-" or (record["protocol_number"] == 1 and record[name] == "0")
                    else int(record[name])
                )
        except ValueError:
            return []
        return [record]

    def capture_flow_logs(
        self,
        handle: object,
        deployment: ProtectedDeployment,
        flows: Sequence[FlowRecord],
        *,
        timeout_seconds: int,
    ) -> Sequence[Mapping[str, Any]]:
        if not isinstance(handle, FlowLogHandle) or set(handle.flow_logs) != set(SITES):
            raise FlowLogError("managed VPC Flow Log capture handle is invalid")
        flow_ids = {flow.flow_id for flow in flows}
        if len(flow_ids) != len(flows) or set(self.flow_windows) != flow_ids:
            raise FlowLogError("Flow Log capture requires one bounded wall-clock window for every declared flow")
        if any(set(self.flow_windows[flow_id]) != {"start_epoch", "end_epoch"} for flow_id in flow_ids):
            raise FlowLogError("Flow Log capture found an unfinished wall-clock window")
        # Bind the expected VPC identities for the bounded query helper without
        # retaining raw CloudWatch events in evidence.
        handle_vpcs = {site: deployment.appliance(site).vpc_id for site in SITES}

        def records() -> list[dict[str, Any]]:
            return self._cloudwatch_flow_records_for_vpcs(
                handle,
                handle_vpcs,
                end_milliseconds=int(time.time() * 1000),
            )

        deadline = self.monotonic() + timeout_seconds
        last_count = 0
        while self.monotonic() < deadline:
            values = records()
            last_count = len(values)
            summaries = [
                self._flow_log_summary(
                    flow,
                    values,
                    window=self.flow_windows[flow.flow_id],
                    workload_identities=self.workload_flow_identities,
                )
                for flow in flows
            ]
            if all(summary is not None for summary in summaries):
                return cast(list[Mapping[str, Any]], summaries)
            self.sleep(min(10, max(0, deadline - self.monotonic())))
        raise FlowLogError(
            f"managed VPC Flow Logs did not deliver every declared protocol tuple within {timeout_seconds}s; parsed_records={last_count}"
        )

    def _cloudwatch_flow_records_for_vpcs(
        self,
        handle: FlowLogHandle,
        vpc_ids: Mapping[Site, str],
        *,
        end_milliseconds: int,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        event_ids: set[str] = set()
        for site in SITES:
            target = handle.flow_logs[site]
            token: str | None = None
            seen_tokens: set[str] = set()
            pages = 0
            while True:
                pages += 1
                if pages > 1_000:
                    raise FlowLogError(f"{site} CloudWatch Flow Log pagination exceeded 1000 pages")
                args = [
                    "logs",
                    "filter-log-events",
                    "--log-group-name",
                    target.log_group_name,
                    "--start-time",
                    str(max(0, handle.started_milliseconds - 60_000)),
                    "--end-time",
                    str(end_milliseconds),
                    "--interleaved",
                ]
                if token is not None:
                    args.extend(["--next-token", token])
                response = self.aws.json(args, region=target.region)
                events = response.get("events")
                if not isinstance(events, list):
                    raise FlowLogError(f"{site} CloudWatch Flow Log query returned an invalid event schema")
                for event in events:
                    if not isinstance(event, Mapping) or not isinstance(event.get("message"), str):
                        raise FlowLogError(f"{site} CloudWatch Flow Log query returned an invalid event")
                    event_id = str(event.get("eventId", ""))
                    if event_id and event_id in event_ids:
                        continue
                    if event_id:
                        event_ids.add(event_id)
                    records.extend(
                        {**record, "site": site}
                        for record in self._parse_cloudwatch_flow_log_text(str(event["message"]))
                        if record.get("vpc_id") == vpc_ids[site] and record.get("region") == target.region
                    )
                next_token = response.get("nextToken")
                if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                    break
                seen_tokens.add(next_token)
                token = next_token
        if len(records) > 100_000:
            raise FlowLogError("CloudWatch VPC Flow Log query exceeded the 100000-record bound")
        return records

    def stop_flow_logs(self, handle: object, *, timeout_seconds: int) -> Mapping[str, Any]:
        if not isinstance(handle, FlowLogHandle) or set(handle.flow_logs) != set(SITES):
            raise FlowLogError("managed VPC Flow Log close handle is invalid")
        for site in SITES:
            expected = handle.flow_logs[site]
            response = self.aws.json(
                ["ec2", "describe-flow-logs", "--flow-log-ids", expected.flow_log_id],
                region=expected.region,
            )
            values = response.get("FlowLogs")
            if (
                not isinstance(values, list)
                or len(values) != 1
                or values[0].get("FlowLogId") != expected.flow_log_id
                or values[0].get("FlowLogStatus") != "ACTIVE"
                or values[0].get("DeliverLogsStatus") != "SUCCESS"
                or values[0].get("LogDestination") != expected.log_group_arn
            ):
                raise FlowLogError(f"{site} managed VPC Flow Log ownership changed during acceptance")
        return {
            "stopped": True,
            "capture_closed": True,
            "ownership_preserved": True,
            "flow_log_count": 2,
        }

    def collect_diagnostics(self, deployment: ProtectedDeployment | None) -> Mapping[str, Any]:
        if deployment is None:
            return {"collection": "not-started", "reason": "deployment output did not parse"}
        diagnostics: dict[str, Any] = {
            "hosts": {},
            "target_health": {},
            "capture_cleanup": list(self.capture_cleanup_events),
            "capture_assertions": list(self.capture_assertion_events),
        }
        for site in SITES:
            appliance = deployment.appliance(site)
            try:
                value = collect_appliance_diagnostics(
                    cast(AwsCLI, self.aws),
                    {"region": appliance.region},
                    appliance.instance_id,
                )
                diagnostics["hosts"][f"{site}-appliance"] = sanitize_evidence_value(value)
            except Exception as error:
                diagnostics["hosts"][f"{site}-appliance"] = {
                    "collection": "failed",
                    "error": _sanitize_string(str(error)),
                }
            diagnostics["target_health"][site] = sanitize_evidence_value(self._target_health(appliance))
            for role in WORKLOAD_ROLES:
                target = deployment.workloads.target(site, role)
                try:
                    result = self._execute(
                        target,
                        "set +e; cloud-init status --long 2>&1; systemctl is-active amazon-ssm-agent.service 2>&1; "
                        "ip -j route show table all 2>&1",
                        timeout_seconds=45,
                        comment="Envelope E2E workload diagnostics",
                    )
                    diagnostics["hosts"][f"{site}-{role}"] = {
                        "status": result.status,
                        "command_id": result.command_id,
                        "output": _sanitize_string(result.stdout),
                    }
                except Exception as error:
                    diagnostics["hosts"][f"{site}-{role}"] = {
                        "collection": "failed",
                        "error": _sanitize_string(str(error)),
                    }
        return diagnostics

    def run_service_stop(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int
    ) -> Mapping[str, Any]:
        self._begin_flow_window(flow)
        target = deployment.appliance("west")
        before_pid = self._pid(target)
        unhealthy: dict[str, Any] | None = None
        try:
            self._execute(
                target,
                "set -euo pipefail; systemctl stop envelope.service; ! systemctl is-active --quiet envelope.service; "
                "printf '{\"stopped\":true,\"success\":true}\\n'",
                timeout_seconds=45,
                comment="Envelope E2E deliberate process stop",
            )
            unhealthy = self._wait_target_status(target, "unhealthy", timeout_seconds=min(90, timeout_seconds / 2))
        finally:
            self._execute(
                target,
                "set -euo pipefail; systemctl start envelope.service",
                timeout_seconds=45,
                comment="Envelope E2E process restoration",
            )
            ready = self._wait_appliance_ready(target, timeout_seconds=max(30, timeout_seconds / 2))
            self._wait_target_status(target, "healthy", timeout_seconds=max(30, timeout_seconds / 2))
        after_pid = cast(int, ready["pid"])
        if after_pid == before_pid or unhealthy is None:
            raise ResilienceError("service drill did not prove a new process and unhealthy target transition")
        before_metrics = self._metric_snapshots(deployment)
        probe = self._run_probe(flow, timeout_seconds=45)
        after_metrics = self._metric_snapshots(deployment)
        metrics = assert_flow_metric_contract(
            before_metrics,
            after_metrics,
            initiator_site=flow.source.site,
            receiver_sessions=cast(int, probe["receiver"]["sessions"]),
        )
        self._end_flow_window(flow)
        return {
            "passed": True,
            "restored": True,
            "continuity": {"expected": False, "reason": "process-local GWLB context reset"},
            "target_transition": ["healthy", "unhealthy", "healthy"],
            "process_generation_changed": True,
            "recovery": {"new_cold_flow": True},
            "probe": probe,
            "metrics": metrics,
        }

    def _boot_identity(self, target: ApplianceTarget) -> dict[str, Any]:
        return self._execute_json(
            target,
            "set -euo pipefail; boot=$(cat /proc/sys/kernel/random/boot_id); "
            "pid=$(systemctl show -p MainPID --value envelope.service); "
            "printf '{\"boot_id\":\"%s\",\"pid\":%s,\"success\":true}\\n' \"$boot\" \"$pid\"",
            timeout_seconds=20,
            comment="Envelope E2E boot generation",
        )

    def run_ec2_reboot(
        self, deployment: ProtectedDeployment, site: Site, flow: FlowRecord, *, timeout_seconds: int
    ) -> Mapping[str, Any]:
        self._begin_flow_window(flow)
        target = deployment.appliance(site)
        if flow.source.site != site:
            raise ResilienceError("reboot recovery flow must originate through the rebooted appliance")
        before = self._boot_identity(target)
        self.aws.json(["ec2", "reboot-instances", "--instance-ids", target.instance_id], region=target.region)
        changed = cast(
            dict[str, Any],
            self._wait_until(
                lambda: self._boot_identity(target),
                lambda value: value.get("boot_id") != before.get("boot_id"),
                timeout_seconds=max(60, timeout_seconds * 0.7),
                description=f"{site} appliance boot generation change",
                interval_seconds=8,
            ),
        )
        ready = self._wait_appliance_ready(target, timeout_seconds=max(45, timeout_seconds * 0.25))
        self._wait_target_status(target, "healthy", timeout_seconds=max(45, timeout_seconds * 0.25))
        if changed.get("boot_id") == before.get("boot_id"):
            raise ResilienceError("EC2 reboot did not prove a new boot/process generation")
        before_metrics = self._metric_snapshots(deployment)
        probe = self._run_probe(flow, timeout_seconds=45)
        after_metrics = self._metric_snapshots(deployment)
        metrics = assert_flow_metric_contract(
            before_metrics,
            after_metrics,
            initiator_site=flow.source.site,
            receiver_sessions=cast(int, probe["receiver"]["sessions"]),
        )
        self._end_flow_window(flow)
        return {
            "passed": True,
            "restored": True,
            "continuity": {"expected": False, "reason": "reboot discards process-local GWLB context"},
            "boot_generation_changed": True,
            "process_generation_changed": True,
            "target_recovered_healthy": True,
            "persistent_configuration_recovered": True,
            "recovery": {"new_cold_flow": True},
            "probe": probe,
            "site": site,
            "metrics": metrics,
        }

    def _bootstrap_identity(self) -> dict[str, Any]:
        manifest = ManifestStore(self.config, cast(AwsCLI, self.aws), self.run_dir).recover()
        parameters = manifest.get("ssm_parameters")
        tailnet = manifest.get("tailnet")
        if not isinstance(parameters, list):
            raise ResilienceError("durable manifest omitted regional bootstrap parameter identities")
        if not isinstance(tailnet, Mapping):
            raise ResilienceError("durable manifest omitted the Tailnet bootstrap identity")
        generation = tailnet.get("key_generation")
        key_id = tailnet.get("auth_key_id")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ResilienceError("durable Tailnet bootstrap generation is invalid")
        if not isinstance(key_id, str) or not key_id:
            raise ResilienceError("durable Tailnet bootstrap key ID is absent")
        versions: dict[Site, int] = {}
        for parameter in parameters:
            if not isinstance(parameter, Mapping) or parameter.get("site") not in SITES:
                raise ResilienceError("durable bootstrap parameter identity is invalid")
            site = cast(Site, parameter["site"])
            response = self.aws.json(
                ["ssm", "get-parameter", "--name", str(parameter.get("name", ""))],
                region=str(parameter.get("region", "")),
            )
            version = response.get("Parameter", {}).get("Version")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise ResilienceError(f"{site} bootstrap parameter version is invalid")
            versions[site] = version
        if set(versions) != set(SITES):
            raise ResilienceError("bootstrap parameter versions do not cover both regions")
        return {
            "bootstrap_generation": generation,
            "bootstrap_identity_sha256": hashlib.sha256(key_id.encode()).hexdigest(),
            "parameter_versions": versions,
        }

    def run_tailscale_withdrawal(
        self, deployment: ProtectedDeployment, flow: FlowRecord, *, timeout_seconds: int, maximum_loss_ns: int
    ) -> Mapping[str, Any]:
        self._begin_flow_window(flow)
        target = deployment.appliance("west")
        remote_cidrs = deployment.runtime("west").remote_tailnet_cidrs
        identity_before = self._bootstrap_identity()
        before_flow_metrics = self._metric_snapshots(deployment)

        def mutate() -> Mapping[str, Any]:
            unhealthy: dict[str, Any] | None = None
            try:
                self._execute(
                    target,
                    "set -euo pipefail; tailscale set --accept-routes=false; "
                    "printf '{\"accept_routes\":false,\"success\":true}\\n'",
                    timeout_seconds=30,
                    comment="Envelope E2E withdraw accepted routes",
                )
                cidr_args = " ".join(shlex.quote(cidr) for cidr in remote_cidrs)
                wait_command = f"""set -euo pipefail
deadline=$((SECONDS+70))
while (( SECONDS < deadline )); do
  missing=true
  for cidr in {cidr_args}; do
    if ip -j route show table 52 "$cidr" | jq -e 'length > 0' >/dev/null; then missing=false; fi
  done
  code=$(curl --silent --output /dev/null --write-out '%{{http_code}}' --max-time 3 http://127.0.0.1:9090/healthz || true)
  if [[ "$missing" == true && "$code" != 200 ]]; then
    printf '{{"routes_withdrawn":true,"health_unready":true,"success":true}}\\n'
    exit 0
  fi
  sleep 2
done
exit 1"""
                withdrawn = self._execute_json(
                    target,
                    wait_command,
                    timeout_seconds=80,
                    comment="Envelope E2E observe route withdrawal",
                )
                if withdrawn.get("routes_withdrawn") is not True or withdrawn.get("health_unready") is not True:
                    raise ResilienceError("route withdrawal did not remove routes and make readiness unhealthy")
                unhealthy = self._wait_target_status(target, "unhealthy", timeout_seconds=50)
            finally:
                self._execute(
                    target,
                    "set -euo pipefail; tailscale set --accept-routes=true; "
                    "printf '{\"accept_routes\":true,\"success\":true}\\n'",
                    timeout_seconds=30,
                    comment="Envelope E2E reaccept routes without key rotation",
                )
                self._wait_appliance_ready(target, timeout_seconds=80)
                self._wait_target_status(target, "healthy", timeout_seconds=60)
            if unhealthy is None:
                raise ResilienceError("route withdrawal did not prove the expected target-health transition")
            return {"routes_withdrawn": True, "routes_reaccepted": True, "health_transition": True}

        analysis, receiver, mutation = self._run_stream_mutation(
            flow,
            timeout_seconds=timeout_seconds,
            maximum_loss_ns=maximum_loss_ns,
            label=Phase.TAILSCALE_WITHDRAWAL.value,
            mutate_and_restore=mutate,
        )
        identity_after = self._bootstrap_identity()
        if identity_after != identity_before:
            raise ResilienceError("route reacceptance changed the auth-key generation, ID, or parameter versions")
        after_flow_metrics = self._metric_snapshots(deployment)
        flow_metrics = assert_flow_metric_contract(
            before_flow_metrics,
            after_flow_metrics,
            initiator_site=flow.source.site,
            receiver_sessions=1,
        )
        self._end_flow_window(flow)
        return {
            "passed": True,
            "restored": True,
            "continuity": {
                "bounded": True,
                "maximum_loss_ns": maximum_loss_ns,
                "missing_markers": len(analysis.missing_sequences),
                "receiver_duplicates": receiver["duplicates"],
            },
            "mutation": mutation,
            "credential_rotation": False,
            "exact_routes_withdrawn": mutation.get("routes_withdrawn") is True,
            "withdrawn_cidrs": sorted(remote_cidrs),
            "restored_cidrs": sorted(remote_cidrs),
            "bootstrap_generation": identity_before["bootstrap_generation"],
            "bootstrap_identity_sha256": identity_before["bootstrap_identity_sha256"],
            "bootstrap_parameter_versions_unchanged": True,
            "stream": analysis.as_dict(),
            "metrics": flow_metrics,
        }


RUN_ALL_STAGES = (
    "build-selected-artifact",
    "protected-preflight",
    "prepare-publish",
    "saved-plan",
    "apply-once",
    "wait-ready",
    "full-e2e",
    "protected-cleanup",
)


class RunAllOperations(Protocol):
    def build(self) -> Mapping[str, Any]: ...

    def preflight(self) -> Mapping[str, Any]: ...

    def prepare(self) -> Mapping[str, Any]: ...

    def plan(self) -> pathlib.Path: ...

    def apply(self, plan_path: pathlib.Path) -> Mapping[str, Any]: ...

    def wait_ready(self, deployment: Mapping[str, Any], *, timeout_seconds: int) -> Mapping[str, Any]: ...

    def run_e2e(
        self,
        deployment: Mapping[str, Any],
        lifecycle: ProtectedLifecycleAPI,
        evidence_path: pathlib.Path,
        budgets: TimeoutBudgets,
    ) -> LiveRunResult: ...

    def cleanup(self) -> Mapping[str, Any]: ...


@dataclasses.dataclass(frozen=True)
class RunAllResult:
    exit_code: int
    record_path: pathlib.Path
    evidence_path: pathlib.Path
    record: Mapping[str, Any]

    @property
    def passed(self) -> bool:
        return self.exit_code == EXIT_OK


class _RunAllE2EResultError(AcceptanceError):
    def __init__(self, result: LiveRunResult):
        super().__init__(result.error or f"full E2E returned exit code {result.exit_code}")
        self.result = result


def _is_inner_ownership_block(result: LiveRunResult, *, run_id: str) -> bool:
    evidence = result.evidence
    failure = evidence.get("failure") if isinstance(evidence, Mapping) else None
    lifecycle = evidence.get("lifecycle") if isinstance(evidence, Mapping) else None
    phases = evidence.get("phases") if isinstance(evidence, Mapping) else None
    cleanup_records = [
        record
        for record in phases or []
        if isinstance(record, Mapping) and record.get("name") == Phase.CLEANUP.value
    ]
    category = failure.get("category") if isinstance(failure, Mapping) else None
    expected_resolution = {
        ConcurrentRunError.__name__: "competing-claim",
        AmbiguousOwnershipError.__name__: "ambiguous-ownership",
    }.get(category)
    cleanup = cleanup_records[0] if len(cleanup_records) == 1 else None
    cleanup_summary = cleanup.get("summary") if isinstance(cleanup, Mapping) else None
    return (
        result.exit_code == EXIT_ACCEPTANCE_FAILED
        and evidence.get("schema") == LIVE_EVIDENCE_SCHEMA
        and evidence.get("kind") == LIVE_EVIDENCE_KIND
        and evidence.get("run_id") == run_id
        and evidence.get("status") == "failed"
        and isinstance(failure, Mapping)
        and failure.get("phase") in {phase.value for phase in LIVE_PHASES}
        and expected_resolution is not None
        and isinstance(lifecycle, Mapping)
        and lifecycle.get("ownership_resolution") == expected_resolution
        and isinstance(cleanup, Mapping)
        and cleanup.get("status") == "skipped"
        and isinstance(cleanup_summary, Mapping)
        and cleanup_summary.get("ownership_resolution") == expected_resolution
    )


def _write_private_json(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class _RunAllLifecycleProxy:
    def __init__(self, delegate: ProtectedLifecycleAPI, cleanup: Callable[[], Mapping[str, Any]]):
        self.delegate = delegate
        self.cleanup_once = cleanup

    def claim(self, raw_deployment: Mapping[str, Any], deployment: ProtectedDeployment) -> Mapping[str, Any]:
        return self.delegate.claim(raw_deployment, deployment)

    def verify_no_drift(self, stage: Literal["before", "after"]) -> Mapping[str, Any]:
        return self.delegate.verify_no_drift(stage)

    def finish(self, passed: bool) -> Mapping[str, Any]:
        return self.delegate.finish(passed)

    def cleanup(self) -> Mapping[str, Any]:
        return self.cleanup_once()


class _BoundedCleanupLifecycleProxy:
    """Delegate lifecycle state while allowing one separately timed cleanup call."""

    def __init__(
        self,
        delegate: ProtectedLifecycleAPI,
        timeout_factory: Callable[[int], Any] = cleanup_hard_timeout,
    ):
        self.delegate = delegate
        self.timeout_factory = timeout_factory
        self.cleanup_attempted = False
        self.cleanup_result: Mapping[str, Any] | None = None
        self.cleanup_error: BaseException | None = None

    def claim(self, raw_deployment: Mapping[str, Any], deployment: ProtectedDeployment) -> Mapping[str, Any]:
        return self.delegate.claim(raw_deployment, deployment)

    def verify_no_drift(self, stage: Literal["before", "after"]) -> Mapping[str, Any]:
        return self.delegate.verify_no_drift(stage)

    def finish(self, passed: bool) -> Mapping[str, Any]:
        return self.delegate.finish(passed)

    def cleanup(self) -> Mapping[str, Any]:
        if self.cleanup_attempted:
            if self.cleanup_error is not None:
                raise self.cleanup_error
            return self.cleanup_result or {"complete": True}
        self.cleanup_attempted = True
        try:
            with self.timeout_factory(DEFAULT_TIMEOUTS.cleanup):
                value = self.delegate.cleanup()
            if not isinstance(value, Mapping):
                raise E2EError("protected cleanup returned a non-object result")
            self.cleanup_result = dict(value)
            return self.cleanup_result
        except BaseException as error:
            self.cleanup_error = error
            raise


class RunAllCoordinator:
    """Own one protected build-to-cleanup transaction with deterministic stage records."""

    def __init__(
        self,
        *,
        config: RunConfig,
        run_dir: pathlib.Path,
        evidence_path: pathlib.Path,
        lifecycle: ProtectedLifecycleAPI,
        operations: RunAllOperations,
        hard_timeout_seconds: int = RUN_ALL_HARD_TIMEOUT_SECONDS,
        readiness_timeout_seconds: int = 900,
        budgets: TimeoutBudgets = DEFAULT_TIMEOUTS,
        lock_factory: Callable[[pathlib.Path], Any] = lifecycle_lock,
        timeout_factory: Callable[[int], Any] = run_all_hard_timeout,
        cleanup_timeout_factory: Callable[[int], Any] = cleanup_hard_timeout,
    ):
        self.config = config
        self.run_dir = run_dir.expanduser().resolve()
        self.evidence_path = evidence_path.expanduser().resolve()
        self.record_path = self.run_dir / "run-all-result.json"
        self.diagnostics_path = self.run_dir / "diagnostics.json"
        if self.evidence_path.parent != self.run_dir:
            raise EvidenceError("run-all evidence must remain directly inside the protected run directory")
        if not 1 <= hard_timeout_seconds <= 7200 - DEFAULT_TIMEOUTS.cleanup:
            raise E2EError("run-all hard timeout plus cleanup reservation must be no greater than 7200 seconds")
        if (
            isinstance(readiness_timeout_seconds, bool)
            or not isinstance(readiness_timeout_seconds, int)
            or not 1 <= readiness_timeout_seconds <= hard_timeout_seconds
        ):
            raise E2EError("run-all readiness timeout must fit inside the hard-timeout window")
        self.lifecycle = lifecycle
        self.operations = operations
        self.active_timeout_seconds = hard_timeout_seconds
        self.readiness_timeout_seconds = readiness_timeout_seconds
        self.budgets = budgets
        self.lock_factory = lock_factory
        self.timeout_factory = timeout_factory
        self.cleanup_timeout_factory = cleanup_timeout_factory
        self.current_stage = RUN_ALL_STAGES[0]
        self.cleanup_authorized = False
        self.cleanup_suppressed_reason: str | None = None
        self.cleanup_attempted = False
        self.cleanup_result: Mapping[str, Any] | None = None
        self.cleanup_error: BaseException | None = None
        self.primary_exit_code = EXIT_OK
        self.live_result: LiveRunResult | None = None
        self.stage_records = {
            name: {"name": name, "status": "pending", "exit_code": None, "summary": {}}
            for name in RUN_ALL_STAGES
        }
        self.document: dict[str, Any] = {
            "schema": 1,
            "kind": "aws-two-region-run-all",
            "run_id": config.run_id,
            "status": "running",
            "exit_code": None,
            "architecture": config.architecture,
            "artifact_manifest": str(config.artifact_manifest),
            "hard_timeout_seconds": hard_timeout_seconds,
            "cleanup_reservation_seconds": DEFAULT_TIMEOUTS.cleanup,
            "evidence": str(self.evidence_path),
            "artifacts": {},
            "stages": [self.stage_records[name] for name in RUN_ALL_STAGES],
            "cleanup": {
                "authorized": False,
                "attempted": False,
                "attempts": 0,
                "status": "pending",
            },
            "failure": None,
            "primary_failure": None,
        }
        self.lifecycle_proxy = _RunAllLifecycleProxy(lifecycle, self._cleanup_once)

    @staticmethod
    def _error_category(error: BaseException) -> str:
        if isinstance(error, _RunAllE2EResultError):
            failure = error.result.evidence.get("failure")
            if isinstance(failure, Mapping) and isinstance(failure.get("category"), str):
                return cast(str, failure["category"])
        return type(error).__name__

    def _artifact_record(self, path: pathlib.Path, *, guaranteed: bool = False) -> dict[str, Any]:
        return {
            "path": str(path),
            "exists": guaranteed or path.is_file() and not path.is_symlink(),
        }

    def _refresh_artifacts(self) -> None:
        self.document["artifacts"] = {
            "run_all_result": self._artifact_record(self.record_path, guaranteed=True),
            "evidence": self._artifact_record(self.evidence_path),
            "diagnostics": self._artifact_record(self.diagnostics_path),
        }
        failure = self.document.get("failure")
        if isinstance(failure, dict):
            artifacts = self._failure_artifacts()
            failure["artifacts"] = artifacts
            stage = failure.get("stage")
            record = self.stage_records.get(stage) if isinstance(stage, str) else None
            if isinstance(record, dict) and isinstance(record.get("summary"), dict):
                record["summary"]["artifacts"] = artifacts

    def _failure_artifacts(self) -> list[dict[str, Any]]:
        artifacts = []
        for kind, path in (("evidence", self.evidence_path), ("diagnostics", self.diagnostics_path)):
            record = self._artifact_record(path)
            if record["exists"]:
                artifacts.append({"kind": kind, **record})
        return artifacts

    def _checkpoint(self) -> None:
        self._refresh_artifacts()
        _write_private_json(self.record_path, cast(Mapping[str, Any], sanitize_evidence_value(self.document)))

    @staticmethod
    def _stage_exit_code(stage: str, error: BaseException) -> int:
        if isinstance(error, _RunAllE2EResultError):
            return error.result.exit_code
        if isinstance(error, (TimeoutError, InterruptedError)):
            return EXIT_ACCEPTANCE_FAILED
        if stage in {RUN_ALL_STAGES[0], RUN_ALL_STAGES[1]}:
            return EXIT_CONTRACT_ERROR
        return EXIT_ACCEPTANCE_FAILED

    def _record_failure(self, stage: str, error: BaseException, exit_code: int) -> None:
        self.document["failure"] = {
            "stage": stage,
            "category": self._error_category(error),
            "message": _sanitize_string(str(error)),
            "exit_code": exit_code,
            "artifacts": self._failure_artifacts(),
        }

    def _stage(self, name: str, operation: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]:
        self.current_stage = name
        record = self.stage_records[name]
        record.update({"status": "running", "exit_code": None, "summary": {}})
        self._checkpoint()
        try:
            value = operation()
            if not isinstance(value, Mapping):
                raise E2EError(f"run-all stage {name} returned a non-object summary")
        except BaseException as error:
            exit_code = self._stage_exit_code(name, error)
            record.update(
                {
                    "status": "failed",
                    "exit_code": exit_code,
                    "summary": {
                        "category": self._error_category(error),
                        "message": _sanitize_string(str(error)),
                        "artifacts": self._failure_artifacts(),
                    },
                }
            )
            self.primary_exit_code = exit_code
            self._record_failure(name, error, exit_code)
            self._checkpoint()
            raise
        record.update({"status": "passed", "exit_code": EXIT_OK, "summary": sanitize_evidence_value(value)})
        self._checkpoint()
        return value

    def _authorize_cleanup(self) -> None:
        self.cleanup_authorized = True
        self.document["cleanup"]["authorized"] = True

    def _suppress_cleanup(self, reason: str) -> None:
        self.cleanup_authorized = False
        self.cleanup_suppressed_reason = reason
        self.document["cleanup"]["authorized"] = False

    def _cleanup_once(self) -> Mapping[str, Any]:
        if not self.cleanup_authorized:
            raise E2EError("run-all cleanup is not authorized before preparation starts")
        if self.cleanup_attempted:
            if self.cleanup_error is not None:
                raise self.cleanup_error
            return self.cleanup_result or {"complete": True}
        self.cleanup_attempted = True
        cleanup_record = self.stage_records[RUN_ALL_STAGES[-1]]
        cleanup_record.update({"status": "running", "exit_code": None, "summary": {"authorized": True}})
        self.document["cleanup"].update({"attempted": True, "attempts": 1, "status": "running"})
        try:
            self._checkpoint()
        except Exception:
            # Stage-record persistence must never prevent the authorized cleanup attempt.
            pass
        try:
            with self.cleanup_timeout_factory(DEFAULT_TIMEOUTS.cleanup):
                value = self.operations.cleanup()
            if not isinstance(value, Mapping):
                raise E2EError("protected cleanup returned a non-object result")
            self.cleanup_result = dict(value)
        except BaseException as error:
            self.cleanup_error = error
            cleanup_record.update(
                {
                    "status": "failed",
                    "exit_code": EXIT_CLEANUP_FAILED,
                    "summary": {"category": type(error).__name__, "message": _sanitize_string(str(error))},
                }
            )
            self.document["cleanup"]["status"] = "failed"
            self._checkpoint()
            raise
        summary = {"authorized": True, "complete": True, **dict(self.cleanup_result)}
        cleanup_record.update({"status": "passed", "exit_code": EXIT_OK, "summary": sanitize_evidence_value(summary)})
        self.document["cleanup"]["status"] = "passed"
        self._checkpoint()
        return summary

    def _run_locked(self) -> RunAllResult:
        primary_error: BaseException | None = None
        self._checkpoint()
        try:
            self._stage(RUN_ALL_STAGES[0], self.operations.build)
            self._stage(RUN_ALL_STAGES[1], self.operations.preflight)
            self._authorize_cleanup()
            self._stage(RUN_ALL_STAGES[2], self.operations.prepare)

            plan_path: pathlib.Path | None = None

            def plan() -> Mapping[str, Any]:
                nonlocal plan_path
                plan_path = self.operations.plan().expanduser().resolve()
                return {"saved_plan": str(plan_path)}

            self._stage(RUN_ALL_STAGES[3], plan)
            assert plan_path is not None
            deployment: Mapping[str, Any] | None = None

            def apply() -> Mapping[str, Any]:
                nonlocal deployment
                deployment = self.operations.apply(plan_path)
                if not isinstance(deployment, Mapping):
                    raise DeploymentError("protected apply returned a non-object deployment")
                digest = hashlib.sha256(
                    json.dumps(deployment, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                ).hexdigest()
                return {"applied_once": True, "deployment_sha256": digest, "saved_plan": str(plan_path)}

            self._stage(RUN_ALL_STAGES[4], apply)
            assert deployment is not None
            self._stage(
                RUN_ALL_STAGES[5],
                lambda: self.operations.wait_ready(deployment, timeout_seconds=self.readiness_timeout_seconds),
            )

            def e2e() -> Mapping[str, Any]:
                result = self.operations.run_e2e(
                    deployment,
                    self.lifecycle_proxy,
                    self.evidence_path,
                    self.budgets,
                )
                if not isinstance(result, LiveRunResult):
                    raise E2EError("full E2E returned an invalid result")
                self.live_result = result
                if result.evidence_path.expanduser().resolve() != self.evidence_path:
                    raise EvidenceError("full E2E wrote outside the run-all evidence path")
                if result.exit_code != EXIT_OK or result.evidence.get("status") != "passed":
                    raise _RunAllE2EResultError(result)
                return {"evidence": str(result.evidence_path), "exit_code": result.exit_code, "status": "passed"}

            self._stage(RUN_ALL_STAGES[6], e2e)
        except BaseException as error:
            primary_error = error
            prepare_rejected = self.current_stage == RUN_ALL_STAGES[2] and isinstance(
                error, (ConcurrentLifecycleError, ConcurrentRunError)
            )
            inner_ownership_blocked = isinstance(
                error, _RunAllE2EResultError
            ) and _is_inner_ownership_block(error.result, run_id=self.config.run_id)
            if prepare_rejected:
                self._suppress_cleanup("concurrent lifecycle ownership was rejected before this process acquired a claim")
            elif inner_ownership_blocked:
                self._suppress_cleanup("inner evidence proved competing or ambiguous durable E2E ownership")
            if self.document["failure"] is None:
                self.primary_exit_code = self._stage_exit_code(self.current_stage, error)
                self._record_failure(self.current_stage, error, self.primary_exit_code)
        finally:
            if self.cleanup_authorized and not self.cleanup_attempted:
                try:
                    self._cleanup_once()
                except BaseException:
                    pass
            elif not self.cleanup_authorized:
                reason = self.cleanup_suppressed_reason or "preparation never started; cleanup not authorized"
                cleanup_record = self.stage_records[RUN_ALL_STAGES[-1]]
                cleanup_record.update(
                    {
                        "status": "skipped",
                        "exit_code": None,
                        "summary": {"reason": reason},
                    }
                )
                self.document["cleanup"]["status"] = "skipped"
                if self.cleanup_suppressed_reason is not None:
                    self.document["cleanup"]["reason"] = reason

        for record in self.document["stages"]:
            if record["status"] == "pending":
                record.update(
                    {
                        "status": "skipped",
                        "exit_code": None,
                        "summary": {"reason": "prior stage failed closed"},
                    }
                )
        if self.cleanup_error is not None:
            if self.document["failure"] is not None:
                self.document["primary_failure"] = self.document["failure"]
            self._record_failure(RUN_ALL_STAGES[-1], self.cleanup_error, EXIT_CLEANUP_FAILED)
            exit_code = EXIT_CLEANUP_FAILED
        elif primary_error is not None:
            exit_code = self.primary_exit_code
        else:
            exit_code = EXIT_OK
        self.document["exit_code"] = exit_code
        self.document["status"] = "passed" if exit_code == EXIT_OK else "failed"
        if exit_code == EXIT_OK:
            self.document["failure"] = None
        self._checkpoint()
        return RunAllResult(exit_code, self.record_path, self.evidence_path, sanitize_evidence_value(self.document))

    def run(self) -> RunAllResult:
        with self.lock_factory(self.run_dir):
            with self.timeout_factory(self.active_timeout_seconds):
                return self._run_locked()


class AwsRunAllOperations:
    """Direct composition of the existing protected lifecycle APIs for run-all."""

    def __init__(
        self,
        config: RunConfig,
        aws: AwsCLI,
        runner: SubprocessRunner,
        run_dir: pathlib.Path,
        terraform_dir: pathlib.Path,
        lifecycle: ProtectedLifecycleAdapter,
    ):
        self.config = config
        self.aws = aws
        self.runner = runner
        self.run_dir = run_dir.expanduser().resolve()
        self.terraform_dir = terraform_dir.expanduser().resolve()
        self.lifecycle = lifecycle
        self._tailscale: Any = None

    def tailscale(self) -> Any:
        if self._tailscale is None:
            self._tailscale = build_tailscale(self.config)
        return self._tailscale

    def build(self) -> Mapping[str, Any]:
        output_dir = self.config.artifact_manifest.parent.resolve()
        if self.config.artifact_manifest != output_dir / "manifest.json":
            raise E2EError("artifact_manifest must be the build output directory's manifest.json")
        repository = pathlib.Path(__file__).resolve().parents[1]
        script = repository / "scripts" / "build_artifacts.sh"
        command = [
            str(script),
            "--output-dir",
            str(output_dir),
            "--architectures",
            self.config.architecture,
        ]
        self.runner.run(command, cwd=repository)
        artifact_path = output_dir / f"envelope-linux-{self.config.architecture}"
        if not self.config.artifact_manifest.is_file() or not artifact_path.is_file():
            raise E2EError("artifact build did not produce the exact configured manifest and selected binary")
        return {
            "architecture": self.config.architecture,
            "artifact": str(artifact_path),
            "manifest": str(self.config.artifact_manifest),
            "allow_dirty": False,
        }

    def preflight(self) -> Mapping[str, Any]:
        artifact, account_id = run_preflight(self.config, self.aws, self.tailscale())
        return {
            "account_id": account_id,
            "architecture": artifact.get("architecture"),
            "artifact_sha256": artifact.get("sha256"),
            "manifest": artifact.get("manifest_path"),
            "read_only": True,
        }

    def prepare(self) -> Mapping[str, Any]:
        manifest = protected_prepare(self.config, self.aws, self.tailscale(), self.run_dir)
        if manifest.get("phase") != "prepared":
            raise LifecycleError("protected preparation did not reach its durable prepared phase")
        return {"manifest_phase": "prepared", "published": True}

    def plan(self) -> pathlib.Path:
        return terraform_plan(
            self.config,
            self.aws,
            self.runner,
            self.run_dir,
            self.terraform_dir,
        )

    def apply(self, plan_path: pathlib.Path) -> Mapping[str, Any]:
        return terraform_apply(
            self.config,
            self.aws,
            self.runner,
            self.run_dir,
            self.terraform_dir,
            plan_path,
            tailscale_factory=self.tailscale,
        )

    def wait_ready(self, deployment: Mapping[str, Any], *, timeout_seconds: int) -> Mapping[str, Any]:
        wait_and_record(
            self.config,
            self.aws,
            self.tailscale(),
            self.run_dir,
            dict(deployment),
            timeout_seconds=timeout_seconds,
        )
        manifest = ManifestStore(self.config, self.aws, self.run_dir).recover()
        if manifest.get("phase") != "ready" or manifest.get("deployment") != deployment:
            raise LifecycleError("protected readiness did not persist the exact deployment in durable ready phase")
        return {"deployment_matches": True, "manifest_phase": "ready"}

    def run_e2e(
        self,
        deployment: Mapping[str, Any],
        lifecycle: ProtectedLifecycleAPI,
        evidence_path: pathlib.Path,
        budgets: TimeoutBudgets,
    ) -> LiveRunResult:
        runner = TwoRegionE2ERunner(
            run_id=self.config.run_id,
            raw_deployment=deployment,
            site_regions={site: self.config.sites[site]["region"] for site in SITES},
            lifecycle=lifecycle,
            operations=AwsLiveOperations(self.config, self.aws, self.run_dir),
            evidence_path=evidence_path,
            budgets=budgets,
        )
        return runner.run()

    def cleanup(self) -> Mapping[str, Any]:
        return self.lifecycle.cleanup()


def _load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise E2EError(f"cannot read JSON {path}: {error}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    validate_parser = subparsers.add_parser("validate-evidence", help="validate a schema-1 core or schema-2 live file")
    validate_parser.add_argument("path", type=pathlib.Path)

    verify_parser = subparsers.add_parser(
        "verify-evidence", help="strictly verify a complete passing schema-2 live evidence bundle"
    )
    verify_parser.add_argument("path", type=pathlib.Path)

    scan_parser = subparsers.add_parser("scan-evidence", help="scan a JSON file for prohibited evidence material")
    scan_parser.add_argument("path", type=pathlib.Path)

    deployment_parser = subparsers.add_parser("parse-deployment", help="validate nested Terraform workload output")
    deployment_parser.add_argument("path", type=pathlib.Path)
    deployment_parser.add_argument("--output-name", default="workload_instances")

    protected_parser = subparsers.add_parser(
        "parse-protected-deployment", help="validate all required protected live deployment outputs"
    )
    protected_parser.add_argument("path", type=pathlib.Path)
    protected_parser.add_argument("--west-region")
    protected_parser.add_argument("--east-region")

    all_parser = subparsers.add_parser(
        "run-all", help="build, provision, test, record evidence, and clean up one protected deployment"
    )
    all_parser.add_argument("--config", type=pathlib.Path, required=True)
    all_parser.add_argument("--run-root", type=pathlib.Path, default=pathlib.Path(".run"))
    all_parser.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    all_parser.add_argument("--evidence", type=pathlib.Path)
    all_parser.add_argument("--hard-timeout-seconds", type=int, default=RUN_ALL_HARD_TIMEOUT_SECONDS)
    all_parser.add_argument("--readiness-timeout-seconds", type=int, default=900)

    live_parser = subparsers.add_parser(
        "run-live", help="resume/recover acceptance from an already-ready protected deployment, then clean up"
    )
    live_parser.add_argument("--config", type=pathlib.Path, required=True)
    live_parser.add_argument("--deployment", type=pathlib.Path, required=True)
    live_parser.add_argument("--run-root", type=pathlib.Path, default=pathlib.Path(".run"))
    live_parser.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    live_parser.add_argument("--evidence", type=pathlib.Path)
    live_parser.add_argument("--hard-timeout-seconds", type=int, default=DEFAULT_TIMEOUTS.hard_timeout)
    return parser


def _authorized_run_all_id(environment: Mapping[str, str]) -> str:
    approved = environment.get("ENVELOPE_E2E_APPROVED_RUN_ID")
    if not isinstance(approved, str) or _RUN_ID_RE.fullmatch(approved) is None:
        raise E2EError("run-all requires one path-safe ENVELOPE_E2E_APPROVED_RUN_ID")
    validate_protected_execution(approved, environment)
    return approved


def _run_all_bootstrap_record(run_id: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "aws-two-region-run-all",
        "run_id": run_id,
        "status": "initializing",
        "exit_code": None,
        "bootstrap": True,
        "resource_authority": False,
        "cleanup": {
            "authorized": False,
            "attempted": False,
            "attempts": 0,
            "status": "pending",
        },
        "failure": None,
    }


def _write_run_all_bootstrap_failure(
    path: pathlib.Path,
    record: dict[str, Any],
    *,
    gate: str,
    error: BaseException,
) -> None:
    record["status"] = "failed"
    record["exit_code"] = EXIT_CONTRACT_ERROR
    record["cleanup"]["status"] = "skipped"
    category = type(error).__name__
    record["failure"] = {
        "gate": gate,
        "category": category if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", category) else "Error",
        "exit_code": EXIT_CONTRACT_ERROR,
    }
    _write_private_json(path, record)


def _run_all_cli(args: argparse.Namespace) -> int:
    approved_run_id = _authorized_run_all_id(os.environ)
    run_root = args.run_root.expanduser().resolve()
    run_dir = run_directory(run_root, approved_run_id).expanduser().resolve()
    if run_dir.parent != run_root:
        raise E2EError("approved run ID did not resolve directly inside the protected run root")
    record_path = run_dir / "run-all-result.json"
    bootstrap_record = _run_all_bootstrap_record(approved_run_id)
    _write_private_json(record_path, bootstrap_record)
    gate = "config-load"
    try:
        config = RunConfig.load(args.config, enforce_future_expiry=False)
        gate = "run-id-match"
        if config.run_id != approved_run_id:
            raise E2EError("protected config run_id does not exactly match the approved run ID")
        gate = "timeout-arguments"
        if (
            isinstance(args.hard_timeout_seconds, bool)
            or not isinstance(args.hard_timeout_seconds, int)
            or not 1 <= args.hard_timeout_seconds <= 7200 - DEFAULT_TIMEOUTS.cleanup
        ):
            raise E2EError("--hard-timeout-seconds plus cleanup reservation must be no greater than 7200")
        if (
            isinstance(args.readiness_timeout_seconds, bool)
            or not isinstance(args.readiness_timeout_seconds, int)
            or not 1 <= args.readiness_timeout_seconds <= args.hard_timeout_seconds
        ):
            raise E2EError("--readiness-timeout-seconds must fit inside the hard-timeout window")
        gate = "ttl"
        expiry = dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00"))
        total_timeout = args.hard_timeout_seconds + DEFAULT_TIMEOUTS.cleanup
        if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=total_timeout):
            raise E2EError("protected run TTL does not reserve the complete run-all and cleanup hard timeout")
        gate = "evidence-path"
        evidence_path = (
            run_dir / "aws-two-region-e2e-evidence.json"
            if args.evidence is None
            else args.evidence.expanduser().resolve()
        )
        if evidence_path.parent != run_dir:
            raise EvidenceError("run-all evidence must remain directly inside the protected run directory")
        gate = "coordinator-construction"
        subprocess_runner = SubprocessRunner(config.oauth_environment_names)
        aws = AwsCLI(subprocess_runner, config.oauth_environment_names)
        lifecycle = ProtectedLifecycleAdapter(config, aws, subprocess_runner, run_dir, args.terraform_dir)
        operations = AwsRunAllOperations(
            config,
            aws,
            subprocess_runner,
            run_dir,
            args.terraform_dir,
            lifecycle,
        )
        coordinator = RunAllCoordinator(
            config=config,
            run_dir=run_dir,
            evidence_path=evidence_path,
            lifecycle=lifecycle,
            operations=operations,
            hard_timeout_seconds=args.hard_timeout_seconds,
            readiness_timeout_seconds=args.readiness_timeout_seconds,
        )
    except Exception as error:
        _write_run_all_bootstrap_failure(record_path, bootstrap_record, gate=gate, error=error)
        if isinstance(error, (LifecycleError, OSError)):
            raise
        raise E2EError(f"run-all bootstrap validation failed at {gate}") from None
    result = coordinator.run()
    print(
        json.dumps(
            {
                "cleanup": result.record["cleanup"],
                "evidence": str(result.evidence_path),
                "exit_code": result.exit_code,
                "record": str(result.record_path),
                "run_id": config.run_id,
                "stages": result.record["stages"],
                "status": result.record["status"],
            },
            sort_keys=True,
        )
    )
    return result.exit_code


def _live_cli(args: argparse.Namespace) -> int:
    config = RunConfig.load(args.config, enforce_future_expiry=False)
    validate_protected_execution(config.run_id, os.environ)
    if not 1 <= args.hard_timeout_seconds <= 7200 - DEFAULT_TIMEOUTS.cleanup:
        raise E2EError("--hard-timeout-seconds must leave the protected cleanup timeout reservation")
    expiry = dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00"))
    total_timeout = args.hard_timeout_seconds + DEFAULT_TIMEOUTS.cleanup
    if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=total_timeout):
        raise E2EError("protected run TTL does not reserve both acceptance and cleanup timeout budgets")
    raw = _load_json(args.deployment.expanduser().resolve())
    if not isinstance(raw, Mapping):
        raise DeploymentError("protected deployment file must contain a JSON object")
    subprocess_runner = SubprocessRunner(config.oauth_environment_names)
    aws = AwsCLI(subprocess_runner, config.oauth_environment_names)
    run_dir = run_directory(args.run_root, config.run_id).expanduser().resolve()
    evidence_path = (
        run_dir / "aws-two-region-e2e-evidence.json"
        if args.evidence is None
        else args.evidence.expanduser().resolve()
    )
    if evidence_path.parent != run_dir:
        raise EvidenceError("live evidence must remain directly inside the protected run directory")
    budgets = dataclasses.replace(DEFAULT_TIMEOUTS, hard_timeout=args.hard_timeout_seconds)
    lifecycle = ProtectedLifecycleAdapter(config, aws, subprocess_runner, run_dir, args.terraform_dir)
    bounded_lifecycle = _BoundedCleanupLifecycleProxy(lifecycle)
    operations = AwsLiveOperations(config, aws, run_dir)
    runner = TwoRegionE2ERunner(
        run_id=config.run_id,
        raw_deployment=cast(Mapping[str, Any], raw),
        site_regions={site: config.sites[site]["region"] for site in SITES},
        lifecycle=bounded_lifecycle,
        operations=operations,
        evidence_path=evidence_path,
        budgets=budgets,
    )
    with lifecycle_lock(run_dir), hard_timeout(budgets.hard_timeout, operation="live E2E acceptance"):
        result = runner.run()
    print(
        json.dumps(
            {
                "evidence": str(result.evidence_path),
                "exit_code": result.exit_code,
                "run_id": config.run_id,
                "status": result.evidence["status"],
            },
            sort_keys=True,
        )
    )
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.subcommand == "validate-evidence":
            document = load_evidence(args.path)
            print(
                json.dumps(
                    {"kind": document.get("kind", "core"), "schema": document["schema"], "valid": True},
                    sort_keys=True,
                )
            )
            return 0
        if args.subcommand == "verify-evidence":
            document = verify_live_evidence(_load_json(args.path))
            print(
                json.dumps(
                    {"kind": document["kind"], "run_id": document["run_id"], "verified": True},
                    sort_keys=True,
                )
            )
            return 0
        if args.subcommand == "scan-evidence":
            findings = scan_evidence(_load_json(args.path))
            print(json.dumps({"findings": findings, "safe": not findings}, sort_keys=True))
            return 0 if not findings else 1
        if args.subcommand == "parse-deployment":
            deployment = parse_deployment_output(_load_json(args.path), output_name=args.output_name)
            print(json.dumps(deployment.as_dict(), sort_keys=True))
            return 0
        if args.subcommand == "parse-protected-deployment":
            regions = None
            if args.west_region is not None or args.east_region is not None:
                if args.west_region is None or args.east_region is None:
                    raise DeploymentError("both --west-region and --east-region are required together")
                regions = {"west": args.west_region, "east": args.east_region}
            deployment = parse_protected_deployment_output(_load_json(args.path), site_regions=regions)
            print(json.dumps(deployment.as_dict(), sort_keys=True))
            return 0
        if args.subcommand == "run-all":
            return _run_all_cli(args)
        if args.subcommand == "run-live":
            return _live_cli(args)
        raise E2EError(f"unknown subcommand: {args.subcommand}")
    except EvidenceVerificationError as error:
        print(redact_runtime_text(str(error)), file=sys.stderr)
        return EXIT_ACCEPTANCE_FAILED
    except (LifecycleError, OSError) as error:
        print(redact_runtime_text(str(error)), file=sys.stderr)
        return EXIT_CONTRACT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
