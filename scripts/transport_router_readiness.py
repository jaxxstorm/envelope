#!/usr/bin/env python3
"""Validate a bidirectional transport router from bounded, sanitized inputs.

The fixtures contain only normalized Tailscale observations, complete relevant
host-route state, exact firewall chains, EC2 identity, and VPC routes. Peer key
expiry and peer-bound ping timestamps are compared with status.CheckedAt.
Collecting these fields is intentionally outside this credential-free checker;
the protected E2E collector must mirror this exact sanitized schema.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
import sys
from typing import Any, Mapping, Sequence


MAX_INPUT_BYTES = 1024 * 1024
MAX_TCP_MSS = 1240
MAX_PING_AGE_SECONDS = 30
MAX_PING_LATENCY_MILLISECONDS = 5000
POLICY_PRIORITY_BASE = 100
_ENI_ID_RE = re.compile(r"eni-[0-9a-f]{8,17}")
_SUBNET_ID_RE = re.compile(r"subnet-[0-9a-f]{8,17}")
_ROUTE_TABLE_ID_RE = re.compile(r"rtb-[0-9a-f]{8,17}")
_GWLBE_ID_RE = re.compile(r"vpce-[0-9a-f]{8,17}")
_AZ_RE = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d+[a-z]")
_PEER_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FORWARD_CHAIN = "ENVELOPE-TRANSPORT-FORWARD"
_MSS_CHAIN = "ENVELOPE-TRANSPORT-MSS"
_ROUTE_TARGET_FIELDS = {
    "CarrierGatewayId",
    "CoreNetworkArn",
    "EgressOnlyInternetGatewayId",
    "GatewayId",
    "InstanceId",
    "LocalGatewayId",
    "NatGatewayId",
    "NetworkInterfaceId",
    "TransitGatewayId",
    "VpcEndpointId",
    "VpcPeeringConnectionId",
}


def build_readiness_contract(
    local_site_cidrs: Sequence[str],
    remote_site_cidrs: Sequence[str],
    underlay_interface: str,
    tailscale_interface: str,
    approved_maximum_tcp_mss: int,
    config_version: int = 2,
) -> dict[str, Any]:
    """Build an exact contract; production callers explicitly select version 3."""

    if isinstance(config_version, bool) or config_version not in (2, 3):
        raise ValueError("transport-router contract version must be 2 or 3")
    local_cidrs = sorted(local_site_cidrs)
    remote_cidrs = sorted(remote_site_cidrs)
    local_policy_input = tailscale_interface if config_version == 2 else "all"
    local_policy_rules = [
        {
            "priority": POLICY_PRIORITY_BASE + index,
            "input": local_policy_input,
            "source": "all",
            "destination": cidr,
            "fwmark": 0,
            "table": "main",
            "action": "lookup",
        }
        for index, cidr in enumerate(local_cidrs)
    ]
    ipv4_policy_rules = [
        {
            "priority": 0,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 0,
            "fwmask": 0,
            "table": "local",
            "action": "lookup",
        },
        *[{**rule, "fwmask": 0} for rule in local_policy_rules],
        *[
            {
                "priority": priority,
                "input": "all",
                "source": "all",
                "destination": "all",
                "fwmark": fwmark,
                "fwmask": fwmask,
                "table": table,
                "action": action,
            }
            for priority, fwmark, fwmask, table, action in (
                (5210, 524288, 16711680, "main", "lookup"),
                (5230, 524288, 16711680, "default", "lookup"),
                (5250, 524288, 16711680, "none", "unreachable"),
                (5270, 0, 0, "52", "lookup"),
                (32766, 0, 0, "main", "lookup"),
                (32767, 0, 0, "default", "lookup"),
            )
        ],
    ]
    forward_rules: list[dict[str, Any]] = []
    mss_rules: list[dict[str, Any]] = []
    for local_cidr in local_cidrs:
        for remote_cidr in remote_cidrs:
            for input_interface, output_interface, source, destination in (
                (
                    underlay_interface,
                    tailscale_interface,
                    local_cidr,
                    remote_cidr,
                ),
                (
                    tailscale_interface,
                    underlay_interface,
                    remote_cidr,
                    local_cidr,
                ),
            ):
                forward_rules.append(
                    {
                        "chain": _FORWARD_CHAIN,
                        "input": input_interface,
                        "output": output_interface,
                        "source": source,
                        "destination": destination,
                        "action": "ACCEPT",
                    }
                )
                mss_rules.append(
                    {
                        "chain": _MSS_CHAIN,
                        "input": input_interface,
                        "output": output_interface,
                        "source": source,
                        "destination": destination,
                        "protocol": "tcp",
                        "tcp_flags": "SYN,RST SYN",
                        "action": "TCPMSS",
                    }
                )
    return {
        "config_version": config_version,
        "local_site_cidrs": local_cidrs,
        "remote_site_cidrs": remote_cidrs,
        "underlay_interface": underlay_interface,
        "tailscale_interface": tailscale_interface,
        "approved_maximum_tcp_mss": approved_maximum_tcp_mss,
        "ipv4_forwarding": True,
        "ipv6_forwarding": False,
        "filter_forward_policy": "DROP",
        "mangle_forward_policy": "ACCEPT",
        "filter_forward_rules": [
            {"chain": "FORWARD", "action": "JUMP", "target": _FORWARD_CHAIN}
        ],
        "mangle_forward_rules": [
            {"chain": "FORWARD", "action": "JUMP", "target": _MSS_CHAIN}
        ],
        "mss_terminal_rules": [{"chain": _MSS_CHAIN, "action": "RETURN"}],
        "nat_rules": [],
        "ipv6_filter_forward_policy": "DROP",
        "ipv6_mangle_forward_policy": "ACCEPT",
        "ipv6_filter_forward_rules": [
            {"chain": "FORWARD", "action": "JUMP", "target": _FORWARD_CHAIN}
        ],
        "ipv6_forward_rules": [],
        "ipv6_mangle_forward_rules": [],
        "readiness_marker": "/var/lib/envelope/transport-router-network.ready",
        "runtime_state": "/var/lib/envelope/transport-router-network.state.json",
        "recovery_marker": "/var/lib/envelope/transport-router-network.configured",
        "mss_formula": (
            "min(min(underlay_mtu,tailscale_mtu)-40,approved_maximum_tcp_mss)"
        ),
        "policy_rule_priority_base": POLICY_PRIORITY_BASE,
        "local_route_table": "main",
        "remote_route_table": 52,
        "local_policy_rules": local_policy_rules,
        "ipv4_policy_rules": ipv4_policy_rules,
        "forward_rules": forward_rules,
        "mss_rules": mss_rules,
    }


def readiness_contract_sha256(contract: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        contract, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ReadinessError(ValueError):
    """The transport router cannot safely carry bidirectional site traffic."""


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReadinessError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReadinessError(f"{field} must be a canonical UTC timestamp") from error
    if parsed.tzinfo != dt.timezone.utc or parsed.microsecond:
        raise ReadinessError(f"{field} must be a canonical UTC timestamp")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ReadinessError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _networks(
    values: Any, field: str
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not isinstance(values, list) or not values:
        raise ReadinessError(f"{field} must be a non-empty CIDR list")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ReadinessError(f"{field} contains a non-string CIDR")
        try:
            result.append(ipaddress.ip_network(value, strict=True))
        except ValueError as error:
            raise ReadinessError(f"{field} contains an invalid CIDR: {value!r}") from error
    if len(set(result)) != len(result):
        raise ReadinessError(f"{field} contains duplicate CIDRs")
    return tuple(result)


def _validated_readiness_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReadinessError("readiness contract must be an object")
    local = _networks(value.get("local_site_cidrs"), "contract local-site CIDRs")
    remote = _networks(value.get("remote_site_cidrs"), "contract remote-site CIDRs")
    if any(not isinstance(network, ipaddress.IPv4Network) for network in (*local, *remote)):
        raise ReadinessError("readiness contract site CIDRs must be IPv4 networks")
    underlay = value.get("underlay_interface")
    tailscale = value.get("tailscale_interface")
    maximum_mss = value.get("approved_maximum_tcp_mss")
    config_version = value.get("config_version")
    if isinstance(config_version, bool) or config_version not in (2, 3):
        raise ReadinessError("readiness contract version must be 2 or 3")
    if (
        not isinstance(underlay, str)
        or not isinstance(tailscale, str)
        or not underlay
        or not tailscale
        or underlay == tailscale
        or {underlay, tailscale} & {"all", "default", "lo", "envelope0"}
    ):
        raise ReadinessError("readiness contract interface identities are invalid")
    if (
        isinstance(maximum_mss, bool)
        or not isinstance(maximum_mss, int)
        or not 536 <= maximum_mss <= MAX_TCP_MSS
    ):
        raise ReadinessError("readiness contract MSS ceiling is invalid")
    expected = build_readiness_contract(
        [str(network) for network in local],
        [str(network) for network in remote],
        underlay,
        tailscale,
        maximum_mss,
        config_version,
    )
    expected_keys = set(expected) | {"contract_sha256"}
    actual_contract = {key: value[key] for key in expected if key in value}
    canonical_actual = json.dumps(
        actual_contract, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    canonical_expected = json.dumps(
        expected, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if (
        set(value) != expected_keys
        or canonical_actual != canonical_expected
        or value.get("contract_sha256") != readiness_contract_sha256(expected)
    ):
        raise ReadinessError("readiness contract differs from the exact expanded contract")
    return {**expected, "contract_sha256": value["contract_sha256"]}


def _status_routes(
    status: Mapping[str, Any], field: str
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    self_status = status.get("Self")
    if not isinstance(self_status, Mapping):
        raise ReadinessError("status.Self must be an object")
    return _networks(self_status.get(field), f"status.Self.{field}")


def _verify_route_peers(
    status: Mapping[str, Any],
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    checked_at: dt.datetime,
    expected_peer_ids: Mapping[str, str] | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    self_status = status.get("Self")
    assert isinstance(self_status, Mapping)
    raw_peers = self_status.get("RoutePeers")
    if not isinstance(raw_peers, list):
        raise ReadinessError("status.Self.RoutePeers must be a list")
    if expected_peer_ids is not None and (
        not isinstance(expected_peer_ids, Mapping)
        or set(expected_peer_ids) != {str(prefix) for prefix in prefixes}
        or any(
            not isinstance(peer_id, str) or not _PEER_ID_RE.fullmatch(peer_id)
            for peer_id in expected_peer_ids.values()
        )
    ):
        raise ReadinessError(
            "configured remote-prefix owners must exactly map every approved prefix"
        )

    observed: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, str] = {}
    summaries: list[dict[str, Any]] = []
    for peer in raw_peers:
        if not isinstance(peer, Mapping) or set(peer) != {
            "Prefix",
            "PeerID",
            "Online",
            "Expired",
            "KeyExpiry",
            "KeyExpiryDisabled",
            "Ping",
        }:
            raise ReadinessError("route-serving peer has the wrong shape")
        networks = _networks([peer["Prefix"]], "route-serving peer prefix")
        prefix = networks[0]
        if prefix not in prefixes:
            raise ReadinessError(f"route-serving peer has an unapproved prefix: {prefix}")
        if prefix in observed:
            raise ReadinessError(f"{prefix} has ambiguous route-serving peers")
        peer_id = peer.get("PeerID")
        if not isinstance(peer_id, str) or not _PEER_ID_RE.fullmatch(peer_id):
            raise ReadinessError("route-serving peer identity is invalid")
        if (
            expected_peer_ids is not None
            and expected_peer_ids.get(str(prefix)) != peer_id
        ):
            raise ReadinessError(
                f"{prefix} is not served by its configured stable owner"
            )
        if peer.get("Online") is not True or peer.get("Expired") is not False:
            raise ReadinessError(f"route-serving peer {peer_id} is offline or expired")
        key_expiry = _timestamp(peer.get("KeyExpiry"), "route-serving peer KeyExpiry")
        key_expiry_disabled = peer.get("KeyExpiryDisabled")
        if not isinstance(key_expiry_disabled, bool):
            raise ReadinessError(
                f"route-serving peer {peer_id} key-expiry mode is invalid"
            )
        if not key_expiry_disabled and key_expiry <= checked_at:
            raise ReadinessError(f"route-serving peer {peer_id} key is expired")
        ping = peer.get("Ping")
        if not isinstance(ping, Mapping) or set(ping) != {
            "PeerID",
            "Succeeded",
            "ObservedAt",
            "LatencyMilliseconds",
        }:
            raise ReadinessError("route-serving peer ping has the wrong shape")
        latency = ping.get("LatencyMilliseconds")
        ping_at = _timestamp(ping.get("ObservedAt"), "route-serving peer ping ObservedAt")
        if (
            ping.get("PeerID") != peer_id
            or ping.get("Succeeded") is not True
            or isinstance(latency, bool)
            or not isinstance(latency, (int, float))
            or not 0 <= latency <= MAX_PING_LATENCY_MILLISECONDS
            or ping_at > checked_at
            or (checked_at - ping_at).total_seconds() > MAX_PING_AGE_SECONDS
        ):
            raise ReadinessError(f"route-serving peer {peer_id} failed its bounded data-plane ping")
        observed[prefix] = peer_id
        summaries.append(
            {
                "prefix": str(prefix),
                "peer_id": peer_id,
                "key_expiry": peer["KeyExpiry"],
                "key_expiry_disabled": key_expiry_disabled,
                "ping_observed_at": ping["ObservedAt"],
                "ping_latency_milliseconds": latency,
            }
        )

    missing = set(prefixes) - set(observed)
    if missing:
        raise ReadinessError(
            "remote prefixes lack a ready route-serving peer: "
            + ", ".join(sorted(str(prefix) for prefix in missing))
        )
    return len(set(observed.values())), summaries


def _routes(value: Any) -> tuple[Mapping[str, Any], ...]:
    routes = value.get("Routes") if isinstance(value, Mapping) else value
    if not isinstance(routes, list):
        raise ReadinessError("VPC routes must be a list or an object with Routes")
    result = []
    for route in routes:
        if not isinstance(route, Mapping):
            raise ReadinessError("VPC routes contain a non-object entry")
        result.append(route)
    return tuple(result)


def _route_network(route: Mapping[str, Any]) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    destination = route.get("DestinationCidrBlock")
    if not isinstance(destination, str):
        return None
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError as error:
        raise ReadinessError(f"VPC route has an invalid destination CIDR: {destination!r}") from error


def _host_route_network(
    route: Mapping[str, Any], field: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    destination = route.get("dst", "default")
    if destination == "default":
        return ipaddress.ip_network("0.0.0.0/0")
    if not isinstance(destination, str):
        raise ReadinessError(f"{field} route has a non-string destination")
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError as error:
        raise ReadinessError(f"{field} route has an invalid destination: {destination!r}") from error


def _host_routes(value: Any, field: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not all(isinstance(route, Mapping) for route in value):
        raise ReadinessError(f"{field} must be a route-object list")
    return tuple(value)


def _prefix_probe_addresses(
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> list[str]:
    offsets = {0, prefix.num_addresses // 2, prefix.num_addresses - 1}
    return [str(prefix.network_address + offset) for offset in sorted(offsets)]


def _verify_host_route_domain(
    routes_value: Any,
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    expected_device: str,
    field: str,
    *,
    exact: bool,
) -> list[dict[str, Any]]:
    parsed = [
        (route, _host_route_network(route, field))
        for route in _host_routes(routes_value, field)
    ]
    for route, network in parsed:
        if route.get("from") not in (None, "all") or route.get("src") not in (None, ""):
            if any(network.overlaps(prefix) for prefix in prefixes if network.version == prefix.version):
                raise ReadinessError(f"{field} contains a source-specific route for an approved prefix")

    summary: list[dict[str, Any]] = []
    for prefix in prefixes:
        intersections = [
            (route, network)
            for route, network in parsed
            if network.version == prefix.version and network.overlaps(prefix)
        ]
        if exact:
            if len(intersections) != 1 or intersections[0][1] != prefix:
                raise ReadinessError(
                    f"{prefix} does not have one isolated exact {field} route"
                )
            winner, owner = intersections[0]
            if (
                winner.get("from") not in (None, "all")
                or winner.get("src") not in (None, "")
            ):
                raise ReadinessError(
                    f"{field} contains a source-specific route for an approved prefix"
                )
            if winner.get("dev") != expected_device or winner.get("type", "unicast") != "unicast":
                raise ReadinessError(f"{prefix} {field} route does not select {expected_device}")
            summary.append(
                {
                    "prefix": str(prefix),
                    "owner": str(owner),
                    "device": expected_device,
                    "checked_addresses": _prefix_probe_addresses(prefix),
                }
            )
            continue
        owners = [
            (route, network)
            for route, network in parsed
            if network.version == prefix.version
            and (network == prefix if exact else prefix.subnet_of(network))
        ]
        if not owners:
            qualifier = "exact " if exact else ""
            raise ReadinessError(f"{prefix} has no {qualifier}{field} route")
        longest = max(network.prefixlen for _route, network in owners)
        winners = [(route, network) for route, network in owners if network.prefixlen == longest]
        if len(winners) != 1:
            raise ReadinessError(f"{prefix} has ambiguous {field} route ownership")
        winner, owner = winners[0]
        if winner.get("dev") != expected_device or winner.get("type", "unicast") != "unicast":
            raise ReadinessError(f"{prefix} {field} route does not select {expected_device}")
        bypasses = [
            str(network)
            for route, network in parsed
            if network.version == prefix.version
            and network != prefix
            and network.subnet_of(prefix)
            and (route.get("dev") != expected_device or route.get("type", "unicast") != "unicast")
        ]
        if bypasses:
            raise ReadinessError(
                f"{prefix} has a more-specific {field} route bypass: {', '.join(sorted(bypasses))}"
            )
        for address in _prefix_probe_addresses(prefix):
            parsed_address = ipaddress.ip_address(address)
            candidates = [
                (route, network)
                for route, network in parsed
                if network.version == parsed_address.version
                and parsed_address in network
            ]
            if not candidates:
                raise ReadinessError(
                    f"{prefix} interior address {address} has no {field} route"
                )
            longest = max(network.prefixlen for _route, network in candidates)
            address_winners = [
                route for route, network in candidates if network.prefixlen == longest
            ]
            if (
                len(address_winners) != 1
                or address_winners[0].get("dev") != expected_device
                or address_winners[0].get("type", "unicast") != "unicast"
            ):
                raise ReadinessError(
                    f"{prefix} interior address {address} does not select {expected_device}"
                )
        summary.append(
            {
                "prefix": str(prefix),
                "owner": str(owner),
                "device": expected_device,
                "checked_addresses": _prefix_probe_addresses(prefix),
            }
        )
    return summary


def _reject_host_route_intersections(
    routes_value: Any,
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    field: str,
) -> None:
    parsed = [
        (route, _host_route_network(route, field))
        for route in _host_routes(routes_value, field)
    ]
    intersections = {
        str(network)
        for _route, network in parsed
        if any(
            network.version == prefix.version and network.overlaps(prefix)
            for prefix in prefixes
        )
    }
    if intersections:
        raise ReadinessError(
            f"{field} intersects protected local prefixes: "
            + ", ".join(sorted(intersections))
        )


def _verify_shadowed_local_table52_routes(
    routes_value: Any,
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    tailscale_interface: str,
) -> list[dict[str, Any]]:
    parsed = [
        (route, _host_route_network(route, "table-52 local"))
        for route in _host_routes(routes_value, "table-52 local")
    ]
    protected = set(prefixes)
    observed: dict[
        ipaddress.IPv4Network | ipaddress.IPv6Network, Mapping[str, Any]
    ] = {}
    for route, network in parsed:
        if not any(
            network.version == prefix.version and network.overlaps(prefix)
            for prefix in prefixes
        ):
            continue
        if (
            network not in protected
            or network in observed
            or route.get("from") not in (None, "all")
            or route.get("src") not in (None, "")
            or route.get("dev") != tailscale_interface
            or route.get("type", "unicast") != "unicast"
        ):
            raise ReadinessError(
                "table-52 local overlap is not an exact safely shadowed Tailscale route"
            )
        observed[network] = route
    return [
        {
            "prefix": str(prefix),
            "device": tailscale_interface,
            "shadowed_by": "destination-only-main-policy",
            "checked_addresses": _prefix_probe_addresses(prefix),
        }
        for prefix in prefixes
        if prefix in observed
    ]


def _verify_firewall(
    transport: Mapping[str, Any],
    underlay_interface: str,
    tailscale_interface: str,
    local_prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    remote_prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    approved_maximum_tcp_mss: int,
) -> tuple[int, int]:
    expected_prefix_directions = {
        (underlay_interface, tailscale_interface, str(local), str(remote))
        for local in local_prefixes
        for remote in remote_prefixes
    } | {
        (tailscale_interface, underlay_interface, str(remote), str(local))
        for local in local_prefixes
        for remote in remote_prefixes
    }
    if transport.get("filter_forward_policy") != "DROP":
        raise ReadinessError("filter FORWARD policy must fail closed")
    if transport.get("mangle_forward_policy") != "ACCEPT":
        raise ReadinessError("mangle FORWARD policy must remain ACCEPT")
    expected_filter_hook = [
        {"chain": "FORWARD", "action": "JUMP", "target": _FORWARD_CHAIN}
    ]
    if transport.get("filter_forward_rules") != expected_filter_hook:
        raise ReadinessError("filter FORWARD must contain only the approved chain hook")
    expected_mangle_hook = [
        {"chain": "FORWARD", "action": "JUMP", "target": _MSS_CHAIN}
    ]
    if transport.get("mangle_forward_rules") != expected_mangle_hook:
        raise ReadinessError("mangle FORWARD must contain only the approved MSS hook")
    forward_rules = transport.get("forward_rules")
    if not isinstance(forward_rules, list) or len(forward_rules) != len(
        expected_prefix_directions
    ):
        raise ReadinessError(
            f"{_FORWARD_CHAIN} must contain every exact prefix direction"
        )
    observed_forward: set[tuple[str, str, str, str]] = set()
    for rule in forward_rules:
        if not isinstance(rule, Mapping) or set(rule) != {
            "chain",
            "input",
            "output",
            "source",
            "destination",
            "action",
        }:
            raise ReadinessError("forward firewall rule has the wrong shape")
        if rule.get("chain") != _FORWARD_CHAIN or rule.get("action") != "ACCEPT":
            raise ReadinessError("transport forwarding does not use the exact approved chain")
        source = _networks([rule.get("source")], "forward firewall source")[0]
        destination = _networks(
            [rule.get("destination")], "forward firewall destination"
        )[0]
        observed_forward.add(
            (
                str(rule.get("input")),
                str(rule.get("output")),
                str(source),
                str(destination),
            )
        )
    if observed_forward != expected_prefix_directions:
        raise ReadinessError(
            f"{_FORWARD_CHAIN} does not cover the exact approved prefix directions"
        )

    mtus = []
    for field in ("underlay_mtu", "tailscale_mtu"):
        mtu = transport.get(field)
        if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 65535:
            raise ReadinessError(f"transport {field.replace('_', ' ')} is invalid")
        mtus.append(mtu)
    path_mtu = min(mtus)
    expected_mss = min(path_mtu - 40, approved_maximum_tcp_mss)

    mss_rules = transport.get("mss_rules")
    if not isinstance(mss_rules, list) or len(mss_rules) != len(
        expected_prefix_directions
    ):
        raise ReadinessError(f"{_MSS_CHAIN} must contain every exact prefix direction")
    observed_mss: set[tuple[str, str, str, str]] = set()
    for rule in mss_rules:
        if not isinstance(rule, Mapping) or set(rule) != {
            "chain",
            "input",
            "output",
            "source",
            "destination",
            "protocol",
            "tcp_flags",
            "action",
            "mss",
        }:
            raise ReadinessError("MSS firewall rule has the wrong shape")
        mss = rule.get("mss")
        if (
            rule.get("chain") != _MSS_CHAIN
            or rule.get("protocol") != "tcp"
            or rule.get("tcp_flags") != "SYN,RST SYN"
            or rule.get("action") != "TCPMSS"
            or isinstance(mss, bool)
            or not isinstance(mss, int)
            or mss != expected_mss
        ):
            raise ReadinessError("transport MSS policy is invalid")
        source = _networks([rule.get("source")], "MSS firewall source")[0]
        destination = _networks(
            [rule.get("destination")], "MSS firewall destination"
        )[0]
        observed_mss.add(
            (
                str(rule.get("input")),
                str(rule.get("output")),
                str(source),
                str(destination),
            )
        )
    if observed_mss != expected_prefix_directions:
        raise ReadinessError(
            f"{_MSS_CHAIN} does not cover the exact approved prefix directions"
        )
    if transport.get("mss_terminal_rules") != [
        {"chain": _MSS_CHAIN, "action": "RETURN"}
    ]:
        raise ReadinessError(f"{_MSS_CHAIN} must end in exactly one RETURN")

    nat_rules = transport.get("nat_rules")
    if not isinstance(nat_rules, list) or nat_rules:
        raise ReadinessError("transport router contains a NAT rewrite rule")
    if transport.get("native_nft_rules") != []:
        raise ReadinessError("transport router contains native nftables state")
    return path_mtu, expected_mss


def _verify_forwarding(
    transport: Mapping[str, Any], underlay_interface: str, tailscale_interface: str
) -> None:
    if transport.get("ipv4_forwarding") is not True:
        raise ReadinessError("IPv4 forwarding is disabled")
    if (
        transport.get("ipv6_forwarding") is not False
        or transport.get("ipv6_filter_forward_policy") != "DROP"
        or transport.get("ipv6_mangle_forward_policy") != "ACCEPT"
        or transport.get("ipv6_filter_forward_rules")
        != [
            {
                "chain": "FORWARD",
                "action": "JUMP",
                "target": _FORWARD_CHAIN,
            }
        ]
        or transport.get("ipv6_forward_rules") != []
        or transport.get("ipv6_mangle_forward_rules") != []
    ):
        raise ReadinessError("disabled IPv6 transit is not fail closed")
    rp_filter = transport.get("rp_filter")
    expected = {"all", "default", underlay_interface, tailscale_interface}
    if not isinstance(rp_filter, Mapping) or set(rp_filter) != expected:
        raise ReadinessError("reverse-path filter state has the wrong interfaces")
    if any(isinstance(value, bool) or value != 0 for value in rp_filter.values()):
        raise ReadinessError("strict reverse-path filtering is enabled")


def _verify_host_network_service(
    value: Any, contract: Mapping[str, Any]
) -> None:
    expected = {
        "unit": "envelope-transport-router-network.service",
        "enabled": True,
        "active": True,
        "readiness_marker": contract["readiness_marker"],
        "runtime_state": contract["runtime_state"],
        "recovery_marker": contract["recovery_marker"],
    }
    if not isinstance(value, Mapping) or dict(value) != expected:
        raise ReadinessError(
            "transport host-network service and recovery markers are not restored"
        )


def _verify_local_policy_rules(
    value: Any,
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
    expected_input: str,
) -> list[int]:
    if not isinstance(value, list):
        raise ReadinessError("local-site policy rules must contain exactly one rule per prefix")
    observed: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    priorities: list[int] = []
    expected_priorities = {
        prefix: POLICY_PRIORITY_BASE + index for index, prefix in enumerate(prefixes)
    }
    for rule in value:
        if not isinstance(rule, Mapping) or set(rule) != {
            "priority",
            "input",
            "source",
            "destination",
            "fwmark",
            "table",
            "action",
        }:
            raise ReadinessError("local-site policy rule has the wrong shape")
        priority = rule.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 32765:
            raise ReadinessError("local-site policy rule priority is invalid")
        networks = _networks([rule.get("destination")], "local-site policy destination")
        prefix = networks[0]
        if (
            prefix not in prefixes
            or prefix in observed
            or priority != expected_priorities[prefix]
            or rule.get("input") != expected_input
            or rule.get("source") != "all"
            or rule.get("fwmark") != 0
            or str(rule.get("table")) not in {"254", "main"}
            or rule.get("action") != "lookup"
        ):
            raise ReadinessError("local-site policy rule can bypass the underlay inspection path")
        observed.add(prefix)
        priorities.append(priority)
    if observed != set(prefixes) or len(value) != len(prefixes):
        raise ReadinessError("local-site policy rules must contain exactly one rule per prefix")
    if priorities != [POLICY_PRIORITY_BASE + index for index in range(len(prefixes))]:
        raise ReadinessError("local-site policy rules are not in exact priority order")
    return priorities


def _verify_route_table_association(
    route_table: Mapping[str, Any], expected_subnet_id: str
) -> None:
    associations = route_table.get("Associations")
    if not isinstance(associations, list):
        raise ReadinessError("VPC route-table associations must be a list")
    matching = [
        association
        for association in associations
        if isinstance(association, Mapping)
        and association.get("SubnetId") == expected_subnet_id
    ]
    if len(matching) != 1:
        raise ReadinessError("transport subnet does not have one exact VPC route-table association")
    association = matching[0]
    state = association.get("AssociationState")
    if (
        association.get("Main") is not False
        or not isinstance(state, Mapping)
        or state.get("State") != "associated"
    ):
        raise ReadinessError("transport subnet VPC route-table association is not active")


def _validated_local_gwlbes(
    value: Any,
    prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> dict[str, str]:
    expected = {str(prefix) for prefix in prefixes}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ReadinessError(
            "local GWLBE map must contain exactly one endpoint for every local-site prefix"
        )
    result: dict[str, str] = {}
    for prefix in sorted(expected):
        endpoint = value.get(prefix)
        if not isinstance(endpoint, str) or not _GWLBE_ID_RE.fullmatch(endpoint):
            raise ReadinessError(f"local GWLBE identity for {prefix} is invalid")
        result[prefix] = endpoint
    return result


def validate_readiness(
    status: Mapping[str, Any],
    transport_state: Mapping[str, Any],
    vpc_route_table: Any,
    local_site_cidrs: Sequence[str],
    remote_site_cidrs: Sequence[str],
    expected_advertised_prefixes: Sequence[str] | str,
    local_gwlbes: Mapping[str, str],
    expected_network_interface_id: str,
    expected_subnet_id: str,
    expected_route_table_id: str,
    expected_availability_zone: str,
    underlay_interface: str,
    tailscale_interface: str,
    readiness_contract: Mapping[str, Any],
    expected_remote_prefix_owners: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a bounded readiness summary or raise ``ReadinessError``."""
    contract = _validated_readiness_contract(readiness_contract)
    if (
        list(local_site_cidrs) != contract["local_site_cidrs"]
        or list(remote_site_cidrs) != contract["remote_site_cidrs"]
        or underlay_interface != contract["underlay_interface"]
        or tailscale_interface != contract["tailscale_interface"]
    ):
        raise ReadinessError(
            "readiness inputs differ from the exact expanded transport contract"
        )
    if set(status) != {"BackendState", "TUN", "Health", "CheckedAt", "Self"}:
        raise ReadinessError("status input has the wrong sanitized fixture shape")
    checked_at = _timestamp(status.get("CheckedAt"), "status.CheckedAt")
    if status.get("BackendState") != "Running":
        raise ReadinessError("Tailscale backend is not Running")
    if status.get("TUN") is not True:
        raise ReadinessError("Tailscale kernel TUN is not enabled")
    if status.get("Health") != []:
        raise ReadinessError("Tailscale reports an unhealthy backend condition")
    self_status = status.get("Self")
    expected_self_fields = {
        "Online",
        "Expired",
        "KeyExpiry",
        "KeyExpiryDisabled",
        "AdvertisedRoutes",
        "AcceptedRoutes",
        "NoSNAT",
        "CorpDNS",
        "RoutePeers",
    }
    if contract["config_version"] == 3:
        expected_self_fields.add("EnabledRoutes")
    if not isinstance(self_status, Mapping) or set(self_status) != expected_self_fields:
        raise ReadinessError("status.Self has the wrong sanitized fixture shape")
    if (
        not isinstance(expected_network_interface_id, str)
        or not _ENI_ID_RE.fullmatch(expected_network_interface_id)
    ):
        raise ReadinessError("expected transport ENI identity is invalid")
    if not isinstance(expected_subnet_id, str) or not _SUBNET_ID_RE.fullmatch(expected_subnet_id):
        raise ReadinessError("expected transport subnet identity is invalid")
    if (
        not isinstance(expected_route_table_id, str)
        or not _ROUTE_TABLE_ID_RE.fullmatch(expected_route_table_id)
    ):
        raise ReadinessError("expected transport route-table identity is invalid")
    if (
        not isinstance(expected_availability_zone, str)
        or not _AZ_RE.fullmatch(expected_availability_zone)
    ):
        raise ReadinessError("transport availability-zone identity is invalid")
    if (
        not isinstance(underlay_interface, str)
        or not isinstance(tailscale_interface, str)
        or not underlay_interface
        or not tailscale_interface
        or underlay_interface == tailscale_interface
        or {underlay_interface, tailscale_interface} & {"all", "default", "lo", "envelope0"}
    ):
        raise ReadinessError("transport interface identities are invalid")
    if not isinstance(transport_state, Mapping) or set(transport_state) != {
        "source_dest_check",
        "network_interface_id",
        "subnet_id",
        "availability_zone",
        "ipv4_forwarding",
        "ipv6_forwarding",
        "ipv6_filter_forward_policy",
        "ipv6_mangle_forward_policy",
        "ipv6_filter_forward_rules",
        "ipv6_forward_rules",
        "ipv6_mangle_forward_rules",
        "rp_filter",
        "underlay_mtu",
        "tailscale_mtu",
        "filter_forward_policy",
        "mangle_forward_policy",
        "filter_forward_rules",
        "forward_rules",
        "mangle_forward_rules",
        "mss_rules",
        "mss_terminal_rules",
        "nat_rules",
        "native_nft_rules",
        "local_policy_rules",
        "ipv4_policy_rules",
        "policy_rule_priority_base",
        "local_route_table",
        "remote_route_table",
        "table52_routes",
        "main_routes",
        "host_network_service",
    }:
        raise ReadinessError("transport state has the wrong shape")
    if transport_state["source_dest_check"] is not False:
        raise ReadinessError("EC2 source/destination checking is enabled")
    if transport_state["network_interface_id"] != expected_network_interface_id:
        raise ReadinessError("transport ENI identity differs from the protected topology")
    if transport_state["subnet_id"] != expected_subnet_id:
        raise ReadinessError("transport subnet identity differs from the protected topology")
    if transport_state["availability_zone"] != expected_availability_zone:
        raise ReadinessError("transport ENI is not in the expected availability zone")
    if (
        transport_state["policy_rule_priority_base"]
        != contract["policy_rule_priority_base"]
        or transport_state["local_route_table"] != contract["local_route_table"]
        or transport_state["remote_route_table"] != contract["remote_route_table"]
        or transport_state["ipv4_policy_rules"] != contract["ipv4_policy_rules"]
    ):
        raise ReadinessError(
            "effective IPv4 policy rules or route-table identities differ from contract"
        )
    _verify_host_network_service(transport_state["host_network_service"], contract)

    local = _networks(list(local_site_cidrs), "local-site CIDRs")
    remote = _networks(list(remote_site_cidrs), "remote-site CIDRs")
    if any(not isinstance(network, ipaddress.IPv4Network) for network in (*local, *remote)):
        raise ReadinessError("transport readiness currently requires IPv4 site CIDRs")
    if any(left.overlaps(right) for left in local for right in remote):
        raise ReadinessError("local-site and remote-site CIDRs overlap")
    for field, networks in (("local-site", local), ("remote-site", remote)):
        if any(
            left.overlaps(right)
            for index, left in enumerate(networks)
            for right in networks[index + 1 :]
        ):
            raise ReadinessError(f"{field} CIDRs overlap each other")
    expected_local_gwlbes = _validated_local_gwlbes(local_gwlbes, local)
    raw_expected_advertisements = (
        [expected_advertised_prefixes]
        if isinstance(expected_advertised_prefixes, str)
        else list(expected_advertised_prefixes)
    )
    expected_advertisements = _networks(
        raw_expected_advertisements, "expected advertised prefixes"
    )
    if contract["config_version"] == 3:
        if set(expected_advertisements) != set(local):
            raise ReadinessError(
                "expected advertisements are not the complete exact local-site CIDR set"
            )
    elif len(expected_advertisements) != 1 or expected_advertisements[0] not in local:
        raise ReadinessError(
            "legacy expected advertisement is not one exact local-site CIDR"
        )
    advertised = _status_routes(status, "AdvertisedRoutes")
    enabled = (
        _status_routes(status, "EnabledRoutes")
        if contract["config_version"] == 3
        else advertised
    )
    accepted = _status_routes(status, "AcceptedRoutes")
    if self_status.get("Online") is not True or self_status.get("Expired") is not False:
        raise ReadinessError("transport router self node is offline or expired")
    self_key_expiry = _timestamp(
        self_status.get("KeyExpiry"), "status.Self.KeyExpiry"
    )
    self_key_expiry_disabled = self_status.get("KeyExpiryDisabled")
    if not isinstance(self_key_expiry_disabled, bool):
        raise ReadinessError("transport router self node key-expiry mode is invalid")
    if not self_key_expiry_disabled and self_key_expiry <= checked_at:
        raise ReadinessError("transport router self node key is expired")
    if self_status.get("NoSNAT") is not True:
        raise ReadinessError("subnet-route SNAT is enabled")
    if self_status.get("CorpDNS") is not False:
        raise ReadinessError("Tailnet DNS acceptance is enabled or unverified")
    if set(advertised) != set(expected_advertisements):
        raise ReadinessError(
            "transport-router advertisements are not the exact expected local-site CIDRs"
        )
    if set(enabled) != set(expected_advertisements):
        raise ReadinessError(
            "transport-router enabled routes are not the exact expected local-site CIDRs"
        )
    if set(accepted) != set(remote):
        raise ReadinessError("accepted remote routes are not the exact approved CIDRs")
    serving_peer_count, serving_peers = _verify_route_peers(
        status,
        remote,
        checked_at,
        expected_remote_prefix_owners,
    )

    _verify_forwarding(transport_state, underlay_interface, tailscale_interface)
    path_mtu, tcp_mss = _verify_firewall(
        transport_state,
        underlay_interface,
        tailscale_interface,
        local,
        remote,
        contract["approved_maximum_tcp_mss"],
    )
    policy_rule_priorities = _verify_local_policy_rules(
        transport_state["local_policy_rules"],
        local,
        tailscale_interface if contract["config_version"] == 2 else "all",
    )
    remote_prefix_chains = _verify_host_route_domain(
        transport_state["table52_routes"],
        remote,
        tailscale_interface,
        "table-52 remote",
        exact=True,
    )
    local_prefix_chains = _verify_host_route_domain(
        transport_state["main_routes"],
        local,
        underlay_interface,
        "local underlay",
        exact=False,
    )
    if contract["config_version"] == 2:
        _reject_host_route_intersections(
            transport_state["table52_routes"],
            local,
            "table-52 route",
        )
        local_tailnet_selection: list[dict[str, Any]] = []
    else:
        local_tailnet_selection = _verify_shadowed_local_table52_routes(
            transport_state["table52_routes"], local, tailscale_interface
        )

    if (
        not isinstance(vpc_route_table, Mapping)
        or vpc_route_table.get("RouteTableId") != expected_route_table_id
    ):
        raise ReadinessError("VPC route-table identity differs from the protected topology")
    _verify_route_table_association(vpc_route_table, expected_subnet_id)
    parsed_routes = tuple((route, _route_network(route)) for route in _routes(vpc_route_table))
    vpc_prefix_chains: list[dict[str, str]] = []
    for prefix in local:
        local_gwlbe = expected_local_gwlbes[str(prefix)]
        exact = [route for route, network in parsed_routes if network == prefix]
        if len(exact) != 1:
            raise ReadinessError(f"{prefix} does not have one exact VPC route")
        route = exact[0]
        if route.get("State") != "active":
            raise ReadinessError(f"{prefix} VPC route is not active")
        if route.get("GatewayId") != local_gwlbe or any(
            route.get(field) not in (None, "") for field in _ROUTE_TARGET_FIELDS - {"GatewayId"}
        ):
            raise ReadinessError(f"{prefix} VPC route does not select local GWLBE {local_gwlbe}")
        overrides = [
            str(network)
            for route, network in parsed_routes
            if network is not None
            and network != prefix
            and network.version == prefix.version
            and network.subnet_of(prefix)
            and (
                route.get("GatewayId") != local_gwlbe
                or route.get("State") != "active"
                or any(
                    route.get(field) not in (None, "")
                    for field in _ROUTE_TARGET_FIELDS - {"GatewayId"}
                )
            )
        ]
        if overrides:
            raise ReadinessError(
                f"{prefix} has a more-specific VPC route that bypasses local GWLBE: {', '.join(sorted(overrides))}"
            )
        vpc_prefix_chains.append(
            {
                "prefix": str(prefix),
                "route_table_id": expected_route_table_id,
                "gwlbe": local_gwlbe,
            }
        )

    return {
        "ready": True,
        "local_gwlbes": expected_local_gwlbes,
        "availability_zone": expected_availability_zone,
        "network_interface_id": expected_network_interface_id,
        "subnet_id": expected_subnet_id,
        "route_table_id": expected_route_table_id,
        "source_dest_check": False,
        "ipv4_forwarding": True,
        "ipv6_forwarding": False,
        "rp_filter_disabled": True,
        "forwarding_directions": 2,
        "mss_directions": 2,
        "forwarding_prefix_rules": len(local) * len(remote) * 2,
        "mss_prefix_rules": len(local) * len(remote) * 2,
        "path_mtu": path_mtu,
        "tcp_mss": tcp_mss,
        "no_nat": True,
        "serving_peer_count": serving_peer_count,
        "route_serving_peers": serving_peers,
        "policy_rule_priorities": policy_rule_priorities,
        "prefix_chains": {
            "local_underlay": local_prefix_chains,
            "remote_tailnet": remote_prefix_chains,
            "local_tailnet_selection": local_tailnet_selection,
            "local_vpc_gwlbe": vpc_prefix_chains,
        },
        "firewall_chains": {
            "filter_forward_policy": "DROP",
            "mangle_forward_policy": "ACCEPT",
            "ipv6_filter_forward_policy": "DROP",
            "ipv6_mangle_forward_policy": "ACCEPT",
            "filter_forward_hook": _FORWARD_CHAIN,
            "mangle_forward_hook": _MSS_CHAIN,
            "mss_terminal_action": "RETURN",
        },
        "host_network_service_restored": True,
        "recovery_marker": contract["recovery_marker"],
        "local_route_table": contract["local_route_table"],
        "remote_route_table": contract["remote_route_table"],
        "contract_sha256": contract["contract_sha256"],
        "underlay_interface": underlay_interface,
        "tailscale_interface": tailscale_interface,
        "local_site_cidrs": [str(network) for network in local],
        "remote_site_cidrs": [str(network) for network in remote],
        **(
            {"advertised_prefix": str(expected_advertisements[0])}
            if contract["config_version"] == 2
            else {
                "advertised_prefixes": [
                    str(prefix) for prefix in expected_advertisements
                ]
            }
        ),
    }


def load_json(path: pathlib.Path) -> Any:
    try:
        with path.open("rb") as source:
            value = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise ReadinessError(f"cannot read {path}: {error.strerror or error}") from error
    if len(value) > MAX_INPUT_BYTES:
        raise ReadinessError(f"{path} exceeds the {MAX_INPUT_BYTES}-byte input limit")
    try:
        return json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReadinessError(f"{path} is not valid JSON") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-file", type=pathlib.Path, required=True)
    parser.add_argument("--transport-file", type=pathlib.Path, required=True)
    parser.add_argument("--vpc-routes-file", type=pathlib.Path, required=True)
    parser.add_argument("--contract-file", type=pathlib.Path, required=True)
    parser.add_argument("--local-site-cidr", action="append", required=True)
    parser.add_argument("--remote-site-cidr", action="append", required=True)
    parser.add_argument("--advertised-prefix", action="append", required=True)
    parser.add_argument("--local-gwlbes-file", type=pathlib.Path, required=True)
    parser.add_argument("--network-interface-id", required=True)
    parser.add_argument("--subnet-id", required=True)
    parser.add_argument("--route-table-id", required=True)
    parser.add_argument("--availability-zone", required=True)
    parser.add_argument("--underlay-interface", required=True)
    parser.add_argument("--tailscale-interface", required=True)
    args = parser.parse_args(argv)
    try:
        status = load_json(args.status_file)
        if not isinstance(status, Mapping):
            raise ReadinessError("status input must be an object")
        result = validate_readiness(
            status,
            load_json(args.transport_file),
            load_json(args.vpc_routes_file),
            args.local_site_cidr,
            args.remote_site_cidr,
            args.advertised_prefix,
            load_json(args.local_gwlbes_file),
            args.network_interface_id,
            args.subnet_id,
            args.route_table_id,
            args.availability_zone,
            args.underlay_interface,
            args.tailscale_interface,
            load_json(args.contract_file),
        )
    except ReadinessError as error:
        print(f"transport-router readiness failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
