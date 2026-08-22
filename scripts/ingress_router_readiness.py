#!/usr/bin/env python3
"""Validate an ingress router from bounded, sanitized local status inputs.

The status fixture contains only the Tailscale fields needed here.  The VPC
route fixture is the route list for the ingress router's selected route table;
collecting it is intentionally outside this credential-free checker.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import sys
from typing import Any, Mapping, Sequence


MAX_INPUT_BYTES = 1024 * 1024


class ReadinessError(ValueError):
    """The ingress router cannot safely receive Tailnet traffic."""


def _networks(values: Any, field: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not isinstance(values, list) or not values:
        raise ReadinessError(f"{field} must be a non-empty CIDR list")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ReadinessError(f"{field} contains a non-string CIDR")
        try:
            result.append(ipaddress.ip_network(value, strict=False))
        except ValueError as error:
            raise ReadinessError(f"{field} contains an invalid CIDR: {value!r}") from error
    if len(set(result)) != len(result):
        raise ReadinessError(f"{field} contains duplicate CIDRs")
    return tuple(result)


def _status_routes(status: Mapping[str, Any], field: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    self_status = status.get("Self")
    if not isinstance(self_status, Mapping):
        raise ReadinessError("status.Self must be an object")
    return _networks(self_status.get(field), f"status.Self.{field}")


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


def validate_readiness(
    status: Mapping[str, Any],
    vpc_routes: Any,
    local_site_cidrs: Sequence[str],
    remote_site_cidrs: Sequence[str],
    local_gwlbe: str,
) -> dict[str, Any]:
    """Return a bounded readiness summary or raise ``ReadinessError``."""
    if status.get("BackendState") != "Running":
        raise ReadinessError("Tailscale backend is not Running")
    if status.get("TUN") is not True:
        raise ReadinessError("Tailscale kernel TUN is not enabled")
    if not isinstance(local_gwlbe, str) or not local_gwlbe:
        raise ReadinessError("local GWLBE must be a non-empty endpoint ID")

    local = _networks(list(local_site_cidrs), "local-site CIDRs")
    remote = _networks(list(remote_site_cidrs), "remote-site CIDRs")
    advertised = _status_routes(status, "AdvertisedRoutes")
    accepted = _status_routes(status, "AcceptedRoutes")
    self_status = status["Self"]
    assert isinstance(self_status, Mapping)
    if self_status.get("NoSNAT") is not True:
        raise ReadinessError("subnet-route SNAT is enabled")
    if set(advertised) != set(local):
        raise ReadinessError("local-site route advertisements are not the exact approved CIDRs")
    if not set(remote).issubset(accepted):
        missing = sorted(str(network) for network in set(remote) - set(accepted))
        raise ReadinessError(f"required remote routes are not accepted: {', '.join(missing)}")

    parsed_routes = tuple((route, _route_network(route)) for route in _routes(vpc_routes))
    for prefix in local:
        exact = [route for route, network in parsed_routes if network == prefix]
        if len(exact) != 1:
            raise ReadinessError(f"{prefix} does not have one exact VPC route")
        route = exact[0]
        if route.get("State") != "active":
            raise ReadinessError(f"{prefix} VPC route is not active")
        if route.get("VpcEndpointId") != local_gwlbe:
            raise ReadinessError(f"{prefix} VPC route does not select local GWLBE {local_gwlbe}")
        overrides = [
            str(network)
            for route, network in parsed_routes
            if network is not None
            and network != prefix
            and network.version == prefix.version
            and network.subnet_of(prefix)
            and (route.get("VpcEndpointId") != local_gwlbe or route.get("State") != "active")
        ]
        if overrides:
            raise ReadinessError(
                f"{prefix} has a more-specific VPC route that bypasses local GWLBE: {', '.join(sorted(overrides))}"
            )

    return {
        "ready": True,
        "local_gwlbe": local_gwlbe,
        "local_site_cidrs": [str(network) for network in local],
        "remote_site_cidrs": [str(network) for network in remote],
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
    parser.add_argument("--vpc-routes-file", type=pathlib.Path, required=True)
    parser.add_argument("--local-site-cidr", action="append", required=True)
    parser.add_argument("--remote-site-cidr", action="append", required=True)
    parser.add_argument("--local-gwlbe", required=True)
    args = parser.parse_args(argv)
    try:
        status = load_json(args.status_file)
        if not isinstance(status, Mapping):
            raise ReadinessError("status input must be an object")
        result = validate_readiness(
            status,
            load_json(args.vpc_routes_file),
            args.local_site_cidr,
            args.remote_site_cidr,
            args.local_gwlbe,
        )
    except ReadinessError as error:
        print(f"ingress-router readiness failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
