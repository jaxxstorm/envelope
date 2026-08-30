#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import transport_router_readiness as readiness  # noqa: E402


LOCAL = ["10.10.0.0/16", "10.11.0.0/16"]
REMOTE = ["10.20.0.0/16", "10.21.0.0/16"]
GWLBE = "vpce-0123456789abcdef0"
ENI = "eni-0123456789abcdef0"
SUBNET = "subnet-0123456789abcdef0"
ROUTE_TABLE = "rtb-0123456789abcdef0"
AZ = "us-west-2a"
UNDERLAY = "ens5"
TAILSCALE = "tailscale0"
CHECKED_AT = "2026-08-27T12:00:00Z"
SELF_KEY_EXPIRY = "2026-08-27T14:00:00Z"
PEER_KEY_EXPIRY = "2026-08-27T13:00:00Z"
PING_OBSERVED_AT = "2026-08-27T11:59:55Z"


def contract_fixture() -> dict:
    contract = readiness.build_readiness_contract(
        LOCAL,
        REMOTE,
        UNDERLAY,
        TAILSCALE,
        readiness.MAX_TCP_MSS,
    )
    return {
        **contract,
        "contract_sha256": readiness.readiness_contract_sha256(contract),
    }


def status_fixture() -> dict:
    return {
        "BackendState": "Running",
        "TUN": True,
        "Health": [],
        "CheckedAt": CHECKED_AT,
        "Self": {
            "Online": True,
            "Expired": False,
            "KeyExpiry": SELF_KEY_EXPIRY,
            "KeyExpiryDisabled": False,
            "AdvertisedRoutes": [LOCAL[0]],
            "AcceptedRoutes": list(REMOTE),
            "NoSNAT": True,
            "RoutePeers": [
                {
                    "Prefix": prefix,
                    "PeerID": f"peer-east-{index}",
                    "Online": True,
                    "Expired": False,
                    "KeyExpiry": PEER_KEY_EXPIRY,
                    "KeyExpiryDisabled": False,
                    "Ping": {
                        "PeerID": f"peer-east-{index}",
                        "Succeeded": True,
                        "ObservedAt": PING_OBSERVED_AT,
                        "LatencyMilliseconds": 12 + index,
                    },
                }
                for index, prefix in enumerate(REMOTE, start=1)
            ],
        },
    }


def route_fixture() -> dict:
    return {
        "RouteTableId": ROUTE_TABLE,
        "Associations": [
            {
                "SubnetId": SUBNET,
                "Main": False,
                "AssociationState": {"State": "associated"},
            }
        ],
        "Routes": [
            {"DestinationCidrBlock": prefix, "GatewayId": GWLBE, "State": "active"}
            for prefix in LOCAL
        ]
    }


def transport_fixture() -> dict:
    directions = [
        direction
        for local in LOCAL
        for remote in REMOTE
        for direction in (
            (UNDERLAY, TAILSCALE, local, remote),
            (TAILSCALE, UNDERLAY, remote, local),
        )
    ]
    return {
        "source_dest_check": False,
        "network_interface_id": ENI,
        "subnet_id": SUBNET,
        "availability_zone": AZ,
        "ipv4_forwarding": True,
        "ipv6_forwarding": False,
        "ipv6_filter_forward_policy": "DROP",
        "ipv6_mangle_forward_policy": "ACCEPT",
        "ipv6_filter_forward_rules": [
            {
                "chain": "FORWARD",
                "action": "JUMP",
                "target": "ENVELOPE-TRANSPORT-FORWARD",
            }
        ],
        "ipv6_forward_rules": [],
        "ipv6_mangle_forward_rules": [],
        "rp_filter": {"all": 0, "default": 0, UNDERLAY: 0, TAILSCALE: 0},
        "underlay_mtu": 1500,
        "tailscale_mtu": 1280,
        "filter_forward_policy": "DROP",
        "mangle_forward_policy": "ACCEPT",
        "filter_forward_rules": [
            {
                "chain": "FORWARD",
                "action": "JUMP",
                "target": "ENVELOPE-TRANSPORT-FORWARD",
            }
        ],
        "forward_rules": [
            {
                "chain": "ENVELOPE-TRANSPORT-FORWARD",
                "input": input_interface,
                "output": output_interface,
                "source": source,
                "destination": destination,
                "action": "ACCEPT",
            }
            for input_interface, output_interface, source, destination in directions
        ],
        "mss_rules": [
            {
                "chain": "ENVELOPE-TRANSPORT-MSS",
                "input": input_interface,
                "output": output_interface,
                "source": source,
                "destination": destination,
                "protocol": "tcp",
                "tcp_flags": "SYN,RST SYN",
                "action": "TCPMSS",
                "mss": 1240,
            }
            for input_interface, output_interface, source, destination in directions
        ],
        "mangle_forward_rules": [
            {
                "chain": "FORWARD",
                "action": "JUMP",
                "target": "ENVELOPE-TRANSPORT-MSS",
            }
        ],
        "mss_terminal_rules": [
            {"chain": "ENVELOPE-TRANSPORT-MSS", "action": "RETURN"}
        ],
        "nat_rules": [],
        "native_nft_rules": [],
        "local_policy_rules": [
            {
                "priority": readiness.POLICY_PRIORITY_BASE + index,
                "input": TAILSCALE,
                "source": "all",
                "destination": prefix,
                "fwmark": 0,
                "table": "main",
                "action": "lookup",
            }
            for index, prefix in enumerate(LOCAL)
        ],
        "ipv4_policy_rules": copy.deepcopy(contract_fixture()["ipv4_policy_rules"]),
        "policy_rule_priority_base": readiness.POLICY_PRIORITY_BASE,
        "local_route_table": "main",
        "remote_route_table": 52,
        "table52_routes": [
            {"dst": prefix, "dev": TAILSCALE, "type": "unicast"} for prefix in REMOTE
        ],
        "main_routes": [
            {"dst": "10.10.0.0/15", "dev": UNDERLAY, "type": "unicast"}
        ],
        "host_network_service": {
            "unit": "envelope-transport-router-network.service",
            "enabled": True,
            "active": True,
            "readiness_marker": "/var/lib/envelope/transport-router-network.ready",
            "runtime_state": "/var/lib/envelope/transport-router-network.state.json",
            "recovery_marker": "/var/lib/envelope/transport-router-network.configured",
        },
    }


def validate(
    *,
    status: dict | None = None,
    transport: dict | None = None,
    routes: dict | None = None,
    contract: dict | None = None,
    expected_remote_prefix_owners: dict[str, str] | None = None,
) -> dict:
    return readiness.validate_readiness(
        status_fixture() if status is None else status,
        transport_fixture() if transport is None else transport,
        route_fixture() if routes is None else routes,
        LOCAL,
        REMOTE,
        LOCAL[0],
        GWLBE,
        ENI,
        SUBNET,
        ROUTE_TABLE,
        AZ,
        AZ,
        UNDERLAY,
        TAILSCALE,
        contract_fixture() if contract is None else contract,
        expected_remote_prefix_owners=expected_remote_prefix_owners,
    )


class TransportRouterReadinessTest(unittest.TestCase):
    def test_ready_router_requires_only_sanitized_fixture_inputs(self) -> None:
        result = validate()

        self.assertTrue(result["ready"])
        self.assertEqual(result["local_gwlbe"], GWLBE)
        self.assertEqual(result["local_site_cidrs"], LOCAL)
        self.assertEqual(result["advertised_prefix"], LOCAL[0])
        self.assertEqual(result["network_interface_id"], ENI)
        self.assertEqual(result["subnet_id"], SUBNET)
        self.assertEqual(result["route_table_id"], ROUTE_TABLE)
        self.assertEqual(result["availability_zone"], AZ)
        self.assertEqual(result["forwarding_directions"], 2)
        self.assertEqual(result["mss_directions"], 2)
        self.assertEqual(result["forwarding_prefix_rules"], 8)
        self.assertEqual(result["mss_prefix_rules"], 8)
        self.assertEqual(result["path_mtu"], 1280)
        self.assertEqual(result["tcp_mss"], 1240)
        self.assertEqual(result["serving_peer_count"], 2)
        self.assertEqual(result["policy_rule_priorities"], [100, 101])
        self.assertEqual(
            [value["peer_id"] for value in result["route_serving_peers"]],
            ["peer-east-1", "peer-east-2"],
        )
        self.assertEqual(
            [value["key_expiry_disabled"] for value in result["route_serving_peers"]],
            [False, False],
        )
        self.assertEqual(
            [value["prefix"] for value in result["prefix_chains"]["remote_tailnet"]],
            REMOTE,
        )
        self.assertEqual(
            [
                value["prefix"]
                for value in result["prefix_chains"]["local_tailnet_selection"]
            ],
            [],
        )
        self.assertEqual(
            [value["gwlbe"] for value in result["prefix_chains"]["local_vpc_gwlbe"]],
            [GWLBE, GWLBE],
        )
        self.assertEqual(result["firewall_chains"]["filter_forward_policy"], "DROP")
        self.assertEqual(result["firewall_chains"]["mangle_forward_policy"], "ACCEPT")
        self.assertTrue(result["host_network_service_restored"])
        self.assertEqual(
            result["recovery_marker"],
            "/var/lib/envelope/transport-router-network.configured",
        )
        self.assertEqual(result["local_route_table"], "main")
        self.assertEqual(result["remote_route_table"], 52)
        self.assertEqual(result["contract_sha256"], contract_fixture()["contract_sha256"])

    def test_ha25_remote_only_table52_shape_is_ready(self) -> None:
        local = ["10.10.1.0/24", "10.10.2.0/24"]
        remote = ["10.20.1.0/24", "10.20.2.0/24"]
        contract = readiness.build_readiness_contract(
            local,
            remote,
            UNDERLAY,
            TAILSCALE,
            readiness.MAX_TCP_MSS,
        )
        contract["contract_sha256"] = readiness.readiness_contract_sha256(contract)
        status = status_fixture()
        status["Self"]["AdvertisedRoutes"] = [local[0]]
        status["Self"]["AcceptedRoutes"] = list(remote)
        for peer, prefix in zip(status["Self"]["RoutePeers"], remote, strict=True):
            peer["Prefix"] = prefix

        transport = transport_fixture()
        prefix_map = dict(zip([*LOCAL, *REMOTE], [*local, *remote], strict=True))
        for rule in [*transport["forward_rules"], *transport["mss_rules"]]:
            rule["source"] = prefix_map[rule["source"]]
            rule["destination"] = prefix_map[rule["destination"]]
        for rule, prefix in zip(transport["local_policy_rules"], local, strict=True):
            rule["destination"] = prefix
        transport["ipv4_policy_rules"] = copy.deepcopy(contract["ipv4_policy_rules"])
        transport["table52_routes"] = [
            {"dst": prefix, "dev": TAILSCALE, "type": "unicast"}
            for prefix in remote
        ]
        transport["main_routes"] = [
            {"dst": "10.10.0.0/16", "dev": UNDERLAY, "type": "unicast"}
        ]
        routes = route_fixture()
        routes["Routes"] = [
            {"DestinationCidrBlock": prefix, "GatewayId": GWLBE, "State": "active"}
            for prefix in local
        ]

        result = readiness.validate_readiness(
            status,
            transport,
            routes,
            local,
            remote,
            local[0],
            GWLBE,
            ENI,
            SUBNET,
            ROUTE_TABLE,
            AZ,
            AZ,
            UNDERLAY,
            TAILSCALE,
            contract,
            expected_remote_prefix_owners={
                prefix: f"peer-east-{index}"
                for index, prefix in enumerate(remote, start=1)
            },
        )

        self.assertEqual(
            [entry["prefix"] for entry in result["prefix_chains"]["remote_tailnet"]],
            remote,
        )
        self.assertEqual(result["prefix_chains"]["local_tailnet_selection"], [])
        self.assertEqual(
            [entry["prefix"] for entry in result["prefix_chains"]["local_underlay"]],
            local,
        )

    def test_requires_the_exact_expanded_contract_and_effective_state(self) -> None:
        contract_cases = []
        stale_recovery = contract_fixture()
        stale_recovery["recovery_marker"] = "/tmp/recovered"
        stale_recovery["contract_sha256"] = readiness.readiness_contract_sha256(
            {key: value for key, value in stale_recovery.items() if key != "contract_sha256"}
        )
        contract_cases.append(("recovery marker", stale_recovery))
        stale_policy = contract_fixture()
        stale_policy["ipv4_policy_rules"][0]["table"] = "main"
        stale_policy["contract_sha256"] = readiness.readiness_contract_sha256(
            {key: value for key, value in stale_policy.items() if key != "contract_sha256"}
        )
        contract_cases.append(("full policy", stale_policy))
        stale_hash = contract_fixture()
        stale_hash["contract_sha256"] = "0" * 64
        contract_cases.append(("SHA", stale_hash))
        for name, contract in contract_cases:
            with self.subTest(contract=name), self.assertRaisesRegex(
                readiness.ReadinessError, "exact expanded contract"
            ):
                validate(contract=contract)

        state_cases = []
        filter_policy = transport_fixture()
        filter_policy["filter_forward_policy"] = "ACCEPT"
        state_cases.append(("filter policy", filter_policy, "fail closed"))
        mangle_policy = transport_fixture()
        mangle_policy["mangle_forward_policy"] = "DROP"
        state_cases.append(("mangle policy", mangle_policy, "mangle FORWARD"))
        ipv6_mangle_policy = transport_fixture()
        ipv6_mangle_policy["ipv6_mangle_forward_policy"] = "DROP"
        state_cases.append(("IPv6 mangle policy", ipv6_mangle_policy, "IPv6 transit"))
        native_nft = transport_fixture()
        native_nft["native_nft_rules"] = [{"table": "unreviewed"}]
        state_cases.append(("native nft", native_nft, "native nftables"))
        full_policy = transport_fixture()
        full_policy["ipv4_policy_rules"][0]["table"] = "main"
        state_cases.append(("effective policy", full_policy, "policy rules"))
        remote_table = transport_fixture()
        remote_table["remote_route_table"] = 53
        state_cases.append(("remote table", remote_table, "route-table identities"))
        service = transport_fixture()
        service["host_network_service"]["recovery_marker"] = "/tmp/missing"
        state_cases.append(("service restoration", service, "not restored"))
        for name, transport, message in state_cases:
            with self.subTest(state=name), self.assertRaisesRegex(
                readiness.ReadinessError, message
            ):
                validate(transport=transport)

    def test_rejects_non_running_userspace_or_missing_kernel_tun(self) -> None:
        for field, value, message in (
            ("BackendState", "Stopped", "not Running"),
            ("TUN", False, "kernel TUN"),
        ):
            with self.subTest(field=field):
                status = status_fixture()
                status[field] = value
                with self.assertRaisesRegex(readiness.ReadinessError, message):
                    validate(status=status)

        status = status_fixture()
        status["Health"] = ["control unavailable"]
        with self.assertRaisesRegex(readiness.ReadinessError, "unhealthy backend"):
            validate(status=status)

    def test_status_fixture_is_exact_and_timestamped(self) -> None:
        extra = status_fixture()
        extra["Credential"] = "must-not-be-collected"
        with self.assertRaisesRegex(readiness.ReadinessError, "wrong sanitized fixture"):
            validate(status=extra)

        noncanonical = status_fixture()
        noncanonical["CheckedAt"] = "2026-08-27T12:00:00+00:00"
        with self.assertRaisesRegex(readiness.ReadinessError, "canonical UTC"):
            validate(status=noncanonical)

        oversized_latency = status_fixture()
        oversized_latency["Self"]["RoutePeers"][0]["Ping"][
            "LatencyMilliseconds"
        ] = readiness.MAX_PING_LATENCY_MILLISECONDS + 1
        with self.assertRaisesRegex(readiness.ReadinessError, "bounded data-plane ping"):
            validate(status=oversized_latency)

    def test_requires_online_nonexpired_self_and_pingable_route_peers(self) -> None:
        cases = []
        offline_self = status_fixture()
        offline_self["Self"]["Online"] = False
        cases.append(("offline self", offline_self, "self node"))
        expired_self = status_fixture()
        expired_self["Self"]["Expired"] = True
        cases.append(("expired self", expired_self, "self node"))
        stale_self_key = status_fixture()
        stale_self_key["Self"]["KeyExpiry"] = CHECKED_AT
        cases.append(("expired self key", stale_self_key, "self node key"))
        missing_peer = status_fixture()
        missing_peer["Self"]["RoutePeers"].pop()
        cases.append(("missing peer", missing_peer, "lack a ready"))
        offline_peer = status_fixture()
        offline_peer["Self"]["RoutePeers"][0]["Online"] = False
        cases.append(("offline peer", offline_peer, "offline or expired"))
        expired_peer = status_fixture()
        expired_peer["Self"]["RoutePeers"][0]["Expired"] = True
        cases.append(("expired peer", expired_peer, "offline or expired"))
        failed_ping = status_fixture()
        failed_ping["Self"]["RoutePeers"][0]["Ping"]["Succeeded"] = False
        cases.append(("failed ping", failed_ping, "bounded data-plane ping"))
        expired_peer_key = status_fixture()
        expired_peer_key["Self"]["RoutePeers"][0]["KeyExpiry"] = CHECKED_AT
        cases.append(("expired peer key", expired_peer_key, "key is expired"))
        stale_ping = status_fixture()
        stale_ping["Self"]["RoutePeers"][0]["Ping"]["ObservedAt"] = (
            "2026-08-27T11:59:29Z"
        )
        cases.append(("stale ping", stale_ping, "bounded data-plane ping"))
        wrong_ping_peer = status_fixture()
        wrong_ping_peer["Self"]["RoutePeers"][0]["Ping"]["PeerID"] = "peer-other"
        cases.append(("wrong ping peer", wrong_ping_peer, "bounded data-plane ping"))
        for name, status, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                readiness.ReadinessError, message
            ):
                validate(status=status)

    def test_configured_remote_owners_reject_missing_duplicate_swapped_and_collapsed(self) -> None:
        owners = {
            REMOTE[0]: "peer-east-1",
            REMOTE[1]: "peer-east-2",
        }
        collapsed = status_fixture()
        shared_peer = collapsed["Self"]["RoutePeers"][0]["PeerID"]
        collapsed["Self"]["RoutePeers"][1]["PeerID"] = shared_peer
        collapsed["Self"]["RoutePeers"][1]["Ping"]["PeerID"] = shared_peer

        unconstrained = validate(status=collapsed)
        self.assertEqual(unconstrained["serving_peer_count"], 1)

        missing = status_fixture()
        missing["Self"]["RoutePeers"].pop()
        duplicate = status_fixture()
        duplicate["Self"]["RoutePeers"].append(
            copy.deepcopy(duplicate["Self"]["RoutePeers"][0])
        )
        swapped = status_fixture()
        first, second = swapped["Self"]["RoutePeers"]
        first["PeerID"], second["PeerID"] = second["PeerID"], first["PeerID"]
        first["Ping"]["PeerID"] = first["PeerID"]
        second["Ping"]["PeerID"] = second["PeerID"]
        for name, status, message in (
            ("missing", missing, "lack a ready"),
            ("duplicate", duplicate, "ambiguous"),
            ("swapped", swapped, "configured stable owner"),
            ("collapsed", collapsed, "configured stable owner"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                readiness.ReadinessError, message
            ):
                validate(status=status, expected_remote_prefix_owners=owners)

    def test_explicitly_disabled_key_expiry_accepts_an_old_control_plane_date(self) -> None:
        status = status_fixture()
        status["Self"]["KeyExpiry"] = CHECKED_AT
        status["Self"]["KeyExpiryDisabled"] = True
        for peer in status["Self"]["RoutePeers"]:
            peer["KeyExpiry"] = CHECKED_AT
            peer["KeyExpiryDisabled"] = True

        result = validate(status=status)

        self.assertTrue(result["ready"])
        self.assertTrue(
            all(
                peer["key_expiry_disabled"]
                for peer in result["route_serving_peers"]
            )
        )

        invalid_self = copy.deepcopy(status)
        invalid_self["Self"]["KeyExpiryDisabled"] = "true"
        with self.assertRaisesRegex(readiness.ReadinessError, "self node key-expiry mode"):
            validate(status=invalid_self)

        invalid_peer = copy.deepcopy(status)
        invalid_peer["Self"]["RoutePeers"][0]["KeyExpiryDisabled"] = None
        with self.assertRaisesRegex(readiness.ReadinessError, "key-expiry mode"):
            validate(status=invalid_peer)

    def test_local_advertisements_must_be_exact_and_without_snat(self) -> None:
        cases = {
            "missing": [],
            "wrong assignment": [LOCAL[1]],
            "broader": ["10.10.0.0/15", LOCAL[1]],
            "extra": [*LOCAL, "10.12.0.0/16"],
            "duplicate": [LOCAL[0], LOCAL[0], LOCAL[1]],
        }
        for name, advertised in cases.items():
            with self.subTest(name=name):
                status = status_fixture()
                status["Self"]["AdvertisedRoutes"] = advertised
                with self.assertRaisesRegex(
                    readiness.ReadinessError,
                    "advertisement|duplicate|non-empty",
                ):
                    validate(status=status)

        status = status_fixture()
        status["Self"]["NoSNAT"] = False
        with self.assertRaisesRegex(readiness.ReadinessError, "SNAT"):
            validate(status=status)

    def test_required_remote_routes_must_be_accepted(self) -> None:
        status = status_fixture()
        status["Self"]["AcceptedRoutes"] = [REMOTE[0]]

        with self.assertRaisesRegex(readiness.ReadinessError, "accepted remote routes"):
            validate(status=status)

    def test_requires_both_forward_and_mss_directions_without_nat(self) -> None:
        cases = []
        open_forward = transport_fixture()
        open_forward["filter_forward_policy"] = "ACCEPT"
        cases.append(("open FORWARD policy", open_forward, "fail closed"))
        extra_filter_hook = transport_fixture()
        extra_filter_hook["filter_forward_rules"].append(
            {"chain": "FORWARD", "action": "ACCEPT", "target": ""}
        )
        cases.append(("extra filter hook", extra_filter_hook, "only the approved"))
        wrong_filter_hook = transport_fixture()
        wrong_filter_hook["filter_forward_rules"][0]["target"] = "UNREVIEWED"
        cases.append(("wrong filter hook", wrong_filter_hook, "only the approved"))
        missing_forward = transport_fixture()
        missing_forward["forward_rules"].pop()
        cases.append(("forward", missing_forward, "FORWARD"))
        wrong_forward = transport_fixture()
        wrong_forward["forward_rules"][0]["output"] = "eth9"
        cases.append(("forward device", wrong_forward, "exact approved prefix"))
        wrong_forward_prefix = transport_fixture()
        wrong_forward_prefix["forward_rules"][0]["source"] = "10.12.0.0/16"
        cases.append(
            ("forward prefix", wrong_forward_prefix, "exact approved prefix")
        )
        extra_forward = transport_fixture()
        extra_forward["forward_rules"].append(
            {
                "chain": "ENVELOPE-TRANSPORT-FORWARD",
                "input": UNDERLAY,
                "output": TAILSCALE,
                "source": "0.0.0.0/0",
                "destination": "0.0.0.0/0",
                "action": "ACCEPT",
            }
        )
        cases.append(("extra effective forward rule", extra_forward, "FORWARD"))
        extra_mangle_hook = transport_fixture()
        extra_mangle_hook["mangle_forward_rules"].append(
            {"chain": "FORWARD", "action": "ACCEPT", "target": ""}
        )
        cases.append(("extra mangle hook", extra_mangle_hook, "only the approved"))
        missing_mss = transport_fixture()
        missing_mss["mss_rules"].pop()
        cases.append(("MSS", missing_mss, "MSS"))
        unsafe_mss = transport_fixture()
        unsafe_mss["mss_rules"][0]["mss"] = 1239
        cases.append(("unsafe MSS", unsafe_mss, "MSS policy"))
        wrong_mss_flags = transport_fixture()
        wrong_mss_flags["mss_rules"][0]["tcp_flags"] = "SYN SYN"
        cases.append(("wrong MSS flags", wrong_mss_flags, "MSS policy"))
        wrong_mss_prefix = transport_fixture()
        wrong_mss_prefix["mss_rules"][0]["destination"] = "10.22.0.0/16"
        cases.append(("wrong MSS prefix", wrong_mss_prefix, "exact approved prefix"))
        missing_mss_return = transport_fixture()
        missing_mss_return["mss_terminal_rules"] = []
        cases.append(("missing MSS return", missing_mss_return, "end in exactly one"))
        extra_mss_return = transport_fixture()
        extra_mss_return["mss_terminal_rules"].append(
            {"chain": "ENVELOPE-TRANSPORT-MSS", "action": "ACCEPT"}
        )
        cases.append(("rule after MSS return", extra_mss_return, "end in exactly one"))
        wrong_live_mtu = transport_fixture()
        wrong_live_mtu["tailscale_mtu"] = 575
        cases.append(("live MTU below contract", wrong_live_mtu, "mtu is invalid"))
        nat = transport_fixture()
        nat["nat_rules"] = ["-A POSTROUTING -j MASQUERADE"]
        cases.append(("NAT", nat, "NAT rewrite"))
        for name, transport, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(readiness.ReadinessError, message):
                validate(transport=transport)

        capped = transport_fixture()
        capped["tailscale_mtu"] = 1500
        result = validate(transport=capped)
        self.assertEqual(result["path_mtu"], 1500)
        self.assertEqual(result["tcp_mss"], 1240)

    def test_requires_forwarding_and_disabled_reverse_path_filtering(self) -> None:
        disabled = transport_fixture()
        disabled["ipv4_forwarding"] = False
        with self.assertRaisesRegex(readiness.ReadinessError, "IPv4 forwarding"):
            validate(transport=disabled)

        ipv6_enabled = transport_fixture()
        ipv6_enabled["ipv6_forwarding"] = True
        with self.assertRaisesRegex(readiness.ReadinessError, "IPv6 transit"):
            validate(transport=ipv6_enabled)

        ipv6_firewall_drift = transport_fixture()
        ipv6_firewall_drift["ipv6_forward_rules"].append(
            {"chain": "ENVELOPE-TRANSPORT-FORWARD", "action": "ACCEPT"}
        )
        with self.assertRaisesRegex(readiness.ReadinessError, "IPv6 transit"):
            validate(transport=ipv6_firewall_drift)

        strict = transport_fixture()
        strict["rp_filter"][UNDERLAY] = 1
        with self.assertRaisesRegex(readiness.ReadinessError, "reverse-path"):
            validate(transport=strict)

        incomplete = transport_fixture()
        del incomplete["rp_filter"]["default"]
        with self.assertRaisesRegex(readiness.ReadinessError, "wrong interfaces"):
            validate(transport=incomplete)

    def test_requires_remote_table52_and_local_underlay_paths(self) -> None:
        unrelated = transport_fixture()
        unrelated["table52_routes"].append(
            {"dst": "10.99.0.0/24", "dev": UNDERLAY, "type": "unicast"}
        )
        self.assertTrue(validate(transport=unrelated)["ready"])

        cases = []
        missing_remote = transport_fixture()
        missing_remote["table52_routes"] = [
            route
            for route in missing_remote["table52_routes"]
            if route.get("dst") != REMOTE[-1]
        ]
        cases.append(("missing remote", missing_remote, "isolated exact table-52"))
        remote_bypass = transport_fixture()
        remote_bypass["table52_routes"].append(
            {"dst": "10.20.1.0/24", "dev": UNDERLAY, "type": "unicast"}
        )
        cases.append(("remote bypass", remote_bypass, "isolated exact table-52"))
        local_bypass = transport_fixture()
        local_bypass["main_routes"].append(
            {"dst": "10.10.1.0/24", "dev": TAILSCALE, "type": "unicast"}
        )
        cases.append(("local bypass", local_bypass, "more-specific"))
        interior_blackhole = transport_fixture()
        interior_blackhole["table52_routes"].append(
            {"dst": "10.20.128.0/25", "type": "blackhole"}
        )
        cases.append(("interior blackhole", interior_blackhole, "isolated exact table-52"))
        source_specific = transport_fixture()
        source_specific["table52_routes"][0]["from"] = "10.10.0.0/16"
        cases.append(("source specific", source_specific, "source-specific"))
        interior_source_specific = transport_fixture()
        interior_source_specific["table52_routes"].append(
            {
                "dst": "10.20.128.0/25",
                "from": "10.10.128.0/25",
                "dev": TAILSCALE,
                "type": "unicast",
            }
        )
        cases.append(
            ("interior source specific", interior_source_specific, "source-specific")
        )
        for name, transport, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(readiness.ReadinessError, message):
                validate(transport=transport)

    def test_rejects_every_local_table52_intersection(self) -> None:
        cases = []
        sibling = transport_fixture()
        sibling["table52_routes"].append(
            {"dst": LOCAL[1], "dev": TAILSCALE, "type": "unicast"}
        )
        cases.append(("sibling", sibling))
        self_owned = transport_fixture()
        self_owned["table52_routes"].append(
            {"dst": LOCAL[0], "dev": TAILSCALE, "type": "unicast"}
        )
        cases.append(("self owned", self_owned))
        narrower = transport_fixture()
        narrower["table52_routes"].append(
            {"dst": "10.10.1.0/24", "dev": TAILSCALE, "type": "unicast"}
        )
        cases.append(("narrower", narrower))
        broader = transport_fixture()
        broader["table52_routes"].append(
            {"dst": "10.10.0.0/15", "dev": TAILSCALE, "type": "unicast"}
        )
        cases.append(("broader", broader))
        wrong_device = transport_fixture()
        wrong_device["table52_routes"].append(
            {"dst": LOCAL[0], "dev": UNDERLAY, "type": "unicast"}
        )
        cases.append(("wrong device", wrong_device))
        blackhole = transport_fixture()
        blackhole["table52_routes"].append(
            {"dst": LOCAL[0], "type": "blackhole"}
        )
        cases.append(("blackhole", blackhole))
        source_specific = transport_fixture()
        source_specific["table52_routes"].append(
            {
                "dst": LOCAL[0],
                "from": REMOTE[0],
                "dev": TAILSCALE,
                "type": "unicast",
            }
        )
        cases.append(("source specific", source_specific))
        for name, transport in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                readiness.ReadinessError, "intersects protected local prefixes"
            ):
                validate(transport=transport)

    def test_requires_exact_tailnet_to_underlay_policy_rules(self) -> None:
        cases = []
        missing = transport_fixture()
        missing["local_policy_rules"].pop()
        cases.append(("missing", missing, "exactly one"))
        wrong_input = transport_fixture()
        wrong_input["local_policy_rules"][0]["input"] = UNDERLAY
        cases.append(("wrong input", wrong_input, "bypass"))
        wrong_table = transport_fixture()
        wrong_table["local_policy_rules"][0]["table"] = 52
        cases.append(("wrong table", wrong_table, "bypass"))
        wrong_priority = transport_fixture()
        wrong_priority["local_policy_rules"][0]["priority"] = 99
        cases.append(("wrong priority", wrong_priority, "bypass"))
        source_specific = transport_fixture()
        source_specific["local_policy_rules"][0]["source"] = "10.20.0.0/16"
        cases.append(("source selector", source_specific, "bypass"))
        marked = transport_fixture()
        marked["local_policy_rules"][0]["fwmark"] = 1
        cases.append(("mark selector", marked, "bypass"))
        reordered = transport_fixture()
        reordered["local_policy_rules"].reverse()
        cases.append(("priority order", reordered, "priority order"))
        more_specific = transport_fixture()
        more_specific["local_policy_rules"][0]["destination"] = "10.10.1.0/24"
        cases.append(("partial prefix", more_specific, "bypass"))
        interior_source = transport_fixture()
        interior_source["local_policy_rules"].insert(
            0,
            {
                "priority": 99,
                "input": TAILSCALE,
                "source": "10.20.128.0/25",
                "destination": LOCAL[0],
                "fwmark": 0,
                "table": 52,
                "action": "lookup",
            },
        )
        cases.append(("interior source policy", interior_source, "bypass"))
        interior_destination = transport_fixture()
        interior_destination["local_policy_rules"].insert(
            0,
            {
                "priority": 99,
                "input": TAILSCALE,
                "source": "all",
                "destination": "10.10.128.0/25",
                "fwmark": 0,
                "table": 52,
                "action": "lookup",
            },
        )
        cases.append(("interior destination policy", interior_destination, "bypass"))
        for name, transport, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                readiness.ReadinessError, message
            ):
                validate(transport=transport)

    def test_requires_exact_ec2_eni_route_table_and_source_dest_check(self) -> None:
        enabled = transport_fixture()
        enabled["source_dest_check"] = True
        with self.assertRaisesRegex(readiness.ReadinessError, "source/destination"):
            validate(transport=enabled)
        wrong_eni = transport_fixture()
        wrong_eni["network_interface_id"] = "eni-1123456789abcdef0"
        with self.assertRaisesRegex(readiness.ReadinessError, "ENI identity"):
            validate(transport=wrong_eni)
        wrong_subnet = transport_fixture()
        wrong_subnet["subnet_id"] = "subnet-1123456789abcdef0"
        with self.assertRaisesRegex(readiness.ReadinessError, "subnet identity"):
            validate(transport=wrong_subnet)
        wrong_az = transport_fixture()
        wrong_az["availability_zone"] = "us-west-2b"
        with self.assertRaisesRegex(readiness.ReadinessError, "availability zone"):
            validate(transport=wrong_az)
        wrong_table = route_fixture()
        wrong_table["RouteTableId"] = "rtb-1123456789abcdef0"
        with self.assertRaisesRegex(readiness.ReadinessError, "route-table identity"):
            validate(routes=wrong_table)

        with self.assertRaisesRegex(readiness.ReadinessError, "GWLBE is not"):
            readiness.validate_readiness(
                status_fixture(),
                transport_fixture(),
                route_fixture(),
                LOCAL,
                REMOTE,
                LOCAL[0],
                GWLBE,
                ENI,
                SUBNET,
                ROUTE_TABLE,
                AZ,
                "us-west-2b",
                UNDERLAY,
                TAILSCALE,
                contract_fixture(),
            )

    def test_transport_subnet_must_be_associated_with_the_checked_route_table(self) -> None:
        missing = route_fixture()
        missing["Associations"] = []
        with self.assertRaisesRegex(readiness.ReadinessError, "one exact.*association"):
            validate(routes=missing)

        inactive = route_fixture()
        inactive["Associations"][0]["AssociationState"]["State"] = "disassociated"
        with self.assertRaisesRegex(readiness.ReadinessError, "not active"):
            validate(routes=inactive)

    def test_each_local_prefix_needs_an_active_exact_gwlbe_route(self) -> None:
        cases = []
        missing = route_fixture()
        missing["Routes"].pop()
        cases.append(("missing", missing, "one exact"))
        wrong_target = route_fixture()
        wrong_target["Routes"][0]["GatewayId"] = "vpce-1123456789abcdef0"
        cases.append(("wrong target", wrong_target, "does not select"))
        wrong_target_field = route_fixture()
        wrong_target_field["Routes"][0].pop("GatewayId")
        wrong_target_field["Routes"][0]["VpcEndpointId"] = GWLBE
        cases.append(("wrong target field", wrong_target_field, "does not select"))
        mixed_target = route_fixture()
        mixed_target["Routes"][0]["InstanceId"] = "i-0123456789abcdef0"
        cases.append(("mixed target fields", mixed_target, "does not select"))
        inactive = route_fixture()
        inactive["Routes"][0]["State"] = "blackhole"
        cases.append(("inactive", inactive, "not active"))
        bypass = route_fixture()
        bypass["Routes"].append(
            {"DestinationCidrBlock": "10.10.1.0/24", "GatewayId": "local", "State": "active"}
        )
        cases.append(("more specific bypass", bypass, "more-specific"))
        for name, routes, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(readiness.ReadinessError, message):
                    validate(routes=routes)

    def test_rejects_overlapping_site_route_domains(self) -> None:
        remote = ["10.10.128.0/17"]
        contract = readiness.build_readiness_contract(
            LOCAL, remote, UNDERLAY, TAILSCALE, readiness.MAX_TCP_MSS
        )
        contract["contract_sha256"] = readiness.readiness_contract_sha256(contract)
        with self.assertRaisesRegex(readiness.ReadinessError, "overlap"):
            readiness.validate_readiness(
                status_fixture(),
                transport_fixture(),
                route_fixture(),
                LOCAL,
                remote,
                LOCAL[0],
                GWLBE,
                ENI,
                SUBNET,
                ROUTE_TABLE,
                AZ,
                AZ,
                UNDERLAY,
                TAILSCALE,
                contract,
            )

    def test_cli_reads_bounded_local_fixtures_without_cloud_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            status_path = directory / "status.json"
            transport_path = directory / "transport.json"
            routes_path = directory / "routes.json"
            contract_path = directory / "contract.json"
            status_path.write_text(json.dumps(status_fixture()))
            transport_path.write_text(json.dumps(transport_fixture()))
            routes_path.write_text(json.dumps(route_fixture()))
            contract_path.write_text(json.dumps(contract_fixture()))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/transport_router_readiness.py"),
                    "--status-file",
                    str(status_path),
                    "--transport-file",
                    str(transport_path),
                    "--vpc-routes-file",
                    str(routes_path),
                    "--contract-file",
                    str(contract_path),
                    "--local-site-cidr",
                    LOCAL[0],
                    "--local-site-cidr",
                    LOCAL[1],
                    "--remote-site-cidr",
                    REMOTE[0],
                    "--remote-site-cidr",
                    REMOTE[1],
                    "--advertised-prefix",
                    LOCAL[0],
                    "--local-gwlbe",
                    GWLBE,
                    "--network-interface-id",
                    ENI,
                    "--subnet-id",
                    SUBNET,
                    "--route-table-id",
                    ROUTE_TABLE,
                    "--availability-zone",
                    AZ,
                    "--local-gwlbe-availability-zone",
                    AZ,
                    "--underlay-interface",
                    UNDERLAY,
                    "--tailscale-interface",
                    TAILSCALE,
                ],
                text=True,
                capture_output=True,
                check=False,
                env={},
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["ready"], True)

    def test_input_size_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "oversized.json"
            path.write_bytes(b" " * (readiness.MAX_INPUT_BYTES + 1))
            with self.assertRaisesRegex(readiness.ReadinessError, "input limit"):
                readiness.load_json(path)


if __name__ == "__main__":
    unittest.main()
