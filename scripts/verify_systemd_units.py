#!/usr/bin/env python3
"""Verify target and transport host-network units without claiming live readiness.

The transport unit owns only host sysctls, firewall policy, and MSS clamping.
Protected readiness separately validates Tailscale peers/routes and AWS ENI/GWLBE
state from credentialed, bounded observations.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_TEMPLATE = ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl"
TRANSPORT_TEMPLATE = ROOT / "example/terraform/cloud-init/transport-router.sh.tftpl"
TARGET_UNIT = "envelope.service"
TRANSPORT_UNIT = "envelope-transport-router-network.service"


def extract_units(text: str) -> dict[str, str]:
    pattern = re.compile(
        r"cat >/etc/systemd/system/(?P<name>[a-z0-9-]+\.service) <<'(?P<marker>[A-Z_]+)'\n(?P<body>.*?)\n(?P=marker)",
        re.DOTALL,
    )
    units: dict[str, str] = {}
    for match in pattern.finditer(text):
        name = match.group("name")
        if name in units:
            raise RuntimeError(f"duplicate rendered systemd unit: {name}")
        units[name] = match.group("body") + "\n"
    return units


def extract_script(text: str, path: str) -> str:
    match = re.search(
        rf"cat >{re.escape(path)} <<'(?P<marker>[A-Z_]+)'\n(?P<body>.*?)\n(?P=marker)",
        text,
        re.DOTALL,
    )
    if not match:
        raise RuntimeError(f"cannot extract rendered script: {path}")
    return match.group("body") + "\n"


def directive_values(unit: str, name: str) -> list[str]:
    return re.findall(rf"^{re.escape(name)}=(.*)$", unit, re.MULTILINE)


def require_all(text: str, values: tuple[str, ...], message: str) -> None:
    missing = [value for value in values if value not in text]
    if missing:
        raise RuntimeError(f"{message}: {', '.join(missing)}")


def prohibit_all(text: str, values: tuple[str, ...], message: str) -> None:
    present = [value for value in values if value in text]
    if present:
        raise RuntimeError(f"{message}: {', '.join(present)}")


def verify_target_contract(text: str, unit: str) -> None:
    required_environment = (
        "ENVELOPE_CONFIG_VERSION=${config_version}",
        "ENVELOPE_MODE=${mode}",
        "ENVELOPE_UDP_BIND=${udp_bind}",
        "ENVELOPE_MAX_INNER_PACKET_SIZE=${max_inner_packet_size}",
    )
    require_all(
        text,
        required_environment,
        "target environment omits the version-2 packet-return contract",
    )
    prohibit_all(
        text,
        (
            "ENVELOPE_GWLB_RETURN_CIDRS",
            "ENVELOPE_LOCAL_DELIVERY_CIDRS",
            "ENVELOPE_REMOTE_TAILNET_CIDRS",
            "ENVELOPE_LOCAL_SITE_CIDRS",
            "ENVELOPE_REMOTE_SITE_CIDRS",
            "ENVELOPE_TUN",
            "ENVELOPE_ROUTING",
            "tailscale",
            "envelope0",
            "iptables",
            "nft ",
            "sysctl",
            "TCPMSS",
            "host-network",
            "CAP_NET_ADMIN",
        ),
        "target template retains a transport-router or obsolete forwarding contract",
    )
    if re.search(
        r"(?i)\b(?:tun|envelope0|tailscaled?|ip_forward|forward_chain|direct[- ]forward)\b",
        text,
    ):
        raise RuntimeError("target template retains TUN or direct-forwarding behavior")

    require_all(
        unit,
        (
            "Description=Envelope AWS GWLB packet-return target",
            "After=network-online.target",
            "Wants=network-online.target",
            "User=envelope",
            "Group=envelope",
            "ExecStartPre=/usr/local/sbin/envelope-preflight",
            "ExecStart=/usr/local/bin/envelope",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "NoNewPrivileges=yes",
        ),
        "Envelope target unit omits its unprivileged packet-return contract",
    )
    if directive_values(unit, "CapabilityBoundingSet") != ["CAP_NET_RAW"]:
        raise RuntimeError("target capability bounding set must be exactly CAP_NET_RAW")
    if directive_values(unit, "AmbientCapabilities") != ["CAP_NET_RAW"]:
        raise RuntimeError("target ambient capabilities must be exactly CAP_NET_RAW")
    if re.search(r"^User=root$", unit, re.MULTILINE):
        raise RuntimeError("Envelope target process must not run as root")
    if re.search(r"^(?:Requires|PartOf)=.*tailscaled", unit, re.MULTILINE):
        raise RuntimeError("Envelope target unit must not depend on tailscaled")
    if text.count("CAP_NET_RAW") != 2:
        raise RuntimeError("CAP_NET_RAW must occur only in target unit capability directives")


def verify_transport_contract(text: str, unit: str) -> None:
    if re.search(r"(?i)ingress[-_ ]router", text):
        raise RuntimeError("transport template retains obsolete ingress-router naming")
    network_path = "/usr/local/sbin/envelope-transport-router-network"
    network = extract_script(text, network_path)
    require_all(
        network,
        (
            'readonly mode="$${1:-activate}"',
            "readonly local_site_cidrs_json='${local_site_cidrs_json}'",
            "readonly remote_site_cidrs_json='${remote_site_cidrs_json}'",
            "readonly approved_maximum_tcp_mss='${approved_maximum_tcp_mss}'",
            "readonly policy_rule_priority_base='${policy_rule_priority_base}'",
            "readonly contract_sha256='${contract_sha256}'",
            "readonly forward_chain='ENVELOPE-TRANSPORT-FORWARD'",
            "readonly mss_chain='ENVELOPE-TRANSPORT-MSS'",
            "readonly local_route_table=main",
            "readonly remote_route_table=52",
            "readonly readiness_marker=/var/lib/envelope/transport-router-network.ready",
            "readonly runtime_state=/var/lib/envelope/transport-router-network.state.json",
            "readonly recovery_marker=/var/lib/envelope/transport-router-network.configured",
            '/usr/bin/rm -f "$readiness_marker" "$runtime_state"',
            "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=0",
            "/usr/sbin/sysctl -q -w net.ipv6.conf.all.forwarding=0",
            "/usr/sbin/iptables --wait 10 -P FORWARD DROP",
            "/usr/sbin/iptables --wait 10 -t mangle -P FORWARD ACCEPT",
            "/usr/sbin/ip6tables --wait 10 -P FORWARD DROP",
            "/usr/sbin/ip6tables --wait 10 -t mangle -P FORWARD ACCEPT",
            "expected_ipv4_policy_rules=$(/usr/bin/jq -cn",
            '.mangle_forward_policy == "ACCEPT"',
            '.ipv6_mangle_forward_policy == "ACCEPT"',
            ".ipv4_policy_rules == $policy_rules",
            '.local_route_table == "main"',
            ".remote_route_table == 52",
            '.recovery_marker == "/var/lib/envelope/transport-router-network.configured"',
            'reconcile_policy_rules',
            "remote_routes_ready || fail 'exact remote-site routes are not live in Tailscale table 52'",
            '-i "$underlay" -o "$tailscale" -s "$local_cidr" -d "$remote_cidr" -j ACCEPT',
            '-i "$tailscale" -o "$underlay" -s "$remote_cidr" -d "$local_cidr" -j ACCEPT',
            "unrelated $binary $table FORWARD state exists; refusing to flush it",
            'configure_chain /usr/sbin/iptables filter "$forward_chain"',
            'configure_chain /usr/sbin/iptables mangle "$mss_chain"',
            'tailscale_mtu=$(interface_mtu "$tailscale")',
            "tailscale0 must be live before transport firewall setup",
            '-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$ipv4_mss"',
            '/usr/sbin/iptables --wait 10 -t mangle -A "$mss_chain" -j RETURN',
            'approved_maximum_tcp_mss < ipv4_mss',
            '"$runtime_state"',
            "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1",
            "/usr/sbin/sysctl -q -w net.ipv6.conf.all.forwarding=0",
            'touch "$readiness_marker"',
        ),
        "transport network script omits the fail-closed forwarding contract",
    )
    prohibit_all(
        network,
        (
            "nft flush ruleset",
            "-j SNAT",
            "-j MASQUERADE",
            "sysctl --system",
            "sysctl -p",
            "ENVELOPE-INGRESS-FORWARD",
            "ENVELOPE-INGRESS-MSS",
            "tailscale status",
            "tailscale ping",
            "tailscale debug",
            "headscale",
            "aws ec2",
            "NetworkInterfaceId",
            "RoutePeers",
            "source_dest_check",
            "network_interface_id",
            "VpcEndpointId",
            "PingSucceeded",
        ),
        "transport network script contains a broad mutation or protected-readiness check",
    )
    if re.search(
        r"/usr/sbin/ip6?tables --wait 10 (?!-t mangle )-P FORWARD ACCEPT",
        network,
    ):
        raise RuntimeError("transport filter FORWARD policy must not be ACCEPT")
    if re.search(
        r'(?m)^\s*(?:"\$binary"|/usr/sbin/ip6?tables)[^\n]* -F(?:\s*$|\s+FORWARD(?:\s|$))',
        network,
    ):
        raise RuntimeError("transport network script must flush only its owned chains")
    if re.search(
        r"(?im)^\s*/usr/sbin/nft\b[^\n]*\bflush\s+(?:ruleset|table)\b", network
    ):
        raise RuntimeError("transport network script must not broadly flush nftables")

    stage_firewall = network.index("\nstage_firewall\n")
    wait_for_tailscale = network.index("tailscale0 must be live before transport firewall setup")
    reconcile_policy = network.index("\nreconcile_policy_rules\n", wait_for_tailscale)
    read_live_mtu = network.index('tailscale_mtu=$(interface_mtu "$tailscale")')
    install_scoped_rules = network.index('for local_cidr in "$${local_site_cidrs[@]}"')
    persist_runtime_state = network.index("state_tmp=$(/usr/bin/mktemp")
    enable_forwarding = network.rindex(
        "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1"
    )
    publish_readiness = network.rindex('touch "$readiness_marker"')
    if not (
        stage_firewall
        < wait_for_tailscale
        < reconcile_policy
        < read_live_mtu
        < install_scoped_rules
        < persist_runtime_state
        < enable_forwarding
        < publish_readiness
    ):
        raise RuntimeError(
            "transport must stage fail-closed state, reconcile host policy, and persist its contract before forwarding"
        )

    require_all(
        unit,
        (
            "Description=Envelope transport-router host-network contract",
            "After=network-online.target tailscaled.service",
            "Requires=tailscaled.service",
            "PartOf=tailscaled.service",
            "User=root",
            "Environment=XTABLES_LOCKFILE=/run/envelope-transport-router-network/xtables.lock",
            f"ExecStart={network_path} activate",
            f"ExecReload={network_path} activate",
            "ExecStop=/usr/bin/rm -f /var/lib/envelope/transport-router-network.ready /var/lib/envelope/transport-router-network.state.json",
            "RemainAfterExit=yes",
            "RuntimeDirectory=envelope-transport-router-network",
            "RuntimeDirectoryMode=0700",
            "ProtectSystem=strict",
            "ReadWritePaths=/run/envelope-transport-router-network /var/lib/envelope",
            "NoNewPrivileges=yes",
        ),
        "transport unit omits its ordered root host-network contract",
    )
    expected_capabilities = ["CAP_NET_ADMIN CAP_NET_RAW"]
    if directive_values(unit, "CapabilityBoundingSet") != expected_capabilities:
        raise RuntimeError(
            "transport capability bounding set must be exactly CAP_NET_ADMIN CAP_NET_RAW"
        )
    if directive_values(unit, "AmbientCapabilities") != expected_capabilities:
        raise RuntimeError(
            "transport ambient capabilities must be exactly CAP_NET_ADMIN CAP_NET_RAW"
        )
    if directive_values(unit, "ReadWritePaths") != [
        "/run/envelope-transport-router-network /var/lib/envelope"
    ]:
        raise RuntimeError("transport unit may write only its runtime and owned state directories")
    unit_block = re.search(
        rf"cat >/etc/systemd/system/{re.escape(TRANSPORT_UNIT)} <<'(?P<marker>[A-Z_]+)'\n.*?\n(?P=marker)",
        text,
        re.DOTALL,
    )
    if not unit_block:
        raise RuntimeError("cannot locate transport unit source block")
    outside_unit = text[: unit_block.start()] + text[unit_block.end() :]
    if "CAP_NET_ADMIN" in outside_unit or "CAP_NET_RAW" in outside_unit:
        raise RuntimeError("transport capabilities must appear only in its systemd unit")

    if "systemctl enable --now" in text:
        raise RuntimeError("transport network unit must not start before tailscaled is live")
    if "systemctl enable envelope-transport-router-network.service" not in text:
        raise RuntimeError("transport network unit must be enabled for subsequent boots")
    if f"{network_path} stage" not in text:
        raise RuntimeError("transport bootstrap must stage fail-closed firewall state before Tailscale")


def verify_privilege_contract(
    target_text: str, transport_text: str, units: dict[str, str]
) -> None:
    expected = {TARGET_UNIT, TRANSPORT_UNIT}
    if set(units) != expected:
        raise RuntimeError(f"expected units {sorted(expected)}, found {sorted(units)}")
    verify_target_contract(target_text, units[TARGET_UNIT])
    verify_transport_contract(transport_text, units[TRANSPORT_UNIT])
    if "CAP_NET_ADMIN" in units[TARGET_UNIT]:
        raise RuntimeError("CAP_NET_ADMIN must remain isolated to the transport unit")
    if "CAP_NET_RAW" not in units[TARGET_UNIT] or "CAP_NET_RAW" not in units[TRANSPORT_UNIT]:
        raise RuntimeError("target and transport units must declare their distinct raw-I/O needs")


def extract_all_units(target_text: str, transport_text: str) -> dict[str, str]:
    units: dict[str, str] = {}
    for text in (target_text, transport_text):
        for name, body in extract_units(text).items():
            if name in units:
                raise RuntimeError(f"unit rendered by multiple templates: {name}")
            units[name] = body
    return units


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ubuntu:24.04")
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="verify extracted source contracts without running systemd-analyze",
    )
    args = parser.parse_args()
    target_text = TARGET_TEMPLATE.read_text()
    if not TRANSPORT_TEMPLATE.is_file():
        raise RuntimeError(
            f"current transport-router template is missing: {TRANSPORT_TEMPLATE}"
        )
    transport_text = TRANSPORT_TEMPLATE.read_text()
    units = extract_all_units(target_text, transport_text)
    verify_privilege_contract(target_text, transport_text, units)
    if args.source_only:
        print("target and transport host-network source contracts passed")
        return 0

    docker = shutil.which("docker")
    docker_ready = False
    if docker is not None:
        try:
            docker_ready = (
                subprocess.run(
                    [docker, "info"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                ).returncode
                == 0
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not docker_ready:
        print(
            "systemd source contracts passed; systemd-analyze skipped: "
            "a running Docker daemon is required",
            file=sys.stderr,
        )
        return 77
    assert docker is not None

    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        for name, content in units.items():
            (directory / name).write_text(content)
        command = [
            docker,
            "run",
            "--rm",
            "--volume",
            f"{directory}:/units:ro",
            args.image,
            "bash",
            "-euc",
            """
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq systemd >/dev/null
install -d /usr/local/bin /usr/local/sbin /etc/envelope /var/lib/envelope
for executable in /usr/local/bin/envelope /usr/local/sbin/envelope-preflight /usr/local/sbin/envelope-transport-router-network; do
  printf '#!/bin/sh\\nexit 0\\n' >"$executable"
  chmod 0755 "$executable"
done
touch /etc/envelope/site.env /etc/envelope/artifact.env
cat >/etc/systemd/system/tailscaled.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/true
UNIT
cp /units/*.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/envelope.service /etc/systemd/system/envelope-transport-router-network.service
""",
        ]
        subprocess.run(command, check=True, timeout=300)
    print("target and transport systemd unit verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
