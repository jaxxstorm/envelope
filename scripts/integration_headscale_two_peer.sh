#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "harness command failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

HEADSCALE_IMAGE='headscale/headscale:0.25.1@sha256:a7a8ae9616bb964a3eed8101ebb020213f73668142a84806ec37a5eeb2c1fceb'
TAILSCALE_IMAGE='tailscale/tailscale:v1.80.3@sha256:af6026ed3e5892c5d4966962618a09685198111507df16803b2aec7066046582'
PLATFORM=${ENVELOPE_INTEGRATION_PLATFORM:-linux/amd64}

for command in docker go python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 77
  fi
done
if ! python3 -c 'import subprocess,sys; sys.exit(subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode)' 2>/dev/null; then
  printf '%s\n' 'a running Docker daemon is required' >&2
  exit 77
fi
python3 scripts/verify_systemd_units.py --source-only >/dev/null

run_id="$$-$(date +%s)"
global_network="envelope-headscale-$run_id"
a_target_underlay="envelope-a-target-$run_id"
a_workload_pre="envelope-a-workload-pre-$run_id"
a_workload_post="envelope-a-workload-post-$run_id"
a_gwlbe_post="envelope-a-gwlbe-post-$run_id"
a_transport_underlay="envelope-a-transport-router-$run_id"
b_workload_pre="envelope-b-workload-pre-$run_id"
b_workload_post="envelope-b-workload-post-$run_id"
b_gwlbe_post="envelope-b-gwlbe-post-$run_id"
b_transport_underlay="envelope-b-transport-router-$run_id"
b_target_underlay="envelope-b-target-$run_id"
networks=(
  "$global_network"
  "$a_target_underlay" "$a_workload_pre" "$a_workload_post" "$a_gwlbe_post" "$a_transport_underlay"
  "$b_target_underlay" "$b_workload_pre" "$b_workload_post" "$b_gwlbe_post" "$b_transport_underlay"
)

headscale="envelope-headscale-control-$run_id"
target_a="envelope-target-a-$run_id"
target_b="envelope-target-b-$run_id"
gwlbe_a="envelope-gwlbe-a-$run_id"
gwlbe_b="envelope-gwlbe-b-$run_id"
post_a="envelope-post-a-$run_id"
post_b="envelope-post-b-$run_id"
workload_a="envelope-workload-a-$run_id"
workload_b="envelope-workload-b-$run_id"
transport_a1="envelope-transport-router-a1-$run_id"
transport_a2="envelope-transport-router-a2-$run_id"
transport_b1="envelope-transport-router-b1-$run_id"
transport_b2="envelope-transport-router-b2-$run_id"
containers=(
  "$target_a" "$target_b" "$gwlbe_a" "$gwlbe_b" "$post_a" "$post_b"
  "$workload_a" "$workload_b" "$transport_a1" "$transport_a2"
  "$transport_b1" "$transport_b2" "$headscale"
)
work_dir=$(mktemp -d)

diagnostics() {
  printf '%s\n' 'Headscale separated-role integration diagnostics:' >&2
  for target in "$target_a" "$target_b"; do
    if docker inspect "$target" >/dev/null 2>&1; then
      printf '\n== %s ==\n' "$target" >&2
      docker logs "$target" >&2 || true
    fi
  done
  for endpoint in "$gwlbe_a" "$gwlbe_b"; do
    if docker inspect "$endpoint" >/dev/null 2>&1; then
      printf '\n== %s ==\n' "$endpoint" >&2
      docker exec "$endpoint" sh -c 'test ! -f /tmp/gwlb.log || tail -n 80 /tmp/gwlb.log' >&2 || true
      docker exec "$endpoint" sh -c 'test ! -f /tmp/gwlb-error || cat /tmp/gwlb-error' >&2 || true
      docker exec "$endpoint" sh -c 'test ! -f /tmp/gwlb-events.jsonl || tail -n 20 /tmp/gwlb-events.jsonl' >&2 || true
    fi
  done
  for router in "$transport_a1" "$transport_a2" "$transport_b1" "$transport_b2"; do
    if docker inspect "$router" >/dev/null 2>&1; then
      printf '\n== %s routes/firewall ==\n' "$router" >&2
      docker exec "$router" ip rule show >&2 || true
      docker exec "$router" ip route show table main >&2 || true
      docker exec "$router" ip route show table 52 >&2 || true
      docker exec "$router" nft -j list ruleset >&2 || true
      docker exec "$router" iptables -L FORWARD -n -v >&2 || true
      docker exec "$router" iptables -L ENVELOPE-TRANSPORT-FORWARD -n -v >&2 || true
      docker exec "$router" iptables -t mangle -L FORWARD -n -v >&2 || true
      docker exec "$router" iptables -t mangle -L ENVELOPE-TRANSPORT-MSS -n -v >&2 || true
    fi
  done
  for domain in "$post_a" "$post_b"; do
    if docker inspect "$domain" >/dev/null 2>&1; then
      printf '\n== %s post-inspection domain ==\n' "$domain" >&2
      docker exec "$domain" ip -s link show >&2 || true
      docker exec "$domain" ip route show table main >&2 || true
      docker exec "$domain" ip neighbor show >&2 || true
      docker exec "$domain" sh -c 'cat /proc/sys/net/ipv4/ip_forward' >&2 || true
    fi
  done
}

cleanup() {
  for container in "${containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  for network in "${networks[@]}"; do
    docker network rm "$network" >/dev/null 2>&1 || true
  done
  rm -rf "$work_dir"
}

finish() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    diagnostics
  fi
  cleanup
  exit "$status"
}
trap finish EXIT

mkdir -p "$work_dir/headscale-state"
chmod 0777 "$work_dir/headscale-state"

cat >"$work_dir/headscale.yaml" <<'YAML'
server_url: http://headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 0.0.0.0:9090
grpc_listen_addr: 0.0.0.0:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: local
    region_name: Local Integration DERP
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
    wal_autocheckpoint: 1000
tls_cert_path: ""
tls_key_path: ""
log:
  format: text
  level: warn
policy:
  mode: file
  path: /etc/headscale/acl.hujson
dns:
  magic_dns: false
  base_domain: integration.invalid
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
randomize_client_port: false
YAML

cat >"$work_dir/render-transport-contract.py" <<'PY'
import hashlib
import json
import pathlib
import re
import sys


template_path, output_path, underlay, tailscale, local_cidr, remote_cidr = sys.argv[1:]
priority_base = 100
maximum_mss = 1240
contract = {
    "config_version": 2,
    "local_site_cidrs": [local_cidr],
    "remote_site_cidrs": [remote_cidr],
    "underlay_interface": underlay,
    "tailscale_interface": tailscale,
    "approved_maximum_tcp_mss": maximum_mss,
    "ipv4_forwarding": True,
    "ipv6_forwarding": False,
    "filter_forward_policy": "DROP",
    "mangle_forward_policy": "ACCEPT",
    "filter_forward_rules": [
        {"chain": "FORWARD", "action": "JUMP", "target": "ENVELOPE-TRANSPORT-FORWARD"}
    ],
    "mangle_forward_rules": [
        {"chain": "FORWARD", "action": "JUMP", "target": "ENVELOPE-TRANSPORT-MSS"}
    ],
    "mss_terminal_rules": [
        {"chain": "ENVELOPE-TRANSPORT-MSS", "action": "RETURN"}
    ],
    "nat_rules": [],
    "ipv6_filter_forward_policy": "DROP",
    "ipv6_mangle_forward_policy": "ACCEPT",
    "ipv6_filter_forward_rules": [
        {"chain": "FORWARD", "action": "JUMP", "target": "ENVELOPE-TRANSPORT-FORWARD"}
    ],
    "ipv6_forward_rules": [],
    "ipv6_mangle_forward_rules": [],
    "readiness_marker": "/var/lib/envelope/transport-router-network.ready",
    "runtime_state": "/var/lib/envelope/transport-router-network.state.json",
    "recovery_marker": "/var/lib/envelope/transport-router-network.configured",
    "mss_formula": "min(min(underlay_mtu,tailscale_mtu)-40,approved_maximum_tcp_mss)",
    "policy_rule_priority_base": priority_base,
    "local_route_table": "main",
    "remote_route_table": 52,
    "local_policy_rules": [
        {
            "priority": priority_base,
            "input": tailscale,
            "source": "all",
            "destination": local_cidr,
            "fwmark": 0,
            "table": "main",
            "action": "lookup",
        }
    ],
    "ipv4_policy_rules": [
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
        {
            "priority": priority_base,
            "input": tailscale,
            "source": "all",
            "destination": local_cidr,
            "fwmark": 0,
            "fwmask": 0,
            "table": "main",
            "action": "lookup",
        },
        {
            "priority": 5210,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 524288,
            "fwmask": 16711680,
            "table": "main",
            "action": "lookup",
        },
        {
            "priority": 5230,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 524288,
            "fwmask": 16711680,
            "table": "default",
            "action": "lookup",
        },
        {
            "priority": 5250,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 524288,
            "fwmask": 16711680,
            "table": "none",
            "action": "unreachable",
        },
        {
            "priority": 5270,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 0,
            "fwmask": 0,
            "table": "52",
            "action": "lookup",
        },
        {
            "priority": 32766,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 0,
            "fwmask": 0,
            "table": "main",
            "action": "lookup",
        },
        {
            "priority": 32767,
            "input": "all",
            "source": "all",
            "destination": "all",
            "fwmark": 0,
            "fwmask": 0,
            "table": "default",
            "action": "lookup",
        },
    ],
    "forward_rules": [
        {
            "chain": "ENVELOPE-TRANSPORT-FORWARD",
            "input": underlay,
            "output": tailscale,
            "source": local_cidr,
            "destination": remote_cidr,
            "action": "ACCEPT",
        },
        {
            "chain": "ENVELOPE-TRANSPORT-FORWARD",
            "input": tailscale,
            "output": underlay,
            "source": remote_cidr,
            "destination": local_cidr,
            "action": "ACCEPT",
        },
    ],
    "mss_rules": [
        {
            "chain": "ENVELOPE-TRANSPORT-MSS",
            "input": underlay,
            "output": tailscale,
            "source": local_cidr,
            "destination": remote_cidr,
            "protocol": "tcp",
            "tcp_flags": "SYN,RST SYN",
            "action": "TCPMSS",
        },
        {
            "chain": "ENVELOPE-TRANSPORT-MSS",
            "input": tailscale,
            "output": underlay,
            "source": remote_cidr,
            "destination": local_cidr,
            "protocol": "tcp",
            "tcp_flags": "SYN,RST SYN",
            "action": "TCPMSS",
        },
    ],
}
contract_json = json.dumps(contract, sort_keys=True, separators=(",", ":"))
template = pathlib.Path(template_path).read_text(encoding="utf-8")
match = re.search(
    r"cat >/usr/local/sbin/envelope-transport-router-network <<'HOST_NETWORK'\n(.*?)\nHOST_NETWORK",
    template,
    re.DOTALL,
)
if not match:
    raise SystemExit("cannot extract production transport host-network contract")
script = match.group(1) + "\n"
replacements = {
    "${underlay_interface}": underlay,
    "${tailscale_interface}": tailscale,
    "${local_site_cidrs_json}": json.dumps([local_cidr], separators=(",", ":")),
    "${remote_site_cidrs_json}": json.dumps([remote_cidr], separators=(",", ":")),
    "${approved_maximum_tcp_mss}": str(maximum_mss),
    "${policy_rule_priority_base}": str(priority_base),
    "${readiness_expectations_json}": contract_json,
    "${contract_sha256}": hashlib.sha256(contract_json.encode()).hexdigest(),
}
for placeholder, value in replacements.items():
    script = script.replace(placeholder, value)
script = script.replace("$${", "${")
if any(placeholder in script for placeholder in replacements) or "$${" in script:
    raise SystemExit("production transport host-network contract was not fully rendered")
output = pathlib.Path(output_path)
output.write_text(script, encoding="utf-8")
output.chmod(0o755)
print(hashlib.sha256(script.encode()).hexdigest())
PY

cat >"$work_dir/acl.hujson" <<'HUJSON'
{
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
}
HUJSON

cat >"$work_dir/gwlb-loop.py" <<'PY'
import hashlib
import ipaddress
import json
import os
import pathlib
import select
import socket
import struct
import sys
import time
import traceback


(
    target,
    post_interface,
    post_peer_mac,
    event_path,
    ready_path,
    local_cidr,
    remote_cidr,
    *specs,
) = sys.argv[1:]

target_address = (socket.gethostbyname(target), 6081)
approved_networks = (ipaddress.ip_network(local_cidr), ipaddress.ip_network(remote_cidr))
inputs = {}
router_specs = []
for spec in specs:
    kind, value = spec.split("=", 1)
    if kind in {"workload", "transport-router"}:
        inputs[kind] = value
    elif kind == "router":
        router_specs.append(value)
    else:
        raise SystemExit(f"unknown fake GWLBE input specification: {kind}")
if set(inputs) != {"workload", "transport-router"}:
    raise SystemExit("exact workload and transport-router GWLBE inputs are required")


def parse_mac(value):
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("invalid post-inspection peer MAC")
    return bytes(int(part, 16) for part in parts)


def interface_mac(interface):
    return parse_mac(pathlib.Path("/sys/class/net", interface, "address").read_text().strip())


transport_router_macs = {}
for spec in router_specs:
    mac, identity = spec.split(",", 1)
    parsed = parse_mac(mac)
    if parsed in transport_router_macs or "transport-router" not in identity:
        raise SystemExit("transport-router MAC observations must be unique and identified")
    transport_router_macs[parsed] = identity
if len(transport_router_macs) != 2:
    raise SystemExit("exactly two observable local transport routers are required")


def packet_fields(inner):
    if len(inner) < 20 or inner[0] >> 4 != 4:
        raise ValueError("fake GWLBE received a non-IPv4 inner packet")
    total = struct.unpack("!H", inner[2:4])[0]
    if total < 20 or total > len(inner):
        raise ValueError("fake GWLBE received an invalid inner length")
    inner = inner[:total]
    source = str(ipaddress.ip_address(inner[12:16]))
    destination = str(ipaddress.ip_address(inner[16:20]))
    if not any(ipaddress.ip_address(source) in network for network in approved_networks):
        raise ValueError("inner source is outside the two test sites")
    if not any(ipaddress.ip_address(destination) in network for network in approved_networks):
        raise ValueError("inner destination is outside the two test sites")
    fragment = struct.unpack("!H", inner[6:8])[0]
    return inner, {
        "source": source,
        "destination": destination,
        "protocol": inner[9],
        "ip_id": struct.unpack("!H", inner[4:6])[0],
        "fragment_offset": fragment & 0x1FFF,
        "more_fragments": bool(fragment & 0x2000),
    }


def packet_correlation_sha256(inner):
    normalized = bytearray(inner)
    header_length = (normalized[0] & 0x0F) * 4
    if header_length < 20 or header_length > len(normalized):
        raise ValueError("fake GWLBE received an invalid IPv4 header length")
    # Normalize routed TTL/checksum updates and the reviewed TCP MSS clamp.
    normalized[8] = 0
    normalized[10:12] = b"\x00\x00"
    fragment = struct.unpack("!H", normalized[6:8])[0]
    if normalized[9] == 6 and fragment & 0x1FFF == 0 and len(normalized) >= header_length + 20:
        tcp_offset = header_length
        normalized[tcp_offset + 16 : tcp_offset + 18] = b"\x00\x00"
        tcp_header_length = (normalized[tcp_offset + 12] >> 4) * 4
        option_offset = tcp_offset + 20
        option_end = min(tcp_offset + tcp_header_length, len(normalized))
        while option_offset < option_end:
            kind = normalized[option_offset]
            if kind == 0:
                break
            if kind == 1:
                option_offset += 1
                continue
            if option_offset + 1 >= option_end:
                break
            length = normalized[option_offset + 1]
            if length < 2 or option_offset + length > option_end:
                break
            if kind == 2 and length == 4:
                # The production transport contract clamps SYN MSS in transit.
                normalized[option_offset + 2 : option_offset + 4] = b"\x00\x00"
            option_offset += length
    return hashlib.sha256(normalized).hexdigest()


events = open(event_path, "w", encoding="utf-8", buffering=1)


def record(phase, cookie, role, observed_transport_router_id, inner, **extra):
    inner, fields = packet_fields(inner)
    value = {
        "phase": phase,
        "cookie": cookie.hex(),
        "role": role,
        "target_id": target,
        "turnaround_id": f"{target}:{cookie.hex()}",
        "inner_sha256": hashlib.sha256(inner).hexdigest(),
        "packet_correlation_sha256": packet_correlation_sha256(inner),
        "observed_transport_router_id": observed_transport_router_id,
        "timestamp_ns": time.time_ns(),
        **fields,
        **extra,
    }
    events.write(json.dumps(value, sort_keys=True) + "\n")


return_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
return_socket.bind(("0.0.0.0", 6081))
return_socket.setblocking(False)
flow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
post_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
post_socket.bind((post_interface, 0))
post_source_mac = interface_mac(post_interface)
post_destination_mac = parse_mac(post_peer_mac)

captures = {}
for role, interface in inputs.items():
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind((interface, 0))
    capture.setblocking(False)
    captures[capture] = role

pending = {}
cookie_counter = 0


def send_to_target(inner, role, observed_transport_router_id):
    global cookie_counter
    inner, _ = packet_fields(inner)
    cookie_counter += 1
    cookie = cookie_counter.to_bytes(4, "big")
    options = (
        struct.pack("!HBB", 0x0108, 1, 2) + bytes.fromhex("1122334455667788")
        + struct.pack("!HBB", 0x2222, 0x7E, 1) + bytes.fromhex("01020304")
        + struct.pack("!HBB", 0x0108, 2, 2) + bytes.fromhex("8877665544332211")
        + struct.pack("!HBB", 0x0108, 3, 1) + cookie
    )
    geneve = bytes((len(options) // 4, 0)) + struct.pack("!H", 0x0800) + b"\x00" * 4 + options + inner
    options_sha256 = hashlib.sha256(options).hexdigest()
    pending[cookie] = {
        "geneve": geneve,
        "inner": inner,
        "role": role,
        "observed_transport_router_id": observed_transport_router_id,
        "options_sha256": options_sha256,
    }
    record(
        "receive",
        cookie,
        role,
        observed_transport_router_id,
        inner,
        ordered_options_sha256=options_sha256,
    )
    try:
        flow_socket.sendto(geneve, target_address)
    except OSError as error:
        record(
            "send_error",
            cookie,
            role,
            observed_transport_router_id,
            inner,
            error=str(error),
        )
    return cookie


pathlib.Path(ready_path).touch()

try:
    while True:
        readable, _, _ = select.select([return_socket, *captures], [], [], 0.1)
        for current in readable:
            if current is return_socket:
                returned, peer = return_socket.recvfrom(65535)
                if len(returned) < 48 or returned[0] >> 6 != 0:
                    raise ValueError("invalid returned GENEVE packet")
                option_length = (returned[0] & 0x3F) * 4
                if option_length != 40 or returned[2:4] != b"\x08\x00":
                    raise ValueError("returned GENEVE metadata changed")
                options = returned[8:48]
                if options[32:36] != bytes.fromhex("01080301"):
                    raise ValueError("returned AWS cookie option changed")
                cookie = options[36:40]
                request = pending.pop(cookie, None)
                if request is None:
                    raise ValueError("duplicate or unknown GENEVE return")
                if returned != request["geneve"]:
                    raise ValueError("target changed GENEVE metadata or inner bytes")
                flow_port = flow_socket.getsockname()[1]
                if peer != (target_address[0], flow_port):
                    raise ValueError("target return used the wrong AWS outer tuple")
                inner = request["inner"]
                record(
                    "return",
                    cookie,
                    request["role"],
                    request["observed_transport_router_id"],
                    inner,
                    byte_identical=True,
                    ordered_options_sha256=request["options_sha256"],
                    turnaround_sha256=hashlib.sha256(returned).hexdigest(),
                    target=peer[0],
                    return_source_port=peer[1],
                )
                frame = post_destination_mac + post_source_mac + b"\x08\x00" + inner
                written = post_socket.send(frame)
                if written != len(frame):
                    raise ValueError("fake GWLBE emitted a partial post-inspection frame")
                record(
                    "post_inspection",
                    cookie,
                    request["role"],
                    request["observed_transport_router_id"],
                    inner,
                    bytes_written=written,
                )
                continue

            frame, packet_address = current.recvfrom(65535)
            if len(frame) < 34 or frame[12:14] != b"\x08\x00":
                continue
            inner, fields = packet_fields(frame[14:])
            if (
                len(packet_address) > 2
                and packet_address[2] == getattr(socket, "PACKET_OUTGOING", 4)
                and fields["fragment_offset"] == 0
            ):
                continue
            role = captures[current]
            observed_transport_router_id = None
            if role == "transport-router":
                observed_transport_router_id = transport_router_macs.get(frame[6:12])
                if observed_transport_router_id is None:
                    raise ValueError(
                        "destination GWLBE observed traffic from an unknown transport-router MAC"
                    )
            send_to_target(inner, role, observed_transport_router_id)
except Exception:
    pathlib.Path("/tmp/gwlb-error").write_text(traceback.format_exc())
    raise
PY

cat >"$work_dir/probe.py" <<'PY'
import pathlib
import socket
import subprocess
import sys
import time


mode, role, address, peer, port, marker, start_at = sys.argv[1:]
port = int(port)
marker = marker.encode()
start_at = float(start_at)
ready = pathlib.Path(f"/tmp/ready-{mode}-{port}")
result = pathlib.Path(f"/tmp/result-{mode}-{role}-{port}")
dispatch = pathlib.Path(f"/tmp/dispatch-{mode}-{role}-{port}")


def wait_for_start():
    while time.time() < start_at:
        time.sleep(0.005)


if mode == "udp":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(15)
    sock.bind((address, port if role == "server" else 0))
    if role == "server":
        ready.touch()
        data, source = sock.recvfrom(4096)
        if data != marker or source[0] != peer:
            raise SystemExit("UDP payload or source was not preserved")
        sock.sendto(b"reply:" + data, source)
        result.write_text(source[0])
    else:
        wait_for_start()
        dispatch.write_text(str(time.time_ns()))
        sock.sendto(marker, (peer, port))
        data, source = sock.recvfrom(4096)
        if data != b"reply:" + marker or source[0] != peer:
            raise SystemExit("UDP reply did not preserve the remote source")
        result.write_text(source[0])
elif mode == "tcp":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    if role == "server":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
        sock.listen(1)
        ready.touch()
        connection, source = sock.accept()
        data = connection.recv(4096)
        if data != marker or source[0] != peer:
            raise SystemExit("TCP payload or source was not preserved")
        connection.sendall(b"reply:" + data)
        connection.close()
        result.write_text(source[0])
    else:
        sock.bind((address, 0))
        wait_for_start()
        dispatch.write_text(str(time.time_ns()))
        sock.connect((peer, port))
        sock.sendall(marker)
        if sock.recv(4096) != b"reply:" + marker:
            raise SystemExit("unexpected TCP reply")
        result.write_text(peer)
elif mode == "icmp":
    if role != "client":
        raise SystemExit("ICMP probes have no userspace server")
    wait_for_start()
    dispatch.write_text(str(time.time_ns()))
    completed = subprocess.run(
        ["ping", "-c", "1", "-W", "10", "-I", address, peer],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "ICMP probe failed: " + completed.stdout[-512:] + completed.stderr[-512:]
        )
    result.write_text(peer)
elif mode == "blocked":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if role == "server":
        sock.settimeout(3)
        sock.bind((address, port))
        ready.touch()
        try:
            data, source = sock.recvfrom(4096)
        except TimeoutError:
            result.write_text("blocked")
        else:
            result.write_text(f"unexpected:{source[0]}:{data.hex()}")
    else:
        sock.bind((address, 0))
        wait_for_start()
        dispatch.write_text(str(time.time_ns()))
        sock.sendto(marker, (peer, port))
        result.write_text("sent")
else:
    raise SystemExit("unknown probe mode")
PY

cat >"$work_dir/fragment-probe.py" <<'PY'
import hashlib
import json
import pathlib
import socket
import struct
import sys
import time


role, address, peer, interface, source_mac, destination_mac, raw_identification, marker, raw_start_at, result_path = sys.argv[1:]
identification = int(raw_identification, 0)
marker = marker.encode()
start_at = float(raw_start_at)
result = pathlib.Path(result_path)


def checksum(value):
    if len(value) % 2:
        value += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(value) // 2), value))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_mac(value):
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("invalid Ethernet address")
    return bytes(int(part, 16) for part in parts)


def fragment_packet():
    source = socket.inet_aton(address)
    destination = socket.inet_aton(peer)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(marker),
        identification,
        1,
        64,
        17,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + marker


def correlation(packet):
    normalized = bytearray(packet)
    normalized[8] = 0
    normalized[10:12] = b"\x00\x00"
    return hashlib.sha256(normalized).hexdigest()


if role == "inject":
    packet = fragment_packet()
    while time.time() < start_at:
        time.sleep(0.005)
    frame = parse_mac(destination_mac) + parse_mac(source_mac) + b"\x08\x00" + packet
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((interface, 0))
    if sock.send(frame) != len(frame):
        raise SystemExit("opaque fragment injection was partial")
    result.write_text(
        json.dumps(
            {
                "source": address,
                "destination": peer,
                "ip_id": identification,
                "fragment_offset": 1,
                "payload_sha256": hashlib.sha256(marker).hexdigest(),
                "inner_sha256": hashlib.sha256(packet).hexdigest(),
                "packet_correlation_sha256": correlation(packet),
                "dispatched_at_ns": time.time_ns(),
            },
            sort_keys=True,
        )
    )
else:
    raise SystemExit("fragment probe role must be inject")
PY

cat >"$work_dir/verify-events.py" <<'PY'
import json
import pathlib
import re
import sys


path, local, remote, *allowed_transport_routers = sys.argv[1:]
allowed_transport_routers = set(allowed_transport_routers)
if len(allowed_transport_routers) != 2:
    raise SystemExit("event verification requires two allowed local transport routers")
events = [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line]
received = {}
returned = {}
post_inspection = {}
for event in events:
    cookie = event["cookie"]
    if event["phase"] == "receive":
        if cookie in received:
            raise SystemExit(f"duplicate receive cookie {cookie}")
        received[cookie] = event
    elif event["phase"] == "return":
        if cookie in returned:
            raise SystemExit(f"target returned cookie {cookie} more than once")
        if event.get("byte_identical") is not True:
            raise SystemExit(f"target return {cookie} lacks byte-identity proof")
        returned[cookie] = event
    elif event["phase"] == "post_inspection":
        if cookie in post_inspection:
            raise SystemExit(f"cookie {cookie} entered the post-inspection domain more than once")
        post_inspection[cookie] = event
    elif event["phase"] == "send_error":
        raise SystemExit(f"fake GWLBE recorded a failed turnaround for cookie {cookie}")

if not received or set(received) != set(returned):
    missing = sorted(set(received) - set(returned))
    raise SystemExit(f"not every GWLBE receive had exactly one return: {missing[:8]}")
if len(returned) > 512:
    raise SystemExit(f"possible inspection recirculation: observed {len(returned)} returns")
if set(post_inspection) != set(received):
    raise SystemExit("packet did not enter the post-inspection route domain exactly once")
for cookie, returned_event in returned.items():
    received_event = received[cookie]
    for field in (
        "inner_sha256",
        "ordered_options_sha256",
        "source",
        "destination",
        "protocol",
        "ip_id",
        "fragment_offset",
        "more_fragments",
        "packet_correlation_sha256",
        "observed_transport_router_id",
        "turnaround_id",
        "target_id",
    ):
        if returned_event[field] != received_event[field]:
            raise SystemExit(f"target changed {field} for cookie {cookie}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(returned_event.get("turnaround_sha256", ""))):
        raise SystemExit(f"target return {cookie} lacks a turnaround hash")
    if returned_event["turnaround_id"] != f'{returned_event["target_id"]}:{cookie}':
        raise SystemExit(f"target return {cookie} has an uncorrelated turnaround ID")
    post_event = post_inspection[cookie]
    for field in (
        "inner_sha256",
        "packet_correlation_sha256",
        "observed_transport_router_id",
        "turnaround_id",
    ):
        if post_event[field] != returned_event[field]:
            raise SystemExit(f"post-inspection domain changed {field} for cookie {cookie}")

expected = (
    (local, remote, "workload"),
    (remote, local, "transport-router"),
)
for protocol in (1, 6, 17):
    for source, destination, role in expected:
        matches = [
            event
            for event in returned.values()
            if event["source"] == source
            and event["destination"] == destination
            and event["role"] == role
            and event["protocol"] == protocol
        ]
        if not matches:
            raise SystemExit(
                f"missing protocol {protocol} {source}->{destination} through {role} GWLBE input"
            )
        for event in matches:
            observed = event["observed_transport_router_id"]
            if role == "workload" and observed is not None:
                raise SystemExit("source turnaround declared an unobserved destination router")
            if role == "transport-router" and observed not in allowed_transport_routers:
                raise SystemExit("destination turnaround lacks an observed local transport router")

for source, destination, role in expected:
    fragments = [
        event
        for event in returned.values()
        if event["source"] == source
        and event["destination"] == destination
        and event["role"] == role
        and event["protocol"] == 17
        and event["fragment_offset"] > 0
    ]
    if len(fragments) != 1:
        raise SystemExit(f"expected one opaque fragment turnaround for {source}->{destination}")

print(f"verified {len(returned)} byte-identical packet turnarounds")
PY

cat >"$work_dir/verify-correlations.py" <<'PY'
import json
import pathlib
import re
import sys


left_path, right_path, site_a, site_b, output_path = sys.argv[1:]


def returned(path):
    values = [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line]
    return [value for value in values if value.get("phase") == "return"]


by_correlation = {}
for site, path in (("a", left_path), ("b", right_path)):
    for event in returned(path):
        correlation = event.get("packet_correlation_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", str(correlation or "")):
            raise SystemExit("turnaround event lacks a packet correlation hash")
        by_correlation.setdefault(correlation, []).append((site, event))

records = []
for correlation, values in by_correlation.items():
    by_site = {
        site: sorted(
            (event for event_site, event in values if event_site == site),
            key=lambda event: event["timestamp_ns"],
        )
        for site in ("a", "b")
    }
    if not by_site["a"] or len(by_site["a"]) != len(by_site["b"]):
        raise SystemExit(f"packet {correlation} did not traverse both site targets equally")
    for occurrence, pair_events in enumerate(zip(by_site["a"], by_site["b"]), start=1):
        pair = (("a", pair_events[0]), ("b", pair_events[1]))
        events = [event for _site, event in pair]
        source = events[0]["source"]
        destination = events[0]["destination"]
        if any(event["source"] != source or event["destination"] != destination for event in events):
            raise SystemExit(f"packet {correlation} changed endpoint identity")
        if (source, destination) == (site_a, site_b):
            source_site, destination_site = "a", "b"
        elif (source, destination) == (site_b, site_a):
            source_site, destination_site = "b", "a"
        else:
            raise SystemExit(f"packet {correlation} is outside the workload pair")
        source_event = next(event for site, event in pair if site == source_site)
        destination_event = next(event for site, event in pair if site == destination_site)
        if source_event.get("role") != "workload":
            raise SystemExit(f"packet {correlation} lacks its source-workload turnaround")
        destination_router = destination_event.get("observed_transport_router_id")
        if destination_event.get("role") != "transport-router" or not destination_router:
            raise SystemExit(f"packet {correlation} lacks an observed destination transport router")
        record = {
            "packet_correlation_sha256": correlation,
            "packet_correlation_occurrence": occurrence,
            "source": source,
            "destination": destination,
            "protocol": source_event["protocol"],
            "ip_id": source_event["ip_id"],
            "fragment_offset": source_event["fragment_offset"],
            "source_turnaround_id": source_event["turnaround_id"],
            "source_turnaround_sha256": source_event["turnaround_sha256"],
            "source_inner_sha256": source_event["inner_sha256"],
            "destination_turnaround_id": destination_event["turnaround_id"],
            "destination_turnaround_sha256": destination_event["turnaround_sha256"],
            "destination_inner_sha256": destination_event["inner_sha256"],
            "observed_destination_transport_router_id": destination_router,
        }
        for field in (
            "source_turnaround_sha256",
            "destination_turnaround_sha256",
            "source_inner_sha256",
            "destination_inner_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(record[field])):
                raise SystemExit(f"packet {correlation} has an invalid {field}")
        records.append(record)

if not records:
    raise SystemExit("no source/destination turnaround correlations were observed")
if {record["source"] for record in records} != {site_a, site_b}:
    raise SystemExit("both packet directions were not correlated")
fragment_records = [record for record in records if record["fragment_offset"] > 0]
if len(fragment_records) != 2 or {record["source"] for record in fragment_records} != {site_a, site_b}:
    raise SystemExit("both opaque fragments lack source/destination turnaround correlation")
pathlib.Path(output_path).write_text(
    "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
    encoding="utf-8",
)
print(f"correlated {len(records)} packets across both target turnarounds")
PY

docker network create "$global_network" >/dev/null
for network in "${networks[@]:1}"; do
  docker network create --internal "$network" >/dev/null
done

docker run -d --platform "$PLATFORM" --name "$headscale" --network "$global_network" --network-alias headscale \
  -v "$work_dir/headscale.yaml:/etc/headscale/config.yaml:ro" \
  -v "$work_dir/acl.hujson:/etc/headscale/acl.hujson:ro" \
  -v "$work_dir/headscale-state:/var/lib/headscale" \
  "$HEADSCALE_IMAGE" serve >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$headscale" headscale users list >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$headscale" headscale users list >/dev/null
docker exec "$headscale" headscale users create integration >/dev/null
headscale_ip=$(docker inspect "$headscale" | python3 -c '
import json, sys
container = json.load(sys.stdin)[0]
print(container["NetworkSettings"]["Networks"][sys.argv[1]]["IPAddress"])
' "$global_network")

create_key() {
  docker exec "$headscale" headscale --output json preauthkeys create --user integration --expiration 1h \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])'
}
for node in transport-router-a1 transport-router-a2 transport-router-b1 transport-router-b2; do
  create_key >"$work_dir/key-$node"
  chmod 0600 "$work_dir/key-$node"
done

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work_dir/envelope" ./cmd/envelope

start_target() {
  local name=$1 alias=$2 network=$3
  docker run -d --platform "$PLATFORM" --name "$name" --hostname "$name" \
    --network "$network" --network-alias "$alias" \
    --cap-drop ALL --cap-add NET_RAW \
    --sysctl net.ipv4.ip_forward=0 --sysctl net.ipv6.conf.all.forwarding=0 \
    --entrypoint /usr/local/bin/envelope \
    -v "$work_dir/envelope:/usr/local/bin/envelope:ro" \
    "$TAILSCALE_IMAGE" \
    --config-version=2 --udp-bind=0.0.0.0:6081 --metrics-addr=0.0.0.0:9090 \
    --max-inner-packet-size=1500 >/dev/null
}

start_helper() {
  local name=$1
  docker run -d --platform "$PLATFORM" --name "$name" --hostname "$name" \
    --network "$global_network" --privileged \
    --entrypoint /bin/sh \
    -v "$work_dir/gwlb-loop.py:/run/envelope-test/gwlb-loop.py:ro" \
    -v "$work_dir/probe.py:/run/envelope-test/probe.py:ro" \
    -v "$work_dir/fragment-probe.py:/run/envelope-test/fragment-probe.py:ro" \
    "$TAILSCALE_IMAGE" -c 'while :; do sleep 3600; done' >/dev/null
}

start_transport_router() {
  local name=$1 key=$2 routes=$3
  docker run -d --platform "$PLATFORM" --name "$name" --hostname "$name" \
    --network "$global_network" --privileged --device=/dev/net/tun \
    --add-host "headscale:$headscale_ip" \
    -e TS_AUTHKEY=file:/run/secrets/authkey -e TS_AUTH_ONCE=true \
    -e TS_STATE_DIR=/var/lib/tailscale -e TS_USERSPACE=false -e TS_ACCEPT_DNS=false \
    -e TS_DEBUG_FIREWALL_MODE=iptables -e TS_DEBUG_USE_DERP_HTTP=true \
    -e TS_ROUTES="$routes" \
    -e 'TS_EXTRA_ARGS=--login-server=http://headscale:8080 --accept-routes --snat-subnet-routes=false --netfilter-mode=off' \
    -v "$key:/run/secrets/authkey:ro" \
    "$TAILSCALE_IMAGE" >/dev/null
}

start_target "$target_a" target-a "$a_target_underlay"
start_target "$target_b" target-b "$b_target_underlay"
for helper in "$gwlbe_a" "$gwlbe_b" "$post_a" "$post_b" "$workload_a" "$workload_b"; do
  start_helper "$helper"
done
start_transport_router "$transport_a1" "$work_dir/key-transport-router-a1" '10.10.0.0/24'
start_transport_router "$transport_a2" "$work_dir/key-transport-router-a2" '10.10.0.0/24'
start_transport_router "$transport_b1" "$work_dir/key-transport-router-b1" '10.20.0.0/24'
start_transport_router "$transport_b2" "$work_dir/key-transport-router-b2" '10.20.0.0/24'

for helper in "$gwlbe_a" "$gwlbe_b"; do
  docker exec "$helper" apk add --no-cache curl iproute2 python3 >/dev/null
done
for helper in "$post_a" "$post_b"; do
  docker exec "$helper" apk add --no-cache iproute2 >/dev/null
done
for helper in "$workload_a" "$workload_b"; do
  docker exec "$helper" apk add --no-cache ethtool iproute2 iputils python3 tcpdump >/dev/null
done
for transport_router in "$transport_a1" "$transport_a2" "$transport_b1" "$transport_b2"; do
  docker exec "$transport_router" apk add --no-cache bash coreutils ethtool iproute2 iptables jq nftables procps python3 >/dev/null
  docker exec "$transport_router" sh -ec '
    install -d /usr/bin /usr/sbin /var/lib/envelope
    for target in /usr/bin/jq /usr/bin/mktemp /usr/bin/mv /usr/bin/rm /usr/bin/sleep \
      /usr/sbin/ip /usr/sbin/iptables /usr/sbin/ip6tables /usr/sbin/iptables-save \
      /usr/sbin/ip6tables-save /usr/sbin/nft /usr/sbin/sysctl; do
      name=${target##*/}
      source=$(command -v "$name")
      if [ "$source" != "$target" ]; then ln -sf "$source" "$target"; fi
    done
    for path in /usr/bin/jq /usr/bin/mktemp /usr/bin/mv /usr/bin/rm /usr/bin/sleep \
      /usr/sbin/ip /usr/sbin/iptables /usr/sbin/ip6tables /usr/sbin/iptables-save \
      /usr/sbin/ip6tables-save /usr/sbin/nft /usr/sbin/sysctl; do
      test -x "$path"
    done
  '
done

connect() {
  docker network connect "$1" "$2"
}
connect "$a_workload_pre" "$workload_a"
connect "$a_workload_pre" "$gwlbe_a"
connect "$a_target_underlay" "$gwlbe_a"
connect "$a_workload_post" "$workload_a"
connect "$a_workload_post" "$post_a"
connect "$a_gwlbe_post" "$gwlbe_a"
connect "$a_gwlbe_post" "$post_a"
for node in "$gwlbe_a" "$post_a" "$transport_a1" "$transport_a2"; do
  connect "$a_transport_underlay" "$node"
done
connect "$b_workload_pre" "$workload_b"
connect "$b_workload_pre" "$gwlbe_b"
connect "$b_target_underlay" "$gwlbe_b"
connect "$b_workload_post" "$workload_b"
connect "$b_workload_post" "$post_b"
connect "$b_gwlbe_post" "$gwlbe_b"
connect "$b_gwlbe_post" "$post_b"
for node in "$gwlbe_b" "$post_b" "$transport_b1" "$transport_b2"; do
  connect "$b_transport_underlay" "$node"
done

for helper in "$workload_a" "$workload_b" "$post_a" "$post_b"; do
  docker network disconnect "$global_network" "$helper"
done

network_ip() {
  docker inspect "$1" | python3 -c '
import json, sys
container = json.load(sys.stdin)[0]
print(container["NetworkSettings"]["Networks"][sys.argv[1]]["IPAddress"])
' "$2"
}

interface_for_ip() {
  docker exec "$1" ip -j -4 address show | python3 -c '
import json, sys
address = sys.argv[1]
for interface in json.load(sys.stdin):
    if any(item.get("local") == address for item in interface.get("addr_info", [])):
        print(interface["ifname"])
        raise SystemExit(0)
raise SystemExit("interface not found for " + address)
' "$2"
}

interface_mac() {
  docker exec "$1" ip -j link show dev "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])'
}

a_workload_pre_ip=$(network_ip "$workload_a" "$a_workload_pre")
a_workload_post_ip=$(network_ip "$workload_a" "$a_workload_post")
a_gwlbe_workload_ip=$(network_ip "$gwlbe_a" "$a_workload_pre")
a_gwlbe_post_ip=$(network_ip "$gwlbe_a" "$a_gwlbe_post")
a_gwlbe_transport_ip=$(network_ip "$gwlbe_a" "$a_transport_underlay")
a_post_gwlbe_ip=$(network_ip "$post_a" "$a_gwlbe_post")
a_post_workload_ip=$(network_ip "$post_a" "$a_workload_post")
a_post_transport_ip=$(network_ip "$post_a" "$a_transport_underlay")
a_transport_a1_ip=$(network_ip "$transport_a1" "$a_transport_underlay")
a_transport_a2_ip=$(network_ip "$transport_a2" "$a_transport_underlay")

b_workload_pre_ip=$(network_ip "$workload_b" "$b_workload_pre")
b_workload_post_ip=$(network_ip "$workload_b" "$b_workload_post")
b_gwlbe_workload_ip=$(network_ip "$gwlbe_b" "$b_workload_pre")
b_gwlbe_post_ip=$(network_ip "$gwlbe_b" "$b_gwlbe_post")
b_gwlbe_transport_ip=$(network_ip "$gwlbe_b" "$b_transport_underlay")
b_post_gwlbe_ip=$(network_ip "$post_b" "$b_gwlbe_post")
b_post_workload_ip=$(network_ip "$post_b" "$b_workload_post")
b_post_transport_ip=$(network_ip "$post_b" "$b_transport_underlay")
b_transport_b1_ip=$(network_ip "$transport_b1" "$b_transport_underlay")
b_transport_b2_ip=$(network_ip "$transport_b2" "$b_transport_underlay")

a_workload_pre_if=$(interface_for_ip "$workload_a" "$a_workload_pre_ip")
a_workload_post_if=$(interface_for_ip "$workload_a" "$a_workload_post_ip")
a_gwlbe_workload_if=$(interface_for_ip "$gwlbe_a" "$a_gwlbe_workload_ip")
a_gwlbe_post_if=$(interface_for_ip "$gwlbe_a" "$a_gwlbe_post_ip")
a_gwlbe_transport_if=$(interface_for_ip "$gwlbe_a" "$a_gwlbe_transport_ip")
a_post_gwlbe_if=$(interface_for_ip "$post_a" "$a_post_gwlbe_ip")
a_post_workload_if=$(interface_for_ip "$post_a" "$a_post_workload_ip")
a_post_transport_if=$(interface_for_ip "$post_a" "$a_post_transport_ip")
a_transport_a1_if=$(interface_for_ip "$transport_a1" "$a_transport_a1_ip")
a_transport_a2_if=$(interface_for_ip "$transport_a2" "$a_transport_a2_ip")

b_workload_pre_if=$(interface_for_ip "$workload_b" "$b_workload_pre_ip")
b_workload_post_if=$(interface_for_ip "$workload_b" "$b_workload_post_ip")
b_gwlbe_workload_if=$(interface_for_ip "$gwlbe_b" "$b_gwlbe_workload_ip")
b_gwlbe_post_if=$(interface_for_ip "$gwlbe_b" "$b_gwlbe_post_ip")
b_gwlbe_transport_if=$(interface_for_ip "$gwlbe_b" "$b_gwlbe_transport_ip")
b_post_gwlbe_if=$(interface_for_ip "$post_b" "$b_post_gwlbe_ip")
b_post_workload_if=$(interface_for_ip "$post_b" "$b_post_workload_ip")
b_post_transport_if=$(interface_for_ip "$post_b" "$b_post_transport_ip")
b_transport_b1_if=$(interface_for_ip "$transport_b1" "$b_transport_b1_ip")
b_transport_b2_if=$(interface_for_ip "$transport_b2" "$b_transport_b2_ip")

disable_capture_path_offload() {
  local node=$1 interface=$2 features
  docker exec "$node" ethtool -K "$interface" tx off
  features=$(docker exec "$node" ethtool -k "$interface")
  grep -Fq 'tx-checksumming: off' <<<"$features"
}
disable_capture_path_offload "$workload_a" "$a_workload_pre_if"
disable_capture_path_offload "$workload_b" "$b_workload_pre_if"
disable_capture_path_offload "$transport_a1" "$a_transport_a1_if"
disable_capture_path_offload "$transport_a2" "$a_transport_a2_if"
disable_capture_path_offload "$transport_b1" "$b_transport_b1_if"
disable_capture_path_offload "$transport_b2" "$b_transport_b2_if"

setup_workload() {
  docker exec -i "$1" sh -s -- "$2" "$3" "$4" "$5" "$6" "$7" <<'SH'
set -eu
local_cidr=$1
remote_cidr=$2
local_ip=$3
pre_interface=$4
gwlbe_ip=$5
post_interface=$6
while ip route del default 2>/dev/null; do :; done
ip address add "$local_ip/32" dev lo
ip route replace "$remote_cidr" via "$gwlbe_ip" dev "$pre_interface"
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w "net.ipv4.conf.$pre_interface.rp_filter=0"
sysctl -q -w "net.ipv4.conf.$post_interface.rp_filter=0"
SH
}

setup_post_domain() {
  docker exec -i "$1" sh -s -- "$2" "$3" "$4" "$5" "$6" "$7" "$8" <<'SH'
set -eu
local_cidr=$1
remote_cidr=$2
gwlbe_interface=$3
workload_interface=$4
workload_ip=$5
transport_interface=$6
transport_ip=$7
while ip route del default 2>/dev/null; do :; done
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
for interface in "$gwlbe_interface" "$workload_interface" "$transport_interface"; do
  sysctl -q -w "net.ipv4.conf.$interface.rp_filter=0"
done
ip route replace "$local_cidr" via "$workload_ip" dev "$workload_interface"
ip route replace "$remote_cidr" via "$transport_ip" dev "$transport_interface"
SH
}

setup_gwlbe_domain() {
  docker exec -i "$1" sh -s -- "$2" "$3" "$4" <<'SH'
set -eu
workload_interface=$1
post_interface=$2
transport_interface=$3
sysctl -q -w net.ipv4.ip_forward=0
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
for interface in "$workload_interface" "$post_interface" "$transport_interface"; do
  sysctl -q -w "net.ipv4.conf.$interface.rp_filter=0"
done
SH
}

setup_workload "$workload_a" '10.10.0.0/24' '10.20.0.0/24' '10.10.0.10' "$a_workload_pre_if" "$a_gwlbe_workload_ip" "$a_workload_post_if"
setup_workload "$workload_b" '10.20.0.0/24' '10.10.0.0/24' '10.20.0.10' "$b_workload_pre_if" "$b_gwlbe_workload_ip" "$b_workload_post_if"
setup_post_domain "$post_a" '10.10.0.0/24' '10.20.0.0/24' "$a_post_gwlbe_if" "$a_post_workload_if" "$a_workload_post_ip" "$a_post_transport_if" "$a_transport_a1_ip"
setup_post_domain "$post_b" '10.20.0.0/24' '10.10.0.0/24' "$b_post_gwlbe_if" "$b_post_workload_if" "$b_workload_post_ip" "$b_post_transport_if" "$b_transport_b1_ip"
setup_gwlbe_domain "$gwlbe_a" "$a_gwlbe_workload_if" "$a_gwlbe_post_if" "$a_gwlbe_transport_if"
setup_gwlbe_domain "$gwlbe_b" "$b_gwlbe_workload_if" "$b_gwlbe_post_if" "$b_gwlbe_transport_if"

wait_running() {
  local node=$1 status
  for _ in $(seq 1 120); do
    status=$(docker exec "$node" tailscale status --json 2>/dev/null || true)
    if grep -Eq '"BackendState"[[:space:]]*:[[:space:]]*"Running"' <<<"$status"; then
      return
    fi
    sleep 0.5
  done
  docker logs "$node" >&2
  printf 'tailscaled did not become Running on %s\n' "$node" >&2
  exit 1
}
for node in "$transport_a1" "$transport_a2" "$transport_b1" "$transport_b2"; do
  wait_running "$node"
done

routes_ready=false
for _ in $(seq 1 120); do
  route_json=$(docker exec "$headscale" headscale --output json routes list)
  route_ids=$(python3 -c '
import json, sys
routes = json.load(sys.stdin)
expected = {"10.10.0.0/24": 2, "10.20.0.0/24": 2}
found = {}
for route in routes:
    found[route["prefix"]] = found.get(route["prefix"], 0) + 1
if all(found.get(prefix) == count for prefix, count in expected.items()):
    print(" ".join(str(route["id"]) for route in routes))
' <<<"$route_json")
  if [[ -n "$route_ids" ]]; then
    for route_id in $route_ids; do
      docker exec "$headscale" headscale routes enable --route "$route_id" >/dev/null
    done
    routes_ready=true
    break
  fi
  sleep 0.5
done
if [[ "$routes_ready" != true ]]; then
  printf '%s\n' 'Headscale did not observe two transport-router advertisements for each site CIDR' >&2
  exit 1
fi

wait_remote_route() {
  local node=$1 remote=$2 expected_peer_a=$3 expected_peer_b=$4
  local route status owner fingerprint previous='' stable=0
  for _ in $(seq 1 180); do
    route=$(docker exec "$node" ip route show table 52 "$remote")
    status=$(docker exec "$node" tailscale status --json)
    owner=$(python3 -c '
import json
import sys

prefix, *expected = sys.argv[1:]
matches = []
for peer in json.load(sys.stdin).get("Peer", {}).values():
    routes = peer.get("PrimaryRoutes", [])
    if prefix in routes:
        addresses = peer.get("TailscaleIPs", [])
        if (
            peer.get("HostName") not in expected
            or peer.get("Online") is not True
            or not addresses
        ):
            raise SystemExit(1)
        matches.append((peer["HostName"], addresses[0]))
if len(matches) != 1:
    raise SystemExit(1)
print(*matches[0], sep="\t")
' "$remote" "$expected_peer_a" "$expected_peer_b" <<<"$status" || true)
    if [[ -n "$owner" ]] && grep -q 'dev tailscale0' <<<"$route"; then
      fingerprint="$owner|$route"
      if [[ "$fingerprint" == "$previous" ]]; then
        ((stable += 1))
      else
        previous=$fingerprint
        stable=1
      fi
      if (( stable >= 6 )) && docker exec "$node" tailscale ping --timeout=5s --c=1 "${owner#*$'\t'}" >/dev/null 2>&1; then
        return
      fi
    else
      previous=''
      stable=0
    fi
    sleep 0.5
  done
  docker exec "$node" ip route show table all >&2
  printf '%s did not stabilize exact remote route %s with a direct peer connection\n' "$node" "$remote" >&2
  exit 1
}
for node in "$transport_a1" "$transport_a2"; do
  wait_remote_route "$node" '10.20.0.0/24' "$transport_b1" "$transport_b2"
done
for node in "$transport_b1" "$transport_b2"; do
  wait_remote_route "$node" '10.10.0.0/24' "$transport_a1" "$transport_a2"
done

verify_transport_router_control_plane() {
  local node=$1 expected_local=$2
  docker exec "$node" tailscale status --json | python3 -c '
import json
import sys
status = json.load(sys.stdin)
self_status = status.get("Self", {})
if (
    status.get("BackendState") != "Running"
    or status.get("TUN") is not True
    or status.get("Health", [])
    or self_status.get("Online") is not True
):
    raise SystemExit("transport-router backend or self node is not ready")
'
  docker exec "$node" tailscale debug prefs | python3 -c '
import json
import sys
expected = {sys.argv[1]}
prefs = json.load(sys.stdin)
if set(prefs.get("AdvertiseRoutes", [])) != expected:
    raise SystemExit("transport-router does not advertise the exact local prefix")
if prefs.get("RouteAll") is not True or prefs.get("NoSNAT") is not True:
    raise SystemExit("transport-router does not accept routes without SNAT")
' "$expected_local"
}
for node in "$transport_a1" "$transport_a2"; do
  verify_transport_router_control_plane "$node" '10.10.0.0/24'
done
for node in "$transport_b1" "$transport_b2"; do
  verify_transport_router_control_plane "$node" '10.20.0.0/24'
done

tailscale_peer_ip() {
  local observer=$1 expected_hostname=$2
  docker exec "$observer" tailscale status --json | python3 -c '
import json
import sys
expected = sys.argv[1]
for peer in json.load(sys.stdin).get("Peer", {}).values():
    if peer.get("HostName") == expected and peer.get("Online") is True:
        addresses = peer.get("TailscaleIPs", [])
        if addresses:
            print(addresses[0])
            raise SystemExit(0)
raise SystemExit("required online route-serving peer is absent")
' "$expected_hostname"
}
for observer in "$transport_a1" "$transport_a2"; do
  for peer in "$transport_b1" "$transport_b2"; do
    docker exec "$observer" tailscale ping --timeout=5s "$(tailscale_peer_ip "$observer" "$peer")" >/dev/null
  done
done
for observer in "$transport_b1" "$transport_b2"; do
  for peer in "$transport_a1" "$transport_a2"; do
    docker exec "$observer" tailscale ping --timeout=5s "$(tailscale_peer_ip "$observer" "$peer")" >/dev/null
  done
done

remove_docker_dns_nft_state() {
  local node=$1 classification
  if ! classification=$(docker exec "$node" nft -j list ruleset | python3 -c '
import json
import sys

items = json.load(sys.stdin).get("nftables", [])
if len(items) == 1 and "metainfo" in items[0]:
    print("empty")
    raise SystemExit(0)
if not items or "metainfo" not in items[0]:
    raise SystemExit("native nftables output lacks metadata")

body = items[1:]
tables = [item["table"] for item in body if set(item) == {"table"}]
chains = [item["chain"] for item in body if set(item) == {"chain"}]
rules = [item["rule"] for item in body if set(item) == {"rule"}]
if len(tables) != 1 or len(tables) + len(chains) + len(rules) != len(body):
    raise SystemExit("unrecognized native nftables object")
if tables[0].get("family") != "ip" or tables[0].get("name") != "nat":
    raise SystemExit("unrecognized native nftables table")
expected_chains = {"DOCKER_OUTPUT", "OUTPUT", "DOCKER_POSTROUTING", "POSTROUTING"}
if {chain.get("name") for chain in chains} != expected_chains:
    raise SystemExit("unrecognized native nftables chains")
if not rules:
    raise SystemExit("Docker DNS nftables table contains no rules")
for rule in rules:
    if rule.get("family") != "ip" or rule.get("table") != "nat" or rule.get("chain") not in expected_chains:
        raise SystemExit("unrecognized native nftables rule location")
    if "127.0.0.11" not in json.dumps(rule, sort_keys=True):
        raise SystemExit("native nftables rule is not scoped to Docker DNS")
    if any(set(expression) - {"match", "counter", "xt", "jump"} for expression in rule.get("expr", [])):
        raise SystemExit("unrecognized native nftables rule expression")
print("docker-dns")
'); then
    printf 'transport-router %s contains unrecognized native nftables state\n' "$node" >&2
    exit 1
  fi
  case "$classification" in
    empty) return ;;
    docker-dns) docker exec "$node" nft delete table ip nat ;;
    *) printf 'unexpected nftables classification for %s: %s\n' "$node" "$classification" >&2; exit 1 ;;
  esac
  docker exec "$node" nft -j list ruleset | python3 -c '
import json, sys
items = json.load(sys.stdin).get("nftables", [])
if len(items) != 1 or "metainfo" not in items[0]:
    raise SystemExit("Docker DNS nftables state was not removed")
'
}

assert_transport_firewall() {
  local node=$1 underlay=$2 local_cidr=$3 remote_cidr=$4
  local filter_forward ipv6_forward ipv6_chain ipv6_mangle ipv4_nat ipv6_nat
  filter_forward=$(docker exec "$node" iptables -S FORWARD)
  grep -Fqx -- '-P FORWARD DROP' <<<"$filter_forward"
  [[ $(docker exec "$node" iptables -S FORWARD | grep -c '^-A ') == 1 ]]
  docker exec "$node" iptables -C FORWARD -j ENVELOPE-TRANSPORT-FORWARD
  [[ $(docker exec "$node" iptables -S ENVELOPE-TRANSPORT-FORWARD | grep -c '^-A ') == 2 ]]
  docker exec "$node" iptables -C ENVELOPE-TRANSPORT-FORWARD \
    -i "$underlay" -o tailscale0 -s "$local_cidr" -d "$remote_cidr" -j ACCEPT
  docker exec "$node" iptables -C ENVELOPE-TRANSPORT-FORWARD \
    -i tailscale0 -o "$underlay" -s "$remote_cidr" -d "$local_cidr" -j ACCEPT

  [[ $(docker exec "$node" iptables -t mangle -S FORWARD | grep -c '^-A ') == 1 ]]
  docker exec "$node" iptables -t mangle -C FORWARD -j ENVELOPE-TRANSPORT-MSS
  [[ $(docker exec "$node" iptables -t mangle -S ENVELOPE-TRANSPORT-MSS | grep -c '^-A ') == 3 ]]
  docker exec "$node" iptables -t mangle -C ENVELOPE-TRANSPORT-MSS \
    -i "$underlay" -o tailscale0 -s "$local_cidr" -d "$remote_cidr" \
    -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
  docker exec "$node" iptables -t mangle -C ENVELOPE-TRANSPORT-MSS \
    -i tailscale0 -o "$underlay" -s "$remote_cidr" -d "$local_cidr" \
    -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
  docker exec "$node" iptables -t mangle -C ENVELOPE-TRANSPORT-MSS -j RETURN

  ipv6_forward=$(docker exec "$node" ip6tables -S FORWARD)
  grep -Fqx -- '-P FORWARD DROP' <<<"$ipv6_forward"
  [[ $(docker exec "$node" ip6tables -S FORWARD | grep -c '^-A ') == 1 ]]
  docker exec "$node" ip6tables -C FORWARD -j ENVELOPE-TRANSPORT-FORWARD
  ipv6_chain=$(docker exec "$node" ip6tables -S ENVELOPE-TRANSPORT-FORWARD)
  if grep -q '^-A ' <<<"$ipv6_chain"; then
    printf 'transport-router %s contains an IPv6 forwarding rule\n' "$node" >&2
    exit 1
  fi
  ipv6_mangle=$(docker exec "$node" ip6tables -t mangle -S FORWARD)
  if grep -q '^-A ' <<<"$ipv6_mangle"; then
    printf 'transport-router %s contains an IPv6 mangle rule\n' "$node" >&2
    exit 1
  fi
  ipv4_nat=$(docker exec "$node" iptables-save -t nat)
  if grep -q '^-A ' <<<"$ipv4_nat"; then
    printf 'transport-router %s contains an IPv4 NAT rule\n' "$node" >&2
    exit 1
  fi
  ipv6_nat=$(docker exec "$node" ip6tables-save -t nat)
  if grep -q '^-A ' <<<"$ipv6_nat"; then
    printf 'transport-router %s contains an IPv6 NAT rule\n' "$node" >&2
    exit 1
  fi
}

setup_transport_router() {
  local node=$1 local_cidr=$2 remote_cidr=$3 underlay=$4 gwlbe_ip=$5
  local contract contract_hash observed_hash state_contract local_probe remote_probe local_route remote_route
  local ipv4_nat firewall_dump
  local_probe=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1]).network_address + 10)' "$local_cidr")
  remote_probe=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1]).network_address + 10)' "$remote_cidr")

  # The local underlay route models the VPC route table. The exact production
  # service executable owns policy rules, sysctls, firewall, and MSS state.
  docker exec "$node" ip route replace "$local_cidr" via "$gwlbe_ip" dev "$underlay"

  contract="$work_dir/transport-contract-$node.sh"
  contract_hash=$(python3 "$work_dir/render-transport-contract.py" \
    example/terraform/cloud-init/transport-router.sh.tftpl "$contract" "$underlay" tailscale0 \
    "$local_cidr" "$remote_cidr")
  docker cp "$contract" "$node:/run/envelope-transport-router-network" >/dev/null
  remove_docker_dns_nft_state "$node"
  docker exec "$node" /run/envelope-transport-router-network stage
  docker exec "$node" sh -ec '
    test "$(sysctl -n net.ipv4.ip_forward)" = 0
    test ! -e /var/lib/envelope/transport-router-network.ready
    test ! -e /var/lib/envelope/transport-router-network.state.json
    test ! -e /var/lib/envelope/transport-router-network.configured
    touch /var/lib/envelope/transport-router-network.configured
  '
  docker exec "$node" /run/envelope-transport-router-network
  observed_hash=$(docker exec "$node" sha256sum /run/envelope-transport-router-network | cut -d' ' -f1)
  if [[ "$observed_hash" != "$contract_hash" ]]; then
    printf 'transport contract hash changed in %s\n' "$node" >&2
    exit 1
  fi
  docker exec "$node" jq -e \
    --arg local "$local_cidr" --arg remote "$remote_cidr" \
    '.ready == true and .ipv4_forwarding == true and .ipv6_forwarding == false and
     .no_nat == true and .tcp_mss == 1240 and .local_site_cidrs == [$local] and
     .remote_site_cidrs == [$remote] and .local_policy_rules == [{
       priority: 100, input: "tailscale0", source: "all", destination: $local,
       fwmark: 0, table: "main", action: "lookup"
     }]' /var/lib/envelope/transport-router-network.state.json >/dev/null
  state_contract=$(docker exec "$node" jq -r .contract_sha256 /var/lib/envelope/transport-router-network.state.json)
  [[ -n "$state_contract" ]]
  [[ $(docker exec "$node" cat /var/lib/envelope/transport-router-firewall.owner) == "$state_contract" ]]
  [[ $(docker exec "$node" cat /var/lib/envelope/transport-router-policy-rules.owner) == "$state_contract" ]]
  docker exec "$node" test -f /var/lib/envelope/transport-router-network.ready
  printf '%s\t%s\n' "$node" "$contract_hash" >>"$work_dir/transport-contract-hashes.tsv"

  remote_route=$(docker exec "$node" ip route get "$remote_probe")
  if [[ "$remote_route" != *"dev tailscale0"* ]]; then
    printf 'remote route on %s bypasses tailscale0: %s\n' "$node" "$remote_route" >&2
    exit 1
  fi
  local_route=$(docker exec "$node" ip route get "$local_probe" from "$remote_probe" iif tailscale0)
  if [[ "$local_route" != *"via $gwlbe_ip dev $underlay"* ]]; then
    printf 'Tailnet-arriving local route on %s bypasses GWLBE: %s\n' "$node" "$local_route" >&2
    exit 1
  fi
  ipv4_nat=$(docker exec "$node" iptables-save -t nat)
  if grep -Eq -- '-j (SNAT|MASQUERADE)( |$)' <<<"$ipv4_nat"; then
    printf 'transport-router %s contains NAT\n' "$node" >&2
    exit 1
  fi
  firewall_dump=$(docker exec "$node" iptables-save)
  if grep -q envelope0 <<<"$firewall_dump"; then
    printf 'transport-router %s firewall references target-only envelope0\n' "$node" >&2
    exit 1
  fi
  assert_transport_firewall "$node" "$underlay" "$local_cidr" "$remote_cidr"
}

setup_transport_router "$transport_a1" '10.10.0.0/24' '10.20.0.0/24' "$a_transport_a1_if" "$a_gwlbe_transport_ip"
setup_transport_router "$transport_a2" '10.10.0.0/24' '10.20.0.0/24' "$a_transport_a2_if" "$a_gwlbe_transport_ip"
setup_transport_router "$transport_b1" '10.20.0.0/24' '10.10.0.0/24' "$b_transport_b1_if" "$b_gwlbe_transport_ip"
setup_transport_router "$transport_b2" '10.20.0.0/24' '10.10.0.0/24' "$b_transport_b2_if" "$b_gwlbe_transport_ip"

assert_local_policy_rule() {
  local node=$1 prefix=$2
  docker exec "$node" ip -j -details -4 rule show | python3 -c '
import ipaddress
import json
import sys

expected = ipaddress.ip_network(sys.argv[1])
matches = []
rules = json.load(sys.stdin)
for rule in rules:
    destination = rule.get("dst")
    if not destination:
        continue
    if "/" not in destination and "dstlen" in rule:
        destination += "/" + str(rule["dstlen"])
    try:
        network = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        continue
    if network == expected:
        matches.append(rule)
if len(matches) != 1:
    raise SystemExit(f"{expected} does not have one exact local inspection policy rule")
rule = matches[0]
if (
    rule.get("priority") != 100
    or rule.get("iif") != "tailscale0"
    or str(rule.get("table")) not in {"254", "main"}
    or str(rule.get("action", "to_tbl")) not in {"to_tbl", "lookup"}
):
    raise SystemExit(f"{expected} local policy rule bypasses the main underlay table")

for candidate in rules:
    if candidate is rule:
        continue
    try:
        priority = int(candidate.get("priority"))
    except (TypeError, ValueError):
        raise SystemExit("local policy state contains an invalid priority")
    if priority <= 0 or priority > 100:
        continue
    if candidate.get("iif") not in (None, "", "all", "tailscale0"):
        continue
    destination = candidate.get("dst", "0.0.0.0/0")
    if not isinstance(destination, str):
        raise SystemExit("local policy state contains an invalid destination")
    if "/" not in destination and "dstlen" in candidate:
        destination += "/" + str(candidate["dstlen"])
    try:
        network = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        raise SystemExit("local policy state contains an invalid destination")
    if not network.overlaps(expected):
        continue
    table = str(candidate.get("table", ""))
    action = str(candidate.get("action", "to_tbl"))
    if table not in {"254", "main"} or action not in {"to_tbl", "lookup"}:
        raise SystemExit(f"{expected} has an earlier interior policy bypass")
' "$prefix"
}
for node in "$transport_a1" "$transport_a2"; do
  assert_local_policy_rule "$node" '10.10.0.0/24'
done
for node in "$transport_b1" "$transport_b2"; do
  assert_local_policy_rule "$node" '10.20.0.0/24'
done

assert_tailnet_route_domain() {
  local node=$1 prefix=$2
  docker exec "$node" ip -j -4 route show table 52 | python3 -c '
import ipaddress
import json
import sys

prefix = ipaddress.ip_network(sys.argv[1])
parsed = []
for route in json.load(sys.stdin):
    destination = route.get("dst", "default")
    if destination == "default":
        continue
    network = ipaddress.ip_network(destination, strict=False)
    if network.version == prefix.version:
        parsed.append((route, network))
exact = [route for route, network in parsed if network == prefix]
if (
    len(exact) != 1
    or exact[0].get("dev") != "tailscale0"
    or exact[0].get("type", "unicast") != "unicast"
    or exact[0].get("from") not in (None, "all")
):
    raise SystemExit(f"{prefix} does not have one exact accepted tailscale0 route")
children = [
    str(network)
    for route, network in parsed
    if network != prefix
    and network.subnet_of(prefix)
    and (
        route.get("dev") != "tailscale0"
        or route.get("type", "unicast") != "unicast"
        or route.get("from") not in (None, "all")
    )
]
if children:
    raise SystemExit(f"{prefix} has a more-specific Tailnet route bypass: {sorted(children)}")
' "$prefix"
}
for node in "$transport_a1" "$transport_a2"; do
  assert_tailnet_route_domain "$node" '10.20.0.0/24'
done
for node in "$transport_b1" "$transport_b2"; do
  assert_tailnet_route_domain "$node" '10.10.0.0/24'
done

for node in "$transport_a1" "$transport_a2" "$transport_b1" "$transport_b2"; do
  [[ $(docker exec "$node" sysctl -n net.ipv4.ip_forward) == 1 ]]
  [[ $(docker exec "$node" sysctl -n net.ipv4.conf.all.rp_filter) == 0 ]]
  [[ $(docker exec "$node" sysctl -n net.ipv4.conf.tailscale0.rp_filter) == 0 ]]
  [[ $(docker exec "$node" iptables -S ENVELOPE-TRANSPORT-FORWARD | grep -c '^-A ') == 2 ]]
  [[ $(docker exec "$node" iptables -t mangle -S ENVELOPE-TRANSPORT-MSS | grep -c -- '--set-mss 1240') == 2 ]]
done

wait_target_healthy() {
  local alias=$1 observer=$2
  for _ in $(seq 1 120); do
    if docker exec "$observer" curl -fsS "http://$alias:9090/healthz" >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done
  printf 'packet-turnaround target %s did not become healthy\n' "$alias" >&2
  exit 1
}
wait_target_healthy target-a "$gwlbe_a"
wait_target_healthy target-b "$gwlbe_b"

assert_target_isolated() {
  local target=$1 processes
  docker exec "$target" sh -c '
    test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0
    test ! -e /dev/net/tun
    test ! -e /sys/class/net/envelope0
    test ! -e /sys/class/net/tailscale0
  '
  processes=$(docker top "$target")
  if grep -q tailscaled <<<"$processes"; then
    printf 'target %s unexpectedly runs tailscaled\n' "$target" >&2
    exit 1
  fi
  docker inspect "$target" | python3 -c '
import json, sys
container = json.load(sys.stdin)[0]
networks = container["NetworkSettings"]["Networks"]
capabilities = container["HostConfig"].get("CapAdd") or []
if len(networks) != 1 or len(capabilities) != 1 or capabilities[0] not in {"NET_RAW", "CAP_NET_RAW"}:
    raise SystemExit("target has an inner network attachment or transport capability")
host = container["HostConfig"]
if host.get("Privileged") or host.get("Devices") or "ALL" not in (host.get("CapDrop") or []):
    raise SystemExit("target has privileges beyond the packet-return sender")
'
  docker exec "$target" sh -c 'cat /proc/net/route' | python3 -c '
import ipaddress
import socket
import struct
import sys

site_networks = (ipaddress.ip_network("10.10.0.0/24"), ipaddress.ip_network("10.20.0.0/24"))
lines = [line.split() for line in sys.stdin.read().splitlines()[1:]]
for fields in lines:
    if len(fields) < 8:
        raise SystemExit("target route table has an invalid row")
    destination = int(fields[1], 16)
    mask = int(fields[7], 16)
    if destination == 0 and mask == 0:
        continue
    address = socket.inet_ntoa(struct.pack("<I", destination))
    netmask = socket.inet_ntoa(struct.pack("<I", mask))
    route = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
    if any(route.overlaps(site) for site in site_networks):
        raise SystemExit(f"target has an inner site route through {route}")
'
}
assert_target_isolated "$target_a"
assert_target_isolated "$target_b"

assert_exact_route() {
  local node=$1 prefix=$2 gateway=$3 interface=$4
  docker exec "$node" ip -j -4 route show table main | python3 -c '
import ipaddress
import json
import sys

prefix = ipaddress.ip_network(sys.argv[1])
gateway, interface = sys.argv[2:]
routes = []
for route in json.load(sys.stdin):
    destination = route.get("dst", "default")
    if destination == "default":
        continue
    network = ipaddress.ip_network(destination, strict=False)
    if network.version == prefix.version:
        routes.append((route, network))
exact = [route for route, network in routes if network == prefix]
if (
    len(exact) != 1
    or exact[0].get("gateway") != gateway
    or exact[0].get("dev") != interface
    or exact[0].get("type", "unicast") != "unicast"
    or exact[0].get("from") not in (None, "all")
):
    raise SystemExit(f"{prefix} does not have one exact route via {gateway} dev {interface}")
children = [
    str(network)
    for route, network in routes
    if network != prefix
    and network.subnet_of(prefix)
    and (
        route.get("gateway") != gateway
        or route.get("dev") != interface
        or route.get("type", "unicast") != "unicast"
        or route.get("from") not in (None, "all")
    )
]
if children:
    raise SystemExit(f"{prefix} has a more-specific route-domain bypass: {sorted(children)}")
' "$prefix" "$gateway" "$interface"
}
assert_exact_route "$workload_a" '10.20.0.0/24' "$a_gwlbe_workload_ip" "$a_workload_pre_if"
assert_exact_route "$workload_b" '10.10.0.0/24' "$b_gwlbe_workload_ip" "$b_workload_pre_if"
assert_exact_route "$post_a" '10.10.0.0/24' "$a_workload_post_ip" "$a_post_workload_if"
assert_exact_route "$post_a" '10.20.0.0/24' "$a_transport_a1_ip" "$a_post_transport_if"
assert_exact_route "$post_b" '10.20.0.0/24' "$b_workload_post_ip" "$b_post_workload_if"
assert_exact_route "$post_b" '10.10.0.0/24' "$b_transport_b1_ip" "$b_post_transport_if"
assert_exact_route "$transport_a1" '10.10.0.0/24' "$a_gwlbe_transport_ip" "$a_transport_a1_if"
assert_exact_route "$transport_a2" '10.10.0.0/24' "$a_gwlbe_transport_ip" "$a_transport_a2_if"
assert_exact_route "$transport_b1" '10.20.0.0/24' "$b_gwlbe_transport_ip" "$b_transport_b1_if"
assert_exact_route "$transport_b2" '10.20.0.0/24' "$b_gwlbe_transport_ip" "$b_transport_b2_if"
for node in "$workload_a" "$workload_b" "$post_a" "$post_b"; do
  default_route=$(docker exec "$node" ip route show default)
  if [[ -n "$default_route" ]]; then
    printf 'route domain %s has an unreviewed default bypass\n' "$node" >&2
    exit 1
  fi
done
for endpoint in "$gwlbe_a" "$gwlbe_b"; do
  [[ $(docker exec "$endpoint" sysctl -n net.ipv4.ip_forward) == 0 ]]
done
for domain in "$post_a" "$post_b"; do
  [[ $(docker exec "$domain" sysctl -n net.ipv4.ip_forward) == 1 ]]
done

a_post_peer_mac=$(interface_mac "$post_a" "$a_post_gwlbe_if")
b_post_peer_mac=$(interface_mac "$post_b" "$b_post_gwlbe_if")
a_workload_pre_mac=$(interface_mac "$workload_a" "$a_workload_pre_if")
b_workload_pre_mac=$(interface_mac "$workload_b" "$b_workload_pre_if")
a_gwlbe_workload_mac=$(interface_mac "$gwlbe_a" "$a_gwlbe_workload_if")
b_gwlbe_workload_mac=$(interface_mac "$gwlbe_b" "$b_gwlbe_workload_if")
a_gwlbe_transport_mac=$(interface_mac "$gwlbe_a" "$a_gwlbe_transport_if")
b_gwlbe_transport_mac=$(interface_mac "$gwlbe_b" "$b_gwlbe_transport_if")
a_transport_a1_mac=$(interface_mac "$transport_a1" "$a_transport_a1_if")
a_transport_a2_mac=$(interface_mac "$transport_a2" "$a_transport_a2_if")
b_transport_b1_mac=$(interface_mac "$transport_b1" "$b_transport_b1_if")
b_transport_b2_mac=$(interface_mac "$transport_b2" "$b_transport_b2_if")
for endpoint in "$gwlbe_a" "$gwlbe_b"; do
  docker exec "$endpoint" rm -f /tmp/gwlb-events.jsonl /tmp/gwlb-ready /tmp/gwlb-error
done
docker exec -d "$gwlbe_a" sh -c "exec python3 /run/envelope-test/gwlb-loop.py target-a '$a_gwlbe_post_if' '$a_post_peer_mac' /tmp/gwlb-events.jsonl /tmp/gwlb-ready 10.10.0.0/24 10.20.0.0/24 workload='$a_gwlbe_workload_if' transport-router='$a_gwlbe_transport_if' router='$a_transport_a1_mac,$transport_a1' router='$a_transport_a2_mac,$transport_a2' >/tmp/gwlb.log 2>&1"
docker exec -d "$gwlbe_b" sh -c "exec python3 /run/envelope-test/gwlb-loop.py target-b '$b_gwlbe_post_if' '$b_post_peer_mac' /tmp/gwlb-events.jsonl /tmp/gwlb-ready 10.20.0.0/24 10.10.0.0/24 workload='$b_gwlbe_workload_if' transport-router='$b_gwlbe_transport_if' router='$b_transport_b1_mac,$transport_b1' router='$b_transport_b2_mac,$transport_b2' >/tmp/gwlb.log 2>&1"
for endpoint in "$gwlbe_a" "$gwlbe_b"; do
  for _ in $(seq 1 50); do
    if docker exec "$endpoint" test -f /tmp/gwlb-ready; then
      break
    fi
    sleep 0.1
  done
  docker exec "$endpoint" test -f /tmp/gwlb-ready
done

wait_file() {
  local container=$1 path=$2
  for _ in $(seq 1 200); do
    if docker exec "$container" test -f "$path"; then
      return
    fi
    sleep 0.1
  done
  printf 'timed out waiting for %s on %s\n' "$path" "$container" >&2
  exit 1
}

assert_shared_dispatch_barrier() {
  python3 -c '
import sys
values = [int(value) for value in sys.argv[1:]]
if len(values) != 6:
    raise SystemExit("the cold-initiation barrier requires all six direction flows")
skew = max(values) - min(values)
if skew > 500_000_000:
    raise SystemExit(f"six-flow cold-initiation dispatch skew {skew}ns exceeds 500ms")
' "$@"
}

run_six_flow_barrier() {
  local start_at mss_a mss_b
  for workload in "$workload_a" "$workload_b"; do
    docker exec "$workload" sh -c 'rm -f /tmp/ready-tcp-* /tmp/ready-udp-* /tmp/result-tcp-* /tmp/result-udp-* /tmp/result-icmp-* /tmp/dispatch-tcp-* /tmp/dispatch-udp-* /tmp/dispatch-icmp-* /tmp/mss-*.pcap'
  done

  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py tcp server 10.10.0.10 10.20.0.10 22001 b-to-a-tcp 0
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py tcp server 10.20.0.10 10.10.0.10 22002 a-to-b-tcp 0
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py udp server 10.10.0.10 10.20.0.10 21001 b-to-a-udp 0
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py udp server 10.20.0.10 10.10.0.10 21002 a-to-b-udp 0
  wait_file "$workload_a" /tmp/ready-tcp-22001
  wait_file "$workload_b" /tmp/ready-tcp-22002
  wait_file "$workload_a" /tmp/ready-udp-21001
  wait_file "$workload_b" /tmp/ready-udp-21002

  docker exec -d "$workload_a" tcpdump -U -i "$a_workload_post_if" -c 1 -w /tmp/mss-a.pcap 'tcp and dst port 22001'
  docker exec -d "$workload_b" tcpdump -U -i "$b_workload_post_if" -c 1 -w /tmp/mss-b.pcap 'tcp and dst port 22002'
  sleep 0.5
  start_at=$(python3 -c 'import time; print(time.time() + 2)')
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py tcp client 10.10.0.10 10.20.0.10 22002 a-to-b-tcp "$start_at"
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py tcp client 10.20.0.10 10.10.0.10 22001 b-to-a-tcp "$start_at"
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py udp client 10.10.0.10 10.20.0.10 21002 a-to-b-udp "$start_at"
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py udp client 10.20.0.10 10.10.0.10 21001 b-to-a-udp "$start_at"
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py icmp client 10.10.0.10 10.20.0.10 24002 a-to-b-icmp "$start_at"
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py icmp client 10.20.0.10 10.10.0.10 24001 b-to-a-icmp "$start_at"

  for spec in \
    "$workload_a:/tmp/result-tcp-server-22001:10.20.0.10" \
    "$workload_a:/tmp/result-tcp-client-22002:10.20.0.10" \
    "$workload_b:/tmp/result-tcp-server-22002:10.10.0.10" \
    "$workload_b:/tmp/result-tcp-client-22001:10.10.0.10" \
    "$workload_a:/tmp/result-udp-server-21001:10.20.0.10" \
    "$workload_a:/tmp/result-udp-client-21002:10.20.0.10" \
    "$workload_b:/tmp/result-udp-server-21002:10.10.0.10" \
    "$workload_b:/tmp/result-udp-client-21001:10.10.0.10" \
    "$workload_a:/tmp/result-icmp-client-24002:10.20.0.10" \
    "$workload_b:/tmp/result-icmp-client-24001:10.10.0.10"; do
    container=${spec%%:*}
    remainder=${spec#*:}
    path=${remainder%%:*}
    expected=${remainder##*:}
    wait_file "$container" "$path"
    [[ $(docker exec "$container" cat "$path") == "$expected" ]]
  done

  assert_shared_dispatch_barrier \
    "$(docker exec "$workload_a" cat /tmp/dispatch-tcp-client-22002)" \
    "$(docker exec "$workload_b" cat /tmp/dispatch-tcp-client-22001)" \
    "$(docker exec "$workload_a" cat /tmp/dispatch-udp-client-21002)" \
    "$(docker exec "$workload_b" cat /tmp/dispatch-udp-client-21001)" \
    "$(docker exec "$workload_a" cat /tmp/dispatch-icmp-client-24002)" \
    "$(docker exec "$workload_b" cat /tmp/dispatch-icmp-client-24001)"

  wait_file "$workload_a" /tmp/mss-a.pcap
  wait_file "$workload_b" /tmp/mss-b.pcap
  mss_a=$(docker exec "$workload_a" tcpdump -nn -vv -r /tmp/mss-a.pcap)
  mss_b=$(docker exec "$workload_b" tcpdump -nn -vv -r /tmp/mss-b.pcap)
  grep -q 'mss 1240' <<<"$mss_a"
  grep -q 'mss 1240' <<<"$mss_b"
}

run_six_flow_barrier

run_opaque_fragments() {
  local start_at
  for node in "$gwlbe_a" "$gwlbe_b"; do
    docker exec "$node" sh -c 'rm -f /tmp/fragment-source-*.json /tmp/fragment-destination-*.json'
  done
  start_at=$(python3 -c 'import time; print(time.time() + 1)')
  docker exec "$gwlbe_a" python3 /run/envelope-test/fragment-probe.py inject 10.10.0.10 10.20.0.10 "$a_gwlbe_workload_if" "$a_workload_pre_mac" "$a_gwlbe_workload_mac" 0x7a31 opaque-a-to-b "$start_at" /tmp/fragment-source-a-to-b.json
  docker exec "$gwlbe_b" python3 /run/envelope-test/fragment-probe.py inject 10.10.0.10 10.20.0.10 "$b_gwlbe_transport_if" "$b_transport_b1_mac" "$b_gwlbe_transport_mac" 0x7a31 opaque-a-to-b "$start_at" /tmp/fragment-destination-a-to-b.json
  docker exec "$gwlbe_b" python3 /run/envelope-test/fragment-probe.py inject 10.20.0.10 10.10.0.10 "$b_gwlbe_workload_if" "$b_workload_pre_mac" "$b_gwlbe_workload_mac" 0x7a32 opaque-b-to-a "$start_at" /tmp/fragment-source-b-to-a.json
  docker exec "$gwlbe_a" python3 /run/envelope-test/fragment-probe.py inject 10.20.0.10 10.10.0.10 "$a_gwlbe_transport_if" "$a_transport_a1_mac" "$a_gwlbe_transport_mac" 0x7a32 opaque-b-to-a "$start_at" /tmp/fragment-destination-b-to-a.json
  wait_file "$gwlbe_a" /tmp/fragment-source-a-to-b.json
  wait_file "$gwlbe_b" /tmp/fragment-source-b-to-a.json
  wait_file "$gwlbe_a" /tmp/fragment-destination-b-to-a.json
  wait_file "$gwlbe_b" /tmp/fragment-destination-a-to-b.json
  docker cp "$gwlbe_a:/tmp/fragment-source-a-to-b.json" "$work_dir/fragment-source-a-to-b.json" >/dev/null
  docker cp "$gwlbe_b:/tmp/fragment-source-b-to-a.json" "$work_dir/fragment-source-b-to-a.json" >/dev/null
  docker cp "$gwlbe_b:/tmp/fragment-destination-a-to-b.json" "$work_dir/fragment-destination-a-to-b.json" >/dev/null
  docker cp "$gwlbe_a:/tmp/fragment-destination-b-to-a.json" "$work_dir/fragment-destination-b-to-a.json" >/dev/null
  python3 - "$work_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for direction in ("a-to-b", "b-to-a"):
    source = json.loads((root / f"fragment-source-{direction}.json").read_text())
    destination = json.loads((root / f"fragment-destination-{direction}.json").read_text())
    for field in (
        "source",
        "destination",
        "ip_id",
        "fragment_offset",
        "payload_sha256",
        "packet_correlation_sha256",
    ):
        if source[field] != destination[field]:
            raise SystemExit(f"opaque fragment {direction} changed between GWLBE input roles")
PY
}

run_opaque_fragments

rule_packets() {
  local node=$1 table=$2 chain=$3 input=$4 output=$5
  docker exec "$node" iptables-save -c -t "$table" | python3 -c '
import shlex
import sys

chain, input_interface, output_interface = sys.argv[1:]
for line in sys.stdin:
    fields = shlex.split(line)
    if not fields or not fields[0].startswith("["):
        continue
    if all(value in fields for value in ("-A", chain, "-i", input_interface, "-o", output_interface)):
        print(fields[0][1:].split(":", 1)[0])
        raise SystemExit(0)
raise SystemExit(f"missing counter for {chain} {input_interface}->{output_interface}")
' "$chain" "$input" "$output"
}

a_underlay_to_tailnet=$((
  $(rule_packets "$transport_a1" filter ENVELOPE-TRANSPORT-FORWARD "$a_transport_a1_if" tailscale0) +
  $(rule_packets "$transport_a2" filter ENVELOPE-TRANSPORT-FORWARD "$a_transport_a2_if" tailscale0)
))
b_underlay_to_tailnet=$((
  $(rule_packets "$transport_b1" filter ENVELOPE-TRANSPORT-FORWARD "$b_transport_b1_if" tailscale0) +
  $(rule_packets "$transport_b2" filter ENVELOPE-TRANSPORT-FORWARD "$b_transport_b2_if" tailscale0)
))
a_tailnet_to_underlay=$((
  $(rule_packets "$transport_a1" filter ENVELOPE-TRANSPORT-FORWARD tailscale0 "$a_transport_a1_if") +
  $(rule_packets "$transport_a2" filter ENVELOPE-TRANSPORT-FORWARD tailscale0 "$a_transport_a2_if")
))
b_tailnet_to_underlay=$((
  $(rule_packets "$transport_b1" filter ENVELOPE-TRANSPORT-FORWARD tailscale0 "$b_transport_b1_if") +
  $(rule_packets "$transport_b2" filter ENVELOPE-TRANSPORT-FORWARD tailscale0 "$b_transport_b2_if")
))
(( a_underlay_to_tailnet > 0 && b_underlay_to_tailnet > 0 ))
(( a_tailnet_to_underlay > 0 && b_tailnet_to_underlay > 0 ))

a_mss_out=$((
  $(rule_packets "$transport_a1" mangle ENVELOPE-TRANSPORT-MSS "$a_transport_a1_if" tailscale0) +
  $(rule_packets "$transport_a2" mangle ENVELOPE-TRANSPORT-MSS "$a_transport_a2_if" tailscale0)
))
b_mss_out=$((
  $(rule_packets "$transport_b1" mangle ENVELOPE-TRANSPORT-MSS "$b_transport_b1_if" tailscale0) +
  $(rule_packets "$transport_b2" mangle ENVELOPE-TRANSPORT-MSS "$b_transport_b2_if" tailscale0)
))
a_mss_in=$((
  $(rule_packets "$transport_a1" mangle ENVELOPE-TRANSPORT-MSS tailscale0 "$a_transport_a1_if") +
  $(rule_packets "$transport_a2" mangle ENVELOPE-TRANSPORT-MSS tailscale0 "$a_transport_a2_if")
))
b_mss_in=$((
  $(rule_packets "$transport_b1" mangle ENVELOPE-TRANSPORT-MSS tailscale0 "$b_transport_b1_if") +
  $(rule_packets "$transport_b2" mangle ENVELOPE-TRANSPORT-MSS tailscale0 "$b_transport_b2_if")
))
(( a_mss_out > 0 && b_mss_out > 0 && a_mss_in > 0 && b_mss_in > 0 ))

assert_transport_firewall "$transport_a1" "$a_transport_a1_if" '10.10.0.0/24' '10.20.0.0/24'
assert_transport_firewall "$transport_a2" "$a_transport_a2_if" '10.10.0.0/24' '10.20.0.0/24'
assert_transport_firewall "$transport_b1" "$b_transport_b1_if" '10.20.0.0/24' '10.10.0.0/24'
assert_transport_firewall "$transport_b2" "$b_transport_b2_if" '10.20.0.0/24' '10.10.0.0/24'

events_verified=false
for _ in $(seq 1 50); do
  docker cp "$gwlbe_a:/tmp/gwlb-events.jsonl" "$work_dir/events-a.jsonl" >/dev/null 2>&1 || true
  docker cp "$gwlbe_b:/tmp/gwlb-events.jsonl" "$work_dir/events-b.jsonl" >/dev/null 2>&1 || true
  if python3 "$work_dir/verify-events.py" "$work_dir/events-a.jsonl" 10.10.0.10 10.20.0.10 "$transport_a1" "$transport_a2" >/dev/null 2>&1 \
    && python3 "$work_dir/verify-events.py" "$work_dir/events-b.jsonl" 10.20.0.10 10.10.0.10 "$transport_b1" "$transport_b2" >/dev/null 2>&1 \
    && python3 "$work_dir/verify-correlations.py" "$work_dir/events-a.jsonl" "$work_dir/events-b.jsonl" 10.10.0.10 10.20.0.10 "$work_dir/turnaround-correlations.jsonl" >/dev/null 2>&1; then
    events_verified=true
    break
  fi
  sleep 0.1
done
if [[ "$events_verified" != true ]]; then
  python3 "$work_dir/verify-events.py" "$work_dir/events-a.jsonl" 10.10.0.10 10.20.0.10 "$transport_a1" "$transport_a2"
  python3 "$work_dir/verify-events.py" "$work_dir/events-b.jsonl" 10.20.0.10 10.10.0.10 "$transport_b1" "$transport_b2"
  python3 "$work_dir/verify-correlations.py" "$work_dir/events-a.jsonl" "$work_dir/events-b.jsonl" 10.10.0.10 10.20.0.10 "$work_dir/turnaround-correlations.jsonl"
  exit 1
fi
test -s "$work_dir/turnaround-correlations.jsonl"

for pair in "target-a:$gwlbe_a" "target-b:$gwlbe_b"; do
  alias=${pair%%:*}
  observer=${pair#*:}
  docker exec "$observer" curl -fsS "http://$alias:9090/metrics" \
    | python3 -c '
import re
import sys
packets = {}
components = {}
target_ready = None
obsolete_prefixes = (
    "datapath_",
    "gwlb_conflicted_contexts",
    "gwlb_context_",
    "gwlb_missing_contexts",
    "gwlb_possible_loops",
    "gwlb_unsupported_inner",
    "routing_",
    "symmetric_unexpected_egress",
    "tun_",
)
for line in sys.stdin:
    if not line.strip() or line.startswith("#"):
        continue
    series, raw_value = line.split()
    name = series.split("{", 1)[0]
    if name.startswith(obsolete_prefixes):
        raise SystemExit(f"target exposed obsolete metric {name}")
    if name in {"geneve_rx_packets", "geneve_tx_packets"}:
        packets[name] = float(raw_value)
    elif name == "gwlb_target_ready":
        target_ready = float(raw_value)
    elif name == "gwlb_target_component_ready":
        match = re.search(r"component=\"([^\"]+)\"", series)
        if match:
            components[match.group(1)] = float(raw_value)
if packets.get("geneve_rx_packets", 0) <= 0 or packets.get("geneve_tx_packets", 0) <= 0:
    raise SystemExit("target lacks receive/return metric evidence")
expected = {"receiver": 1.0, "validation": 1.0, "sender": 1.0}
if target_ready != 1.0 or components != expected:
    raise SystemExit(
        f"target lacks current readiness metric evidence: ready={target_ready} components={components}"
    )
'
done

run_blocked_pair() {
  local target=$1 alias=$2 observer=$3 port_a=$4 port_b=$5 start_at
  docker stop -t 1 "$target" >/dev/null
  for workload in "$workload_a" "$workload_b"; do
    docker exec "$workload" sh -c "rm -f /tmp/ready-blocked-$port_a /tmp/ready-blocked-$port_b /tmp/result-blocked-*-$port_a /tmp/result-blocked-*-$port_b"
  done
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py blocked server 10.10.0.10 10.20.0.10 "$port_a" blocked-b-to-a 0
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py blocked server 10.20.0.10 10.10.0.10 "$port_b" blocked-a-to-b 0
  wait_file "$workload_a" "/tmp/ready-blocked-$port_a"
  wait_file "$workload_b" "/tmp/ready-blocked-$port_b"
  start_at=$(python3 -c 'import time; print(time.time() + 0.5)')
  docker exec -d "$workload_a" python3 /run/envelope-test/probe.py blocked client 10.10.0.10 10.20.0.10 "$port_b" blocked-a-to-b "$start_at"
  docker exec -d "$workload_b" python3 /run/envelope-test/probe.py blocked client 10.20.0.10 10.10.0.10 "$port_a" blocked-b-to-a "$start_at"
  wait_file "$workload_a" "/tmp/result-blocked-server-$port_a"
  wait_file "$workload_b" "/tmp/result-blocked-server-$port_b"
  [[ $(docker exec "$workload_a" cat "/tmp/result-blocked-server-$port_a") == blocked ]]
  [[ $(docker exec "$workload_b" cat "/tmp/result-blocked-server-$port_b") == blocked ]]
  docker start "$target" >/dev/null
  wait_target_healthy "$alias" "$observer"
}

# Each stopped target blocks both its source-site and destination-site inspection
# positions. Successful delivery here would prove a route-domain bypass.
run_blocked_pair "$target_a" target-a "$gwlbe_a" 23001 23002
run_blocked_pair "$target_b" target-b "$gwlbe_b" 23003 23004

[[ $(wc -l <"$work_dir/transport-contract-hashes.tsv") -eq 4 ]]
printf '%s\n' 'headscale separated-role six-flow/fragment integration ok; production host-network script executed'
