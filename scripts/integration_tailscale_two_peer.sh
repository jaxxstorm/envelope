#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "SaaS transport-router harness failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

TAILSCALE_IMAGE='tailscale/tailscale:v1.80.3@sha256:af6026ed3e5892c5d4966962618a09685198111507df16803b2aec7066046582'

for variable in TAILSCALE_AUTH_KEY_A_FILE TAILSCALE_AUTH_KEY_B_FILE; do
  if [[ -z "${!variable:-}" || ! -r "${!variable}" ]]; then
    printf 'optional authenticated transport-router integration requires readable %s\n' "$variable" >&2
    exit 77
  fi
done
if [[ "${ENVELOPE_TAILNET_ROUTES_PREAPPROVED:-}" != "1" ]]; then
  printf '%s\n' "set ENVELOPE_TAILNET_ROUTES_PREAPPROVED=1 only after the test Tailnet auto-approves both transport routers' routes" >&2
  exit 77
fi
for command in docker python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 77
  fi
done
if ! python3 -c 'import subprocess,sys; sys.exit(subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode)' 2>/dev/null; then
  printf '%s\n' 'a running Docker daemon is required' >&2
  exit 77
fi

run_id="$$-$(date +%s)"
transport_router_a="envelope-transport-router-a-$run_id"
transport_router_b="envelope-transport-router-b-$run_id"
state_a="envelope-transport-router-state-a-$run_id"
state_b="envelope-transport-router-state-b-$run_id"

cleanup() {
  docker rm -f "$transport_router_a" "$transport_router_b" >/dev/null 2>&1 || true
  docker volume rm "$state_a" "$state_b" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$state_a" >/dev/null
docker volume create "$state_b" >/dev/null

start_transport_router() {
  local name=$1 state=$2 key_file=$3 routes=$4
  docker run -d \
    --name "$name" \
    --hostname "$name" \
    --privileged \
    --device=/dev/net/tun \
    -e TS_AUTHKEY=file:/run/secrets/tailscale-auth-key \
    -e TS_AUTH_ONCE=true \
    -e TS_STATE_DIR=/var/lib/tailscale \
    -e TS_USERSPACE=false \
    -e TS_ACCEPT_DNS=false \
    -e TS_ROUTES="$routes" \
    -e "TS_EXTRA_ARGS=--hostname=$name --accept-routes --snat-subnet-routes=false --netfilter-mode=off" \
    -v "$state:/var/lib/tailscale" \
    -v "$key_file:/run/secrets/tailscale-auth-key:ro" \
    "$TAILSCALE_IMAGE" >/dev/null
}

start_transport_router "$transport_router_a" "$state_a" "$TAILSCALE_AUTH_KEY_A_FILE" \
  "10.10.0.0/24,10.11.0.0/24"
start_transport_router "$transport_router_b" "$state_b" "$TAILSCALE_AUTH_KEY_B_FILE" \
  "10.20.0.0/24,10.21.0.0/24"

for transport_router in "$transport_router_a" "$transport_router_b"; do
  docker exec "$transport_router" apk add --no-cache iproute2 iptables nftables python3 >/dev/null
done

wait_running() {
  local transport_router=$1
  for _ in $(seq 1 90); do
    if docker exec "$transport_router" tailscale status --json 2>/dev/null \
      | grep -Eq '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then
      return
    fi
    sleep 1
  done
  printf 'tailscaled did not become Running on transport-router %s\n' "$transport_router" >&2
  exit 1
}
wait_running "$transport_router_a"
wait_running "$transport_router_b"

verify_transport_router_control_plane() {
  local transport_router=$1 expected_hostname=$2 expected_routes=$3
  docker exec "$transport_router" tailscale status --json | python3 -c '
import json
import sys

expected = sys.argv[1]
status = json.load(sys.stdin)
self_status = status.get("Self", {})
if (
    status.get("BackendState") != "Running"
    or status.get("TUN") is not True
    or status.get("Health", [])
    or self_status.get("Online") is not True
    or self_status.get("HostName") != expected
):
    raise SystemExit("transport-router backend, TUN, health, or hostname is not ready")
' "$expected_hostname"
  docker exec "$transport_router" tailscale debug prefs | python3 -c '
import json
import sys

expected = set(sys.argv[1].split(","))
prefs = json.load(sys.stdin)
if set(prefs.get("AdvertiseRoutes", [])) != expected:
    raise SystemExit("transport-router does not advertise the exact optional SaaS prefixes")
if prefs.get("RouteAll") is not True or prefs.get("NoSNAT") is not True:
    raise SystemExit("transport-router does not accept routes without SNAT")
' "$expected_routes"
}
verify_transport_router_control_plane "$transport_router_a" "$transport_router_a" \
  "10.10.0.0/24,10.11.0.0/24"
verify_transport_router_control_plane "$transport_router_b" "$transport_router_b" \
  "10.20.0.0/24,10.21.0.0/24"

wait_remote_routes() {
  local transport_router=$1 routes=$2 route ready
  IFS=, read -r -a expected <<<"$routes"
  for _ in $(seq 1 90); do
    ready=true
    for route in "${expected[@]}"; do
      if ! docker exec "$transport_router" ip route show table 52 "$route" \
        | grep -Fq 'dev tailscale0'; then
        ready=false
        break
      fi
    done
    if [[ "$ready" == true ]]; then
      return
    fi
    sleep 1
  done
  printf 'transport-router %s did not accept exact remote routes %s\n' \
    "$transport_router" "$routes" >&2
  exit 1
}
wait_remote_routes "$transport_router_a" "10.20.0.0/24,10.21.0.0/24"
wait_remote_routes "$transport_router_b" "10.10.0.0/24,10.11.0.0/24"

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
raise SystemExit("required online transport-router peer is absent")
' "$expected_hostname"
}
docker exec "$transport_router_a" tailscale ping --timeout=5s \
  "$(tailscale_peer_ip "$transport_router_a" "$transport_router_b")" >/dev/null
docker exec "$transport_router_b" tailscale ping --timeout=5s \
  "$(tailscale_peer_ip "$transport_router_b" "$transport_router_a")" >/dev/null

configure_transport_router() {
  docker exec -i "$1" sh -s -- "$2" "$3" "$4" "$5" <<'SH'
set -eu
first_local_cidr=$1
first_local_ip=$2
second_local_cidr=$3
second_local_ip=$4

ip netns add workload
ip link add workload0 type veth peer name workload-peer
ip link set workload-peer netns workload
ip link set workload0 up
ip -n workload link set lo up
ip -n workload link set workload-peer up
ip address add 198.18.255.1/32 dev workload0
ip -n workload address add "$first_local_ip/32" dev workload-peer
ip -n workload address add "$second_local_ip/32" dev workload-peer
ip route replace "$first_local_cidr" dev workload0
ip route replace "$second_local_cidr" dev workload0
ip -n workload route add default via 198.18.255.1 dev workload-peer onlink

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.tailscale0.rp_filter=0
sysctl -q -w net.ipv4.conf.workload0.rp_filter=0

nft flush ruleset
iptables -P FORWARD DROP
iptables -N ENVELOPE-TRANSPORT-FORWARD
iptables -A FORWARD -j ENVELOPE-TRANSPORT-FORWARD
iptables -A ENVELOPE-TRANSPORT-FORWARD -i workload0 -o tailscale0 -j ACCEPT
iptables -A ENVELOPE-TRANSPORT-FORWARD -i tailscale0 -o workload0 -j ACCEPT
iptables -t mangle -N ENVELOPE-TRANSPORT-MSS
iptables -t mangle -A FORWARD -j ENVELOPE-TRANSPORT-MSS
iptables -t mangle -A ENVELOPE-TRANSPORT-MSS -i workload0 -o tailscale0 \
  -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -A ENVELOPE-TRANSPORT-MSS -i tailscale0 -o workload0 \
  -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -A ENVELOPE-TRANSPORT-MSS -j RETURN
if iptables-save -t nat | grep -Eq -- '-j (SNAT|MASQUERADE)( |$)'; then
  printf '%s\n' 'optional SaaS transport-router contains NAT' >&2
  exit 1
fi
test ! -e /sys/class/net/envelope0
SH
}

configure_transport_router "$transport_router_a" \
  "10.10.0.0/24" "10.10.0.1" "10.11.0.0/24" "10.11.0.1"
configure_transport_router "$transport_router_b" \
  "10.20.0.0/24" "10.20.0.1" "10.21.0.0/24" "10.21.0.1"

send_and_receive() {
  local source_router=$1 source_ip=$2 destination_router=$3 destination_ip=$4
  local port=$5 marker=$6 received="/tmp/tailscale-transport-received-$port"

  docker exec "$destination_router" rm -f "$received"
  docker exec -d "$destination_router" ip netns exec workload python3 -c \
    "import pathlib,socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$destination_ip',$port)); d,p=s.recvfrom(64); ok=d == b'$marker' and p[0] == '$source_ip'; pathlib.Path('$received').write_bytes(d if ok else b''); raise SystemExit(0 if ok else 2)"
  sleep 0.2
  docker exec "$source_router" ip netns exec workload python3 -c \
    "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$source_ip',0)); s.sendto(b'$marker',('$destination_ip',$port)); s.close()"
  for _ in $(seq 1 20); do
    if docker exec "$destination_router" python3 -c \
      "from pathlib import Path; raise SystemExit(0 if Path('$received').read_bytes() == b'$marker' else 1)" \
      2>/dev/null; then
      return
    fi
    sleep 0.2
  done
  printf 'optional SaaS transport-router delivery did not reach %s\n' "$destination_router" >&2
  exit 1
}

# This retains only the historical optional Tailnet route check. It neither runs
# an Envelope target nor provides a compatibility path for version-2 target TUN
# or direct-forwarding behavior; the Headscale harness is the local acceptance gate.
send_and_receive "$transport_router_a" 10.10.0.1 "$transport_router_b" 10.20.0.1 \
  19000 site_a_to_b
send_and_receive "$transport_router_b" 10.21.0.1 "$transport_router_a" 10.11.0.1 \
  19002 site_b_to_a

printf '%s\n' 'optional historical Tailscale SaaS transport-router route check ok (not version-2 target compatibility)'
