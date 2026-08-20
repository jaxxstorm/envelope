#!/usr/bin/env bash
set -euo pipefail

TAILSCALE_IMAGE='tailscale/tailscale:v1.80.3@sha256:af6026ed3e5892c5d4966962618a09685198111507df16803b2aec7066046582'

for variable in TAILSCALE_AUTH_KEY_A_FILE TAILSCALE_AUTH_KEY_B_FILE; do
  if [[ -z "${!variable:-}" || ! -r "${!variable}" ]]; then
    printf 'authenticated integration requires readable %s\n' "$variable" >&2
    exit 77
  fi
done
if [[ "${ENVELOPE_TAILNET_ROUTES_PREAPPROVED:-}" != "1" ]]; then
  printf '%s\n' "set ENVELOPE_TAILNET_ROUTES_PREAPPROVED=1 only after the test Tailnet auto-approves both peers' routes" >&2
  exit 77
fi
for command in docker go curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 77
  fi
done

run_id="$$"
site_a="envelope-ts-a-$run_id"
site_b="envelope-ts-b-$run_id"
state_a="envelope-ts-state-a-$run_id"
state_b="envelope-ts-state-b-$run_id"
binary_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$site_a" "$site_b" >/dev/null 2>&1 || true
  docker volume rm "$state_a" "$state_b" >/dev/null 2>&1 || true
  rm -rf "$binary_dir"
}
trap cleanup EXIT

CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$binary_dir/envelope" ./cmd/envelope
docker volume create "$state_a" >/dev/null
docker volume create "$state_b" >/dev/null

start_peer() {
  local name=$1
  local state=$2
  local key_file=$3
  local routes=$4
  docker run -d \
    --name "$name" \
    --hostname "$name" \
    --privileged \
    --device=/dev/net/tun \
    -e TS_AUTHKEY=file:/run/secrets/tailscale-auth-key \
    -e TS_AUTH_ONCE=true \
    -e TS_STATE_DIR=/var/lib/tailscale \
    -e TS_USERSPACE=false \
    -e TS_ROUTES="$routes" \
    -e 'TS_EXTRA_ARGS=--accept-routes --snat-subnet-routes=false --netfilter-mode=off' \
    -v "$state:/var/lib/tailscale" \
    -v "$key_file:/run/secrets/tailscale-auth-key:ro" \
    -v "$binary_dir/envelope:/usr/local/bin/envelope:ro" \
    "$TAILSCALE_IMAGE" >/dev/null
}

start_peer "$site_a" "$state_a" "$TAILSCALE_AUTH_KEY_A_FILE" "10.10.0.0/24,10.11.0.0/24"
start_peer "$site_b" "$state_b" "$TAILSCALE_AUTH_KEY_B_FILE" "10.20.0.0/24,10.21.0.0/24"

for peer in "$site_a" "$site_b"; do
  docker exec "$peer" sh -c 'apk add --no-cache curl iproute2 iptables nftables python3 >/dev/null; mkdir -p /usr/bin /usr/sbin; ln -sf /usr/local/bin/tailscale /usr/bin/tailscale; ln -sf "$(command -v ip)" /usr/sbin/ip; ln -sf "$(command -v iptables)" /usr/sbin/iptables; ln -sf "$(command -v ip6tables)" /usr/sbin/ip6tables; ln -sf "$(command -v iptables-save)" /usr/sbin/iptables-save; ln -sf "$(command -v ip6tables-save)" /usr/sbin/ip6tables-save; nft_path=$(command -v nft); if [ "$nft_path" != /usr/sbin/nft ]; then ln -sf "$nft_path" /usr/sbin/nft; fi'
done

wait_running() {
  local peer=$1
  for _ in $(seq 1 90); do
    if docker exec "$peer" tailscale status --json 2>/dev/null | grep -Eq '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then
      return
    fi
    sleep 1
  done
  printf 'tailscaled did not become Running on %s\n' "$peer" >&2
  exit 1
}
wait_running "$site_a"
wait_running "$site_b"

configure_site() {
  local peer=$1
  local return_cidr=$2
  local return_ip=$3
  local delivery_cidr=$4
  local delivery_ip=$5
  local remote_cidrs=$6

  docker exec "$peer" ip netns add workload
  docker exec "$peer" ip link add workload0 type veth peer name workload-peer
  docker exec "$peer" ip link set workload-peer netns workload
  docker exec "$peer" ip link set workload0 up
  docker exec "$peer" ip -n workload link set lo up
  docker exec "$peer" ip -n workload link set workload-peer up
  docker exec "$peer" ip addr add 198.18.255.1/32 dev workload0
  docker exec "$peer" ip -n workload addr add "$return_ip/32" dev workload-peer
  docker exec "$peer" ip -n workload addr add "$delivery_ip/32" dev workload-peer
  docker exec "$peer" ip route add "$return_cidr" dev workload0
  docker exec "$peer" ip route add "$delivery_cidr" dev workload0
  docker exec "$peer" ip -n workload route add default via 198.18.255.1 dev workload-peer onlink
  docker exec "$peer" sysctl -q -w net.ipv4.ip_forward=1
  docker exec "$peer" sysctl -q -w net.ipv6.conf.all.forwarding=1
  docker exec "$peer" sysctl -q -w net.ipv4.conf.all.rp_filter=0
  docker exec "$peer" sysctl -q -w net.ipv4.conf.default.rp_filter=0
  docker exec "$peer" sysctl -q -w net.ipv4.conf.eth0.rp_filter=0
  docker exec "$peer" sysctl -q -w net.ipv4.conf.tailscale0.rp_filter=0
  docker exec "$peer" sysctl -q -w net.ipv4.conf.workload0.rp_filter=0
  docker exec "$peer" nft flush ruleset

  for binary in /usr/sbin/iptables /usr/sbin/ip6tables; do
    docker exec "$peer" "$binary" -P FORWARD ACCEPT
    docker exec "$peer" "$binary" -N ENVELOPE-FORWARD
    docker exec "$peer" "$binary" -I FORWARD 1 -j ENVELOPE-FORWARD
    docker exec "$peer" "$binary" -t mangle -N ENVELOPE-MSS
    docker exec "$peer" "$binary" -t mangle -I FORWARD 1 -j ENVELOPE-MSS
    for path in "workload0 tailscale0" "tailscale0 workload0" "envelope0 tailscale0" "tailscale0 envelope0"; do
      read -r input output <<<"$path"
      docker exec "$peer" "$binary" -A ENVELOPE-FORWARD -i "$input" -o "$output" -j ACCEPT
      mss=1240
      if [[ "$binary" == /usr/sbin/ip6tables ]]; then
        mss=1220
      fi
      docker exec "$peer" "$binary" -t mangle -A ENVELOPE-MSS -i "$input" -o "$output" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    done
    docker exec "$peer" "$binary" -t mangle -A ENVELOPE-MSS -j RETURN
  done

  docker exec -d "$peer" envelope \
    --udp-bind=0.0.0.0:6081 \
    --metrics-addr=127.0.0.1:9090 \
    --tun-name=envelope0 \
    --tun-mtu=1280 \
    --routing-mode=manage \
    --underlay-interface=workload0 \
    --tailscale-iface=tailscale0 \
    --gwlb-return-cidrs="$return_cidr" \
    --local-delivery-cidrs="$delivery_cidr" \
    --remote-tailnet-cidrs="$remote_cidrs"
}

configure_site "$site_a" "10.10.0.0/24" "10.10.0.1" "10.11.0.0/24" "10.11.0.1" "10.20.0.0/24,10.21.0.0/24"
configure_site "$site_b" "10.21.0.0/24" "10.21.0.1" "10.20.0.0/24" "10.20.0.1" "10.10.0.0/24,10.11.0.0/24"

wait_healthy() {
  local peer=$1
  for _ in $(seq 1 90); do
    if docker exec "$peer" curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  printf 'Envelope did not become healthy on %s\n' "$peer" >&2
  docker exec "$peer" curl -s http://127.0.0.1:9090/healthz >&2 || true
  exit 1
}
wait_healthy "$site_a"
wait_healthy "$site_b"

tun_reads() {
  local peer=$1
  docker exec "$peer" sh -c "curl -fsS http://127.0.0.1:9090/metrics | awk '\$1 ~ /^tun_rx_packets(_total)?\$/ {print int(\$2)}'"
}

send_and_receive() {
  local source_peer=$1
  local source_ip=$2
  local destination_peer=$3
  local destination_ip=$4
  local port=$5
  local marker=$6
	local received="/tmp/envelope-received-$port"

  docker exec "$destination_peer" rm -f "$received"
  docker exec -d "$destination_peer" ip netns exec workload python3 -c "import socket, pathlib; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$destination_ip',$port)); d,_=s.recvfrom(64); pathlib.Path('$received').write_bytes(d); raise SystemExit(0 if d == b'$marker' else 2)"
  sleep 0.2
  docker exec "$source_peer" ip netns exec workload python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$source_ip',0)); s.sendto(b'$marker',('$destination_ip',$port)); s.close()"
  for _ in $(seq 1 20); do
    if docker exec "$destination_peer" python3 -c "from pathlib import Path; raise SystemExit(0 if Path('$received').read_bytes() == b'$marker' else 1)" 2>/dev/null; then
      return
    fi
    sleep 0.2
  done
  printf 'local delivery did not reach %s\n' "$destination_peer" >&2
  exit 1
}

# Lane A: A initiates to B's local-delivery prefix. B's Envelope TUN must not
# observe the cold packet; the response role enters A's Envelope exactly once.
b_before=$(tun_reads "$site_b")
send_and_receive "$site_a" 10.10.0.1 "$site_b" 10.20.0.1 19000 lane_a
b_after=$(tun_reads "$site_b")
[[ "$b_after" -eq "$b_before" ]]
a_before=$(tun_reads "$site_a")
docker exec "$site_b" ip netns exec workload python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.20.0.1',0)); s.sendto(b'return_a',('10.10.0.1',19001)); s.close()"
sleep 1
a_after=$(tun_reads "$site_a")
[[ "$a_after" -eq $((a_before + 1)) ]]

# Lane B reverses the directional roles and proves the same behavior on the
# other authenticated peer.
a_before=$(tun_reads "$site_a")
send_and_receive "$site_b" 10.21.0.1 "$site_a" 10.11.0.1 19002 lane_b
a_after=$(tun_reads "$site_a")
[[ "$a_after" -eq "$a_before" ]]
b_before=$(tun_reads "$site_b")
docker exec "$site_a" ip netns exec workload python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.11.0.1',0)); s.sendto(b'return_b',('10.21.0.1',19003)); s.close()"
sleep 1
b_after=$(tun_reads "$site_b")
[[ "$b_after" -eq $((b_before + 1)) ]]

printf '%s\n' "optional Tailscale SaaS route compatibility integration ok"
