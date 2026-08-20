#!/usr/bin/env bash
set -euo pipefail

HEADSCALE_IMAGE='headscale/headscale:0.25.1@sha256:a7a8ae9616bb964a3eed8101ebb020213f73668142a84806ec37a5eeb2c1fceb'
TAILSCALE_IMAGE='tailscale/tailscale:v1.80.3@sha256:af6026ed3e5892c5d4966962618a09685198111507df16803b2aec7066046582'
PLATFORM=${ENVELOPE_INTEGRATION_PLATFORM:-linux/amd64}

for command in docker go python3 awk; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 77
  fi
done
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'a running Docker daemon is required' >&2
  exit 77
fi

run_id="$$-$(date +%s)"
network="envelope-headscale-$run_id"
headscale="envelope-headscale-control-$run_id"
site_a="envelope-headscale-a-$run_id"
site_b="envelope-headscale-b-$run_id"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$site_a" "$site_b" "$headscale" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

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

cat >"$work_dir/acl.hujson" <<'HUJSON'
{
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
}
HUJSON

cat >"$work_dir/setup-site.sh" <<'SH'
#!/bin/sh
set -eu

delivery_cidr=$1
delivery_ip=$2
delivery_gateway=$3

apk add --no-cache curl iproute2 iptables nftables python3 >/dev/null
mkdir -p /usr/bin /usr/sbin
ln -sf /usr/local/bin/tailscale /usr/bin/tailscale
ln -sf "$(command -v ip)" /usr/sbin/ip
ln -sf "$(command -v iptables)" /usr/sbin/iptables
ln -sf "$(command -v ip6tables)" /usr/sbin/ip6tables
ln -sf "$(command -v iptables-save)" /usr/sbin/iptables-save
ln -sf "$(command -v ip6tables-save)" /usr/sbin/ip6tables-save
nft_path=$(command -v nft)
if [ "$nft_path" != /usr/sbin/nft ]; then
  ln -sf "$nft_path" /usr/sbin/nft
fi

ip netns add workload
ip link add workload0 type veth peer name workload-peer
ip link set workload-peer netns workload
ip link set workload0 up
ip -n workload link set lo up
ip -n workload link set workload-peer up
ip addr add "$delivery_gateway/32" dev workload0
ip -n workload addr add "$delivery_ip/32" dev workload-peer
ip route add "$delivery_cidr" dev workload0
ip -n workload route add default via "$delivery_gateway" dev workload-peer onlink

ip netns add gwlb
ip link add gwlb0 type veth peer name gwlb-peer
ip link set gwlb-peer netns gwlb
ip link set gwlb0 up
ip -n gwlb link set lo up
ip -n gwlb link set gwlb-peer up
ip addr add 192.0.2.1/30 dev gwlb0
ip -n gwlb addr add 192.0.2.2/30 dev gwlb-peer

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.workload0.rp_filter=0
sysctl -q -w net.ipv4.conf.tailscale0.rp_filter=0
nft flush ruleset

for binary in /usr/sbin/iptables /usr/sbin/ip6tables; do
  "$binary" -P FORWARD ACCEPT
  "$binary" -N ENVELOPE-FORWARD
  "$binary" -I FORWARD 1 -j ENVELOPE-FORWARD
  "$binary" -t mangle -N ENVELOPE-MSS
  "$binary" -t mangle -I FORWARD 1 -j ENVELOPE-MSS
  mss=1240
  if [ "$binary" = /usr/sbin/ip6tables ]; then
    mss=1220
  fi
  for path in 'workload0 tailscale0' 'tailscale0 workload0' 'envelope0 tailscale0' 'tailscale0 envelope0'; do
    set -- $path
    "$binary" -A ENVELOPE-FORWARD -i "$1" -o "$2" -j ACCEPT
    "$binary" -t mangle -A ENVELOPE-MSS -i "$1" -o "$2" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
  done
  "$binary" -t mangle -A ENVELOPE-MSS -j RETURN
done
SH
chmod 0755 "$work_dir/setup-site.sh"

cat >"$work_dir/udp-responder.py" <<'PY'
import pathlib
import socket
import sys

address, port, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
ready = pathlib.Path("/tmp/responder-ready-" + sys.argv[2])
completed = pathlib.Path("/tmp/responder-completed-" + sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((address, port))
ready.write_text("ready")
data, peer = sock.recvfrom(4096)
if data != marker:
    raise SystemExit("unexpected cold payload")
sock.sendto(b"reply:" + data, peer)
sock.close()
completed.write_text(repr(peer))
PY

cat >"$work_dir/geneve-lane.py" <<'PY'
import ipaddress
import socket
import struct
import sys

outer_local = "192.0.2.2"
outer_envelope = "192.0.2.1"
source_ip, destination_ip = sys.argv[1], sys.argv[2]
source_port, destination_port = int(sys.argv[3]), int(sys.argv[4])
flow_port = int(sys.argv[5])
marker = sys.argv[6].encode()

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(marker), 0) + marker
header = struct.pack(
    "!BBHHHBBH4s4s",
    0x45,
    0,
    20 + len(udp),
    0x4242,
    0x4000,
    64,
    socket.IPPROTO_UDP,
    0,
    ipaddress.IPv4Address(source_ip).packed,
    ipaddress.IPv4Address(destination_ip).packed,
)
header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
options = bytes.fromhex("01080301a1b2c3d4")
geneve = bytes.fromhex("0200080000000000") + options + header + udp

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((outer_local, 6081))
listener.settimeout(20)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.bind((outer_local, flow_port))
sender.sendto(geneve, (outer_envelope, 6081))
sender.close()

returned, peer = listener.recvfrom(65535)
if peer != (outer_envelope, flow_port):
    raise SystemExit("wrong mapped outer peer: %r" % (peer,))
if len(returned) < 44 or returned[:8] != geneve[:8] or returned[8:16] != options:
    raise SystemExit("GENEVE header/options were not preserved")
inner = returned[16:]
ihl = (inner[0] & 0x0f) * 4
if inner[0] >> 4 != 4 or inner[9] != socket.IPPROTO_UDP:
    raise SystemExit("mapped return is not IPv4 UDP")
if str(ipaddress.IPv4Address(inner[12:16])) != destination_ip or str(ipaddress.IPv4Address(inner[16:20])) != source_ip:
    raise SystemExit("mapped return addresses are not reversed")
returned_source, returned_destination, length, _ = struct.unpack("!HHHH", inner[ihl:ihl + 8])
payload = inner[ihl + 8:ihl + length]
if (returned_source, returned_destination) != (destination_port, source_port):
    raise SystemExit("mapped return ports are not reversed")
if payload != b"reply:" + marker:
    raise SystemExit("mapped return payload mismatch")
listener.settimeout(1)
try:
    duplicate, duplicate_peer = listener.recvfrom(65535)
    raise SystemExit("duplicate mapped return from %r (%d bytes)" % (duplicate_peer, len(duplicate)))
except socket.timeout:
    pass
listener.close()
print("correlated mapped return ok")
PY

docker network create "$network" >/dev/null
docker run -d \
  --platform "$PLATFORM" \
  --name "$headscale" \
  --network "$network" \
  --network-alias headscale \
  -v "$work_dir/headscale.yaml:/etc/headscale/config.yaml:ro" \
  -v "$work_dir/acl.hujson:/etc/headscale/acl.hujson:ro" \
  -v "$work_dir/headscale-state:/var/lib/headscale" \
  "$HEADSCALE_IMAGE" serve >/dev/null

headscale_ready=false
for _ in $(seq 1 60); do
  if docker exec "$headscale" headscale users list >/dev/null 2>&1; then
    headscale_ready=true
    break
  fi
  sleep 0.5
done
if [[ "$headscale_ready" != true ]]; then
  docker logs "$headscale" >&2
  printf '%s\n' 'Headscale did not become ready' >&2
  exit 1
fi
docker exec "$headscale" headscale users create integration >/dev/null

create_key() {
  local raw
  raw=$(docker exec "$headscale" headscale --output json preauthkeys create --user integration --expiration 1h)
  python3 -c 'import json,sys; value=json.load(sys.stdin); print(value["key"])' <<<"$raw"
}
create_key >"$work_dir/key-a"
create_key >"$work_dir/key-b"
chmod 0600 "$work_dir/key-a" "$work_dir/key-b"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work_dir/envelope" ./cmd/envelope

start_site() {
  local name=$1
  local key_file=$2
  local routes=$3
  docker run -d \
    --platform "$PLATFORM" \
    --name "$name" \
    --hostname "$name" \
    --network "$network" \
    --privileged \
    --device=/dev/net/tun \
    -e TS_AUTHKEY=file:/run/secrets/authkey \
    -e TS_AUTH_ONCE=true \
    -e TS_STATE_DIR=/var/lib/tailscale \
    -e TS_USERSPACE=false \
    -e TS_ACCEPT_DNS=false \
    -e TS_DEBUG_FIREWALL_MODE=iptables \
    -e TS_DEBUG_USE_DERP_HTTP=true \
    -e TS_ROUTES="$routes" \
    -e 'TS_EXTRA_ARGS=--login-server=http://headscale:8080 --accept-routes --snat-subnet-routes=false --netfilter-mode=off' \
    -v "$key_file:/run/secrets/authkey:ro" \
    -v "$work_dir/envelope:/usr/local/bin/envelope:ro" \
    -v "$work_dir/setup-site.sh:/run/envelope-test/setup-site.sh:ro" \
    -v "$work_dir/udp-responder.py:/run/envelope-test/udp-responder.py:ro" \
    -v "$work_dir/geneve-lane.py:/run/envelope-test/geneve-lane.py:ro" \
    "$TAILSCALE_IMAGE" >/dev/null
}

start_site "$site_a" "$work_dir/key-a" '10.10.0.0/24,10.11.0.0/24'
start_site "$site_b" "$work_dir/key-b" '10.20.0.0/24,10.21.0.0/24'

wait_running() {
  local site=$1
  for _ in $(seq 1 120); do
    if docker exec "$site" tailscale status --json 2>/dev/null | grep -Eq '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then
      return
    fi
    sleep 0.5
  done
  docker logs "$site" >&2
  printf 'tailscaled did not become Running on %s\n' "$site" >&2
  exit 1
}
wait_running "$site_a"
wait_running "$site_b"

routes_ready=false
for _ in $(seq 1 120); do
  route_json=$(docker exec "$headscale" headscale --output json routes list)
  route_ids=$(python3 -c 'import json,sys; routes=json.load(sys.stdin); expected={"10.10.0.0/24","10.11.0.0/24","10.20.0.0/24","10.21.0.0/24"}; found={r["prefix"] for r in routes}; print(" ".join(str(r["id"]) for r in routes)) if expected <= found else None' <<<"$route_json")
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
  printf '%s\n' 'Headscale did not observe all advertised routes' >&2
  exit 1
fi

docker exec "$site_a" /run/envelope-test/setup-site.sh '10.11.0.0/24' '10.11.0.10' '198.18.255.1'
docker exec "$site_b" /run/envelope-test/setup-site.sh '10.20.0.0/24' '10.20.0.10' '198.18.255.1'

wait_healthy_status() {
  local site=$1
  for _ in $(seq 1 60); do
    if docker exec "$site" tailscale status --json 2>/dev/null | python3 -c 'import json,sys; raise SystemExit(1 if json.load(sys.stdin).get("Health") else 0)'; then
      return
    fi
    sleep 0.5
  done
  printf 'tailscaled health did not clear on %s\n' "$site" >&2
  docker exec "$site" tailscale status --json >&2 || true
  exit 1
}
wait_healthy_status "$site_a"
wait_healthy_status "$site_b"

wait_peer_path() {
  local site=$1
  local peer_ip=$2
  for _ in $(seq 1 60); do
    if docker exec "$site" tailscale ping --c 1 --timeout=2s --until-direct=false "$peer_ip" >/dev/null 2>&1; then
      return
    fi
    sleep 0.5
  done
  printf 'Tailscale path from %s to %s did not become ready\n' "$site" "$peer_ip" >&2
  docker exec "$site" tailscale ping --c 1 --timeout=5s --until-direct=false "$peer_ip" >&2 || true
  exit 1
}
wait_peer_path "$site_a" '100.64.0.2'
wait_peer_path "$site_b" '100.64.0.1'

start_envelope() {
  local site=$1
  local return_cidrs=$2
  local delivery_cidrs=$3
  local remote_cidrs=$4
  docker exec "$site" sh -c "nohup /usr/local/bin/envelope \\
    --udp-bind=192.0.2.1:6081 \\
    --metrics-addr=127.0.0.1:9090 \\
    --tun-name=envelope0 \\
    --tun-mtu=1280 \\
    --routing-mode=manage \\
    --underlay-interface=workload0 \\
    --tailscale-iface=tailscale0 \\
    --gwlb-return-cidrs=$return_cidrs \\
    --local-delivery-cidrs=$delivery_cidrs \\
    --remote-tailnet-cidrs=$remote_cidrs \\
    >/tmp/envelope.log 2>&1 & echo \$! >/tmp/envelope.pid"
}

start_envelope "$site_a" '10.10.0.0/24' '10.11.0.0/24' '10.20.0.0/24,10.21.0.0/24'
start_envelope "$site_b" '10.21.0.0/24' '10.20.0.0/24' '10.10.0.0/24,10.11.0.0/24'

wait_healthy() {
  local site=$1
  for _ in $(seq 1 120); do
    if docker exec "$site" curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
      return
    fi
    sleep 0.5
  done
  printf 'Envelope did not become healthy on %s\n' "$site" >&2
  docker exec "$site" sh -c 'cat /tmp/envelope.log; curl -s http://127.0.0.1:9090/debug/routing || true' >&2
  exit 1
}
wait_healthy "$site_a"
wait_healthy "$site_b"

tun_reads() {
  local site=$1
  docker exec "$site" curl -fsS http://127.0.0.1:9090/metrics | awk '$1 == "tun_rx_packets" {print int($2)}'
}

run_lane() {
  local initiator=$1
  local responder=$2
  local source_ip=$3
  local destination_ip=$4
  local source_port=$5
  local destination_port=$6
  local flow_port=$7
  local marker=$8
  local peer_ip=$9
  local initiator_before responder_before initiator_after responder_after

  docker exec "$initiator" tailscale ping --c 1 --timeout=5s --until-direct=false "$peer_ip" >/dev/null
  docker exec "$responder" rm -f "/tmp/responder-ready-$destination_port" "/tmp/responder-completed-$destination_port"
  docker exec -d "$responder" ip netns exec workload python3 /run/envelope-test/udp-responder.py "$destination_ip" "$destination_port" "$marker"
  for _ in $(seq 1 40); do
    if docker exec "$responder" test -f "/tmp/responder-ready-$destination_port"; then
      break
    fi
    sleep 0.1
  done
  docker exec "$responder" test -f "/tmp/responder-ready-$destination_port"

  initiator_before=$(tun_reads "$initiator")
  responder_before=$(tun_reads "$responder")
  if ! docker exec "$initiator" ip netns exec gwlb python3 /run/envelope-test/geneve-lane.py \
    "$source_ip" "$destination_ip" "$source_port" "$destination_port" "$flow_port" "$marker"; then
    for site in "$initiator" "$responder"; do
      docker logs "$site" >&2 || true
      docker exec "$site" sh -c 'cat /tmp/envelope.log; ls -l /tmp/responder-* 2>/dev/null || true; ip -details rule show; ip route show table 52; ip -s link; iptables -L -v -n; curl -s http://127.0.0.1:9090/debug/routing; curl -s http://127.0.0.1:9090/metrics | grep -E "^(geneve_|tun_|gwlb_|drops |routing_ready)"' >&2 || true
    done
    return 1
  fi
  initiator_after=$(tun_reads "$initiator")
  responder_after=$(tun_reads "$responder")
  if [[ "$initiator_after" -ne $((initiator_before + 1)) ]]; then
    printf 'initiator TUN reads changed from %s to %s, want exactly one mapped return\n' "$initiator_before" "$initiator_after" >&2
    exit 1
  fi
  if [[ "$responder_after" -ne "$responder_before" ]]; then
    printf 'cold responder traffic entered Envelope: %s -> %s\n' "$responder_before" "$responder_after" >&2
    exit 1
  fi
}

run_lane "$site_a" "$site_b" '10.10.0.10' '10.20.0.10' 40000 20000 19000 'lane-a' '100.64.0.2'
run_lane "$site_b" "$site_a" '10.21.0.10' '10.11.0.10' 40001 20001 19001 'lane-b' '100.64.0.1'

for site in "$site_a" "$site_b"; do
  docker exec "$site" kill "$(docker exec "$site" cat /tmp/envelope.pid)"
done

printf '%s\n' 'headscale two-peer directional GENEVE integration ok'
