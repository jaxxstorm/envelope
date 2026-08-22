#!/usr/bin/env bash
set -euo pipefail

HEADSCALE_IMAGE='headscale/headscale:0.25.1@sha256:a7a8ae9616bb964a3eed8101ebb020213f73668142a84806ec37a5eeb2c1fceb'
TAILSCALE_IMAGE='tailscale/tailscale:v1.80.3@sha256:af6026ed3e5892c5d4966962618a09685198111507df16803b2aec7066046582'
PLATFORM=${ENVELOPE_INTEGRATION_PLATFORM:-linux/amd64}

for command in docker go python3; do
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
target_a="envelope-target-a-$run_id"
target_b="envelope-target-b-$run_id"
ingress_a1="envelope-ingress-a1-$run_id"
ingress_a2="envelope-ingress-a2-$run_id"
ingress_b1="envelope-ingress-b1-$run_id"
ingress_b2="envelope-ingress-b2-$run_id"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$target_a" "$target_b" "$ingress_a1" "$ingress_a2" "$ingress_b1" "$ingress_b2" "$headscale" >/dev/null 2>&1 || true
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

cat >"$work_dir/setup-target.sh" <<'SH'
#!/bin/sh
set -eu

local_cidr=$1
remote_cidr=$2
local_ip=$3

apk add --no-cache curl iproute2 iptables nftables python3 tcpdump >/dev/null
mkdir -p /usr/bin /usr/sbin
ln -sf /usr/local/bin/tailscale /usr/bin/tailscale
for binary in ip iptables ip6tables iptables-save ip6tables-save; do
  ln -sf "$(command -v "$binary")" "/usr/sbin/$binary"
done
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
ip addr add 198.18.0.1/30 dev workload0
ip -n workload addr add 198.18.0.2/30 dev workload-peer
ip -n workload addr add "$local_ip/32" dev lo
ip -n workload route add default via 198.18.0.1 dev workload-peer
ip route add "$local_cidr" dev workload0

ip netns add gwlb
ip link add gwlb0 type veth peer name gwlb-peer
ip link set gwlb-peer netns gwlb
ip link set gwlb0 up
ip -n gwlb link set lo up
ip -n gwlb link set gwlb-peer up
ip addr add 192.0.2.1/30 dev gwlb0
ip -n gwlb addr add 192.0.2.2/30 dev gwlb-peer
ip rule add priority 100 iif workload0 to "$remote_cidr" table 101
ip route add table 101 "$remote_cidr" via 192.0.2.2 dev gwlb0

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.workload0.rp_filter=0
sysctl -q -w net.ipv4.conf.gwlb0.rp_filter=0
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
  for path in 'envelope0 workload0' 'envelope0 tailscale0'; do
    set -- $path
    "$binary" -A ENVELOPE-FORWARD -i "$1" -o "$2" -j ACCEPT
    "$binary" -t mangle -A ENVELOPE-MSS -i "$1" -o "$2" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
  done
  "$binary" -t mangle -A ENVELOPE-MSS -j RETURN
done
SH
chmod 0755 "$work_dir/setup-target.sh"

cat >"$work_dir/setup-ingress.sh" <<'SH'
#!/bin/sh
set -eu

local_cidr=$1

apk add --no-cache iproute2 python3 >/dev/null
mkdir -p /usr/bin /usr/sbin
ln -sf /usr/local/bin/tailscale /usr/bin/tailscale
ln -sf "$(command -v ip)" /usr/sbin/ip

ip netns add gwlb
ip link add gwlb0 type veth peer name gwlb-peer
ip link set gwlb-peer netns gwlb
ip link set gwlb0 up
ip -n gwlb link set lo up
ip -n gwlb link set gwlb-peer up
ip addr add 198.19.0.1/30 dev gwlb0
ip -n gwlb addr add 198.19.0.2/30 dev gwlb-peer
ip route add "$local_cidr" via 198.19.0.2 dev gwlb0
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.gwlb0.rp_filter=0
sysctl -q -w net.ipv4.conf.tailscale0.rp_filter=0
SH
chmod 0755 "$work_dir/setup-ingress.sh"

cat >"$work_dir/gwlb-wrap.py" <<'PY'
import ipaddress
import socket
import struct
import sys

interface, destination_cidr, target = sys.argv[1:]
destination_network = ipaddress.ip_network(destination_cidr)
cookie = bytes.fromhex("01080301a1b2c3d4")
capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
capture.bind((interface, 0))
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    frame = capture.recv(65535)
    if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00":
        continue
    inner = frame[14:]
    if inner[0] >> 4 != 4:
        continue
    length = struct.unpack("!H", inner[2:4])[0]
    if length < 20 or length > len(inner):
        continue
    inner = inner[:length]
    if ipaddress.ip_address(inner[16:20]) not in destination_network:
        continue
    geneve = bytes.fromhex("0200080000000000") + cookie + inner
    sender.sendto(geneve, (target, 6081))
PY

cat >"$work_dir/probe.py" <<'PY'
import pathlib
import socket
import sys

mode, role, address, peer, port, marker = sys.argv[1:]
port = int(port)
marker = marker.encode()
ready = pathlib.Path("/tmp/ready-" + mode + "-" + str(port))
result = pathlib.Path("/tmp/result-" + mode + "-" + str(port))

if mode == "udp":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(15)
    sock.bind((address, port if role == "server" else 0))
    if role == "server":
        ready.touch()
        data, source = sock.recvfrom(4096)
        if data != marker:
            raise SystemExit("unexpected UDP payload")
        sock.sendto(b"reply:" + data, source)
        result.write_text(source[0])
    else:
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
        conn, source = sock.accept()
        data = conn.recv(4096)
        if data != marker:
            raise SystemExit("unexpected TCP payload")
        conn.sendall(b"reply:" + data)
        conn.close()
        result.write_text(source[0])
    else:
        sock.connect((peer, port))
        sock.sendall(marker)
        if sock.recv(4096) != b"reply:" + marker:
            raise SystemExit("unexpected TCP reply")
        result.write_text(peer)
else:
    raise SystemExit("unknown probe mode")
PY

docker network create "$network" >/dev/null
docker run -d --platform "$PLATFORM" --name "$headscale" --network "$network" --network-alias headscale \
  -v "$work_dir/headscale.yaml:/etc/headscale/config.yaml:ro" \
  -v "$work_dir/acl.hujson:/etc/headscale/acl.hujson:ro" \
  -v "$work_dir/headscale-state:/var/lib/headscale" \
  "$HEADSCALE_IMAGE" serve >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$headscale" headscale users list >/dev/null 2>&1; then break; fi
  sleep 0.5
done
docker exec "$headscale" headscale users list >/dev/null
docker exec "$headscale" headscale users create integration >/dev/null

create_key() {
  docker exec "$headscale" headscale --output json preauthkeys create --user integration --expiration 1h | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])'
}
for node in target-a target-b ingress-a1 ingress-a2 ingress-b1 ingress-b2; do
  create_key >"$work_dir/key-$node"
  chmod 0600 "$work_dir/key-$node"
done

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work_dir/envelope" ./cmd/envelope

start_node() {
  local name=$1 key=$2 routes=$3
  docker run -d --platform "$PLATFORM" --name "$name" --hostname "$name" --network "$network" --network-alias "$name" \
    --privileged --device=/dev/net/tun \
    -e TS_AUTHKEY=file:/run/secrets/authkey -e TS_AUTH_ONCE=true -e TS_STATE_DIR=/var/lib/tailscale \
    -e TS_USERSPACE=false -e TS_ACCEPT_DNS=false -e TS_DEBUG_FIREWALL_MODE=iptables -e TS_DEBUG_USE_DERP_HTTP=true \
    -e TS_ROUTES="$routes" -e 'TS_EXTRA_ARGS=--login-server=http://headscale:8080 --accept-routes --snat-subnet-routes=false --netfilter-mode=off' \
    -v "$key:/run/secrets/authkey:ro" \
    -v "$work_dir/setup-target.sh:/run/envelope-test/setup-target.sh:ro" \
    -v "$work_dir/setup-ingress.sh:/run/envelope-test/setup-ingress.sh:ro" \
    -v "$work_dir/gwlb-wrap.py:/run/envelope-test/gwlb-wrap.py:ro" \
    -v "$work_dir/probe.py:/run/envelope-test/probe.py:ro" \
    -v "$work_dir/envelope:/usr/local/bin/envelope:ro" \
    "$TAILSCALE_IMAGE" >/dev/null
}

start_node "$target_a" "$work_dir/key-target-a" ''
start_node "$target_b" "$work_dir/key-target-b" ''
start_node "$ingress_a1" "$work_dir/key-ingress-a1" '10.10.0.0/24'
start_node "$ingress_a2" "$work_dir/key-ingress-a2" '10.10.0.0/24'
start_node "$ingress_b1" "$work_dir/key-ingress-b1" '10.20.0.0/24'
start_node "$ingress_b2" "$work_dir/key-ingress-b2" '10.20.0.0/24'

wait_running() {
  local node=$1
  for _ in $(seq 1 120); do
    if docker exec "$node" tailscale status --json 2>/dev/null | grep -Eq '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then return; fi
    sleep 0.5
  done
  docker logs "$node" >&2
  printf 'tailscaled did not become Running on %s\n' "$node" >&2
  exit 1
}
for node in "$target_a" "$target_b" "$ingress_a1" "$ingress_a2" "$ingress_b1" "$ingress_b2"; do wait_running "$node"; done

routes_ready=false
for _ in $(seq 1 120); do
  route_json=$(docker exec "$headscale" headscale --output json routes list)
  route_ids=$(python3 -c 'import json,sys; routes=json.load(sys.stdin); expected={"10.10.0.0/24":2,"10.20.0.0/24":2}; found={}; [found.__setitem__(r["prefix"], found.get(r["prefix"], 0)+1) for r in routes]; print(" ".join(str(r["id"]) for r in routes)) if all(found.get(prefix, 0) == count for prefix, count in expected.items()) else None' <<<"$route_json")
  if [[ -n "$route_ids" ]]; then
    for route_id in $route_ids; do docker exec "$headscale" headscale routes enable --route "$route_id" >/dev/null; done
    routes_ready=true
    break
  fi
  sleep 0.5
done
if [[ "$routes_ready" != true ]]; then
  printf '%s\n' 'Headscale did not observe two ingress advertisements for each site CIDR' >&2
  exit 1
fi

docker exec "$target_a" /run/envelope-test/setup-target.sh '10.10.0.0/24' '10.20.0.0/24' '10.10.0.10'
docker exec "$target_b" /run/envelope-test/setup-target.sh '10.20.0.0/24' '10.10.0.0/24' '10.20.0.10'
docker exec "$ingress_a1" /run/envelope-test/setup-ingress.sh '10.10.0.0/24'
docker exec "$ingress_a2" /run/envelope-test/setup-ingress.sh '10.10.0.0/24'
docker exec "$ingress_b1" /run/envelope-test/setup-ingress.sh '10.20.0.0/24'
docker exec "$ingress_b2" /run/envelope-test/setup-ingress.sh '10.20.0.0/24'

docker exec -d "$target_a" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.20.0.0/24' 192.0.2.1
docker exec -d "$target_b" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.10.0.0/24' 192.0.2.1
docker exec -d "$ingress_a1" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.10.0.0/24' "$target_a"
docker exec -d "$ingress_a2" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.10.0.0/24' "$target_a"
docker exec -d "$ingress_b1" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.20.0.0/24' "$target_b"
docker exec -d "$ingress_b2" ip netns exec gwlb python3 /run/envelope-test/gwlb-wrap.py gwlb-peer '10.20.0.0/24' "$target_b"

start_envelope() {
  local target=$1 local_cidr=$2 remote_cidr=$3
  docker exec "$target" sh -c "nohup /usr/local/bin/envelope --udp-bind=:6081 --metrics-addr=127.0.0.1:9090 --tun-name=envelope0 --tun-mtu=1280 --routing-mode=manage --underlay-interface=workload0 --tailscale-iface=tailscale0 --local-site-cidrs=$local_cidr --remote-site-cidrs=$remote_cidr >/tmp/envelope.log 2>&1 & echo \$! >/tmp/envelope.pid"
}
start_envelope "$target_a" '10.10.0.0/24' '10.20.0.0/24'
start_envelope "$target_b" '10.20.0.0/24' '10.10.0.0/24'

wait_healthy() {
  local target=$1
  for _ in $(seq 1 120); do
    if docker exec "$target" curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then return; fi
    sleep 0.5
  done
  docker logs "$target" >&2
  docker exec "$target" sh -c 'cat /tmp/envelope.log; ip rule show; ip route show table all; tailscale status --json' >&2 || true
  printf 'Envelope did not become healthy on %s\n' "$target" >&2
  exit 1
}
wait_healthy "$target_a"
wait_healthy "$target_b"

assert_post_inspection_rule() {
  local target=$1 cidr=$2
  docker exec "$target" ip -j -details -4 rule show | python3 -c '
import json, sys
cidr = sys.argv[1]
for rule in json.load(sys.stdin):
    destination = rule.get("dst", "")
    if "/" not in destination and "dstlen" in rule:
        destination += "/" + str(rule["dstlen"])
    if (rule.get("priority") == 100 and rule.get("iif") == "envelope0" and
            destination == cidr and str(rule.get("table")) in {"254", "main"} and
            str(rule.get("protocol")) in {"186", "bgp"}):
        raise SystemExit(0)
raise SystemExit("missing owned envelope0-to-main post-inspection rule for " + cidr)
' "$cidr"
}
assert_post_inspection_rule "$target_a" '10.10.0.0/24'
assert_post_inspection_rule "$target_b" '10.20.0.0/24'

# Target ingress from envelope0 has no GWLBE next hop; only workloads and ingress
# routers use their distinct pre-inspection GWLBE domain.
docker exec "$target_a" ip route get 10.10.0.10 from 10.20.0.10 iif envelope0 | grep -q 'dev workload0'
docker exec "$target_a" ip route get 10.20.0.10 from 10.10.0.10 iif envelope0 | grep -q 'dev tailscale0'
docker exec "$target_b" ip route get 10.20.0.10 from 10.10.0.10 iif envelope0 | grep -q 'dev workload0'
docker exec "$target_b" ip route get 10.10.0.10 from 10.20.0.10 iif envelope0 | grep -q 'dev tailscale0'
for ingress in "$ingress_a1" "$ingress_a2"; do docker exec "$ingress" ip route get 10.10.0.10 | grep -q 'dev gwlb0'; done
for ingress in "$ingress_b1" "$ingress_b2"; do docker exec "$ingress" ip route get 10.20.0.10 | grep -q 'dev gwlb0'; done
for target in "$target_a" "$target_b"; do
  if docker exec "$target" tailscale status --json | python3 -c 'import json,sys; local={"10.10.0.0/24","10.20.0.0/24"}; self=json.load(sys.stdin)["Self"]; raise SystemExit(bool(local.intersection(self.get("AllowedIPs", []))))'; then
    printf 'target %s unexpectedly advertises a site route\n' "$target" >&2
    exit 1
  fi
done

wait_ready() {
  local target=$1 mode=$2 port=$3
  for _ in $(seq 1 100); do
    if docker exec "$target" test -f "/tmp/ready-$mode-$port"; then return; fi
    sleep 0.1
  done
  printf '%s server did not become ready on %s\n' "$mode" "$target" >&2
  exit 1
}

run_bidirectional() {
  local mode=$1 port_a=$2 port_b=$3
  docker exec "$target_a" rm -f "/tmp/ready-$mode-$port_a" "/tmp/result-$mode-$port_a"
  docker exec "$target_b" rm -f "/tmp/ready-$mode-$port_b" "/tmp/result-$mode-$port_b"
  docker exec -d "$target_a" ip netns exec workload python3 /run/envelope-test/probe.py "$mode" server 10.10.0.10 10.20.0.10 "$port_a" "a-to-b-$mode"
  docker exec -d "$target_b" ip netns exec workload python3 /run/envelope-test/probe.py "$mode" server 10.20.0.10 10.10.0.10 "$port_b" "b-to-a-$mode"
  wait_ready "$target_a" "$mode" "$port_a"
  wait_ready "$target_b" "$mode" "$port_b"
  docker exec -d "$target_a" ip netns exec workload python3 /run/envelope-test/probe.py "$mode" client 10.10.0.10 10.20.0.10 "$port_b" "a-to-b-$mode"
  docker exec -d "$target_b" ip netns exec workload python3 /run/envelope-test/probe.py "$mode" client 10.20.0.10 10.10.0.10 "$port_a" "b-to-a-$mode"
  for _ in $(seq 1 150); do
    if docker exec "$target_a" test -f "/tmp/result-$mode-$port_a" && docker exec "$target_b" test -f "/tmp/result-$mode-$port_b"; then break; fi
    sleep 0.1
  done
  docker exec "$target_a" test -f "/tmp/result-$mode-$port_a"
  docker exec "$target_b" test -f "/tmp/result-$mode-$port_b"
  [[ $(docker exec "$target_a" cat "/tmp/result-$mode-$port_a") == 10.20.0.10 ]]
  [[ $(docker exec "$target_b" cat "/tmp/result-$mode-$port_b") == 10.10.0.10 ]]
}

run_bidirectional udp 21001 21002

docker exec -d "$target_a" ip netns exec workload tcpdump -U -i workload-peer -c 1 -w /tmp/mss-a.pcap 'tcp and dst port 22001'
docker exec -d "$target_b" ip netns exec workload tcpdump -U -i workload-peer -c 1 -w /tmp/mss-b.pcap 'tcp and dst port 22002'
run_bidirectional tcp 22001 22002
for target in "$target_a" "$target_b"; do
  for _ in $(seq 1 50); do
    if docker exec "$target" test -s /tmp/mss-a.pcap 2>/dev/null || docker exec "$target" test -s /tmp/mss-b.pcap 2>/dev/null; then break; fi
    sleep 0.1
  done
done
docker exec "$target_a" ip netns exec workload tcpdump -nn -vv -r /tmp/mss-a.pcap | grep -q 'mss 1240'
docker exec "$target_b" ip netns exec workload tcpdump -nn -vv -r /tmp/mss-b.pcap | grep -q 'mss 1240'

docker exec "$target_a" ip netns exec workload ping -c 1 -W 10 -I 10.10.0.10 10.20.0.10 >/dev/null &
ping_a=$!
docker exec "$target_b" ip netns exec workload ping -c 1 -W 10 -I 10.20.0.10 10.10.0.10 >/dev/null &
ping_b=$!
wait "$ping_a"
wait "$ping_b"

printf '%s\n' 'headscale symmetric two-site TCP/UDP/ICMP integration ok'
