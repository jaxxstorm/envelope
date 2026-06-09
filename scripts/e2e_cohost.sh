#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "root required"
  exit 1
fi

for cmd in ip curl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required tool: $cmd"
    exit 1
  fi
done

mkdir -p ./bin

go build -o ./bin/envelope ./cmd/envelope

TS_IFACE=${E2E_TS_IFACE:-tailscale-e2e0}
CIDR=${E2E_PROTECTED_CIDR:-172.16.0.0/16}
ROUTE_TABLE=${E2E_ROUTE_TABLE:-100}
RULE_PRIORITY=${E2E_RULE_PRIORITY:-100}
METRICS_ADDR=${E2E_METRICS_ADDR:-127.0.0.1:9091}
UDP_BIND=${E2E_UDP_BIND:-127.0.0.1:6082}

cleanup() {
  kill "${env_pid:-}" >/dev/null 2>&1 || true
  kill "${ts_pid:-}" >/dev/null 2>&1 || true
  if [[ "${dummy_iface:-0}" == "1" ]]; then
    ip link del "$TS_IFACE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if command -v tailscaled >/dev/null 2>&1; then
  tailscaled \
    --tun="$TS_IFACE" \
    --state=mem: \
    --socket=/tmp/tailscaled-e2e.sock \
    >/tmp/tailscaled-e2e.log 2>&1 &
  ts_pid=$!
  sleep 2
else
  echo "tailscaled not found; creating dummy interface $TS_IFACE"
  ip tuntap add dev "$TS_IFACE" mode tun
  ip link set "$TS_IFACE" up
  dummy_iface=1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

./bin/envelope \
  --udp-bind="$UDP_BIND" \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr="$METRICS_ADDR" \
  --routing-mode=manage \
  --tailscale-iface="$TS_IFACE" \
  --protected-cidrs="$CIDR" \
  --routing-table-id="$ROUTE_TABLE" \
  --routing-rule-priority="$RULE_PRIORITY" &
env_pid=$!

for _ in $(seq 1 20); do
  if curl -fsS "http://$METRICS_ADDR/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS "http://$METRICS_ADDR/healthz" >/dev/null

if ! ip -4 rule show | grep -q "iif $TS_IFACE .* to $CIDR .* lookup $ROUTE_TABLE"; then
  echo "missing expected policy rule"
  exit 1
fi

if ! ip -4 route show table "$ROUTE_TABLE" "$CIDR" | grep -q "dev envelope0"; then
  echo "missing expected route in table $ROUTE_TABLE"
  exit 1
fi

E2E_UDP_PORT="${UDP_BIND##*:}" E2E_UDP_HOST="${UDP_BIND%%:*}" python3 ./scripts/e2e.py

echo "cohost e2e ok"
