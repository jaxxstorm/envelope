#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  printf '%s\n' 'Linux is required for raw GWLB packet I/O' >&2
  exit 77
fi
if [[ $(id -u) -ne 0 ]]; then
  printf '%s\n' 'root is required; this wrapper does not install or preserve file capabilities' >&2
  exit 77
fi
for command in go python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 77
  fi
done
if ! python3 -c 'import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); sock.close()' \
  >/dev/null 2>&1; then
  printf '%s\n' 'CAP_NET_RAW is required for the packet-turnaround sender' >&2
  exit 77
fi

mkdir -p ./bin

go build -o ./bin/envelope ./cmd/envelope

forwarding_before=$(< /proc/sys/net/ipv4/ip_forward)
routes_before=$(< /proc/net/route)
interface_state() {
  local interface
  for interface in /sys/class/net/*; do
    printf '%s\n' "${interface##*/}"
  done
}
interfaces_before=$(interface_state)
log_file=$(mktemp)

./bin/envelope \
  --config-version=2 \
  --udp-bind=127.0.0.1:6081 \
  --max-inner-packet-size=1500 \
  --metrics-addr=127.0.0.1:9090 \
  >"$log_file" 2>&1 &

pid=$!
cleanup() {
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  rm -f "$log_file"
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 50); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    printf '%s\n' 'packet-turnaround target exited before readiness' >&2
    cat "$log_file" >&2
    exit 1
  fi
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:9090/healthz", timeout=.2).read()' \
    >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  printf '%s\n' 'packet-turnaround target did not become ready' >&2
  cat "$log_file" >&2
  exit 1
fi

if readlink "/proc/$pid/fd/"* 2>/dev/null | grep -Fxq /dev/net/tun; then
  printf '%s\n' 'packet-turnaround target unexpectedly opened a TUN device' >&2
  exit 1
fi
[[ $(< /proc/sys/net/ipv4/ip_forward) == "$forwarding_before" ]]
[[ $(< /proc/net/route) == "$routes_before" ]]
[[ $(interface_state) == "$interfaces_before" ]]

python3 ./scripts/component_wire_smoke.py

[[ $(< /proc/sys/net/ipv4/ip_forward) == "$forwarding_before" ]]
[[ $(< /proc/net/route) == "$routes_before" ]]
[[ $(interface_state) == "$interfaces_before" ]]
