#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "root required"
  exit 1
fi

mkdir -p ./bin

go build -o ./bin/envelope ./cmd/envelope

./bin/envelope \
  --udp-bind=127.0.0.1:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=127.0.0.1:9090 \
  --routing-mode=off &

pid=$!
trap 'kill ${pid} >/dev/null 2>&1 || true' EXIT

sleep 1
python3 ./scripts/e2e.py
