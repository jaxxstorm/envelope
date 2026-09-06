#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Linux ]] || { printf '%s\n' 'Linux is required; cross-compilation is not execution evidence.' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { printf '%s\n' 'Explicit root approval is required for isolated kernel fixtures.' >&2; exit 2; }
for tool in go unshare ip iptables-legacy ip6tables-legacy nft sysctl; do
  command -v "$tool" >/dev/null || { printf 'Missing integration prerequisite: %s\n' "$tool" >&2; exit 2; }
done
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
go test -c -tags=attestorintegration -o "$temporary/attestor.test" ./internal/controller/attestation
unshare --net -- env ENVELOPE_ATTESTOR_KERNEL_TEST=1 \
  "$temporary/attestor.test" -test.v -test.timeout=90s -test.run='^TestNativeKernelReadiness$'
