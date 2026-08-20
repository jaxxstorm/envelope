#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  printf '%s\n' 'root required' >&2
  exit 1
fi
for command in go ip nft tcpdump python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$command" >&2
    exit 1
  fi
done

legacy_tables_available() {
  local family=$1
  local candidate save
  for candidate in "$family-legacy" "$family"; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi
    if ! "$candidate" --version 2>/dev/null | grep -q '(legacy)'; then
      continue
    fi
    save="$family-save"
    if [[ "$candidate" == *-legacy ]]; then
      save="$family-legacy-save"
    fi
    if command -v "$save" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

if ! legacy_tables_available iptables || ! legacy_tables_available ip6tables; then
  printf '%s\n' 'legacy iptables/ip6tables and matching save tools are required' >&2
  exit 1
fi

printf '%s\n' 'synthetic routing smoke only: no Tailscale control/data plane'
go test -tags=integration ./internal/routing \
  -run '^TestRoutingNamespace(DirectionalRoles|IPv6SourceSpecificRouteRejection)$' \
  -count=1 \
  -v
printf '%s\n' 'synthetic routing smoke ok'
