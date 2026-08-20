#!/usr/bin/env bash
set -euo pipefail

output=$(mktemp)
trap 'rm -f "$output"' EXIT

printf '%s\n' "running GENEVE, datapath, and routing microbenchmarks"
go test -run '^$' -bench=. -benchmem ./internal/geneve ./internal/datapath ./internal/routing | tee "$output"

check_threshold() {
  local benchmark=$1
  local max_ns=$2
  local max_bytes=$3
  local max_allocs=$4
  local line
  line=$(grep -E "^${benchmark}-[0-9]+[[:space:]]" "$output" | tail -n 1)
  if [[ -z "$line" ]]; then
    printf 'missing benchmark result: %s\n' "$benchmark" >&2
    exit 1
  fi
  awk -v name="$benchmark" -v max_ns="$max_ns" -v max_bytes="$max_bytes" -v max_allocs="$max_allocs" '
    {
      for (i = 1; i <= NF; i++) {
        if ($(i + 1) == "ns/op") ns = $i
        if ($(i + 1) == "B/op") bytes = $i
        if ($(i + 1) == "allocs/op") allocs = $i
      }
      if (ns > max_ns || bytes > max_bytes || allocs > max_allocs) {
        printf "%s exceeded threshold: %.2f ns/op %.2f B/op %.2f allocs/op\n", name, ns, bytes, allocs > "/dev/stderr"
        exit 1
      }
    }
  ' <<<"$line"
}

check_threshold BenchmarkEnsureManagedIdempotent 250000 32768 400
check_threshold BenchmarkEffectiveRouteValidation 200000 24576 300
check_threshold BenchmarkDirectionalPacketPath 100000 16384 200
printf '%s\n' "benchmark thresholds passed"
