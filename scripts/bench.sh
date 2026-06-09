#!/usr/bin/env bash
set -euo pipefail

echo "running datapath + routing microbenchmarks"
go test -run '^$' -bench Benchmark -benchmem ./internal/datapath ./internal/routing
