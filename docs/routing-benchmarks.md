# Routing Benchmark Gate

The routing change uses the following thresholds, recorded before its acceptance benchmark run. They are regression limits rather than throughput claims.

## Profile

- Linux, `amd64` or `arm64`, Go 1.22 or newer.
- No CPU quota below one core.
- `go test -run '^$' -bench=. -benchmem ./internal/routing ./internal/datapath`.
- Five or more benchmark iterations are recommended when comparing changes; the gate uses the value reported by the current run.

## Thresholds

| Benchmark | Maximum latency | Maximum bytes/op | Maximum allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkEnsureManagedIdempotent` | 250,000 ns/op | 32,768 B/op | 400 allocs/op |
| `BenchmarkEffectiveRouteValidation` | 200,000 ns/op | 24,576 B/op | 300 allocs/op |
| `BenchmarkDirectionalPacketPath` | 100,000 ns/op | 16,384 B/op | 200 allocs/op |

The routing benchmarks use deterministic fake command operations so they measure reconciliation and effective-path decision overhead without including process startup. The packet-path benchmark covers one valid AWS-profile ingress plus its mapped reverse egress. Privileged namespace tests separately cover real command and kernel behavior.

## Acceptance Run

Recorded 2026-08-19 with Go 1.22 in a Linux/arm64 Docker VM after enabling full-prefix policy-table auditing:

| Benchmark | Latency | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkEnsureManagedIdempotent` | 11,315 ns/op | 11,913 B/op | 200 allocs/op |
| `BenchmarkEffectiveRouteValidation` | 10,658 ns/op | 11,626 B/op | 185 allocs/op |
| `BenchmarkDirectionalPacketPath` | 365.5 ns/op | 72 B/op | 2 allocs/op |

All three are below the thresholds recorded above.
