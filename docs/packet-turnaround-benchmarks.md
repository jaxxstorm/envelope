# Packet-Turnaround Benchmarks

The local benchmark gate covers only the current target hot path. It does not benchmark Linux routing, Tailscale, AWS, GWLBE convergence, HA, or protected acceptance.

Run:

```bash
./scripts/bench.sh
```

The script runs `go test -run '^$' -bench=. -benchmem ./internal/geneve ./internal/datapath` and checks these deliberately generous regression ceilings:

| Benchmark | Maximum latency | Maximum bytes/op | Maximum allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkTLVValidationLoggingDisabled` | 2,000 ns/op | 0 B/op | 0 allocs/op |
| `BenchmarkPacketConstruction` | 5,000 ns/op | 0 B/op | 0 allocs/op |

The values are static local regression bounds, not performance capacity, latency, or cost claims. Transport-router and AWS route behavior require their separate readiness and protected acceptance checks.
