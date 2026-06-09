# Envelope

> [!WARNING]
> **Experimental WIP: this does not currently work.**
>
> Envelope is an in-progress prototype. The code, tests, scripts, and Terraform
> examples are here to capture the current direction and make iteration easier,
> but this repository should not be treated as production-ready or even as a
> functional preview yet. Expect broken behavior, incomplete integration points,
> unsafe assumptions, and major changes.

Envelope is a minimal datapath that terminates AWS GWLB-style GENEVE (UDP/6081), decapsulates inner L3 IP packets, and forwards them to a local TUN device (`envelope0`). Return traffic from the TUN is re-encapsulated into GENEVE and sent back using a flow-to-peer mapping based on the inner 5-tuple.

Envelope is designed to run alongside `tailscaled` on the same Linux host. Envelope handles GENEVE termination/origination, while host routing carries traffic between `envelope0` and the Tailscale interface (`tailscale0` by default).

## What It Is

- A Linux-only GENEVE <-> TUN shim for L3 IP packets.
- A single-process datapath with Prometheus metrics and a health endpoint.
- A co-resident routing integration for Envelope + `tailscaled` using policy routes.

## What It Is Not

- An L2 bridge (no Ethernet payloads in v1).
- A NAT/conntrack engine.
- A full GWLB control plane.

## Deployment Modes

- `routing-mode=off`: Datapath only. No routing checks or route/rule management.
- `routing-mode=verify`: Validate routing prerequisites and mark health unhealthy if they are missing.
- `routing-mode=manage`: Validate and reconcile required rules/routes for protected CIDRs.

## Local Run

Build:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

Datapath-only run:

```bash
sudo ./bin/envelope \
  --udp-bind=0.0.0.0:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=0.0.0.0:9090 \
  --routing-mode=off
```

Co-resident run with managed routing:

```bash
sudo ./bin/envelope \
  --udp-bind=0.0.0.0:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=0.0.0.0:9090 \
  --tailscale-iface=tailscale0 \
  --routing-mode=manage \
  --protected-cidrs=172.16.0.0/16 \
  --routing-table-id=100 \
  --routing-rule-priority=100
```

Health and metrics:

- `GET :9090/healthz`
- `GET :9090/metrics`

## Required Linux Capabilities and Sysctls

Capabilities:

- `CAP_NET_ADMIN` (create/configure TUN, set MTU, manage routes/rules)
- `CAP_NET_RAW` (recommended for raw socket operations and diagnostics)

Sysctls for co-resident routing mode:

- `net.ipv4.ip_forward=1`
- `net.ipv6.conf.all.forwarding=1` (required when protected CIDRs include IPv6)

## Routing Integration Flags

- `--tailscale-iface` (default: `tailscale0`)
- `--routing-mode` (`off|verify|manage`, default: `off`)
- `--protected-cidrs` (required when `routing-mode=manage`)
- `--routing-table-id` (default: `100`)
- `--routing-rule-priority` (default: `100`)

Routing metrics:

- `routing_apply_attempts`
- `routing_apply_failures`
- `routing_drift_repairs`

## MTU Guidance (Tailscale)

Tailscale uses a fixed tunnel MTU of **1280**. Envelope defaults `envelope0` to 1280 to match this behavior.

GENEVE encapsulation adds overhead. Ensure the outer path MTU can carry the inner 1280-byte packet plus encapsulation:

```
required_path_mtu = 1280 + (outer_ip + udp + geneve + options)
```

Typical overhead:

- Outer IPv4: 20 bytes (IPv6: 40 bytes)
- UDP: 8 bytes
- GENEVE base header: 8 bytes
- Options: 0-252 bytes

## GENEVE Options

Envelope preserves GENEVE options opaque-by-default. Options received on ingress are stored with flow mapping and emitted unchanged on egress.

Optional TLV parsing is disabled by default. When enabled, Envelope parses only allowlisted TLVs for logging/mapping hints and still preserves raw option bytes.

Enable parsing:

```bash
sudo ./bin/envelope \
  --geneve-tlv-parse \
  --geneve-tlv-allowlist=0x0102:0x03,4:5
```

Options bounds:

- `--geneve-options-max-bytes` (default: `252`). Packets exceeding this size are dropped.

## End-to-End Harnesses

Datapath harness:

```bash
sudo ./scripts/e2e.sh
```

Co-resident Envelope + tailscaled harness:

```bash
sudo ./scripts/e2e_cohost.sh
```

`e2e_cohost.sh` starts Envelope in `routing-mode=manage`, validates policy rule/route state for protected CIDRs, and runs datapath validation.

## Benchmark Task

Run repeatable microbenchmarks:

```bash
./scripts/bench.sh
```

## Troubleshooting

- No packets on `envelope0`: verify interface exists and process has `CAP_NET_ADMIN`.
- Health is `503` in `verify/manage`: check `tailscale-iface`, forwarding sysctls, and required route/rule state.
- No return traffic: ensure a matching flow has been seen on ingress to seed flow mapping.
- MTU drops: lower `--tun-mtu` to account for encapsulation overhead.

## Rollback

To disable host-routing integration and return to datapath-only behavior:

1. Restart Envelope with `--routing-mode=off`.
2. Remove managed routing entries if present:
   - `ip rule del priority <routing-rule-priority> iif <tailscale-iface> to <cidr> table <routing-table-id>`
   - `ip route del table <routing-table-id> <cidr>`
