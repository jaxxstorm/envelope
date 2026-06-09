## Context

Envelope is a Linux-only Go service that must terminate AWS GWLB-style GENEVE (UDP/6081) traffic, decapsulate inner L3 IP packets, and deliver them to a local TUN device (`envelope0`). Return traffic from the TUN must be re-encapsulated into GENEVE and sent back to GWLB, preserving symmetry. The MVP must be simple, observable, and safe around MTU, while avoiding unnecessary allocations on the hot path.

## Goals / Non-Goals

**Goals:**
- Implement a minimal, reliable datapath: UDP/6081 in -> GENEVE decap -> write inner IP to TUN; read from TUN -> GENEVE encap -> UDP/6081 out.
- Provide health and metrics endpoints on :9090.
- Preserve GENEVE options as opaque bytes and propagate them on the return path.
- Minimize hot-path allocations using buffer pools.
- Be explicit about MTU handling and drop behavior.

**Non-Goals:**
- L2 bridging or Ethernet payload handling.
- eBPF, iptables, or NAT-based routing.
- Flow/peer mapping beyond a last-seen UDP peer.
- Deep GENEVE TLV option interpretation.
- High-performance tuning beyond basic buffer reuse.

## Architecture

The MVP consists of four main components:
- **UDP listener/sender** bound to UDP/6081 for GENEVE traffic.
- **GENEVE codec** that parses/serializes the fixed header, VNI, and opaque options.
- **TUN device manager** that creates/opens `envelope0` and reads/writes L3 packets.
- **HTTP server** for `/healthz` and `/metrics` on :9090.

Datapath operations are split into two loops (or goroutines):
- **Ingress**: UDP recv -> GENEVE decap -> write inner IP payload to TUN.
- **Egress**: TUN read -> GENEVE encap -> UDP send to the last-seen peer.

## Interfaces

- **UDP/6081**: Receives and sends GENEVE-encapsulated packets. The MVP accepts packets from any peer and tracks the last-seen source for return traffic.
- **TUN device (`envelope0`)**: Receives and emits raw L3 IP packets (IPv4 and IPv6). No Ethernet headers.
- **HTTP**: `:9090/healthz` (200 OK when ready) and `:9090/metrics` (Prometheus).
- **Configuration** (CLI/env): bind address, VNI (optional fixed or inferred), TUN MTU, and buffer sizes.

## Data plane

### Ingress (GENEVE -> TUN)
1. Read UDP datagram into a pooled buffer.
2. Parse minimal GENEVE header:
   - Validate version and header length.
   - Extract VNI.
   - Extract options section as opaque bytes (no TLV parsing).
3. Treat the remaining payload as an L3 IP packet and write to the TUN fd.
4. Update counters (`geneve_rx_packets`, `geneve_rx_bytes`, `tun_tx_packets`, `decap_errors`, `drops`).

### Egress (TUN -> GENEVE)
1. Read an L3 IP packet from the TUN into a pooled buffer.
2. Construct GENEVE header:
   - Set version and header length.
   - Set VNI (configured or last-seen).
   - Reattach the last-seen opaque options bytes.
3. Encapsulate the inner payload and send via UDP to the last-seen peer.
4. Update counters (`tun_rx_packets`, `geneve_tx_packets`, `geneve_tx_bytes`, `encap_errors`, `drops`).

### Minimal GENEVE parsing/serialization
- **Required fields**: version, header length, protocol type (opaque for now), VNI.
- **Options**: preserved and forwarded as an opaque byte slice.
- **No** TLV interpretation, option modification, or schema validation in v1.

## Control plane (minimal)

There is no dynamic control plane in the MVP. Configuration is static at startup. Observability is limited to health and metrics. Future iterations can add per-flow or per-peer control data.

## Return path & symmetry

Return traffic is sent using a **flow-to-peer mapping** keyed by the inner 5-tuple. Each ingress packet updates the mapping with the sender’s UDP peer, VNI, and options. Egress uses that mapping to ensure GWLB-compatible symmetry, with idle entries expiring after a configurable timeout.

## MTU strategy

Encapsulation adds overhead (outer IP + UDP + GENEVE header + options). The TUN MTU should be set to a conservative default that avoids fragmentation. The service should:
- Compute encapsulation overhead from the configured GENEVE header length and options.
- Set or recommend a safe default MTU (configurable) for `envelope0`.
- Drop packets that exceed the configured MTU rather than fragmenting.
- Log and count oversized drops via `drops` and `encap_errors`/`decap_errors`.

## Failure modes

- **Malformed GENEVE headers**: drop, increment `decap_errors`.
- **Oversized packets**: drop, increment `drops` and relevant error counter.
- **TUN read/write errors**: log and retry; if persistent, mark `/healthz` degraded.
- **UDP send errors**: drop, increment `encap_errors`.
- **No last-seen peer**: drop TUN egress, increment `drops` and log.
- **Metrics server failure**: log; datapath continues.

## Testing

- Unit tests for the GENEVE codec with minimal header, header with options, and oversized/MTU-related cases.
- Local end-to-end harness that replays UDP/6081 traffic and verifies inner packets appear on TUN and are re-encapsulated on output.
- Metrics and health endpoints verified via HTTP in integration tests.

## Decisions

- **Minimal GENEVE codec**: parse only required fields (VNI + header length) and preserve options as opaque bytes. Alternative: full TLV parsing. Chosen to reduce complexity while keeping forward compatibility.
- **L3-only payload**: treat inner payload as IP. Alternative: L2 bridging and Ethernet support. Chosen to match current GWLB use and simplify TUN handling.
- **Last-seen peer for return path**: simplest symmetry approach for MVP. Alternative: full flow/peer map. Deferred to a future iteration.
- **Buffer pooling**: use `sync.Pool` for UDP and TUN buffers to minimize allocations. Alternative: per-packet allocation. Chosen to reduce GC pressure.
- **Use `golang.org/x/sys/unix`** for TUN creation and socket options to avoid cgo.

## Risks / Trade-offs

- [Flow mapping gaps] -> Mitigation: expire idle entries, validate inner packet headers, and drop when no mapping exists.
- [MTU misconfiguration] -> Mitigation: compute overhead, set conservative defaults, and provide guidance.
- [Options handling ambiguity] -> Mitigation: preserve opaque options bytes and avoid modification in v1.
- [Limited observability] -> Mitigation: provide counters for ingress/egress and error drops; add latency metrics later if needed.

## Migration Plan

- Deploy as a standalone process behind GWLB with UDP/6081 open.
- Verify `/healthz` and `/metrics` before enabling traffic.
- Rollback by stopping the service and removing the TUN device; no data migrations are required.

## Open Questions

- Are IPv6 extension headers in scope for flow-key extraction?
- Should VNI be fixed, configurable, or inferred per packet in the MVP?
- Do we need IPv6-specific handling or validation beyond treating payload as opaque IP?
