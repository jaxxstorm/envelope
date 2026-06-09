## Why

Envelope needs a minimal, reliable datapath to terminate AWS GWLB-style GENEVE traffic and hand L3 IP packets to a local TUN device, with a symmetric return path back to GWLB. Building this MVP now enables end-to-end validation of the traffic flow before optimizing performance or adding advanced routing features.

## What Changes

- Add a Linux-only GENEVE (UDP/6081) receive/send loop that decapsulates to TUN and encapsulates from TUN back to GENEVE.
- Implement a minimal GENEVE codec: parse/serialize VNI and preserve options as opaque bytes without TLV interpretation.
- Establish GWLB-compatible return-path behavior using a flow-to-peer mapping keyed by the inner 5-tuple, with idle timeouts.
- Create a managed TUN device (`envelope0`) for L3 IP packets (no L2 bridging in v1).
- Expose health and Prometheus metrics endpoints on :9090.
- Add buffer pooling on the hot path to avoid unnecessary allocations.

## Capabilities

### New Capabilities
- `geneve-tun-datapath`: MVP GENEVE <-> TUN datapath for L3 IP payloads, including return-path handling, MTU considerations, and required health/metrics endpoints.

### Modified Capabilities
- (none)

## Impact

- New Go packages/modules for UDP socket handling, GENEVE encode/decode, and TUN device I/O (using `golang.org/x/sys/unix`).
- Adds a network listener on UDP/6081 and a metrics/health listener on :9090.
- Requires Linux capabilities for TUN device creation and raw UDP socket options.
- Introduces operational guidance for MTU sizing and symmetric return-path expectations.
