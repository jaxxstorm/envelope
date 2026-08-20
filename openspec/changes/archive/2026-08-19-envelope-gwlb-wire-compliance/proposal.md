## Why

Envelope currently replies to AWS Gateway Load Balancer GENEVE packets as if they were ordinary UDP requests, which reverses the UDP ports and causes GWLB to discard return traffic. The datapath also lacks an explicit contract for the complete AWS outer tuple, fixed GENEVE header, and lifecycle of the per-flow return context.

## What Changes

- Preserve the GWLB-selected UDP source port on return traffic and always use UDP/6081 as the GENEVE destination port while swapping only the outer IPv4 addresses.
- Capture the ingress destination address and complete GWLB return context instead of retaining only the sender socket address.
- Preserve and validate the AWS-required GENEVE VNI, fixed-header semantics, protocol type, and ordered options block for the matching flow.
- Bound and observe GWLB return contexts, refresh active contexts, and define behavior for expiry, collisions, process restart, fragments, and IPv6 extension headers.
- Add packet-level Linux tests and AWS-wire-compatible fixtures that assert outer IP/UDP headers, VNI, options, and flow-cookie fidelity.
- Make datapath readiness reflect persistent receive, TUN, and compliant-send failures rather than descriptor creation alone.

## Capabilities

### New Capabilities
- `gwlb-wire-interop`: Define the AWS GWLB outer IPv4/UDP and GENEVE contract, per-flow return context, and packet-level interoperability acceptance criteria.

### Modified Capabilities
- `geneve-tun-datapath`: Make egress, return-path symmetry, flow lifetime, observability, and readiness requirements precise enough for AWS GWLB traffic.

## Impact

- Affects the Linux UDP receive/send path, GENEVE codec, flow table, configuration, readiness, and metrics.
- Requires Linux packet-info receive support and a sender that can select a per-packet UDP source port; `CAP_NET_RAW` becomes a runtime requirement if raw packet emission is used.
- Replaces UDP request/reply tests with packet-level assertions and adds sanitized AWS-compatible PCAP fixtures.
- Provides the wire-level prerequisite for AWS appliance deployment and two-region testing.
