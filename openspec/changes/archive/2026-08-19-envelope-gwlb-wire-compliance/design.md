## Context

AWS GWLB sends an outer IPv4/UDP GENEVE packet from a flow-selected source port to appliance port 6081. A compliant appliance swaps the outer IPv4 addresses but does not reverse the UDP ports: the return packet uses the same flow-selected source port and destination port 6081. Envelope currently uses a UDP socket bound to 6081 and replies to the received source socket address, which emits the inverse tuple.

The current flow table stores the inner tuple, sender address, VNI, and options. It does not retain the ingress destination address, complete fixed GENEVE header, or enough transport state to construct a compliant response. Unit and local E2E tests model request/reply UDP rather than the GWLB packet contract.

## Goals / Non-Goals

**Goals:**
- Emit AWS-compliant outer IPv4/UDP and GENEVE packets for mapped return traffic.
- Preserve the exact ordered options block and fixed-header semantics associated with the matching flow.
- Make return-context lifetime, capacity, collisions, unsupported packet forms, and restart behavior explicit.
- Verify behavior at packet level on Linux and with AWS-wire-compatible fixtures.
- Degrade readiness when the live datapath can no longer receive, use its TUN, or emit compliant packets.

**Non-Goals:**
- Supporting non-AWS GENEVE peers in the first compliant profile.
- Supporting overlapping inner tuples from multiple GWLBE tenants when no unambiguous return selector exists.
- Persisting or sharing flow context across processes or appliances.
- Supporting fragmented inner packets or IPv6 extension-header chains until a stable return-key design is implemented.
- Adding an L2 payload mode.

## Decisions

### 1. Receive packet metadata, not only a peer socket address

The Linux receive path will use `recvmsg`/`ReadMsgUDP` with packet-info control messages to capture the local IPv4 destination address in addition to the GWLB source address and source port. The context stored for a flow is:

```text
outer peer IP
outer local IP
GWLB flow-selected UDP port
GENEVE VNI, protocol type, fixed-header flags, and ordered options
last activity timestamp and inner protocol
```

Alternative: derive the local address from the instance interface. Rejected because wildcard binds and future multiple addresses make that ambiguous.

### 2. Use a packet-oriented Linux sender

Return traffic will be emitted with source `<local-ip>:<flow-port>` and destination `<gwlb-ip>:6081`. The sender will construct a valid outer IPv4/UDP packet, including lengths and checksums, using `x/sys/unix` without cgo. The implementation will expose a packet-sender interface so unit tests inspect the requested tuple without requiring privileges; a privileged network-namespace test will inspect actual emitted packets.

Alternative: one UDP socket per observed source port. Rejected because the port range is large, ports can collide with local services, and an unbounded socket cache is unsuitable for the hot path.

### 3. Define an AWS GWLB profile

The AWS profile requires outer IPv4, a listener bound to UDP/6081, GENEVE version 0, VNI 0, zero option reserved bits, exactly one four-byte AWS flow cookie, and inner protocol type IPv4 or IPv6. OAM packets are rejected. Fixed-header reserved bits are ignored on receive and zeroed on transmit. The generic parser can tolerate option reserved bits, but the AWS profile rejects them because return transmission must use zero and must not silently mutate GWLB metadata. Flow-cookie extraction for return identity is mandatory and independent of the observability allowlist supplied by `envelope-geneve-options`.

Alternative: silently accept arbitrary VNIs and flags. Rejected because it can produce packets that GWLB will discard while health remains green.

### 4. Fail closed on ambiguous return context

The ingress inner flow key remains the stored lookup key. Egress uses only the reverse tuple; a same-orientation TUN packet is treated as a possible routing loop and dropped. If the same ingress key is observed with any difference in peer IP, local IP, flow-selected port, flow cookie, VNI, protocol type, fixed-header flags, or ordered options, all live identities are tracked independently and return packets are dropped with a dedicated metric while more than one remains. Tracking is bounded to four complete identities plus an overflow activity lease. Each identity has its own protocol timeout, allowing a continuously active survivor to recover automatically after competitors expire. The ingress ifindex is a mutable route hint, not authoritative wire identity. Silent last-writer-wins behavior is not allowed.

Alternative: include the flow cookie in the lookup key. Rejected because a packet read from TUN does not carry that cookie.

### 5. Bound and refresh flow state

Flow capacity is configurable and finite. Ingress and successful mapped egress refresh activity. Defaults align with GWLB's default protocol lifetimes: 350 seconds for TCP and 120 seconds for UDP and other protocols. An indexed minimum-expiry heap removes only due identities, and an LRU list selects the oldest inactive flow without a table scan. Expired entries are removed before capacity eviction; if capacity remains exhausted, the oldest inactive entry is evicted and counted. Restart intentionally clears all contexts, and health recovery does not claim continuity for pre-restart flows.

### 6. Reject unsupported flow-key inputs explicitly

Every fragmented IPv4 packet (`MF=1` or non-zero offset), every IPv6 Fragment header, IPv6 packets with extension headers that are not parsed, and truncated transport headers are dropped before a context is installed. Metrics distinguish these from malformed GENEVE. Support can be added later without changing the compliant base path.

### 7. Readiness represents sustained datapath ability

Initialization remains necessary but not sufficient. Persistent receive, TUN read/write, or packet-send failures transition datapath readiness to false after a bounded threshold. A successful operation or explicit component reinitialization restores readiness; an idle receive timeout is a successful poll and restores receive liveness without requiring peer traffic. Peer-controlled datagram truncation is a reason-counted packet drop, not a component failure. The threshold prevents one transient error from flapping GWLB target health.

## Risks / Trade-offs

- [Raw packet emission needs elevated privilege] -> Run with a minimal `CAP_NET_RAW` capability and test checksum/header construction independently.
- [Per-packet header construction costs CPU] -> Reuse buffers, avoid allocations, and benchmark before enabling batching.
- [Collision handling drops otherwise routable traffic] -> Expose collision metrics and document that overlapping inner tuples require a future control-plane selector.
- [Protocol timeouts can diverge from customized target-group values] -> Make timeouts explicit configuration and pass the Terraform target-group values to Envelope.
- [Readiness flaps under intermittent errors] -> Use bounded consecutive-error or duration thresholds and test recovery.

## Migration Plan

1. Land AWS options corrections and fixtures.
2. Add packet metadata and sender abstractions behind tests.
3. Add the Linux packet sender and privileged capture tests.
4. Switch egress to the compliant sender and remove UDP request/reply assumptions.
5. Add flow bounds, protocol lifetimes, collision handling, and liveness readiness.
6. Roll back by stopping the new service artifact; the old sender is not retained because it is known incompatible with GWLB.

The options change must be implemented, synced to the canonical specification, and archived before this change is marked complete. This change deliberately does not replace the options change's `Minimal GENEVE header handling` requirement.

## Open Questions

- Whether the first implementation should use an IPv4 raw socket with `IP_HDRINCL` or an equivalent kernel packet socket after benchmarking both.
- Whether customized GWLB TCP idle timeout should be discovered from deployment input or remain an explicit Envelope flag.
