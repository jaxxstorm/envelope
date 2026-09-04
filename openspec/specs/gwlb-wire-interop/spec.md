# gwlb-wire-interop Specification

## Purpose
Define the AWS Gateway Load Balancer outer IPv4/UDP and GENEVE contract for immediate packet-scoped turnaround, packet-level interoperability tests, observability, and sustained datapath liveness.

## Requirements
### Requirement: AWS GWLB ingress tuple capture
The system SHALL accept the AWS GWLB profile over outer IPv4 and capture the outer peer IPv4 address, local destination IPv4 address, GWLB-selected UDP source port, destination port 6081, interface route hint, and complete GENEVE metadata in the current packet's processing scope. None of those values SHALL persist as a prerequisite for another packet.

#### Scenario: Valid AWS GWLB packet
- **WHEN** an outer IPv4 packet arrives from `<gwlb-ip>:<flow-port>` at `<appliance-ip>:6081` with a valid AWS GENEVE payload
- **THEN** the system validates and captures the tuple and metadata for that packet's immediate return without installing an inner-flow return context or injecting the inner packet into TUN

#### Scenario: AWS profile listener invariant
- **WHEN** the AWS GWLB profile is configured with a local UDP port other than 6081
- **THEN** startup fails, while packets sent to other unbound ports are never delivered to the datapath

### Requirement: AWS GWLB return tuple
The system SHALL emit the current valid packet from `<appliance-ip>:<flow-port>` to `<gwlb-ip>:6081`, preserving the ingress UDP ports in their original source and destination positions and swapping only the outer IPv4 addresses. Outer IPv4 and UDP lengths and checksums SHALL cover the complete returned GENEVE packet.

#### Scenario: Immediate packet return
- **WHEN** a valid packet arrives from `<gwlb-ip>:<flow-port>` at `<appliance-ip>:6081`
- **THEN** its immediate return has source `<appliance-ip>:<flow-port>` and destination `<gwlb-ip>:6081` without consulting another packet

#### Scenario: Valid outer packet fields
- **WHEN** the packet-scoped return is emitted
- **THEN** its outer IPv4 and UDP lengths and checksums are valid for the complete GENEVE payload

### Requirement: AWS GENEVE profile fidelity
The system SHALL require GENEVE version 0, VNI 0, zero option reserved bits, and exactly one valid four-byte AWS flow cookie for the AWS profile, SHALL reject OAM packets, and SHALL emit the current packet with the same inner bytes, VNI, protocol type, critical-option state, and complete ordered options block.

#### Scenario: AWS metadata and inner-packet round trip
- **WHEN** a valid GWLB packet contains AWS options including a flow cookie
- **THEN** its immediate return contains the byte-identical inner packet, VNI 0, and identical ordered options bytes including the cookie

#### Scenario: Invalid AWS profile
- **WHEN** an AWS-profile packet has an unsupported VNI, OAM bit, non-zero option reserved bits, malformed known option, or missing or duplicate flow cookie
- **THEN** the packet is rejected and no packet-scoped return is sent

### Requirement: Packet-scoped GWLB turnaround identity
For each valid AWS GWLB ingress packet, the system SHALL construct exactly one return packet from only that ingress packet's outer tuple and GENEVE metadata, emit it immediately, and discard the packet-scoped identity after the send. It SHALL NOT install, query, refresh, conflict-check, expire, evict, or restore metadata keyed by an inner flow or used by another packet.

#### Scenario: Concurrent packets with different identities
- **WHEN** concurrent valid packets carry identical inner tuples but different GWLB peers, flow-selected ports, or ordered options
- **THEN** each packet is returned exactly once with its own ingress identity and neither packet creates a cross-packet conflict

#### Scenario: Target restart
- **WHEN** a target restarts and receives its first valid packet
- **THEN** it returns that packet using the current packet's metadata without restoring pre-restart state

### Requirement: Inner packet remains opaque across target turnaround
The target SHALL preserve the complete inner packet byte-for-byte and SHALL NOT require an inner flow key, inject the packet into TUN, decrement its TTL, apply NAT, or forward it directly to a VPC or Tailscale interface.

#### Scenario: Valid fragmented or extended inner packet
- **WHEN** a valid AWS GENEVE packet contains an otherwise supported inner IP packet that cannot form the former return-context key
- **THEN** the target returns the same inner bytes instead of rejecting the packet for missing flow-key information

#### Scenario: Invalid outer or GENEVE packet
- **WHEN** tuple, framing, profile, length, option, or inner protocol validation fails
- **THEN** no return packet is emitted

### Requirement: Packet-level GWLB interoperability verification
The system SHALL provide deterministic packet-level tests that validate immediate packet turnaround, the AWS outer tuple, the complete GENEVE metadata, and inner-packet byte identity rather than relying on ordinary UDP request/reply semantics.

#### Scenario: Linux capture test
- **WHEN** the privileged Linux interoperability test sends valid ingress from a non-6081 source port
- **THEN** capture observes exactly one immediate return with the original source port as return source, destination port 6081, swapped outer addresses, VNI 0, identical ordered options and cookie, and identical inner bytes

#### Scenario: Sanitized AWS fixture
- **WHEN** the AWS-compatible PCAP fixture suite is executed
- **THEN** every valid packet independently round trips while malformed tuple, header, and metadata cases emit nothing and fail with their specified reasons

### Requirement: GWLB wire observability
The system SHALL expose bounded metrics for profile rejection, receive-boundary drop, valid packet receipt, packet-scoped return success and failure, target readiness, and total drops. It SHALL NOT expose a missing-context, conflicted-context, possible-loop, context-expiry, context-eviction, TUN-injection, or target inner-forwarding condition as part of the version-2 normal path.

#### Scenario: Packet is returned without context
- **WHEN** a valid packet is delivered by GWLB to a healthy symmetric target
- **THEN** valid-receive and compliant-return metrics increase and no cross-packet context or TUN metric is required

#### Scenario: Packet-scoped send fails
- **WHEN** validation succeeds but the AWS-compliant return send fails
- **THEN** return-failure and total-drop observability increase without retaining the packet identity for retry by a later packet

### Requirement: Sustained datapath liveness
The system SHALL report healthy only while the receive path and packet-scoped AWS-compliant send path are initialized and have not exceeded their persistent-error thresholds. TUN, host routing, and Tailscale SHALL NOT be target liveness prerequisites.

#### Scenario: Persistent datapath failure
- **WHEN** receive or compliant-return failures exceed the configured threshold
- **THEN** target liveness becomes unhealthy with a component-specific reason

#### Scenario: Datapath recovery
- **WHEN** the failed receive or send component is reinitialized and meets its configured recovery condition
- **THEN** target liveness returns to healthy without a TUN or Tailscale check
