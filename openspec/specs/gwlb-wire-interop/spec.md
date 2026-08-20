# gwlb-wire-interop Specification

## Purpose
Define the AWS Gateway Load Balancer outer IPv4/UDP and GENEVE contract, bounded per-flow return identity, packet-level interoperability tests, observability, and sustained datapath liveness.
## Requirements
### Requirement: AWS GWLB ingress tuple capture
The system SHALL accept the AWS GWLB profile over outer IPv4 and SHALL capture the outer peer IPv4 address, local destination IPv4 address, GWLB-selected UDP source port, destination port 6081, and complete GENEVE return metadata for each valid packet.

#### Scenario: Valid AWS GWLB packet
- **WHEN** an outer IPv4 packet arrives from `<gwlb-ip>:<flow-port>` at `<appliance-ip>:6081` with a valid AWS GENEVE payload
- **THEN** the system records both outer addresses, `<flow-port>`, and the GENEVE return metadata before injecting the inner packet into TUN

#### Scenario: AWS profile listener invariant
- **WHEN** the AWS GWLB profile is configured with a local UDP port other than 6081
- **THEN** startup fails, while packets sent to other unbound ports are never delivered to the datapath

### Requirement: AWS GWLB return tuple
The system SHALL emit mapped return traffic from `<appliance-ip>:<flow-port>` to `<gwlb-ip>:6081`, preserving the ingress UDP ports in their original source and destination positions and swapping only the outer IPv4 addresses.

#### Scenario: Mapped return packet
- **WHEN** a TUN packet matches a context learned from `<gwlb-ip>:<flow-port>` to `<appliance-ip>:6081`
- **THEN** the emitted packet has source `<appliance-ip>:<flow-port>` and destination `<gwlb-ip>:6081`

#### Scenario: Valid outer packet fields
- **WHEN** a mapped return packet is emitted
- **THEN** its outer IPv4 and UDP lengths and checksums are valid for the complete GENEVE payload

### Requirement: AWS GENEVE profile fidelity
The system SHALL require GENEVE version 0, VNI 0, zero option reserved bits, and exactly one valid four-byte AWS flow cookie for the AWS profile, SHALL reject OAM packets, and SHALL emit the mapped protocol type, critical-option state, and ordered options block required by the matching context.

#### Scenario: AWS metadata round trip
- **WHEN** a valid GWLB packet contains AWS options including a flow cookie
- **THEN** mapped return traffic contains VNI 0 and the identical ordered options bytes

#### Scenario: Unsupported VNI
- **WHEN** an AWS-profile packet contains a non-zero VNI
- **THEN** the packet is rejected, the reason is counted, and no context is installed

#### Scenario: OAM packet
- **WHEN** an AWS-profile packet has the GENEVE OAM bit set
- **THEN** its inner payload is not forwarded and no return context is installed

#### Scenario: Missing or duplicate flow cookie
- **WHEN** an AWS-profile packet has no AWS flow cookie or has more than one flow cookie
- **THEN** the packet is rejected and no return context is installed

#### Scenario: Non-zero option reserved bits
- **WHEN** an otherwise structurally valid AWS-profile packet has non-zero reserved bits in an option header
- **THEN** the packet is rejected before return-context installation so transmit never preserves reserved bits that must be zero

### Requirement: Unambiguous GWLB return context
The system SHALL associate each supported inner flow with exactly one complete return identity consisting of peer IP, local IP, flow-selected port, flow cookie, VNI, protocol type, fixed-header flags, and ordered options, MUST bound per-key conflict tracking, and MUST fail closed while an identical inner key has conflicting live identities. Interface index is a mutable route hint rather than authoritative wire identity, and conflicting identities SHALL expire independently.

#### Scenario: Unique context
- **WHEN** repeated ingress packets for an inner flow carry an identical complete return identity
- **THEN** the existing context is refreshed without becoming conflicted

#### Scenario: Conflicting context
- **WHEN** an identical inner flow key is observed with any difference in peer IP, local IP, flow-selected port, flow cookie, VNI, protocol type, fixed-header flags, or ordered options
- **THEN** mapped return traffic for that key is dropped until the conflict is resolved and a collision metric is incremented

#### Scenario: Route-hint change
- **WHEN** an otherwise identical return identity arrives on a different interface index
- **THEN** its route hint is refreshed without creating a wire-identity conflict

#### Scenario: Surviving identity recovers
- **WHEN** conflicting identities share an inner key, only one continues receiving traffic, and every competing identity exceeds its protocol timeout
- **THEN** the surviving identity automatically becomes usable while its own activity remains fresh

#### Scenario: Multiple identities remain active
- **WHEN** two or more conflicting identities continue receiving traffic within their protocol timeout
- **THEN** mapped return traffic remains fail-closed

### Requirement: Bounded GWLB return-context lifecycle
The system SHALL enforce configurable finite context capacity and protocol-aware idle timeouts, SHALL refresh a context on valid ingress and successful mapped egress, and SHALL expose expiry and eviction counts.

#### Scenario: Default TCP lifetime
- **WHEN** a TCP context is active and no timeout override is supplied
- **THEN** its idle timeout is 350 seconds and activity in either mapped direction refreshes it

#### Scenario: Default UDP lifetime
- **WHEN** a UDP context is active and no timeout override is supplied
- **THEN** its idle timeout is 120 seconds and activity in either mapped direction refreshes it

#### Scenario: Capacity exhausted
- **WHEN** a valid new context arrives at configured capacity and no expired entry exists
- **THEN** the oldest inactive context is evicted, the event is counted, and capacity remains bounded

#### Scenario: Process restart
- **WHEN** Envelope restarts
- **THEN** no pre-restart return context is used and new traffic must establish new contexts

### Requirement: Unsupported inner-flow forms fail explicitly
The AWS profile SHALL reject inner packets for which it cannot derive a stable supported return key, including every fragmented IPv4 packet, every IPv6 Fragment header, unparsed IPv6 extension-header chains, and truncated TCP or UDP headers.

#### Scenario: Fragmented IPv4 packet
- **WHEN** a valid GENEVE packet contains IPv4 `MF=1` or a non-zero fragment offset
- **THEN** the inner packet is dropped before context installation and the unsupported-flow counter is incremented

#### Scenario: IPv6 Fragment header
- **WHEN** a valid GENEVE packet contains an IPv6 Fragment header
- **THEN** the inner packet is dropped before context installation and the unsupported-flow counter is incremented

#### Scenario: IPv6 extension header not supported
- **WHEN** a valid GENEVE packet contains an IPv6 extension-header chain the flow parser does not support
- **THEN** the inner packet is dropped before context installation and the unsupported-flow counter is incremented

### Requirement: Packet-level GWLB interoperability verification
The system SHALL provide deterministic packet-level tests that validate the AWS outer tuple and GENEVE metadata rather than relying on ordinary UDP request/reply semantics.

#### Scenario: Linux capture test
- **WHEN** the privileged Linux interoperability test sends ingress from a non-6081 source port and injects a mapped return packet
- **THEN** packet capture observes the original source port as the return source, destination port 6081, swapped outer addresses, VNI 0, and identical options

#### Scenario: Sanitized AWS fixture
- **WHEN** the AWS-compatible PCAP fixture suite is executed
- **THEN** valid packets decode and round trip while malformed tuple, header, and context cases fail with their specified reasons

### Requirement: GWLB wire observability
The system SHALL expose metrics for profile rejection, receive-boundary packet drops, compliant-send failure, missing and conflicted contexts, possible routing loops, context expiry and eviction, unsupported inner forms, liveness transitions, and total drops.

#### Scenario: Missing return context
- **WHEN** a reverse-orientation TUN packet is dropped because no return context exists
- **THEN** both total drops and the missing-context metric increase

#### Scenario: Forward-orientation loop prevention
- **WHEN** a forward-orientation TUN packet is rejected instead of using a direct context lookup
- **THEN** both total drops and the possible-loop metric increase

### Requirement: Sustained datapath liveness
The system SHALL report healthy only while the receive path, TUN path, and AWS-compliant send path are initialized and have not exceeded their persistent-error thresholds.

#### Scenario: Persistent datapath failure
- **WHEN** receive, TUN read/write, or compliant-send failures exceed the configured threshold
- **THEN** datapath liveness becomes unhealthy with a component-specific reason

#### Scenario: Datapath recovery
- **WHEN** the failed component resumes successful operation or is reinitialized and meets the configured recovery condition
- **THEN** datapath liveness returns to healthy

#### Scenario: Idle receive recovery
- **WHEN** the receive component is unhealthy and a subsequent receive poll completes with an idle timeout
- **THEN** receive liveness recovers without requiring an ingress packet

#### Scenario: Oversized peer datagram
- **WHEN** a peer sends a UDP datagram larger than the bounded receive buffer
- **THEN** the packet and truncation reason are counted without changing receive-component liveness
