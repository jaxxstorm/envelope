## MODIFIED Requirements

### Requirement: Egress TUN encapsulation to GENEVE
The system SHALL read supported L3 IP packets from the `envelope0` TUN device, match them to an unambiguous GWLB return context, encapsulate them in GENEVE, and emit them using the AWS-compliant outer tuple.

#### Scenario: TUN packet with return context
- **WHEN** a supported L3 IP packet is read from TUN and an unambiguous matching return context exists
- **THEN** the system emits an AWS-compliant GENEVE packet using that context

#### Scenario: No return context available
- **WHEN** an L3 IP packet is read from TUN and no matching return context exists
- **THEN** the packet is dropped, `drops` is incremented, and a missing-context reason is counted

#### Scenario: Conflicted return context
- **WHEN** an L3 IP packet is read from TUN and its return context is conflicted
- **THEN** the packet is dropped and collision and drop metrics identify the reason

### Requirement: Return path symmetry (GWLB)
The system SHALL maintain a bounded, protocol-aware return-context table keyed by the supported ingress inner flow tuple and SHALL use reverse-orientation TUN traffic to return packets through the same GWLB flow-selected port, peer, local address, VNI, and options that were learned on ingress.

#### Scenario: Return-context update
- **WHEN** a valid AWS GWLB packet is received for a supported flow
- **THEN** the flow context is installed or refreshed with the complete outer and GENEVE return metadata

#### Scenario: Reverse-flow egress
- **WHEN** a TUN packet contains the reverse tuple of an unambiguous live context
- **THEN** it is emitted with that context's AWS-compliant outer tuple and GENEVE metadata

#### Scenario: No flow mapping
- **WHEN** a TUN packet's reverse tuple has no live context
- **THEN** it is dropped and missing-context observability is updated

#### Scenario: Forward-orientation TUN packet
- **WHEN** a TUN packet has the same orientation as an ingress context instead of the required reverse orientation
- **THEN** it is dropped as a possible routing loop and is not re-encapsulated through that context

#### Scenario: Flow mapping expiration
- **WHEN** a return context is idle beyond its configured protocol timeout
- **THEN** it is expired and no longer used for egress

#### Scenario: Flow mapping collision
- **WHEN** one inner key maps to conflicting live GWLB contexts
- **THEN** return traffic fails closed until the ambiguity is removed

### Requirement: Tailscale-optimized flow timeout
The system SHALL use configurable protocol-aware GWLB return-context timeouts, defaulting to 350 seconds for TCP and 120 seconds for UDP and other protocols, and SHALL refresh activity on valid ingress and successful mapped egress.

#### Scenario: Protocol timeout defaults
- **WHEN** the system starts without explicit context timeout overrides
- **THEN** TCP uses 350 seconds and UDP and other protocols use 120 seconds

#### Scenario: Active return-only traffic
- **WHEN** mapped return traffic is emitted successfully before timeout
- **THEN** the context activity timestamp is refreshed
