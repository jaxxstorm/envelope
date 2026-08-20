## Purpose

Define the GWLB-oriented GENEVE <-> TUN datapath optimized for Tailscale, including flow-based return-path symmetry, MTU handling, and required health/metrics endpoints.
## Requirements
### Requirement: Ingress GENEVE decapsulation to TUN
The system SHALL accept UDP/6081 packets, parse a minimal GENEVE header, and write the inner L3 IP payload to the `envelope0` TUN device.

#### Scenario: Valid GENEVE packet
- **WHEN** a UDP/6081 packet with a valid GENEVE header and an inner IP payload is received
- **THEN** the inner IP payload is written to the TUN device without an Ethernet header

#### Scenario: Malformed GENEVE packet
- **WHEN** a UDP/6081 packet has an invalid or unsupported GENEVE header
- **THEN** the packet is dropped and `decap_errors` is incremented

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

### Requirement: Minimal GENEVE header handling
The system SHALL validate the GENEVE base header and complete TLV structure and SHALL preserve the complete ordered options block associated with a flow as opaque bytes. Configured read-only value parsing MUST NOT mutate, normalize, reorder, insert, or remove option bytes.

#### Scenario: Matching return packet preserves options
- **WHEN** a valid GENEVE packet contains options and a later return packet matches that flow
- **THEN** the exact ordered options bytes are emitted on the matching return packet

#### Scenario: Structurally malformed options
- **WHEN** the aggregate option length or an internal TLV length is inconsistent with the received packet
- **THEN** the packet is dropped and a specific options-validation error is incremented

#### Scenario: Reserved option bits
- **WHEN** an option length byte has non-zero reserved high bits and a valid low five-bit length
- **THEN** generic structural validation ignores the reserved bits and uses only the low five bits for data length, without promising AWS-profile return transmission for that packet

#### Scenario: Unknown non-critical option
- **WHEN** a structurally valid unknown option does not have its critical bit set
- **THEN** the packet remains valid and the unknown option bytes are preserved unchanged

#### Scenario: Unknown critical option
- **WHEN** a packet contains an unknown option with its critical bit set
- **THEN** the packet is dropped and a critical-option validation reason is incremented

### Requirement: Optional allocation-free TLV value parsing
The system SHALL structurally validate all option headers and SHALL expose configured option values for observability through an iterator that does not allocate per packet when value logging is disabled.

#### Scenario: Value parsing disabled
- **WHEN** configured TLV value parsing is disabled
- **THEN** all headers and critical semantics are validated without materializing a TLV result collection

#### Scenario: Allowlisted value parsing
- **WHEN** value parsing is enabled with an allowlist of class and seven-bit type identifiers
- **THEN** only allowlisted values are exposed for logging while every option header is validated and raw bytes remain unchanged

#### Scenario: Bounded redacted logging
- **WHEN** an allowlisted AWS value is logged
- **THEN** class, type, and length are available while full endpoint identifiers and flow-cookie values are redacted by default

### Requirement: AWS GWLB option validation
The system SHALL recognize AWS class `0x0108` VPCE ID, attachment ID, and flow cookie option shapes, SHALL require exactly one four-byte flow cookie for the AWS profile independent of the logging allowlist, SHALL permit at most one VPCE ID and one attachment ID, and SHALL preserve unknown non-critical AWS options for forward compatibility.

#### Scenario: Valid AWS option block
- **WHEN** an option block contains class `0x0108` type 1 with 8 bytes and type 3 with 4 bytes
- **THEN** validation succeeds and both options remain byte-identical and in the same order

#### Scenario: Optional attachment ID
- **WHEN** an option block contains class `0x0108` type 2 with 8 bytes
- **THEN** validation succeeds and the option is preserved unchanged

#### Scenario: Known AWS option with wrong length
- **WHEN** a recognized AWS option type has a data length different from its defined length
- **THEN** the packet is dropped and an AWS-option-length error is incremented

#### Scenario: Missing or duplicate AWS flow cookie
- **WHEN** an AWS-profile option block has no flow cookie or more than one flow cookie
- **THEN** the packet is dropped and an AWS-option-cardinality error is incremented

#### Scenario: Duplicate VPCE or attachment identity
- **WHEN** an AWS-profile option block has more than one VPCE ID or more than one attachment ID
- **THEN** the packet is dropped and an AWS-option-cardinality error is incremented

### Requirement: Options size bounds
The system SHALL enforce a configurable maximum total options size no greater than the GENEVE protocol maximum and SHALL drop larger option blocks.

#### Scenario: Oversized options block
- **WHEN** the options length exceeds the configured maximum
- **THEN** the packet is dropped and `decap_errors` is incremented

### Requirement: AWS-compatible option fixtures
The test suite SHALL include sanitized AWS captures or wire-identical fixtures that cover valid ordered metadata with zero reserved transmit bits, parser-only reserved-bit tolerance, malformed lengths, option cardinality, and critical-option behavior.

#### Scenario: Valid fixture round trip
- **WHEN** a fixture with multiple AWS GWLB options is decoded and emitted for its matching flow
- **THEN** an independent comparison confirms the complete option block is byte-identical

#### Scenario: Invalid fixture matrix
- **WHEN** malformed and unknown-critical fixtures are processed
- **THEN** each packet is rejected for the expected specific reason

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

### Requirement: MTU-aware handling
The system SHALL enforce the configured inner MTU, SHALL integrate with host TCP MSS policy so valid TCP streams do not become persistent silent blackholes, and SHALL receive every complete legal IPv4 UDP payload so unsupported oversized traffic is dropped with an explicit MTU reason. The GWLB profile MUST NOT claim PMTU signalling until related ICMP-to-context behavior is specified and proven.

#### Scenario: Tailscale-safe TCP flow
- **WHEN** traffic crosses a configured 1280-byte Tailscale path
- **THEN** host routing constrains TCP MSS to a value that prevents packets larger than the Envelope inner MTU

#### Scenario: Every directed Tailscale TCP path
- **WHEN** IPv4 or IPv6 TCP traffic crosses underlay to Tailscale, Tailscale to underlay, Envelope to Tailscale, or Tailscale to Envelope
- **THEN** the SYN advertises the derived safe MSS and a full-sized TCP transfer completes without a silent drop

#### Scenario: Oversized packet
- **WHEN** an inner packet exceeds the configured Envelope MTU
- **THEN** it is dropped with an MTU-specific reason and counter rather than an undifferentiated drop

#### Scenario: Maximum-options one-byte oversize ingress
- **WHEN** a complete UDP datagram contains 252 bytes of valid options and an inner packet exactly one byte above the configured MTU
- **THEN** receive capacity preserves the complete datagram and reports an ingress MTU drop rather than UDP truncation

#### Scenario: Arbitrarily oversized valid ingress
- **WHEN** a complete legal UDP datagram contains a valid GENEVE packet whose inner packet is two or substantially more bytes above the configured MTU
- **THEN** receive capacity preserves the complete datagram and reports the appropriate IPv4 or IPv6 ingress MTU reason rather than generic truncation

#### Scenario: Real-TUN one-byte oversize egress
- **WHEN** a real TUN returns an inner frame exactly one byte above the configured Envelope MTU
- **THEN** Envelope observes and drops it without encapsulating truncated or stale buffer contents

### Requirement: Tailscale-optimized MTU defaults
The system SHALL default the TUN MTU to 1280 to match Tailscale’s fixed tunnel MTU, and it MUST remain configurable for environments with different path MTUs.

#### Scenario: Default MTU
- **WHEN** the system starts without an explicit `--tun-mtu`
- **THEN** the TUN MTU is set to 1280

### Requirement: GENEVE protocol type validation
The system SHALL accept only GENEVE packets with protocol type set to IPv4 (`0x0800`) or IPv6 (`0x86DD`) and drop others without modifying any options.

#### Scenario: Unsupported protocol type
- **WHEN** a GENEVE packet has a protocol type other than IPv4 or IPv6
- **THEN** the packet is dropped and `decap_errors` is incremented

### Requirement: Tailscale-optimized flow timeout
The system SHALL use configurable protocol-aware GWLB return-context timeouts, defaulting to 350 seconds for TCP and 120 seconds for UDP and other protocols, and SHALL refresh activity on valid ingress and successful mapped egress.

#### Scenario: Protocol timeout defaults
- **WHEN** the system starts without explicit context timeout overrides
- **THEN** TCP uses 350 seconds and UDP and other protocols use 120 seconds

#### Scenario: Active return-only traffic
- **WHEN** mapped return traffic is emitted successfully before timeout
- **THEN** the context activity timestamp is refreshed

### Requirement: Metrics exposure
The system SHALL expose all GWLB datapath and context metrics plus routing apply attempts and failures, effective-path failures by reason, drift repairs, ownership decisions, Tailscale readiness failures, MTU-specific drops, and current routing readiness.

#### Scenario: Datapath-only metrics scrape
- **WHEN** a client requests `:9090/metrics` in routing mode `off`
- **THEN** the response includes all required GWLB datapath and context metrics

#### Scenario: Routing-integrated metrics scrape
- **WHEN** a client requests `:9090/metrics` in routing mode `verify` or `manage`
- **THEN** the response additionally includes all routing and host-path metrics with reason labels or bounded reason-specific counters

### Requirement: Health endpoint
The system SHALL return HTTP 200 from `:9090/healthz` only when the live GWLB datapath is healthy and, in `verify` or `manage` mode, the Tailscale backend, effective forward and return routes, host forwarding, reverse-path filtering, firewall, MSS policy, and managed state are ready.

#### Scenario: Datapath-only readiness
- **WHEN** routing mode is `off` and the live datapath is healthy
- **THEN** `:9090/healthz` returns HTTP 200

#### Scenario: Routing-integrated readiness
- **WHEN** routing mode is `verify` or `manage` and every effective routing prerequisite is valid
- **THEN** `:9090/healthz` returns HTTP 200

#### Scenario: Routing prerequisite missing
- **WHEN** any required backend, route, rule, sysctl, reverse-path, firewall, MSS, or ownership condition is invalid
- **THEN** `:9090/healthz` returns HTTP 503 with a bounded component-specific reason

#### Scenario: Persistent datapath failure
- **WHEN** the GWLB receive, TUN, or compliant-send path exceeds its persistent-error threshold
- **THEN** routing state cannot mask the failure and `:9090/healthz` returns HTTP 503

#### Scenario: Unexpected loop termination
- **WHEN** the receive or TUN-read loop closes without process cancellation or explicit shutdown
- **THEN** the component becomes immediately unhealthy, sibling loops are cancelled, resources close once, and the process supervisor receives an error

### Requirement: Envelope datapath ownership boundary
The system SHALL terminate and originate GENEVE on the Envelope-owned TUN device and MUST NOT share that TUN with `tailscaled`; host routing SHALL connect the Envelope and Tailscale interfaces according to explicit CIDR roles.

#### Scenario: Co-resident tailscaled deployment
- **WHEN** Envelope runs with an active `tailscaled`
- **THEN** each process retains its configured interface and packets move between them only through verified host routing

#### Scenario: Pre-existing Envelope TUN
- **WHEN** the configured Envelope TUN name already identifies a persistent or attached device
- **THEN** exclusive TUN creation fails startup rather than sharing or reconfiguring that device

#### Scenario: Local-delivery Tailnet packet
- **WHEN** a cold Tailnet packet is destined for a configured local-delivery CIDR
- **THEN** host routing bypasses `envelope0`, so the packet is not subjected to a nonexistent local GWLB return context
