## Purpose

Define the GWLB-oriented GENEVE datapath for immediate packet-scoped GWLB turnaround, including AWS profile validation, opaque metadata preservation, bounded MTU handling, and required health/metrics endpoints.

## Requirements
### Requirement: Immediate packet-scoped GENEVE turnaround
The version-2 target datapath SHALL validate each AWS GENEVE ingress packet and immediately emit exactly one AWS-compliant GENEVE return containing the same inner packet and the current packet's VNI, protocol metadata, and ordered options. It SHALL NOT write the inner packet to TUN, wait for a reverse packet, route the inner packet, or retain metadata for another packet.

#### Scenario: Valid packet turnaround
- **WHEN** a healthy target receives one valid AWS GENEVE packet
- **THEN** it returns the same inner bytes with that packet's AWS tuple and GENEVE metadata before discarding the packet-scoped identity

#### Scenario: Independent packet processing
- **WHEN** a later packet has the same inner tuple or arrives after target restart
- **THEN** its result depends only on its own validation and metadata and not on earlier processing

#### Scenario: No target inner forwarding
- **WHEN** the destination belongs to either configured site
- **THEN** the target returns the packet to GWLB and neither a TUN nor a Tailscale or VPC forwarding path receives the inner packet directly

### Requirement: Minimal GENEVE header handling
The system SHALL validate the GENEVE base header and complete TLV structure and SHALL preserve the current packet's complete ordered options block as opaque bytes. Configured read-only parsing MUST NOT mutate, normalize, reorder, insert, or remove option bytes, and no option bytes SHALL be stored for a later packet.

#### Scenario: Current packet preserves options
- **WHEN** a valid GENEVE packet contains ordered options
- **THEN** its immediate return contains the exact same ordered option bytes

#### Scenario: Structurally malformed or unknown critical option
- **WHEN** the aggregate option length, internal TLV length, or critical-option semantics are invalid
- **THEN** the packet is dropped and no return is emitted

#### Scenario: Unknown non-critical option
- **WHEN** a structurally valid unknown option is non-critical
- **THEN** the current packet remains valid and the unknown bytes are returned unchanged

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
The test suite SHALL include sanitized AWS captures or wire-identical fixtures that cover valid ordered metadata with zero reserved transmit bits, malformed lengths, option cardinality, and critical-option behavior using immediate per-packet turnaround.

#### Scenario: Valid fixture packet round trip
- **WHEN** a fixture with multiple AWS GWLB options is processed
- **THEN** an independent comparison confirms that one immediate return has the complete byte-identical inner packet and ordered option block

#### Scenario: Invalid fixture matrix
- **WHEN** malformed and unknown-critical fixtures are processed
- **THEN** each packet is rejected for the expected specific reason and produces no return

### Requirement: Return path symmetry (GWLB)
The system SHALL complete the appliance leg for every individually valid packet by returning it to the GWLB that sent it, using only packet-scoped metadata. Inter-site symmetry SHALL come from both sites routing each direction through their GWLBE and GWLB, not from an Envelope return-context table or direct target inner forwarding.

#### Scenario: Any flow orientation reaches a target
- **WHEN** GWLB delivers a forward- or reverse-orientation packet to a healthy target that did not receive an earlier packet for that flow
- **THEN** the target validates and immediately returns that packet without a missing-context decision

#### Scenario: Target restart
- **WHEN** an Envelope target restarts and later becomes healthy
- **THEN** it can return a valid post-restart packet without restoring pre-restart flow state

### Requirement: MTU-aware handling
The target SHALL receive every complete packet up to the configured AWS-profile bound, validate declared lengths before return, and either return the complete byte-identical inner packet or drop it with an explicit bounded-size reason. It SHALL NOT truncate a packet or depend on a target TUN MTU. Transport-router forwarding and MSS policy SHALL enforce the Tailscale path MTU separately.

#### Scenario: Largest accepted packet
- **WHEN** a complete valid packet is at the configured target receive bound
- **THEN** the immediate return contains the complete untruncated inner packet

#### Scenario: Oversized or truncated packet
- **WHEN** a datagram exceeds the receive bound or its declared lengths are incomplete
- **THEN** it is dropped with the specific receive-boundary reason and no partial return is emitted

### Requirement: GENEVE protocol type validation
The system SHALL accept only GENEVE packets with protocol type set to IPv4 (`0x0800`) or IPv6 (`0x86DD`) and drop others without modifying any options.

#### Scenario: Unsupported protocol type
- **WHEN** a GENEVE packet has a protocol type other than IPv4 or IPv6
- **THEN** the packet is dropped and `decap_errors` is incremented

### Requirement: Metrics exposure
The system SHALL expose AWS profile and receive drops, valid packet receipt, packet-scoped return success and failure, MTU-specific drops, liveness transitions, and target readiness. Version-2 target metrics SHALL NOT require context, TUN, host-routing, or Tailscale state.

#### Scenario: Datapath metrics scrape
- **WHEN** a client requests `:9090/metrics` from a version-2 target
- **THEN** packet-turnaround counters and current receiver/sender readiness are present without normal-path context or TUN counters

### Requirement: Health endpoint
The system SHALL return HTTP 200 from `:9090/healthz` only while AWS packet validation, receive, and packet-scoped compliant-send components are initialized and below persistent-error thresholds. A TUN, local/remote route, forwarding sysctl, firewall transit rule, MSS rule, or Tailscale backend SHALL NOT be a target health prerequisite.

#### Scenario: Packet-turnaround target ready
- **WHEN** receive, validation, and compliant-send components are healthy
- **THEN** `:9090/healthz` returns HTTP 200 without TUN or Tailscale readiness

#### Scenario: Persistent packet-turnaround failure
- **WHEN** receive or compliant-send failure exceeds its persistent-error threshold
- **THEN** `:9090/healthz` returns HTTP 503 with a bounded component-specific reason
