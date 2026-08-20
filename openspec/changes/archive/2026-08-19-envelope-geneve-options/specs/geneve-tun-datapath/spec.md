## MODIFIED Requirements

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

### Requirement: GENEVE protocol type validation
The system SHALL accept only GENEVE packets with protocol type set to IPv4 (`0x0800`) or IPv6 (`0x86DD`) and drop others without modifying any options.

#### Scenario: Unsupported protocol type
- **WHEN** a GENEVE packet has a protocol type other than IPv4 or IPv6
- **THEN** the packet is dropped and `decap_errors` is incremented

## ADDED Requirements

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
