## MODIFIED Requirements

### Requirement: Minimal GENEVE header handling
The system SHALL parse and serialize only the GENEVE version, header length, VNI, and options length; options SHALL be preserved as opaque bytes and reattached on egress without TLV interpretation.

#### Scenario: Options present on ingress
- **WHEN** a GENEVE packet contains options bytes
- **THEN** the options bytes are preserved and emitted unchanged on the next egress packet

#### Scenario: Options validation
- **WHEN** a GENEVE packet contains options with a length that is not a multiple of 4 or exceeds the maximum allowed options size
- **THEN** the packet is dropped and `decap_errors` is incremented

### Requirement: Return path symmetry (GWLB)
The system SHALL maintain a flow-to-peer mapping keyed by the inner 5-tuple (src IP, dst IP, IP protocol, src port, dst port) and use it to send return traffic to the correct UDP peer.

#### Scenario: Flow mapping update
- **WHEN** a valid GENEVE packet is received for a flow
- **THEN** the flow’s mapping is updated with the sender’s UDP peer, VNI, and options bytes

#### Scenario: Flow-based egress
- **WHEN** a TUN packet is read and a matching flow mapping exists
- **THEN** the packet is encapsulated using the mapped VNI/options and sent to the mapped UDP peer

#### Scenario: No flow mapping
- **WHEN** a TUN packet is read and no mapping exists
- **THEN** the packet is dropped and `drops` is incremented

#### Scenario: Flow mapping expiration
- **WHEN** a flow mapping has been idle beyond the configured timeout
- **THEN** it is expired and no longer used for egress

### Requirement: GENEVE protocol type validation
The system SHALL accept only GENEVE packets with protocol type set to IPv4 (0x0800) or IPv6 (0x86DD) and drop others.

#### Scenario: Unsupported protocol type
- **WHEN** a GENEVE packet has a protocol type other than IPv4 or IPv6
- **THEN** the packet is dropped and `decap_errors` is incremented

## ADDED Requirements

### Requirement: Optional TLV parsing for logging/mapping
The system SHALL preserve GENEVE options end-to-end by default, and MAY optionally parse selected TLVs (configured) for logging or mapping hints without modifying the options bytes.

#### Scenario: Opaque preserve default
- **WHEN** TLV parsing is disabled
- **THEN** options are preserved verbatim and no TLVs are interpreted

#### Scenario: Selected TLV parsing
- **WHEN** TLV parsing is enabled with a configured allowlist of option classes/types
- **THEN** only those TLVs are parsed for logging/mapping hints and the options bytes are preserved unchanged

### Requirement: Options size bounds
The system SHALL enforce a maximum total options size and drop packets that exceed it.

#### Scenario: Oversized options block
- **WHEN** the options length exceeds the configured maximum
- **THEN** the packet is dropped and `decap_errors` is incremented
