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
The system SHALL read L3 IP packets from the `envelope0` TUN device, encapsulate them in GENEVE, and send them via UDP/6081.

#### Scenario: TUN packet available
- **WHEN** an L3 IP packet is read from the TUN device
- **THEN** the system encapsulates it into GENEVE and sends it over UDP/6081

#### Scenario: No return peer available
- **WHEN** an L3 IP packet is read from the TUN device and no return peer is known
- **THEN** the packet is dropped and `drops` is incremented

### Requirement: Minimal GENEVE header handling
The system SHALL parse and serialize only the GENEVE version, header length, VNI, and options length; options SHALL be preserved as opaque bytes and reattached on egress without TLV interpretation.

#### Scenario: Options present on ingress
- **WHEN** a GENEVE packet contains options bytes
- **THEN** the options bytes are preserved and emitted unchanged on the next egress packet

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

### Requirement: MTU-aware handling
The system SHALL enforce a configured TUN MTU and drop packets that exceed it rather than fragmenting.

#### Scenario: Oversized inner packet
- **WHEN** an inner packet exceeds the configured TUN MTU
- **THEN** the packet is dropped and `drops` is incremented

### Requirement: Tailscale-optimized MTU defaults
The system SHALL default the TUN MTU to 1280 to match Tailscale’s fixed tunnel MTU, and it MUST remain configurable for environments with different path MTUs.

#### Scenario: Default MTU
- **WHEN** the system starts without an explicit `--tun-mtu`
- **THEN** the TUN MTU is set to 1280

### Requirement: GENEVE protocol type validation
The system SHALL accept only GENEVE packets with protocol type set to IPv4 (0x0800) or IPv6 (0x86DD) and drop others.

#### Scenario: Unsupported protocol type
- **WHEN** a GENEVE packet has a protocol type other than IPv4 or IPv6
- **THEN** the packet is dropped and `decap_errors` is incremented

### Requirement: Tailscale-optimized flow timeout
The system SHALL default the flow mapping idle timeout to 5 minutes and allow configuration.

#### Scenario: Default flow timeout
- **WHEN** the system starts without an explicit flow timeout
- **THEN** the idle timeout is set to 5 minutes

### Requirement: Metrics exposure
The system SHALL expose Prometheus metrics on `:9090/metrics` and MUST include counters: `geneve_rx_packets`, `geneve_rx_bytes`, `geneve_tx_packets`, `geneve_tx_bytes`, `decap_errors`, `encap_errors`, `tun_rx_packets`, `tun_tx_packets`, and `drops`.

#### Scenario: Metrics scrape
- **WHEN** a client requests `:9090/metrics`
- **THEN** the response includes all required counters

### Requirement: Health endpoint
The system SHALL expose a health endpoint at `:9090/healthz` that returns HTTP 200 when the datapath is initialized and ready to process packets.

#### Scenario: Health check
- **WHEN** a client requests `:9090/healthz`
- **THEN** the response is HTTP 200 if the UDP socket and TUN device are ready
