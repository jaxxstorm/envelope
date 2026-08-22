## MODIFIED Requirements

### Requirement: Egress TUN encapsulation to GENEVE
The system SHALL operate Envelope targets in symmetric inline mode. In this mode, a validated GENEVE packet is decapsulated and injected into `envelope0` for host forwarding, and normal TUN traffic SHALL NOT be encapsulated or emitted as a target-originated GENEVE packet. A packet unexpectedly read from the TUN egress path SHALL be dropped, counted with a bounded symmetric-mode reason, and MUST NOT be forwarded using a return context.

#### Scenario: Decapsulated remote packet
- **WHEN** a valid GWLB GENEVE packet contains an inner packet for a local-site or remote-site CIDR
- **THEN** the inner packet is injected into `envelope0` and host routing forwards it toward the configured local VPC or Tailscale path without a target-originated GENEVE packet

#### Scenario: Unexpected TUN egress
- **WHEN** symmetric inline mode reads an IP packet from `envelope0`'s egress path
- **THEN** it drops the packet, increments total drops and the symmetric unexpected-egress metric, and emits no raw IPv4 or UDP packet

### Requirement: Return path symmetry (GWLB)
The system SHALL obtain inter-site flow symmetry from both directions traversing their local GWLBE and GWLB rather than from an Envelope return-context table. A healthy target SHALL forward any individually valid GWLB-delivered packet without requiring that target to have processed an earlier packet from the same inner flow.

#### Scenario: Reverse packet reaches another target
- **WHEN** GWLB delivers a reverse-orientation packet to a healthy Envelope target that did not receive a previous packet for that flow
- **THEN** the target validates, decapsulates, and injects the packet into `envelope0` without a missing-context drop

#### Scenario: Target restart
- **WHEN** an Envelope target restarts and later becomes healthy
- **THEN** it can forward a valid post-restart GWLB-delivered packet without restoring pre-restart flow state

## REMOVED Requirements

### Requirement: Tailscale-optimized flow timeout
**Reason**: Symmetric inline forwarding does not use an Envelope GWLB return-context table.
**Migration**: Remove context-timeout configuration from target services; use the GWLB and transport timeout evidence defined by the HA acceptance profile.
