## MODIFIED Requirements

### Requirement: AWS GWLB ingress tuple capture
The system SHALL accept the AWS GWLB profile over outer IPv4, validate the complete AWS GENEVE wire contract, and retain only bounded observability needed to identify the receiving target and packet path. Symmetric inline forwarding SHALL NOT persist an outer tuple, flow-selected port, or GENEVE options as a prerequisite for forwarding a later packet.

#### Scenario: Valid AWS GWLB packet
- **WHEN** an outer IPv4 packet arrives from `<gwlb-ip>:<flow-port>` at `<appliance-ip>:6081` with a valid AWS GENEVE payload
- **THEN** the system validates the tuple and metadata, records bounded receive observability, and injects the inner packet into TUN without installing a return context

#### Scenario: AWS profile listener invariant
- **WHEN** the AWS GWLB profile is configured with a local UDP port other than 6081
- **THEN** startup fails, while packets sent to other unbound ports are never delivered to the datapath

### Requirement: GWLB wire observability
The system SHALL expose profile-rejection, receive-boundary drop, TUN injection, unexpected symmetric TUN-egress, target-ready, and total-drop metrics. It SHALL NOT report a missing-context, conflicted-context, possible-loop, context-expiry, or context-eviction condition as a normal symmetric-mode forwarding requirement.

#### Scenario: Packet is forwarded without context
- **WHEN** a valid packet is delivered by GWLB to a healthy symmetric target
- **THEN** receive and TUN-transmit metrics increase and no missing-context metric is required for the packet

## REMOVED Requirements

### Requirement: AWS GWLB return tuple
**Reason**: Symmetric inline targets do not originate normal-path GENEVE return packets.
**Migration**: Route the reverse packet through its local GWLBE and GWLB so a target receives it as validated GENEVE ingress.

### Requirement: Unambiguous GWLB return context
**Reason**: GWLB provides target selection when both packet directions traverse the endpoint and load balancer.
**Migration**: Remove return-identity and conflict configuration; verify that no inter-site path bypasses its local GWLBE.

### Requirement: Bounded GWLB return-context lifecycle
**Reason**: Symmetric inline forwarding has no return-context lifecycle.
**Migration**: Remove flow-capacity and flow-timeout configuration and use bounded target/ingress-router health evidence instead.
