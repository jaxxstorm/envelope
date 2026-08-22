## ADDED Requirements

### Requirement: Symmetric inter-site GWLB traversal
The system SHALL route every packet between configured disjoint site CIDRs through the source site's GWLBE and GWLB before it reaches an Envelope target. A remote Tailnet packet for a local-site CIDR SHALL first enter the local site through a Tailscale ingress router and then traverse that site's GWLBE and GWLB; no cold Tailnet packet may bypass GWLB and directly reach a workload.

#### Scenario: Local workload initiates
- **WHEN** a workload in site A sends a packet to a site B CIDR
- **THEN** the packet traverses site A's GWLBE, site A's GWLB, an Envelope target, Tailscale, site B's ingress router, site B's GWLBE, site B's GWLB, an Envelope target, and the site B workload path without source NAT

#### Scenario: Remote workload initiates
- **WHEN** a workload in site B sends a new packet to a site A CIDR
- **THEN** the packet follows the equivalent reverse sequence and reaches site A without relying on a pre-existing Envelope return context

### Requirement: Separated route domains
The deployment SHALL create separate workload, Tailscale-ingress, GWLBE, Envelope-target, and management route domains. Workload and Tailscale-ingress domains SHALL route exact inter-site prefixes to their local GWLBE, while an Envelope-target domain SHALL directly deliver local-site prefixes and send remote-site prefixes through Tailscale. No Envelope-target route domain may send a site CIDR to a GWLBE.

#### Scenario: Post-inspection local delivery
- **WHEN** an Envelope target decapsulates a packet for its local-site CIDR
- **THEN** the effective host and VPC path delivers it to the workload without another GWLBE traversal

#### Scenario: Route-domain loop
- **WHEN** any target route table or host route can send a local-site or remote-site packet back to a GWLBE
- **THEN** plan validation and target readiness fail before the target is registered healthy

### Requirement: Bounded high availability behavior
Each enabled site AZ SHALL have a local GWLBE and at least one healthy Envelope target, and each site SHALL have at least two healthy Tailscale ingress routers advertising exactly the same local-site prefixes without subnet-route SNAT. The system SHALL prove alternate-path new-flow recovery after target, process, and ingress-router loss, and SHALL record established-flow recovery and packet loss as evidence without promising hitless continuity.

#### Scenario: Target failure
- **WHEN** the selected Envelope target becomes unhealthy during protected acceptance
- **THEN** a new inter-site flow succeeds through a remaining healthy target and evidence identifies the failed and succeeding targets, recovery duration, and packet-loss result

#### Scenario: Ingress-router failure
- **WHEN** one Tailscale ingress router becomes unavailable during protected acceptance
- **THEN** a new remote-to-local flow succeeds through another router advertising the exact same local-site prefix and evidence identifies the recovery duration

#### Scenario: Established transport interruption
- **WHEN** a target, process, or ingress router fails during an established TCP or UDP flow
- **THEN** acceptance records whether TCP resumed and the observed UDP loss, and does not report a hitless-continuity guarantee
