## MODIFIED Requirements

### Requirement: Symmetric inter-site GWLB traversal
After the target phase has registered healthy Envelope targets, the system SHALL route every packet between configured disjoint site CIDRs through both sites' GWLBE and GWLB paths without NAT. At each site an Envelope target SHALL return the current packet to GWLB before that site's GWLBE route table selects local delivery or a same-site transport-router ENI. No target or transport router may bypass the required local GWLB traversal. Before the target phase, the same GWLBE and GWLB paths SHALL exist with no registered Envelope target, and traffic selected into those paths SHALL fail rather than bypass inspection.

#### Scenario: Infrastructure phase has no inspection bypass
- **WHEN** the reviewed infrastructure phase has created a workload or transport-router route through a GWLBE
- **THEN** the GWLB target group has no Envelope registration and selected data-plane traffic fails without a direct workload-to-workload or router-to-workload bypass

#### Scenario: Local workload initiates after target activation
- **WHEN** a workload in site A sends a packet to a site B CIDR after healthy targets are registered
- **THEN** the packet traverses site A's GWLBE, site A's GWLB, a packet turnaround at a site A target, the site A GWLBE route table, a site A transport-router ENI, Tailscale, a site B transport router, site B's GWLBE, site B's GWLB, a packet turnaround at a site B target, and the site B GWLBE local-delivery path

#### Scenario: Remote workload initiates after target activation
- **WHEN** a workload in site B sends a new packet to a site A CIDR after healthy targets are registered
- **THEN** the packet follows the equivalent reverse sequence and reaches site A without CIDR-role partitioning or any target state learned from an earlier packet

### Requirement: GWLBE-owned post-inspection route domains
The deployment SHALL create separate workload, transport-router, GWLBE, Envelope-target, and management route domains. Workload route tables SHALL send exact remote-site CIDRs to the same-AZ GWLBE. Every transport-router route table SHALL send each exact local-site CIDR to the GWLBE in that destination workload prefix's AZ, independent of the router AZ. Each GWLBE subnet route table SHALL use VPC local delivery for local-site CIDRs and the active ENI of that GWLBE AZ's source-prefix owner for every exact remote-site CIDR. Target route tables SHALL carry only outer GWLB and management traffic and SHALL NOT route inner site traffic. The infrastructure phase SHALL create these routes and GWLBE endpoints before target deployment, without adding an alternate inner-traffic path.

#### Scenario: Infrastructure route domains are complete but unserved
- **WHEN** the infrastructure phase is planned
- **THEN** every configured workload and transport route selects its required same-AZ or destination-prefix-AZ GWLBE and every GWLBE route has its reviewed local or controller-owned remote route, while no target route table carries an inner site route and no target is registered

#### Scenario: Post-inspection local delivery
- **WHEN** GWLB returns an inspected packet for a local-site CIDR after target activation
- **THEN** the GWLBE subnet route table selects VPC local delivery and the packet reaches the workload without target host forwarding

#### Scenario: Post-inspection remote transit
- **WHEN** GWLB returns an inspected packet for a remote-site CIDR after target activation
- **THEN** the GWLBE subnet route table selects the ready same-site transport-router ENI whose Tailnet advertisement owns the source workload prefix associated with that GWLBE

#### Scenario: Route-domain bypass or loop
- **WHEN** a workload packet can bypass its source-AZ GWLBE, a Tailnet-arriving local packet can bypass its destination-prefix-AZ GWLBE, a target can directly forward an inner packet, or a GWLBE-returned local packet can re-enter the endpoint
- **THEN** plan validation and protected readiness fail before acceptance traffic
