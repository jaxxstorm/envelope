## ADDED Requirements

### Requirement: Symmetric inter-site GWLB traversal
The system SHALL route every packet between configured disjoint site CIDRs through both sites' GWLBE and GWLB paths without NAT. At each site an Envelope target SHALL return the current packet to GWLB before that site's GWLBE route table selects local delivery or a same-site transport-router ENI. No target or transport router may bypass the required local GWLB traversal.

#### Scenario: Local workload initiates
- **WHEN** a workload in site A sends a packet to a site B CIDR
- **THEN** the packet traverses site A's GWLBE, site A's GWLB, a packet turnaround at a site A target, the site A GWLBE route table, a site A transport-router ENI, Tailscale, a site B transport router, site B's GWLBE, site B's GWLB, a packet turnaround at a site B target, and site B's GWLBE local-delivery path

#### Scenario: Remote workload initiates
- **WHEN** a workload in site B sends a new packet to a site A CIDR
- **THEN** the packet follows the equivalent reverse sequence and reaches site A without CIDR-role partitioning or any target state learned from an earlier packet

### Requirement: GWLBE-owned post-inspection route domains
The deployment SHALL create separate workload, transport-router, GWLBE, Envelope-target, and management route domains. Workload route tables SHALL send exact remote-site CIDRs to the same-AZ GWLBE. Transport-router route tables SHALL send exact local-site CIDRs to the same-AZ GWLBE. Each GWLBE subnet route table SHALL use VPC local delivery for local-site CIDRs and the active ENI of that GWLBE AZ's source-prefix owner for every exact remote-site CIDR. Target route tables SHALL carry only outer GWLB and management traffic and SHALL NOT route inner site traffic.

#### Scenario: Post-inspection local delivery
- **WHEN** GWLB returns an inspected packet for a local-site CIDR to its GWLBE
- **THEN** the GWLBE subnet route table selects VPC local delivery and the packet reaches the workload without target host forwarding

#### Scenario: Post-inspection remote transit
- **WHEN** GWLB returns an inspected packet for a remote-site CIDR to its GWLBE
- **THEN** the GWLBE subnet route table selects the ready same-site transport-router ENI whose Tailnet advertisement owns the source workload prefix associated with that GWLBE

#### Scenario: Route-domain bypass or loop
- **WHEN** a workload or Tailnet-arriving local packet can bypass its GWLBE, a target can directly forward an inner packet, or a GWLBE-returned local packet can re-enter the endpoint
- **THEN** plan validation and protected readiness fail before acceptance traffic

### Requirement: Redundant bidirectional site transport
Each site SHALL have at least two AZ-spread Tailscale transport routers whose disjoint initial advertisement sets exactly cover the local-site prefixes. Every router SHALL accept all exact remote-site routes, preserve source addresses with subnet-route SNAT disabled, remain capable of every site prefix during bounded takeover, and forward both underlay-to-Tailscale remote traffic and Tailscale-to-underlay local traffic. On each router, table 52 SHALL contain exactly the opposite site's workload prefixes and no local-site prefix; no same-site observer SHALL report a protected local `PrimaryRoutes` claim. Every local prefix, whether self- or sibling-owned by the singleton advertisement map, SHALL remain on `main` and the VPC underlay, where the higher-priority `iif tailscale0` rules make every router capable of normal and takeover delivery. Envelope targets SHALL NOT run Tailscale or serve as site transit routers.

#### Scenario: Remote-bound inspected packet
- **WHEN** a GWLBE subnet route delivers a remote-site packet to a selected transport-router ENI
- **THEN** that router forwards the unchanged source and destination through its accepted Tailscale route without NAT

#### Scenario: Tailnet-arriving local packet
- **WHEN** a transport router receives a packet from Tailscale for its local-site CIDR
- **THEN** its higher-priority local rule selects `main`, the VPC underlay, and the local GWLBE before workload delivery without a local table-52 route

#### Scenario: ha25 exposes only opposite-site serving paths
- **WHEN** the failed protected run `ha25` route evidence is reconciled for its two-prefix-per-site profile
- **THEN** each router's table 52 contains exactly the two opposite-site workload routes, every serving path is opposite-site, and no protected local prefix has a same-site `PrimaryRoutes` claim or Tailnet route

### Requirement: Protected runner owns bounded ENI route failover
Every GWLBE remote-site route SHALL initially select the explicitly configured run-owned, ready, same-AZ transport-router ENI that owns that GWLBE AZ's workload source prefix, with at least one capable same-site alternate. That source-prefix owner/ENI coupling SHALL be derived from singleton advertisements, control-plane stable identities, and opposite-site observations. Only the protected runner SHALL transfer that exact Tailnet prefix and replace those exact routes during acceptance. It SHALL verify ownership and readiness, persist prior advertisements, route targets, and an expiring owner lease through the CAS-protected run claim, bound both control planes' convergence and recovery, settle ambiguous completion, restore each baseline advertisement and original target on success, failure, interruption, or recovered runner loss, and fail closed on ambiguous ownership. Targets and transport routers SHALL have no AWS route-mutation authority.

#### Scenario: Selected transport router fails
- **WHEN** acceptance makes the transport router selected by a GWLBE remote-site route unavailable
- **THEN** the protected runner transfers the selected router's owned prefix to the alternate, observes every opposite-site observer converge on the alternate stable node while local Tailnet routes remain absent, replaces only the authorized routes with the alternate ENI, and proves a new flow within the configured bound

#### Scenario: Route restoration
- **WHEN** a failover exercise succeeds, fails, or times out after route mutation
- **THEN** the protected runner restores and verifies every baseline advertisement and prior run-owned route target and records both mutations and restoration results

#### Scenario: Durable route recovery
- **WHEN** a protected runner is lost while its durable route transaction is active
- **THEN** no terminal claim is written and a successor may restore the prior routes only after the owner lease and CAS claim are reconciled

### Requirement: Bounded high availability behavior
Each enabled site AZ SHALL have a local GWLBE and a healthy-capable Envelope target path, and each site SHALL have at least two ready transport routers. The system SHALL prove alternate-target new-flow recovery and runner-owned transport ENI route recovery and SHALL record established-flow recovery and packet loss without promising hitless continuity or requiring an original five-tuple to resume. For instance, router, or route failure, a complete observation that continues sending after the mutation MAY record an exact right-censored interruption; the target-process post-restoration marker requirement remains unchanged.

#### Scenario: Target failure
- **WHEN** the selected Envelope target becomes unhealthy during protected acceptance
- **THEN** a new inter-site flow succeeds through a remaining healthy target and evidence identifies the failed and succeeding targets, recovery duration, and packet-loss result

#### Scenario: Transport-router failure
- **WHEN** a selected Tailscale transport router becomes unavailable during protected acceptance
- **THEN** new flows recover through an alternate transport router after the required Tailnet selection or protected ENI route replacement and evidence identifies which control plane changed the path

#### Scenario: Established transport interruption
- **WHEN** a target, process, transport router, or ENI route fails during an established TCP or UDP flow
- **THEN** acceptance records exact attempted, acknowledged, and lost marker counts, whether the observation resumed or ended right-censored, and does not report a hitless-continuity or bounded-interruption claim without a trailing acknowledgement
