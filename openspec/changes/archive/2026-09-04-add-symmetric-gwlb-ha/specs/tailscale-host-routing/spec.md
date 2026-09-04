## ADDED Requirements

### Requirement: Separated target and transport-router roles
Envelope targets SHALL NOT run or require `tailscaled`, own `envelope0`, advertise site routes, or forward an inner packet to a VPC or Tailscale interface. Dedicated Tailscale transport routers SHALL own all inner site transit. Version-2 configuration SHALL reject legacy directional fields and obsolete draft-v2 target `local-site-cidrs`, `remote-site-cidrs`, TUN, and host-routing fields before mutation.

#### Scenario: Target receives either site destination
- **WHEN** a target receives a valid GWLB packet for a local-site or remote-site CIDR
- **THEN** it returns that packet to GWLB without consulting host routes or a Tailscale backend

#### Scenario: Obsolete target routing configuration
- **WHEN** a version-2 target configuration supplies a directional-lane field or a draft-v2 direct-inner-forwarding field
- **THEN** configuration fails before TUN, route, Tailscale, or forwarding state is inspected or mutated

### Requirement: Bidirectional no-NAT transport-router readiness
The deployment SHALL validate every Tailscale transport router separately from Envelope targets. A ready router SHALL have a healthy Running kernel-TUN backend, enable only its singleton assigned exact local-site CIDR advertisement in normal operation, accept every exact remote-site route, remain capable of advertising every exact local-site CIDR during bounded failover, disable subnet-route SNAT and Tailnet DNS acceptance, preserve the VPC resolver and workload source addresses, enable underlay-to-Tailscale and Tailscale-to-underlay forwarding, and prove that its subnet route table sends each local-site CIDR to that destination workload prefix's AZ GWLBE independent of the router AZ. The fleet's normal enabled advertisement sets SHALL be non-empty and pairwise disjoint and their union SHALL equal all exact local-site CIDRs. Table 52 and Tailnet serving paths SHALL contain only opposite-site workload prefixes; all local prefixes SHALL remain on the main/VPC underlay with no same-site protected `PrimaryRoutes` claim. A router ENI SHALL be eligible for a GWLBE's remote routes only while that router owns the GWLBE AZ's workload source prefix.

#### Scenario: Ready transport router
- **WHEN** the backend, exact advertisements and accepted routes, source preservation, forwarding, firewall, MSS, ENI identity, and destination-prefix GWLBE routes all pass
- **THEN** the router is ready for both post-inspection remote egress and Tailnet-arriving local ingress

#### Scenario: Either transit direction is invalid
- **WHEN** a required sysctl, reverse-path setting, source/destination check, no-NAT assertion, firewall path, MSS rule, host route, or VPC route is invalid
- **THEN** transport-router readiness fails before acceptance traffic or ENI-route selection

#### Scenario: Tailnet packet could bypass inspection
- **WHEN** a transport-router subnet can directly deliver a local-site CIDR or selects the receiving router's endpoint instead of the destination prefix's GWLBE
- **THEN** readiness is unhealthy and identifies the affected prefix

### Requirement: Secretless separated-role acceptance
The system SHALL provide a required local integration with immutable Headscale and Tailscale versions, runtime-generated credentials, dedicated transport-router namespaces, fake GWLBE/GWLB paths, and stateless packet-turnaround targets. It SHALL prove both transit directions, source preservation, and two site inspection loops without external Tailscale credentials.

#### Scenario: Simultaneous cold initiation
- **WHEN** both site workloads initiate cold traffic through the separated-role harness
- **THEN** both flows cross their source and destination packet-turnaround targets and no target directly forwards an inner packet

#### Scenario: No-NAT transport
- **WHEN** a packet crosses either transport router direction
- **THEN** the destination observes the original workload source and the harness detects no SNAT or masquerade rule

## MODIFIED Requirements

### Requirement: Effective forward route to Tailscale
Transport-router readiness SHALL prove the complete configured prefixes rather than only boundary addresses. For every remote-site destination received from a selected GWLBE ENI, effective host routing SHALL select `tailscale0` and the configured stable owner of that exact prefix. In normal operation, table 52 SHALL contain exactly one exact `tailscale0` route for each opposite-site workload prefix and no local-site prefix route. For every local-site destination received from `tailscale0`, whether its singleton advertiser is self or sibling, the higher-priority `iif tailscale0` local-prefix policy rule SHALL select `main` and the VPC underlay, and the associated VPC route table SHALL select the destination workload prefix's AZ GWLBE. More-specific, source-specific, policy, blackhole, unreachable, prohibit, duplicate, swapped-owner, wrong-device, wrong-endpoint, or local table-52 routes that bypass either result SHALL fail readiness.

#### Scenario: Effective remote route
- **WHEN** a post-inspection remote-site packet is delivered to a transport-router ENI
- **THEN** every address in the destination prefix selects `tailscale0` through an accepted exact route

#### Scenario: Effective local inspection route
- **WHEN** a Tailnet packet for a local-site CIDR is forwarded to the underlay
- **THEN** every address in the destination prefix selects that workload prefix's AZ GWLBE before local delivery, independent of the receiving router AZ

#### Scenario: ha25 remote-only table 52
- **WHEN** the failed protected run `ha25` route and serving-path evidence is evaluated
- **THEN** each router in its two-prefix-per-site profile has exactly the two opposite-site workload routes in table 52, forms only opposite-site serving paths, and has no protected local `PrimaryRoutes` claim or Tailnet route

#### Scenario: Local Tailnet route is present
- **WHEN** any self- or sibling-owned local prefix has a same-site `PrimaryRoutes` claim or table-52 route
- **THEN** readiness fails even when the higher-priority `iif tailscale0` rule would select `main`

#### Scenario: Interior route shadowing
- **WHEN** a more-specific or source-specific route can bypass Tailscale or the destination-prefix GWLBE for any interior subset
- **THEN** full-prefix readiness fails even if boundary lookups succeed

### Requirement: Linux forwarding prerequisites
Transport-router readiness SHALL require persistent IPv4 forwarding, required IPv6 forwarding when enabled, disabled reverse-path filtering for `conf/all`, the underlay, and `tailscale0`, disabled EC2 source/destination checks, a deterministic underlay-to-Tailscale and Tailscale-to-underlay firewall contract, no NAT rewrite, and TCP MSS policy derived from the live Tailscale path MTU. No forwarding rule SHALL reference `envelope0`.

#### Scenario: Bidirectional forwarding ready
- **WHEN** both interface directions have the exact reviewed forwarding and MSS rules and no NAT rule exists
- **THEN** host forwarding readiness succeeds with source preservation

#### Scenario: Unsupported forwarding state
- **WHEN** strict reverse-path filtering, a blocking or extra forwarding rule, NAT, missing MSS policy, enabled source/destination checking, or an `envelope0` forwarding rule is present
- **THEN** readiness fails closed with a bounded reason

### Requirement: Tailscale backend and route readiness
Each transport router SHALL use the pinned supported Tailscale status and preferences schemas in kernel-TUN mode, report a healthy Running backend and online non-expired self node, report `CorpDNS` false with no Tailscale health condition, advertise its approved assigned exact local-site prefix with subnet-route SNAT disabled, and pass a bounded data-plane ping to every selected serving peer. Every opposite-site observer SHALL select exactly one online non-expired `PrimaryRoutes` owner matching the configured stable node for each exact remote-site prefix, and table 52 SHALL contain those exact remote-site routes only. Every protected local-site prefix SHALL have no same-site `PrimaryRoutes` claim and no table-52 route, whether its singleton advertiser is self or sibling. Ownership SHALL use stable node identity rather than hostname alone. At least two routers per site SHALL independently satisfy readiness, and their assigned advertisements SHALL exactly partition the site prefixes.

#### Scenario: Redundant ready advertisements
- **WHEN** a site is ready
- **THEN** at least two transport routers collectively advertise every exact local-site prefix exactly once without SNAT, accept every exact remote-site route, and remain capable of bounded takeover

#### Scenario: Backend, route, or peer unavailable
- **WHEN** a backend is not Running, Tailnet DNS acceptance is enabled, any Tailscale health condition is present, a local advertisement is unapproved, a remote route is absent, a local Tailnet route or `PrimaryRoutes` claim is present, a serving peer is stale, or a bounded ping fails
- **THEN** that router is ineligible for GWLBE ENI selection and readiness identifies the condition

### Requirement: Routing observability
The deployment SHALL expose bounded transport-router readiness for backend, singleton assigned advertisements, opposite-site per-prefix `PrimaryRoutes` ownership, remote-only table 52, absence of local Tailnet routes and claims, forwarding, source preservation, MSS, effective host routes, associated GWLBE routes, and ENI identity. Evidence SHALL map configured and selected owners to protected transport-router instance IDs, derive the source-prefix owner from singleton advertisements, control-plane stable identities, and opposite-site observations, prove that owner agrees with protected-runner GWLBE ENI selection, record coordinated takeover and restoration separately for both control planes, and SHALL not expose credentials, peer keys, or flow cookies.

#### Scenario: Redacted transport status
- **WHEN** protected readiness or diagnostics are collected
- **THEN** site, router and ENI identifiers, exact prefixes, selected interfaces, route targets, and bounded reasons are reported without secrets

### Requirement: Routing performance regression gate
The system SHALL define a reviewed benchmark profile for transport-router readiness and the bidirectional no-NAT packet path, with allocation and latency thresholds before implementation performance is accepted.

#### Scenario: Benchmark within threshold
- **WHEN** transport-router readiness and bidirectional no-NAT datapath benchmarks run on the documented Linux profile
- **THEN** measured allocations and latency remain within the pre-approved thresholds recorded with the change evidence

#### Scenario: Benchmark regression
- **WHEN** a benchmark exceeds a pre-approved threshold
- **THEN** the change remains incomplete until the regression is fixed or the threshold change is reviewed before rerun

## REMOVED Requirements

### Requirement: Envelope and tailscaled co-residency
**Reason**: Version-2 Envelope targets are packet-turnaround appliances and dedicated transport routers own Tailscale; the roles are not co-resident.
**Migration**: Deploy revised version 2 from fresh state with separate target and transport-router fleets and no compatibility TUN.

### Requirement: Explicit directional CIDR roles
**Reason**: Separate initiator/responder CIDRs prevent arbitrary bidirectional site-to-site initiation.
**Migration**: Keep disjoint site CIDRs in topology version 2 and configure them on transport and VPC route domains, not as target forwarding roles.

### Requirement: Managed GWLB-return routing
**Reason**: Tailnet-originated packets enter GWLB through a transport-router subnet route, and targets have no TUN or host-route manager.
**Migration**: Remove managed `iif tailscale0` to `envelope0` state and use the revised version-2 transport-router and GWLBE route domains.

### Requirement: Routing modes are explicit
**Reason**: Packet-turnaround targets no longer verify or manage host transit routing.
**Migration**: Remove target routing mode from version 2; transport-router bootstrap and protected readiness own the fixed transit contract.

### Requirement: Ownership-safe transactional management
**Reason**: Envelope no longer mutates Linux policy routes. Coordinated Tailscale advertisement transfer and AWS ENI route replacement are separately bounded and owned by the protected runner.
**Migration**: Remove the target route-manager table, priority, protocol, and lock fields without a compatibility path; use the protected runner's CAS transaction for transport failover.

### Requirement: Secretless co-resident acceptance
**Reason**: Target and Tailscale roles are intentionally separated.
**Migration**: Use the secretless separated-role acceptance requirement with fake two-site GWLBE/GWLB turnaround paths.
