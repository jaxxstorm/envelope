## MODIFIED Requirements

### Requirement: Bidirectional no-NAT transport-router readiness
The deployment SHALL validate every Tailscale transport router separately from Envelope targets. A ready router SHALL have a healthy Running kernel-TUN backend, advertise and have enabled the complete exact local-site CIDR set shared by every same-site failover candidate, accept every exact remote-site route, disable subnet-route SNAT and Tailnet DNS acceptance, preserve the VPC resolver and workload source addresses, enable underlay-to-Tailscale and Tailscale-to-underlay forwarding, and prove that its subnet route table sends each local-site CIDR to that destination workload prefix's AZ GWLBE independent of the router AZ. Higher-priority full-prefix local policy rules SHALL prevent any accepted same-site route in table 52 from shadowing `main`. A router ENI SHALL be eligible for a GWLBE's remote routes only while a fresh controller quorum observes that router as the sole primary owner of the GWLBE source workload prefix.

#### Scenario: Ready transport router
- **WHEN** the backend, complete overlapping advertisements, accepted routes, source preservation, forwarding, firewall, MSS, ENI identity, full-prefix local policy, and destination-prefix GWLBE routes all pass
- **THEN** the router is ready for native Tailnet failover, post-inspection remote egress, and Tailnet-arriving local ingress

#### Scenario: Either transit direction is invalid
- **WHEN** a required sysctl, reverse-path setting, source/destination check, no-NAT assertion, firewall path, MSS rule, host route, or VPC route is invalid
- **THEN** transport-router readiness fails before acceptance traffic or controller ENI eligibility

#### Scenario: Tailnet packet could bypass inspection
- **WHEN** a local table-52 route, transport subnet route, or receiving-router endpoint can shadow the higher-priority local-main and destination-prefix GWLBE path
- **THEN** readiness is unhealthy and identifies the affected prefix

### Requirement: Effective forward route to Tailscale
Transport-router readiness SHALL prove complete configured prefixes rather than only boundary addresses. For every remote-site destination received from a selected GWLBE ENI, effective host routing SHALL select `tailscale0` and the control plane's sole primary owner for that exact prefix. For every local-site destination from any interface, a higher-priority full-prefix policy rule SHALL select `main` and the VPC underlay, and the associated VPC route table SHALL select the destination workload prefix's AZ GWLBE. More-specific, source-specific, policy, blackhole, unreachable, prohibit, wrong-device, wrong-endpoint, or local table-52 routes that bypass either effective result SHALL fail readiness.

#### Scenario: Effective remote route
- **WHEN** a post-inspection remote-site packet is delivered to a transport-router ENI
- **THEN** every address in the destination prefix selects `tailscale0` through an accepted exact route

#### Scenario: Effective local inspection route
- **WHEN** any packet on a transport router targets a local-site CIDR
- **THEN** every address in the destination prefix selects `main` and that workload prefix's AZ GWLBE before local delivery, independent of the receiving router AZ

#### Scenario: Accepted local route is shadowed safely
- **WHEN** overlapping native HA causes table 52 to contain a same-site local prefix through another router
- **THEN** the higher-priority full-prefix policy selects `main` for every address in that prefix and readiness rejects any shadowing exception

#### Scenario: Interior route shadowing
- **WHEN** a more-specific or source-specific route can bypass Tailscale or the destination-prefix GWLBE for any interior subset
- **THEN** full-prefix readiness fails even if boundary lookups succeed

### Requirement: Linux forwarding prerequisites
Transport-router readiness SHALL require persistent IPv4 forwarding, required IPv6 forwarding when enabled, disabled reverse-path filtering for `conf/all`, the underlay, and `tailscale0`, disabled EC2 source/destination checks, deterministic underlay-to-Tailscale and Tailscale-to-underlay firewall policy, no NAT rewrite, TCP MSS policy derived from the live Tailscale path MTU, and a higher-priority full-prefix `main` policy for every exact local-site CIDR. No forwarding rule SHALL reference `envelope0`.

#### Scenario: Bidirectional forwarding ready
- **WHEN** both interface directions have the exact reviewed forwarding and MSS rules, every local prefix has the main-table policy, and no NAT rule exists
- **THEN** host forwarding readiness succeeds with source preservation despite overlapping Tailscale advertisements

#### Scenario: Unsupported forwarding state
- **WHEN** strict reverse-path filtering, a blocking or extra forwarding rule, NAT, missing MSS policy, enabled source/destination checking, a missing local-main policy, or an `envelope0` forwarding rule is present
- **THEN** readiness fails closed with a bounded reason

### Requirement: Tailscale backend and route readiness
Each transport router SHALL use the pinned supported Tailscale status and preferences schemas in kernel-TUN mode, report a healthy Running backend and online non-expired self node, report `CorpDNS` false with no Tailscale health condition, advertise and have enabled every exact local-site prefix with subnet-route SNAT disabled, and pass a bounded data-plane ping to every selected serving peer. Every controller observer SHALL select exactly one online non-expired `PrimaryRoutes` owner from the configured router set for each exact prefix. Ownership SHALL use stable node identity rather than hostname alone. At least two routers per site SHALL independently satisfy readiness as equivalent exact-prefix candidates.

#### Scenario: Redundant ready advertisements
- **WHEN** a site is ready
- **THEN** at least two routers each advertise every exact local-site prefix without SNAT and every fresh controller observer agrees on one primary per prefix

#### Scenario: Backend, route, or peer unavailable
- **WHEN** a backend is not Running, Tailnet DNS acceptance is enabled, a Tailscale health condition is present, an expected advertisement is not enabled, a remote route is absent, a serving peer is stale, or ownership has no sole configured primary
- **THEN** that router or failover domain is ineligible and readiness identifies the condition

### Requirement: Routing observability
The deployment SHALL expose bounded transport-router and controller readiness for backend state, complete overlapping advertisements, per-prefix `PrimaryRoutes` ownership from every controller observer, effective local-main policy, forwarding, source preservation, MSS, host routes, associated GWLBE routes, and ENI identity. Evidence SHALL map each observed stable owner to its configured transport-router instance and ENI, prove agreement with the controller-selected GWLBE route target, and record native ownership and AWS route transitions without exposing credentials, peer keys, or flow cookies.

#### Scenario: Redacted transport status
- **WHEN** readiness, controller reconciliation, or diagnostics are collected
- **THEN** site, domain, stable-node hash, router and ENI identifiers, exact prefixes, selected interfaces, route targets, observation quorum, and bounded reasons are reported without secrets
