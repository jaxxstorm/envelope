## MODIFIED Requirements

### Requirement: Secret-contained Tailscale bootstrap
The deployment SHALL retrieve a runner-generated, short-lived, reusable, preauthorized Tailscale bootstrap credential from a run-scoped encrypted secret only on transport-router instances. It MUST NOT place the credential in Terraform variables, plans, state, outputs, rendered user data, or any Envelope target. Envelope targets SHALL have no Tailscale bootstrap dependency.

#### Scenario: Authorized transport-router bootstrap
- **WHEN** a transport router boots with permission to the configured secret
- **THEN** it authenticates with the requested transport tag without logging the credential

#### Scenario: Target configuration rendered
- **WHEN** an Envelope target's launch template and service are rendered
- **THEN** neither contains a Tailscale credential reference, route advertisement, or backend dependency

### Requirement: Tailnet administrative lifecycle
The protected runner SHALL use a separate narrowly scoped Tailscale OAuth/API credential outside Terraform to create and revoke the run-scoped bootstrap key and remove every run-owned transport-router node. Required exact local-site route approvals and grants SHALL be preconfigured through Tailnet policy before AWS creation. Additional canonical approvals and grants MAY remain when they are disjoint from the active protected prefixes.

#### Scenario: Non-interactive credential creation
- **WHEN** an approved run starts after Tailnet policy preflight
- **THEN** the runner creates one bounded reusable key for the transport-router fleet, stores it in the encrypted run secret, and records only identifiers in the cleanup manifest

#### Scenario: Tailnet cleanup
- **WHEN** a run succeeds or fails after transport routers authenticate
- **THEN** the runner removes every run-owned node, revokes the generated key, and deletes the run-scoped secret

#### Scenario: Tailnet policy not preconfigured
- **WHEN** tag ownership, exact route auto-approval, or required grants are missing
- **THEN** preflight fails before AWS resources are created

#### Scenario: Unrelated Tailnet policy entries coexist
- **WHEN** the policy includes every required exact approval and grant plus additional canonical entries disjoint from the active protected prefixes
- **THEN** preflight accepts the required policy without requiring removal of the unrelated entries

### Requirement: Boot-persistent Envelope service
The deployment SHALL install an idempotent systemd service on each target that starts Envelope after underlay networking, restarts it on failure, and grants only capabilities required to receive and emit AWS-compliant GENEVE packets. It SHALL NOT create a TUN, wait for Tailscale, enable host forwarding, or render inner-routing fields.

#### Scenario: First boot convergence
- **WHEN** cloud-init and underlay networking complete successfully
- **THEN** `envelope.service` becomes active with the reviewed version-2 packet-turnaround configuration

#### Scenario: Service failure or reboot
- **WHEN** Envelope exits unexpectedly or its target reboots
- **THEN** systemd restores packet-turnaround readiness without restoring cross-packet state or waiting for Tailscale

### Requirement: Persistent host forwarding prerequisites
The deployment SHALL persist forwarding, reverse-path, no-NAT firewall, and TCP MSS prerequisites on each transport router, not on Envelope targets. The contract SHALL cover underlay-to-Tailscale and Tailscale-to-underlay directions, disable EC2 source/destination checks, and restore before a router is eligible for GWLBE route selection.

#### Scenario: Required transport state after boot
- **WHEN** transport-router cloud-init and network preflight complete
- **THEN** effective sysctls, both forwarding directions, no-NAT state, MSS policy, Tailscale routes, and the local-site VPC route through GWLBE satisfy readiness

#### Scenario: Target host remains outside transit
- **WHEN** an Envelope target boots
- **THEN** no transport forwarding or Tailscale prerequisite is required and no inner site route is installed for the target

#### Scenario: Transport prerequisite missing
- **WHEN** a required router sysctl, route, source/destination check, firewall, no-NAT, or MSS assertion is invalid
- **THEN** the router is ineligible for GWLBE route selection and acceptance remains unready

## ADDED Requirements

### Requirement: Multi-AZ symmetric site deployment
The protected deployment SHALL keep topology and runtime configuration version 2 and create at least two enabled AZs per site, a GWLBE in every enabled workload and transport-router AZ, and at least one Envelope target in every enabled target AZ. Each workload route table SHALL send exact remote-site CIDRs to its same-AZ GWLBE; each transport-router route table SHALL send exact local-site CIDRs to its same-AZ GWLBE; and each GWLBE route table SHALL send local-site traffic through VPC local delivery and remote-site traffic to the ENI of the deterministic initial owner of that GWLBE AZ's workload prefix. Target subnets SHALL carry no inner site route.

#### Scenario: Both sites have symmetric paths
- **WHEN** Terraform plans a valid two-site configuration
- **THEN** each site contains the required workload, transport-router, endpoint, target, and management route domains and every declared site CIDR has an exact pre- and post-inspection path

#### Scenario: Missing AZ target
- **WHEN** an enabled site AZ has a GWLBE but no healthy-capable Envelope target path
- **THEN** Terraform validation rejects the plan before apply

#### Scenario: Obsolete draft-v2 field
- **WHEN** a version-2 configuration contains target TUN, target Tailscale, target local/remote forwarding, or ingress-only router semantics
- **THEN** preflight rejects it without translation, compatibility resources, or a version change

### Requirement: Redundant Tailscale transport routers
The deployment SHALL create at least two independent Tailscale transport routers per site, spread across enabled AZs. Each router's baseline enabled advertisement SHALL be its non-empty singleton assigned workload prefix; those assignments SHALL be pairwise disjoint and their exact union SHALL equal all local-site CIDRs. Every router SHALL accept all exact remote-site routes, remain capable of forwarding every site prefix during failover, disable subnet-route SNAT, preserve workload source addresses, and forward in both site-transit directions. Readiness SHALL require table 52 to contain exactly the opposite site's exact workload routes, bind each route to its configured stable owner on every opposite-site observer, and reject every same-site protected local `PrimaryRoutes` claim or table-52 route. Every local prefix, whether its singleton advertiser is self or sibling, SHALL remain on the main/VPC underlay, and the higher-priority `iif tailscale0` rules SHALL make every router capable of delivering all local prefixes during normal and takeover paths. The deployment SHALL expose each router's primary ENI and advertised prefix; source-prefix owner/ENI coupling SHALL be derived from singleton advertisements, control-plane stable identities, and opposite-site observations. Envelope targets SHALL not join Tailscale or act as route advertisers.

#### Scenario: Redundant local-site advertisements
- **WHEN** a site is deployed successfully
- **THEN** at least two ready transport routers collectively advertise every exact local-site prefix once without NAT, accept every remote-site prefix through a remote-only table 52, remain capable of takeover, and expose distinct eligible ENIs

#### Scenario: ha25 live route graph is reconciled
- **WHEN** the failed protected run `ha25` route and serving-path evidence is evaluated
- **THEN** the two-prefix profile requires exactly the two opposite-site workload routes in each router's table 52, only opposite-site serving paths, and no same-site protected local `PrimaryRoutes` claim or Tailnet route

#### Scenario: Local prefix uses the underlay
- **WHEN** a packet received on `tailscale0` targets any local prefix, whether its singleton advertiser is the receiving router or its sibling
- **THEN** the higher-priority local rule selects `main` and the VPC underlay to the same-AZ GWLBE without a local table-52 route

#### Scenario: Incomplete router contract
- **WHEN** one transport router advertises a broader, narrower, or missing local-site prefix, lacks a remote route, enables SNAT, or cannot forward one direction
- **THEN** protected preflight fails before resources are created

- **WHEN** a configured local-site prefix contains the VPC DNS resolver address and would therefore have an unavoidable narrower main-table route
- **THEN** protected configuration validation fails before AWS resources are created

### Requirement: Packet-turnaround target readiness and drain
The deployment SHALL register an Envelope target healthy only after its AWS GENEVE receiver, validation, and packet-scoped compliant-return sender are ready. TUN, target host forwarding, site routes, and Tailscale SHALL not be target prerequisites. A planned target stop or replacement SHALL mark it unready, wait for documented deregistration and drain evidence, and retain redacted diagnostics.

#### Scenario: Premature target registration
- **WHEN** packet receive, validation, or compliant-return readiness is unhealthy
- **THEN** its GWLB target health remains unhealthy and the protected workflow stops before live traffic

#### Scenario: Planned target replacement
- **WHEN** the protected workflow replaces a healthy target
- **THEN** it records the unready transition, AWS target drain evidence, replacement readiness, and the succeeding target identity

### Requirement: Protected ENI route failover lifecycle
The protected runner SHALL be the only component authorized to coordinate temporary transport-prefix advertisement transfer and GWLBE remote-route replacement between eligible same-site routers during acceptance. Version 2 SHALL accept exactly explicit per-GWLBE-AZ initial selections plus mutation, restoration, and recovery bounds. The runner SHALL verify run ownership, exact source-prefix owner, stable Tailnet identities and opposite-site observer graph, absence of same-site local Tailnet ownership, advertisement sets, route-table and prefix allowlists, current and alternate readiness, and cleanup authority; persist both control planes' prior state and an expiring owner lease through the CAS-protected durable manifest before mutation; use bounded mutation, ambiguous-result settlement, and convergence waits; record before and after state; and restore advertisements and every original route target with independent deadlines on every exit path. A terminal E2E claim SHALL be prohibited while either control plane remains active in the transaction. Targets and transport routers SHALL not receive EC2 route-mutation permission.

#### Scenario: Authorized alternate route
- **WHEN** a selected transport router is failed during an approved exercise
- **THEN** the runner transfers only the failed owner's exact prefix to a ready alternate, proves the expected opposite-site stable-node ownership graph and continued absence of local Tailnet routes, replaces only the affected run-owned remote-site routes with the alternate ENI, and proves a new flow within the configured bound

#### Scenario: Ambiguous or out-of-scope route
- **WHEN** a route table, prefix, current target, alternate ENI, or ownership tag differs from the durable run manifest
- **THEN** mutation fails closed and diagnostics contain no credentials

#### Scenario: Bounded restoration
- **WHEN** the exercise completes, fails, times out, or is interrupted after mutation
- **THEN** owned cleanup restores and verifies each router's baseline advertisements and each prior route target within independent deadlines and residual auditing reports any failure

#### Scenario: Runner lost after mutation
- **WHEN** the route-transaction owner disappears and its durable lease expires
- **THEN** a successor that proves the same CAS claim restores the original advertisements and routes before any new exercise or terminal cleanup handoff

### Requirement: Symmetric HA acceptance evidence
The protected acceptance SHALL prove new bidirectional TCP, UDP, and ICMP flows without directional CIDR partitioning; prove packet-scoped target return with identical inner bytes, VNI, ordered options and cookie, and AWS tuple using bounded independent AF_PACKET ingress/return captures; prove both site GWLBE/GWLB traversals; and execute target-process, target-instance, transport-router, and protected ENI-route failover exercises. Raw captures, payloads, and cookie values SHALL be deleted after inspection; evidence SHALL retain only redacted decoded identities and hashes. Evidence SHALL record endpoint, target, router, ENI and route identities, health and route transitions, recovery duration, established TCP outcome, UDP loss, restoration, and post-cleanup residual audit.

#### Scenario: Bidirectional cold flows
- **WHEN** both site workloads initiate cold TCP, UDP, and ICMP flows concurrently
- **THEN** each flow succeeds without CIDR-role partitioning and evidence proves both site target turnarounds and GWLBE/GWLB traversals

#### Scenario: Alternate target recovery
- **WHEN** a selected target process or instance is made unavailable
- **THEN** a new flow succeeds through another healthy target and evidence records bounded recovery rather than a hitless guarantee

#### Scenario: Alternate transport-router recovery
- **WHEN** a selected Tailscale transport router is made unavailable
- **THEN** new flows recover after the applicable Tailnet selection or runner-owned GWLBE ENI route replacement and evidence identifies both the router and control-plane transition

## REMOVED Requirements

### Requirement: Site-specific runtime configuration
**Reason**: Targets no longer need directional or local/remote inner-route configuration; version 2 defines packet turnaround and keeps site CIDRs in topology and transport route domains.
**Migration**: Revise version 2 in place with target packet-turnaround settings, enabled AZs, target and transport-router fleets, ENI route selections, and HA thresholds; do not translate obsolete fields.

### Requirement: Single regional flow owner
**Reason**: Every ingress packet carries all metadata needed for its own immediate return, so no later packet must find a regional flow owner.
**Migration**: Use the enabled-AZ target fleet and packet-scoped turnaround; do not add shared flow state or target return affinity.

### Requirement: Tailscale control-plane readiness
**Reason**: Envelope targets have no Tailscale responsibility; dedicated transport routers own the Tailnet control plane and both transit directions.
**Migration**: Targets have no Tailscale responsibility; validate redundant transport-router advertisements, accepted routes, no-NAT forwarding, ENIs, and local GWLBE route readiness.

### Requirement: GWLB target bootstrap readiness
**Reason**: A target must prove packet-scoped receive and compliant return plus coordinated drain, not TUN and site-forwarding prerequisites for a single regional owner.
**Migration**: Use packet-turnaround target readiness and drain evidence for every enabled target.
