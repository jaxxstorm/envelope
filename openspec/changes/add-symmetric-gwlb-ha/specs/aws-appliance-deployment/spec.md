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
- **THEN** effective sysctls, both forwarding directions, no-NAT state, MSS policy, Tailscale routes, and every local-site VPC route through its destination workload prefix's GWLBE satisfy readiness

#### Scenario: Target host remains outside transit
- **WHEN** an Envelope target boots
- **THEN** no transport forwarding or Tailscale prerequisite is required and no inner site route is installed for the target

#### Scenario: Transport prerequisite missing
- **WHEN** a required router sysctl, route, source/destination check, firewall, no-NAT, or MSS assertion is invalid
- **THEN** the router is ineligible for GWLBE route selection and acceptance remains unready

## ADDED Requirements

### Requirement: Multi-AZ symmetric site deployment
The protected deployment SHALL keep topology and runtime configuration version 2 and create at least two enabled AZs per site, a GWLBE in every enabled workload and transport-router AZ, and at least one Envelope target in every enabled target AZ. Each workload route table SHALL send exact remote-site CIDRs to its same-AZ GWLBE; every transport-router route table SHALL send each exact local-site CIDR to the GWLBE in that destination workload prefix's AZ, independent of the router AZ; and each GWLBE route table SHALL send local-site traffic through VPC local delivery and remote-site traffic to the ENI of the deterministic initial owner of that GWLBE AZ's workload prefix. Target subnets SHALL carry no inner site route.

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
The deployment SHALL create at least two independent Tailscale transport routers per site, spread across enabled AZs. Each router's baseline enabled advertisement SHALL be its non-empty singleton assigned workload prefix; those assignments SHALL be pairwise disjoint and their exact union SHALL equal all local-site CIDRs. Every router SHALL accept all exact remote-site routes, remain capable of forwarding every site prefix during failover, disable subnet-route SNAT and Tailnet DNS acceptance, preserve the VPC resolver and workload source addresses, and forward in both site-transit directions. Readiness SHALL require table 52 to contain exactly the opposite site's exact workload routes, bind each route to its configured stable owner on every opposite-site observer, reject every same-site protected local `PrimaryRoutes` claim or table-52 route, verify the live `CorpDNS` preference is false, and reject every Tailscale health condition. Every local prefix, whether its singleton advertiser is self or sibling, SHALL remain on the main/VPC underlay, and the higher-priority `iif tailscale0` rules SHALL make every router capable of delivering all local prefixes during normal and takeover paths. The deployment SHALL expose each router's primary ENI and advertised prefix; source-prefix owner/ENI coupling SHALL be derived from singleton advertisements, control-plane stable identities, and opposite-site observations. Envelope targets SHALL not join Tailscale or act as route advertisers.

#### Scenario: Redundant local-site advertisements
- **WHEN** a site is deployed successfully
- **THEN** at least two ready transport routers collectively advertise every exact local-site prefix once without NAT, accept every remote-site prefix through a remote-only table 52, remain capable of takeover, and expose distinct eligible ENIs

#### Scenario: ha25 live route graph is reconciled
- **WHEN** the failed protected run `ha25` route and serving-path evidence is evaluated
- **THEN** the two-prefix profile requires exactly the two opposite-site workload routes in each router's table 52, only opposite-site serving paths, and no same-site protected local `PrimaryRoutes` claim or Tailnet route

#### Scenario: Local prefix uses the underlay
- **WHEN** a packet received on `tailscale0` targets any local prefix, whether its singleton advertiser is the receiving router or its sibling
- **THEN** the higher-priority local rule selects `main` and the VPC underlay to the destination workload prefix's AZ GWLBE without a local table-52 route

#### Scenario: Incomplete router contract
- **WHEN** one transport router advertises a broader, narrower, or missing local-site prefix, lacks a remote route, enables SNAT or Tailnet DNS acceptance, reports a Tailscale health condition, or cannot forward one direction
- **THEN** protected readiness fails before acceptance traffic or GWLBE route eligibility

- **WHEN** a configured local-site prefix contains the VPC DNS resolver address and would therefore have an unavoidable narrower main-table route
- **THEN** protected configuration validation fails before AWS resources are created

### Requirement: Packet-turnaround target readiness and drain
The deployment SHALL register an Envelope target healthy only after its AWS GENEVE receiver, validation, and packet-scoped compliant-return sender are ready. TUN, target host forwarding, site routes, and Tailscale SHALL not be target prerequisites. Both GWLB target groups SHALL use an explicit 10-second health interval, 5-second timeout, healthy threshold 5, and unhealthy threshold 2, and the protected saved-plan validator SHALL reject any different or implicit timing. A planned target stop SHALL prove the service and `/healthz` are unavailable and observe the exact AWS `unhealthy` transition before alternate-flow evidence; an unrelated `unused` state SHALL not satisfy process-failure evidence. A replacement SHALL wait for documented deregistration and drain evidence. Both workflows SHALL retain redacted diagnostics.

#### Scenario: Premature target registration
- **WHEN** packet receive, validation, or compliant-return readiness is unhealthy
- **THEN** its GWLB target health remains unhealthy and the protected workflow stops before live traffic

#### Scenario: Planned target replacement
- **WHEN** the protected workflow replaces a healthy target
- **THEN** it records the unready transition, AWS target drain evidence, replacement readiness, and the succeeding target identity

### Requirement: Protected ENI route failover lifecycle
The active failover reservation SHALL include worst-case durable restoration checkpoints and stream headroom. The cleanup reservation SHALL separately include successor preflight, every bounded CAS checkpoint and finalization, backend finalization, receipt promotion, lock release, output, and the complete 900-second resource cleanup under the same outer alarm; the active and cleanup reservations SHALL fit the complete protected lifecycle envelope. The initial route journal SHALL have an exact envelope and stable host/boot owner, every update SHALL preserve immutable authority and monotonic progress, a fresh restoration attempt SHALL require a separately persisted recovery claim, and finalization SHALL match the exact retained terminal status and timestamp.

The protected runner SHALL be the only component authorized to coordinate temporary transport-prefix advertisement transfer and GWLBE remote-route replacement between eligible same-site routers during acceptance. Version 2 SHALL accept exactly explicit per-GWLBE-AZ initial selections plus mutation, restoration, and recovery bounds. Before acquiring resource authority, run-all SHALL derive both failover transaction reservations and worst-case restoration from those inputs and reject configurations that exceed the active-run, per-stream, or cleanup bounds. The runner SHALL verify run ownership, exact source-prefix owner, stable Tailnet identities and opposite-site observer graph, absence of same-site local Tailnet ownership, advertisement sets, route-table and prefix allowlists, current and alternate readiness, and cleanup authority; persist stable node hashes in a separate pre-transaction CAS; persist both control planes' prior state and an expiring owner lease through the CAS-protected durable manifest before mutation; use bounded mutation, ambiguous-result settlement, and convergence waits; record before and after state; and restore advertisements and every original route target with independent deadlines on every exit path. A terminal E2E claim SHALL be prohibited while either control plane remains active in the transaction. After normal run expiry, a recovery-only invocation MAY accept that expiry only when the exact retained deployment contains an abandoned active route transaction or its verified cleanup-pending handoff. It SHALL validate the output hash and every immutable topology, VPC, route-table, prefix, router, ENI, stable-node, snapshot, progress, and generation binding before CAS adoption; SHALL NOT replay acceptance; SHALL prevent marker takeover while another fresh cleanup claim exists; SHALL retain cleanup authority across terminal and incomplete-cleanup phases; and SHALL retain success only after verified restoration, an exact integer-zero final residual audit, durable private receipt persistence, and backend finalization. Targets and transport routers SHALL not receive EC2 route-mutation permission.

#### Scenario: Authorized alternate route
- **WHEN** a selected transport router is failed during an approved exercise
- **THEN** the runner transfers only the failed owner's exact prefix to a ready alternate, proves the expected opposite-site stable-node ownership graph and continued absence of local Tailnet routes, and replaces only the affected run-owned remote-site routes with the alternate ENI within `mutation_timeout_seconds`, then proves the sequential TCP and UDP new flows within one joint `recovery_timeout_seconds` bound

#### Scenario: Ambiguous or out-of-scope route
- **WHEN** a route table, prefix, current target, alternate ENI, or ownership tag differs from the durable run manifest
- **THEN** mutation fails closed and diagnostics contain no credentials

#### Scenario: Bounded restoration
- **WHEN** the exercise completes, fails, times out, or is interrupted after mutation
- **THEN** owned cleanup restores and verifies each router's baseline advertisements with Tailnet DNS acceptance disabled and each prior route target within independent deadlines and residual auditing reports any failure

#### Scenario: Runner lost after mutation
- **WHEN** the route-transaction owner disappears and its durable lease expires
- **THEN** a successor that proves the same CAS claim restores the original advertisements and routes before any new exercise or terminal cleanup handoff

#### Scenario: Recovery after run expiry
- **WHEN** normal acceptance TTL has expired and the durable manifest retains an abandoned route transaction or its cleanup-pending handoff
- **THEN** a recovery-only successor validates every immutable retained binding before CAS adoption, performs no acceptance replay, and persists completion only after verified restoration, an exact integer-zero final residual audit, and backend finalization

#### Scenario: Recovery interrupted after restoration
- **WHEN** a recovery-only successor exits after transaction finalization, failed-result handoff, cleanup, backend deletion, or pending-receipt persistence
- **THEN** a later invocation resumes from the leased cleanup marker or private pending receipt, performs no acceptance replay, and cannot report success before exact backend finalization

### Requirement: Symmetric HA acceptance evidence
Target-instance and transport-router TCP/UDP streams SHALL run concurrently around one shared mutation interval and retain the complete admitted transaction reservation plus bounded paired-control headroom as their command watchdog. The mutation callback SHALL execute on the protected main thread so active timeout or termination control flow can transition directly to cleanup. Every receiver SHALL start before its client, retain a bounded initial wait, and begin its full bounded observation duration exactly once when it accepts the first valid marker so dispatch startup cannot consume the client's final acknowledgement window. Both client stops SHALL be requested after the mutation-end clock sample and before either client result is awaited; each client SHALL complete at least 20 successful sends and a final post-mutation send, and both client results SHALL complete before either receiver stop is requested. Analysis SHALL validate every successful-send completion timestamp and acknowledged marker without post-hoc truncation, while schema evidence SHALL retain exact sent, acknowledged, and lost counts rather than raw timestamp arrays. Each bounded contiguous resumed loss episode SHALL have its first missing successful send complete during the mutation; later missing sends in that same episode MAY cross the mutation endpoint before its trailing acknowledgement, but every separately starting out-of-interval episode SHALL invalidate the observation. A right-censored result SHALL likewise require the first unacknowledged successful send to complete during the mutation; an isolated unacknowledged post-mutation final send, local send error, short UDP marker write, or short UDP acknowledgement write SHALL invalidate the observation. Ambiguous SSM dispatch ownership or unconfirmed termination SHALL suppress managed-responder restoration. Target-process streams SHALL retain their fixed post-restoration observation behavior. Before resource authority, admission SHALL require both sequential route-transaction reservations and the symmetric non-route acceptance reservations, including fixed target-process durations and the paired target-instance watchdog, to fit the active-run deadline. Earlier run-all provisioning and readiness SHALL remain bounded by that outer active deadline without an unsupported static liveness claim.

The protected acceptance SHALL install and checksum-verify the bounded wire inspector on every packet-return target before traffic; prove new bidirectional TCP, UDP, and ICMP flows without directional CIDR partitioning; prove packet-scoped target return with identical inner bytes, VNI, ordered options and cookie, and AWS tuple using bounded independent AF_PACKET ingress/return captures; prove both site GWLBE/GWLB traversals; and execute target-process, target-instance, transport-router, and protected ENI-route failover exercises. Target metric proofs SHALL aggregate every finite reason-labeled series in each exact required failure-counter family and SHALL reject absent or non-finite metrics. Long-lived TCP continuity agents SHALL preserve bounded trailing bytes when one read contains multiple newline-delimited frames, and their command execution and wait deadlines SHALL leave fixed reporting headroom beyond the measured stream. Every target-process continuity stream SHALL reserve bounded mutation overhead before its post-mutation observation window and SHALL retain a marker after the measured mutation interval. Remote marker output SHALL remain below the SSM inline-result bound by storing shared identities once and compact timestamp tuples, and the runner SHALL reconstruct the full schema while rejecting malformed or truncated output without coercing topology identities. The initial topology SHALL use distinct site regions and exact string identities, with one target group per site whose ARN matches that site region and one AWS account across both sites. Target-instance replacement SHALL drain and replace the UDP stream's packet-correlated target, record each protocol's actual selected target without requiring cross-protocol co-selection, treat a differently selected TCP stream only as a measured control, require both new-flow paths to exclude the replaced target, refresh the victim's process generation immediately before mutation, and retain the replacement's exact AZ. Passing evidence SHALL keep the initial topology for all pre-replacement observations and SHALL validate later transport-router paths against one exact substitution that removes the victim and binds a globally distinct replacement to that victim's site, AZ, and target group. Raw captures, payloads, and cookie values SHALL be deleted after inspection; evidence SHALL retain only redacted decoded identities and hashes, while failures SHALL retain the redacted underlying inspection command error. Evidence SHALL record endpoint, target, router, ENI and route identities, health and route transitions, recovery duration, established TCP outcome, UDP loss, restoration, and post-cleanup residual audit.

#### Scenario: Bidirectional cold flows
- **WHEN** both site workloads initiate cold TCP, UDP, and ICMP flows concurrently
- **THEN** each flow succeeds without CIDR-role partitioning and evidence proves both site target turnarounds and GWLBE/GWLB traversals

#### Scenario: Dynamic probe tools precede workload-specific readiness
- **WHEN** a protected workload or target is SSM-online while cloud-init is still completing
- **THEN** each dynamic observer or inspector installer waits for cloud-init, creates only the reviewed root-owned directory, verifies its payload from a unique private temporary file, atomically installs the expected executable, and removes the temporary file on success or failure

#### Scenario: Alternate target recovery
- **WHEN** a selected target process or instance is made unavailable
- **THEN** a new flow succeeds through another healthy target and evidence records bounded recovery rather than a hitless guarantee

#### Scenario: Established tuple remains pinned during target replacement
- **WHEN** a target instance is drained and replaced while an established TCP or UDP tuple continues sending through target-group flow state
- **THEN** acceptance MAY record a right-censored interruption only after the complete send window extends beyond replacement, the acknowledged markers form one exact prefix, both fresh TCP and UDP paths exclude the victim, and evidence retains exact sent, received, and lost counts without claiming a maximum interruption duration

#### Scenario: New flow while continuity is established
- **WHEN** target recovery probes a new TCP or UDP tuple while the corresponding established continuity socket remains active on the reviewed application port
- **THEN** the established socket retains only its exact session, the one-shot receiver owns a non-aliased listener, nested responder suspension remains active until both operations finish, every command has shutdown/reporting headroom, and each bounded retry uses a fresh source tuple

#### Scenario: Later recovery traverses a replacement target
- **WHEN** transport-router recovery runs after one target instance was replaced earlier in the same acceptance lifecycle
- **THEN** its TCP and UDP paths are validated against the initial target fleet with only the declared victim removed and its globally distinct same-site, same-AZ, same-target-group successor substituted, while pre-replacement paths continue to reject that successor

#### Scenario: Long transaction completes before its reservation
- **WHEN** a target-instance or transport-router mutation and restoration completes while its continuity command still has unused worst-case reservation time
- **THEN** both TCP/UDP client stops precede either client wait, each client completes at least 20 successful sends and one final post-mutation marker, both client results precede either receiver stop, and evidence retains exact sent, acknowledged, and lost counts while a contiguous episode that starts during mutation may recover after the endpoint and every distinct episode starting outside mutation still fails

#### Scenario: Receiver starts before its client
- **WHEN** server dispatch and listener readiness precede continuity-client dispatch
- **THEN** the first-marker wait remains bounded, the receiver starts its full observation duration exactly once at the first valid marker, the command watchdog retains fixed startup and reporting headroom, and an actually unacknowledged final sequence still fails strict analysis

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
**Migration**: Targets have no Tailscale responsibility; validate redundant transport-router advertisements, accepted routes, no-NAT forwarding, ENIs, and destination-prefix GWLBE route readiness.

### Requirement: GWLB target bootstrap readiness
**Reason**: A target must prove packet-scoped receive and compliant return plus coordinated drain, not TUN and site-forwarding prerequisites for a single regional owner.
**Migration**: Use packet-turnaround target readiness and drain evidence for every enabled target.
