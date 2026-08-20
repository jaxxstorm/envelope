# tailscale-host-routing Specification

## Purpose
TBD - created by archiving change envelope-tailscale-routing. Update Purpose after archive.
## Requirements
### Requirement: Envelope and tailscaled co-residency
The system SHALL run Envelope and `tailscaled` concurrently with independently configurable and distinct TUN interface ownership and SHALL identify the appliance underlay interface explicitly.

#### Scenario: Default interface names
- **WHEN** the service starts without interface overrides
- **THEN** Envelope owns `envelope0` and routing integration targets Tailscale-owned `tailscale0`

#### Scenario: Identical interface names
- **WHEN** Envelope and Tailscale interface configuration resolves to the same name
- **THEN** startup fails before either routing mode mutates host state

#### Scenario: Pre-existing Envelope interface
- **WHEN** the configured Envelope TUN name already exists as a persistent or attached device
- **THEN** exclusive TUN creation fails rather than attaching to or reconfiguring state owned by another lifecycle

#### Scenario: Missing underlay interface
- **WHEN** routing integration is enabled without a valid configured underlay interface
- **THEN** startup or readiness fails before traffic is enabled

### Requirement: Explicit directional CIDR roles
The system SHALL configure pairwise disjoint local GWLB-return CIDRs, local-delivery CIDRs, and remote Tailnet CIDRs and SHALL reject malformed, overlapping, or covering assignments across any two role sets.

#### Scenario: Valid directional roles
- **WHEN** local GWLB-return and local-delivery CIDRs are disjoint and remote CIDRs are valid
- **THEN** startup accepts the configuration and reports each role separately

#### Scenario: Overlapping local roles
- **WHEN** a local-delivery CIDR overlaps or is covered by a local GWLB-return CIDR
- **THEN** startup fails with an error naming both conflicting entries

#### Scenario: Remote CIDR overlaps a local role
- **WHEN** a remote Tailnet CIDR overlaps or covers a local GWLB-return or local-delivery CIDR
- **THEN** startup fails before effective route lookup can shadow the local role

#### Scenario: Missing managed return CIDRs
- **WHEN** routing mode is `manage` and no GWLB-return CIDRs are configured
- **THEN** startup fails with a configuration error

### Requirement: Managed GWLB-return routing
Managed mode SHALL install and reconcile policy rules and dedicated-table routes only for traffic entering from `tailscale0` and destined for configured local GWLB-return CIDRs.

#### Scenario: Managed return setup
- **WHEN** routing mode is `manage` and host prerequisites are valid
- **THEN** each GWLB-return CIDR has an `iif tailscale0` rule and dedicated-table route through `envelope0`

#### Scenario: Local-delivery bypass
- **WHEN** traffic enters from `tailscale0` for a configured local-delivery CIDR
- **THEN** no Envelope-managed rule selects `envelope0` and effective routing uses local delivery

#### Scenario: Drift repaired
- **WHEN** an Envelope-owned return rule or route is removed
- **THEN** reconciliation restores it and increments the drift-repair metric

#### Scenario: Reserved routing table
- **WHEN** the configured Envelope table is unspec, Tailscale table 52, default, main, local, or outside the supported numeric range
- **THEN** configuration fails before host state is inspected or mutated

### Requirement: Effective forward route to Tailscale
The system SHALL symbolically audit ordered policy rules and every selected route table for the complete same-family source-role/destination-role prefix Cartesian product. The proof SHALL account for source and destination selectors on rules and routes, input interfaces, zero-mark matching, terminal actions, suppression, and all intersecting routes; first/last-address structured lookups SHALL remain supplementary checks. Relevant source-specific routes SHALL fail closed unless every intersecting source subtree is proved. Return routing SHALL select the configured Envelope table/device, local delivery SHALL select the configured underlay in main table 254, and remote routing SHALL select `tailscale0` in Tailscale table 52 for every address in each role.

#### Scenario: Effective remote route
- **WHEN** route lookup is evaluated for every boundary/source combination from `envelope0` to a remote Tailnet CIDR
- **THEN** every result is unicast through `tailscale0` in table 52

#### Scenario: Remote route absent or shadowed
- **WHEN** a remote Tailnet route is missing or another route wins effective lookup
- **THEN** routing readiness is false and the affected CIDR is reported

#### Scenario: Prefix-edge shadowing
- **WHEN** one boundary address or one same-family source combination selects a wrong table, type, or device
- **THEN** the complete role is unhealthy even if another address in that prefix resolves correctly

#### Scenario: Interior more-specific route
- **WHEN** a more-specific route intersects only an interior subset of a role prefix, including a blackhole, unreachable, prohibit, or wrong-device route that misses both boundary addresses
- **THEN** full-prefix readiness fails even when every supplementary boundary lookup succeeds

#### Scenario: Interior source-policy shadow
- **WHEN** an earlier policy rule matches only an interior subset of a source role and can select a different table for a required destination role
- **THEN** full-prefix readiness fails even when first/last source probes do not match that rule

#### Scenario: IPv6 source-specific route
- **WHEN** a selected route table contains a route whose non-universe `from` selector intersects a required source role and whose destination intersects a required destination role
- **THEN** full-prefix readiness fails closed even when boundary lookups select the expected route

#### Scenario: Source-specific rejection evidence on every kernel
- **WHEN** routing verification is tested on any kernel
- **THEN** structured route-decoder and full-prefix-auditor fixtures prove that relevant IPv6 source-specific routes are retained and rejected

#### Scenario: Privileged source-specific reproduction on a capable kernel
- **WHEN** the privileged test kernel supports `CONFIG_IPV6_SUBTREES`
- **THEN** a real namespace source-specific route is decoded and rejected by the full-prefix auditor

#### Scenario: Privileged source-specific reproduction on an incapable kernel
- **WHEN** the privileged test kernel does not support `CONFIG_IPV6_SUBTREES`
- **THEN** only that supplemental reproduction reports an explicit capability skip without weakening the mandatory fixtures or runtime fail-closed requirement

#### Scenario: Tailscale FIB overlaps a local role
- **WHEN** any route in table 52 intersects a local return or delivery role
- **THEN** routing readiness fails closed before traffic is enabled

### Requirement: Routing modes are explicit
The system SHALL support `off`, `verify`, and `manage`, SHALL default to `off`, and MUST NOT mutate host routing in `off` or `verify` mode.

#### Scenario: Off mode
- **WHEN** routing mode is omitted or set to `off`
- **THEN** routing readiness is neutral and no route, rule, sysctl, or firewall state is changed

#### Scenario: Verify mode valid
- **WHEN** verify mode finds the complete effective path valid
- **THEN** readiness is healthy without host mutation

#### Scenario: Verify mode invalid
- **WHEN** verify mode finds any required effective-path prerequisite invalid
- **THEN** readiness is unhealthy and failure metrics and logs identify the prerequisite

#### Scenario: Manage mode invalid at startup
- **WHEN** initial managed reconciliation, ownership locking, or effective-path verification fails
- **THEN** process startup fails before datapath serving begins

### Requirement: Linux forwarding prerequisites
Routing readiness SHALL require forwarding sysctls, disabled or loose reverse-path filtering for `conf/all`, the configured underlay interface, `tailscale0`, and `envelope0`, a deterministic legacy-iptables contract, and executable native-nft inspection tooling. Complete `iptables-save` and `ip6tables-save` output SHALL be inspected across `raw`, `mangle`, `nat`, `filter`, and `security`; every forwarding-relevant built-in hook SHALL use policy `ACCEPT` and be pristine except for the exact owned contracts. Filter `FORWARD` SHALL contain only an unconditional jump to the exact deployment-owned forwarding chain. Mangle `FORWARD` SHALL contain only the unconditional jump to the exact deployment-owned MSS chain. Each path's MSS SHALL equal the minimum live/configured path MTU minus the IPv4 or IPv6 TCP/IP header allowance.

#### Scenario: Strict reverse-path filtering
- **WHEN** strict reverse-path filtering is effective through `conf/all` or on the underlay, Tailscale, or Envelope interface
- **THEN** readiness is unhealthy and identifies the interface and value

#### Scenario: Forwarding firewall blocks a path
- **WHEN** host firewall policy blocks any required underlay-to-Tailscale, Tailscale-to-underlay, Envelope-to-Tailscale, or Tailscale-to-Envelope direction
- **THEN** readiness is unhealthy and identifies the blocked direction

#### Scenario: MSS policy absent
- **WHEN** the Tailscale MTU is 1280 and required TCP MSS policy is not effective
- **THEN** readiness is unhealthy before TCP acceptance traffic is enabled

#### Scenario: Unsupported firewall layout
- **WHEN** a forwarding-relevant policy is `DROP`, a raw/security drop, mangle mark, NAT rewrite, policy-only acceptance, conditional or extra owned rule, nft-backed iptables, native nft/firewalld object, or any additional filter/mangle `FORWARD` rule makes the path unprovable
- **THEN** readiness fails closed with a firewall or MSS reason

#### Scenario: Native nft inspection unavailable
- **WHEN** `/usr/sbin/nft` is missing, cannot be statted, is not executable, or cannot return its JSON ruleset
- **THEN** readiness fails closed with a firewall reason instead of treating native nft state as empty

### Requirement: Tailscale backend and route readiness
Routing readiness SHALL require the pinned Tailscale v1.80.x status schema in kernel-TUN mode, a healthy Running backend, an online non-expired self node, approved local routes, online non-expired route-serving peers present in the network map/magicsock/engine, accepted table-52 routes for every remote role, and a successful bounded data-plane ping to each serving peer.

#### Scenario: Interface exists but backend is not Running
- **WHEN** `tailscale0` exists but `tailscale status` reports a non-Running backend
- **THEN** readiness is unhealthy

#### Scenario: Advertised or accepted route unavailable
- **WHEN** a required local advertisement is unapproved or a remote route is not accepted
- **THEN** readiness is unhealthy and reports the affected prefix

#### Scenario: Route withdrawn after startup
- **WHEN** a previously effective remote route is withdrawn
- **THEN** readiness becomes unhealthy by the next reconcile interval

#### Scenario: Unsupported status schema or userspace mode
- **WHEN** Tailscale is not v1.80.x, omits a pinned status field, or does not use kernel TUN mode
- **THEN** readiness fails with a bounded backend reason

#### Scenario: Control-plane route without data plane
- **WHEN** a peer advertises the required route but has no matching table-52 owner or cannot answer a bounded Tailscale ping
- **THEN** readiness is unhealthy

#### Scenario: Reachable peer is temporarily relayed
- **WHEN** one bounded Tailscale ping receives a valid DERP relay pong while direct-path discovery is still converging
- **THEN** the peer data plane is accepted as reachable without requiring a direct-only path

### Requirement: Ownership-safe transactional management
Managed mode SHALL reserve protocol 186 together with the configured table and rule priority as its ownership namespace, hold a nonblocking cross-process lock for its lifecycle, track state it created, preserve equivalent unmarked pre-existing state, install routes before rules, and roll back partial apply while cleanup continues with an independent deadline per object. A successful add SHALL enter the transaction before verification reread; an add that returns an error MUST NOT claim or delete subsequently observed protocol-186 state. Cleanup SHALL delete and reread the exact reserved object, retaining ownership and reporting failure while owned or conflicting protocol-186 state remains.

#### Scenario: Equivalent operator-owned state
- **WHEN** a required equivalent rule or route exists before Envelope starts
- **THEN** Envelope accepts it, does not claim ownership, and leaves it on shutdown

#### Scenario: Partial managed apply failure
- **WHEN** adding one required object fails after another was created
- **THEN** the newly created state from that transaction is rolled back and readiness remains unhealthy

#### Scenario: Successful add cannot be reread
- **WHEN** a route or rule add succeeds but its immediate verification reread fails, is inconclusive, or reports conflicting protocol-186 state
- **THEN** the successful mutation is transaction-owned and rollback removes it

#### Scenario: Failed add has ambiguous observed state
- **WHEN** a route or rule add returns an error and the reread observes equivalent protocol-186 state
- **THEN** Envelope reports an ownership failure without claiming or deleting the observed state

#### Scenario: Graceful shutdown
- **WHEN** managed Envelope stops
- **THEN** only state created and owned by that process is removed and cleanup attempts every owned object

#### Scenario: Cleanup conflict persists
- **WHEN** exact deletion is a no-op and reread still reports owned or conflicting protocol-186 state
- **THEN** Envelope retains its process ownership record, increments cleanup failure, and does not record successful removal

#### Scenario: Concurrent manager
- **WHEN** another managed process holds the routing ownership lock
- **THEN** managed startup fails without mutating routing state

### Requirement: Routing observability
The system SHALL expose apply attempts and failures, effective-path validation failures by reason, drift repairs, ownership decisions, Tailscale readiness failures, and current routing readiness.

#### Scenario: Effective-path failure
- **WHEN** any effective route, backend, sysctl, reverse-path, firewall, or MSS prerequisite fails
- **THEN** the corresponding reason metric increases and readiness reports the same class of failure

#### Scenario: Metrics scrape
- **WHEN** a client scrapes metrics in verify or manage mode
- **THEN** all routing counters and current readiness state are present

#### Scenario: Redacted routing status
- **WHEN** a client requests `/debug/routing`
- **THEN** role CIDRs, interfaces, table, priority, protocol marker, schema, and readiness are reported without auth keys, peer keys, or flow cookies

### Requirement: Secretless co-resident acceptance
The system SHALL provide a required local integration using immutable Headscale 0.25.1 with an embedded local DERP and Tailscale 1.80.3 images, runtime-generated preauth keys, kernel-TUN peers, workload namespaces whose router transit addresses are outside all role CIDRs, exact deployment-owned netfilter policy with native nft inspection, and valid AWS-profile GENEVE traffic. External Tailscale SaaS credentials MUST NOT be required for acceptance.

#### Scenario: Correlated directional lanes
- **WHEN** each peer receives a valid cookie-bearing GENEVE flow for its local initiator role
- **THEN** cold traffic bypasses the responder Envelope and exactly one response is re-encapsulated with the correlated outer identity and byte-identical options

#### Scenario: Optional SaaS compatibility
- **WHEN** external auth-key files and pre-approved routes are explicitly supplied
- **THEN** the separate SaaS harness may run without replacing or weakening the local Headscale acceptance gate

### Requirement: Routing performance regression gate
The system SHALL define a reviewed routing reconciliation and packet-path benchmark profile with allocation and latency thresholds before implementation performance is accepted.

#### Scenario: Benchmark within threshold
- **WHEN** routing and datapath benchmarks run on the documented Linux profile
- **THEN** measured allocations and latency remain within the pre-approved thresholds recorded with the change evidence

#### Scenario: Benchmark regression
- **WHEN** a benchmark exceeds a pre-approved threshold
- **THEN** the change remains incomplete until the regression is fixed or the threshold change is reviewed before rerun
