## ADDED Requirements

### Requirement: Standalone production control plane
The system SHALL provide an `envelope-controller` Go process that runs outside Envelope packet targets and Tailscale transport routers. The controller SHALL use direct AWS and Tailscale APIs and SHALL NOT require repository Python scripts, shell orchestration, SSM commands, acceptance manifests, or an Envelope agent on a target. A separate read-only Go router attestor MAY inspect forwarding and publish authenticated readiness, but SHALL NOT mutate host networking, advertisements, or EC2 routes. Envelope targets and transport routers SHALL retain no EC2 route-mutation authority.

#### Scenario: Controller starts independently
- **WHEN** a controller replica starts with its topology, AWS identity, DynamoDB access, and embedded Tailnet observer credentials
- **THEN** it can observe every configured failover domain and participate as a follower or lease holder without contacting an Envelope target or executing code on a transport router

#### Scenario: Test tooling is absent
- **WHEN** the production deployment contains no repository scripts, acceptance run directory, SSM document, or protected-run manifest
- **THEN** autonomous ownership observation and AWS route reconciliation remain available

### Requirement: Strict immutable topology authority
The controller SHALL consume a strict schema-versioned JSON topology that explicitly identifies the deployment, controller policy, DynamoDB authority, Tailnet, sites, routers, stable node IDs, instances, ENIs, VPCs, Regions, AZs, GWLBE route tables, each table's exact GWLBE subnet ID and explicit route-table association ID, source workload prefixes, remote destination prefixes, and preferred baseline owners. It SHALL reject unknown fields, duplicate or overlapping authority, a route table, GWLBE subnet, or route-table association shared by failover domains, and any observed resource outside the configured allowlists. The canonical topology hash SHALL include both association identities and bind every durable domain record, and a changed hash SHALL NOT adopt an active transaction.

#### Scenario: Exact topology is valid
- **WHEN** every identity and prefix is unique, each domain has a disjoint table and GWLBE subnet association, and every router and table VPC belongs to its configured site
- **THEN** the controller computes one deterministic topology hash and exposes the domain as observable

#### Scenario: Mutation scope is discovered dynamically
- **WHEN** a route, router, prefix, ENI, VPC, GWLBE subnet, or route-table association appears only through Terraform state, tags, or API inventory and is absent from the topology document
- **THEN** the controller excludes it from authority and fails closed rather than expanding mutation scope

### Requirement: Replicated observation and fenced lease
Each controller replica SHALL publish bounded Tailnet ownership observations to a controller-specific partition derived from deployment ID, topology hash, and controller ID. Per-replica IAM SHALL permit observation writes only to that replica's partition, SHALL permit reads of all configured observation partitions, and SHALL permit domain-state writes only in active mode. Observation listing SHALL issue exactly one strongly consistent `GetItem` per configured controller partition in deterministic controller order and SHALL NOT query a shared observation partition. A lease holder SHALL require a configured quorum of fresh, topology-matching replicas and SHALL own a monotonically increasing fencing term before changing durable desired state or an AWS route. Lease acquisition, renewal, takeover, and state updates SHALL use conditional writes; TTL SHALL be used only for garbage collection. A contender SHALL NOT take over a present lease until its record version remains unchanged for one complete lease duration measured locally.

#### Scenario: Healthy leader reconciles
- **WHEN** one replica holds and renews the exact lease while a fresh observer quorum agrees
- **THEN** only that fencing term may advance the domain transaction and invoke route mutation

#### Scenario: Replica pauses past its lease
- **WHEN** a former holder resumes after another replica conditionally acquires a higher fencing term
- **THEN** its state writes fail and it performs no new route call after observing the lost lease

#### Scenario: Durable authority is unavailable
- **WHEN** strongly consistent reads or conditional writes cannot be completed
- **THEN** every replica reports not ready and performs no route mutation

#### Scenario: Replica claims another observer identity
- **WHEN** a process using controller-a's AWS credentials publishes an observation claiming controller-b
- **THEN** the derived controller-b partition is outside controller-a's allowed leading key and IAM denies the write

### Requirement: Conservative owner eligibility
The controller SHALL consider a candidate owner eligible only when a quorum of fresh embedded Tailscale observers agrees that its configured stable node is the sole `PrimaryRoutes` owner for the exact source prefix through the applicable stability window, the peer is online and healthy, the router advertises and has enabled the exact expected prefixes, and AWS reports the configured instance and primary ENI healthy and attached in the expected Region, VPC, subnet, and AZ. Failover, failback, observation freshness, and cooldown durations SHALL be explicit bounded configuration.

#### Scenario: Native Tailscale failover converges
- **WHEN** the current router becomes unavailable and Tailscale selects an eligible alternate for the exact prefix
- **THEN** the controller waits for failover quorum stability before persisting route intent

#### Scenario: Observers disagree
- **WHEN** fresh observers report different primary owners or no sole owner for a prefix
- **THEN** the controller retains the current route, marks the domain degraded, and waits for stable agreement

#### Scenario: Tailnet owner lacks cloud health
- **WHEN** observers agree on a router whose instance or configured primary ENI is not eligible
- **THEN** the controller performs no route mutation and reports the failed eligibility check

### Requirement: Durable route reconciliation
For each source-prefix failover domain, the controller SHALL durably persist immutable authority containing the exact GWLBE subnet and route-table association IDs and SHALL persist the transaction ID, fencing term, desired stable-node owner, desired ENI, complete before-snapshot, and ordered route intent before calling EC2 `ReplaceRoute`. Every authoritative route-table read SHALL require exactly one active non-main association matching the configured subnet, association ID, table ID, and site VPC. It SHALL mutate only the configured exact remote destination prefixes, read each route back to stable convergence, and conditionally append acknowledged progress. The selected Tailnet owner and every route target SHALL agree before the domain returns to stable.

#### Scenario: Route table is associated to a different subnet
- **WHEN** the configured route table has no active explicit association, more than one active non-main association, a main association, or an association whose subnet, association ID, reflected table ID, or VPC differs from immutable authority
- **THEN** the controller reports the domain ineligible and performs no route mutation

#### Scenario: Owner changes cleanly
- **WHEN** a new eligible Tailnet owner remains stable and every current route target is allowlisted
- **THEN** the controller persists intent, replaces each exact route with the owner's configured ENI, verifies convergence, and records that owner as stable

#### Scenario: Route call outcome is ambiguous
- **WHEN** `ReplaceRoute` returns an error or exceeds its deadline after durable intent
- **THEN** the controller settles the outcome with authoritative reads, resumes toward the durable desired owner only while it retains the lease, and never blindly retries an unknown mutation

#### Scenario: Route resolves outside authority
- **WHEN** any observed route selects an unknown target or oscillates without stable settlement
- **THEN** the transaction enters a durable degraded state and automatic mutation stops

### Requirement: Durable failover and stability-gated failback
An alternate selected after failure SHALL be a valid durable steady-state owner; the controller SHALL NOT restore the preferred baseline merely because one reconciliation completed. A later native Tailscale selection of the preferred owner SHALL be treated as a separate failback transaction and SHALL require the configured longer failback stability window and cooldown. The controller SHALL prioritize alignment with the sole eligible Tailnet owner over an unavailable preferred owner.

#### Scenario: Alternate remains active
- **WHEN** failover converges and Tailscale continues selecting the alternate
- **THEN** the controller keeps every domain route on that alternate across process restart and leader replacement

#### Scenario: Preferred owner returns
- **WHEN** Tailscale selects the healthy preferred owner after the cooldown and failback stability window
- **THEN** the controller starts a new fenced route transaction rather than rewriting or rolling back the completed failover transaction

### Requirement: Fail-closed operations and observability
Each replica SHALL expose private `/healthz`, `/readyz`, and Prometheus metrics for process health, Tailnet observer health, durable-store access, lease state, fencing term, observation age and quorum, selected owner, route agreement, transaction phase and duration, failover and failback totals, ambiguous calls, API errors, and degraded domains. Logs and metrics SHALL not expose auth keys, node keys, credentials, or unbounded cloud responses. The first version SHALL expose no remote mutation endpoint.

#### Scenario: Follower is ready
- **WHEN** a replica has valid topology, working durable and Tailnet clients, fresh observations, and can confirm another healthy lease holder
- **THEN** readiness succeeds without claiming leadership

#### Scenario: Domain is degraded
- **WHEN** owner quorum, cloud eligibility, lease safety, or route agreement fails
- **THEN** readiness and metrics identify the bounded reason while credentials and cryptographic identities remain redacted

### Requirement: Authenticated router forwarding attestation
Eligibility SHALL require fresh live forwarding evidence from an independently authenticated publisher bound to the exact configured router instance, primary ENI, stable node, deployment, topology hash, and canonical collector configuration digest. Evidence SHALL prove all supported forwarding prerequisites, reject unsupported collection, and use a verifier challenge plus bounded capture and expiry to prevent replay, including across verifier restarts. Runtime artifacts and configuration SHALL be immutable to the attestor, whose inspection loop SHALL NOT execute shell, Python, or SSM. A distinct boot-only enrollment operation MAY resolve exact versioned configuration and per-router SecureString references before sealing local files. It SHALL verify independently supplied public-key authority, version-1 identity/configuration binding, and native local identity before installation; report claims alone SHALL NOT enroll keys.

#### Scenario: Claimed identity differs from authenticated publisher
- **WHEN** an otherwise healthy report claims an allowlisted router but authenticated transport identifies a different instance or publisher
- **THEN** the controller rejects the report without granting eligibility

#### Scenario: Evidence is replayed or incomplete
- **WHEN** a report uses a different challenge, is stale or future-dated, or omits a required live forwarding check
- **THEN** the controller fails closed and does not substitute a boot marker or configuration assertion

#### Scenario: Supplementary forwarding authority changes
- **WHEN** a validly signed report has the expected topology but a different collector configuration digest
- **THEN** it is rejected even if every reported check says pass

#### Scenario: Another instance shares the router role
- **WHEN** credentials from another instance or an unbound role session request the router's seed or enrollment records
- **THEN** an explicit source-instance deny prevents the read, independently of broader allows on that role

### Requirement: Deployment-owned domain lifecycle
A separate Go deployment command SHALL initialize journals under route-denied credentials only after fresh stable quorum, candidate eligibility, and actual authoritative route/owner agreement. Initialization SHALL conditionally create a lease-free journal without overwriting any existing state. Activation SHALL be independent topology-bound durable state. Rollout SHALL enforce one deployment-wide lock and per-replica health gates. Migration SHALL exclude old writers, prove quiescence, reject active or ambiguous journals, and retain recoverable state on uncertainty.

#### Scenario: Preferred owner differs from actual agreement
- **WHEN** initialization observes a healthy stable alternate with every exact route on its ENI
- **THEN** the initial stable journal records that alternate, not the preferred owner

#### Scenario: Journal already exists
- **WHEN** initialization races with another initializer or encounters an existing journal
- **THEN** it refuses replacement and leaves the existing lease, fence, topology, and progress intact

### Requirement: Retryable application continuity boundary
The production availability contract SHALL guarantee bounded new-flow recovery only after Tailnet ownership and AWS route convergence. It SHALL NOT guarantee established five-tuple continuity or lossless UDP. Operator guidance SHALL require TCP reconnect with bounded jitter and idempotency for side-effecting operations and SHALL require important UDP messages to use message IDs, sequencing, acknowledgements, deduplication, and bounded retransmission or a durable queue.

#### Scenario: Established traffic is interrupted
- **WHEN** a router or route fails during an established TCP or UDP exchange
- **THEN** the system may lose transport progress while a fresh retry succeeds after convergence, without reporting hitless continuity

#### Scenario: Important UDP message is retried
- **WHEN** an acknowledgement is absent across a failover interval
- **THEN** the application retransmits the same message ID within its bound and the receiver suppresses duplicate side effects
