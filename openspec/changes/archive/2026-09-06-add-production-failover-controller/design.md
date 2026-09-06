## Context

The accepted version-2 topology has redundant Envelope targets and Tailscale transport routers, but its route failover is an acceptance exercise. A protected Python runner temporarily changes one router's advertisement, waits for Tailnet ownership, replaces exact GWLBE routes, proves recovery, and restores the baseline. That mechanism assumes a reachable test environment, has no continuous health policy, and intentionally never holds a failed-over production state.

The production controller must not run on Envelope packet targets, grant them route authority, invoke repository scripts, use SSM to execute test-bed helpers, or depend on acceptance manifests. It must preserve exact source-prefix owner/ENI coupling: the transport router selected by Tailscale for a GWLBE AZ's source workload prefix must also be the ENI selected by that GWLBE route table for all exact remote-site prefixes.

Tailscale already provides exact-prefix subnet-router failover when multiple routers advertise the same route. The production design can therefore remove advertisement mutation from Envelope's control plane. Transport routers advertise the complete exact local-site prefix set continuously, Tailscale selects one primary per prefix, and the controller reconciles AWS routes to that selected owner.

## Goals / Non-Goals

**Goals:**
- Run a production controller as an independent Go binary on three disposable replicas outside target and transport-router instances.
- Recover new flows automatically after a transport-router failure without Python, shell, or SSM in the runtime control loop. A small read-only Go router attestor is permitted; it has no route or host-network mutation authority.
- Use multiple embedded Tailscale observers and AWS health/readback to make conservative, stable route decisions.
- Serialize each failover domain with durable lease, fencing, intent, progress, and recovery state.
- Hold an alternate owner as normal durable state and process later native-owner changes as separately stability-gated failback.
- Preserve target statelessness, no-NAT transport, exact route allowlists, and fail-closed behavior under ambiguity.
- Publish actionable health, leader, ownership, route, transition, and recovery telemetry.
- Define an explicit retryable transport contract for applications.

**Non-Goals:**
- Make AWS route replacement and Tailscale convergence atomic or hitless.
- Replicate TCP, UDP, conntrack, WireGuard, or GWLB flow state.
- Guarantee that an original five-tuple resumes after failure or that UDP loses no datagrams.
- Survive complete loss of the authoritative controller Region in the first production version.
- Provide arbitrary topology discovery from Terraform state, tags, or Tailnet inventory.
- Add route mutation, Tailscale, DynamoDB, or controller behavior to the `envelope` packet target.

## Decisions

### 1. Run a standalone controller rather than embedding control in Envelope

Add `cmd/envelope-controller` and isolated `internal/controller` packages. The controller has cloud and Tailnet observation authority but no packet-processing privilege. Envelope targets retain only `CAP_NET_RAW`; transport routers retain forwarding responsibility and no EC2 route permission.

Embedding a controller in Envelope targets is rejected because GWLB can replace targets independently, targets intentionally have no site-routing identity, and granting every target cloud mutation authority expands both the blast radius and split-brain surface.

### 2. Use DynamoDB conditional state instead of embedded Raft

Three controller replicas share an encrypted, point-in-time-recoverable DynamoDB table. A per-failover-domain item stores immutable topology hash, monotonically increasing fencing term, lease record version, active transaction, desired owner, acknowledged route progress, and the last stable state. Separate per-replica observation items store bounded Tailnet snapshots.

A fresh lease is created with a conditional put. Renewal requires the exact holder, record version, and fence. A contender records the current lease record version, waits one complete lease duration on its monotonic clock, and can take over only if a strongly consistent reread still has that version. Every state update requires the current fence and document revision. DynamoDB TTL is used only for stale observation garbage collection, never lock correctness.

Raft is rejected for this version because it would require stable peer identities, persistent volumes, peer discovery, mTLS, membership changes, snapshots, quorum placement, upgrades, and disaster recovery. It would not make EC2 or Tailscale operations transactional or fence a delayed external API call. The initial DynamoDB authority is regional and multi-AZ; controllers fail closed if it is unavailable.

### 3. Delegate route-owner election to native Tailscale HA

Every router in a site continuously advertises the same complete set of exact local workload prefixes with subnet-route SNAT and Tailnet DNS acceptance disabled. Standard Tailscale failover mode selects one online primary for each exact prefix. Regional routing and in-region load balancing are outside this version because different observers choosing different routers would violate source-prefix owner/ENI coupling.

Each controller embeds a pinned `tsnet` observer node. It reads stable node IDs, online state, health, and `PrimaryRoutes` directly from the Tailscale control plane and publishes an IAM-bound observation to a DynamoDB partition derived from deployment ID, topology hash, and controller ID. Each replica role can write only its own observation partition and read all configured observation partitions, so credentials for one replica cannot claim another replica's identity without signatures. The leader reads each configured partition strongly and requires a quorum of fresh replicas to agree on one eligible primary before changing AWS. No controller invokes `tailscale set`, modifies router preferences, or runs code remotely on a router.

The Tailscale Admin API is used only for read-only validation that every configured router advertises and has enabled every exact local prefix. Dynamic approval mutation is rejected because it would recreate a second ordered actuator and introduce full-device route-set races.

### 4. Protect local routing under overlapping advertisements

Because routers accept opposite-site routes while all same-site routers advertise overlapping local prefixes, Tailscale can expose a local-prefix route in table 52 on a standby. Each router installs higher-priority full-prefix policy rules that force every local-site destination to `main`, not only packets arriving on `tailscale0`. Readiness proves every address in each local prefix uses the destination-prefix AZ's GWLBE through the VPC underlay and that no table-52 route can shadow that decision.

This replaces the prior requirement that table 52 contain no local prefix at all. The effective forwarding result remains unchanged and source addresses remain intact.

### 5. Treat topology as explicit immutable input

The controller reads one strict schema-versioned JSON document; it never reads Terraform state or discovers mutation scope from tags. The document identifies deployment, replicas, timing policy, DynamoDB authority, Tailnet, sites, routers, stable node IDs, instance IDs, primary ENIs, VPCs, regions, GWLBE route tables, each table's exact GWLBE subnet and explicit route-table association IDs, source prefixes, remote destination prefixes, and preferred baseline owners.

Validation rejects unknown fields, duplicate identities, overlapping site CIDRs, route tables, GWLBE subnets, or route-table associations shared across failover domains, routers outside the site VPC/Region, a route target outside the configured ENI set, and timing relationships that cannot renew a lease before an external action deadline. EC2 readback requires the table and its configured GWLBE subnet to belong to the site VPC and requires exactly one active non-main association whose subnet, association ID, and reflected table ID match authority.

The canonical JSON hash includes both GWLBE association identities and is persisted with every domain. An explicit association ID is stable for the lifetime of that AWS association; replacing or re-associating it changes topology authority. A changed hash requires a quiescent migration and cannot adopt an active transaction.

### 6. Reconcile one source-prefix route domain at a time

A failover domain contains one source workload prefix, its GWLBE route table and exact explicit subnet association, every exact remote-site destination route in that table, and all eligible same-site router ENIs. Domains have independent leases and may reconcile concurrently only when their route tables, GWLBE subnet associations, and destination prefixes are disjoint. Active replicas accept at most 32 domains and reserve one bounded worker for each domain because a possibly committed route call cannot be safely preempted; passive read-only and dry-run replicas may inspect larger topologies with bounded shared workers.

The durable phases are:

```text
stable
  -> owner-observed
  -> route-intent-persisted
  -> routes-converging
  -> stable

any phase -> degraded
degraded -> owner-observed only after ambiguity is authoritatively settled
```

The alternate is a normal `stable` owner after failover. A later return to the preferred owner is a new owner observation and transaction, gated by the longer failback stability interval and cooldown. The controller follows the Tailscale-selected primary; it does not force a preferred owner.

### 7. Combine quorum, hysteresis, and cloud eligibility

Every replica samples Tailnet state at a bounded interval and publishes observations with controller ID, topology hash, capture time, sequence, backend health, and the exact owner per prefix. The lease holder changes a route only when:

- at least the configured quorum has fresh observations;
- all quorum observations agree on the same stable node ID for the complete stability window;
- the candidate peer is online, non-expired, healthy, and configured for the exact prefix;
- EC2 reports the candidate instance running, both status checks healthy, and the configured primary ENI attached in the expected Region, VPC, subnet, and AZ;
- the route table is in the configured site VPC and has exactly one active non-main association matching the configured GWLBE subnet and association IDs;
- every current route is active and selects an allowlisted ENI;
- cooldown and lease safety margins permit the complete bounded operation.

Disagreement, stale observations, an unknown owner, or a partially healthy candidate produces a degraded status and no mutation. Failover uses a shorter stability window than automatic failback to avoid flapping.

### 8. Journal and read back every EC2 route mutation

Before each `ReplaceRoute`, the controller persists transaction ID, fence, desired owner/ENI, complete before-snapshot, and the ordered attempted-prefix list. After the call it performs strongly consistent EC2 readback until the exact route is stably observed, then appends that prefix to completed progress with CAS.

An API error or timeout is ambiguous, not a failed write. The controller reads until the route stabilizes on either an authorized previous or desired ENI, records the settled result, and resumes toward the durable desired owner only while it still holds the lease. Unknown targets or oscillation enter `degraded`; no automatic rollback points traffic at a router Tailscale no longer selects.

EC2 has no conditional fencing token. To bound stale-writer risk, the controller renews immediately before each mutation, refuses to begin within the lease danger window, uses short SDK deadlines, persists intent first, and continuously reconciles routes to durable desired state. Strict downstream stale-writer exclusion would require a separate serialized actuator and is outside this version.

### 9. Expose only operational endpoints

Each replica serves a private Prometheus endpoint and `/healthz` plus `/readyz`. Health means the process and observer loop are running. Readiness additionally requires DynamoDB access, a running embedded Tailnet observer, fresh observations, valid topology, and either a held lease or confirmed follower state. There is no remote mutation API in the first version.

Metrics cover replica/lease state, fencing term, observation age and quorum, selected owner, route target agreement, reconciliation phase and duration, failover/failback counts, ambiguous calls, degraded domains, and API errors. Logs use structured redacted fields and never include auth keys, node keys, or complete credential-bearing responses.

### 10. Keep application continuity above the network layer

The controller guarantees only bounded new-flow recovery once Tailscale ownership and AWS routes converge. TCP applications use reconnect with bounded jitter and idempotency keys for non-read-only operations. Retryable UDP protocols use message IDs, sequence numbers, acknowledgements, deduplication windows, and bounded retransmission. Durable commands use an application queue or outbox rather than raw UDP.

QUIC is a valid application transport for reconnection and loss recovery but is not presented as a hitless network guarantee. The controller records route-convergence SLOs; it does not claim established-flow continuity.

### 11. Separate router attestation from route control

Approved architecture amendment: a separate Go attestor reads the live Linux forwarding contract and Tailscale local API on each router. It does not execute shell, Python, SSM, or the existing readiness scripts and cannot repair forwarding or change advertisements. The existing deployment uses legacy iptables, not an nftables forwarding backend; a collector must inspect legacy IPv4/IPv6 filter, mangle, and NAT tables as well as reject unexpected nftables state. Boot markers or configuration-derived `ready` booleans are not live evidence.

Reports bind deployment, canonical topology hash, complete router instance/primary ENI/stable-node authority, capture/expiry times, and a challenge generated by the verifier. Publisher authentication is independent of report contents: an untrusted payload cannot establish its own publisher identity. The deployment must bind authenticated publisher credentials to the exact instance, not merely a shared router role, hostname, or instance ID copied from configuration. Challenge responses prevent replay across verifier restarts; expiry also bounds collection and consumption. Missing, unsupported, stale, malformed, or unauthenticated checks fail closed. Runtime artifacts and configuration are immutable to the service. No external certificate issuer or credential broker is assumed to exist.

The native inspector decodes complete rtnetlink rule/route dumps and the Linux 64-bit iptables/ip6tables getsockopt ABI, rejecting unrecognized forwarding selectors, matches, targets, truncation, and interrupted dumps. Full-prefix proofs use all overlapping routes, not just address probes. Live link MTUs determine MSS. Native nftables table enumeration must be empty. EC2 readback binds the transport association and every destination workload subnet/AZ to its configured GWLBE subnet/endpoint. Reports additionally bind the canonical collector-configuration SHA-256, so supplementary transport-table and endpoint authority cannot change behind a constant topology hash.

Linux legacy netfilter inspection requires CAP_NET_ADMIN even for reads; use a datagram control socket, not a raw packet socket, and grant no CAP_NET_RAW or AWS route-mutation permission. The trusted immutable Go inspector exposes only read operations. This is a real host-network administrative capability if the process is compromised, not a claim of capability-free inspection. ProtectSystem/ProtectKernelTunables, bounded concurrency/resources, restricted address families, private ingress, and no runtime subprocess or mutation endpoint limit its use.

Enrollment is two-phase to avoid instance-ID/topology bootstrap cycles. Router cloud-init installs a hash/version-pinned binary and a separate boot-only enrollment unit using public-key and exact parameter references known before instance creation. After router IDs are reviewed, Terraform publishes the canonical collector configuration and grants only the exact source-instance credentials access to that router's versioned signing-seed parameter and configuration. The boot unit verifies the seed's public key and local instance/ENI identity, then installs root-owned immutable files and exits. Only the Go inspector remains in the runtime loop; SSM/secret delivery is not a steady-state readiness mechanism. Seeds are supplied as existing per-router SecureStrings and never enter Terraform values/state, logs, or reports.

### 12. Use a separate Go deployment lifecycle command

Approved architecture amendment: initialization, per-domain activation, serialized replica rollout, and quiescent topology migration belong to a separate Go deployment command, not the reconciler or acceptance script. Initialization runs under explicitly route-denied credentials, reads fresh stable observer quorum and authoritative EC2 routes, validates candidate eligibility, and conditionally creates a lease-free journal for the actual agreeing owner. It never substitutes the preferred owner or overwrites an existing journal.

Activation is separate durable state bound to the topology hash, not a topology field that changes that hash. Rollout needs one deployment-wide conditional lock, a durable per-replica operation journal, and pre/post replacement health gates; Terraform parallelism alone is not a lock. Ambiguous replacement or process loss retains the lock for inspected recovery. Migration first excludes old writers, observes unchanged lease/state versions for a complete lease/action bound, rejects active or ambiguous journals, and checks old and new route/owner agreement. A changed topology must never silently invalidate an active journal.

The deployment lock is a separate IAM-isolated `lifecycle#<deployment>` partition. It never expires automatically: another deployment may start only after an exact-operation conditional completion. Domain activation and migration use DynamoDB transactions checking that lock and every old document/item version. Deactivation retains all journal content and waits a complete lease plus route-action bound before quiescence is acknowledged. An interrupted operation retains the lock and journal for inspected recovery, not automatic takeover. The first migration implementation requires the same deployment, regional table, and domain-ID set (at most 32 domains); additions/removals require a separately reviewed migration rather than dropping records. Rollout applies one reviewed saved Terraform plan containing only one controller instance replacement and its state-volume attachment, with healthy unchanged peer quorum before and fresh replacement observation/route agreement after. Deployment tooling may invoke the pinned Terraform binary directly; that is not part of the controller runtime loop.

### 13. Separate simulation evidence and live credentials

Approved architecture amendment: observer disagreement, stale-fence rejection, ambiguous responses, and exact crash checkpoints may be demonstrated by the deterministic Go integration harness. They must be labeled simulated, not declared supported by the live adapter. Live evidence independently covers real router loss/recovery, leader loss/recovery, lease renewal, native ownership, route convergence, durable alternate state, failback, application retries, and cleanup. No test-only runtime failure-injection API is required.

Protected execution uses separate deployment, measured observation, quiescence, and cleanup jobs and process identities. Deployment and observation use different isolated runner groups. GitHub OIDC subjects bind repository, environment, exact workflow/ref, run ID, and attempt; the required repository subject customization is checked before claiming resources. Observation has an explicit closed API deny and exact resource denies, cannot assume another role, cannot read deployment state or secrets, and cannot execute on routers/controllers. No deployment credential is handed to it.

The deployment process publishes an immutable versioned handoff containing exact claim ownership, canonical topology, actor identities/tags, public attestor authority, and production dependency receipts. It freezes its entire OIDC issuer and unconditionally denies deployment/lifecycle sessions before measurement can begin, including sessions issued during handoff preparation. Cleanup sessions issued on or before the observer drain deadline are explicitly denied. The observer independently checks the exact S3 claim version/body, handoff digest, invocation context, effective role policy, credential lifetime, revocation, and actual actor ownership before faults. Mutable local ledgers do not establish authority.

Measured evidence uses a new versioned live-only contract. Real router stop/recovery, stable native ownership, route convergence, lease renewal, real leader stop/higher-fence handoff/recovery, durable alternate ownership, failback gates, fresh TCP/UDP retries, and established outcomes are required. Exact checkpoint, disagreement, stale-fence, and ambiguous-response scenarios are separate integration-only results from actual Go test output, never live receipts. A live leader fault may occur in stable state; no production barrier or injector is introduced.

Quiescence uses only an exact-instance stop/start plus durable-read identity; it can start routers but cannot restart controllers. After observer issuance closes and all possible one-hour observer sessions expire, it restores run-owned router faults, stops every controller, waits a full lease/action drain interval, and proves unchanged journals and stopped actors before emitting a versioned quiescence receipt. Cleanup first rechecks that proof with the narrow identity, then obtains its separate deployment-capable credentials. A partial deployment can be cleaned automatically only before controller creation was attempted and after proving no owned controllers exist; otherwise it requires independently approved inspected quiescence and manual recovery. Failed or interrupted cleanup retains claims, private recovery state, and sanitized evidence; no later unrelated invocation adopts them. Two consecutive zero-residual audits precede reopening deployment authority; reopening replaces the unconditional deny with an old-session cutoff so frozen tokens never become valid again. Architectural approval remains separate from permission to execute a billable run.

## Risks / Trade-offs

- [Tailscale observers disagree during control-plane convergence] -> Require a fresh quorum and stability window; keep the current AWS route and report degraded state until agreement.
- [Overlapping local routes appear in table 52] -> Install and verify higher-priority full-prefix main-table rules and test interior addresses, not only prefix boundaries.
- [A former lease holder resumes immediately before an EC2 call] -> Renew before bounded calls, enforce a danger window, journal intent, read back every route, and continuously reconcile; document that EC2 lacks strict fencing.
- [DynamoDB Region is unavailable] -> Fail closed without route mutation; initial controller availability is multi-AZ, not multi-Region.
- [Tailscale automatically returns to an older preferred router] -> Apply the longer failback stability window and cooldown before following the new primary; do not force ownership independently.
- [A stability window increases packet loss during real failure] -> Publish detection and convergence separately and tune only from protected evidence without weakening quorum.
- [Terraform reverts a legitimate dynamic target] -> Make controller-owned route targets an explicit lifecycle boundary and validate route shape separately from current ENI ownership.
- [Embedded tsnet substantially increases artifact size and dependency surface] -> Pin one reviewed Tailscale version, keep it out of the packet-target import graph, build statically, and test reproducibility and vulnerability updates separately.
- [Applications assume transparent continuity] -> Publish the retry contract and test new-flow recovery plus reference retry/dedup behavior under injected route interruption.

## Migration Plan

1. Deploy the DynamoDB table, read-only controller IAM, three controller replicas, and Tailnet observer identities while the protected runner remains the only writer.
2. Configure all routers to advertise the complete exact local prefix set and add full-prefix local-main policy rules; verify native Tailscale owner election and source-preserving paths without granting controller route writes.
3. Generate and review the immutable controller topology document and persist its hash in quiescent domain records.
4. Grant exact EC2 route mutation permission to the controller role, mark dynamic route targets controller-owned in Terraform, and disable direct route mutation in the acceptance runner.
5. Split route-graph deployment/cleanup credentials from a route-denied acceptance-observer session, perform an ownership-checked handoff, then run protected live replica/router loss, recovery, failback, and cleanup. Retain separately labeled deterministic integration evidence for disagreement, stale fences, ambiguous responses, and exact crash checkpoints.
6. Enable autonomous reconciliation one domain at a time, then expand after measured SLO review.
7. Roll back by disabling controller mutation, waiting for all leases to expire, reconciling every domain to a reviewed stable owner, restoring Terraform route ownership, and removing overlapping advertisements only after route and Tailnet state agree.

## Open Questions

- A future multi-Region controller requires either DynamoDB multi-Region strong consistency in supported Regions or a separately operated quorum store; ordinary eventually consistent Global Tables are not a lock.
- Strict EC2 stale-writer fencing requires a serialized downstream actuator if bounded lease fencing and reconciliation are insufficient for the production threat model.
