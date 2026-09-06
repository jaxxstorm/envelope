## 1. Controller Contract And Configuration

- [x] 1.1 Add the standalone controller package and command structure without importing it from the packet target.
- [x] 1.2 Add strict schema-versioned topology and process configuration with canonical hashing, secret indirection, bounded timing validation, and unknown-field rejection.
- [x] 1.3 Add validation tests for overlapping authority, duplicate identities, route-domain isolation, timing safety, and deterministic hashes.
- [x] 1.4 Pin reviewed AWS SDK and Tailscale dependencies compatible with the repository toolchain and static Linux artifacts.

## 2. Durable State And Leadership

- [x] 2.1 Define failover-domain state, phases, immutable authority, observations, route progress, errors, and fencing terms without SDK-specific types.
- [x] 2.2 Define narrow lease, observation, and domain-store interfaces plus deterministic in-memory implementations and a fake clock.
- [x] 2.3 Implement DynamoDB strongly consistent reads, conditional fresh acquisition, record-version lease takeover, renewal, fenced state CAS, observation publication, and bounded observation listing.
- [x] 2.4 Test competing leaders, pause past lease, stale-fence rejection, topology-hash mismatch, monotonic progress, and store ambiguity.

## 3. Tailnet Observation And Quorum

- [x] 3.1 Embed a pinned `tsnet` observer with private persistent state, bounded startup, stable-node identity extraction, health redaction, and clean shutdown.
- [x] 3.2 Add read-only Tailscale Admin API validation for exact advertised and enabled route sets without dynamic router mutation.
- [x] 3.3 Implement fresh multi-replica observation quorum, owner stability windows, failover/failback differentiation, and disagreement reasons.
- [x] 3.4 Test sole-owner, offline-owner, unknown-owner, stale-observation, split-observer, and automatic-return cases.

## 4. AWS Eligibility And Route Control

- [x] 4.1 Implement EC2 instance, status-check, ENI, route-table, exact GWLBE subnet/association identity, VPC, Region, AZ, prefix, origin, state, and allowlisted-target validation.
- [x] 4.2 Implement bounded `ReplaceRoute` with pre-call lease safety, authoritative convergence polling, ambiguous-call settlement, and redacted errors.
- [x] 4.3 Test healthy and ineligible candidates, unauthorized current targets, partial progress, timeout-after-commit, oscillation, and cancellation.

## 5. Production Reconciliation

- [x] 5.1 Implement one reconciliation state machine per isolated source-prefix route domain.
- [x] 5.2 Persist intent and ordered route progress before and after every external action, recover every phase, and retain alternate ownership as stable state.
- [x] 5.3 Implement shorter failover stability, longer failback stability, cooldown, lease danger windows, and fail-closed degraded handling.
- [x] 5.4 Test successful failover/failback, leader loss at every checkpoint, stale leader resumption, observer disagreement, cloud ineligibility, and durable restart.

## 6. Service Lifecycle And Observability

- [x] 6.1 Add controller observer, lease, and reconcile loops with bounded concurrency, signal cancellation, and clean shutdown.
- [x] 6.2 Add a private Prometheus registry and `/healthz` and `/readyz` endpoints for replica, lease, quorum, owner, route, phase, duration, ambiguity, failover/failback, and API status.
- [x] 6.3 Add the `envelope-controller` CLI, version metadata, Zap production logging, secret-safe startup output, and dry-run/read-only mode.
- [x] 6.4 Test follower readiness, leader readiness, degraded health, HTTP shutdown, cancellation, and metric registration isolation.

## 7. Topology And Deployment

- [x] 7.1 Change the production transport topology to complete overlapping exact-prefix advertisements and higher-priority full-prefix local-main routing, with static and integration tests.
- [x] 7.2 Add Terraform for the encrypted DynamoDB authority, PITR/deletion protection, controller IAM, exact route scope, observer secret references, multi-AZ controller placement inputs, and alarms.
- [x] 7.3 Make dynamic GWLBE route targets an explicit controller ownership boundary while Terraform retains and validates exact table, GWLBE subnet association, VPC, prefix, and eligible-target shape.
- [x] 7.4 Build a distinct reproducible static controller artifact and add a hardened systemd service with no packet or network-administration capabilities.
- [x] 7.5 Add the approved read-only Go router attestor, authenticated exact-instance/ENI/stable-node/topology binding, freshness and replay protection, immutable runtime, and controller eligibility consumption without shell/Python/SSM or router route-mutation authority.
- [x] 7.6 Add the separate Go lifecycle command with route-denied initialization from actual route/owner agreement, independent topology-bound activation, locked health-gated serialized rollout, and quiescent migration that preserves active journals.

## 8. Conformance And Application Recovery

- [x] 8.1 Add a Go integration harness with fake Tailnet/AWS/store adapters that injects router loss and proves fresh TCP/UDP retry after route convergence.
- [x] 8.2 Add duplicate-leader, lease-loss, stale writer, ambiguous API, crash checkpoint, ownership flap, and automatic failback conformance scenarios.
- [x] 8.3 Convert protected acceptance to real router/leader failure and recovery without runtime mechanisms or direct route mutation; split deployment/cleanup from route-denied observer credentials with ownership-checked handoff, and explicitly separate simulated disagreement/stale-fence/ambiguous-response evidence from live evidence.
- [x] 8.4 Add application guidance and executable reference tests for TCP reconnect/idempotency and UDP IDs, acknowledgement, deduplication, and bounded retransmission.

## 9. Documentation And Verification

- [x] 9.1 Document controller architecture, deployment, IAM, topology schema, health policy, operations, failback, degraded recovery, rollback, and regional authority limits.
- [x] 9.2 Publish explicit detection, ownership, route-convergence, new-flow recovery, and permitted established-flow/UDP-loss SLO boundaries.
- [x] 9.3 Update diagrams and onboarding to distinguish packet targets, transport routers, native Tailscale HA, controller replicas, and durable state.
- [x] 9.4 Run Go unit/race/vet, controller integration, documentation, Terraform, artifact reproducibility, secret scan, and strict OpenSpec validation.
- [ ] 9.5 Execute a protected clean deployment with controller-owned router failure, leader failure, failback, new-flow retry, retained evidence, and zero-residual cleanup.

## Approved Architecture Implementation Checkpoint

7.5 is implemented: native bounded rtnetlink/UAPI inspection, exact IPv4/IPv6 legacy firewall/no-NAT/MSS validation, empty nftables enforcement, full-prefix host/VPC routing and destination workload/GWLBE AZ proof, repeated kernel/cloud checks, pinned local Tailscale route/peer validation, and IMDS identity binding. Signed reports require both topology and full collector configuration digests. Appliance bootstrap installs the immutable binary; native boot-only enrollment verifies per-instance version-1 key/config bindings, installs sealed files atomically, and exits. The new router-attestor Terraform root grants exact source-instance config/seed access (including an explicit shared-role deny) without reading seed values into state. CAP_NET_ADMIN is explicitly documented for inspection; CAP_NET_RAW is not required. Unsupported input still fails closed. Unit/adversarial/fuzz tests pass. An executable isolated Linux kernel integration check and CI step are supplied and cross-compiled for both architectures, but were not executed from Darwin; this is not live evidence.

7.6 is implemented within the documented bounded scope: initialization, activation, deactivation, single-replica saved-plan rollout, and same-table/existing-domain-set quiescent migration. A separate non-expiring IAM-isolated lock is checked in atomic domain rewrites; paused controller writers are fenced by activation checks in both stores, not only the engine. Rollout verifies unchanged healthy peers, termination of the old instance, fresh replacement observations, stable journals, and route/owner agreement. Failure or ambiguity retains locks and journals. Terraform provisions explicit caller/ExternalId trust and route-denied lifecycle authority, with optional exact backend/KMS rollout scope. Region/table moves, domain additions/removals, multi-replica or IAM/route-changing plans, and drain bounds of 12 minutes or more fail closed. Both old/new observation and attestation generations are migration prerequisites. Recovery/unlock is deliberately not automatic.

8.3 is complete offline: the workflow separates deployment, observation, quiescence, and cleanup identities and runner groups. Versioned claim/handoff checks, unconditional deployment/lifecycle freezes, cleanup-session cutoff through observer drain, schema-3 live-only evidence, Go-event-derived integration-only receipts, observer-expiry/drain proof, and ordered cleanup are implemented. Cleanup requires two consecutive zero-residual audits; interrupted or uncertain cleanup retains claims. `scripts/test_controller_acceptance_phases.py` exercises actual phase orchestration with mocked external boundaries: exact S3/IAM identities, OIDC and credential isolation, handoff construction, enrollment identities/client subnets, pinned initialization/serialized rollout, raw AWS/HTTP snapshot consumption, router/leader stop/restart, quiescence, failures/interruption across deployment and cleanup, private-state rebasing, backend finalization and bundle consistency. Controller/application outcome fixtures remain offline; they are never published as live evidence. `deploy/terraform/controller-acceptance/README.md` supplies external IAM/environment setup, permission/denial matrices, prerequisite retention boundaries, and an independently approved retained-lock manual recovery procedure without automatic adoption.

9.5 remains unexecuted: no billable AWS/Tailscale execution is approved. Offline verification is not live evidence.

The controller artifact manifest includes four components for both amd64 and arm64: controller, topology tool, deployment lifecycle, and router attestor. Reproducibility tests build all eight static Linux artifacts twice using dirty non-live fixtures. Neither the STS/cloud lifecycle nor native Linux router collection was executed against live infrastructure. Task count is 37/38, with only 9.5 open.

Prior checkpoint gates: Go unit/integration, race, and vet passed; Python discovery passed 626 tests including eight-artifact reproducibility; mocked Terraform passed 29 appliance, 28 controller, and 6 enrollment tests; both parser fuzz targets passed; actionlint, Ruff on changed Python, secret scan, whitespace checks, and all seven strict OpenSpec items passed. The Linux integration executable was cross-compiled for amd64/arm64, not executed on this Darwin host.

Final task-8.3 gates: Go unit/race/vet, an uncached controller integration run, and Python discovery (651 tests, including eight-artifact reproducibility) passed. Mocked Terraform passed 29 appliance, 28 controller, 6 enrollment, and 3 acceptance-role tests. Both parser fuzz targets passed; attestor kernel integration binaries cross-compiled for Linux amd64/arm64 but were not executed on Darwin. Actionlint, Ruff on split modules/updated tests, secret scan, whitespace checks, and all seven strict OpenSpec items passed. Prior broader Ruff reported eight existing issues in `aws_appliance.py` outside this edit (unused import and exact-type comparisons); those remain unchanged. No live AWS/Tailscale operation, workflow execution, commit, push, or `.opencode` edit was performed.
