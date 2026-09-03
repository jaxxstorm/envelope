## 1. Packet-Turnaround Target Contract

- [x] 1.1 Revise topology and runtime configuration version 2 in place for packet turnaround and separated transport routers; reject directional-lane fields and obsolete draft-v2 target CIDR, TUN, Tailscale, and host-routing fields before mutation, with no compatibility parser or version 3.
- [x] 1.2 Correct CLI help, service rendering, metrics names, health/debug schemas, and operator surfaces to require normal-path packet-scoped AWS GENEVE return and prohibit target inner forwarding.
- [x] 1.3 Restore only the target privileges and dependencies required for AWS-compliant raw IPv4/UDP GENEVE return, and remove target TUN creation, Tailscale bootstrap, host forwarding, routing-manager, firewall-transit, and MSS dependencies.
- [x] 1.4 Replace configuration and API contract tests with version-2 packet-turnaround, obsolete-draft rejection, no-compatibility, target-isolation, and least-privilege cases.

## 2. Packet-Scoped GENEVE Datapath

- [x] 2.1 Refactor the target datapath so every valid AWS GENEVE ingress packet is immediately returned exactly once with the byte-identical inner packet, VNI, protocol metadata, ordered options and cookie, and that packet's AWS outer tuple.
- [x] 2.2 Implement packet-scoped return identity with no inner-flow key or cross-packet install, lookup, refresh, collision, capacity, timeout, eviction, persistence, or restart recovery; ensure concurrent identical inner tuples remain independent.
- [x] 2.3 Remove normal-path TUN reads/writes and all target direct forwarding to Tailscale or the VPC; restore compliant raw send checksums and tuple handling without restoring the old return-context table.
- [x] 2.4 Update health, debug output, and Prometheus metrics to prove receive, validation, and packet-scoped send readiness and to remove context, TUN, target-routing, and target-Tailscale liveness conditions.
- [x] 2.5 Replace deterministic unit, fixture, codec, and privileged packet-capture tests to assert exactly one immediate return, inner-byte/VNI/ordered-option/cookie/AWS-tuple fidelity, malformed no-send behavior, concurrent packet isolation, and restart without restored state.

## 3. Host and Local Integration Routing

- [x] 3.1 Remove Envelope target routing-manager and co-resident Tailscale behavior; move local/remote full-prefix host-route validation to dedicated bidirectional transport routers and assert that targets have no inner route path.
- [x] 3.2 Replace ingress-router readiness with transport-router readiness for both underlay-to-Tailscale and Tailscale-to-underlay directions, exact local advertisements, accepted remote routes, no NAT, disabled source/destination checks, ENI identity, and local-site routing through the destination-prefix-AZ GWLBE.
- [x] 3.3 Rebuild the secretless Headscale/Linux integration harness with separate packet-turnaround targets, GWLBE post-inspection route domains, bidirectional transport routers, and simultaneous cold initiation in both directions.
- [x] 3.4 Re-run and correct loop/bypass negatives, source preservation, forwarding firewall, TCP MSS, UDP, ICMP, inner-fragment opacity, and no-target-forwarding integration coverage for every revised transit direction.

## 4. Multi-AZ AWS Topology

- [x] 4.1 Revise the unaccepted version-2 Terraform inputs and plan validation in place for enabled AZs, disjoint site CIDRs, stateless target fleets, bidirectional transport-router fleets and ENIs, initial route selections, and approved HA/cost/failover bounds, with no compatibility resources.
- [x] 4.2 Provision distinct workload, transport-router, GWLBE, target, and management route domains; assert workload remote routes to the source-workload-AZ GWLBE, every transport local prefix route to the destination-workload-AZ GWLBE, GWLBE local delivery, GWLBE remote routes to one same-site transport-router ENI, and no target inner routes.
- [x] 4.3 Provision a GWLBE and healthy-capable Envelope target path in every enabled AZ, with target-group registration and cross-zone behavior explicitly reviewed.
- [x] 4.4 Convert each site's two AZ-spread Tailscale nodes into bidirectional no-NAT transport routers with distinct eligible ENIs, exact local advertisements, accepted remote routes, and no Envelope target Tailscale membership or route-advertiser role.
- [x] 4.5 Replace Terraform static, plan-shape, fresh-plan, no-drift, destroy, cost-profile, and negative bypass/loop tests for GWLBE post-inspection routing, authorized same-site ENIs, separated roles, and version-2 no-compatibility invariants.

## 5. Protected Lifecycle and HA Evidence

- [x] 5.1 Correct protected preflight and readiness for version-2 packet-turnaround target health, exact GWLBE pre/post-inspection route domains, transport-router bidirectional readiness, eligible ENIs, initial route selections, Tailnet policy, and absence of target inner forwarding.
- [x] 5.2 Add target quiesce, AWS deregistration/drain observation, process restart, and instance replacement lifecycle operations with ownership-safe diagnostics and cleanup.
- [x] 5.3 Replace ingress-only router failure handling with graceful and abrupt transport-router exercises plus protected-runner ownership-checked, allowlisted, bounded GWLBE ENI route replacement and unconditional verified restoration; targets and routers receive no route-mutation authority.
- [x] 5.4 Revise the unaccepted protected evidence schema and verifier to require packet-scoped inner/VNI/options/cookie/AWS-tuple fidelity, symmetric initiation, both site GWLB traversals, selected endpoint/target/router/ENI identities, target recovery, Tailnet selection, ENI route transitions and restoration, transport outcomes, and residual audit.
- [x] 5.5 Replace unit tests for fail-closed preflight, target lifecycle, route-mutation authorization and bounds, partial mutation rollback, timeout/interruption restoration, separated control-plane evidence, redaction/schema validation, and cleanup failure precedence.

## 6. Live Acceptance and Documentation

- [x] 6.1 Correct the Docsify onboarding pages, root README, AWS appliance runbook, and two-region E2E runbook to remove target direct-forwarding claims and describe packet turnaround, GWLBE route-table delivery, bidirectional no-NAT transport routers, runner-owned ENI failover, retained version 2, HA limits, and cost.
- [x] 6.2 Add static documentation checks that reject directional-lane production claims, raw credentials, obsolete configuration examples, and hitless-continuity claims.
- [x] 6.3 Run the corrected repository unit, race, vet, static, Terraform, separated-role local integration, packet-capture, secret-scan, and strict OpenSpec validation suites after all reopened architecture work passes.
- [ ] 6.4 Execute the approved protected AWS acceptance run with a fresh configuration and expiry, verify the versioned evidence, perform owned cleanup, and record observed recovery and cost results; failed runs `ha25`-`ha51` supplied route, readiness, budget, inspector, labeled-metric, target-health timing, stream-framing, post-mutation window, bounded SSM-output, independent target-hash, concurrent-listener, installer-ordering, provider-reflected NAT-route validation, failed-journal cleanup recovery, established-flow pinning/outcome-model, omitted-false Tailnet observer-schema, durable lifecycle-proxy, unsupported SSM option, Bash dynamic-scope, delayed transport startup, transient SSM inspection, destination-endpoint symmetry, separated mutation/recovery deadline, continuity observation-tail, abrupt-restart DNS-health, contiguous-loss endpoint-attribution, and temporal replacement-target evidence with eventual zero residuals, but did not satisfy acceptance. For `ha36` and `ha40`, ownership-checked recovery removed all run resources after the original cleanup failed; `ha45`-`ha51` cleanup each passed in one attempt with `final_residual_count` 0. The retained schema-3 bundles through `ha51` remain failed.

## 7. Live-Discovered Source-Prefix Ownership Correction

- [x] 7.1 Reconcile the proposal, design, and delta specs with `ha24`: source-preserving no-SNAT traffic requires deterministic per-prefix Tailnet ownership coupled to GWLBE egress, while retaining configuration version 2 and existing topology inputs.
- [x] 7.2 Derive disjoint per-AZ initial advertisements from workload subnets and initial GWLBE selections; update Terraform, output parsing, protected readiness, reciprocal stable-node ownership validation, and evidence while every router remains capable of all site prefixes.
- [x] 7.3 Extend the CAS-protected route transaction to transfer the failed router's exact Tailnet advertisement and affected GWLBE routes together, validate every immutable binding before successor CAS, settle ambiguous results, restore both control planes, and retain resumable cleanup authority through terminal and backend handoff.
- [x] 7.4 Add deterministic mismatch, takeover, interruption, runner-loss, restoration, and source-preservation regressions across Python, Terraform, and the separated-role Headscale integration.
- [x] 7.5 Correct operator documentation and rerun the complete unit, race, vet, static, Terraform, privileged/local integration, secret-scan, and strict OpenSpec gates before another protected run.

## 8. Live-Discovered Destination Endpoint Symmetry Correction

- [x] 8.1 Reconcile the proposal, design, and delta specs with `ha46`: every transport route table must map each local destination prefix to that workload prefix's AZ GWLBE, independent of the receiving router AZ, while workload source-AZ routing and GWLBE source-prefix owner ENI coupling remain unchanged.
- [x] 8.2 Update Terraform, saved-plan validation, protected readiness, probe identity, passing evidence validation, and deterministic regressions for destination-prefix-anchored GWLBE routes and cross-AZ transport takeover.
- [x] 8.3 Correct operator documentation and rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run; retain the unchanged prior privileged Linux coverage because the one-prefix local harness cannot distinguish the AWS per-prefix endpoint map.

## 9. Live-Discovered Recovery Deadline Correction

- [x] 9.1 Reconcile the proposal, design, delta specs, and operator documentation with `ha47`: route ownership and ENI convergence use `mutation_timeout_seconds`, while the sequential full TCP/UDP alternate-path proofs jointly use the separately reserved `recovery_timeout_seconds`.
- [x] 9.2 Start the post-convergence recovery deadline independently from the mutation deadline and add deterministic coverage proving a probe can complete inside recovery after the mutation clock would have expired, without weakening unconditional restoration.
- [x] 9.3 Rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run.

## 10. Live-Discovered Continuity Observation Correction

- [x] 10.1 Reconcile the proposal, design, delta specs, and operator documentation with `ha48`: the complete durable transaction reservation remains a command watchdog, while paired instance and transport-router TCP/UDP observations run concurrently around one shared mutation and end prospectively after at least 20 successful sends and a runner-requested final post-mutation send without post-hoc marker truncation.
- [x] 10.2 Add token-bound client and receiver completion signals, validate actual successful-send completion timestamps internally and retain exact counts in schema evidence, preserve strict out-of-interval rejection, reject short UDP writes, fail closed on ambiguous SSM ownership, include the non-route critical path in active admission, preserve the full transaction reservation plus paired-control headroom, leave target-process streams unchanged, and add deterministic orchestration and embedded-agent coverage.
- [x] 10.3 Rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run.

## 11. Live-Discovered Transport DNS Readiness Correction

- [x] 11.1 Reconcile the proposal, design, delta specs, task history, and operator documentation with `ha49`: transport routers use VPC DNS, keep Tailnet DNS acceptance disabled, and remain ineligible while the pinned Tailscale backend reports any health condition.
- [x] 11.2 Set `accept-dns=false` during transport-router bootstrap and every restoration, verify the live `CorpDNS` preference in host-side advertisement checks and both protected readiness layers, retain strict empty-health validation, and add deterministic Terraform, readiness, and restoration coverage.
- [x] 11.3 Rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run.

## 12. Live-Discovered Continuity Episode Attribution Correction

- [x] 12.1 Reconcile the proposal, design, delta spec, task history, and operator documentation with `ha50`: a bounded contiguous interruption is attributed by its first missing successful send, may retain later missing sends across the sampled mutation endpoint, and does not permit a distinct out-of-interval loss episode.
- [x] 12.2 Make resumed analysis use the same onset attribution as right-censored analysis without widening timestamps or discarding attempts, and add exact `ha50` crossing-window plus separately starting post-mutation regressions.
- [x] 12.3 Rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run.

## 13. Live-Discovered Temporal Target Evidence Correction

- [x] 13.1 Reconcile the proposal, design, delta spec, task history, and operator documentation with `ha51`: passing evidence keeps the initial topology for pre-replacement observations and derives one exact target substitution for later transport-router paths.
- [x] 13.2 Retain the replacement AZ, bind the successor to the removed target's exact site, AZ, and target group, require one regional target group per site in the same AWS account, reject global target/router identity collisions and string coercion, refresh the victim's process generation immediately before replacement, remove the victim from post-replacement eligibility, and add temporal-topology, premature-use, unknown-target, metadata-tampering, and recovery-order regressions.
- [x] 13.3 Rerun all macOS-available unit, race, vet, static, Terraform, fixture, source-only systemd, secret-scan, and strict OpenSpec gates before another protected run.
