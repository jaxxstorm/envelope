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
- [x] 3.2 Replace ingress-router readiness with transport-router readiness for both underlay-to-Tailscale and Tailscale-to-underlay directions, exact local advertisements, accepted remote routes, no NAT, disabled source/destination checks, ENI identity, and local-site routing through the same-AZ GWLBE.
- [x] 3.3 Rebuild the secretless Headscale/Linux integration harness with separate packet-turnaround targets, GWLBE post-inspection route domains, bidirectional transport routers, and simultaneous cold initiation in both directions.
- [x] 3.4 Re-run and correct loop/bypass negatives, source preservation, forwarding firewall, TCP MSS, UDP, ICMP, inner-fragment opacity, and no-target-forwarding integration coverage for every revised transit direction.

## 4. Multi-AZ AWS Topology

- [x] 4.1 Revise the unaccepted version-2 Terraform inputs and plan validation in place for enabled AZs, disjoint site CIDRs, stateless target fleets, bidirectional transport-router fleets and ENIs, initial route selections, and approved HA/cost/failover bounds, with no compatibility resources.
- [x] 4.2 Provision distinct workload, transport-router, GWLBE, target, and management route domains; assert workload remote and transport local pre-inspection routes to same-AZ GWLBE, GWLBE local delivery, GWLBE remote routes to one same-site transport-router ENI, and no target inner routes.
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
- [ ] 6.4 Execute the approved protected AWS acceptance run with a fresh configuration and expiry, verify the versioned evidence, perform owned cleanup, and record observed recovery and cost results; failed runs `ha25`-`ha38` supplied route, readiness, budget, inspector, labeled-metric, target-health timing, stream-framing, post-mutation window, bounded SSM-output, independent target-hash, concurrent-listener, installer-ordering, provider-reflected NAT-route validation, failed-journal cleanup recovery, established-flow pinning/outcome-model, and omitted-false Tailnet observer-schema evidence with eventual zero residuals, but did not satisfy acceptance. For `ha36`, ownership-checked recovery removed all run resources after the original cleanup failed; `ha37` and `ha38` cleanup each passed in one attempt with `final_residual_count` 0. All three retained schema-3 symmetric evidence bundles remain failed.

## 7. Live-Discovered Source-Prefix Ownership Correction

- [x] 7.1 Reconcile the proposal, design, and delta specs with `ha24`: source-preserving no-SNAT traffic requires deterministic per-prefix Tailnet ownership coupled to GWLBE egress, while retaining configuration version 2 and existing topology inputs.
- [x] 7.2 Derive disjoint per-AZ initial advertisements from workload subnets and initial GWLBE selections; update Terraform, output parsing, protected readiness, reciprocal stable-node ownership validation, and evidence while every router remains capable of all site prefixes.
- [x] 7.3 Extend the CAS-protected route transaction to transfer the failed router's exact Tailnet advertisement and affected GWLBE routes together, settle ambiguous results, and restore both control planes before terminal lifecycle or cleanup handoff.
- [x] 7.4 Add deterministic mismatch, takeover, interruption, runner-loss, restoration, and source-preservation regressions across Python, Terraform, and the separated-role Headscale integration.
- [x] 7.5 Correct operator documentation and rerun the complete unit, race, vet, static, Terraform, privileged/local integration, secret-scan, and strict OpenSpec gates before another protected run.
