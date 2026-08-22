## 1. Symmetric Target Contract

- [x] 1.1 Replace directional-lane configuration with a versioned symmetric target configuration containing disjoint local-site and remote-site CIDRs; reject legacy lane and return-context fields before host mutation.
- [x] 1.2 Update CLI help, service rendering, metrics names, health/debug schemas, and operator documentation for symmetric inline targets and the removal of normal-path raw GENEVE egress.
- [x] 1.3 Remove no-longer-needed target service privileges and configuration dependencies, while preserving only capabilities required for TUN injection and verified host forwarding.
- [x] 1.4 Add configuration and API contract tests for valid symmetric roles, disjointness failures, and legacy configuration rejection.

## 2. Symmetric GENEVE Datapath

- [x] 2.1 Refactor the datapath so valid AWS GENEVE ingress is fully validated and injected into `envelope0` without installing or reading a per-flow return context.
- [x] 2.2 Remove normal-path raw IPv4/UDP GENEVE return emission, return-identity conflict handling, and context capacity/timeout lifecycle from the symmetric target runtime.
- [x] 2.3 Detect and drop unexpected TUN egress in symmetric mode with bounded metrics and logs, and ensure it cannot emit a GENEVE packet.
- [x] 2.4 Update health and Prometheus metrics to prove receiver and TUN-injection readiness without context-based liveness conditions.
- [x] 2.5 Add deterministic unit, codec, and privileged component tests for bidirectional packets delivered independently to different healthy targets, restart without restored state, and no target-originated GENEVE egress.

## 3. Host and Local Integration Routing

- [x] 3.1 Replace managed `tailscale0`-to-`envelope0` return rules with full-prefix validation that `envelope0` local-site traffic reaches the post-inspection underlay path and remote-site traffic reaches `tailscale0`.
- [x] 3.2 Add a separate ingress-router readiness checker that verifies Running Tailscale, exact approved local-site route advertisements without SNAT, and effective VPC routing to the local GWLBE.
- [x] 3.3 Extend the secretless Headscale/Linux integration harness to model two site CIDRs, ingress routers, separate target route domains, and simultaneous cold initiation in both directions.
- [x] 3.4 Add loop-negative, source-preservation, TCP MSS, UDP, and ICMP integration coverage for all symmetric forwarding directions.

## 4. Multi-AZ AWS Topology

- [x] 4.1 Replace directional-lane Terraform inputs and plan validation with a versioned symmetric two-site schema containing enabled AZs, local/remote site CIDRs, target fleet, ingress-router fleet, and approved HA/cost thresholds.
- [x] 4.2 Provision distinct workload, Tailnet-ingress, GWLBE, target, and management route domains; assert exact endpoint routes for pre-inspection traffic and direct post-inspection target delivery.
- [x] 4.3 Provision a GWLBE and healthy-capable Envelope target path in every enabled AZ, with target-group registration and cross-zone behavior explicitly reviewed.
- [x] 4.4 Provision at least two AZ-spread Tailscale ingress routers per site that advertise the exact same local-site routes without subnet-route SNAT; prevent targets from being the required route advertisers.
- [x] 4.5 Extend Terraform static, plan-shape, fresh-plan, no-drift, destroy, cost-profile, and negative route-loop tests for the symmetric topology.

## 5. Protected Lifecycle and HA Evidence

- [x] 5.1 Replace directional protected preflight and readiness gates with symmetric configuration validation, route-domain checks, target fleet health, ingress-router readiness, and Tailnet policy validation.
- [x] 5.2 Add target quiesce, AWS deregistration/drain observation, process restart, and instance replacement lifecycle operations with ownership-safe diagnostics and cleanup.
- [x] 5.3 Add ingress-router graceful and abrupt failure operations, identify the selected router/target for each probe, and collect bounded recovery timing without credentials or raw captures.
- [x] 5.4 Version the protected evidence schema and verifier to require bidirectional GWLBE/GWLB traversal, alternate-target/alternate-router new-flow recovery, established TCP outcome, UDP loss, health transitions, and residual audit results.
- [x] 5.5 Add unit tests for lifecycle state transitions, fail-closed preflight, evidence redaction/schema validation, and failure cleanup paths.

## 6. Live Acceptance and Documentation

- [x] 6.1 Update the Docsify onboarding pages, root README, AWS appliance runbook, and two-region E2E runbook to describe symmetric site-to-site forwarding, multi-AZ topology, HA limits, cost implications, and the breaking migration.
- [x] 6.2 Add static documentation checks that reject directional-lane production claims, raw credentials, obsolete configuration examples, and hitless-continuity claims.
- [x] 6.3 Run repository unit, race, vet, static, Terraform, local integration, secret-scan, and strict OpenSpec validation.
- [ ] 6.4 Execute the approved protected AWS acceptance run with a fresh configuration and expiry, verify the versioned evidence, perform owned cleanup, and record observed recovery and cost results.
