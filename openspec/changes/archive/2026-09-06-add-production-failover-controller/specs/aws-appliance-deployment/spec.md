## MODIFIED Requirements

### Requirement: Redundant Tailscale transport routers
The production deployment SHALL create at least two independent Tailscale transport routers per site, spread across enabled AZs. Every router SHALL advertise and have enabled the same complete set of exact local workload prefixes for Tailscale native failover. Every router SHALL accept all exact remote-site routes, disable subnet-route SNAT and Tailnet DNS acceptance, preserve the VPC resolver and workload source addresses, and forward in both site-transit directions. Readiness SHALL verify healthy backend and peers, exact advertisements, sole per-prefix primary ownership from the controller observers, higher-priority full-prefix local-main policy, effective destination-prefix GWLBE routing, and distinct eligible ENIs. Envelope targets SHALL not join Tailscale or act as route advertisers.

#### Scenario: Redundant local-site advertisements
- **WHEN** a production site is deployed successfully
- **THEN** at least two ready AZ-spread transport routers each advertise every exact local-site prefix without NAT and expose distinct controller-eligible primary ENIs

#### Scenario: Local prefix uses the underlay
- **WHEN** a packet on any transport router targets a local-site prefix
- **THEN** the higher-priority full-prefix rule selects `main`, the VPC underlay, and the destination workload prefix's AZ GWLBE even if table 52 contains an overlapping local route

#### Scenario: Incomplete router contract
- **WHEN** one router advertises a broader, narrower, or incomplete local prefix set, lacks a remote route, enables SNAT or Tailnet DNS acceptance, reports a Tailscale health condition, lacks the local-main policy, or cannot forward one direction
- **THEN** production readiness excludes that router and the controller cannot select its ENI

#### Scenario: Local prefix contains the VPC resolver
- **WHEN** a configured local-site prefix contains the VPC DNS resolver address and cannot satisfy deterministic full-prefix routing
- **THEN** configuration validation fails before AWS resources are created

## ADDED Requirements

### Requirement: Standalone controller deployment boundary
The production deployment SHALL run at least three `envelope-controller` replicas across independent failure domains outside Envelope targets and transport routers. It SHALL provide an encrypted strongly consistent DynamoDB authority with point-in-time recovery and deletion protection, persistent private state for each embedded Tailnet observer identity, resilient management egress, and a dedicated controller IAM role. The role SHALL be scoped to the configured table and required read APIs plus EC2 route replacement for only the configured route tables; target and router roles SHALL retain no route-mutation permission.

#### Scenario: One controller replica fails
- **WHEN** a replica or its availability zone becomes unavailable
- **THEN** another replica can acquire a higher fenced lease after the prior record version remains unchanged for one lease duration and continue from durable state

#### Scenario: Controller role is overprivileged
- **WHEN** a plan grants controller packet privileges, grants target or router route mutation, or permits controller mutation outside configured route tables
- **THEN** static policy validation rejects the deployment

#### Scenario: Controller Region is unavailable
- **WHEN** the regional strongly consistent authority cannot be reached
- **THEN** replicas fail closed and do not claim multi-Region control-plane availability

### Requirement: Controller-owned dynamic route targets
Terraform SHALL own each GWLBE route's table, exact GWLBE subnet and explicit route-table association identities, site VPC, exact destination prefix, and eligible target set while treating the current ENI target as controller-owned dynamic state after handoff. Subnet and association identities SHALL be unique across domains. A saved plan SHALL resolve the subnet and table in their configured Region, require both to belong to the site's VPC, and require exactly one non-main table association matching the configured subnet, association ID, and table ID. It SHALL reject route or association deletion, association replacement, prefix changes, unknown eligible ENIs, or a topology-hash mismatch but SHALL NOT revert a legitimate controller-selected ENI merely because it differs from the preferred baseline.

#### Scenario: Terraform runs after failover
- **WHEN** the controller has durably converged a route domain to an eligible alternate
- **THEN** a subsequent plan preserves that target while validating the route shape and controller authority

#### Scenario: Route target is unknown
- **WHEN** an exact route points to an ENI outside its configured same-site candidate set
- **THEN** controller readiness fails and the plan or reconciliation reports the unauthorized target without silently adopting it

#### Scenario: GWLBE association drifts
- **WHEN** a managed route table is main, is associated with a different subnet or association ID, has multiple active non-main associations, or its table or subnet is outside the configured site VPC
- **THEN** Terraform planning and controller reconciliation fail closed without adopting the changed association or mutating a route

### Requirement: Production controller conformance evidence
Protected acceptance SHALL inject controller-relevant failures while the production Go controller, rather than the test runner, owns route reconciliation. Live evidence SHALL cover observer quorum, lease renewal and real leader loss/recovery, real router failure/recovery, stable native Tailscale owner selection, exact AWS route convergence, durable alternate state, stability-gated failback, new TCP and UDP flow recovery, established-flow outcome, and cleanup. Deterministic observer disagreement, stale-fence rejection, ambiguous API settlement, and precise crash checkpoints MAY remain in the integration harness and SHALL be labeled simulated, not live capabilities or live receipts. The controller SHALL remain independent of the acceptance runner and its run files.

The route graph deployment and cleanup identity SHALL be distinct from the acceptance-observer identity. Before fault injection, the deployment identity SHALL be removed and the acceptance identity SHALL have an explicit deny for every EC2 route and route-table-association mutation API. A local command ledger SHALL NOT substitute for that credential boundary. Until the split identity and ownership-checked handoff exist, protected controller conformance SHALL fail before backend claim acquisition or resource creation.

Run-owned SecureString creation, deletion, and residual audit SHALL reconcile bounded stable invocation-tagged visibility or stable absence and SHALL fail cleanup while the result is uncertain. A lost conditional backend-claim response SHALL authorize cleanup only when the immediately attempted invocation reads one exact object version whose complete body matches its claim; a later invocation SHALL NOT adopt that claim. Fault restoration SHALL retain stop intent through EC2 transitional states until repeated exact reads prove the instance running. Readiness and failure bodies SHALL be reduced to allowlisted or redacted values before truncation, and evidence scanning SHALL include every Tailnet, controller, and temporary AWS session credential. Local protected run data SHALL be removed only after successful evidence upload and an independent check of the exact cleanup sequence, every completion flag, ordered zero-residual audits, backend finalization, and an empty error set, or an exact not-required result before claim acquisition.

#### Scenario: Router fails under controller ownership
- **WHEN** protected acceptance makes the selected transport router unavailable
- **THEN** Tailscale selects an eligible exact-prefix alternate, the controller quorum converges the corresponding GWLBE routes, and fresh TCP and UDP retries succeed with measured recovery and loss

#### Scenario: Leader exits during route progress
- **WHEN** the lease holder exits after persisting intent or after an ambiguous route call
- **THEN** a successor with a higher fence settles observed state and completes safe reconciliation without replaying an unjournaled mutation

#### Scenario: Established flow does not resume
- **WHEN** an established TCP or UDP tuple remains interrupted after route convergence
- **THEN** evidence may record that bounded outcome only when a fresh retry succeeds and no hitless or lossless claim is emitted

#### Scenario: Mutable cleanup outcome is ambiguous
- **WHEN** a SecureString or conditional backend-claim operation loses its response, EC2 remains transitional during fault restoration, or cleanup evidence contradicts its completion status
- **THEN** the runner reconciles only invocation-bound state within its cleanup budget and retains forensic state rather than reporting not-required or complete cleanup on uncertainty
