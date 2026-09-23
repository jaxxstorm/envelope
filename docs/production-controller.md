# Production Failover Controller

> **Status:** The controller implementation and offline conformance work are complete. Its live AWS/Tailscale acceptance remains unapproved and unexecuted. See [Controller E2E Acceptance](developer/controller-e2e-acceptance.md) for the protected evidence boundary.

## Runtime Boundary

`envelope-controller` is a standalone control-plane process. Run at least three disposable replicas in independent failure domains, outside Envelope packet-target and Tailscale transport-router instances. Packet targets remain stateless GWLB packet-turnaround services; transport routers remain no-NAT forwarding hosts. Neither role has EC2 route-mutation authority.

Each replica combines a pinned `tsnet` observer with private persistent state, encrypted strongly consistent DynamoDB state, cloud eligibility inspection, and exact GWLBE route readback. DynamoDB conditional writes, record versions, document revisions, and monotonically increasing fencing terms provide regional authority; the controller does not use embedded Raft. Observation TTL removes stale observations only and never decides lease correctness.

The approved runtime consists of the controller binary, immutable topology, AWS workload identity, Tailnet credential references, private observer state, and a read-only Go router attestor. It does not use repository test scripts, Python or shell orchestration, SSM, or a router-side control agent. The attestor exposes no mutation API and does not change forwarding, advertisements, or AWS routes.

## Architecture

```text
                               regional control authority
                       +--------------------------------+
                       | encrypted DynamoDB             |
                       | lease, fence, domain journal   |
                       | bounded observer snapshots     |
                       +---------------+----------------+
                                       ^
                      conditional writes | strongly consistent reads
                                       |
 +------------------- controller replicas --------------------+
 | embedded tsnet observer + reconciler, outside data-plane    |
 +-------------------------------+-----------------------------+
                                 |
              read-only Tailnet ownership and scoped EC2 route read/write
                                 |
 workload -> GWLBE -> GWLB -> Envelope target -> GWLBE -> owner router ENI
```

The controller is not in the packet path. Losing all replicas leaves current AWS route targets and Tailscale advertisements in place, but safely aligned automatic routing cannot resume until durable authority and observer quorum return.

## Ownership And Route Model

Production routers continuously advertise overlapping exact local workload prefixes. Native Tailscale HA selects the sole `PrimaryRoutes` owner; the controller follows that owner and never changes router advertisements, route approvals, or router preferences.

A failover domain contains one source workload prefix, one exact GWLBE route table and association, immutable remote destination prefixes, and an allowlisted set of same-site router identities and primary ENIs. The selected owner and every dynamic route target must agree. Domains can reconcile concurrently only when their route-table and destination-prefix authority is disjoint. Active replicas support at most 32 domains, reserving one worker per domain.

## Reconciliation

Before changing a route, the lease holder requires:

1. Strict-majority fresh, topology-matching observer agreement on one stable owner.
2. The configured failover or failback stability window and cooldown.
3. Read-only Tailscale validation, eligible cloud instance and ENI state, fresh router attestation, and the exact GWLBE association.
4. A complete authoritative route snapshot containing only configured exact destinations and eligible ENI targets.

The controller persists intent, fence, desired owner, before-snapshot, and route progress before every external action. It renews its lease before each bounded `ReplaceRoute`, settles ambiguous calls through reads, and returns to `stable` only when every route agrees with the eligible owner. Split ownership, unauthorized targets, oscillation, or uncertain state enters durable fail-closed `degraded` state.

Failover uses the shorter stability window. Automatic failback uses a longer stability window and cooldown. An alternate selected during failover becomes normal durable `stable` state until a new, separately fenced failback transaction completes.

## Operational Endpoints

- `GET /healthz` reports process liveness only.
- `GET /readyz` fails closed for observer, store, freshness, domain, lease, quorum, eligibility, degraded-state, and route-agreement failures. A follower can be ready without holding leadership.
- `GET /metrics` exposes private `envelope_controller_*` observer, state, lease/fence, owner/quorum, route, phase, and bounded API-error metrics.

Bind endpoints to loopback or a private address. Alert on sustained readiness failure, stale observations, missing quorum, lease danger, degraded domains, unauthorized routes, ambiguous calls, API errors, and long phases.

## Lifecycle And Recovery

Deployment tooling initializes inactive journals, activates or deactivates approved domains, performs a locked single-replica rollout, and carries out bounded quiescent migration. Initialization never grants activation. Deployment locks do not expire automatically; an interrupted operation retains its lock and journal for separately reviewed recovery.

Start replicas read-only, establish fresh observation and exact route agreement, then activate only approved domains. Do not edit durable journals, discard fences, change a topology hash to bypass a gate, manually replace routes, or use Terraform parallelism as a lifecycle substitute. For `degraded` state, first restore the prerequisite for quorum, Tailnet ownership, cloud eligibility, or route authority; use separately audited break-glass authority only after safe read-only diagnosis.

## Security And Authority

Controller EC2 write authority is limited to `ReplaceRoute` on configured GWLBE route tables. Packet targets and transport routers retain no DynamoDB lease access or EC2 route-mutation permission. The router attestor is read-only and requires explicit Linux inspection privilege (`CAP_NET_ADMIN`), while the controller itself requires neither packet-processing nor host-network capabilities.

Topology contains environment variable names, never credentials. Logs and metrics contain bounded IDs and reasons, not auth keys, node keys, credential-bearing responses, or raw provider errors.

## Availability Boundary

The controller improves route alignment for new flows; it does not provide hitless forwarding. Tailscale selection and AWS route replacement are coordinated but not atomic. Established TCP can be interrupted and UDP can lose packets. Applications must retry and use the [Application Resilience](application-resilience.md) contract.

The initial detection, ownership, route-convergence, and new-flow objectives remain objectives rather than production SLOs until protected evidence exists. The controlled acceptance model and all live-operation prerequisites are documented in [Developer E2E Documentation](developer/README.md).
