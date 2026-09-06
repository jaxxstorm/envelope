## Why

Envelope's redundant transport routers and alternate ENI routes recover only when the protected acceptance runner coordinates them. Production deployments need an autonomous, highly available control plane that detects router failure and converges Tailnet ownership and AWS routes without running test scripts, SSM commands, or control agents on Envelope targets.

## What Changes

- Add a standalone Go `envelope-controller` process that runs outside Envelope targets and transport routers, with multiple disposable replicas coordinated by a strongly consistent DynamoDB lease and durable reconciliation state.
- Configure every same-site transport router to advertise the same exact local workload prefixes so Tailscale's native subnet-router HA owns router selection; embed a Tailscale observer in each controller replica and require stable multi-observer ownership before AWS mutation.
- Reconcile each GWLBE route table's exact remote-site routes to the ENI of the Tailscale-selected owner for that table's source workload prefix, binding authority to the exact GWLBE subnet and explicit route-table association as well as the table, VPC, prefixes, and ENIs, using fencing terms, write-ahead state, authoritative readback, hysteresis, and cooldown.
- Keep failed-over ownership as durable steady state and make failback a separate stability-gated policy decision instead of unconditionally restoring the initial owner.
- Add health, leader, transaction, route, and ownership metrics plus fail-closed readiness and operator-visible degraded states.
- Add a dedicated controller deployment/IAM boundary, reproducible artifacts, deterministic state-machine and crash-recovery tests, and protected controller-conformance exercises.
- Add a small read-only Go router attestor with authenticated exact-instance/ENI/stable-node and freshness/replay binding, plus a separate Go deployment lifecycle command for initialization, activation, serialized rollout, and quiescent migration. Neither provides router route-mutation authority or invokes shell/Python/SSM in the runtime loop.
- Split deployment/cleanup credentials from route-denied acceptance credentials and distinguish deterministic simulated conformance from real live failure/recovery evidence; live billable execution requires separate approval.
- Preserve the non-hitless availability contract: new flows recover after convergence, TCP clients reconnect as needed, and retryable UDP applications sequence, deduplicate, and retransmit important datagrams.
- **BREAKING** replace singleton per-prefix transport-router advertisements in the production profile with overlapping exact-prefix Tailscale HA, and add production-controller AWS route authority independent of the test-only runner. Existing version-2 acceptance deployments require a fresh topology rather than in-place state reuse.

## Capabilities

### New Capabilities
- `production-failover-controller`: Autonomous controller election, health policy, Tailnet ownership observation, AWS route reconciliation, durable recovery, observability, and operator controls.

### Modified Capabilities
- `symmetric-gwlb-ha-topology`: Replace coordinated advertisement transfer with native overlapping-route HA and align each GWLBE route group to the selected Tailscale owner.
- `tailscale-host-routing`: Make every same-site router an exact-prefix failover candidate while preserving local underlay routing, no-NAT transit, and source identity.
- `aws-appliance-deployment`: Add the standalone controller deployment, durable store, IAM boundary, artifacts, readiness, and production failover acceptance contract.

## Impact

- Adds a new Go command and controller packages, AWS SDK v2 DynamoDB/EC2 adapters, and an embedded Tailscale observer; Envelope's packet-turnaround binary and target privileges remain unchanged.
- Adds production control-plane configuration, DynamoDB and IAM resources, controller deployment assets, Prometheus metrics, health endpoints, runbooks, and SLOs.
- Changes transport-router route advertisements and local-prefix policy validation, Terraform route ownership, protected acceptance responsibilities, and static architecture tests.
- Requires controller credentials for only the configured DynamoDB records and EC2 route groups. Targets and transport routers retain no AWS route-mutation authority, and the controller receives no packet-processing privilege.
