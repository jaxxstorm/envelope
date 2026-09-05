## Why

Envelope has no test that traverses real GWLBs, two authenticated Tailscale appliances, and workloads in both AWS regions. Existing harnesses can pass with a dummy interface and validate the same incorrect UDP reply model, so they cannot establish that Envelope works.

## Supersession

This change was superseded before completion by `add-symmetric-gwlb-ha`, which replaced its directional lanes, target TUN forwarding, and cross-packet GWLB return context with packet-scoped target turnaround, GWLBE post-inspection routing, and dedicated symmetric Tailscale transport routers. Its tasks remain unchecked intentionally, and its obsolete `aws-two-region-e2e` delta is archived without being synced to canonical specifications.

## What Changes

- Add a full two-region Terraform acceptance profile with separate initiator and responder workload lanes in each region.
- Route each initiator lane through its local GWLB while routing the responder return lane through the remote Tailscale appliance, so no GWLB receives an unsupported response-only flow.
- Run cold-flow ICMP, TCP, and UDP acceptance in both directions without warming flow state first.
- Gate traffic tests on cloud-init, systemd, Tailscale control-plane state, accepted routes, Envelope readiness, and healthy GWLB targets.
- Require the configured GWLBE endpoints to remain available for a bounded stabilization interval before the first packet; target health alone does not prove endpoint data-plane readiness immediately after creation.
- Capture and assert actual AWS outer UDP ports, swapped outer IP addresses, VNI 0, ordered AWS options, and flow-cookie preservation.
- Exercise MTU/MSS boundaries, concurrent flows, service restart, route drift, target failure, and appliance reboot.
- Collect sanitized diagnostics on failure and always destroy test-owned AWS, artifact, and Tailnet resources.

## Capabilities

### New Capabilities
- `aws-two-region-e2e`: Define repeatable live acceptance and evidence requirements for the supported two-region Envelope deployment.

### Modified Capabilities
- (none)

## Impact

- Adds Terraform acceptance topology, test clients, orchestration scripts, packet-capture tooling, assertions, and an operator runbook.
- Uses real AWS and Tailscale credentials and creates billable resources, so execution requires an explicit preflight, timeout, and unconditional cleanup.
- Requires the options, wire-compliance, host-routing, and appliance-deployment changes to be complete first.
- Requires the selected Terraform executable to satisfy the profile's declared core-version constraint before any durable prepare or apply action.
- Proves the directional-lane deployment contract; arbitrary bidirectional initiation from the same workload subnet remains outside this version unless a stateful classifier is specified separately.
