# AWS Two-Region E2E Runbook

## Status

This page describes the required acceptance boundary for the symmetric two-site GWLB topology. The protected lifecycle and schema-3 HA evidence verifier are implemented, but execution remains restricted to an approved protected environment and a fresh run-owned configuration.

Do not execute an earlier acceptance workflow, use direct Terraform commands, or reuse previous state, plans, evidence, or configuration. The earlier deployment contract is incompatible with version 2. Every run must start with a fresh approved run identity and use only the lifecycle that owns creation, evidence, and cleanup.

## Acceptance Topology

Both sites use ordinary local workload CIDRs, so either site can cold-initiate TCP, UDP, or ICMP traffic to the other. The expected path for every inter-site packet is:

```text
source workload -> source-site GWLBE -> source-site GWLB -> source-site target
  -> Tailscale -> destination-site ingress router
  -> destination-site GWLBE -> destination-site GWLB -> destination-site target
  -> destination workload
```

The remote ingress router is separate from the target fleet. It advertises the exact destination local-site CIDRs without subnet-route SNAT and routes received Tailnet traffic to its local GWLBE. The target decapsulates GENEVE into `envelope0`, sends local-site traffic to the post-inspection VPC path, and sends remote-site traffic to `tailscale0`. No normal inter-site path performs NAT or bypasses a local GWLB.

## Required Profile

- Two enabled availability zones per site.
- A GWLBE and healthy-capable target path in every enabled AZ.
- At least two AZ-spread ingress routers per site advertising identical exact local-site CIDRs.
- Disjoint local-site and remote-site CIDRs, with each remote list equal to the peer's local list.
- Separate workload, ingress, GWLBE, target, and management route domains.
- An approved cost ceiling and short, explicit resource expiry before any future apply.

The [Terraform topology shape](terraform-example.md) is illustrative only and deliberately omits a protected configuration. It is not a deployment instruction.

## Evidence Expectations

Protected acceptance proves bidirectional cold TCP, UDP, and ICMP flows through both sites' GWLBE/GWLB paths. It separately exercises target-process, target-instance, and ingress-router loss, proving that a new flow can use an alternate healthy target or router.

Evidence must identify selected and succeeding targets and ingress routers, record health transitions and bounded recovery time, record the established TCP outcome and UDP loss, and complete an ownership-safe residual audit. Retained evidence must be redacted and pass the repository secret scan.

## Availability Limit

The profile is designed for bounded new-flow recovery. It is not hitless. A target, instance, AZ, GWLB, or ingress-router failure can interrupt established TCP and lose UDP traffic while AWS and Tailscale control planes converge. Applications must provide retry behavior; acceptance records observed behavior rather than claiming uninterrupted transport.

## Protected-Run Safety

- Run acceptance only from an approved protected environment with reviewed source and scoped, short-lived credentials.
- Keep credentials out of config files, Terraform input, command arguments, plans, diagnostics, and logs.
- Do not enable shell tracing around lifecycle tooling.
- Do not retain or upload state, plans, raw packet captures, rendered user data, or unredacted diagnostics.
- Cleanup must use exact run ownership and leave shared backend infrastructure untouched.

Use local/static validation before requesting a protected run:

```bash
python3 scripts/test_docs.py
python3 scripts/test_terraform_contract.py
python3 scripts/secret_scan.py --root .
```
