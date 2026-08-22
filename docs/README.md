# Envelope

> **Experimental.** Envelope is a Linux-only, Layer 3 symmetric inline GWLB datapath. The multi-AZ topology and protected acceptance lifecycle are still under development and are not a production deployment offering.

Envelope lets two disjoint sites exchange traffic through AWS Gateway Load Balancer (GWLB), GENEVE, `envelope0`, and Tailscale without NAT. A target accepts validated GENEVE ingress and injects an inner IP packet into `envelope0`; host routing sends it to a local post-inspection VPC path or `tailscale0`.

## The Packet Path

```text
site A workload -> site A GWLBE -> site A GWLB -> site A target
  -> envelope0 -> tailscale0 -> site B ingress router
  -> site B GWLBE -> site B GWLB -> site B target
  -> envelope0 -> site B workload
```

Site B can initiate a new flow to site A through the equivalent reverse path. Both directions reach a local GWLBE and GWLB before a target receives the packet. Targets do not send normal-path GENEVE traffic or require retained flow state from an earlier packet.

## Supported Topology

Each site uses two separate fleets:

| Fleet | Responsibility |
| --- | --- |
| Envelope targets | Receive GWLB GENEVE, inject into `envelope0`, and forward local-site traffic to the VPC or remote-site traffic to `tailscale0`. |
| Tailscale ingress routers | Advertise exact local-site CIDRs without subnet-route SNAT and send Tailnet-arriving local traffic to the local GWLBE. |

The version-2 target contract uses disjoint `local-site-cidrs` and `remote-site-cidrs`. Every enabled site requires at least two availability zones, a GWLBE and healthy-capable target path in each, and at least two ingress routers. Target route domains never route a site CIDR back to a GWLBE.

## Availability Boundary

The topology supports alternate-path recovery for new flows after a target or ingress-router loss. It is not hitless: established TCP can be interrupted and UDP can lose packets during GWLB or Tailscale control-plane failover. The protected acceptance work must measure and record that recovery; it does not promise continuity.

## Breaking Migration

The prior directional configuration, state, plans, and evidence are incompatible. Create a fresh version-2 topology with separate workload, Tailscale-ingress, GWLBE, target, and management route domains. Do not combine old resources with the new route model.

## Choose Your Next Step

- [Build and validate locally](getting-started.md) for development-only checks.
- [Review the Terraform input shape](terraform-example.md) for the version-2 topology model.
- Read the [AWS appliance runbook](aws-appliance-runbook.md) and [two-region E2E runbook](aws-two-region-e2e-runbook.md) for protected-run safety boundaries. They intentionally contain no current live-run procedure while lifecycle implementation is incomplete.
