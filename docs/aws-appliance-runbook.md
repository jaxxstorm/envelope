# AWS Appliance Deployment Runbook

## Status

The AWS appliance topology uses the version-2 symmetric two-site design. The protected lifecycle implements preflight, draining, replacement, ingress-router failure, and evidence collection. This page remains a safety and architecture reference, not an executable live-run procedure.

Do not use an older protected configuration, saved plan, state file, workflow, or direct Terraform command with this topology. Do not attempt to translate an old configuration by hand. The protected lifecycle creates a fresh, run-owned version-2 deployment and owns its cleanup.

## Required Architecture

Each site must have at least two enabled availability zones and these separate route domains:

| Domain | Required forwarding behavior |
| --- | --- |
| Workload | Exact peer-site CIDRs go to the local GWLBE. |
| Tailscale ingress | Exact local-site CIDRs go to the local GWLBE. |
| GWLBE | Delivers traffic to the local GWLB. |
| Envelope target | Local-site CIDRs use the post-inspection VPC path; remote-site CIDRs use Tailscale. Neither site CIDR returns to a GWLBE. |
| Management | Kept separate from packet-forwarding domains. |

Every enabled AZ requires a local GWLBE and a healthy-capable Envelope target. Each site also requires at least two independent Tailscale ingress routers, spread across enabled AZs, advertising the same exact local-site CIDRs with subnet-route SNAT disabled. Targets join Tailscale for remote-site egress but are not the required route advertisers.

The inter-site path is symmetric: both the workload-originated packet and a remote Tailnet packet entering a site pass through that site's GWLBE and GWLB before an Envelope target receives validated GENEVE. The data path preserves source addresses and uses no NAT.

## Target Readiness

Before a target is registered healthy, it must prove:

- GENEVE receive and TUN injection readiness.
- Version-2 local-site and remote-site route validation.
- Local post-inspection VPC delivery and remote Tailscale egress.
- Required forwarding, firewall, reverse-path-filter, and MSS prerequisites.

Ingress-router readiness is independent. It must prove Running Tailscale, exact approved local-site advertisements without SNAT, accepted remote routes, and an effective VPC route from each local-site CIDR to the local GWLBE.

## Security Boundary

- Use only an approved protected environment and short-lived, scoped credentials supplied to the lifecycle runner.
- Never place AWS credentials, Tailscale keys, OAuth secrets, or backend credentials in repository files, Terraform variables, command arguments, plans, or retained logs.
- Treat saved plans, state, rendered user data, packet captures, and diagnostics as sensitive. Retain only redacted evidence selected by the lifecycle and secret-scan it before upload.
- Every run must use fresh resource ownership and expiry, review current AWS pricing, and enforce an approved fixed-cost ceiling before resources are created.
- Cleanup must be ownership-safe, exact-resource scoped, and include a residual audit. Never substitute broad tag-based deletion.

## Availability And Cost

The two-AZ target fleet and redundant ingress routers support bounded alternate-path recovery for new flows after target, process, instance, or router loss. They do not provide a hitless guarantee. GWLB health reassignment and Tailscale route convergence can interrupt established TCP and lose UDP packets.

Protected acceptance must measure and retain target/router identity, health transitions, new-flow recovery time, established TCP outcome, UDP loss, and cleanup results. It must not report continuity as guaranteed.

The profile increases fixed cost through multiple endpoints, targets, and ingress routers, and adds variable GWLB/GWLBE processing plus possible cross-AZ and inter-region transfer. Price and approve the complete profile before a protected run.

## Current Safe Checks

The following checks do not create AWS resources and may run from a reviewed checkout:

```bash
python3 scripts/test_docs.py
python3 scripts/test_terraform_contract.py
python3 scripts/secret_scan.py --root .
```

Follow the [two-region E2E runbook](aws-two-region-e2e-runbook.md) for the protected-run boundary and required evidence. It intentionally does not publish an unsafe direct infrastructure command sequence.
