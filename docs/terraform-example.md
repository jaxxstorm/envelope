# Terraform Topology Shape

This is an **illustrative input shape**, not a runnable deployment configuration or protected-run input. It deliberately omits account, artifact, backend, AMI, and credential references. Do not add credentials, complete the omitted fields, or use this page as an apply instruction.

```json
{
  "symmetric_topology": {
    "version": 2,
    "sites": {
      "west": {
        "azs": {"a": "<west-az-a>", "b": "<west-az-b>"},
        "vpc_cidr": "<west-vpc-cidr>",
        "local_site_cidrs": ["<west-workload-cidr-a>", "<west-workload-cidr-b>"],
        "remote_site_cidrs": ["<east-workload-cidr-a>", "<east-workload-cidr-b>"],
        "workload_subnet_cidrs": {"a": "<west-workload-cidr-a>", "b": "<west-workload-cidr-b>"},
        "ingress_subnet_cidrs": {"a": "<west-ingress-cidr-a>", "b": "<west-ingress-cidr-b>"},
        "gwlbe_subnet_cidrs": {"a": "<west-gwlbe-cidr-a>", "b": "<west-gwlbe-cidr-b>"},
        "gwlb_subnet_cidrs": {"a": "<west-gwlb-cidr-a>", "b": "<west-gwlb-cidr-b>"},
        "target_subnet_cidrs": {"a": "<west-target-cidr-a>", "b": "<west-target-cidr-b>"},
        "management_subnet_cidr": "<west-management-cidr>",
        "target_az_keys": ["a", "b"],
        "ingress_router_az_keys": ["a", "b"]
      },
      "east": {
        "azs": {"a": "<east-az-a>", "b": "<east-az-b>"},
        "vpc_cidr": "<east-vpc-cidr>",
        "local_site_cidrs": ["<east-workload-cidr-a>", "<east-workload-cidr-b>"],
        "remote_site_cidrs": ["<west-workload-cidr-a>", "<west-workload-cidr-b>"],
        "workload_subnet_cidrs": {"a": "<east-workload-cidr-a>", "b": "<east-workload-cidr-b>"},
        "ingress_subnet_cidrs": {"a": "<east-ingress-cidr-a>", "b": "<east-ingress-cidr-b>"},
        "gwlbe_subnet_cidrs": {"a": "<east-gwlbe-cidr-a>", "b": "<east-gwlbe-cidr-b>"},
        "gwlb_subnet_cidrs": {"a": "<east-gwlb-cidr-a>", "b": "<east-gwlb-cidr-b>"},
        "target_subnet_cidrs": {"a": "<east-target-cidr-a>", "b": "<east-target-cidr-b>"},
        "management_subnet_cidr": "<east-management-cidr>",
        "target_az_keys": ["a", "b"],
        "ingress_router_az_keys": ["a", "b"]
      }
    }
  },
  "approved_max_fixed_hourly_usd": "<approved-ceiling>"
}
```

## Topology Rules

- The schema version is `2`, with exactly two sites and two enabled AZs per site.
- A site's local CIDRs exactly cover its workload subnets; its remote CIDRs exactly match the peer's local CIDRs; the lists are disjoint.
- Each enabled AZ has a workload, Tailscale-ingress, GWLBE, GWLB, and target route domain.
- Every enabled AZ has a GWLBE and an Envelope target. Each site has two independent ingress routers, spread across those AZs.
- Workload routes send peer CIDRs to the local GWLBE. Ingress-router routes send local CIDRs to the local GWLBE. Target routes deliver local CIDRs directly and remote CIDRs through Tailscale, never through a GWLBE.
- Inter-site forwarding preserves source addresses and uses no NAT.

## Migration Boundary

This replaces the prior directional profile. Existing state, plans, evidence, and configuration are not portable. The protected lifecycle requires a complete fresh run-owned configuration and is intentionally not reproduced here. Review the [AWS appliance runbook](aws-appliance-runbook.md) before requesting protected use.
