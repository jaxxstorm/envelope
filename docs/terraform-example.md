# Terraform Inputs

The appliance root at `example/terraform` creates the AWS side of an Envelope deployment. It is the first phase in the [Deployment Guide](deployment.md).

## Required Inputs

Provide these values in a reviewed `production.tfvars` file that is not committed to the repository:

| Input group | Purpose |
| --- | --- |
| Run identity | `name`, `expires_at`, and additional tags identify and expire the deployment. |
| Rollout phase | `deployment_phase` is exactly `infrastructure` or `targets`; it makes the review boundary explicit without Terraform `-target`. |
| AWS placement | `west_region`, `east_region`, AMIs, architecture, and instance types select exactly two sites and two AZs per site. |
| Target artifact | Path, SHA-256, Git revision, and version identify the Linux `envelope` binary installed on target EC2 instances. |
| Tailscale access | SecureString parameter ARNs, KMS keys, tag, and pinned version let transport routers join the Tailnet without exposing keys in Terraform variables. |
| Cost and load | The fixed hourly ceiling and reviewed traffic profile gate the planned topology. |
| `symmetric_topology` | Defines VPC CIDRs, subnets, workload prefixes, GWLBE/GWLB/target placement, and route-failover ownership. |

For production, set `symmetric_topology.version = 3`. Version 3 makes every same-site router advertise the complete local workload-prefix set and is required by the production controller. Version 2 is retained only for the legacy acceptance profile.

## Topology Rules

Each site needs two enabled availability zones and separate workload, transport-router, GWLBE, GWLB, target, and management subnets. Local workload CIDRs must be non-overlapping, and each site's remote CIDRs must exactly equal the peer site's local CIDRs.

The appliance root pins `terraform-aws-modules/vpc/aws` to v6.7.2 for both VPCs, their DNS/IGW/NAT foundation, and management subnet. It keeps workload, transport-router, GWLBE, GWLB, target, and management route domains and associations explicit because GWLB routing requires stable per-AZ identities.

Use `deployment_phase = "infrastructure"` first. It creates the GWLB, target group, listener, endpoint service, GWLBE endpoints, every workload/transport route, EC2 transport routers, and production-v3 controller topology inputs, but intentionally creates no Envelope EC2 target or target-group attachment. The resulting inspected path is expected to fail, with no direct-route fallback. After reviewing that state, change only to `deployment_phase = "targets"`; that normal plan creates one Envelope target EC2 instance per enabled target AZ and registers it with its site's existing target group. The health contract remains HTTP `/healthz` on port `9090`, healthy threshold `5`, interval `10`, timeout `5`, unhealthy threshold `2`, while GWLB sends GENEVE over UDP `6081`.

Envelope targets are Linux EC2 packet-turnaround appliances, not ECS services. They do not run Tailscale, create a TUN, or receive Tailscale credentials. EC2 transport routers perform the no-NAT forwarding and Tailscale route advertisement; the standalone production-v3 controller alone reconciles GWLBE route targets.

## Tailnet Policy Before Infrastructure

Configure the Tailnet policy before the infrastructure apply. Replace `tag:REVIEWED-ROUTER-TAG` everywhere with the exact `tailscale_tag` input and replace the creator group with the approved bootstrap-key creator group, but do not broaden the exact workload prefixes. For the configured two-site example, the complete template is:

```json
{
  "tagOwners": {
    "tag:REVIEWED-ROUTER-TAG": ["group:REVIEWED-BOOTSTRAP-KEY-CREATORS"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["172.16.4.0/24", "172.16.5.0/24"],
      "dst": ["172.17.4.0/24:1-65535", "172.17.5.0/24:1-65535"]
    },
    {
      "action": "accept",
      "src": ["172.17.4.0/24", "172.17.5.0/24"],
      "dst": ["172.16.4.0/24:1-65535", "172.16.5.0/24:1-65535"]
    }
  ],
  "autoApprovers": {
    "routes": {
      "172.16.4.0/24": ["tag:REVIEWED-ROUTER-TAG"],
      "172.16.5.0/24": ["tag:REVIEWED-ROUTER-TAG"],
      "172.17.4.0/24": ["tag:REVIEWED-ROUTER-TAG"],
      "172.17.5.0/24": ["tag:REVIEWED-ROUTER-TAG"]
    }
  }
}
```

For another reviewed topology, replace each listed prefix only with the exact union of `symmetric_topology.sites.west.local_site_cidrs` and `.east.local_site_cidrs`, preserving one auto-approval per prefix. The two ACLs are directional and CIDR-limited; `:1-65535` avoids a destination wildcard. Do not use wildcard sources or destinations, supernets, target tags, target enrollment, unrelated route approvals, or manual route activation as substitutes.

Create reusable, preauthorized bootstrap keys tagged only with `tailscale_tag`. Store each key only as the regional encrypted SecureString named by `west_tailscale_secret_arn` or `east_tailscale_secret_arn`; Envelope targets, workloads, and controllers do not receive it.

## Vendored Router Cloud-Init

Transport routers retain the local [`tailscale-cloudinit` module](../example/terraform/modules/tailscale-cloudinit/PROVENANCE.md), rather than upstream `tailscale/terraform-cloudinit-tailscale` v0.0.12. The reviewed upstream comparison found that v0.0.12 lacks both a checksum-pinned package installer and the pre-setup gate required before router credential resolution and `tailscale up`. The local module verifies the RPM URL/checksum and signing key, then waits for the router gate. Its input and template checksums are recorded in [`SOURCE.sha256`](../example/terraform/modules/tailscale-cloudinit/SOURCE.sha256).

The full input schema is enforced by `example/terraform/variables.tf`. Use `terraform validate` and a saved plan before applying. The [Deployment Guide](deployment.md) gives the command sequence and describes how those appliance outputs feed the router-attestor and controller roots.

## State And Secrets

Configure the S3 backend before `terraform init`, using a unique backend key for this root. Do not reuse it for router-attestor or controller state. Supply parameter and KMS ARNs only; do not place Tailscale keys, AWS credentials, or backend credentials in `.tfvars`, state, user data, or the repository.
