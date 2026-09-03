# Terraform Topology Shape

This is an **illustrative input shape**, not a runnable deployment configuration or protected-run input. The protected lifecycle passes the shown `symmetric_topology` object as the Terraform topology variable, but this fragment deliberately uses invalid placeholders and omits the rest of the account, artifact, backend, credential, and lifecycle configuration. Field names show the corrected version-2 architecture, not a compatibility contract for the rejected draft. Do not add credentials, complete the omitted fields, or use this page as an infrastructure execution instruction. Timeout values are examples, not defaults or approved bounds for a live run.

```json
{
  "symmetric_topology": {
    "version": 2,
    "route_failover": {
      "mutation_timeout_seconds": 120,
      "restoration_timeout_seconds": 120,
      "recovery_timeout_seconds": 600,
      "initial_transport_router_az_by_gwlbe_az": {
        "west": {"a": "a", "b": "b"},
        "east": {"a": "a", "b": "b"}
      }
    },
    "sites": {
      "west": {
        "region": "<west-region>",
        "ami_id": "<west-ami-id>",
        "ssm_kms_key_arn": "<west-ssm-kms-key-arn>",
        "azs": {"a": "<west-az-a>", "b": "<west-az-b>"},
        "vpc_cidr": "<west-vpc-cidr>",
        "local_site_cidrs": ["<west-workload-cidr-a>", "<west-workload-cidr-b>"],
        "remote_site_cidrs": ["<east-workload-cidr-a>", "<east-workload-cidr-b>"],
        "workload_subnet_cidrs": {"a": "<west-workload-cidr-a>", "b": "<west-workload-cidr-b>"},
        "transport_subnet_cidrs": {"a": "<west-transport-cidr-a>", "b": "<west-transport-cidr-b>"},
        "gwlbe_subnet_cidrs": {"a": "<west-gwlbe-cidr-a>", "b": "<west-gwlbe-cidr-b>"},
        "gwlb_subnet_cidrs": {"a": "<west-gwlb-cidr-a>", "b": "<west-gwlb-cidr-b>"},
        "target_subnet_cidrs": {"a": "<west-target-cidr-a>", "b": "<west-target-cidr-b>"},
        "management_subnet_cidr": "<west-management-cidr>",
        "target_az_keys": ["a", "b"],
        "transport_router_az_keys": ["a", "b"]
      },
      "east": {
        "region": "<east-region>",
        "ami_id": "<east-ami-id>",
        "ssm_kms_key_arn": "<east-ssm-kms-key-arn>",
        "azs": {"a": "<east-az-a>", "b": "<east-az-b>"},
        "vpc_cidr": "<east-vpc-cidr>",
        "local_site_cidrs": ["<east-workload-cidr-a>", "<east-workload-cidr-b>"],
        "remote_site_cidrs": ["<west-workload-cidr-a>", "<west-workload-cidr-b>"],
        "workload_subnet_cidrs": {"a": "<east-workload-cidr-a>", "b": "<east-workload-cidr-b>"},
        "transport_subnet_cidrs": {"a": "<east-transport-cidr-a>", "b": "<east-transport-cidr-b>"},
        "gwlbe_subnet_cidrs": {"a": "<east-gwlbe-cidr-a>", "b": "<east-gwlbe-cidr-b>"},
        "gwlb_subnet_cidrs": {"a": "<east-gwlb-cidr-a>", "b": "<east-gwlb-cidr-b>"},
        "target_subnet_cidrs": {"a": "<east-target-cidr-a>", "b": "<east-target-cidr-b>"},
        "management_subnet_cidr": "<east-management-cidr>",
        "target_az_keys": ["a", "b"],
        "transport_router_az_keys": ["a", "b"]
      }
    }
  },
  "cost": {
    "estimated_fixed_hourly_usd": 4.00,
    "approved_max_fixed_hourly_usd": 5.00
  }
}
```

## Route-Failover Contract

`symmetric_topology.route_failover` is an exact external object. Missing fields, extra aliases, booleans, fractional seconds, and values outside these constraints are rejected:

| Field | External meaning |
| --- | --- |
| `mutation_timeout_seconds` | Whole number from `1` through `7200` bounding authorized ownership transfer and GWLBE route mutation and convergence. |
| `restoration_timeout_seconds` | Whole number from `1` through `7200` bounding unconditional restoration and verification. |
| `recovery_timeout_seconds` | Whole number from `1` through `7200` jointly bounding the sequential TCP and UDP alternate-path proofs after route convergence. |
| `initial_transport_router_az_by_gwlbe_az` | Object containing exactly `west` and `east`; in each site every GWLBE AZ key maps to the equal enabled transport-router AZ key. |

`initial_transport_router_az_by_gwlbe_az` is required same-AZ key equality. A cross-AZ initial mapping is rejected; the map does not contain ENI IDs, infer readiness, or choose a fallback. There is no separate owner input. For each AZ, the map assigns the local workload prefix to that AZ's router and selects that router's primary ENI for every exact remote-site CIDR route in the corresponding GWLBE subnet route table. A distinct same-site ENI remains the eligible acceptance alternate.

The protected lifecycle derives its settlement timeout, quiet window, and owner lease from reviewed external bounds. `settlement_timeout_seconds`, `quiet_window_seconds`, and `owner_lease_seconds` are internal values, not accepted input fields.

## Output Boundary

The `symmetric_topology` output gives every transport-router fleet member exactly one `advertised_prefix`. Those non-empty singleton assignments are pairwise disjoint and exactly cover the site's local workload CIDRs. The separate `route_failover` output gives each GWLBE AZ a `source_workload_prefix`, route-table ID, exact remote-site CIDRs, selected transport-router AZ key, and primary ENI ID. `advertised_prefix` and `source_workload_prefix` must identify the same owner selected by the same-AZ map. The `same_az_preferred` result records that required equality; it is not permission for a cross-AZ initial state or proof of live router health. Source-prefix owner/ENI coupling remains mandatory: it is derived from singleton advertisements, control-plane stable identities, and opposite-site observations during credentialed readiness.

On every router, Tailnet DNS acceptance remains disabled so VPC DNS stays authoritative, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix, and the backend reports no health condition. Every opposite-site observer selects each protected remote prefix's configured stable-node `PrimaryRoutes` owner, while no same-site observer reports a protected local `PrimaryRoutes` claim. Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay. The higher-priority `iif tailscale0` local-prefix rules make every router forwarding-capable for bounded takeover and able to deliver all local prefixes during normal and takeover paths.

Failed protected run `ha25` proved this route shape by showing exactly the two opposite-site workload routes and only opposite-site serving paths on every router in the illustrated two-prefix profile. It did not pass acceptance and is not live-readiness evidence for a future plan.

Failed protected run `ha47` proved destination-prefix endpoint symmetry and both cross-AZ recovery paths, then exposed that the sequential full TCP and UDP proofs cannot share the preceding mutation deadline. The runner now completes ownership and GWLBE route convergence within `mutation_timeout_seconds`, then starts one fresh `recovery_timeout_seconds` deadline jointly covering those two proofs. Restoration and cleanup reached zero residuals, but the run did not pass acceptance.

Failed protected run `ha48` proved that deadline correction and completed graceful recovery and restoration, then an isolated TCP marker was lost more than 13 minutes into the unused 2,735-second observation tail. The full durable transaction reservation remains the continuity-command watchdog with a conservative 600-second paired-control allowance, but instance and transport-router TCP/UDP streams now run concurrently around one shared mutation and use runner-controlled completion after at least 20 successful sends and a final post-mutation marker. Successful-send completion timestamps are validated internally, while schema evidence retains exact sent, acknowledged, and lost counts; target-process streams remain unchanged, and every distinct loss episode starting outside mutation still fails. Cleanup reached zero residuals, but the run did not pass acceptance.

Failed protected run `ha49` proved controlled completion and both abrupt alternate-path probes, then strict readiness rejected the restarted original router's three Tailscale health conditions while its DNS forwarder had no upstream resolver. Bootstrap and restoration now explicitly set `accept-dns=false`, and host plus protected readiness verify `CorpDNS` false without weakening the empty-health requirement. Cleanup restored the singleton advertisements, owner graph, and original ENI routes before zero-residual teardown, but the run did not pass acceptance.

Failed protected run `ha50` proved that DNS correction and abrupt restoration, then exposed endpoint-sensitive resumed-stream analysis. One TCP loss episode began during mutation, crossed the sampled endpoint by 274 milliseconds, and resumed at the next marker; the previous all-missing-sends rule treated that single episode as unrelated post-mutation loss. Analysis now attributes each bounded contiguous episode by its first missing successful send, retains its complete duration and exact counts, and still rejects any separately starting post-mutation episode. Cleanup passed in one attempt with zero residuals, but the run did not pass acceptance.

Failed protected run `ha51` proved that stream correction and completed every live recovery, both route restorations, final no-drift verification, and zero-residual cleanup. Final evidence validation then rejected a later UDP path through the target replacement because its target lookup still used only the initial topology. Evidence now keeps that initial topology for earlier observations and derives one exact post-replacement fleet by removing the victim and substituting its globally distinct same-site, same-AZ, same-target-group successor. The run did not pass acceptance.

Terraform emits the host contract separately as `transport_router_readiness_expectations`, including each site's exact CIDRs, forwarding, policy, firewall, MSS, IPv6, no-NAT expectations, and contract hash. That output is an expectation consumed by credentialed protected readiness, not a user input and not proof that a deployed router is ready.

## Topology Rules

- The schema stays at version `2`, with exactly two sites and two enabled AZs per site. There is no version 3 or compatibility mode.
- A site's local CIDRs are non-empty, pairwise disjoint, and exactly cover its workload subnets; its remote CIDRs exactly match the peer's local CIDRs and are disjoint from the local set.
- Each enabled AZ has separate workload, transport-router, GWLBE, GWLB, and target route domains, plus a separate management domain per site.
- Every enabled AZ has a GWLBE and healthy-capable Envelope target path. Each site has two independent AZ-spread transport routers with distinct eligible ENIs.
- Protected topology and evidence name each router collection `transport_router_fleet`; transport hosts run the `envelope-transport-router-network.service` unit for host sysctls, fail-closed firewall chains, and MSS clamping only. Protected readiness owns Tailnet, route, AWS, and ENI eligibility checks.
- Workload routes send peer CIDRs to the source workload's same-AZ GWLBE. Every transport-router route table sends each local CIDR to that destination workload prefix's AZ GWLBE, independent of the receiving router AZ.
- After inspection, each GWLBE subnet route table sends local-site CIDRs through VPC local delivery and each exact remote-site CIDR to the explicitly selected same-site transport-router primary ENI. Live readiness is a separate gate.
- Targets carry only outer GWLB and management routes. They do not receive site CIDRs as forwarding configuration, create a TUN, join Tailscale, or forward an inner packet.
- Each transport router advertises exactly its one assigned `advertised_prefix` at baseline. Per-site assignments are non-empty and pairwise disjoint and exactly cover local workload CIDRs; normal duplicate or overlapping ownership is invalid.
- Every transport router remains forwarding-capable for bounded takeover of all local prefixes, accepts exact remote routes, keeps Tailnet DNS acceptance disabled, forwards in both directions, preserves source addresses, and performs no transit NAT.
- Each transport router's table 52 contains only the exact remote-site workload routes; local prefixes use `main` and the VPC underlay without same-site protected `PrimaryRoutes` claims.

## Cost Assumptions

The planning profile behind the values above uses two GWLBs, four GWLBE endpoints, four `t3.medium` target instances, four `t3.micro` transport-router instances, four `t3.micro` workload instances, two NAT gateways and Elastic IPs for management egress, and supporting logs and storage. That is exactly one shared NAT in each site's single management subnet. Private egress is therefore not multi-AZ within a site; this management-cost limitation is outside the inspected inter-site path and is not repaired by target or transport-router failover. The `$4.00/hour` fixed estimate must remain at or below the `$5.00/hour` fixed ceiling.

Variable GWLB/GWLBE processing, cross-AZ and inter-region transfer, NAT data processing, logging volume, storage, taxes, and later AWS price changes are not represented by that fixed estimate. A protected run still requires a fresh saved-plan count review, current regional pricing, a short explicit expiry, and immediate cleanup. The illustrative values do not establish that live acceptance passed.

## Migration Boundary

The rejected direct-forwarding draft did not ship. Its target CIDR, TUN, Tailscale, host-routing, and directional-lane inputs are not portable and are rejected rather than translated. Build a fresh version-2 deployment and use only protected lifecycle inputs reviewed for the corrected packet-turnaround and endpoint-routing model. Review the [AWS appliance runbook](aws-appliance-runbook.md) before requesting protected use.
