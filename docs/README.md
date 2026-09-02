# Envelope

> **Experimental.** Envelope is a Linux-only, Layer 3 packet-turnaround target for a symmetric inline GWLB topology. The corrected multi-AZ version-2 topology and protected acceptance lifecycle are still under development, have not recorded a passing live acceptance run, and are not a production deployment offering.

For each valid AWS GENEVE ingress packet, an Envelope target immediately sends exactly one return to its GWLB using only that packet's outer tuple and metadata. It preserves the complete inner packet, VNI, protocol metadata, ordered options, and flow cookie. A target has no `envelope0` or `tailscale0` path: it does not inject into a TUN, directly forward inner traffic, choose a site route, or retain identity for another packet.

## The Packet Path

```text
site A workload -> site A GWLBE -> site A GWLB -> site A target
  -> immediate return to GWLB -> site A GWLBE post-inspection route
  -> selected site A transport-router ENI -> Tailscale -> site B transport router
  -> site B GWLBE -> site B GWLB -> site B target
  -> immediate return to GWLB -> site B GWLBE local route -> site B workload
```

Site B can initiate a new flow to site A through the equivalent reverse path. Both directions traverse both sites' GWLBE and GWLB paths without NAT. Packet symmetry comes from the route graph, not target flow state or direct target forwarding.

## Supported Topology

Each site separates three responsibilities:

| Role | Responsibility |
| --- | --- |
| Envelope targets | Validate each AWS GENEVE packet and immediately return it to GWLB with byte-identical inner data and packet-scoped metadata. Targets have only outer and management routes. |
| GWLBE subnet route tables | After inspection, select VPC local delivery for local-site CIDRs or one ready same-site transport-router ENI for remote-site CIDRs. |
| Tailscale transport routers | Advertise one assigned local workload prefix at baseline, accept exact remote-site routes, and forward both underlay-to-Tailscale and Tailscale-to-underlay traffic without NAT. |

Every enabled site uses at least two availability zones, a GWLBE and healthy-capable target path in each, and at least two AZ-spread transport routers. Each router has exactly one baseline `advertised_prefix`; the per-router prefix sets are non-empty and pairwise disjoint and exactly cover the site's local workload CIDRs. Every router remains forwarding-capable for bounded takeover of all local prefixes. Workload remote-site routes select the source workload's same-AZ GWLBE; every transport route table selects each destination workload prefix's AZ GWLBE, independent of the receiving router AZ. Target route domains never carry an inner site CIDR. Tailscale table 52 and serving paths contain only opposite-site workload prefixes.

## External Failover Contract

The external `symmetric_topology.route_failover` object has exactly four fields: `mutation_timeout_seconds`, `restoration_timeout_seconds`, `recovery_timeout_seconds`, and `initial_transport_router_az_by_gwlbe_az`. Each timeout is a whole number from `1` through `7200`. The selection object contains exactly `west` and `east`; in each site every GWLBE AZ key must map to the equal enabled transport-router AZ key.

The map is required same-AZ key equality; there is no valid cross-AZ initial mapping and no separate owner input. For each AZ, the map derives both the router's singleton `advertised_prefix` and the route output's `source_workload_prefix`; every exact remote-site route in that source prefix's GWLBE table initially selects the same owner's primary ENI. It does not select by observed readiness or automatically fail over. Internal settlement, quiet-window, and owner-lease durations are lifecycle-derived values, not external inputs. Terraform emits `transport_router_readiness_expectations` separately; that output is an expected host contract, not live readiness evidence.

Credentialed readiness requires every opposite-site observer to select each protected remote prefix's configured stable-node `PrimaryRoutes` owner. On every router, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix, and no same-site observer reports a protected local `PrimaryRoutes` claim. Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay. The higher-priority `iif tailscale0` local-prefix rules make every router capable of delivering all local prefixes through the destination workload prefix's AZ GWLBE during normal and takeover paths, including cross-AZ takeover. Source-prefix owner/ENI coupling remains mandatory: it is derived from singleton advertisements, control-plane stable identities, and opposite-site observations, binds those identities to protected instance IDs, and must agree with the GWLBE owner ENI selected by the same-AZ map.

Failed protected run `ha25` proved this live route shape: each router installed exactly the two opposite-site workload routes in table 52 and formed only opposite-site serving paths. It did not complete acceptance, but it invalidated the earlier same-site sibling table-52/`PrimaryRoutes` requirement.

Failed protected run `ha46` proved the separate destination-endpoint invariant: a cross-AZ receiving router must retain the destination workload prefix's AZ GWLBE rather than select its own AZ endpoint. The run cleaned up to zero residuals but did not satisfy acceptance.

Failed protected run `ha47` proved that corrected path and completed both cross-AZ TCP and UDP recovery proofs, but the second proof finished about eight seconds beyond the shared mutation deadline. `mutation_timeout_seconds` now bounds ownership transfer and GWLBE route convergence; after convergence, the sequential TCP and UDP proofs jointly use a fresh `recovery_timeout_seconds` deadline. Restoration and one-attempt cleanup reached zero residuals, but the run did not satisfy acceptance.

Failed protected run `ha48` proved that deadline correction and completed graceful takeover, both cross-AZ proofs, and restoration, then an isolated TCP marker was lost more than 13 minutes after restoration during the unused 2,735-second observation tail. The full durable transaction reservation remains the continuity-command watchdog with a conservative 600-second paired-control allowance, but instance and transport-router TCP/UDP streams now run concurrently around one shared mutation and use runner-controlled completion after at least 20 successful sends and a final post-mutation marker. The runner validates every successful-send completion timestamp internally and emits exact sent, acknowledged, and lost counts plus strict out-of-interval results; target-process streams remain unchanged. One-attempt cleanup reached zero residuals, but the run did not satisfy acceptance.

## Availability Boundary

The topology is designed for bounded new-flow recovery through alternate targets and transport routers. The operation is coordinated but not atomic. It is not hitless: established TCP can be interrupted and UDP can lose packets during process, instance, AZ, GWLB, VPC-route, or Tailscale control-plane failover. Applications must retry, and future protected acceptance must measure recovery and loss rather than promise continuity.

Graceful and abrupt router failover use one durable CAS/lease transaction ordered as: persist, alternate temporary advertisement expansion, current withdrawal or stop, opposite-site observer stable ownership convergence with local Tailnet routes still absent, replacement of every affected GWLBE route with the alternate ENI, then probe. Unaffected owners stay fixed. Normal overlap and duplicate ownership are forbidden; temporary overlap exists only inside that transaction.

Restoration restarts the original singleton baseline while the alternate covers, removes the transferred prefix from the alternate, waits for opposite-site baseline owner-graph convergence and continued absence of local Tailnet routes, then restores and quietly verifies the original ENI routes. No terminal result or cleanup handoff is allowed until advertisements, ownership, and routes are all restored; after lease expiry, successor recovery acquires the transaction by CAS. Targets and transport routers cannot mutate these AWS routes, and this exercise is not a production failover controller.

Protected packet-fidelity evidence is hash-only after inspection. Bounded Linux `AF_PACKET` captures are reduced to frame, inner-packet, ordered-option, and flow-cookie SHA-256 values plus protocol-field assertions, then the raw PCAP is deleted. Transfer evidence includes the source prefix, fenced forward and restore generations, stable-node hashes bound to protected instance IDs, before/transferred/restored opposite-site owner graphs, absence of local Tailnet routes and claims, ENI transitions, and verified all-component restoration. Raw payload bytes, ordered-option bytes, and flow-cookie values are not retained. No passing live acceptance result is claimed.

## Version And Migration

The unshipped direct-forwarding draft is replaced in place while retaining version `2`. There is no compatibility mode, translation layer, dual behavior, or version 3. Directional-lane and obsolete draft-v2 target CIDR, TUN, Tailscale, and host-routing fields are rejected before mutation.

Create a fresh version-2 topology with separate workload, transport-router, GWLBE, target, and management route domains. Do not combine prior state, plans, resources, configuration, or evidence with this route model. Topology `local-site-cidrs` and `remote-site-cidrs` describe VPC and transport routes; they are not target forwarding settings.

## Cost Boundary

The checked-in planning profile models two sites, two AZs per site, two GWLBs, four GWLBE endpoints, four targets, four transport routers, four workloads, and one management NAT gateway per VPC. Its fixed-cost estimate is `$4.00/hour` under a `$5.00/hour` fixed ceiling. This one-NAT-per-site layout shares private egress through each site's single management subnet and is not multi-AZ management egress; it remains outside the inspected data path. Variable processing, transfer, NAT data, logging, storage, taxes, and price drift are outside that estimate, so a fresh plan and current prices still require review. These assumptions do not authorize or prove a live run.

## Choose Your Next Step

- [Build and validate locally](getting-started.md) for development-only checks.
- [Review the Terraform input shape](terraform-example.md) for the version-2 topology model.
- Read the [AWS appliance runbook](aws-appliance-runbook.md) and [two-region E2E runbook](aws-two-region-e2e-runbook.md) for protected-run safety, failover, restoration, evidence, and cost boundaries. They intentionally do not provide a direct live infrastructure command sequence.
