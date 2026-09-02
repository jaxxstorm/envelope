# Envelope

> [!WARNING]
> **Experimental WIP: this does not currently work as a production service.**
>
> Envelope, its Terraform profile, and the protected acceptance workflow are under active development. The corrected version-2 topology has not recorded a passing live acceptance run. Treat the repository as an engineering prototype, not a deployment guide.

Envelope is a Linux-only Layer 3 packet-turnaround target for symmetric inline AWS Gateway Load Balancer (GWLB) inspection between two sites. For each valid AWS IPv4 GENEVE packet received on UDP/6081, a target immediately sends exactly one AWS-compliant return to the GWLB using only that packet's outer tuple and GENEVE metadata. The return preserves the inner packet byte-for-byte, including its VNI, protocol metadata, ordered options, and AWS flow cookie.

A target does not inject the inner packet into a TUN, forward it directly to the VPC or Tailscale, or retain return identity for another packet. It does not create `envelope0`, use `tailscale0`, make a local-versus-remote route decision, or restore flow state after restart.

## Documentation

Start with the [Docsify onboarding guide](docs/index.html) for the symmetric topology and migration boundary. The [AWS appliance runbook](docs/aws-appliance-runbook.md) and [two-region E2E runbook](docs/aws-two-region-e2e-runbook.md) define the protected lifecycle boundary and evidence requirements.

## Symmetric Topology

Each site has independent route and compute roles:

- Workload route tables send the peer site's exact CIDRs to a same-AZ GWLBE.
- Every enabled AZ has a GWLBE and a healthy-capable Envelope target path.
- After a target returns a packet to GWLB, the route table associated with the GWLBE subnet selects VPC local delivery for local-site CIDRs or one ready same-site transport-router ENI for remote-site CIDRs.
- At least two AZ-spread Tailscale transport routers accept the exact remote-site routes, disable subnet-route SNAT, and forward in both directions. At baseline, each router advertises exactly one assigned workload prefix. Each site's assigned prefix sets are non-empty and pairwise disjoint, their union exactly covers the local workload CIDRs, and every router remains forwarding-capable for bounded takeover of all local prefixes. Tailscale table 52 and serving paths contain only opposite-site workload prefixes; local prefixes stay on the VPC underlay.
- Every transport-router subnet route table sends each local-site CIDR to that destination workload prefix's AZ GWLBE, independent of the receiving router AZ. Target subnets carry only outer GWLB and management routes, never inner site routes.

For a packet from site A to site B, the path is:

```text
site A workload -> site A GWLBE -> site A GWLB -> site A target
  -> immediate return to site A GWLB -> site A GWLBE post-inspection route
  -> selected site A transport-router ENI -> Tailscale -> site B transport router
  -> site B GWLBE -> site B GWLB -> site B target
  -> immediate return to site B GWLB -> site B GWLBE local route -> site B workload
```

The reverse direction follows the same shape. Either workload may initiate a new TCP, UDP, or ICMP flow from its ordinary site CIDR. The transport routers preserve source addresses, and the inter-site path performs no NAT.

## Version-2 Configuration

Topology and target runtime configuration remain at version `2`. The rejected direct-inner-forwarding draft never shipped or passed protected acceptance, so version 2 is corrected in place rather than adding version 3 or a compatibility mode.

Targets accept packet-turnaround settings such as `--config-version=2`, `--udp-bind`, and `--max-inner-packet-size`. Site CIDRs belong to topology, GWLBE route tables, and transport-router configuration, not to target forwarding configuration. Target parsing rejects directional-lane fields and obsolete draft-v2 target CIDR, TUN, Tailscale, and host-routing fields before host or AWS mutation. Do not reuse an older configuration, Terraform state, plan, evidence file, or protected-run input.

The external `symmetric_topology.route_failover` object contains exactly these four fields:

- `mutation_timeout_seconds`: whole-second bound from `1` through `7200` for an authorized route mutation and convergence probe.
- `restoration_timeout_seconds`: whole-second bound from `1` through `7200` for unconditional route restoration and verification.
- `recovery_timeout_seconds`: whole-second bound from `1` through `7200` for the associated protected recovery exercise.
- `initial_transport_router_az_by_gwlbe_az`: exactly `west` and `east` maps in which every GWLBE AZ key maps to the equal enabled transport-router AZ key in that site.

The initial-selection map is same-AZ key equality, not a readiness election: a cross-AZ initial mapping is invalid. It is the only initial owner assignment. For each AZ, it derives both the transport-router fleet member's singleton `advertised_prefix` and the `source_workload_prefix` whose GWLBE route table sends every exact remote-site route to that same owner's primary ENI. There is no separate owner input. Internal settlement, quiet-window, and owner-lease durations are derived by the protected lifecycle and are not user inputs. The `transport_router_readiness_expectations` Terraform output is separate from topology and failover outputs; it describes the expected host contract and is not an observation that a router is ready.

An illustrative, incomplete Terraform shape is in [docs/terraform-example.md](docs/terraform-example.md). It is not a live deployment input.

## Local Run

Build the development binary:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

Run the packet-turnaround target locally on Linux:

```bash
sudo ./bin/envelope \
  --config-version=2 \
  --udp-bind=0.0.0.0:6081 \
  --max-inner-packet-size=1280 \
  --metrics-addr=0.0.0.0:9090
```

This starts only the target component. It does not construct the two-site route graph or prove AWS, Tailnet, multi-AZ, or failover behavior.

## Observability

- `GET :9090/healthz` reports packet receive and compliant-send readiness.
- `GET :9090/metrics` exposes valid receive, packet-return, profile-rejection, receive-boundary drop, MTU-drop, send-failure, and liveness metrics.

Relevant target metrics include `geneve_rx_packets`, `geneve_tx_packets`, `gwlb_profile_rejections_total`, `gwlb_receive_drops_total`, `gwlb_return_build_failures_total`, `gwlb_send_failures_total`, `gwlb_mtu_drops_total`, `gwlb_target_ready`, and `gwlb_target_component_ready`. Target health does not depend on a TUN, host forwarding, site routes, or Tailscale.

## Linux Requirements

The version-2 target service needs only `CAP_NET_RAW` for packet emission and does not need `CAP_NET_ADMIN`. The systemd unit grants that ambient capability to its unprivileged service process. It does not create a TUN, run `tailscaled`, enable host forwarding, or manage policy routes.

The local component wire smoke must be invoked with `sudo` and needs effective `CAP_NET_RAW`; its wrapper does not support a non-root file-capability invocation. The separate `envelope-transport-router-network.service` runs as root with `CAP_NET_ADMIN` and `CAP_NET_RAW`, and configures only host forwarding sysctls, the fail-closed firewall, and MSS clamping. Credentialed protected readiness, not that unit, verifies Tailscale backend and peer state, exact policy/route domains, EC2 source/destination checks, ENI identity, and the complete destination-prefix GWLBE route map.

Credentialed readiness checks every transport router as an observer. Every opposite-site observer must select each protected remote prefix's configured stable-node `PrimaryRoutes` owner. On every router, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix, and no same-site observer reports a protected local `PrimaryRoutes` claim. Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay. The higher-priority `iif tailscale0` local-prefix rules make every router capable of delivering all local prefixes through each destination workload prefix's AZ GWLBE during normal and takeover paths, including cross-AZ takeover. Source-prefix owner/ENI coupling remains mandatory: it is derived from singleton advertisements, control-plane stable identities, and opposite-site observations, binds those identities to protected instance IDs, and must agree with the primary ENI selected by `initial_transport_router_az_by_gwlbe_az`.

Failed protected run `ha25` proved this live route shape: each router installed exactly the two opposite-site workload routes in table 52 and formed only opposite-site serving paths. It did not complete acceptance, but it invalidated the earlier same-site sibling table-52/`PrimaryRoutes` requirement.

Failed protected run `ha46` proved why endpoint identity must follow the destination prefix rather than the receiving router: east/a takeover traffic for an east/b workload crossed both GWLBs through GWLBE a but produced no SYN-ACK because the workload reverse path used GWLBE b. Cleanup completed with zero residuals; no passing live acceptance result exists yet.

## Availability And Failover

The two-AZ profile supports bounded recovery for new flows through another healthy target or transport router. Failover is coordinated but not atomic. It is not hitless. A process, instance, AZ, GWLB, VPC route, or Tailscale selection change can interrupt established TCP and lose UDP packets. Protected acceptance must record recovery duration, established TCP outcome, and UDP loss; applications remain responsible for retries.

Graceful and abrupt transport-router exercises use the same single durable CAS/lease transaction. The protected runner first persists the transaction, temporarily expands the alternate's advertisement, withdraws or stops the current owner, waits for every opposite-site observer to converge on the transferred stable-node owner while local Tailnet routes remain absent, replaces every affected GWLBE route with the alternate ENI, and only then probes. Owners of unaffected prefixes stay fixed. Normal overlap and duplicate ownership are forbidden; temporary overlap is allowed only inside this durable transfer.

Restoration is part of that transaction on success, failure, timeout, or interruption. The original owner restarts at its singleton baseline while the alternate still covers the transferred prefix; the alternate then removes that prefix, every opposite-site observer converges on the baseline owner graph while local Tailnet routes remain absent, and every original ENI route is restored and held through a quiet verification window. The runner cannot publish a terminal result or hand off cleanup until advertisements, ownership, and routes are all restored. After lease expiry, a successor uses CAS to claim and complete recovery. Targets and transport routers have no AWS route-mutation authority, and this acceptance-only mechanism is not a production failover controller.

## Protected Evidence Boundary

The protected evidence contract uses bounded Linux `AF_PACKET` captures on target underlays to assert packet-scoped turnaround. The capture is reduced to frame, inner-packet, ordered-option, and flow-cookie SHA-256 values plus VNI and outer-tuple checks, and the raw PCAP is deleted. Ownership evidence records the transferred source prefix, fenced forward and restore generations, stable-node hashes bound to protected instance IDs, before/transferred/restored opposite-site owner graphs, absence of local Tailnet routes and claims, current-to-alternate-to-original ENI transitions, and verified restoration of advertisements, ownership, and routes. Retained evidence contains no raw packet payload, ordered-option bytes, or flow-cookie value. This is an evidence requirement, not a claim that live acceptance passed.

## Acceptance Cost

The checked-in HA planning profile assumes two sites with two AZs each, two GWLBs, four GWLBE endpoints, four `t3.medium` targets, four `t3.micro` transport routers, four `t3.micro` workloads, and one management NAT gateway and Elastic IP per VPC. Its Terraform defaults use an estimated fixed cost of `$4.00/hour` and an approved fixed-cost ceiling of `$5.00/hour`.

The one-NAT-per-site layout is a management-cost limitation, not site-level egress HA. One shared NAT in each site's single management subnet serves private egress across that site; a NAT or management-AZ failure can remove bootstrap and control-plane egress. It remains outside the inspected inter-site path and does not strengthen the transport availability claim.

Those values are plan gates, not a current AWS price quote or authorization to run. They exclude variable GWLB/GWLBE processing, cross-AZ and inter-region transfer, NAT data processing, logging, storage, taxes, and price drift. Before a protected run, review the fresh plan's counts and current regional prices, keep the estimate within the approved ceiling, set a short expiry, and clean up immediately.

## Local Validation

```bash
go test ./...
python3 scripts/verify_geneve_fixtures.py
python3 scripts/verify_systemd_units.py --source-only
python3 scripts/test_docs.py
python3 scripts/secret_scan.py --root .
```

These checks are not live AWS acceptance.

## Migration And Protected Runs

Migration is breaking. Destroy only resources owned by an old acceptance run before creating a fresh version-2 topology; never mix old and corrected route domains or reuse old evidence.

The protected lifecycle owns preflight, deployment, drain, failover exercises, evidence verification, route restoration, and cleanup. It is intentionally not presented as a copy-paste command: use it only from an approved protected environment with a fresh run identity, reviewed version-2 configuration, current cost approval, and scoped credentials. Do not use old protected-run configuration snippets, direct Terraform commands, or prior workflow procedures.
