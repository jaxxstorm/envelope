# AWS Two-Region E2E Runbook

## Status

This page defines the required acceptance boundary for the corrected symmetric two-site GWLB topology. It does not record a successful live run. Protected run `ha25` failed acceptance but supplied the live route evidence used to correct the readiness contract below. Execution remains restricted to an approved protected environment and a fresh run-owned version-2 configuration after the implementation and static gates pass.

Do not execute an earlier acceptance workflow, use direct Terraform commands, or reuse previous state, plans, evidence, or configuration. The rejected target-forwarding draft is incompatible with corrected version 2. Every run must start with a fresh approved run identity and use only the lifecycle that owns creation, route mutation, evidence, restoration, and cleanup.

## Acceptance Topology

Both sites use ordinary local workload CIDRs, so either site can cold-initiate TCP, UDP, or ICMP traffic to the other. The expected path for every inter-site packet is:

```text
source workload -> source-site GWLBE -> source-site GWLB -> source-site target
  -> immediate return to source GWLB -> source GWLBE post-inspection route
  -> selected source transport-router ENI -> Tailscale -> destination transport router
  -> destination-site GWLBE -> destination-site GWLB -> destination-site target
  -> immediate return to destination GWLB -> destination GWLBE local route
  -> destination workload
```

Each target handles only the current AWS GENEVE packet and returns it exactly once with identical inner bytes, VNI, protocol metadata, ordered options, cookie, and packet-specific AWS tuple. It does not use a TUN, Tailscale, host forwarding, or retained flow identity.

The dedicated transport routers are bidirectional. A source-site router receives post-inspection remote traffic through its selected ENI and forwards it through Tailscale without NAT. A destination-site router receives Tailnet traffic for a local-site CIDR and forwards it to the underlay, where its subnet route selects the same-AZ GWLBE. After each target turnaround, the GWLBE route table selects remote ENI transit or VPC local delivery.

## Required Profile

- Exactly two sites in distinct regions and two enabled availability zones per site.
- A GWLBE and healthy-capable target path in every enabled AZ.
- At least two AZ-spread transport routers per site with distinct eligible ENIs.
- Exactly one assigned workload-prefix advertisement per router at baseline; each site's per-router prefix sets are non-empty, pairwise disjoint, and exactly cover local workload CIDRs.
- Every router remains forwarding-capable for bounded takeover of all local prefixes, accepts exact remote-site routes, disables subnet-route SNAT, and preserves source addresses.
- Tailscale table 52 and serving paths contain only opposite-site workload prefixes; every local prefix stays on the main/VPC underlay.
- Disjoint local-site and remote-site CIDRs, with each remote list equal to the peer's local list.
- Separate workload, transport-router, GWLBE, target, and management route domains.
- Workload remote routes and transport-router local routes through same-AZ GWLBE endpoints.
- GWLBE post-inspection local delivery and one selected same-site transport-router ENI per exact remote prefix.
- An approved fixed-cost ceiling and short, explicit resource expiry before any future infrastructure creation.

The [Terraform topology shape](terraform-example.md) is illustrative only and deliberately omits a protected configuration. It is not a deployment instruction.

## External Failover Input

`symmetric_topology.route_failover` accepts exactly `mutation_timeout_seconds`, `restoration_timeout_seconds`, `recovery_timeout_seconds`, and `initial_transport_router_az_by_gwlbe_az`. The three timeout values are whole seconds from `1` through `7200`. The selection object has exactly `west` and `east` maps; each map covers every GWLBE AZ key, and every mapped transport-router AZ key must equal that GWLBE AZ key. Extra lifecycle timing fields or compatibility aliases are rejected.

`initial_transport_router_az_by_gwlbe_az` is required same-AZ key equality, so no cross-AZ initial mapping is valid. It is declarative initial state, not a readiness election or an autonomous failover rule, and there is no separate owner input. For each AZ it derives both the transport-router fleet member's singleton `advertised_prefix` and the route output's `source_workload_prefix`; all exact remote-site routes in that source prefix's GWLBE table select the same owner's primary ENI. Settlement, quiet-window, and owner-lease timing is derived internally from reviewed external bounds and is not supplied by the operator.

Terraform's `route_failover` output resolves those selections to route-table and ENI identities. The separate `transport_router_readiness_expectations` output describes the expected host contract; credentialed protected readiness must still prove the live Tailnet, host, AWS route, source/destination-check, and ENI state.

## Preflight Boundary

Before billable resources or live traffic, protected preflight must fail closed unless it proves:

- Fresh version-2 configuration with no directional, compatibility, target TUN, target Tailscale, target site-CIDR, or host-routing fields.
- Exact run ownership, durable cleanup authority, expiry, scoped credentials, artifact identity, and Tailnet policy.
- Expected two-AZ target and transport-router fleets, route tables, endpoint identities, eligible ENIs, and initial route selections.
- Target packet-receive, validation, and compliant-send readiness independent of transport readiness.
- Both transport directions, no NAT, exact advertisements and accepted routes, source preservation, and local GWLBE routing.
- Exact local policy rules and complete prefix route chains, non-expired serving peers with peer-bound bounded ping observations, and the live-MTU-derived MSS rule in both directions.
- Every opposite-site observer selects each protected remote prefix's configured stable-node `PrimaryRoutes` owner, with stable-node identity bound to its protected transport-router instance ID.
- On every router, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix; no same-site observer reports a protected local `PrimaryRoutes` claim.
- Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay; the higher-priority `iif tailscale0` local-prefix rules make every router capable of delivering all local prefixes during normal and takeover paths.
- Source-prefix owner/ENI coupling remains mandatory: it is derived from singleton advertisements, control-plane stable identities, and opposite-site observations and must agree with the protected instance ID and initial GWLBE owner ENI selected by the same-AZ map.
- Fresh plan resource counts, a current fixed-cost estimate within the approved ceiling, and review of variable-cost exposure.
- Derived graceful and abrupt transaction reservations must fit the active-run and per-stream bounds, and worst-case restoration must fit the independent cleanup reservation, before run-all acquires resource authority.

No preflight result is evidence that live traffic or failover passed.

Failed protected run `ha25` proved the corrected live route shape: each router installed exactly the two opposite-site workload routes in table 52 and formed only opposite-site serving paths. It invalidated the earlier same-site sibling table-52/`PrimaryRoutes` requirement but did not pass acceptance task 6.4.

Failed protected run `ha26` reached corrected deployment readiness and again cleaned up with zero residuals, but its two worst-case failover reservations totaled 5,560 seconds against a 5,400-second active-run bound. Run-all now rejects that mismatch before resource authority; the next reviewed configuration reduces recovery from 600 to 300 seconds without changing the cleanup, mutation, or restoration bounds.

Failed protected run `ha27` passed readiness and simultaneous bidirectional cold initiation, then exposed that the checksum-pinned wire inspector was not installed on the four packet-return targets. Every capture completed and every raw PCAP was deleted, but inspection failed closed with exit 127. Symmetric readiness now installs and verifies the inspector on every target before acceptance traffic and preserves the redacted command failure when inspection fails.

Failed protected run `ha28` proved the target inspector correction: all four captures completed, were inspected, and had their raw PCAPs deleted. The subsequent target proof exposed that the runner accepted only unlabeled metric samples even though the required production failure counters are labeled by reason. Target proofs now aggregate every finite series in each exact failure-counter family and continue to fail closed on missing or non-finite metrics.

Failed protected run `ha29` passed both bidirectional traversals, packet fidelity, and labeled metric proofs, then reached target-process recovery. The stopped target remained AWS `healthy` through the runner's 90-second wait because implicit provider timing used a 30-second interval and three unhealthy observations, leaving no consensus or API margin. Both target groups now use an explicit 10-second interval, 5-second timeout, healthy threshold 5, and unhealthy threshold 2. The saved-plan contract rejects different or implicit timing, and process failure proves the service and `/healthz` are down before requiring the exact AWS `unhealthy` transition.

Failed protected run `ha30` proved the target-health correction by observing the exact AWS `unhealthy` transition, alternate-flow recovery, and restoration. Its long-lived TCP continuity commands then failed: retained SSM status showed a receiver JSON decode error and a client execution timeout. Review found that the embedded newline-frame reader discarded bounded trailing bytes when one TCP read contained multiple frames, while the SSM deadlines left only 5-10 seconds beyond the measured stream. The reader now carries trailing bytes between frames, regression coverage injects coalesced frames, command execution leaves 30 seconds of reporting headroom, and waits leave 40 seconds.

Failed protected run `ha31` proved that framing correction: both TCP and UDP continuity clients and receivers completed successfully, TCP resumed and recorded 158 markers, and UDP resumed after bounded loss with 39 trailing markers. The UDP stream's last marker nevertheless preceded the restoration-end clock by 2.49 seconds because target-process stream sizing reserved only the generic 30-second overhead around a mutation that also performed bounded control and restoration work. Target-process callers now reserve an additional 30-second mutation margin before the generic post-mutation window; analysis still requires a marker after the measured mutation interval.

## Evidence Expectations

Protected acceptance must prove simultaneous cold initiation from both sites for TCP, UDP, and ICMP without directional CIDR partitioning. For each direction, evidence must bind the source and destination GWLBE, GWLB target, transport router, and ENI identities and prove both target turnarounds. Preflight evidence records bounded per-prefix Tailnet ownership from every opposite-site observer, maps stable node IDs to protected transport-router instance IDs, proves local Tailnet routes and claims are absent, and verifies that each source-prefix owner agrees with the GWLBE ENI selection.

Packet-level assertions must show exactly one immediate return for each valid ingress packet with byte-identical inner data, VNI, protocol metadata, ordered options, cookie, and the current packet's AWS outer tuple. Invalid packets must produce no send. The assertion must not infer turnaround solely from an application response or aggregate counter.

The protected evidence boundary uses bounded Linux `AF_PACKET` captures on each target underlay. Capture processing retains only capture/frame counts, frame SHA-256 values, `inner_packet_sha256`, `ordered_options_sha256`, `flow_cookie_sha256`, VNI, and tuple/port assertion results. The raw PCAP is deleted, and retained evidence contains no raw application payload, ordered-option bytes, or flow-cookie value.

The lifecycle must separately exercise:

- Target process quiesce, AWS deregistration and drain, restart, and alternate-target new-flow recovery.
- Target instance replacement and restored target-fleet readiness.
- Graceful and abrupt transport-router loss through the single durable Tailnet-ownership and GWLBE-route transaction.
- Protected-runner replacement of all affected exact GWLBE remote routes with the eligible alternate same-site ENI only after opposite-site stable ownership converges and local Tailnet routes remain absent.
- Unconditional ordered restoration and verification of the original advertisements, opposite-site owner graph, local-route absence, and every original ENI route target.

Evidence must record health transitions, the transferred source prefix, fenced forward and restore generations, stable-node hashes bound to protected instance IDs, before/transferred/restored owner graphs from every opposite-site observer, absence of same-site local Tailnet routes and claims, current-to-alternate-to-original ENI transitions, recovery duration, established TCP outcome, UDP sent/received/loss, all-component restoration of advertisements, ownership, and routes, cost values, and an ownership-safe residual audit. Retained evidence must be redacted and pass the repository secret scan. No corrected evidence bundle is documented as accepted yet.

## ENI Route Exercise

Only the protected runner owns this exercise. The current source-prefix owner and ENI are resolved together from `initial_transport_router_az_by_gwlbe_az`, singleton advertisements, control-plane stable identities, and opposite-site observations, not from observed readiness or a separate owner field. Before mutation, the runner verifies the durable run and cleanup claim, exact source prefix, route table and remote-prefix allowlists, current and alternate stable-node/instance/ENI bindings, deterministic singleton baselines, remote-only table 52, absence of local Tailnet routes and claims, and readiness. Graceful and abrupt failures both use one durable CAS/lease transaction in this order:

1. Persist the authorized transaction and fenced forward/restore generations before any mutation.
2. Temporarily expand the alternate advertisement to include the source prefix while retaining its own prefix.
3. Withdraw or stop the current owner with the fenced forward generation.
4. Wait through the quiet window for every opposite-site observer to select the alternate stable node for the transferred prefix while every unaffected owner stays fixed and local Tailnet routes remain absent.
5. Replace every affected exact remote-prefix route in the GWLBE table with the alternate primary ENI and verify route convergence.
6. Probe new TCP and UDP flows only after the owner graph and every affected ENI route agree.

Normal overlap and duplicate primary ownership are forbidden. Temporary overlap is permitted only inside the persisted transfer, including the bounded interval between alternate expansion and current withdrawal.

After success, probe failure, timeout, interruption, or partial mutation, restoration remains in that transaction and follows this order:

1. Restart the original owner at its singleton baseline while the alternate still covers the transferred prefix.
2. Remove the transferred prefix from the alternate, returning it to its singleton baseline.
3. Wait for every opposite-site observer to converge on the complete baseline owner graph, verify local Tailnet routes remain absent, and reverify both routers.
4. Restore all affected routes to the original ENI and hold the complete snapshot through the quiet verification window.

The lifecycle cannot emit a terminal result or permit cleanup handoff to another phase while advertisements, ownership, or routes remain unrestored. If the runner disappears, the durable journal remains authoritative; only after lease expiry may a successor win the CAS recovery claim and complete restoration. Ambiguous ownership or unexpected route state fails closed, and restoration failure remains a failed acceptance result and reported residual. Targets and transport routers have no route-mutation authority.

The Tailnet ownership transfer and GWLBE route replacements are coordinated but are not atomic. Evidence must identify each control-plane transition and prove their ordered agreement.

## Availability Limit

The profile is designed for bounded new-flow recovery. It is not hitless. A target process, instance, transport router, AZ, GWLB, GWLBE route, or Tailscale selection failure can interrupt established TCP and lose UDP traffic while AWS and Tailscale control planes converge. The coordinated ownership and route operation is not atomic, and neither target reassignment nor Tailnet convergence implies stateful transport continuity.

Applications must provide retry behavior. Acceptance records observed recovery and packet loss against approved bounds; it does not promise uninterrupted transport or establish a production SLO.

## Cost Boundary

The approved planning assumptions are two sites with two AZs each, two GWLBs, four GWLBE endpoints, four `t3.medium` targets, four `t3.micro` transport routers, four `t3.micro` workloads, and one management NAT gateway and Elastic IP per VPC. The profile uses a `$4.00/hour` fixed estimate and a `$5.00/hour` approved fixed ceiling. Each NAT is shared from its site's single management subnet, so private management and bootstrap egress is not multi-AZ. This one-NAT-per-site limitation is outside the inspected inter-site route and is not covered by target or transport-router HA exercises.

The estimate omits variable GWLB/GWLBE processing, NAT data, cross-AZ and inter-region transfer, log ingestion, storage, taxes, and price changes. Protected preflight must review a fresh saved plan and current regional prices rather than treating these values as a quote. The run expiry must reserve acceptance and cleanup time without exceeding the lifecycle's bounded new-run window, and cleanup starts immediately after the exercise.

## Protected-Run Safety

- Run acceptance only from an approved protected environment with reviewed source and scoped, short-lived credentials.
- Keep credentials out of config files, Terraform input, command arguments, plans, diagnostics, and logs.
- Do not enable shell tracing around lifecycle tooling.
- Do not retain or upload state, plans, raw packet captures, rendered user data, or unredacted diagnostics.
- Cleanup must use exact run ownership, restore route mutations, remove run-owned resources, and leave shared backend infrastructure untouched.

Use local and static validation before requesting a protected run:

```bash
python3 scripts/test_docs.py
python3 scripts/test_terraform_contract.py
python3 scripts/test_transport_router_readiness.py
python3 scripts/verify_systemd_units.py --source-only
python3 scripts/secret_scan.py --root .
```
