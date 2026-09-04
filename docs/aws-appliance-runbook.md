# AWS Appliance Deployment Runbook

## Status

The AWS appliance topology retains version `2` while replacing the rejected target-forwarding draft with packet-scoped GWLB turnaround, GWLBE subnet routing, and separate transport routers. Fresh protected run `ha53` passed the corrected profile; earlier failed runs supplied the live Tailnet, endpoint-symmetry, deadline, continuity, DNS-health, evidence, and receiver-window results used to correct the contract below. The project remains experimental, and this page is a safety and architecture reference rather than an executable live-run procedure.

Do not use an older protected configuration, saved plan, state file, workflow, evidence file, or direct Terraform command with this topology. Do not translate an old configuration by hand. Every future approved run must create a fresh, run-owned version-2 deployment and own its cleanup.

## Required Architecture

Each site must have at least two enabled availability zones and these separate route domains:

| Domain | Required forwarding behavior |
| --- | --- |
| Workload | Exact remote-site CIDRs select the same-AZ GWLBE. |
| Transport router | In every table, each exact local-site CIDR selects that destination workload prefix's AZ GWLBE, independent of the receiving router AZ; accepted exact remote routes select Tailscale. |
| GWLBE subnet | After GWLB inspection, local-site CIDRs use VPC local delivery and remote-site CIDRs select one ready same-site transport-router ENI. |
| Envelope target | Outer GWLB and management traffic only; no inner site route, TUN, Tailscale, or host transit. |
| Management | Kept separate from packet-transit route domains. |

Every enabled AZ requires a local GWLBE and a healthy-capable Envelope target path. Each site also requires at least two independent AZ-spread Tailscale transport routers with distinct eligible ENIs. At baseline, each router advertises exactly one assigned workload prefix. The per-router assigned prefix sets are non-empty and pairwise disjoint and exactly cover the local workload CIDRs; every router nevertheless remains forwarding-capable for bounded takeover of all local prefixes. Routers accept exact remote-site routes, disable subnet-route SNAT and Tailnet DNS acceptance, retain the VPC resolver, and forward both site-transit directions. Tailscale table 52 and serving paths contain only opposite-site workload prefixes. Local-site CIDRs must exclude the VPC DNS resolver address at VPC network address plus two so its unavoidable host route cannot intersect a protected prefix. Targets do not join Tailscale or advertise routes.

## Packet Turnaround

For every valid AWS packet received from `<gwlb-ip>:<flow-port>` at `<target-ip>:6081`, the target immediately emits exactly one return from `<target-ip>:<flow-port>` to `<gwlb-ip>:6081`. The return uses only that ingress packet's identity and preserves its byte-identical inner packet, VNI, protocol metadata, critical-option state, complete ordered options, and AWS flow cookie.

The target discards that packet-scoped identity after the send. It does not index an inner tuple, retain return context, wait for a reverse packet, inject into a TUN, decrement the inner TTL, apply NAT, or forward directly to the VPC or Tailscale. Invalid outer, GENEVE, option, cookie, length, or inner-protocol framing produces no return.

GWLB sends the returned packet back to the GWLBE. Only then does the GWLBE subnet route table decide whether the destination is local or remote. This endpoint-owned post-inspection decision is required for both source-site remote transit and destination-site local delivery.

## Target Readiness

Before a target is registered healthy, it must prove:

- AWS GENEVE receive and complete profile validation are initialized.
- Packet-scoped compliant-send initialization succeeded.
- Persistent receive or send errors remain below the configured threshold.
- The service uses the reviewed version-2 packet-turnaround settings, needs only `CAP_NET_RAW`, and does not need `CAP_NET_ADMIN`.

Target readiness must not depend on TUN state, Tailscale, host forwarding, site CIDRs, firewall transit rules, MSS policy, or transport routes. Before a planned process stop or instance replacement, the protected lifecycle must mark the target unready, observe AWS deregistration and drain, retain bounded redacted diagnostics, and only then stop or replace it.

## Transport-Router Readiness

Transport-router readiness is independent of target health. Every eligible router must prove:

- Running Tailscale in kernel-TUN mode, an online non-expired node, and exactly its one assigned `advertised_prefix` at baseline.
- Live `CorpDNS` false, VPC DNS still authoritative, and no Tailscale health condition.
- Exact accepted remote-site routes with a bounded data-plane check to the serving peer.
- Every opposite-site observer selects each protected remote prefix's configured stable-node `PrimaryRoutes` owner, which is online and non-expired.
- On every router, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix; no same-site observer reports a protected local `PrimaryRoutes` claim.
- Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay.
- Stable-node identities are bound to protected instance IDs, and source-prefix owner/ENI coupling is derived from singleton advertisements, control-plane stable identities, and opposite-site observations and must agree with the primary ENI selected for that source prefix's GWLBE route table.
- Subnet-route SNAT disabled and source addresses preserved.
- Persistent bidirectional forwarding, supported reverse-path settings, the reviewed no-NAT firewall and MSS policy, and disabled EC2 source/destination checks.
- An effective remote route to Tailscale and, across each complete local prefix, an effective VPC route to that destination workload prefix's AZ GWLBE.
- A distinct run-owned ENI eligible only for same-site GWLBE remote routes.

A transport router's root host-network setup runs as `envelope-transport-router-network.service` and uses `CAP_NET_ADMIN` and `CAP_NET_RAW`. The unit owns only forwarding and reverse-path sysctls, exact fail-closed firewall chains, and MSS clamping; its service state or local marker does not declare AWS, Tailnet, route, or ENI readiness. Terraform emits the expected host contract as the separate `transport_router_readiness_expectations` output. That output is not part of `symmetric_topology.route_failover` and is not a live readiness result. The credentialed protected readiness gate separately observes exact policy and prefix route chains, Tailscale peer expiry and bounded ping results, EC2 source/destination checks, ENI identity, and the complete destination-prefix GWLBE map. These transport privileges are not granted to the Envelope target service.

The priority-100 `iif tailscale0` local-prefix rules make every router capable of delivering all local prefixes during normal and takeover paths by sending arriving local traffic through `main`, the VPC underlay, and the destination workload prefix's AZ GWLBE. Any local table-52 route or same-site protected local `PrimaryRoutes` claim makes the router ineligible, as does a broader, narrower, missing, duplicate, source-specific, shadowed, terminal, wrong-device, wrong-endpoint, or NAT-rewritten route.

Failed protected run `ha25` proved this shape directly: each router installed exactly the two opposite-site workload routes in table 52 and formed only opposite-site serving paths. The finding corrects the contract; it is not a passing acceptance result.

Failed protected run `ha46` proved the endpoint half of this shape during graceful takeover: east/a received a packet for the east/b workload, but its old uniform local routes selected GWLBE a while the workload reverse route selected GWLBE b. Both GWLBs observed SYNs, no SYN-ACK returned, cleanup reached zero residuals, and the run did not satisfy acceptance.

Failed protected run `ha47` proved the corrected endpoint shape: ownership and both affected routes transferred to east/a, and both full TCP and UDP cross-AZ recovery proofs completed. The second sequential proof finished about eight seconds after the shared 120-second mutation deadline. The runner now bounds ownership transfer and GWLBE route convergence with `mutation_timeout_seconds`, then jointly bounds the sequential TCP and UDP proofs with a fresh `recovery_timeout_seconds` deadline. Restoration and one-attempt cleanup reached zero residuals; the run still did not satisfy acceptance.

Failed protected run `ha48` proved the separated recovery deadline and completed the graceful transfer, both full cross-AZ proofs, and restoration. Its nested TCP agent then lost one isolated marker more than 13 minutes after restoration because observation continued for the full 2,735-second worst-case reservation. The full durable transaction reservation remains the continuity-command watchdog with a conservative 600-second paired-control allowance, but instance and transport-router TCP/UDP streams now run concurrently around one shared mutation and use runner-controlled completion after at least 20 successful sends and a final post-mutation marker. The runner validates every successful-send completion timestamp internally, emits exact sent, acknowledged, and lost counts, and still rejects any earlier loss outside the measured interval; target-process streams are unchanged. One-attempt cleanup reached zero residuals; the run still did not satisfy acceptance.

Failed protected run `ha49` proved controlled completion and both abrupt alternate-path probes, then the abruptly restarted original router reported three Tailscale health conditions while its DNS forwarder logged that no upstream resolvers were available. Strict readiness correctly withheld original-route restoration. Transport bootstrap and restoration now explicitly keep `accept-dns=false`, and host plus protected readiness verify `CorpDNS` false while retaining the empty-health gate. Cleanup reconciled both singleton advertisements, opposite-site ownership, and original ENI routes before one-attempt cleanup returned `final_residual_count` 0; the run still did not satisfy acceptance.

Fresh protected run `ha53` passed target process and instance recovery plus graceful and abrupt router failover from exact revision `edd33dc8693c381f7ba8428f445c7b7bc512a866`. Every fresh flow succeeded, every router continuity stream resumed, advertisements, ownership, and routes restored, final no-drift verification passed, and strict schema-3 evidence verification accepted the result. Its $4.09/hour fixed estimate was within the $5.00/hour ceiling; one-attempt cleanup and independent authoritative checks found no live AWS, backend, or Tailnet residual. The two-region E2E runbook retains the measured durations and evidence digest.

## Runner-Owned ENI Failover

Each GWLBE table's exact remote-site routes have one active transport-router ENI target and at least one ready same-site alternate. At baseline, the same router owns that GWLBE AZ's source workload prefix in Tailscale; route and stable-node ownership must agree.

The external `symmetric_topology.route_failover` object contains exactly `mutation_timeout_seconds`, `restoration_timeout_seconds`, `recovery_timeout_seconds`, and `initial_transport_router_az_by_gwlbe_az`. All three timeouts are whole seconds from `1` through `7200`. `mutation_timeout_seconds` bounds ownership transfer and GWLBE route convergence. After convergence, the sequential TCP and UDP proofs jointly use a fresh `recovery_timeout_seconds` deadline; unconditional restoration uses its separate bound. The final object contains exactly `west` and `east` maps; each map covers every GWLBE AZ key, and every value must equal its GWLBE AZ key.

`initial_transport_router_az_by_gwlbe_az` is required same-AZ key equality; a cross-AZ initial mapping is invalid. It is the sole initial ownership input, not a readiness election. For each AZ it derives the transport-router output's singleton `advertised_prefix`, the route output's `source_workload_prefix`, and the owner primary ENI targeted by every exact remote-site route in that source prefix's GWLBE table. There is no separate owner input. Internal settlement, quiet-window, and owner-lease durations are derived by the protected lifecycle and must not be supplied as external fields.

Only the protected runner may coordinate the Tailnet ownership and GWLBE route changes during an approved acceptance exercise. Before mutation it verifies the durable run identity, exact source prefix, route-table and remote-prefix allowlists, current and alternate stable-node/instance/ENI bindings, deterministic baselines, router readiness, and cleanup authority. Graceful and abrupt failures then use one durable CAS/lease transaction in this order:

1. Persist the authorized transaction and its fenced forward and restore generations before mutation.
2. Temporarily expand the alternate from its singleton baseline to include the transferred source prefix.
3. Withdraw or stop the current owner using the same fenced forward generation.
4. Wait through the quiet window until every opposite-site observer selects the alternate's stable node for that prefix while every unaffected owner stays fixed and local Tailnet routes remain absent.
5. Replace every affected exact GWLBE remote-prefix route with the alternate's primary ENI and verify convergence.
6. Run the new-flow probe only after Tailnet ownership and every affected AWS route agree.

Normal advertisement overlap and duplicate primary ownership are forbidden. Temporary overlap during the alternate expansion, including the interval before current withdrawal, is valid only while recorded inside this durable transfer. The coordinated Tailnet and per-route AWS updates are not atomic or hitless.

Restoration is unconditional and remains in the same transaction on success, failure, timeout, or interruption. It runs in this order:

1. Restart the original owner at its singleton baseline with Tailnet DNS acceptance disabled while the alternate still covers the transferred prefix.
2. Return the alternate to its singleton baseline, removing the transferred prefix.
3. Wait for every opposite-site observer to converge on the complete original owner graph, verify local Tailnet routes remain absent, and verify both routers are ready.
4. Restore every affected route to the original owner ENI, then hold the complete route snapshot through the quiet verification window.

No terminal result or cleanup handoff is permitted while advertisements, ownership, or routes are unrestored. If the runner disappears, the durable journal remains active; after lease expiry a successor must win the CAS recovery claim and complete restoration before the lifecycle proceeds. Ambiguous ownership, unexpected current state, or an out-of-scope prefix fails closed. Envelope targets and transport routers receive no EC2 route-mutation permission. This bounded acceptance mechanism is not an autonomous production failover controller.

## Security Boundary

- Use only an approved protected environment and short-lived, scoped credentials supplied to the lifecycle runner.
- Tailnet preflight requires every active exact route approval and grant. Additional canonical entries may remain only when disjoint from the active protected prefixes; broader, narrower, wildcard, or overlapping entries still fail closed.
- Never place AWS credentials, Tailscale keys, OAuth secrets, or backend credentials in repository files, Terraform variables, command arguments, plans, or retained logs.
- Treat saved plans, state, rendered user data, packet captures, and diagnostics as sensitive. Retain only redacted evidence selected by the lifecycle and secret-scan it before upload.
- Packet-fidelity assertions use bounded Linux `AF_PACKET` captures on target underlays. Retained evidence contains frame, inner-packet, ordered-option, and flow-cookie SHA-256 values and decoded field assertions only; the raw PCAP, raw payload, option bytes, and flow-cookie value are deleted rather than retained.
- Transport-transfer evidence includes the exact source prefix, fenced forward and restore generations, stable-node hashes bound to protected instance IDs, before/transferred/restored owner graphs from every opposite-site observer, absence of same-site local Tailnet routes and claims, current-to-alternate-to-original ENI transitions, and verified restoration of advertisements, ownership, and routes.
- Every run must use fresh resource ownership and expiry, review current AWS pricing, and enforce the approved fixed-cost ceiling before resources are created.
- Cleanup must be ownership-safe and exact-resource scoped, restore all mutated routes, and include a residual audit. Never substitute broad tag-based deletion.

## Availability And Cost

The two-AZ target fleet and two transport routers per site support bounded alternate-path recovery for new flows after target process, target instance, transport-router, or selected-ENI loss. Recovery is coordinated but not atomic. It is not hitless. GWLB health reassignment, VPC route replacement, and Tailscale route convergence can interrupt established TCP and lose UDP packets, so applications must retry. A complete AZ, GWLB, endpoint, route-domain, or control-plane failure can also prevent recovery within the exercise bound.

Protected acceptance must measure target, router, endpoint, and ENI identities; health and route transitions; new-flow recovery time; established TCP outcome; UDP loss; route restoration; and cleanup. Protected run `ha53` produced the first verified corrected evidence; its observed result does not convert those measurements into a production SLO.

The checked-in planning profile assumes two regions, two AZs per site, two GWLBs, four GWLBE endpoints, four `t3.medium` targets, four `t3.micro` transport routers, four `t3.micro` workloads, and one NAT gateway and Elastic IP per VPC for management egress. The fixed estimate is `$4.00/hour`, bounded by an approved `$5.00/hour` fixed ceiling. The single NAT is shared through each site's one management subnet, so private egress is not multi-AZ within a site. This one-NAT-per-site management limitation remains outside the inspected data path and does not change the no-NAT inter-site transport contract.

The fixed estimate excludes variable GWLB/GWLBE processing, NAT data processing, cross-AZ and inter-region transfer, logs, storage, taxes, and price drift. A future run must review fresh resource counts and current regional pricing, stay within its explicit expiry, and clean up immediately. The ceiling alone is not authorization to run.

## Current Safe Checks

The following checks do not create AWS resources and may run from a reviewed checkout:

```bash
python3 scripts/test_docs.py
python3 scripts/test_terraform_contract.py
python3 scripts/test_transport_router_readiness.py
python3 scripts/verify_systemd_units.py --source-only
python3 scripts/secret_scan.py --root .
```

Follow the [two-region E2E runbook](aws-two-region-e2e-runbook.md) for the protected-run boundary and required evidence. It intentionally does not publish an unsafe direct infrastructure command sequence.
