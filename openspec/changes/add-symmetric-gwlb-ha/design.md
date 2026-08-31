## Context

The accepted baseline is deliberately asymmetric: a regional Envelope process records AWS GENEVE return metadata in memory, and a packet returned from Tailscale must reach that same process to be re-encapsulated. Static routes therefore divide every site into initiator and responder CIDRs, and Terraform rejects more than one regional target. This prevents a normal site-to-site network in which either workload may initiate traffic.

The first implementation of topology/configuration version 2 attempted to solve that limitation by treating an Envelope target as a router. It validated and decapsulated a GWLB packet, injected the inner packet into `envelope0`, and forwarded it directly to either `tailscale0` or the local VPC. Live acceptance run `ha14` demonstrated that this path does not complete the AWS service chain.

The packet-turnaround correction reached real bidirectional traffic in protected run `ha24`, where all six cold probes timed out. Read-only SSM history proved that one remote UDP workload received the source-preserved request and emitted its acknowledgement, but the receiving Tailscale router rejected that return because a different same-site router owned the source prefix in its `PrimaryRoutes` view. With SNAT disabled, WireGuard cryptokey routing requires the packet-emitting peer to own the preserved source prefix. Tailscale regional routing can select different overlapping advertisers for different observers, so Tailnet ownership and GWLBE egress cannot remain independent.

Protected run `ha25` did not pass acceptance, but its live route evidence disproved part of the resulting readiness contract. Every router installed exactly the two opposite-site workload routes in table 52 and formed serving paths only to opposite-site peers. A same-site observer does not need, and must not be required to report, its sibling's local prefix as a protected `PrimaryRoutes` owner or table-52 route. All local prefixes, whether assigned to the current router or its sibling, remain on the main/VPC underlay; the higher-priority `iif tailscale0` local-prefix rules make every router capable of delivering them during normal operation and takeover. Durable failover and restoration ordering, fencing, non-hitless behavior, and evidence requirements remain unchanged.

AWS documents a GWLB as a transparent single entry and exit point. A target appliance receives GENEVE traffic and sends it back to GWLB; GWLB returns it to the GWLBE, and the route table associated with the GWLBE subnet sends the inspected packet to its final next hop. The relevant AWS descriptions are [What is a Gateway Load Balancer?](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/introduction.html), [Gateway Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html), and [Access virtual appliances through AWS PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/vpce-gateway-load-balancer.html). The corrected design follows that appliance-return and endpoint-routing model.

## Goals / Non-Goals

**Goals:**
- Support arbitrary TCP, UDP, and ICMP initiation between disjoint site CIDRs without NAT.
- Send every inter-site packet through the source site's and destination site's GWLBE, GWLB, and healthy Envelope target fleet exactly once per site traversal.
- Return every valid target ingress packet immediately to its GWLB with the same inner bytes and that packet's AWS tuple and GENEVE metadata.
- Keep target processing independent between packets, with no target flow table or later-packet metadata lookup.
- Support at least two AZs per site, an Envelope target in every enabled target AZ, and at least two Tailscale transport routers per site.
- Use each GWLBE subnet route table for post-inspection local delivery or selection of the deterministic owner ENI for the source prefix associated with that GWLBE.
- Require table 52 and Tailnet serving paths to contain only opposite-site workload prefixes while every local prefix remains on the main/VPC underlay.
- Prove bounded target and runner-owned ENI-route failover behavior and report observed packet loss and recovery time.

**Non-Goals:**
- A lossless or hitless guarantee for TCP, UDP, Tailscale, GWLB, instance, or AZ failure.
- Target forwarding of decapsulated inner traffic to Tailscale or the VPC, target TUN injection, or target Tailscale membership.
- NAT, conntrack, Ethernet bridging, distributed flow-state replication, target-IP mobility, or modification of the inner packet.
- A production transport-router failover controller; route mutation is limited to the protected acceptance runner.
- A production rollout. The protected AWS profile remains an acceptance environment.
- Backward compatibility with directional-lane configuration or the rejected draft-v2 direct-forwarding topology.

## Decisions

### 1. Return each packet to GWLB from packet-scoped metadata

For an accepted AWS packet received from `<gwlb-ip>:<flow-port>` at `<target-ip>:6081`, Envelope validates the complete outer IPv4/UDP and GENEVE profile. In the same packet-processing operation it emits one GENEVE packet from `<target-ip>:<flow-port>` to `<gwlb-ip>:6081`. The emitted packet contains the byte-identical inner packet, VNI, protocol type, critical-option state, and complete ordered options block, including the AWS flow cookie.

The return identity exists only in the object for the current ingress packet. It is not indexed by an inner tuple, retained after the send, refreshed by another packet, or recovered after restart. Invalid packets are dropped and never emitted. Targets do not create or read `envelope0`, inject an inner packet into Linux forwarding, or make a local-versus-remote route decision.

This restores the raw IPv4/UDP send path and its least privileges, but it does not restore the cross-packet return-context table. Packet concurrency cannot create an identity collision because every send uses only its own receive metadata.

Alternative: directly forward the decapsulated inner packet from the target. Rejected because `ha14` failed on that topology and AWS documents the appliance return to GWLB as the step before GWLBE subnet routing.

Alternative: retain the asymmetric path and replicate a flow-owner directory. Rejected because later Tailnet traffic would still require owner steering, fencing, and durable metadata, none of which is needed for packet turnaround.

### 2. Put post-inspection routing on the GWLBE subnet

Each enabled AZ has a GWLBE in its own subnet and an explicitly associated route table. Route domains have these responsibilities:

| Route domain | Exact destination | Next hop |
| --- | --- | --- |
| Workload subnet | Remote-site CIDRs | Same-AZ GWLBE |
| Transport-router subnet | Local-site workload CIDRs | Same-AZ GWLBE |
| GWLBE subnet after inspection | Local-site CIDRs | VPC local delivery |
| GWLBE subnet after inspection | Remote-site CIDRs | ENI of the transport router that owns the workload prefix associated with this GWLBE |
| Target subnet | Outer GWLB and management traffic only | Normal underlay route; never an inner site path |

For a packet from site A to site B, site A's workload route selects its GWLBE. GWLB sends the packet to a target and receives the packet back. The site A GWLBE route table then selects a site A transport-router ENI for the remote destination. Tailscale delivers the packet to a site B transport router, whose subnet route sends the local destination through site B's GWLBE. After the site B target returns the packet, site B's GWLBE route table uses VPC local delivery to reach the workload. The reverse packet follows the exact reverse sequence, including both GWLBs.

No target subnet route table selects Tailscale, a workload, or a GWLBE for an inner site CIDR. This makes the point before inspection and the point after inspection unambiguous.

### 3. Use redundant bidirectional Tailscale transport routers

Each site has at least two AZ-spread transport routers independent of the Envelope target fleet. Initially, each router's enabled advertisement is the single workload prefix assigned to its AZ; those advertisement sets are non-empty, pairwise disjoint, and their union is the site's exact local CIDRs. Every router accepts all exact remote-site routes, remains capable of forwarding every local-site prefix during failover, disables Tailscale subnet-route SNAT, disables EC2 source/destination checks, and enables the reviewed underlay-to-Tailscale and Tailscale-to-underlay forwarding, reverse-path, firewall, and MSS contract. On each router, table 52 contains exactly the opposite site's workload prefixes and no local-site prefix; same-site protected `PrimaryRoutes` claims are absent.

The routers are bidirectional. A packet arriving from a GWLBE-selected ENI for a remote-site CIDR is forwarded into `tailscale0`. A packet arriving from `tailscale0` for any local-site CIDR is selected by the higher-priority `iif tailscale0` rule, remains on `main` and the VPC underlay, and reaches the transport-router subnet route that selects the local GWLBE. This is true whether the prefix's singleton advertiser is the receiving router or its sibling, so every router can deliver every local prefix in normal and takeover paths. Neither direction performs NAT. Envelope targets do not run `tailscaled`, advertise routes, or act as transit routers.

Alternative: co-locate transport and target roles. Rejected because it reintroduces direct inner forwarding at a GWLB target and makes endpoint-return routing dependent on target host routes.

### 4. Give the protected runner coordinated advertisement and ENI-route failover authority

A VPC route table has one active next hop for an exact remote-site prefix. Each GWLBE AZ is already paired with one workload subnet prefix, and the protected profile's initial transport-router selection makes that prefix's same-AZ router both its sole initial Tailnet advertiser and the GWLBE's remote-traffic ENI. At least one additional same-site router is capable of temporarily advertising the failed owner's prefix and serving as the GWLBE alternate.

Only the protected runner may change those routes during acceptance. Version 2 accepts exactly `initial_transport_router_az_by_gwlbe_az`, `mutation_timeout_seconds`, `restoration_timeout_seconds`, and `recovery_timeout_seconds` for this lifecycle. Internal API-settlement, quiet-verification, and owner-lease windows are derived from those reviewed bounds rather than exposed as compatibility inputs. Before resource authority, run-all derives both graceful and abrupt transaction reservations plus worst-case restoration and rejects any configuration that cannot fit the active-run, per-stream, or cleanup bounds.

Before mutation the runner verifies the run-owned route table, exact transferred source prefix, current and alternate advertisement sets, stable Tailnet node identities, opposite-site observer ownership graph, absence of same-site local Tailnet ownership, current ENI, alternate ENI, router readiness, and cleanup authority. It conditionally persists both control planes' prior state, allowlists, operation state, and expiring owner lease in the CAS-protected run manifest before the first Tailscale or route call; a mode-0600 local journal is evidence only. Every transition uses the durable revision. A successor runner may recover an abandoned transaction only after the lease expires and the same durable claim still authorizes cleanup.

The runner first expands the alternate's advertisement to the exact union of its baseline prefix and the transferred prefix, then withdraws or stops the current owner and waits until every opposite-site observer selects the alternate stable node for the transferred prefix without changing unaffected owners. Only then may it replace the authorized GWLBE routes and probe the alternate path. Restoration starts the original owner with its baseline prefix while the alternate still covers both, withdraws the transferred prefix from the alternate, proves the deterministic opposite-site ownership graph and continued absence of local Tailnet routes, restores the original ENI routes with independent deadlines, and verifies both controls before finalizing. Ambiguous SSM or AWS completion enters bounded settlement. Success, failure, timeout, interruption, or runner loss cannot finalize the E2E claim while either control plane remains unrestored. Transport routers and Envelope targets receive no AWS route-mutation permission.

Normal operation has no overlapping advertisements: every exact prefix has one configured owner derived from `workload_subnet_cidrs` and `initial_transport_router_az_by_gwlbe_az`. Every opposite-site observer must select that stable node as the prefix's `PrimaryRoutes` owner. On same-site observers, every protected local prefix has no `PrimaryRoutes` claim and no table-52 route, regardless of whether its configured singleton advertiser is self or sibling. Table 52 therefore contains exactly the opposite-site workload routes, while all local destinations remain on `main` and the VPC underlay. The higher-priority `iif tailscale0` rules force every arriving local prefix through that underlay and the local GWLBE, making every router capable of local delivery in normal and takeover paths. Source-prefix owner/ENI coupling remains mandatory and is derived from singleton advertisements, control-plane stable identities, and opposite-site observations. Temporary overlap exists only inside the durable failover transaction and must converge to the intended alternate before AWS route mutation. Readiness rejects swapped, missing, duplicate, broader, narrower, source-specific, terminal, or wrong-device remote ownership, as well as any same-site local Tailnet ownership or route.

Alternative: install an autonomous production failover daemon. Rejected because this change is an acceptance profile and has not established production route-convergence or fencing requirements.

### 5. Make packet-turnaround readiness and drain explicit

An Envelope target is healthy only after its GENEVE receiver and packet-scoped AWS-compliant sender are initialized, packet validation is active, and persistent receive or send errors remain below their threshold. Target health does not depend on a TUN, host forwarding, local/remote site routes, or Tailscale. A maintenance operation first makes a target unready, waits for AWS deregistration/drain evidence, then stops or replaces it.

A transport router has separate readiness for Tailscale state, advertisements, accepted routes, source preservation, host forwarding, its associated VPC routes, and ENI identity. Target readiness cannot mask transport-router or endpoint-route failure.

### 6. Keep the unshipped schema at version 2

Topology and runtime configuration remain version 2. The version-2 field set and semantics are replaced in place because the draft has neither passed task 6.4 nor shipped. Parsers reject directional-lane fields and obsolete draft-v2 target-routing/TUN fields rather than translating them. No compatibility adapter, dual behavior, migration mode, or version 3 schema is added. Protected acceptance uses a fresh plan, fresh state key, and fresh evidence.

### 7. Define measurable, bounded HA rather than state continuity

The protected profile requires two AZs per site, a target path in every enabled AZ, and two transport routers per site. It proves symmetric cold initiation, packet turnaround, both site GWLB traversals, alternate-target new-flow recovery, and runner-owned transport ENI route failover and restoration. Readiness installs and checksum-verifies the bounded wire inspector on every target before traffic. Bounded root-run AF_PACKET captures independently correlate each ingress/return pair and retain only hashes and decoded non-secret identity after deleting raw captures; inspection failures retain only the redacted underlying command error. Target proofs aggregate all finite reason-labeled series in each required failure-counter family and reject absent or non-finite metrics. Target groups use an exact saved-plan-enforced 10-second health interval, 5-second timeout, healthy threshold 5, and unhealthy threshold 2 so both failure and restoration retain margin inside each 90-second observation bound. Process failure proves the service and health endpoint are down and accepts only the AWS `unhealthy` state. Long-lived TCP probes use bounded newline framing that preserves trailing frames from coalesced reads, and their SSM execution and wait deadlines reserve fixed completion and reporting headroom beyond the measured stream. Target-process TCP and UDP callers reserve a separate fixed mutation margin before that generic post-mutation observation window, and strict analysis still requires a marker after the measured mutation interval. Remote marker output stores shared identities once and compact timestamp tuples below the SSM inline limit; the runner reconstructs the full validated marker schema and rejects malformed or truncated results. Target-instance replacement binds the UDP stream to the exact replaced target and records TCP's independently hashed target as a control when it differs; both new flows must avoid the victim. The profile measures established TCP outcome and UDP loss for each failure class rather than promising hitless continuity.

Protected run `ha34` reached the target-instance alternate-path probe and showed that an established continuity receiver and a concurrent one-shot receiver cannot both retain the same generic listener identity. TCP continuity closes only its listening socket after accepting the established connection; UDP continuity connects its socket to the established peer so a new tuple can bind the same reviewed application port. Nested stream and probe operations hold one reentrant managed-responder pause, remote command deadlines retain fixed shutdown/reporting headroom, and each bounded recovery retry uses a fresh reserved source tuple so a killed or GWLB-pinned attempt cannot alias the next attempt.

This is stronger than the existing one-target profile but still depends on AWS target health, GWLB flow reassignment, VPC route propagation, and Tailscale route selection. Evidence records each selected endpoint, target, transport router and ENI, every route mutation, recovery duration, packet loss, and cleanup result.

## Risks / Trade-offs

- [Raw packet emission is privileged and a malformed return tuple is discarded by GWLB] -> retain the independently decoded packet-level tuple, checksum, VNI, option, cookie, and inner-byte assertions and grant only the required send capability.
- [AWS flow reassignment after an unhealthy target is not a lossless transport guarantee] -> record interruption and require bounded new-flow recovery; application protocols remain responsible for retry semantics.
- [VPC ENI route replacement is neither atomic across tables nor instant] -> mutate an explicit bounded set, record each transition, probe only after all routes are active, and always run owned restoration.
- [The protected runner can exit after a route mutation] -> store the transaction under the durable E2E claim with an expiring lease, prohibit terminal claim writes while active, and allow a successor to restore only after CAS and ownership reconciliation.
- [Tailscale ownership and GWLBE egress can diverge for preserved sources] -> use disjoint deterministic initial advertisements and transfer the affected prefix and GWLBE routes in one durable transaction.
- [A route-domain error can bypass inspection or recirculate traffic] -> enforce static route-graph assertions plus live route-table, ENI, packet-capture, and hop evidence before acceptance traffic.
- [Multiple AZ endpoints, targets, and transport routers increase cost] -> keep AZ count and approved hourly ceiling explicit in the protected configuration and plan validator.
- [Both directions traverse two site GWLBs] -> document latency, data-processing, and cross-AZ cost; constrain acceptance traffic and TTL.

## Migration Plan

1. Revise topology and runtime configuration version 2 in place and reject legacy directional fields plus obsolete draft-v2 direct-forwarding fields before host or AWS mutation.
2. Replace target TUN forwarding with packet-scoped AWS GENEVE turnaround and its local packet-level tests.
3. Replace ingress-only routers and target route domains with bidirectional transport routers and GWLBE post-inspection route tables.
4. Add bounded, ownership-safe protected-runner ENI route failover, restoration, and evidence.
5. Deploy only a fresh protected acceptance run; old state, plans, evidence, and rejected draft-v2 configurations are not reusable.
6. Run symmetric packet-path, target/process failure, transport-router failure, ENI-route failover, and restoration acceptance. If any prerequisite fails, run the owned cleanup workflow.
7. Roll back by destroying only run-owned symmetric resources. A separately deployed directional-lane revision keeps its original configuration and acceptance contract; no topology resources or compatibility behavior are mixed.

## Open Questions

- What measured VPC route-propagation and transport recovery bounds should become a future production SLO after protected acceptance establishes the baseline?
- Does target drain behavior in the protected account require an additional application-level quiesce delay beyond AWS target deregistration?
