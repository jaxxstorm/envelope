## Context

The current acceptance profile is deliberately asymmetric: a regional Envelope process records AWS GENEVE return metadata in memory, and a packet returned from Tailscale must reach that same process to be re-encapsulated. Static routes therefore divide every site into initiator and responder CIDRs, and Terraform rejects more than one regional target. This prevents a normal site-to-site network in which either workload may initiate traffic.

AWS GWLB already provides target selection for a flow when both directions enter a Gateway Load Balancer endpoint. The design changes the topology to use that property rather than reproducing return affinity in Envelope. Tailscale supplies the site-to-site transport and redundant route advertisers; it does not select a GWLB target.

## Goals / Non-Goals

**Goals:**
- Support arbitrary TCP, UDP, and ICMP initiation between disjoint site CIDRs without NAT.
- Send both directions of every inter-site packet through the originating site's GWLBE, GWLB, and healthy Envelope target fleet.
- Support at least two AZs per site, an Envelope target in every enabled target AZ, and redundant Tailscale ingress routers advertising identical local-site routes.
- Remove normal-path dependence on per-process GWLB return contexts, so a recovered or replacement target can forward an existing packet flow after it is healthy.
- Prove bounded failover behavior and report the observed packet loss and recovery time.

**Non-Goals:**
- A lossless or hitless guarantee for TCP, UDP, Tailscale, GWLB, instance, or AZ failure.
- NAT, conntrack, Ethernet bridging, distributed flow-state replication, or target-IP mobility.
- A production rollout. The protected AWS profile remains an acceptance environment.
- Backward compatibility with directional-lane configuration, Terraform variables, or its old run evidence schema.

## Decisions

### 1. Use symmetric inline service insertion

Each site has a local GWLBE in every enabled AZ. Workloads send remote-site CIDRs to the local GWLBE. A remote Tailnet packet first reaches a local Tailscale ingress router, whose subnet route table sends the local-site CIDR to that same site's GWLBE. GWLB therefore selects an Envelope target for the first packet in either direction and sees every reverse packet as well.

Envelope validates and decapsulates AWS GENEVE, then injects the inner IP packet into `envelope0`. Linux forwards it either to `tailscale0` for a remote-site CIDR or to the post-inspection VPC path for a local-site CIDR. Envelope does not originate a normal-path GENEVE return packet and does not retain flow metadata for forwarding decisions.

Alternative: retain the asymmetric path and replicate a flow-owner directory. Rejected because every Tailnet return would still need correct owner steering, original target source identity, fencing, and durable state; it is more complex than letting GWLB keep its native flow affinity.

### 2. Separate Tailscale ingress routers from GWLB targets

Each site uses at least two Tailscale ingress routers, independent of the Envelope target fleet. They advertise the exact local-site CIDRs with subnet-route SNAT disabled and route received Tailnet packets to the local GWLBE. Envelope targets join the Tailnet to forward post-inspection packets but do not advertise the local-site routes.

This separates Tailnet route selection from GWLB target selection. It also prevents a target's post-inspection traffic from entering the GWLBE route domain again.

Alternative: make every target a route advertiser. Rejected because a target receiving a Tailnet packet cannot both send it to a GWLBE and directly deliver a decapsulated packet using one undifferentiated VPC route domain without a loop-prone multi-ENI design.

### 3. Use explicit pre- and post-inspection route domains

Terraform creates distinct workload, Tailnet-ingress, GWLBE, target, and management subnet route tables. Workload and ingress-router route tables have exact remote/local site routes to their local GWLBE. Target route tables use direct VPC local delivery for local-site CIDRs and Tailscale forwarding for remote-site CIDRs. No target route table may target a GWLBE for either site CIDR.

Route validation proves these domains from representative source interfaces and complete prefixes before a target can become healthy. Source/destination checks remain disabled on forwarding instances, and no component performs SNAT.

### 4. Make target readiness and drain part of the data-plane contract

An Envelope target is healthy only after its GENEVE receiver, TUN injection, local-site route, remote Tailnet route, forwarding/sysctl/firewall/MSS prerequisites, and Tailscale backend are ready. A maintenance operation first makes a target unready, waits for AWS deregistration/drain evidence, then stops or replaces it. It is never marked healthy before the complete path is revalidated.

Alternative: rely on EC2 instance health. Rejected because an instance can be healthy while the TUN, Tailscale routes, or post-inspection route path is unavailable.

### 5. Define measurable, bounded HA rather than state continuity

The first protected profile requires two AZs per site, a target path in every enabled AZ, and two ingress routers per site. It proves that a healthy alternate target and alternate ingress router can carry new flows after a target/process/router failure. It measures, rather than SLO-gates, established TCP recovery and UDP loss. The configuration and evidence record the observed timeout, loss, chosen target, ingress router, and recovery outcome.

This is intentionally stronger than the existing one-target profile but does not claim hitless continuity, because GWLB health detection/flow reassignment and Tailscale route failover are external control planes.

## Risks / Trade-offs

- [AWS flow reassignment after an unhealthy target is not a lossless transport guarantee] → failover acceptance records interruption and requires new-flow recovery; application protocols remain responsible for retry semantics.
- [Tailscale overlapping subnet routes can take time to fail over] → use exact identical prefixes, expose router readiness, and test both graceful and abrupt router loss.
- [A route-domain error can recirculate traffic through a GWLBE] → enforce static Terraform graph assertions and host/VPC route evidence before target registration.
- [Multiple AZ endpoints and targets increase cost] → make AZ count and approved hourly ceiling explicit in the protected configuration and plan validator.
- [Removing return-context egress changes the current operator interface] → reject legacy lane fields and require a new configuration version rather than silently interpreting them.
- [Both directions traverse two site GWLBs] → document latency, data-processing, and cross-AZ cost; constrain acceptance traffic and TTL.

## Migration Plan

1. Add the symmetric configuration schema and reject legacy directional-lane fields before infrastructure creation.
2. Implement and locally test symmetric Envelope forwarding while retaining no raw-GENEVE normal path.
3. Replace the Terraform topology and protected-run plan validator with the explicit multi-AZ route domains, target fleet, and ingress routers.
4. Deploy only a fresh protected acceptance run; old state, plans, evidence, and lane configurations are not reusable.
5. Run packet-path, target/process failure, and ingress-router failure acceptance. If any prerequisite fails, run the owned cleanup workflow.
6. Roll back by destroying only run-owned symmetric resources. Revert to a separately deployed directional-lane revision only with its original configuration and acceptance contract; do not mix topology resources.

## Open Questions

- Does the target health/drain behavior observed in the protected AWS account require an additional application-level quiesce delay beyond AWS target deregistration?
- Which Tailscale plan and regional-routing setting will the production-oriented design require, versus baseline overlapping-route failover?
