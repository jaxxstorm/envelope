## Why

Envelope currently proves a one-target, asymmetric return path using process-local GWLB return context and separate initiator/responder CIDRs. The first draft of this change tried to remove that state by having a GWLB target decapsulate each packet and directly forward the inner packet to Tailscale or the VPC. Live run `ha14` failed on that path, and the AWS GWLB routing contract requires the appliance to send inspected traffic back to GWLB so the GWLBE subnet route table can select the packet's next hop.

The symmetric design must therefore keep each target in the GWLB appliance loop while moving site transit to endpoint routing and redundant Tailscale routers. The draft topology and runtime configuration version 2 has not passed acceptance or shipped, so its semantics can be corrected in place without a compatibility mode or a version 3 schema.

Protected run `ha24` proved packet turnaround and complete route readiness but exposed a second unshipped topology defect: with subnet-route SNAT disabled, a receiving Tailscale router accepts a preserved source prefix only from that prefix's selected primary advertiser. Independently selecting an overlapping advertiser and a same-AZ GWLBE egress router can therefore make the forward path succeed while WireGuard rejects the reverse packet. Version 2 must bind each source prefix to one deterministic initial transport owner and transfer advertisement ownership together with the affected GWLBE routes.

Protected run `ha25` failed acceptance but corrected the live-discovered route contract: each router installed exactly the two opposite-site workload routes in table 52 and formed serving paths only to opposite-site peers. Requiring a same-site sibling `PrimaryRoutes` owner and local table-52 route was wrong. At baseline, each enabled advertisement is a singleton, the per-site sets remain pairwise disjoint and exactly cover the site, every opposite-site observer must select each prefix's configured stable owner, and every local prefix stays on the main/VPC underlay with no same-site Tailnet route or protected local `PrimaryRoutes` claim. The higher-priority `iif tailscale0` rules make every router capable of local delivery in both normal and takeover paths. This correction does not change durable failover and restoration ordering, fencing, the non-hitless availability boundary, or evidence requirements.

## What Changes

- Add packet-scoped GWLB turnaround: each valid ingress packet is immediately re-encapsulated and returned to GWLB with the same inner packet, VNI, protocol metadata, ordered options and flow cookie, and AWS outer tuple learned from that packet.
- Remove all normal-path cross-packet target flow state, TUN injection, and target forwarding of inner traffic to Tailscale or the VPC.
- Add a two-site topology in which each workload prefix has one deterministic initial Tailscale transport owner, and that prefix's GWLBE subnet route table delivers inspected remote traffic through the same owner's ENI while inspected local traffic uses the VPC local route.
- Make redundant Tailscale routers bidirectional, no-NAT site transit routers: each initially advertises its disjoint owned workload prefix, table 52 contains only opposite-site workload routes, every local prefix remains on the main/VPC underlay, every router remains capable of all site prefixes for failover, and Tailnet-arriving local traffic enters the local GWLBE.
- Give the protected runner bounded, ownership-checked control of coordinated Tailscale advertisement and transport-router ENI route failover and restoration during acceptance, with both prior states and an expiring owner lease persisted in the CAS-protected run manifest for runner-loss recovery.
- **BREAKING** revise the unaccepted topology and runtime configuration version 2 in place; reject both directional-lane fields and the obsolete draft-v2 direct-forwarding fields without compatibility translation.
- Preserve symmetric initiation, two-site GWLB traversal, multi-target readiness and drain, and bounded HA evidence without promising hitless transport continuity.
- Define bounded HA guarantees: availability for new flows and transport recovery after bounded packet loss are in scope; hitless TCP/UDP continuity during an instance, AZ, GWLB, or Tailscale failover is not promised.

## Capabilities

### New Capabilities
- `symmetric-gwlb-ha-topology`: Defines packet turnaround at each target, GWLBE post-inspection routing, redundant bidirectional transport routers, and bounded target and ENI-route failover behavior.

### Modified Capabilities
- `geneve-tun-datapath`: Replace TUN-based target forwarding with immediate packet-scoped GENEVE turnaround and no cross-packet state.
- `gwlb-wire-interop`: Preserve strict AWS validation and define byte-identical inner-packet and metadata return using only the current ingress packet's AWS tuple.
- `tailscale-host-routing`: Separate Envelope targets from redundant bidirectional Tailscale transport routers and define their no-NAT forwarding contract.
- `aws-appliance-deployment`: Replace the single regional target/lane deployment with multiple stateless GWLB targets, transport-router ENIs, endpoint-owned post-inspection routes, and HA-aware acceptance.

## Impact

- Affects Go configuration, raw GENEVE send behavior, datapath metrics and health, and removal of target TUN and Tailscale routing dependencies.
- Replaces the current draft-v2 Terraform route graph, per-router advertisement ownership, transport-router readiness, protected runner coordinated failover authority, and live evidence while retaining version 2. Existing workload-subnet and per-GWLBE-AZ selection fields derive singleton advertisements and source-prefix owner/ENI coupling; control-plane stable identities and opposite-site observations verify that binding without requiring same-site Tailnet ownership.
- Requires corrected privileged packet-turnaround tests and protected AWS tests for target loss, process restart, transport-router loss, bounded ENI route replacement, restoration, and two-site traversal.
