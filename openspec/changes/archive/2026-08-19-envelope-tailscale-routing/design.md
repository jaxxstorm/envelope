## Context

Envelope owns `envelope0`; `tailscaled` owns `tailscale0`. GENEVE ingress seeds return context only on the appliance behind the initiator region's GWLB. A first packet arriving over Tailscale at the responder region has no local GWLB context and must reach the local responder directly, while a response arriving over Tailscale at the initiator region must enter `envelope0` for re-encapsulation.

One undifferentiated protected-CIDR list cannot represent both roles. The supported first deployment therefore assigns disjoint initiator and responder workload prefixes. The final two-region test has one lane in each direction so both regional appliances are exercised without sending a response through a GWLB that did not process the initial packet.

## Goals / Non-Goals

**Goals:**
- Keep distinct process and interface ownership.
- Express and validate local GWLB-return, local-delivery, and remote Tailnet CIDR roles.
- Program only the policy routes required for mapped Tailnet returns.
- Verify the effective forward and reverse routes, Tailscale backend, host forwarding, firewall, reverse-path filtering, and MSS policy.
- Reconcile only Envelope-owned state transactionally.
- Make health and metrics identify effective-path failures.
- Provide a real privileged Tailscale integration test.

**Non-Goals:**
- Arbitrary bidirectional initiation from one workload CIDR without a stateful classifier.
- Embedding or supervising `tailscaled` in the Envelope process.
- Sharing one TUN between processes.
- NAT or conntrack in this routing version.
- Multi-appliance return affinity or shared GWLB flow state.
- Generating related ICMP PMTU errors through a GWLB flow context in this version.

## Decisions

### 1. Separate interfaces are mandatory

Envelope uses `envelope0` and Tailscale uses `tailscale0` by default, and the appliance underlay ENI is configured explicitly. Configuration fails if the Envelope and Tailscale names are identical or a required interface name is empty. Envelope creates its TUN with `IFF_TUN_EXCL`, so a persistent or otherwise pre-existing device with that name also fails startup rather than being attached. Host routing, not shared TUN reads, connects the processes.

### 2. CIDR roles are explicit and disjoint

`gwlb-return-cidrs` are local initiator prefixes whose packets arriving from `tailscale0` have an expected local GWLB return context and must route to `envelope0`. `local-delivery-cidrs` are local responder prefixes whose cold Tailnet arrivals bypass Envelope and follow normal local delivery. `remote-tailnet-cidrs` must resolve through an accepted Tailscale route for GENEVE-decapsulated traffic.

All three role sets must be pairwise non-overlapping. A local-delivery prefix cannot be covered by a broader GWLB-return or remote prefix, and a remote route cannot overlap either local role. Ambiguous configurations fail at startup before route lookup can shadow local delivery.

Alternative: send every local prefix to Envelope and reinject unmapped packets. Rejected because it hides configuration errors, complicates loop prevention, and does not solve unsupported destination-GWLB asymmetry.

### 3. Managed policy applies only to GWLB returns

For each GWLB-return CIDR, manage mode installs an `iif tailscale0 to <cidr>` rule and a dedicated-table route to `envelope0`. Local-delivery CIDRs receive no such rule. Forward traffic from `envelope0` uses the main/effective route installed by Tailscale for a remote Tailnet CIDR.

### 4. Effective-route checks are required

Readiness symbolically audits ordered IPv4/IPv6 policy rules and all selected route tables for the complete Cartesian product of same-family source-role and destination-role prefixes. The proof accounts for source/destination selectors, input interfaces, zero-mark matching, terminal actions, and prefix suppression. It rejects any intersecting interior more-specific route, terminal route, unsupported selector, earlier source-policy lookup, or relevant IPv6 route with a non-universe `from` selector that can divert part of a role. Source-specific routes always fail closed because the current proof does not partition and validate every source subtree. Structured decoder and auditor unit fixtures are mandatory on every test kernel. The supplemental privileged reproduction installs a real source-specific route when the kernel supports `CONFIG_IPV6_SUBTREES`; otherwise its dedicated Go test reports an explicit capability skip. That capability gate does not waive runtime rejection or any other full-prefix test. Structured first/last-address `ip route get` probes remain supplementary kernel checks. Return traffic must select the configured Envelope device and dedicated table, local-delivery traffic must select the configured underlay in main table 254, and remote traffic must select `tailscale0` in Tailscale table 52. Router-owned transit addresses must be outside every role prefix so local-table host routes cannot shadow the role.

### 5. Routing mode remains opt-in

The default remains `off` to avoid unexpected host mutation. `verify` checks the complete effective path without changing it. `manage` owns and reconciles only the return rules/routes after host prerequisites pass. AWS deployment explicitly chooses `manage`.

### 6. Host MTU policy prevents persistent TCP blackholes

The host validates live MTUs for all three interfaces. For each forwarding direction, path MTU is the minimum of configured TUN MTU and both live interface MTUs; exact maximum MSS is path MTU minus 40 for IPv4 and minus 60 for IPv6. At 1280 these are 1240 and 1220. Privileged evidence captures the SYN MSS and transfers full-sized data in all four directions for both address families. Strict reverse-path filtering is rejected for `conf/all`, the underlay ENI, `tailscale0`, and `envelope0`; disabled or loose mode is accepted.

The supported firewall contract is legacy `iptables`/`ip6tables`, inspected from complete save output across `raw`, `mangle`, `nat`, `filter`, and `security`. Every forwarding-relevant built-in hook has policy `ACCEPT` and is pristine except that filter `FORWARD` contains only an unconditional jump to deployment-owned `ENVELOPE-FORWARD` and mangle `FORWARD` contains only an unconditional jump to `ENVELOPE-MSS`. The owned chains have exact rule cardinality and shape. Deployment assets set `-P FORWARD ACCEPT` rather than delegating acceptance from a `DROP` policy. `/usr/sbin/nft` is a mandatory executable inspection dependency even when native rules are absent; missing/stat/execution failures, raw/security drops, mangle marks, NAT rewrites, policy-only acceptance, conditional/extra owned rules, nft-backed iptables, concurrent native nft/firewalld objects, or later mangle `DROP`/`TCPMSS` rules are unprovable and fail closed. The receive pool covers the maximum legal IPv4 UDP payload so every complete oversized GENEVE packet, from MTU+1 through 65,507 bytes including headers/options, receives an MTU-specific reason. Real-TUN egress is classified the same way; no ICMP PMTU signalling is claimed until related ICMP traversal is proven.

### 7. Tailscale backend and routes are health dependencies

Interface existence is insufficient. The supported contract is the Tailscale v1.80.x `ipnstate.Status` shape in kernel-TUN mode. Readiness requires a healthy Running backend, online/non-expired self and serving peers, approved local roles, peer `PrimaryRoutes`, network-map/magicsock/engine presence, and one bounded `tailscale ping --until-direct=false`; a successful relay pong proves data-plane reachability without making direct-path convergence a startup requirement. Tailscale table 52 is audited directly: each remote role needs a covering `tailscale0` unicast route and no table-52 entry may overlap either local role. Route withdrawal changes readiness before or during the next reconcile interval.

### 8. Managed state tracks ownership

Protocol 186, the configured table, and the configured rule priority form Envelope's reserved ownership namespace; table IDs that collide with unspec, Tailscale (52), default, main, or local are rejected. Operators must not create objects in that namespace, and Envelope cannot distinguish a deliberately forged protocol-186 object. A nonblocking `/run/envelope-routing.lock` is held from managed initialization through cleanup. Equivalent unmarked pre-existing state is accepted but not deleted. Routes are installed before rules. Every successful add is recorded as transaction-owned before its verification reread, so a failed or conflicting reread rolls it back by deleting the exact reserved object. An add that returns an error never claims or deletes protocol-186 state observed afterward because creation is ambiguous. Partial changes roll back in reverse order. Every cleanup operation uses an independent deadline and verifies absence afterward; a persistent conflict retains process ownership and records cleanup failure rather than falsely recording removal. `manage` fails startup before packet serving if initial reconciliation fails; `verify` remains non-mutating and unhealthy.

### 9. Integration uses local Headscale and pinned peers

The required privileged integration starts Headscale 0.25.1 with its embedded local DERP and Tailscale 1.80.3 by immutable digest, generates one-hour preauth keys at runtime, and uses two kernel-TUN peers with Tailscale netfilter disabled in favor of the exact deployment-owned chains. Workload/fake-GWLB namespaces use transit addresses outside every role prefix and install mandatory nft inspection tooling. Each lane injects a valid AWS flow-cookie GENEVE packet and requires cold responder bypass plus exactly one correlated, option-preserving mapped return. It needs no external secret or Tailnet. A synthetic namespace test remains a routing smoke test only; an external Tailscale SaaS harness is optional compatibility evidence and is not an acceptance gate.

### 10. Command execution and status are bounded

Routing commands use fixed absolute executables, a minimal environment, process-group cancellation, a deadline, and bounded combined output. Structured JSON is used for route/rule/status state. `/debug/routing` exposes only role CIDRs, interfaces, table/priority/marker, readiness, and the pinned schema identifier; it does not expose keys, cookies, or peer identities.

## Risks / Trade-offs

- [Directional roles limit generality] -> State the supported model explicitly and require a separate stateful-classifier design for same-subnet bidirectional initiation.
- [Tailscale status invocation adds a control dependency] -> Pin the supported v1.80 schema, bound process/output, verify table 52, and probe the serving peer.
- [MSS/firewall tooling differs by distribution] -> Support one deterministic legacy-chain layout, require executable nft inspection tooling, and fail closed on ambiguous backends; deployment assets install that exact layout later.
- [Ownership metadata is process-local] -> Reconcile conservatively and never remove equivalent pre-existing state.

## Migration Plan

0. Verify `envelope-geneve-options` and `envelope-gwlb-wire-compliance` are implemented, synced to the canonical datapath spec, and archived so cumulative health and metrics requirements use the final wire contract.
1. Add new CIDR-role configuration and reject overlap/interface collision.
2. Add effective route and Tailscale backend checks.
3. Make managed apply transactional and ownership-aware.
4. Add host prerequisite and MTU/MSS validation plus reason-specific health/metrics.
5. Replace cohost claims with the required local Headscale two-peer GENEVE integration; retain SaaS only as an optional test.
6. Update deployment to pass site-specific roles explicitly.
7. Remove `--protected-cidrs` after updating all examples; rollback uses `routing-mode=off` and ownership-aware cleanup.

## Open Questions

- The stateful classification design required to support arbitrary initiation from the same local workload prefix is deferred to a future change.
