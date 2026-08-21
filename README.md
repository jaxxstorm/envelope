# Envelope

> [!WARNING]
> **Experimental WIP: this does not currently work.**
>
> Envelope is an in-progress prototype. The code, tests, scripts, and Terraform
> examples are here to capture the current direction and make iteration easier,
> but this repository should not be treated as production-ready or even as a
> functional preview yet. Expect broken behavior, incomplete integration points,
> unsafe assumptions, and major changes.

Envelope is a minimal datapath that terminates the AWS GWLB IPv4 GENEVE profile (UDP/6081), decapsulates inner L3 IP packets, and forwards them to a local TUN device (`envelope0`). Return traffic from the TUN is re-encapsulated using a bounded, process-local return context learned from the matching inner flow.

Envelope is designed to run alongside `tailscaled` on the same Linux host. Envelope handles GENEVE termination/origination, while host routing carries traffic between `envelope0` and the Tailscale interface (`tailscale0` by default).

## What It Is

- A Linux-only GENEVE <-> TUN shim for L3 IP packets.
- A single-process datapath with Prometheus metrics and a health endpoint.
- A co-resident routing integration for Envelope + `tailscaled` using policy routes.

## What It Is Not

- An L2 bridge (no Ethernet payloads in v1).
- A NAT/conntrack engine.
- A full GWLB control plane.

## Deployment Modes

- `routing-mode=off`: Datapath only. No routing checks or route/rule management.
- `routing-mode=verify`: Validate routing prerequisites and mark health unhealthy if they are missing.
- `routing-mode=manage`: Validate the complete host path and reconcile only GWLB-return rules/routes owned by this process.

Routing is opt-in and defaults to `off`. `off` and `verify` never mutate routes, rules, sysctls, firewall policy, or MSS policy.

## Directional CIDR Model

Each appliance has three pairwise-disjoint CIDR roles:

- `gwlb-return-cidrs`: local initiator prefixes. Packets arriving from `tailscale0` for these destinations must have local GWLB return context and are policy-routed into `envelope0`.
- `local-delivery-cidrs`: local responder prefixes. Cold packets arriving from `tailscale0` bypass `envelope0` and use normal local delivery.
- `remote-tailnet-cidrs`: remote workload prefixes. Packets arriving from `envelope0` must use an approved, accepted route through `tailscale0`.

Envelope rejects malformed CIDRs and every overlapping, covering, or duplicate assignment before host access. The supported topology uses separate initiator and responder prefixes, with one directional lane per initiation direction. Arbitrary initiation in both directions from the same workload prefix is not supported without a future stateful classifier.

Migration is intentionally breaking: remove the former aggregate CIDR flag, classify each local prefix as either GWLB-return or local-delivery, and list every accepted remote Tailnet prefix separately. Do not copy one old aggregate list into all three roles; overlap validation will reject it.

## Local Run

Build:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

Datapath-only run:

```bash
sudo ./bin/envelope \
  --udp-bind=0.0.0.0:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=0.0.0.0:9090 \
  --routing-mode=off
```

Co-resident run with managed routing:

```bash
sudo ./bin/envelope \
  --udp-bind=0.0.0.0:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=0.0.0.0:9090 \
  --underlay-interface=ens5 \
  --tailscale-iface=tailscale0 \
  --routing-mode=manage \
  --gwlb-return-cidrs=172.16.0.0/24 \
  --local-delivery-cidrs=172.16.1.0/24 \
  --remote-tailnet-cidrs=172.17.0.0/24,172.17.1.0/24 \
  --routing-table-id=100 \
  --routing-rule-priority=100
```

Health and metrics:

- `GET :9090/healthz`
- `GET :9090/metrics`
- `GET :9090/debug/routing` (redacted role/interface/table/status-schema state)

## Required Linux Capabilities and Sysctls

Capabilities:

- `CAP_NET_ADMIN` (create/configure TUN, set MTU, manage routes/rules)
- `CAP_NET_RAW` (required for compliant raw IPv4/UDP return packets)

Host prerequisites for `verify` and `manage`:

- `net.ipv4.ip_forward=1`
- `net.ipv6.conf.all.forwarding=1`
- `net.ipv4.conf.all.rp_filter` and the configured underlay, `tailscale0`, and `envelope0` values must be disabled (`0`) or loose (`2`), never strict (`1`). If Linux cannot represent an asymmetric supplementary lookup on `envelope0`, readiness accepts the complete policy/FIB proof only when both `conf/all` and `envelope0` are disabled (`0`).
- The supported firewall layout is legacy `iptables`/`ip6tables`. Filter `FORWARD` must use policy `ACCEPT` and contain only an unconditional jump to `ENVELOPE-FORWARD`, which contains exactly one unconditional accept for each underlay -> Tailscale, Tailscale -> underlay, Envelope -> Tailscale, and Tailscale -> Envelope path. Deployment must set `-P FORWARD ACCEPT`; policy-only acceptance, conditional rules, the nft iptables backend, native nft/firewalld objects, and extra rules in the owned chain fail closed.
- Mangle `FORWARD` must use policy `ACCEPT` and contain only one unconditional jump to `ENVELOPE-MSS`. The owned chain contains exactly one TCP SYN `--set-mss` rule per directed path followed by `RETURN`. Every forwarding-relevant built-in hook in the complete legacy `raw`, `mangle`, `nat`, `filter`, and `security` save output must have an `ACCEPT` policy and be pristine outside these two exact owned contracts; rules such as `raw`/`security` drops, mangle marks, NAT rewrites, or later `DROP`/`TCPMSS` rules are rejected.
- `/usr/sbin/nft` is mandatory even when native nft rules are intentionally absent. It must be a statable executable regular file, and `nft -j list ruleset` must succeed so Envelope can prove that no concurrent native nft/firewalld objects exist.
- MSS values are derived from live interface MTUs: `path_mtu = min(tun_mtu, input_mtu, output_mtu)`, then IPv4 MSS is `path_mtu - 40` and IPv6 MSS is `path_mtu - 60`. At MTU 1280 these are 1240 and 1220.

Envelope validates these prerequisites but does not install or persist them. Even in `manage`, it mutates only `iif tailscale0 to <gwlb-return-cidr>` rules and matching dedicated-table routes to `envelope0`.

## Routing Integration Flags

- `--tailscale-iface` (default: `tailscale0`)
- `--underlay-interface` (required in `verify` and `manage`)
- `--routing-mode` (`off|verify|manage`, default: `off`)
- `--gwlb-return-cidrs` (required in `manage`)
- `--local-delivery-cidrs`
- `--remote-tailnet-cidrs`
- `--routing-table-id` (default: `100`)
- `--routing-rule-priority` (default: `100`)

Readiness uses bounded, output-limited commands at fixed absolute paths. The supported status schema is Tailscale v1.80.x in kernel-TUN mode. It requires a healthy `BackendState=Running`, an online non-expired self node, approved local return/delivery routes, and an online non-expired route-serving peer present in the network map, magicsock, and engine. Each serving peer is proved with one bounded `tailscale ping --until-direct=false`; a successful DERP relay pong is valid data-plane evidence while direct-path discovery converges.

Envelope reads the ordered IPv4/IPv6 policy-rule sets and every table they can select, then proves each complete source-role/destination-role prefix through the required device and table. Any intersecting more-specific route, terminal route/rule, unsupported selector, or earlier source-policy lookup that can divert an interior address fails readiness. A relevant IPv6 source-specific route with a non-universe `from` selector also fails closed because boundary probes cannot prove the complete source subtree. Boundary `ip route get` probes over first/last addresses remain supplementary kernel checks, not the full-prefix proof. Tailscale table 52 is also audited directly: every remote role needs a covering `tailscale0` unicast route and no entry may overlap a local return or delivery role. Router-owned transit/interface addresses must therefore be outside all configured role prefixes. Return traffic selects the configured Envelope table/device, local delivery selects the configured underlay in main table 254, and remote traffic selects `tailscale0` in table 52.

Routing table IDs `0`, `52`, `253`, `254`, and `255` are reserved and rejected. Protocol `186`, together with the configured table and rule priority, is Envelope's reserved ownership namespace; operators must not create objects in that namespace. Envelope cannot distinguish an operator that deliberately forges protocol `186`. A nonblocking `/run/envelope-routing.lock` is held for the complete managed lifecycle. Routes are installed before rules. A successful add enters the rollback transaction before its verification reread, while an add that returns an error never claims or deletes protocol-186 state observed afterward because its ownership is ambiguous. Rollback and shutdown delete the exact reserved object, reread it, and retain ownership with a cleanup-failure metric if a conflict remains. Each cleanup operation has an independent deadline, and equivalent unmarked pre-existing objects are preserved. A `manage` initialization failure terminates startup before packet serving; `verify` remains non-mutating and reports HTTP 503 until the contract becomes valid.

Routing metrics:

- `routing_apply_attempts`
- `routing_apply_failures`
- `routing_drift_repairs`
- `routing_validation_failures_total{reason}`
- `routing_ownership_decisions_total{decision}`
- `routing_ready`

## MTU Guidance (Tailscale)

Tailscale uses a fixed tunnel MTU of **1280**. Envelope defaults `envelope0` to 1280 to match this behavior.

TCP MSS policy prevents persistent TCP blackholes. Privileged acceptance captures the advertised MSS and transfers a full 128 KiB over underlay -> Tailscale, Tailscale -> underlay, Envelope -> Tailscale, and Tailscale -> Envelope for both IPv4 and IPv6. The UDP receive pool is bounded at the maximum legal IPv4 UDP payload, 65,507 bytes, so every complete legal GENEVE datagram with an inner packet above the configured MTU reaches MTU classification rather than generic truncation. Oversized IPv4 and IPv6 inner packets increment `drops` plus `gwlb_mtu_drops_total{family,direction}`. Envelope does not claim to generate a usable related ICMP PMTU response through the original GWLB context.

GENEVE encapsulation adds overhead. Ensure the outer path MTU can carry the inner 1280-byte packet plus encapsulation:

```
required_path_mtu = 1280 + (outer_ip + udp + geneve + options)
```

Typical overhead:

- Outer IPv4: 20 bytes
- UDP: 8 bytes
- GENEVE base header: 8 bytes
- Options: 0-252 bytes

## AWS GWLB Wire Contract

Envelope accepts only outer IPv4 on a listener bound to UDP/6081. For an ingress packet selected by GWLB:

```text
ingress: <gwlb-ip>:<flow-port> -> <appliance-ip>:6081
return:  <appliance-ip>:<flow-port> -> <gwlb-ip>:6081
```

Only the outer addresses swap. The UDP ports retain their ingress orientation; this is deliberately not ordinary UDP request/reply behavior. Linux `IP_PKTINFO` records the exact ingress local address and interface index, and the raw sender applies both as return-route hints. There is no ordinary UDP send fallback.

The AWS profile requires:

- GENEVE version 0, VNI 0, and OAM clear.
- An inner protocol type of IPv4 (`0x0800`) or IPv6 (`0x86DD`) matching the inner IP version.
- Zero reserved bits in every option header.
- Exactly one four-byte AWS class `0x0108`, type `3` flow cookie.
- A byte-identical ordered options block on mapped return traffic.

Fixed-header reserved bits are ignored on receive and emitted as zero. A listener address with a port other than 6081, an IPv6 listener address, or a non-zero `--vni` fails configuration validation.

## Return Contexts

Each context retains the peer and local IPv4 addresses, GWLB-selected flow port, VNI, protocol type, supported fixed flags, flow cookie, ordered options, inner protocol, and activity generation. The ingress interface index is retained and refreshed separately as a route hint; an interface change alone does not create a wire-identity conflict. Egress uses only the reverse inner tuple. A same-orientation TUN packet is dropped as a possible routing loop.

Contexts are in memory only and are intentionally lost at process restart. Defaults are:

- `--flow-capacity=65536`
- `--tcp-flow-timeout=350s`
- `--udp-flow-timeout=120s`
- `--other-flow-timeout=120s`
- `--persistent-error-threshold=3`

Valid ingress and successful mapped egress refresh activity. Failed sends do not. An indexed expiry heap and LRU list remove due entries before selecting the least recently active entry, without scanning the full table under capacity churn. If one inner key has multiple live wire identities, return traffic fails closed. Up to four identities are tracked independently, with an additional bounded overflow lease; stale identities age out independently so a sole surviving identity automatically becomes usable even while it remains active.

## GENEVE Options

Envelope treats the complete ordered GENEVE options block as opaque return metadata. After validation, the exact bytes are copied into the matching flow entry and emitted unchanged for that flow. Parsed values never select a route, peer, or flow mapping. TUN creation is exclusive (`IFF_TUN_EXCL`), so startup fails instead of attaching to a persistent or otherwise pre-existing interface with the configured name.

Structural and semantic validation is mandatory even when option value logging is disabled:

- Every TLV header is scanned without allocating a parsed result collection.
- The low five bits of the option length byte determine data length. Generic parsing ignores the three reserved high bits, while the AWS datapath profile rejects non-zero values before installing context.
- The option type's high bit is the critical flag; configuration and logs use the remaining seven-bit type.
- A critical option requires the base-header critical bit, and the base bit requires at least one critical option.
- Unknown critical options are dropped. Unknown non-critical options remain opaque and retain their original position and bytes.

Envelope recognizes these AWS class `0x0108` shapes:

- Type `1`: 8-byte VPC endpoint ID, at most one.
- Type `2`: 8-byte attachment ID, at most one.
- Type `3`: 4-byte flow cookie, exactly one for every accepted AWS-profile packet.

Unknown non-critical AWS types are accepted for forward compatibility, but do not remove the flow-cookie requirement. The flow cookie is extracted during mandatory validation independently of logging configuration; the original bytes remain authoritative.

Optional value logging is disabled by default and does not change validation or flow behavior. When enabled at debug log level, only allowlisted class and seven-bit type pairs are logged. AWS values are redacted; generic values and the number of entries per packet are bounded.

Enable value logging:

```bash
sudo ./bin/envelope \
  --log-level=debug \
  --geneve-tlv-parse \
  --geneve-tlv-allowlist=0x0108:1,0x0108:3
```

Options bounds:

- `--geneve-options-max-bytes` (default: `252`) accepts word-aligned values from 4 through 252. Larger option blocks are dropped.

Option validation rejections increment `decap_errors`, `drops`, and `geneve_options_validation_errors_total{reason=...}`. Reasons are `structural`, `critical`, `size`, `aws_length`, and `aws_cardinality`.

## Unsupported Packets

Envelope rejects before context installation:

- Every fragmented inner IPv4 packet (`MF=1` or non-zero fragment offset).
- Every inner IPv6 Fragment header.
- Inner IPv6 extension-header chains that are not supported by the flow parser.
- Truncated TCP or UDP headers.

Envelope does not fragment return packets. The raw IPv4 builder sets DF and emits valid IPv4 and UDP checksums.

Wire observability includes `gwlb_profile_rejections_total{reason}`, `gwlb_receive_drops_total{reason}`, `gwlb_send_failures_total`, `gwlb_missing_contexts_total`, `gwlb_conflicted_contexts_total`, `gwlb_possible_loops_total`, `gwlb_unsupported_inner_total{reason}`, context expiry/eviction/collision counters, `datapath_component_healthy{component}`, and `datapath_liveness_transitions_total{component,state}`. Persistent receive, TUN read/write, or raw-send errors make `/healthz` return `503` with the failing component. A successful packet operation recovers its component; an idle receive timeout also proves the receive poll path is working. The `datagram_truncated` reason remains a defensive kernel-read diagnostic, but the production receive buffer covers the full legal IPv4 UDP payload range.

Verify the deterministic sanitized AWS-wire-shaped fixtures independently of the Go codec:

```bash
python3 scripts/verify_geneve_fixtures.py
```

## Component and Integration Harnesses

Local fake-TUN component wire smoke test:

```bash
sudo ./scripts/component_wire_smoke.sh
```

This loopback harness injects a synthetic GWLB-shaped packet into a local Envelope process and observes one TUN return. It does not use AWS, a Tailnet, real GWLB endpoints, or two regions and is not full E2E acceptance.

Synthetic routing smoke test:

```bash
sudo ./scripts/routing_smoke.sh
```

`routing_smoke.sh` uses synthetic interfaces and a synthetic bounded status response. It validates directional effective routes and owned cleanup only; it is not a Tailscale E2E test.

The required two-peer integration uses local Headscale with its embedded local DERP and generated one-hour preauth keys. It pins Headscale 0.25.1 and Tailscale 1.80.3 by digest, runs kernel-TUN peers with Tailscale netfilter disabled in favor of exact owned chains, uses out-of-role workload transit addresses, and requires no external Tailnet or secret:

```bash
./scripts/integration_headscale_two_peer.sh

# Equivalent tagged test on a Linux Docker host:
go test -tags=integration -run TestCohostDirectionalRoles ./internal/routing
```

For both directional lanes, the harness injects an AWS-valid, cookie-bearing GENEVE packet, proves cold traffic bypasses the responder Envelope, and validates exactly one correlated mapped GENEVE return with byte-identical options. The external Tailscale SaaS harness remains an optional compatibility test named `TestSaaSCohostDirectionalRoles`; it is not acceptance evidence.

## AWS Appliance Deployment

The reproducible two-region appliance example, protected runner workflow, cost profile, readiness gates, and ownership-safe rollback are documented in [`docs/aws-appliance-runbook.md`](docs/aws-appliance-runbook.md). It accepts only run-scoped SSM SecureString ARNs; no Tailscale key value is a Terraform input.

The real, billable two-region directional-lane acceptance procedure is documented separately in [`docs/aws-two-region-e2e-runbook.md`](docs/aws-two-region-e2e-runbook.md). It is restricted to the `_lbr_sandbox` Tailnet and must run only from an approved protected environment; the local component smoke test above is not a substitute.

## Benchmark Task

Run repeatable microbenchmarks:

```bash
./scripts/bench.sh
```

## Troubleshooting

- No packets on `envelope0`: verify interface exists and process has `CAP_NET_ADMIN`.
- Health is `503` in `verify/manage`: inspect the bounded reason in `/healthz` and `routing_validation_failures_total{reason}`; check the backend, route approval/acceptance, all three interfaces, forwarding, `rp_filter`, firewall, and MSS policy.
- No return traffic: verify `CAP_NET_RAW`, confirm a reverse-orientation packet has a live unambiguous context, and inspect the missing/conflicted/send-failure metrics.
- Profile rejections: inspect `gwlb_profile_rejections_total{reason}` and verify VNI 0, one flow cookie, zero option reserved bits, and matching protocol type.
- Repeated context conflicts: overlapping inner tuples from multiple GWLB identities are unsupported without a future return selector.
- Health reports `receive`, `tun_read`, `tun_write`, or `send`: inspect the corresponding component and allow one successful operation to clear the persistent-error state.
- MTU drops: inspect `gwlb_mtu_drops_total{family,direction}` and fix MSS/path sizing; no related-ICMP PMTU behavior is promised.

## Rollback

To disable host-routing integration and return to datapath-only behavior, stop the managed process cleanly and restart with `--routing-mode=off`. Shutdown attempts every object with an independent deadline and removes only exact rules/routes created by that process; equivalent state present before startup is retained.

Ownership metadata is process-local. After an ungraceful process loss, inspect exact entries before deleting them; a replacement process conservatively treats equivalent pre-existing state as operator-owned. Do not reuse Envelope's protocol-186/table/priority namespace for operator routes or rules. Manual cleanup, when ownership is known, uses `ip rule del priority <priority> iif <tailscale-iface> to <gwlb-return-cidr> table <table> protocol 186` and `ip route del table <table> <gwlb-return-cidr> dev <envelope-iface> proto 186`.
