## Why

Envelope and `tailscaled` need deterministic, loop-free routing on one Linux appliance, but the current single `protected-cidrs` model sends cold Tailnet packets toward an Envelope process that has no destination-side GWLB context. The existing change also claims real bidirectional and Terraform acceptance that its dummy-interface harness and Tailscale-only user data do not provide.

## What Changes

- Keep strict separate ownership of `envelope0` and `tailscale0`, reject identical names, and create the Envelope TUN exclusively so pre-existing devices cannot be attached.
- **BREAKING**: replace ambiguous protected CIDRs with disjoint local GWLB-return CIDRs and local-delivery CIDRs, plus explicit remote Tailnet CIDRs.
- Route Tailnet returns for local initiator lanes into `envelope0`, while cold packets for local responder lanes bypass Envelope and use normal local delivery.
- Validate the forward path from GENEVE/TUN toward an accepted remote Tailscale route as well as the mapped return path.
- Define persistent forwarding, non-strict `rp_filter`, forwarding firewall, TCP MSS clamp, and explicit oversized-packet drop observability for a 1280-byte Tailscale path.
- Make readiness depend on a symbolic full-prefix policy-rule/table audit that fails closed on relevant source-specific routes, plus supplementary structured boundary lookups, Tailscale table-52 ownership, a pinned v1.80 kernel-TUN status schema, and serving-peer data-plane probes, not interface existence alone.
- Require complete legacy-iptables save inspection, deterministic `ACCEPT` forwarding policies and owned chains, executable native-nft inspection, and live-MTU-derived exact MSS values on every directed path; reject unprovable nft/firewalld layouts.
- Make managed route/rule reconciliation use a reserved protocol-186/table/priority ownership namespace, a cross-process lock, transactional rollback, and verified cleanup so failed adds never claim observed state and unresolved conflicts never count as removal.
- Keep routing mode default `off`; AWS deployment must opt into `manage` explicitly after host preflight.
- Replace false cohost acceptance with a required, secretless, digest-pinned Headscale/Tailscale environment that proves a correlated GENEVE return through real kernel-TUN peers and workload namespaces. Keep external Tailscale SaaS testing optional and separate.

## Capabilities

### New Capabilities
- `tailscale-host-routing`: Define directional CIDR roles, effective Linux forwarding, Tailscale readiness, MTU behavior, and ownership-safe reconciliation for co-resident Envelope and Tailscale.

### Modified Capabilities
- `geneve-tun-datapath`: make routing-aware health, metrics, interface ownership, and end-to-end MTU behavior cumulative with GWLB datapath liveness.

## Impact

- Affects configuration names, routing manager behavior, readiness, metrics, host preflight, integration tests, and documentation.
- Existing `--protected-cidrs` users must migrate to explicit local GWLB-return and local-delivery CIDR roles.
- Terraform implementation moves to `envelope-aws-appliance-deployment`; live two-region proof moves to `envelope-two-region-e2e`.
