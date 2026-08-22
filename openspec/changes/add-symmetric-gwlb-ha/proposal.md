## Why

Envelope currently proves a one-target, asymmetric return path using process-local GWLB return context and separate initiator/responder CIDRs. That model cannot provide a general site-to-site Tailscale service with arbitrary bidirectional initiation or resilient multi-target operation, so the deployment must instead make GWLB inspect both directions of every inter-site flow.

## What Changes

- Add a symmetric inline GWLB forwarding mode in which Envelope decapsulates validated GWLB traffic and forwards it by destination without requiring a locally stored return context for normal traffic.
- Add a two-plane site topology: redundant Tailscale ingress routers send Tailnet-originated site traffic to the local GWLBE, while a multi-AZ GWLB target fleet forwards inspected traffic to the local VPC or Tailscale.
- **BREAKING** replace the directional initiator/responder CIDR role model and one-regional-target Terraform profile with explicit local-site, remote-site, ingress-router, endpoint, and target route domains.
- Add target readiness, draining, and failure evidence for multiple targets and redundant Tailscale route advertisers.
- Define bounded HA guarantees: availability for new flows and transport recovery after bounded packet loss are in scope; hitless TCP/UDP continuity during an instance, AZ, GWLB, or Tailscale failover is not promised.

## Capabilities

### New Capabilities
- `symmetric-gwlb-ha-topology`: Defines the two-plane site-to-site topology, route-domain separation, multi-AZ target/endpoint requirements, and bounded HA behavior.

### Modified Capabilities
- `geneve-tun-datapath`: Replace context-dependent egress as the normal site-to-site path with symmetric inline forwarding behavior.
- `gwlb-wire-interop`: Preserve strict AWS GENEVE validation while making return-context capture optional for the new symmetric forwarding mode.
- `tailscale-host-routing`: Replace directional CIDR roles with verified ingress-router and post-inspection route domains.
- `aws-appliance-deployment`: Replace the single regional target/lane deployment with redundant ingress routers, multiple GWLB targets, and HA-aware acceptance.

## Impact

- Affects Go configuration, datapath flow handling, metrics, health, and host-routing validation.
- Replaces the current acceptance Terraform topology, its protected-run configuration schema, Tailnet route policy requirements, and live E2E evidence.
- Requires new privileged local integration and protected AWS failure testing for target loss, process restart, and Tailscale ingress-router failover.
