## ADDED Requirements

### Requirement: Symmetric target route validation
Envelope target routing SHALL configure disjoint `local-site-cidrs` and `remote-site-cidrs`. For every local-site CIDR, packets injected from `envelope0` SHALL select direct local VPC delivery; for every remote-site CIDR, packets injected from `envelope0` SHALL select `tailscale0`. The target SHALL reject legacy directional CIDR roles and SHALL not install an `iif tailscale0` rule to `envelope0`.

#### Scenario: Local-site target forwarding
- **WHEN** a GWLB-delivered packet is injected into `envelope0` with a local-site destination
- **THEN** effective routing selects the configured underlay and post-inspection local VPC path

#### Scenario: Remote-site target forwarding
- **WHEN** a GWLB-delivered packet is injected into `envelope0` with a remote-site destination
- **THEN** effective routing selects `tailscale0` and an accepted Tailnet route

#### Scenario: Legacy directional configuration
- **WHEN** a target configuration supplies `gwlb-return-cidrs` or `local-delivery-cidrs`
- **THEN** configuration fails before host state is inspected or mutated

### Requirement: Tailscale ingress-router readiness
The deployment SHALL validate each Tailscale ingress router separately from Envelope targets. An ingress router SHALL advertise the exact local-site CIDRs without subnet-route SNAT, accept its required remote routes, and have an effective VPC route from each local-site CIDR to the local GWLBE before it is considered ready.

#### Scenario: Ready ingress router
- **WHEN** the Tailscale backend is Running, exact local-site route advertisements are approved, and each local-site CIDR selects the local GWLBE
- **THEN** the ingress router is ready to receive a remote Tailnet packet

#### Scenario: Direct-delivery ingress route
- **WHEN** an ingress router can directly deliver a local-site CIDR instead of selecting the local GWLBE
- **THEN** ingress-router readiness is unhealthy and identifies the affected prefix

## REMOVED Requirements

### Requirement: Explicit directional CIDR roles
**Reason**: Separate initiator/responder CIDRs prevent arbitrary bidirectional site-to-site initiation.
**Migration**: Replace the three directional role lists with disjoint `local-site-cidrs` and `remote-site-cidrs`; configure GWLBE routing through the deployment's ingress-router and target route domains.

### Requirement: Managed GWLB-return routing
**Reason**: Tailnet-originated packets now enter GWLB through a dedicated ingress router rather than relying on a target-local return context.
**Migration**: Remove managed `iif tailscale0` to `envelope0` rules and deploy the ingress-router route domain.
