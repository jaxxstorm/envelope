## ADDED Requirements

### Requirement: Multi-AZ symmetric site deployment
The protected deployment SHALL create at least two enabled AZs per site, a GWLBE in every enabled workload and Tailscale-ingress AZ, and at least one Envelope target in every enabled target AZ. Each workload route table SHALL send exact remote-site CIDRs to its local GWLBE, and each ingress-router route table SHALL send exact local-site CIDRs to its local GWLBE.

#### Scenario: Both sites have symmetric paths
- **WHEN** Terraform plans a valid two-site configuration
- **THEN** each site contains the required endpoint, target, workload, and ingress-router route domains and every declared site CIDR has an exact reviewed path

#### Scenario: Missing AZ target
- **WHEN** an enabled site AZ has a GWLBE but no healthy-capable Envelope target path
- **THEN** Terraform validation rejects the plan before apply

### Requirement: Redundant Tailscale ingress routers
The deployment SHALL create at least two independent Tailscale ingress routers per site, spread across enabled AZs, that advertise exactly the same local-site CIDRs with subnet-route SNAT disabled. Envelope targets SHALL not be the required local-site route advertisers.

#### Scenario: Overlapping local-site advertisements
- **WHEN** a site is deployed successfully
- **THEN** at least two ready ingress routers advertise every exact local-site prefix and target nodes are not the sole route advertiser for that prefix

#### Scenario: Incomplete router advertisements
- **WHEN** one ingress router advertises a broader, narrower, or missing local-site prefix
- **THEN** protected preflight fails before resources are created

### Requirement: HA-aware target readiness and drain
The deployment SHALL register an Envelope target healthy only after symmetric datapath, TUN injection, target route validation, Tailscale egress, forwarding, firewall, and MSS prerequisites are ready. A planned target stop or replacement SHALL mark it unready, wait for documented deregistration/drain evidence, and retain diagnostics without credentials.

#### Scenario: Premature target registration
- **WHEN** any symmetric target prerequisite is unhealthy
- **THEN** its GWLB target health remains unhealthy and the protected workflow stops before live traffic

#### Scenario: Planned target replacement
- **WHEN** the protected workflow replaces a healthy target
- **THEN** it records the unready transition, AWS target drain evidence, replacement readiness, and the succeeding target identity

### Requirement: Symmetric HA acceptance evidence
The protected acceptance SHALL prove new bidirectional TCP, UDP, and ICMP flows using the same workload CIDR at both sites, capture each direction's local GWLBE and GWLB traversal, and execute target-process, target-instance, and ingress-router failure exercises. Evidence SHALL record target and router identities, health transitions, recovery duration, established TCP outcome, UDP loss, and post-cleanup residual audit.

#### Scenario: Bidirectional cold flows
- **WHEN** both site workloads initiate cold TCP, UDP, and ICMP flows concurrently
- **THEN** each flow succeeds without CIDR-role partitioning and evidence proves both local GWLB traversals

#### Scenario: Alternate target recovery
- **WHEN** a selected target process or instance is made unavailable
- **THEN** a new flow succeeds through another healthy target and evidence records bounded recovery rather than a hitless guarantee

#### Scenario: Alternate ingress-router recovery
- **WHEN** a selected Tailscale ingress router is made unavailable
- **THEN** a new remote-initiated flow succeeds through another exact-prefix router and evidence records bounded recovery

## REMOVED Requirements

### Requirement: Site-specific runtime configuration
**Reason**: The current configuration encodes one regional target and directional lane roles instead of the symmetric site model.
**Migration**: Use the versioned symmetric configuration with local-site/remote-site CIDRs, enabled AZs, target fleet inputs, ingress-router inputs, and approved HA acceptance thresholds.

### Requirement: Single regional flow owner
**Reason**: Symmetric traversal lets GWLB provide target affinity and removes target-local return ownership.
**Migration**: Replace the one-target constraint with an enabled-AZ target fleet and validate that every inter-site packet traverses a GWLBE in both directions.

### Requirement: Tailscale control-plane readiness
**Reason**: Target and ingress-router Tailscale responsibilities are now distinct.
**Migration**: Validate target egress routes separately from ingress-router exact-prefix advertisements and GWLBE route readiness.

### Requirement: GWLB target bootstrap readiness
**Reason**: A target must now prove symmetric forwarding prerequisites and coordinated drain behavior, not only a single regional target's health.
**Migration**: Use HA-aware target readiness and drain evidence for every enabled target.
