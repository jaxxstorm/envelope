## MODIFIED Requirements

### Requirement: Redundant bidirectional site transport
Each site SHALL have at least two AZ-spread Tailscale transport routers that continuously advertise the same complete set of exact local-site workload prefixes for native subnet-router HA. Every router SHALL accept all exact remote-site routes, preserve source addresses with subnet-route SNAT disabled, keep Tailnet DNS acceptance disabled so the VPC resolver remains authoritative, and forward both underlay-to-Tailscale remote traffic and Tailscale-to-underlay local traffic. Higher-priority full-prefix policy rules SHALL force every local-site destination to `main` and the VPC underlay before any local route accepted into table 52; every opposite-site observer SHALL identify exactly one eligible primary owner for each prefix. Envelope targets SHALL NOT run Tailscale or serve as site transit routers.

#### Scenario: Remote-bound inspected packet
- **WHEN** a GWLBE subnet route delivers a remote-site packet to the ENI of the Tailscale-selected source-prefix owner
- **THEN** that router forwards the unchanged source and destination through its accepted Tailscale route without NAT

#### Scenario: Tailnet-arriving local packet
- **WHEN** any site router receives a packet from Tailscale for a local-site CIDR
- **THEN** its higher-priority full-prefix local rule selects `main`, the VPC underlay, and the destination workload prefix's AZ GWLBE before workload delivery, independent of the receiving router AZ or a local table-52 route

#### Scenario: Native route owner fails
- **WHEN** the selected Tailscale router disconnects and another configured router becomes the sole primary for the same exact prefix
- **THEN** the alternate is eligible for the corresponding GWLBE routes only after controller observer quorum and cloud readiness agree

## ADDED Requirements

### Requirement: Autonomous production route alignment
The production topology SHALL run a separate highly available controller that continuously aligns each GWLBE route domain's exact remote-site routes with the ENI of the sole eligible Tailscale primary for that domain's source workload prefix. Each domain's immutable authority SHALL name its exact GWLBE subnet and explicit route-table association IDs, and authoritative readback SHALL require that sole active non-main association in the configured site VPC before route mutation. The controller SHALL use durable fenced state and bounded owner stability. Targets and transport routers SHALL have no AWS route-mutation authority, and production recovery SHALL not depend on the protected acceptance runner.

#### Scenario: Stable alternate is selected
- **WHEN** Tailscale converges an exact source prefix to an eligible alternate and a fresh controller quorum agrees
- **THEN** the controller replaces only that domain's allowlisted routes with the alternate ENI and retains it as stable state

#### Scenario: Ownership is ambiguous
- **WHEN** observers disagree, no sole primary exists, or the selected primary is outside the configured router set
- **THEN** the controller performs no route mutation and reports the domain degraded
