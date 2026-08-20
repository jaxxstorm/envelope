## MODIFIED Requirements

### Requirement: MTU-aware handling
The system SHALL enforce the configured inner MTU, SHALL integrate with host TCP MSS policy so valid TCP streams do not become persistent silent blackholes, and SHALL receive every complete legal IPv4 UDP payload so unsupported oversized traffic is dropped with an explicit MTU reason. The GWLB profile MUST NOT claim PMTU signalling until related ICMP-to-context behavior is specified and proven.

#### Scenario: Tailscale-safe TCP flow
- **WHEN** traffic crosses a configured 1280-byte Tailscale path
- **THEN** host routing constrains TCP MSS to a value that prevents packets larger than the Envelope inner MTU

#### Scenario: Every directed Tailscale TCP path
- **WHEN** IPv4 or IPv6 TCP traffic crosses underlay to Tailscale, Tailscale to underlay, Envelope to Tailscale, or Tailscale to Envelope
- **THEN** the SYN advertises the derived safe MSS and a full-sized TCP transfer completes without a silent drop

#### Scenario: Oversized packet
- **WHEN** an inner packet exceeds the configured Envelope MTU
- **THEN** it is dropped with an MTU-specific reason and counter rather than an undifferentiated drop

#### Scenario: Maximum-options one-byte oversize ingress
- **WHEN** a complete UDP datagram contains 252 bytes of valid options and an inner packet exactly one byte above the configured MTU
- **THEN** receive capacity preserves the complete datagram and reports an ingress MTU drop rather than UDP truncation

#### Scenario: Arbitrarily oversized valid ingress
- **WHEN** a complete legal UDP datagram contains a valid GENEVE packet whose inner packet is two or substantially more bytes above the configured MTU
- **THEN** receive capacity preserves the complete datagram and reports the appropriate IPv4 or IPv6 ingress MTU reason rather than generic truncation

#### Scenario: Real-TUN one-byte oversize egress
- **WHEN** a real TUN returns an inner frame exactly one byte above the configured Envelope MTU
- **THEN** Envelope observes and drops it without encapsulating truncated or stale buffer contents

### Requirement: Metrics exposure
The system SHALL expose all GWLB datapath and context metrics plus routing apply attempts and failures, effective-path failures by reason, drift repairs, ownership decisions, Tailscale readiness failures, MTU-specific drops, and current routing readiness.

#### Scenario: Datapath-only metrics scrape
- **WHEN** a client requests `:9090/metrics` in routing mode `off`
- **THEN** the response includes all required GWLB datapath and context metrics

#### Scenario: Routing-integrated metrics scrape
- **WHEN** a client requests `:9090/metrics` in routing mode `verify` or `manage`
- **THEN** the response additionally includes all routing and host-path metrics with reason labels or bounded reason-specific counters

### Requirement: Health endpoint
The system SHALL return HTTP 200 from `:9090/healthz` only when the live GWLB datapath is healthy and, in `verify` or `manage` mode, the Tailscale backend, effective forward and return routes, host forwarding, reverse-path filtering, firewall, MSS policy, and managed state are ready.

#### Scenario: Datapath-only readiness
- **WHEN** routing mode is `off` and the live datapath is healthy
- **THEN** `:9090/healthz` returns HTTP 200

#### Scenario: Routing-integrated readiness
- **WHEN** routing mode is `verify` or `manage` and every effective routing prerequisite is valid
- **THEN** `:9090/healthz` returns HTTP 200

#### Scenario: Routing prerequisite missing
- **WHEN** any required backend, route, rule, sysctl, reverse-path, firewall, MSS, or ownership condition is invalid
- **THEN** `:9090/healthz` returns HTTP 503 with a bounded component-specific reason

#### Scenario: Persistent datapath failure
- **WHEN** the GWLB receive, TUN, or compliant-send path exceeds its persistent-error threshold
- **THEN** routing state cannot mask the failure and `:9090/healthz` returns HTTP 503

#### Scenario: Unexpected loop termination
- **WHEN** the receive or TUN-read loop closes without process cancellation or explicit shutdown
- **THEN** the component becomes immediately unhealthy, sibling loops are cancelled, resources close once, and the process supervisor receives an error

## ADDED Requirements

### Requirement: Envelope datapath ownership boundary
The system SHALL terminate and originate GENEVE on the Envelope-owned TUN device and MUST NOT share that TUN with `tailscaled`; host routing SHALL connect the Envelope and Tailscale interfaces according to explicit CIDR roles.

#### Scenario: Co-resident tailscaled deployment
- **WHEN** Envelope runs with an active `tailscaled`
- **THEN** each process retains its configured interface and packets move between them only through verified host routing

#### Scenario: Pre-existing Envelope TUN
- **WHEN** the configured Envelope TUN name already identifies a persistent or attached device
- **THEN** exclusive TUN creation fails startup rather than sharing or reconfiguring that device

#### Scenario: Local-delivery Tailnet packet
- **WHEN** a cold Tailnet packet is destined for a configured local-delivery CIDR
- **THEN** host routing bypasses `envelope0`, so the packet is not subjected to a nonexistent local GWLB return context
