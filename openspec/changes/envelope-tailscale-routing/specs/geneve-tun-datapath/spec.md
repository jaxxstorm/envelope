## MODIFIED Requirements

### Requirement: Metrics exposure
The system SHALL expose Prometheus metrics on `:9090/metrics` and MUST include counters: `geneve_rx_packets`, `geneve_rx_bytes`, `geneve_tx_packets`, `geneve_tx_bytes`, `decap_errors`, `encap_errors`, `tun_rx_packets`, `tun_tx_packets`, and `drops`. When routing integration is enabled, it MUST additionally expose routing counters for apply attempts, apply failures, and drift repairs.

#### Scenario: Metrics scrape
- **WHEN** a client requests `:9090/metrics`
- **THEN** the response includes all required datapath counters and routing counters applicable to the configured routing mode

### Requirement: Health endpoint
The system SHALL expose a health endpoint at `:9090/healthz` that returns HTTP 200 when the datapath is initialized and ready to process packets. If routing mode is `manage` or `verify`, readiness MUST also require routing prerequisites (configured interfaces, required policy rules/routes, and required forwarding sysctls).

#### Scenario: Datapath-only readiness
- **WHEN** routing mode is `off` and a client requests `:9090/healthz`
- **THEN** the response is HTTP 200 if the UDP socket and Envelope TUN device are ready

#### Scenario: Routing-integrated readiness
- **WHEN** routing mode is `manage` or `verify` and a client requests `:9090/healthz`
- **THEN** the response is HTTP 200 only if datapath readiness and routing prerequisites are all satisfied

#### Scenario: Routing prerequisite missing
- **WHEN** routing mode is `manage` or `verify` and required routing state is missing
- **THEN** the response is HTTP 503 and readiness indicates routing is not ready

## ADDED Requirements

### Requirement: Envelope datapath ownership boundary
The system SHALL terminate and originate GENEVE on the Envelope-owned TUN device and MUST NOT assume shared TUN ownership with `tailscaled`.

#### Scenario: Co-resident tailscaled deployment
- **WHEN** Envelope runs on a host where `tailscaled` is active
- **THEN** Envelope continues using its configured TUN interface and relies on host routing for forwarding to/from Tailscale
