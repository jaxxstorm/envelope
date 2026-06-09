## ADDED Requirements

### Requirement: Envelope and tailscaled co-residency
The system SHALL support running Envelope and `tailscaled` concurrently on the same Linux host with distinct interface ownership: Envelope on `envelope0` and Tailscale on `tailscale0` (configurable names).

#### Scenario: Default interface names
- **WHEN** the service starts without explicit interface overrides
- **THEN** Envelope uses `envelope0` and routing checks target `tailscale0`

#### Scenario: Custom interface names
- **WHEN** the service starts with explicit routing interface configuration
- **THEN** routing checks and route programming use the configured interface names

### Requirement: Managed routing mode
The system SHALL provide a managed routing mode that programs policy rules and routes so traffic entering from `tailscale0` and destined for configured protected CIDRs is forwarded to `envelope0`.

#### Scenario: Managed routing setup
- **WHEN** routing mode is `manage` and protected CIDRs are configured
- **THEN** the system installs required policy rule(s) and route entries in the configured routing table

#### Scenario: Idempotent reconciliation
- **WHEN** required rules/routes already exist with the desired state
- **THEN** the system does not create duplicates and continues running

### Requirement: Routing verification mode
The system SHALL provide a verification mode that validates required routing prerequisites without mutating host routing state.

#### Scenario: Verify mode with valid host state
- **WHEN** routing mode is `verify` and required rules/routes/sysctls are present
- **THEN** readiness reports healthy without installing or changing routes

#### Scenario: Verify mode with invalid host state
- **WHEN** routing mode is `verify` and required rules/routes/sysctls are missing
- **THEN** readiness reports unhealthy and the service logs the missing prerequisites

### Requirement: Protected CIDR contract
The system SHALL require explicit protected CIDRs for managed routing and MUST reject invalid CIDR entries.

#### Scenario: Missing protected CIDRs in manage mode
- **WHEN** routing mode is `manage` and no protected CIDRs are configured
- **THEN** startup fails with a configuration error

#### Scenario: Invalid CIDR input
- **WHEN** a protected CIDR value is malformed
- **THEN** startup fails with a validation error naming the invalid entry

### Requirement: Routing observability
The system SHALL expose routing-specific metrics for apply attempts, apply failures, and reconciliation drift repairs.

#### Scenario: Managed apply failure
- **WHEN** route or rule programming fails in managed mode
- **THEN** the corresponding routing failure metric is incremented

#### Scenario: Drift repaired
- **WHEN** a reconcile pass detects and restores missing route/rule state
- **THEN** the drift-repair metric is incremented
