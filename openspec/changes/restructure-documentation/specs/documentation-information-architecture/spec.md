## ADDED Requirements

### Requirement: Concise repository orientation
The repository root README SHALL identify Envelope, its experimental Linux-only GWLB packet-turnaround scope, the separation between packet targets and transport/control-plane roles, and the `docs/` entrypoint. It SHALL not contain detailed E2E run history, protected acceptance procedures, or a full operational runbook.

#### Scenario: Reader opens the repository
- **WHEN** a reader opens `README.md`
- **THEN** they can determine Envelope's purpose and follow a direct link to the user documentation without reading developer E2E detail

### Requirement: User-facing operating documentation
The `docs/` root SHALL provide user-facing pages that explain Envelope components, supported packet and control-plane architecture, operating modes, safe automated checks, manual diagnostics, troubleshooting, and application or operator best practices. The documentation SHALL identify what each check proves and does not prove.

#### Scenario: Operator selects a workflow
- **WHEN** an operator needs to build, validate, operate, or diagnose Envelope
- **THEN** the user documentation directs them to a page appropriate to that activity and states the applicable safety and validation boundary

### Requirement: Developer E2E documentation boundary
The `docs/developer/` hierarchy SHALL contain protected E2E acceptance architecture, workflow and evidence details, historical run records, and developer verification guidance. User-facing pages SHALL link to this hierarchy for protected-run detail rather than embedding historical evidence narratives.

#### Scenario: Developer investigates acceptance evidence
- **WHEN** a developer needs E2E failure, recovery, evidence, or workflow detail
- **THEN** the developer documentation provides that material without presenting it as a standard user operation

### Requirement: Maintainer deployment and validation guidance
Documentation SHALL distinguish local automated validation, Terraform deployment, manual deployment order, and protected acceptance. It SHALL provide the reviewed Terraform phase order for the appliance, router-attestor, and controller roots, identify their required inputs and separate state boundaries, and document the controller initialization and activation gate. It SHALL provide a manual component deployment order without credentials or account-specific values. It SHALL require reviewed inputs, short-lived credentials, cost approval, explicit expiry, and cleanup authority for live AWS or Tailscale operations.

#### Scenario: Maintainer deploys the topology
- **WHEN** a maintainer needs to deploy Envelope into AWS
- **THEN** the documentation explains the appliance, router-attestor, and controller Terraform phases; gives the Terraform plan/apply command form; and identifies the reviewed inputs and controller activation gate required before routes can change

#### Scenario: Reader runs a local check
- **WHEN** a reader follows local automated or manual guidance
- **THEN** the documentation states that the result is not AWS, Tailnet, multi-AZ, or protected acceptance evidence

### Requirement: Verifiable documentation navigation
The Docsify landing page and sidebar SHALL present distinct user and developer documentation sections. Repository documentation tests SHALL validate required entrypoints, sidebar targets, and repository-relative links after documentation moves.

#### Scenario: Static site navigation loads
- **WHEN** a static host serves `docs/`
- **THEN** the landing page and every sidebar target resolve to their intended user or developer documentation page

#### Scenario: Documentation is validated in CI
- **WHEN** the repository documentation test suite runs
- **THEN** it rejects missing required pages, broken repository-relative links, or a sidebar that omits either documentation section
