# docsify-onboarding Specification

## Purpose
Define a static newcomer documentation path that explains Envelope's supported architecture, local verification boundary, and protected AWS lifecycle without exposing runnable infrastructure configuration or credentials.

## Requirements

### Requirement: Static Docsify documentation entrypoint
The repository SHALL provide a Docsify-compatible static entrypoint in `docs/` with navigation to newcomer documentation pages. The entrypoint SHALL render repository Markdown without requiring a Node dependency, generated site artifact, or server-side application.

#### Scenario: Static host serves the documentation
- **WHEN** a static host serves the `docs/` directory
- **THEN** the Docsify entrypoint loads the landing page and every sidebar target resolves to a repository documentation page

### Requirement: Newcomer architecture explanation
The documentation SHALL explain why Envelope is useful behind AWS GWLB and how workload routes, GWLBE/GWLB paths, immediate target packet turnaround, GWLBE post-inspection routing, and dedicated Tailscale transport routers compose the supported symmetric path. It SHALL identify Envelope as experimental, Linux-only, and L3-only and SHALL state that targets do not create a TUN, join Tailscale, or directly forward inner traffic.

#### Scenario: New reader evaluates fit
- **WHEN** a reader opens the documentation landing page without prior Envelope knowledge
- **THEN** the reader can identify the AWS GWLB/Tailscale problem Envelope addresses and the topology it does not support

### Requirement: Safe local and protected-run guidance
The documentation SHALL distinguish a local build and component smoke check from protected AWS acceptance. It SHALL state the required Linux privileges for host integration and direct readers to the existing protected runbook for any billable AWS operation.

#### Scenario: Reader follows the local path
- **WHEN** a reader wants to try Envelope without AWS credentials
- **THEN** the documentation provides a local build command and labels the component check as non-AWS, non-Tailnet validation

#### Scenario: Reader wants a live AWS deployment
- **WHEN** a reader reaches the AWS setup guidance
- **THEN** the documentation directs them to the protected lifecycle rather than a raw Terraform apply and identifies current approval, expiry, and credential requirements

### Requirement: Illustrative Terraform configuration
The documentation SHALL include a redacted, non-executable Terraform fragment showing the version-2 symmetric topology, regional site and route-domain inputs, route-failover shape, and cost fields. It SHALL mark its placeholders invalid and its account, artifact, backend, credential, and lifecycle configuration as intentionally omitted. It SHALL not contain credentials, account-specific backend identifiers, or an instruction to run raw `terraform apply`.

#### Scenario: Reader adapts the Terraform example
- **WHEN** a reader reviews the Terraform example
- **THEN** the reader can identify which values must be replaced and can follow the linked runbook to use the protected lifecycle
