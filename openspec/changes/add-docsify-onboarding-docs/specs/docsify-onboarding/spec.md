## ADDED Requirements

### Requirement: Static Docsify documentation entrypoint
The repository SHALL provide a Docsify-compatible static entrypoint in `docs/` with navigation to newcomer documentation pages. The entrypoint SHALL render repository Markdown without requiring a Node dependency, generated site artifact, or server-side application.

#### Scenario: Static host serves the documentation
- **WHEN** a static host serves the `docs/` directory
- **THEN** the Docsify entrypoint loads the landing page and every sidebar target resolves to a repository documentation page

### Requirement: Newcomer architecture explanation
The documentation SHALL explain why Envelope is useful behind AWS GWLB and how inbound GENEVE packets, `envelope0`, host routing, and `tailscale0` compose the supported path. It SHALL identify Envelope as experimental, Linux-only, L3-only, and limited to separate directional initiator and responder prefixes.

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
The documentation SHALL include a redacted, non-executable Terraform acceptance configuration example showing the directional CIDR roles, regional site inputs, artifact manifest, Tailnet environment-variable references, and cost/expiry approval fields. It SHALL not contain credentials, account-specific backend identifiers, or an instruction to run raw `terraform apply`.

#### Scenario: Reader adapts the Terraform example
- **WHEN** a reader reviews the Terraform example
- **THEN** the reader can identify which values must be replaced and can follow the linked runbook to use the protected lifecycle
