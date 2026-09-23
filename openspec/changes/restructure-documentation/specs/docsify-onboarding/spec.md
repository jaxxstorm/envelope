## MODIFIED Requirements

### Requirement: Static Docsify documentation entrypoint
The repository SHALL provide a Docsify-compatible static entrypoint in `docs/` with distinct navigation sections for user-facing and developer documentation. The entrypoint SHALL render repository Markdown without requiring a Node dependency, generated site artifact, or server-side application.

#### Scenario: Static host serves the documentation
- **WHEN** a static host serves the `docs/` directory
- **THEN** the Docsify entrypoint loads the user landing page and every sidebar target resolves to a repository documentation page in its intended section

### Requirement: Safe local and protected-run guidance
The documentation SHALL distinguish local build and validation from maintainer Terraform deployment, manual deployment order, and protected acceptance. It SHALL state the required Linux privileges for host integration, identify local results as non-AWS and non-Tailnet validation, and link to a user-facing deployment guide that gives the reviewed Terraform plan/apply form, phase order, and activation boundary. It SHALL not include credentials or account-specific deployment values.

#### Scenario: Reader follows the local path
- **WHEN** a reader wants to try Envelope without AWS credentials
- **THEN** the documentation provides a local build or validation command, identifies its privilege boundary, and labels the result as non-AWS and non-Tailnet validation

#### Scenario: Reader wants an AWS deployment
- **WHEN** a maintainer reaches the AWS setup guidance
- **THEN** the documentation directs them to the deployment guide and identifies reviewed inputs, approval, expiry, credential, cost-review, controller activation, and cleanup requirements

### Requirement: Illustrative Terraform configuration
The documentation SHALL provide a maintainer Terraform deployment guide for the appliance, router-attestor, and controller roots. It SHALL identify each root's required reviewed inputs and separate state boundary; provide the Terraform init, validate, saved-plan, and apply command form; and describe controller initialization, one-replica activation, and rollback order. It SHALL not contain credentials, account-specific values, or treat an incomplete topology fragment as a deployable environment configuration.

#### Scenario: Maintainer follows the Terraform deployment path
- **WHEN** a maintainer prepares an AWS deployment
- **THEN** the documentation identifies the appliance, router-attestor, and controller phase order; the topology, artifact, secret-reference, enrollment, and lifecycle inputs; and the deployment commands to review and execute
