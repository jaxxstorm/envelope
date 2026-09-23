## MODIFIED Requirements

### Requirement: Fresh-state Terraform convergence
The deployment SHALL support a clean Terraform plan and normal apply for a reviewed `infrastructure` phase from empty state, followed by a reviewed normal plan and apply for the `targets` phase from the same state, a no-change plan after each completed phase, and complete destroy. The infrastructure phase SHALL intentionally contain no Envelope target instances or target-group attachments; the targets phase SHALL add the target fleet without a Terraform `-target` operation.

#### Scenario: Fresh-state infrastructure plan
- **WHEN** Terraform plans from empty state with valid inputs and the `infrastructure` phase
- **THEN** all foundational resource instance keys are known during planning, the plan completes without `-target`, and it contains no Envelope target or target-group attachment

#### Scenario: Infrastructure apply is intentionally unavailable
- **WHEN** the reviewed infrastructure plan is applied
- **THEN** VPCs, GWLBs, target groups, GWLBE endpoints, routers, controller topology inputs, and routes converge with empty target groups, and inspected data-plane traffic is expected to fail

#### Scenario: Reviewed target apply
- **WHEN** Terraform plans and applies the reviewed `targets` phase from the infrastructure state
- **THEN** the EC2 Envelope target fleet and its target-group registrations converge without changing the reviewed foundational route, router, or controller topology resources

#### Scenario: Idempotent phase plan
- **WHEN** Terraform plans again after either successfully completed unchanged phase
- **THEN** the plan reports no changes for that phase

#### Scenario: Complete destroy
- **WHEN** the destroy plan is applied from either phase's state
- **THEN** no test-owned AWS resources remain in state or in either Region

### Requirement: Reproducible Terraform inputs
The deployment SHALL pin tested Terraform, provider, AMI, artifact, and module inputs, including `terraform-aws-modules/vpc/aws` exactly at v6.7.2, and SHALL retain a dependency lock with checksums for supported execution platforms. It SHALL retain the reviewed vendored Tailscale cloud-init module when its package verification and pre-setup ordering are required. It SHALL use reviewed explicit west and east Availability Zone names rather than dynamic first-N discovery.

#### Scenario: Clean initialization
- **WHEN** Terraform initializes from a clean checkout
- **THEN** it selects the reviewed provider versions, `terraform-aws-modules/vpc/aws` v6.7.2, local vendored module, and verifies their locked checksums where applicable

#### Scenario: Unreviewed dependency change
- **WHEN** an initialization or plan would select a different provider, VPC module, AMI, artifact, or vendored module source
- **THEN** the change is visible for review before apply

#### Scenario: Explicit regional AZs
- **WHEN** a clean plan is created
- **THEN** all enabled west and east Availability Zone names come from reviewed inputs rather than dynamic first-N discovery

#### Scenario: Architecture compatibility
- **WHEN** artifact architecture, AMI architecture, appliance type, or test instance type are incompatible
- **THEN** protected preflight queries the selected AWS image and instance-type metadata and fails before planning resources
