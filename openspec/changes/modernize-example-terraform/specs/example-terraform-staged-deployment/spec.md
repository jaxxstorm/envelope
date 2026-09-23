## ADDED Requirements

### Requirement: Pinned VPC module topology
The example Terraform SHALL declare `terraform-aws-modules/vpc/aws` at exactly v6.7.2 for each site VPC and SHALL retain a dependency lock containing checksums for the selected module and providers. It SHALL pass reviewed explicit Region, AZ, VPC CIDR, subnet CIDR, DNS, internet-gateway, and NAT inputs to the module rather than discover a first-N AZ set. The resulting topology SHALL retain separate workload, transport-router, GWLBE, GWLB, target, and management route domains and their explicit route-table associations.

#### Scenario: Clean module initialization
- **WHEN** Terraform initializes the example from a clean checkout
- **THEN** it selects `terraform-aws-modules/vpc/aws` v6.7.2 and the locked provider and module checksums

#### Scenario: Explicit symmetric topology is planned
- **WHEN** Terraform plans the reviewed two-site topology
- **THEN** each module-backed VPC uses the configured AZ and CIDR inputs and the plan retains one explicit route domain and association for every configured site/AZ role

#### Scenario: Unreviewed module version is selected
- **WHEN** initialization or planning would use a VPC module version other than v6.7.2
- **THEN** the dependency change is visible for review and the reviewed example dependency contract is not satisfied

### Requirement: Reviewed staged target rollout
The example Terraform SHALL expose a validated deployment phase with exactly `infrastructure` and `targets` values. Both phases SHALL create the module-backed VPCs, GWLBs, target groups and listeners, endpoint services, one GWLBE endpoint per enabled workload/transport-router AZ, exact workload and transport routes through those endpoints, EC2 transport routers, and production-v3 controller topology inputs. Only the `targets` phase SHALL create the EC2 Envelope target fleet and register it with the corresponding GWLB target groups. Neither phase SHALL use Terraform `-target` as a deployment mechanism.

#### Scenario: Infrastructure phase creates an empty inspection service
- **WHEN** a reviewed plan and apply use the `infrastructure` phase
- **THEN** every configured site/AZ has its GWLB, GWLBE endpoint, route-domain association, and empty target group, while no Envelope target instance or target-group attachment is planned or created

#### Scenario: Infrastructure data plane is unavailable
- **WHEN** a workload or transport-router packet selects a GWLBE during the `infrastructure` phase
- **THEN** GWLB has no registered Envelope target to process it, the packet fails rather than using a direct route, and outputs and operator guidance identify the failure as expected until the target phase

#### Scenario: Reviewed target phase activates inspection
- **WHEN** the same deployment state is changed to `targets` and its normal Terraform plan is reviewed and applied
- **THEN** Terraform creates the configured EC2 Envelope targets, registers them only with their site's GWLB target group, and leaves the VPC, endpoint, router, and controller topology resources intact

#### Scenario: Target phase remains EC2-based
- **WHEN** the `targets` phase is planned
- **THEN** every Envelope target is an EC2 instance in its configured target subnet and the plan contains no ECS service, task definition, or container-based replacement for a target, router, or controller

### Requirement: Retained verified Tailscale cloud-init module
The example Terraform SHALL retain `./modules/tailscale-cloudinit` for EC2 transport-router cloud-init. Its provenance documentation SHALL state that it is retained instead of `tailscale/terraform-cloudinit-tailscale` v0.0.12 because the upstream module does not provide both checksum-pinned package installation and a pre-setup gate. The vendored module SHALL continue to verify the reviewed Tailscale package and complete the transport-router pre-setup gate before resolving the runtime credential or invoking `tailscale up`.

#### Scenario: Router cloud-init uses verified ordered setup
- **WHEN** a transport router is rendered for either site
- **THEN** its cloud-init uses the vendored module, pins the reviewed package URL and checksum, and places the transport-router network setup behind the configured pre-setup gate before Tailscale authentication

#### Scenario: Upstream substitution is proposed
- **WHEN** an implementation proposes `tailscale/terraform-cloudinit-tailscale` v0.0.12 as the router module source
- **THEN** the proposal is rejected because it lacks the required checksum-pinned package-install and pre-setup-gate controls
