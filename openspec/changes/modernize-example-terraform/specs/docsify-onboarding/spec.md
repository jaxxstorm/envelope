## MODIFIED Requirements

### Requirement: Newcomer architecture explanation
The documentation SHALL explain why Envelope is useful behind AWS GWLB and how workload routes, GWLBE/GWLB paths, immediate target packet turnaround, GWLBE post-inspection routing, dedicated EC2 Tailscale transport routers, and the production-v3 standalone controller compose the supported symmetric path. It SHALL identify Envelope as experimental, Linux-only, and L3-only and SHALL state that targets do not create a TUN, join Tailscale, directly forward inner traffic, or run on ECS. It SHALL distinguish the intentionally unavailable infrastructure phase from the target phase that registers healthy EC2 targets.

#### Scenario: New reader evaluates fit
- **WHEN** a reader opens the documentation landing page without prior Envelope knowledge
- **THEN** the reader can identify the AWS GWLB/Tailscale problem Envelope addresses, the EC2 target/router/controller roles, the staged activation boundary, and the topology it does not support

## ADDED Requirements

### Requirement: Appliance and Tailnet operator configuration
The documentation SHALL provide an appliance operator guide that explains packet-scoped Envelope target behavior, dedicated EC2 transport-router forwarding and route advertisement behavior, and production-v3 controller route reconciliation. It SHALL require operators to configure one reviewed `tailscale_tag` for router bootstrap; a `tagOwners` entry authorizing the approved bootstrap-key creator for exactly that tag; ACL entries allowing only bidirectional traffic from the configured west workload CIDRs to the configured east workload CIDRs and the reverse; and `autoApprovers.routes` entries approving every exact configured local workload CIDR for exactly that tag. It SHALL state that router bootstrap keys are reusable, preauthorized, tagged only with the configured router tag, and stored only in the configured regional encrypted SSM parameter. It SHALL reject wildcards, supernets, unrelated route approvals, target tags, target Tailscale enrollment, and unapproved manual route activation as substitutes for these requirements.

#### Scenario: Operator configures Tailnet before infrastructure apply
- **WHEN** an operator prepares a deployment with configured `tailscale_tag`, west local-site CIDRs, and east local-site CIDRs
- **THEN** the guide supplies an exact policy template with one tag-owner entry for that tag, two directional ACL rules limited to those CIDR sets, and one auto-approval entry for every exact west and east local workload CIDR bound to that tag

#### Scenario: Operator evaluates route approval scope
- **WHEN** a Tailnet policy omits an exact advertised prefix, grants an unconfigured prefix or supernet, permits a wildcard source or destination, or permits a target to join Tailscale
- **THEN** the guide identifies the policy as unsupported and directs the operator to correct it before AWS resources are created

#### Scenario: Operator distinguishes target and router credentials
- **WHEN** an operator configures bootstrap credentials
- **THEN** the guide directs the credential only to tagged EC2 transport routers through the regional encrypted parameter and states that Envelope targets, workloads, and the controller do not receive that bootstrap credential

### Requirement: Vendored cloud-init rationale
The documentation SHALL state that `example/terraform/modules/tailscale-cloudinit` is intentionally retained instead of `tailscale/terraform-cloudinit-tailscale` v0.0.12 because the upstream module lacks checksum-pinned Tailscale package installation and the pre-setup gate needed before router authentication and route advertisement. It SHALL direct maintainers to the vendored provenance and input checksum records.

#### Scenario: Maintainer considers an upstream module replacement
- **WHEN** a maintainer reads the Terraform appliance documentation before changing the transport-router cloud-init source
- **THEN** the documentation identifies the two required controls and explains why the current vendored module remains the supported choice
