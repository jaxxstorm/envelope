## Why

The example Terraform currently hand-defines its VPC topology and couples GWLB endpoint creation to Envelope target deployment. Operators cannot review the network foundation independently, and the user documentation does not provide the exact appliance and Tailnet policy contract needed to operate the supported production-v3 architecture.

## What Changes

- Refactor `example/terraform` to use the pinned `terraform-aws-modules/vpc/aws` v6.7.2 module while retaining the existing two-region, multi-AZ route-domain topology.
- Introduce reviewed infrastructure and target deployment phases: infrastructure creates GWLB, target groups, and GWLBE endpoints without Envelope target instances or registrations; the target phase creates and registers the EC2 Envelope targets. The infrastructure phase intentionally has no working data plane.
- Preserve the production-v3 standalone controller and dedicated EC2 Tailscale transport-router model; this is not an ECS migration.
- Retain the vendored `modules/tailscale-cloudinit` module and document why it is used instead of `tailscale/terraform-cloudinit-tailscale` v0.0.12: the vendored module supplies checksum-pinned package installation and the pre-setup gate required by this deployment.
- Add user documentation explaining the appliance, the target and router roles, Tailscale setup, and the exact ACL, tag ownership, and route approval requirements.

## Capabilities

### New Capabilities
- `example-terraform-staged-deployment`: Defines the module-pinned, two-phase Terraform deployment contract for the example topology.

### Modified Capabilities
- `aws-appliance-deployment`: Changes example Terraform convergence from a single target-coupled deployment to a reviewed infrastructure phase followed by a target phase, while retaining reproducible dependency and cloud-init controls.
- `symmetric-gwlb-ha-topology`: Adds the intentionally unavailable no-target state before the symmetric inspected path becomes active.
- `docsify-onboarding`: Requires appliance and exact Tailnet administrative guidance for the supported deployment model.

## Impact

The implementation will change only the example Terraform topology, dependency lock and module usage, phase controls, tests, and user documentation. It will add `terraform-aws-modules/vpc/aws` v6.7.2 as a locked dependency, retain the local Tailscale cloud-init module, and leave the Envelope runtime, production-v3 controller, and EC2 transport routers unchanged.
