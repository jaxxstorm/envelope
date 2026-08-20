## Why

The Terraform example creates GWLB targets and installs Tailscale, but it never installs, configures, or starts Envelope, so a fresh apply cannot produce a healthy appliance. Provider selection, credentials, host networking, and Availability Zone behavior are also not reproducible enough for an acceptance environment.

## What Changes

- Produce versioned Linux Envelope artifacts with recorded checksums and deploy them through a deterministic artifact channel.
- Extend appliance cloud-init to install Envelope, persistent host-network prerequisites, and an idempotent systemd service ordered after networking and `tailscaled`.
- Pass explicit site-specific runtime configuration to west and east appliances and verify the effective systemd command line.
- Retrieve short-lived Tailscale bootstrap credentials without embedding plaintext secrets in Terraform variables, plans, state, or user data.
- Define Tailnet tag ownership, route approval, grants, advertised prefixes, accepted routes, and backend-readiness gates.
- Make a clean Terraform plan and single apply converge without targeted staging, then produce an empty second plan.
- Pin Terraform/provider/module/image inputs and use a committed dependency lock.
- Define a test-safe GWLB topology with a healthy target path for every enabled endpoint AZ and explicit rejection of unsupported multi-appliance flow ownership.

## Capabilities

### New Capabilities
- `aws-appliance-deployment`: Build and reproducibly deploy a boot-persistent Envelope plus Tailscale appliance that can become a healthy GWLB target.

### Modified Capabilities
- (none)

## Impact

- Affects `example/terraform`, artifact build scripts, IAM, cloud-init, systemd assets, host sysctls/firewall rules, and deployment documentation.
- Adds an artifact store/read path and narrowly scoped instance permissions.
- Changes Terraform state and secret-handling expectations; existing plaintext Tailscale keys must be revoked before rollout.
- Consumes the completed GWLB wire and Tailscale host-routing contracts.
