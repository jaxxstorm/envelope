## Why

Envelope's documentation currently places protected E2E history and verification detail alongside the newcomer path. Readers cannot quickly identify the packet target, transport routers, production controller, supported operating model, or safe troubleshooting steps without crossing an internal testing boundary.

## What Changes

- Refocus the repository `README.md` on what Envelope is, its supported boundary, and the user documentation entrypoint.
- Reorganize `docs/` as user-facing documentation for product purpose, components, architecture, Terraform deployment, manual deployment order, local testing, operations, best practices, and troubleshooting.
- Move E2E acceptance architecture, historical run evidence, workflow internals, and verification guidance to `docs/developer/`.
- Replace mixed navigation with clear user and developer documentation sections and provide a maintainer deployment guide with the reviewed Terraform phase order, explicit prerequisites, and rollback boundaries.
- Add documentation checks that enforce the intended information architecture and link integrity.

## Capabilities

### New Capabilities
- `documentation-information-architecture`: Defines the public documentation hierarchy, content boundaries, navigation, and verification for user-facing and developer-focused material.

### Modified Capabilities
- `docsify-onboarding`: Revises the Docsify landing and navigation requirements to separate user documentation from developer E2E documentation.

## Impact

- Affects `README.md`, `docs/`, the Docsify sidebar, Terraform/deployment documentation tests, and developer runbook locations.
- Does not change packet processing, Terraform behavior, AWS/Tailscale authority, or protected-run approval requirements.
