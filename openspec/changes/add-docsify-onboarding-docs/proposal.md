## Why

Envelope's README is a detailed technical reference, but a new operator has no guided explanation of the problem it solves, the supported deployment boundary, or a safe path from build to AWS GWLB deployment. Documentation needs a browsable entry point before the live acceptance workflow can be used by someone unfamiliar with the project.

## What Changes

- Add a Docsify site rooted in `docs/` with a concise newcomer-oriented landing page and navigation.
- Explain Envelope's role between AWS Gateway Load Balancer, GENEVE, a Linux TUN device, and Tailscale, including supported directional-lane behavior and explicit non-goals.
- Document local build and component-smoke commands separately from the protected, billable AWS workflow.
- Add a reviewed example Terraform configuration that illustrates the required directional CIDR, region, Tailnet, and artifact inputs without including credentials or a runnable operator configuration.

## Capabilities

### New Capabilities
- `docsify-onboarding`: A browsable, safe onboarding guide that explains Envelope, its deployment model, local verification, and Terraform configuration to new users.

### Modified Capabilities
- None.

## Impact

- Adds Docsify entrypoint and Markdown navigation/content under `docs/`.
- Links to the existing README and AWS appliance/two-region runbooks without changing Envelope's datapath, Terraform resources, APIs, or live-acceptance policy.
- Uses Docsify from a CDN in static HTML; no repository build system or generated documentation artifact is introduced.
