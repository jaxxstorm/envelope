## Why

Envelope's README is a detailed technical reference, but a new operator has no guided explanation of the problem it solves, the supported deployment boundary, or a safe path from build to AWS GWLB deployment. Documentation needs a browsable entry point before the live acceptance workflow can be used by someone unfamiliar with the project.

## What Changes

- Add a Docsify site rooted in `docs/` with a concise newcomer-oriented landing page and navigation.
- Explain Envelope's role across AWS Gateway Load Balancer, packet-turnaround targets, GWLBE post-inspection routing, and dedicated Tailscale transport routers, including the supported symmetric path and explicit non-goals.
- Document local build and component-smoke commands separately from the protected, billable AWS workflow.
- Add a reviewed Terraform fragment that illustrates the version-2 symmetric topology, regional route domains, failover shape, and cost boundary without including credentials or a runnable operator configuration.

## Capabilities

### New Capabilities
- `docsify-onboarding`: A browsable, safe onboarding guide that explains Envelope, its deployment model, local verification, and Terraform configuration to new users.

### Modified Capabilities
- None.

## Impact

- Adds Docsify entrypoint and Markdown navigation/content under `docs/`.
- Links to the existing README and AWS appliance/two-region runbooks without changing Envelope's datapath, Terraform resources, APIs, or live-acceptance policy.
- Uses Docsify from a CDN in static HTML; no repository build system or generated documentation artifact is introduced.
