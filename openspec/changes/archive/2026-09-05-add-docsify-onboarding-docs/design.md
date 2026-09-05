## Context

The repository has a detailed root README and two operational AWS runbooks, but no documentation site or newcomer path. The existing material is accurate but starts with implementation and operational detail, making it difficult to determine whether Envelope fits a prospective AWS GWLB and Tailscale deployment before encountering privileged commands or billable workflow instructions.

The documentation must remain static, reviewable in Git, and safe to publish. It must not turn the experimental symmetric HA acceptance profile into a general-purpose or production deployment claim.

## Goals / Non-Goals

**Goals:**
- Provide a Docsify entrypoint in `docs/` that can be opened through a static-file host without a documentation build step.
- Give a first-time reader a short mental model of GENEVE packet turnaround, GWLBE post-inspection routing, and dedicated Tailscale transport.
- Distinguish local component verification from privileged host integration and protected AWS acceptance.
- Provide an illustrative Terraform input example with placeholders and explicit credential/approval boundaries.
- Make existing detailed runbooks discoverable from the newcomer path.

**Non-Goals:**
- Change Envelope's datapath, AWS acceptance topology, Terraform module behavior, or routing contract.
- Publish a production-ready deployment guide, arbitrary topology, hitless HA guarantee, or automated Terraform apply instructions.
- Add a Node package, generated static-site artifact, analytics, credential form, or runtime configuration service.

## Decisions

### 1. Use static Docsify files under `docs/`

Add a minimal `index.html`, landing Markdown, and sidebar navigation under `docs/`. The HTML loads Docsify from a pinned major-version CDN URL and renders only repository Markdown, allowing GitHub Pages or any static host to serve it.

Alternative: introduce a generated documentation framework. Rejected because it adds package/toolchain maintenance to a Go project and produces generated artifacts for a small documentation surface.

### 2. Organize by newcomer questions

The top-level navigation will answer, in order: why Envelope exists and how packets move; how to build and run local checks; how the symmetric AWS/Tailscale topology is shaped; and where to find protected operator procedures. The landing page remains concise and links to dedicated setup and Terraform-example pages instead of duplicating the complete README or runbooks.

Alternative: expose existing runbooks as the landing page. Rejected because their operational detail is not a suitable first explanation and could lead a reader directly to billable commands.

### 3. Keep Terraform illustrative and non-executable

The Terraform page will show a redacted JSON fragment of the documented version-2 `symmetric_topology` input shape. It will use invalid documentation-only IDs and CIDRs, illustrate the route-failover and cost boundaries, deliberately omit account, artifact, backend, credential, and lifecycle configuration, and link to the protected runbook. It will not include secrets, a valid production config, or a raw `terraform apply` command.

Alternative: copy a working local run config. Rejected because it can be stale, contain account-specific identifiers, and encourage bypassing the protected lifecycle.

### 4. Preserve experimental and protected-run warnings

Every entrypoint will state that Envelope is experimental and that targets immediately return packets to GWLB without a target TUN, Tailscale path, or direct inner forwarding. The documented symmetric topology and non-hitless availability boundary remain explicit. Local commands will be labelled as component checks; AWS execution will require protected credentials, current approval, a fresh expiry, and the lifecycle runner.

Alternative: omit warnings to simplify the page. Rejected because it would overstate the current acceptance result and conflict with the existing README and runbooks.

## Risks / Trade-offs

- [CDN dependency is unavailable under a restrictive network policy] -> Keep all documentation content as plain Markdown and document that any static host can serve the files with an approved local Docsify mirror if needed.
- [Examples become stale as protected config evolves] -> Derive field names and safety constraints from the runbook, keep the example intentionally incomplete, and link to the authoritative runbook.
- [Newcomers mistake a component smoke test for live validation] -> Label validation levels and link to the protected two-region acceptance procedure.
- [Static HTML introduces unsafe external content] -> Load only Docsify assets, avoid user-supplied query evaluation, analytics, and embedded secrets.

## Migration Plan

1. Add the Docsify entrypoint, sidebar, and newcomer Markdown pages under `docs/`.
2. Add static checks that verify the entrypoint, navigation targets, required safety language, and Terraform-example placeholders.
3. Serve `docs/` through a static host or open it locally for review; no migration or runtime rollout is required.
4. Remove the files to roll back the documentation site without affecting the binary, Terraform state, or AWS resources.

## Open Questions

- Which static hosting location, if any, should publish `docs/` after the initial repository-only site is reviewed?
