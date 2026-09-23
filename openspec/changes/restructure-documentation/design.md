## Context

The root README and Docsify landing page currently contain detailed legacy acceptance history, protected-run timing, and E2E evidence alongside basic architecture and local-use guidance. The sidebar exposes protected runbooks as peer links to user onboarding. This makes routine adoption and troubleshooting difficult to follow and obscures the separation between safe documentation and protected, billable operations.

## Goals / Non-Goals

**Goals:**

- Give first-time readers a concise root README that explains Envelope and links to Docsify documentation.
- Organize `docs/` around the supported components, packet path, operating model, local automation, manual diagnostics, troubleshooting, and best practices.
- Place acceptance internals, historical E2E evidence, protected workflow behavior, and developer verification material below `docs/developer/`.
- Preserve architecture accuracy while giving maintainers an executable Terraform deployment path and a clear manual deployment order.
- Keep Docsify navigation and repository documentation checks valid after the move.

**Non-Goals:**

- Change packet, routing, Terraform, controller, IAM, or Tailscale behavior.
- Publish credentials or account-specific configuration, or claim that the checked-in example replaces reviewed production inputs.
- Rewrite or reinterpret historical acceptance evidence.
- Replace the existing Docsify static-site implementation.

## Decisions

### Keep the root README as an orientation page

The root README will state the project purpose, experimental status, core supported boundary, and a direct link to `docs/`. It will not duplicate an operations manual or historical verification narrative. This keeps the repository entrypoint useful to readers outside the documentation site.

### Separate documentation by audience and purpose

User-facing pages remain directly under `docs/`. They will cover component responsibilities, topology and control-plane relationships, operation, safe automated and manual checks, diagnostics, troubleshooting, and application best practices. Developer-only E2E workflows, historical run records, evidence schemas, and protected lifecycle internals move to `docs/developer/`.

Keeping developer material in the same Docsify site preserves discoverability without presenting it as normal operator guidance. A dedicated sidebar section and explicit links establish the boundary. A separate documentation site was rejected because it adds hosting and navigation complexity without a user need.

### Preserve safety language at every execution boundary

User guidance will provide the reviewed Terraform phase order and command form for maintainer-owned deployments, plus a manual deployment order for teams integrating the components themselves. It will require reviewed inputs, short-lived credentials, cost approval, explicit expiry, and cleanup authority. It will not contain credentials, account-specific values, or present the illustrative topology fragment as deployable.

### Move rather than duplicate E2E content

Historical run evidence and detailed acceptance mechanics will be relocated rather than summarized repeatedly in user pages. User pages will retain short status statements and link to developer material for the source evidence. This reduces drift between operational and verification narratives.

### Test information architecture as documentation behavior

The existing documentation test suite will assert the root README link, user/developer sidebar sections, required user pages, developer E2E locations, and relative-link resolution. Content tests will avoid brittle assertions over prose or run identifiers.

## Risks / Trade-offs

- [Moved links can break external bookmarks] → Keep redirects impractical in static Markdown, so retain concise pointer pages where needed and validate all repository-relative links.
- [User pages can present an incomplete Terraform root as a turnkey deployment] → Name every required root, prerequisites, state boundary, activation gate, and rollback order.
- [Historical evidence can lose context] → Move complete runbooks and preserve their revision/evidence details under `docs/developer/`.
- [The user/developer boundary can duplicate architecture] → Make user pages authoritative for supported operations and link developer pages for verification internals.

## Migration Plan

1. Create the user-facing documentation hierarchy and developer directory.
2. Rewrite the root README and Docsify landing/sidebar to link into the new hierarchy.
3. Relocate E2E runbooks and historical acceptance detail, updating internal links.
4. Add or update documentation checks, then run the documentation suite and link validation.
5. Roll back by restoring the prior file locations and sidebar if validation detects broken navigation; no runtime migration is involved.

## Open Questions

- None. The existing protected-run safety controls remain authoritative.
