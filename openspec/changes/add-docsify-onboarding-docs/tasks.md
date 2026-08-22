## 1. Docsify Foundation

- [x] 1.1 Add a static Docsify `docs/index.html` entrypoint with a bounded CDN dependency and repository-local Markdown home page.
- [x] 1.2 Add `docs/_sidebar.md` navigation that resolves every newcomer page and the existing AWS runbooks.
- [x] 1.3 Link the repository README to the Docsify entrypoint without replacing its detailed technical reference.

## 2. Newcomer Guidance

- [x] 2.1 Write the landing page explaining the AWS GWLB, GENEVE, `envelope0`, host-routing, and `tailscale0` packet path.
- [x] 2.2 Add setup guidance covering local build, component smoke checks, Linux capability boundaries, and the distinction between local and protected live validation.
- [x] 2.3 State the experimental, Linux-only, L3-only, directional initiator/responder topology limits and link to authoritative detailed documentation.

## 3. Terraform Example

- [x] 3.1 Add a redacted, non-executable Terraform acceptance configuration example with directional CIDRs, regional inputs, artifact manifest, Tailnet environment-variable references, and approval fields.
- [x] 3.2 Explain required replacements and direct AWS operators to the protected lifecycle/runbook instead of raw Terraform apply.

## 4. Documentation Validation

- [x] 4.1 Add a static documentation test that validates the Docsify entrypoint, sidebar targets, required safety language, and absence of credentials in the Terraform example.
- [x] 4.2 Run the documentation test, repository secret scan, and strict OpenSpec validation.
