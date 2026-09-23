## 1. Documentation Architecture

- [x] 1.1 Inventory current README and Docsify content, classify each page or section as user-facing or developer E2E material, and define the target page map under `docs/` and `docs/developer/`.
- [x] 1.2 Rewrite the root `README.md` as a concise project orientation with experimental status, component boundary, and a direct user-documentation link.
- [x] 1.3 Create or revise the Docsify landing page to introduce the supported architecture and route readers to user workflows without duplicating E2E history.
- [x] 1.4 Update `docs/_sidebar.md` with distinct user and developer sections and only resolvable repository-relative targets.

## 2. User Documentation

- [x] 2.1 Document Envelope components and the supported packet, transport-router, and controller architecture in user-facing pages.
- [x] 2.2 Document how to build, run, and validate supported components, distinguishing local automated checks from protected acceptance.
- [x] 2.3 Add manual diagnostic and troubleshooting guidance for packet targets, transport routers, and controller health without granting deployment or route-mutation instructions.
- [x] 2.4 Add application and operator best practices, including the established-flow and UDP recovery boundary.
- [x] 2.5 Document the live-operation boundary, reviewed Terraform deployment phases, required inputs, controller activation, cost review, and cleanup authority without embedding credentials or account-specific values.

## 3. Developer E2E Documentation

- [x] 3.1 Create `docs/developer/` and relocate protected E2E acceptance architecture, workflow, evidence, and historical run material from user-facing pages.
- [x] 3.2 Preserve all relevant protected-run safety, evidence-retention, recovery, and cleanup constraints while updating links to their developer locations.
- [x] 3.3 Add developer verification guidance that clearly separates mocked/static checks from native Linux and live AWS/Tailscale evidence.

## 4. Documentation Verification

- [x] 4.1 Update documentation tests for the root entrypoint, user/developer navigation sections, required page locations, and repository-relative link resolution.
- [x] 4.2 Run the documentation test suite and strict OpenSpec validation; fix broken navigation or unsafe/misclassified guidance found by the checks.

## 5. Maintainer Deployment Journey

- [x] 5.1 Rewrite user-facing landing, architecture, and component documentation in maintainer language that explains Envelope as a GWLB-to-Tailscale site-to-site connectivity solution.
- [x] 5.2 Add a Mermaid architecture diagram and deployment guide covering the appliance, router-attestor, and controller Terraform roots, required inputs, apply order, initialization/activation, and rollback order.
- [x] 5.3 Add a manual deployment order and local-testing path that distinguish what the repository automates from what an operator must provide.
- [x] 5.4 Update documentation tests and validate the revised maintainer deployment journey.
