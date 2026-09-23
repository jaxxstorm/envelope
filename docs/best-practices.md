# Best Practices

## Design for New-Flow Recovery

Treat Envelope as a bounded new-flow recovery path. Do not assume a five-tuple survives target, router, route, or ownership change. Use connection retry and idempotent request handling for TCP; use message IDs, acknowledgements, deduplication, and bounded retransmission for UDP. See [Application Resilience](application-resilience.md) for executable reference patterns.

## Keep Responsibilities Separate

Keep packet targets packet-scoped and transport routers responsible for no-NAT forwarding. Controllers alone reconcile approved GWLBE routes after fresh observations, durable fencing, eligibility checks, and exact route readback. Do not add AWS route authority to targets or transport routers.

## Validate at the Right Boundary

Use unit, fixture, static, and local integration tests for their stated component boundaries. Run native Linux checks on a capable Linux host. Treat AWS/Tailscale recovery proof as protected evidence only, never as an implication of local results.

## Protect Live Operations

Before requesting live work, review the exact topology and scope, credential isolation, current cost estimate, expiry, restoration plan, retained evidence, and zero-residual cleanup authority. Do not use direct Terraform apply, reused state, old evidence, or broad cleanup. The [developer E2E workflow](developer/e2e-acceptance.md) defines the protected boundary.
