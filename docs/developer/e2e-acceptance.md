# E2E Acceptance

## Verification Levels

Envelope maintains distinct verification boundaries:

| Level | What it verifies | What it does not verify |
| --- | --- | --- |
| Unit, fixture, static, and mocked Terraform checks | Parsing, contracts, reproducible artifacts, and configured shapes | Linux kernel behavior, AWS, Tailnet, or live recovery |
| Native Linux integration | Privileged host behavior, systemd rendering, and local packet or routing checks | AWS identity, GWLBE convergence, durable protected cleanup, or live Tailnet evidence |
| Protected E2E acceptance | Approved AWS/Tailscale deployment, controlled failures, recovery, evidence retention, and zero-residual cleanup | A permanent production SLO or authorization for later runs |

## Protected Boundary

Only an approved protected environment may create billable resources or exercise live failures. Every run uses a fresh, reviewed configuration and run identity; scoped short-lived credentials; a current cost review; explicit expiry; isolated deployment, observation, and cleanup authority; retained redacted evidence; and ownership-safe restoration and cleanup.

Do not use a raw Terraform apply to execute the protected failure workflow, reuse plans or state, publish credentials, or bypass lifecycle locks. Use the [Deployment Guide](../deployment.md) for a normal maintainer installation. The detailed constraints, failure history, and evidence schema remain in the [AWS Appliance Runbook](aws-appliance-runbook.md) and [AWS Two-Region E2E Runbook](aws-two-region-e2e-runbook.md).

## Evidence Classification

Mocked disagreement, stale-fence, ambiguous-response, and phase-interruption scenarios are integration evidence only. Native Linux checks are host evidence only. A live claim requires a protected run's retained evidence bundle and an ownership-safe zero-residual audit. Neither offline nor historical evidence authorizes a new live operation.
