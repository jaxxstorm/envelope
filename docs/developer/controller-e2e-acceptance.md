# Controller E2E Acceptance

## Status

Controller runtime, router attestation, deployment lifecycle, and split acceptance orchestration are implemented and tested offline. Task 9.5, a billable clean AWS/Tailscale deployment with router and leader failures, failback, new-flow retry, retained evidence, and zero-residual cleanup, remains unapproved and unexecuted.

Cross-compiling native Linux checks on Darwin is not native Linux evidence. Mocked phase orchestration, disagreement, stale-fence, ambiguous-response, and interruption coverage are integration-only evidence. None of these results authorizes a live run.

## Split Acceptance Roles

The protected workflow separates deployment, observation, quiescence, and cleanup identities and runner groups. Deployment creates versioned ownership-checked handoff references and freezes deployment/lifecycle authority before observation begins. Observation verifies the handoff and may observe faults, but has no deployment secret or state access.

Quiescence waits through the observer issuance cutoff and session lifetime, restores stopped routers, stops controllers, and proves journal drain before cleanup credentials are used. Cleanup requires two consecutive zero-residual audits. Interrupted or uncertain cleanup retains claims and forensic state; later work must use independently reviewed recovery and never automatically adopts a lock.

## Required Live Evidence

A live acceptance bundle must bind the reviewed topology, artifact identities, protected router and controller identities, fresh observer quorum, native router attestation, exact route authority, ownership/fence progression, route convergence, router and leader failure/recovery, failback, fresh TCP/UDP retry, retained redacted evidence, and ownership-safe cleanup.

The workflow must separately classify simulated receipts from live evidence. It must not use a runner, router, or packet target to mutate production routes outside the controller's approved authority.

## Preconditions

Before requesting a live run, obtain separate approval for the billable scope, review effective account IAM and OIDC trust, use isolated short-lived credentials and runner environments, verify native Linux support, review cost and expiry, and confirm retained-lock recovery ownership. Do not enable old workflows by weakening unavailable-capability gates or reuse configuration, state, plans, claims, or evidence.

For external IAM setup and manual retained-lock recovery, see [Controller Acceptance Infrastructure](../../deploy/terraform/controller-acceptance/README.md). User-facing controller operations are in [Production Controller](../production-controller.md).
