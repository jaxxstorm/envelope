## 1. Configuration and validation

- [x] 1.1 Add routing config fields/flags/env for `tailscale_iface`, `routing_mode` (`manage|verify|off`), `protected_cidrs`, `routing_table_id`, and `routing_rule_priority`.
- [x] 1.2 Validate routing configuration combinations (for example, require `protected_cidrs` when `routing_mode=manage`) and reject malformed CIDRs with clear errors.
- [x] 1.3 Add/update config unit tests covering defaults, valid combinations, and invalid combinations.

## 2. Linux routing integration primitives

- [x] 2.1 Implement Linux helpers for interface existence checks, forwarding sysctl checks, policy-rule management, and route management using `x/sys/unix` + standard netlink-compatible shelling strategy already used in project style.
- [x] 2.2 Implement idempotent apply/reconcile logic so duplicate rules/routes are not created and missing state can be repaired.
- [x] 2.3 Add unit tests for route/rule diffing and reconciliation behavior, including failure paths.

## 3. Application wiring and lifecycle

- [x] 3.1 Wire a routing manager into app startup so `routing_mode=manage` applies desired state before reporting ready.
- [x] 3.2 Implement `routing_mode=verify` to check prerequisites without mutating host state.
- [x] 3.3 Implement `routing_mode=off` compatibility behavior that skips routing checks and preserves existing datapath-only behavior.

## 4. Health and metrics

- [x] 4.1 Extend health readiness to include routing prerequisites in `manage`/`verify` modes and return HTTP 503 when routing is not ready.
- [x] 4.2 Add routing metrics counters for apply attempts, apply failures, and drift repairs.
- [x] 4.3 Add health/metrics tests to verify routing-aware readiness and metric emission across routing modes.

## 5. Datapath contract alignment

- [x] 5.1 Update datapath/runtime contracts and logs to explicitly document/enforce separate Envelope/Tailscale interface ownership (no shared TUN assumptions).
- [x] 5.2 Add tests for co-resident behavior assumptions (Envelope keeps using configured TUN while routing integration targets Tailscale interface).

## 6. End-to-end and performance validation

- [x] 6.1 Extend integration/e2e harness to validate bidirectional forwarding for protected CIDRs with Envelope + `tailscaled` running together.
- [x] 6.2 Add failure-case integration checks (missing route/rule/sysctl) to confirm startup/readiness behavior in `manage` and `verify` modes.
- [x] 6.3 Add a repeatable benchmark/profile task to confirm no material regression in datapath behavior and that expected throughput targets remain within practical Tailscale limits.

## 7. Documentation and deployment assets

- [x] 7.1 Update `README.md` with deployment guidance for co-running Envelope and `tailscaled`, required sysctls, routing modes, and troubleshooting.
- [x] 7.2 Update Terraform example files to provision the co-resident model and configure routing inputs for protected CIDRs.
- [x] 7.3 Add operational notes for rollback (`routing_mode=off` and cleanup of managed rules/routes).
