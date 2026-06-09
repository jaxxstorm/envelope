## Context

Envelope currently owns `envelope0` and performs GENEVE decapsulation/encapsulation, but it does not define how decapsulated packets are forwarded through `tailscaled` (`tailscale0`) for real deployments. GWLB site-to-site VPN use requires both processes on one Linux host with deterministic forwarding in both directions, while keeping the datapath simple and preserving flow symmetry back to GWLB.

The design must avoid shared TUN assumptions, keep packet handling in the kernel where possible, and remain operationally clear for AWS + Tailscale operators.

## Goals / Non-Goals

**Goals:**
- Run Envelope and `tailscaled` concurrently on the same host with explicit interface ownership (`envelope0` and `tailscale0`).
- Provide deterministic forwarding between the two interfaces for bidirectional site-to-site traffic.
- Define managed routing behavior in Envelope (route/rule programming + validation) with safe idempotency.
- Expose readiness and metrics for routing state, not only UDP/TUN state.
- Keep throughput practical for Tailscale-scale targets (up to ~10 Gb/s depending on host/network).

**Non-Goals:**
- Embedding or supervising `tailscaled` from Envelope.
- NAT/conntrack-heavy dataplane logic in Envelope.
- L2 bridging or Ethernet payload support.
- Advanced traffic engineering beyond required policy routing for GWLB/Tailscale interop.

## Decisions

### 1. Separate process and interface ownership
Envelope SHALL continue owning `envelope0`; `tailscaled` SHALL continue owning `tailscale0`. Envelope will not attempt to share or hijack Tailscale's TUN.

- Why: Linux TUN ownership/read semantics make shared consumption fragile, and separation keeps failure domains clear.
- Alternative considered: shared TUN (`tailscaled --tun=envelope0`). Rejected due to ownership contention and ambiguous packet-read behavior.

### 2. Managed policy-routing mode with explicit protected CIDRs
Envelope SHALL support a routing integration mode that programs Linux policy rules and routes for configured protected CIDRs.

Proposed behavior:
- Enable/verify `net.ipv4.ip_forward` (and IPv6 forwarding when configured).
- Add policy rule(s) for traffic entering `tailscale0` destined to protected CIDRs to use a dedicated routing table.
- Populate that table with protected CIDRs via `envelope0`.
- Validate route/rule presence at startup and periodically for health/readiness.

- Why: deterministic return path from Tailnet traffic back to Envelope is required for GWLB symmetry.
- Alternative considered: manual-only routing setup. Rejected as default because drift and operator mistakes are common; retained as optional mode for advanced users.

### 3. Config-driven routing integration contract
Add config for routing behavior and interfaces, with defaults:
- Envelope TUN interface: existing `--tun-name` (default `envelope0`)
- Tailscale interface: new `--tailscale-iface` (default `tailscale0`)
- Routing mode: new `--routing-mode` (`manage|verify|off`, default `manage`)
- Protected CIDRs: new repeatable flag/env (required for `manage`, optional for `verify`)
- Routing table ID and rule priority: configurable with safe defaults

- Why: makes behavior explicit, testable, and reproducible across EC2/AMI setups.
- Alternative considered: hard-coded interface names/table IDs. Rejected for portability and multi-environment deployment needs.

### 4. Health and observability include routing state
`/healthz` readiness SHALL include routing integration checks when routing mode is `manage` or `verify`.

Add metrics/counters for:
- route/rule apply attempts and failures
- routing reconcile drift repairs
- forwarding validation failures (interface missing, sysctl mismatch)

- Why: datapath can be up while forwarding is broken; operators need immediate signal.
- Alternative considered: keep health tied only to UDP/TUN open state. Rejected as insufficient for production routing scenarios.

### 5. Keep packet forwarding in kernel fast path
Do not add packet relay loops between Envelope and Tailscale in userspace. Envelope remains responsible only for GENEVE termination/reorigination; host kernel routing forwards between interfaces.

- Why: avoids extra copies/context switches and aligns with performance target.
- Alternative considered: userspace forwarding bridge. Rejected due to avoidable overhead and complexity.

## Risks / Trade-offs

- [Routing misconfiguration blackholes traffic] -> Mitigation: fail-fast startup validation, routing-mode `verify`, and explicit health failures when rules/routes are missing.
- [Conflicts with existing host routing policy] -> Mitigation: configurable table/rule priority and `off` mode for environments with pre-managed networking.
- [Kernel/sysctl differences across AMIs] -> Mitigation: startup checks with actionable logs and documentation for required sysctls/rp_filter settings.
- [Performance variance by instance type and NIC settings] -> Mitigation: document expected ceiling, keep hot path minimal, and provide counters for drop/error diagnosis.

## Migration Plan

1. Introduce config and routing manager with `routing-mode=off` compatibility path to avoid breaking existing setups.
2. Add `verify` mode and tests so operators can validate host networking before enabling management.
3. Enable `manage` mode in Terraform/examples and document required sysctls/capabilities.
4. Update e2e/integration tests to exercise Envelope + `tailscaled` co-running path with protected CIDR routing.
5. Rollback strategy: set `routing-mode=off`, remove managed rules/routes, and keep existing Envelope datapath behavior unchanged.

## Open Questions

- Should managed mode reconcile continuously (controller loop) or only at startup + health checks?
- Do we need IPv6 protected-CIDR routing in this first iteration, or IPv4-first with clear non-goal language?
- Should we expose route/rule state in a debug endpoint in addition to metrics/logs?
