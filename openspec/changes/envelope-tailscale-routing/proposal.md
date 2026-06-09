## Why

Envelope currently validates GENEVE <-> TUN behavior in isolation, but production AWS GWLB deployments need that traffic to be forwarded through `tailscaled` on the same host to reach the Tailnet. We need an explicit co-existence and host-routing design now so Envelope can be used as a practical site-to-site VPN building block rather than a standalone datapath demo.

## What Changes

- Add support for running Envelope alongside `tailscaled` on the same Linux appliance, with clear ownership boundaries (`envelope0` for Envelope, `tailscale0` for Tailscale).
- Add explicit host routing and policy-routing behavior to forward decapsulated traffic from `envelope0` toward `tailscale0`, and return traffic from `tailscale0` back to `envelope0` for re-encapsulation.
- Add configuration and startup validation for routing integration (interface names, routing table/rule parameters, and optional managed route programming mode).
- Add health/metrics coverage for routing readiness and forwarding failures so operators can diagnose broken forwarding quickly.
- Update deployment docs and Terraform examples to run Envelope and `tailscaled` together for GWLB-backed site-to-site connectivity.

## Capabilities

### New Capabilities
- `tailscale-host-routing`: Run Envelope and `tailscaled` concurrently on the same host and provide deterministic host routing between `envelope0` and `tailscale0` suitable for GWLB site-to-site VPN traffic.

### Modified Capabilities
- `geneve-tun-datapath`: clarify the datapath contract so Envelope terminates/originates GENEVE while host routing (not shared TUN ownership) handles forwarding to/from Tailscale.

## Impact

- Affected code: `internal/config`, `internal/app`, `internal/datapath`, Linux networking helpers, and startup/readiness checks.
- Affected tests: unit tests for config/routing validation, integration tests for route programming and forwarding behavior, and e2e harness updates.
- Affected docs/examples: `README.md`, `example/terraform/*`, and operational runbooks for GWLB + Tailscale deployment.
- Runtime/ops impact: requires Linux forwarding and policy-routing setup; performance target is practical throughput within Tailscale-supported ranges (up to ~10 Gb/s depending on instance/networking).
