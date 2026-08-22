# Build and Try Envelope

## Build

Envelope is a Go and Linux project. Build a local development binary:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

For the reviewed static Linux artifact used by future protected acceptance work:

```bash
./scripts/build_artifacts.sh --output-dir dist --architectures amd64
```

The artifact is not permission to deploy a live topology manually.

## Local Validation

Run unit and static documentation checks:

```bash
go test ./...
python3 scripts/test_docs.py
```

The component wire smoke test creates a local fake-TUN setup and injects a synthetic GWLB-shaped packet:

```bash
sudo ./scripts/component_wire_smoke.sh
```

This does not contact AWS, create a GWLB endpoint, connect to a Tailnet, model two sites, or test failover.

## Host Integration

Symmetric targets need `CAP_NET_ADMIN` for `envelope0` and supported host-route validation or management. They do not need raw-socket privileges for normal forwarding.

`routing-mode=off` is datapath-only. `verify` validates host prerequisites without changing them. `manage` validates the configured symmetric path and reconciles only its documented routing ownership. For either enabled mode, provide version 2 with disjoint `local-site-cidrs` and `remote-site-cidrs`; a target must deliver the first to its local post-inspection VPC path and the second to `tailscale0`.

Do not configure a target as a Tailscale ingress router. Ingress routers are a separate fleet that advertises the exact local-site CIDRs without SNAT and routes Tailnet-arriving local traffic through its local GWLBE.

## Protected AWS Runs

The AWS profile is billable and requires a protected environment. The version-2 protected lifecycle, target drain operations, ingress-router failure exercises, and evidence verifier are not yet documented as executable operations. Do not adapt old configuration files or run old commands for the new topology.

Use the [AWS appliance runbook](aws-appliance-runbook.md) and [two-region E2E runbook](aws-two-region-e2e-runbook.md) to understand the required safety boundary, topology, cost review, and bounded-failover claims.
