# Operations

## Local Component Operation

Build a development target on Linux:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

For a local development run, root or an equivalent effective `CAP_NET_RAW` capability is required:

```bash
sudo ./bin/envelope \
  --config-version=2 \
  --udp-bind=0.0.0.0:6081 \
  --max-inner-packet-size=1280 \
  --metrics-addr=127.0.0.1:9090
```

Inspect `GET /healthz` and `GET /metrics` to diagnose the packet target. This starts only the packet component. It does not create an AWS topology, connect to a Tailnet, or validate route failover.

## Safe Automation

Run local checks from a reviewed checkout:

```bash
go test ./...
python3 scripts/verify_geneve_fixtures.py
python3 scripts/test_docs.py
python3 scripts/secret_scan.py --root .
```

On an Ubuntu Linux host, `sudo ./scripts/component_wire_smoke.sh` verifies synthetic packet turnaround and confirms it did not alter forwarding, routes, or interfaces. The optional Headscale harness exercises a secretless local integration boundary. Neither check is AWS, Tailnet, multi-AZ, or protected acceptance evidence.

## Manual Operation And Diagnosis

Manual work is limited to read-only diagnosis and local component control. Confirm the target's health and metrics; inspect the transport-router service, policy routes, firewall counters, and Tailscale status; and inspect controller `/healthz`, `/readyz`, and `/metrics` before escalating. Do not manually replace GWLBE routes, alter advertisements, or treat a local marker as cloud readiness.

See [Troubleshooting](troubleshooting.md) for symptom-oriented guidance.

## Deployment Operations

Use the [Deployment Guide](deployment.md) for the appliance, router-attestor, and controller Terraform phases. A live operation needs reviewed configuration and scope, short-lived credentials, a current cost review, explicit expiry, and authority to restore and clean up owned resources. The developer [E2E Acceptance](developer/e2e-acceptance.md) material explains how the deployment is verified under failure; it is not the normal installation guide.
