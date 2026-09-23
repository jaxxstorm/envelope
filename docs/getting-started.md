# Build and Try Envelope

## Build

Envelope is a Go and Linux project. Build a local development binary:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

Build the reviewed static Linux artifact when you need to validate the release build path:

```bash
./scripts/build_artifacts.sh --output-dir dist --architectures amd64
```

Artifacts do not authorize a live deployment.

## Automated Local Validation

Run unit, fixture, and documentation checks:

```bash
go test ./...
python3 scripts/verify_geneve_fixtures.py
python3 scripts/test_docs.py
```

These checks do not contact AWS, create a GWLBE, connect to a Tailnet, model two sites, or test failover.

On Linux, run the local packet wire smoke:

```bash
sudo ./scripts/component_wire_smoke.sh
```

The wrapper builds the target, sends synthetic AWS-profile TCP, UDP, ICMP, and fragmented-inner GENEVE packets, verifies exactly one byte-identical packet turnaround for each, rejects malformed metadata, and confirms that forwarding, routes, and interfaces were not changed. It requires root with effective `CAP_NET_RAW`, does not need `CAP_NET_ADMIN`, and is not an AWS, Tailnet, multi-AZ, transport-router, or failover test.

## Run the Target Component

For a direct local development run:

```bash
sudo ./bin/envelope \
  --config-version=2 \
  --udp-bind=0.0.0.0:6081 \
  --max-inner-packet-size=1280 \
  --metrics-addr=127.0.0.1:9090
```

The target validates each accepted AWS-profile packet and returns it to the sending GWLB identity. It does not create a TUN, run Tailscale, enable Linux forwarding, or configure a site route. Use [Operations](operations.md) and [Troubleshooting](troubleshooting.md) for the component and host boundaries.

## Optional Local Integration

On an Ubuntu Linux host with Docker, run the separated-role Headscale harness:

```bash
./scripts/integration_headscale_two_peer.sh
```

It exercises local TCP, UDP, ICMP, packet correlation, and rendered router host-network configuration. It does not prove credentialed stable-node ownership, stable-node-to-protected-instance binding, GWLBE owner-ENI coupling, AWS route replacement, or durable CAS/lease recovery. It cannot prove the protected ownership or recovery contract.

## Next Steps

Read [Architecture](architecture.md) and [Components](components.md) before operating a topology. For controller behavior, read [Production Controller](production-controller.md) and the [Application Resilience](application-resilience.md) contract. Live AWS or Tailscale work is protected-only; see [Developer E2E Documentation](developer/README.md).
