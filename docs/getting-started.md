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

Run unit, fixture, and static documentation checks:

```bash
go test ./...
python3 scripts/verify_geneve_fixtures.py
python3 scripts/test_docs.py
```

These checks do not contact AWS, create a GWLBE, connect to a Tailnet, model two sites, or test failover.

On Linux, run the local component wire smoke exactly as follows:

```bash
sudo ./scripts/component_wire_smoke.sh
```

The wrapper builds the target, sends synthetic AWS-profile TCP, UDP, ICMP, and fragmented-inner GENEVE packets, verifies exactly one byte-identical packet turnaround for each, rejects malformed metadata, and confirms that forwarding, routes, and interfaces were not changed. The wrapper requires root with effective `CAP_NET_RAW` and does not support a non-root file-capability invocation; run it with the exact `sudo` command above. It does not need `CAP_NET_ADMIN`. This is a local component check, not AWS, Tailnet, multi-AZ, transport-router, or failover acceptance.

## Run The Target Component

On Linux, start the version-2 packet-turnaround target as root for a direct development run:

```bash
sudo ./bin/envelope \
  --config-version=2 \
  --udp-bind=0.0.0.0:6081 \
  --max-inner-packet-size=1280 \
  --metrics-addr=127.0.0.1:9090
```

This component validates each accepted AWS-profile packet and immediately returns it to the sending GWLB identity. It does not create a TUN, run Tailscale, enable Linux forwarding, or configure a local-versus-remote route path. Local startup alone is not a useful end-to-end traffic test.

## Target And Transport Roles

The target parser retains version `2` and rejects obsolete target forwarding inputs, including directional fields, target site CIDRs, TUN settings, Tailscale settings, and routing modes. There is no compatibility mode or alternate version-2 behavior.

Dedicated Tailscale transport routers own inner site transit. At baseline, each ready router advertises exactly one assigned workload prefix; the per-site assignments are non-empty, pairwise disjoint, and exactly cover local workload CIDRs. Every router remains forwarding-capable for bounded takeover of all local prefixes, accepts every exact remote-site route, disables subnet-route SNAT and Tailnet DNS acceptance, preserves the VPC resolver and source addresses, and forwards both interface directions. Every transport route table maps each local CIDR to that destination workload prefix's AZ GWLBE, independent of the receiving router AZ. Transport-router forwarding, reverse-path, firewall, MSS, source/destination-check, route, and ENI readiness are separate from target health.

On every router, Tailscale table 52 contains exactly the opposite site's exact workload prefixes and no local-site prefix. Every opposite-site observer selects each protected remote prefix's configured stable-node `PrimaryRoutes` owner, while no same-site observer reports a protected local `PrimaryRoutes` claim. Every local prefix, whether self- or sibling-owned in the singleton advertisement map, remains on `main` and the VPC underlay. The higher-priority `iif tailscale0` local-prefix rules make every router capable of delivering all local prefixes during normal and takeover paths. Mandatory source-prefix owner/ENI coupling is derived from singleton advertisements, control-plane stable identities, and opposite-site observations and binds the selected owner to its protected instance ID and primary ENI.

Failed protected run `ha25` proved this route shape by showing exactly the two opposite-site workload routes and only opposite-site serving paths on every router. It did not pass acceptance and does not turn these development instructions into a protected-run procedure.

Failed protected run `ha46` then proved that the local endpoint route must remain destination-prefix anchored during cross-AZ router takeover. It cleaned up with zero residuals but did not pass acceptance.

Failed protected run `ha47` proved that corrected route and completed both cross-AZ TCP and UDP recovery paths, but the second full proof exceeded the shared mutation deadline by about eight seconds. Ownership transfer and GWLBE route convergence now use `mutation_timeout_seconds`; the sequential TCP and UDP proofs jointly use a fresh `recovery_timeout_seconds` deadline after convergence. Restoration and cleanup again reached zero residuals, but the run did not pass acceptance.

Failed protected run `ha48` proved the separated deadline and graceful cross-AZ recovery, then strict stream analysis rejected one isolated TCP marker loss more than 13 minutes after restoration in the unused observation tail. The full durable transaction reservation remains the continuity-command watchdog with a conservative 600-second paired-control allowance, but instance and transport-router TCP/UDP streams now run concurrently around one shared mutation and use runner-controlled completion after at least 20 successful sends and a final post-mutation marker. The runner validates successful-send completion timestamps internally and emits exact sent, acknowledged, and lost counts. Target-process streams are unchanged. Cleanup again reached zero residuals, but the run did not pass acceptance.

Failed protected run `ha49` proved controlled completion and both abrupt alternate-path probes, then the restarted original router reported three Tailscale health conditions while its DNS forwarder had no upstream resolver. Transport bootstrap and restoration now keep `accept-dns=false`; readiness verifies `CorpDNS` false and still requires an empty health set. Cleanup reconciled advertisements, ownership, and original ENI routes before one-attempt zero-residual teardown, but the run did not pass acceptance.

The installed target systemd service runs as an unprivileged user with ambient `CAP_NET_RAW`; it does not need `CAP_NET_ADMIN`. The transport-router host-network unit, `envelope-transport-router-network.service`, runs as root with `CAP_NET_ADMIN` and `CAP_NET_RAW`, but configures only forwarding sysctls, its exact fail-closed firewall chains, and MSS clamping. Terraform publishes the expected host contract as the separate `transport_router_readiness_expectations` output; that output is not a live readiness result. Protected readiness separately observes disabled Tailnet DNS acceptance, empty Tailscale health, peer expiry and bounded pings, exact policy and prefix route chains, EC2 source/destination checks, ENI identity, and the complete destination-prefix GWLBE map.

## Secretless Linux Integration

On an Ubuntu Linux host with Docker, run the required local separated-role harness:

```bash
./scripts/integration_headscale_two_peer.sh
```

The harness uses digest-pinned Headscale `0.25.1` and Tailscale `1.80.3` images and runtime-generated preauthorization keys. It starts both directions of TCP, UDP, and ICMP under one six-flow barrier, correlates source and destination target turnaround IDs and hashes from packet events, derives the destination transport-router identity from the observed underlay source MAC, and sends non-initial IPv4 fragments from each source workload through both targets and the transport routers to the peer workload.

For host networking, the harness extracts, renders, executes, and hash-checks the production `envelope-transport-router-network.service` `ExecStart` script. It does not reproduce systemd PID 1 ordering or sandbox enforcement, the cloud-init package installation environment, credentialed stable-node ownership, stable-node-to-protected-instance binding, GWLBE owner-ENI coupling, AWS route replacement, or durable CAS/lease recovery after interruption. It therefore cannot prove the protected ownership or recovery contract. `python3 scripts/verify_systemd_units.py` covers rendered unit syntax in a disposable Ubuntu image; protected acceptance owns the remaining live checks.

## Protected AWS Runs

The AWS profile is billable and requires a protected environment. Protected run `ha53` is the first documented passing corrected version-2 result; it does not make these local instructions a live-run procedure. Do not adapt old configuration files, state, evidence, or commands for the topology.

The checked-in acceptance planning values are a `$4.00/hour` fixed estimate and a `$5.00/hour` fixed ceiling for the two-site, two-AZ HA profile. They exclude variable charges and are not current-price or spending approval. The profile has one shared NAT in each site's single management subnet, so private management and bootstrap egress is not multi-AZ even though the inspected transit topology spans two AZs. Use the [AWS appliance runbook](aws-appliance-runbook.md) and [two-region E2E runbook](aws-two-region-e2e-runbook.md) to understand the required route graph, protected-runner ENI failover and restoration, current cost review, and non-hitless availability boundary.
