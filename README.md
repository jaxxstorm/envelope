# Envelope

> [!WARNING]
> **Experimental WIP: this does not currently work as a production service.**
>
> Envelope, its Terraform profile, and the protected acceptance workflow are under active development. Treat the repository as an engineering prototype, not a deployment guide.

Envelope is a Linux-only Layer 3 datapath for symmetric inline AWS Gateway Load Balancer (GWLB) inspection between two sites. A target validates AWS IPv4 GENEVE on UDP/6081, decapsulates the inner packet, and injects it into `envelope0`. Linux then forwards the packet either to the local post-inspection VPC path or to `tailscale0`.

The normal data path does not originate GENEVE packets, retain per-flow return state, or perform NAT. Every inter-site packet is delivered to a target as validated GENEVE ingress by the source site's GWLBE and GWLB.

## Documentation

Start with the [Docsify onboarding guide](docs/index.html) for the symmetric topology and migration boundary. The [AWS appliance runbook](docs/aws-appliance-runbook.md) and [two-region E2E runbook](docs/aws-two-region-e2e-runbook.md) define the protected lifecycle boundary and evidence requirements.

## Symmetric Topology

Each site has these independent planes:

- Workload route tables send the peer site's exact CIDRs to a local GWLBE.
- At least two AZs host a GWLBE and at least one Envelope target per enabled AZ.
- A separate fleet of at least two Tailscale ingress routers advertises the exact local-site CIDRs with subnet-route SNAT disabled.
- Target route tables deliver local-site CIDRs through the post-inspection VPC path and remote-site CIDRs through `tailscale0`; target routes never send either site CIDR to a GWLBE.

For a packet from site A to site B, the path is:

```text
site A workload -> site A GWLBE -> site A GWLB -> Envelope target
  -> envelope0 -> tailscale0 -> site B ingress router
  -> site B GWLBE -> site B GWLB -> Envelope target
  -> envelope0 -> site B post-inspection VPC path -> site B workload
```

The reverse direction follows the same shape. Either workload may initiate a new TCP, UDP, or ICMP flow from its ordinary site CIDR. Inter-site traffic preserves source addresses: no NAT is part of this path.

## Target Configuration

Version 2 is a breaking configuration contract. A target uses disjoint local and remote site CIDR lists:

- `--local-site-cidrs`: local CIDRs delivered through the post-inspection VPC path.
- `--remote-site-cidrs`: peer CIDRs forwarded through `tailscale0`.

Targets reject overlapping CIDRs and reject the prior directional configuration before inspecting or changing host state. Do not reuse an older configuration, Terraform state, plan, evidence file, or protected-run input with this topology.

An illustrative, incomplete Terraform shape is in [docs/terraform-example.md](docs/terraform-example.md). It is not a live deployment input.

## Local Run

Build the development binary:

```bash
go build -o ./bin/envelope ./cmd/envelope
```

Run only the datapath locally:

```bash
sudo ./bin/envelope \
  --udp-bind=0.0.0.0:6081 \
  --tun-name=envelope0 \
  --tun-mtu=1280 \
  --metrics-addr=0.0.0.0:9090 \
  --routing-mode=off
```

A host intended to validate symmetric forwarding needs an approved `--routing-mode=verify` or `--routing-mode=manage` configuration with its actual `--underlay-interface`, `--local-site-cidrs`, and `--remote-site-cidrs`. Do not derive host routes or service configuration from an earlier acceptance profile.

## Observability

- `GET :9090/healthz` reports datapath and enabled routing readiness.
- `GET :9090/metrics` exposes receive, TUN-injection, profile-rejection, and routing metrics.
- `GET :9090/debug/routing` returns redacted route-validation status.

Relevant symmetric datapath metrics include `geneve_rx_packets`, `tun_tx_packets`, `gwlb_profile_rejections_total`, `gwlb_receive_drops_total`, `symmetric_unexpected_egress_total`, and `datapath_component_healthy`. An unexpected packet read from TUN egress is dropped and counted; it cannot become a target-originated GENEVE packet.

## Linux Requirements

Envelope needs `CAP_NET_ADMIN` to create/configure `envelope0` and to validate or manage supported routing. On the protected Amazon Linux profile it also receives `CAP_NET_RAW` solely because `iptables-legacy` requires it for continuous read-only firewall inspection; symmetric forwarding does not emit raw packets.

For `verify` and `manage`, the target must satisfy forwarding, reverse-path-filter, firewall, MSS, local VPC delivery, and remote Tailscale-route validation. The target is ready only after its GENEVE receiver, TUN injection, and complete route path are ready. The ingress-router readiness check is separate: it verifies Running Tailscale, exact approved local-site advertisements without SNAT, and an effective local GWLBE route.

## Availability And Cost

The two-AZ profile requires a GWLBE and healthy-capable target path in every enabled AZ plus two independent ingress routers per site. It provides a path for new flows to recover through another healthy target or ingress router after control-plane failover.

This is bounded failover, not a hitless guarantee. A target, instance, AZ, GWLB, or Tailscale-router failure can interrupt established TCP and lose UDP packets. Acceptance must record observed recovery and loss; applications remain responsible for retries.

Multiple endpoints, targets, ingress routers, GWLB processing, and possible cross-AZ/inter-region traffic increase fixed and variable cost. Review the profile's approved hourly ceiling and current AWS prices before any future protected run.

## Local Validation

```bash
go test ./...
sudo ./scripts/component_wire_smoke.sh
python3 scripts/verify_geneve_fixtures.py
python3 scripts/test_docs.py
python3 scripts/secret_scan.py --root .
```

The component smoke test is not AWS, Tailnet, multi-AZ, or failover acceptance.

## Migration And Protected Runs

Migration is breaking. Destroy only resources owned by an old acceptance run before creating a fresh version-2 topology; never mix the old and new route domains or reuse old evidence.

The protected lifecycle owns preflight, deployment, drain, failover exercises, evidence verification, and cleanup. It is intentionally not presented as a copy-paste command: use it only from an approved protected environment with a fresh run identity, reviewed version-2 configuration, current cost approval, and scoped credentials. Do not use old protected-run configuration snippets, direct Terraform commands, or prior workflow procedures.
