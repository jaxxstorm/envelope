## Context

The current Terraform sends every private subnet's remote-VPC route through its local GWLBE. That makes a destination region's GWLB see a response for an initial packet it did not process, which AWS does not support. Routing every Tailnet arrival into `envelope0` also drops a cold packet when the destination appliance has no local GWLB context.

The acceptance topology needs to prove both regional appliances without requiring conntrack-based dynamic service insertion. It therefore separates initiation and response roles by workload subnet. Each tested flow traverses exactly one GWLB: the initiator region's GWLB. The responder region bypasses its GWLB for that flow while its separate initiator lane independently tests the opposite direction.

## Goals / Non-Goals

**Goals:**
- Prove a cold west-to-east flow and a separately cold east-to-west flow through real AWS GWLB and Tailscale infrastructure.
- Assert application, routing, control-plane, packet-wire, MTU, and observability contracts before declaring success.
- Produce deterministic diagnostics and cleanup for both success and failure.
- Exercise both regional GWLB targets in one deployed environment.

**Non-Goals:**
- Proving arbitrary bidirectional initiation from the same workload subnet.
- Proving multi-target high availability or flow-state replication.
- Running live AWS acceptance on untrusted pull requests.
- Retaining unredacted state, credentials, user data, or packet captures as CI artifacts.

## Decisions

### 1. Use two directional workload lanes

The test provisions four workload instances and assigns two private workload subnets per region:

```text
west-initiator -> west GWLBE/GWLB -> west Envelope -> Tailscale
  -> east appliance direct routing -> east-responder

east-responder -> east appliance ENI -> Tailscale -> west Envelope
  -> west GWLB/GWLBE -> west-initiator

east-initiator -> east GWLBE/GWLB -> east Envelope -> Tailscale
  -> west appliance direct routing -> west-responder

west-responder -> west appliance ENI -> Tailscale -> east Envelope
  -> east GWLB/GWLBE -> east-initiator
```

West `gwlb-return-cidrs` contains only the west initiator subnet; east contains only the east initiator subnet. Responder subnets are local-delivery CIDRs and bypass `envelope0` on Tailnet arrival. The sets must be disjoint.

Alternative: one subnet per region with both local initiation and response. Rejected because static VPC routes cannot distinguish a new local flow from a response without a stateful classifier.

### 2. Use separate workload, endpoint, and appliance route domains

GWLBE endpoints live in dedicated endpoint subnets. Initiator workload route tables select the same-AZ GWLBE for the paired responder CIDR. Responder workload route tables select the local appliance ENI for the paired initiator CIDR. Appliance route lookup uses accepted Tailscale routes for those remote prefixes. More-specific lane routes avoid whole-VPC ambiguity.

### 3. Clear flow context before each cold test

The orchestrator restarts Envelope on both appliances, waits for both targets to return healthy, and then initiates exactly one direction. It repeats the reset before testing the opposite direction. No reverse warm-up is allowed. A failure to establish the return path within 30 seconds is terminal.

### 4. Gate packet tests on effective readiness

Apply completion is not readiness. Before traffic, the orchestrator checks cloud-init, both systemd services, Tailscale Running state, route approval/acceptance, effective Linux routes, sysctls/firewall/MSS state, Envelope health/metrics, and GWLB target health. It also requires each `available` GWLBE endpoint to be at least five minutes old. Live observations showed that target health can become green while a newly created endpoint still drops the first workload packet without reaching the GWLB; the bounded endpoint age prevents this transient from being misclassified as an Envelope routing failure.

### 5. Capture live wire evidence

Bounded `tcpdump` captures on appliance underlay, `envelope0`, and `tailscale0` surround each cold test. Assertions identify the flow and verify the GWLB-selected UDP source port remains the return source, destination remains 6081, outer addresses are swapped, VNI is 0, and AWS options including the flow cookie are byte-identical. Readiness-gated one-packet captures use packet-buffered output so their PCAP header is visible before the first packet is sent. Captures are sanitized or deleted after assertions.

### 6. Test traffic in increasing risk order

Each lane runs ICMP, short TCP, UDP, MTU-boundary probes, and bounded `iperf3`. Metrics are snapshotted before and after. Success requires expected GENEVE/TUN counters to increase and unexpected decode, send, collision, missing-context, and drop counters to remain unchanged.

### 7. Make cleanup unconditional

A wrapper configures a unique run key in the shared operator-owned durable encrypted backend, writes a protected run-owned cleanup manifest, and installs a cleanup trap before apply. The manifest and TTL tags allow an independent janitor or emergency command to retry destroy after partial failure or runner loss. Cleanup removes Terraform resources, test artifacts, Tailnet nodes, generated auth key/secret, and run-owned backend objects after residual auditing while preserving shared backend infrastructure.

## Risks / Trade-offs

- [Four workloads and two regions increase cost] -> Use small instances, one NAT per VPC, a hard timeout, TTL tags, and immediate cleanup.
- [Directional lanes could be mistaken for general site-to-site support] -> Name lane roles in outputs/docs and explicitly reject overlapping initiator/responder CIDRs.
- [Packet captures can contain sensitive addresses and metadata] -> Limit filters and duration, assert in place, and retain only redacted summaries.
- [Live tests can fail for external AWS or Tailscale reasons] -> Separate preflight/readiness failures from datapath failures and collect component-specific evidence.
- [A healthy target may precede usable endpoint data-plane service] -> Require an available GWLBE endpoint stabilization interval and record its age before traffic.
- [A capture can deadlock waiting for its own first packet] -> Flush the PCAP header before readiness checks and keep the capture bounded and cleanup-owned.
- [A quick restart may not cross GWLB unhealthy thresholds] -> Prove a new process generation and empty context before each cold test; reserve a deliberate long stop for target-health transition acceptance.
- [Runner loss bypasses local cleanup] -> Recover durable state and the protected manifest through an independent TTL janitor.

## Migration Plan

1. Implement this profile only after options, wire, host-routing, and appliance-deployment changes verify complete.
2. Add static Terraform contract tests for graph shape and lane routes.
3. Add a protected manual runner with preflight and unconditional cleanup.
4. Prove cold ICMP, then TCP/UDP, packet fidelity, MTU, resilience, and no-drift behavior.
5. Keep the existing local harness as a component smoke test but rename it so it cannot be confused with live E2E.

## Open Questions

- What initial throughput threshold is realistic for the selected test instance sizes and regions.
- Whether live acceptance should run manually only or on a scheduled protected workflow after the first stable baseline.
