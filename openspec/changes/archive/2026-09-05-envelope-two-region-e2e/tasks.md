> Archived incomplete: `add-symmetric-gwlb-ha` superseded this directional-lane design before completion. The unchecked tasks and unsynced delta are retained as historical context rather than reported as completed work.

## 1. Runner, Isolation, and Preflight

- [ ] 1.0 Verify all four prerequisite changes are implemented, synced to canonical specs, archived, and pass their verification gates. Acceptance: E2E contains no unresolved production behavior and consumes final artifact/routing/wire contracts. Test: OpenSpec list/show and strict validation. Spec: prerequisite for `aws-two-region-e2e`.
- [ ] 1.1 Add one non-interactive runner that owns build/publish, isolated Terraform data, durable state/manifest, saved plan, apply, readiness, tests, evidence, and destroy phases. Acceptance: phase names and exit status are deterministic and both local cleanup and independent janitor recovery are armed before creation. Test: runner unit tests with command fakes. Spec: `aws-two-region-e2e` / Saved-plan and convergence gate; Unconditional ownership-safe cleanup.
- [ ] 1.2 Implement AWS, Terraform/tool, quota, region, artifact, durable state/manifest, Tailnet OAuth/node secret/policy, cost, unique-name, TTL, timeout, and concurrency preflight. Acceptance: every missing input fails before billable resources and produces a redacted reason. Test: preflight failure matrix. Spec: `aws-two-region-e2e` / Live-environment preflight; Acceptance execution isolation.
- [ ] 1.2.1 Reject an unsupported selected Terraform executable before durable prepare. Acceptance: a Terraform core version outside the profile constraint fails in protected preflight without creating a manifest, secret, Tailnet node, or AWS resource. Test: preflight version matrix. Spec: `aws-two-region-e2e` / Live-environment preflight.
- [ ] 1.3 Enforce protected execution policy for live credentials. Acceptance: fork/untrusted contexts cannot run live acceptance and approved runs are serialized with a hard timeout. Test: CI policy tests. Spec: `aws-two-region-e2e` / Acceptance execution isolation.

## 2. Directional-Lane Terraform Profile

- [ ] 2.1 Add west/east initiator and responder workload instances in distinct route domains. Acceptance: four workloads have stable role outputs and SSM access. Test: Terraform plan resource/role assertions. Spec: `aws-two-region-e2e` / Two-region directional-lane topology.
- [ ] 2.2 Route each initiator to its same-region GWLBE for the paired responder prefix and route each responder return prefix to its local appliance ENI. Acceptance: no responder region GWLB receives a reverse-only flow and lane routes are more specific than broad VPC routes. Test: route-table plan tests and runtime route queries. Spec: `aws-two-region-e2e` / Two-region directional-lane topology.
- [ ] 2.3 Pass west initiator and east initiator prefixes as their respective GWLB-return CIDRs and responder prefixes as local-delivery CIDRs. Acceptance: role sets are disjoint and Terraform rejects overlap. Test: positive/negative variable tests. Spec: `aws-two-region-e2e` / Unsupported overlapping lane roles.
- [ ] 2.4 Install bounded traffic and diagnostic tools on test instances without manual sessions. Acceptance: ping, TCP/UDP probes, `iperf3`, and SSM diagnostics are ready after cloud-init. Test: workload bootstrap checks. Spec: `aws-two-region-e2e` / Runtime readiness gate.
- [ ] 2.5 Add and assert least-privilege workload/appliance security-group and NACL behavior for health, GENEVE, Tailscale, direct routing, ICMP, TCP/5201, and UDP/5201 in both lanes. Acceptance: every declared probe is allowed by an intentional rule and unrelated inbound application ports remain closed. Test: saved-plan policy assertions plus runtime flow evidence. Spec: `aws-two-region-e2e` / Directional-lane network policy.

## 3. Plan and Runtime Readiness Gates

- [ ] 3.1 Add saved-plan JSON assertions for exact topology, lane routes, target count, cross-zone setting, artifact checksum, site config, and absence of unexpected destroy/replace actions. Acceptance: applying is impossible when contract assertions fail. Test: plan fixture tests. Spec: `aws-two-region-e2e` / Saved-plan and convergence gate.
- [ ] 3.2 Add SSM checks for cloud-init, services, links, listeners, sysctls, firewall/MSS state, policy rules, effective routes, Tailscale backend, advertisements, and accepted routes. Acceptance: all checks pass in both regions before traffic. Test: readiness parser tests and live gate. Spec: `aws-two-region-e2e` / Runtime readiness gate.
- [ ] 3.3 Wait for both GWLB target groups to become healthy and capture reasons on timeout. Acceptance: traffic never starts against initial, unhealthy, draining, or unused targets. Test: healthy and service-stopped cases. Spec: `aws-two-region-e2e` / Runtime readiness gate.
- [ ] 3.3.1 Require every available GWLBE endpoint to pass a bounded five-minute stabilization interval before traffic. Acceptance: the runner records endpoint age and does not send the first cold packet while endpoint service may still be converging. Test: endpoint-age wait and readiness-summary tests, then protected live evidence. Spec: `aws-two-region-e2e` / Gateway endpoint stabilization.
- [ ] 3.4 Require a no-change Terraform plan after runtime convergence. Acceptance: unexpected infrastructure drift fails acceptance before packet tests. Test: live no-drift check. Spec: `aws-two-region-e2e` / Saved-plan and convergence gate.

## 4. Packet Capture and Wire Assertions

- [ ] 4.1 Add bounded filtered captures on appliance underlay, `envelope0`, and `tailscale0` around each directional test. Acceptance: capture lifecycle cannot outlive the test and payload retention is minimized. Test: capture controller tests. Spec: `aws-two-region-e2e` / Live GWLB wire assertions.
- [ ] 4.1.1 Flush the PCAP header for readiness-gated one-packet MTU and SYN captures. Acceptance: readiness can observe a nonempty capture before the first probe without consuming or retaining the probe packet. Test: shell-command fixtures and protected MTU evidence. Spec: `aws-two-region-e2e` / Live GWLB wire assertions.
- [ ] 4.2 Implement independent outer IPv4/UDP and GENEVE assertions. Acceptance: swapped IPs, unchanged source/destination port orientation, destination 6081, VNI 0, checksums, ordered options, and flow cookie are verified. Test: parser fixtures plus live capture. Spec: `aws-two-region-e2e` / Live GWLB wire assertions.
- [ ] 4.3 Fail wire acceptance even when application traffic succeeds through an unintended path. Acceptance: injected port/options assertion failures produce terminal test failure. Test: negative capture fixtures. Spec: `aws-two-region-e2e` / Unexpected wire behavior.

## 5. Cold-Flow Functional Acceptance

- [ ] 5.1 Restart both Envelope services, wait for target recovery, prove no matching context, then run cold west-to-east ICMP. Acceptance: response returns through the original west GWLB context within 30 seconds. Test: live `TestTwoRegionColdFlowWestToEast`. Spec: `aws-two-region-e2e` / Cold-flow acceptance in both directions.
- [ ] 5.2 Clear contexts again and run cold east-to-west ICMP with no reverse warm-up. Acceptance: response returns through the original east GWLB context within 30 seconds. Test: live `TestTwoRegionColdFlowEastToWest`. Spec: `aws-two-region-e2e` / Cold-flow acceptance in both directions.
- [ ] 5.3 Run short TCP and UDP probes in both lane directions from cleared context where applicable. Acceptance: connections/data succeed and remote GWLB captures show no unsupported reverse-only flow. Test: live transport matrix. Spec: `aws-two-region-e2e` / Cold-flow acceptance in both directions.
- [ ] 5.4 Compare pre/post metrics for every flow. Acceptance: expected GENEVE/TUN counters increase and unexpected decode/send/collision/missing-context/drop counters remain unchanged. Test: metrics delta assertions. Spec: `aws-two-region-e2e` / Flow and failure observability.

## 6. MTU, Concurrency, and Performance

- [ ] 6.1 Test IPv4 TCP MSS and full-sized data in both lanes. Acceptance: negotiated MSS is safe for 1280 MTU and sustained data has no MTU drop growth. Test: SYN capture plus TCP transfer. Spec: `aws-two-region-e2e` / MTU and transport acceptance.
- [ ] 6.2 Test inner MTU boundary and explicit oversized ICMP/UDP drop behavior. Acceptance: safe size succeeds, oversized traffic increments MTU-specific drop metrics, and the test does not expect an ICMP PMTU response. Test: bounded size matrix. Spec: `aws-two-region-e2e` / MTU boundary.
- [ ] 6.3 Approve profile-specific throughput, loss, latency, concurrency, and duration thresholds before apply, then run concurrent TCP/UDP and bounded bidirectional `iperf3`. Acceptance: the pre-approved profile passes without context collision, unexpected eviction, or error growth. Test: live load profile. Spec: `aws-two-region-e2e` / Bounded throughput run; Concurrent flow profile.

## 7. Resilience and Failure Cases

- [ ] 7.1 Remove an owned return rule and verify readiness/drift repair and metrics. Acceptance: traffic is gated while invalid and succeeds after managed repair. Test: live route-drift scenario. Spec: `aws-two-region-e2e` / Route drift repair.
- [ ] 7.2 Stop/restart Envelope and verify GWLB target health transitions and new cold-flow recovery. Acceptance: stopped target is unhealthy and no pre-restart context continuity is claimed. Test: live target-process scenario. Spec: `aws-two-region-e2e` / Target process stopped.
- [ ] 7.3 Reboot each appliance independently and rerun a cold flow. Acceptance: persistent host/service/Tailnet state recovers without manual repair. Test: live appliance-reboot scenarios. Spec: `aws-two-region-e2e` / Appliance reboot.
- [ ] 7.4 Disable remote-route acceptance locally on one appliance, then restore it. Acceptance: readiness blocks traffic, reports the exact prefix, and recovers without mutating Tailnet policy. Test: protected route-acceptance failure scenario. Spec: `aws-two-region-e2e` / Runtime readiness gate; Flow and failure observability.

## 8. Evidence and Cleanup

- [ ] 8.1 Build a redacted evidence bundle with versions, selected Terraform outputs, target health, cloud-init, journald, Tailscale/routing state, health/metrics deltas, and packet assertion summaries. Acceptance: bundle contains no state, user data, credentials, or unredacted payloads. Test: evidence content/secret scan. Spec: `aws-two-region-e2e` / Deterministic failure evidence.
- [ ] 8.2 Implement unconditional destroy and retry for success, failure, timeout, interruption, and partial apply using the shared durable backend's run key and protected manifest. Acceptance: cleanup status is always reported, run-owned state/lock/manifest objects are removed after audit, shared backend infrastructure is preserved, and no local-only state is required. Test: injected-failure/interrupt drills. Spec: `aws-two-region-e2e` / Unconditional ownership-safe cleanup.
- [ ] 8.3 Add an independent TTL janitor/emergency cleanup command and simulate runner host loss. Acceptance: the janitor discovers the manifest/tagged run, recovers durable state, and removes abandoned resources. Test: runner-loss drill. Spec: `aws-two-region-e2e` / Runner lost.
- [ ] 8.4 Verify no tagged EC2, VPC, NAT, EIP, GWLB, endpoint, IAM, S3 artifact, Tailnet node/route, run secret, generated credential, or run-owned backend object remains. Acceptance: both-region, Tailnet, and run-key audits are empty while shared backend infrastructure remains. Test: post-destroy audit. Spec: `aws-two-region-e2e` / Successful cleanup.

## 9. Documentation and Final Verification

- [ ] 9.1 Document prerequisites, cost profile, directional-lane limitation, one-command workflow, expected evidence, troubleshooting, and emergency cleanup. Acceptance: operators cannot confuse this profile with arbitrary same-subnet bidirectional or HA support. Test: runbook walkthrough. Spec: all requirements in this change.
- [ ] 9.2 Add static PR checks and a protected manual/scheduled live workflow without exposing credentials to forks. Acceptance: static checks run on every PR; live workflow requires approval and always invokes cleanup. Test: workflow policy tests. Spec: `aws-two-region-e2e` / Acceptance execution isolation.
- [ ] 9.3 Execute the complete full two-region acceptance from a clean checkout. Acceptance: preflight, one apply, readiness, both cold directions, wire, MTU, load, resilience, no-drift, evidence, destroy, and residual audit all pass. Test: the live runner itself. Spec: all requirements in this change.
- [ ] 9.4 Run strict OpenSpec verification and archive only after live evidence is reviewed. Acceptance: all task boxes map to retained redacted evidence and no requirement is waived silently. Test: `openspec validate envelope-two-region-e2e --strict` and OpenSpec implementation verification. Spec: all requirements in this change.
