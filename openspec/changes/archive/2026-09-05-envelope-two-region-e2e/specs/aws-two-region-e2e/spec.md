## ADDED Requirements

### Requirement: Two-region directional-lane topology
The acceptance environment SHALL provide independent west-to-east and east-to-west lanes in which each initiator subnet uses its regional GWLB and each responder subnet returns through its local Tailscale appliance without traversing the responder region's GWLB.

#### Scenario: West-to-east lane routes
- **WHEN** the west initiator sends to the east responder
- **THEN** the initial packet traverses west GWLBE, west GWLB, west Envelope, and Tailscale, while the response returns through the east appliance, Tailscale, west Envelope, and the original west GWLB context

#### Scenario: East-to-west lane routes
- **WHEN** the east initiator sends to the west responder
- **THEN** the initial packet traverses east GWLBE, east GWLB, east Envelope, and Tailscale, while the response returns through the west appliance, Tailscale, east Envelope, and the original east GWLB context

#### Scenario: Unsupported overlapping lane roles
- **WHEN** a workload CIDR is configured as both a GWLB-return initiator CIDR and a direct local-delivery responder CIDR
- **THEN** Terraform validation rejects the topology

### Requirement: Directional-lane network policy
The acceptance environment SHALL configure least-privilege security-group and network-ACL behavior for GWLB health/GENEVE, Tailscale transport, direct routed responder traffic, and every declared ICMP, TCP, and UDP probe in both lanes.

#### Scenario: Saved-plan policy assertions
- **WHEN** the acceptance plan is reviewed
- **THEN** workload and appliance policies allow the configured paired CIDRs, protocols, and ports without opening unrelated inbound application traffic

#### Scenario: Runtime policy path
- **WHEN** ICMP, TCP, and UDP probes run in either lane
- **THEN** security-group and network-ACL flow evidence confirms the intended path is permitted and no probe depends on an accidental broad rule

### Requirement: Live-environment preflight
The acceptance runner SHALL verify AWS identity and regions, required permissions and quotas, Terraform/tool versions, artifact availability, durable isolated state and cleanup manifest, scoped Tailscale administrative and node-secret access, tag ownership, grants, route auto-approval, and an approved cost/TTL before apply.

#### Scenario: Complete preflight
- **WHEN** all required AWS, Tailnet, artifact, tool, state, and cleanup inputs are valid
- **THEN** the runner records a redacted preflight summary and permits planning

#### Scenario: Preflight failure
- **WHEN** any required identity, permission, quota, secret, policy, artifact, or cleanup input is missing
- **THEN** the runner exits before creating billable resources and identifies the failed gate

#### Scenario: Unsupported Terraform executable
- **WHEN** the selected Terraform executable is not the reviewed `1.10.5` version
- **THEN** protected preflight fails before durable preparation or resource creation and identifies the selected version

### Requirement: Saved-plan and convergence gate
The acceptance runner SHALL initialize from a clean working directory, validate and inspect a saved plan, apply exactly that plan once, and require a no-change plan after runtime convergence.

#### Scenario: Reviewed apply
- **WHEN** a fresh saved plan contains only the expected two-region test resources and reviewed sensitive inputs
- **THEN** the runner applies that exact plan without targeted staging

#### Scenario: Post-convergence drift
- **WHEN** a plan after successful bootstrap contains unexpected changes
- **THEN** acceptance fails and the drift is captured before cleanup

### Requirement: Runtime readiness gate
The acceptance runner SHALL require cloud-init completion, active `tailscaled` and Envelope services, Running Tailscale backends, approved and effective lane routes, valid host-network prerequisites, healthy Envelope endpoints, and healthy GWLB targets in both regions before packet tests.

#### Scenario: Both regions ready
- **WHEN** all runtime checks succeed in west and east within the configured timeout
- **THEN** the runner proceeds to cold-flow tests

#### Scenario: Component not ready
- **WHEN** any required component does not become ready before timeout
- **THEN** traffic tests do not start and component-specific diagnostics are collected

### Requirement: Gateway endpoint stabilization
The acceptance runner SHALL require every configured Gateway Load Balancer endpoint to be `available` and at least five minutes old before sending the first test packet. It SHALL record the observed endpoint age in readiness evidence.

#### Scenario: Fresh available endpoint
- **WHEN** a GWLBE reports `available` but its newest creation timestamp is less than five minutes old
- **THEN** the runner waits within the readiness budget and does not start traffic until the stabilization interval completes

#### Scenario: Endpoint cannot stabilize
- **WHEN** the remaining readiness budget cannot accommodate the endpoint stabilization interval
- **THEN** the runner fails before traffic and reports the endpoint-readiness condition

### Requirement: Cold-flow acceptance in both directions
The acceptance runner SHALL clear Envelope flow context before each directional test and SHALL prove ICMP, TCP, and UDP connectivity without reverse-direction warm-up.

#### Scenario: Cold west-to-east flow
- **WHEN** both Envelope processes have restarted, targets are healthy, and the west initiator sends the first packet to the east responder
- **THEN** the flow receives a valid response through the west GWLB context within 30 seconds

#### Scenario: Cold east-to-west flow
- **WHEN** both Envelope processes have restarted again, targets are healthy, and the east initiator sends the first packet to the west responder
- **THEN** the flow receives a valid response through the east GWLB context within 30 seconds

#### Scenario: Warm-state masking prohibited
- **WHEN** a directional test begins
- **THEN** evidence shows no matching return context existed before its initial packet

### Requirement: Live GWLB wire assertions
The acceptance runner SHALL capture and assert the actual AWS outer IPv4/UDP and GENEVE fields for each directional cold flow.

#### Scenario: Return tuple and metadata
- **WHEN** a cold flow returns through its initiator region's Envelope process
- **THEN** capture shows swapped outer IPv4 addresses, the original GWLB-selected source port as return source, destination port 6081, VNI 0, and an identical ordered AWS options block and flow cookie

#### Scenario: Unexpected wire behavior
- **WHEN** a captured return packet reverses UDP ports, changes required metadata, or fails checksum/header validation
- **THEN** acceptance fails even if an application probe reports success

#### Scenario: Readiness-gated one-packet capture
- **WHEN** an MTU or TCP SYN test waits for a one-packet PCAP before sending its probe
- **THEN** the capture flushes its PCAP header so readiness completes without waiting for the packet it gates

### Requirement: MTU and transport acceptance
The acceptance runner SHALL verify MTU-safe ICMP, TCP MSS behavior, UDP payload boundaries, and bounded throughput in both directional lanes.

#### Scenario: Tailscale-safe TCP MSS
- **WHEN** TCP connects across a lane using the configured 1280-byte Tailscale path
- **THEN** the negotiated MSS prevents full-sized segments from being silently dropped by Envelope

#### Scenario: MTU boundary
- **WHEN** probes are sent at and above the supported inner MTU
- **THEN** safe-size traffic succeeds and oversized traffic is rejected with the specified MTU-specific drop metrics

#### Scenario: Bounded throughput run
- **WHEN** `iperf3` runs for the configured duration in each direction
- **THEN** it exceeds a profile-specific threshold approved before the run without unexpected drop or error growth

#### Scenario: Concurrent flow profile
- **WHEN** the pre-approved concurrent TCP and UDP flow profile runs in both lanes
- **THEN** all flows complete within the approved loss/latency bounds without context collision, unexpected eviction, or error growth

### Requirement: Flow and failure observability
The acceptance runner SHALL compare pre-test and post-test metrics and SHALL exercise route drift, locally disabled route acceptance, service restart, target failure, and appliance reboot with expected health transitions.

#### Scenario: Successful flow metrics
- **WHEN** a directional flow succeeds
- **THEN** expected GENEVE and TUN counters increase while unexpected decode, send, collision, missing-context, and drop counters do not

#### Scenario: Route drift repair
- **WHEN** a managed return rule is removed
- **THEN** readiness becomes unhealthy or reports drift, reconciliation restores the owned rule, and repair metrics increase

#### Scenario: Target process stopped
- **WHEN** Envelope is stopped on one appliance
- **THEN** its health endpoint fails, its GWLB target becomes unhealthy, and a restart restores readiness for new cold flows

#### Scenario: Appliance reboot
- **WHEN** either appliance reboots
- **THEN** persistent configuration and services recover and a new cold flow succeeds after target health returns

### Requirement: Deterministic failure evidence
The acceptance runner SHALL collect a redacted evidence bundle on failure containing Terraform selections, AWS target health, cloud-init status, systemd journals, Tailscale status and routes, Linux links/rules/routes/sysctls/firewall state, Envelope health and metrics, and bounded packet-capture assertions.

#### Scenario: Test failure
- **WHEN** any acceptance gate or traffic assertion fails
- **THEN** the evidence bundle identifies the component and stage without containing credentials, Terraform state, rendered user data, or unredacted packet payloads

### Requirement: Unconditional ownership-safe cleanup
The acceptance runner and an independent janitor SHALL be able to clean up after success, failure, interruption, runner loss, and partial apply using durable state, a protected cleanup manifest, and TTL tags, and SHALL verify removal of all test-owned AWS, artifact, Tailnet node, route, secret, and credential resources.

#### Scenario: Successful cleanup
- **WHEN** acceptance completes normally
- **THEN** Terraform state is empty, tagged residual-resource checks pass in both regions, test Tailnet nodes and credentials are removed, run-owned state/lock/manifest objects are deleted, and shared backend infrastructure remains intact

#### Scenario: Interrupted apply or test
- **WHEN** the runner is interrupted after resource creation begins
- **THEN** its cleanup handler uses the same durable state and recorded identifiers to retry destruction and reports any residual resources

#### Scenario: Runner lost
- **WHEN** the runner host disappears and its trap cannot execute
- **THEN** the independent janitor or emergency cleanup command uses the durable backend, manifest, and TTL tags to remove and report abandoned resources

### Requirement: Acceptance execution isolation
Live two-region acceptance SHALL run only in an approved protected environment with serialized execution, a hard timeout, unique names, TTL tags, and no exposure of AWS or Tailscale credentials to untrusted code.

#### Scenario: Protected execution
- **WHEN** a manual or scheduled live run starts
- **THEN** concurrency, timeout, credential scope, unique naming, and TTL controls are active before apply

#### Scenario: Untrusted pull request
- **WHEN** code originates from an untrusted fork or unapproved context
- **THEN** live AWS/Tailscale acceptance is not permitted to access credentials or create resources
