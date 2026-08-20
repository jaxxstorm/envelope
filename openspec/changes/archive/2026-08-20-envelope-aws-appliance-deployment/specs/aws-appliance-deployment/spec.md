## ADDED Requirements

### Requirement: Reproducible Envelope artifact
The deployment SHALL build a versioned static Linux Envelope binary for the selected EC2 architecture, record its source revision and SHA-256, and install only an artifact whose checksum matches the reviewed Terraform input.

#### Scenario: Artifact built for selected architecture
- **WHEN** the deployment architecture is `amd64` or `arm64`
- **THEN** the build produces a matching Linux binary with source revision and checksum metadata

#### Scenario: Artifact checksum mismatch
- **WHEN** an appliance downloads an artifact whose SHA-256 differs from the configured value
- **THEN** installation fails, Envelope does not start, and the GWLB target cannot report healthy

### Requirement: Secret-contained Tailscale bootstrap
The deployment SHALL retrieve a runner-generated short-lived, reusable, preauthorized Tailscale bootstrap credential from a run-scoped external encrypted secret at instance boot and MUST NOT place the credential value in Terraform variables, plans, state, outputs, or rendered user data.

#### Scenario: Authorized secret retrieval
- **WHEN** an appliance boots with permission to the configured secret ARN
- **THEN** it retrieves the credential at runtime and authenticates with the requested Envelope tag without logging the value

#### Scenario: Secret unavailable
- **WHEN** an appliance cannot read or decrypt the configured secret
- **THEN** bootstrap fails closed, readiness remains unhealthy, and diagnostics identify secret retrieval without exposing a credential

### Requirement: Tailnet administrative lifecycle
The protected runner SHALL use a separate narrowly scoped Tailscale OAuth/API credential outside Terraform to create and revoke the run-scoped bootstrap key and remove test nodes, while route approval and grants SHALL be preconfigured through Tailnet policy.

#### Scenario: Non-interactive credential creation
- **WHEN** an approved run starts after Tailnet policy preflight
- **THEN** the runner creates one short-lived reusable preauthorized key, stores it in the run-scoped encrypted secret, and records only identifiers in the cleanup manifest

#### Scenario: Tailnet cleanup
- **WHEN** the run succeeds or fails after node creation
- **THEN** the runner removes both test nodes, revokes the generated auth key, and deletes the run-scoped secret using the administrative credential

#### Scenario: Tailnet policy not preconfigured
- **WHEN** tag ownership, route auto-approval, or lane grants are missing
- **THEN** preflight fails before AWS resources are created rather than waiting for manual approval

### Requirement: Boot-persistent Envelope service
The deployment SHALL install an idempotent systemd service that starts Envelope after network and Tailscale prerequisites, restarts it on failure, and grants only the capabilities required for TUN/routing and AWS-compliant packet emission.

#### Scenario: First boot convergence
- **WHEN** cloud-init, networking, and `tailscaled` complete successfully
- **THEN** `envelope.service` becomes active with the reviewed artifact and site configuration

#### Scenario: Service failure
- **WHEN** the Envelope process exits unexpectedly
- **THEN** systemd restarts it according to a bounded restart policy and records the failure in journald

#### Scenario: Appliance reboot
- **WHEN** an appliance reboots
- **THEN** persistent host configuration is restored and both `tailscaled` and Envelope return to ready state without manual commands

### Requirement: Site-specific runtime configuration
The deployment SHALL render independent west and east Envelope configurations, including local GWLB-return CIDRs, local-delivery CIDRs, remote Tailnet CIDRs, routing mode, interface names, table identifiers, context timeouts, and artifact identity.

#### Scenario: West configuration
- **WHEN** the west appliance starts
- **THEN** its effective service configuration contains only the west-local lane roles and east-remote routes

#### Scenario: East configuration
- **WHEN** the east appliance starts
- **THEN** its effective service configuration contains only the east-local lane roles and west-remote routes

#### Scenario: Ambiguous shared CIDRs
- **WHEN** west and east are configured from one shared local-return CIDR list
- **THEN** Terraform validation rejects the configuration

### Requirement: Persistent host forwarding prerequisites
The deployment SHALL persist IPv4 forwarding, required IPv6 forwarding when enabled, disabled reverse-path filtering for `conf/all` and the dynamically created Envelope TUN, non-strict reverse-path filtering for the underlay and Tailscale interfaces, forwarding firewall policy, and TCP MSS rules compatible with the configured Tailscale MTU.

#### Scenario: Required host state after boot
- **WHEN** cloud-init and systemd preflight complete
- **THEN** effective sysctls, route lookup, firewall forwarding, and MSS-clamp state satisfy the host-routing specification

#### Scenario: Host prerequisite missing
- **WHEN** a required sysctl or forwarding rule is absent after boot
- **THEN** Envelope readiness remains unhealthy and the missing state is reported

#### Scenario: Asymmetric TUN source validation
- **WHEN** Linux returns `EINVAL` or `EXDEV` for an ordinary-unicast IPv4 boundary lookup entering the configured Envelope TUN
- **THEN** the supplementary lookup may be omitted only when the full-prefix policy/FIB audit passes and effective reverse-path filtering is disabled through both `conf/all` and the Envelope interface

### Requirement: Fresh-state Terraform convergence
The deployment SHALL support a clean Terraform plan and one non-targeted apply from empty state, followed by a no-change plan and complete destroy.

#### Scenario: Fresh-state plan
- **WHEN** Terraform plans from empty state with valid inputs
- **THEN** all resource instance keys are known during planning and the plan completes without `-target`

#### Scenario: Single-pass apply
- **WHEN** the reviewed fresh-state plan is applied
- **THEN** all infrastructure and both appliance services converge without a second targeted apply

#### Scenario: Idempotent plan
- **WHEN** Terraform plans again after successful convergence with unchanged inputs
- **THEN** the plan reports no changes

#### Scenario: Complete destroy
- **WHEN** the destroy plan is applied from the same state
- **THEN** no test-owned AWS resources remain in state or in either region

### Requirement: Reproducible Terraform inputs
The deployment SHALL pin tested Terraform, provider, module, AMI, and artifact inputs and SHALL retain a dependency lock with checksums for supported execution platforms.

#### Scenario: Clean initialization
- **WHEN** Terraform initializes from a clean checkout
- **THEN** it selects the reviewed dependency versions and verifies their checksums

#### Scenario: Unreviewed dependency change
- **WHEN** an initialization or plan would select a different provider, module, AMI, or artifact
- **THEN** the change is visible for review before apply

#### Scenario: Explicit regional AZs
- **WHEN** a clean plan is created
- **THEN** all enabled west and east Availability Zone names come from reviewed inputs rather than dynamic first-N discovery

#### Scenario: Architecture compatibility
- **WHEN** artifact architecture, AMI architecture, appliance type, or test instance type are incompatible
- **THEN** protected preflight queries the selected AWS image and instance-type metadata and fails before planning resources

### Requirement: Single regional flow owner
The deployment SHALL route all GWLB traffic and mapped Tailnet returns in each region to one Envelope process unless a separate approved design provides deterministic return affinity to multiple processes.

#### Scenario: Multiple endpoint AZs with one target
- **WHEN** the acceptance profile enables GWLBE endpoints in multiple AZs and one regional target
- **THEN** GWLB cross-zone behavior is explicitly enabled and every endpoint can reach that target

#### Scenario: Unsupported multiple targets
- **WHEN** more than one Envelope target per region is requested without a return-affinity mode
- **THEN** Terraform validation rejects the configuration

#### Scenario: Loop-free subnet roles
- **WHEN** workload, GWLBE, and appliance subnets are created
- **THEN** their route tables prevent post-inspection packets from recirculating through the same GWLBE

### Requirement: Tailscale control-plane readiness
The deployment SHALL verify preconfigured tag ownership, route auto-approval, grants, advertised local prefixes, accepted remote prefixes, disabled subnet-route SNAT, and a Running backend before declaring an appliance ready.

#### Scenario: Approved and accepted routes
- **WHEN** both appliances are authenticated and Tailnet policy is correct
- **THEN** each appliance advertises its configured local prefixes and has effective routes for the configured remote prefixes

#### Scenario: Route awaiting approval
- **WHEN** an advertised route is not approved
- **THEN** the appliance remains unready and the pending prefix is reported

#### Scenario: Backend not Running
- **WHEN** `tailscale0` exists but the Tailscale backend is not Running
- **THEN** the appliance remains unready

### Requirement: GWLB target bootstrap readiness
The deployment SHALL expose Envelope health on the configured target health-check port and SHALL provide a deterministic wait operation for both regional targets to become healthy after appliance bootstrap.

#### Scenario: Both targets healthy
- **WHEN** both appliance services and routing paths are ready for the configured profile
- **THEN** both GWLB target groups report their registered targets healthy

#### Scenario: Target remains unhealthy
- **WHEN** a regional target does not become healthy within the configured timeout
- **THEN** deployment acceptance stops and collects cloud-init, systemd, routing, Tailscale, and health diagnostics

### Requirement: Sensitive state handling
The deployment SHALL use a pre-provisioned operator-owned encrypted durable backend with locking and a unique run-owned state key, SHALL persist a protected run-owned cleanup manifest and TTL ownership tags independent of the runner process, and SHALL treat plan files, state, rendered cloud-init, packet captures, and debug logs as sensitive artifacts.

#### Scenario: Test operator initializes state
- **WHEN** a test deployment is prepared
- **THEN** durable state and lock storage are isolated to the test run, encrypted, access-controlled, and excluded from source control

#### Scenario: Test teardown
- **WHEN** the run is complete
- **THEN** temporary credentials are revoked, residual auditing completes, run-owned state/lock/manifest objects are removed, shared backend infrastructure is preserved, and sensitive local artifacts are securely removed or retained only in an approved protected location

#### Scenario: Runner host lost
- **WHEN** the runner and its local trap disappear after resource creation
- **THEN** an independent cleanup command or janitor can recover the durable state/manifest and remove TTL-tagged test resources

### Requirement: Bounded acceptance deployment cost
The deployment SHALL expose a reviewed resource-count and hourly-cost profile and SHALL minimize fixed test infrastructure while preserving required SSM, artifact, Tailscale, and GWLB connectivity.

#### Scenario: Reviewed cost profile
- **WHEN** a saved plan is approved
- **THEN** NAT gateways, GWLBE endpoints, GWLBs, public IPv4 addresses, instances, and other fixed-cost resources match the pre-approved count and TTL
