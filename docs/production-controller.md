# Production Failover Controller

> **Status:** This is the production-controller architecture and operations contract. The SLO values on this page are initial objectives pending protected controller evidence. Protected run `ha54` exercised the earlier runner-coordinated topology and is not evidence for this controller profile.

## Runtime Boundary

`envelope-controller` is a standalone control-plane process. Run at least three disposable replicas in independent failure domains, outside Envelope packet-target instances and outside Tailscale transport-router instances. Packet targets remain stateless GWLB packet-turnaround services. Transport routers remain no-NAT forwarding hosts. Neither role runs, embeds, or imports the controller, and neither role has EC2 route-mutation authority.

Each controller replica contains an embedded, pinned `tsnet` observer with its own stable Tailnet identity and private persistent state. Replicas publish bounded observations and coordinate through one encrypted, strongly consistent DynamoDB table. DynamoDB conditional writes, record versions, document revisions, and monotonically increasing fencing terms provide regional authority; the controller does not use embedded Raft.

A contender records the current lease record version, waits one complete lease duration on its local monotonic clock, and takes over only when a strongly consistent reread still has that version. The conditional takeover advances both record version and fence. Observation TTL is garbage collection only and never establishes lease expiry or ownership.

The approved production runtime consists of the controller binary, an immutable topology document, AWS workload identity, Tailnet credential references, private observer state, and a small read-only Go router attestor. It does not require or invoke repository test scripts, Python or shell orchestration, a protected or acceptance test runner, SSM commands, acceptance manifests, remote execution, or an Envelope agent on a packet target. The attestor is not a router-side control agent: it exposes no mutation API and does not change forwarding, advertisements, or AWS routes. Linux inspection privileges are explicit below; they are not claimed to be capability-free. There is no remote mutation HTTP endpoint.

## Implementation Checkpoint

Task 7.5 has a complete native inspection and immutable enrollment path. Task 7.6 has implemented, tested lifecycle operations within the bounded scope below. The split acceptance implementation includes mocked phase integration and an external IAM setup/recovery runbook. Do not dispatch the workflow without separate task 9.5 approval and account-specific IAM review. Live billable execution has not been approved or performed. Native Linux integration is an executable check, not evidence obtained by cross-compiling it on Darwin.

- Implemented: signed Ed25519 challenge-response verification, strict bounded reports, complete router-authority matching, capture/expiry checks, replay rejection across verifier restarts, and HTTPS fetching with no redirects or environment proxy. TLS authenticates the independently enrolled Ed25519 key, including with short-lived self-signed certificates. Every required check must explicitly pass; missing and unsupported checks fail closed.
- Implemented: the Go deployment initialization command, a restrictive STS session policy, fresh stable observer quorum before and after cloud inspection, fresh forwarding attestation, authoritative stable route agreement, and conditional lease-free journal creation for the actual owner. A lost create response is uncertain, not permission to overwrite or activate.
- Implemented: active reconciliation no longer initializes missing journals. It reports `domain-not-initialized`, makes no route call, and waits for deployment initialization. Initialized journals have `activated=false`, outside the topology authority/hash, and cannot acquire a lease or reconcile until explicitly activated. Activated journal recovery is unchanged. An older record with no activation field fails closed without deleting or rewriting its journal; never use a topology change or hand-edit to bypass this gate.
- Implemented: native Go attestor service, IMDSv2 instance/primary-ENI binding, actual procfs forwarding/reverse-path reads, pinned Tailscale local-API backend/preferences checks, serving-peer TSMP checks, and a hardened read-only systemd unit. The service checks that its signing key matches the configured public key and requires root-owned immutable configuration and a mode-0400 seed. No shell, Python, or SSM is executed in its runtime loop.
- Implemented: controller runtime attestation consumption for eligibility and again before every route call. Terraform now requires explicit unique public-key authority for every topology router and delivers a content-addressed, SHA-256- and version-pinned trust document as mode 0444. This input is independent enrollment authority, not a key discovered from signed identity claims. No private signing keys enter Terraform state.
- Implemented: complete native rtnetlink policy/route decoding, legacy IPv4/IPv6 firewall/no-NAT/MSS validation, empty nftables-state enforcement, and full-prefix host/VPC forwarding proof tied to destination workload/GWLBE subnet AZs. Repeated snapshots reject changes during collection. The existing router backend is legacy iptables; an nftables-only collector or a signed boot marker would not prove it. Unknown selectors, matches, targets, malformed or unsupported state remain rejected, never reported as passing.
- Implemented: immutable router binary installation in the appliance root, boot-only Go enrollment, conditional per-router seed provisioning, public version-1 key bindings, and source-instance-bound config/seed delivery in `deploy/terraform/router-attestor`. Seeds never enter Terraform state or user data. The [enrollment runbook](../deploy/terraform/router-attestor/README.md) documents the staged workflow and required inputs.
- Implemented: deployment activation, deactivation, non-expiring deployment-wide locking, saved-plan single-replica replacement with health gates, and quiescent migration of the existing domain set. Region/table moves, domain additions/removals, multi-replica plans, IAM changes, route changes, and create-before-destroy rollout are rejected. Do not change a topology hash to enable a domain or discard a live journal.
- Implemented: separate deployment, observation, quiescence, and cleanup processes/credentials, versioned ownership-checked handoff, and schema-3 live evidence separate from integration-only receipts. Mocked phase integration covers faults, interruptions, credential isolation, ownership and cleanup; inspected manual recovery is documented, not an automatic lock takeover. The legacy combined-evidence runner still fails its capability preflight.

### Deployment Initialization

The command is `cmd/envelope-controller-deploy`. It is deployment tooling, not a runtime dependency. It and `cmd/envelope-router-attestor` are included in the reproducible static amd64/arm64 controller release manifest. Initialization is:

```bash
envelope-controller-deploy initialize \
  --topology /reviewed/controller-topology.json \
  --domain east-workload \
  --initialization-role-arn arn:aws:iam::123456789012:role/reviewed-initializer \
  --external-id reviewed-deployment-identity \
  --router-trust /reviewed/router-trust.json
```

This is a cloud-writing deployment command, not an offline validation command; do not execute it without deployment approval. Configure the controller Terraform root's `deployment_lifecycle` input with explicit trusted IAM role ARNs and an external ID. It provisions a separately trusted route-denied role and outputs `deployment_lifecycle_role_arn`. Null leaves lifecycle authority unprovisioned. Controller principals and wildcard/account-root trust are rejected. The current workflow's `AWS_E2E_ROLE_ARN` is not assumed to support role chaining; supply the actual trusted caller through deployment configuration.

The command first validates inputs locally, then obtains a 900-second restricted session. Initialization's explicit `NotAction` deny permits only the four required EC2 Describe APIs, DynamoDB `GetItem`/`PutItem`, and DynamoDB-context-only KMS decryption. It cannot mutate routes, modify IAM, execute SSM, or assume another role. Session allows restrict DynamoDB reads to the reviewed deployment/observer partitions and writes to the exact deployment partition and table. Other lifecycle operations add conditional lock checks; rollout adds a closed set of compute/backend operations further restricted by the provisioned role. The optional `deployment_lifecycle.rollout` input supplies exact backend and KMS authority. These session policies intersect existing role permissions; they do not grant missing permissions. Policies exceeding STS's inline size bound fail before credential acquisition. Commands have a 14-minute deadline within the 15-minute session and retain exclusion on timeout.

The independently reviewed trust document has schema `1`, `deployment_id`, the canonical `topology_hash`, and a `routers` list containing exactly one entry per topology router: `router_id`, a 64-lowercase-hex `ed25519_public_key`, the required `configuration_sha256`, and an HTTPS `url`. Router IDs, enrolled keys, and URLs cannot be shared. This file is enrollment authority, not evidence obtained from the router. Never enroll a key based solely on a reported instance ID, hostname, shared instance role, or acceptance discovery. Exact-instance enrollment uses configured public-key authority, a version-1 instance/ENI/stable-node/config binding, source-instance credential restrictions, and native local identity checks. Supplementary transport-table, association, MSS, and endpoint authority is covered by the configuration digest.

The attestor protocol signs the exact bounded JSON report bytes prefixed with `envelope-router-attestation-v1\n`. The detached signature uses the `Envelope-Attestation-Signature` response header with standard base64 encoding. The verifier sends a new 256-bit `challenge` query value for every call. Reports include schema, deployment/hash, complete `OwnerAuthority`, challenge, capture/expiry, and all live forwarding check results. TLS 1.3 verifies the enrolled Ed25519 public key and certificate validity, independently of report contents; a CA/hostname assertion cannot replace enrollment. The service creates a 24-hour certificate in memory and the unit restarts within 12 hours. Collector and verifier clocks must be synchronized: capture before the challenge start or after receipt is rejected, with no implicit skew allowance. Report lifetime is bounded to at most one minute and the configured freshness. These protocol tests use simulated signed reports; they are not live forwarding evidence.

Every signed report also requires `configuration_sha256` equal to the independently enrolled collector digest. Missing or mismatched configuration binding is rejected, even when the topology, public key, instance, and challenge otherwise match.

Initialization requires uninterrupted quorum through the longer failback stability window, even for a preferred owner. It checks candidate cloud health, fresh attestation, the exact GWLBE association and complete route set, then rechecks owner continuity generations before creating state. Initialization grants no activation. All routers must be enrolled with reachable private endpoints and passing native checks before deployment can proceed. Existing journals, including a different topology or active transaction, are never adopted or replaced.

The Linux inspector runs as root with only `CAP_NET_ADMIN`, which Linux requires even for legacy netfilter GET_INFO/GET_ENTRIES and nftables enumeration. It uses datagram control sockets and does not require `CAP_NET_RAW`. This is real host-network administrative privilege if the trusted binary is compromised. Root may also be trusted by local systemd/Tailscale daemon authorization independently of capability bits; this trusted signer is not a hardware-attestation boundary. The immutable binary exposes no setter or remote mutation endpoint; systemd restricts writable mounts, capabilities, syscalls, address families, and resources. AWS credentials remain route-denied. Boot-only SSM/S3 enrollment is separate from the native inspection loop. Supported resolver state is a direct VPC resolver or Amazon-provided resolver, not an unverified local DNS stub.

### Locked Lifecycle Operations

The other command names are `activate`, `deactivate`, `rollout`, and `migrate`; they share the topology, trust, role ARN, and external-ID flags. Retain the emitted `operation_id` on every outcome. The separate `lifecycle#<deployment>` DynamoDB partition has no TTL or automatic takeover. Domain rewrites transactionally check the exact lock, old payload, and item version. Controller roles cannot write that partition. Activation is deployment-only; controller CAS cannot toggle it. Both durable adapters reject lease acquisition, takeover, renewal, and journal writes while inactive, including resumed stale writers.

- `activate --domain ID` checks fresh stable route/owner agreement and conditionally activates one stable inactive domain, clearing only an expired lease while preserving its fence. It does not grant IAM permissions or change process mode.
- `deactivate` atomically marks the complete domain set inactive without discarding any journal content, waits an unchanged full lease plus API/convergence bound, and requires stable non-ambiguous journals with no live lease before completing. In-flight changes restart the observation window. Unsettled journals retain the lock for reviewed recovery.
- `rollout --replica ID --terraform-dir DIR --terraform PATH --terraform-sha256 SHA --plan PATH --plan-sha256 SHA` copies the reviewed Terraform executable and saved plan into private immutable files. The entire plan must contain only one delete-then-create controller replacement and its observer-volume attachment; all other mutations are rejected. All replicas must have fresh IAM-bound observations and healthy EC2 status before replacement. Afterwards, peer instance IDs must be unchanged, the original selected instance must be terminated, and the replacement plus peers must have healthy cloud status and newly captured observations. Fresh route/owner agreement and stable journals are checked on both sides. No shell is invoked; Terraform is a deployment-only subprocess with only the restricted AWS session and a scrubbed environment.
- `migrate --next-topology PATH --next-router-trust PATH` requires the same deployment, regional table, and complete domain-ID set, at most 32 domains. It deactivates and drains the old authority, validates fresh old and new topology-bound observations/attestations and routes, then replaces all stable domain authorities in one guarded transaction. Revisions increase, fences and cooldown are retained, leases are cleared, and the new generation remains inactive. Supply both observation and attestation generations during preflight; missing either generation fails closed. This command does not provision those observation processes or perform a table/domain-set migration.

Start replicas read-only and initialize journals first. Stage the reviewed exact route IAM grants separately while processes remain read-only; the rollout command deliberately cannot edit IAM. Generate one saved replacement plan at a time to start active-mode replicas while domains remain inactive, then activate domains individually. A plan for a shared artifact/IAM change is not a safe one-replica plan and will be rejected; stage its required permissions separately. Do not use Terraform parallelism or an unvalidated targeted apply as a substitute for the lifecycle lock.

The lifecycle preflight rejects policies whose lease plus API/convergence drain bound is 12 minutes or longer, before acquiring the lock. Longer-lived authority needs a separately budgeted deployment operation, not a silently truncated quiescence wait.

There is no automatic recovery/unlock command. A failed external apply, lost transaction response, failed post-health gate, or interrupted process retains the lock and journal. Quarantine the deployment caller, verify no Terraform process or cloud operation remains outstanding, and use separately reviewed recovery authority rather than deleting the lock or reusing an operation ID. Retention is intentional exclusion, not successful completion.

## Architecture

```text
                                      regional control authority
                              +--------------------------------+
                              | encrypted DynamoDB             |
                              | lease + fence + domain journal |
                              | bounded observer snapshots     |
                              +---------------+----------------+
                                              ^
                           conditional writes | strongly consistent reads
                                              |
       +----------------------+---------------+----------------------+
       |                      |                                      |
+------+---------------+ +----+-----------------+ +------------------+----+
| controller replica A | | controller replica B | | controller replica C |
| embedded tsnet       | | embedded tsnet       | | embedded tsnet       |
| observer + reconciler| | observer + reconciler| | observer + reconciler|
+-----+------------+---+ +---+-------------+----+ +----+-------------+---+
      |            |         |             |           |             |
      | read-only Tailnet ownership        | scoped EC2 read/ReplaceRoute
      v                                    v
+----------------------+       +-------------------------------+
| Tailscale control    |       | GWLBE subnet route tables     |
| sole PrimaryRoutes   |       | exact remote prefixes -> ENI  |
+----------+-----------+       +---------------+---------------+
           |                                           |
           v                                           v
  +------------------------------- site -------------------------------+
  | router A and router B continuously advertise the complete exact    |
  | local workload-prefix set; native Tailscale HA selects each owner  |
  |                                                                   |
  | workload -> GWLBE -> GWLB -> Envelope target -> GWLBE -> owner ENI |
  +-------------------------------------------------------------------+
```

The controller is not in the packet path. Loss of every controller leaves the last AWS route targets and Tailscale advertisements in place, but no safe automated route alignment can occur until regional authority and an observer quorum return.

## Ownership And Route Model

Every same-site production transport router continuously advertises and has enabled the complete set of exact local workload prefixes. These overlapping exact-prefix advertisements are the normal native Tailscale HA configuration, not a temporary transfer. Tailscale selects the sole `PrimaryRoutes` owner for each prefix. The controller follows that selection; it never changes router advertisements, route approval, or router preferences.

Because a standby can accept an overlapping same-site prefix into table 52, every router must have higher-priority full-prefix policy rules that select `main` and the VPC underlay for every local destination. Effective routing must then select the destination workload prefix's AZ GWLBE, independent of the receiving router AZ. Remote destinations still select accepted exact routes through `tailscale0`, and subnet-route SNAT remains disabled.

A failover domain is the smallest mutation boundary. It contains:

- One source workload prefix and its associated GWLBE subnet route table.
- The exact GWLBE subnet ID and explicit route-table association ID for that
  table. Both are immutable topology authority, not discovered mutation scope.
- Every exact remote-site destination prefix in that route table.
- The allowlisted same-site router identities and primary ENIs eligible for those routes.
- One preferred baseline owner, used only to distinguish failover from failback.

The selected Tailnet owner for the source prefix and every exact remote route's ENI target must agree. Domains may reconcile concurrently only when route tables and destination-prefix authority are disjoint. An active replica supports at most 32 domains and reserves one worker per domain so an uninterruptible ambiguous route call cannot consume another domain's lease-renewal capacity; read-only and dry-run replicas may inspect larger validated topologies with bounded shared workers.

## Reconciliation

The lease holder processes an owner change in this order:

1. Require a strict majority of fresh, topology-matching embedded observers to agree on the same sole stable-node owner.
2. Hold that agreement through the configured failover or failback stability window and cooldown.
3. Verify through the read-only Tailscale Admin API that the router advertises and has enabled the complete expected exact-prefix set.
4. Verify that the peer is online, non-expired, and healthy and that EC2 reports the instance running, both status checks healthy, and its primary ENI attached in the configured Region, VPC, subnet, and AZ.
5. Read the complete route domain and require the configured table to belong to the site's VPC with exactly one active non-main association. That association must have the topology's exact GWLBE subnet ID, route-table association ID, and route-table ID and must not be a gateway association. Reject a missing route, non-active route, wrong origin, non-ENI target, or ENI outside immutable authority.
6. Persist the transaction ID, fence, desired stable owner and ENI, complete before-snapshot, and ordered route progress before any external mutation.
7. Renew the lease immediately before each bounded `ReplaceRoute` call, refuse work inside the lease danger window, and replace only the configured exact destination prefix.
8. Read the route table authoritatively until the route is stably observed on the desired or previous allowlisted ENI, then append acknowledged progress with a fenced compare-and-swap.
9. Return to `stable` only when every exact route agrees with the sole eligible Tailnet owner.

An EC2 error or timeout after a call is ambiguous. The controller settles it with reads rather than blindly retrying. An unknown target, split route ownership, or oscillation enters durable `degraded` state and stops automatic mutation. EC2 does not accept the controller's fence token, so lease renewal, danger windows, short API deadlines, write-ahead intent, readback, and continuous reconciliation bound but do not eliminate stale external-writer risk.

The durable phases are:

```text
stable -> owner-observed -> route-intent-persisted -> routes-converging -> stable
   |              |                  |                       |
   +--------------+------------------+-----------------------+-> degraded

degraded -> stable only after quorum, eligibility, and authoritative routes agree
```

## Health Hysteresis

No observation alone authorizes a route change. The policy requires a strict-majority quorum, observation freshness covering at least two sampling intervals, unanimous owner agreement within that quorum, cloud eligibility, route agreement, and lease safety. Failover uses the shorter stability window. Automatic failback uses a longer stability window and the cooldown, reducing route churn when a preferred router flaps.

The following policy values align with the initial SLO objectives and are an initial tuning example, not protected evidence or universal defaults:

```json
{
  "replica_count": 3,
  "observation_quorum": 2,
  "observation_interval": "5s",
  "observation_freshness": "15s",
  "failover_stability": "15s",
  "failback_stability": "2m",
  "cooldown": "5m",
  "lease_duration": "1m",
  "lease_renew_interval": "10s",
  "lease_danger_window": "30s",
  "api_timeout": "5s",
  "route_convergence_timeout": "20s"
}
```

Validation requires `failback_stability` to exceed `failover_stability`, freshness to cover at least two observation intervals, and the lease danger window to cover both the API and route-convergence bounds. Lease renewal plus the danger window must remain shorter than the lease duration.

## Topology Schema

Every replica receives the same strict schema-versioned JSON document. Unknown fields, non-canonical prefixes, duplicate identities, overlapping site CIDRs, shared route tables, shared GWLBE subnet or association identities, shared route authority, out-of-site routers, and unsafe timing relationships are rejected. The canonical document hash covers each domain's `gwlbe_subnet_id` and `route_table_association_id` and is stored in every domain and observation, so changing or replacing either association identity changes authority and cannot adopt an active transaction.

Production Terraform does not attempt to reimplement Go duration normalization. The reviewed `envelope-controller-topology identity` release artifact parses a source document through the controller config package and emits one identity containing the exact base64 `CanonicalJSON` bytes, canonical SHA-256, normalized policy durations, component, revision, version, Go toolchain, and `vcs_modified=false`. Terraform consumes that identity, checks its release provenance against `controller-manifest.json`, and derives the SSM document and IAM observation keys from it. At boot, every replica downloads the architecture-matched, versioned topology tool by exact object identity and SHA-256; `verify` requires the retrieved bytes to equal Go `CanonicalJSON` and to hash to the IAM-bound value before systemd starts. Thus a valid alias such as `"2000ms"` for `"2s"` cannot silently create a different Terraform and runtime topology identity.

| JSON path | Required authority |
| --- | --- |
| `schema_version` | Exactly `1` for the current controller schema. This is separate from the packet-target topology version. |
| `deployment_id` | Stable identity for this controller deployment and its DynamoDB key space. |
| `controller_ids[]` | Exact replica IDs; count must equal `policy.replica_count`. |
| `policy` | `replica_count`, `observation_quorum`, observation interval/freshness, failover/failback stability, cooldown, lease duration/renewal/danger window, API timeout, and route-convergence timeout. |
| `dynamodb` | Exact `table` and regional `region` for durable authority. |
| `tailnet` | Tailnet `name`, optional HTTPS `control_url`, `tsnet_auth_key_env`, read-only `admin_api_key_env`, and absolute private `state_base_dir`. |
| `sites[]` | Site `id`, `vpc_id`, AWS `region`, and canonical exact `local_prefixes`. |
| `routers[]` | Router `id`, `site_id`, stable node ID, instance ID, primary ENI ID, VPC, subnet, AZ, and Region. |
| `domains[]` | Domain `id`, `site_id`, exact `source_prefix`, GWLBE `route_table_id`, `gwlbe_subnet_id`, stable explicit `route_table_association_id`, exact `remote_prefixes`, and preferred router ID. Subnet and association IDs must each be globally unique across domains. |

Topology contains environment variable names, never Tailnet secret values. Deliver the two referenced values through the deployment's secret mechanism, give each embedded observer a private state directory under `state_base_dir`, and never share that directory between replicas.

## Deployment And Handoff

1. Build from a clean reviewed revision with the pinned Go toolchain. Retain `controller-manifest.json`; select the controller and topology-tool entries for one architecture; upload both as immutable versioned objects; and retain exact object keys, version IDs, and SHA-256 values. Generate the topology identity with that reviewed topology tool, never by hand.
2. Select an exact AMI through an explicit trusted AWS account allowlist. Require the AMI and instance type to agree with the manifest architecture and require an available EBS-backed HVM image. Separately qualify the AMI's systemd, AWS CLI, curl, ext4, and GNU utility contents because EC2 image metadata cannot attest packages.
3. Provision the regional DynamoDB table with encryption, point-in-time recovery, deletion protection, string partition and sort keys named `pk` and `sk`, and TTL named `ttl`. TTL applies only to stale observation garbage collection and never decides lease correctness.
4. Establish resilient private management egress and deploy at least three controller replicas in independent failure domains. For the supported NAT contract, every private subnet has a unique explicit route table and unique available public NAT in the same AZ; the NAT subnet has an explicit default route through an Internet gateway attached to the VPC. Validate the complete path from live AWS data, not tags or documentation, and do not colocate a replica process on a packet target or transport router.
5. Give each replica a unique allowlisted controller ID, private persistent `tsnet` state, AWS workload identity, and secret references. The controller needs no packet-processing, `CAP_NET_RAW`, or `CAP_NET_ADMIN` privilege.
6. Configure a real external readiness publisher identity, private scrape-source CIDRs, bounded sampling interval, exact metric dimensions, and at least one alarm action before rollout. Missing readiness data must alarm.
7. Configure every same-site router with complete overlapping exact-prefix advertisements and higher-priority full-prefix local-main policy. Verify native owner selection, no-NAT transit, destination-prefix GWLBE routing, and distinct eligible ENIs before route handoff.
8. Start all replicas in `--read-only` mode with the reviewed topology. Require matching topology hashes, fresh observer publication, quorum, owner eligibility, and exact route agreement.
9. Mark only current ENI targets as controller-owned dynamic state while infrastructure management continues to own route tables, exact GWLBE subnet associations, destination prefixes, and eligible ENI sets. Resolve each GWLBE subnet in the domain Region, require it and its route table to match the topology site's VPC, and require exactly one explicit non-main association with the configured subnet and association IDs. Grant route writes only after a reviewed plan shows no route-shape drift.
10. Enable active reconciliation for a limited domain set, observe a complete stability window, then expand. Acceptance tooling may inject faults and collect evidence, but it must not supply runtime ownership observation or mutate routes for the controller.

A normal process invocation is:

```bash
/usr/local/bin/envelope-controller \
  --controller-id=controller-a \
  --topology=/etc/envelope/controller-topology.json \
  --metrics-addr=127.0.0.1:9091 \
  --log-level=info
```

Use `--dry-run` to evaluate without durable or cloud mutation, or `--read-only` to inspect existing durable and cloud state without acquiring leases. The modes are mutually exclusive. Bind operational endpoints only to loopback or a private address.

The deployment root validates but does not provision the AMI, artifact bucket, NAT gateways, route tables, Internet gateway, readiness collector, collector policy, or alarm destinations. Its built-in egress contract intentionally supports distinct same-AZ public NAT paths because the embedded Tailnet observer and DERP need non-AWS HTTPS reachability. An endpoint-only design must explicitly provide and validate that external Tailnet path in addition to AWS service endpoints; AWS VPC endpoints alone are not evidence of complete controller egress.

## Protected Controller Conformance

The manual-only `.github/workflows/aws-two-region-e2e-live.yml` invokes `scripts/aws_controller_acceptance.py` in separate deployment, observation, quiescence, and cleanup jobs. Offline implementation is not approval to execute it. Deployment and observation require isolated `envelope-production-deployment` and `envelope-production-observation` runner groups, distinct protected environments, and private endpoint reachability. The [external IAM setup and inspected recovery runbook](../deploy/terraform/controller-acceptance/README.md) specifies OIDC customization, role trust, permissions, protected environments, retained prerequisites, failure handling and manual recovery without lock adoption.

The configuration secret is `ENVELOPE_PRODUCTION_CONTROLLER_SPLIT_CONFIG_TEMPLATE_B64`. GitHub OIDC subject customization must include repository, environment, exact workflow/ref, run ID, and attempt. The deployment phase publishes exact-version claim/handoff references and encrypted private recovery checkpoints, unconditionally freezes the deployment/lifecycle roles and deployment OIDC issuer, and denies cleanup sessions issued before the observer drain deadline. This closes the session-issuance race during handoff preparation. Observation verifies ownership and policies before faults; it has no deployment secrets or state access. Live schema 3 is separate from `integration-only` results generated from actual Go test events.

Quiescence waits until the observer issuance cutoff plus its maximum one-hour session lifetime, restores routers, stops controllers, and checks unchanged journals through a complete lease/action drain. Its role cannot restart controllers. Cleanup rechecks quiescence before acquiring privileged credentials and requires two consecutive zero-residual audits before finalization. Failed or interrupted cleanup retains claims and forensic state. The workflow does not delete local run directories or encrypted recovery snapshots, even after success. Partial controller deployments without quiescence require inspected recovery, not automatic adoption by a later invocation.

`scripts/test_controller_acceptance_phases.py` exercises production phase orchestration with mocked external I/O, including raw AWS/HTTP observation records, exact S3 versions, IAM revocation, private checkpoint restoration, pinned lifecycle requests, stop/restart faults, quiescence, ordered cleanup and bundle consistency. Observation/application fixtures are explicitly offline; Go integration separately tests production reconciliation. Do not infer live readiness from these tests or execute task 9.5 without separate approval. Effective account IAM, native Linux attestation and real AWS/Tailscale behavior remain live verification prerequisites.

### Legacy Scaffold

The following describes the superseded combined-evidence runner, not the current split workflow. Its capability gate remains closed and its command is not an alternative live procedure.

The old ignored config used the protected `ENVELOPE_PRODUCTION_CONTROLLER_CONFIG_TEMPLATE_B64` secret. The scaffold requires `symmetric_topology.version` 3 and separate state paths at `runs/<run-id>/appliance/terraform.tfstate` and `runs/<run-id>/controller/terraform.tfstate`. Version-2 state, plans, manifests, and evidence are never reused. The earlier Python orchestrator remains isolated as the explicit legacy-v2 runner.

The currently blocked acceptance AWS session explicitly denies every route and route-table-association actuator: `AssociateRouteTable`, `CreateRoute`, `DeleteRoute`, `DisassociateRouteTable`, `ReplaceRoute`, and `ReplaceRouteTableAssociation`. `ENVELOPE_RUNNER_ROUTE_MUTATION_DENIED=true` records that workflow gate, but it does not grant authority or prove the effective policy by itself. The runner command guard independently rejects the same direct AWS CLI operations even when AWS global options precede them, and rejects `tailscale set`, `tailscale up`, advertisement, route, or preference mutation. Remote SSM commands are allowlisted to the dedicated workload instances; the runner never executes on packet targets, transport routers, or controller replicas.

One session cannot both retain that deny and create or destroy the appliance route graph. This is why the old scaffold cannot be enabled and the split implementation above is required. Do not weaken the deny or treat the local mutation ledger as proof that Terraform-provider calls were absent.

Runner-only Tailnet management uses `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET` to create and revoke the ephemeral router bootstrap key and to list or delete run-owned devices. Controller runtime credentials use separate protected inputs: `ENVELOPE_CONTROLLER_TSNET_AUTH_KEY` for the three persistent embedded observer identities and `ENVELOPE_CONTROLLER_ADMIN_API_KEY` for read-only Admin API validation. The tsnet key must be reusable, preauthorized, and restricted to the reviewed controller tag because all three replicas create independent persistent identities from it. The workflow writes those values to invocation-tagged run-owned SecureString parameters under the configured controller KMS key, passes only parameter names and ARNs to Terraform, excludes the values from child environments, and retains only hashed references in evidence. Parameter creation, deletion, and residual audit require bounded stable invocation-tagged visibility or stable absence; an ambiguous or inconsistent result fails cleanup. Operational response bodies are reduced to allowlisted reasons and redacted against every Tailnet and temporary AWS session credential before truncation. Scanner-rejected evidence is never written or uploaded. The Admin API credential must be read-only; neither controller credential may approve routes or change advertisements.

The current runner still uses the older combined-evidence contract, requiring deterministic observer disagreement, an in-progress leader barrier, stale-fence receipts, and ambiguous-call injection. It cannot produce passing task 9.5 evidence and must stop at capability preflight. The approved replacement does not require production fault-injection endpoints: those precise cases remain separately labeled simulated evidence in `internal/controller/integration`. Do not enable the old runner by changing unavailable capabilities to true. Real live evidence must independently prove router and leader failure/recovery, lease renewal, native owner selection, route convergence, durable alternate ownership, failback, fresh TCP/UDP retries, and cleanup. The following is the old scaffold's sequence, not an implemented or approved live procedure:

1. Build clean, reviewed packet and controller artifacts with the pinned toolchains, deploy the version-3 appliance, derive explicit controller authority from the nonsecret Terraform seed, and bind stable Tailnet node IDs to the reviewed router instances and ENIs.
2. Upload the controller and topology tool as exact versioned objects, generate the topology identity with the reviewed Go tool, and deploy all three replicas in read-only mode with no route-table write resources.
3. Require cold read-only observations, empty domain state, fresh observer quorum, private endpoint health, and baseline Tailnet/AWS route agreement before promoting the controller IAM policy to exact active route-table ARNs. Retain a same-fence lease renewal across a complete renewal interval.
4. Start established TCP and UDP samples on dedicated workloads, stop the selected native Tailnet owner through EC2, retain a real observer-disagreement interval with unchanged routes, and stop the current controller lease holder only while a durable route transaction is held at the reviewed in-progress barrier.
5. Require a distinct successor with a higher fence to settle the journaled transaction, then retain stale-fence rejection and injected ambiguous-call settlement receipts. Prove fresh TCP and acknowledged UDP retries only after repeated authoritative route convergence and retain the alternate as durable stable state.
6. Restart the failed router, observe the preferred owner without an early route rewrite through the failback gate, wait for the longer failback stability and cooldown policy, and prove fresh flows again after stable failback. Established-flow results use bounded agent output to classify survived, reset, or timed out; they are never inferred from SSM status or converted into a hitless or lossless claim.

On every handled terminal path the runner restores an outstanding router fault through the EC2 stopping/stopped transition and retains restoration intent until repeated exact reads prove the instance running, rolls active controllers back to read-only, waits one lease duration, destroys the controller deployment, deletes controller parameters and exact artifact versions, destroys the appliance, removes run-owned Tailnet devices and keys, performs zero-residual AWS/SSM/Tailnet audits, and only then deletes both backend state keys and lock objects. `protected_acceptance_mode=true` is accepted only with exact `EnvelopeRun` and canonical `ExpiresAt` tags; it disables DynamoDB deletion protection and final observer snapshots and uses AWS-managed storage encryption so this short-lived exercise can leave zero residual resources. This mode is default-off and must not be used for production retention.

Abrupt process or runner loss is not automatically recoverable in the current implementation. An existing backend claim is never adopted, and `run-all` is not a cleanup-recovery command. Immediately after this invocation attempts its conditional claim write, a lost response may be reconciled only by reading the single exact object version and matching its complete body to the invocation; a matching claim arms cleanup, while any unresolved outcome preserves failed cleanup state. This does not authorize adoption on a later invocation. The self-hosted checkout preserves a failed `.run/<run-id>` directory as mode-restricted forensic state and every same-ID invocation refuses to overwrite its config or evidence. Keep the runner quarantined and use a separately reviewed manual cleanup procedure; do not delete the claim, rerun the ID, or interpret retained files as cleanup authority. Successful upload plus semantically complete zero-residual cleanup, or exact not-required cleanup before any claim, removes the local directory.

The retained schema-2 bundle kind is `aws-production-controller-v3`. A passing bundle must prove read-only-before-active ordering, every failover domain at every stage, exact GWLBE subnet and route-table association authority, immutable artifact versions, higher-fence leader handoff, durable alternate ownership, stability-gated failback, fresh TCP and UDP recovery, bounded established-flow outcomes, zero runner route/advertisement calls, no target/router remote execution, and ordered zero-residual cleanup. `validate-evidence`, `verify-evidence`, and `scan-evidence` are separate fail-closed commands. Controller-owned live evidence remains pending until task 9.5 executes this workflow on one clean protected revision.

The superseded scaffold command used one lifecycle owner:

```bash
python3 scripts/aws_production_controller_e2e.py run-all \
  --config ".run/${RUN_ID}/config.json" \
  --appliance-terraform-dir example/terraform \
  --controller-terraform-dir deploy/terraform/envelope-controller \
  --hard-timeout-seconds 10800 \
  --aws-role-duration-seconds 21600 \
  --job-timeout-seconds 21600
```

The hard timeout bounds acceptance work. The runner atomically replaces it with a separately reserved cleanup deadline, defers termination during cleanup, and requires the acceptance, cleanup, and setup margins to fit the six-hour role session and job budget. Cleanup uses shorter explicit Terraform command bounds than deployment and must contain one read-only controller apply, both Terraform destroys, Terraform initialization and output bounds, one full lease wait, and the non-Terraform API margin. The workflow must not add a competing destroy trap for cloud resources. Only after sanitized evidence upload succeeds does the always-running local step independently require the exact cleanup sequence, every completion flag, every ordered zero-residual audit, backend finalization, and no cleanup errors before removing `.run/<run-id>`; exact not-required cleanup is permitted only before a claim. Upload failure, semantic inconsistency, uncertainty, or incomplete cleanup preserves the run directory as forensic state.

## IAM And Secrets

Use a dedicated controller role. Its minimum API surface is:

| Service | Allowed use |
| --- | --- |
| DynamoDB | Strongly consistent `GetItem` for the exact domain item and one bounded read per configured observer partition, plus conditional `PutItem` in the IAM-bound key space. No shared-partition `Query` is granted. With the production customer-managed key, `kms:Decrypt` is restricted to regional DynamoDB and the exact table/account encryption context. Operational table inspection may use a separately reviewed read role. |
| EC2 read | `DescribeInstances`, `DescribeInstanceStatus`, `DescribeNetworkInterfaces`, and `DescribeRouteTables` for configured identities. Apply resource and condition scoping where AWS supports it. |
| EC2 write | `ReplaceRoute` only on the configured GWLBE route-table resources. IAM does not express the complete destination-prefix and eligible-ENI relationship, so strict topology validation and route readback enforce that narrower application boundary. Explicitly deny unreviewed route tables. |
| Tailscale | A per-replica embedded-node credential plus a separate Admin API credential restricted to read-only device and route validation. |

Do not grant the controller packet or host-network capabilities. Packet-target and transport-router roles retain no route-mutation permission; do not grant them DynamoDB lease access or EC2 route replacement. Keep break-glass route authority in a separate audited operator role. Logs and metrics must contain bounded topology IDs and reasons, never auth keys, node keys, credential-bearing responses, or raw provider errors.

Readiness publication uses a separate existing IAM role, not a controller role. Production inputs identify its exact role name and ARN, stable publisher ID, private source CIDRs, and scrape interval. Terraform resolves the role and binds `PublisherId` into each alarm's metric dimensions, but deliberately does not manage that external role's policies or collector process. Before rollout, independently verify that only the approved publisher can use `cloudwatch:PutMetricData` for the configured non-AWS namespace and that it emits exactly one bounded sample per replica and interval.

The deployment output gives the publisher each replica's private address, `/readyz` path, and exact dimensions. Treat that output as the handoff contract; do not discover targets by broad tags or publish one aggregate value for the replica set.

## Operational Endpoints

- `GET /healthz` is process liveness. Do not use it as proof of quorum or route safety.
- `GET /readyz` fails closed for observer, store, freshness, domain, lease, quorum, eligibility, degraded-state, or route-agreement failures. A confirmed follower can be ready without claiming leadership.
- `GET /metrics` uses a private Prometheus registry and exposes the `envelope_controller_*` families for observer and store health, observation age, lease/fence state, owner/quorum, route agreement and progress, phases, failover/failback, ambiguous calls, and bounded API errors.

Alert on sustained readiness failure, observation age near freshness, missing quorum, lease danger, any degraded domain, unauthorized or disagreeing routes, ambiguous calls, API errors, long phase duration, and a mismatch between stable, observed, and consensus owners. The HTTP surface is private and operational only; it has no route-mutation endpoint.

Every production alarm has one or more explicit action ARNs. A configured alarm with no notification or incident action is rejected rather than treated as observability. The readiness alarm uses exact `DeploymentId`, `ControllerId`, and `PublisherId` dimensions; value `1` means HTTP 200, value `0` means any explicit not-ready result, and missing data is breaching.

## Durable Failover And Automatic Failback

A successfully selected alternate becomes normal durable `stable` state. Process restart, replica replacement, or a new lease holder resumes from that owner and journal; no completion handler unconditionally restores the preferred baseline.

If native Tailscale HA later selects the healthy preferred owner, the controller treats that as a new transaction. It waits through cooldown and the longer `failback_stability` interval, rechecks observer quorum and cloud eligibility, persists new fenced intent, and reconciles the exact routes. If Tailscale continues to select the alternate, the AWS routes remain on the alternate.

## Degraded Recovery

`degraded` is fail-closed, not a request to restart everything or force the preferred owner. Use this sequence:

1. Identify the affected domain, bounded reason, fence, lease holder, observed/consensus/stable owners, route progress, and topology hash from private health, metrics, and durable state.
2. Freeze topology and infrastructure changes. If manual intervention is required, replace the active rollout with read-only replicas or stop every active replica, then wait at least one full lease duration and verify that no holder can mutate.
3. Restore the prerequisite first: regional DynamoDB access, fresh observer quorum, Tailnet health and sole owner, or EC2 instance/ENI eligibility. Transient observation and eligibility failures clear automatically only after authoritative routes already agree with the eligible owner.
4. For an ambiguous or partial route result, use read-only Tailnet and EC2 observations to determine the sole eligible owner. First require the route table's exact configured GWLBE subnet association; do not repair routes while its subnet, association ID, table ID, main flag, or VPC differs. If association authority agrees but routes do not all select that owner's allowlisted ENI, use the separate audited break-glass role to align only the domain's configured exact routes. Never point a route at an unknown ENI, edit lease records by hand, or delete the journal.
5. Restart in read-only mode and require fresh quorum, exact route agreement, and a matching topology hash. Then restore active replicas and verify the domain returns to `stable`; revoke break-glass access and retain the incident timeline.

Regional authority loss makes every replica not ready and prohibits route mutation. Existing data-plane state may continue to carry traffic, but operators must not infer that it remains correct. Restore the same regional table and strongly consistent access rather than creating an unfenced replacement authority.

## Rollback

Rollback is a quiescent ownership transfer, not a blind rewrite to the preferred ENI:

1. Roll all replicas to `--read-only` or stop them, wait at least one full lease duration, and confirm no active mutation can start.
2. Settle every in-progress or ambiguous transaction. Require each domain to have one eligible Tailnet owner and every exact route on that owner's allowlisted ENI.
3. Preserve the DynamoDB table, point-in-time recovery, topology document, and observer state until rollback verification and incident retention complete.
4. Revoke the controller's `ReplaceRoute` authority, then return current ENI target ownership to the reviewed infrastructure workflow without changing route-table, explicit GWLBE subnet association, or prefix shape. Replacing an association creates a new topology identity and requires a quiescent migration.
5. If reverting to a singleton-advertisement topology, change advertisements only after controller shutdown and route/Tailnet agreement. Treat it as a breaking migration with fresh state; do not reuse prior acceptance state or evidence.
6. Remove controller replicas and credentials last. Verify packet-target roles and router roles still have no route-mutation permission.

An older controller binary may resume only when it understands the exact persisted schema and topology hash and no active transaction requires newer semantics. Otherwise remain read-only and perform a reviewed quiescent migration.

## Regional Authority Limit

The DynamoDB table is multi-AZ within one configured AWS Region but is not a multi-Region consensus system. Loss or isolation of that authority Region stops safe election and mutation. Eventually consistent DynamoDB Global Tables are not a lock, and adding replicas in another Region does not create safe cross-Region authority. Multi-Region control requires a separately designed strongly consistent authority and disaster-recovery procedure.

## Proposed SLO Boundaries

All values in this section are **initial objectives pending protected controller evidence**. They are not current production SLOs, and they must not be promoted or loosened without retained evidence from controller-owned failure injection. Measure per failover domain at p99 for supported single-router or single-controller-failure events with regional DynamoDB, AWS APIs, Tailscale control, an observer quorum, and an eligible alternate available.

| Boundary | Clock starts | Clock stops | Initial objective |
| --- | --- | --- | --- |
| Failure detection | Fault injection or first externally observable router failure. | A fresh observer quorum excludes the failed owner as online, healthy sole primary. | p99 at or below **15 seconds**. |
| Native ownership | Detection boundary stops. | A fresh quorum agrees on the same sole eligible `PrimaryRoutes` owner continuously through `failover_stability`. | p99 at or below **45 seconds**. |
| Exact route convergence | Fenced route intent is durably persisted. | Every configured exact route is active on the desired allowlisted ENI, stable readback succeeds, and progress is durable. | p99 at or below **30 seconds** per domain. |
| Fresh-flow recovery | Exact route convergence stops. | A fresh TCP connection completes an idempotent transaction and a fresh retryable UDP message receives its matching ACK. | p99 at or below **15 seconds**; composite detection-to-recovery at or below **105 seconds**. |
| Established TCP outcome | Fault injection. | Each sampled pre-existing connection is classified as survived, resumed, reset, timed out, or right-censored. | **No survival objective: 0% minimum. Up to 100% may require reconnect.** Report outcomes; do not call this hitless continuity. |
| Permitted raw UDP loss | Fault injection. | Fresh-flow recovery stops. | **Up to 100% of unacknowledged datagrams in the fault-to-recovery interval may be lost, duplicated, or reordered; that interval has the initial 105-second composite objective.** Report exact counts. Exceeding 105 seconds is an SLO breach, not a delivery promise; there is no lossless UDP objective. |

Detection, ownership, route convergence, and fresh-flow recovery are separate clocks. Do not hide a slow stage inside a single aggregate. Events without regional authority, quorum, or an eligible alternate are control-plane-unavailable events, not successful samples. Established-flow survival and raw UDP delivery are observations, not Envelope repair guarantees.

Applications that need durable outcomes must implement the [application resilience contract](application-resilience.md).
