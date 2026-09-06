# Envelope Controller Terraform

This Terraform 1.10.x root deploys exactly three standalone
`envelope-controller` EC2 replicas in three supplied private subnets and
availability zones. It does not create Envelope packet targets, transport
routers, acceptance helpers, or GWLBE routes.

The native router attestor validates policy routes, legacy IPv4/IPv6 firewall,
no-NAT, live MSS, and destination-prefix GWLBE forwarding. Runtime eligibility
requires a fresh signed report bound to the complete collector configuration.
Unknown or unsupported state is rejected. The separate router enrollment root
and appliance bootstrap install the pinned binary/config and provision exact
source-instance access to per-router seeds. Do not interpret a successful plan
or process health endpoint as forwarding readiness or live execution approval.

## Boundary

- Each replica receives its own controller role/profile, and no controller
  identity is assigned to a packet target or transport router.
- Each role can read the exact authority table, versioned controller and
  topology-verifier artifacts, topology parameter, and two existing secret
  parameters. KMS decrypt is restricted to each secret's key, exact SSM
  encryption context, account, and regional SSM service. Both release objects
  are selected by component and architecture from one hash-pinned clean-build
  manifest.
- DynamoDB reads are restricted to the deployment domain partition and every
  configured deployment/topology/controller observation partition. Each
  replica's observation `PutItem` is restricted to only its own partition;
  domain `PutItem` is present only in active mode. Artifact access is restricted
  to the exact S3 object ARN and version ID, and object keys containing IAM
  wildcard or control characters are rejected.
- EC2 inventory calls are read-only and Region-bounded. In active mode only,
  `ec2:ReplaceRoute` is split by Region and scoped to the exact supplied
  route-table ARNs. IAM cannot restrict `ReplaceRoute` by destination CIDR or
  target ENI, so strict topology, live route-table checks, and controller
  readback enforce those dimensions.
- The root creates no `aws_route` resources. Existing route targets remain
  dynamic controller state after handoff.
- Controller instances keep source/destination checks enabled and receive no
  packet-processing or network-administration capability.

## Prerequisites

- Terraform `>= 1.10.1, < 1.11.0`.
- AWS provider `6.33.0`, which supports per-data-source Regions for validating
  route tables in every topology Region.
- Three existing private subnets in one controller VPC and three unique AZs.
  `map_public_ip_on_launch` must be false. Each must use a distinct explicit
  route table whose only IPv4 default selects a distinct available public NAT
  gateway in the same AZ. The NAT subnet's explicit route table must have one
  IPv4 default through an available Internet gateway attached to the VPC. The
  root validates the complete path rather than accepting an egress assertion.
- An exact reviewed Linux AMI and nonempty trusted publisher-account allowlist.
  `data.aws_ami` resolves owner, selected architecture, `ebs` root device, `hvm`
  virtualization, and `available` state. The instance type must support the
  same architecture. AWS image metadata cannot attest packages, so the AMI must
  separately be qualified with systemd, AWS CLI v2, curl, `base64`, `blkid`,
  ext4 tools, and normal GNU user/filesystem utilities.
- Immutable, versioned S3 controller and `envelope-controller-topology`
  executables plus exact `controller-manifest.json` bytes and a reviewed hash.
  Both objects must be readable with `s3:GetObjectVersion`; use SSE-S3 unless an
  independently reviewed artifact KMS permission is added. Terraform rejects a
  dirty build, wrong component/file/hash, architecture mismatch, source
  revision mismatch, version mismatch, or unreviewed Go toolchain.
- Existing TSNet auth and read-only Tailscale Admin API SecureString parameters
  in the controller Region. Supply only each parameter's name, ARN, and KMS key
  ARN, never its value.
- Existing GWLBE route tables, their exact explicit subnet associations, and
  exact remote-prefix routes. Each table must have exactly one non-main
  association to its declared GWLBE subnet and association ID, the subnet and
  table must belong to the declared site VPC, and every current route target
  must already be one of the declared same-site eligible router ENIs before
  this root can plan.
- A real external readiness collector IAM role, private source CIDRs, and
  scrape interval, plus at least one alarm action ARN. This root resolves but
  does not provision or grant permissions to the collector.

## Inputs

The important fail-closed inputs are:

- `deployment_mode`: defaults to `read-only`. `active` must be explicitly set
  before controller processes and IAM can mutate domain authority or routes.
- `controller_ids` and `controller_placements`: exactly three matching keys,
  unique subnet IDs, and unique AZs.
- `topology_identity_json`: exact identity emitted by the reviewed
  `envelope-controller-topology identity` command. It carries base64 canonical
  bytes, canonical SHA-256, clean release provenance, and Go-normalized policy
  durations. Terraform checks those durations against the decoded document and
  uses the canonical hash for IAM keys. Do not hand-author this identity.
- `artifact_manifest_json` and `artifact_manifest_sha256`: exact reviewed clean
  release manifest bytes and digest. Terraform also reads
  `scripts/reviewed-go-toolchain.txt` and requires matching provenance.
- `controller_architecture`, `artifact`, and `topology_identity_artifact`: the
  selected `amd64` or `arm64` release and exact Region, bucket name/ARN, object
  key/ARN, version ID, and content SHA-256 for both manifest-selected binaries.
- `controller_ami_id` and `controller_ami_trusted_owner_ids`: exact AMI identity
  and one or more explicitly trusted publisher accounts.
- `management_egress`: one entry per replica naming its private route table,
  same-AZ NAT gateway/subnet, NAT-subnet route table, and Internet gateway.
- `secret_parameters`: exact existing TSNet/Admin SSM names and ARNs plus their
  exact KMS key ARNs.
- `router_attestations`: required explicit enrollment for every topology router,
  with a unique lowercase Ed25519 public key, required `configuration_sha256`, and private HTTPS endpoint. The
  root binds these to the topology hash and writes a content-addressed public
  SSM document; boot fetches exact version 1, checks its SHA-256, and installs it
  root-owned mode 0444. TLS and report signatures must match the enrolled key.
  Do not infer enrollment authority from a router's signed identity claims.
- `deployment_lifecycle`: optional explicit trusted deployment-role principals
  and ExternalId. This provisions a separate route-denied lifecycle role with
  conditional domain/lock access and no observation publication permission.
  Its optional `rollout` block supplies the exact state bucket/key and KMS ARNs
  required for one-replica saved-plan replacement. Actual principal ARNs and
  key references are deployment inputs, not assumed external infrastructure.
- `managed_route_tables`: one entry per topology domain with exact Region, VPC,
  route-table ID/ARN, GWLBE subnet ID, route-table association ID, source
  prefix, complete remote destination set, and every eligible same-site router
  ENI. Subnet and association identities are unique across domains.
- `transport_topology`: one entry per site and router. Every router must expect
  the site's complete exact local-prefix set as advertised, enabled, and
  local-main-routed, and must accept the complete exact remote-prefix set. The
  local-main priority range must precede the Tailscale table-52 rule priority.
- `readiness_publisher` and `alarm_actions`: exact collector ID, IAM role
  name/ARN, allowed private scrape CIDRs, sampling interval, and nonempty
  notification destinations.

`tests/fixtures/topology.json` and `tests/controller.tftest.hcl` show a complete
fake two-site input. The IDs are test-only.

## Usage

Build from a clean reviewed revision. The builder emits controller, topology,
deployment lifecycle, and router attestor components for each selected
architecture in one manifest. On a compatible release runner,
use the manifest-selected topology binary to convert a reviewed source topology
into the only topology input Terraform accepts:

```sh
scripts/build_controller_artifacts.sh --output-dir dist/controller --version 1.2.3
dist/controller/envelope-controller-topology-linux-amd64 identity \
  --input controller-topology.source.json > controller-topology-identity.json
```

Upload both selected binaries as immutable versioned objects, retain their
version IDs, and review the manifest and all SHA-256 values. Provide reviewed
values through the normal noncommitted variable mechanism, then run:

```sh
terraform init
terraform plan -out=controller.tfplan
terraform show controller.tfplan
terraform apply controller.tfplan
```

The first apply should omit `deployment_mode` and therefore install all three
replicas read-only. Initialize journals with `envelope-controller-deploy
initialize` under its restricted STS session, using the lifecycle role output and
configured ExternalId. Confirm observer quorum and attested route agreement
before staging the reviewed active IAM policy. Keep domains inactive while
rolling replicas individually through `envelope-controller-deploy rollout` and
then use `activate --domain ID`. Mode is immutable user data: do not apply a
shared mode/artifact change that replaces all three replicas simultaneously.
The rollout command validates the complete saved plan, not merely `-target` or
Terraform parallelism. It rejects IAM/route mutations and multi-replica changes.

Lifecycle locks have no expiry or automatic takeover. Activation and migration
use lock-checked DynamoDB transactions; deactivation fences stale controller
writers and requires an unchanged complete lease/action window. Failures retain
locks and journals rather than silently unlocking or replacing active progress.
Migration currently supports only the same deployment, regional table, and
domain-ID set, with both old/new observation and attestation generations supplied.
See [the lifecycle runbook](../../../docs/production-controller.md#locked-lifecycle-operations)
for command flags, health gates, bounded policy support, and recovery limits.

`protected_acceptance_mode` is a separate, default-off lifecycle switch for the
short-lived controller conformance workflow only. It requires exact
`EnvelopeRun` and `ExpiresAt` tags, uses AWS-managed storage encryption, turns
off DynamoDB deletion protection, and suppresses final observer-volume
snapshots so a protected run can prove zero residuals. Do not enable it for a
production deployment; normal mode retains the dedicated rotated CMK, protected
authority table, and final observer-state snapshots.

Configure an approved remote backend before team operation. This root does not
embed backend credentials or settings.

Planning reads each declared route table and GWLBE subnet in its own Region. It
fails if either resource is in the wrong VPC, the table does not have exactly
one explicit non-main association matching the configured subnet and stable
association ID, an exact destination is absent or duplicated, a more-specific
route shadows that destination, or the current target is not an eligible ENI.
The `dynamic_route_ownership` output records association and route shape,
eligible targets, observed targets, topology hash, and the explicit fact that
Terraform does not own current target selection. A later plan observes a valid
controller-selected alternate without restoring the preferred baseline.

## Bootstrap

Terraform stores the nonsecret topology in an advanced SSM String parameter.
User data contains parameter/object identities and hashes only. At boot it:

1. Retrieves and hashes the topology document.
2. Downloads the exact version of the manifest-selected topology tool, verifies
   its SHA-256, and runs `verify`. The tool uses the controller config package,
   requires the bytes to equal `CanonicalJSON`, and checks the canonical hash
   before systemd can start. A valid but noncanonical alias such as `2000ms` for
   `2s` fails bootstrap instead of binding runtime DynamoDB access to a
   different hash.
3. Downloads the exact controller S3 object version and verifies its SHA-256.
4. Waits for the replica's separately managed encrypted EBS volume, mounts it
   at `/var/lib/envelope-controller`, and creates the topology-selected private
   TSNet state directory.
5. Fetches both SecureStrings once and writes all process configuration to a
   root-owned mode-`0400` systemd environment file. Secret values are accepted
   only when they can be represented without environment-file metacharacters.
6. Installs the repository's hardened systemd unit with no fallback or drop-in.
   The effective service directly executes `/usr/local/bin/envelope-controller`;
   it has no runtime shell wrapper or `ExecStartPre`.

Secret values are never Terraform variables, topology fields, state values,
tags, user data, command-line arguments, or logs. Persistent observer volumes
survive instance replacement within their fixed controller/AZ slot. Moving a
slot to another AZ replaces its EBS volume and requires an explicit identity
migration decision.

## Authority Store

The authority table uses `pk`/`sk` string keys, on-demand billing, CMK
encryption with rotation, point-in-time recovery, deletion protection, and TTL
attribute `ttl`. TTL is only the controller's observation garbage-collection
mechanism; lease correctness uses strongly consistent reads and conditional
writes.

The Go key layout gives every observer its own partition key,
`observations#<deployment>#<topology-hash>#<controller-id>`, with
`controller#<id>` as the sort key. Listing performs exactly one strongly
consistent `GetItem` for each configured controller in deterministic controller
ID order; it never queries a shared partition. The configured controller bound
therefore also bounds DynamoDB calls and returned data.

Every per-replica role can `GetItem` all configured observation partitions for
quorum evaluation, but its observation `PutItem` condition names only that
replica's partition through `dynamodb:LeadingKeys`. Because the claimed
controller ID selects the partition key, a process using controller-a's AWS
credentials and claiming controller-b attempts controller-b's partition and is
denied by IAM. The item decoder also requires the partition, sort key, metadata,
and JSON controller identity to agree. This binds observations to AWS role
credentials and immutable topology identity without observation signatures.

## Alarms

The root creates per-replica EC2 status alarms and table-scoped DynamoDB
`ReadThrottleEvents` and `WriteThrottleEvents` alarms. Because DynamoDB emits
`SystemErrors` only for a `TableName`/`Operation` dimension pair, its error alarm
uses metric math over the exact `GetItem` and `PutItem` operations.

It also creates one fail-closed custom ready alarm per replica. The Go process
exposes `/readyz` but does not publish CloudWatch metrics, and its IAM role
intentionally lacks `cloudwatch:PutMetricData`. The exact external role from
`readiness_publisher` must scrape from one of its declared CIDRs, each of which
must also appear in `metrics_ingress_cidrs`, and publish value `1` for HTTP 200
and `0` otherwise at the declared interval. It must use namespace/metric from
`controller_ready_metric` and exact dimensions `DeploymentId`, `ControllerId`,
and `PublisherId`. Missing data is breaching, and every alarm has at least one
action. The complete identity and sampling contract is exported as
`controller_ready_metric_assumptions`, including each private target address,
path, and exact dimensions.

## Deliberate Limits

This root validates but does not create NAT gateways, route tables, Internet
gateways, the readiness collector, its `cloudwatch:PutMetricData` policy, alarm
destinations, the artifact bucket, or the AMI. Endpoint-only private egress is
not modeled because the embedded Tailnet observer and DERP path require an
explicitly designed non-AWS HTTPS path; add such a path as a reviewed extension
rather than silently treating AWS service endpoints as complete egress.

## Validation

No validation command requires an AWS API call except an actual plan's intended
read-only subnet, VPC, and route-table checks:

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
python3 ../../../scripts/test_controller_terraform.py
python3 ../../../scripts/test_controller_artifacts.py
python3 ../../../scripts/test_docs.py
```
