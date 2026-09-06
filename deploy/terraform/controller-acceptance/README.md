# Protected Split Acceptance

This root creates only the invocation-bound observation and quiescence roles.
`scripts/aws_controller_acceptance.py` coordinates deployment, handoff, measured
acceptance, quiescence, and cleanup. The production Go controller owns runtime
route reconciliation. Neither these Terraform roles nor the observer may change
routes, approve advertisements, execute on routers/controllers, or assume another
role. Workload-only SSM is permitted for application probes.

**Offline verification is not approval for a billable run. Task 9.5 remains
pending.** Commands below are operator setup/recovery instructions, not commands
executed by the offline test suite. Use a dedicated sandbox AWS account and the
reviewed `_lbr_sandbox` Tailnet, never an account containing production workloads.

## External Prerequisites

An account administrator, independent of the runners, must provision/review:

1. A GitHub OIDC provider for `https://token.actions.githubusercontent.com` with
   audience `sts.amazonaws.com`, in the same account as both privileged roles.
2. Separate deployment and cleanup roles. Deployment needs a six-hour maximum
   session; cleanup needs at least three hours. Do not use instance profiles,
   credential files, role chaining, access keys, or ambient runner credentials.
3. A private, encrypted, versioned S3 backend bucket, its customer-managed KMS
   key, and a separate private versioned artifact/evidence bucket. Public
   authority objects use SSE-KMS with S3 bucket keys disabled so the encryption
   context identifies each object, not the whole backend bucket. Evidence uses
   SSE-S3. Do not grant the observer backend prefix-wide access.
4. The explicitly configured AMIs, KMS keys for SecureStrings, private controller
   VPC/subnets and independent management egress, existing readiness publisher,
   alarm destinations, and private management routing to both appliance sites.
   Enrollment ingress includes the observed controller subnet CIDRs and the
   configured management/metrics client CIDRs. No public attestor ingress.
5. Reviewed Tailnet ACLs and route auto-approval for the exact sandbox prefixes,
   router tag and controller tag. Controller Admin API credentials are read-only;
   the reusable preauthorized tsnet key is controller-tag-restricted. Router key
   creation and run-owned device/key cleanup use separate runner OAuth inputs.

The backend and artifact buckets, KMS keys, management infrastructure, and the
two privileged roles are **external retained prerequisites**, not resources
created or deleted by this acceptance. Private recovery objects are retained
forensics, not a zero-storage-cost claim. Set independently reviewed retention
for them after successful cleanup and the inspection period.

## GitHub Boundary

Configure repository OIDC subject customization through GitHub's repository OIDC
API with this exact JSON (review impact on other workflows first):

```json
{
  "use_default": false,
  "include_claim_keys": ["repo", "environment", "workflow_ref", "run_id", "run_attempt"]
}
```

The runner checks the returned subject before its STS request; STS verifies the
token. Missing customization fails before backend claim acquisition. `run_id`
in this subject is **GitHub's numeric run ID**, not the human approval/run name.

Create four environments, restricted to the reviewed protected branch/ref:
`envelope-controller-deployment`, `envelope-controller-observation`,
`envelope-controller-quiescence`, and `envelope-controller-cleanup`. Require
independent reviewers, prevent self-approval and administrative bypass where
available, and restrict which repository/workflow can use the runner groups.
An observation approval must finish within the 15-minute issuance window; a
missed window is a failed measurement, not permission to extend trust.

Use isolated ephemeral Linux/x64 runner groups:

- `envelope-production-deployment`: deployment, quiescence, cleanup. Private
  access to controller endpoints and router attestors is required.
- `envelope-production-observation`: measurement only. No shared disks, caches,
  process namespace, instance profile, home directory, or reusable credentials
  with deployment hosts. It must reach private controller metrics and workloads.

Do not reuse a retained `.run/<run-id>` directory. The workflow deliberately
preserves local data; recycle successful ephemeral runners only after reviewing
the sanitized upload and authoritative cleanup. Quarantine failed runners.
The workflow is manual-only and has non-cancelling global concurrency. Do not
add a schedule, competing destroy trap, or a second cleanup workflow.

## Privileged Trust

Use the following deployment trust, substituting account, repository, and exact
protected workflow ref. Keep exactly one Allow statement, with this action,
principal and condition structure. No AWS principal, alternate workflow,
wildcard environment, or `sts:AssumeRole` trust is permitted.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:environment:envelope-controller-deployment:workflow_ref:OWNER/REPO/.github/workflows/aws-two-region-e2e-live.yml@refs/heads/main:run_id:*:run_attempt:*"
      }
    }
  }]
}
```

Initial cleanup trust has the identical shape, replacing the environment with
`envelope-controller-cleanup`. Deployment narrows that trust to the exact current
run/attempt with an expiry, and denies all cleanup sessions issued on or before
`observer_sessions_until`. The next deployment can narrow the previously expired
cleanup trust to its new invocation; a cleanup job cannot reopen that trust.

During measurement the deployment and lifecycle roles have unconditional
`Deny`, `Action: "*"`, `Resource: "*"` inline policies. The deployment OIDC
provider also has an unconditional trust Deny with an invocation-specific Sid.
This excludes sessions minted between handoff creation and issuer freeze.
The observer independently reads these policies and exact trust documents.
Cleanup replaces the deployment freeze with a cutoff denying every old session
before removing the owned OIDC freeze. Do not delete a cutoff deny to reuse an
old credential. New OIDC sessions, not revived deployment sessions, are required.

## Privileged Permissions

Attach a reviewed **inline policy named `acceptance-boundary`** to cleanup.
Its canonical hash is bound into the handoff and independently rechecked before
cleanup. Deployment also needs a reviewed infrastructure policy. These are
privileged deployment identities, not the narrow policies generated by this
root. An observation-style route deny on either will make Terraform deployment
or destroy fail. Never solve that by granting deployment authority to observation.

Use a dedicated run-name prefix (for example `pc-`) and scope creation/deletion
to that namespace and the configured account/Regions. Review a saved plan for
all four roots against these permissions. Required permission families are:

| Surface | Deployment | Cleanup | Required Scope |
| --- | --- | --- | --- |
| STS | GetCallerIdentity; AssumeRole for Go lifecycle | GetCallerIdentity | AssumeRole only on `arn:aws:iam::ACCOUNT:role/pc-*-lifecycle`, with the invocation ExternalId required by its trust |
| EC2 | Describe APIs; create/tag/manage the appliance graph and controller instances, ENIs, volumes, endpoints, routes, associations, security groups, NAT/Internet gateways and addresses | Describe and delete that graph; detach/terminate managed instances/volumes | Exact account and both configured site Regions plus controller Region; resource/request tags where the API supports them; no unrelated VPC or route authority |
| ELBv2 | Describe; create/configure/tag GWLBs, listeners and target groups; register/deregister targets | Describe; deregister/delete | Run-named GWLB/target-group resources |
| IAM | Get/List; create/delete/tag run roles/profiles; inline policies; attach/detach reviewed AWS managed policies; PassRole to EC2/flow logs | Read; remove run policies/profiles/roles and detach managed policies | Run role/profile ARN prefix; PassRole only to required AWS services; existing readiness publisher is read-only |
| IAM freeze | GetRole/GetRolePolicy, UpdateAssumeRolePolicy and PutRolePolicy on both privileged roles; PutRolePolicy on run lifecycle role | GetRole/GetRolePolicy, PutRolePolicy and UpdateAssumeRolePolicy on deployment role; DeleteRolePolicy on run lifecycle role | Exact two external role ARNs and run lifecycle ARN; no OIDC provider or unrelated role administration |
| DynamoDB | Describe/List; create/tag/update authority table and PITR; read initialized state | Describe/read; delete run table | Run authority table; lifecycle journal writes occur only through the separately scoped Go lifecycle role |
| SSM | PutParameter, GetParameter, DescribeParameters, ListTagsForResource, AddTagsToResource for bootstrap/runtime inputs and enrollment | Same read APIs and DeleteParameter for exact owned versions/parameters | `/<run-id>/...`, `/envelope/<run-id>/...`, and `/envelope/attestor-bindings/<unique-public-key>`; bind ownership by run/invocation tags and version-1 receipts |
| S3 backend | Bucket versioning/location/encryption reads; ListBucket/ListBucketVersions; GetObject/GetObjectVersion; PutObject/DeleteObject | Same, including final version deletion | Backend bucket metadata and exact `runs/<run-id>/` objects; state and `.tflock` keys for appliance/controller/attestor/sessions; claim, handoff and private journal namespaces |
| S3 artifacts | Bucket metadata; object version reads/writes/deletes; create/configure/delete run-owned appliance/enrollment buckets | Read/delete run objects and run-owned buckets | Exact external artifact bucket run prefix; run-owned buckets only; never change/delete an external bucket policy or bucket |
| KMS | DescribeKey, Encrypt/Decrypt, GenerateDataKey; CreateGrant where required by encrypted volumes | Decrypt backend and owned parameters; required grant cleanup | Exact reviewed keys, service and encryption contexts; no key creation/deletion or unrestricted cross-account decrypt |
| Logs/CloudWatch | Describe/read; create/tag/configure run log groups and flow logs; create/delete run alarms | Describe/delete run logs and alarms | Run-named resources and exact configured readiness metric inputs |

AWS APIs that do not support resource-level permissions require `Resource: "*"`
in separate statements, constrained by `aws:RequestedRegion` where supported.
Do not put an EC2 ARN on a Describe-only action and assume it grants the read.
S3 bucket-list statements require bucket ARNs; object statements require object
ARNs. KMS key policies must authorize the corresponding identity policies.
Provider refresh may need additional read-only APIs for the pinned AWS provider;
review those explicitly rather than adding `AdministratorAccess`.

The IAM freeze operations are intentionally powerful and scoped to dedicated
acceptance roles. Do not share either external role with another workflow.
The generated observation/quiescence roles must have no extra attached policies,
resource-based grants, or external session issuers. Their exact inline policies
are generated by `controller_acceptance_policy.boundary_policy`, not hand-written
copies. In particular, quiescence can start only routers and stop only controllers.

Before approving execution, an administrator must evaluate the effective IAM
permissions (including SCPs, key policies and boundaries), using IAM simulation
where supported, against this negative matrix:

| Identity | Must Be Denied |
| --- | --- |
| Observe | Every route/association mutation; AssumeRole; IAM writes; SSM parameter reads; private/backend state reads; commands on any non-workload; stop/start of any foreign instance |
| Quiesce | All of the above plus every SSM command and controller StartInstances |
| Frozen deployment/lifecycle | Every action, including sessions issued after handoff creation |
| Cleanup issued before observer drain | Every action |
| Foreign repository/ref/environment/run/attempt | OIDC role assumption |

Local mocks test generated documents and orchestration; they do **not** certify
the effective policies of an AWS account. Account review is a prerequisite of
separately approved task 9.5, not a claimed offline test result.

## Configuration And Evidence

`ENVELOPE_PRODUCTION_CONTROLLER_SPLIT_CONFIG_TEMPLATE_B64` is base64-encoded JSON:

```json
{
  "schema": 1,
  "production": {"artifact_manifest": "build/manifest.json"},
  "deployment_role_arn": "arn:aws:iam::ACCOUNT:role/envelope-acceptance-deployment",
  "cleanup_role_arn": "arn:aws:iam::ACCOUNT:role/envelope-acceptance-cleanup",
  "oidc_provider_arn": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com",
  "artifact_store": {"bucket": "REVIEWED-VERSIONED-BUCKET", "region": "us-west-2"},
  "context": {}
}
```

The `production` object above is abbreviated, **not a deployable configuration**.
Supply the complete strict `ProductionRunConfig` contract in
`scripts/aws_production_controller_e2e.py`, including production topology version
3, exact placements, KMS/egress/readiness identities, cost/expiry bounds and
timeouts. `transition_seconds` must be at most 300. `prepare-config` supplies the
protected context, run ID, seven-hour expiry and independent state keys. It never
copies credentials into the configuration. Both role ARNs and OIDC provider must
belong to the same account. See `load_config` in
`scripts/controller_acceptance_deploy.py` for the exact outer schema.

Only deployment receives the template and controller credential secrets. Cleanup
receives only runner OAuth credentials and downloads exact-version encrypted
private recovery state after quiescence. Observation receives only its role ARN
and immutable handoff reference. Do not add `configure-aws-credentials`, secret
exports or artifact downloads containing deployment state to that job.

The handoff includes canonical topology identity, unique per-router attestor
public keys/configuration hashes, clean component hashes at the exact workflow
revision, and ordered production lifecycle receipts. Lifecycle initialization
receipts must match the requested domain/topology; rollout/activation completion
must match the started operation ID. Saved rollout plan and Terraform executable
digests are verified by the Go lifecycle command, with the controller's private
`TF_DATA_DIR` and separately restricted role, never deployment credentials.

Schema-3 `aws-production-controller-live` evidence contains actual router/leader
stop/recovery, quorum/leases, route convergence, durable alternate, failback and
application outcomes. Integration-only disagreement, stale-fence, ambiguous-call
and checkpoint evidence comes from completed Go JSON test events. No flags can
turn those into live receipts. The final `controller-acceptance-bundle` includes
live, integration-only, quiescence and ordered cleanup evidence. Optional missing
or invalid measurement evidence fails the bundle but must not block owned cleanup.

Offline validators (no credentials required):

```bash
python3 scripts/aws_controller_acceptance.py validate-handoff HANDOFF.json
python3 scripts/aws_controller_acceptance.py validate-live LIVE.json --handoff HANDOFF.json
python3 scripts/aws_controller_acceptance.py verify-bundle BUNDLE.json --handoff HANDOFF.json
```

These validate structure and consistency, not AWS provenance. Obtain documents
only by exact S3 version and digest from the protected invocation. Never use a
mutable latest object, a local `complete` flag, or an uploaded fixture as authority.

## Failure And Manual Recovery

There is deliberately **no automatic adoption, lock takeover, force-unlock,
claim deletion shortcut or rerun recovery command**. The CLI refuses reused run
directories. Fresh jobs have exact invocation subjects; later attempts cannot
adopt an old handoff. Interrupted lifecycle operations retain a non-expiring
`lifecycle#<deployment>` lock and operation journal. An IAM/route repair is not
implicit permission to discard that journal.

| Failure Point | Expected Behavior |
| --- | --- |
| Before claim | No resource cleanup authority; retain local failure evidence |
| Conditional claim response lost | Only the immediately attempting invocation may reconcile one exact version and the complete claim body; ambiguity retains ownership state |
| Partial deployment, no controllers attempted | Still-owning deployment may clean up after proving no run-owned controllers exist |
| Controller creation, initialization, rollout or activation uncertain | Retain claim, Terraform locks/state and private checkpoints; no blind partial destroy |
| Handoff publication/readback or revocation uncertain | No observation output; quarantine deployment; retain freeze/claim and inspect exact object versions |
| Observation failure/interruption | Compensate armed faults where possible; quiescence restores exact run routers after observer sessions expire, then stops controllers |
| Quiescence denied or journals change | Withhold cleanup credentials; retain state and inspect writers |
| Cleanup failure/interruption | Stop later cleanup steps, retain claim and checkpoints; never report complete or delete forensic files |
| Bundle publication/upload failure after cleanup | Retain local bundle and private snapshots; inspect cloud absence and final claim deletion, do not rerun the run ID |

An independently authorized incident operator follows this inspected procedure:

1. Quarantine every involved runner and block new environment approvals. Preserve
   logs, exact S3 versions, local private-state files, Terraform lock records,
   lifecycle operation IDs, failure JSON and sanitized evidence. Do not expose
   private snapshots through GitHub artifacts. Record the original repository,
   commit, GitHub run/attempt, human run ID and invocation hash.
2. Read the exact claim version/body, handoff digest (if any) and private snapshot
   chain under a separate read-only incident identity. Confirm account, run,
   invocation and configuration digest, and actual EC2/SSM ownership tags. Check
   the S3 version sets for competing writes/delete markers. If identity is not
   exclusive, stop; tags or a matching run name alone do not authorize deletion.
3. Independently revoke/freeze all possible deployment, lifecycle and cleanup
   issuers and old sessions, including any issuance during an interrupted trust
   update. Stop or isolate retained credential-bearing processes. Do not merely
   wait for the handoff's old cutoff if revocation was incomplete. Wait for the
   maximum lifetime of every potentially issued session unless an effective
   explicit deny is independently proved. Observation's bound is its issuance
   cutoff plus 3600 seconds. Include compromised or manually issued sessions in
   the inventory; this is not an automated safety inference.
4. With a narrowly scoped incident role, restore only the exact owned routers,
   and stop every controller replica. Deny their restart and any other writer
   path. Repeatedly read EC2 ownership and stopped state. Read complete durable
   items strongly, wait at least lease duration plus API timeout plus route
   convergence timeout, then require unchanged item hashes/versions and expired
   leases. Unknown instances, active transactions, changed authority, or journal
   drift require investigation; do not grant destroy authority yet.
5. Inspect each retained lifecycle operation and saved Terraform plan/state with
   the exact clean revision and pinned tools. Determine which operations actually
   committed from authoritative AWS readback. A held lifecycle/Terraform lock is
   not stale solely because its process is gone. Any manual conditional lock
   repair must name the exact operation/item version and have independent review;
   never delete or replace active journals to make a deployment start. If safe
   completion cannot be established, leave the lock and claim retained.
6. After independent quiescence approval, grant a time-bounded incident cleanup
   identity scoped to the proved resources. Reconstruct only portable local
   artifact paths from exact reviewed hashes; never import old host credentials.
   Use reviewed destroy plans in order: controller, attestor enrollment,
   controller/seed material and exact artifact versions, appliance, owned Tailnet
   identities/keys, observation/quiescence roles. Recheck claim ownership before
   each mutation. Do not use `run-all` or launch a new workflow attempt as recovery.
7. Require two consecutive zero-residual AWS/SSM/Tailnet audits, including public
   attestor bindings/pointers and phase roles. Preserve forensic snapshots. Only
   then replace the deployment unconditional deny with an old-session cutoff,
   remove the exact owned OIDC freeze, finalize all four state and lock key
   version sets, and delete the exact claim version last. On any ambiguity stop
   and retain the remaining claim/state; obtain a new reviewed incident decision.
8. Record an incident-specific signed/reviewed recovery report. Manual recovery
   must never manufacture a passing live bundle. Retain the original failure,
   commands/plans, resource readbacks and approvers. A new acceptance requires a
   new run ID and separate task 9.5 authorization.

## Offline Verification

`scripts/test_controller_acceptance_phases.py` runs real orchestration with mocked
external AWS/subprocess responses, exact-version S3 storage and IAM documents.
It exercises revocation, credential scrubbing, OIDC subject/STS identity checks,
handoff failures, domain initialization and serialized rollout with pinned files,
router/leader stop and compensating restart, quiescence, interruption at cleanup
steps, retained claims, finalization and bundle consistency. Controller observation
and application outcomes in these Python tests are fixtures, not live receipts;
the Go integration suite separately exercises the production state machine.

`scripts/test_controller_acceptance.py` provides adversarial evidence/policy and
stable-absence checks. Existing production runner tests exercise the reused
bounded AWS/SSM/Tailnet/route-read primitives. `scripts/test_terraform.sh` uses
mocked providers and isolated backend-disabled copies of all four roots,
including this root's exact OIDC/session/route-deny tests. No offline test assumes
AWS/Tailscale credentials or supplies proof of task 9.5.
