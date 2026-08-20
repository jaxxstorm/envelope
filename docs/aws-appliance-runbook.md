# AWS Appliance Deployment Runbook

This runbook operates the `example/terraform` acceptance profile. It is not a production HA design: each region has exactly one Envelope process and one GWLB target. GWLB cross-zone load balancing lets every configured endpoint AZ reach that sole process, but process restart or replacement discards flow context and promises recovery only for new flows.

## Security Boundary

- Never open, print, copy, migrate, or use the ignored legacy `example/terraform/terraform.tfvars`, local state, state backup, or old plan files. They are not inputs to this workflow.
- Before any live run, revoke the legacy plaintext Tailscale key through the Tailnet administration console/API and rotate any credential that may have appeared in legacy state or logs. Quarantine or securely remove those local files only after rotation under the operator's approved retention process.
- Terraform receives only two run-scoped SSM SecureString ARNs and their exact regional KMS key ARNs. The generated auth-key value exists only in protected-runner memory and short-lived mode-0600 AWS CLI input files, which are removed immediately.
- Supply AWS credentials through the normal protected runner credential chain. Supply the Tailscale OAuth client through `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET`. Do not put either in repository files, Terraform variables, backend configuration, command arguments, or retained logs.
- Treat saved plans, state, rendered MIME, packet captures, and diagnostic output as sensitive. Keep them under `.run/` with mode 0600, scan retained evidence, and remove it after the residual audit.

## Required Authority

The AWS principal needs read-only EC2 image/instance-type metadata, Terraform authority for the resources in `example/terraform`, permission to create/delete the two named SSM parameters with the supplied KMS keys, and access to one operator-owned backend bucket. The backend is shared infrastructure and must already have:

- Versioning `Enabled`.
- Default `aws:kms` encryption using the exact configured key ARN.
- All four S3 public-access-block settings enabled.
- Access controls granting protected operators the exact bucket reads used by preflight, `ListBucketVersions`, and the object read/write, manifest tagging, lock deletion, and exact version-deletion actions used by the lifecycle runner.
- A retention/lifecycle policy reviewed for abandoned run objects.
- A non-public bucket policy that grants each configured exact operator principal access to the run prefix and denies insecure transport.
- An enabled customer-managed symmetric KMS key whose key policy grants those exact operators encrypt, decrypt, data-key, describe-key, and get-key-policy authority.

The runner creates only `runs/<run>/terraform.tfstate`, its `.tflock`, and `runs/<run>/manifest.json`. Cleanup removes every version of those exact objects and never deletes or changes the shared bucket or KMS key. No backend credential belongs in this repository.

Create a narrowly scoped Tailscale OAuth client that can read the policy, list/delete devices, and create/revoke auth keys. Do not grant policy mutation. Scope names can change in the Tailscale console; approve only the API operations used by `scripts/aws_appliance.py`.

## Tailnet Policy

Preconfigure policy before creating AWS resources. The required shape is equivalent to:

```json
{
  "tagOwners": {
    "tag:envelope-acceptance": ["group:network-admins"]
  },
  "autoApprovers": {
    "routes": {
      "172.16.0.0/24": ["tag:envelope-acceptance"],
      "172.16.1.0/24": ["tag:envelope-acceptance"],
      "172.17.0.0/24": ["tag:envelope-acceptance"],
      "172.17.1.0/24": ["tag:envelope-acceptance"]
    }
  },
  "grants": [
    {"src": ["172.16.0.0/24", "172.16.1.0/24"], "dst": ["172.17.0.0/24", "172.17.1.0/24"], "ip": ["*"]},
    {"src": ["172.17.0.0/24", "172.17.1.0/24"], "dst": ["172.16.0.0/24", "172.16.1.0/24"], "ip": ["*"]}
  ]
}
```

The actual owners and lane CIDRs must match the protected run configuration. The runner fails before key or AWS resource creation when tag ownership, auto-approval, either directional grant, administrative read authority, or `snat_subnet_routes=false` is absent. Terraform hard-codes Tailscale subnet-route SNAT and netfilter integration off; Envelope owns the forwarding contract.

## Build Artifacts

Use a clean, reviewed source revision and a supported Go toolchain:

```bash
./scripts/build_artifacts.sh --output-dir dist --version 0.1.0 --architectures amd64,arm64
python3 ./scripts/inspect_artifact.py dist/envelope-linux-amd64 --expect-architecture amd64
python3 ./scripts/inspect_artifact.py dist/envelope-linux-arm64 --expect-architecture arm64
```

`dist/manifest.json` records the full source revision, deterministic source timestamp, reviewed Go toolchain, `go version -m` OS/architecture/VCS state, application version, byte size, and SHA-256. The builder requires the exact toolchain in `scripts/reviewed-go-toolchain.txt`. Builds are static Linux ELF binaries with no program interpreter. Terraform uploads one selected artifact to a run-owned private versioned S3 bucket and object encrypted with SSE-S3. Appliance IAM can read only that object; only the two external SSM SecureStrings require exact KMS decrypt grants. Avoiding a run-owned KMS key also avoids a scheduled-deletion residual after destroy.

The build refuses a dirty worktree by default, and protected preflight rejects manifests marked dirty. `--allow-dirty` exists only for local fixture tests and does not produce a deployable acceptance artifact.

Do not edit a manifest digest to match an unreviewed binary. Protected metadata preflight verifies the manifest and ELF before querying both regions for exact AMI and instance-type metadata. Mapping is strictly `amd64` to `x86_64` and `arm64` to `arm64`.

## Protected Run Configuration

Create `.run/<run>/config.json` mode 0600. It contains references, never credentials:

```json
{
  "run_id": "envelope-accept-001",
  "expires_at": "<RFC3339-WITHIN-24-HOURS>",
  "architecture": "amd64",
  "artifact_manifest": "../../dist/manifest.json",
  "instance_type": "t3.medium",
  "test_instance_type": "t3.micro",
  "backend": {
    "bucket": "operator-owned-terraform-state",
    "region": "us-west-2",
    "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/BACKEND-KEY-ID",
    "state_key": "runs/envelope-accept-001/terraform.tfstate",
    "operator_principal_arns": ["arn:aws:iam::123456789012:role/protected-envelope-operator"]
  },
  "sites": {
    "west": {
      "region": "us-west-2",
      "ami_id": "ami-REVIEWEDWEST",
      "ssm_kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/WEST-KEY-ID",
      "azs": {"a": "us-west-2a", "b": "us-west-2b"},
      "appliance_az_key": "a",
      "vpc_cidr": "172.16.0.0/16",
      "public_subnet_cidr": "172.16.40.0/24",
      "appliance_subnet_cidr": "172.16.30.0/24",
      "workload_subnet_cidrs": {"a": "172.16.0.0/24", "b": "172.16.1.0/24"},
      "gwlbe_subnet_cidrs": {"a": "172.16.10.0/24", "b": "172.16.11.0/24"},
      "gwlb_subnet_cidrs": {"a": "172.16.20.0/24", "b": "172.16.21.0/24"},
      "gwlb_return_cidrs": ["172.16.0.0/24"],
      "local_delivery_cidrs": ["172.16.1.0/24"]
    },
    "east": {
      "region": "us-east-1",
      "ami_id": "ami-REVIEWEDEAST",
      "ssm_kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/EAST-KEY-ID",
      "azs": {"a": "us-east-1a", "b": "us-east-1b"},
      "appliance_az_key": "a",
      "vpc_cidr": "172.17.0.0/16",
      "public_subnet_cidr": "172.17.40.0/24",
      "appliance_subnet_cidr": "172.17.30.0/24",
      "workload_subnet_cidrs": {"a": "172.17.0.0/24", "b": "172.17.1.0/24"},
      "gwlbe_subnet_cidrs": {"a": "172.17.10.0/24", "b": "172.17.11.0/24"},
      "gwlb_subnet_cidrs": {"a": "172.17.20.0/24", "b": "172.17.21.0/24"},
      "gwlb_return_cidrs": ["172.17.1.0/24"],
      "local_delivery_cidrs": ["172.17.0.0/24"]
    }
  },
  "tailnet": {
    "name": "example.com",
    "tag": "tag:envelope-acceptance",
    "tag_owners": ["group:network-admins"],
    "snat_subnet_routes": false,
    "auth_key_expiry_seconds": 3600
  }
}
```

Use real explicit AL2023 AMI IDs. The placeholders above intentionally fail validation. Expiry must be 30 minutes to 24 hours in the future for prepare/plan/apply operations. Cleanup and janitor recovery safely load expired configurations after validating the durable manifest identity. This JSON is the sole protected input source: the runner derives every Terraform variable and every Tailnet policy prefix from it. Do not create a separate network tfvars file. Local return and delivery roles must be a non-empty disjoint exact partition of local workload subnets; remote roles are derived from the opposite workload subnet set and cannot diverge.

## Preflight And Prepare

Run the artifact and read-only AWS metadata check first. It performs only `DescribeImages` and `DescribeInstanceTypes` after local artifact inspection:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json metadata-preflight
```

Then expose the protected OAuth values only to the runner process and run the complete policy/backend preflight:

```bash
export TS_OAUTH_CLIENT_ID
export TS_OAUTH_CLIENT_SECRET
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json preflight
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json prepare
```

`prepare` writes the durable secret-free manifest before creating anything. The initial manifest already contains all non-secret Terraform destroy inputs, artifact source/object recovery identity, the exact auth-key description, and both intended regional SSM names/ARNs. Each create-started and create-completed phase is uploaded independently. It then writes `.run/<run>/runtime.tfvars.json`. Any partial failure deletes both predictable parameter names and revokes the exact key ID or the uniquely described recovery key. Never redirect debug shell tracing around these commands.

## Initialize, Plan, And Apply

Safe initialization revalidates the backend and writes mode-0600 backend configuration with `encrypt=true`, the exact KMS key, unique state key, and `use_lockfile=true`:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json init --terraform-dir example/terraform
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json plan --terraform-dir example/terraform
python3 ./scripts/secret_scan.py --root . --extra .run/<run>/apply.tfplan.json
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json apply --terraform-dir example/terraform
```

The runner resolves the config, run directory, backend file, Terraform directory, artifact, plan, and `TF_DATA_DIR` to absolute paths before changing Terraform's cwd. It strips the configured OAuth client ID/secret variables from every AWS CLI and Terraform child environment. `plan` validates and durably binds the saved-plan digest. `apply` uploads `apply_started` with `nodes_expected=true` before launching Terraform, so runner-loss cleanup does not mistake an empty node selection for success.

Do not use `-target`. The plan gate rejects unplanned deletion/replacement, a target count other than one per region, disabled cross-zone behavior, wrong fixed-cost counts, public appliance IPs, missing route domains, artifact digest drift, missing TTL ownership, or credential material in MIME.

The reviewed fixed profile has two VPCs, two NAT gateways/EIPs, two GWLBs, one GWLBE per configured AZ, two appliance instances, two test instances, one artifact bucket, and one target per region. `cost_profile` records the count, pre-approved estimate, TTL, and excluded variable charges. Review current AWS prices before every apply.

## Readiness

Apply completion is not readiness:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json wait \
  --deployment-file .run/<run>/deployment.json --timeout-seconds 900
```

The runner requires both instances to be SSM-online, bounded cloud-init completion, active `tailscaled`, host-network and Envelope units, Running Tailscale v1.80.x kernel-TUN state, approved local advertisements, accepted remote table-52 routes, valid artifact checksum, HTTP health, and exactly one healthy target in each target group. Failure launches the redacted on-host diagnostic collector for both regions and reports only command IDs.

On-host bootstrap downloads the exact S3 object, verifies SHA-256, installs atomically, and keeps Envelope stopped on mismatch. Persistent host setup disables firewalld/native nft objects, requires executable `/usr/sbin/nft`, selects legacy iptables/ip6tables, loads only `/etc/sysctl.d/90-envelope.conf`, disables `rp_filter` for `conf/all` and the dynamically created Envelope TUN, applies the remaining dynamic-interface settings explicitly, and creates the sole filter and mangle `FORWARD` jumps plus exact four-direction MSS contracts. `envelope.service` runs as an unprivileged user with only `CAP_NET_ADMIN` and `CAP_NET_RAW`, starts after network/Tailscale/host setup, and restarts on failure.

After readiness, require no drift:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json verify-no-drift \
  --terraform-dir example/terraform
```

The protected operation revalidates the backend, durable manifest, artifact identity, and generated variable set; resolves every path before changing directory; strips both OAuth variables from AWS/Terraform children; and invokes Terraform with `-detailed-exitcode`. Exit code 0 is required. Exit code 2 is reported as drift and blocks acceptance.

## Failure, Reboot, And Replacement

These are live acceptance operations and must not be marked complete without retained redacted evidence.

Process recovery:

```bash
env -u TS_OAUTH_CLIENT_ID -u TS_OAUTH_CLIENT_SECRET aws ssm send-command --region <region> --instance-ids <appliance-id> \
  --document-name AWS-RunShellScript --parameters 'commands=["systemctl kill --signal=KILL envelope.service"]'
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json wait --deployment-file .run/<run>/deployment.json
```

Confirm a new process generation and new-flow recovery; never claim pre-failure context continuity.

Reboot recovery:

```bash
env -u TS_OAUTH_CLIENT_ID -u TS_OAUTH_CLIENT_SECRET aws ec2 reboot-instances --region <region> --instance-ids <appliance-id>
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json wait --deployment-file .run/<run>/deployment.json
```

Replacement recovery rotates bootstrap authority before planning. `plan-replacement` creates a new short-lived key, updates both SecureStrings with rollback on either regional failure, durably records the new ID, revokes the old key, and then creates a separately reviewable replacement plan for one exact address:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json plan-replacement \
  --terraform-dir example/terraform --replace aws_instance.envelope_west
python3 ./scripts/secret_scan.py --root . --extra .run/<run>/replace.tfplan.json
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json apply \
  --terraform-dir example/terraform --plan-file .run/<run>/replace.tfplan
```

Apply only that saved plan, refresh `deployment.json`, and rerun readiness and cold new-flow checks.

## Cleanup And Emergency Recovery

Normal cleanup initializes the same durable backend, destroys without targeting, checks that Terraform state is empty, deletes the exact durably recorded Tailnet node IDs, verifies their absence, deletes both intended SSM names, revokes every current/pending run key, removes only allowlisted resources with the exact run/TTL tags, and finally deletes and re-lists every version/delete marker of the exact state, lock, and manifest objects. Hostname/tag selection is allowed only when `nodes_expected=true` and exact IDs were lost during partial post-apply recovery; zero, one, or both expected nodes are safe, while any duplicate hostname/tag identity fails closed.

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json cleanup \
  --terraform-dir example/terraform
```

If the original runner is lost, a new protected runner can recover the durable manifest and state without local state:

```bash
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json janitor \
  --terraform-dir example/terraform --dry-run
python3 ./scripts/aws_appliance.py --config .run/<run>/config.json janitor \
  --terraform-dir example/terraform
```

Dry-run reports identifiers/counts without deletion. Janitor deletion requires the exact TTL to be expired. Cleanup validates every residual's exact run and TTL tags, rejects unknown resource types, and never admits the configured shared backend ARN to the deletion allowlist. If Terraform destroy fails, cleanup still attempts Tailnet, SSM, auth-key, and dependency-ordered allowlisted AWS recovery for up to 15 minutes. It aggregates failures only after all independent paths run and preserves the manifest/state whenever any path or the final residual audit is not clean. Resolve the reported errors and retry. Do not replace this with broad tag-based deletion commands.

When preparation fails before a state object exists, normal cleanup detects the absent run state and cleans the recorded key/parameters without invoking Terraform. Use `--skip-destroy` only for an explicit secrets-only emergency action when AWS infrastructure must remain; it deliberately preserves all backend objects for a later destroy.

## Static Gates

The non-live gates are:

```bash
TERRAFORM_BIN=/approved/path/to/terraform-1.10.5 ./scripts/test_terraform.sh
python3 scripts/test_aws_appliance.py
python3 scripts/test_terraform_contract.py
python3 scripts/test_artifacts.py
python3 scripts/secret_scan.py --root .
go test ./...
go test -race ./...
go vet ./...
openspec validate envelope-aws-appliance-deployment --strict
```

`test_terraform.sh` copies only an explicit source/template/module/test allowlist into a disposable directory before running fmt, clean backend-disabled init, validate, and the real refresh-disabled mocked plan. It never copies or discovers legacy tfvars/state. If `TERRAFORM_BIN` is omitted and exact 1.10.5 is unavailable, it downloads a platform-specific archive and checks a pinned SHA-256 without changing user configuration. `secret_scan.py` obtains its default file list from `git ls-files --exclude-standard`; therefore it does not open ignored legacy tfvars/state/backups. Supply only approved redacted artifacts with `--extra`.

## Live Blockers

A live apply additionally requires valid protected AWS/Tailscale credentials, two reviewed AL2023 AMI IDs, two regional SSM KMS keys, the compliant shared backend, approved Tailnet policy, current cost approval, and package availability for legacy iptables on those exact AMIs. Metadata preflight is read-only but cannot prove package repository contents; first boot fails closed if the selected AL2023 image cannot install an actual legacy backend. Do not claim apply, reboot, replacement, no-drift, destroy, key revocation, Tailnet policy smoke, or janitor recovery until those operations have run and their redacted evidence has been reviewed.
