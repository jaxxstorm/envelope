# AWS Two-Region E2E Runbook

This is the operator procedure for the real, billable AWS GWLB and Tailscale acceptance profile. It is permitted only in the `_lbr_sandbox` Tailnet and from a protected runner. Pull requests, forks, developer Tailnets, and production Tailnets must never receive the live credentials.

The profile proves two independent directional lanes:

| Role | Example CIDR | Initiates toward |
| --- | --- | --- |
| west initiator | `172.16.0.0/24` | east responder |
| west responder | `172.16.1.0/24` | none in the west-to-east test |
| east responder | `172.17.0.0/24` | none in the east-to-west test |
| east initiator | `172.17.1.0/24` | west responder |

Each initiator uses the single GWLBE in its own AZ and its regional GWLB. The remote responder returns through its local appliance ENI and Tailscale without traversing the responder region's GWLB. The deployment has one Envelope process and one GWLB target per region.

This does **not** prove arbitrary initiation in both directions from one workload CIDR, active/active targets, multi-target HA, state replication, or flow continuity across restart/reboot. The load phase can exercise the two declared lanes concurrently, but that is not arbitrary bidirectional routing.

## Prerequisites

- Use a clean, reviewed, protected revision on a Linux runner. The artifact builder rejects dirty source.
- Install Python 3.11 or newer, AWS CLI v2, `jq`, the Go version in `scripts/reviewed-go-toolchain.txt`, and Terraform exactly `1.10.5` with its CLI wrapper disabled.
- Complete the backend, KMS, AMI, package-availability, IAM, and artifact prerequisites in the [AWS appliance runbook](aws-appliance-runbook.md).
- Use an operator-owned versioned, KMS-encrypted S3 backend. The run may create and remove only its exact state, lock, and manifest keys; it must never delete the shared bucket or key.
- Use two reviewed AL2023 AMI IDs and two regional SSM KMS keys. Confirm regional EC2, VPC, NAT, EIP, GWLB/GWLBE, SSM, IAM, S3, CloudWatch Logs, and service-quota capacity before apply.
- Configure a protected GitHub environment named `envelope-two-region-e2e` with required reviewers, protected-branch deployment rules, no self-review, and no secrets available to forks.
- Configure the AWS OIDC role trust for only `repo:jaxxstorm/envelope:environment:envelope-two-region-e2e` with audience `sts.amazonaws.com`. Grant only the read/preflight, run-scoped create/update/delete, exact backend-prefix, exact KMS, SSM, and residual-audit actions used by the runners.
- Create a narrowly scoped `_lbr_sandbox` OAuth client that can read policy, list/delete run nodes, and create/revoke run auth keys. Do not grant Tailnet policy mutation.
- Recheck prices and explicitly approve the TTL, fixed-cost ceiling, and every `e2e_load_profile` threshold before the saved plan is created.

## Tailnet Policy

Install and review this shape only in `_lbr_sandbox`; the runner reads and verifies it but does not mutate it. Replace the owner if needed, and keep the tag and CIDRs identical to the protected config.

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
    {
      "src": ["172.16.0.0/24", "172.16.1.0/24"],
      "dst": ["172.17.0.0/24", "172.17.1.0/24"],
      "ip": ["*"]
    },
    {
      "src": ["172.17.0.0/24", "172.17.1.0/24"],
      "dst": ["172.16.0.0/24", "172.16.1.0/24"],
      "ip": ["*"]
    }
  ]
}
```

The config must set `tailnet.name` to `_lbr_sandbox`, `snat_subnet_routes` to `false`, and the reviewed tag owner list. Terraform also disables Tailscale netfilter integration; Envelope's exact forwarding and MSS chains are authoritative.

## Environment

The live process requires these values:

| Variable | Contract |
| --- | --- |
| `ENVELOPE_E2E_APPROVED_RUN_ID` | Must exactly equal `config.json` `run_id`; this is a typed approval, not a prefix or wildcard. |
| `TS_OAUTH_CLIENT_ID` | `_lbr_sandbox` scoped OAuth client ID. |
| `TS_OAUTH_CLIENT_SECRET` | Matching OAuth client secret. |
| `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` | Protected local role credentials, or short-lived GitHub OIDC credentials. Never store static AWS keys in the repository or config. |
| `AWS_REGION`/`AWS_DEFAULT_REGION` | Protected runner bootstrap region; every regional operation is still bound to the config. |

The config can select different OAuth environment-variable names, but both names must be distinct shell identifiers. Do not set or persist a Tailscale auth key; the lifecycle creates a short-lived run key and stores only regional SSM SecureString references in Terraform.

## Protected Config

Create `.run/<run-id>/config.json` with mode `0600`. `.run/` is ignored. The four lane roles are explicit through each site's two workload subnets and the disjoint singleton `gwlb_return_cidrs` (initiator) and `local_delivery_cidrs` (responder) lists.

```json
{
  "run_id": "envelope-e2e-001",
  "expires_at": "<RFC3339-AT-LEAST-3-HOURS-IN-THE-FUTURE>",
  "architecture": "amd64",
  "artifact_manifest": "../../dist/manifest.json",
  "instance_type": "t3.medium",
  "test_instance_type": "t3.micro",
  "ebs_root_volume_size": 20,
  "tailscale_version": "1.80.3",
  "cost": {
    "estimated_fixed_hourly_usd": 1.50,
    "approved_max_fixed_hourly_usd": 2.00
  },
  "e2e_load_profile": {
    "profile_id": "envelope-e2e-v1",
    "approved_at": "<UTC-RFC3339-APPROVED-BEFORE-APPLY>",
    "safe_inner_mtu": 1280,
    "maximum_tcp_mss": 1240,
    "sustained_tcp_duration_seconds": 15,
    "minimum_sustained_tcp_bytes": 1048576,
    "iperf_duration_seconds": 10,
    "minimum_throughput_mbps": 5.0,
    "concurrent_duration_seconds": 15,
    "concurrent_tcp_flows": 4,
    "concurrent_udp_flows": 4,
    "maximum_udp_loss_percent": 1.0,
    "maximum_p99_latency_ms": 250.0
  },
  "backend": {
    "bucket": "operator-owned-terraform-state",
    "region": "us-west-2",
    "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/BACKEND-KEY-ID",
    "state_key": "runs/envelope-e2e-001/terraform.tfstate",
    "operator_principal_arns": [
      "arn:aws:iam::123456789012:role/protected-envelope-operator"
    ]
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
      "workload_subnet_cidrs": {
        "a": "172.16.0.0/24",
        "b": "172.16.1.0/24"
      },
      "gwlbe_subnet_cidrs": {
        "a": "172.16.10.0/24",
        "b": "172.16.11.0/24"
      },
      "gwlb_subnet_cidrs": {
        "a": "172.16.20.0/24",
        "b": "172.16.21.0/24"
      },
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
      "workload_subnet_cidrs": {
        "a": "172.17.0.0/24",
        "b": "172.17.1.0/24"
      },
      "gwlbe_subnet_cidrs": {
        "a": "172.17.10.0/24",
        "b": "172.17.11.0/24"
      },
      "gwlb_subnet_cidrs": {
        "a": "172.17.20.0/24",
        "b": "172.17.21.0/24"
      },
      "gwlb_return_cidrs": ["172.17.1.0/24"],
      "local_delivery_cidrs": ["172.17.0.0/24"]
    }
  },
  "tailnet": {
    "name": "_lbr_sandbox",
    "tag": "tag:envelope-acceptance",
    "tag_owners": ["group:network-admins"],
    "snat_subnet_routes": false,
    "auth_key_expiry_seconds": 3600,
    "oauth_client_id_env": "TS_OAUTH_CLIENT_ID",
    "oauth_client_secret_env": "TS_OAUTH_CLIENT_SECRET"
  },
  "envelope": {
    "routing_mode": "manage",
    "tun_name": "envelope0",
    "tailscale_iface": "tailscale0",
    "underlay_interface": "ens5",
    "routing_table_id": 100,
    "routing_rule_priority": 100
  }
}
```

Replace every placeholder. `run_id` must be 4-19 lowercase letters, digits, or hyphens, start with a letter, and end with a letter or digit. `backend.state_key` must be exactly `runs/<run-id>/terraform.tfstate`. The two regions and VPCs must differ, all role subnets must be disjoint, and each site must have exactly two AZ mappings. Terraform creates one GWLBE only in the AZ containing that site's initiator, even though dedicated endpoint subnet CIDRs are reserved in both AZs.

`e2e_load_profile.approved_at` is a human approval record. It must be canonical UTC RFC3339 with seconds, cannot be later than config load, and must precede the durable apply claim. Do not update it automatically at execution time. The reviewed plan, Terraform output, durable manifest, runtime result, and evidence all bind the exact profile and digest.

The supported path MTU is fixed at `1280`; IPv4 TCP MSS must be at most `1240`. Envelope does not promise a usable related ICMP PMTU response for oversized traffic.

## Cost And TTL

The current fixed estimate is `$1.50/hour`, with a default approved ceiling of `$2.00/hour`. The fixed profile contains two NAT gateways/EIPs, two GWLBs, two initiator-AZ GWLBE endpoints, two appliance instances, four workload instances, one artifact bucket, two managed VPC Flow Logs/log groups, and one GWLB target per region. The values are gates, not a price quote; review current regional pricing before every run.

Variable charges are excluded from the estimate: NAT/GWLB/GWLBE data processing, inter-region and internet transfer, CloudWatch ingestion/storage, S3 and API requests/storage, and taxes. The TTL must be 30 minutes to 24 hours in the future for creation and must leave room for the 90-minute acceptance budget plus the reserved 15-minute cleanup budget. Use at least three hours for the standard profile and destroy immediately after the run.

## One-Command Run

From the repository root on an approved protected runner:

```bash
RUN_ID=envelope-e2e-001
CONFIG=".run/${RUN_ID}/config.json"
export ENVELOPE_E2E_APPROVED_RUN_ID="$RUN_ID"
export TS_OAUTH_CLIENT_ID
export TS_OAUTH_CLIENT_SECRET

python3 scripts/aws_two_region_e2e.py run-all \
  --config "$CONFIG" \
  --terraform-dir example/terraform \
  --hard-timeout-seconds 5400
```

`run-all` is the lifecycle owner. It performs protected artifact/preflight, durable prepare/init/plan, exact saved-plan apply, all-six-node readiness, no-drift gates, both cold directional lanes, live wire assertions, MTU/MSS/load and resilience phases, sanitized evidence, destroy, Tailnet/secret cleanup, backend-object cleanup, and the residual audit. It installs cleanup ownership before resource creation and reserves the cleanup timeout. Do not wrap it with a second Terraform destroy or workflow cleanup trap.

## Lower-Level Resume

`run-all` is the fresh-run entrypoint, not permission to replay a claimed one-shot plan. After an interruption, first inspect `.run/<run-id>/run-all-result.json` and the durable manifest. If `run-all` completed cleanup, start a new approved run ID. If the runner was lost before its cleanup handler completed, keep the exact config identity and state key and use only the recovery operation allowed by the durable phase.

For phase-specific diagnosis or recovery on a protected runner, use the lower-level lifecycle commands with the same config and inspect each result before advancing:

```bash
python3 scripts/aws_appliance.py --config "$CONFIG" metadata-preflight
python3 scripts/aws_appliance.py --config "$CONFIG" preflight
python3 scripts/aws_appliance.py --config "$CONFIG" prepare
python3 scripts/aws_appliance.py --config "$CONFIG" init --terraform-dir example/terraform
python3 scripts/aws_appliance.py --config "$CONFIG" plan --terraform-dir example/terraform
python3 scripts/aws_appliance.py --config "$CONFIG" apply --terraform-dir example/terraform
python3 scripts/aws_appliance.py --config "$CONFIG" wait \
  --deployment-file ".run/${RUN_ID}/deployment.json" --timeout-seconds 900
python3 scripts/aws_two_region_e2e.py run-live \
  --config "$CONFIG" \
  --deployment ".run/${RUN_ID}/deployment.json" \
  --terraform-dir example/terraform \
  --hard-timeout-seconds 5400
```

Do not paste this sequence blindly. Read the durable phase first. `apply` is one-shot. `run-live` is the lower-level resume entrypoint only for an already-ready exact deployment; it claims that deployment and owns final cleanup. Do not run raw `terraform apply`, use `-target`, edit the saved plan, or bypass its plan validator.

## Evidence Verification

The runner can produce three retainable JSON files under `.run/<run-id>/`:

| File | Availability and verification |
| --- | --- |
| `run-all-result.json` | Required for every completed `run-all` invocation, including build, preflight, prepare, plan, and apply failures. It is scanned as generic sanitized JSON and is not passed to the schema-2 verifier. |
| `aws-two-region-e2e-evidence.json` | Present only after the full E2E evidence writer starts. It is scanned and schema-2 validated whenever present. A successful `run-all` requires it and must pass strict verification. |
| `diagnostics.json` | Optional bounded diagnostics that can exist before full E2E evidence. It is scanned as generic sanitized JSON and must not be passed to the schema-2 validator or verifier. |

The protected workflow applies the equivalent checks below, adding every file that exists to the repository secret scan:

```bash
RUN_DIR=".run/${RUN_ID}"
RUN_RESULT="${RUN_DIR}/run-all-result.json"
EVIDENCE="${RUN_DIR}/aws-two-region-e2e-evidence.json"
DIAGNOSTICS="${RUN_DIR}/diagnostics.json"

[[ -f "$RUN_RESULT" ]]
retained=("$RUN_RESULT")
python3 scripts/aws_two_region_e2e.py scan-evidence "$RUN_RESULT"

if [[ -f "$EVIDENCE" ]]; then
  python3 scripts/aws_two_region_e2e.py scan-evidence "$EVIDENCE"
  jq --exit-status '.schema == 2 and .kind == "aws-two-region-live"' "$EVIDENCE" >/dev/null
  python3 scripts/aws_two_region_e2e.py validate-evidence "$EVIDENCE"
  retained+=("$EVIDENCE")
fi

if [[ -f "$DIAGNOSTICS" ]]; then
  python3 scripts/aws_two_region_e2e.py scan-evidence "$DIAGNOSTICS"
  retained+=("$DIAGNOSTICS")
fi

secret_scan_args=(--root .)
for path in "${retained[@]}"; do
  secret_scan_args+=(--extra "$path")
done
python3 scripts/secret_scan.py "${secret_scan_args[@]}"
```

For a successful run, require and strictly verify the full evidence after the checks above:

```bash
[[ -f "$EVIDENCE" ]]
python3 scripts/aws_two_region_e2e.py verify-evidence "$EVIDENCE"
```

On failure, absence of `aws-two-region-e2e-evidence.json` means full E2E never began and does not block retention of the scanned run result and optional diagnostics. The workflow copies only the successfully scanned files listed above to a fresh mode-`0700` staging directory, uploads that directory, and then propagates the original nonzero `run-all` exit status. Raw captures are asserted in place and deleted. Never upload the run config, deployment output, state, plans, backend files, command logs, pcaps, or any diagnostics other than the scanned `diagnostics.json`.

## Troubleshooting

- Preflight failure: verify the exact AWS identity/regions/quotas, backend versioning/KMS/public block/policy, `_lbr_sandbox` Tailnet name and OAuth scope, tag owner, all four route auto-approvals, both cross-site grants, artifact provenance, cost ceiling, approval timestamp, and TTL. Preflight must fail before billable resources.
- Plan failure: inspect the redacted plan-validator reason. Expect two appliances, four workloads, two Flow Logs, one regional target, one initiator-AZ GWLBE per region, four semantic lane routes, and no replacement or unexpected deletion.
- Readiness failure: all six EC2 nodes must be SSM-online and cloud-init complete; both appliances additionally require healthy services, accepted routes, routing/firewall/MSS state, HTTP health, and one healthy GWLB target.
- Cold-flow/wire failure: confirm the selected source is the declared initiator, no reverse warm-up occurred, the responder bypasses its regional GWLB, UDP source-port orientation is preserved, destination is 6081, VNI is 0, and ordered AWS options/cookie match.
- MTU/load failure: keep MTU `1280` and MSS at or below `1240`; do not lower approved throughput or raise loss/latency thresholds after planning. A profile change requires a newly reviewed run and plan.
- Cleanup failure: acceptance is failed. Preserve the exact config and durable backend objects, resolve the reported narrow permission/dependency error, and rerun ownership-safe cleanup. Never use broad tag-based deletion.

Do not enable shell tracing around credentials or lifecycle commands. The runner strips OAuth values from AWS and Terraform child environments; retain that boundary when diagnosing.

## Interruption And Cleanup

On `SIGTERM`, timeout, test failure, or normal completion, `run-all` enters its reserved cleanup path and records the outcome in `run-all-result.json` and, when full E2E began, the schema-2 evidence. Allow it to finish. A second concurrent destroy can race manifest compare-and-swap, state locking, Tailnet identity cleanup, and residual auditing.

If the process exited before completing cleanup but the runner and exact local config remain, retry normal recovery cleanup:

```bash
python3 scripts/aws_appliance.py --config "$CONFIG" cleanup \
  --terraform-dir example/terraform --recover
```

If infrastructure must deliberately remain while leaked bootstrap authority is removed, `cleanup --skip-destroy` is the secrets-only emergency operation. It preserves backend objects for later destroy and is not successful infrastructure cleanup.

If the original runner is lost, recover the same non-secret config and use the durable backend manifest. First perform a non-destructive report:

```bash
python3 scripts/aws_appliance.py --config "$CONFIG" janitor \
  --terraform-dir example/terraform --dry-run
```

The TTL janitor refuses destructive cleanup before the exact durable `expires_at`. After expiry:

```bash
python3 scripts/aws_appliance.py --config "$CONFIG" janitor \
  --terraform-dir example/terraform
```

Janitor and emergency cleanup validate exact run/TTL ownership, use an allowlist, audit both regions and the Tailnet, preserve shared backend infrastructure, and retain manifest/state when any cleanup or residual check fails. Retry reported failures; never replace this with account-wide or broad tag deletion.

## GitHub Actions Contract

`.github/workflows/static.yml` runs untrusted PR checks with a permissionless `GITHUB_TOKEN` (`permissions: {}`), no OIDC permission, no repository credential persistence, no secrets, and Terraform `1.10.5`. It performs Go unit/race/vet, Python, Terraform, strict OpenSpec, shell syntax, and repository secret checks only; it makes no live AWS or Tailscale calls.

`.github/workflows/aws-two-region-e2e-live.yml` has only manual and scheduled triggers, serializes runs, requires the `envelope-two-region-e2e` environment, rejects unprotected refs, and obtains AWS credentials only through OIDC. Configure these environment secrets:

- `AWS_E2E_ROLE_ARN`
- `AWS_E2E_REGION`
- `TS_OAUTH_CLIENT_ID`
- `TS_OAUTH_CLIENT_SECRET`
- `ENVELOPE_E2E_CONFIG_TEMPLATE_B64`

`ENVELOPE_E2E_CONFIG_TEMPLATE_B64` is base64 of the reviewed non-credential JSON template above. The workflow writes it under ignored `.run/<run-id>/`, forces mode `0600`, and replaces only `run_id`, `expires_at`, and the exact backend state key. It rejects a template whose Tailnet is not `_lbr_sandbox`; it does not rewrite `e2e_load_profile` or cost approval.

A manual dispatch requires `run_id` and a second exact `approved_run_id` confirmation. Scheduled runs derive a unique `e2e-<GitHub-run-id>` and still wait for environment approval. The workflow sets `ENVELOPE_E2E_APPROVED_RUN_ID` to that exact value and passes the short-lived AWS and Tailscale credentials only to the `run-all` step. Evidence scanning and upload do not receive those credentials. The workflow always requires and scans `run-all-result.json`, conditionally scans `diagnostics.json`, and conditionally validates schema-2 evidence. Success requires strict schema-2 verification; an early failure can upload the sanitized run result and diagnostics before the original run status fails the job. Only the dedicated staging directory is uploaded.
