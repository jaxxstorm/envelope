## Context

The existing Terraform creates two VPCs, GWLBs, endpoint services, Tailscale appliance instances, and test instances. Appliance user data is only the Tailscale cloud-init module output. Envelope-specific values are outputs rather than runtime inputs, so no binary or health server exists on either GWLB target. A fresh plan also depends on apply-time subnet IDs as `for_each` keys, which prevents clean convergence.

The deployment must consume the wire-compliance and host-routing contracts without inventing packet behavior. Because flow context is process-local, this version uses exactly one Envelope flow owner per region. Multiple endpoint AZs can use that target only with explicit GWLB cross-zone behavior; multiple active Envelope targets require a future return-affinity or shared-state design.

## Goals / Non-Goals

**Goals:**
- Build, publish, verify, install, configure, and run Envelope on both regional appliances.
- Make one clean Terraform plan/apply converge and a second plan show no changes.
- Keep Tailscale bootstrap secrets out of Terraform values and rendered user data.
- Persist and validate host-network prerequisites across reboot.
- Make west/east runtime inputs, Tailnet authorization, and GWLB target readiness observable.
- Make provider, module, architecture, and image selections reproducible.

**Non-Goals:**
- Building a general-purpose release service or package repository.
- Supporting multiple active Envelope targets per region without explicit flow affinity.
- Managing organization-wide Tailnet policy from this example.
- Claiming production high availability from the acceptance profile.

## Decisions

### 1. Build once and deploy a checksum-addressed artifact

A build step produces a static Linux binary for the selected architecture with version metadata and SHA-256. Terraform uploads the artifact to a test-owned, encrypted S3 object and grants each appliance read access only to that object. Cloud-init verifies the checksum before atomically installing it.

Alternative: install Go and build from a mutable repository during boot. Rejected because it is slow, non-reproducible, and makes target replacement dependent on external source state.

### 2. Retrieve Tailscale credentials at boot

The protected runner holds a separate narrowly scoped Tailscale OAuth/API credential outside Terraform. It creates a short-lived, reusable, preauthorized, ephemeral-node auth key, writes that generated key to regional run-scoped SSM SecureStrings, and records intended parameter identities before creation. After readiness it requests full device records and durably records both exact node IDs. Terraform receives only each site's SSM parameter ARN. Site-specific instance roles permit one exact parameter/KMS encryption context and the exact artifact. Cleanup deletes and verifies exact node IDs; hostname/tag fallback is limited to a post-apply partial-recovery manifest and must identify exactly both nodes. Replacement rotates the key across both regions with rollback, durably records the new ID, and revokes the old key before planning.

Alternative: a sensitive Terraform string. Rejected because sensitivity redacts display but not state or user data.

### 3. Install a first-class systemd service

The vendored, checksummed derivative of Tailscale cloud-init 0.0.11 preserves `additional_parts` while replacing its mutable installer with exact signed/checksummed 1.80.3 AL2023 packages. Package verification completes before the SSM resolver or first `tailscale up`. Additional parts install host configuration, Envelope configuration, and `envelope.service`. A root `envelope-host-network.service` oneshot owns every sysctl/firewall mutation and is ordered before Envelope. The unprivileged Envelope `ExecStartPre` is read-only under `ProtectKernelTunables`; the service restarts on failure and receives only the capabilities required for TUN/routing and compliant packet emission.

### 4. Persist host-network requirements

Cloud-init writes versioned sysctl and firewall/MSS-clamp configuration instead of one-time commands. Boot validation covers forwarding, reverse-path filtering, forwarding policy, Tailscale backend state, accepted remote routes, and required return-routing rules. Reboot is an acceptance condition.

### 5. Use static Terraform graph keys

Resources indexed by subnets or AZs use configuration-known keys such as AZ index or CIDR, never provider-computed subnet IDs. A clean plan must succeed without `-target`, and one apply must converge. Resource names derive from `var.name` to isolate runs.

### 6. Pin execution inputs

Terraform and provider ranges have tested upper bounds, `.terraform.lock.hcl` is explicitly unignored, vendored module content has a reviewed hash manifest, regional AZ names are explicit inputs, and the AMI ID is explicit per region and architecture. The artifact builder pins the reviewed Go toolchain and validates `go version -m` OS/architecture/VCS provenance against the manifest. Validation maps Go `amd64` to EC2 `x86_64`, Go `arm64` to EC2 `arm64`, and rejects instance types incompatible with the chosen AMIs/artifact. Saved plans record all selected IDs and artifact hashes.

### 7. Keep one flow owner per region

The acceptance deployment creates one Envelope/Tailscale appliance and one GWLB target per region. When endpoints span multiple AZs, cross-zone load balancing is explicitly enabled. Terraform rejects more than one target until the routing design can guarantee that Tailnet returns reach the process holding the matching GWLB context. Workload, GWLBE, and appliance subnets have separate route tables to prevent recirculation.

### 8. Treat Tailnet state as a deployment gate

The test Tailnet policy is preconfigured with tag ownership, route auto-approval for the Envelope tag and lane CIDRs, and grants between lane CIDRs. Live automation does not mutate Tailnet policy or depend on manual approval. Bootstrap success requires disabled subnet-route SNAT, `tailscale status --json` reporting a Running backend, and effective remote routes; interface existence alone is insufficient.

### 9. Use durable run state and independent cleanup

Terraform uses a pre-provisioned, encrypted, access-controlled operator-owned backend with locking and a unique per-run state key. One validated run configuration supplies AZs, subnet roles, lane roles, Tailnet policy inputs, and every Terraform variable; no second network tfvars source is accepted. The run owns its state object, lock, and protected cleanup manifest, but never deletes the shared backend infrastructure. Before any create, the manifest contains every non-secret destroy input, artifact recovery locator, predictable SSM identities, and exact ownership/TTL identity. Prepare and apply boundaries are uploaded before side effects. An independent janitor can recover expired runs, use Terraform state when present, and remove only allowlisted residual types carrying the exact run/TTL tags. Cleanup verifies every historical state/lock/manifest version and delete marker is absent while preserving the backend bucket and KMS key.

## Risks / Trade-offs

- [S3 artifact and secret dependencies add IAM] -> Scope permissions to exact ARNs and verify with policy tests.
- [Cross-zone GWLB adds cost and an AZ dependency] -> Label this as an acceptance profile and add a later per-AZ design before HA claims.
- [Cloud-init can finish while services are still converging] -> Add explicit SSM/systemd/Tailnet/GWLB readiness gates after apply.
- [Mutable Tailnet policy can break a run] -> Validate effective policy and routes during preflight and retain redacted evidence.
- [AMI pinning needs maintenance] -> Make AMI updates an explicit reviewed input rather than automatic replacement.
- [Runner loss can strand billable resources] -> Use durable state, a protected cleanup manifest, TTL tags, and an independent janitor.

## Migration Plan

0. Verify the options, GWLB wire, and Tailscale routing changes are implemented, synced, and archived.
1. Revoke the existing plaintext Tailscale key, quarantine legacy local artifacts, and configure a scoped Tailnet OAuth/API credential.
2. Fix configuration-known Terraform graph keys and pin dependencies.
3. Add artifact build/upload and least-privilege download permissions.
4. Add persistent host setup, site configuration, and systemd unit through cloud-init.
5. Add Tailnet and GWLB readiness outputs/checks.
6. Prove fresh plan, single apply, reboot, no-drift plan, and destroy using durable isolated state.
7. Prove janitor cleanup after simulated runner loss.
8. Roll back by destroying the test stack, deleting generated nodes/secret, and revoking the generated key; no previous non-working bootstrap path is retained.

## Open Questions

- Whether the long-term artifact channel should remain S3 or become a signed GitHub release/package repository.
- Whether a future HA design will use AZ-specific Tailscale prefixes, flow-state replication, or another return-affinity mechanism.
