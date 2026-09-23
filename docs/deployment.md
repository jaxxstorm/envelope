# Deployment Guide

This guide deploys the production version-3 topology: two AWS sites connected by Tailscale, with GWLB inspection and a production controller. It uses three Terraform state roots because the appliance topology, per-router enrollment authority, and controller route authority have different lifecycles.

## Before You Start

You need:

- Terraform `>= 1.10.1, < 1.11.0` and the pinned AWS provider.
- Two AWS Regions and two availability zones per site.
- Reviewed Amazon Linux AMIs for the target, transport-router, and controller architectures.
- A private remote Terraform backend and one distinct state key per root.
- A clean reviewed checkout and reviewed Go toolchain for release artifacts.
- Tailscale tags, ACL/route approvals, and SecureString parameters for router and controller credentials.
- IAM and KMS authority for the resources each phase creates or reads.
- An explicit expiration time, current cost review, and a cleanup owner.

The deployment creates billable AWS resources. Do not use the placeholder values in [Terraform Inputs](terraform-example.md), reuse old state, or combine state keys between phases.

## 1. Build The Target Artifact

From a clean reviewed checkout, build the Linux target artifact that the appliance root uploads and installs on target EC2 instances:

```bash
./scripts/build_artifacts.sh --output-dir dist --version 1.0.0 --architectures amd64
```

Record the artifact path, SHA-256, Git revision, and version for the appliance variables. Build `arm64` instead when your selected AMIs use that architecture.

## 2. Deploy The Appliance Topology

`example/terraform` creates the two VPCs, workload and transport subnets, GWLBs, GWLBE endpoints, EC2 transport routers, and route tables. It uses a reviewed two-phase deployment: infrastructure first creates the intentionally empty inspection service, then targets registers the Envelope target EC2 fleet.

Prepare a reviewed `production.tfvars` outside version control. It must provide the run name and expiry, regions, AMIs, artifact identity, Tailscale SecureString and KMS references, Tailscale tag, cost ceiling, load profile, and complete `symmetric_topology`. Set `symmetric_topology.version = 3` for the production controller topology. Version 2 is the legacy acceptance profile.

Use a dedicated backend key for the appliance state:

```bash
terraform -chdir=example/terraform init -backend-config=appliance.backend.hcl
terraform -chdir=example/terraform validate
terraform -chdir=example/terraform plan -var-file=production.tfvars -var='deployment_phase=infrastructure' -out=appliance-infrastructure.tfplan
terraform -chdir=example/terraform show appliance-infrastructure.tfplan
terraform -chdir=example/terraform apply appliance-infrastructure.tfplan
terraform -chdir=example/terraform plan -var-file=production.tfvars -var='deployment_phase=targets' -out=appliance-targets.tfplan
terraform -chdir=example/terraform show appliance-targets.tfplan
terraform -chdir=example/terraform apply appliance-targets.tfplan
```

Save the infrastructure outputs before proceeding. During infrastructure, target groups are intentionally empty and inspected application traffic fails without a direct-route fallback. Review the targets plan before applying it; only that phase adds the Envelope EC2 targets and registrations. The next phases need the target/router identities, route tables, GWLBE associations, controller topology seed, and router-attestor enrollment seed. The controller does not yet own failover.

## 3. Enroll Production Routers

Production routers must have a unique signed-attestation key and immutable configuration before the controller will consider them eligible. Build the controller artifact set, provision a unique seed for each future router, and create the enrollment configuration from the appliance outputs.

```bash
scripts/build_controller_artifacts.sh --output-dir dist/controller --version 1.0.0
envelope-router-attestor provision-key --region REGION \
  --parameter /envelope/DEPLOYMENT/ROUTER/UNIQUE-SEED \
  --kms-key-arn KMS_KEY_ARN
terraform -chdir=deploy/terraform/router-attestor init -backend-config=router-attestor.backend.hcl
terraform -chdir=deploy/terraform/router-attestor plan -var-file=router-attestor.tfvars -out=router-attestor.tfplan
terraform -chdir=deploy/terraform/router-attestor apply router-attestor.tfplan
```

`router-attestor.tfvars` contains the actual router IDs, public keys, instance and ENI identities, private controller source CIDRs, and versioned artifact/configuration references. Keep the enrollment root's state separate from appliance and controller state. Its `router_attestations` output is an input to the controller root. See [Router Attestor Enrollment](../deploy/terraform/router-attestor/README.md) for the complete input contract.

## 4. Deploy Controller Replicas

The controller root creates exactly three standalone controller EC2 replicas. It does not create the GWLB or transport routers; it validates and manages the existing route domains.

Create a canonical controller topology identity from the reviewed source topology, then apply the controller root in its default read-only mode:

```bash
dist/controller/envelope-controller-topology-linux-amd64 identity \
  --input controller-topology.source.json > controller-topology-identity.json
terraform -chdir=deploy/terraform/envelope-controller init -backend-config=controller.backend.hcl
terraform -chdir=deploy/terraform/envelope-controller plan \
  -var-file=controller.tfvars -out=controller.tfplan
terraform -chdir=deploy/terraform/envelope-controller apply controller.tfplan
```

`controller.tfvars` supplies three private controller placements, the immutable artifact manifest and identity, controller AMI and egress, secret parameter references, `router_attestations`, exact route domains, transport topology, readiness publisher, alarm actions, and lifecycle trust. The controller root checks that current GWLBE targets are already eligible router ENIs.

## Logging And Monitoring

Both Terraform roots accept `cloudwatch_log_retention_in_days`, which defaults to `7` and accepts only CloudWatch Logs retention values. Set the same reviewed value in the appliance and controller variable files when a different retention period is required.

The appliance root sends VPC Flow Logs and application logs to CloudWatch Logs. Each site has `/envelope/RUN_NAME/SITE/application`; targets write the Envelope service log, while transport routers write their host-network, Tailscale, and router-attestor logs. The controller root sends controller logs to `/envelope/RUN_NAME/controller/application`. CloudWatch Agent delivery roles can create streams and publish events only in their assigned application log group; they cannot create log groups or alter retention.

Treat application logs as operational data. Do not log Tailnet auth keys, controller API credentials, or Terraform/backend credentials.

## 5. Initialize And Activate Route Control

The first controller apply installs read-only replicas. Do not grant active route authority until all replicas report fresh observations and every router has a passing attestation.

1. Use `envelope-controller-deploy initialize` with the reviewed topology, router trust document, `deployment_lifecycle_role_arn` output, and external ID to create inactive domain journals.
2. Confirm all replicas are healthy and their `/readyz` endpoints report fresh quorum and route agreement.
3. Prepare one reviewed saved plan at a time to move a single controller replica to active mode. Use `envelope-controller-deploy rollout` to apply it; do not replace all replicas together.
4. Use `envelope-controller-deploy activate --domain DOMAIN_ID` only after the active replica, router attestation, owner agreement, and current route targets agree.

The controller can now align approved GWLBE route targets with the Tailscale owner. It never changes workload routes, target-group membership, router advertisements, or unlisted route tables.

The command form is:

```bash
envelope-controller-deploy initialize \
  --topology controller-topology.json \
  --domain DOMAIN_ID \
  --initialization-role-arn LIFECYCLE_ROLE_ARN \
  --external-id REVIEWED_EXTERNAL_ID \
  --router-trust router-trust.json

envelope-controller-deploy activate \
  --topology controller-topology.json \
  --domain DOMAIN_ID \
  --initialization-role-arn LIFECYCLE_ROLE_ARN \
  --external-id REVIEWED_EXTERNAL_ID \
  --router-trust router-trust.json
```

`router-trust.json` is the reviewed topology-bound trust document assembled from the router-attestor enrollment outputs. The controller Terraform root also publishes the same trust data to SSM for runtime use. Keep the document and lifecycle role configuration under the same change review as the topology.

## Manual Deployment Order

Terraform is the supported way to create the complete resource graph. If you integrate manually through your own IaC or AWS console, reproduce this order:

1. Create separate workload, target, GWLB, GWLBE, transport-router, and management subnets in two availability zones at each site.
2. Create a GWLB and target group in each site; install `envelope` on target EC2 instances, allow UDP/6081 from GWLB, and register one healthy target per enabled availability zone.
3. Create GWLBE endpoints and workload routes so remote-site prefixes enter the same-site GWLBE. Configure GWLBE subnet routes to send remote prefixes only to eligible same-site transport-router ENIs.
4. Create at least two transport routers per site, install Tailscale, advertise the complete local workload-prefix set, accept the peer's prefixes, and configure no-NAT forwarding, firewall, and MSS clamping.
5. Enroll every production router with the attestor, then deploy three read-only controller replicas with exact route-domain authority.
6. Initialize journals, verify health and owner agreement, roll one controller replica to active mode, and activate domains individually.

Manual deployment must still create the same IAM boundaries, immutable artifact references, durable controller state, alarms, and rollback path enforced by the Terraform roots. Do not point a GWLBE route directly at an unverified router or give targets and routers AWS route-mutation authority.

## Rollback And Cleanup

To stop controller route changes, deactivate the affected domains and wait for the required lease/action drain. Keep durable journals and lifecycle locks for reviewed recovery; do not delete them to force progress. Roll controller replicas back to read-only before destroying controller infrastructure.

Restore each GWLBE route to a known eligible router ENI before destroying the appliance topology. Destroy in reverse state order: controller root, router-attestor root, then appliance root. Confirm no run-owned AWS resources, SSM parameters, Tailnet devices, backend objects, or route changes remain before closing the deployment.

## Local Testing

For a non-AWS development path, see [Local Testing](getting-started.md). Unit tests and local integration prove only their stated boundaries; they do not prove your AWS routes, Tailscale policy, or production recovery.
