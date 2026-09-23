## Context

`example/terraform` currently creates VPC primitives directly and creates the GWLB target fleet in the same graph as GWLB endpoints and routes. The supported topology is production-v3: Envelope runs only as an EC2 packet-turnaround target, dedicated EC2 transport routers run Tailscale, and the standalone controller reconciles GWLBE route targets. The current local Tailscale cloud-init module is a reviewed derivative with a pinned installer and a pre-setup network gate.

This change must make the foundational network reviewable before target rollout without permitting a traffic bypass, while preserving the existing two-region, two-AZ route domains and controller/router authority boundaries.

## Goals / Non-Goals

**Goals:**
- Replace hand-authored VPC and common subnet primitives with `terraform-aws-modules/vpc/aws` v6.7.2, pinned in configuration and `.terraform.lock.hcl`.
- Add an explicit deployment-phase input with `infrastructure` and `targets` values.
- Make `infrastructure` create the VPCs, route domains, GWLBs, target groups/listeners, endpoint services, GWLBE endpoints, workload and router paths, and controller topology inputs, while creating no Envelope EC2 target or target-group attachment.
- Make `targets` add the existing EC2 Envelope fleet and its registrations after a reviewed plan, without changing the controller or router model.
- Document the exact policy fragments operators must derive from the configured tag and site CIDRs, and why the vendored cloud-init module remains necessary.

**Non-Goals:**
- Migrating the controller, targets, or routers to ECS or any container orchestration platform.
- Altering Envelope's version-2 packet-turnaround runtime, EC2 target health check, target IAM boundary, or target routing model.
- Changing production-v3 controller ownership, Tailscale native route ownership, or EC2 router forwarding behavior.
- Replacing the vendored module with `tailscale/terraform-cloudinit-tailscale` v0.0.12.
- Making the infrastructure-only phase usable for application traffic.

## Decisions

### Use a root-module phase selector rather than Terraform `-target`

Add a validated input such as `deployment_phase = "infrastructure" | "targets"`. The foundational resources remain present in both phases. Only Envelope target instances, their target-only supporting resources where dependencies permit, and `aws_lb_target_group_attachment` resources are conditional on `targets`. Operators first review and apply the infrastructure plan, then change the explicit phase, review the second plan, and apply normally against the same state.

This creates a durable, auditable empty-target-group state and avoids Terraform's unsafe partial-graph `-target` behavior. A second root module or separate state was rejected because it would duplicate cross-phase identifiers and complicate endpoint, route, artifact, IAM, and destroy ownership.

### Treat the empty target group as an intentional fail-closed state

The infrastructure phase creates GWLB, listener, endpoint service, GWLBE endpoints, and the workload and transport routes that select them. It creates zero Envelope targets and zero attachments. Probes through an inspected path are therefore expected to fail until the target phase has registered healthy targets; no alternate direct route is introduced. Outputs and tests will identify this expected unavailable state so it is not mistaken for a completed deployment.

### Use the VPC module only for VPC primitives; retain explicit specialized route domains

Instantiate `terraform-aws-modules/vpc/aws` v6.7.2 once per Region with the appropriate provider alias and explicit reviewed AZ/CIDR inputs. Map its VPC, internet gateway, NAT gateway, subnet, and common route-table outputs into the existing topology. Continue to declare GWLBE, GWLB, target, transport, workload, and management associations and exact routes explicitly where the module does not model the required AWS GWLB route-domain semantics.

Using a single generic subnet class or relying on dynamic AZ discovery was rejected because the topology requires stable, named, per-AZ inspection paths and controller-bound association identities.

### Retain the reviewed local Tailscale cloud-init module

Keep `./modules/tailscale-cloudinit` as the transport-router module source. Its provenance documentation will explicitly compare it with upstream `tailscale/terraform-cloudinit-tailscale` v0.0.12 and state that upstream does not supply the required checksum-pinned RPM installation or pre-setup gate. The local module's pinned package URL/checksum, vendored signing key, `SOURCE.sha256`, and `pre_setup_gate` ensure network prerequisites complete before credential resolution and `tailscale up`.

Upstream v0.0.12 is rejected until it demonstrably provides both controls under a reviewed supply-chain contract.

### Publish policy derived from declared topology, not permissive examples

User documentation will provide a policy template whose only substitutions are the configured `tailscale_tag` and the exact union of `symmetric_topology.sites.*.local_site_cidrs`. It will require one tag-owner entry for the configured router tag, an ACL allowing only bidirectional traffic between the configured west and east workload CIDRs, and `autoApprovers.routes` entries approving every exact local workload CIDR for that tag. The bootstrap key must be reusable, preauthorized, tagged only with that tag, and stored only in the regional SecureString referenced by the router instances. Route approval and policy validation precede the infrastructure apply.

Broad `autogroup:member`, `*`, supernet, or all-port policy examples are rejected because they conceal the source-preserving site-transit boundary.

## Risks / Trade-offs

- [Infrastructure phase fails application probes by design] → Output and user documentation label the empty target groups and expected data-plane failure; target-phase tests prove the transition to registered targets.
- [VPC module upgrade changes implicit resource shape] → Pin v6.7.2, retain the dependency lock, use explicit reviewed AZ/CIDR inputs, and add plan assertions for each route domain and endpoint.
- [Conditional targets leave stale instances after returning to infrastructure] → Document `infrastructure` as an initial-deployment phase, validate phase-specific planned counts, and require a reviewed plan before any phase change.
- [Operators grant too much Tailnet access] → Publish exact tag, CIDR, ACL, and route-approval requirements and make policy preflight fail before AWS creation.
- [Replacing the vendored module weakens supply-chain or ordering guarantees] → Keep the local module and test its pinned package and pre-setup gate contract.

## Migration Plan

1. Update module configuration, lockfile, topology references, and Terraform tests while preserving the current explicit two-site inputs and resource ownership.
2. Introduce `infrastructure` as the documented first-phase value. Run `terraform init`, review the plan, and apply normally to create endpoints and the empty target groups.
3. Verify each site/AZ has a GWLB and GWLBE endpoint, each target group has no registered target, and routed data-plane probes fail without a direct-path fallback.
4. Configure and validate the exact Tailscale tag ownership, ACL, and per-prefix route approval policy before router bootstrap.
5. Change the phase to `targets`, review the normal plan, and apply it to create the EC2 Envelope instances and target-group attachments. Wait for the reviewed health contract before traffic validation and controller lifecycle actions.
6. Roll back a failed target rollout by returning to the reviewed infrastructure state or removing target resources; the resulting empty target groups continue to fail closed. Do not substitute direct workload routes or move roles to ECS.

## Open Questions

None. The phase selector, v6.7.2 pin, EC2 role preservation, local cloud-init module, and required Tailnet policy scope are fixed by this change.
