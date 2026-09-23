# Envelope

Envelope builds a site-to-site network between two AWS VPCs. It uses Tailscale as the encrypted transport and puts AWS Gateway Load Balancer (GWLB) in front of that transport so traffic can be inspected in both directions.

You deploy three things:

1. **Envelope targets**: EC2 instances behind GWLB. They return each inspected packet to GWLB so AWS can choose the next hop.
2. **Tailscale transport routers**: EC2 instances that carry traffic between the two VPCs without NAT.
3. **Production controller**: three EC2 replicas that watch Tailscale ownership and update the approved GWLBE route targets when a router fails or returns.

## Deploy Envelope

Follow the [Deployment Guide](deployment.md). It gives the Terraform phase order, input checklist, controller initialization and activation steps, and rollback order.

## Understand The Design

- [Architecture](architecture.md): the traffic path and a complete deployment diagram.
- [Components](components.md): what each EC2 role runs and owns.
- [Production Controller](production-controller.md): how controller replicas make route changes safe.

## Operate It

- [Operations](operations.md): health endpoints, routine checks, and deployment stages.
- [Troubleshooting](troubleshooting.md): common target, router, and controller failures.
- [Best Practices](best-practices.md): application retries and operating boundaries.

## Develop And Test

- [Local Testing](getting-started.md): build, test, and run the target locally.
- [Terraform Inputs](terraform-example.md): how the appliance topology is configured.
- [Developer E2E Documentation](developer/README.md): acceptance harnesses and historical evidence.
