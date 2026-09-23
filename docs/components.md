# Components

Envelope uses four roles. Each role has a narrow job so a packet-processing process cannot also control AWS routing.

| Role | Runs on | What it does |
| --- | --- | --- |
| Envelope target | EC2 behind a GWLB target group | Returns every inspected packet to GWLB. AWS then sends it to the local VPC or a transport router. |
| Transport router | EC2 in each site's transport subnet | Runs Tailscale and forwards traffic between the VPC and Tailnet without NAT. |
| Router attestor | Each production transport router | Checks the router's forwarding, firewall, route, and identity state and reports whether it is eligible. |
| Production controller | Three EC2 replicas outside targets and routers | Watches Tailscale ownership, persists a lease and route journal, and updates approved GWLBE routes. |

## Envelope Target

Install `envelope` on a Linux EC2 instance and register the instance with a GWLB target group. The target listens on UDP/6081. It does not run Tailscale, create a tunnel interface, or decide whether traffic is local or remote. The appliance Terraform root builds this fleet and registration for every enabled availability zone.

## Transport Router

Each site needs at least two transport routers in different availability zones. They advertise the site's workload prefixes to Tailscale, accept the peer site's prefixes, and preserve source IP addresses. They are the only hosts that carry traffic across the Tailnet.

## Production Controller

The controller is required for the production version-3 topology. Run three replicas in separate failure domains. Before updating a GWLBE route, the controller requires fresh router observations, signed attestation, Tailscale owner agreement, AWS instance and ENI eligibility, a durable lease, and route readback.

## Deployment Order

Deploy the appliance topology first, enroll the transport-router attestors second, then deploy controller replicas in read-only mode and activate approved domains. The [Deployment Guide](deployment.md) provides commands and inputs for each phase.
