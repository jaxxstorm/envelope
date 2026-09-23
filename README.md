# Envelope

Envelope connects two AWS VPCs as a site-to-site network using Tailscale for encrypted transport and AWS Gateway Load Balancer (GWLB) for inline inspection. Workloads keep their ordinary private IP addresses: traffic between sites passes through GWLB, crosses Tailscale between dedicated router EC2 instances, then passes through GWLB again at the destination site.

Envelope runs on EC2 instances registered as GWLB targets. It receives an inspected packet from GWLB and returns it so AWS can send the traffic either to the local VPC or to the site's Tailscale router. A separate production controller keeps the AWS route targets aligned with Tailscale router ownership during failure and recovery.

Start with the [deployment guide](docs/deployment.md). It covers the Terraform roots, controller activation, rollback order, and required AWS/Tailscale inputs. Read [Architecture](docs/architecture.md) to understand the components and [Local Testing](docs/getting-started.md) to run Envelope without AWS.

> [!WARNING]
> Envelope is **Experimental**. The repository provides the implementation and deployment roots, but a maintainer must supply reviewed AWS, Tailscale, artifact, backend, and credential inputs for each environment.
