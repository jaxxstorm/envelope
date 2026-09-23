# Troubleshooting

## Packet Target Is Unready

Check the target process, `GET /healthz`, and the receive, profile-rejection, return-build, send-failure, and MTU metrics. Confirm the configured version, UDP bind address, and packet size. A target health result only describes packet turnaround; it does not diagnose Tailscale or GWLBE routing.

Inspect the target stream in `/envelope/RUN_NAME/SITE/application` in CloudWatch Logs. Its stream name ends in `/envelope-target`.

The target needs `CAP_NET_RAW` but not `CAP_NET_ADMIN`. Do not add routing or Tailscale privileges to resolve a target symptom.

## Transport Router Cannot Carry Traffic

Use read-only host and Tailscale inspection to verify the service is active, forwarding and reverse-path settings match the reviewed contract, no-NAT firewall and MSS rules are present, and exact remote routes select Tailscale. Confirm `CorpDNS` is disabled, the health set is empty, and local workload prefixes remain on the VPC underlay rather than Tailscale table 52.

Inspect the `/transport-router`, `/tailscaled`, and, when enabled, `/router-attestor` streams in the site's application log group.

Do not repair the symptom with manual GWLBE route changes or unreviewed route advertisements. Escalate through the protected workflow when cloud eligibility, ownership, or route convergence is involved.

## Controller Is Not Ready

Inspect controller `/healthz`, `/readyz`, `/metrics`, and structured logs. A follower can be healthy while not holding a domain lease. A leader remains route-ineligible when observations disagree, a router attestation is stale, cloud eligibility fails, or route readback is ambiguous.

Controller logs are in `/envelope/RUN_NAME/controller/application`, with one `/controller` stream per replica.

Do not clear durable journals, locks, or fencing state to force progress. Follow the documented controller recovery and approved lifecycle procedures.

## Traffic Did Not Survive A Failure

Envelope does not provide hitless transport continuity. Established TCP can be interrupted and UDP can lose packets while routes or ownership converge. Confirm whether a new flow recovered, then investigate application retry behavior separately from network control-plane evidence. See [Best Practices](best-practices.md) and [Application Resilience](application-resilience.md).
