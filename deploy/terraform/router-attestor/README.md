# Router Attestor Enrollment

This root completes phase two of production router enrollment. It creates no
routers and executes no code remotely. It publishes reviewed collector configs,
version-1 public key bindings, exact source-instance permissions, and private
attestation ingress. Signing seeds are per-router SecureStrings: no seed values
enter Terraform variables, state, user data, logs, or attestation reports.

## Deployment Order

These commands require deployment approval. Local verification does not execute
them against live AWS or Tailscale.

1. Build a clean reviewed release using `scripts/build_controller_artifacts.sh`.
2. For each future router, run the deployment-only `envelope-router-attestor provision-key --region REGION --parameter /envelope/DEPLOYMENT/ROUTER/UNIQUE-SEED --kms-key-arn ARN`. It conditionally creates a fresh seed, never overwrites one, verifies two invocation-bound readbacks, and emits only its ARN, version, and public key. Retain the receipt. Uncertain creation is not cleanup authority. Never reuse an old seed.
3. Supply `router_attestor_bootstrap` to `example/terraform` before creating routers. It requires the exact binary object version/hash, clean manifest, each router's public key, authority region, future unique configuration-parameter ARN, and seed ARN/version. Cloud-init installs the root-owned mode-0555 binary and a boot-only Go enrollment unit. The legacy/data-plane-only profile can omit this input but cannot satisfy controller eligibility.
4. Review actual router instance, primary ENI, stable Tailscale node, transport table/association, workload subnets, and destination-prefix GWLBE identities. Create a `CollectorConfig` and run the reviewed binary's `identity --config PATH`. This emits canonical bytes and hashes without cloud access or secrets. `internal/controller/attestation/testdata/router-config.json` is a synthetic schema example, not deployable authority.
5. Configure this root with an `enrollments` entry per router: the Go identity, actual IAM role and attached security group, and exact parameter references from bootstrap. Supply private `controller_source_cidrs`. Private management routing between controller and site VPCs must already exist.
6. Initialize this root's S3 backend with a reviewed private encrypted bucket, unique state key, and locking configuration, then apply the reviewed enrollment plan. Do not share the appliance or controller state key. Boot-only enrollment retrieves the version-1 pointer, exact S3 config version, version-1 binding, and exact seed version. It verifies hashes, the seed's public key, IMDSv2 instance/ENI/AZ identity, and local stable Tailscale node before atomically installing `/etc/envelope/router-attestor`.
7. Feed this root's `router_attestations` output to the controller root. It contains the independently enrolled public key, configuration SHA-256, and private HTTPS endpoint. Enrollment authority is never learned from a report.

## Immutability And Privileges

Configuration objects are encrypted, private, content-addressed and versioned.
Pointers and public bindings are immutable version-1 records. Updating or
reassigning one fails its postcondition. Use a fresh per-instance key and unique
pointer name for a new configuration or replacement. Deleting a retired binding
does not authorize reusing its old seed. Key retirement and audit retention are
separately reviewed lifecycle operations.

IAM confirms the declared instance's actual transport role and primary ENI.
`ec2:SourceInstanceARN` restricts configuration/seed reads to that exact instance's
credentials. An explicit deny protects against broader grants on shared roles.
KMS decryption is restricted to SSM and the exact parameter encryption context;
direct KMS decryption cannot bypass the source-instance SSM gate. The router role
denies everything except required Describe APIs and bootstrap reads: no route
mutation, IAM mutation, role chaining, DynamoDB writes, or SSM remote execution.
Version-2 legacy acceptance must not use this production policy.

Config/binding files are mode 0444, the seed is 0400, and the directory is 0500.
Existing enrollments are verified, never overwritten. On reboot the enroller
uses sealed files rather than resolving mutable secret state. It starts the
inspector through systemd D-Bus and stops its boot timer. SSM/S3 enrollment is a
separate boot operation, not a steady-state readiness mechanism.

The inspector requires **CAP_NET_ADMIN** for Linux netfilter reads. Datagram
control sockets avoid **CAP_NET_RAW**. NET_ADMIN is real host-network admin
privilege if the trusted process is compromised, not a fictitious read-only
capability. The inspector exposes only read operations. The unit bounds
capabilities, syscalls, writable mounts, address families, memory, descriptors,
and tasks. AWS permissions remain read-only independently of Linux privileges.

Root UID is also used for restricted local Tailscale preferences and systemd
state. Local daemon authorization may trust root independently of Linux
capability bits. A compromised signer therefore remains a compromised trusted
host component, not a hardware-attestation boundary; capability bounding alone
does not make arbitrary root code read-only. Collector code invokes only status,
preference reads, peer probes, and kernel/cloud inspection.

## Kernel Contract

Supported: Linux LP64 amd64/arm64, pinned Tailscale 1.80.3 kernel-TUN mode, legacy
iptables/ip6tables, and direct VPC DNS resolver entries in `/etc/resolv.conf`.
Local DNS stubs require a separate upstream proof and are rejected. Unknown
rtnetlink selectors, nexthop objects, encapsulation, firewall matches/targets,
native nftables tables, inconsistent/truncated dumps, NAT, and stale MSS fail
closed. No unsupported result can authorize eligibility.

The inspector verifies complete policy rules, every overlapping host route,
legacy hooks/chains, IPv6 denial, live MTUs, exact VPC associations and routes,
and destination workload/GWLBE AZ agreement. Kernel/cloud checks are repeated
before signing. Markers and service state are additional prerequisites, never
substitutes for live forwarding proof. No runtime shell, Python, or subprocess
is invoked by the inspector.

## Verification

`terraform test` uses mocked AWS providers. Go fixtures cover UAPI decoding,
full-prefix bypasses, association/AZ drift, config/signature binding, ambiguous
seed creation, and immutable installation.

On an approved Linux host, run `sudo bash scripts/integration_router_attestor.sh`
from the repository root. It requires iproute2, legacy iptables/ip6tables,
nftables, util-linux, and the reviewed Go toolchain. It uses an isolated network
namespace and actual kernel fixtures, tests failure/recovery, and removes
CAP_NET_RAW during native inspection. It never joins a Tailnet or contacts AWS.
Missing privileges or kernel prerequisites fail the check, not produce a pass.

Darwin can cross-compile the tagged test, but cannot execute it. Cross-compilation
is not native Linux execution evidence and neither is protected live evidence.
