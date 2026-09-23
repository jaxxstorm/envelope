# Vendored Tailscale Cloud-Init Module

This module retains the multipart `cloudinit_config` and `additional_parts`
interface from `tailscale/terraform-cloudinit-tailscale`. It is intentionally
vendored instead of using upstream v0.0.12. The reviewed comparison found that
v0.0.12 does not provide both controls required by this deployment:

- checksum-pinned Tailscale package installation; and
- a pre-setup gate that completes before runtime credential resolution and
  `tailscale up`.

The mutable track installer is replaced with exact Tailscale 1.80.3 Amazon Linux
2023 RPM URLs, repository-metadata SHA-256 values, and the vendored Tailscale
package signing key. Package installation and signature verification complete
before the runtime SSM auth-key resolver or `tailscale up` can run. The reviewed
transport derivative explicitly disables Tailnet DNS acceptance so the VPC
resolver remains authoritative.

`SOURCE.sha256` pins every executable, Terraform, license, and signing-key input
in this reviewed vendored module. Do not replace the local source with upstream
until a reviewed upstream version supplies both controls and its inputs are
verified under the same supply-chain contract.
