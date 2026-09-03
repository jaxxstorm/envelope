# Vendored Tailscale Cloud-Init Module

This module is a reviewed derivative of `tailscale/tailscale/cloudinit` release
`0.0.11`. Its multipart `cloudinit_config` and `additional_parts` interface are
retained, with reviewed `pre_setup_parts` for prerequisites that must complete
before route advertisement. The mutable track installer was replaced with exact
Tailscale 1.80.3 Amazon Linux 2023 RPM URLs, repository-metadata SHA-256 values,
and the vendored Tailscale package signing key. Package installation and
signature verification complete before the runtime SSM auth-key resolver or
`tailscale up` can run. The reviewed transport derivative explicitly disables
Tailnet DNS acceptance so the VPC resolver remains authoritative.
`SOURCE.sha256` pins every executable, Terraform, license, and signing-key input
in the reviewed vendored module.
