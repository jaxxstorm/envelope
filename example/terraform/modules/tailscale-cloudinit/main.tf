locals {
  upstream_release = "tailscale/tailscale/cloudinit@0.0.11"
}

data "cloudinit_config" "main" {
  gzip          = false
  base64_encode = true

  lifecycle {
    precondition {
      condition     = startswith(var.auth_key, "command:")
      error_message = "The protected deployment accepts only a runtime command: auth-key resolver."
    }
  }

  part {
    filename     = "10-install-pinned-tailscale.sh"
    content_type = "text/x-shellscript"
    content = templatefile("${path.module}/templates/install_tailscale.sh.tftpl", {
      package_version = var.package_version
      package_url     = var.package_url
      package_sha256  = var.package_sha256
      signing_key     = base64encode(file("${path.module}/files/repo.gpg"))
      max_retries     = var.max_retries
      retry_delay     = var.retry_delay
    })
  }

  part {
    filename     = "20-setup-tailscale.sh"
    content_type = "text/x-shellscript"
    content = templatefile("${path.module}/templates/setup_tailscale.sh.tftpl", {
      auth_key           = sensitive(var.auth_key)
      hostname           = var.hostname
      advertise_tags     = join(",", var.advertise_tags)
      advertise_routes   = join(",", var.advertise_routes)
      accept_routes      = var.accept_routes
      snat_subnet_routes = var.snat_subnet_routes
      netfilter_mode     = var.netfilter_mode
      timeout            = var.timeout
      max_retries        = var.max_retries
      retry_delay        = var.retry_delay
      package_version    = var.package_version
    })
  }

  dynamic "part" {
    for_each = var.additional_parts
    content {
      filename     = part.value.filename
      content_type = part.value.content_type
      content      = part.value.content
    }
  }
}
