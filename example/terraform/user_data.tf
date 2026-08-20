locals {
  west_auth_resolver = "command:AWS_PAGER= /usr/bin/aws ssm get-parameter --region ${var.west_region} --name '${var.west_tailscale_secret_arn}' --with-decryption --query Parameter.Value --output text"
  east_auth_resolver = "command:AWS_PAGER= /usr/bin/aws ssm get-parameter --region ${var.east_region} --name '${var.east_tailscale_secret_arn}' --with-decryption --query Parameter.Value --output text"

  tailscale_packages = {
    amd64 = {
      url    = "https://pkgs.tailscale.com/stable/amazon-linux/2023/x86_64/tailscale_1.80.3_x86_64.rpm"
      sha256 = "aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2"
    }
    arm64 = {
      url    = "https://pkgs.tailscale.com/stable/amazon-linux/2023/aarch64/tailscale_1.80.3_aarch64.rpm"
      sha256 = "84ea51f9200a2c93362208f9617948fc8dbae06f3ed7faddf08eebc8a5371c32"
    }
  }

  west_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", {
    site                  = "west"
    run_name              = var.name
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
    tailscale_version     = var.tailscale_version
    tun_name              = var.envelope_tun_name
    tailscale_iface       = var.envelope_tailscale_iface
    underlay_iface        = var.envelope_underlay_interface
    routing_mode          = var.envelope_routing_mode
    gwlb_return_cidrs     = join(",", var.envelope_gwlb_return_cidrs["west"])
    local_delivery_cidrs  = join(",", var.envelope_local_delivery_cidrs["west"])
    remote_tailnet_cidrs  = join(",", var.envelope_remote_tailnet_cidrs["west"])
    routing_table_id      = var.envelope_routing_table_id
    routing_rule_priority = var.envelope_routing_rule_priority
  })

  west_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })

  east_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", {
    site                  = "east"
    run_name              = var.name
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
    tailscale_version     = var.tailscale_version
    tun_name              = var.envelope_tun_name
    tailscale_iface       = var.envelope_tailscale_iface
    underlay_iface        = var.envelope_underlay_interface
    routing_mode          = var.envelope_routing_mode
    gwlb_return_cidrs     = join(",", var.envelope_gwlb_return_cidrs["east"])
    local_delivery_cidrs  = join(",", var.envelope_local_delivery_cidrs["east"])
    remote_tailnet_cidrs  = join(",", var.envelope_remote_tailnet_cidrs["east"])
    routing_table_id      = var.envelope_routing_table_id
    routing_rule_priority = var.envelope_routing_rule_priority
  })

  east_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })
}

module "tailscale_client_west" {
  source = "./modules/tailscale-cloudinit"

  gzip               = true
  auth_key           = local.west_auth_resolver
  hostname           = "${var.name}-west"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = concat(var.envelope_gwlb_return_cidrs["west"], var.envelope_local_delivery_cidrs["west"])
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256

  additional_parts = [
    {
      filename     = "80-envelope-artifact.sh"
      content_type = "text/x-shellscript"
      content      = local.west_artifact_installer
    },
    {
      filename     = "90-envelope-bootstrap.sh"
      content_type = "text/x-shellscript"
      content      = local.west_bootstrap
    },
  ]
}

module "tailscale_client_east" {
  source = "./modules/tailscale-cloudinit"

  gzip               = true
  auth_key           = local.east_auth_resolver
  hostname           = "${var.name}-east"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = concat(var.envelope_gwlb_return_cidrs["east"], var.envelope_local_delivery_cidrs["east"])
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256

  additional_parts = [
    {
      filename     = "80-envelope-artifact.sh"
      content_type = "text/x-shellscript"
      content      = local.east_artifact_installer
    },
    {
      filename     = "90-envelope-bootstrap.sh"
      content_type = "text/x-shellscript"
      content      = local.east_bootstrap
    },
  ]
}

locals {
  ec2_user_data_raw_limit_bytes    = 16384
  ec2_user_data_base64_limit_bytes = 4 * ceil(local.ec2_user_data_raw_limit_bytes / 3)

  west_user_data_base64_bytes = length(nonsensitive(module.tailscale_client_west.rendered))
  east_user_data_base64_bytes = length(nonsensitive(module.tailscale_client_east.rendered))
  west_user_data_raw_bytes = floor(local.west_user_data_base64_bytes * 3 / 4) - (
    endswith(nonsensitive(module.tailscale_client_west.rendered), "==") ? 2 :
    endswith(nonsensitive(module.tailscale_client_west.rendered), "=") ? 1 : 0
  )
  east_user_data_raw_bytes = floor(local.east_user_data_base64_bytes * 3 / 4) - (
    endswith(nonsensitive(module.tailscale_client_east.rendered), "==") ? 2 :
    endswith(nonsensitive(module.tailscale_client_east.rendered), "=") ? 1 : 0
  )
}

output "cloud_init_sha256" {
  description = "Reviewable identities for rendered MIME without exposing it as an output"
  value = {
    west = nonsensitive(sha256(module.tailscale_client_west.rendered))
    east = nonsensitive(sha256(module.tailscale_client_east.rendered))
  }
}
