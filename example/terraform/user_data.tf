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
  west_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })
  east_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.east_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })
}

module "tailscale_target_west" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.west.target_az_keys
  gzip               = true
  auth_key           = local.west_auth_resolver
  hostname           = "${var.name}-west-target-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = []
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
    { filename = "80-envelope-artifact.sh", content_type = "text/x-shellscript", content = local.west_artifact_installer },
    { filename = "90-envelope-bootstrap.sh", content_type = "text/x-shellscript", content = local.west_target_bootstrap },
  ]
}
module "tailscale_target_east" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.east.target_az_keys
  gzip               = true
  auth_key           = local.east_auth_resolver
  hostname           = "${var.name}-east-target-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = []
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
    { filename = "80-envelope-artifact.sh", content_type = "text/x-shellscript", content = local.east_artifact_installer },
    { filename = "90-envelope-bootstrap.sh", content_type = "text/x-shellscript", content = local.east_target_bootstrap },
  ]
}
module "tailscale_ingress_west" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.west.ingress_router_az_keys
  gzip               = true
  auth_key           = local.west_auth_resolver
  hostname           = "${var.name}-west-ingress-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = local.sites.west.local_site_cidrs
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256
}
module "tailscale_ingress_east" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.east.ingress_router_az_keys
  gzip               = true
  auth_key           = local.east_auth_resolver
  hostname           = "${var.name}-east-ingress-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = local.sites.east.local_site_cidrs
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256
}
