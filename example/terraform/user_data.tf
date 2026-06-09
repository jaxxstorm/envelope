module "tailscale_client_west" {
  source             = "tailscale/tailscale/cloudinit"
  version            = "0.0.11"
  auth_key           = var.tailscale_auth_key
  enable_ssh         = true
  hostname           = "${var.name}-west"
  advertise_tags     = var.advertise_tags
  advertise_routes   = [var.west_vpc_cidr]
  accept_routes      = true
  snat_subnet_routes = var.tailscale_snat_subnet_routes
  netfilter_mode     = var.tailscale_netfilter_mode
  max_retries        = 10
  retry_delay        = 10
}

module "tailscale_client_east" {
  source             = "tailscale/tailscale/cloudinit"
  version            = "0.0.11"
  auth_key           = var.tailscale_auth_key
  enable_ssh         = true
  hostname           = "${var.name}-east"
  advertise_tags     = var.advertise_tags
  advertise_routes   = [var.east_vpc_cidr]
  accept_routes      = true
  snat_subnet_routes = var.tailscale_snat_subnet_routes
  netfilter_mode     = var.tailscale_netfilter_mode
  max_retries        = 10
  retry_delay        = 10
}
