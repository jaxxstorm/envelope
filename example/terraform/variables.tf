variable "name" { type = string }
variable "expires_at" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}
variable "west_region" { type = string }
variable "east_region" { type = string }
variable "architecture" { type = string }
variable "west_ami_id" { type = string }
variable "east_ami_id" { type = string }
variable "instance_type" {
  type    = string
  default = "t3.medium"
}
variable "test_instance_type" {
  type    = string
  default = "t3.micro"
}
variable "artifact_path" { type = string }
variable "artifact_sha256" { type = string }
variable "artifact_revision" { type = string }
variable "artifact_version" { type = string }
variable "west_tailscale_secret_arn" { type = string }
variable "east_tailscale_secret_arn" { type = string }
variable "west_tailscale_kms_key_arn" { type = string }
variable "east_tailscale_kms_key_arn" { type = string }
variable "tailscale_tag" { type = string }
variable "tailscale_version" {
  type    = string
  default = "1.80.3"
}
variable "envelope_routing_mode" {
  type    = string
  default = "manage"
}
variable "envelope_tun_name" {
  type    = string
  default = "envelope0"
}
variable "envelope_tailscale_iface" {
  type    = string
  default = "tailscale0"
}
variable "envelope_underlay_interface" {
  type    = string
  default = "ens5"
}
variable "envelope_routing_table_id" {
  type    = number
  default = 100
}
variable "envelope_routing_rule_priority" {
  type    = number
  default = 100
}
variable "estimated_fixed_hourly_usd" {
  type    = number
  default = 4
}
variable "approved_max_fixed_hourly_usd" {
  type    = number
  default = 5
}

variable "e2e_load_profile" {
  type = object({
    profile_id                     = string
    approved_at                    = string
    safe_inner_mtu                 = number
    maximum_tcp_mss                = number
    sustained_tcp_duration_seconds = number
    minimum_sustained_tcp_bytes    = number
    iperf_duration_seconds         = number
    minimum_throughput_mbps        = number
    concurrent_duration_seconds    = number
    concurrent_tcp_flows           = number
    concurrent_udp_flows           = number
    maximum_udp_loss_percent       = number
    maximum_p99_latency_ms         = number
  })
}

variable "symmetric_topology" {
  type = object({
    version = number
    sites = map(object({
      azs                    = map(string)
      vpc_cidr               = string
      local_site_cidrs       = list(string)
      remote_site_cidrs      = list(string)
      workload_subnet_cidrs  = map(string)
      ingress_subnet_cidrs   = map(string)
      gwlbe_subnet_cidrs     = map(string)
      gwlb_subnet_cidrs      = map(string)
      target_subnet_cidrs    = map(string)
      management_subnet_cidr = string
      target_az_keys         = set(string)
      ingress_router_az_keys = set(string)
    }))
  })

  validation {
    condition     = var.symmetric_topology.version == 2 && toset(keys(var.symmetric_topology.sites)) == toset(["west", "east"])
    error_message = "symmetric_topology must be version 2 with exactly west and east sites."
  }

  validation {
    condition = alltrue([
      for site in values(var.symmetric_topology.sites) :
      length(site.azs) == 2 && length(distinct(values(site.azs))) == 2 &&
      site.target_az_keys == toset(keys(site.azs)) &&
      site.ingress_router_az_keys == toset(keys(site.azs)) &&
      toset(keys(site.workload_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.ingress_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.gwlbe_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.gwlb_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.target_subnet_cidrs)) == toset(keys(site.azs))
    ])
    error_message = "Each site requires exactly two enabled AZs and a target, ingress router, and all route-domain subnets in both."
  }
}

locals {
  sites = var.symmetric_topology.sites
  ec2_architecture = {
    amd64 = "x86_64"
    arm64 = "arm64"
  }[var.architecture]
  common_tags = merge(var.tags, {
    EnvelopeRun = var.name
    ExpiresAt   = var.expires_at
    ManagedBy   = "terraform"
    Profile     = "symmetric-gwlb-ha-v2"
  })
}
