variable "name" {
  type = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,17}[a-z0-9]$", var.name))
    error_message = "name must be a 4-19 character lowercase run identifier safe for AWS names and shell interpolation."
  }
}
variable "expires_at" {
  type = string

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.expires_at)) && can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.expires_at))
    error_message = "expires_at must be a canonical UTC RFC3339 timestamp."
  }
}
variable "tags" {
  type    = map(string)
  default = {}

  validation {
    condition = (
      length(setintersection(toset(keys(var.tags)), toset(["EnvelopeRun", "ExpiresAt", "ManagedBy", "Profile"]))) == 0 &&
      alltrue([
        for key, value in var.tags :
        can(regex("^[A-Za-z0-9 +\\-=._:/@]{1,128}$", key)) &&
        can(regex("^[A-Za-z0-9 +\\-=._:/@]{0,256}$", value))
      ])
    )
    error_message = "tags must be printable AWS-safe strings and must not replace protected ownership tags."
  }
}
variable "west_region" {
  type = string

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.west_region)) && length(var.west_region) <= 20
    error_message = "west_region must be an explicit AWS region safe for shell interpolation."
  }
}
variable "east_region" {
  type = string

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.east_region)) && length(var.east_region) <= 20
    error_message = "east_region must be an explicit AWS region safe for shell interpolation."
  }
}
variable "architecture" {
  type = string

  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "architecture must be amd64 or arm64."
  }
}
variable "west_ami_id" {
  type = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.west_ami_id))
    error_message = "west_ami_id must be an explicit AMI ID."
  }
}
variable "east_ami_id" {
  type = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.east_ami_id))
    error_message = "east_ami_id must be an explicit AMI ID."
  }
}
variable "instance_type" {
  type    = string
  default = "t3.medium"
}
variable "test_instance_type" {
  type    = string
  default = "t3.micro"
}
variable "artifact_path" {
  type = string

  validation {
    condition     = var.artifact_path != "" && !strcontains(var.artifact_path, "\n") && !strcontains(var.artifact_path, "\r")
    error_message = "artifact_path must be a non-empty single-line path."
  }
}
variable "artifact_sha256" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.artifact_sha256))
    error_message = "artifact_sha256 must be a lowercase SHA-256 digest."
  }
}
variable "artifact_revision" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.artifact_revision))
    error_message = "artifact_revision must be a lowercase 40-character Git revision safe for shell interpolation."
  }
}
variable "artifact_version" {
  type = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$", var.artifact_version))
    error_message = "artifact_version must be a single shell-safe version token."
  }
}
variable "west_tailscale_secret_arn" {
  type = string

  validation {
    condition     = can(regex("^arn:aws:ssm:${var.west_region}:[0-9]{12}:parameter/[A-Za-z0-9_./-]+$", var.west_tailscale_secret_arn))
    error_message = "west_tailscale_secret_arn must be an exact commercial-partition regional SSM parameter ARN safe for shell interpolation."
  }
}
variable "east_tailscale_secret_arn" {
  type = string

  validation {
    condition     = can(regex("^arn:aws:ssm:${var.east_region}:[0-9]{12}:parameter/[A-Za-z0-9_./-]+$", var.east_tailscale_secret_arn))
    error_message = "east_tailscale_secret_arn must be an exact commercial-partition regional SSM parameter ARN safe for shell interpolation."
  }
}
variable "west_tailscale_kms_key_arn" {
  type = string

  validation {
    condition     = can(regex("^arn:aws:kms:${var.west_region}:[0-9]{12}:key/[A-Za-z0-9-]{1,128}$", var.west_tailscale_kms_key_arn))
    error_message = "west_tailscale_kms_key_arn must be an exact commercial-partition regional KMS key ARN."
  }
}
variable "east_tailscale_kms_key_arn" {
  type = string

  validation {
    condition     = can(regex("^arn:aws:kms:${var.east_region}:[0-9]{12}:key/[A-Za-z0-9-]{1,128}$", var.east_tailscale_kms_key_arn))
    error_message = "east_tailscale_kms_key_arn must be an exact commercial-partition regional KMS key ARN."
  }
}
variable "tailscale_tag" {
  type = string

  validation {
    condition     = can(regex("^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$", var.tailscale_tag))
    error_message = "tailscale_tag must be one shell-safe Tailscale tag."
  }
}
variable "tailscale_version" {
  type    = string
  default = "1.80.3"

  validation {
    condition     = var.tailscale_version == "1.80.3"
    error_message = "tailscale_version must remain pinned to the reviewed 1.80.3 release."
  }
}
variable "envelope_tailscale_iface" {
  type    = string
  default = "tailscale0"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,15}$", var.envelope_tailscale_iface))
    error_message = "envelope_tailscale_iface must be a valid Linux interface name."
  }
}
variable "envelope_underlay_interface" {
  type    = string
  default = "ens5"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,15}$", var.envelope_underlay_interface))
    error_message = "envelope_underlay_interface must be a valid Linux interface name."
  }
}
variable "estimated_fixed_hourly_usd" {
  type    = number
  default = 4

  validation {
    condition     = var.estimated_fixed_hourly_usd >= 0
    error_message = "estimated_fixed_hourly_usd must not be negative."
  }
}
variable "approved_max_fixed_hourly_usd" {
  type    = number
  default = 5

  validation {
    condition     = var.approved_max_fixed_hourly_usd > 0
    error_message = "approved_max_fixed_hourly_usd must be positive."
  }
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

  validation {
    condition = (
      var.e2e_load_profile.safe_inner_mtu == 1280 &&
      floor(var.e2e_load_profile.safe_inner_mtu) == var.e2e_load_profile.safe_inner_mtu &&
      var.e2e_load_profile.maximum_tcp_mss >= 536 &&
      var.e2e_load_profile.maximum_tcp_mss <= var.e2e_load_profile.safe_inner_mtu - 40 &&
      floor(var.e2e_load_profile.maximum_tcp_mss) == var.e2e_load_profile.maximum_tcp_mss &&
      var.e2e_load_profile.sustained_tcp_duration_seconds >= 3 &&
      var.e2e_load_profile.sustained_tcp_duration_seconds <= 120 &&
      floor(var.e2e_load_profile.sustained_tcp_duration_seconds) == var.e2e_load_profile.sustained_tcp_duration_seconds &&
      var.e2e_load_profile.minimum_sustained_tcp_bytes > 0 &&
      var.e2e_load_profile.minimum_sustained_tcp_bytes <= 1000000000 &&
      floor(var.e2e_load_profile.minimum_sustained_tcp_bytes) == var.e2e_load_profile.minimum_sustained_tcp_bytes &&
      var.e2e_load_profile.iperf_duration_seconds >= 3 &&
      var.e2e_load_profile.iperf_duration_seconds <= 120 &&
      floor(var.e2e_load_profile.iperf_duration_seconds) == var.e2e_load_profile.iperf_duration_seconds &&
      var.e2e_load_profile.minimum_throughput_mbps > 0 &&
      var.e2e_load_profile.minimum_throughput_mbps <= 100000 &&
      var.e2e_load_profile.concurrent_duration_seconds >= 3 &&
      var.e2e_load_profile.concurrent_duration_seconds <= 120 &&
      floor(var.e2e_load_profile.concurrent_duration_seconds) == var.e2e_load_profile.concurrent_duration_seconds &&
      var.e2e_load_profile.concurrent_tcp_flows > 0 &&
      var.e2e_load_profile.concurrent_tcp_flows <= 32 &&
      floor(var.e2e_load_profile.concurrent_tcp_flows) == var.e2e_load_profile.concurrent_tcp_flows &&
      var.e2e_load_profile.concurrent_udp_flows > 0 &&
      var.e2e_load_profile.concurrent_udp_flows <= 32 &&
      floor(var.e2e_load_profile.concurrent_udp_flows) == var.e2e_load_profile.concurrent_udp_flows &&
      var.e2e_load_profile.maximum_udp_loss_percent >= 0 &&
      var.e2e_load_profile.maximum_udp_loss_percent <= 100 &&
      var.e2e_load_profile.maximum_p99_latency_ms > 0 &&
      var.e2e_load_profile.maximum_p99_latency_ms <= 60000 &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", var.e2e_load_profile.profile_id)) &&
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.e2e_load_profile.approved_at)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.e2e_load_profile.approved_at))
    )
    error_message = "e2e_load_profile must remain within the reviewed MTU, MSS, duration, load, loss, and latency bounds."
  }
}

variable "symmetric_topology" {
  description = "Exact symmetric topology; version 3 is production native HA and version 2 is the isolated legacy acceptance profile"
  type        = any

  validation {
    condition = try(
      contains([2, 3], var.symmetric_topology.version) &&
      toset(keys(var.symmetric_topology)) == toset(["version", "sites", "route_failover"]) &&
      toset(keys(var.symmetric_topology.sites)) == toset(["west", "east"]),
      false,
    )
    error_message = "symmetric_topology must be production version 3 or legacy-acceptance version 2 with exactly sites and route_failover."
  }

  validation {
    condition = try(alltrue([
      for site in values(var.symmetric_topology.sites) : toset(keys(site)) == toset([
        "region",
        "ami_id",
        "ssm_kms_key_arn",
        "azs",
        "vpc_cidr",
        "local_site_cidrs",
        "remote_site_cidrs",
        "workload_subnet_cidrs",
        "transport_subnet_cidrs",
        "gwlbe_subnet_cidrs",
        "gwlb_subnet_cidrs",
        "target_subnet_cidrs",
        "management_subnet_cidr",
        "target_az_keys",
        "transport_router_az_keys",
      ])
    ]), false)
    error_message = "Each site must contain exactly the reviewed symmetric topology fields; compatibility and obsolete draft fields are unsupported."
  }

  validation {
    condition = try(alltrue([
      for site in values(var.symmetric_topology.sites) :
      length(site.azs) == 2 && length(distinct(values(site.azs))) == 2 &&
      length(site.target_az_keys) == length(distinct(site.target_az_keys)) &&
      length(site.transport_router_az_keys) == length(distinct(site.transport_router_az_keys)) &&
      toset(site.target_az_keys) == toset(keys(site.azs)) &&
      toset(site.transport_router_az_keys) == toset(keys(site.azs)) &&
      toset(keys(site.workload_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.transport_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.gwlbe_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.gwlb_subnet_cidrs)) == toset(keys(site.azs)) &&
      toset(keys(site.target_subnet_cidrs)) == toset(keys(site.azs))
    ]), false)
    error_message = "Each site requires exactly two enabled AZs and a target, transport router, and all route-domain subnets in both."
  }

  validation {
    condition = try(alltrue([
      for site in values(var.symmetric_topology.sites) :
      can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", site.region)) &&
      can(regex("^ami-[0-9a-f]{8,17}$", site.ami_id)) &&
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{1,128}$", site.ssm_kms_key_arn)) &&
      alltrue([
        for az_key, availability_zone in site.azs :
        can(regex("^[a-z][a-z0-9-]{0,7}$", az_key)) &&
        can(regex("^${site.region}[a-z]$", availability_zone))
      ])
    ]), false)
    error_message = "Site regions, AMIs, KMS ARNs, AZ keys, and availability zones must be exact shell-safe AWS identities."
  }

  validation {
    condition = try(
      toset(keys(var.symmetric_topology.route_failover)) == toset([
        "initial_transport_router_az_by_gwlbe_az",
        "mutation_timeout_seconds",
        "restoration_timeout_seconds",
        "recovery_timeout_seconds",
      ]) &&
      toset(keys(var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az)) == toset(["west", "east"]) &&
      alltrue([
        for site, selections in var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az :
        toset(keys(selections)) == toset(keys(var.symmetric_topology.sites[site].gwlbe_subnet_cidrs)) &&
        alltrue([
          for gwlbe_az, transport_router_az in selections :
          gwlbe_az == transport_router_az &&
          contains(var.symmetric_topology.sites[site].transport_router_az_keys, transport_router_az)
        ])
      ]) &&
      alltrue([
        for seconds in [
          var.symmetric_topology.route_failover.mutation_timeout_seconds,
          var.symmetric_topology.route_failover.restoration_timeout_seconds,
          var.symmetric_topology.route_failover.recovery_timeout_seconds,
        ] : seconds >= 1 && seconds <= 7200 && floor(seconds) == seconds
      ]),
      false,
    )
    error_message = "route_failover must map every GWLBE AZ to the same transport-router AZ and contain whole-second mutation, restoration, and recovery bounds from 1 through 7200."
  }

  validation {
    condition = try(
      var.symmetric_topology.route_failover.restoration_timeout_seconds >= 2 &&
      var.symmetric_topology.route_failover.recovery_timeout_seconds > min(
        10,
        max(1, floor(var.symmetric_topology.route_failover.restoration_timeout_seconds / 10)),
      ),
      false,
    )
    error_message = "route_failover restoration must leave time for a quiet window and recovery must exceed the derived ownership quiet window."
  }
}

locals {
  sites = {
    for site_name, site in var.symmetric_topology.sites : site_name => {
      region                   = tostring(site.region)
      ami_id                   = tostring(site.ami_id)
      ssm_kms_key_arn          = tostring(site.ssm_kms_key_arn)
      azs                      = tomap(site.azs)
      vpc_cidr                 = tostring(site.vpc_cidr)
      local_site_cidrs         = sort(tolist(site.local_site_cidrs))
      remote_site_cidrs        = sort(tolist(site.remote_site_cidrs))
      workload_subnet_cidrs    = tomap(site.workload_subnet_cidrs)
      transport_subnet_cidrs   = tomap(site.transport_subnet_cidrs)
      gwlbe_subnet_cidrs       = tomap(site.gwlbe_subnet_cidrs)
      gwlb_subnet_cidrs        = tomap(site.gwlb_subnet_cidrs)
      target_subnet_cidrs      = tomap(site.target_subnet_cidrs)
      management_subnet_cidr   = tostring(site.management_subnet_cidr)
      target_az_keys           = toset(site.target_az_keys)
      transport_router_az_keys = toset(site.transport_router_az_keys)
    }
  }
  route_failover = {
    initial_transport_router_az_by_gwlbe_az = {
      for site, selections in var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az :
      site => tomap(selections)
    }
    mutation_timeout_seconds    = tonumber(var.symmetric_topology.route_failover.mutation_timeout_seconds)
    restoration_timeout_seconds = tonumber(var.symmetric_topology.route_failover.restoration_timeout_seconds)
    recovery_timeout_seconds    = tonumber(var.symmetric_topology.route_failover.recovery_timeout_seconds)
  }
  initial_transport_router_advertise_routes = {
    for site, topology in local.sites : site => {
      for transport_az in topology.transport_router_az_keys : transport_az => (
        var.symmetric_topology.version == 2 ? sort([
          for gwlbe_az, selected_transport_az in local.route_failover.initial_transport_router_az_by_gwlbe_az[site] :
          topology.workload_subnet_cidrs[gwlbe_az]
          if selected_transport_az == transport_az
        ]) : sort(topology.local_site_cidrs)
      )
    }
  }
  site_subnet_cidrs = {
    for site, topology in local.sites : site => concat(
      values(topology.workload_subnet_cidrs),
      values(topology.transport_subnet_cidrs),
      values(topology.gwlbe_subnet_cidrs),
      values(topology.gwlb_subnet_cidrs),
      values(topology.target_subnet_cidrs),
      [topology.management_subnet_cidr],
    )
  }
  site_configured_cidrs = {
    for site, topology in local.sites : site => concat(
      [topology.vpc_cidr],
      local.site_subnet_cidrs[site],
      topology.local_site_cidrs,
      topology.remote_site_cidrs,
    )
  }
  ipv4_network_bounds = {
    for cidr in distinct(flatten(values(local.site_configured_cidrs))) : cidr => {
      first = try(sum([
        for index, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * pow(256, 3 - index)
      ]), -1)
      last = try(
        sum([
          for index, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * pow(256, 3 - index)
        ]) + pow(2, 32 - tonumber(split("/", cidr)[1])) - 1,
        -1,
      )
    }
  }
  ec2_architecture = {
    amd64 = "x86_64"
    arm64 = "arm64"
  }[var.architecture]
  common_tags = merge(var.tags, {
    EnvelopeRun = var.name
    ExpiresAt   = var.expires_at
    ManagedBy   = "terraform"
    Profile     = var.symmetric_topology.version == 2 ? "legacy-symmetric-acceptance-v2" : "production-native-ha-v3"
  })
}
