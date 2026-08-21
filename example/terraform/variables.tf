variable "name" {
  description = "Globally unique run name used as the prefix for every owned resource"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,17}[a-z0-9]$", var.name))
    error_message = "name must be 4-19 lowercase letters, digits, or hyphens, begin with a letter, and end with a letter or digit."
  }
}

variable "expires_at" {
  description = "RFC3339 TTL applied to all supported run-owned resources"
  type        = string

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.expires_at))
    error_message = "expires_at must be an RFC3339 timestamp."
  }
}

variable "tags" {
  description = "Additional non-sensitive tags; run ownership tags cannot be overridden"
  type        = map(string)
  default     = {}
}

variable "west_region" {
  description = "AWS region for the west site"
  type        = string
  default     = "us-west-2"
}

variable "east_region" {
  description = "AWS region for the east site"
  type        = string
  default     = "us-east-1"
}

variable "west_azs" {
  description = "Exactly two reviewed logical-key to explicit Availability Zone mappings for west"
  type        = map(string)

  validation {
    condition     = length(var.west_azs) == 2 && length(distinct(values(var.west_azs))) == 2
    error_message = "west_azs must contain exactly two distinct explicit Availability Zone names."
  }
}

variable "east_azs" {
  description = "Exactly two reviewed logical-key to explicit Availability Zone mappings for east"
  type        = map(string)

  validation {
    condition     = length(var.east_azs) == 2 && length(distinct(values(var.east_azs))) == 2
    error_message = "east_azs must contain exactly two distinct explicit Availability Zone names."
  }
}

variable "west_appliance_az_key" {
  description = "Configuration-known west AZ key that owns the single regional appliance"
  type        = string
}

variable "east_appliance_az_key" {
  description = "Configuration-known east AZ key that owns the single regional appliance"
  type        = string
}

variable "west_vpc_cidr" {
  description = "CIDR for the west VPC"
  type        = string
  default     = "172.16.0.0/16"

  validation {
    condition     = can(cidrhost(var.west_vpc_cidr, 0))
    error_message = "west_vpc_cidr must be a valid CIDR."
  }
}

variable "east_vpc_cidr" {
  description = "CIDR for the east VPC"
  type        = string
  default     = "172.17.0.0/16"

  validation {
    condition     = can(cidrhost(var.east_vpc_cidr, 0))
    error_message = "east_vpc_cidr must be a valid CIDR."
  }
}

variable "west_public_subnet_cidr" {
  description = "West NAT subnet CIDR in west_appliance_az_key"
  type        = string
}

variable "east_public_subnet_cidr" {
  description = "East NAT subnet CIDR in east_appliance_az_key"
  type        = string
}

variable "west_appliance_subnet_cidr" {
  description = "Dedicated west appliance subnet CIDR"
  type        = string
}

variable "east_appliance_subnet_cidr" {
  description = "Dedicated east appliance subnet CIDR"
  type        = string
}

variable "west_workload_subnet_cidrs" {
  description = "West workload subnet CIDRs keyed exactly like west_azs"
  type        = map(string)
}

variable "east_workload_subnet_cidrs" {
  description = "East workload subnet CIDRs keyed exactly like east_azs"
  type        = map(string)
}

variable "west_gwlbe_subnet_cidrs" {
  description = "West GWLBE-only subnet CIDRs keyed exactly like west_azs"
  type        = map(string)
}

variable "east_gwlbe_subnet_cidrs" {
  description = "East GWLBE-only subnet CIDRs keyed exactly like east_azs"
  type        = map(string)
}

variable "west_gwlb_subnet_cidrs" {
  description = "West GWLB-only subnet CIDRs keyed exactly like west_azs"
  type        = map(string)
}

variable "east_gwlb_subnet_cidrs" {
  description = "East GWLB-only subnet CIDRs keyed exactly like east_azs"
  type        = map(string)
}

variable "architecture" {
  description = "Go artifact architecture; protected preflight maps this to EC2 architecture"
  type        = string

  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "architecture must be amd64 or arm64."
  }
}

variable "west_ami_id" {
  description = "Reviewed explicit AL2023 AMI ID for west"
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.west_ami_id))
    error_message = "west_ami_id must be an explicit AMI ID."
  }
}

variable "east_ami_id" {
  description = "Reviewed explicit AL2023 AMI ID for east"
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.east_ami_id))
    error_message = "east_ami_id must be an explicit AMI ID."
  }
}

variable "instance_type" {
  description = "Appliance instance type validated by protected AWS metadata preflight"
  type        = string
  default     = "t3.medium"
}

variable "test_instance_type" {
  description = "Test instance type validated by protected AWS metadata preflight"
  type        = string
  default     = "t3.micro"
}

variable "ebs_root_volume_size" {
  description = "Encrypted root volume size in GiB"
  type        = number
  default     = 20

  validation {
    condition     = var.ebs_root_volume_size >= 8 && var.ebs_root_volume_size <= 100
    error_message = "ebs_root_volume_size must be between 8 and 100 GiB."
  }
}

variable "artifact_path" {
  description = "Reviewed local static Linux Envelope artifact path"
  type        = string

  validation {
    condition     = length(trimspace(var.artifact_path)) > 0
    error_message = "artifact_path is required."
  }
}

variable "artifact_sha256" {
  description = "Reviewed lowercase SHA-256 of artifact_path"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.artifact_sha256))
    error_message = "artifact_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "artifact_revision" {
  description = "Full source revision embedded in the artifact"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.artifact_revision))
    error_message = "artifact_revision must be a full 40-character Git revision."
  }
}

variable "artifact_version" {
  description = "Operator-reviewed artifact version embedded at build time"
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$", var.artifact_version))
    error_message = "artifact_version contains unsupported characters or is too long."
  }
}

variable "west_tailscale_secret_arn" {
  description = "Run-scoped west SSM SecureString ARN created by the protected runner"
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:ssm:[^:]+:[0-9]{12}:parameter/.+$", var.west_tailscale_secret_arn))
    error_message = "west_tailscale_secret_arn must be an SSM parameter ARN."
  }
}

variable "east_tailscale_secret_arn" {
  description = "Run-scoped east SSM SecureString ARN created by the protected runner"
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:ssm:[^:]+:[0-9]{12}:parameter/.+$", var.east_tailscale_secret_arn))
    error_message = "east_tailscale_secret_arn must be an SSM parameter ARN."
  }
}

variable "west_tailscale_kms_key_arn" {
  description = "Exact west KMS key ARN encrypting the run-scoped SSM parameter"
  type        = string
}

variable "east_tailscale_kms_key_arn" {
  description = "Exact east KMS key ARN encrypting the run-scoped SSM parameter"
  type        = string
}

variable "tailscale_tag" {
  description = "Pre-owned Tailnet tag used by both ephemeral appliances"
  type        = string

  validation {
    condition     = can(regex("^tag:[A-Za-z0-9-]+$", var.tailscale_tag))
    error_message = "tailscale_tag must be a single tag: value."
  }
}

variable "tailscale_version" {
  description = "Pinned Tailscale version matching the supported v1.80 status schema"
  type        = string
  default     = "1.80.3"

  validation {
    condition     = var.tailscale_version == "1.80.3"
    error_message = "tailscale_version must be the reviewed 1.80.3 package release."
  }
}

variable "envelope_routing_mode" {
  description = "Envelope routing mode"
  type        = string
  default     = "manage"

  validation {
    condition     = contains(["off", "verify", "manage"], var.envelope_routing_mode)
    error_message = "envelope_routing_mode must be off, verify, or manage."
  }
}

variable "envelope_tun_name" {
  description = "Envelope-owned TUN interface"
  type        = string
  default     = "envelope0"
}

variable "envelope_tailscale_iface" {
  description = "Tailscale-owned kernel TUN interface"
  type        = string
  default     = "tailscale0"
}

variable "envelope_underlay_interface" {
  description = "AL2023 appliance underlay interface checked by Envelope"
  type        = string
  default     = "ens5"
}

variable "envelope_gwlb_return_cidrs" {
  description = "One local initiator prefix per site whose Tailnet returns enter Envelope"
  type        = map(list(string))

  validation {
    condition = (
      toset(keys(var.envelope_gwlb_return_cidrs)) == toset(["west", "east"]) &&
      alltrue([
        for cidrs in values(var.envelope_gwlb_return_cidrs) :
        length(cidrs) == 1 && alltrue([for cidr in cidrs : can(cidrhost(cidr, 0))])
      ])
    )
    error_message = "envelope_gwlb_return_cidrs must contain exactly one valid initiator CIDR for each of west and east."
  }
}

variable "envelope_local_delivery_cidrs" {
  description = "One local responder prefix per site whose cold Tailnet traffic bypasses Envelope"
  type        = map(list(string))

  validation {
    condition = (
      toset(keys(var.envelope_local_delivery_cidrs)) == toset(["west", "east"]) &&
      alltrue([
        for cidrs in values(var.envelope_local_delivery_cidrs) :
        length(cidrs) == 1 && alltrue([for cidr in cidrs : can(cidrhost(cidr, 0))])
      ])
    )
    error_message = "envelope_local_delivery_cidrs must contain exactly one valid responder CIDR for each of west and east."
  }
}

variable "envelope_remote_tailnet_cidrs" {
  description = "Independent per-site remote prefixes that must use accepted Tailnet routes"
  type        = map(list(string))

  validation {
    condition     = toset(keys(var.envelope_remote_tailnet_cidrs)) == toset(["west", "east"]) && alltrue(flatten([for values in values(var.envelope_remote_tailnet_cidrs) : [for value in values : can(cidrhost(value, 0))]]))
    error_message = "envelope_remote_tailnet_cidrs must contain valid west and east CIDR lists."
  }
}

variable "envelope_routing_table_id" {
  description = "Linux routing table reserved by Envelope"
  type        = number
  default     = 100

  validation {
    condition     = var.envelope_routing_table_id >= 1 && var.envelope_routing_table_id <= 252 && !contains([52], var.envelope_routing_table_id)
    error_message = "envelope_routing_table_id must be 1-252 excluding Tailscale table 52."
  }
}

variable "envelope_routing_rule_priority" {
  description = "Linux policy-rule priority reserved by Envelope"
  type        = number
  default     = 100

  validation {
    condition     = var.envelope_routing_rule_priority >= 1 && var.envelope_routing_rule_priority <= 32765
    error_message = "envelope_routing_rule_priority must be between 1 and 32765."
  }
}

variable "appliance_target_count" {
  description = "Regional Envelope target count; only one process-local flow owner is supported"
  type        = number
  default     = 1

  validation {
    condition     = var.appliance_target_count == 1
    error_message = "appliance_target_count must be exactly 1 until deterministic multi-process return affinity is implemented."
  }
}

variable "e2e_load_profile" {
  description = "Required immutable load and transport thresholds approved before the saved plan is created"
  nullable    = false
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
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", var.e2e_load_profile.profile_id))
    error_message = "e2e_load_profile.profile_id must be a 1-128 character safe identifier."
  }

  validation {
    condition = (
      can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.e2e_load_profile.approved_at)) &&
      try(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.e2e_load_profile.approved_at) == var.e2e_load_profile.approved_at, false)
    )
    error_message = "e2e_load_profile.approved_at must be canonical UTC RFC3339 with seconds and a trailing Z."
  }

  validation {
    condition = alltrue([
      for value in [
        var.e2e_load_profile.safe_inner_mtu,
        var.e2e_load_profile.maximum_tcp_mss,
        var.e2e_load_profile.sustained_tcp_duration_seconds,
        var.e2e_load_profile.minimum_sustained_tcp_bytes,
        var.e2e_load_profile.iperf_duration_seconds,
        var.e2e_load_profile.concurrent_duration_seconds,
        var.e2e_load_profile.concurrent_tcp_flows,
        var.e2e_load_profile.concurrent_udp_flows,
      ] : value == floor(value)
    ])
    error_message = "e2e_load_profile MTU, MSS, duration, byte, and flow-count fields must be integers."
  }

  validation {
    condition = (
      var.e2e_load_profile.safe_inner_mtu >= 576 && var.e2e_load_profile.safe_inner_mtu <= 1500 &&
      var.e2e_load_profile.maximum_tcp_mss >= 536 && var.e2e_load_profile.maximum_tcp_mss <= 1460 &&
      var.e2e_load_profile.sustained_tcp_duration_seconds >= 3 && var.e2e_load_profile.sustained_tcp_duration_seconds <= 120 &&
      var.e2e_load_profile.minimum_sustained_tcp_bytes >= 1 && var.e2e_load_profile.minimum_sustained_tcp_bytes <= 1000000000 &&
      var.e2e_load_profile.iperf_duration_seconds >= 3 && var.e2e_load_profile.iperf_duration_seconds <= 120 &&
      var.e2e_load_profile.concurrent_duration_seconds >= 3 && var.e2e_load_profile.concurrent_duration_seconds <= 120 &&
      var.e2e_load_profile.concurrent_tcp_flows >= 1 && var.e2e_load_profile.concurrent_tcp_flows <= 32 &&
      var.e2e_load_profile.concurrent_udp_flows >= 1 && var.e2e_load_profile.concurrent_udp_flows <= 32
    )
    error_message = "e2e_load_profile integer fields exceed their approved fail-closed bounds."
  }

  validation {
    condition = (
      var.e2e_load_profile.safe_inner_mtu == 1280 &&
      var.e2e_load_profile.maximum_tcp_mss <= var.e2e_load_profile.safe_inner_mtu - 40
    )
    error_message = "e2e_load_profile must use safe_inner_mtu 1280 and maximum_tcp_mss no greater than 1240."
  }

  validation {
    condition = (
      var.e2e_load_profile.minimum_throughput_mbps >= 0.001 && var.e2e_load_profile.minimum_throughput_mbps <= 100000 &&
      var.e2e_load_profile.maximum_udp_loss_percent >= 0 && var.e2e_load_profile.maximum_udp_loss_percent <= 100 &&
      var.e2e_load_profile.maximum_p99_latency_ms >= 0.001 && var.e2e_load_profile.maximum_p99_latency_ms <= 60000
    )
    error_message = "e2e_load_profile throughput, UDP loss, and p99 latency thresholds must be finite and within approved bounds."
  }
}

variable "estimated_fixed_hourly_usd" {
  description = "Reviewed estimate for this acceptance profile before traffic charges"
  type        = number
  default     = 1.50

  validation {
    condition     = var.estimated_fixed_hourly_usd > 0
    error_message = "estimated_fixed_hourly_usd must be positive."
  }
}

variable "approved_max_fixed_hourly_usd" {
  description = "Operator-approved fixed hourly cost ceiling"
  type        = number
  default     = 2.00

  validation {
    condition     = var.approved_max_fixed_hourly_usd > 0
    error_message = "approved_max_fixed_hourly_usd must be positive."
  }
}

locals {
  common_tags = merge(var.tags, {
    EnvelopeRun = var.name
    ExpiresAt   = var.expires_at
    ManagedBy   = "terraform"
    Profile     = "envelope-aws-appliance"
  })

  ec2_architecture = {
    amd64 = "x86_64"
    arm64 = "arm64"
  }[var.architecture]

  west_initiator_cidr = one(var.envelope_gwlb_return_cidrs["west"])
  west_responder_cidr = one(var.envelope_local_delivery_cidrs["west"])
  east_initiator_cidr = one(var.envelope_gwlb_return_cidrs["east"])
  east_responder_cidr = one(var.envelope_local_delivery_cidrs["east"])

  west_initiator_az_key = coalesce(one([for az_key, cidr in var.west_workload_subnet_cidrs : az_key if cidr == local.west_initiator_cidr]), sort(keys(var.west_workload_subnet_cidrs))[0])
  west_responder_az_key = coalesce(one([for az_key, cidr in var.west_workload_subnet_cidrs : az_key if cidr == local.west_responder_cidr]), sort(keys(var.west_workload_subnet_cidrs))[0])
  east_initiator_az_key = coalesce(one([for az_key, cidr in var.east_workload_subnet_cidrs : az_key if cidr == local.east_initiator_cidr]), sort(keys(var.east_workload_subnet_cidrs))[0])
  east_responder_az_key = coalesce(one([for az_key, cidr in var.east_workload_subnet_cidrs : az_key if cidr == local.east_responder_cidr]), sort(keys(var.east_workload_subnet_cidrs))[0])

  west_workloads = {
    initiator = { az_key = local.west_initiator_az_key, cidr = local.west_initiator_cidr }
    responder = { az_key = local.west_responder_az_key, cidr = local.west_responder_cidr }
  }
  east_workloads = {
    initiator = { az_key = local.east_initiator_az_key, cidr = local.east_initiator_cidr }
    responder = { az_key = local.east_responder_az_key, cidr = local.east_responder_cidr }
  }

  workload_probe_ingress = {
    icmp = { description = "ICMP and MTU probes", protocol = "icmp", from_port = -1, to_port = -1 }
    tcp  = { description = "TCP and iperf3 probes", protocol = "tcp", from_port = 5201, to_port = 5201 }
    udp  = { description = "UDP, MTU, and iperf3 probes", protocol = "udp", from_port = 5201, to_port = 5201 }
  }
}
