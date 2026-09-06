variable "name" {
  description = "Unique production controller deployment name."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.name))
    error_message = "name must be 3-40 lowercase alphanumeric or hyphen characters and start with a letter."
  }
}

variable "aws_region" {
  description = "AWS Region containing the controller replicas and DynamoDB authority."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS Region name."
  }
}

variable "aws_account_id" {
  description = "Twelve-digit AWS account ID used to validate every supplied ARN and KMS condition."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must contain exactly 12 digits."
  }
}

variable "vpc_id" {
  description = "VPC in which the standalone controller instances run."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must be a valid VPC ID."
  }
}

variable "controller_ami_id" {
  description = "Exact reviewed Linux AMI ID resolved through the trusted-owner and architecture data-source contract."
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.controller_ami_id))
    error_message = "controller_ami_id must be a valid AMI ID."
  }
}

variable "controller_ami_trusted_owner_ids" {
  description = "Nonempty allowlist of AWS accounts trusted to publish the controller AMI."
  type        = set(string)

  validation {
    condition = (
      length(var.controller_ami_trusted_owner_ids) > 0 &&
      alltrue([for id in var.controller_ami_trusted_owner_ids : can(regex("^[0-9]{12}$", id))])
    )
    error_message = "controller_ami_trusted_owner_ids must contain one or more explicit twelve-digit AWS account IDs."
  }
}

variable "controller_architecture" {
  description = "Go artifact architecture; Terraform maps amd64 to EC2 x86_64 and arm64 to EC2 arm64."
  type        = string

  validation {
    condition     = contains(["amd64", "arm64"], var.controller_architecture)
    error_message = "controller_architecture must be amd64 or arm64."
  }
}

variable "controller_instance_type" {
  description = "EC2 instance type used only by standalone controller replicas."
  type        = string
  default     = "t3.small"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,31}$", var.controller_instance_type))
    error_message = "controller_instance_type must be a valid EC2 instance type name."
  }
}

variable "deployment_mode" {
  description = "Controller operating mode. Keep read-only through observation validation, then explicitly promote to active."
  type        = string
  default     = "read-only"

  validation {
    condition     = contains(["read-only", "active"], var.deployment_mode)
    error_message = "deployment_mode must be read-only or active."
  }
}

variable "protected_acceptance_mode" {
  description = "Explicit ephemeral protected-run lifecycle: permit complete destroy, avoid retained snapshots, and use AWS-owned storage encryption. Production must retain the default false value."
  type        = bool
  default     = false
}

variable "controller_ids" {
  description = "Exactly three immutable controller replica IDs."
  type        = set(string)

  validation {
    condition = (
      length(var.controller_ids) == 3 &&
      alltrue([for id in var.controller_ids : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", id))])
    )
    error_message = "controller_ids must contain exactly three unique controller IDs."
  }
}

variable "controller_placements" {
  description = "Exactly three controller slots keyed by controller ID, each in a distinct supplied private subnet and AZ."
  type = map(object({
    subnet_id         = string
    availability_zone = string
  }))

  validation {
    condition = (
      length(var.controller_placements) == 3 &&
      length(distinct([for placement in values(var.controller_placements) : placement.subnet_id])) == 3 &&
      length(distinct([for placement in values(var.controller_placements) : placement.availability_zone])) == 3 &&
      alltrue([
        for placement in values(var.controller_placements) :
        can(regex("^subnet-[0-9a-f]{8,17}$", placement.subnet_id)) &&
        can(regex("^[a-z][a-z0-9-]+-[0-9]+[a-z]$", placement.availability_zone))
      ])
    )
    error_message = "controller_placements must define exactly three unique subnet/AZ slots with valid IDs."
  }
}

variable "management_egress" {
  description = "Per-replica private route table and same-AZ public NAT identity proving independent HTTPS management egress."
  type = map(object({
    route_table_id      = string
    nat_gateway_id      = string
    nat_subnet_id       = string
    nat_route_table_id  = string
    internet_gateway_id = string
  }))

  validation {
    condition = (
      length(var.management_egress) == 3 &&
      length(distinct([for contract in values(var.management_egress) : contract.route_table_id])) == 3 &&
      length(distinct([for contract in values(var.management_egress) : contract.nat_gateway_id])) == 3 &&
      length(distinct([for contract in values(var.management_egress) : contract.nat_subnet_id])) == 3 &&
      alltrue([
        for contract in values(var.management_egress) :
        can(regex("^rtb-[0-9a-f]{8,17}$", contract.route_table_id)) &&
        can(regex("^nat-[0-9a-f]{8,17}$", contract.nat_gateway_id)) &&
        can(regex("^subnet-[0-9a-f]{8,17}$", contract.nat_subnet_id)) &&
        can(regex("^rtb-[0-9a-f]{8,17}$", contract.nat_route_table_id)) &&
        can(regex("^igw-[0-9a-f]{8,17}$", contract.internet_gateway_id))
      ])
    )
    error_message = "management_egress must define three unique private route tables, NAT gateways, and NAT subnets plus explicit NAT route-table and Internet-gateway identities."
  }
}

variable "root_volume" {
  description = "Encrypted disposable root volume settings for each controller."
  type = object({
    size_gib = number
    type     = string
  })
  default = {
    size_gib = 16
    type     = "gp3"
  }

  validation {
    condition = (
      var.root_volume.size_gib >= 8 &&
      var.root_volume.size_gib <= 1024 &&
      floor(var.root_volume.size_gib) == var.root_volume.size_gib &&
      contains(["gp3", "gp2"], var.root_volume.type)
    )
    error_message = "root_volume must use gp2/gp3 and contain a whole-number size from 8 through 1024 GiB."
  }
}

variable "observer_state_volume_size_gib" {
  description = "Size of each controller's independently encrypted persistent tsnet state volume."
  type        = number
  default     = 8

  validation {
    condition = (
      var.observer_state_volume_size_gib >= 1 &&
      var.observer_state_volume_size_gib <= 1024 &&
      floor(var.observer_state_volume_size_gib) == var.observer_state_volume_size_gib
    )
    error_message = "observer_state_volume_size_gib must be a whole number from 1 through 1024."
  }
}

variable "authority_table_name" {
  description = "Exact name embedded in the topology identity document and assigned to the new DynamoDB authority table."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{3,255}$", var.authority_table_name))
    error_message = "authority_table_name must satisfy DynamoDB table naming rules."
  }
}

variable "topology_identity_json" {
  description = "Exact nonsecret identity JSON emitted by the reviewed envelope-controller-topology artifact."
  type        = string

  validation {
    condition = try(
      var.topology_identity_json == trimspace(var.topology_identity_json) &&
      length(var.topology_identity_json) <= 16384 &&
      toset(keys(jsondecode(var.topology_identity_json))) == toset([
        "schema", "component", "version", "revision", "go_version", "vcs_modified",
        "canonical_sha256", "canonical_json_base64", "policy_durations",
      ]) &&
      jsondecode(var.topology_identity_json).schema == 1 &&
      jsondecode(var.topology_identity_json).component == "envelope-controller-topology" &&
      can(regex("^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$", jsondecode(var.topology_identity_json).version)) &&
      can(regex("^[0-9a-f]{40}$", jsondecode(var.topology_identity_json).revision)) &&
      can(regex("^go[0-9]+\\.[0-9]+(?:\\.[0-9]+)?$", jsondecode(var.topology_identity_json).go_version)) &&
      jsondecode(var.topology_identity_json).vcs_modified == false &&
      can(regex("^[0-9a-f]{64}$", jsondecode(var.topology_identity_json).canonical_sha256)) &&
      base64encode(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64)) == jsondecode(var.topology_identity_json).canonical_json_base64 &&
      length(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64)) <= 8192 &&
      base64decode(jsondecode(var.topology_identity_json).canonical_json_base64) == trimspace(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64)) &&
      can(jsondecode(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64))) &&
      sha256(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64)) == jsondecode(var.topology_identity_json).canonical_sha256 &&
      toset(keys(jsondecode(var.topology_identity_json).policy_durations)) == toset([
        "observation_interval", "observation_freshness", "failover_stability", "failback_stability", "cooldown",
        "lease_duration", "lease_renew_interval", "lease_danger_window", "api_timeout", "route_convergence_timeout",
      ]) &&
      alltrue([
        for name, duration in jsondecode(var.topology_identity_json).policy_durations :
        jsondecode(base64decode(jsondecode(var.topology_identity_json).canonical_json_base64)).policy[name] == duration
      ]),
      false,
    )
    error_message = "topology_identity_json must be an unmodified clean-release identity emitted by envelope-controller-topology with matching canonical bytes, SHA-256, and normalized policy durations."
  }

  validation {
    condition = try(
      !can(regex(
        "(?i)(tskey-|nodekey:|machinekey:|privkey:|-----begin[ ]+private[ ]+key-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})",
        base64decode(jsondecode(var.topology_identity_json).canonical_json_base64),
      )),
      false,
    )
    error_message = "topology_identity_json appears to contain secret material; use environment-variable references only."
  }
}

variable "topology_parameter_name" {
  description = "Name for the nonsecret SSM String parameter created for topology delivery."
  type        = string

  validation {
    condition = (
      can(regex("^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$", var.topology_parameter_name)) &&
      length(var.topology_parameter_name) <= 256
    )
    error_message = "topology_parameter_name must be an absolute, bounded SSM parameter path."
  }
}

variable "artifact" {
  description = "Immutable S3 identity and content hash for the manifest-selected controller executable."
  type = object({
    region      = string
    bucket_name = string
    bucket_arn  = string
    object_key  = string
    object_arn  = string
    version_id  = string
    sha256      = string
  })

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]+-[0-9]+$", var.artifact.region)) &&
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.artifact.bucket_name)) &&
      startswith(var.artifact.bucket_arn, "arn:") &&
      startswith(var.artifact.object_arn, "arn:") &&
      var.artifact.object_key != "" &&
      length(var.artifact.object_key) <= 512 &&
      !startswith(var.artifact.object_key, "/") &&
      !can(regex("[*?\\p{Cc}]", var.artifact.object_key)) &&
      var.artifact.version_id != "" &&
      length(var.artifact.version_id) <= 256 &&
      lower(var.artifact.version_id) != "null" &&
      !strcontains(var.artifact.version_id, "\n") &&
      can(regex("^[0-9a-f]{64}$", var.artifact.sha256))
    )
    error_message = "artifact must identify one versioned S3 object and its lowercase SHA-256 digest."
  }
}

variable "topology_identity_artifact" {
  description = "Immutable S3 identity and content hash for the manifest-selected Go topology producer/verifier."
  type = object({
    region      = string
    bucket_name = string
    bucket_arn  = string
    object_key  = string
    object_arn  = string
    version_id  = string
    sha256      = string
  })

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]+-[0-9]+$", var.topology_identity_artifact.region)) &&
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.topology_identity_artifact.bucket_name)) &&
      startswith(var.topology_identity_artifact.bucket_arn, "arn:") &&
      startswith(var.topology_identity_artifact.object_arn, "arn:") &&
      var.topology_identity_artifact.object_key != "" &&
      length(var.topology_identity_artifact.object_key) <= 512 &&
      !startswith(var.topology_identity_artifact.object_key, "/") &&
      !can(regex("[*?\\p{Cc}]", var.topology_identity_artifact.object_key)) &&
      var.topology_identity_artifact.version_id != "" &&
      length(var.topology_identity_artifact.version_id) <= 256 &&
      lower(var.topology_identity_artifact.version_id) != "null" &&
      !strcontains(var.topology_identity_artifact.version_id, "\n") &&
      can(regex("^[0-9a-f]{64}$", var.topology_identity_artifact.sha256))
    )
    error_message = "topology_identity_artifact must identify one versioned S3 object and its lowercase SHA-256 digest."
  }
}

variable "artifact_manifest_json" {
  description = "Exact controller-manifest.json bytes reviewed for this deployment, without trailing whitespace."
  type        = string

  validation {
    condition = try(
      var.artifact_manifest_json == trimspace(var.artifact_manifest_json) &&
      length(var.artifact_manifest_json) <= 65536 &&
      jsondecode(var.artifact_manifest_json).schema == 1 &&
      jsondecode(var.artifact_manifest_json).component == "envelope-controller" &&
      jsondecode(var.artifact_manifest_json).source_dirty == false,
      false,
    )
    error_message = "artifact_manifest_json must be the bounded schema-1 clean-release envelope-controller manifest without surrounding whitespace."
  }
}

variable "artifact_manifest_sha256" {
  description = "Reviewed lowercase SHA-256 of the exact artifact_manifest_json bytes."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.artifact_manifest_sha256))
    error_message = "artifact_manifest_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "secret_parameters" {
  description = "Existing SecureString references; no secret values are accepted by this module."
  type = object({
    tsnet = object({
      name        = string
      arn         = string
      kms_key_arn = string
    })
    admin = object({
      name        = string
      arn         = string
      kms_key_arn = string
    })
  })

  validation {
    condition = (
      var.secret_parameters.tsnet.name != var.secret_parameters.admin.name &&
      var.secret_parameters.tsnet.arn != var.secret_parameters.admin.arn &&
      alltrue([
        for secret in values(var.secret_parameters) :
        can(regex("^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$", secret.name)) &&
        length(secret.name) <= 256 &&
        startswith(secret.arn, "arn:") &&
        startswith(secret.kms_key_arn, "arn:") &&
        !can(regex("(?i)(tskey-|nodekey:|machinekey:|privkey:)", secret.name))
      ])
    )
    error_message = "secret_parameters must contain distinct absolute SSM names, exact ARNs, and KMS key ARNs, never values."
  }
}

variable "managed_route_tables" {
  description = "Exact GWLBE route-domain contracts keyed by topology domain ID; current targets remain controller-owned."
  type = map(object({
    region                     = string
    vpc_id                     = string
    route_table_id             = string
    route_table_arn            = string
    gwlbe_subnet_id            = string
    route_table_association_id = string
    source_prefix              = string
    destination_cidrs          = set(string)
    eligible_eni_ids           = set(string)
  }))

  validation {
    condition = (
      length(var.managed_route_tables) > 0 &&
      length(distinct([for contract in values(var.managed_route_tables) : contract.route_table_id])) == length(var.managed_route_tables) &&
      length(distinct([for contract in values(var.managed_route_tables) : contract.gwlbe_subnet_id])) == length(var.managed_route_tables) &&
      length(distinct([for contract in values(var.managed_route_tables) : contract.route_table_association_id])) == length(var.managed_route_tables) &&
      alltrue([
        for contract in values(var.managed_route_tables) :
        can(regex("^[a-z][a-z0-9-]+-[0-9]+$", contract.region)) &&
        can(regex("^vpc-[0-9a-f]{8,17}$", contract.vpc_id)) &&
        can(regex("^rtb-[0-9a-f]{8,17}$", contract.route_table_id)) &&
        can(regex("^subnet-[0-9a-f]{8,17}$", contract.gwlbe_subnet_id)) &&
        can(regex("^rtbassoc-[0-9a-f]{8,17}$", contract.route_table_association_id)) &&
        startswith(contract.route_table_arn, "arn:") &&
        length(contract.destination_cidrs) > 0 &&
        length(contract.eligible_eni_ids) >= 2 &&
        alltrue([for eni in contract.eligible_eni_ids : can(regex("^eni-[0-9a-f]{8,17}$", eni))]) &&
        alltrue([
          for cidr in setunion(contract.destination_cidrs, toset([contract.source_prefix])) : try(
            !strcontains(cidr, ":") &&
            cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}",
            false,
          )
        ])
      ])
    )
    error_message = "managed_route_tables must contain unique exact route tables and GWLBE subnet associations, canonical IPv4 prefixes, and at least two eligible ENIs."
  }
}

variable "transport_topology" {
  description = "Production router expectations proving complete overlapping exact-prefix advertisements and higher-priority local-main routing."
  type = map(object({
    local_prefixes                = set(string)
    local_main_rule_priority_base = number
    tailscale_route_rule_priority = number
    routers = map(object({
      stable_node_id                    = string
      instance_id                       = string
      eni_id                            = string
      expected_advertised_prefixes      = set(string)
      expected_enabled_prefixes         = set(string)
      expected_accepted_remote_prefixes = set(string)
      expected_local_main_prefixes      = set(string)
    }))
  }))

  validation {
    condition = (
      length(var.transport_topology) >= 2 &&
      alltrue([
        for site_id, site in var.transport_topology :
        length(site.local_prefixes) > 0 &&
        length(site.routers) >= 2 &&
        floor(site.local_main_rule_priority_base) == site.local_main_rule_priority_base &&
        floor(site.tailscale_route_rule_priority) == site.tailscale_route_rule_priority &&
        site.local_main_rule_priority_base >= 1 &&
        site.tailscale_route_rule_priority <= 32765 &&
        site.local_main_rule_priority_base + length(site.local_prefixes) - 1 < site.tailscale_route_rule_priority &&
        alltrue([
          for router in values(site.routers) :
          router.expected_advertised_prefixes == site.local_prefixes &&
          router.expected_enabled_prefixes == site.local_prefixes &&
          router.expected_local_main_prefixes == site.local_prefixes &&
          router.expected_accepted_remote_prefixes == setsubtract(
            toset(flatten([for other in values(var.transport_topology) : tolist(other.local_prefixes)])),
            site.local_prefixes,
          ) &&
          router.stable_node_id != "" &&
          can(regex("^i-[0-9a-f]{8,17}$", router.instance_id)) &&
          can(regex("^eni-[0-9a-f]{8,17}$", router.eni_id))
        ])
      ])
    )
    error_message = "every transport router must expect every exact local prefix advertised, enabled, and forced to main, plus every exact remote prefix accepted."
  }
}

variable "metrics_ingress_cidrs" {
  description = "Private IPv4 CIDRs allowed to scrape controller metrics and readiness on the configured port."
  type        = set(string)

  validation {
    condition = (
      length(var.metrics_ingress_cidrs) > 0 &&
      alltrue([
        for cidr in var.metrics_ingress_cidrs : try(
          !strcontains(cidr, ":") &&
          cidr != "0.0.0.0/0" &&
          cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" &&
          (
            startswith(cidrhost(cidr, 0), "10.") && tonumber(split("/", cidr)[1]) >= 8 ||
            can(regex("^172\\.(?:1[6-9]|2[0-9]|3[01])\\.", cidrhost(cidr, 0))) && tonumber(split("/", cidr)[1]) >= 12 ||
            startswith(cidrhost(cidr, 0), "192.168.") && tonumber(split("/", cidr)[1]) >= 16
          ),
          false,
        )
      ])
    )
    error_message = "metrics_ingress_cidrs must contain one or more RFC1918 IPv4 CIDRs and cannot contain 0.0.0.0/0."
  }
}

variable "metrics_port" {
  description = "Private Prometheus, health, and readiness HTTP port."
  type        = number
  default     = 9091

  validation {
    condition     = var.metrics_port >= 1024 && var.metrics_port <= 65535 && floor(var.metrics_port) == var.metrics_port
    error_message = "metrics_port must be a whole-number unprivileged TCP port."
  }
}

variable "log_level" {
  description = "Controller production log level."
  type        = string
  default     = "info"

  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.log_level)
    error_message = "log_level must be debug, info, warn, or error."
  }
}

variable "controller_ready_metric" {
  description = "CloudWatch custom metric contract expected from an external private readiness collector."
  type = object({
    namespace          = string
    metric_name        = string
    period_seconds     = number
    evaluation_periods = number
  })
  default = {
    namespace          = "Envelope/Controller"
    metric_name        = "Ready"
    period_seconds     = 60
    evaluation_periods = 2
  }

  validation {
    condition = (
      can(regex("^[A-Za-z0-9_./#:-]{1,255}$", var.controller_ready_metric.namespace)) &&
      !startswith(var.controller_ready_metric.namespace, "AWS/") &&
      can(regex("^[A-Za-z][A-Za-z0-9_.-]{0,254}$", var.controller_ready_metric.metric_name)) &&
      var.controller_ready_metric.period_seconds >= 60 &&
      var.controller_ready_metric.period_seconds <= 86400 &&
      var.controller_ready_metric.period_seconds % 60 == 0 &&
      var.controller_ready_metric.evaluation_periods >= 1 &&
      var.controller_ready_metric.evaluation_periods <= 10 &&
      floor(var.controller_ready_metric.evaluation_periods) == var.controller_ready_metric.evaluation_periods
    )
    error_message = "controller_ready_metric must describe a non-AWS standard-resolution metric and bounded alarm window."
  }
}

variable "readiness_publisher" {
  description = "Existing external collector AWS identity and network/sampling contract for publishing fail-closed readiness metrics."
  type = object({
    id                      = string
    role_name               = string
    role_arn                = string
    source_cidrs            = set(string)
    scrape_interval_seconds = number
  })

  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", var.readiness_publisher.id)) &&
      can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.readiness_publisher.role_name)) &&
      startswith(var.readiness_publisher.role_arn, "arn:") &&
      strcontains(var.readiness_publisher.role_arn, ":iam::") &&
      strcontains(var.readiness_publisher.role_arn, ":role/") &&
      !strcontains(var.readiness_publisher.role_arn, "*") &&
      length(var.readiness_publisher.source_cidrs) > 0 &&
      alltrue([
        for cidr in var.readiness_publisher.source_cidrs : try(
          !strcontains(cidr, ":") &&
          cidr != "0.0.0.0/0" &&
          cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" &&
          (
            startswith(cidrhost(cidr, 0), "10.") && tonumber(split("/", cidr)[1]) >= 8 ||
            can(regex("^172\\.(?:1[6-9]|2[0-9]|3[01])\\.", cidrhost(cidr, 0))) && tonumber(split("/", cidr)[1]) >= 12 ||
            startswith(cidrhost(cidr, 0), "192.168.") && tonumber(split("/", cidr)[1]) >= 16
          ),
          false,
        )
      ]) &&
      var.readiness_publisher.scrape_interval_seconds >= 10 &&
      var.readiness_publisher.scrape_interval_seconds <= 300 &&
      floor(var.readiness_publisher.scrape_interval_seconds) == var.readiness_publisher.scrape_interval_seconds
    )
    error_message = "readiness_publisher must identify one exact IAM role, private source CIDRs, and a whole 10-300 second scrape interval."
  }
}

variable "alarm_actions" {
  description = "Nonempty exact ARNs notified by every controller alarm."
  type        = set(string)

  validation {
    condition = (
      length(var.alarm_actions) > 0 &&
      alltrue([
        for arn in var.alarm_actions :
        arn == trimspace(arn) &&
        length(arn) <= 2048 &&
        can(regex("^arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:[^[:space:]]+$", arn)) &&
        !can(regex("[*?\\p{Cc}]", arn))
      ])
    )
    error_message = "alarm_actions must contain one or more exact ARNs."
  }
}

variable "tags" {
  description = "Additional nonsecret tags; deployment-owned Name and Role tags take precedence."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for key, value in var.tags :
      key != "" && value != "" &&
      !can(regex("(?i)(secret|token|password|private.?key)", key)) &&
      !can(regex("(?i)(tskey-|nodekey:|machinekey:|privkey:|-----begin[ ]+private[ ]+key-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})", value))
    ])
    error_message = "tags must be nonempty and must not be used to carry secrets."
  }
}
