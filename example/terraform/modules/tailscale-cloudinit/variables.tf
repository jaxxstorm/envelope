variable "auth_key" {
  description = "Runtime auth-key resolver; command: values execute only after the pinned package is installed"
  type        = string
  sensitive   = true

  validation {
    condition = can(regex(
      "^command:AWS_PAGER= /usr/bin/aws ssm get-parameter --region [a-z0-9-]+ --name 'arn:aws:ssm:[a-z0-9-]+:[0-9]{12}:parameter/[A-Za-z0-9_./-]+' --with-decryption --query Parameter.Value --output text$",
      var.auth_key,
    ))
    error_message = "auth_key must be the reviewed single-line regional SSM runtime resolver."
  }
}

variable "gzip" {
  description = "Compress rendered multipart MIME before base64 encoding"
  type        = bool
}

variable "hostname" {
  type = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,61}[a-z0-9]$", var.hostname))
    error_message = "hostname must be a shell-safe lowercase Tailscale hostname."
  }
}

variable "advertise_tags" {
  type = list(string)

  validation {
    condition     = length(var.advertise_tags) == 1 && alltrue([for tag in var.advertise_tags : can(regex("^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$", tag))])
    error_message = "advertise_tags must contain exactly one shell-safe reviewed tag."
  }
}

variable "advertise_routes" {
  type = list(string)

  validation {
    condition = length(var.advertise_routes) > 0 && length(var.advertise_routes) == length(distinct(var.advertise_routes)) && alltrue([
      for cidr in var.advertise_routes : try(
        cidrnetmask(cidr) != "" && cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}",
        false,
      )
    ])
    error_message = "advertise_routes must contain canonical IPv4 networks."
  }
}

variable "accept_routes" {
  type = bool

  validation {
    condition     = var.accept_routes
    error_message = "accept_routes must remain enabled for reviewed bidirectional transport routers."
  }
}

variable "snat_subnet_routes" {
  type = bool

  validation {
    condition     = !var.snat_subnet_routes
    error_message = "snat_subnet_routes must remain disabled."
  }
}

variable "netfilter_mode" {
  type = string

  validation {
    condition     = var.netfilter_mode == "off"
    error_message = "netfilter_mode must remain off so the reviewed host firewall is the sole owner."
  }
}

variable "max_retries" {
  type = number

  validation {
    condition     = var.max_retries >= 1 && var.max_retries <= 60 && floor(var.max_retries) == var.max_retries
    error_message = "max_retries must be a whole number from 1 through 60."
  }
}

variable "retry_delay" {
  type = number

  validation {
    condition     = var.retry_delay >= 1 && var.retry_delay <= 300 && floor(var.retry_delay) == var.retry_delay
    error_message = "retry_delay must be a whole number from 1 through 300."
  }
}

variable "timeout" {
  type = string

  validation {
    condition     = can(regex("^[1-9][0-9]{0,2}[smh]$", var.timeout))
    error_message = "timeout must be a bounded shell-safe duration token."
  }
}

variable "package_version" {
  type = string

  validation {
    condition     = var.package_version == "1.80.3"
    error_message = "package_version must remain pinned to reviewed Tailscale 1.80.3."
  }
}

variable "package_url" {
  type = string

  validation {
    condition = contains([
      "https://pkgs.tailscale.com/stable/amazon-linux/2023/x86_64/tailscale_1.80.3_x86_64.rpm",
      "https://pkgs.tailscale.com/stable/amazon-linux/2023/aarch64/tailscale_1.80.3_aarch64.rpm",
    ], var.package_url)
    error_message = "package_url must select one reviewed Tailscale 1.80.3 Amazon Linux 2023 RPM."
  }
}

variable "package_sha256" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.package_sha256))
    error_message = "package_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "additional_parts" {
  type = list(object({
    filename     = string
    content_type = string
    content      = string
  }))
  default = []
}

variable "pre_setup_parts" {
  description = "Reviewed cloud-init parts that must complete before tailscale up advertises routes"
  type = list(object({
    filename     = string
    content_type = string
    content      = string
  }))
  default = []
}

variable "pre_setup_gate" {
  description = "Absolute marker that must exist before tailscale up; empty disables the gate"
  type        = string
  default     = ""

  validation {
    condition     = var.pre_setup_gate == "" || startswith(var.pre_setup_gate, "/var/lib/")
    error_message = "pre_setup_gate must be empty or an absolute path under /var/lib."
  }
}
