variable "auth_key" {
  description = "Runtime auth-key resolver; command: values execute only after the pinned package is installed"
  type        = string
  sensitive   = true
}

variable "hostname" {
  type = string
}

variable "advertise_tags" {
  type = list(string)
}

variable "advertise_routes" {
  type = list(string)
}

variable "accept_routes" {
  type = bool
}

variable "snat_subnet_routes" {
  type = bool
}

variable "netfilter_mode" {
  type = string

  validation {
    condition     = contains(["on", "nodivert", "off"], var.netfilter_mode)
    error_message = "netfilter_mode must be on, nodivert, or off."
  }
}

variable "max_retries" {
  type = number
}

variable "retry_delay" {
  type = number
}

variable "timeout" {
  type = string
}

variable "package_version" {
  type = string
}

variable "package_url" {
  type = string
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
