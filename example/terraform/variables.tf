

variable "name" {
  description = "Name of the subnet router"
  type        = string
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

variable "west_vpc_cidr" {
  description = "CIDR for the west VPC"
  type        = string
  default     = "172.16.0.0/16"
}

variable "west_private_subnets" {
  description = "Private subnets for the west VPC"
  type        = list(string)
  default     = ["172.16.0.0/24", "172.16.1.0/24", "172.16.2.0/24"]
}

variable "west_public_subnets" {
  description = "Public subnets for the west VPC"
  type        = list(string)
  default     = ["172.16.3.0/24", "172.16.4.0/24", "172.16.5.0/24"]
}

variable "east_vpc_cidr" {
  description = "CIDR for the east VPC"
  type        = string
  default     = "172.17.0.0/16"
}

variable "east_private_subnets" {
  description = "Private subnets for the east VPC"
  type        = list(string)
  default     = ["172.17.0.0/24", "172.17.1.0/24", "172.17.2.0/24"]
}

variable "east_public_subnets" {
  description = "Public subnets for the east VPC"
  type        = list(string)
  default     = ["172.17.3.0/24", "172.17.4.0/24", "172.17.5.0/24"]
}

variable "enable_aws_ssm" {
  description = "Enable AWS SSM for the instance"
  type        = bool
  default     = true

}

variable "tags" {
  description = "EC2 tags to apply to the instance"
  type        = map(string)
  default     = {}
}

variable "architecture" {
  description = "Architecture of the instance"
  type        = string
  default     = "x86_64"
}

variable "instance_type" {
  description = "Instance type to use for the subnet routers"
  default     = "t3.medium"
  type        = string
}

variable "test_instance_type" {
  description = "Instance type to use for test instances"
  default     = "t3.micro"
  type        = string
}

variable "ebs_root_volume_size" {
  description = "Size of the root volume in GB"
  default     = 20
  type        = number
}


variable "tailscale_auth_key" {
  description = "Tailscale authentication key"
  type        = string
  sensitive   = true
}

variable "advertise_tags" {
  description = "Tags to advertise for the subnet routers"
  type        = list(string)
  default     = []
}

variable "hostname" {
  description = "The hostname for the Tailscale ec2 instances"
  type        = string
  default     = "subnet-router"
}

variable "tailscale_snat_subnet_routes" {
  description = "Whether Tailscale should SNAT subnet-routed traffic"
  type        = bool
  default     = false
}

variable "tailscale_netfilter_mode" {
  description = "Tailscale netfilter mode (on, nodivert, off)"
  type        = string
  default     = "off"

  validation {
    condition     = contains(["on", "nodivert", "off"], var.tailscale_netfilter_mode)
    error_message = "tailscale_netfilter_mode must be one of: on, nodivert, off."
  }
}

variable "envelope_routing_mode" {
  description = "Envelope routing mode (off, verify, manage)"
  type        = string
  default     = "manage"

  validation {
    condition     = contains(["off", "verify", "manage"], var.envelope_routing_mode)
    error_message = "envelope_routing_mode must be one of: off, verify, manage."
  }
}

variable "envelope_tailscale_iface" {
  description = "Tailscale interface name expected by Envelope"
  type        = string
  default     = "tailscale0"
}

variable "envelope_protected_cidrs" {
  description = "Protected CIDRs routed between GWLB and Tailscale through Envelope"
  type        = list(string)
  default     = ["172.16.0.0/16"]
}

variable "envelope_routing_table_id" {
  description = "Linux routing table ID used by Envelope routing integration"
  type        = number
  default     = 100
}

variable "envelope_routing_rule_priority" {
  description = "Linux policy rule priority used by Envelope routing integration"
  type        = number
  default     = 100
}
