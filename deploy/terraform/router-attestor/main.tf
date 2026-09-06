terraform {
  backend "s3" {}
  required_version = ">= 1.10.1, < 1.11.0"
  required_providers { aws = { source = "hashicorp/aws", version = "6.33.0" } }
}

provider "aws" { region = var.authority_region }

variable "authority_region" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]+-[0-9]+$", var.authority_region))
    error_message = "authority_region must be an explicit AWS region."
  }
}

variable "protected_acceptance" {
  type    = bool
  default = false
}
variable "run_tags" {
  type    = map(string)
  default = {}
  validation {
    condition     = !var.protected_acceptance || try(var.run_tags.EnvelopeRun == var.name && can(regex("^[0-9a-f]{64}$", var.run_tags.EnvelopeInvocation)) && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.run_tags.ExpiresAt)), false)
    error_message = "Disposable enrollment requires exact run, invocation and expiry tags."
  }
}
variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.name))
    error_message = "name must be a unique bounded deployment identifier."
  }
}
variable "controller_source_cidrs" {
  description = "Exact private management source CIDRs reaching router attestation endpoints. Routing between management and site VPCs must already exist."
  type        = set(string)
  validation {
    condition     = length(var.controller_source_cidrs) > 0 && alltrue([for cidr in var.controller_source_cidrs : can(cidrnetmask(cidr)) && tonumber(split("/", cidr)[1]) >= 8 && (startswith(cidr, "10.") || startswith(cidr, "192.168.") || (startswith(cidr, "172.") && tonumber(split(".", cidr)[1]) >= 16 && tonumber(split(".", cidr)[1]) <= 31))])
    error_message = "Controller sources must be nonempty bounded RFC1918 IPv4 CIDRs."
  }
}
variable "enrollments" {
  description = "Reviewed Go collector identities and exact existing per-router SecureString references. Seed values must never be supplied to Terraform."
  type = map(object({
    configuration_identity_json  = string
    configuration_parameter_name = string
    seed_parameter_arn           = string
    seed_version                 = number
    seed_kms_key_arn             = string
    role_name                    = string
    security_group_id            = string
  }))
  validation {
    condition = length(var.enrollments) > 0 && alltrue([for id, entry in var.enrollments : (
      can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$", id)) &&
      can(regex("^/envelope/[A-Za-z0-9/_-]+$", entry.configuration_parameter_name)) &&
      can(regex("^arn:aws:ssm:[a-z0-9-]+:[0-9]{12}:parameter/envelope/[A-Za-z0-9/_-]+$", entry.seed_parameter_arn)) &&
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", entry.seed_kms_key_arn)) &&
      can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", entry.role_name)) &&
      can(regex("^sg-[0-9a-f]{8,17}$", entry.security_group_id)) &&
      entry.seed_version >= 1 && entry.seed_version <= 100 && floor(entry.seed_version) == entry.seed_version
    )]) && length(distinct([for e in var.enrollments : e.seed_parameter_arn])) == length(var.enrollments) && length(distinct([for e in var.enrollments : e.configuration_parameter_name])) == length(var.enrollments)
    error_message = "Each router needs unique exact configuration/seed references, explicit IAM/SG authority, and an integer seed version."
  }
}

data "aws_caller_identity" "current" {}
locals {
  identities    = { for id, e in var.enrollments : id => jsondecode(e.configuration_identity_json) }
  canonical     = { for id, identity in local.identities : id => base64decode(identity.canonical_json_base64) }
  configs       = { for id, raw in local.canonical : id => jsondecode(raw) }
  owners        = { for id, c in local.configs : id => one([for router in c.topology.routers : router if router.id == id]) }
  instance_arns = { for id, owner in local.owners : id => "arn:aws:ec2:${owner.region}:${data.aws_caller_identity.current.account_id}:instance/${owner.instance_id}" }
  ingress       = { for entry in distinct(flatten([for id, e in var.enrollments : [for cidr in var.controller_source_cidrs : { region = local.owners[id].region, group = e.security_group_id, cidr = cidr }]])) : "${entry.region}/${entry.group}/${entry.cidr}" => entry }
}

data "aws_instance" "router" {
  for_each    = var.enrollments
  region      = local.owners[each.key].region
  instance_id = local.owners[each.key].instance_id
}
data "aws_iam_instance_profile" "router" {
  for_each = var.enrollments
  name     = data.aws_instance.router[each.key].iam_instance_profile
}
data "aws_iam_role" "router" {
  for_each = var.enrollments
  name     = each.value.role_name
}
data "aws_security_group" "router" {
  for_each = var.enrollments
  region   = local.owners[each.key].region
  id       = each.value.security_group_id
}

resource "terraform_data" "contract" {
  for_each = var.enrollments
  lifecycle {
    precondition {
      condition = try(
        local.identities[each.key].schema == 1 && local.identities[each.key].component == "envelope-router-attestor" && local.identities[each.key].source_modified == false &&
        local.identities[each.key].go_version == trimspace(file("${path.module}/../../../scripts/reviewed-go-toolchain.txt")) &&
        can(regex("^[0-9a-f]{40}$", local.identities[each.key].revision)) && local.identities[each.key].version != "dev" &&
        local.identities[each.key].canonical_sha256 == sha256(local.canonical[each.key]) &&
        local.identities[each.key].router_id == each.key && local.configs[each.key].router_id == each.key &&
        local.identities[each.key].ed25519_public_key == local.configs[each.key].ed25519_public_key &&
        can(regex("^[0-9a-f]{64}$", local.identities[each.key].ed25519_public_key)) &&
        can(regex("^[0-9a-f]{64}$", local.identities[each.key].topology_sha256)) &&
        length(distinct([for i in local.identities : i.ed25519_public_key])) == length(local.identities) &&
        startswith(each.value.seed_parameter_arn, "arn:aws:ssm:${var.authority_region}:${data.aws_caller_identity.current.account_id}:parameter/envelope/") &&
        startswith(each.value.seed_kms_key_arn, "arn:aws:kms:${var.authority_region}:${data.aws_caller_identity.current.account_id}:key/") &&
        data.aws_instance.router[each.key].instance_state == "running" && data.aws_instance.router[each.key].source_dest_check == false &&
        data.aws_instance.router[each.key].network_interface_id == local.owners[each.key].eni_id &&
        data.aws_instance.router[each.key].subnet_id == local.owners[each.key].subnet_id &&
        data.aws_instance.router[each.key].availability_zone == local.owners[each.key].availability_zone &&
        data.aws_iam_instance_profile.router[each.key].role_name == each.value.role_name &&
        data.aws_iam_role.router[each.key].tags["Role"] == "transport-router" &&
        data.aws_security_group.router[each.key].vpc_id == local.owners[each.key].vpc_id &&
      contains(data.aws_instance.router[each.key].vpc_security_group_ids, each.value.security_group_id), false)
      error_message = "Enrollment must be a clean reviewed Go identity bound to the exact running router instance, primary ENI, subnet/AZ, actual transport role, and attached site security group."
    }
  }
}

resource "aws_s3_bucket" "configurations" {
  bucket        = "${substr(var.name, 0, 16)}-attestor-${substr(sha256(var.name), 0, 8)}-${data.aws_caller_identity.current.account_id}-${var.authority_region}"
  force_destroy = var.protected_acceptance
  tags          = merge(var.run_tags, { Component = "router-attestor-enrollment", Deployment = var.name })
}
resource "aws_s3_bucket_versioning" "configurations" {
  bucket = aws_s3_bucket.configurations.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "configurations" {
  bucket = aws_s3_bucket.configurations.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "configurations" {
  bucket                  = aws_s3_bucket.configurations.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "configurations" {
  bucket = aws_s3_bucket.configurations.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.configurations.arn, "${aws_s3_bucket.configurations.arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } }] })
}
resource "aws_s3_object" "configuration" {
  for_each               = var.enrollments
  bucket                 = aws_s3_bucket.configurations.id
  key                    = "configurations/${local.identities[each.key].canonical_sha256}.json"
  content_base64         = local.identities[each.key].canonical_json_base64
  content_type           = "application/json"
  server_side_encryption = "AES256"
  depends_on             = [terraform_data.contract, aws_s3_bucket_versioning.configurations, aws_s3_bucket_public_access_block.configurations]
}

# An enrollment key is bound to one instance/ENI/stable node/configuration.
# Reusing it for a replacement fails the version-1 check before granting access.
resource "aws_ssm_parameter" "binding" {
  for_each = var.enrollments
  name     = "/envelope/attestor-bindings/${local.identities[each.key].ed25519_public_key}"
  type     = "String"
  tags     = var.run_tags
  value = jsonencode({
    instance_id          = local.owners[each.key].instance_id
    eni_id               = local.owners[each.key].eni_id
    stable_node_id       = local.owners[each.key].stable_node_id
    configuration_sha256 = local.identities[each.key].canonical_sha256
    ed25519_public_key   = local.identities[each.key].ed25519_public_key
    seed_parameter_arn   = each.value.seed_parameter_arn
    seed_version         = each.value.seed_version
  })
  depends_on = [terraform_data.contract]
  lifecycle {
    postcondition {
      condition     = self.version == 1
      error_message = "Key bindings are immutable version 1. Generate a fresh per-instance key instead of reassigning an enrolled key."
    }
  }
}
resource "aws_ssm_parameter" "configuration" {
  for_each = var.enrollments
  name     = each.value.configuration_parameter_name
  type     = "String"
  tags     = var.run_tags
  value = jsonencode({
    bucket     = aws_s3_bucket.configurations.id
    key        = aws_s3_object.configuration[each.key].key
    version_id = aws_s3_object.configuration[each.key].version_id
    sha256     = local.identities[each.key].canonical_sha256
  })
  depends_on = [aws_ssm_parameter.binding]
  lifecycle {
    postcondition {
      condition     = self.version == 1
      error_message = "Enrollment pointers are immutable version 1. Supply a new parameter name for a new enrollment."
    }
  }
}

resource "aws_iam_role_policy" "router" {
  for_each = var.enrollments
  name     = "attestor-${substr(sha256(each.key), 0, 12)}"
  role     = each.value.role_name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    {
      Sid = "ReadOnlyRouterAuthority", Effect = "Deny", NotAction = ["ec2:Describe*", "ssm:GetParameter", "kms:Decrypt", "s3:GetObjectVersion"], Resource = "*"
    },
    {
      Sid       = "ReadForwardingIdentity", Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables", "ec2:DescribeSubnets", "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcs"], Resource = "*"
      Condition = { StringEquals = { "aws:RequestedRegion" = local.owners[each.key].region }, ArnEquals = { "ec2:SourceInstanceARN" = local.instance_arns[each.key] } }
    },
    {
      Sid       = "ReadOnlyOwnEnrollment", Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [aws_ssm_parameter.binding[each.key].arn, aws_ssm_parameter.configuration[each.key].arn, each.value.seed_parameter_arn]
      Condition = { StringEquals = { "aws:RequestedRegion" = var.authority_region }, ArnEquals = { "ec2:SourceInstanceARN" = local.instance_arns[each.key] } }
    },
    {
      Sid       = "DenyOtherInstancesEvenWithSharedRole", Effect = "Deny", Action = ["ssm:GetParameter"], Resource = [aws_ssm_parameter.binding[each.key].arn, aws_ssm_parameter.configuration[each.key].arn, each.value.seed_parameter_arn]
      Condition = { ArnNotEquals = { "ec2:SourceInstanceARN" = local.instance_arns[each.key] } }
    },
    {
      Sid       = "DecryptOnlyOwnSeed", Effect = "Allow", Action = ["kms:Decrypt"], Resource = each.value.seed_kms_key_arn
      Condition = { StringEquals = { "kms:ViaService" = "ssm.${var.authority_region}.amazonaws.com", "kms:EncryptionContext:PARAMETER_ARN" = each.value.seed_parameter_arn, "kms:CallerAccount" = data.aws_caller_identity.current.account_id } }
    },
    {
      Sid       = "ReadOnlyOwnConfigurationVersion", Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = aws_s3_object.configuration[each.key].arn
      Condition = { StringEquals = { "s3:VersionId" = aws_s3_object.configuration[each.key].version_id }, ArnEquals = { "ec2:SourceInstanceARN" = local.instance_arns[each.key] } }
    },
  ] })
  depends_on = [terraform_data.contract, aws_ssm_parameter.binding, aws_ssm_parameter.configuration]
}

resource "aws_vpc_security_group_ingress_rule" "attestation" {
  for_each          = local.ingress
  region            = each.value.region
  security_group_id = each.value.group
  cidr_ipv4         = each.value.cidr
  from_port         = 9443
  to_port           = 9443
  ip_protocol       = "tcp"
  description       = "Private controller attestation"
  depends_on        = [terraform_data.contract]
}

output "router_attestations" {
  description = "Feed this independently reviewed enrollment authority to the controller root. No key is learned from a router report."
  value = { for id, identity in local.identities : id => {
    ed25519_public_key   = identity.ed25519_public_key
    configuration_sha256 = identity.canonical_sha256
    url                  = "https://${data.aws_instance.router[id].private_ip}:9443/attestation"
  } }
  depends_on = [aws_ssm_parameter.binding, aws_ssm_parameter.configuration]
}
