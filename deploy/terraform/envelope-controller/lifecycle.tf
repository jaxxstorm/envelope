variable "deployment_lifecycle" {
  description = "Explicit deployment caller trust. Null provisions no lifecycle role. Rollout additionally requires exact backend and KMS resource authority. Never use a controller/router principal here."
  type = object({
    trusted_principal_arns = set(string)
    external_id            = string
    rollout = optional(object({
      state_bucket_arn = string
      state_key        = string
      kms_key_arns     = set(string)
    }))
  })
  default = null

  validation {
    condition = var.deployment_lifecycle == null ? true : (
      length(var.deployment_lifecycle.trusted_principal_arns) > 0 &&
      alltrue([for arn in var.deployment_lifecycle.trusted_principal_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn))]) &&
      can(regex("^[A-Za-z0-9_-]{16,128}$", var.deployment_lifecycle.external_id))
    )
    error_message = "Lifecycle trust requires explicit IAM role principals and a 16-128 character external ID, with no wildcard or account-root principal."
  }

  validation {
    condition = try(var.deployment_lifecycle.rollout, null) == null ? true : (
      can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]+$", var.deployment_lifecycle.rollout.state_bucket_arn)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9/_.-]+$", var.deployment_lifecycle.rollout.state_key)) &&
      !strcontains(var.deployment_lifecycle.rollout.state_key, "..") &&
      length(var.deployment_lifecycle.rollout.kms_key_arns) > 0 &&
      alltrue([for arn in var.deployment_lifecycle.rollout.kms_key_arns : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", arn))])
    )
    error_message = "Rollout requires one exact backend bucket/key and explicit KMS key ARNs; wildcards and traversal are forbidden."
  }
}

locals {
  lifecycle_enabled = var.deployment_lifecycle != null
  lifecycle_rollout = try(var.deployment_lifecycle.rollout, null)
  lifecycle_state_keys = local.lifecycle_rollout == null ? [] : [
    local.lifecycle_rollout.state_key,
    "${local.lifecycle_rollout.state_key}.tflock",
  ]
  lifecycle_lock_key     = "lifecycle#${local.topology.deployment_id}"
  lifecycle_read_actions = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables"]
  lifecycle_rollout_actions = [
    "ec2:Describe*", "ec2:RunInstances", "ec2:TerminateInstances", "ec2:CreateTags", "ec2:AttachVolume", "ec2:DetachVolume", "ec2:StopInstances", "ec2:ModifyInstanceAttribute",
    "iam:PassRole", "iam:GetRole", "iam:GetInstanceProfile", "sts:GetCallerIdentity",
    "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "kms:GenerateDataKey", "kms:CreateGrant", "kms:DescribeKey",
  ]
}

resource "aws_iam_role" "deployment_lifecycle" {
  count = local.lifecycle_enabled ? 1 : 0
  name  = "${var.name}-lifecycle"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = sort(tolist(var.deployment_lifecycle.trusted_principal_arns)) }
      Condition = { StringEquals = { "sts:ExternalId" = var.deployment_lifecycle.external_id } }
    }]
  })
  max_session_duration = 3600
  tags                 = merge(local.common_tags, { Role = "deployment-lifecycle" })

  lifecycle {
    precondition {
      condition     = length(setintersection(var.deployment_lifecycle.trusted_principal_arns, toset([for role in aws_iam_role.controller : role.arn]))) == 0
      error_message = "Controller roles cannot assume deployment lifecycle authority."
    }
  }
}

resource "aws_iam_role_policy" "deployment_lifecycle" {
  count = local.lifecycle_enabled ? 1 : 0
  name  = "${var.name}-lifecycle"
  role  = aws_iam_role.deployment_lifecycle[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "DenyRouteMutationAndEscalation"
        Effect    = "Deny"
        NotAction = concat(local.lifecycle_read_actions, ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:ConditionCheckItem", "kms:Decrypt"], local.lifecycle_rollout == null ? [] : local.lifecycle_rollout_actions)
        Resource  = "*"
      },
      {
        Sid      = "ReadDeploymentHealth"
        Effect   = "Allow"
        Action   = local.lifecycle_read_actions
        Resource = "*"
      },
      {
        Sid      = "ReadBothTopologyGenerations"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:ConditionCheckItem"]
        Resource = aws_dynamodb_table.authority.arn
        Condition = {
          "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = [local.domain_partition_key, local.lifecycle_lock_key, "observations#${local.topology.deployment_id}#*"] }
          Null                      = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Sid      = "WriteOnlyDeploymentAndLock"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.authority.arn
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = [local.domain_partition_key, local.lifecycle_lock_key] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Sid      = "DecryptAuthorityOnly"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"                                  = "dynamodb.${var.aws_region}.amazonaws.com"
            "kms:CallerAccount"                               = var.aws_account_id
            "kms:EncryptionContext:aws:dynamodb:tableName"    = var.authority_table_name
            "kms:EncryptionContext:aws:dynamodb:subscriberId" = var.aws_account_id
          }
        }
      },
      ], jsondecode(local.lifecycle_rollout == null ? "[]" : jsonencode([
        {
          Sid      = "ReadRolloutInfrastructure"
          Effect   = "Allow"
          Action   = ["ec2:Describe*", "iam:GetRole", "iam:GetInstanceProfile", "sts:GetCallerIdentity"]
          Resource = "*"
        },
        {
          Sid       = "PassOnlyControllerRoles"
          Effect    = "Allow"
          Action    = ["iam:PassRole"]
          Resource  = [for role in aws_iam_role.controller : role.arn]
          Condition = { StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" } }
        },
        {
          Sid    = "LaunchReviewedControllerResources"
          Effect = "Allow"
          Action = ["ec2:RunInstances"]
          Resource = concat([
            "arn:aws:ec2:${var.aws_region}::image/${data.aws_ami.controller.id}",
            "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:security-group/${aws_security_group.controller.id}",
            "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
            "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
            "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*",
          ], [for placement in var.controller_placements : "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:subnet/${placement.subnet_id}"])
        },
        {
          Sid       = "TagOnlyNewControllerResources"
          Effect    = "Allow"
          Action    = ["ec2:CreateTags"]
          Resource  = ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*", "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:volume/*", "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"]
          Condition = { StringEquals = { "ec2:CreateAction" = "RunInstances", "aws:RequestTag/Deployment" = var.name } }
        },
        {
          Sid       = "ReplaceOnlyTaggedControllers"
          Effect    = "Allow"
          Action    = ["ec2:TerminateInstances", "ec2:StopInstances", "ec2:ModifyInstanceAttribute"]
          Resource  = "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
          Condition = { StringEquals = { "ec2:ResourceTag/Deployment" = var.name, "ec2:ResourceTag/Role" = "envelope-controller" } }
        },
        {
          Sid       = "ReattachOnlyObserverState"
          Effect    = "Allow"
          Action    = ["ec2:AttachVolume", "ec2:DetachVolume"]
          Resource  = concat([for volume in aws_ebs_volume.observer_state : volume.arn], ["arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"])
          Condition = { StringEquals = { "ec2:ResourceTag/Deployment" = var.name } }
        },
        {
          Sid      = "ExactTerraformBackend"
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
          Resource = [for key in local.lifecycle_state_keys : "${local.lifecycle_rollout.state_bucket_arn}/${key}"]
        },
        {
          Sid       = "ListTerraformBackend"
          Effect    = "Allow"
          Action    = ["s3:ListBucket"]
          Resource  = local.lifecycle_rollout.state_bucket_arn
          Condition = { StringLike = { "s3:prefix" = local.lifecycle_state_keys } }
        },
        {
          Sid       = "DecryptRolloutStorage"
          Effect    = "Allow"
          Action    = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
          Resource  = sort(tolist(local.lifecycle_rollout.kms_key_arns))
          Condition = { StringEquals = { "kms:CallerAccount" = var.aws_account_id, "kms:ViaService" = ["ec2.${var.aws_region}.amazonaws.com", "s3.${var.aws_region}.amazonaws.com"] } }
        },
        {
          Sid       = "GrantOnlyAWSStorageUse"
          Effect    = "Allow"
          Action    = ["kms:CreateGrant"]
          Resource  = sort(tolist(local.lifecycle_rollout.kms_key_arns))
          Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
        },
    ])))
  })
}

output "deployment_lifecycle_role_arn" {
  description = "Explicit route-denied deployment role; pass its configured ExternalId to the Go command. Null means lifecycle authority was not provisioned."
  value       = try(aws_iam_role.deployment_lifecycle[0].arn, null)
}
