locals {
  ec2_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EC2AssumeRole"
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  domain_partition_key = "deployment#${local.topology.deployment_id}"
  observation_partition_keys = {
    for controller_id in var.controller_ids :
    controller_id => "observations#${local.topology.deployment_id}#${local.topology_sha256}#${controller_id}"
  }
  observation_partition_key_values = [
    for controller_id in sort(tolist(var.controller_ids)) : local.observation_partition_keys[controller_id]
  ]

  controller_policy_statements = {
    for controller_id in var.controller_ids : controller_id => concat(
      [
        {
          Sid      = "ReadDomainAuthority"
          Effect   = "Allow"
          Action   = ["dynamodb:GetItem"]
          Resource = [aws_dynamodb_table.authority.arn]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = var.aws_region }
            "ForAllValues:StringEquals" = {
              "dynamodb:LeadingKeys" = [local.domain_partition_key]
            }
            Null = { "dynamodb:LeadingKeys" = "false" }
          }
        },
        {
          Sid      = "ReadObservationQuorum"
          Effect   = "Allow"
          Action   = ["dynamodb:GetItem"]
          Resource = [aws_dynamodb_table.authority.arn]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = var.aws_region }
            "ForAllValues:StringEquals" = {
              "dynamodb:LeadingKeys" = local.observation_partition_key_values
            }
            Null = { "dynamodb:LeadingKeys" = "false" }
          }
        },
        {
          Sid      = "PublishObservation"
          Effect   = "Allow"
          Action   = ["dynamodb:PutItem"]
          Resource = [aws_dynamodb_table.authority.arn]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = var.aws_region }
            "ForAllValues:StringEquals" = {
              "dynamodb:LeadingKeys" = [local.observation_partition_keys[controller_id]]
            }
            Null = { "dynamodb:LeadingKeys" = "false" }
          }
        },
        {
          Sid    = "ReadControllerBootstrapParameters"
          Effect = "Allow"
          Action = ["ssm:GetParameter"]
          Resource = [
            aws_ssm_parameter.topology.arn,
            aws_ssm_parameter.router_trust.arn,
            var.secret_parameters.tsnet.arn,
            var.secret_parameters.admin.arn,
          ]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = var.aws_region }
          }
        },
        {
          Sid      = "ReadVersionedControllerArtifact"
          Effect   = "Allow"
          Action   = ["s3:GetObjectVersion"]
          Resource = [var.artifact.object_arn]
          Condition = {
            StringEquals = {
              "aws:RequestedRegion" = var.artifact.region
              "s3:VersionId"        = var.artifact.version_id
            }
          }
        },
        {
          Sid      = "ReadVersionedTopologyIdentityArtifact"
          Effect   = "Allow"
          Action   = ["s3:GetObjectVersion"]
          Resource = [var.topology_identity_artifact.object_arn]
          Condition = {
            StringEquals = {
              "aws:RequestedRegion" = var.topology_identity_artifact.region
              "s3:VersionId"        = var.topology_identity_artifact.version_id
            }
          }
        },
        {
          Sid    = "ReadCloudEligibilityAndRoutes"
          Effect = "Allow"
          Action = [
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeRouteTables",
          ]
          Resource = ["*"]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = sort(tolist(local.topology_site_regions)) }
          }
        },
        {
          Sid      = "WriteApplicationLogs"
          Effect   = "Allow"
          Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
          Resource = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.application.name}:*"]
        },
        {
          Sid      = "DescribeApplicationLogGroupsAndStreams"
          Effect   = "Allow"
          Action   = ["logs:DescribeLogGroups", "logs:DescribeLogStreams"]
          Resource = ["*"]
        },
      ],
      [
        for secret_name in ["tsnet", "admin"] : {
          Sid      = "Decrypt${title(secret_name)}ParameterOnly"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.secret_parameters[secret_name].kms_key_arn]
          Condition = {
            StringEquals = {
              "kms:CallerAccount"                   = var.aws_account_id
              "kms:EncryptionContext:PARAMETER_ARN" = var.secret_parameters[secret_name].arn
              "kms:ViaService"                      = "ssm.${var.aws_region}.${data.aws_partition.current.dns_suffix}"
            }
          }
        }
      ],
      var.protected_acceptance_mode ? [] : [
        {
          Sid      = "DecryptDynamoDBAuthorityTableOnly"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [local.controller_kms_key_arn]
          Condition = {
            StringEquals = {
              "kms:CallerAccount"                               = var.aws_account_id
              "kms:EncryptionContext:aws:dynamodb:subscriberId" = var.aws_account_id
              "kms:EncryptionContext:aws:dynamodb:tableName"    = var.authority_table_name
              "kms:ViaService"                                  = "dynamodb.${var.aws_region}.${data.aws_partition.current.dns_suffix}"
            }
            "ForAllValues:StringEquals" = {
              "kms:EncryptionContextKeys" = [
                "aws:dynamodb:subscriberId",
                "aws:dynamodb:tableName",
              ]
            }
          }
        }
      ],
      var.deployment_mode == "active" ? [
        {
          Sid      = "WriteDomainAuthority"
          Effect   = "Allow"
          Action   = ["dynamodb:PutItem"]
          Resource = [aws_dynamodb_table.authority.arn]
          Condition = {
            StringEquals = { "aws:RequestedRegion" = var.aws_region }
            "ForAllValues:StringEquals" = {
              "dynamodb:LeadingKeys" = [local.domain_partition_key]
            }
            Null = { "dynamodb:LeadingKeys" = "false" }
          }
        },
      ] : [],
      var.deployment_mode == "active" ? [
        for region, route_table_arns in local.route_table_arns_by_region : {
          Sid      = "ReplaceRoutes${replace(title(region), "-", "")}"
          Effect   = "Allow"
          Action   = ["ec2:ReplaceRoute"]
          Resource = route_table_arns
          Condition = {
            StringEquals = { "aws:RequestedRegion" = region }
          }
        }
      ] : [],
    )
  }

  controller_policies = {
    for controller_id, statements in local.controller_policy_statements : controller_id => jsonencode({
      Version   = "2012-10-17"
      Statement = statements
    })
  }
}

resource "aws_iam_role" "controller" {
  for_each = var.controller_placements

  name                 = local.controller_iam_names[each.key]
  description          = "Dedicated Envelope controller role for replica ${each.key}"
  assume_role_policy   = local.ec2_assume_role_policy
  max_session_duration = 3600

  tags = merge(local.common_tags, {
    Name         = local.controller_iam_names[each.key]
    Role         = "envelope-controller"
    ControllerID = each.key
  })

  depends_on = [terraform_data.input_contract]
}

resource "aws_iam_role_policy" "controller" {
  for_each = var.controller_placements

  name   = "${local.controller_iam_names[each.key]}-policy"
  role   = aws_iam_role.controller[each.key].id
  policy = local.controller_policies[each.key]
}

resource "aws_iam_instance_profile" "controller" {
  for_each = var.controller_placements

  name = local.controller_iam_names[each.key]
  role = aws_iam_role.controller[each.key].name

  tags = merge(local.common_tags, {
    Name         = local.controller_iam_names[each.key]
    Role         = "envelope-controller"
    ControllerID = each.key
  })
}
