locals {
  ec2_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  runtime_policy = {
    west = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:GetObject"], Resource = [local.artifact_object_arn] },
        { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
      ]
    })
    east = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:GetObject"], Resource = [local.artifact_object_arn] },
        { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
      ]
    })
  }
  workload_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
    ]
  })
  transport_policy = {
    west = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [var.west_tailscale_secret_arn] },
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.west_tailscale_kms_key_arn]
          Condition = {
            StringEquals = {
              "kms:CallerAccount"                   = data.aws_caller_identity.current.account_id
              "kms:EncryptionContext:PARAMETER_ARN" = var.west_tailscale_secret_arn
              "kms:ViaService"                      = "ssm.${var.west_region}.amazonaws.com"
            }
          }
        },
        { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
      ]
    })
    east = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [var.east_tailscale_secret_arn] },
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.east_tailscale_kms_key_arn]
          Condition = {
            StringEquals = {
              "kms:CallerAccount"                   = data.aws_caller_identity.current.account_id
              "kms:EncryptionContext:PARAMETER_ARN" = var.east_tailscale_secret_arn
              "kms:ViaService"                      = "ssm.${var.east_region}.amazonaws.com"
            }
          }
        },
        { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
      ]
    })
  }
  ssm_core_actions = [
    "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage",
    "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply",
    "ssm:DescribeAssociation", "ssm:DescribeDocument", "ssm:GetDeployablePatchSnapshotForInstance",
    "ssm:GetDocument", "ssm:GetManifest", "ssm:ListAssociations", "ssm:ListInstanceAssociations",
    "ssm:PutComplianceItems", "ssm:PutConfigurePackageResult", "ssm:PutInventory",
    "ssm:UpdateAssociationStatus", "ssm:UpdateInstanceAssociationStatus", "ssm:UpdateInstanceInformation",
    "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
  ]
  flow_log_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Condition = {
        ArnLike      = { "aws:SourceArn" = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*" }
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
  flow_log_delivery_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
        Resource = [
          "arn:aws:logs:${var.west_region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.flow_west.name}:*",
          "arn:aws:logs:${var.east_region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.flow_east.name}:*",
        ]
      },
      { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = ["*"] },
    ]
  })
}

resource "aws_iam_role" "runtime_west" {
  name               = "${var.name}-west-runtime"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-west-runtime" })
}
resource "aws_iam_role" "runtime_east" {
  name               = "${var.name}-east-runtime"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-east-runtime" })
}
resource "aws_iam_role_policy" "runtime_west" {
  name   = "${var.name}-west-runtime"
  role   = aws_iam_role.runtime_west.id
  policy = local.runtime_policy.west
}
resource "aws_iam_role_policy" "runtime_east" {
  name   = "${var.name}-east-runtime"
  role   = aws_iam_role.runtime_east.id
  policy = local.runtime_policy.east
}
resource "aws_iam_instance_profile" "runtime_west" {
  name = "${var.name}-west-runtime"
  role = aws_iam_role.runtime_west.name
}
resource "aws_iam_instance_profile" "runtime_east" {
  name = "${var.name}-east-runtime"
  role = aws_iam_role.runtime_east.name
}

resource "aws_iam_role" "workload_west" {
  name               = "${var.name}-west-workload"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-west-workload", Site = "west", Role = "workload" })
}
resource "aws_iam_role" "workload_east" {
  name               = "${var.name}-east-workload"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-east-workload", Site = "east", Role = "workload" })
}
resource "aws_iam_role_policy" "workload_west" {
  name   = "${var.name}-west-workload"
  role   = aws_iam_role.workload_west.id
  policy = local.workload_policy
}
resource "aws_iam_role_policy" "workload_east" {
  name   = "${var.name}-east-workload"
  role   = aws_iam_role.workload_east.id
  policy = local.workload_policy
}
resource "aws_iam_instance_profile" "workload_west" {
  name = "${var.name}-west-workload"
  role = aws_iam_role.workload_west.name
}
resource "aws_iam_instance_profile" "workload_east" {
  name = "${var.name}-east-workload"
  role = aws_iam_role.workload_east.name
}

resource "aws_iam_role" "transport_west" {
  name               = "${var.name}-west-transport"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-west-transport", Site = "west", Role = "transport-router" })
}
resource "aws_iam_role" "transport_east" {
  name               = "${var.name}-east-transport"
  assume_role_policy = local.ec2_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-east-transport", Site = "east", Role = "transport-router" })
}
resource "aws_iam_role_policy" "transport_west" {
  name   = "${var.name}-west-transport"
  role   = aws_iam_role.transport_west.id
  policy = local.transport_policy.west
}
resource "aws_iam_role_policy" "transport_east" {
  name   = "${var.name}-east-transport"
  role   = aws_iam_role.transport_east.id
  policy = local.transport_policy.east
}
resource "aws_iam_instance_profile" "transport_west" {
  name = "${var.name}-west-transport"
  role = aws_iam_role.transport_west.name
}
resource "aws_iam_instance_profile" "transport_east" {
  name = "${var.name}-east-transport"
  role = aws_iam_role.transport_east.name
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name}-flow-logs"
  assume_role_policy = local.flow_log_assume_policy
  tags               = merge(local.common_tags, { Name = "${var.name}-flow-logs", Role = "flow-logs" })
}
resource "aws_iam_role_policy" "flow_logs" {
  name   = "${var.name}-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = local.flow_log_delivery_policy
}
