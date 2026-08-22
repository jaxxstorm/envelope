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
        { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [var.west_tailscale_secret_arn] },
        { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [var.west_tailscale_kms_key_arn] },
        { Effect = "Allow", Action = local.ssm_core_actions, Resource = ["*"] },
      ]
    })
    east = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:GetObject"], Resource = [local.artifact_object_arn] },
        { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [var.east_tailscale_secret_arn] },
        { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [var.east_tailscale_kms_key_arn] },
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
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.flow_west.arn}:*", "${aws_cloudwatch_log_group.flow_east.arn}:*"]
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
