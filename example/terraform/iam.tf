locals {
  ec2_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  regional_ssm_core_actions = [
    "ec2messages:AcknowledgeMessage",
    "ec2messages:DeleteMessage",
    "ec2messages:FailMessage",
    "ec2messages:GetEndpoint",
    "ec2messages:GetMessages",
    "ec2messages:SendReply",
    "ssm:DescribeAssociation",
    "ssm:DescribeDocument",
    "ssm:GetDeployablePatchSnapshotForInstance",
    "ssm:GetDocument",
    "ssm:GetManifest",
    "ssm:ListAssociations",
    "ssm:ListInstanceAssociations",
    "ssm:PutComplianceItems",
    "ssm:PutConfigurePackageResult",
    "ssm:PutInventory",
    "ssm:UpdateAssociationStatus",
    "ssm:UpdateInstanceAssociationStatus",
    "ssm:UpdateInstanceInformation",
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
  ]

  appliance_runtime_policy_west = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactArtifactObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = [local.artifact_object_arn]
      },
      {
        Sid      = "ReadExactWestTailscaleParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [var.west_tailscale_secret_arn]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.west_region }
        }
      },
      {
        Sid      = "DecryptExactWestTailscaleParameter"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.west_tailscale_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService"                      = "ssm.${var.west_region}.amazonaws.com"
            "kms:EncryptionContext:PARAMETER_ARN" = var.west_tailscale_secret_arn
          }
        }
      },
      {
        Sid      = "WestSystemsManagerCore"
        Effect   = "Allow"
        Action   = local.regional_ssm_core_actions
        Resource = ["*"]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.west_region }
        }
      },
    ]
  })

  appliance_runtime_policy_east = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactArtifactObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = [local.artifact_object_arn]
      },
      {
        Sid      = "ReadExactEastTailscaleParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [var.east_tailscale_secret_arn]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.east_region }
        }
      },
      {
        Sid      = "DecryptExactEastTailscaleParameter"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.east_tailscale_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService"                      = "ssm.${var.east_region}.amazonaws.com"
            "kms:EncryptionContext:PARAMETER_ARN" = var.east_tailscale_secret_arn
          }
        }
      },
      {
        Sid      = "EastSystemsManagerCore"
        Effect   = "Allow"
        Action   = local.regional_ssm_core_actions
        Resource = ["*"]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.east_region }
        }
      },
    ]
  })

  workload_runtime_policy_west = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WestSystemsManagerCore"
      Effect   = "Allow"
      Action   = local.regional_ssm_core_actions
      Resource = ["*"]
      Condition = {
        StringEquals = { "aws:RequestedRegion" = var.west_region }
      }
    }]
  })

  workload_runtime_policy_east = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "EastSystemsManagerCore"
      Effect   = "Allow"
      Action   = local.regional_ssm_core_actions
      Resource = ["*"]
      Condition = {
        StringEquals = { "aws:RequestedRegion" = var.east_region }
      }
    }]
  })
}

resource "aws_iam_role" "appliance_west" {
  name               = "${var.name}-west-appliance"
  assume_role_policy = local.ec2_assume_policy
  tags               = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }
}

resource "aws_iam_role" "appliance_east" {
  name               = "${var.name}-east-appliance"
  assume_role_policy = local.ec2_assume_policy
  tags               = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }
}

resource "aws_iam_instance_profile" "appliance_west" {
  name = "${var.name}-west-appliance"
  role = aws_iam_role.appliance_west.name
  tags = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }
}

resource "aws_iam_instance_profile" "appliance_east" {
  name = "${var.name}-east-appliance"
  role = aws_iam_role.appliance_east.name
  tags = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }
}

resource "aws_iam_role_policy" "appliance_runtime_west" {
  name   = "${var.name}-west-runtime"
  role   = aws_iam_role.appliance_west.id
  policy = local.appliance_runtime_policy_west
}

resource "aws_iam_role_policy" "appliance_runtime_east" {
  name   = "${var.name}-east-runtime"
  role   = aws_iam_role.appliance_east.id
  policy = local.appliance_runtime_policy_east
}

resource "aws_iam_role" "workload_west" {
  name               = "${var.name}-west-workload"
  assume_role_policy = local.ec2_assume_policy
  tags               = { Name = "${var.name}-west-workload", Site = "west", Role = "workload" }
}

resource "aws_iam_role" "workload_east" {
  name               = "${var.name}-east-workload"
  assume_role_policy = local.ec2_assume_policy
  tags               = { Name = "${var.name}-east-workload", Site = "east", Role = "workload" }
}

resource "aws_iam_instance_profile" "workload_west" {
  name = "${var.name}-west-workload"
  role = aws_iam_role.workload_west.name
  tags = { Name = "${var.name}-west-workload", Site = "west", Role = "workload" }
}

resource "aws_iam_instance_profile" "workload_east" {
  name = "${var.name}-east-workload"
  role = aws_iam_role.workload_east.name
  tags = { Name = "${var.name}-east-workload", Site = "east", Role = "workload" }
}

resource "aws_iam_role_policy" "workload_runtime_west" {
  name   = "${var.name}-west-runtime"
  role   = aws_iam_role.workload_west.id
  policy = local.workload_runtime_policy_west
}

resource "aws_iam_role_policy" "workload_runtime_east" {
  name   = "${var.name}-east-runtime"
  role   = aws_iam_role.workload_east.id
  policy = local.workload_runtime_policy_east
}

output "appliance_runtime_policy_json" {
  value = {
    west = local.appliance_runtime_policy_west
    east = local.appliance_runtime_policy_east
  }
}
