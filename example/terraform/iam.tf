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
      ]
    })
    east = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:GetObject"], Resource = [local.artifact_object_arn] },
        { Effect = "Allow", Action = ["ssm:GetParameter"], Resource = [var.east_tailscale_secret_arn] },
        { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [var.east_tailscale_kms_key_arn] },
      ]
    })
  }
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
