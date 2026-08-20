data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "artifact" {
  bucket        = local.artifact_bucket_name
  force_destroy = true
  tags          = { Name = "${var.name}-artifact", Role = "artifact" }
}

resource "aws_s3_bucket_public_access_block" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifact" {
  bucket = aws_s3_bucket.artifact.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifact" {
  bucket = aws_s3_bucket.artifact.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifact" {
  bucket = aws_s3_bucket.artifact.id
  rule {
    blocked_encryption_types = ["SSE-C"]
    bucket_key_enabled       = false
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "artifact_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifact.arn,
      "${aws_s3_bucket.artifact.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifact" {
  bucket = aws_s3_bucket.artifact.id
  policy = data.aws_iam_policy_document.artifact_bucket.json
}

locals {
  artifact_bucket_name = "${var.name}-${data.aws_caller_identity.current.account_id}-${var.west_region}-artifact"
  artifact_object_key  = "artifacts/${var.artifact_revision}/envelope-linux-${var.architecture}"
  artifact_object_arn  = "arn:aws:s3:::${local.artifact_bucket_name}/${local.artifact_object_key}"
}

resource "aws_s3_object" "envelope" {
  bucket                 = aws_s3_bucket.artifact.id
  key                    = local.artifact_object_key
  source                 = var.artifact_path
  source_hash            = var.artifact_sha256
  checksum_algorithm     = "SHA256"
  server_side_encryption = "AES256"
  tags                   = { Name = "${var.name}-envelope", Role = "artifact", Architecture = var.architecture, Revision = var.artifact_revision }

  depends_on = [
    aws_s3_bucket_public_access_block.artifact,
    aws_s3_bucket_ownership_controls.artifact,
    aws_s3_bucket_versioning.artifact,
    aws_s3_bucket_server_side_encryption_configuration.artifact,
  ]

  lifecycle {
    precondition {
      condition     = filesha256(var.artifact_path) == var.artifact_sha256
      error_message = "artifact_path does not match the reviewed artifact_sha256."
    }
  }
}

output "artifact_identity" {
  value = {
    bucket       = local.artifact_bucket_name
    key          = local.artifact_object_key
    sha256       = var.artifact_sha256
    architecture = var.architecture
    ec2_arch     = local.ec2_architecture
    revision     = var.artifact_revision
    version      = var.artifact_version
  }
}
