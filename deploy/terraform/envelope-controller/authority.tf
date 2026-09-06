resource "aws_kms_key" "controller" {
  count = var.protected_acceptance_mode ? 0 : 1

  description             = "${var.name} controller authority and observer-state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  multi_region            = false

  tags = merge(local.common_tags, {
    Name = "${var.name}-controller"
    Role = "controller-authority"
  })

  depends_on = [terraform_data.input_contract]
}

resource "aws_kms_alias" "controller" {
  count = var.protected_acceptance_mode ? 0 : 1

  name          = "alias/${var.name}-controller"
  target_key_id = one(aws_kms_key.controller[*].key_id)
}

resource "aws_dynamodb_table" "authority" {
  name         = var.authority_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = !var.protected_acceptance_mode

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = !var.protected_acceptance_mode
    kms_key_arn = local.controller_kms_key_arn
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name = var.authority_table_name
    Role = "controller-authority"
  })
}

resource "aws_ssm_parameter" "topology" {
  name        = var.topology_parameter_name
  description = "${var.name} immutable nonsecret controller topology (${local.topology_sha256})"
  type        = "String"
  tier        = "Advanced"
  data_type   = "text"
  value       = local.topology_json

  tags = merge(local.common_tags, {
    Name       = var.topology_parameter_name
    Role       = "controller-topology"
    SecretData = "false"
  })

  depends_on = [terraform_data.input_contract]
}
