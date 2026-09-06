variable "router_attestations" {
  description = "Independently enrolled public-key authority for every exact topology router. Never populate keys from untrusted signed identity claims. The TLS certificate key must match this enrolled Ed25519 key."
  type = map(object({
    ed25519_public_key   = string
    configuration_sha256 = string
    url                  = string
  }))
  validation {
    condition = (
      length(var.router_attestations) > 0 &&
      alltrue([for router in var.router_attestations : can(regex("^[0-9a-f]{64}$", router.ed25519_public_key)) && can(regex("^[0-9a-f]{64}$", router.configuration_sha256)) && can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?/attestation$", router.url))]) &&
      length(distinct([for router in var.router_attestations : router.ed25519_public_key])) == length(var.router_attestations) &&
      length(distinct([for router in var.router_attestations : router.url])) == length(var.router_attestations)
    )
    error_message = "Router enrollment requires unique lowercase Ed25519 public keys and unique HTTPS attestation endpoints, without credentials, queries, or fragments."
  }
}

locals {
  router_trust_json = jsonencode({
    schema_version = 1
    deployment_id  = local.topology.deployment_id
    topology_hash  = local.topology_sha256
    routers = [for id in sort(keys(var.router_attestations)) : {
      router_id            = id
      ed25519_public_key   = var.router_attestations[id].ed25519_public_key
      configuration_sha256 = var.router_attestations[id].configuration_sha256
      url                  = var.router_attestations[id].url
    }]
  })
  router_trust_sha256 = sha256(local.router_trust_json)
}

resource "aws_ssm_parameter" "router_trust" {
  name  = "/${var.name}/router-trust/${local.router_trust_sha256}"
  type  = "String"
  tier  = "Advanced"
  value = local.router_trust_json
  tags  = local.common_tags
  lifecycle {
    precondition {
      condition     = toset(keys(var.router_attestations)) == toset(keys(local.topology_routers_by_id)) && length(local.router_trust_json) <= 8192
      error_message = "Enrollment must bind every exact topology router and fit one bounded immutable SSM document."
    }
  }
}

output "router_attestation_trust" {
  description = "Content-addressed public-key authority. Private signing keys never enter this root or its state."
  value = {
    parameter_name = aws_ssm_parameter.router_trust.name
    sha256         = local.router_trust_sha256
    topology_hash  = local.topology_sha256
  }
}
