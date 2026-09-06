variable "router_attestor_bootstrap" {
  description = "Two-phase production attestor installation. Null is data-plane-only/legacy deployment and cannot satisfy production controller eligibility. Contains public authority and secret references only."
  type = object({
    authority_region       = string
    artifact_manifest_json = string
    artifact               = object({ region = string, bucket = string, key = string, version_id = string, sha256 = string })
    routers = map(object({
      ed25519_public_key          = string
      configuration_parameter_arn = string
      seed_parameter_arn          = string
      seed_version                = number
    }))
  })
  default = null
  validation {
    condition = var.router_attestor_bootstrap == null ? true : (
      can(regex("^[a-z0-9-]+-[0-9]+$", var.router_attestor_bootstrap.authority_region)) &&
      can(regex("^[a-z0-9-]+-[0-9]+$", var.router_attestor_bootstrap.artifact.region)) &&
      can(regex("^[a-z0-9][a-z0-9.-]{2,62}$", var.router_attestor_bootstrap.artifact.bucket)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9/_.-]+$", var.router_attestor_bootstrap.artifact.key)) &&
      !strcontains(var.router_attestor_bootstrap.artifact.key, "..") &&
      var.router_attestor_bootstrap.artifact.version_id != "" && var.router_attestor_bootstrap.artifact.version_id != "null" &&
      can(regex("^[0-9a-f]{64}$", var.router_attestor_bootstrap.artifact.sha256)) &&
      length(var.router_attestor_bootstrap.routers) > 0 &&
      length(distinct([for router in var.router_attestor_bootstrap.routers : router.ed25519_public_key])) == length(var.router_attestor_bootstrap.routers) &&
      length(distinct([for router in var.router_attestor_bootstrap.routers : router.seed_parameter_arn])) == length(var.router_attestor_bootstrap.routers) &&
      length(distinct([for router in var.router_attestor_bootstrap.routers : router.configuration_parameter_arn])) == length(var.router_attestor_bootstrap.routers) &&
      alltrue([for router in var.router_attestor_bootstrap.routers : (
        can(regex("^[0-9a-f]{64}$", router.ed25519_public_key)) &&
        can(regex("^arn:aws:ssm:${var.router_attestor_bootstrap.authority_region}:[0-9]{12}:parameter/envelope/[A-Za-z0-9/_-]+$", router.configuration_parameter_arn)) &&
        can(regex("^arn:aws:ssm:${var.router_attestor_bootstrap.authority_region}:[0-9]{12}:parameter/envelope/[A-Za-z0-9/_-]+$", router.seed_parameter_arn)) &&
        router.configuration_parameter_arn != router.seed_parameter_arn && router.seed_version >= 1 && router.seed_version <= 100 && floor(router.seed_version) == router.seed_version
      )])
    )
    error_message = "Attestor bootstrap requires unique per-router public keys and exact versioned secret/config references, plus a hash/version-pinned binary. No plaintext seeds, wildcard keys, or latest versions are accepted."
  }
}

locals {
  attestor_bootstrap_routers = var.router_attestor_bootstrap == null ? {} : var.router_attestor_bootstrap.routers
  attestor_manifest          = var.router_attestor_bootstrap == null ? null : jsondecode(var.router_attestor_bootstrap.artifact_manifest_json)
  attestor_manifest_entries  = try([for entry in local.attestor_manifest.artifacts : entry if entry.component == "envelope-router-attestor" && entry.architecture == var.architecture], [])
  attestor_bootstrap_scripts = {
    for id, router in local.attestor_bootstrap_routers : id => templatefile("${path.module}/cloud-init/router-attestor.sh.tftpl", {
      artifact_region      = var.router_attestor_bootstrap.artifact.region
      artifact_bucket_b64  = base64encode(var.router_attestor_bootstrap.artifact.bucket)
      artifact_key_b64     = base64encode(var.router_attestor_bootstrap.artifact.key)
      artifact_version_b64 = base64encode(var.router_attestor_bootstrap.artifact.version_id)
      artifact_sha256      = var.router_attestor_bootstrap.artifact.sha256
      bootstrap_b64 = base64encode(jsonencode(merge(router, {
        router_id        = id
        authority_region = var.router_attestor_bootstrap.authority_region
      })))
      unit_b64 = base64encode(file("${path.module}/../../deploy/systemd/envelope-router-attestor.service"))
    })
  }
}

resource "terraform_data" "attestor_bootstrap_contract" {
  count = var.router_attestor_bootstrap == null ? 0 : 1
  lifecycle {
    precondition {
      condition = (
        var.symmetric_topology.version == 3 &&
        toset(keys(local.attestor_bootstrap_routers)) == toset(concat([for key in local.sites.west.transport_router_az_keys : "west-${key}"], [for key in local.sites.east.transport_router_az_keys : "east-${key}"])) &&
        try(local.attestor_manifest.schema == 1 && local.attestor_manifest.component == "envelope-controller" && local.attestor_manifest.source_dirty == false, false) &&
        length(local.attestor_manifest_entries) == 1 &&
        try(local.attestor_manifest_entries[0].sha256 == var.router_attestor_bootstrap.artifact.sha256 && local.attestor_manifest_entries[0].vcs_modified == false && local.attestor_manifest_entries[0].version == local.attestor_manifest.version && local.attestor_manifest_entries[0].vcs_revision == local.attestor_manifest.revision && local.attestor_manifest_entries[0].goos == "linux" && local.attestor_manifest_entries[0].goarch == var.architecture && local.attestor_manifest_entries[0].file == "envelope-router-attestor-linux-${var.architecture}" && local.attestor_manifest_entries[0].go_version == trimspace(file("${path.module}/../../scripts/reviewed-go-toolchain.txt")), false)
      )
      error_message = "Every production router must have independent enrollment authority and the selected binary must match a clean reviewed Linux release manifest."
    }
  }
}

resource "aws_iam_role_policy" "attestor_binary" {
  for_each = var.router_attestor_bootstrap == null ? toset([]) : toset(["west", "east"])
  name     = "${var.name}-${each.key}-attestor-binary"
  role     = each.key == "west" ? aws_iam_role.transport_west.name : aws_iam_role.transport_east.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["s3:GetObjectVersion"]
      Resource  = "arn:aws:s3:::${var.router_attestor_bootstrap.artifact.bucket}/${var.router_attestor_bootstrap.artifact.key}"
      Condition = { StringEquals = { "s3:VersionId" = var.router_attestor_bootstrap.artifact.version_id, "aws:RequestedRegion" = var.router_attestor_bootstrap.artifact.region } }
    }]
  })
  depends_on = [terraform_data.attestor_bootstrap_contract]
}
