locals {
  topology_identity = jsondecode(var.topology_identity_json)
  topology_json     = base64decode(local.topology_identity.canonical_json_base64)
  topology_sha256   = local.topology_identity.canonical_sha256
  topology          = jsondecode(local.topology_json)

  # Protected acceptance must be fully removable. Normal production retains a
  # dedicated CMK, deletion protection, and final observer-state snapshots.
  controller_kms_key_arn = var.protected_acceptance_mode ? null : one(aws_kms_key.controller[*].arn)

  artifact_manifest     = jsondecode(var.artifact_manifest_json)
  reviewed_go_toolchain = trimspace(file("${path.module}/../../../scripts/reviewed-go-toolchain.txt"))
  ec2_architecture      = { amd64 = "x86_64", arm64 = "arm64" }[var.controller_architecture]
  controller_manifest_entries = [
    for entry in local.artifact_manifest.artifacts : entry
    if try(entry.component == "envelope-controller" && entry.architecture == var.controller_architecture, false)
  ]
  topology_identity_manifest_entries = [
    for entry in local.artifact_manifest.artifacts : entry
    if try(entry.component == "envelope-controller-topology" && entry.architecture == var.controller_architecture, false)
  ]
  controller_manifest_entry        = try(one(local.controller_manifest_entries), null)
  topology_identity_manifest_entry = try(one(local.topology_identity_manifest_entries), null)

  topology_sites_by_id   = { for site in local.topology.sites : site.id => site }
  topology_routers_by_id = { for router in local.topology.routers : router.id => router }
  topology_domains_by_id = { for domain in local.topology.domains : domain.id => domain }
  topology_routers_by_site = {
    for site_id in keys(local.topology_sites_by_id) : site_id => {
      for router in local.topology.routers : router.id => router if router.site_id == site_id
    }
  }
  topology_all_local_prefixes = toset(flatten([
    for site in local.topology.sites : site.local_prefixes
  ]))
  topology_local_prefix_records = flatten([
    for site in local.topology.sites : [
      for cidr in site.local_prefixes : { site_id = site.id, cidr = cidr }
    ]
  ])
  topology_remote_prefixes_by_site = {
    for site_id, site in local.topology_sites_by_id :
    site_id => setsubtract(local.topology_all_local_prefixes, toset(site.local_prefixes))
  }
  topology_site_regions = toset([for site in local.topology.sites : site.region])
  topology_prefix_bounds = {
    for cidr in local.topology_all_local_prefixes : cidr => {
      first = sum([
        for index, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * pow(256, 3 - index)
      ])
      last = sum([
        for index, octet in split(".", cidrhost(cidr, -1)) : tonumber(octet) * pow(256, 3 - index)
      ])
    }
  }

  topology_document_sha256 = sha256(local.topology_json)

  common_tags = {
    Component      = "envelope-controller"
    Deployment     = var.name
    DeploymentMode = var.deployment_mode
    TopologyHash   = local.topology_sha256
  }

  route_table_arns_by_region = {
    for region in sort(distinct([for contract in values(var.managed_route_tables) : contract.region])) :
    region => sort([for contract in values(var.managed_route_tables) : contract.route_table_arn if contract.region == region])
  }

  controller_iam_names = {
    for id in var.controller_ids : id => "${substr(var.name, 0, 24)}-${substr(id, 0, 20)}-${substr(sha256(id), 0, 12)}"
  }

  systemd_unit_path       = "${path.module}/../../systemd/envelope-controller.service"
  controller_systemd_unit = file(local.systemd_unit_path)
}
