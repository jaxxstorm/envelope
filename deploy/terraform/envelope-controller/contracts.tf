data "aws_vpc" "controller" {
  id = var.vpc_id
}

data "aws_ami" "controller" {
  most_recent = false
  owners      = sort(tolist(var.controller_ami_trusted_owner_ids))

  filter {
    name   = "image-id"
    values = [var.controller_ami_id]
  }
  filter {
    name   = "architecture"
    values = [local.ec2_architecture]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ec2_instance_type" "controller" {
  instance_type = var.controller_instance_type
}

data "aws_subnet" "controller" {
  for_each = var.controller_placements

  id = each.value.subnet_id
}

data "aws_route_table" "management_egress" {
  for_each = var.management_egress

  route_table_id = each.value.route_table_id
}

data "aws_nat_gateway" "management_egress" {
  for_each = var.management_egress

  id = each.value.nat_gateway_id
}

data "aws_subnet" "management_nat" {
  for_each = var.management_egress

  id = each.value.nat_subnet_id
}

data "aws_route_table" "management_nat" {
  for_each = var.management_egress

  route_table_id = each.value.nat_route_table_id
}

data "aws_internet_gateway" "management_egress" {
  for_each = toset([for contract in values(var.management_egress) : contract.internet_gateway_id])

  internet_gateway_id = each.value
}

data "aws_iam_role" "readiness_publisher" {
  name = var.readiness_publisher.role_name
}

data "aws_route_table" "managed" {
  for_each = var.managed_route_tables

  region         = each.value.region
  route_table_id = each.value.route_table_id
}

data "aws_subnet" "managed_gwlbe" {
  for_each = var.managed_route_tables

  region = each.value.region
  id     = each.value.gwlbe_subnet_id
}

locals {
  management_default_routes = {
    for controller_id, contract in var.management_egress : controller_id => [
      for route in data.aws_route_table.management_egress[controller_id].routes : route
      if try(route.cidr_block, "") == "0.0.0.0/0"
    ]
  }
  management_nat_default_routes = {
    for controller_id, contract in var.management_egress : controller_id => [
      for route in data.aws_route_table.management_nat[controller_id].routes : route
      if try(route.cidr_block, "") == "0.0.0.0/0"
    ]
  }
  live_route_matches = {
    for domain_id, contract in var.managed_route_tables : domain_id => {
      for cidr in sort(tolist(contract.destination_cidrs)) : cidr => [
        for route in data.aws_route_table.managed[domain_id].routes : route
        if try(route.cidr_block, "") == cidr
      ]
    }
  }
  live_route_shadowing = {
    for domain_id, contract in var.managed_route_tables : domain_id => {
      for cidr in sort(tolist(contract.destination_cidrs)) : cidr => [
        for route in data.aws_route_table.managed[domain_id].routes : try(route.cidr_block, "")
        if try(
          route.cidr_block != cidr &&
          tonumber(split("/", route.cidr_block)[1]) > tonumber(split("/", cidr)[1]) &&
          sum([
            for index, octet in split(".", cidrhost(route.cidr_block, 0)) : tonumber(octet) * pow(256, 3 - index)
          ]) >= local.topology_prefix_bounds[cidr].first &&
          sum([
            for index, octet in split(".", cidrhost(route.cidr_block, 0)) : tonumber(octet) * pow(256, 3 - index)
          ]) <= local.topology_prefix_bounds[cidr].last,
          false,
        )
      ]
    }
  }
  current_route_targets = {
    for domain_id, prefixes in local.live_route_matches : domain_id => {
      for cidr, matches in prefixes : cidr => try(one(matches).network_interface_id, null)
    }
  }
}

resource "terraform_data" "input_contract" {
  input = {
    architecture            = var.controller_architecture
    artifact_manifest       = var.artifact_manifest_sha256
    controller_artifact     = var.artifact.object_arn
    controller_ids          = sort(tolist(var.controller_ids))
    deployment_mode         = var.deployment_mode
    readiness_publisher_arn = var.readiness_publisher.role_arn
    topology_artifact       = var.topology_identity_artifact.object_arn
    topology_sha256         = local.topology_sha256
    route_tables            = sort([for contract in values(var.managed_route_tables) : contract.route_table_arn])
    gwlbe_subnet_associations = {
      for domain_id, contract in var.managed_route_tables : domain_id => {
        subnet_id      = contract.gwlbe_subnet_id
        association_id = contract.route_table_association_id
      }
    }
  }

  lifecycle {
    precondition {
      condition     = toset(keys(var.controller_placements)) == var.controller_ids
      error_message = "controller_placements keys must exactly equal the three controller_ids."
    }
    precondition {
      condition = (
        data.aws_vpc.controller.id == var.vpc_id &&
        data.aws_vpc.controller.enable_dns_support == true &&
        data.aws_ami.controller.id == var.controller_ami_id &&
        data.aws_ami.controller.image_id == var.controller_ami_id &&
        contains(var.controller_ami_trusted_owner_ids, data.aws_ami.controller.owner_id) &&
        data.aws_ami.controller.architecture == local.ec2_architecture &&
        data.aws_ami.controller.root_device_type == "ebs" &&
        data.aws_ami.controller.virtualization_type == "hvm" &&
        data.aws_ami.controller.state == "available" &&
        data.aws_ec2_instance_type.controller.instance_type == var.controller_instance_type &&
        contains(data.aws_ec2_instance_type.controller.supported_architectures, local.ec2_architecture)
      )
      error_message = "the controller AMI must resolve from a trusted owner as an available EBS-backed HVM image whose architecture is supported by the instance type."
    }
    precondition {
      condition = !var.protected_acceptance_mode || (
        try(var.tags.EnvelopeRun, "") == var.name &&
        can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", try(var.tags.ExpiresAt, "")))
      )
      error_message = "protected_acceptance_mode requires exact EnvelopeRun and canonical ExpiresAt lifecycle tags."
    }
    precondition {
      condition = alltrue([
        for id, placement in var.controller_placements :
        data.aws_subnet.controller[id].id == placement.subnet_id &&
        data.aws_subnet.controller[id].vpc_id == var.vpc_id &&
        data.aws_subnet.controller[id].availability_zone == placement.availability_zone &&
        data.aws_subnet.controller[id].map_public_ip_on_launch == false &&
        startswith(placement.availability_zone, var.aws_region)
      ])
      error_message = "each controller slot must resolve to its exact supplied private subnet, VPC, Region, and unique AZ."
    }
    precondition {
      condition = (
        toset(keys(var.management_egress)) == var.controller_ids &&
        alltrue([
          for id, contract in var.management_egress :
          data.aws_route_table.management_egress[id].id == contract.route_table_id &&
          data.aws_route_table.management_egress[id].vpc_id == var.vpc_id &&
          length([
            for association in data.aws_route_table.management_egress[id].associations : association
            if try(association.subnet_id, "") == var.controller_placements[id].subnet_id
          ]) == 1 &&
          length(local.management_default_routes[id]) == 1 &&
          try(one(local.management_default_routes[id]).nat_gateway_id, "") == contract.nat_gateway_id &&
          data.aws_nat_gateway.management_egress[id].id == contract.nat_gateway_id &&
          data.aws_nat_gateway.management_egress[id].vpc_id == var.vpc_id &&
          data.aws_nat_gateway.management_egress[id].subnet_id == contract.nat_subnet_id &&
          data.aws_nat_gateway.management_egress[id].connectivity_type == "public" &&
          data.aws_nat_gateway.management_egress[id].state == "available" &&
          data.aws_subnet.management_nat[id].id == contract.nat_subnet_id &&
          data.aws_subnet.management_nat[id].vpc_id == var.vpc_id &&
          data.aws_subnet.management_nat[id].availability_zone == var.controller_placements[id].availability_zone &&
          data.aws_route_table.management_nat[id].id == contract.nat_route_table_id &&
          data.aws_route_table.management_nat[id].vpc_id == var.vpc_id &&
          length([
            for association in data.aws_route_table.management_nat[id].associations : association
            if try(association.subnet_id, "") == contract.nat_subnet_id
          ]) == 1 &&
          length(local.management_nat_default_routes[id]) == 1 &&
          try(one(local.management_nat_default_routes[id]).gateway_id, "") == contract.internet_gateway_id &&
          data.aws_internet_gateway.management_egress[contract.internet_gateway_id].id == contract.internet_gateway_id &&
          length([
            for attachment in data.aws_internet_gateway.management_egress[contract.internet_gateway_id].attachments : attachment
            if attachment.vpc_id == var.vpc_id && attachment.state == "available"
          ]) == 1
        ])
      )
      error_message = "each controller private subnet must have its own route table, available same-AZ public NAT, and a NAT-subnet default route through an attached Internet gateway."
    }
    precondition {
      condition = (
        toset(keys(local.topology)) == toset([
          "schema_version", "deployment_id", "controller_ids", "policy", "dynamodb", "tailnet", "sites", "routers", "domains",
        ]) &&
        local.topology.schema_version == 1 &&
        local.topology.deployment_id == var.name &&
        toset(local.topology.controller_ids) == var.controller_ids &&
        local.topology.policy.replica_count == 3 &&
        local.topology.policy.observation_quorum == 2 &&
        local.topology.dynamodb.table == var.authority_table_name &&
        local.topology.dynamodb.region == var.aws_region
      )
      error_message = "the topology identity must contain the exact version-1 root shape and match this three-replica deployment and DynamoDB authority."
    }
    precondition {
      condition = (
        toset(keys(local.topology.policy)) == toset([
          "replica_count", "observation_quorum", "observation_interval", "observation_freshness", "failover_stability", "failback_stability", "cooldown", "lease_duration", "lease_renew_interval", "lease_danger_window", "api_timeout", "route_convergence_timeout",
        ]) &&
        toset(keys(local.topology.dynamodb)) == toset(["table", "region"]) &&
        length(setsubtract(toset(keys(local.topology.tailnet)), toset(["name", "control_url", "tsnet_auth_key_env", "admin_api_key_env", "state_base_dir"]))) == 0 &&
        length(setsubtract(toset(["name", "tsnet_auth_key_env", "admin_api_key_env", "state_base_dir"]), toset(keys(local.topology.tailnet)))) == 0 &&
        alltrue([for site in local.topology.sites : toset(keys(site)) == toset(["id", "vpc_id", "region", "local_prefixes"])]) &&
        alltrue([for router in local.topology.routers : toset(keys(router)) == toset(["id", "site_id", "stable_node_id", "instance_id", "eni_id", "vpc_id", "subnet_id", "availability_zone", "region"])]) &&
        alltrue([for domain in local.topology.domains : toset(keys(domain)) == toset(["id", "site_id", "source_prefix", "route_table_id", "gwlbe_subnet_id", "route_table_association_id", "remote_prefixes", "preferred_owner"])])
      )
      error_message = "the topology identity contains an unknown or missing policy, authority, Tailnet, site, router, or domain field."
    }
    precondition {
      condition = (
        local.topology_sha256 == local.topology_document_sha256 &&
        tolist(local.topology.controller_ids) == sort(local.topology.controller_ids) &&
        tolist([for site in local.topology.sites : site.id]) == sort([for site in local.topology.sites : site.id]) &&
        tolist([for router in local.topology.routers : router.id]) == sort([for router in local.topology.routers : router.id]) &&
        tolist([for domain in local.topology.domains : domain.id]) == sort([for domain in local.topology.domains : domain.id]) &&
        alltrue([for site in local.topology.sites : tolist(site.local_prefixes) == sort(site.local_prefixes)]) &&
        alltrue([for domain in local.topology.domains : tolist(domain.remote_prefixes) == sort(domain.remote_prefixes)])
      )
      error_message = "the topology identity must contain sorted Go-canonical collections and bytes whose SHA-256 is its canonical identity."
    }
    precondition {
      condition = (
        can(regex("^[A-Z_][A-Z0-9_]*$", local.topology.tailnet.tsnet_auth_key_env)) &&
        can(regex("^[A-Z_][A-Z0-9_]*$", local.topology.tailnet.admin_api_key_env)) &&
        local.topology.tailnet.tsnet_auth_key_env != local.topology.tailnet.admin_api_key_env &&
        startswith(local.topology.tailnet.state_base_dir, "/var/lib/envelope-controller/") &&
        length(local.topology.tailnet.state_base_dir) <= 512 &&
        can(regex("^/var/lib/envelope-controller/[A-Za-z0-9._/-]+$", local.topology.tailnet.state_base_dir)) &&
        !strcontains(local.topology.tailnet.state_base_dir, "//") &&
        !strcontains(local.topology.tailnet.state_base_dir, "..")
      )
      error_message = "nonsecret Tailnet environment/state indirection does not match the deployment contract."
    }
    precondition {
      condition = (
        length(local.topology_sites_by_id) == length(local.topology.sites) &&
        length(local.topology_routers_by_id) == length(local.topology.routers) &&
        length(local.topology_domains_by_id) == length(local.topology.domains) &&
        toset(keys(var.transport_topology)) == toset(keys(local.topology_sites_by_id)) &&
        toset(keys(var.managed_route_tables)) == toset(keys(local.topology_domains_by_id)) &&
        toset([for domain in local.topology.domains : domain.source_prefix]) == local.topology_all_local_prefixes &&
        length(local.topology.domains) == length(local.topology_all_local_prefixes) &&
        length(distinct([for domain in local.topology.domains : domain.gwlbe_subnet_id])) == length(local.topology.domains) &&
        length(distinct([for domain in local.topology.domains : domain.route_table_association_id])) == length(local.topology.domains)
      )
      error_message = "sites, routers, domains, GWLBE subnet associations, transport descriptors, and managed route contracts must have unique and complete identities."
    }
    precondition {
      condition = alltrue(flatten([
        for left_index, left in local.topology_local_prefix_records : [
          for right_index, right in local.topology_local_prefix_records : left_index == right_index || (
            local.topology_prefix_bounds[left.cidr].last < local.topology_prefix_bounds[right.cidr].first ||
            local.topology_prefix_bounds[right.cidr].last < local.topology_prefix_bounds[left.cidr].first
          )
        ]
      ]))
      error_message = "site local prefixes must be canonical, disjoint IPv4 authority."
    }
    precondition {
      condition = (
        alltrue([
          for site in local.topology.sites :
          can(regex("^vpc-[0-9a-f]{8,17}$", site.vpc_id)) &&
          can(regex("^[a-z][a-z0-9-]+-[0-9]+$", site.region)) &&
          length(site.local_prefixes) == length(toset(site.local_prefixes)) &&
          alltrue([
            for cidr in site.local_prefixes : try(
              !strcontains(cidr, ":") &&
              cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}",
              false,
            )
          ])
        ]) &&
        length(distinct([for site in local.topology.sites : site.vpc_id])) == length(local.topology.sites) &&
        length(distinct([for router in local.topology.routers : router.stable_node_id])) == length(local.topology.routers) &&
        length(distinct([for router in local.topology.routers : router.instance_id])) == length(local.topology.routers) &&
        length(distinct([for router in local.topology.routers : router.eni_id])) == length(local.topology.routers) &&
        alltrue([
          for router in local.topology.routers :
          contains(keys(local.topology_sites_by_id), router.site_id) &&
          can(regex("^subnet-[0-9a-f]{8,17}$", router.subnet_id)) &&
          router.vpc_id == local.topology_sites_by_id[router.site_id].vpc_id &&
          router.region == local.topology_sites_by_id[router.site_id].region &&
          can(regex("^${router.region}[a-z]$", router.availability_zone))
        ]) &&
        alltrue([
          for domain in local.topology.domains :
          contains(keys(local.topology_routers_by_site[domain.site_id]), domain.preferred_owner)
        ])
      )
      error_message = "topology sites, prefixes, router cloud identities, and preferred owners must be exact, unique, and site-local."
    }
    precondition {
      condition = alltrue([
        for site_id, descriptor in var.transport_topology :
        descriptor.local_prefixes == toset(local.topology_sites_by_id[site_id].local_prefixes) &&
        toset(keys(descriptor.routers)) == toset(keys(local.topology_routers_by_site[site_id])) &&
        length(distinct([for router in values(local.topology_routers_by_site[site_id]) : router.availability_zone])) >= 2 &&
        alltrue([
          for router_id, expectation in descriptor.routers :
          expectation.stable_node_id == local.topology_routers_by_id[router_id].stable_node_id &&
          expectation.instance_id == local.topology_routers_by_id[router_id].instance_id &&
          expectation.eni_id == local.topology_routers_by_id[router_id].eni_id &&
          expectation.expected_advertised_prefixes == descriptor.local_prefixes &&
          expectation.expected_enabled_prefixes == descriptor.local_prefixes &&
          expectation.expected_local_main_prefixes == descriptor.local_prefixes &&
          expectation.expected_accepted_remote_prefixes == local.topology_remote_prefixes_by_site[site_id]
        ])
      ])
      error_message = "every site's AZ-spread routers must exactly match topology and share complete overlapping local advertisements, enabled routes, local-main rules, and remote accepts."
    }
    precondition {
      condition = alltrue([
        for domain_id, contract in var.managed_route_tables :
        contract.route_table_id == local.topology_domains_by_id[domain_id].route_table_id &&
        contract.gwlbe_subnet_id == local.topology_domains_by_id[domain_id].gwlbe_subnet_id &&
        contract.route_table_association_id == local.topology_domains_by_id[domain_id].route_table_association_id &&
        contract.source_prefix == local.topology_domains_by_id[domain_id].source_prefix &&
        contract.destination_cidrs == toset(local.topology_domains_by_id[domain_id].remote_prefixes) &&
        contract.destination_cidrs == local.topology_remote_prefixes_by_site[local.topology_domains_by_id[domain_id].site_id] &&
        contract.region == local.topology_sites_by_id[local.topology_domains_by_id[domain_id].site_id].region &&
        contract.vpc_id == local.topology_sites_by_id[local.topology_domains_by_id[domain_id].site_id].vpc_id &&
        contract.eligible_eni_ids == toset([
          for router in values(local.topology_routers_by_site[local.topology_domains_by_id[domain_id].site_id]) : router.eni_id
        ]) &&
        contract.route_table_arn == "arn:${data.aws_partition.current.partition}:ec2:${contract.region}:${var.aws_account_id}:route-table/${contract.route_table_id}"
      ])
      error_message = "managed route tables must exactly match domain table, GWLBE subnet association, source, complete remote CIDRs, site, and eligible router ENIs."
    }
    precondition {
      condition = try(
        sha256(var.artifact_manifest_json) == var.artifact_manifest_sha256 &&
        toset(keys(local.artifact_manifest)) == toset([
          "schema", "component", "version", "revision", "source_dirty", "source_date_epoch", "build_date", "go_version", "artifacts",
        ]) &&
        can(regex("^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$", local.artifact_manifest.version)) &&
        can(regex("^[0-9a-f]{40}$", local.artifact_manifest.revision)) &&
        local.artifact_manifest.go_version == local.reviewed_go_toolchain &&
        local.artifact_manifest.source_dirty == false &&
        floor(local.artifact_manifest.source_date_epoch) == local.artifact_manifest.source_date_epoch &&
        local.artifact_manifest.source_date_epoch > 0 &&
        can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", local.artifact_manifest.build_date)) &&
        length(local.artifact_manifest.artifacts) >= 2 &&
        length(toset([
          for entry in local.artifact_manifest.artifacts : "${entry.component}/${entry.architecture}"
        ])) == length(local.artifact_manifest.artifacts) &&
        alltrue([
          for entry in local.artifact_manifest.artifacts :
          toset(keys(entry)) == toset([
            "component", "architecture", "ec2_architecture", "file", "goos", "goarch", "go_version",
            "vcs_revision", "vcs_modified", "version", "sha256", "size",
          ]) &&
          contains(["envelope-controller", "envelope-controller-topology"], entry.component) &&
          contains(["amd64", "arm64"], entry.architecture) &&
          entry.ec2_architecture == try({ amd64 = "x86_64", arm64 = "arm64" }[entry.architecture], "") &&
          entry.file == "${entry.component}-linux-${entry.architecture}" &&
          entry.goos == "linux" &&
          entry.goarch == entry.architecture &&
          entry.go_version == local.reviewed_go_toolchain &&
          entry.go_version == local.artifact_manifest.go_version &&
          entry.vcs_revision == local.artifact_manifest.revision &&
          entry.vcs_modified == false &&
          entry.version == local.artifact_manifest.version &&
          can(regex("^[0-9a-f]{64}$", entry.sha256)) &&
          entry.size > 0 && floor(entry.size) == entry.size
        ]) &&
        length(local.controller_manifest_entries) == 1 &&
        length(local.topology_identity_manifest_entries) == 1 &&
        local.controller_manifest_entry.ec2_architecture == local.ec2_architecture &&
        local.controller_manifest_entry.file == basename(var.artifact.object_key) &&
        local.controller_manifest_entry.sha256 == var.artifact.sha256 &&
        local.topology_identity_manifest_entry.ec2_architecture == local.ec2_architecture &&
        local.topology_identity_manifest_entry.file == basename(var.topology_identity_artifact.object_key) &&
        local.topology_identity_manifest_entry.sha256 == var.topology_identity_artifact.sha256 &&
        local.topology_identity.component == local.topology_identity_manifest_entry.component &&
        local.topology_identity.version == local.artifact_manifest.version &&
        local.topology_identity.revision == local.artifact_manifest.revision &&
        local.topology_identity.go_version == local.reviewed_go_toolchain &&
        local.topology_identity.vcs_modified == false,
        false,
      )
      error_message = "the reviewed clean artifact manifest, selected controller/topology files, hashes, architecture, revision, version, and Go toolchain must form one exact release identity."
    }
    precondition {
      condition = (
        data.aws_iam_role.readiness_publisher.name == var.readiness_publisher.role_name &&
        data.aws_iam_role.readiness_publisher.arn == var.readiness_publisher.role_arn &&
        startswith(var.readiness_publisher.role_arn, "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/") &&
        length(setsubtract(var.readiness_publisher.source_cidrs, var.metrics_ingress_cidrs)) == 0 &&
        var.controller_ready_metric.period_seconds >= var.readiness_publisher.scrape_interval_seconds &&
        var.controller_ready_metric.period_seconds % var.readiness_publisher.scrape_interval_seconds == 0 &&
        !contains(values(local.controller_iam_names), var.readiness_publisher.role_name)
      )
      error_message = "the readiness publisher must resolve to its exact external account role, scrape from allowed private CIDRs, and publish at an interval dividing the alarm period."
    }
    precondition {
      condition = (
        var.artifact.bucket_arn == "arn:${data.aws_partition.current.partition}:s3:::${var.artifact.bucket_name}" &&
        var.artifact.object_arn == "${var.artifact.bucket_arn}/${var.artifact.object_key}" &&
        var.topology_identity_artifact.bucket_arn == "arn:${data.aws_partition.current.partition}:s3:::${var.topology_identity_artifact.bucket_name}" &&
        var.topology_identity_artifact.object_arn == "${var.topology_identity_artifact.bucket_arn}/${var.topology_identity_artifact.object_key}" &&
        var.topology_identity_artifact.object_arn != var.artifact.object_arn &&
        alltrue([
          for secret in values(var.secret_parameters) :
          secret.arn == "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:parameter${secret.name}" &&
          can(regex(
            "^arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.aws_account_id}:key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$",
            secret.kms_key_arn,
          ))
        ])
      )
      error_message = "artifact, topology-tool, and secret identity ARNs must exactly match their supplied names, account, partition, and Regions."
    }
  }
}

resource "terraform_data" "route_contract" {
  for_each = var.managed_route_tables

  input = {
    route_table_id             = each.value.route_table_id
    gwlbe_subnet_id            = each.value.gwlbe_subnet_id
    route_table_association_id = each.value.route_table_association_id
    destinations               = sort(tolist(each.value.destination_cidrs))
    eligible_enis              = sort(tolist(each.value.eligible_eni_ids))
    current_targets            = local.current_route_targets[each.key]
  }

  lifecycle {
    precondition {
      condition = (
        data.aws_route_table.managed[each.key].id == each.value.route_table_id &&
        data.aws_route_table.managed[each.key].vpc_id == each.value.vpc_id &&
        data.aws_subnet.managed_gwlbe[each.key].id == each.value.gwlbe_subnet_id &&
        data.aws_subnet.managed_gwlbe[each.key].vpc_id == each.value.vpc_id
      )
      error_message = "managed GWLBE route table or subnet identity and VPC do not match its immutable contract."
    }
    precondition {
      condition = try(
        length(data.aws_route_table.managed[each.key].associations) == 1 &&
        one(data.aws_route_table.managed[each.key].associations).main == false &&
        one(data.aws_route_table.managed[each.key].associations).subnet_id == each.value.gwlbe_subnet_id &&
        one(data.aws_route_table.managed[each.key].associations).route_table_association_id == each.value.route_table_association_id &&
        one(data.aws_route_table.managed[each.key].associations).route_table_id == each.value.route_table_id &&
        one(data.aws_route_table.managed[each.key].associations).gateway_id == "",
        false,
      )
      error_message = "managed GWLBE route table must have exactly one non-main association with the configured subnet and association identities."
    }
    precondition {
      condition = alltrue([
        for cidr, matches in local.live_route_matches[each.key] :
        length(matches) == 1 &&
        try(contains(each.value.eligible_eni_ids, one(matches).network_interface_id), false)
      ])
      error_message = "every managed exact destination must exist once and currently select an explicitly eligible same-site router ENI."
    }
    precondition {
      condition = alltrue([
        for route in data.aws_route_table.managed[each.key].routes :
        try(route.destination_prefix_list_id, "") == ""
      ])
      error_message = "managed GWLBE route tables cannot contain unexpanded prefix-list destinations."
    }
    precondition {
      condition     = alltrue([for shadowing in values(local.live_route_shadowing[each.key]) : length(shadowing) == 0])
      error_message = "a more-specific route shadows part of a controller-managed exact destination prefix."
    }
  }

  depends_on = [terraform_data.input_contract]
}
