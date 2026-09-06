output "controller_instances" {
  description = "The three standalone replicas and their exact private failure-domain placement."
  value = {
    for controller_id, instance in aws_instance.controller : controller_id => {
      instance_id        = instance.id
      private_ip         = instance.private_ip
      subnet_id          = instance.subnet_id
      availability_zone  = instance.availability_zone
      observer_volume_id = aws_ebs_volume.observer_state[controller_id].id
    }
  }
}

output "controller_security_group_id" {
  description = "Dedicated controller-only security group ID."
  value       = aws_security_group.controller.id
}

output "controller_iam" {
  description = "Per-replica controller roles/profiles, IAM-bound observation partitions, and mode-dependent route mutation scope."
  value = {
    deployment_mode                     = var.deployment_mode
    readable_observation_partition_keys = local.observation_partition_key_values
    replicas = {
      for controller_id in var.controller_ids : controller_id => {
        role_arn                  = aws_iam_role.controller[controller_id].arn
        instance_profile_arn      = aws_iam_instance_profile.controller[controller_id].arn
        observation_partition_key = local.observation_partition_keys[controller_id]
      }
    }
    exact_route_table_arns = var.deployment_mode == "active" ? sort([for contract in values(var.managed_route_tables) : contract.route_table_arn]) : []
  }
}

output "dynamodb_authority" {
  description = "Encrypted regional authority table contract."
  value = {
    name                        = aws_dynamodb_table.authority.name
    arn                         = aws_dynamodb_table.authority.arn
    partition_key               = "pk"
    sort_key                    = "sk"
    ttl_attribute               = "ttl"
    billing_mode                = "PAY_PER_REQUEST"
    point_in_time_recovery      = true
    deletion_protection         = !var.protected_acceptance_mode
    kms_key_arn                 = local.controller_kms_key_arn
    encryption_key_mode         = var.protected_acceptance_mode ? "aws-owned" : "customer-managed"
    regional_strong_consistency = true
  }
}

output "protected_acceptance_lifecycle" {
  description = "Explicit cleanup behavior; enabled only for short-lived protected conformance deployments."
  value = {
    enabled                      = var.protected_acceptance_mode
    dynamodb_deletion_protection = !var.protected_acceptance_mode
    observer_final_snapshots     = !var.protected_acceptance_mode
    customer_managed_storage_key = !var.protected_acceptance_mode
  }
}

output "topology_identity" {
  description = "Nonsecret immutable topology delivery and Go-produced canonical identity."
  value = {
    parameter_name         = aws_ssm_parameter.topology.name
    parameter_arn          = aws_ssm_parameter.topology.arn
    canonical_sha256       = local.topology_document_sha256
    source_document_sha256 = local.topology_document_sha256
    schema_version         = local.topology.schema_version
    producer = {
      component    = local.topology_identity.component
      revision     = local.topology_identity.revision
      version      = local.topology_identity.version
      go_version   = local.topology_identity.go_version
      vcs_modified = local.topology_identity.vcs_modified
    }
  }
}

output "artifact_identity" {
  description = "Manifest-bound immutable controller and topology-verifier artifacts installed on every replica."
  value = {
    architecture     = var.controller_architecture
    ec2_architecture = local.ec2_architecture
    manifest_sha256  = var.artifact_manifest_sha256
    revision         = local.artifact_manifest.revision
    version          = local.artifact_manifest.version
    go_version       = local.artifact_manifest.go_version
    vcs_modified     = local.artifact_manifest.source_dirty
    controller       = var.artifact
    topology_tool    = var.topology_identity_artifact
  }
}

output "dynamic_route_ownership" {
  description = "Controller handoff: Terraform validates GWLBE association and route shape plus eligible targets but creates no aws_route and never restores a baseline ENI."
  value = {
    topology_sha256          = local.topology_sha256
    terraform_manages_target = false
    deployment_mode          = var.deployment_mode
    controller_action        = var.deployment_mode == "active" ? "ec2:ReplaceRoute" : null
    domains = {
      for domain_id, contract in var.managed_route_tables : domain_id => {
        region                     = contract.region
        vpc_id                     = contract.vpc_id
        route_table_id             = contract.route_table_id
        route_table_arn            = contract.route_table_arn
        gwlbe_subnet_id            = contract.gwlbe_subnet_id
        route_table_association_id = contract.route_table_association_id
        source_prefix              = contract.source_prefix
        exact_destination_cidrs    = sort(tolist(contract.destination_cidrs))
        eligible_eni_ids           = sort(tolist(contract.eligible_eni_ids))
        observed_target_by_cidr    = local.current_route_targets[domain_id]
        preferred_baseline_router  = local.topology_domains_by_id[domain_id].preferred_owner
      }
    }
  }
}

output "transport_topology_expectations" {
  description = "Complete overlapping exact-prefix and higher-priority local-main contract for every production transport router."
  value = {
    topology_sha256 = local.topology_sha256
    sites           = var.transport_topology
  }
}

output "controller_ready_metric_assumptions" {
  description = "External collector contract for fail-closed controller-ready alarms; the controller role cannot publish CloudWatch metrics."
  value = {
    endpoint                = "/readyz"
    healthy_http_status     = 200
    ready_value             = 1
    not_ready_value         = 0
    namespace               = var.controller_ready_metric.namespace
    metric_name             = var.controller_ready_metric.metric_name
    dimensions              = ["DeploymentId", "ControllerId", "PublisherId"]
    period_seconds          = var.controller_ready_metric.period_seconds
    scrape_interval_seconds = var.readiness_publisher.scrape_interval_seconds
    missing_data            = "breaching"
    publisher = {
      id           = var.readiness_publisher.id
      role_name    = data.aws_iam_role.readiness_publisher.name
      role_arn     = data.aws_iam_role.readiness_publisher.arn
      source_cidrs = sort(tolist(var.readiness_publisher.source_cidrs))
    }
    targets = {
      for controller_id, instance in aws_instance.controller : controller_id => {
        address = "${instance.private_ip}:${var.metrics_port}"
        path    = "/readyz"
        dimensions = {
          DeploymentId = var.name
          ControllerId = controller_id
          PublisherId  = var.readiness_publisher.id
        }
      }
    }
    controller_can_publish = false
  }
}

output "management_egress" {
  description = "Validated per-replica private route and same-AZ public NAT identities."
  value = {
    for controller_id, contract in var.management_egress : controller_id => {
      controller_subnet_id = var.controller_placements[controller_id].subnet_id
      availability_zone    = var.controller_placements[controller_id].availability_zone
      route_table_id       = data.aws_route_table.management_egress[controller_id].id
      nat_gateway_id       = data.aws_nat_gateway.management_egress[controller_id].id
      nat_subnet_id        = data.aws_subnet.management_nat[controller_id].id
      nat_route_table_id   = data.aws_route_table.management_nat[controller_id].id
      internet_gateway_id  = contract.internet_gateway_id
      connectivity_type    = data.aws_nat_gateway.management_egress[controller_id].connectivity_type
      state                = data.aws_nat_gateway.management_egress[controller_id].state
    }
  }
}

output "alarm_arns" {
  description = "Instance, DynamoDB, and externally published controller-ready alarm ARNs."
  value = {
    instance_status        = { for id, alarm in aws_cloudwatch_metric_alarm.instance_status : id => alarm.arn }
    dynamodb_system_errors = aws_cloudwatch_metric_alarm.dynamodb_system_errors.arn
    dynamodb_throttles     = { for name, alarm in aws_cloudwatch_metric_alarm.dynamodb_throttles : name => alarm.arn }
    controller_ready       = { for id, alarm in aws_cloudwatch_metric_alarm.controller_ready : id => alarm.arn }
  }
}
