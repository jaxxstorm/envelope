run "production_attestor_bootstrap_is_immutable_and_reference_only" {
  command = plan
  variables {
    router_attestor_bootstrap = {
      authority_region = "us-west-2"
      artifact         = { region = "us-west-2", bucket = "reviewed-attestor-artifacts", key = "attestor/envelope-router-attestor-linux-amd64", version_id = "reviewed-version", sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      artifact_manifest_json = jsonencode({
        schema    = 1, component = "envelope-controller", source_dirty = false, version = "test.1", revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        artifacts = [{ component = "envelope-router-attestor", architecture = "amd64", goarch = "amd64", goos = "linux", file = "envelope-router-attestor-linux-amd64", sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", version = "test.1", vcs_revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vcs_modified = false, go_version = "go1.26.2" }]
      })
      routers = { for id in ["east-a", "east-b", "west-a", "west-b"] : id => {
        ed25519_public_key          = sha256(id)
        configuration_parameter_arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/${id}/enrollment-one"
        seed_parameter_arn          = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/${id}/seed-one"
        seed_version                = 1
      } }
    }
  }
  assert {
    condition = (
      length(local.attestor_bootstrap_scripts) == 4 &&
      strcontains(local.attestor_bootstrap_scripts["west-a"], "--version-id") &&
      strcontains(local.attestor_bootstrap_scripts["west-a"], "-m 0555") &&
      strcontains(local.attestor_bootstrap_scripts["west-a"], "ExecStart=/usr/local/bin/envelope-router-attestor enroll") &&
      jsondecode(aws_iam_role_policy.attestor_binary["west"].policy).Statement[0].Condition.StringEquals["s3:VersionId"] == "reviewed-version" &&
      jsondecode(aws_iam_role_policy.attestor_binary["west"].policy).Statement[0].Action == ["s3:GetObjectVersion"]
    )
    error_message = "Every production router must install an immutable binary and reference-only native boot enrollment, with no broad S3 grant."
  }
}

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_resource "aws_instance" {
    defaults = {
      id                           = "i-0123456789abcdef0"
      primary_network_interface_id = "eni-0123456789abcdef0"
    }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/envelope-plan-west-gwlb/0123456789abcdef" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/envelope-plan-west-gwlb-tg/0123456789abcdef" }
  }
  mock_resource "aws_vpc_endpoint_service" {
    defaults = { service_name = "com.amazonaws.vpce.us-west-2.vpce-svc-0123456789abcdef0" }
  }
  mock_resource "aws_vpc_endpoint" {
    defaults = { id = "vpce-0123456789abcdef0" }
  }
  mock_resource "aws_nat_gateway" {
    defaults = { id = "nat-0123456789abcdef0" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/west" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/envelope-plan-flow-logs" }
  }
}

mock_provider "aws" {
  alias = "east"
  mock_resource "aws_instance" {
    defaults = {
      id                           = "i-1123456789abcdef0"
      primary_network_interface_id = "eni-1123456789abcdef0"
    }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/envelope-plan-east-gwlb/1123456789abcdef" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/envelope-plan-east-gwlb-tg/1123456789abcdef" }
  }
  mock_resource "aws_vpc_endpoint_service" {
    defaults = { service_name = "com.amazonaws.vpce.us-east-1.vpce-svc-1123456789abcdef0" }
  }
  mock_resource "aws_vpc_endpoint" {
    defaults = { id = "vpce-1123456789abcdef0" }
  }
  mock_resource "aws_nat_gateway" {
    defaults = { id = "nat-1123456789abcdef0" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/east" }
  }
}

variables {
  name                       = "envelope-plan"
  deployment_phase           = "targets"
  expires_at                 = "2030-01-01T00:00:00Z"
  west_region                = "us-west-2"
  east_region                = "us-east-1"
  architecture               = "amd64"
  west_ami_id                = "ami-0123456789abcdef0"
  east_ami_id                = "ami-0fedcba9876543210"
  artifact_path              = "../../testdata/deployment/artifact-fixture"
  artifact_sha256            = "61fad8c939a87bac8b2e11c53ad9b900ba335428a871a49bbb5d4245ed2b0fb4"
  artifact_revision          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  artifact_version           = "fixture.1"
  west_tailscale_secret_arn  = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-plan/tailscale-auth"
  east_tailscale_secret_arn  = "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-plan/tailscale-auth"
  west_tailscale_kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/west"
  east_tailscale_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/east"
  tailscale_tag              = "tag:envelope-ci"
  e2e_load_profile = {
    profile_id                     = "envelope-e2e-v1"
    approved_at                    = "2026-08-20T10:00:00Z"
    safe_inner_mtu                 = 1280
    maximum_tcp_mss                = 1240
    sustained_tcp_duration_seconds = 15
    minimum_sustained_tcp_bytes    = 1048576
    iperf_duration_seconds         = 10
    minimum_throughput_mbps        = 5.0
    concurrent_duration_seconds    = 15
    concurrent_tcp_flows           = 4
    concurrent_udp_flows           = 4
    maximum_udp_loss_percent       = 1.0
    maximum_p99_latency_ms         = 250.0
  }
  symmetric_topology = {
    version = 3
    route_failover = {
      initial_transport_router_az_by_gwlbe_az = {
        west = { a = "a", b = "b" }
        east = { a = "a", b = "b" }
      }
      mutation_timeout_seconds    = 120
      restoration_timeout_seconds = 120
      recovery_timeout_seconds    = 300
    }
    sites = {
      west = {
        region                   = "us-west-2"
        ami_id                   = "ami-0123456789abcdef0"
        ssm_kms_key_arn          = "arn:aws:kms:us-west-2:123456789012:key/west"
        azs                      = { a = "us-west-2a", b = "us-west-2b" }
        vpc_cidr                 = "172.16.0.0/16"
        local_site_cidrs         = ["172.16.4.0/24", "172.16.5.0/24"]
        remote_site_cidrs        = ["172.17.4.0/24", "172.17.5.0/24"]
        workload_subnet_cidrs    = { a = "172.16.4.0/24", b = "172.16.5.0/24" }
        transport_subnet_cidrs   = { a = "172.16.10.0/24", b = "172.16.11.0/24" }
        gwlbe_subnet_cidrs       = { a = "172.16.20.0/24", b = "172.16.21.0/24" }
        gwlb_subnet_cidrs        = { a = "172.16.30.0/24", b = "172.16.31.0/24" }
        target_subnet_cidrs      = { a = "172.16.40.0/24", b = "172.16.41.0/24" }
        management_subnet_cidr   = "172.16.50.0/24"
        target_az_keys           = ["a", "b"]
        transport_router_az_keys = ["a", "b"]
      }
      east = {
        region                   = "us-east-1"
        ami_id                   = "ami-0fedcba9876543210"
        ssm_kms_key_arn          = "arn:aws:kms:us-east-1:123456789012:key/east"
        azs                      = { a = "us-east-1a", b = "us-east-1b" }
        vpc_cidr                 = "172.17.0.0/16"
        local_site_cidrs         = ["172.17.4.0/24", "172.17.5.0/24"]
        remote_site_cidrs        = ["172.16.4.0/24", "172.16.5.0/24"]
        workload_subnet_cidrs    = { a = "172.17.4.0/24", b = "172.17.5.0/24" }
        transport_subnet_cidrs   = { a = "172.17.10.0/24", b = "172.17.11.0/24" }
        gwlbe_subnet_cidrs       = { a = "172.17.20.0/24", b = "172.17.21.0/24" }
        gwlb_subnet_cidrs        = { a = "172.17.30.0/24", b = "172.17.31.0/24" }
        target_subnet_cidrs      = { a = "172.17.40.0/24", b = "172.17.41.0/24" }
        management_subnet_cidr   = "172.17.50.0/24"
        target_az_keys           = ["a", "b"]
        transport_router_az_keys = ["a", "b"]
      }
    }
  }
}

run "infrastructure_phase_creates_routes_and_endpoints_without_targets" {
  command = plan

  variables {
    deployment_phase = "infrastructure"
  }

  assert {
    condition = (
      output.deployment_phase.phase == "infrastructure" &&
      output.deployment_phase.inspected_data_plane_available == false &&
      strcontains(output.deployment_phase.expected_inspected_path, "intentionally empty") &&
      length(aws_vpc_endpoint.west) == 2 &&
      length(aws_vpc_endpoint.east) == 2 &&
      length(aws_route.workload_to_remote_west) == 4 &&
      length(aws_route.workload_to_remote_east) == 4 &&
      length(aws_route.transport_to_local_west) == 4 &&
      length(aws_route.transport_to_local_east) == 4 &&
      length(aws_route.gwlbe_to_remote_west) == 4 &&
      length(aws_route.gwlbe_to_remote_east) == 4 &&
      length(aws_instance.envelope_target_west) == 0 &&
      length(aws_instance.envelope_target_east) == 0 &&
      length(aws_lb_target_group_attachment.west) == 0 &&
      length(aws_lb_target_group_attachment.east) == 0 &&
      length(aws_instance.transport_router_west) == 2 &&
      length(aws_instance.transport_router_east) == 2
    )
    error_message = "Infrastructure must retain every inspected route domain, endpoint, router, and controller input while intentionally leaving GWLB target groups empty without a direct-route fallback."
  }
}

run "symmetric_two_az_paths" {
  command = plan

  assert {
    condition     = length(aws_vpc_endpoint.west) == 2 && length(aws_vpc_endpoint.east) == 2 && length(aws_instance.envelope_target_west) == 2 && length(aws_instance.envelope_target_east) == 2 && length(aws_instance.transport_router_west) == 2 && length(aws_instance.transport_router_east) == 2
    error_message = "every enabled AZ must have a GWLBE, target, and AZ-spread transport router."
  }
  assert {
    condition = (
      output.deployment_phase.phase == "targets" &&
      output.deployment_phase.inspected_data_plane_available == true &&
      length(aws_lb_target_group_attachment.west) == 2 &&
      length(aws_lb_target_group_attachment.east) == 2 &&
      alltrue([for target in values(aws_instance.envelope_target_west) : target.subnet_id == aws_subnet.target_west[target.tags.ZoneKey].id]) &&
      alltrue([for target in values(aws_instance.envelope_target_east) : target.subnet_id == aws_subnet.target_east[target.tags.ZoneKey].id]) &&
      !strcontains(file("${path.module}/topology.tf"), "aws_ecs_")
    )
    error_message = "The targets phase must add only EC2 targets and their registrations; it must not replace targets, routers, or the controller with ECS resources."
  }
  assert {
    condition     = length(aws_instance.workload_west) == 2 && length(aws_instance.workload_east) == 2 && toset(keys(aws_instance.workload_west)) == toset(["initiator", "responder"]) && toset(keys(aws_instance.workload_east)) == toset(["initiator", "responder"])
    error_message = "each site must have one workload per AZ with explicit initiator and responder roles."
  }
  assert {
    condition     = output.workload_instances.west.initiator.cidr == local.workload_roles.west.initiator.cidr && output.workload_instances.east.responder.cidr == local.workload_roles.east.responder.cidr && output.artifact_identity.sha256 == var.artifact_sha256 && output.e2e_load_profile == var.e2e_load_profile && output.route_failover.config_version == 3 && output.route_failover.mutation_timeout_seconds == 120 && output.route_failover.restoration_timeout_seconds == 120 && output.route_failover.recovery_timeout_seconds == 300 && output.route_failover.target_ownership == "envelope-controller"
    error_message = "protected lifecycle workload, artifact, load-profile, and route-failover outputs must be emitted."
  }
  assert {
    condition     = alltrue([for target in values(aws_instance.envelope_target_west) : target.source_dest_check == true]) && alltrue([for target in values(aws_instance.envelope_target_east) : target.source_dest_check == true]) && alltrue([for router in values(aws_instance.transport_router_west) : router.source_dest_check == false]) && alltrue([for router in values(aws_instance.transport_router_east) : router.source_dest_check == false])
    error_message = "raw own-IP packet-return targets must retain source/destination checks while transport routers disable them."
  }
  assert {
    condition     = alltrue([for runtime in values(output.envelope_runtime_config) : toset(keys(runtime)) == toset(["config_version", "mode", "udp_bind", "max_inner_packet_size", "artifact_sha256", "artifact_revision"]) && runtime.config_version == 2 && runtime.mode == "packet-return" && runtime.udp_bind == "0.0.0.0:6081" && runtime.max_inner_packet_size == 1280 && runtime.artifact_sha256 == var.artifact_sha256 && runtime.artifact_revision == var.artifact_revision])
    error_message = "target runtime output must be the exact version-2 packet-return contract."
  }
  assert {
    condition     = alltrue([for target in values(aws_instance.envelope_target_west) : target.user_data_base64 == data.cloudinit_config.target_west.rendered]) && alltrue([for target in values(aws_instance.envelope_target_east) : target.user_data_base64 == data.cloudinit_config.target_east.rendered]) && length(module.tailscale_transport_west) == 2 && length(module.tailscale_transport_east) == 2
    error_message = "targets must use direct multipart cloud-init while transport routers retain tailscale-cloudinit."
  }
  assert {
    condition     = !contains(flatten([for statement in jsondecode(aws_iam_role_policy.runtime_west.policy).Statement : statement.Action]), "ssm:GetParameter") && !contains(flatten([for statement in jsondecode(aws_iam_role_policy.runtime_west.policy).Statement : statement.Action]), "kms:Decrypt") && !contains(flatten([for statement in jsondecode(aws_iam_role_policy.runtime_east.policy).Statement : statement.Action]), "ssm:GetParameter") && !contains(flatten([for statement in jsondecode(aws_iam_role_policy.runtime_east.policy).Statement : statement.Action]), "kms:Decrypt")
    error_message = "target runtime profiles must not resolve or decrypt Tailnet credentials."
  }
  assert {
    condition = (
      toset(flatten([for statement in jsondecode(aws_iam_role_policy.workload_west.policy).Statement : statement.Action])) == toset(local.ssm_core_actions) &&
      toset(flatten([for statement in jsondecode(aws_iam_role_policy.workload_east.policy).Statement : statement.Action])) == toset(local.ssm_core_actions) &&
      !strcontains(aws_iam_role_policy.workload_west.policy, "s3:GetObject") &&
      !strcontains(aws_iam_role_policy.workload_east.policy, "s3:GetObject") &&
      !strcontains(aws_iam_role_policy.workload_west.policy, "ssm:GetParameter") &&
      !strcontains(aws_iam_role_policy.workload_east.policy, "kms:Decrypt") &&
      alltrue([for instance in values(aws_instance.workload_west) : instance.iam_instance_profile == aws_iam_instance_profile.workload_west.name]) &&
      alltrue([for instance in values(aws_instance.workload_east) : instance.iam_instance_profile == aws_iam_instance_profile.workload_east.name])
    )
    error_message = "workloads must use separate SSM-core-only profiles with no artifact or Tailnet secret access."
  }
  assert {
    condition     = contains(flatten([for statement in jsondecode(aws_iam_role_policy.transport_west.policy).Statement : statement.Action]), "ssm:GetParameter") && contains(flatten([for statement in jsondecode(aws_iam_role_policy.transport_west.policy).Statement : statement.Action]), "kms:Decrypt") && contains(flatten([for statement in jsondecode(aws_iam_role_policy.transport_east.policy).Statement : statement.Action]), "ssm:GetParameter") && contains(flatten([for statement in jsondecode(aws_iam_role_policy.transport_east.policy).Statement : statement.Action]), "kms:Decrypt")
    error_message = "only per-site transport profiles may resolve and decrypt Tailnet credentials."
  }
  assert {
    condition = (
      one([for statement in jsondecode(aws_iam_role_policy.transport_west.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:CallerAccount"] == "123456789012" &&
      one([for statement in jsondecode(aws_iam_role_policy.transport_west.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:EncryptionContext:PARAMETER_ARN"] == var.west_tailscale_secret_arn &&
      one([for statement in jsondecode(aws_iam_role_policy.transport_west.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:ViaService"] == "ssm.${var.west_region}.amazonaws.com" &&
      one([for statement in jsondecode(aws_iam_role_policy.transport_east.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:CallerAccount"] == "123456789012" &&
      one([for statement in jsondecode(aws_iam_role_policy.transport_east.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:EncryptionContext:PARAMETER_ARN"] == var.east_tailscale_secret_arn &&
      one([for statement in jsondecode(aws_iam_role_policy.transport_east.policy).Statement : statement if contains(statement.Action, "kms:Decrypt")]).Condition.StringEquals["kms:ViaService"] == "ssm.${var.east_region}.amazonaws.com"
    )
    error_message = "transport KMS decrypt must be bound to the account, exact parameter encryption context, and regional SSM service."
  }
  assert {
    condition = jsondecode(aws_iam_role_policy.flow_logs.policy) == {
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
          Resource = [
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/west:*",
            "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/east:*",
          ]
        },
        { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = ["*"] },
      ]
    }
    error_message = "flow-log IAM must be plan-time-known and limited to the two exact regional stream namespaces."
  }
  assert {
    condition = (
      aws_cloudwatch_log_group.application_west.retention_in_days == var.cloudwatch_log_retention_in_days &&
      aws_cloudwatch_log_group.application_east.retention_in_days == var.cloudwatch_log_retention_in_days &&
      alltrue([
        for policy in [aws_iam_role_policy.runtime_west.policy, aws_iam_role_policy.runtime_east.policy, aws_iam_role_policy.transport_west.policy, aws_iam_role_policy.transport_east.policy] :
        contains(flatten([for statement in jsondecode(policy).Statement : statement.Action]), "logs:CreateLogStream") &&
        contains(flatten([for statement in jsondecode(policy).Statement : statement.Action]), "logs:PutLogEvents")
      ]) &&
      strcontains(local.cloudwatch_agent_bootstrap.west, "/var/log/envelope-target/envelope.log") &&
      strcontains(local.cloudwatch_agent_bootstrap.west, "/var/log/envelope-router/transport-router.log") &&
      strcontains(local.cloudwatch_agent_bootstrap.west, "/var/log/envelope-router/tailscaled.log") &&
      strcontains(local.cloudwatch_agent_bootstrap.east, "/var/log/envelope-router/router-attestor.log")
    )
    error_message = "targets and transport routers must ship their application logs only to their site's retained CloudWatch log group."
  }
  assert {
    condition = alltrue([
      for instance in concat(
        values(aws_instance.envelope_target_west),
        values(aws_instance.envelope_target_east),
        values(aws_instance.transport_router_west),
        values(aws_instance.transport_router_east),
        ) : (
        instance.user_data_replace_on_change == true &&
        one(instance.root_block_device).delete_on_termination == true &&
        one(instance.root_block_device).encrypted == true &&
        one(instance.root_block_device).volume_type == "gp3" &&
        one(instance.metadata_options).http_endpoint == "enabled" &&
        one(instance.metadata_options).http_protocol_ipv6 == "disabled" &&
        one(instance.metadata_options).http_put_response_hop_limit == 1 &&
        one(instance.metadata_options).http_tokens == "required" &&
        one(instance.metadata_options).instance_metadata_tags == "disabled"
      )
    ])
    error_message = "targets and transport routers must replace on user-data change and use encrypted disposable roots plus hop-limited IMDSv2."
  }
  assert {
    condition     = length(aws_route.workload_to_remote_west) == 4 && length(aws_route.workload_to_remote_east) == 4 && length(aws_route.transport_to_local_west) == 4 && length(aws_route.transport_to_local_east) == 4 && length(aws_route.gwlbe_to_remote_west) == 4 && length(aws_route.gwlbe_to_remote_east) == 4
    error_message = "every AZ must have complete pre-inspection and post-inspection prefix routes."
  }
  assert {
    condition     = toset([for route in values(aws_route.gwlbe_to_remote_west) : route.destination_cidr_block]) == toset(var.symmetric_topology.sites.west.remote_site_cidrs) && toset([for route in values(aws_route.gwlbe_to_remote_east) : route.destination_cidr_block]) == toset(var.symmetric_topology.sites.east.remote_site_cidrs)
    error_message = "GWLBE route tables must route only exact remote-site prefixes after inspection."
  }
  assert {
    condition     = toset(keys(aws_route.gwlbe_to_remote_west)) == toset(flatten([for az_key in keys(var.symmetric_topology.sites.west.azs) : [for cidr in var.symmetric_topology.sites.west.remote_site_cidrs : "${az_key}:${cidr}"]])) && toset(keys(aws_route.gwlbe_to_remote_east)) == toset(flatten([for az_key in keys(var.symmetric_topology.sites.east.azs) : [for cidr in var.symmetric_topology.sites.east.remote_site_cidrs : "${az_key}:${cidr}"]]))
    error_message = "post-inspection routes must cover every exact AZ and remote-prefix pair."
  }
  assert {
    condition     = alltrue([for site, selections in local.route_failover.initial_transport_router_az_by_gwlbe_az : alltrue([for gwlbe_az, transport_az in selections : gwlbe_az == transport_az])]) && output.route_failover.same_az_preferred.west && output.route_failover.same_az_preferred.east
    error_message = "every GWLBE AZ must have an explicit reviewed same-AZ initial transport-router selection."
  }
  assert {
    condition = (
      length(aws_route_table.workload_west) == 2 && length(aws_route_table.workload_east) == 2 &&
      length(aws_route_table.transport_west) == 2 && length(aws_route_table.transport_east) == 2 &&
      length(aws_route_table.gwlbe_west) == 2 && length(aws_route_table.gwlbe_east) == 2 &&
      length(aws_route_table.target_west) == 2 && length(aws_route_table.target_east) == 2 &&
      length(aws_route_table_association.workload_west) == 2 && length(aws_route_table_association.workload_east) == 2 &&
      length(aws_route_table_association.transport_west) == 2 && length(aws_route_table_association.transport_east) == 2 &&
      length(aws_route_table_association.gwlbe_west) == 2 && length(aws_route_table_association.gwlbe_east) == 2 &&
      length(aws_route_table_association.target_west) == 2 && length(aws_route_table_association.target_east) == 2 &&
      length(aws_route.target_default_west) == 2 && length(aws_route.target_default_east) == 2 &&
      alltrue([for route in concat(values(aws_route.target_default_west), values(aws_route.target_default_east)) : route.destination_cidr_block == "0.0.0.0/0"])
    )
    error_message = "workload, transport, GWLBE, and target route domains must remain distinct and explicitly associated, with no target inner routes."
  }
  assert {
    condition     = aws_lb.west.enable_cross_zone_load_balancing == true && aws_lb.east.enable_cross_zone_load_balancing == true
    error_message = "the reviewed GWLB target-fleet behavior requires cross-zone load balancing to remain explicitly enabled."
  }
  assert {
    condition = alltrue([
      for target_group in [aws_lb_target_group.west, aws_lb_target_group.east] : (
        one(target_group.health_check).healthy_threshold == 5 &&
        one(target_group.health_check).interval == 10 &&
        one(target_group.health_check).path == "/healthz" &&
        one(target_group.health_check).port == "9090" &&
        one(target_group.health_check).protocol == "HTTP" &&
        one(target_group.health_check).timeout == 5 &&
        one(target_group.health_check).unhealthy_threshold == 2
      )
    ])
    error_message = "both target groups must use the exact bounded health transition contract."
  }
  assert {
    condition = alltrue([
      for site in ["west", "east"] :
      alltrue([
        for router in output.symmetric_topology.sites[site].transport_router_fleet :
        toset(keys(router)) == toset(["region", "az_key", "instance_id", "network_interface_id", "gwlbe_route_table_id", "advertised_prefixes"]) &&
        toset(router.advertised_prefixes) == toset(local.sites[site].local_site_cidrs)
      ]) &&
      output.symmetric_topology.transport_router_profile == "production-native-ha-v3" &&
      alltrue([for routes in values(local.initial_transport_router_advertise_routes[site]) : toset(routes) == toset(local.sites[site].local_site_cidrs)]) &&
      alltrue([
        for gwlbe_az, route in output.route_failover.sites[site] :
        route.source_workload_prefix == local.sites[site].workload_subnet_cidrs[gwlbe_az] &&
        contains(one([
          for router in output.symmetric_topology.sites[site].transport_router_fleet :
          router.advertised_prefixes
          if router.az_key == route.initial_transport_router_az_key
        ]), route.source_workload_prefix) &&
        toset(route.eligible_network_interface_ids) == toset([
          for router in output.symmetric_topology.sites[site].transport_router_fleet : router.network_interface_id
        ])
      ])
    ])
    error_message = "the production topology must expose every router as a complete exact-prefix candidate and every route domain's eligible ENI set."
  }
  assert {
    condition = (
      output.production_controller_topology_seed.config_version == 3 &&
      output.production_controller_topology_seed.deployment_id == var.name &&
      toset(keys(output.production_controller_topology_seed.sites)) == toset(["west", "east"]) &&
      length(output.production_controller_topology_seed.routers) == 4 &&
      length(output.production_controller_topology_seed.domains) == 4 &&
      alltrue([
        for domain in output.production_controller_topology_seed.domains :
        domain.route_table_id != "" &&
        domain.gwlbe_subnet_id != "" &&
        domain.route_table_association_id != "" &&
        domain.source_prefix != "" &&
        length(domain.remote_prefixes) == 2
      ])
    )
    error_message = "version 3 must emit complete route-table, GWLBE subnet, explicit association, source, and destination identities for controller topology generation."
  }
  assert {
    condition     = toset(flatten([for rule in aws_security_group.transport_west.ingress : rule.cidr_blocks])) == toset(var.symmetric_topology.sites.west.local_site_cidrs) && toset(flatten([for rule in aws_security_group.transport_east.ingress : rule.cidr_blocks])) == toset(var.symmetric_topology.sites.east.local_site_cidrs)
    error_message = "transit ENIs must accept preserved-source traffic from only exact local-site CIDRs."
  }
  assert {
    condition = (
      strcontains(local.transport_router_bootstrap.west, "iptables --wait 10 -P FORWARD DROP") &&
      strcontains(local.transport_router_bootstrap.west, "iptables --wait 10 -t mangle -P FORWARD ACCEPT") &&
      strcontains(local.transport_router_bootstrap.west, "ip6tables --wait 10 -P FORWARD DROP") &&
      strcontains(local.transport_router_bootstrap.west, "ip6tables --wait 10 -t mangle -P FORWARD ACCEPT") &&
      strcontains(local.transport_router_bootstrap.west, "unexpected $binary $table FORWARD policy") &&
      strcontains(local.transport_router_bootstrap.west, "unrelated $binary $table FORWARD state exists; refusing to flush it") &&
      strcontains(local.transport_router_bootstrap.west, "unrelated or conflicting IPv4 policy rule state exists") &&
      strcontains(local.transport_router_bootstrap.west, "IPv4 policy rules do not match the complete reviewed rule set") &&
      strcontains(local.transport_router_bootstrap.west, "interior or source-specific main-table route affects local protected prefix") &&
      strcontains(local.transport_router_bootstrap.west, "route-table state intersects a protected prefix before its reviewed decision") &&
      strcontains(local.transport_router_bootstrap.west, "readonly local_site_cidrs_json='${jsonencode(sort(local.sites.west.local_site_cidrs))}'") &&
      strcontains(local.transport_router_bootstrap.west, "readonly remote_site_cidrs_json='${jsonencode(sort(local.sites.west.remote_site_cidrs))}'") &&
      strcontains(local.transport_router_bootstrap.west, "readonly approved_maximum_tcp_mss='${var.e2e_load_profile.maximum_tcp_mss}'") &&
      !strcontains(local.transport_router_bootstrap.west, "nft flush ruleset") &&
      !strcontains(local.transport_router_bootstrap.west, "iptables --wait 10 -P FORWARD ACCEPT") &&
      !strcontains(local.transport_router_bootstrap.west, "ip6tables --wait 10 -P FORWARD ACCEPT") &&
      strcontains(local.transport_router_bootstrap.west, "/usr/sbin/sysctl -q -w net.ipv4.ip_forward=0") &&
      strcontains(local.transport_router_bootstrap.west, "net.ipv4.ip_forward = 0") &&
      !strcontains(local.transport_router_bootstrap.west, "rule add priority \"$priority\" iif \"$tailscale\"") &&
      strcontains(local.transport_router_bootstrap.west, "to \"${local.sites.west.local_site_cidrs[0]}\" lookup main") == false &&
      strcontains(local.transport_router_bootstrap.west, "to \"$${local_site_cidrs[$index]}\" lookup main") &&
      strcontains(local.transport_router_bootstrap.west, "assert_shadowed_local_tailnet_route \"$prefix\"") &&
      strcontains(local.transport_router_bootstrap.west, "assert_local_main_lookups \"$prefix\"") &&
      strcontains(local.transport_router_bootstrap.west, "network.num_addresses // 2") &&
      !strcontains(local.transport_router_bootstrap.west, "/usr/local/sbin/envelope-transport-advertisements") &&
      strcontains(local.transport_router_bootstrap.west, "-s \"$local_cidr\" -d \"$remote_cidr\" -j ACCEPT") &&
      strcontains(local.transport_router_bootstrap.west, "-s \"$remote_cidr\" -d \"$local_cidr\" -j ACCEPT") &&
      strcontains(local.transport_router_bootstrap.west, "-j TCPMSS --set-mss \"$ipv4_mss\"") &&
      strcontains(local.transport_router_bootstrap.west, "tailscale_mtu=$(interface_mtu \"$tailscale\")") &&
      strcontains(local.transport_router_bootstrap.west, "if (( approved_maximum_tcp_mss < ipv4_mss ))") &&
      strcontains(local.transport_router_bootstrap.west, "tailscale0 must be live before transport firewall setup") &&
      strcontains(local.transport_router_bootstrap.west, "exact remote-site routes are not live in Tailscale table 52") &&
      strcontains(local.transport_router_bootstrap.west, "ExecReload=/usr/local/sbin/envelope-transport-router-network activate") &&
      strcontains(local.transport_router_bootstrap.west, "After=network-online.target tailscaled.service") &&
      strcontains(local.transport_router_bootstrap.west, "PartOf=tailscaled.service") &&
      strcontains(local.transport_router_bootstrap.west, "ConditionPathExists=/var/lib/envelope/transport-router-network.configured") &&
      strcontains(local.transport_router_bootstrap.west, "Restart=on-failure") &&
      strcontains(local.transport_router_bootstrap.west, "RestartSec=10s") &&
      strcontains(local.transport_router_bootstrap.west, "WantedBy=tailscaled.service") &&
      strcontains(local.transport_router_bootstrap.west, "/usr/local/sbin/envelope-transport-router-network stage") &&
      !strcontains(local.transport_router_bootstrap.west, "net.ipv6.conf.all.forwarding=1") &&
      strcontains(local.transport_router_activation, "touch \"$recovery\"") &&
      strcontains(local.transport_router_activation, "rm -f \"$ready\" \"$state\"") &&
      strcontains(local.transport_router_activation, "systemctl stop envelope-transport-router-network.service") &&
      strcontains(local.transport_router_activation, "systemctl reset-failed envelope-transport-router-network.service") &&
      strcontains(local.transport_router_activation, "systemctl start --no-block envelope-transport-router-network.service") &&
      !strcontains(local.transport_router_activation, "systemctl restart envelope-transport-router-network.service") &&
      !strcontains(local.transport_router_bootstrap.west, "-j SNAT") &&
      !strcontains(local.transport_router_bootstrap.west, "-j MASQUERADE")
    )
    error_message = "transport bootstrap must own exact filter/mangle policies, audit complete protected policy and route paths, recover after tailscaled restarts, keep IPv6 disabled, avoid NAT, and cap live-MTU MSS."
  }
  assert {
    condition = (
      output.transport_router_readiness_expectations.sites.west.local_site_cidrs == sort(local.sites.west.local_site_cidrs) &&
      output.transport_router_readiness_expectations.config_version == 3 &&
      output.transport_router_readiness_expectations.sites.west.config_version == 3 &&
      output.transport_router_readiness_expectations.sites.west.remote_site_cidrs == sort(local.sites.west.remote_site_cidrs) &&
      output.transport_router_readiness_expectations.sites.west.approved_maximum_tcp_mss == var.e2e_load_profile.maximum_tcp_mss &&
      output.transport_router_readiness_expectations.sites.west.filter_forward_policy == "DROP" &&
      output.transport_router_readiness_expectations.sites.west.mangle_forward_policy == "ACCEPT" &&
      output.transport_router_readiness_expectations.sites.west.ipv6_filter_forward_policy == "DROP" &&
      output.transport_router_readiness_expectations.sites.west.ipv6_mangle_forward_policy == "ACCEPT" &&
      output.transport_router_readiness_expectations.sites.west.policy_rule_priority_base == 100 &&
      output.transport_router_readiness_expectations.sites.west.local_route_table == "main" &&
      output.transport_router_readiness_expectations.sites.west.remote_route_table == 52 &&
      output.transport_router_readiness_expectations.sites.west.recovery_marker == "/var/lib/envelope/transport-router-network.configured" &&
      length(output.transport_router_readiness_expectations.sites.west.local_policy_rules) == length(local.sites.west.local_site_cidrs) &&
      alltrue([
        for index, rule in output.transport_router_readiness_expectations.sites.west.local_policy_rules :
        rule.priority == 100 + index && rule.input == "all" && rule.source == "all" && rule.destination == sort(local.sites.west.local_site_cidrs)[index] && rule.fwmark == 0 && rule.table == "main" && rule.action == "lookup"
      ]) &&
      length(output.transport_router_readiness_expectations.sites.west.ipv4_policy_rules) == 7 + length(local.sites.west.local_site_cidrs) &&
      length(distinct([for rule in output.transport_router_readiness_expectations.sites.west.ipv4_policy_rules : rule.priority])) == length(output.transport_router_readiness_expectations.sites.west.ipv4_policy_rules) &&
      output.transport_router_readiness_expectations.sites.west.ipv4_policy_rules[0] == { priority = 0, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "local", action = "lookup" } &&
      one([for rule in output.transport_router_readiness_expectations.sites.west.ipv4_policy_rules : rule if rule.priority == 5270]) == { priority = 5270, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "52", action = "lookup" } &&
      length(output.transport_router_readiness_expectations.sites.west.forward_rules) == 2 * length(local.sites.west.local_site_cidrs) * length(local.sites.west.remote_site_cidrs) &&
      toset([
        for rule in output.transport_router_readiness_expectations.sites.west.forward_rules :
        "${rule.input}|${rule.output}|${rule.source}|${rule.destination}"
        ]) == toset(flatten([
          for local_cidr in local.sites.west.local_site_cidrs : [
            for remote_cidr in local.sites.west.remote_site_cidrs : [
              "${var.envelope_underlay_interface}|${var.envelope_tailscale_iface}|${local_cidr}|${remote_cidr}",
              "${var.envelope_tailscale_iface}|${var.envelope_underlay_interface}|${remote_cidr}|${local_cidr}",
            ]
          ]
      ])) &&
      length(output.transport_router_readiness_expectations.sites.west.mss_rules) == 2 * length(local.sites.west.local_site_cidrs) * length(local.sites.west.remote_site_cidrs) &&
      output.transport_router_readiness_expectations.sites.west.ipv6_forwarding == false &&
      output.transport_router_readiness_expectations.sites.west.ipv6_forward_rules == [] &&
      output.transport_router_readiness_expectations.sites.west.ipv6_mangle_forward_rules == [] &&
      output.transport_router_readiness_expectations.sites.west.nat_rules == []
    )
    error_message = "transport readiness output must expose exact built-in policies, complete live IPv4 policy expectations, selected route tables, CIDRs, prefix-pair firewall selectors, MSS ceiling, recovery gate, and disabled IPv6/NAT state."
  }
  assert {
    condition = (
      !strcontains(local.west_target_bootstrap, "tailscale") &&
      !strcontains(local.east_target_bootstrap, "tailscale") &&
      !strcontains(local.west_target_bootstrap, "iptables") &&
      !strcontains(local.east_target_bootstrap, "iptables") &&
      !strcontains(local.west_target_bootstrap, "sysctl") &&
      !strcontains(local.east_target_bootstrap, "sysctl")
    )
    error_message = "packet-return targets must have no Tailnet, firewall-transit, forwarding, or routing-manager bootstrap."
  }
  assert {
    condition = (
      alltrue([
        for metric in [
          "geneve_rx_packets",
          "geneve_rx_bytes",
          "geneve_tx_packets",
          "geneve_tx_bytes",
          "drops",
          "geneve_options_validation_errors",
          "gwlb_profile_rejections_total",
          "gwlb_receive_drops_total",
          "gwlb_return_build_failures_total",
          "gwlb_send_failures_total",
          "gwlb_inner_validation_failures_total",
          "gwlb_target_ready",
          "gwlb_target_component_ready",
          "gwlb_target_readiness_transitions_total",
          "gwlb_sender_reinitializations_total",
          "gwlb_mtu_drops_total",
        ] : strcontains(local.west_target_bootstrap, "allowed[\"${metric}\"] = 1")
      ]) &&
      alltrue([
        for metric in [
          "decap_errors",
          "encap_errors",
          "gwlb_unsupported_inner_total",
          "datapath_component_healthy",
          "datapath_liveness_transitions_total",
        ] : !strcontains(local.west_target_bootstrap, "allowed[\"${metric}\"] = 1")
      ])
    )
    error_message = "target diagnostics must allowlist every exact current Go metric and no obsolete datapath metric."
  }
  assert {
    condition     = output.cost_profile.profile == "production-native-ha-v3" && output.cost_profile.estimated_fixed_hourly_usd <= output.cost_profile.approved_max_hourly_usd && output.cost_profile.resource_counts.gwlbe_endpoints == 4 && output.cost_profile.resource_counts.target_instances == { west = 2, east = 2 } && output.cost_profile.resource_counts.transport_routers == { west = 2, east = 2 } && output.cost_profile.resource_counts.workload_instances == 4 && output.cost_profile.resource_counts.nat_gateways == 2 && output.cost_profile.resource_counts.gateway_load_balancers == 2 && output.cost_profile.resource_counts.flow_log_iam_roles == 1 && output.cost_profile.resource_counts.iam_roles.workload == 2 && output.cost_profile.nat_topology_limit.gateways_per_site == 1 && output.cost_profile.nat_topology_limit.expanded_for_ha == false
    error_message = "the reviewed HA, separate workload profile, and unchanged one-NAT-per-site topology must remain inside the approved fixed-cost ceiling."
  }
}

run "legacy_singleton_acceptance_profile_is_explicit" {
  command = plan

  variables {
    symmetric_topology = merge(var.symmetric_topology, { version = 2 })
  }

  assert {
    condition = (
      output.symmetric_topology.config_version == 2 &&
      !can(output.symmetric_topology.transport_router_profile) &&
      alltrue([
        for site, assignments in local.initial_transport_router_advertise_routes :
        alltrue([for routes in values(assignments) : length(routes) == 1]) &&
        toset(flatten(values(assignments))) == toset(local.sites[site].local_site_cidrs)
      ]) &&
      alltrue(flatten([
        for site in ["west", "east"] : [
          for router in output.symmetric_topology.sites[site].transport_router_fleet :
          can(router.advertised_prefix) && !can(router.advertised_prefixes)
        ]
      ])) &&
      strcontains(local.transport_router_bootstrap.west, "rule add priority \"$priority\" iif \"$tailscale\"") &&
      strcontains(local.transport_router_bootstrap.west, "/usr/local/sbin/envelope-transport-advertisements") &&
      output.cost_profile.profile == "legacy-symmetric-acceptance-v2" &&
      !can(output.route_failover.target_ownership) &&
      output.production_controller_topology_seed == null
    )
    error_message = "version 2 must remain an explicitly isolated singleton advertisement-mutation acceptance profile."
  }
}

run "reject_unsupported_topology_version" {
  command = plan

  variables {
    symmetric_topology = merge(var.symmetric_topology, { version = 4 })
  }

  expect_failures = [var.symmetric_topology]
}

run "reject_invalid_deployment_phase" {
  command = plan

  variables {
    deployment_phase = "target"
  }

  expect_failures = [var.deployment_phase]
}

run "reject_incomplete_target_fleet" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, { target_az_keys = ["a"] })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_incomplete_transport_fleet" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        east = merge(var.symmetric_topology.sites.east, { transport_router_az_keys = ["a"] })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_duplicate_target_fleet_az" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, { target_az_keys = ["a", "a", "b"] })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_duplicate_transport_fleet_az" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        east = merge(var.symmetric_topology.sites.east, { transport_router_az_keys = ["a", "a", "b"] })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_obsolete_target_routing_field" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, { tun_name = "envelope0" })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_partial_site_cidr_overlap" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, {
          remote_site_cidrs = ["172.16.4.128/25", "172.17.5.0/24"]
        })
      })
    })
  }
  expect_failures = [terraform_data.input_validation]
}

run "reject_vpc_resolver_overlap" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, {
          local_site_cidrs      = ["172.16.0.0/24", "172.16.5.0/24"]
          workload_subnet_cidrs = merge(var.symmetric_topology.sites.west.workload_subnet_cidrs, { a = "172.16.0.0/24" })
        })
        east = merge(var.symmetric_topology.sites.east, {
          remote_site_cidrs = ["172.16.0.0/24", "172.16.5.0/24"]
        })
      })
    })
  }
  expect_failures = [terraform_data.input_validation]
}

run "reject_route_domain_loop" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        east = merge(var.symmetric_topology.sites.east, {
          transport_subnet_cidrs = merge(var.symmetric_topology.sites.east.transport_subnet_cidrs, {
            a = "172.17.4.128/25"
          })
        })
      })
    })
  }
  expect_failures = [terraform_data.input_validation]
}

run "reject_unapproved_cost" {
  command = plan
  variables {
    estimated_fixed_hourly_usd    = 6
    approved_max_fixed_hourly_usd = 5
  }
  expect_failures = [terraform_data.input_validation]
}

run "reject_unreviewed_tailscale_version" {
  command = plan
  variables {
    tailscale_version = "1.80.4"
  }
  expect_failures = [var.tailscale_version]
}

run "reject_unsafe_shell_interpolation" {
  command = plan
  variables {
    artifact_revision = "revision'; touch /tmp/unsafe; #"
  }
  expect_failures = [var.artifact_revision]
}

run "reject_unsafe_shell_name" {
  command = plan
  variables {
    name = "envelope-plan';id"
  }
  expect_failures = [var.name]
}

run "reject_unsafe_shell_tag" {
  command = plan
  variables {
    tailscale_tag = "tag:envelope-ci';id"
  }
  expect_failures = [var.tailscale_tag]
}

run "reject_unsafe_shell_arn" {
  command = plan
  variables {
    west_tailscale_secret_arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-plan/tailscale-auth';id"
  }
  expect_failures = [var.west_tailscale_secret_arn]
}

run "reject_foreign_route_failover_selection" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        initial_transport_router_az_by_gwlbe_az = merge(
          var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az,
          { west = { a = "a", b = "east-a" } },
        )
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_cross_az_route_failover_selection" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        initial_transport_router_az_by_gwlbe_az = merge(
          var.symmetric_topology.route_failover.initial_transport_router_az_by_gwlbe_az,
          { west = { a = "b", b = "a" } },
        )
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_unbounded_route_failover" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        restoration_timeout_seconds = 7201
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_too_short_restoration_timeout" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        restoration_timeout_seconds = 1
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_recovery_not_exceeding_quiet_window" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        recovery_timeout_seconds = 10
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "reject_route_failover_compatibility_alias" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      route_failover = merge(var.symmetric_topology.route_failover, {
        initial_transport_router_az_keys = { west = { a = "a", b = "b" }, east = { a = "a", b = "b" } }
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}

run "distinct_transport_enis_and_controller_route_boundary" {
  command = apply

  override_resource {
    target = aws_vpc_endpoint.west["a"]
    values = { id = "vpce-0123456789abcdef0" }
  }
  override_resource {
    target = aws_vpc_endpoint.west["b"]
    values = { id = "vpce-1123456789abcdef0" }
  }
  override_resource {
    target = aws_vpc_endpoint.east["a"]
    values = { id = "vpce-2123456789abcdef0" }
  }
  override_resource {
    target = aws_vpc_endpoint.east["b"]
    values = { id = "vpce-3123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_west["a"]
    values = { primary_network_interface_id = "eni-0123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_west["b"]
    values = { primary_network_interface_id = "eni-1123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_east["a"]
    values = { primary_network_interface_id = "eni-2123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_east["b"]
    values = { primary_network_interface_id = "eni-3123456789abcdef0" }
  }
  assert {
    condition     = length(toset([for router in values(aws_instance.transport_router_west) : router.primary_network_interface_id])) == 2 && length(toset([for router in values(aws_instance.transport_router_east) : router.primary_network_interface_id])) == 2
    error_message = "each site's transport routers must expose distinct eligible ENIs."
  }
  assert {
    condition = (
      alltrue([for key, route in aws_route.gwlbe_to_remote_west : route.network_interface_id == aws_instance.transport_router_west[local.route_failover.initial_transport_router_az_by_gwlbe_az.west[split(":", key)[0]]].primary_network_interface_id]) &&
      alltrue([for key, route in aws_route.gwlbe_to_remote_east : route.network_interface_id == aws_instance.transport_router_east[local.route_failover.initial_transport_router_az_by_gwlbe_az.east[split(":", key)[0]]].primary_network_interface_id]) &&
      alltrue([for domain in values(output.route_failover.sites.west) : toset(domain.eligible_network_interface_ids) == toset([for router in values(aws_instance.transport_router_west) : router.primary_network_interface_id])]) &&
      alltrue([for domain in values(output.route_failover.sites.east) : toset(domain.eligible_network_interface_ids) == toset([for router in values(aws_instance.transport_router_east) : router.primary_network_interface_id])]) &&
      output.route_failover.same_az_preferred.west == true &&
      output.route_failover.same_az_preferred.east == true
    )
    error_message = "GWLBE routes must expose a preferred baseline and each complete controller-eligible ENI set."
  }
  assert {
    condition = (
      alltrue([for route in values(aws_route.transport_to_local_west) : route.vpc_endpoint_id == aws_vpc_endpoint.west[one([for az_key, prefix in var.symmetric_topology.sites.west.workload_subnet_cidrs : az_key if prefix == route.destination_cidr_block])].id]) &&
      alltrue([for route in values(aws_route.transport_to_local_east) : route.vpc_endpoint_id == aws_vpc_endpoint.east[one([for az_key, prefix in var.symmetric_topology.sites.east.workload_subnet_cidrs : az_key if prefix == route.destination_cidr_block])].id])
    )
    error_message = "every transport route table must select each destination workload prefix's GWLBE, including cross-AZ prefix routes."
  }
}

run "reject_duplicate_transport_enis" {
  command = apply

  module {
    source = "./"
  }

  override_resource {
    target = aws_instance.transport_router_west["a"]
    values = { primary_network_interface_id = "eni-0123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_west["b"]
    values = { primary_network_interface_id = "eni-0123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_east["a"]
    values = { primary_network_interface_id = "eni-2123456789abcdef0" }
  }
  override_resource {
    target = aws_instance.transport_router_east["b"]
    values = { primary_network_interface_id = "eni-3123456789abcdef0" }
  }

  expect_failures = [aws_route.gwlbe_to_remote_west]
}

run "seed_controller_owned_route_target" {
  command = apply

  module {
    source = "./tests/fixtures/controller-owned-route"
  }

  variables {
    configured_target = "eni-controller-selected"
    eligible_targets = [
      "eni-controller-selected",
      "eni-terraform-configured",
    ]
  }

  assert {
    condition     = terraform_data.route.output.network_interface_id == "eni-controller-selected"
    error_message = "The stateful ownership test must seed the controller-selected target."
  }
}

run "plan_preserves_controller_owned_route_target" {
  command = plan

  module {
    source = "./tests/fixtures/controller-owned-route"
  }

  variables {
    configured_target = "eni-terraform-configured"
    eligible_targets = [
      "eni-controller-selected",
      "eni-terraform-configured",
    ]
  }

  assert {
    condition     = terraform_data.route.output.network_interface_id == "eni-controller-selected"
    error_message = "A Terraform plan must not overwrite the controller-selected target."
  }
}

run "plan_rejects_ineligible_controller_owned_route_target" {
  command = plan

  module {
    source = "./tests/fixtures/controller-owned-route"
  }

  variables {
    configured_target = "eni-terraform-configured"
    eligible_targets  = ["eni-terraform-configured"]
  }

  expect_failures = [
    terraform_data.route,
  ]
}
