mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_ami" {
    defaults = {
      architecture = "x86_64"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["x86_64"]
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{}"
    }
  }

  mock_resource "aws_lb" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/mock-west/0123456789abcdef"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/mock-west/0123456789abcdef"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/west"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/envelope-plan-flow-logs"
    }
  }
}

mock_provider "aws" {
  alias = "east"

  mock_data "aws_ami" {
    defaults = {
      architecture = "x86_64"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["x86_64"]
    }
  }

  mock_resource "aws_lb" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/mock-east/0123456789abcdef"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/mock-east/0123456789abcdef"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc-flow-logs/envelope-plan/east"
    }
  }
}

variables {
  name       = "envelope-plan"
  expires_at = "2030-01-01T00:00:00Z"

  west_azs = {
    a = "us-west-2a"
    b = "us-west-2b"
  }
  east_azs = {
    a = "us-east-1a"
    b = "us-east-1b"
  }
  west_appliance_az_key = "a"
  east_appliance_az_key = "a"

  west_public_subnet_cidr    = "172.16.40.0/24"
  east_public_subnet_cidr    = "172.17.40.0/24"
  west_appliance_subnet_cidr = "172.16.30.0/24"
  east_appliance_subnet_cidr = "172.17.30.0/24"
  west_workload_subnet_cidrs = { a = "172.16.0.0/24", b = "172.16.1.0/24" }
  east_workload_subnet_cidrs = { a = "172.17.0.0/24", b = "172.17.1.0/24" }
  west_gwlbe_subnet_cidrs    = { a = "172.16.10.0/24", b = "172.16.11.0/24" }
  east_gwlbe_subnet_cidrs    = { a = "172.17.10.0/24", b = "172.17.11.0/24" }
  west_gwlb_subnet_cidrs     = { a = "172.16.20.0/24", b = "172.16.21.0/24" }
  east_gwlb_subnet_cidrs     = { a = "172.17.20.0/24", b = "172.17.21.0/24" }

  architecture = "amd64"
  west_ami_id  = "ami-0123456789abcdef0"
  east_ami_id  = "ami-0fedcba9876543210"

  artifact_path     = "../../testdata/deployment/artifact-fixture"
  artifact_sha256   = "61fad8c939a87bac8b2e11c53ad9b900ba335428a871a49bbb5d4245ed2b0fb4"
  artifact_revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  artifact_version  = "fixture.1"

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

  envelope_gwlb_return_cidrs = {
    west = ["172.16.0.0/24"]
    east = ["172.17.1.0/24"]
  }
  envelope_local_delivery_cidrs = {
    west = ["172.16.1.0/24"]
    east = ["172.17.0.0/24"]
  }
  envelope_remote_tailnet_cidrs = {
    west = ["172.17.0.0/24", "172.17.1.0/24"]
    east = ["172.16.0.0/24", "172.16.1.0/24"]
  }
}

run "fresh_mocked_apply" {
  command = apply

  assert {
    condition = (
      length(aws_vpc_endpoint.west) == 1 &&
      length(aws_vpc_endpoint.east) == 1 &&
      toset(keys(aws_vpc_endpoint.west)) == toset([local.west_initiator_az_key]) &&
      toset(keys(aws_vpc_endpoint.east)) == toset([local.east_initiator_az_key]) &&
      toset(aws_vpc_endpoint.west[local.west_initiator_az_key].subnet_ids) == toset([aws_subnet.gwlbe_west[local.west_initiator_az_key].id]) &&
      toset(aws_vpc_endpoint.east[local.east_initiator_az_key].subnet_ids) == toset([aws_subnet.gwlbe_east[local.east_initiator_az_key].id])
    )
    error_message = "each site must have exactly one role-keyed GWLBE in its initiator AZ"
  }

  assert {
    condition = (
      local.west_initiator_az_key == "a" &&
      local.west_responder_az_key == "b" &&
      local.east_initiator_az_key == "b" &&
      local.east_responder_az_key == "a" &&
      local.west_workloads.initiator.cidr == one(var.envelope_gwlb_return_cidrs["west"]) &&
      local.west_workloads.responder.cidr == one(var.envelope_local_delivery_cidrs["west"]) &&
      local.east_workloads.initiator.cidr == one(var.envelope_gwlb_return_cidrs["east"]) &&
      local.east_workloads.responder.cidr == one(var.envelope_local_delivery_cidrs["east"])
    )
    error_message = "semantic initiator and responder AZ keys must be derived from the configured workload CIDR maps"
  }

  assert {
    condition = (
      toset(keys(aws_instance.workload_west)) == toset(["initiator", "responder"]) &&
      toset(keys(aws_instance.workload_east)) == toset(["initiator", "responder"]) &&
      toset(keys(aws_security_group.workload_west)) == toset(["initiator", "responder"]) &&
      toset(keys(aws_security_group.workload_east)) == toset(["initiator", "responder"])
    )
    error_message = "each site must have exactly one role-keyed initiator and responder workload instance and security group"
  }

  assert {
    condition = (
      alltrue([
        for role, workload in local.west_workloads :
        aws_instance.workload_west[role].subnet_id == aws_subnet.workload_west[workload.az_key].id &&
        toset(aws_instance.workload_west[role].vpc_security_group_ids) == toset([aws_security_group.workload_west[role].id]) &&
        aws_instance.workload_west[role].iam_instance_profile == aws_iam_instance_profile.workload_west.name &&
        aws_instance.workload_west[role].tags.Role == role &&
        aws_instance.workload_west[role].volume_tags.Role == role &&
        aws_instance.workload_west[role].volume_tags.ZoneKey == workload.az_key
      ]) &&
      alltrue([
        for role, workload in local.east_workloads :
        aws_instance.workload_east[role].subnet_id == aws_subnet.workload_east[workload.az_key].id &&
        toset(aws_instance.workload_east[role].vpc_security_group_ids) == toset([aws_security_group.workload_east[role].id]) &&
        aws_instance.workload_east[role].iam_instance_profile == aws_iam_instance_profile.workload_east.name &&
        aws_instance.workload_east[role].tags.Role == role &&
        aws_instance.workload_east[role].volume_tags.Role == role &&
        aws_instance.workload_east[role].volume_tags.ZoneKey == workload.az_key
      ])
    )
    error_message = "workloads must use their role AZ subnet, role SG, regional SSM profile, and explicit role volume tags"
  }

  assert {
    condition = (
      length(aws_security_group.workload_west["initiator"].ingress) == 0 &&
      length(aws_security_group.workload_east["initiator"].ingress) == 0 &&
      toset([
        for rule in aws_security_group.workload_west["responder"].ingress :
        "${rule.protocol}:${rule.from_port}:${rule.to_port}"
      ]) == toset(["icmp:-1:-1", "tcp:5201:5201", "udp:5201:5201"]) &&
      toset([
        for rule in aws_security_group.workload_east["responder"].ingress :
        "${rule.protocol}:${rule.from_port}:${rule.to_port}"
      ]) == toset(["icmp:-1:-1", "tcp:5201:5201", "udp:5201:5201"]) &&
      alltrue([
        for rule in aws_security_group.workload_west["responder"].ingress :
        toset(rule.cidr_blocks) == toset([local.east_initiator_cidr])
      ]) &&
      alltrue([
        for rule in aws_security_group.workload_east["responder"].ingress :
        toset(rule.cidr_blocks) == toset([local.west_initiator_cidr])
      ]) &&
      toset([for rule in aws_security_group.workload_west["responder"].ingress : rule.description]) == toset([
        "ICMP and MTU probes from paired east initiator",
        "TCP and iperf3 probes from paired east initiator",
        "UDP, MTU, and iperf3 probes from paired east initiator",
      ]) &&
      toset([for rule in aws_security_group.workload_east["responder"].ingress : rule.description]) == toset([
        "ICMP and MTU probes from paired west initiator",
        "TCP and iperf3 probes from paired west initiator",
        "UDP, MTU, and iperf3 probes from paired west initiator",
      ])
    )
    error_message = "initiators must have no application ingress and responders must admit only paired initiator ICMP/MTU and TCP/UDP/iperf3 on 5201"
  }

  assert {
    condition = (
      length([
        for rule in aws_security_group.envelope_west.ingress : rule
        if rule.description == "Forward local responder returns" && rule.protocol == "-1" && toset(rule.cidr_blocks) == toset([local.west_responder_cidr])
      ]) == 1 &&
      length([
        for rule in aws_security_group.envelope_east.ingress : rule
        if rule.description == "Forward local responder returns" && rule.protocol == "-1" && toset(rule.cidr_blocks) == toset([local.east_responder_cidr])
      ]) == 1
    )
    error_message = "each appliance must intentionally admit forwarding only from its exact local responder CIDR"
  }

  assert {
    condition = (
      toset(aws_network_acl.appliance_west.subnet_ids) == toset([aws_subnet.appliance_west.id]) &&
      toset(aws_network_acl.appliance_east.subnet_ids) == toset([aws_subnet.appliance_east.id]) &&
      alltrue([
        for policy in [
          {
            acl            = aws_network_acl.appliance_west
            initiator_cidr = local.west_initiator_cidr
            responder_cidr = local.west_responder_cidr
          },
          {
            acl            = aws_network_acl.appliance_east
            initiator_cidr = local.east_initiator_cidr
            responder_cidr = local.east_responder_cidr
          },
        ] :
        length(policy.acl.ingress) == 2 &&
        length(policy.acl.egress) == 3 &&
        length([
          for rule in policy.acl.ingress : rule
          if rule.rule_no == 100 && rule.action == "allow" && rule.protocol == "-1" && rule.cidr_block == policy.responder_cidr
        ]) == 1 &&
        length([
          for rule in policy.acl.ingress : rule
          if rule.rule_no == 200 && rule.action == "allow" && rule.protocol == "-1" && rule.cidr_block == "0.0.0.0/0"
        ]) == 1 &&
        length([
          for rule in policy.acl.egress : rule
          if rule.rule_no == 100 && rule.action == "deny" && rule.protocol == "-1" && rule.cidr_block == policy.initiator_cidr
        ]) == 1 &&
        length([
          for rule in policy.acl.egress : rule
          if rule.rule_no == 110 && rule.action == "allow" && rule.protocol == "-1" && rule.cidr_block == policy.responder_cidr
        ]) == 1 &&
        length([
          for rule in policy.acl.egress : rule
          if rule.rule_no == 200 && rule.action == "allow" && rule.protocol == "-1" && rule.cidr_block == "0.0.0.0/0"
        ]) == 1
      ])
    )
    error_message = "appliance NACLs must explicitly allow responder delivery/returns, deny direct initiator bypass, and retain required stateless underlay traffic"
  }

  assert {
    condition = (
      aws_route.initiator_to_responder_west.route_table_id == aws_route_table.workload_west[local.west_initiator_az_key].id &&
      aws_route.initiator_to_responder_west.destination_cidr_block == local.east_responder_cidr &&
      aws_route.initiator_to_responder_west.vpc_endpoint_id == aws_vpc_endpoint.west[local.west_initiator_az_key].id &&
      aws_route.initiator_to_responder_east.route_table_id == aws_route_table.workload_east[local.east_initiator_az_key].id &&
      aws_route.initiator_to_responder_east.destination_cidr_block == local.west_responder_cidr &&
      aws_route.initiator_to_responder_east.vpc_endpoint_id == aws_vpc_endpoint.east[local.east_initiator_az_key].id
    )
    error_message = "each initiator must route only its paired remote responder CIDR through its same-AZ local GWLBE"
  }

  assert {
    condition = (
      aws_route.responder_return_west.route_table_id == aws_route_table.workload_west[local.west_responder_az_key].id &&
      aws_route.responder_return_west.destination_cidr_block == local.east_initiator_cidr &&
      aws_route.responder_return_west.network_interface_id == aws_instance.envelope_west.primary_network_interface_id &&
      aws_route.responder_return_east.route_table_id == aws_route_table.workload_east[local.east_responder_az_key].id &&
      aws_route.responder_return_east.destination_cidr_block == local.west_initiator_cidr &&
      aws_route.responder_return_east.network_interface_id == aws_instance.envelope_east.primary_network_interface_id
    )
    error_message = "each responder must return only its paired remote initiator CIDR through the local appliance primary ENI"
  }

  assert {
    condition = (
      alltrue([for instance in values(aws_instance.workload_west) : instance.user_data_base64 == local.workload_user_data]) &&
      alltrue([for instance in values(aws_instance.workload_east) : instance.user_data_base64 == local.workload_user_data]) &&
      startswith(local.workload_user_data, "H4sI") &&
      local.workload_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
      local.workload_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes &&
      strcontains(local.workload_bootstrap, base64encode(file("${path.module}/cloud-init/envelope-e2e-agent.py"))) &&
      alltrue([
        for package in ["amazon-ssm-agent", "coreutils", "grep", "gzip", "iperf3", "iproute", "iputils", "jq", "procps-ng", "python3", "tcpdump"] :
        strcontains(local.workload_bootstrap, package)
      ]) &&
      strcontains(local.workload_bootstrap, "mv -f \"$agent_tmp\" /opt/envelope/e2e-agent") &&
      strcontains(local.workload_bootstrap, "ExecStart=/opt/envelope/e2e-agent serve --protocol tcp") &&
      strcontains(local.workload_bootstrap, "ExecStart=/opt/envelope/e2e-agent serve --protocol udp") &&
      length(regexall("(?m)^ExecStart=/opt/envelope/e2e-agent serve --protocol (tcp|udp) --bind 0\\.0\\.0\\.0 --port 5201 --timeout 21600 --max-messages 100000$", local.workload_bootstrap)) == 2 &&
      length(regexall("(?m)^Restart=always$", local.workload_bootstrap)) == 2 &&
      !strcontains(local.workload_bootstrap, "--timeout 3600") &&
      strcontains(local.workload_bootstrap, "systemctl enable --now envelope-e2e-agent-tcp.service envelope-e2e-agent-udp.service") &&
      strcontains(local.workload_bootstrap, "systemctl is-active --quiet envelope-e2e-agent-tcp.service") &&
      strcontains(local.workload_bootstrap, "systemctl is-active --quiet envelope-e2e-agent-udp.service") &&
      length(regexall("(?m)^KillMode=control-group$", local.workload_bootstrap)) == 2 &&
      length(regexall("(?m)^KillSignal=SIGTERM$", local.workload_bootstrap)) == 2 &&
      length(regexall("(?m)^TimeoutStopSec=5$", local.workload_bootstrap)) == 2 &&
      !strcontains(local.workload_bootstrap, "RefuseManualStop=true")
    )
    error_message = "all workloads must receive bounded gzip cloud-init with capture/load diagnostics and stoppable TCP/UDP managed listeners"
  }

  assert {
    condition = (
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "MAX_FRAME_BYTES = 4096") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "MAX_MESSAGES = 100_000") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "MAX_TIMEOUT_SECONDS = 21_600.0") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "MAX_TCP_CLIENTS = 32") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "listener.listen(MAX_TCP_CLIENTS)") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "one TCP socket changed connection_id") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "threading.Barrier(client_count)") &&
      strcontains(file("${path.module}/cloud-init/envelope-e2e-agent.py"), "subparsers.add_parser(\"self-test\"")
    )
    error_message = "the embedded workload agent must retain frame/message bounds, a six-hour timeout, 32-client TCP concurrency, per-socket identity, and its loopback barrier self-test"
  }

  assert {
    condition = (
      aws_cloudwatch_log_group.flow_west.retention_in_days == 7 &&
      aws_cloudwatch_log_group.flow_east.retention_in_days == 7 &&
      aws_flow_log.west.vpc_id == aws_vpc.west.id &&
      aws_flow_log.east.vpc_id == aws_vpc.east.id &&
      aws_flow_log.west.log_destination == aws_cloudwatch_log_group.flow_west.arn &&
      aws_flow_log.east.log_destination == aws_cloudwatch_log_group.flow_east.arn &&
      aws_flow_log.west.iam_role_arn == aws_iam_role.flow_logs.arn &&
      aws_flow_log.east.iam_role_arn == aws_iam_role.flow_logs.arn &&
      alltrue([
        for flow_log in [aws_flow_log.west, aws_flow_log.east] :
        flow_log.traffic_type == "ALL" &&
        flow_log.log_destination_type == "cloud-watch-logs" &&
        flow_log.max_aggregation_interval == 60 &&
        flow_log.log_format == local.flow_log_format
      ]) &&
      strcontains(local.flow_log_format, "$${action}") &&
      strcontains(local.flow_log_format, "$${flow-direction}") &&
      strcontains(local.flow_log_format, "$${traffic-path}") &&
      strcontains(local.flow_log_assume_policy, "vpc-flow-logs.amazonaws.com") &&
      strcontains(local.flow_log_assume_policy, data.aws_caller_identity.current.account_id) &&
      strcontains(local.flow_log_delivery_policy, "logs:CreateLogGroup") &&
      strcontains(local.flow_log_delivery_policy, "logs:CreateLogStream") &&
      strcontains(local.flow_log_delivery_policy, "logs:PutLogEvents") &&
      strcontains(local.flow_log_delivery_policy, aws_cloudwatch_log_group.flow_west.arn) &&
      strcontains(local.flow_log_delivery_policy, aws_cloudwatch_log_group.flow_east.arn) &&
      output.flow_log_evidence.west.flow_log_id == aws_flow_log.west.id &&
      output.flow_log_evidence.east.flow_log_id == aws_flow_log.east.id
    )
    error_message = "both VPCs must emit bounded-retention ALL Flow Logs with path fields and one scoped delivery role"
  }

  assert {
    condition = (
      toset(keys(output.workload_instances)) == toset(["west", "east"]) &&
      toset(keys(output.workload_instances.west)) == toset(["initiator", "responder"]) &&
      toset(keys(output.workload_instances.east)) == toset(["initiator", "responder"]) &&
      alltrue([
        for role, workload in local.west_workloads :
        output.workload_instances.west[role].instance_id == aws_instance.workload_west[role].id &&
        output.workload_instances.west[role].private_ip == aws_instance.workload_west[role].private_ip &&
        output.workload_instances.west[role].az_key == workload.az_key &&
        output.workload_instances.west[role].availability_zone == var.west_azs[workload.az_key] &&
        output.workload_instances.west[role].subnet_id == aws_subnet.workload_west[workload.az_key].id &&
        output.workload_instances.west[role].cidr == workload.cidr &&
        output.workload_instances.west[role].route_table_id == aws_route_table.workload_west[workload.az_key].id
      ]) &&
      alltrue([
        for role, workload in local.east_workloads :
        output.workload_instances.east[role].instance_id == aws_instance.workload_east[role].id &&
        output.workload_instances.east[role].private_ip == aws_instance.workload_east[role].private_ip &&
        output.workload_instances.east[role].az_key == workload.az_key &&
        output.workload_instances.east[role].availability_zone == var.east_azs[workload.az_key] &&
        output.workload_instances.east[role].subnet_id == aws_subnet.workload_east[workload.az_key].id &&
        output.workload_instances.east[role].cidr == workload.cidr &&
        output.workload_instances.east[role].route_table_id == aws_route_table.workload_east[workload.az_key].id
      ])
    )
    error_message = "workload output must be nested by site and role with identity, network, CIDR, and route-table fields"
  }

  assert {
    condition = (
      aws_lb.west.enable_cross_zone_load_balancing &&
      aws_lb.east.enable_cross_zone_load_balancing &&
      aws_lb_target_group_attachment.west.target_id == aws_instance.envelope_west.id &&
      aws_lb_target_group_attachment.east.target_id == aws_instance.envelope_east.id
    )
    error_message = "each regional GWLB must retain cross-zone behavior and exactly its one direct appliance target"
  }

  assert {
    condition     = aws_instance.envelope_west.associate_public_ip_address == false && aws_instance.envelope_east.associate_public_ip_address == false
    error_message = "appliances must use the one regional NAT instead of public addresses"
  }

  assert {
    condition = (
      output.instance_ids == { west = aws_instance.envelope_west.id, east = aws_instance.envelope_east.id } &&
      output.cost_profile.profile == "directional-lane-acceptance" &&
      output.cost_profile.resource_counts.nat_gateways == 2 &&
      output.cost_profile.resource_counts.gateway_load_balancers == 2 &&
      output.cost_profile.resource_counts.gwlbe_endpoints == 2 &&
      output.cost_profile.resource_counts.semantic_lane_routes == 4 &&
      output.cost_profile.resource_counts.appliance_instances == 2 &&
      output.cost_profile.resource_counts.workload_instances == 4 &&
      output.cost_profile.resource_counts.network_acls == 2 &&
      output.cost_profile.resource_counts.vpc_flow_logs == 2 &&
      output.cost_profile.resource_counts.cloudwatch_log_groups == 2 &&
      output.cost_profile.resource_counts.flow_log_iam_roles == 1 &&
      output.cost_profile.resource_counts.regional_targets == { west = 1, east = 1 }
    )
    error_message = "the exact two-region directional-lane topology and evidence resource count must remain explicit"
  }

  assert {
    condition = (
      output.e2e_load_profile == var.e2e_load_profile &&
      toset(keys(output.e2e_load_profile)) == toset([
        "profile_id",
        "approved_at",
        "safe_inner_mtu",
        "maximum_tcp_mss",
        "sustained_tcp_duration_seconds",
        "minimum_sustained_tcp_bytes",
        "iperf_duration_seconds",
        "minimum_throughput_mbps",
        "concurrent_duration_seconds",
        "concurrent_tcp_flows",
        "concurrent_udp_flows",
        "maximum_udp_loss_percent",
        "maximum_p99_latency_ms",
      ])
    )
    error_message = "the reviewed E2E load profile must be emitted verbatim with exactly the protected fields"
  }

  assert {
    condition     = output.artifact_identity.sha256 == var.artifact_sha256 && output.artifact_identity.ec2_arch == "x86_64"
    error_message = "artifact identity must carry the reviewed digest and mapped EC2 architecture"
  }

  assert {
    condition = (
      startswith(nonsensitive(module.tailscale_client_west.rendered), "H4sI") &&
      startswith(nonsensitive(module.tailscale_client_east.rendered), "H4sI") &&
      local.west_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
      local.east_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
      local.west_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes &&
      local.east_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes &&
      strcontains(local.west_auth_resolver, var.west_tailscale_secret_arn) &&
      strcontains(local.east_auth_resolver, var.east_tailscale_secret_arn) &&
      !strcontains(local.west_auth_resolver, "tskey-auth-") &&
      !strcontains(local.east_auth_resolver, "tskey-auth-") &&
      strcontains(local.west_bootstrap, "tcpdump") &&
      strcontains(local.east_bootstrap, "tcpdump")
    )
    error_message = "rendered MIME must be gzip-compressed within both EC2 limits, use regional SSM references, and include the bounded capture tool"
  }


  assert {
    condition = (
      local.tailscale_packages.amd64.url == "https://pkgs.tailscale.com/stable/amazon-linux/2023/x86_64/tailscale_1.80.3_x86_64.rpm" &&
      local.tailscale_packages.amd64.sha256 == "aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2"
    )
    error_message = "rendered MIME inputs must install only the exact checksummed Tailscale package before auth"
  }

  assert {
    condition = (
      strcontains(output.appliance_runtime_policy_json.west, var.west_tailscale_secret_arn) &&
      !strcontains(output.appliance_runtime_policy_json.west, var.east_tailscale_secret_arn) &&
      strcontains(output.appliance_runtime_policy_json.east, var.east_tailscale_secret_arn) &&
      !strcontains(output.appliance_runtime_policy_json.east, var.west_tailscale_secret_arn) &&
      strcontains(output.appliance_runtime_policy_json.west, "kms:EncryptionContext:PARAMETER_ARN") &&
      strcontains(output.appliance_runtime_policy_json.east, "kms:EncryptionContext:PARAMETER_ARN")
    )
    error_message = "each appliance policy must be site-isolated with exact SSM/KMS encryption context"
  }
}

run "second_name_is_disjoint" {
  command = plan

  variables {
    name                      = "envelope-other"
    west_tailscale_secret_arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-other/tailscale-auth"
    east_tailscale_secret_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-other/tailscale-auth"
  }

  assert {
    condition = (
      aws_lb.west.name == "envelope-other-west-gwlb" &&
      aws_iam_role.appliance_west.name == "envelope-other-west-appliance" &&
      startswith(aws_s3_bucket.artifact.bucket, "envelope-other-")
    )
    error_message = "run-scoped names must derive from the validated name input"
  }
}

run "reject_overlong_name" {
  command = plan

  variables {
    name = "envelope-name-is-too-long"
  }

  expect_failures = [var.name]
}

run "reject_unsafe_load_profile_id" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      profile_id = "unsafe profile!"
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_noncanonical_load_profile_approval" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      approved_at = "2026-08-20T10:00:00+00:00"
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_fractional_load_profile_integer" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      concurrent_tcp_flows = 4.5
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_wrong_load_profile_mtu" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      safe_inner_mtu = 1279
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_unsafe_load_profile_mss" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      maximum_tcp_mss = 1241
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_load_profile_duration_bound" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      sustained_tcp_duration_seconds = 2
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_nonpositive_load_profile_throughput" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      minimum_throughput_mbps = 0
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_load_profile_udp_loss_bound" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      maximum_udp_loss_percent = 100.001
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_nonpositive_load_profile_latency" {
  command = plan

  variables {
    e2e_load_profile = merge(run.fresh_mocked_apply.e2e_load_profile, {
      maximum_p99_latency_ms = 0
    })
  }

  expect_failures = [var.e2e_load_profile]
}

run "reject_wrong_az_cardinality" {
  command = plan

  variables {
    west_azs = {
      a = "us-west-2a"
    }
  }

  expect_failures = [var.west_azs]
}

run "reject_non_singleton_gwlb_return_role" {
  command = plan

  variables {
    envelope_gwlb_return_cidrs = {
      west = ["172.16.0.0/24", "172.16.1.0/24"]
      east = ["172.17.1.0/24"]
    }
  }

  expect_failures = [var.envelope_gwlb_return_cidrs]
}

run "reject_non_singleton_local_delivery_role" {
  command = plan

  variables {
    envelope_local_delivery_cidrs = {
      west = ["172.16.1.0/24"]
      east = []
    }
  }

  expect_failures = [var.envelope_local_delivery_cidrs]
}

run "reject_multiple_targets" {
  command = plan

  variables {
    appliance_target_count = 2
  }

  expect_failures = [var.appliance_target_count]
}

run "reject_duplicate_site_roles" {
  command = plan

  variables {
    envelope_local_delivery_cidrs = {
      west = ["172.16.0.0/24"]
      east = ["172.17.0.0/24"]
    }
  }

  expect_failures = [terraform_data.input_validation]
}

run "reject_overlapping_site_roles" {
  command = plan

  variables {
    envelope_local_delivery_cidrs = {
      west = ["172.16.0.128/25"]
      east = ["172.17.0.0/24"]
    }
  }

  expect_failures = [terraform_data.input_validation]
}

run "reject_architecture_mismatch" {
  command = plan

  override_data {
    target = data.aws_ami.west
    values = {
      architecture = "arm64"
    }
  }

  expect_failures = [
    aws_instance.envelope_west,
    aws_instance.workload_west["initiator"],
    aws_instance.workload_west["responder"],
  ]
}
