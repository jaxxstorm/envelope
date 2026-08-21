data "aws_ami" "west" {
  owners = ["amazon"]

  filter {
    name   = "image-id"
    values = [var.west_ami_id]
  }
}

data "aws_ami" "east" {
  provider = aws.east
  owners   = ["amazon"]

  filter {
    name   = "image-id"
    values = [var.east_ami_id]
  }
}

data "aws_ec2_instance_type" "west_appliance" {
  instance_type = var.instance_type
}

data "aws_ec2_instance_type" "east_appliance" {
  provider      = aws.east
  instance_type = var.instance_type
}

data "aws_ec2_instance_type" "west_test" {
  instance_type = var.test_instance_type
}

data "aws_ec2_instance_type" "east_test" {
  provider      = aws.east
  instance_type = var.test_instance_type
}

resource "aws_security_group" "envelope_west" {
  name        = "${var.name}-west-appliance"
  description = "Run-owned Envelope appliance traffic"
  vpc_id      = aws_vpc.west.id

  ingress {
    description = "GWLB GENEVE"
    from_port   = 6081
    to_port     = 6081
    protocol    = "udp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "GWLB health"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "Forward local responder returns"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [local.west_responder_cidr]
  }

  egress {
    description = "Required SSM, S3, package, and Tailnet egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }
}

resource "aws_security_group" "envelope_east" {
  provider = aws.east

  name        = "${var.name}-east-appliance"
  description = "Run-owned Envelope appliance traffic"
  vpc_id      = aws_vpc.east.id

  ingress {
    description = "GWLB GENEVE"
    from_port   = 6081
    to_port     = 6081
    protocol    = "udp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "GWLB health"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "Forward local responder returns"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [local.east_responder_cidr]
  }

  egress {
    description = "Required SSM, S3, package, and Tailnet egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }
}

resource "aws_instance" "envelope_west" {
  ami                         = var.west_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.appliance_west.id
  vpc_security_group_ids      = [aws_security_group.envelope_west.id]
  iam_instance_profile        = aws_iam_instance_profile.appliance_west.name
  associate_public_ip_address = false
  ebs_optimized               = true
  source_dest_check           = false
  user_data_base64            = module.tailscale_client_west.rendered
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    volume_size = var.ebs_root_volume_size
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags        = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance", Architecture = var.architecture }
  volume_tags = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }

  depends_on = [
    aws_iam_role_policy.appliance_runtime_west,
    aws_route.appliance_default_west,
    aws_s3_object.envelope,
  ]

  lifecycle {
    precondition {
      condition     = data.aws_ami.west.architecture == local.ec2_architecture
      error_message = "The west AMI architecture does not match the reviewed artifact architecture."
    }
    precondition {
      condition     = contains(data.aws_ec2_instance_type.west_appliance.supported_architectures, local.ec2_architecture)
      error_message = "The west appliance instance type does not support the reviewed architecture."
    }
    precondition {
      condition = (
        local.west_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
        local.west_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes
      )
      error_message = "The gzip-compressed west cloud-init MIME exceeds EC2's 16 KiB raw or base64-encoded user-data limit."
    }
  }
}

resource "aws_instance" "envelope_east" {
  provider = aws.east

  ami                         = var.east_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.appliance_east.id
  vpc_security_group_ids      = [aws_security_group.envelope_east.id]
  iam_instance_profile        = aws_iam_instance_profile.appliance_east.name
  associate_public_ip_address = false
  ebs_optimized               = true
  source_dest_check           = false
  user_data_base64            = module.tailscale_client_east.rendered
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    volume_size = var.ebs_root_volume_size
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags        = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance", Architecture = var.architecture }
  volume_tags = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }

  depends_on = [
    aws_iam_role_policy.appliance_runtime_east,
    aws_route.appliance_default_east,
    aws_s3_object.envelope,
  ]

  lifecycle {
    precondition {
      condition     = data.aws_ami.east.architecture == local.ec2_architecture
      error_message = "The east AMI architecture does not match the reviewed artifact architecture."
    }
    precondition {
      condition     = contains(data.aws_ec2_instance_type.east_appliance.supported_architectures, local.ec2_architecture)
      error_message = "The east appliance instance type does not support the reviewed architecture."
    }
    precondition {
      condition = (
        local.east_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
        local.east_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes
      )
      error_message = "The gzip-compressed east cloud-init MIME exceeds EC2's 16 KiB raw or base64-encoded user-data limit."
    }
  }
}

resource "aws_security_group" "workload_west" {
  for_each = local.west_workloads

  name        = "${var.name}-west-${each.key}"
  description = "Run-owned west ${each.key} workload"
  vpc_id      = aws_vpc.west.id

  dynamic "ingress" {
    for_each = each.key == "responder" ? local.workload_probe_ingress : {}

    content {
      description = "${ingress.value.description} from paired east initiator"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [local.east_initiator_cidr]
    }
  }

  egress {
    description = "Required SSM, package, and test egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key }
}

resource "aws_security_group" "workload_east" {
  provider = aws.east
  for_each = local.east_workloads

  name        = "${var.name}-east-${each.key}"
  description = "Run-owned east ${each.key} workload"
  vpc_id      = aws_vpc.east.id

  dynamic "ingress" {
    for_each = each.key == "responder" ? local.workload_probe_ingress : {}

    content {
      description = "${ingress.value.description} from paired west initiator"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [local.west_initiator_cidr]
    }
  }

  egress {
    description = "Required SSM, package, and test egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key }
}

locals {
  workload_bootstrap = templatefile("${path.module}/cloud-init/workload.sh.tftpl", {
    agent_base64 = base64encode(file("${path.module}/cloud-init/envelope-e2e-agent.py"))
  })
  workload_user_data              = base64gzip(local.workload_bootstrap)
  workload_user_data_base64_bytes = length(local.workload_user_data)
  workload_user_data_raw_bytes = floor(local.workload_user_data_base64_bytes * 3 / 4) - (
    endswith(local.workload_user_data, "==") ? 2 :
    endswith(local.workload_user_data, "=") ? 1 : 0
  )
}

resource "aws_instance" "workload_west" {
  for_each = local.west_workloads

  ami                         = var.west_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_west[each.value.az_key].id
  vpc_security_group_ids      = [aws_security_group.workload_west[each.key].id]
  iam_instance_profile        = aws_iam_instance_profile.workload_west.name
  associate_public_ip_address = false
  user_data_base64            = local.workload_user_data
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags        = { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key }
  volume_tags = { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key }

  depends_on = [aws_iam_role_policy.workload_runtime_west, aws_route.workload_default_west]

  lifecycle {
    precondition {
      condition     = data.aws_ami.west.architecture == local.ec2_architecture && contains(data.aws_ec2_instance_type.west_test.supported_architectures, local.ec2_architecture)
      error_message = "The west workload AMI or instance type is incompatible with the reviewed architecture."
    }
    precondition {
      condition = (
        local.workload_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
        local.workload_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes
      )
      error_message = "The gzip-compressed workload bootstrap exceeds EC2's 16 KiB raw or base64-encoded user-data limit."
    }
  }
}

resource "aws_instance" "workload_east" {
  provider = aws.east
  for_each = local.east_workloads

  ami                         = var.east_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_east[each.value.az_key].id
  vpc_security_group_ids      = [aws_security_group.workload_east[each.key].id]
  iam_instance_profile        = aws_iam_instance_profile.workload_east.name
  associate_public_ip_address = false
  user_data_base64            = local.workload_user_data
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags        = { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key }
  volume_tags = { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key }

  depends_on = [aws_iam_role_policy.workload_runtime_east, aws_route.workload_default_east]

  lifecycle {
    precondition {
      condition     = data.aws_ami.east.architecture == local.ec2_architecture && contains(data.aws_ec2_instance_type.east_test.supported_architectures, local.ec2_architecture)
      error_message = "The east workload AMI or instance type is incompatible with the reviewed architecture."
    }
    precondition {
      condition = (
        local.workload_user_data_raw_bytes <= local.ec2_user_data_raw_limit_bytes &&
        local.workload_user_data_base64_bytes <= local.ec2_user_data_base64_limit_bytes
      )
      error_message = "The gzip-compressed workload bootstrap exceeds EC2's 16 KiB raw or base64-encoded user-data limit."
    }
  }
}

output "instance_ids" {
  value = { west = aws_instance.envelope_west.id, east = aws_instance.envelope_east.id }
}

output "workload_instances" {
  value = {
    west = {
      for role, workload in local.west_workloads : role => {
        instance_id       = aws_instance.workload_west[role].id
        private_ip        = aws_instance.workload_west[role].private_ip
        az_key            = workload.az_key
        availability_zone = var.west_azs[workload.az_key]
        subnet_id         = aws_subnet.workload_west[workload.az_key].id
        cidr              = workload.cidr
        route_table_id    = aws_route_table.workload_west[workload.az_key].id
      }
    }
    east = {
      for role, workload in local.east_workloads : role => {
        instance_id       = aws_instance.workload_east[role].id
        private_ip        = aws_instance.workload_east[role].private_ip
        az_key            = workload.az_key
        availability_zone = var.east_azs[workload.az_key]
        subnet_id         = aws_subnet.workload_east[workload.az_key].id
        cidr              = workload.cidr
        route_table_id    = aws_route_table.workload_east[workload.az_key].id
      }
    }
  }
}

output "envelope_runtime_config" {
  value = {
    west = {
      routing_mode          = var.envelope_routing_mode
      tun_name              = var.envelope_tun_name
      underlay_interface    = var.envelope_underlay_interface
      tailscale_iface       = var.envelope_tailscale_iface
      gwlb_return_cidrs     = var.envelope_gwlb_return_cidrs["west"]
      local_delivery_cidrs  = var.envelope_local_delivery_cidrs["west"]
      remote_tailnet_cidrs  = var.envelope_remote_tailnet_cidrs["west"]
      routing_table_id      = var.envelope_routing_table_id
      routing_rule_priority = var.envelope_routing_rule_priority
      artifact_sha256       = var.artifact_sha256
      artifact_revision     = var.artifact_revision
    }
    east = {
      routing_mode          = var.envelope_routing_mode
      tun_name              = var.envelope_tun_name
      underlay_interface    = var.envelope_underlay_interface
      tailscale_iface       = var.envelope_tailscale_iface
      gwlb_return_cidrs     = var.envelope_gwlb_return_cidrs["east"]
      local_delivery_cidrs  = var.envelope_local_delivery_cidrs["east"]
      remote_tailnet_cidrs  = var.envelope_remote_tailnet_cidrs["east"]
      routing_table_id      = var.envelope_routing_table_id
      routing_rule_priority = var.envelope_routing_rule_priority
      artifact_sha256       = var.artifact_sha256
      artifact_revision     = var.artifact_revision
    }
  }
}

output "e2e_load_profile" {
  description = "Immutable load and transport thresholds embedded verbatim in the reviewed saved plan"
  value       = var.e2e_load_profile
}

output "cost_profile" {
  value = {
    profile                    = "directional-lane-acceptance"
    estimated_fixed_hourly_usd = var.estimated_fixed_hourly_usd
    approved_max_hourly_usd    = var.approved_max_fixed_hourly_usd
    expires_at                 = var.expires_at
    resource_counts = {
      vpcs                   = 2
      nat_gateways           = 2
      elastic_ips            = 2
      gateway_load_balancers = 2
      gwlbe_endpoints        = length(aws_vpc_endpoint.west) + length(aws_vpc_endpoint.east)
      semantic_lane_routes   = 4
      appliance_instances    = 2
      workload_instances     = 4
      artifact_buckets       = 1
      network_acls           = 2
      vpc_flow_logs          = 2
      cloudwatch_log_groups  = 2
      flow_log_iam_roles     = 1
      regional_targets       = { west = 1, east = 1 }
    }
    excludes = "data processing, transfer, log ingestion and storage, requests, and taxes"
  }
}
