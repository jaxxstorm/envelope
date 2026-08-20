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

resource "aws_security_group" "test_west" {
  name        = "${var.name}-west-test"
  description = "Run-owned west workload probes"
  vpc_id      = aws_vpc.west.id

  ingress {
    description = "ICMP acceptance from east"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "TCP acceptance from east"
    from_port   = 5201
    to_port     = 5201
    protocol    = "tcp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "UDP acceptance from east"
    from_port   = 5201
    to_port     = 5201
    protocol    = "udp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  egress {
    description = "Required SSM, package, and test egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-west-test", Site = "west", Role = "test" }
}

resource "aws_security_group" "test_east" {
  provider = aws.east

  name        = "${var.name}-east-test"
  description = "Run-owned east workload probes"
  vpc_id      = aws_vpc.east.id

  ingress {
    description = "ICMP acceptance from west"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "TCP acceptance from west"
    from_port   = 5201
    to_port     = 5201
    protocol    = "tcp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "UDP acceptance from west"
    from_port   = 5201
    to_port     = 5201
    protocol    = "udp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  egress {
    description = "Required SSM, package, and test egress through NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-east-test", Site = "east", Role = "test" }
}

locals {
  workload_user_data = base64encode(<<-EOT
    #!/usr/bin/env bash
    set -euo pipefail
    dnf install -y iperf3 jq
    systemctl enable --now amazon-ssm-agent
  EOT
  )
}

resource "aws_instance" "test_west" {
  ami                         = var.west_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_west[local.west_primary_key].id
  vpc_security_group_ids      = [aws_security_group.test_west.id]
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

  tags = { Name = "${var.name}-west-test", Site = "west", Role = "test", ZoneKey = local.west_primary_key }

  depends_on = [aws_iam_role_policy.workload_runtime_west, aws_route.workload_default_west]

  lifecycle {
    precondition {
      condition     = data.aws_ami.west.architecture == local.ec2_architecture && contains(data.aws_ec2_instance_type.west_test.supported_architectures, local.ec2_architecture)
      error_message = "The west test AMI or instance type is incompatible with the reviewed architecture."
    }
  }
}

resource "aws_instance" "test_east" {
  provider = aws.east

  ami                         = var.east_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_east[local.east_primary_key].id
  vpc_security_group_ids      = [aws_security_group.test_east.id]
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

  tags = { Name = "${var.name}-east-test", Site = "east", Role = "test", ZoneKey = local.east_primary_key }

  depends_on = [aws_iam_role_policy.workload_runtime_east, aws_route.workload_default_east]

  lifecycle {
    precondition {
      condition     = data.aws_ami.east.architecture == local.ec2_architecture && contains(data.aws_ec2_instance_type.east_test.supported_architectures, local.ec2_architecture)
      error_message = "The east test AMI or instance type is incompatible with the reviewed architecture."
    }
  }
}

output "instance_ids" {
  value = { west = aws_instance.envelope_west.id, east = aws_instance.envelope_east.id }
}

output "test_instance_ids" {
  value = { west = aws_instance.test_west.id, east = aws_instance.test_east.id }
}

output "test_instance_private_ips" {
  value = { west = aws_instance.test_west.private_ip, east = aws_instance.test_east.private_ip }
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

output "cost_profile" {
  value = {
    profile                    = "single-flow-owner-acceptance"
    estimated_fixed_hourly_usd = var.estimated_fixed_hourly_usd
    approved_max_hourly_usd    = var.approved_max_fixed_hourly_usd
    expires_at                 = var.expires_at
    resource_counts = {
      vpcs                   = 2
      nat_gateways           = 2
      elastic_ips            = 2
      gateway_load_balancers = 2
      gwlbe_endpoints        = length(var.west_azs) + length(var.east_azs)
      appliance_instances    = 2
      workload_instances     = 2
      artifact_buckets       = 1
      regional_targets       = { west = 1, east = 1 }
    }
    excludes = "data processing, transfer, storage, requests, and taxes"
  }
}
