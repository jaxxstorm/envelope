data "aws_ami" "main_west" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "architecture"
    values = [var.architecture]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*"]
  }
}

data "aws_ami" "main_east" {
  provider    = aws.east
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "architecture"
    values = [var.architecture]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*"]
  }
}

resource "aws_security_group" "envelope_west" {
  name        = "${var.name}-west"
  description = "Used by ${var.name}-west in subnet ${module.vpc_west.public_subnets[0]}"
  vpc_id      = module.vpc_west.vpc_id

  ingress {
    description = "Allow UDP traffic to Tailscale for direct connections"
    from_port   = 41641
    to_port     = 41641
    protocol    = "UDP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow UDP traffic for GWLB GENEVE encapsulation"
    from_port   = 6081
    to_port     = 6081
    protocol    = "UDP"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "Allow GWLB health checks to Envelope /healthz"
    from_port   = 9090
    to_port     = 9090
    protocol    = "TCP"
    cidr_blocks = [var.west_vpc_cidr]
  }

  egress {
    description      = "Unrestricted egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-west"
    Site = "west"
  })
}

resource "aws_security_group" "envelope_east" {
  provider    = aws.east
  name        = "${var.name}-east"
  description = "Used by ${var.name}-east in subnet ${module.vpc_east.public_subnets[0]}"
  vpc_id      = module.vpc_east.vpc_id

  ingress {
    description = "Allow UDP traffic to Tailscale for direct connections"
    from_port   = 41641
    to_port     = 41641
    protocol    = "UDP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow UDP traffic for GWLB GENEVE encapsulation"
    from_port   = 6081
    to_port     = 6081
    protocol    = "UDP"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "Allow GWLB health checks to Envelope /healthz"
    from_port   = 9090
    to_port     = 9090
    protocol    = "TCP"
    cidr_blocks = [var.east_vpc_cidr]
  }

  egress {
    description      = "Unrestricted egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-east"
    Site = "east"
  })
}

resource "aws_instance" "envelope_west" {
  ami                    = data.aws_ami.main_west.id
  instance_type          = var.instance_type
  subnet_id              = module.vpc_west.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.envelope_west.id]
  iam_instance_profile   = aws_iam_instance_profile.main.name

  ebs_optimized     = true
  source_dest_check = false

  user_data_base64            = module.tailscale_client_west.rendered
  associate_public_ip_address = true
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(var.tags, {
    Name = "${var.name}-west"
    Site = "west"
  })
}

resource "aws_instance" "envelope_east" {
  provider               = aws.east
  ami                    = data.aws_ami.main_east.id
  instance_type          = var.instance_type
  subnet_id              = module.vpc_east.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.envelope_east.id]
  iam_instance_profile   = aws_iam_instance_profile.main.name

  ebs_optimized     = true
  source_dest_check = false

  user_data_base64            = module.tailscale_client_east.rendered
  associate_public_ip_address = true
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(var.tags, {
    Name = "${var.name}-east"
    Site = "east"
  })
}

resource "aws_security_group" "test_west" {
  name        = "${var.name}-test-west"
  description = "Used by ${var.name}-test-west in subnet ${module.vpc_west.private_subnets[0]}"
  vpc_id      = module.vpc_west.vpc_id

  ingress {
    description = "Allow ICMP from east VPC for site-to-site tests"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  ingress {
    description = "Allow iperf3 from east VPC for throughput tests"
    from_port   = 5201
    to_port     = 5201
    protocol    = "tcp"
    cidr_blocks = [var.east_vpc_cidr]
  }

  egress {
    description      = "Unrestricted egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-test-west"
    Site = "west"
    Role = "test"
  })
}

resource "aws_security_group" "test_east" {
  provider    = aws.east
  name        = "${var.name}-test-east"
  description = "Used by ${var.name}-test-east in subnet ${module.vpc_east.private_subnets[0]}"
  vpc_id      = module.vpc_east.vpc_id

  ingress {
    description = "Allow ICMP from west VPC for site-to-site tests"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  ingress {
    description = "Allow iperf3 from west VPC for throughput tests"
    from_port   = 5201
    to_port     = 5201
    protocol    = "tcp"
    cidr_blocks = [var.west_vpc_cidr]
  }

  egress {
    description      = "Unrestricted egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-test-east"
    Site = "east"
    Role = "test"
  })
}

resource "aws_instance" "test_west" {
  ami                    = data.aws_ami.main_west.id
  instance_type          = var.test_instance_type
  subnet_id              = module.vpc_west.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.test_west.id]
  iam_instance_profile   = aws_iam_instance_profile.main.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(var.tags, {
    Name = "${var.name}-test-west"
    Site = "west"
    Role = "test"
  })
}

resource "aws_instance" "test_east" {
  provider               = aws.east
  ami                    = data.aws_ami.main_east.id
  instance_type          = var.test_instance_type
  subnet_id              = module.vpc_east.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.test_east.id]
  iam_instance_profile   = aws_iam_instance_profile.main.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(var.tags, {
    Name = "${var.name}-test-east"
    Site = "east"
    Role = "test"
  })
}

output "instance_ids" {
  value = {
    west = aws_instance.envelope_west.id
    east = aws_instance.envelope_east.id
  }
}

output "instance_public_ips" {
  value = {
    west = aws_instance.envelope_west.public_ip
    east = aws_instance.envelope_east.public_ip
  }
}

output "test_instance_ids" {
  value = {
    west = aws_instance.test_west.id
    east = aws_instance.test_east.id
  }
}

output "test_instance_private_ips" {
  value = {
    west = aws_instance.test_west.private_ip
    east = aws_instance.test_east.private_ip
  }
}

output "test_ssm_start_session_commands" {
  value = {
    west = "aws ssm start-session --region ${var.west_region} --target ${aws_instance.test_west.id}"
    east = "aws ssm start-session --region ${var.east_region} --target ${aws_instance.test_east.id}"
  }
}

output "envelope_runtime_flags" {
  value = {
    routing_mode          = var.envelope_routing_mode
    tailscale_iface       = var.envelope_tailscale_iface
    protected_cidrs       = var.envelope_protected_cidrs
    routing_table_id      = var.envelope_routing_table_id
    routing_rule_priority = var.envelope_routing_rule_priority
  }
}
