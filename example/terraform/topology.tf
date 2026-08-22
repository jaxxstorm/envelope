resource "terraform_data" "input_validation" {
  input = var.symmetric_topology

  lifecycle {
    precondition {
      condition = alltrue([
        for site, topology in local.sites :
        toset(topology.local_site_cidrs) == toset(values(topology.workload_subnet_cidrs)) &&
        toset(topology.remote_site_cidrs) == toset(local.sites[site == "west" ? "east" : "west"].local_site_cidrs) &&
        length(setintersection(toset(topology.local_site_cidrs), toset(topology.remote_site_cidrs))) == 0
      ])
      error_message = "Local site CIDRs must exactly cover local workloads, equal the peer remote CIDRs, and remain disjoint."
    }
    precondition {
      condition     = var.estimated_fixed_hourly_usd <= var.approved_max_fixed_hourly_usd
      error_message = "The reviewed HA topology exceeds its approved hourly cost ceiling."
    }
  }
}

resource "aws_vpc" "west" {
  cidr_block           = local.sites.west.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.common_tags, { Name = "${var.name}-west-vpc", Site = "west" })
  depends_on           = [terraform_data.input_validation]
}
resource "aws_vpc" "east" {
  provider             = aws.east
  cidr_block           = local.sites.east.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.common_tags, { Name = "${var.name}-east-vpc", Site = "east" })
  depends_on           = [terraform_data.input_validation]
}
resource "aws_internet_gateway" "west" {
  vpc_id = aws_vpc.west.id
  tags   = merge(local.common_tags, { Name = "${var.name}-west-igw" })
}
resource "aws_internet_gateway" "east" {
  provider = aws.east
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-igw" })
}

resource "aws_subnet" "workload_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.workload_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-workload-${each.key}", Role = "workload", ZoneKey = each.key })
}
resource "aws_subnet" "workload_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.workload_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-workload-${each.key}", Role = "workload", ZoneKey = each.key })
}
resource "aws_subnet" "ingress_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.ingress_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-ingress-${each.key}", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_subnet" "ingress_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.ingress_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-ingress-${each.key}", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_subnet" "gwlbe_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.gwlbe_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-gwlbe-${each.key}", Role = "gwlbe", ZoneKey = each.key })
}
resource "aws_subnet" "gwlbe_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.gwlbe_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-gwlbe-${each.key}", Role = "gwlbe", ZoneKey = each.key })
}
resource "aws_subnet" "gwlb_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.gwlb_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-gwlb-${each.key}", Role = "gwlb", ZoneKey = each.key })
}
resource "aws_subnet" "gwlb_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.gwlb_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-gwlb-${each.key}", Role = "gwlb", ZoneKey = each.key })
}
resource "aws_subnet" "target_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.target_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-target-${each.key}", Role = "target", ZoneKey = each.key })
}
resource "aws_subnet" "target_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.target_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-target-${each.key}", Role = "target", ZoneKey = each.key })
}
resource "aws_subnet" "management_west" {
  vpc_id            = aws_vpc.west.id
  availability_zone = local.sites.west.azs[sort(keys(local.sites.west.azs))[0]]
  cidr_block        = local.sites.west.management_subnet_cidr
  tags              = merge(local.common_tags, { Name = "${var.name}-west-management", Role = "management" })
}
resource "aws_subnet" "management_east" {
  provider          = aws.east
  vpc_id            = aws_vpc.east.id
  availability_zone = local.sites.east.azs[sort(keys(local.sites.east.azs))[0]]
  cidr_block        = local.sites.east.management_subnet_cidr
  tags              = merge(local.common_tags, { Name = "${var.name}-east-management", Role = "management" })
}

resource "aws_route_table" "workload_west" {
  for_each = local.sites.west.azs
  vpc_id   = aws_vpc.west.id
  tags     = merge(local.common_tags, { Name = "${var.name}-west-workload-${each.key}", Role = "workload", ZoneKey = each.key })
}
resource "aws_route_table" "workload_east" {
  provider = aws.east
  for_each = local.sites.east.azs
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-workload-${each.key}", Role = "workload", ZoneKey = each.key })
}
resource "aws_route_table" "ingress_west" {
  for_each = local.sites.west.azs
  vpc_id   = aws_vpc.west.id
  tags     = merge(local.common_tags, { Name = "${var.name}-west-ingress-${each.key}", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_route_table" "ingress_east" {
  provider = aws.east
  for_each = local.sites.east.azs
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-ingress-${each.key}", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_route_table" "gwlbe_west" {
  for_each = local.sites.west.azs
  vpc_id   = aws_vpc.west.id
  tags     = merge(local.common_tags, { Name = "${var.name}-west-gwlbe-${each.key}", Role = "gwlbe", ZoneKey = each.key })
}
resource "aws_route_table" "gwlbe_east" {
  provider = aws.east
  for_each = local.sites.east.azs
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-gwlbe-${each.key}", Role = "gwlbe", ZoneKey = each.key })
}
resource "aws_route_table" "target_west" {
  for_each = local.sites.west.azs
  vpc_id   = aws_vpc.west.id
  tags     = merge(local.common_tags, { Name = "${var.name}-west-target-${each.key}", Role = "target", ZoneKey = each.key })
}
resource "aws_route_table" "target_east" {
  provider = aws.east
  for_each = local.sites.east.azs
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-target-${each.key}", Role = "target", ZoneKey = each.key })
}
resource "aws_route_table" "management_west" {
  vpc_id = aws_vpc.west.id
  tags   = merge(local.common_tags, { Name = "${var.name}-west-management", Role = "management" })
}
resource "aws_route_table" "management_east" {
  provider = aws.east
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-management", Role = "management" })
}

resource "aws_route_table_association" "workload_west" {
  for_each       = local.sites.west.azs
  subnet_id      = aws_subnet.workload_west[each.key].id
  route_table_id = aws_route_table.workload_west[each.key].id
}
resource "aws_route_table_association" "workload_east" {
  provider       = aws.east
  for_each       = local.sites.east.azs
  subnet_id      = aws_subnet.workload_east[each.key].id
  route_table_id = aws_route_table.workload_east[each.key].id
}
resource "aws_route_table_association" "ingress_west" {
  for_each       = local.sites.west.azs
  subnet_id      = aws_subnet.ingress_west[each.key].id
  route_table_id = aws_route_table.ingress_west[each.key].id
}
resource "aws_route_table_association" "ingress_east" {
  provider       = aws.east
  for_each       = local.sites.east.azs
  subnet_id      = aws_subnet.ingress_east[each.key].id
  route_table_id = aws_route_table.ingress_east[each.key].id
}
resource "aws_route_table_association" "gwlbe_west" {
  for_each       = local.sites.west.azs
  subnet_id      = aws_subnet.gwlbe_west[each.key].id
  route_table_id = aws_route_table.gwlbe_west[each.key].id
}
resource "aws_route_table_association" "gwlbe_east" {
  provider       = aws.east
  for_each       = local.sites.east.azs
  subnet_id      = aws_subnet.gwlbe_east[each.key].id
  route_table_id = aws_route_table.gwlbe_east[each.key].id
}
resource "aws_route_table_association" "target_west" {
  for_each       = local.sites.west.azs
  subnet_id      = aws_subnet.target_west[each.key].id
  route_table_id = aws_route_table.target_west[each.key].id
}
resource "aws_route_table_association" "target_east" {
  provider       = aws.east
  for_each       = local.sites.east.azs
  subnet_id      = aws_subnet.target_east[each.key].id
  route_table_id = aws_route_table.target_east[each.key].id
}
resource "aws_route_table_association" "management_west" {
  subnet_id      = aws_subnet.management_west.id
  route_table_id = aws_route_table.management_west.id
}
resource "aws_route_table_association" "management_east" {
  provider       = aws.east
  subnet_id      = aws_subnet.management_east.id
  route_table_id = aws_route_table.management_east.id
}
resource "aws_eip" "nat_west" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.west]
}
resource "aws_eip" "nat_east" {
  provider   = aws.east
  domain     = "vpc"
  depends_on = [aws_internet_gateway.east]
}
resource "aws_nat_gateway" "west" {
  allocation_id = aws_eip.nat_west.id
  subnet_id     = aws_subnet.management_west.id
}
resource "aws_nat_gateway" "east" {
  provider      = aws.east
  allocation_id = aws_eip.nat_east.id
  subnet_id     = aws_subnet.management_east.id
}
resource "aws_route" "management_default_west" {
  route_table_id         = aws_route_table.management_west.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.west.id
}
resource "aws_route" "management_default_east" {
  provider               = aws.east
  route_table_id         = aws_route_table.management_east.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.east.id
}
resource "aws_route" "target_default_west" {
  for_each               = local.sites.west.azs
  route_table_id         = aws_route_table.target_west[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}
resource "aws_route" "target_default_east" {
  provider               = aws.east
  for_each               = local.sites.east.azs
  route_table_id         = aws_route_table.target_east[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.east.id
}
resource "aws_route" "ingress_default_west" {
  for_each               = local.sites.west.azs
  route_table_id         = aws_route_table.ingress_west[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}
resource "aws_route" "ingress_default_east" {
  provider               = aws.east
  for_each               = local.sites.east.azs
  route_table_id         = aws_route_table.ingress_east[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.east.id
}

resource "aws_lb" "west" {
  name                             = "${var.name}-west-gwlb"
  load_balancer_type               = "gateway"
  subnets                          = [for key in sort(keys(local.sites.west.azs)) : aws_subnet.gwlb_west[key].id]
  enable_cross_zone_load_balancing = true
  tags                             = merge(local.common_tags, { Name = "${var.name}-west-gwlb", Site = "west" })
}
resource "aws_lb" "east" {
  provider                         = aws.east
  name                             = "${var.name}-east-gwlb"
  load_balancer_type               = "gateway"
  subnets                          = [for key in sort(keys(local.sites.east.azs)) : aws_subnet.gwlb_east[key].id]
  enable_cross_zone_load_balancing = true
  tags                             = merge(local.common_tags, { Name = "${var.name}-east-gwlb", Site = "east" })
}
resource "aws_lb_target_group" "west" {
  name        = "${var.name}-west-gwlb-tg"
  port        = 6081
  protocol    = "GENEVE"
  target_type = "instance"
  vpc_id      = aws_vpc.west.id
  health_check {
    protocol = "HTTP"
    path     = "/healthz"
    port     = "9090"
  }
}
resource "aws_lb_target_group" "east" {
  provider    = aws.east
  name        = "${var.name}-east-gwlb-tg"
  port        = 6081
  protocol    = "GENEVE"
  target_type = "instance"
  vpc_id      = aws_vpc.east.id
  health_check {
    protocol = "HTTP"
    path     = "/healthz"
    port     = "9090"
  }
}
resource "aws_lb_listener" "west" {
  load_balancer_arn = aws_lb.west.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.west.arn
  }
}
resource "aws_lb_listener" "east" {
  provider          = aws.east
  load_balancer_arn = aws_lb.east.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.east.arn
  }
}
resource "aws_vpc_endpoint_service" "west" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.west.arn]
}
resource "aws_vpc_endpoint_service" "east" {
  provider                   = aws.east
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.east.arn]
}
resource "aws_vpc_endpoint" "west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  service_name      = aws_vpc_endpoint_service.west.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_west[each.key].id]
}
resource "aws_vpc_endpoint" "east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  service_name      = aws_vpc_endpoint_service.east.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_east[each.key].id]
}
resource "aws_route" "workload_to_remote_west" {
  for_each = {
    for pair in setproduct(toset(keys(local.sites.west.azs)), toset(local.sites.west.remote_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.workload_west[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.west[each.value.az_key].id
}
resource "aws_route" "workload_to_remote_east" {
  provider = aws.east
  for_each = {
    for pair in setproduct(toset(keys(local.sites.east.azs)), toset(local.sites.east.remote_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.workload_east[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.east[each.value.az_key].id
}
resource "aws_route" "ingress_to_local_west" {
  for_each = {
    for pair in setproduct(toset(keys(local.sites.west.azs)), toset(local.sites.west.local_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.ingress_west[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.west[each.value.az_key].id
}
resource "aws_route" "ingress_to_local_east" {
  provider = aws.east
  for_each = {
    for pair in setproduct(toset(keys(local.sites.east.azs)), toset(local.sites.east.local_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.ingress_east[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.east[each.value.az_key].id
}

resource "aws_security_group" "target_west" {
  name   = "${var.name}-west-target"
  vpc_id = aws_vpc.west.id
  ingress {
    from_port   = 6081
    to_port     = 6081
    protocol    = "udp"
    cidr_blocks = [local.sites.west.vpc_cidr]
  }
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [local.sites.west.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-west-target", Role = "target" })
}
resource "aws_security_group" "target_east" {
  provider = aws.east
  name     = "${var.name}-east-target"
  vpc_id   = aws_vpc.east.id
  ingress {
    from_port   = 6081
    to_port     = 6081
    protocol    = "udp"
    cidr_blocks = [local.sites.east.vpc_cidr]
  }
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [local.sites.east.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-east-target", Role = "target" })
}
resource "aws_security_group" "ingress_west" {
  name   = "${var.name}-west-ingress"
  vpc_id = aws_vpc.west.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-west-ingress", Role = "tailnet-ingress" })
}
resource "aws_security_group" "ingress_east" {
  provider = aws.east
  name     = "${var.name}-east-ingress"
  vpc_id   = aws_vpc.east.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-east-ingress", Role = "tailnet-ingress" })
}

locals {
  west_target_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", {
    site                  = "west"
    run_name              = var.name
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
    tailscale_version     = var.tailscale_version
    config_version        = var.symmetric_topology.version
    tun_name              = var.envelope_tun_name
    tailscale_iface       = var.envelope_tailscale_iface
    underlay_iface        = var.envelope_underlay_interface
    routing_mode          = var.envelope_routing_mode
    local_site_cidrs      = join(",", local.sites.west.local_site_cidrs)
    remote_site_cidrs     = join(",", local.sites.west.remote_site_cidrs)
    routing_table_id      = var.envelope_routing_table_id
    routing_rule_priority = var.envelope_routing_rule_priority
  })
  east_target_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", {
    site                  = "east"
    run_name              = var.name
    artifact_region       = var.east_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
    tailscale_version     = var.tailscale_version
    config_version        = var.symmetric_topology.version
    tun_name              = var.envelope_tun_name
    tailscale_iface       = var.envelope_tailscale_iface
    underlay_iface        = var.envelope_underlay_interface
    routing_mode          = var.envelope_routing_mode
    local_site_cidrs      = join(",", local.sites.east.local_site_cidrs)
    remote_site_cidrs     = join(",", local.sites.east.remote_site_cidrs)
    routing_table_id      = var.envelope_routing_table_id
    routing_rule_priority = var.envelope_routing_rule_priority
  })
  target_service_env = {
    west = local.west_target_bootstrap
    east = local.east_target_bootstrap
  }
}

resource "aws_instance" "envelope_target_west" {
  for_each                    = local.sites.west.target_az_keys
  ami                         = var.west_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.target_west[each.key].id
  vpc_security_group_ids      = [aws_security_group.target_west.id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_west.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_target_west[each.key].rendered
  tags                        = merge(local.common_tags, { Name = "${var.name}-west-target-${each.key}", Site = "west", Role = "target", ZoneKey = each.key })
}
resource "aws_instance" "envelope_target_east" {
  provider                    = aws.east
  for_each                    = local.sites.east.target_az_keys
  ami                         = var.east_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.target_east[each.key].id
  vpc_security_group_ids      = [aws_security_group.target_east.id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_east.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_target_east[each.key].rendered
  tags                        = merge(local.common_tags, { Name = "${var.name}-east-target-${each.key}", Site = "east", Role = "target", ZoneKey = each.key })
}
resource "aws_instance" "tailnet_ingress_west" {
  for_each                    = local.sites.west.ingress_router_az_keys
  ami                         = var.west_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.ingress_west[each.key].id
  vpc_security_group_ids      = [aws_security_group.ingress_west.id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_west.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_ingress_west[each.key].rendered
  tags                        = merge(local.common_tags, { Name = "${var.name}-west-ingress-${each.key}", Site = "west", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_instance" "tailnet_ingress_east" {
  provider                    = aws.east
  for_each                    = local.sites.east.ingress_router_az_keys
  ami                         = var.east_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.ingress_east[each.key].id
  vpc_security_group_ids      = [aws_security_group.ingress_east.id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_east.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_ingress_east[each.key].rendered
  tags                        = merge(local.common_tags, { Name = "${var.name}-east-ingress-${each.key}", Site = "east", Role = "tailnet-ingress", ZoneKey = each.key })
}
resource "aws_lb_target_group_attachment" "west" {
  for_each         = aws_instance.envelope_target_west
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = each.value.id
}
resource "aws_lb_target_group_attachment" "east" {
  provider         = aws.east
  for_each         = aws_instance.envelope_target_east
  target_group_arn = aws_lb_target_group.east.arn
  target_id        = each.value.id
}

output "envelope_runtime_config" {
  value = {
    for site, topology in local.sites : site => {
      config_version    = var.symmetric_topology.version
      local_site_cidrs  = topology.local_site_cidrs
      remote_site_cidrs = topology.remote_site_cidrs
    }
  }
}
output "cost_profile" {
  value = {
    profile                    = "symmetric-gwlb-ha-v2"
    estimated_fixed_hourly_usd = var.estimated_fixed_hourly_usd
    approved_max_hourly_usd    = var.approved_max_fixed_hourly_usd
    resource_counts = {
      gwlbe_endpoints  = length(aws_vpc_endpoint.west) + length(aws_vpc_endpoint.east)
      target_instances = { west = length(aws_instance.envelope_target_west), east = length(aws_instance.envelope_target_east) }
      ingress_routers  = { west = length(aws_instance.tailnet_ingress_west), east = length(aws_instance.tailnet_ingress_east) }
    }
  }
}
