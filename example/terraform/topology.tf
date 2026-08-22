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
resource "aws_route" "workload_default_west" {
  for_each               = local.sites.west.azs
  route_table_id         = aws_route_table.workload_west[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}
resource "aws_route" "workload_default_east" {
  provider               = aws.east
  for_each               = local.sites.east.azs
  route_table_id         = aws_route_table.workload_east[each.key].id
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
resource "aws_security_group" "workload_west" {
  for_each = local.workload_roles.west
  name     = "${var.name}-west-${each.key}"
  vpc_id   = aws_vpc.west.id
  dynamic "ingress" {
    for_each = each.key == "responder" ? local.workload_probe_ingress : {}
    content {
      description = "${ingress.value.description} from paired east initiator"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [local.workload_roles.east.initiator.cidr]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key })
}
resource "aws_security_group" "workload_east" {
  provider = aws.east
  for_each = local.workload_roles.east
  name     = "${var.name}-east-${each.key}"
  vpc_id   = aws_vpc.east.id
  dynamic "ingress" {
    for_each = each.key == "responder" ? local.workload_probe_ingress : {}
    content {
      description = "${ingress.value.description} from paired west initiator"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [local.workload_roles.west.initiator.cidr]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key })
}

locals {
  workload_roles = {
    for site, topology in local.sites : site => {
      initiator = {
        az_key = sort(keys(topology.azs))[0]
        cidr   = topology.workload_subnet_cidrs[sort(keys(topology.azs))[0]]
      }
      responder = {
        az_key = sort(keys(topology.azs))[1]
        cidr   = topology.workload_subnet_cidrs[sort(keys(topology.azs))[1]]
      }
    }
  }
  workload_probe_ingress = {
    icmp = { description = "ICMP and MTU probes", protocol = "icmp", from_port = -1, to_port = -1 }
    tcp  = { description = "TCP and iperf3 probes", protocol = "tcp", from_port = 5201, to_port = 5201 }
    udp  = { description = "UDP, MTU, and iperf3 probes", protocol = "udp", from_port = 5201, to_port = 5201 }
  }
  workload_bootstrap = templatefile("${path.module}/cloud-init/workload.sh.tftpl", {
    agent_base64 = base64encode(file("${path.module}/cloud-init/envelope-e2e-agent.py"))
  })
  workload_user_data = base64gzip(local.workload_bootstrap)
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
resource "aws_instance" "workload_west" {
  for_each                    = local.workload_roles.west
  ami                         = var.west_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_west[each.value.az_key].id
  vpc_security_group_ids      = [aws_security_group.workload_west[each.key].id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_west.name
  associate_public_ip_address = false
  user_data_base64            = local.workload_user_data
  user_data_replace_on_change = true
  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key })
  depends_on  = [aws_iam_role_policy.runtime_west, aws_route.workload_default_west, aws_route.workload_to_remote_west]
}
resource "aws_instance" "workload_east" {
  provider                    = aws.east
  for_each                    = local.workload_roles.east
  ami                         = var.east_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.workload_east[each.value.az_key].id
  vpc_security_group_ids      = [aws_security_group.workload_east[each.key].id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_east.name
  associate_public_ip_address = false
  user_data_base64            = local.workload_user_data
  user_data_replace_on_change = true
  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key })
  depends_on  = [aws_iam_role_policy.runtime_east, aws_route.workload_default_east, aws_route.workload_to_remote_east]
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

locals {
  flow_log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}", "$${srcaddr}", "$${dstaddr}",
    "$${srcport}", "$${dstport}", "$${protocol}", "$${packets}", "$${bytes}", "$${start}",
    "$${end}", "$${action}", "$${log-status}", "$${vpc-id}", "$${subnet-id}", "$${instance-id}",
    "$${region}", "$${az-id}", "$${flow-direction}", "$${traffic-path}", "$${pkt-srcaddr}", "$${pkt-dstaddr}",
  ])
}
resource "aws_cloudwatch_log_group" "flow_west" {
  name              = "/aws/vpc-flow-logs/${var.name}/west"
  retention_in_days = 7
  tags              = merge(local.common_tags, { Name = "${var.name}-west-flow-logs", Site = "west", Role = "flow-logs" })
}
resource "aws_cloudwatch_log_group" "flow_east" {
  provider          = aws.east
  name              = "/aws/vpc-flow-logs/${var.name}/east"
  retention_in_days = 7
  tags              = merge(local.common_tags, { Name = "${var.name}-east-flow-logs", Site = "east", Role = "flow-logs" })
}
resource "aws_flow_log" "west" {
  vpc_id                   = aws_vpc.west.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_west.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  log_format               = local.flow_log_format
  tags                     = merge(local.common_tags, { Name = "${var.name}-west-flow-logs", Site = "west", Role = "flow-logs" })
  depends_on               = [aws_iam_role_policy.flow_logs]
}
resource "aws_flow_log" "east" {
  provider                 = aws.east
  vpc_id                   = aws_vpc.east.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_east.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  log_format               = local.flow_log_format
  tags                     = merge(local.common_tags, { Name = "${var.name}-east-flow-logs", Site = "east", Role = "flow-logs" })
  depends_on               = [aws_iam_role_policy.flow_logs]
}

output "instance_ids" {
  value = {
    west = aws_instance.envelope_target_west[sort(keys(aws_instance.envelope_target_west))[0]].id
    east = aws_instance.envelope_target_east[sort(keys(aws_instance.envelope_target_east))[0]].id
  }
}
output "vpc_ids" {
  value = { west = aws_vpc.west.id, east = aws_vpc.east.id }
}
output "gwlb_target_group_arns" {
  value = { west = aws_lb_target_group.west.arn, east = aws_lb_target_group.east.arn }
}
output "gwlb_endpoint_ids" {
  value = {
    west = { for key, endpoint in aws_vpc_endpoint.west : key => endpoint.id }
    east = { for key, endpoint in aws_vpc_endpoint.east : key => endpoint.id }
  }
}
output "workload_instances" {
  value = {
    west = {
      for role, workload in local.workload_roles.west : role => {
        instance_id       = aws_instance.workload_west[role].id
        private_ip        = aws_instance.workload_west[role].private_ip
        az_key            = workload.az_key
        availability_zone = local.sites.west.azs[workload.az_key]
        subnet_id         = aws_subnet.workload_west[workload.az_key].id
        cidr              = workload.cidr
        route_table_id    = aws_route_table.workload_west[workload.az_key].id
      }
    }
    east = {
      for role, workload in local.workload_roles.east : role => {
        instance_id       = aws_instance.workload_east[role].id
        private_ip        = aws_instance.workload_east[role].private_ip
        az_key            = workload.az_key
        availability_zone = local.sites.east.azs[workload.az_key]
        subnet_id         = aws_subnet.workload_east[workload.az_key].id
        cidr              = workload.cidr
        route_table_id    = aws_route_table.workload_east[workload.az_key].id
      }
    }
  }
}
output "flow_log_evidence" {
  value = {
    west = { flow_log_id = aws_flow_log.west.id, log_group_arn = aws_cloudwatch_log_group.flow_west.arn, region = var.west_region }
    east = { flow_log_id = aws_flow_log.east.id, log_group_arn = aws_cloudwatch_log_group.flow_east.arn, region = var.east_region }
  }
}
output "e2e_load_profile" {
  value = var.e2e_load_profile
}
output "symmetric_topology" {
  value = {
    config_version = var.symmetric_topology.version
    run_id         = var.name
    sites = {
      west = {
        region               = var.west_region
        local_site_cidrs     = local.sites.west.local_site_cidrs
        remote_site_cidrs    = local.sites.west.remote_site_cidrs
        target_fleet         = [for key in sort(keys(aws_instance.envelope_target_west)) : { region = var.west_region, az_key = key, instance_id = aws_instance.envelope_target_west[key].id, target_group_arn = aws_lb_target_group.west.arn }]
        ingress_router_fleet = [for key in sort(keys(aws_instance.tailnet_ingress_west)) : { region = var.west_region, az_key = key, instance_id = aws_instance.tailnet_ingress_west[key].id }]
      }
      east = {
        region               = var.east_region
        local_site_cidrs     = local.sites.east.local_site_cidrs
        remote_site_cidrs    = local.sites.east.remote_site_cidrs
        target_fleet         = [for key in sort(keys(aws_instance.envelope_target_east)) : { region = var.east_region, az_key = key, instance_id = aws_instance.envelope_target_east[key].id, target_group_arn = aws_lb_target_group.east.arn }]
        ingress_router_fleet = [for key in sort(keys(aws_instance.tailnet_ingress_east)) : { region = var.east_region, az_key = key, instance_id = aws_instance.tailnet_ingress_east[key].id }]
      }
    }
  }
}

output "envelope_runtime_config" {
  value = {
    for site, topology in local.sites : site => {
      config_version        = var.symmetric_topology.version
      local_site_cidrs      = topology.local_site_cidrs
      remote_site_cidrs     = topology.remote_site_cidrs
      routing_mode          = var.envelope_routing_mode
      tun_name              = var.envelope_tun_name
      underlay_interface    = var.envelope_underlay_interface
      tailscale_iface       = var.envelope_tailscale_iface
      gwlb_return_cidrs     = [local.workload_roles[site].initiator.cidr]
      local_delivery_cidrs  = [local.workload_roles[site].responder.cidr]
      remote_tailnet_cidrs  = topology.remote_site_cidrs
      routing_table_id      = var.envelope_routing_table_id
      routing_rule_priority = var.envelope_routing_rule_priority
      artifact_sha256       = var.artifact_sha256
      artifact_revision     = var.artifact_revision
    }
  }
}
output "cost_profile" {
  value = {
    profile                    = "symmetric-gwlb-ha-v2"
    estimated_fixed_hourly_usd = var.estimated_fixed_hourly_usd
    approved_max_hourly_usd    = var.approved_max_fixed_hourly_usd
    resource_counts = {
      gwlbe_endpoints       = length(aws_vpc_endpoint.west) + length(aws_vpc_endpoint.east)
      target_instances      = { west = length(aws_instance.envelope_target_west), east = length(aws_instance.envelope_target_east) }
      ingress_routers       = { west = length(aws_instance.tailnet_ingress_west), east = length(aws_instance.tailnet_ingress_east) }
      workload_instances    = length(aws_instance.workload_west) + length(aws_instance.workload_east)
      vpc_flow_logs         = 2
      cloudwatch_log_groups = 2
      flow_log_iam_roles    = 1
    }
  }
}
