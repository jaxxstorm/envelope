resource "terraform_data" "input_validation" {
  input = var.symmetric_topology

  lifecycle {
    precondition {
      condition = alltrue([
        for site, topology in local.sites :
        toset(topology.local_site_cidrs) == toset(values(topology.workload_subnet_cidrs)) &&
        toset(topology.remote_site_cidrs) == toset(local.sites[site == "west" ? "east" : "west"].local_site_cidrs) &&
        length(topology.local_site_cidrs) == length(distinct(topology.local_site_cidrs)) &&
        length(topology.remote_site_cidrs) == length(distinct(topology.remote_site_cidrs))
      ])
      error_message = "Local and remote site CIDRs must be duplicate-free, exactly cover local workloads, and equal the peer contract."
    }
    precondition {
      condition = var.symmetric_topology.version == 2 ? alltrue([
        for site, assignments in local.initial_transport_router_advertise_routes :
        alltrue([for routes in values(assignments) : length(routes) == 1]) &&
        length(flatten(values(assignments))) == length(distinct(flatten(values(assignments)))) &&
        toset(flatten(values(assignments))) == toset(local.sites[site].local_site_cidrs)
        ]) : alltrue([
        for site, assignments in local.initial_transport_router_advertise_routes :
        length(assignments) >= 2 && alltrue([
          for routes in values(assignments) :
          toset(routes) == toset(local.sites[site].local_site_cidrs)
        ])
      ])
      error_message = "Production transport routers must all advertise the complete exact local workload-prefix set; only explicit version 2 retains singleton legacy acceptance assignments."
    }
    precondition {
      condition = alltrue([
        for topology in values(local.sites) : alltrue([
          for cidr in topology.local_site_cidrs :
          !try(
            local.ipv4_network_bounds[cidr].first <= local.ipv4_network_bounds[topology.vpc_cidr].first + 2 &&
            local.ipv4_network_bounds[topology.vpc_cidr].first + 2 <= local.ipv4_network_bounds[cidr].last,
            true,
          )
        ])
      ])
      error_message = "Local workload CIDRs must exclude the VPC DNS resolver address."
    }
    precondition {
      condition = alltrue(flatten([
        for cidrs in values(local.site_configured_cidrs) : [
          for cidr in cidrs : try(
            cidrnetmask(cidr) != "" &&
            cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}",
            false,
          )
        ]
      ]))
      error_message = "Every topology CIDR must be a canonical IPv4 network."
    }
    precondition {
      condition = alltrue(flatten([
        for site, cidrs in local.site_subnet_cidrs : [
          for cidr in cidrs : try(
            local.ipv4_network_bounds[cidr].first >= local.ipv4_network_bounds[local.sites[site].vpc_cidr].first &&
            local.ipv4_network_bounds[cidr].last <= local.ipv4_network_bounds[local.sites[site].vpc_cidr].last,
            false,
          )
        ]
      ]))
      error_message = "Every route-domain subnet must be fully contained by its site VPC."
    }
    precondition {
      condition = alltrue(flatten([
        for cidrs in values(local.site_subnet_cidrs) : [
          for left_index, left in cidrs : [
            for right_index, right in cidrs : !try(
              local.ipv4_network_bounds[left].first <= local.ipv4_network_bounds[right].last &&
              local.ipv4_network_bounds[right].first <= local.ipv4_network_bounds[left].last,
              true,
            ) if left_index < right_index
          ]
        ]
      ]))
      error_message = "Workload, transport-router, GWLBE, GWLB, target, and management subnet CIDRs must not overlap."
    }
    precondition {
      condition = alltrue(flatten([
        for topology in values(local.sites) : [
          for local_cidr in topology.local_site_cidrs : [
            for remote_cidr in topology.remote_site_cidrs : !try(
              local.ipv4_network_bounds[local_cidr].first <= local.ipv4_network_bounds[remote_cidr].last &&
              local.ipv4_network_bounds[remote_cidr].first <= local.ipv4_network_bounds[local_cidr].last,
              true,
            )
          ]
        ]
      ]))
      error_message = "Local and remote site CIDRs must not overlap at any prefix length."
    }
    precondition {
      condition = !try(
        local.ipv4_network_bounds[local.sites.west.vpc_cidr].first <= local.ipv4_network_bounds[local.sites.east.vpc_cidr].last &&
        local.ipv4_network_bounds[local.sites.east.vpc_cidr].first <= local.ipv4_network_bounds[local.sites.west.vpc_cidr].last,
        true,
      )
      error_message = "West and east VPC CIDRs must not overlap."
    }
    precondition {
      condition = (
        local.sites.west.region == var.west_region &&
        local.sites.east.region == var.east_region &&
        local.sites.west.ami_id == var.west_ami_id &&
        local.sites.east.ami_id == var.east_ami_id &&
        local.sites.west.ssm_kms_key_arn == var.west_tailscale_kms_key_arn &&
        local.sites.east.ssm_kms_key_arn == var.east_tailscale_kms_key_arn &&
        var.west_region != var.east_region &&
        var.envelope_underlay_interface != var.envelope_tailscale_iface
      )
      error_message = "Topology region, AMI, KMS, and interface identities must match the reviewed explicit inputs."
    }
    precondition {
      condition = try(
        split(":", var.west_tailscale_secret_arn)[4] == data.aws_caller_identity.current.account_id &&
        split(":", var.east_tailscale_secret_arn)[4] == data.aws_caller_identity.current.account_id &&
        split(":", var.west_tailscale_kms_key_arn)[4] == data.aws_caller_identity.current.account_id &&
        split(":", var.east_tailscale_kms_key_arn)[4] == data.aws_caller_identity.current.account_id,
        false,
      )
      error_message = "Tailnet SSM parameters and KMS keys must be exact ARNs in the deployment account."
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
resource "aws_subnet" "transport_west" {
  for_each          = local.sites.west.azs
  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = local.sites.west.transport_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-west-transport-${each.key}", Role = "transport-router", ZoneKey = each.key })
}
resource "aws_subnet" "transport_east" {
  provider          = aws.east
  for_each          = local.sites.east.azs
  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = local.sites.east.transport_subnet_cidrs[each.key]
  tags              = merge(local.common_tags, { Name = "${var.name}-east-transport-${each.key}", Role = "transport-router", ZoneKey = each.key })
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
resource "aws_route_table" "transport_west" {
  for_each = local.sites.west.azs
  vpc_id   = aws_vpc.west.id
  tags     = merge(local.common_tags, { Name = "${var.name}-west-transport-${each.key}", Role = "transport-router", ZoneKey = each.key })
}
resource "aws_route_table" "transport_east" {
  provider = aws.east
  for_each = local.sites.east.azs
  vpc_id   = aws_vpc.east.id
  tags     = merge(local.common_tags, { Name = "${var.name}-east-transport-${each.key}", Role = "transport-router", ZoneKey = each.key })
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
resource "aws_route_table_association" "transport_west" {
  for_each       = local.sites.west.azs
  subnet_id      = aws_subnet.transport_west[each.key].id
  route_table_id = aws_route_table.transport_west[each.key].id
}
resource "aws_route_table_association" "transport_east" {
  provider       = aws.east
  for_each       = local.sites.east.azs
  subnet_id      = aws_subnet.transport_east[each.key].id
  route_table_id = aws_route_table.transport_east[each.key].id
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
  depends_on    = [aws_route_table_association.management_west, aws_route.management_default_west]
}
resource "aws_nat_gateway" "east" {
  provider      = aws.east
  allocation_id = aws_eip.nat_east.id
  subnet_id     = aws_subnet.management_east.id
  depends_on    = [aws_route_table_association.management_east, aws_route.management_default_east]
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
resource "aws_route" "transport_default_west" {
  for_each               = local.sites.west.azs
  route_table_id         = aws_route_table.transport_west[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}
resource "aws_route" "transport_default_east" {
  provider               = aws.east
  for_each               = local.sites.east.azs
  route_table_id         = aws_route_table.transport_east[each.key].id
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
    healthy_threshold   = 5
    interval            = 10
    path                = "/healthz"
    port                = "9090"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
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
    healthy_threshold   = 5
    interval            = 10
    path                = "/healthz"
    port                = "9090"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
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
resource "aws_route" "transport_to_local_west" {
  for_each = {
    for pair in setproduct(toset(keys(local.sites.west.azs)), toset(keys(local.sites.west.workload_subnet_cidrs))) :
    "${pair[0]}:${local.sites.west.workload_subnet_cidrs[pair[1]]}" => {
      transport_az_key = pair[0]
      workload_az_key  = pair[1]
      cidr             = local.sites.west.workload_subnet_cidrs[pair[1]]
    }
  }
  route_table_id         = aws_route_table.transport_west[each.value.transport_az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.west[each.value.workload_az_key].id

  lifecycle {
    precondition {
      condition     = each.value.cidr == local.sites.west.workload_subnet_cidrs[each.value.workload_az_key]
      error_message = "West transport routes must select the GWLBE in each destination workload prefix's AZ."
    }
  }
}
resource "aws_route" "transport_to_local_east" {
  provider = aws.east
  for_each = {
    for pair in setproduct(toset(keys(local.sites.east.azs)), toset(keys(local.sites.east.workload_subnet_cidrs))) :
    "${pair[0]}:${local.sites.east.workload_subnet_cidrs[pair[1]]}" => {
      transport_az_key = pair[0]
      workload_az_key  = pair[1]
      cidr             = local.sites.east.workload_subnet_cidrs[pair[1]]
    }
  }
  route_table_id         = aws_route_table.transport_east[each.value.transport_az_key].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = aws_vpc_endpoint.east[each.value.workload_az_key].id

  lifecycle {
    precondition {
      condition     = each.value.cidr == local.sites.east.workload_subnet_cidrs[each.value.workload_az_key]
      error_message = "East transport routes must select the GWLBE in each destination workload prefix's AZ."
    }
  }
}
resource "aws_route" "gwlbe_to_remote_west" {
  for_each = {
    for pair in setproduct(toset(keys(local.sites.west.azs)), toset(local.sites.west.remote_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.gwlbe_west[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  network_interface_id = aws_instance.transport_router_west[
    local.gwlbe_initial_owners.west[each.value.az_key]
  ].primary_network_interface_id

  lifecycle {
    # Terraform owns route shape; the controller owns the refreshed current ENI.
    ignore_changes = [network_interface_id]

    precondition {
      condition = contains(
        local.sites.west.transport_router_az_keys,
        local.gwlbe_initial_owners.west[each.value.az_key],
        ) && (
        local.gwlbe_initial_owners.west[each.value.az_key] == each.value.az_key || var.symmetric_topology.version == 3
      )
      error_message = "West GWLBE routes must select the transport router in the same AZ."
    }
    precondition {
      condition = contains(
        local.initial_transport_router_advertise_routes.west[
          local.gwlbe_initial_owners.west[each.value.az_key]
        ],
        local.sites.west.workload_subnet_cidrs[each.value.az_key],
      )
      error_message = "West GWLBE routes must start on an eligible exact-prefix transport router."
    }
    precondition {
      condition     = length(toset([for instance in values(aws_instance.transport_router_west) : instance.primary_network_interface_id])) == length(aws_instance.transport_router_west)
      error_message = "West transport routers must expose distinct eligible primary ENIs."
    }
    postcondition {
      condition = (
        self.route_table_id == aws_route_table.gwlbe_west[each.value.az_key].id &&
        self.destination_cidr_block == each.value.cidr
      )
      error_message = "West controller-owned route shape drifted from its exact table and destination prefix."
    }
    postcondition {
      condition = contains(
        [for instance in values(aws_instance.transport_router_west) : instance.primary_network_interface_id],
        self.network_interface_id,
      )
      error_message = "West controller-owned route selects an ENI outside its eligible transport-router set."
    }
  }
}
resource "aws_route" "gwlbe_to_remote_east" {
  provider = aws.east
  for_each = {
    for pair in setproduct(toset(keys(local.sites.east.azs)), toset(local.sites.east.remote_site_cidrs)) :
    "${pair[0]}:${pair[1]}" => { az_key = pair[0], cidr = pair[1] }
  }
  route_table_id         = aws_route_table.gwlbe_east[each.value.az_key].id
  destination_cidr_block = each.value.cidr
  network_interface_id = aws_instance.transport_router_east[
    local.gwlbe_initial_owners.east[each.value.az_key]
  ].primary_network_interface_id

  lifecycle {
    # Terraform owns route shape; the controller owns the refreshed current ENI.
    ignore_changes = [network_interface_id]

    precondition {
      condition = contains(
        local.sites.east.transport_router_az_keys,
        local.gwlbe_initial_owners.east[each.value.az_key],
        ) && (
        local.gwlbe_initial_owners.east[each.value.az_key] == each.value.az_key || var.symmetric_topology.version == 3
      )
      error_message = "East GWLBE routes must select the transport router in the same AZ."
    }
    precondition {
      condition = contains(
        local.initial_transport_router_advertise_routes.east[
          local.gwlbe_initial_owners.east[each.value.az_key]
        ],
        local.sites.east.workload_subnet_cidrs[each.value.az_key],
      )
      error_message = "East GWLBE routes must start on an eligible exact-prefix transport router."
    }
    precondition {
      condition     = length(toset([for instance in values(aws_instance.transport_router_east) : instance.primary_network_interface_id])) == length(aws_instance.transport_router_east)
      error_message = "East transport routers must expose distinct eligible primary ENIs."
    }
    postcondition {
      condition = (
        self.route_table_id == aws_route_table.gwlbe_east[each.value.az_key].id &&
        self.destination_cidr_block == each.value.cidr
      )
      error_message = "East controller-owned route shape drifted from its exact table and destination prefix."
    }
    postcondition {
      condition = contains(
        [for instance in values(aws_instance.transport_router_east) : instance.primary_network_interface_id],
        self.network_interface_id,
      )
      error_message = "East controller-owned route selects an ENI outside its eligible transport-router set."
    }
  }
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
resource "aws_security_group" "transport_west" {
  name   = "${var.name}-west-transport"
  vpc_id = aws_vpc.west.id
  dynamic "ingress" {
    for_each = toset(local.sites.west.local_site_cidrs)
    content {
      description = "Preserved-source transit from ${ingress.value}"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = [ingress.value]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-west-transport", Role = "transport-router" })
}
resource "aws_security_group" "transport_east" {
  provider = aws.east
  name     = "${var.name}-east-transport"
  vpc_id   = aws_vpc.east.id
  dynamic "ingress" {
    for_each = toset(local.sites.east.local_site_cidrs)
    content {
      description = "Preserved-source transit from ${ingress.value}"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = [ingress.value]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-east-transport", Role = "transport-router" })
}
resource "aws_security_group" "workload_west" {
  for_each = local.workload_roles.west
  name     = "${var.name}-west-${each.key}"
  vpc_id   = aws_vpc.west.id
  dynamic "ingress" {
    for_each = local.workload_probe_ingress
    content {
      description = "${ingress.value.description} from east workloads"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [for role in values(local.workload_roles.east) : role.cidr]
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
    for_each = local.workload_probe_ingress
    content {
      description = "${ingress.value.description} from west workloads"
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [for role in values(local.workload_roles.west) : role.cidr]
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
}

resource "aws_instance" "envelope_target_west" {
  for_each                    = local.sites.west.target_az_keys
  ami                         = var.west_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.target_west[each.key].id
  vpc_security_group_ids      = [aws_security_group.target_west.id]
  iam_instance_profile        = aws_iam_instance_profile.runtime_west.name
  associate_public_ip_address = false
  source_dest_check           = true
  user_data_base64            = data.cloudinit_config.target_west.rendered
  user_data_replace_on_change = true
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-west-target-${each.key}", Site = "west", Role = "target", ZoneKey = each.key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-west-target-${each.key}", Site = "west", Role = "target", ZoneKey = each.key })
  depends_on = [
    aws_iam_role_policy.runtime_west,
    aws_route_table_association.target_west,
    aws_route.target_default_west,
    aws_s3_bucket_policy.artifact,
    aws_s3_object.envelope,
  ]
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
  source_dest_check           = true
  user_data_base64            = data.cloudinit_config.target_east.rendered
  user_data_replace_on_change = true
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-east-target-${each.key}", Site = "east", Role = "target", ZoneKey = each.key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-east-target-${each.key}", Site = "east", Role = "target", ZoneKey = each.key })
  depends_on = [
    aws_iam_role_policy.runtime_east,
    aws_route_table_association.target_east,
    aws_route.target_default_east,
    aws_s3_bucket_policy.artifact,
    aws_s3_object.envelope,
  ]
}
resource "aws_instance" "transport_router_west" {
  for_each                    = local.sites.west.transport_router_az_keys
  ami                         = var.west_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.transport_west[each.key].id
  vpc_security_group_ids      = [aws_security_group.transport_west.id]
  iam_instance_profile        = aws_iam_instance_profile.transport_west.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_transport_west[each.key].rendered
  user_data_replace_on_change = true
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-west-transport-${each.key}", Site = "west", Role = "transport-router", ZoneKey = each.key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-west-transport-${each.key}", Site = "west", Role = "transport-router", ZoneKey = each.key })
  depends_on = [
    aws_iam_role_policy.transport_west,
    aws_iam_role_policy.attestor_binary,
    aws_route_table_association.transport_west,
    aws_route.transport_default_west,
    aws_route.transport_to_local_west,
  ]
}
resource "aws_instance" "transport_router_east" {
  provider                    = aws.east
  for_each                    = local.sites.east.transport_router_az_keys
  ami                         = var.east_ami_id
  instance_type               = var.test_instance_type
  subnet_id                   = aws_subnet.transport_east[each.key].id
  vpc_security_group_ids      = [aws_security_group.transport_east.id]
  iam_instance_profile        = aws_iam_instance_profile.transport_east.name
  associate_public_ip_address = false
  source_dest_check           = false
  user_data_base64            = module.tailscale_transport_east[each.key].rendered
  user_data_replace_on_change = true
  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-east-transport-${each.key}", Site = "east", Role = "transport-router", ZoneKey = each.key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-east-transport-${each.key}", Site = "east", Role = "transport-router", ZoneKey = each.key })
  depends_on = [
    aws_iam_role_policy.transport_east,
    aws_iam_role_policy.attestor_binary,
    aws_route_table_association.transport_east,
    aws_route.transport_default_east,
    aws_route.transport_to_local_east,
  ]
}

resource "aws_instance" "workload_west" {
  for_each                    = local.workload_roles.west
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
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-west-${each.key}", Site = "west", Role = each.key, ZoneKey = each.value.az_key })
  depends_on  = [aws_iam_role_policy.workload_west, aws_route_table_association.workload_west, aws_route.workload_default_west, aws_route.workload_to_remote_west]
}
resource "aws_instance" "workload_east" {
  provider                    = aws.east
  for_each                    = local.workload_roles.east
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
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags        = merge(local.common_tags, { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key })
  volume_tags = merge(local.common_tags, { Name = "${var.name}-east-${each.key}", Site = "east", Role = each.key, ZoneKey = each.value.az_key })
  depends_on  = [aws_iam_role_policy.workload_east, aws_route_table_association.workload_east, aws_route.workload_default_east, aws_route.workload_to_remote_east]
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
  value = merge({
    config_version = var.symmetric_topology.version
    run_id         = var.name
    route_failover = local.route_failover
    sites = {
      west = {
        region            = var.west_region
        local_site_cidrs  = local.sites.west.local_site_cidrs
        remote_site_cidrs = local.sites.west.remote_site_cidrs
        target_fleet      = [for key in sort(keys(aws_instance.envelope_target_west)) : { region = var.west_region, az_key = key, instance_id = aws_instance.envelope_target_west[key].id, target_group_arn = aws_lb_target_group.west.arn }]
        transport_router_fleet = [
          for key in sort(keys(aws_instance.transport_router_west)) : merge({
            region               = var.west_region
            az_key               = key
            instance_id          = aws_instance.transport_router_west[key].id
            network_interface_id = aws_instance.transport_router_west[key].primary_network_interface_id
            gwlbe_route_table_id = aws_route_table.gwlbe_west[key].id
            }, jsondecode(var.symmetric_topology.version == 2 ? jsonencode({
              advertised_prefix = one(local.initial_transport_router_advertise_routes.west[key])
              }) : jsonencode({
              advertised_prefixes = local.initial_transport_router_advertise_routes.west[key]
          })))
        ]
      }
      east = {
        region            = var.east_region
        local_site_cidrs  = local.sites.east.local_site_cidrs
        remote_site_cidrs = local.sites.east.remote_site_cidrs
        target_fleet      = [for key in sort(keys(aws_instance.envelope_target_east)) : { region = var.east_region, az_key = key, instance_id = aws_instance.envelope_target_east[key].id, target_group_arn = aws_lb_target_group.east.arn }]
        transport_router_fleet = [
          for key in sort(keys(aws_instance.transport_router_east)) : merge({
            region               = var.east_region
            az_key               = key
            instance_id          = aws_instance.transport_router_east[key].id
            network_interface_id = aws_instance.transport_router_east[key].primary_network_interface_id
            gwlbe_route_table_id = aws_route_table.gwlbe_east[key].id
            }, jsondecode(var.symmetric_topology.version == 2 ? jsonencode({
              advertised_prefix = one(local.initial_transport_router_advertise_routes.east[key])
              }) : jsonencode({
              advertised_prefixes = local.initial_transport_router_advertise_routes.east[key]
          })))
        ]
      }
    }
    }, var.symmetric_topology.version == 2 ? {} : {
    transport_router_profile = "production-native-ha-v3"
  })
}

output "envelope_runtime_config" {
  value = {
    for site in keys(local.sites) : site => local.packet_return_runtime
  }
}
output "transport_router_readiness_expectations" {
  value = {
    config_version = var.symmetric_topology.version
    sites = {
      for site, contract in local.transport_router_contracts : site => merge(contract, {
        contract_sha256 = local.transport_router_contract_sha256[site]
      })
    }
  }
}
output "route_failover" {
  value = merge({
    config_version              = var.symmetric_topology.version
    mutation_timeout_seconds    = local.route_failover.mutation_timeout_seconds
    restoration_timeout_seconds = local.route_failover.restoration_timeout_seconds
    recovery_timeout_seconds    = local.route_failover.recovery_timeout_seconds
    same_az_preferred = {
      for site, selections in local.route_failover.initial_transport_router_az_by_gwlbe_az :
      site => alltrue([for gwlbe_az, transport_az in selections : gwlbe_az == transport_az])
    }
    sites = {
      west = {
        for gwlbe_az, transport_az in local.route_failover.initial_transport_router_az_by_gwlbe_az.west :
        gwlbe_az => merge({
          route_table_id                  = aws_route_table.gwlbe_west[gwlbe_az].id
          source_workload_prefix          = local.sites.west.workload_subnet_cidrs[gwlbe_az]
          remote_site_cidrs               = sort(local.sites.west.remote_site_cidrs)
          initial_transport_router_az_key = transport_az
          initial_network_interface_id    = aws_instance.transport_router_west[transport_az].primary_network_interface_id
          }, var.symmetric_topology.version == 2 ? {} : {
          eligible_network_interface_ids = sort([for instance in values(aws_instance.transport_router_west) : instance.primary_network_interface_id])
        })
      }
      east = {
        for gwlbe_az, transport_az in local.route_failover.initial_transport_router_az_by_gwlbe_az.east :
        gwlbe_az => merge({
          route_table_id                  = aws_route_table.gwlbe_east[gwlbe_az].id
          source_workload_prefix          = local.sites.east.workload_subnet_cidrs[gwlbe_az]
          remote_site_cidrs               = sort(local.sites.east.remote_site_cidrs)
          initial_transport_router_az_key = transport_az
          initial_network_interface_id    = aws_instance.transport_router_east[transport_az].primary_network_interface_id
          }, var.symmetric_topology.version == 2 ? {} : {
          eligible_network_interface_ids = sort([for instance in values(aws_instance.transport_router_east) : instance.primary_network_interface_id])
        })
      }
    }
    }, var.symmetric_topology.version == 2 ? {} : {
    target_ownership = "envelope-controller"
  })
}
output "production_controller_topology_seed" {
  description = "Version-3-only nonsecret authority seed consumed by the protected production-controller runner."
  value = var.symmetric_topology.version == 3 ? {
    config_version = 3
    deployment_id  = var.name
    sites = {
      west = {
        vpc_id                        = aws_vpc.west.id
        region                        = var.west_region
        local_prefixes                = sort(local.sites.west.local_site_cidrs)
        local_main_rule_priority_base = local.transport_router_contracts.west.policy_rule_priority_base
        tailscale_route_rule_priority = 5270
      }
      east = {
        vpc_id                        = aws_vpc.east.id
        region                        = var.east_region
        local_prefixes                = sort(local.sites.east.local_site_cidrs)
        local_main_rule_priority_base = local.transport_router_contracts.east.policy_rule_priority_base
        tailscale_route_rule_priority = 5270
      }
    }
    routers = concat(
      [for key in sort(keys(aws_instance.transport_router_west)) : {
        id                = "west-${key}"
        expected_hostname = "${var.name}-west-transport-${key}"
        site_id           = "west"
        instance_id       = aws_instance.transport_router_west[key].id
        eni_id            = aws_instance.transport_router_west[key].primary_network_interface_id
        vpc_id            = aws_vpc.west.id
        subnet_id         = aws_subnet.transport_west[key].id
        availability_zone = local.sites.west.azs[key]
        region            = var.west_region
      }],
      [for key in sort(keys(aws_instance.transport_router_east)) : {
        id                = "east-${key}"
        expected_hostname = "${var.name}-east-transport-${key}"
        site_id           = "east"
        instance_id       = aws_instance.transport_router_east[key].id
        eni_id            = aws_instance.transport_router_east[key].primary_network_interface_id
        vpc_id            = aws_vpc.east.id
        subnet_id         = aws_subnet.transport_east[key].id
        availability_zone = local.sites.east.azs[key]
        region            = var.east_region
      }],
    )
    domains = concat(
      [for gwlbe_az in sort(keys(local.sites.west.azs)) : {
        id                         = "west-${gwlbe_az}"
        site_id                    = "west"
        source_prefix              = local.sites.west.workload_subnet_cidrs[gwlbe_az]
        route_table_id             = aws_route_table.gwlbe_west[gwlbe_az].id
        gwlbe_subnet_id            = aws_subnet.gwlbe_west[gwlbe_az].id
        route_table_association_id = aws_route_table_association.gwlbe_west[gwlbe_az].id
        remote_prefixes            = sort(local.sites.west.remote_site_cidrs)
        preferred_owner            = "west-${local.route_failover.initial_transport_router_az_by_gwlbe_az.west[gwlbe_az]}"
      }],
      [for gwlbe_az in sort(keys(local.sites.east.azs)) : {
        id                         = "east-${gwlbe_az}"
        site_id                    = "east"
        source_prefix              = local.sites.east.workload_subnet_cidrs[gwlbe_az]
        route_table_id             = aws_route_table.gwlbe_east[gwlbe_az].id
        gwlbe_subnet_id            = aws_subnet.gwlbe_east[gwlbe_az].id
        route_table_association_id = aws_route_table_association.gwlbe_east[gwlbe_az].id
        remote_prefixes            = sort(local.sites.east.remote_site_cidrs)
        preferred_owner            = "east-${local.route_failover.initial_transport_router_az_by_gwlbe_az.east[gwlbe_az]}"
      }],
    )
  } : null
}
output "cost_profile" {
  value = {
    profile                    = var.symmetric_topology.version == 2 ? "legacy-symmetric-acceptance-v2" : "production-native-ha-v3"
    estimated_fixed_hourly_usd = var.estimated_fixed_hourly_usd
    approved_max_hourly_usd    = var.approved_max_fixed_hourly_usd
    resource_counts = {
      gwlbe_endpoints        = length(aws_vpc_endpoint.west) + length(aws_vpc_endpoint.east)
      target_instances       = { west = length(aws_instance.envelope_target_west), east = length(aws_instance.envelope_target_east) }
      transport_routers      = { west = length(aws_instance.transport_router_west), east = length(aws_instance.transport_router_east) }
      workload_instances     = length(aws_instance.workload_west) + length(aws_instance.workload_east)
      nat_gateways           = length(aws_nat_gateway.west[*]) + length(aws_nat_gateway.east[*])
      elastic_ips            = length(aws_eip.nat_west[*]) + length(aws_eip.nat_east[*])
      gateway_load_balancers = length(aws_lb.west[*]) + length(aws_lb.east[*])
      vpc_flow_logs          = length(aws_flow_log.west[*]) + length(aws_flow_log.east[*])
      cloudwatch_log_groups  = length(aws_cloudwatch_log_group.flow_west[*]) + length(aws_cloudwatch_log_group.flow_east[*])
      flow_log_iam_roles     = length(aws_iam_role.flow_logs[*])
      iam_roles = {
        target    = length(aws_iam_role.runtime_west[*]) + length(aws_iam_role.runtime_east[*])
        workload  = length(aws_iam_role.workload_west[*]) + length(aws_iam_role.workload_east[*])
        transport = length(aws_iam_role.transport_west[*]) + length(aws_iam_role.transport_east[*])
        flow_log  = length(aws_iam_role.flow_logs[*])
      }
      iam_instance_profiles = {
        target    = length(aws_iam_instance_profile.runtime_west[*]) + length(aws_iam_instance_profile.runtime_east[*])
        workload  = length(aws_iam_instance_profile.workload_west[*]) + length(aws_iam_instance_profile.workload_east[*])
        transport = length(aws_iam_instance_profile.transport_west[*]) + length(aws_iam_instance_profile.transport_east[*])
      }
    }
    route_failover_bounds = {
      mutation_timeout_seconds    = local.route_failover.mutation_timeout_seconds
      restoration_timeout_seconds = local.route_failover.restoration_timeout_seconds
      recovery_timeout_seconds    = local.route_failover.recovery_timeout_seconds
    }
    nat_topology_limit = {
      gateways_per_site = 1
      expanded_for_ha   = false
      placement         = "one shared NAT gateway in each site's single management subnet"
      limitation        = "private egress is not multi-AZ within a site and remains outside the protected data path"
    }
  }
}
