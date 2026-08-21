resource "terraform_data" "input_validation" {
  input = {
    name         = var.name
    architecture = var.architecture
    expires_at   = var.expires_at
  }

  lifecycle {
    precondition {
      condition = alltrue([
        toset(keys(var.west_workload_subnet_cidrs)) == toset(keys(var.west_azs)),
        toset(keys(var.west_gwlbe_subnet_cidrs)) == toset(keys(var.west_azs)),
        toset(keys(var.west_gwlb_subnet_cidrs)) == toset(keys(var.west_azs)),
        toset(keys(var.east_workload_subnet_cidrs)) == toset(keys(var.east_azs)),
        toset(keys(var.east_gwlbe_subnet_cidrs)) == toset(keys(var.east_azs)),
        toset(keys(var.east_gwlb_subnet_cidrs)) == toset(keys(var.east_azs)),
      ])
      error_message = "Every subnet-role map must use exactly the configuration-known keys from its regional AZ map."
    }

    precondition {
      condition     = contains(keys(var.west_azs), var.west_appliance_az_key) && contains(keys(var.east_azs), var.east_appliance_az_key)
      error_message = "Each appliance AZ key must exist in its explicit regional AZ map."
    }

    precondition {
      condition = alltrue([
        length(setintersection(toset(var.envelope_gwlb_return_cidrs["west"]), toset(var.envelope_local_delivery_cidrs["west"]))) == 0,
        length(setintersection(toset(var.envelope_gwlb_return_cidrs["east"]), toset(var.envelope_local_delivery_cidrs["east"]))) == 0,
        toset(concat(var.envelope_gwlb_return_cidrs["west"], var.envelope_local_delivery_cidrs["west"])) == toset(values(var.west_workload_subnet_cidrs)),
        toset(concat(var.envelope_gwlb_return_cidrs["east"], var.envelope_local_delivery_cidrs["east"])) == toset(values(var.east_workload_subnet_cidrs)),
        toset(var.envelope_remote_tailnet_cidrs["west"]) == toset(values(var.east_workload_subnet_cidrs)),
        toset(var.envelope_remote_tailnet_cidrs["east"]) == toset(values(var.west_workload_subnet_cidrs)),
      ])
      error_message = "Each site's singleton initiator and responder CIDRs must be a disjoint exact partition of its two workload subnets, and remote roles must equal the opposite workload subnet set."
    }

    precondition {
      condition     = var.envelope_tun_name != var.envelope_tailscale_iface
      error_message = "Envelope and Tailscale interfaces must be distinct."
    }

    precondition {
      condition     = var.estimated_fixed_hourly_usd <= var.approved_max_fixed_hourly_usd
      error_message = "The estimated fixed hourly cost exceeds the operator-approved ceiling."
    }

    precondition {
      condition = alltrue([
        strcontains(var.west_tailscale_secret_arn, ":ssm:${var.west_region}:"),
        strcontains(var.east_tailscale_secret_arn, ":ssm:${var.east_region}:"),
        strcontains(var.west_tailscale_secret_arn, ":parameter/${var.name}/"),
        strcontains(var.east_tailscale_secret_arn, ":parameter/${var.name}/"),
        strcontains(var.west_tailscale_kms_key_arn, ":kms:${var.west_region}:"),
        strcontains(var.east_tailscale_kms_key_arn, ":kms:${var.east_region}:"),
      ])
      error_message = "Tailscale SSM parameters and KMS keys must be run-scoped and regional."
    }
  }
}

resource "aws_vpc" "west" {
  cidr_block           = var.west_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name}-west-vpc"
    Site = "west"
  }

  depends_on = [terraform_data.input_validation]
}

resource "aws_vpc" "east" {
  provider = aws.east

  cidr_block           = var.east_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name}-east-vpc"
    Site = "east"
  }

  depends_on = [terraform_data.input_validation]
}

resource "aws_internet_gateway" "west" {
  vpc_id = aws_vpc.west.id
  tags   = { Name = "${var.name}-west-igw", Site = "west" }
}

resource "aws_internet_gateway" "east" {
  provider = aws.east
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-igw", Site = "east" }
}

resource "aws_subnet" "public_west" {
  vpc_id                  = aws_vpc.west.id
  availability_zone       = var.west_azs[var.west_appliance_az_key]
  cidr_block              = var.west_public_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-west-nat", Site = "west", Role = "nat" }
}

resource "aws_subnet" "public_east" {
  provider = aws.east

  vpc_id                  = aws_vpc.east.id
  availability_zone       = var.east_azs[var.east_appliance_az_key]
  cidr_block              = var.east_public_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-east-nat", Site = "east", Role = "nat" }
}

resource "aws_subnet" "appliance_west" {
  vpc_id            = aws_vpc.west.id
  availability_zone = var.west_azs[var.west_appliance_az_key]
  cidr_block        = var.west_appliance_subnet_cidr
  tags              = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }
}

resource "aws_subnet" "appliance_east" {
  provider = aws.east

  vpc_id            = aws_vpc.east.id
  availability_zone = var.east_azs[var.east_appliance_az_key]
  cidr_block        = var.east_appliance_subnet_cidr
  tags              = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }
}

resource "aws_subnet" "workload_west" {
  for_each = var.west_azs

  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = var.west_workload_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-west-workload-${each.key}", Site = "west", Role = "workload", ZoneKey = each.key }
}

resource "aws_subnet" "workload_east" {
  provider = aws.east
  for_each = var.east_azs

  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = var.east_workload_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-east-workload-${each.key}", Site = "east", Role = "workload", ZoneKey = each.key }
}

resource "aws_subnet" "gwlbe_west" {
  for_each = var.west_azs

  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = var.west_gwlbe_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-west-gwlbe-${each.key}", Site = "west", Role = "gwlbe", ZoneKey = each.key }
}

resource "aws_subnet" "gwlbe_east" {
  provider = aws.east
  for_each = var.east_azs

  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = var.east_gwlbe_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-east-gwlbe-${each.key}", Site = "east", Role = "gwlbe", ZoneKey = each.key }
}

resource "aws_subnet" "gwlb_west" {
  for_each = var.west_azs

  vpc_id            = aws_vpc.west.id
  availability_zone = each.value
  cidr_block        = var.west_gwlb_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-west-gwlb-${each.key}", Site = "west", Role = "gwlb", ZoneKey = each.key }
}

resource "aws_subnet" "gwlb_east" {
  provider = aws.east
  for_each = var.east_azs

  vpc_id            = aws_vpc.east.id
  availability_zone = each.value
  cidr_block        = var.east_gwlb_subnet_cidrs[each.key]
  tags              = { Name = "${var.name}-east-gwlb-${each.key}", Site = "east", Role = "gwlb", ZoneKey = each.key }
}

resource "aws_eip" "nat_west" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.west]
  tags       = { Name = "${var.name}-west-nat", Site = "west" }
}

resource "aws_eip" "nat_east" {
  provider = aws.east
  domain   = "vpc"

  depends_on = [aws_internet_gateway.east]
  tags       = { Name = "${var.name}-east-nat", Site = "east" }
}

resource "aws_nat_gateway" "west" {
  allocation_id = aws_eip.nat_west.id
  subnet_id     = aws_subnet.public_west.id
  tags          = { Name = "${var.name}-west-nat", Site = "west" }
}

resource "aws_nat_gateway" "east" {
  provider = aws.east

  allocation_id = aws_eip.nat_east.id
  subnet_id     = aws_subnet.public_east.id
  tags          = { Name = "${var.name}-east-nat", Site = "east" }
}

resource "aws_route_table" "public_west" {
  vpc_id = aws_vpc.west.id
  tags   = { Name = "${var.name}-west-public", Site = "west", Role = "nat" }
}

resource "aws_route_table" "public_east" {
  provider = aws.east
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-public", Site = "east", Role = "nat" }
}

resource "aws_route" "public_default_west" {
  route_table_id         = aws_route_table.public_west.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.west.id
}

resource "aws_route" "public_default_east" {
  provider = aws.east

  route_table_id         = aws_route_table.public_east.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.east.id
}

resource "aws_route_table_association" "public_west" {
  subnet_id      = aws_subnet.public_west.id
  route_table_id = aws_route_table.public_west.id
}

resource "aws_route_table_association" "public_east" {
  provider = aws.east

  subnet_id      = aws_subnet.public_east.id
  route_table_id = aws_route_table.public_east.id
}

resource "aws_route_table" "appliance_west" {
  vpc_id = aws_vpc.west.id
  tags   = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance" }
}

resource "aws_route_table" "appliance_east" {
  provider = aws.east
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance" }
}

resource "aws_route" "appliance_default_west" {
  route_table_id         = aws_route_table.appliance_west.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}

resource "aws_route" "appliance_default_east" {
  provider = aws.east

  route_table_id         = aws_route_table.appliance_east.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.east.id
}

resource "aws_route_table_association" "appliance_west" {
  subnet_id      = aws_subnet.appliance_west.id
  route_table_id = aws_route_table.appliance_west.id
}

resource "aws_route_table_association" "appliance_east" {
  provider = aws.east

  subnet_id      = aws_subnet.appliance_east.id
  route_table_id = aws_route_table.appliance_east.id
}

resource "aws_route_table" "workload_west" {
  for_each = var.west_azs
  vpc_id   = aws_vpc.west.id
  tags     = { Name = "${var.name}-west-workload-${each.key}", Site = "west", Role = "workload", ZoneKey = each.key }
}

resource "aws_route_table" "workload_east" {
  provider = aws.east
  for_each = var.east_azs
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-workload-${each.key}", Site = "east", Role = "workload", ZoneKey = each.key }
}

resource "aws_route" "workload_default_west" {
  for_each = var.west_azs

  route_table_id         = aws_route_table.workload_west[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.west.id
}

resource "aws_route" "workload_default_east" {
  provider = aws.east
  for_each = var.east_azs

  route_table_id         = aws_route_table.workload_east[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.east.id
}

resource "aws_route_table_association" "workload_west" {
  for_each = var.west_azs

  subnet_id      = aws_subnet.workload_west[each.key].id
  route_table_id = aws_route_table.workload_west[each.key].id
}

resource "aws_route_table_association" "workload_east" {
  provider = aws.east
  for_each = var.east_azs

  subnet_id      = aws_subnet.workload_east[each.key].id
  route_table_id = aws_route_table.workload_east[each.key].id
}

resource "aws_route_table" "gwlbe_west" {
  for_each = var.west_azs
  vpc_id   = aws_vpc.west.id
  tags     = { Name = "${var.name}-west-gwlbe-${each.key}", Site = "west", Role = "gwlbe", ZoneKey = each.key }
}

resource "aws_route_table" "gwlbe_east" {
  provider = aws.east
  for_each = var.east_azs
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-gwlbe-${each.key}", Site = "east", Role = "gwlbe", ZoneKey = each.key }
}

resource "aws_route_table_association" "gwlbe_west" {
  for_each = var.west_azs

  subnet_id      = aws_subnet.gwlbe_west[each.key].id
  route_table_id = aws_route_table.gwlbe_west[each.key].id
}

resource "aws_route_table_association" "gwlbe_east" {
  provider = aws.east
  for_each = var.east_azs

  subnet_id      = aws_subnet.gwlbe_east[each.key].id
  route_table_id = aws_route_table.gwlbe_east[each.key].id
}

resource "aws_route_table" "gwlb_west" {
  for_each = var.west_azs
  vpc_id   = aws_vpc.west.id
  tags     = { Name = "${var.name}-west-gwlb-${each.key}", Site = "west", Role = "gwlb", ZoneKey = each.key }
}

resource "aws_route_table" "gwlb_east" {
  provider = aws.east
  for_each = var.east_azs
  vpc_id   = aws_vpc.east.id
  tags     = { Name = "${var.name}-east-gwlb-${each.key}", Site = "east", Role = "gwlb", ZoneKey = each.key }
}

resource "aws_route_table_association" "gwlb_west" {
  for_each = var.west_azs

  subnet_id      = aws_subnet.gwlb_west[each.key].id
  route_table_id = aws_route_table.gwlb_west[each.key].id
}

resource "aws_route_table_association" "gwlb_east" {
  provider = aws.east
  for_each = var.east_azs

  subnet_id      = aws_subnet.gwlb_east[each.key].id
  route_table_id = aws_route_table.gwlb_east[each.key].id
}

resource "aws_network_acl" "appliance_west" {
  vpc_id     = aws_vpc.west.id
  subnet_ids = [aws_subnet.appliance_west.id]

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = local.west_responder_cidr
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "deny"
    cidr_block = local.west_initiator_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 110
    action     = "allow"
    cidr_block = local.west_responder_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.name}-west-appliance", Site = "west", Role = "appliance-bypass-guard" }
}

resource "aws_network_acl" "appliance_east" {
  provider = aws.east

  vpc_id     = aws_vpc.east.id
  subnet_ids = [aws_subnet.appliance_east.id]

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = local.east_responder_cidr
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "deny"
    cidr_block = local.east_initiator_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 110
    action     = "allow"
    cidr_block = local.east_responder_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.name}-east-appliance", Site = "east", Role = "appliance-bypass-guard" }
}

locals {
  flow_log_format = join(" ", [
    "$${version}",
    "$${account-id}",
    "$${interface-id}",
    "$${srcaddr}",
    "$${dstaddr}",
    "$${srcport}",
    "$${dstport}",
    "$${protocol}",
    "$${packets}",
    "$${bytes}",
    "$${start}",
    "$${end}",
    "$${action}",
    "$${log-status}",
    "$${vpc-id}",
    "$${subnet-id}",
    "$${instance-id}",
    "$${region}",
    "$${az-id}",
    "$${flow-direction}",
    "$${traffic-path}",
    "$${pkt-srcaddr}",
    "$${pkt-dstaddr}",
  ])
}

resource "aws_cloudwatch_log_group" "flow_west" {
  name              = "/aws/vpc-flow-logs/${var.name}/west"
  retention_in_days = 7
  tags              = { Name = "${var.name}-west-flow-logs", Site = "west", Role = "flow-logs" }
}

resource "aws_cloudwatch_log_group" "flow_east" {
  provider = aws.east

  name              = "/aws/vpc-flow-logs/${var.name}/east"
  retention_in_days = 7
  tags              = { Name = "${var.name}-east-flow-logs", Site = "east", Role = "flow-logs" }
}

resource "aws_flow_log" "west" {
  vpc_id                   = aws_vpc.west.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_west.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  log_format               = local.flow_log_format
  tags                     = { Name = "${var.name}-west-flow-logs", Site = "west", Role = "flow-logs" }

  depends_on = [aws_iam_role_policy.flow_logs]
}

resource "aws_flow_log" "east" {
  provider = aws.east

  vpc_id                   = aws_vpc.east.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_east.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  log_format               = local.flow_log_format
  tags                     = { Name = "${var.name}-east-flow-logs", Site = "east", Role = "flow-logs" }

  depends_on = [aws_iam_role_policy.flow_logs]
}

output "vpc_ids" {
  value = { west = aws_vpc.west.id, east = aws_vpc.east.id }
}

output "flow_log_evidence" {
  value = {
    west = {
      flow_log_id   = aws_flow_log.west.id
      log_group_arn = aws_cloudwatch_log_group.flow_west.arn
      region        = var.west_region
    }
    east = {
      flow_log_id   = aws_flow_log.east.id
      log_group_arn = aws_cloudwatch_log_group.flow_east.arn
      region        = var.east_region
    }
  }
}
