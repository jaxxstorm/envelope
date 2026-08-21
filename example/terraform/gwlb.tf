resource "aws_lb" "west" {
  name                             = "${var.name}-west-gwlb"
  load_balancer_type               = "gateway"
  subnets                          = [for key in sort(keys(var.west_azs)) : aws_subnet.gwlb_west[key].id]
  enable_cross_zone_load_balancing = true

  tags = { Name = "${var.name}-west-gwlb", Site = "west" }
}

resource "aws_lb" "east" {
  provider = aws.east

  name                             = "${var.name}-east-gwlb"
  load_balancer_type               = "gateway"
  subnets                          = [for key in sort(keys(var.east_azs)) : aws_subnet.gwlb_east[key].id]
  enable_cross_zone_load_balancing = true

  tags = { Name = "${var.name}-east-gwlb", Site = "east" }
}

resource "aws_lb_target_group" "west" {
  name                 = "${var.name}-west-gwlb-tg"
  port                 = 6081
  protocol             = "GENEVE"
  target_type          = "instance"
  vpc_id               = aws_vpc.west.id
  deregistration_delay = 0

  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/healthz"
    port                = "9090"
    healthy_threshold   = 3
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 5
  }

  tags = { Name = "${var.name}-west-gwlb-tg", Site = "west" }
}

resource "aws_lb_target_group" "east" {
  provider = aws.east

  name                 = "${var.name}-east-gwlb-tg"
  port                 = 6081
  protocol             = "GENEVE"
  target_type          = "instance"
  vpc_id               = aws_vpc.east.id
  deregistration_delay = 0

  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/healthz"
    port                = "9090"
    healthy_threshold   = 3
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 5
  }

  tags = { Name = "${var.name}-east-gwlb-tg", Site = "east" }
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

resource "aws_lb_target_group_attachment" "west" {
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = aws_instance.envelope_west.id
}

resource "aws_lb_target_group_attachment" "east" {
  provider         = aws.east
  target_group_arn = aws_lb_target_group.east.arn
  target_id        = aws_instance.envelope_east.id
}

resource "aws_vpc_endpoint_service" "west" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.west.arn]
  tags                       = { Name = "${var.name}-west-gwlb-svc", Site = "west" }
}

resource "aws_vpc_endpoint_service" "east" {
  provider = aws.east

  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.east.arn]
  tags                       = { Name = "${var.name}-east-gwlb-svc", Site = "east" }
}

resource "aws_vpc_endpoint" "west" {
  for_each = toset([local.west_initiator_az_key])

  vpc_id            = aws_vpc.west.id
  service_name      = aws_vpc_endpoint_service.west.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_west[each.key].id]
  tags              = { Name = "${var.name}-west-gwlbe-${each.key}", Site = "west", ZoneKey = each.key }
}

resource "aws_vpc_endpoint" "east" {
  provider = aws.east
  for_each = toset([local.east_initiator_az_key])

  vpc_id            = aws_vpc.east.id
  service_name      = aws_vpc_endpoint_service.east.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_east[each.key].id]
  tags              = { Name = "${var.name}-east-gwlbe-${each.key}", Site = "east", ZoneKey = each.key }
}

resource "aws_route" "initiator_to_responder_west" {
  route_table_id         = aws_route_table.workload_west[local.west_initiator_az_key].id
  destination_cidr_block = local.east_responder_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.west[local.west_initiator_az_key].id
}

resource "aws_route" "initiator_to_responder_east" {
  provider = aws.east

  route_table_id         = aws_route_table.workload_east[local.east_initiator_az_key].id
  destination_cidr_block = local.west_responder_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.east[local.east_initiator_az_key].id
}

resource "aws_route" "responder_return_west" {
  route_table_id         = aws_route_table.workload_west[local.west_responder_az_key].id
  destination_cidr_block = local.east_initiator_cidr
  network_interface_id   = aws_instance.envelope_west.primary_network_interface_id
}

resource "aws_route" "responder_return_east" {
  provider = aws.east

  route_table_id         = aws_route_table.workload_east[local.east_responder_az_key].id
  destination_cidr_block = local.west_initiator_cidr
  network_interface_id   = aws_instance.envelope_east.primary_network_interface_id
}

output "gwlb_arns" {
  value = { west = aws_lb.west.arn, east = aws_lb.east.arn }
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
