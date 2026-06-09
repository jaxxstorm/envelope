resource "aws_lb" "west" {
  name               = substr("${var.name}-west-gwlb", 0, 32)
  load_balancer_type = "gateway"
  subnets            = module.vpc_west.private_subnets

  tags = merge(var.tags, {
    Name = substr("${var.name}-west-gwlb", 0, 32)
    Site = "west"
  })
}

resource "aws_lb" "east" {
  provider           = aws.east
  name               = substr("${var.name}-east-gwlb", 0, 32)
  load_balancer_type = "gateway"
  subnets            = module.vpc_east.private_subnets

  tags = merge(var.tags, {
    Name = substr("${var.name}-east-gwlb", 0, 32)
    Site = "east"
  })
}

resource "aws_lb_target_group" "west" {
  name        = substr("${var.name}-west-gwlb-tg", 0, 32)
  port        = 6081
  protocol    = "GENEVE"
  target_type = "instance"
  vpc_id      = module.vpc_west.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/healthz"
    port                = "9090"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 10
    timeout             = 5
  }

  tags = merge(var.tags, {
    Name = substr("${var.name}-west-gwlb-tg", 0, 32)
    Site = "west"
  })
}

resource "aws_lb_target_group" "east" {
  provider    = aws.east
  name        = substr("${var.name}-east-gwlb-tg", 0, 32)
  port        = 6081
  protocol    = "GENEVE"
  target_type = "instance"
  vpc_id      = module.vpc_east.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/healthz"
    port                = "9090"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 10
    timeout             = 5
  }

  tags = merge(var.tags, {
    Name = substr("${var.name}-east-gwlb-tg", 0, 32)
    Site = "east"
  })
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

  tags = merge(var.tags, {
    Name = substr("${var.name}-west-gwlb-svc", 0, 32)
    Site = "west"
  })
}

resource "aws_vpc_endpoint_service" "east" {
  provider                   = aws.east
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.east.arn]

  tags = merge(var.tags, {
    Name = substr("${var.name}-east-gwlb-svc", 0, 32)
    Site = "east"
  })
}

locals {
  west_private_subnet_index = { for idx, subnet_id in module.vpc_west.private_subnets : subnet_id => idx }
  east_private_subnet_index = { for idx, subnet_id in module.vpc_east.private_subnets : subnet_id => idx }
}

resource "aws_vpc_endpoint" "west" {
  for_each = local.west_private_subnet_index

  vpc_id            = module.vpc_west.vpc_id
  service_name      = aws_vpc_endpoint_service.west.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [each.key]

  tags = merge(var.tags, {
    Name = substr("${var.name}-west-gwlb-endpoint-${each.value}", 0, 32)
    Site = "west"
  })
}

resource "aws_vpc_endpoint" "east" {
  provider = aws.east
  for_each = local.east_private_subnet_index

  vpc_id            = module.vpc_east.vpc_id
  service_name      = aws_vpc_endpoint_service.east.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [each.key]

  tags = merge(var.tags, {
    Name = substr("${var.name}-east-gwlb-endpoint-${each.value}", 0, 32)
    Site = "east"
  })
}

data "aws_route_table" "west_private" {
  for_each  = local.west_private_subnet_index
  subnet_id = each.key
}

data "aws_route_table" "east_private" {
  provider  = aws.east
  for_each  = local.east_private_subnet_index
  subnet_id = each.key
}

resource "aws_route" "private_to_remote_via_gwlbe_west" {
  for_each = data.aws_route_table.west_private

  route_table_id         = each.value.id
  destination_cidr_block = var.east_vpc_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.west[each.key].id
}

resource "aws_route" "private_to_remote_via_gwlbe_east" {
  provider = aws.east
  for_each = data.aws_route_table.east_private

  route_table_id         = each.value.id
  destination_cidr_block = var.west_vpc_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.east[each.key].id
}

output "gwlb_arns" {
  value = {
    west = aws_lb.west.arn
    east = aws_lb.east.arn
  }
}

output "gwlb_dns_names" {
  value = {
    west = aws_lb.west.dns_name
    east = aws_lb.east.dns_name
  }
}

output "gwlb_target_group_arns" {
  value = {
    west = aws_lb_target_group.west.arn
    east = aws_lb_target_group.east.arn
  }
}

output "gwlb_endpoint_service_names" {
  value = {
    west = aws_vpc_endpoint_service.west.service_name
    east = aws_vpc_endpoint_service.east.service_name
  }
}

output "gwlb_endpoint_ids" {
  value = {
    west = { for subnet_id, ep in aws_vpc_endpoint.west : subnet_id => ep.id }
    east = { for subnet_id, ep in aws_vpc_endpoint.east : subnet_id => ep.id }
  }
}
