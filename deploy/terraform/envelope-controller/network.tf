resource "aws_security_group" "controller" {
  name_prefix            = "${var.name}-controller-"
  description            = "Standalone Envelope controller; private readiness ingress only"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, {
    Name = "${var.name}-controller"
    Role = "envelope-controller"
  })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [terraform_data.input_contract]
}

resource "aws_vpc_security_group_ingress_rule" "controller_metrics" {
  for_each = var.metrics_ingress_cidrs

  security_group_id = aws_security_group.controller.id
  description       = "Private controller metrics and readiness"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = var.metrics_port
  to_port           = var.metrics_port
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.controller.id
  description       = "AWS, Tailscale control, and DERP HTTPS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "vpc_dns_udp" {
  security_group_id = aws_security_group.controller.id
  description       = "VPC resolver UDP"
  cidr_ipv4         = data.aws_vpc.controller.cidr_block
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "vpc_dns_tcp" {
  security_group_id = aws_security_group.controller.id
  description       = "VPC resolver TCP"
  cidr_ipv4         = data.aws_vpc.controller.cidr_block
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "route53_resolver_udp" {
  security_group_id = aws_security_group.controller.id
  description       = "Route 53 Resolver link-local UDP"
  cidr_ipv4         = "169.254.169.253/32"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "route53_resolver_tcp" {
  security_group_id = aws_security_group.controller.id
  description       = "Route 53 Resolver link-local TCP"
  cidr_ipv4         = "169.254.169.253/32"
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "instance_metadata" {
  security_group_id = aws_security_group.controller.id
  description       = "IMDSv2 role credentials and private address"
  cidr_ipv4         = "169.254.169.254/32"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "amazon_time_sync" {
  security_group_id = aws_security_group.controller.id
  description       = "Amazon Time Sync Service"
  cidr_ipv4         = "169.254.169.123/32"
  ip_protocol       = "udp"
  from_port         = 123
  to_port           = 123
}
