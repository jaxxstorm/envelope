data "aws_availability_zones" "west" {
  state = "available"
}

data "aws_availability_zones" "east" {
  provider = aws.east
  state    = "available"
}

module "vpc_west" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name               = "lbr-vpc-west"
  cidr               = var.west_vpc_cidr
  enable_nat_gateway = true

  azs             = slice(data.aws_availability_zones.west.names, 0, 3)
  private_subnets = var.west_private_subnets
  public_subnets  = var.west_public_subnets

  tags = merge(var.tags, {
    Site = "west"
  })
}

module "vpc_east" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  providers = {
    aws = aws.east
  }

  name               = "lbr-vpc-east"
  cidr               = var.east_vpc_cidr
  enable_nat_gateway = true

  azs             = slice(data.aws_availability_zones.east.names, 0, 3)
  private_subnets = var.east_private_subnets
  public_subnets  = var.east_public_subnets

  tags = merge(var.tags, {
    Site = "east"
  })
}

output "vpc_ids" {
  value = {
    west = module.vpc_west.vpc_id
    east = module.vpc_east.vpc_id
  }
}
