terraform {
  required_version = ">= 1.10.1, < 1.11.0"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.33.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "= 2.3.7"
    }
  }
}

provider "aws" {
  region = var.west_region

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias  = "east"
  region = var.east_region

  default_tags {
    tags = local.common_tags
  }
}
