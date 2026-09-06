terraform {
  required_version = ">= 1.10.1, < 1.11.0"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.33.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = merge(var.tags, {
      Component  = "envelope-controller"
      Deployment = var.name
      ManagedBy  = "Terraform"
    })
  }
}

data "aws_partition" "current" {}
