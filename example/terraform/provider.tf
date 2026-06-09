terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = ">= 2.0"
    }
  }
}

provider "aws" {
  region = var.west_region
}

provider "aws" {
  alias  = "east"
  region = var.east_region
}
