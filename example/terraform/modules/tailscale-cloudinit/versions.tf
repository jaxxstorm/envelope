terraform {
  required_version = ">= 1.10.1, < 1.11.0"

  required_providers {
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "= 2.3.7"
    }
  }
}
