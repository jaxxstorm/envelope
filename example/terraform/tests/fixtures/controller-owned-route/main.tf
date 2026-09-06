terraform {
  required_version = ">= 1.10.0"
}

variable "configured_target" {
  type = string
}

variable "eligible_targets" {
  type = set(string)
}

resource "terraform_data" "route" {
  input = {
    route_table_id         = "rtb-workload"
    destination_cidr_block = "10.20.0.0/16"
    network_interface_id   = var.configured_target
  }

  lifecycle {
    ignore_changes = [input["network_interface_id"]]

    postcondition {
      condition     = contains(var.eligible_targets, self.output.network_interface_id)
      error_message = "The controller-owned route target must remain one of the eligible router ENIs."
    }
  }
}
