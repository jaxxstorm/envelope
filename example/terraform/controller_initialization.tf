variable "production_initial_router_owners" {
  description = "Deployment-only initial owner selection after native observer quorum, before domain initialization. Updating this input alone never reverts controller-owned targets."
  type        = map(map(string))
  default     = {}
  validation {
    condition = length(var.production_initial_router_owners) == 0 ? true : (
      var.symmetric_topology.version == 3 && toset(keys(var.production_initial_router_owners)) == toset(["west", "east"]) &&
      alltrue([for site, owners in var.production_initial_router_owners : toset(keys(owners)) == toset(keys(var.symmetric_topology.sites[site].azs)) && alltrue([for owner in owners : contains(var.symmetric_topology.sites[site].transport_router_az_keys, owner)])])
    )
    error_message = "Initial production owners must exactly cover each site's source AZs and name eligible same-site routers; legacy acceptance cannot use this input."
  }
}

locals {
  gwlbe_initial_owners = length(var.production_initial_router_owners) == 0 ? local.route_failover.initial_transport_router_az_by_gwlbe_az : var.production_initial_router_owners
}

output "router_attestor_enrollment_seed" {
  description = "Explicit nonsecret production enrollment authority derived from deployment-owned resources."
  value = var.symmetric_topology.version == 3 ? merge(
    { for key, instance in aws_instance.transport_router_west : "west-${key}" => {
      role_name         = aws_iam_role.transport_west.name
      security_group_id = aws_security_group.transport_west.id
      configuration = {
        router_id                = "west-${key}"
        underlay_interface       = var.envelope_underlay_interface
        maximum_tcp_mss          = var.e2e_load_profile.maximum_tcp_mss
        transport_route_table_id = aws_route_table.transport_west[key].id
        transport_association_id = aws_route_table_association.transport_west[key].id
        local_destinations       = [for az in sort(keys(local.sites.west.azs)) : { prefix = local.sites.west.workload_subnet_cidrs[az], workload_subnet_id = aws_subnet.workload_west[az].id, endpoint_id = aws_vpc_endpoint.west[az].id }]
      }
    } },
    { for key, instance in aws_instance.transport_router_east : "east-${key}" => {
      role_name         = aws_iam_role.transport_east.name
      security_group_id = aws_security_group.transport_east.id
      configuration = {
        router_id                = "east-${key}"
        underlay_interface       = var.envelope_underlay_interface
        maximum_tcp_mss          = var.e2e_load_profile.maximum_tcp_mss
        transport_route_table_id = aws_route_table.transport_east[key].id
        transport_association_id = aws_route_table_association.transport_east[key].id
        local_destinations       = [for az in sort(keys(local.sites.east.azs)) : { prefix = local.sites.east.workload_subnet_cidrs[az], workload_subnet_id = aws_subnet.workload_east[az].id, endpoint_id = aws_vpc_endpoint.east[az].id }]
      }
    } },
  ) : null
}
