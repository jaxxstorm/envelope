mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

mock_provider "aws" { alias = "east" }

variables {
  name                       = "envelope-plan"
  expires_at                 = "2030-01-01T00:00:00Z"
  west_region                = "us-west-2"
  east_region                = "us-east-1"
  architecture               = "amd64"
  west_ami_id                = "ami-0123456789abcdef0"
  east_ami_id                = "ami-0fedcba9876543210"
  artifact_path              = "../../testdata/deployment/artifact-fixture"
  artifact_sha256            = "61fad8c939a87bac8b2e11c53ad9b900ba335428a871a49bbb5d4245ed2b0fb4"
  artifact_revision          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  artifact_version           = "fixture.1"
  west_tailscale_secret_arn  = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-plan/tailscale-auth"
  east_tailscale_secret_arn  = "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-plan/tailscale-auth"
  west_tailscale_kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/west"
  east_tailscale_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/east"
  tailscale_tag              = "tag:envelope-ci"
  symmetric_topology = {
    version = 2
    sites = {
      west = {
        azs                    = { a = "us-west-2a", b = "us-west-2b" }
        vpc_cidr               = "172.16.0.0/16"
        local_site_cidrs       = ["172.16.0.0/24", "172.16.1.0/24"]
        remote_site_cidrs      = ["172.17.0.0/24", "172.17.1.0/24"]
        workload_subnet_cidrs  = { a = "172.16.0.0/24", b = "172.16.1.0/24" }
        ingress_subnet_cidrs   = { a = "172.16.10.0/24", b = "172.16.11.0/24" }
        gwlbe_subnet_cidrs     = { a = "172.16.20.0/24", b = "172.16.21.0/24" }
        gwlb_subnet_cidrs      = { a = "172.16.30.0/24", b = "172.16.31.0/24" }
        target_subnet_cidrs    = { a = "172.16.40.0/24", b = "172.16.41.0/24" }
        management_subnet_cidr = "172.16.50.0/24"
        target_az_keys         = ["a", "b"]
        ingress_router_az_keys = ["a", "b"]
      }
      east = {
        azs                    = { a = "us-east-1a", b = "us-east-1b" }
        vpc_cidr               = "172.17.0.0/16"
        local_site_cidrs       = ["172.17.0.0/24", "172.17.1.0/24"]
        remote_site_cidrs      = ["172.16.0.0/24", "172.16.1.0/24"]
        workload_subnet_cidrs  = { a = "172.17.0.0/24", b = "172.17.1.0/24" }
        ingress_subnet_cidrs   = { a = "172.17.10.0/24", b = "172.17.11.0/24" }
        gwlbe_subnet_cidrs     = { a = "172.17.20.0/24", b = "172.17.21.0/24" }
        gwlb_subnet_cidrs      = { a = "172.17.30.0/24", b = "172.17.31.0/24" }
        target_subnet_cidrs    = { a = "172.17.40.0/24", b = "172.17.41.0/24" }
        management_subnet_cidr = "172.17.50.0/24"
        target_az_keys         = ["a", "b"]
        ingress_router_az_keys = ["a", "b"]
      }
    }
  }
}

run "symmetric_two_az_paths" {
  command = plan

  assert {
    condition     = length(aws_vpc_endpoint.west) == 2 && length(aws_vpc_endpoint.east) == 2 && length(aws_instance.envelope_target_west) == 2 && length(aws_instance.envelope_target_east) == 2 && length(aws_instance.tailnet_ingress_west) == 2 && length(aws_instance.tailnet_ingress_east) == 2
    error_message = "every enabled AZ must have a GWLBE, target, and AZ-spread ingress router."
  }
  assert {
    condition     = alltrue([for target in values(aws_instance.envelope_target_west) : target.source_dest_check == false]) && alltrue([for target in values(aws_instance.envelope_target_east) : target.source_dest_check == false]) && alltrue([for router in values(aws_instance.tailnet_ingress_west) : router.source_dest_check == false]) && alltrue([for router in values(aws_instance.tailnet_ingress_east) : router.source_dest_check == false])
    error_message = "all forwarding targets and ingress routers must disable source/destination checks."
  }
  assert {
    condition     = output.envelope_runtime_config.west.config_version == 2 && toset(output.envelope_runtime_config.west.local_site_cidrs) == toset(var.symmetric_topology.sites.west.local_site_cidrs)
    error_message = "target service input must use v2 site CIDRs and target route tables must not target a GWLBE."
  }
}

run "reject_incomplete_target_fleet" {
  command = plan
  variables {
    symmetric_topology = merge(var.symmetric_topology, {
      sites = merge(var.symmetric_topology.sites, {
        west = merge(var.symmetric_topology.sites.west, { target_az_keys = ["a"] })
      })
    })
  }
  expect_failures = [var.symmetric_topology]
}
