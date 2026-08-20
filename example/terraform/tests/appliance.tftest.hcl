mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_ami" {
    defaults = {
      architecture = "x86_64"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["x86_64"]
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{}"
    }
  }
}

mock_provider "aws" {
  alias = "east"

  mock_data "aws_ami" {
    defaults = {
      architecture = "x86_64"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["x86_64"]
    }
  }
}

variables {
  name       = "envelope-plan"
  expires_at = "2030-01-01T00:00:00Z"

  west_azs = {
    a = "us-west-2a"
    b = "us-west-2b"
  }
  east_azs = {
    a = "us-east-1a"
    b = "us-east-1b"
  }
  west_appliance_az_key = "a"
  east_appliance_az_key = "a"

  west_public_subnet_cidr    = "172.16.40.0/24"
  east_public_subnet_cidr    = "172.17.40.0/24"
  west_appliance_subnet_cidr = "172.16.30.0/24"
  east_appliance_subnet_cidr = "172.17.30.0/24"
  west_workload_subnet_cidrs = { a = "172.16.0.0/24", b = "172.16.1.0/24" }
  east_workload_subnet_cidrs = { a = "172.17.0.0/24", b = "172.17.1.0/24" }
  west_gwlbe_subnet_cidrs    = { a = "172.16.10.0/24", b = "172.16.11.0/24" }
  east_gwlbe_subnet_cidrs    = { a = "172.17.10.0/24", b = "172.17.11.0/24" }
  west_gwlb_subnet_cidrs     = { a = "172.16.20.0/24", b = "172.16.21.0/24" }
  east_gwlb_subnet_cidrs     = { a = "172.17.20.0/24", b = "172.17.21.0/24" }

  architecture = "amd64"
  west_ami_id  = "ami-0123456789abcdef0"
  east_ami_id  = "ami-0fedcba9876543210"

  artifact_path     = "../../testdata/deployment/artifact-fixture"
  artifact_sha256   = "61fad8c939a87bac8b2e11c53ad9b900ba335428a871a49bbb5d4245ed2b0fb4"
  artifact_revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  artifact_version  = "fixture.1"

  west_tailscale_secret_arn  = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-plan/tailscale-auth"
  east_tailscale_secret_arn  = "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-plan/tailscale-auth"
  west_tailscale_kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/west"
  east_tailscale_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/east"
  tailscale_tag              = "tag:envelope-ci"

  envelope_gwlb_return_cidrs = {
    west = ["172.16.0.0/24"]
    east = ["172.17.1.0/24"]
  }
  envelope_local_delivery_cidrs = {
    west = ["172.16.1.0/24"]
    east = ["172.17.0.0/24"]
  }
  envelope_remote_tailnet_cidrs = {
    west = ["172.17.0.0/24", "172.17.1.0/24"]
    east = ["172.16.0.0/24", "172.16.1.0/24"]
  }
}

run "fresh_mocked_plan" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition     = length(aws_vpc_endpoint.west) == 2 && length(aws_vpc_endpoint.east) == 2
    error_message = "every explicit endpoint AZ must have one configuration-keyed GWLBE"
  }

  assert {
    condition = (
      length(aws_route.workload_to_remote_west) == 4 &&
      length(aws_route.workload_to_remote_east) == 4 &&
      toset([for route in aws_route.workload_to_remote_west : route.destination_cidr_block]) == toset(var.envelope_remote_tailnet_cidrs["west"]) &&
      toset([for route in aws_route.workload_to_remote_east : route.destination_cidr_block]) == toset(var.envelope_remote_tailnet_cidrs["east"])
    )
    error_message = "inspection routes must enumerate only configured remote workload/lane CIDRs in every AZ"
  }

  assert {
    condition     = aws_lb.west.enable_cross_zone_load_balancing && aws_lb.east.enable_cross_zone_load_balancing
    error_message = "both sole regional flow owners require explicit GWLB cross-zone behavior"
  }

  assert {
    condition     = aws_instance.envelope_west.associate_public_ip_address == false && aws_instance.envelope_east.associate_public_ip_address == false
    error_message = "appliances must use the one regional NAT instead of public addresses"
  }

  assert {
    condition     = output.cost_profile.resource_counts.nat_gateways == 2 && output.cost_profile.resource_counts.regional_targets == { west = 1, east = 1 }
    error_message = "cost and single-owner output shape changed"
  }

  assert {
    condition     = output.artifact_identity.sha256 == var.artifact_sha256 && output.artifact_identity.ec2_arch == "x86_64"
    error_message = "artifact identity must carry the reviewed digest and mapped EC2 architecture"
  }

  assert {
    condition = (
      strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), var.west_tailscale_secret_arn) &&
      strcontains(nonsensitive(base64decode(module.tailscale_client_east.rendered)), var.east_tailscale_secret_arn) &&
      !strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), "tskey-auth-") &&
      !strcontains(nonsensitive(base64decode(module.tailscale_client_east.rendered)), "tskey-auth-")
    )
    error_message = "rendered MIME must contain only regional SSM references, never auth-key material"
  }


  assert {
    condition = (
      strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), "tailscale_1.80.3_x86_64.rpm") &&
      strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), "aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2") &&
      !strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), "tailscale.com/install.sh") &&
      !strcontains(nonsensitive(base64decode(module.tailscale_client_west.rendered)), "TRACK=")
    )
    error_message = "rendered MIME must install only the exact checksummed Tailscale package before auth"
  }

  assert {
    condition = (
      strcontains(output.appliance_runtime_policy_json.west, var.west_tailscale_secret_arn) &&
      !strcontains(output.appliance_runtime_policy_json.west, var.east_tailscale_secret_arn) &&
      strcontains(output.appliance_runtime_policy_json.east, var.east_tailscale_secret_arn) &&
      !strcontains(output.appliance_runtime_policy_json.east, var.west_tailscale_secret_arn) &&
      strcontains(output.appliance_runtime_policy_json.west, "kms:EncryptionContext:PARAMETER_ARN") &&
      strcontains(output.appliance_runtime_policy_json.east, "kms:EncryptionContext:PARAMETER_ARN")
    )
    error_message = "each appliance policy must be site-isolated with exact SSM/KMS encryption context"
  }
}

run "second_name_is_disjoint" {
  command = plan

  variables {
    name                      = "envelope-other"
    west_tailscale_secret_arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-other/tailscale-auth"
    east_tailscale_secret_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/envelope-other/tailscale-auth"
  }

  assert {
    condition = (
      aws_lb.west.name == "envelope-other-west-gwlb" &&
      aws_iam_role.appliance_west.name == "envelope-other-west-appliance" &&
      startswith(aws_s3_bucket.artifact.bucket, "envelope-other-")
    )
    error_message = "run-scoped names must derive from the validated name input"
  }
}

run "reject_overlong_name" {
  command = plan

  variables {
    name = "envelope-name-is-too-long"
  }

  expect_failures = [var.name]
}

run "reject_multiple_targets" {
  command = plan

  variables {
    appliance_target_count = 2
  }

  expect_failures = [var.appliance_target_count]
}

run "reject_overlapping_site_roles" {
  command = plan

  variables {
    envelope_local_delivery_cidrs = {
      west = ["172.16.0.128/25"]
      east = ["172.17.0.0/24"]
    }
  }

  expect_failures = [terraform_data.input_validation]
}

run "reject_architecture_mismatch" {
  command = plan

  override_data {
    target = data.aws_ami.west
    values = {
      architecture = "arm64"
    }
  }

  expect_failures = [aws_instance.envelope_west, aws_instance.test_west]
}
