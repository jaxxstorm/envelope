mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
  mock_data "aws_instance" {
    defaults = {
      instance_state         = "running"
      source_dest_check      = false
      network_interface_id   = "eni-33333333333333333"
      subnet_id              = "subnet-33333333333333333"
      availability_zone      = "us-east-1a"
      iam_instance_profile   = "test-transport-profile"
      private_ip             = "10.20.3.10"
      vpc_security_group_ids = ["sg-33333333333333333"]
    }
  }
  mock_data "aws_iam_instance_profile" { defaults = { role_name = "test-transport" } }
  mock_data "aws_iam_role" { defaults = { tags = { Role = "transport-router" } } }
  mock_data "aws_security_group" { defaults = { vpc_id = "vpc-22222222222222222" } }
  mock_resource "aws_ssm_parameter" { defaults = { version = 1, arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/enrollment" } }
  mock_resource "aws_s3_object" { defaults = { version_id = "immutable-configuration-version", arn = "arn:aws:s3:::test-configurations/configurations/config.json" } }
}

variables {
  name                    = "attestor-test"
  authority_region        = "us-west-2"
  controller_source_cidrs = ["10.30.0.0/24"]
  enrollments = {
    east-a = {
      configuration_identity_json = jsonencode({
        schema                = 1
        component             = "envelope-router-attestor"
        version               = "test.1"
        revision              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        source_modified       = false
        go_version            = "go1.26.2"
        router_id             = "east-a"
        ed25519_public_key    = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        topology_sha256       = "711d87ffd52e3e400d5b846b604d74aa7f5094a057bcdfcd406de37e3d9786c7"
        canonical_json_base64 = base64encode(trimspace(file("tests/fixtures/configuration.json")))
        canonical_sha256      = sha256(trimspace(file("tests/fixtures/configuration.json")))
      })
      configuration_parameter_name = "/envelope/test/east-a/enrollment-one"
      seed_parameter_arn           = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/east-a/seed-one"
      seed_version                 = 1
      seed_kms_key_arn             = "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-4000-8000-000000000000"
      role_name                    = "test-transport"
      security_group_id            = "sg-33333333333333333"
    }
  }
}

run "immutable_enrollment_and_source_instance_boundary" {
  command = apply
  assert {
    condition = (
      aws_s3_bucket_versioning.configurations.versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_public_access_block.configurations.block_public_policy &&
      jsondecode(aws_ssm_parameter.binding["east-a"].value).instance_id == "i-33333333333333333" &&
      jsondecode(aws_ssm_parameter.binding["east-a"].value).configuration_sha256 == "f6262ec7791d73f2e0c079625729cd56c1b543a237582845d5c1e600ec87b0cf" &&
      jsondecode(aws_ssm_parameter.configuration["east-a"].value).version_id == "immutable-configuration-version" &&
      jsondecode(aws_iam_role_policy.router["east-a"].policy).Statement[3].Effect == "Deny" &&
      jsondecode(aws_iam_role_policy.router["east-a"].policy).Statement[3].Condition.ArnNotEquals["ec2:SourceInstanceARN"] == "arn:aws:ec2:us-east-1:123456789012:instance/i-33333333333333333" &&
      !contains(jsondecode(aws_iam_role_policy.router["east-a"].policy).Statement[0].NotAction, "ec2:ReplaceRoute")
    )
    error_message = "Enrollment must retain immutable content/key binding and explicitly deny cross-instance reads and route mutation."
  }
}

run "reject_wrong_instance_eni" {
  command = plan
  override_data {
    target = data.aws_instance.router["east-a"]
    values = { network_interface_id = "eni-99999999999999999" }
  }
  expect_failures = [terraform_data.contract["east-a"]]
}

run "reject_non_transport_role" {
  command = plan
  override_data {
    target = data.aws_iam_role.router["east-a"]
    values = { tags = { Role = "envelope-controller" } }
  }
  expect_failures = [terraform_data.contract["east-a"]]
}

run "reject_role_profile_mismatch" {
  command = plan
  override_data {
    target = data.aws_iam_instance_profile.router["east-a"]
    values = { role_name = "another-role" }
  }
  expect_failures = [terraform_data.contract["east-a"]]
}

run "reject_public_ingress" {
  command = plan
  variables { controller_source_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.controller_source_cidrs]
}

run "reject_reassigned_key_binding" {
  command = apply
  module { source = "./" }
  override_resource {
    target = aws_ssm_parameter.binding["east-a"]
    values = { version = 2 }
  }
  expect_failures = [aws_ssm_parameter.binding["east-a"]]
}
