run "deployment_lifecycle_rollout_scope" {
  command = apply
  variables {
    deployment_lifecycle = {
      trusted_principal_arns = ["arn:aws:iam::123456789012:role/reviewed-deployer"]
      external_id            = "reviewed-deployment-identity"
      rollout = {
        state_bucket_arn = "arn:aws:s3:::reviewed-controller-state"
        state_key        = "controller/terraform.tfstate"
        kms_key_arns     = ["arn:aws:kms:us-west-2:123456789012:key/00000000-0000-4000-8000-000000000000"]
      }
    }
  }
  assert {
    condition = (
      !contains(jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[0].NotAction, "ec2:ReplaceRoute") &&
      !contains(jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[0].NotAction, "iam:PutRolePolicy") &&
      one([for statement in jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement : statement.Resource if statement.Sid == "ExactTerraformBackend"]) == [
        "arn:aws:s3:::reviewed-controller-state/controller/terraform.tfstate",
        "arn:aws:s3:::reviewed-controller-state/controller/terraform.tfstate.tflock",
      ]
    )
    error_message = "Rollout authority must remain route-denied and confined to the reviewed state and lock objects."
  }
}

run "reject_incomplete_router_enrollment" {
  command = plan
  variables {
    router_attestations = {
      east-a = { ed25519_public_key = "1111111111111111111111111111111111111111111111111111111111111111", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://east-a.example.com/attestation" }
    }
  }
  expect_failures = [aws_ssm_parameter.router_trust]
}

run "reject_shared_router_enrollment_key" {
  command = plan
  variables {
    router_attestations = {
      east-a = { ed25519_public_key = "1111111111111111111111111111111111111111111111111111111111111111", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://east-a.example.com/attestation" }
      east-b = { ed25519_public_key = "1111111111111111111111111111111111111111111111111111111111111111", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://east-b.example.com/attestation" }
      west-a = { ed25519_public_key = "3333333333333333333333333333333333333333333333333333333333333333", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://west-a.example.com/attestation" }
      west-b = { ed25519_public_key = "4444444444444444444444444444444444444444444444444444444444444444", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://west-b.example.com/attestation" }
    }
  }
  expect_failures = [var.router_attestations]
}

run "deployment_lifecycle_trust_and_route_deny" {
  command = apply
  variables {
    deployment_lifecycle = {
      trusted_principal_arns = ["arn:aws:iam::123456789012:role/reviewed-deployer"]
      external_id            = "reviewed-deployment-identity"
    }
  }
  assert {
    condition = (
      jsondecode(aws_iam_role.deployment_lifecycle[0].assume_role_policy).Statement[0].Condition.StringEquals["sts:ExternalId"] == "reviewed-deployment-identity" &&
      jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[0].Effect == "Deny" &&
      !contains(jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[0].NotAction, "ec2:ReplaceRoute") &&
      !contains(jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[0].NotAction, "sts:AssumeRole") &&
      jsondecode(aws_iam_role_policy.deployment_lifecycle[0].policy).Statement[3].Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["deployment#envelope-controller-test", "lifecycle#envelope-controller-test"]
    )
    error_message = "Lifecycle authority must be separately trusted, route-denied, and isolated from observer publication."
  }
}

run "reject_lifecycle_wildcard_trust" {
  command = plan
  variables {
    deployment_lifecycle = {
      trusted_principal_arns = ["*"]
      external_id            = "reviewed-deployment-identity"
    }
  }
  expect_failures = [var.deployment_lifecycle]
}

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_vpc" {
    defaults = {
      id                   = "vpc-00000000000000000"
      cidr_block           = "10.0.0.0/16"
      enable_dns_support   = true
      enable_dns_hostnames = true
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id                  = "ami-00000000000000000"
      image_id            = "ami-00000000000000000"
      owner_id            = "123456789012"
      architecture        = "x86_64"
      root_device_type    = "ebs"
      virtualization_type = "hvm"
      state               = "available"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      instance_type           = "t3.small"
      supported_architectures = ["x86_64"]
    }
  }

  mock_data "aws_iam_role" {
    defaults = {
      name = "envelope-readiness-publisher"
      arn  = "arn:aws:iam::123456789012:role/monitoring/envelope-readiness-publisher"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-4000-8000-000000000000"
      key_id = "00000000-0000-4000-8000-000000000000"
    }
  }

  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-west-2:123456789012:table/envelope-controller-test-authority"
    }
  }

  mock_resource "aws_ssm_parameter" {
    defaults = {
      arn = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-controller-test/topology"
    }
  }

  mock_resource "aws_ebs_volume" {
    defaults = {
      id = "vol-00000000000000000"
    }
  }

  mock_resource "aws_instance" {
    defaults = {
      id         = "i-00000000000000000"
      private_ip = "10.0.1.10"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/envelope-controller-test-controller"
    }
  }

  mock_resource "aws_iam_instance_profile" {
    defaults = {
      arn = "arn:aws:iam::123456789012:instance-profile/envelope-controller-test-controller"
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-a"]
    values = {
      id                      = "subnet-00000000000000001"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2a"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-b"]
    values = {
      id                      = "subnet-00000000000000002"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2b"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-c"]
    values = {
      id                      = "subnet-00000000000000003"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2c"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.managed_gwlbe["west-workload"]
    values = {
      id                = "subnet-55555555555555555"
      vpc_id            = "vpc-11111111111111111"
      availability_zone = "us-west-2a"
    }
  }

  override_data {
    target = data.aws_subnet.managed_gwlbe["east-workload"]
    values = {
      id                = "subnet-66666666666666666"
      vpc_id            = "vpc-22222222222222222"
      availability_zone = "us-east-1a"
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-a"]
    values = {
      id     = "rtb-00000000000000001"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000001"
        route_table_id             = "rtb-00000000000000001"
        subnet_id                  = "subnet-00000000000000001"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000001"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-b"]
    values = {
      id     = "rtb-00000000000000002"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000002"
        route_table_id             = "rtb-00000000000000002"
        subnet_id                  = "subnet-00000000000000002"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000002"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-c"]
    values = {
      id     = "rtb-00000000000000003"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000003"
        route_table_id             = "rtb-00000000000000003"
        subnet_id                  = "subnet-00000000000000003"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000003"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-a"]
    values = {
      id                = "nat-00000000000000001"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000011"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-b"]
    values = {
      id                = "nat-00000000000000002"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000012"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-c"]
    values = {
      id                = "nat-00000000000000003"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000013"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-a"]
    values = {
      id                = "subnet-00000000000000011"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2a"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-b"]
    values = {
      id                = "subnet-00000000000000012"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2b"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-c"]
    values = {
      id                = "subnet-00000000000000013"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2c"
    }
  }

  override_data {
    target = data.aws_route_table.management_nat["controller-a"]
    values = {
      id     = "rtb-00000000000000021"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000021"
        route_table_id             = "rtb-00000000000000021"
        subnet_id                  = "subnet-00000000000000011"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = "igw-00000000000000000"
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_nat["controller-b"]
    values = {
      id     = "rtb-00000000000000022"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000022"
        route_table_id             = "rtb-00000000000000022"
        subnet_id                  = "subnet-00000000000000012"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = "igw-00000000000000000"
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_nat["controller-c"]
    values = {
      id     = "rtb-00000000000000023"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000023"
        route_table_id             = "rtb-00000000000000023"
        subnet_id                  = "subnet-00000000000000013"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = "igw-00000000000000000"
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_internet_gateway.management_egress["igw-00000000000000000"]
    values = {
      id = "igw-00000000000000000"
      attachments = [{
        state  = "available"
        vpc_id = "vpc-00000000000000000"
      }]
    }
  }

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.20.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-22222222222222222"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.managed["east-workload"]
    values = {
      id     = "rtb-22222222222222222"
      vpc_id = "vpc-22222222222222222"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-22222222222222222"
        route_table_id             = "rtb-22222222222222222"
        subnet_id                  = "subnet-66666666666666666"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.10.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-33333333333333333"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }
}

variables {
  router_attestations = {
    east-a = { ed25519_public_key = "1111111111111111111111111111111111111111111111111111111111111111", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://east-a.example.com/attestation" }
    east-b = { ed25519_public_key = "2222222222222222222222222222222222222222222222222222222222222222", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://east-b.example.com/attestation" }
    west-a = { ed25519_public_key = "3333333333333333333333333333333333333333333333333333333333333333", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://west-a.example.com/attestation" }
    west-b = { ed25519_public_key = "4444444444444444444444444444444444444444444444444444444444444444", configuration_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url = "https://west-b.example.com/attestation" }
  }
  name                             = "envelope-controller-test"
  aws_region                       = "us-west-2"
  aws_account_id                   = "123456789012"
  vpc_id                           = "vpc-00000000000000000"
  controller_ami_id                = "ami-00000000000000000"
  controller_ami_trusted_owner_ids = ["123456789012"]
  controller_architecture          = "amd64"
  authority_table_name             = "envelope-controller-test-authority"
  controller_ids                   = ["controller-a", "controller-b", "controller-c"]
  controller_placements = {
    controller-a = { subnet_id = "subnet-00000000000000001", availability_zone = "us-west-2a" }
    controller-b = { subnet_id = "subnet-00000000000000002", availability_zone = "us-west-2b" }
    controller-c = { subnet_id = "subnet-00000000000000003", availability_zone = "us-west-2c" }
  }
  management_egress = {
    controller-a = { route_table_id = "rtb-00000000000000001", nat_gateway_id = "nat-00000000000000001", nat_subnet_id = "subnet-00000000000000011", nat_route_table_id = "rtb-00000000000000021", internet_gateway_id = "igw-00000000000000000" }
    controller-b = { route_table_id = "rtb-00000000000000002", nat_gateway_id = "nat-00000000000000002", nat_subnet_id = "subnet-00000000000000012", nat_route_table_id = "rtb-00000000000000022", internet_gateway_id = "igw-00000000000000000" }
    controller-c = { route_table_id = "rtb-00000000000000003", nat_gateway_id = "nat-00000000000000003", nat_subnet_id = "subnet-00000000000000013", nat_route_table_id = "rtb-00000000000000023", internet_gateway_id = "igw-00000000000000000" }
  }
  topology_identity_json = jsonencode({
    schema                = 1
    component             = "envelope-controller-topology"
    version               = "1.2.3"
    revision              = "cccccccccccccccccccccccccccccccccccccccc"
    go_version            = "go1.26.2"
    vcs_modified          = false
    canonical_sha256      = sha256(trimspace(file("tests/fixtures/topology.json")))
    canonical_json_base64 = base64encode(trimspace(file("tests/fixtures/topology.json")))
    policy_durations = {
      observation_interval      = "2s"
      observation_freshness     = "6s"
      failover_stability        = "6s"
      failback_stability        = "20s"
      cooldown                  = "30s"
      lease_duration            = "30s"
      lease_renew_interval      = "5s"
      lease_danger_window       = "6s"
      api_timeout               = "2s"
      route_convergence_timeout = "4s"
    }
  })
  topology_parameter_name  = "/envelope-controller-test/controller/topology"
  artifact_manifest_json   = trimspace(file("tests/fixtures/controller-manifest.json"))
  artifact_manifest_sha256 = "a3d337fbc229cc36dc09042856264efd07049532491eba304169eb2e3132ff0e"
  artifact = {
    region      = "us-west-2"
    bucket_name = "envelope-controller-test-artifacts"
    bucket_arn  = "arn:aws:s3:::envelope-controller-test-artifacts"
    object_key  = "controller/envelope-controller-linux-amd64"
    object_arn  = "arn:aws:s3:::envelope-controller-test-artifacts/controller/envelope-controller-linux-amd64"
    version_id  = "test-version-id"
    sha256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  topology_identity_artifact = {
    region      = "us-west-2"
    bucket_name = "envelope-controller-test-artifacts"
    bucket_arn  = "arn:aws:s3:::envelope-controller-test-artifacts"
    object_key  = "controller/envelope-controller-topology-linux-amd64"
    object_arn  = "arn:aws:s3:::envelope-controller-test-artifacts/controller/envelope-controller-topology-linux-amd64"
    version_id  = "topology-version-id"
    sha256      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
  secret_parameters = {
    tsnet = {
      name        = "/envelope-controller-test/controller/tsnet-auth"
      arn         = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-controller-test/controller/tsnet-auth"
      kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"
    }
    admin = {
      name        = "/envelope-controller-test/controller/admin-api"
      arn         = "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-controller-test/controller/admin-api"
      kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-4222-8222-222222222222"
    }
  }
  managed_route_tables = {
    east-workload = {
      region                     = "us-east-1"
      vpc_id                     = "vpc-22222222222222222"
      route_table_id             = "rtb-22222222222222222"
      route_table_arn            = "arn:aws:ec2:us-east-1:123456789012:route-table/rtb-22222222222222222"
      gwlbe_subnet_id            = "subnet-66666666666666666"
      route_table_association_id = "rtbassoc-22222222222222222"
      source_prefix              = "10.20.0.0/24"
      destination_cidrs          = ["10.10.0.0/24"]
      eligible_eni_ids           = ["eni-33333333333333333", "eni-44444444444444444"]
    }
    west-workload = {
      region                     = "us-west-2"
      vpc_id                     = "vpc-11111111111111111"
      route_table_id             = "rtb-11111111111111111"
      route_table_arn            = "arn:aws:ec2:us-west-2:123456789012:route-table/rtb-11111111111111111"
      gwlbe_subnet_id            = "subnet-55555555555555555"
      route_table_association_id = "rtbassoc-11111111111111111"
      source_prefix              = "10.10.0.0/24"
      destination_cidrs          = ["10.20.0.0/24"]
      eligible_eni_ids           = ["eni-11111111111111111", "eni-22222222222222222"]
    }
  }
  transport_topology = {
    east = {
      local_prefixes                = ["10.20.0.0/24"]
      local_main_rule_priority_base = 100
      tailscale_route_rule_priority = 5270
      routers = {
        east-a = {
          stable_node_id                    = "node-east-a"
          instance_id                       = "i-33333333333333333"
          eni_id                            = "eni-33333333333333333"
          expected_advertised_prefixes      = ["10.20.0.0/24"]
          expected_enabled_prefixes         = ["10.20.0.0/24"]
          expected_accepted_remote_prefixes = ["10.10.0.0/24"]
          expected_local_main_prefixes      = ["10.20.0.0/24"]
        }
        east-b = {
          stable_node_id                    = "node-east-b"
          instance_id                       = "i-44444444444444444"
          eni_id                            = "eni-44444444444444444"
          expected_advertised_prefixes      = ["10.20.0.0/24"]
          expected_enabled_prefixes         = ["10.20.0.0/24"]
          expected_accepted_remote_prefixes = ["10.10.0.0/24"]
          expected_local_main_prefixes      = ["10.20.0.0/24"]
        }
      }
    }
    west = {
      local_prefixes                = ["10.10.0.0/24"]
      local_main_rule_priority_base = 100
      tailscale_route_rule_priority = 5270
      routers = {
        west-a = {
          stable_node_id                    = "node-west-a"
          instance_id                       = "i-11111111111111111"
          eni_id                            = "eni-11111111111111111"
          expected_advertised_prefixes      = ["10.10.0.0/24"]
          expected_enabled_prefixes         = ["10.10.0.0/24"]
          expected_accepted_remote_prefixes = ["10.20.0.0/24"]
          expected_local_main_prefixes      = ["10.10.0.0/24"]
        }
        west-b = {
          stable_node_id                    = "node-west-b"
          instance_id                       = "i-22222222222222222"
          eni_id                            = "eni-22222222222222222"
          expected_advertised_prefixes      = ["10.10.0.0/24"]
          expected_enabled_prefixes         = ["10.10.0.0/24"]
          expected_accepted_remote_prefixes = ["10.20.0.0/24"]
          expected_local_main_prefixes      = ["10.10.0.0/24"]
        }
      }
    }
  }
  metrics_ingress_cidrs = ["10.0.0.0/8"]
  readiness_publisher = {
    id                      = "central-readiness"
    role_name               = "envelope-readiness-publisher"
    role_arn                = "arn:aws:iam::123456789012:role/monitoring/envelope-readiness-publisher"
    source_cidrs            = ["10.0.0.0/8"]
    scrape_interval_seconds = 30
  }
  alarm_actions = ["arn:aws:sns:us-west-2:123456789012:controller-alarms"]
}

run "dynamodb_cmk_policy_contract" {
  command = apply

  assert {
    condition = (
      length(aws_kms_key.controller) == 1 &&
      aws_dynamodb_table.authority.server_side_encryption[0].enabled == true &&
      aws_dynamodb_table.authority.server_side_encryption[0].kms_key_arn == local.controller_kms_key_arn &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        length([for statement in statements : statement if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == 1 &&
        one([for statement in statements : statement.Action if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == ["kms:Decrypt"] &&
        one([for statement in statements : statement.Resource if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == [local.controller_kms_key_arn] &&
        toset(keys(one([for statement in statements : statement.Condition.StringEquals if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]))) == toset([
          "kms:CallerAccount",
          "kms:EncryptionContext:aws:dynamodb:subscriberId",
          "kms:EncryptionContext:aws:dynamodb:tableName",
          "kms:ViaService",
        ]) &&
        one([for statement in statements : statement.Condition.StringEquals["kms:CallerAccount"] if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == "123456789012" &&
        one([for statement in statements : statement.Condition.StringEquals["kms:EncryptionContext:aws:dynamodb:subscriberId"] if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == "123456789012" &&
        one([for statement in statements : statement.Condition.StringEquals["kms:EncryptionContext:aws:dynamodb:tableName"] if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == "envelope-controller-test-authority" &&
        one([for statement in statements : statement.Condition.StringEquals["kms:ViaService"] if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == "dynamodb.us-west-2.amazonaws.com" &&
        one([for statement in statements : statement.Condition["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"] if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == [
          "aws:dynamodb:subscriberId",
          "aws:dynamodb:tableName",
        ] &&
        alltrue([
          for secret_name in ["tsnet", "admin"] :
          length([for statement in statements : statement if statement.Sid == "Decrypt${title(secret_name)}ParameterOnly"]) == 1 &&
          one([for statement in statements : statement.Action if statement.Sid == "Decrypt${title(secret_name)}ParameterOnly"]) == ["kms:Decrypt"] &&
          one([for statement in statements : statement.Resource if statement.Sid == "Decrypt${title(secret_name)}ParameterOnly"]) == [var.secret_parameters[secret_name].kms_key_arn] &&
          one([for statement in statements : statement.Condition.StringEquals["kms:EncryptionContext:PARAMETER_ARN"] if statement.Sid == "Decrypt${title(secret_name)}ParameterOnly"]) == var.secret_parameters[secret_name].arn &&
          one([for statement in statements : statement.Condition.StringEquals["kms:ViaService"] if statement.Sid == "Decrypt${title(secret_name)}ParameterOnly"]) == "ssm.us-west-2.amazonaws.com"
        ])
      ])
    )
    error_message = "normal production controller roles must decrypt only the exact authority CMK through regional DynamoDB with the exact table/account context, independently of exact SSM decrypt grants."
  }
}

run "protected_acceptance_cleanup_contract" {
  command = plan

  variables {
    protected_acceptance_mode = true
    tags = {
      EnvelopeRun = "envelope-controller-test"
      ExpiresAt   = "2030-01-01T00:00:00Z"
    }
  }

  assert {
    condition = (
      length(aws_kms_key.controller) == 0 &&
      aws_dynamodb_table.authority.deletion_protection_enabled == false &&
      aws_dynamodb_table.authority.server_side_encryption[0].enabled == false &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        length([for statement in statements : statement if statement.Sid == "DecryptDynamoDBAuthorityTableOnly"]) == 0 &&
        length([for statement in statements : statement if endswith(statement.Sid, "ParameterOnly")]) == 2
      ]) &&
      alltrue(flatten([
        for statements in values(local.controller_policy_statements) : [
          for statement in statements : [
            for resource in statement.Resource : resource != null
          ]
        ]
      ])) &&
      alltrue([for volume in values(aws_ebs_volume.observer_state) : volume.final_snapshot == false]) &&
      output.protected_acceptance_lifecycle == {
        enabled                      = true
        dynamodb_deletion_protection = false
        observer_final_snapshots     = false
        customer_managed_storage_key = false
      }
    )
    error_message = "protected acceptance must be encrypted with AWS-managed keys and leave no protected table, CMK, or final observer snapshot behind."
  }
}

run "standalone_controller_contract" {
  command = plan

  override_data {
    target = data.aws_subnet.controller["controller-a"]
    values = {
      id                      = "subnet-00000000000000001"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2a"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-b"]
    values = {
      id                      = "subnet-00000000000000002"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2b"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-c"]
    values = {
      id                      = "subnet-00000000000000003"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2c"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-a"]
    values = {
      id     = "rtb-00000000000000001"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000001"
        route_table_id             = "rtb-00000000000000001"
        subnet_id                  = "subnet-00000000000000001"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000001"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-b"]
    values = {
      id     = "rtb-00000000000000002"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000002"
        route_table_id             = "rtb-00000000000000002"
        subnet_id                  = "subnet-00000000000000002"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000002"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-c"]
    values = {
      id     = "rtb-00000000000000003"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000003"
        route_table_id             = "rtb-00000000000000003"
        subnet_id                  = "subnet-00000000000000003"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000003"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-a"]
    values = {
      id                = "nat-00000000000000001"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000011"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-b"]
    values = {
      id                = "nat-00000000000000002"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000012"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-c"]
    values = {
      id                = "nat-00000000000000003"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000013"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-a"]
    values = {
      id                = "subnet-00000000000000011"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2a"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-b"]
    values = {
      id                = "subnet-00000000000000012"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2b"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-c"]
    values = {
      id                = "subnet-00000000000000013"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2c"
    }
  }

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.20.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-22222222222222222"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.managed["east-workload"]
    values = {
      id     = "rtb-22222222222222222"
      vpc_id = "vpc-22222222222222222"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-22222222222222222"
        route_table_id             = "rtb-22222222222222222"
        subnet_id                  = "subnet-66666666666666666"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.10.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-33333333333333333"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  assert {
    condition = (
      length(aws_instance.controller) == 3 &&
      length(aws_iam_role.controller) == 3 &&
      length(aws_iam_instance_profile.controller) == 3 &&
      length(distinct([for profile in values(aws_iam_instance_profile.controller) : profile.name])) == 3 &&
      length(distinct([for instance in values(aws_instance.controller) : instance.availability_zone])) == 3 &&
      alltrue([
        for controller_id, instance in aws_instance.controller :
        instance.associate_public_ip_address == false &&
        instance.source_dest_check == true &&
        instance.ami == data.aws_ami.controller.id &&
        instance.iam_instance_profile == aws_iam_instance_profile.controller[controller_id].name
      ]) &&
      data.aws_ami.controller.owner_id == "123456789012" &&
      data.aws_ami.controller.architecture == "x86_64" &&
      data.aws_ami.controller.root_device_type == "ebs" &&
      data.aws_ami.controller.virtualization_type == "hvm" &&
      data.aws_ami.controller.state == "available" &&
      output.artifact_identity.architecture == "amd64" &&
      output.artifact_identity.ec2_architecture == "x86_64" &&
      output.artifact_identity.revision == "cccccccccccccccccccccccccccccccccccccccc" &&
      output.artifact_identity.version == "1.2.3" &&
      output.artifact_identity.go_version == "go1.26.2" &&
      output.artifact_identity.vcs_modified == false
    )
    error_message = "three private replicas must use unique profiles and the manifest-bound trusted AMI, architecture, source revision, version, and toolchain."
  }

  assert {
    condition = (
      length(output.management_egress) == 3 &&
      length(distinct([for contract in values(output.management_egress) : contract.nat_gateway_id])) == 3 &&
      alltrue([
        for controller_id, contract in output.management_egress :
        contract.controller_subnet_id == var.controller_placements[controller_id].subnet_id &&
        contract.availability_zone == data.aws_subnet.management_nat[controller_id].availability_zone &&
        contract.connectivity_type == "public" &&
        contract.state == "available"
      ])
    )
    error_message = "every replica must expose a distinct available same-AZ public NAT egress contract."
  }

  assert {
    condition = (
      aws_dynamodb_table.authority.billing_mode == "PAY_PER_REQUEST" &&
      aws_dynamodb_table.authority.deletion_protection_enabled == true &&
      aws_dynamodb_table.authority.point_in_time_recovery[0].enabled == true &&
      aws_dynamodb_table.authority.server_side_encryption[0].enabled == true &&
      aws_dynamodb_table.authority.ttl[0].enabled == true &&
      aws_dynamodb_table.authority.ttl[0].attribute_name == "ttl"
    )
    error_message = "the DynamoDB authority must retain encryption, PITR, deletion protection, on-demand billing, and ttl."
  }

  assert {
    condition = (
      var.deployment_mode == "read-only" &&
      toset(flatten([
        for statements in values(local.controller_policy_statements) : [
          for statement in statements : statement.Action
        ]
        ])) == toset([
        "dynamodb:GetItem", "dynamodb:PutItem", "ssm:GetParameter", "s3:GetObjectVersion",
        "ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables",
        "kms:Decrypt",
      ]) &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        length([for statement in statements : statement if statement.Sid == "WriteDomainAuthority"]) == 0
      ]) &&
      alltrue([
        for controller_id, statements in local.controller_policy_statements :
        toset(one([for statement in statements : statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] if statement.Sid == "PublishObservation"])) == toset([local.observation_partition_keys[controller_id]])
      ]) &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        toset(one([for statement in statements : statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] if statement.Sid == "ReadObservationQuorum"])) == toset(local.observation_partition_key_values)
      ]) &&
      output.controller_iam.deployment_mode == "read-only" &&
      toset(output.controller_iam.readable_observation_partition_keys) == toset(local.observation_partition_key_values) &&
      alltrue([
        for controller_id, replica in output.controller_iam.replicas :
        replica.observation_partition_key == local.observation_partition_keys[controller_id]
      ]) &&
      length(output.controller_iam.exact_route_table_arns) == 0
    )
    error_message = "read-only IAM must retain observation publication/quorum reads but omit domain and route mutation."
  }

  assert {
    condition = (
      one([
        for statement in local.controller_policy_statements["controller-a"] :
        statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]
        if statement.Sid == "PublishObservation"
      ]) == [local.observation_partition_keys["controller-a"]] &&
      !contains(
        one([
          for statement in local.controller_policy_statements["controller-a"] :
          statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]
          if statement.Sid == "PublishObservation"
        ]),
        local.observation_partition_keys["controller-b"],
      )
    )
    error_message = "controller-a credentials must not authorize an observation claiming controller-b."
  }

  assert {
    condition = (
      output.dynamic_route_ownership.terraform_manages_target == false &&
      output.dynamic_route_ownership.deployment_mode == "read-only" &&
      output.dynamic_route_ownership.controller_action == null &&
      output.dynamic_route_ownership.domains["west-workload"].gwlbe_subnet_id == "subnet-55555555555555555" &&
      output.dynamic_route_ownership.domains["west-workload"].route_table_association_id == "rtbassoc-11111111111111111" &&
      output.dynamic_route_ownership.domains["west-workload"].observed_target_by_cidr["10.20.0.0/24"] == "eni-22222222222222222" &&
      output.dynamic_route_ownership.domains["east-workload"].observed_target_by_cidr["10.10.0.0/24"] == "eni-33333333333333333"
    )
    error_message = "existing exact routes must be validated and reported without Terraform target ownership."
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.instance_status) == 3 &&
      length(aws_cloudwatch_metric_alarm.dynamodb_throttles) == 2 &&
      toset(flatten([
        for query in aws_cloudwatch_metric_alarm.dynamodb_system_errors.metric_query : [
          for metric in query.metric : metric.dimensions.Operation
        ]
      ])) == toset(["GetItem", "PutItem"]) &&
      length(aws_cloudwatch_metric_alarm.controller_ready) == 3 &&
      alltrue([for alarm in values(aws_cloudwatch_metric_alarm.controller_ready) : toset(alarm.alarm_actions) == var.alarm_actions]) &&
      alltrue([for alarm in values(aws_cloudwatch_metric_alarm.controller_ready) : alarm.dimensions.PublisherId == var.readiness_publisher.id]) &&
      output.controller_ready_metric_assumptions.controller_can_publish == false &&
      output.controller_ready_metric_assumptions.publisher.role_arn == var.readiness_publisher.role_arn &&
      output.controller_ready_metric_assumptions.scrape_interval_seconds == 30 &&
      length(output.controller_ready_metric_assumptions.targets) == 3 &&
      output.controller_ready_metric_assumptions.targets["controller-a"].dimensions.PublisherId == var.readiness_publisher.id &&
      output.controller_ready_metric_assumptions.missing_data == "breaching"
    )
    error_message = "instance, DynamoDB, and fail-closed external-ready alarms must be present."
  }
  assert {
    condition = (
      aws_cloudwatch_log_group.application.retention_in_days == var.cloudwatch_log_retention_in_days &&
      output.application_log_group.name == "/envelope/${var.name}/controller/application" &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        length([for statement in statements : statement if statement.Sid == "WriteApplicationLogs" && statement.Action == ["logs:CreateLogStream", "logs:PutLogEvents"]]) == 1 &&
        length([for statement in statements : statement if statement.Sid == "DescribeApplicationLogGroupsAndStreams" && statement.Action == ["logs:DescribeLogGroups", "logs:DescribeLogStreams"]]) == 1
      ]) &&
      alltrue([for instance in values(aws_instance.controller) : strcontains(instance.user_data, "amazon-cloudwatch-agent")])
    )
    error_message = "every controller must ship its application log to the retained deployment log group with only stream-delivery permissions."
  }
}

run "active_controller_contract" {
  command = plan

  variables {
    deployment_mode = "active"
  }

  override_data {
    target = data.aws_subnet.controller["controller-a"]
    values = {
      id                      = "subnet-00000000000000001"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2a"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-b"]
    values = {
      id                      = "subnet-00000000000000002"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2b"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_subnet.controller["controller-c"]
    values = {
      id                      = "subnet-00000000000000003"
      vpc_id                  = "vpc-00000000000000000"
      availability_zone       = "us-west-2c"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-a"]
    values = {
      id     = "rtb-00000000000000001"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000001"
        route_table_id             = "rtb-00000000000000001"
        subnet_id                  = "subnet-00000000000000001"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000001"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-b"]
    values = {
      id     = "rtb-00000000000000002"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000002"
        route_table_id             = "rtb-00000000000000002"
        subnet_id                  = "subnet-00000000000000002"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000002"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.management_egress["controller-c"]
    values = {
      id     = "rtb-00000000000000003"
      vpc_id = "vpc-00000000000000000"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-00000000000000003"
        route_table_id             = "rtb-00000000000000003"
        subnet_id                  = "subnet-00000000000000003"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "0.0.0.0/0"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = "nat-00000000000000003"
        network_interface_id       = ""
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-a"]
    values = {
      id                = "nat-00000000000000001"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000011"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-b"]
    values = {
      id                = "nat-00000000000000002"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000012"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_nat_gateway.management_egress["controller-c"]
    values = {
      id                = "nat-00000000000000003"
      vpc_id            = "vpc-00000000000000000"
      subnet_id         = "subnet-00000000000000013"
      connectivity_type = "public"
      state             = "available"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-a"]
    values = {
      id                = "subnet-00000000000000011"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2a"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-b"]
    values = {
      id                = "subnet-00000000000000012"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2b"
    }
  }

  override_data {
    target = data.aws_subnet.management_nat["controller-c"]
    values = {
      id                = "subnet-00000000000000013"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2c"
    }
  }

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.20.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-22222222222222222"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  override_data {
    target = data.aws_route_table.managed["east-workload"]
    values = {
      id     = "rtb-22222222222222222"
      vpc_id = "vpc-22222222222222222"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-22222222222222222"
        route_table_id             = "rtb-22222222222222222"
        subnet_id                  = "subnet-66666666666666666"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.10.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-33333333333333333"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  assert {
    condition = (
      var.deployment_mode == "active" &&
      length(aws_iam_role.controller) == 3 &&
      length(aws_iam_instance_profile.controller) == 3 &&
      toset(flatten([
        for statements in values(local.controller_policy_statements) : [
          for statement in statements : statement.Action
        ]
        ])) == toset([
        "dynamodb:GetItem", "dynamodb:PutItem", "ssm:GetParameter", "s3:GetObjectVersion",
        "ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables",
        "kms:Decrypt", "ec2:ReplaceRoute",
      ]) &&
      alltrue([
        for statements in values(local.controller_policy_statements) :
        length([for statement in statements : statement if statement.Sid == "WriteDomainAuthority"]) == 1 &&
        toset(one([for statement in statements : statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] if statement.Sid == "WriteDomainAuthority"])) == toset([local.domain_partition_key])
      ]) &&
      alltrue([
        for controller_id, statements in local.controller_policy_statements :
        toset(one([for statement in statements : statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] if statement.Sid == "PublishObservation"])) == toset([local.observation_partition_keys[controller_id]])
      ]) &&
      toset(flatten([
        for statements in values(local.controller_policy_statements) : [
          for statement in statements : statement.Resource
          if contains(statement.Action, "ec2:ReplaceRoute")
        ]
        ])) == toset([
        "arn:aws:ec2:us-east-1:123456789012:route-table/rtb-22222222222222222",
        "arn:aws:ec2:us-west-2:123456789012:route-table/rtb-11111111111111111",
      ]) &&
      output.controller_iam.deployment_mode == "active" &&
      output.dynamic_route_ownership.controller_action == "ec2:ReplaceRoute"
    )
    error_message = "active mode must reach every direct controller process and add only exact domain and route mutation scope."
  }
}

run "reject_wildcard_artifact_key" {
  command = plan

  variables {
    artifact = {
      region      = "us-west-2"
      bucket_name = "envelope-controller-test-artifacts"
      bucket_arn  = "arn:aws:s3:::envelope-controller-test-artifacts"
      object_key  = "controller/*/envelope-controller"
      object_arn  = "arn:aws:s3:::envelope-controller-test-artifacts/controller/*/envelope-controller"
      version_id  = "test-version-id"
      sha256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }

  expect_failures = [var.artifact]
}

run "reject_control_character_artifact_key" {
  command = plan

  variables {
    artifact = {
      region      = "us-west-2"
      bucket_name = "envelope-controller-test-artifacts"
      bucket_arn  = "arn:aws:s3:::envelope-controller-test-artifacts"
      object_key  = "controller/unsafe\tkey"
      object_arn  = "arn:aws:s3:::envelope-controller-test-artifacts/controller/unsafe\tkey"
      version_id  = "test-version-id"
      sha256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }

  expect_failures = [var.artifact]
}

run "reject_empty_alarm_actions" {
  command = plan

  variables {
    alarm_actions = []
  }

  expect_failures = [var.alarm_actions]
}

run "reject_empty_ami_owner_allowlist" {
  command = plan

  variables {
    controller_ami_trusted_owner_ids = []
  }

  expect_failures = [var.controller_ami_trusted_owner_ids]
}

run "reject_untrusted_live_ami" {
  command = plan

  variables {
    controller_ami_trusted_owner_ids = ["999999999999"]
  }

  expect_failures = [terraform_data.input_contract]
}

run "reject_ambiguous_readiness_publisher" {
  command = plan

  variables {
    readiness_publisher = {
      id                      = "central-readiness"
      role_name               = "envelope-readiness-publisher"
      role_arn                = "arn:aws:iam::123456789012:role/monitoring/*"
      source_cidrs            = ["10.0.0.0/8"]
      scrape_interval_seconds = 30
    }
  }

  expect_failures = [var.readiness_publisher]
}

run "reject_shared_management_nat" {
  command = plan

  variables {
    management_egress = {
      controller-a = { route_table_id = "rtb-00000000000000001", nat_gateway_id = "nat-00000000000000001", nat_subnet_id = "subnet-00000000000000011", nat_route_table_id = "rtb-00000000000000021", internet_gateway_id = "igw-00000000000000000" }
      controller-b = { route_table_id = "rtb-00000000000000002", nat_gateway_id = "nat-00000000000000001", nat_subnet_id = "subnet-00000000000000012", nat_route_table_id = "rtb-00000000000000022", internet_gateway_id = "igw-00000000000000000" }
      controller-c = { route_table_id = "rtb-00000000000000003", nat_gateway_id = "nat-00000000000000003", nat_subnet_id = "subnet-00000000000000013", nat_route_table_id = "rtb-00000000000000023", internet_gateway_id = "igw-00000000000000000" }
    }
  }

  expect_failures = [var.management_egress]
}

run "reject_cross_az_management_nat" {
  command = plan

  override_data {
    target = data.aws_subnet.management_nat["controller-c"]
    values = {
      id                = "subnet-00000000000000013"
      vpc_id            = "vpc-00000000000000000"
      availability_zone = "us-west-2a"
    }
  }

  expect_failures = [terraform_data.input_contract]
}

run "reject_dirty_artifact_manifest" {
  command = plan

  variables {
    artifact_manifest_json = replace(
      trimspace(file("tests/fixtures/controller-manifest.json")),
      "\"source_dirty\":false",
      "\"source_dirty\":true",
    )
  }

  expect_failures = [var.artifact_manifest_json]
}

run "reject_manifest_artifact_hash_mismatch" {
  command = plan

  variables {
    artifact = {
      region      = "us-west-2"
      bucket_name = "envelope-controller-test-artifacts"
      bucket_arn  = "arn:aws:s3:::envelope-controller-test-artifacts"
      object_key  = "controller/envelope-controller-linux-amd64"
      object_arn  = "arn:aws:s3:::envelope-controller-test-artifacts/controller/envelope-controller-linux-amd64"
      version_id  = "test-version-id"
      sha256      = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  }

  expect_failures = [terraform_data.input_contract]
}

run "reject_readiness_publisher_identity_mismatch" {
  command = plan

  variables {
    readiness_publisher = {
      id                      = "central-readiness"
      role_name               = "envelope-readiness-publisher"
      role_arn                = "arn:aws:iam::123456789012:role/monitoring/different-publisher"
      source_cidrs            = ["10.0.0.0/8"]
      scrape_interval_seconds = 30
    }
  }

  expect_failures = [terraform_data.input_contract]
}

run "reject_noncanonical_duration_identity" {
  command = plan

  variables {
    topology_identity_json = jsonencode({
      schema                = 1
      component             = "envelope-controller-topology"
      version               = "1.2.3"
      revision              = "cccccccccccccccccccccccccccccccccccccccc"
      go_version            = "go1.26.2"
      vcs_modified          = false
      canonical_sha256      = sha256(replace(trimspace(file("tests/fixtures/topology.json")), "\"observation_interval\":\"2s\"", "\"observation_interval\":\"2000ms\""))
      canonical_json_base64 = base64encode(replace(trimspace(file("tests/fixtures/topology.json")), "\"observation_interval\":\"2s\"", "\"observation_interval\":\"2000ms\""))
      policy_durations = {
        observation_interval      = "2s"
        observation_freshness     = "6s"
        failover_stability        = "6s"
        failback_stability        = "20s"
        cooldown                  = "30s"
        lease_duration            = "30s"
        lease_renew_interval      = "5s"
        lease_danger_window       = "6s"
        api_timeout               = "2s"
        route_convergence_timeout = "4s"
      }
    })
  }

  expect_failures = [var.topology_identity_json]
}

run "reject_wrong_gwlbe_subnet_association" {
  command = plan

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-77777777777777777"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.20.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-22222222222222222"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  expect_failures = [terraform_data.route_contract["west-workload"]]
}

run "reject_wrong_gwlbe_route_table_association_id" {
  command = plan

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-77777777777777777"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [{
        carrier_gateway_id         = ""
        cidr_block                 = "10.20.0.0/24"
        core_network_arn           = ""
        destination_prefix_list_id = ""
        egress_only_gateway_id     = ""
        gateway_id                 = ""
        instance_id                = ""
        ipv6_cidr_block            = ""
        local_gateway_id           = ""
        nat_gateway_id             = ""
        network_interface_id       = "eni-22222222222222222"
        transit_gateway_id         = ""
        vpc_endpoint_id            = ""
        vpc_peering_connection_id  = ""
      }]
    }
  }

  expect_failures = [terraform_data.route_contract["west-workload"]]
}

run "reject_gwlbe_subnet_outside_site_vpc" {
  command = plan

  override_data {
    target = data.aws_subnet.managed_gwlbe["west-workload"]
    values = {
      id                = "subnet-55555555555555555"
      vpc_id            = "vpc-77777777777777777"
      availability_zone = "us-west-2a"
    }
  }

  expect_failures = [terraform_data.route_contract["west-workload"]]
}

run "reject_duplicate_managed_gwlbe_subnet" {
  command = plan

  variables {
    managed_route_tables = {
      east-workload = {
        region                     = "us-east-1"
        vpc_id                     = "vpc-22222222222222222"
        route_table_id             = "rtb-22222222222222222"
        route_table_arn            = "arn:aws:ec2:us-east-1:123456789012:route-table/rtb-22222222222222222"
        gwlbe_subnet_id            = "subnet-55555555555555555"
        route_table_association_id = "rtbassoc-22222222222222222"
        source_prefix              = "10.20.0.0/24"
        destination_cidrs          = ["10.10.0.0/24"]
        eligible_eni_ids           = ["eni-33333333333333333", "eni-44444444444444444"]
      }
      west-workload = {
        region                     = "us-west-2"
        vpc_id                     = "vpc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        route_table_arn            = "arn:aws:ec2:us-west-2:123456789012:route-table/rtb-11111111111111111"
        gwlbe_subnet_id            = "subnet-55555555555555555"
        route_table_association_id = "rtbassoc-11111111111111111"
        source_prefix              = "10.10.0.0/24"
        destination_cidrs          = ["10.20.0.0/24"]
        eligible_eni_ids           = ["eni-11111111111111111", "eni-22222222222222222"]
      }
    }
  }

  expect_failures = [var.managed_route_tables]
}

run "allow_less_specific_ipv4_route" {
  command = plan

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [
        {
          carrier_gateway_id         = ""
          cidr_block                 = "10.20.0.0/24"
          core_network_arn           = ""
          destination_prefix_list_id = ""
          egress_only_gateway_id     = ""
          gateway_id                 = ""
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = "eni-22222222222222222"
          transit_gateway_id         = ""
          vpc_endpoint_id            = ""
          vpc_peering_connection_id  = ""
        },
        {
          carrier_gateway_id         = ""
          cidr_block                 = "0.0.0.0/0"
          core_network_arn           = ""
          destination_prefix_list_id = ""
          egress_only_gateway_id     = ""
          gateway_id                 = "igw-11111111111111111"
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = ""
          transit_gateway_id         = ""
          vpc_endpoint_id            = ""
          vpc_peering_connection_id  = ""
        },
      ]
    }
  }

  assert {
    condition = (
      length(local.live_route_shadowing["west-workload"]["10.20.0.0/24"]) == 0 &&
      local.current_route_targets["west-workload"]["10.20.0.0/24"] == "eni-22222222222222222"
    )
    error_message = "a broader IPv4 route must not invalidate an exact eligible controller route."
  }
}

run "reject_more_specific_ipv4_route_shadow" {
  command = plan

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [
        {
          carrier_gateway_id         = ""
          cidr_block                 = "10.20.0.0/24"
          core_network_arn           = ""
          destination_prefix_list_id = ""
          egress_only_gateway_id     = ""
          gateway_id                 = ""
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = "eni-22222222222222222"
          transit_gateway_id         = ""
          vpc_endpoint_id            = ""
          vpc_peering_connection_id  = ""
        },
        {
          carrier_gateway_id         = ""
          cidr_block                 = "10.20.0.0/25"
          core_network_arn           = ""
          destination_prefix_list_id = ""
          egress_only_gateway_id     = ""
          gateway_id                 = ""
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = "eni-22222222222222222"
          transit_gateway_id         = ""
          vpc_endpoint_id            = ""
          vpc_peering_connection_id  = ""
        },
      ]
    }
  }

  expect_failures = [terraform_data.route_contract["west-workload"]]
}

run "reject_managed_route_prefix_list" {
  command = plan

  override_data {
    target = data.aws_route_table.managed["west-workload"]
    values = {
      id     = "rtb-11111111111111111"
      vpc_id = "vpc-11111111111111111"
      associations = [{
        gateway_id                 = ""
        main                       = false
        route_table_association_id = "rtbassoc-11111111111111111"
        route_table_id             = "rtb-11111111111111111"
        subnet_id                  = "subnet-55555555555555555"
      }]
      routes = [
        {
          carrier_gateway_id         = ""
          cidr_block                 = "10.20.0.0/24"
          core_network_arn           = ""
          destination_prefix_list_id = ""
          egress_only_gateway_id     = ""
          gateway_id                 = ""
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = "eni-22222222222222222"
          transit_gateway_id         = ""
          vpc_endpoint_id            = ""
          vpc_peering_connection_id  = ""
        },
        {
          carrier_gateway_id         = ""
          cidr_block                 = ""
          core_network_arn           = ""
          destination_prefix_list_id = "pl-00000000000000000"
          egress_only_gateway_id     = ""
          gateway_id                 = ""
          instance_id                = ""
          ipv6_cidr_block            = ""
          local_gateway_id           = ""
          nat_gateway_id             = ""
          network_interface_id       = ""
          transit_gateway_id         = ""
          vpc_endpoint_id            = "vpce-00000000000000000"
          vpc_peering_connection_id  = ""
        },
      ]
    }
  }

  expect_failures = [terraform_data.route_contract["west-workload"]]
}
