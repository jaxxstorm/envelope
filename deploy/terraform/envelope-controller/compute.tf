resource "aws_ebs_volume" "observer_state" {
  for_each = var.controller_placements

  availability_zone = each.value.availability_zone
  encrypted         = true
  final_snapshot    = !var.protected_acceptance_mode
  kms_key_id        = local.controller_kms_key_arn
  size              = var.observer_state_volume_size_gib
  type              = "gp3"

  tags = merge(local.common_tags, {
    Name         = "${var.name}-${each.key}-observer-state"
    Role         = "controller-observer-state"
    ControllerID = each.key
  })
}

resource "aws_instance" "controller" {
  for_each = var.controller_placements

  ami                         = data.aws_ami.controller.id
  instance_type               = var.controller_instance_type
  availability_zone           = each.value.availability_zone
  subnet_id                   = each.value.subnet_id
  associate_public_ip_address = false
  source_dest_check           = true
  iam_instance_profile        = aws_iam_instance_profile.controller[each.key].name
  vpc_security_group_ids      = [aws_security_group.controller.id]
  monitoring                  = true
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/cloud-init/controller.sh.tftpl", {
    artifact_bucket_b64        = base64encode(var.artifact.bucket_name)
    artifact_key_b64           = base64encode(var.artifact.object_key)
    artifact_region            = var.artifact.region
    artifact_sha256            = var.artifact.sha256
    artifact_version_b64       = base64encode(var.artifact.version_id)
    controller_id_b64          = base64encode(each.key)
    deployment_mode            = var.deployment_mode
    log_level                  = var.log_level
    metrics_port               = var.metrics_port
    observer_volume_id         = aws_ebs_volume.observer_state[each.key].id
    state_base_dir_b64         = base64encode(local.topology.tailnet.state_base_dir)
    systemd_unit_b64           = base64encode(local.controller_systemd_unit)
    topology_document_sha256   = local.topology_document_sha256
    topology_parameter_b64     = base64encode(aws_ssm_parameter.topology.name)
    topology_region            = var.aws_region
    router_trust_parameter_b64 = base64encode("${aws_ssm_parameter.router_trust.name}:1")
    router_trust_sha256        = local.router_trust_sha256
    topology_tool_bucket_b64   = base64encode(var.topology_identity_artifact.bucket_name)
    topology_tool_key_b64      = base64encode(var.topology_identity_artifact.object_key)
    topology_tool_region       = var.topology_identity_artifact.region
    topology_tool_sha256       = var.topology_identity_artifact.sha256
    topology_tool_version_b64  = base64encode(var.topology_identity_artifact.version_id)
    tsnet_env_name             = local.topology.tailnet.tsnet_auth_key_env
    tsnet_parameter_name_b64   = base64encode(var.secret_parameters.tsnet.name)
    admin_env_name             = local.topology.tailnet.admin_api_key_env
    admin_parameter_name_b64   = base64encode(var.secret_parameters.admin.name)
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = local.controller_kms_key_arn
    volume_size           = var.root_volume.size_gib
    volume_type           = var.root_volume.type
  }

  volume_tags = merge(local.common_tags, {
    Role         = "controller-root"
    ControllerID = each.key
  })

  tags = merge(local.common_tags, {
    Name         = "${var.name}-${each.key}"
    Role         = "envelope-controller"
    ControllerID = each.key
    Architecture = var.controller_architecture
  })

  depends_on = [
    aws_iam_role_policy.controller,
    terraform_data.route_contract,
  ]
}

resource "aws_volume_attachment" "observer_state" {
  for_each = var.controller_placements

  device_name                    = "/dev/sdh"
  instance_id                    = aws_instance.controller[each.key].id
  volume_id                      = aws_ebs_volume.observer_state[each.key].id
  force_detach                   = false
  stop_instance_before_detaching = true
}
