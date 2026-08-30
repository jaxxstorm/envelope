locals {
  west_transport_auth_resolver = "command:AWS_PAGER= /usr/bin/aws ssm get-parameter --region ${var.west_region} --name '${var.west_tailscale_secret_arn}' --with-decryption --query Parameter.Value --output text"
  east_transport_auth_resolver = "command:AWS_PAGER= /usr/bin/aws ssm get-parameter --region ${var.east_region} --name '${var.east_tailscale_secret_arn}' --with-decryption --query Parameter.Value --output text"
  tailscale_packages = {
    amd64 = {
      url    = "https://pkgs.tailscale.com/stable/amazon-linux/2023/x86_64/tailscale_1.80.3_x86_64.rpm"
      sha256 = "aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2"
    }
    arm64 = {
      url    = "https://pkgs.tailscale.com/stable/amazon-linux/2023/aarch64/tailscale_1.80.3_aarch64.rpm"
      sha256 = "84ea51f9200a2c93362208f9617948fc8dbae06f3ed7faddf08eebc8a5371c32"
    }
  }
  west_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.west_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })
  east_artifact_installer = templatefile("${path.module}/cloud-init/install-artifact.sh.tftpl", {
    artifact_region       = var.east_region
    artifact_bucket       = local.artifact_bucket_name
    artifact_key          = local.artifact_object_key
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
    artifact_version      = var.artifact_version
    artifact_architecture = var.architecture
  })
  packet_return_runtime = {
    config_version        = var.symmetric_topology.version
    mode                  = "packet-return"
    udp_bind              = "0.0.0.0:6081"
    max_inner_packet_size = 1280
    artifact_sha256       = var.artifact_sha256
    artifact_revision     = var.artifact_revision
  }
  west_target_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", merge(local.packet_return_runtime, {
    site     = "west"
    run_name = var.name
  }))
  east_target_bootstrap = templatefile("${path.module}/cloud-init/bootstrap.sh.tftpl", merge(local.packet_return_runtime, {
    site     = "east"
    run_name = var.name
  }))
  transport_policy_rule_priority_base = 100
  transport_router_contracts = {
    for site, topology in local.sites : site => {
      config_version           = 2
      local_site_cidrs         = sort(topology.local_site_cidrs)
      remote_site_cidrs        = sort(topology.remote_site_cidrs)
      underlay_interface       = var.envelope_underlay_interface
      tailscale_interface      = var.envelope_tailscale_iface
      approved_maximum_tcp_mss = var.e2e_load_profile.maximum_tcp_mss
      ipv4_forwarding          = true
      ipv6_forwarding          = false
      filter_forward_policy    = "DROP"
      mangle_forward_policy    = "ACCEPT"
      filter_forward_rules = [
        { chain = "FORWARD", action = "JUMP", target = "ENVELOPE-TRANSPORT-FORWARD" },
      ]
      mangle_forward_rules = [
        { chain = "FORWARD", action = "JUMP", target = "ENVELOPE-TRANSPORT-MSS" },
      ]
      mss_terminal_rules = [
        { chain = "ENVELOPE-TRANSPORT-MSS", action = "RETURN" },
      ]
      nat_rules                  = []
      ipv6_filter_forward_policy = "DROP"
      ipv6_mangle_forward_policy = "ACCEPT"
      ipv6_filter_forward_rules  = [{ chain = "FORWARD", action = "JUMP", target = "ENVELOPE-TRANSPORT-FORWARD" }]
      ipv6_forward_rules         = []
      ipv6_mangle_forward_rules  = []
      readiness_marker           = "/var/lib/envelope/transport-router-network.ready"
      runtime_state              = "/var/lib/envelope/transport-router-network.state.json"
      recovery_marker            = "/var/lib/envelope/transport-router-network.configured"
      mss_formula                = "min(min(underlay_mtu,tailscale_mtu)-40,approved_maximum_tcp_mss)"
      policy_rule_priority_base  = local.transport_policy_rule_priority_base
      local_route_table          = "main"
      remote_route_table         = 52
      local_policy_rules = [
        for index, cidr in sort(topology.local_site_cidrs) : {
          priority    = local.transport_policy_rule_priority_base + index
          input       = var.envelope_tailscale_iface
          source      = "all"
          destination = cidr
          fwmark      = 0
          table       = "main"
          action      = "lookup"
        }
      ]
      ipv4_policy_rules = concat(
        [
          { priority = 0, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "local", action = "lookup" },
        ],
        [
          for index, cidr in sort(topology.local_site_cidrs) : {
            priority    = local.transport_policy_rule_priority_base + index
            input       = var.envelope_tailscale_iface
            source      = "all"
            destination = cidr
            fwmark      = 0
            fwmask      = 0
            table       = "main"
            action      = "lookup"
          }
        ],
        [
          { priority = 5210, input = "all", source = "all", destination = "all", fwmark = 524288, fwmask = 16711680, table = "main", action = "lookup" },
          { priority = 5230, input = "all", source = "all", destination = "all", fwmark = 524288, fwmask = 16711680, table = "default", action = "lookup" },
          { priority = 5250, input = "all", source = "all", destination = "all", fwmark = 524288, fwmask = 16711680, table = "none", action = "unreachable" },
          { priority = 5270, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "52", action = "lookup" },
          { priority = 32766, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "main", action = "lookup" },
          { priority = 32767, input = "all", source = "all", destination = "all", fwmark = 0, fwmask = 0, table = "default", action = "lookup" },
        ],
      )
      forward_rules = flatten([
        for local_cidr in sort(topology.local_site_cidrs) : [
          for remote_cidr in sort(topology.remote_site_cidrs) : [
            {
              chain       = "ENVELOPE-TRANSPORT-FORWARD"
              input       = var.envelope_underlay_interface
              output      = var.envelope_tailscale_iface
              source      = local_cidr
              destination = remote_cidr
              action      = "ACCEPT"
            },
            {
              chain       = "ENVELOPE-TRANSPORT-FORWARD"
              input       = var.envelope_tailscale_iface
              output      = var.envelope_underlay_interface
              source      = remote_cidr
              destination = local_cidr
              action      = "ACCEPT"
            },
          ]
        ]
      ])
      mss_rules = flatten([
        for local_cidr in sort(topology.local_site_cidrs) : [
          for remote_cidr in sort(topology.remote_site_cidrs) : [
            {
              chain       = "ENVELOPE-TRANSPORT-MSS"
              input       = var.envelope_underlay_interface
              output      = var.envelope_tailscale_iface
              source      = local_cidr
              destination = remote_cidr
              protocol    = "tcp"
              tcp_flags   = "SYN,RST SYN"
              action      = "TCPMSS"
            },
            {
              chain       = "ENVELOPE-TRANSPORT-MSS"
              input       = var.envelope_tailscale_iface
              output      = var.envelope_underlay_interface
              source      = remote_cidr
              destination = local_cidr
              protocol    = "tcp"
              tcp_flags   = "SYN,RST SYN"
              action      = "TCPMSS"
            },
          ]
        ]
      ])
    }
  }
  transport_router_contract_sha256 = {
    for site, contract in local.transport_router_contracts : site => sha256(jsonencode(contract))
  }
  transport_router_bootstrap = {
    for site, topology in local.sites : site => templatefile("${path.module}/cloud-init/transport-router.sh.tftpl", {
      underlay_interface          = var.envelope_underlay_interface
      tailscale_interface         = var.envelope_tailscale_iface
      local_site_cidrs_json       = jsonencode(sort(topology.local_site_cidrs))
      remote_site_cidrs_json      = jsonencode(sort(topology.remote_site_cidrs))
      approved_maximum_tcp_mss    = var.e2e_load_profile.maximum_tcp_mss
      policy_rule_priority_base   = local.transport_policy_rule_priority_base
      readiness_expectations_json = jsonencode(local.transport_router_contracts[site])
      contract_sha256             = local.transport_router_contract_sha256[site]
    })
  }
  transport_router_activation = <<-SCRIPT
    #!/usr/bin/env bash
    set -euo pipefail
    readonly ready=/var/lib/envelope/transport-router-network.ready
    readonly state=/var/lib/envelope/transport-router-network.state.json
    readonly recovery=/var/lib/envelope/transport-router-network.configured
    rm -f "$ready"
    trap 'systemctl stop envelope-transport-router-network.service >/dev/null 2>&1 || true; rm -f "$ready"' ERR
    touch "$recovery"
    systemctl restart envelope-transport-router-network.service
    systemctl is-active --quiet envelope-transport-router-network.service tailscaled.service
    /usr/bin/jq -e '.ready == true and .ipv4_forwarding == true and .ipv6_forwarding == false and .filter_forward_policy == "DROP" and .mangle_forward_policy == "ACCEPT" and .no_nat == true' "$state" >/dev/null
    test -f "$ready"
    trap - ERR
  SCRIPT
}

data "cloudinit_config" "target_west" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "80-envelope-artifact.sh"
    content_type = "text/x-shellscript"
    content      = local.west_artifact_installer
  }
  part {
    filename     = "90-envelope-packet-return.sh"
    content_type = "text/x-shellscript"
    content      = local.west_target_bootstrap
  }
}
data "cloudinit_config" "target_east" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "80-envelope-artifact.sh"
    content_type = "text/x-shellscript"
    content      = local.east_artifact_installer
  }
  part {
    filename     = "90-envelope-packet-return.sh"
    content_type = "text/x-shellscript"
    content      = local.east_target_bootstrap
  }
}
module "tailscale_transport_west" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.west.transport_router_az_keys
  gzip               = true
  auth_key           = local.west_transport_auth_resolver
  hostname           = "${var.name}-west-transport-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = local.initial_transport_router_advertise_routes.west[each.key]
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256
  pre_setup_parts = [
    { filename = "15-transport-router.sh", content_type = "text/x-shellscript", content = local.transport_router_bootstrap.west },
  ]
  pre_setup_gate = "/var/lib/envelope/transport-router-network.installed"
  additional_parts = [
    { filename = "30-activate-transport-router.sh", content_type = "text/x-shellscript", content = local.transport_router_activation },
  ]
}
module "tailscale_transport_east" {
  source             = "./modules/tailscale-cloudinit"
  for_each           = local.sites.east.transport_router_az_keys
  gzip               = true
  auth_key           = local.east_transport_auth_resolver
  hostname           = "${var.name}-east-transport-${each.key}"
  advertise_tags     = [var.tailscale_tag]
  advertise_routes   = local.initial_transport_router_advertise_routes.east[each.key]
  accept_routes      = true
  snat_subnet_routes = false
  netfilter_mode     = "off"
  max_retries        = 12
  retry_delay        = 10
  timeout            = "2m"
  package_version    = var.tailscale_version
  package_url        = local.tailscale_packages[var.architecture].url
  package_sha256     = local.tailscale_packages[var.architecture].sha256
  pre_setup_parts = [
    { filename = "15-transport-router.sh", content_type = "text/x-shellscript", content = local.transport_router_bootstrap.east },
  ]
  pre_setup_gate = "/var/lib/envelope/transport-router-network.installed"
  additional_parts = [
    { filename = "30-activate-transport-router.sh", content_type = "text/x-shellscript", content = local.transport_router_activation },
  ]
}
