output "rendered" {
  value     = data.cloudinit_config.main.rendered
  sensitive = true
}

output "vendored_release" {
  value = local.upstream_release
}
