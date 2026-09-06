terraform {
  required_version = ">= 1.10.1, < 1.11.0"
  required_providers { aws = { source = "hashicorp/aws", version = "6.33.0" } }
  backend "s3" {}
}
variable "aws_region" { type = string }
provider "aws" { region = var.aws_region }
variable "oidc_provider_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/token.actions.githubusercontent.com$", var.oidc_provider_arn))
    error_message = "An explicit GitHub OIDC provider ARN is required."
  }
}
variable "handoff_json" { type = string }
variable "boundary_policies" { type = map(string) }
locals {
  handoff    = jsondecode(var.handoff_json)
  role_names = { for phase in ["observe", "quiesce"] : phase => "${local.handoff.run_id}-${substr(local.handoff.invocation_id, 0, 12)}-${phase}" }
}
resource "terraform_data" "contract" {
  lifecycle {
    precondition {
      condition = try(
        local.handoff.schema == 1 && local.handoff.kind == "production-controller-handoff" &&
        can(regex("^[0-9a-f]{64}$", local.handoff.invocation_id)) &&
        toset(keys(var.boundary_policies)) == toset(["observe", "quiesce"]) &&
        alltrue([for phase, encoded in var.boundary_policies : (
          jsondecode(encoded).Statement[0].Effect == "Deny" &&
          jsondecode(encoded).Statement[0].Sid == "DenyEveryOtherAPI" &&
          !contains(jsondecode(encoded).Statement[0].NotAction, "*") &&
          !contains(jsondecode(encoded).Statement[0].NotAction, "ec2:ReplaceRoute") &&
          !contains(jsondecode(encoded).Statement[0].NotAction, "sts:AssumeRole") &&
          !contains(jsondecode(encoded).Statement[0].NotAction, "iam:PutRolePolicy") &&
          strcontains(local.handoff.roles[phase].subject, ":run_id:${local.handoff.context.workflow_run_id}:run_attempt:${local.handoff.context.attempt}")
      )]), false)
      error_message = "Protected observation/quiescence must be invocation-bound and explicitly route/privilege denied."
    }
  }
}
resource "aws_iam_role" "phase" {
  for_each             = local.role_names
  name                 = each.value
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.oidc_provider_arn }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = each.key == "quiesce" ? [local.handoff.roles.quiesce.subject, local.handoff.roles.cleanup.subject] : [local.handoff.roles.observe.subject]
        }
        DateLessThan = { "aws:CurrentTime" = each.key == "observe" ? local.handoff.observer_issuance_until : local.handoff.expires_at }
      }
    }]
  })
  tags       = { EnvelopeRun = local.handoff.run_id, EnvelopeInvocation = local.handoff.invocation_id, ExpiresAt = local.handoff.expires_at, Role = "controller-acceptance-${each.key}" }
  depends_on = [terraform_data.contract]
}
resource "aws_iam_role_policy" "boundary" {
  for_each = local.role_names
  name     = "acceptance-boundary"
  role     = aws_iam_role.phase[each.key].name
  policy   = var.boundary_policies[each.key]
}
output "phase_roles" { value = { for phase, role in aws_iam_role.phase : phase => role.arn } }
