mock_provider "aws" {}

variables {
  aws_region        = "us-west-2"
  oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  handoff_json = jsonencode({
    schema                  = 1
    kind                    = "production-controller-handoff"
    run_id                  = "accept-fixture"
    invocation_id           = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    expires_at              = "2030-01-01T06:00:00Z"
    observer_issuance_until = "2030-01-01T00:15:00Z"
    context                 = { workflow_run_id = "42", attempt = "1" }
    roles = {
      observe = { subject = "repo:example/envelope:environment:envelope-controller-observation:workflow_ref:example/envelope/.github/workflows/aws-two-region-e2e-live.yml@refs/heads/main:run_id:42:run_attempt:1" }
      quiesce = { subject = "repo:example/envelope:environment:envelope-controller-quiescence:workflow_ref:example/envelope/.github/workflows/aws-two-region-e2e-live.yml@refs/heads/main:run_id:42:run_attempt:1" }
      cleanup = { subject = "repo:example/envelope:environment:envelope-controller-cleanup:workflow_ref:example/envelope/.github/workflows/aws-two-region-e2e-live.yml@refs/heads/main:run_id:42:run_attempt:1" }
    }
  })
  boundary_policies = { for phase in ["observe", "quiesce"] : phase => jsonencode({ Version = "2012-10-17", Statement = [{ Sid = "DenyEveryOtherAPI", Effect = "Deny", NotAction = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"], Resource = "*" }] }) }
}

run "separate_invocation_bound_roles_with_expiring_observer_issuer" {
  command = apply
  assert {
    condition = (
      aws_iam_role.phase["observe"].name != aws_iam_role.phase["quiesce"].name &&
      aws_iam_role.phase["observe"].max_session_duration == 3600 &&
      jsondecode(aws_iam_role.phase["observe"].assume_role_policy).Statement[0].Condition.DateLessThan["aws:CurrentTime"] == "2030-01-01T00:15:00Z" &&
      length(jsondecode(aws_iam_role.phase["observe"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) == 1 &&
      length(jsondecode(aws_iam_role.phase["quiesce"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) == 2 &&
      jsondecode(aws_iam_role_policy.boundary["observe"].policy).Statement[0].Effect == "Deny"
    )
    error_message = "Measurement must have a separate one-hour role and a bounded exact invocation issuer; cleanup may only reuse the narrow quiescence identity for its precheck."
  }
}

run "reject_route_mutation_bypass" {
  command = plan
  variables {
    boundary_policies = { for phase in ["observe", "quiesce"] : phase => jsonencode({ Version = "2012-10-17", Statement = [{ Sid = "DenyEveryOtherAPI", Effect = "Deny", NotAction = ["ec2:ReplaceRoute"], Resource = "*" }] }) }
  }
  expect_failures = [terraform_data.contract]
}

run "reject_foreign_oidc_provider" {
  command = plan
  variables { oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/foreign.example" }
  expect_failures = [var.oidc_provider_arn]
}
