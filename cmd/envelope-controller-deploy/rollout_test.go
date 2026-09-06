package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jaxxstorm/envelope/internal/controller/config"
)

func TestRolloutPreservesPrivateWorkspaceButNotDeploymentCredentials(t *testing.T) {
	t.Setenv("TF_DATA_DIR", "/private/controller-data")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "deployment-secret")
	t.Setenv("TF_CLI_ARGS_apply", "unreviewed-arguments")
	t.Setenv("AWS_PROFILE", "deployment")
	values, err := rolloutEnvironment("/private/home", "us-west-2", aws.Credentials{AccessKeyID: "restricted-key", SecretAccessKey: "restricted-secret", SessionToken: "restricted-token"})
	if err != nil {
		t.Fatal(err)
	}
	environment := strings.Join(values, "\n")
	for _, required := range []string{"TF_DATA_DIR=/private/controller-data", "AWS_SECRET_ACCESS_KEY=restricted-secret", "AWS_SESSION_TOKEN=restricted-token", "AWS_CONFIG_FILE=/dev/null", "AWS_SHARED_CREDENTIALS_FILE=/dev/null", "AWS_EC2_METADATA_DISABLED=true"} {
		if !strings.Contains(environment, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, prohibited := range []string{"deployment-secret", "TF_CLI_ARGS", "AWS_PROFILE"} {
		if strings.Contains(environment, prohibited) {
			t.Fatalf("inherited %s", prohibited)
		}
	}
	t.Setenv("TF_DATA_DIR", "relative-data")
	if _, err := rolloutEnvironment("/private/home", "us-west-2", aws.Credentials{}); err == nil {
		t.Fatal("accepted an ambiguous workspace")
	}
}

func TestSavedRolloutPlanIsExactlyOneReplica(t *testing.T) {
	for _, mode := range []string{"valid", "second-replica", "route", "iam", "create-before-destroy", "duplicate", "no-replacement", "wrong-toolchain"} {
		t.Run(mode, func(t *testing.T) {
			change := map[string]any{"address": `aws_instance.controller["controller-a"]`, "mode": "managed", "change": map[string]any{"actions": []string{"delete", "create"}, "before": map[string]any{"id": "i-old"}}}
			changes := []any{change}
			plan := map[string]any{"format_version": "1.2", "terraform_version": "1.10.5", "resource_changes": changes}
			switch mode {
			case "second-replica", "route", "iam":
				address := map[string]string{"second-replica": `aws_instance.controller["controller-b"]`, "route": "aws_route.remote", "iam": "aws_iam_role_policy.controller"}[mode]
				plan["resource_changes"] = append(changes, map[string]any{"address": address, "mode": "managed", "change": map[string]any{"actions": []string{"update"}}})
			case "create-before-destroy":
				change["change"].(map[string]any)["actions"] = []string{"create", "delete"}
			case "duplicate":
				plan["resource_changes"] = append(changes, change)
			case "no-replacement":
				change["change"].(map[string]any)["actions"] = []string{"no-op"}
			case "wrong-toolchain":
				plan["terraform_version"] = "1.11.0"
			}
			payload, _ := json.Marshal(plan)
			id, err := validateRolloutPlan(payload, "controller-a")
			if (err == nil) != (mode == "valid") || (err == nil && id != "i-old") {
				t.Fatalf("plan=%s error=%v", payload, err)
			}
		})
	}
}

func TestDeploymentSessionPoliciesFitAndDenyEscalation(t *testing.T) {
	topology, err := config.ParseFile("../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"activate", "deactivate", "migrate", "rollout"} {
		policy, err := deploymentPolicy(topology, "123456789012", operation)
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		var parsed struct {
			Statement []struct {
				Effect    string
				NotAction []string
			}
		}
		if json.Unmarshal([]byte(policy), &parsed) != nil || parsed.Statement[0].Effect != "Deny" {
			t.Fatal("missing explicit deny")
		}
		for _, action := range parsed.Statement[0].NotAction {
			if action == "*" || action == "ec2:*" || action == "ec2:ReplaceRoute" || action == "sts:AssumeRole" || action == "iam:*" {
				t.Fatalf("unsafe %s session action %s", operation, action)
			}
		}
	}
}
