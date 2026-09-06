package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jaxxstorm/envelope/internal/controller/config"
)

func TestInitializationSessionCannotMutateRoutesOrEscalate(t *testing.T) {
	topology, err := config.ParseFile("../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := initializationPolicy(topology, "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Statement []struct {
			Effect    string
			NotAction []string
			Action    any
			Resource  string
			Condition map[string]any
		}
	}
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		t.Fatal(err)
	}
	want := []string{"ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables", "dynamodb:GetItem", "dynamodb:PutItem", "kms:Decrypt"}
	if len(document.Statement) != 5 || document.Statement[0].Effect != "Deny" || document.Statement[0].Resource != "*" || !reflect.DeepEqual(document.Statement[0].NotAction, want) {
		t.Fatalf("session does not explicitly deny everything outside reads and initialization: %s", policy)
	}
	if document.Statement[3].Action != "dynamodb:PutItem" || document.Statement[3].Resource != "arn:aws:dynamodb:us-west-2:123456789012:table/"+topology.DynamoDB.Table {
		t.Fatal("initialization write escaped exact table")
	}
	condition := document.Statement[3].Condition["ForAllValues:StringEquals"].(map[string]any)
	if !reflect.DeepEqual(condition["dynamodb:LeadingKeys"], []any{"deployment#" + topology.DeploymentID}) {
		t.Fatal("write escaped deployment partition")
	}
	if document.Statement[4].Condition["StringEquals"].(map[string]any)["kms:ViaService"] != "dynamodb.us-west-2.amazonaws.com" {
		t.Fatal("KMS decryption is not DynamoDB-only")
	}
}

func TestUnsupportedLifecycleCommandsFailBeforeCredentials(t *testing.T) {
	for _, args := range [][]string{nil, {"activate"}, {"rollout"}, {"migrate"}, {"initialize"}, {"initialize", "--unknown"}} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted unsupported command: %v", args)
		}
	}
}

func TestTrustRequiresEveryRouterAndUniqueEnrolledKey(t *testing.T) {
	topology, err := config.ParseFile("../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := topology.Hash()
	for _, name := range []string{"valid", "wrong-hash", "missing", "duplicate-key", "duplicate-router", "unknown-router", "http", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			routers := make([]map[string]any, 0, len(topology.Routers))
			for index, router := range topology.Routers {
				routers = append(routers, map[string]any{"router_id": router.ID, "ed25519_public_key": strings.Repeat(string("1234"[index]), 64), "configuration_sha256": hash, "url": "https://" + router.ID + ".example.com/attestation"})
			}
			doc := map[string]any{"schema_version": 1, "deployment_id": topology.DeploymentID, "topology_hash": hash, "routers": routers}
			switch name {
			case "wrong-hash":
				doc["topology_hash"] = strings.Repeat("f", 64)
			case "missing":
				doc["routers"] = routers[1:]
			case "duplicate-key":
				routers[1]["ed25519_public_key"] = routers[0]["ed25519_public_key"]
			case "duplicate-router":
				routers[1]["router_id"] = routers[0]["router_id"]
			case "unknown-router":
				routers[1]["router_id"] = "unknown-router"
			case "http":
				routers[0]["url"] = "http://router.example.com/attestation"
			case "unknown-field":
				doc["ready"] = true
			}
			payload, _ := json.Marshal(doc)
			path := filepath.Join(t.TempDir(), "trust.json")
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadTrust(path, topology)
			if (err == nil) != (name == "valid") {
				t.Fatalf("trust %s: %v", name, err)
			}
		})
	}
}
