// envelope-controller-deploy is deployment tooling, never a runtime dependency.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/lifecycle"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

var version = "dev"
var revision = "unknown"
var buildDate = "unknown"
var sourceModified = "true"

// This session cannot mutate routes or escalate authority even if its parent
// role can. Explicit NotAction denial prevents accidentally broad future allows.
func initializationPolicy(topology *config.Topology, account string) (string, error) {
	allowed := []string{"ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables", "dynamodb:GetItem", "dynamodb:PutItem", "kms:Decrypt"}
	hash, err := topology.Hash()
	if err != nil {
		return "", err
	}
	readKeys := []string{"deployment#" + topology.DeploymentID}
	for _, id := range topology.ControllerIDs {
		readKeys = append(readKeys, "observations#"+topology.DeploymentID+"#"+hash+"#"+id)
	}
	table := "arn:aws:dynamodb:" + topology.DynamoDB.Region + ":" + account + ":table/" + topology.DynamoDB.Table
	statements := []any{
		map[string]any{"Effect": "Deny", "NotAction": allowed, "Resource": "*"},
		map[string]any{"Effect": "Allow", "Action": allowed[:4], "Resource": "*"},
		map[string]any{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table, "Condition": map[string]any{"ForAllValues:StringEquals": map[string]any{"dynamodb:LeadingKeys": readKeys}, "Null": map[string]string{"dynamodb:LeadingKeys": "false"}}},
		map[string]any{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table, "Condition": map[string]any{"ForAllValues:StringEquals": map[string]any{"dynamodb:LeadingKeys": []string{"deployment#" + topology.DeploymentID}}, "Null": map[string]string{"dynamodb:LeadingKeys": "false"}}},
		map[string]any{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]string{"kms:ViaService": "dynamodb." + topology.DynamoDB.Region + ".amazonaws.com", "kms:CallerAccount": account, "kms:EncryptionContext:aws:dynamodb:tableName": topology.DynamoDB.Table, "kms:EncryptionContext:aws:dynamodb:subscriberId": account}}},
	}
	payload, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil || len(payload) > 2048 {
		return "", errors.New("initialization session policy exceeds STS bound")
	}
	return string(payload), nil
}

func deploymentPolicy(topology *config.Topology, account, operation string) (string, error) {
	base, err := initializationPolicy(topology, account)
	if err != nil {
		return "", err
	}
	if operation == "initialize" || operation == "check-routers" {
		return base, nil
	}
	var policy map[string]any
	if json.Unmarshal([]byte(base), &policy) != nil {
		return "", lifecycle.ErrPreflight
	}
	statements := policy["Statement"].([]any)
	deny := statements[0].(map[string]any)
	deny["NotAction"] = append(deny["NotAction"].([]any), "dynamodb:ConditionCheckItem")
	for _, index := range []int{2, 3} {
		statement := statements[index].(map[string]any)
		condition := statement["Condition"].(map[string]any)["ForAllValues:StringEquals"].(map[string]any)
		keys := append(condition["dynamodb:LeadingKeys"].([]any), "lifecycle#"+topology.DeploymentID)
		condition["dynamodb:LeadingKeys"] = keys
		if index == 2 {
			statement["Action"] = []string{"dynamodb:GetItem", "dynamodb:ConditionCheckItem"}
			// Deployment reads both topology generations during migration. Only
			// reads use the deployment-scoped pattern; writes remain exact keys.
			statement["Condition"] = map[string]any{"ForAllValues:StringLike": map[string]any{"dynamodb:LeadingKeys": []string{"deployment#" + topology.DeploymentID, "lifecycle#" + topology.DeploymentID, "observations#" + topology.DeploymentID + "#*"}}, "Null": map[string]string{"dynamodb:LeadingKeys": "false"}}
		}
	}
	if operation == "rollout" {
		// The role policy further scopes instance/profile, state bucket, and KMS
		// resources. No route actuator, IAM mutation, or STS role chaining exists.
		actions := []any{"ec2:Describe*", "ec2:RunInstances", "ec2:TerminateInstances", "ec2:CreateTags", "ec2:AttachVolume", "ec2:DetachVolume", "ec2:StopInstances", "ec2:ModifyInstanceAttribute", "iam:PassRole", "iam:GetRole", "iam:GetInstanceProfile", "sts:GetCallerIdentity", "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "kms:GenerateDataKey", "kms:CreateGrant", "kms:DescribeKey"}
		deny["NotAction"] = append(deny["NotAction"].([]any), actions...)
		// Resource scoping comes from the required lifecycle Terraform role.
		// Keep the session boundary small enough for STS while explicitly
		// denying every operation outside this closed API allowlist.
		statements = []any{deny, map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*"}}
	}
	policy["Statement"] = statements
	payload, err := json.Marshal(policy)
	if err != nil || len(payload) > 2048 {
		return "", errors.New("deployment session policy exceeds STS bound")
	}
	return string(payload), nil
}

func loadTrust(path string, topology *config.Topology) (lifecycle.Forwarding, error) {
	trust, err := attestation.LoadTrust(path, topology)
	if err != nil {
		return nil, err
	}
	return trust.Check, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(output).Encode(map[string]string{"component": "envelope-controller-deploy", "version": version, "revision": revision, "build_date": buildDate, "source_modified": sourceModified})
	}
	flags := flag.NewFlagSet("envelope-controller-deploy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("topology", "", "reviewed immutable topology")
	domain := flags.String("domain", "", "one domain to initialize")
	role := flags.String("initialization-role-arn", "", "existing role explicitly trusting the deployment caller")
	externalID := flags.String("external-id", "", "external ID required by the provisioned lifecycle role trust")
	trust := flags.String("router-trust", "", "independently enrolled topology-bound router keys and HTTPS endpoints")
	nextPath := flags.String("next-topology", "", "reviewed migration destination topology")
	nextTrustPath := flags.String("next-router-trust", "", "independently enrolled migration destination keys")
	replica := flags.String("replica", "", "one replica to replace")
	terraformDir := flags.String("terraform-dir", "", "initialized reviewed Terraform directory")
	terraformBin := flags.String("terraform", "", "pinned Terraform 1.10.5 executable")
	terraformSHA := flags.String("terraform-sha256", "", "reviewed Terraform executable digest")
	planPath := flags.String("plan", "", "reviewed saved one-replica replacement plan")
	planSHA := flags.String("plan-sha256", "", "reviewed saved plan digest")
	if len(args) == 0 || flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" || *trust == "" {
		return errors.New("usage: envelope-controller-deploy initialize|activate|deactivate|migrate|rollout --topology PATH --initialization-role-arn ARN --router-trust PATH [operation flags]")
	}
	operation := args[0]
	switch operation {
	case "initialize", "activate":
		if *domain == "" {
			return lifecycle.ErrPreflight
		}
	case "deactivate", "check-routers":
	case "migrate":
		if *nextPath == "" || *nextTrustPath == "" {
			return lifecycle.ErrPreflight
		}
	case "rollout":
		if *replica == "" || *terraformDir == "" || *terraformBin == "" || *terraformSHA == "" || *planPath == "" || *planSHA == "" {
			return lifecycle.ErrPreflight
		}
	default:
		return lifecycle.ErrPreflight
	}
	match := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`).FindStringSubmatch(*role)
	if match == nil {
		return errors.New("an explicit assumable initialization role is required")
	}
	topology, err := config.ParseFile(*path)
	if err != nil {
		return lifecycle.ErrPreflight
	}
	if operation == "initialize" || operation == "activate" {
		if _, err := topology.DomainAuthority(*domain); err != nil {
			return lifecycle.ErrPreflight
		}
	}
	forwarding, err := loadTrust(*trust, topology)
	if err != nil {
		return lifecycle.ErrPreflight
	}
	var next *config.Topology
	var nextForwarding lifecycle.Forwarding
	if operation == "migrate" {
		next, err = config.ParseFile(*nextPath)
		if err != nil || next.DeploymentID != topology.DeploymentID || next.DynamoDB != topology.DynamoDB {
			return lifecycle.ErrPreflight
		}
		nextForwarding, err = loadTrust(*nextTrustPath, next)
		if err != nil {
			return lifecycle.ErrPreflight
		}
	}
	policy, err := deploymentPolicy(topology, match[1], operation)
	if err != nil {
		return lifecycle.ErrPreflight
	}
	ctx, cancel := context.WithTimeout(ctx, 14*time.Minute)
	defer cancel()
	configuration, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(topology.DynamoDB.Region))
	if err != nil {
		return lifecycle.ErrPreflight
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return lifecycle.ErrPreflight
	}
	session, err := sts.NewFromConfig(configuration).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: role, RoleSessionName: aws.String("envelope-init-" + hex.EncodeToString(nonce[:])),
		DurationSeconds: aws.Int32(900), Policy: aws.String(policy),
		ExternalId: func() *string {
			if *externalID == "" {
				return nil
			}
			return externalID
		}(),
	})
	if err != nil || session == nil || session.Credentials == nil || session.Credentials.Expiration == nil ||
		!session.Credentials.Expiration.After(time.Now().Add(time.Minute)) || aws.ToString(session.Credentials.AccessKeyId) == "" ||
		aws.ToString(session.Credentials.SecretAccessKey) == "" || aws.ToString(session.Credentials.SessionToken) == "" {
		return errors.New("route-denied initialization session unavailable; verify the explicit role trust and permissions")
	}
	configuration.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
		aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)))
	session = nil
	hash, _ := topology.Hash()
	identities := make([]store.ObserverIdentity, 0, len(topology.ControllerIDs))
	for _, id := range topology.ControllerIDs {
		identities = append(identities, store.ObserverIdentity{DeploymentID: topology.DeploymentID, TopologyHash: hash, ControllerID: id})
	}
	if next != nil {
		nextHash, _ := next.Hash()
		if nextHash != hash {
			for _, id := range next.ControllerIDs {
				identities = append(identities, store.ObserverIdentity{DeploymentID: next.DeploymentID, TopologyHash: nextHash, ControllerID: id})
			}
		}
	}
	durable, err := store.NewDynamoDBStore(dynamodb.NewFromConfig(configuration), topology.DynamoDB.Table, store.RealClock{}, topology.Policy.APITimeout.Duration(), identities...)
	if err != nil {
		return lifecycle.ErrPreflight
	}
	clouds := map[string]lifecycle.Inspector{}
	sites := append([]config.Site(nil), topology.Sites...)
	if next != nil {
		sites = append(sites, next.Sites...)
	}
	for _, site := range sites {
		configuration.Region = site.Region
		cloud, err := awscontrol.New(ec2.NewFromConfig(configuration), site.Region, awscontrol.WithAPITimeout(topology.Policy.APITimeout.Duration()))
		if err != nil {
			return lifecycle.ErrPreflight
		}
		clouds[site.Region] = cloud
	}
	deployment := lifecycle.Deployment{Topology: topology, Store: durable, Cloud: clouds, Forwarding: forwarding, Clock: store.RealClock{}}
	operationID := hex.EncodeToString(nonce[:])
	if operation == "check-routers" {
		checked := map[string]bool{}
		for _, domain := range topology.Domains {
			authority, err := topology.DomainAuthority(domain.ID)
			if err != nil {
				return lifecycle.ErrPreflight
			}
			for _, owner := range authority.Owners {
				if checked[owner.RouterID] {
					continue
				}
				if _, err := clouds[authority.Region].ValidateOwner(ctx, authority, owner); err != nil {
					return lifecycle.ErrPreflight
				}
				expires, err := forwarding(ctx, authority, owner)
				if err != nil || !expires.After(time.Now()) {
					return lifecycle.ErrPreflight
				}
				checked[owner.RouterID] = true
			}
		}
		if len(checked) != len(topology.Routers) {
			return lifecycle.ErrPreflight
		}
		return json.NewEncoder(output).Encode(map[string]any{"checked": true, "routers": len(checked), "topology_hash": hash})
	}
	if operation == "initialize" {
		authority, _ := topology.DomainAuthority(*domain)
		state, err := lifecycle.Initialize(ctx, topology, *domain, durable, clouds[authority.Region], forwarding, store.RealClock{})
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"domain_id": authority.DomainID, "topology_hash": hash, "revision": state.Revision, "initialized": true, "activated": false})
	}
	// Retain the operation identity even if a response is lost. There is no
	// automatic lock takeover or cleanup of uncertain operations.
	if err := json.NewEncoder(output).Encode(map[string]string{"operation_id": operationID, "operation": operation, "status": "starting"}); err != nil {
		return err
	}
	switch operation {
	case "activate":
		err = deployment.Activate(ctx, operationID, *domain)
	case "deactivate":
		err = deployment.Deactivate(ctx, operationID)
	case "migrate":
		err = deployment.Migrate(ctx, operationID, next, nextForwarding)
	case "rollout":
		private, privateErr := os.MkdirTemp("", "envelope-rollout-")
		if privateErr != nil {
			return lifecycle.ErrPreflight
		}
		defer os.RemoveAll(private)
		binary, copyErr := privateCopy(*terraformBin, *terraformSHA, private, "terraform", true)
		if copyErr != nil {
			return copyErr
		}
		plan, copyErr := privateCopy(*planPath, *planSHA, private, "plan", false)
		if copyErr != nil {
			return copyErr
		}
		directory, absErr := filepath.Abs(*terraformDir)
		if absErr != nil {
			return lifecycle.ErrPreflight
		}
		creds, credErr := configuration.Credentials.Retrieve(ctx)
		if credErr != nil {
			return lifecycle.ErrPreflight
		}
		configuration.Region = topology.DynamoDB.Region
		environment, envErr := rolloutEnvironment(private, topology.DynamoDB.Region, creds)
		if envErr != nil {
			return envErr
		}
		action := &terraformRollout{directory: directory, binary: binary, plan: plan, replica: *replica, topology: topology, durable: durable, ec2: ec2.NewFromConfig(configuration), applyEnvironment: environment}
		err = deployment.Rollout(ctx, operationID, *replica, action)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]string{"operation_id": operationID, "status": "complete"})
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
