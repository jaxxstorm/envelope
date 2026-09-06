package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/lifecycle"
	"github.com/jaxxstorm/envelope/internal/controller/store"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

type terraformRollout struct {
	directory, binary, plan, replica string
	topology                         *config.Topology
	durable                          lifecycle.InitialStore
	ec2                              *ec2.Client
	oldInstance                      string
	beforeInstances                  map[string]string
	applyEnvironment                 []string
}

func rolloutEnvironment(private, region string, creds aws.Credentials) ([]string, error) {
	result := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + private, "TF_IN_AUTOMATION=1", "AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE=/dev/null", "AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_REGION=" + region, "AWS_ACCESS_KEY_ID=" + creds.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + creds.SecretAccessKey, "AWS_SESSION_TOKEN=" + creds.SessionToken,
	}
	// Preserve only the initialized backend/plugin workspace location, never
	// the deployment caller's credentials or arbitrary Terraform flags.
	if data := os.Getenv("TF_DATA_DIR"); data != "" {
		if !filepath.IsAbs(data) {
			return nil, lifecycle.ErrPreflight
		}
		result = append(result, "TF_DATA_DIR="+data)
	}
	return result, nil
}

func privateCopy(path, expected, directory, name string, executable bool) (string, error) {
	if len(expected) != 64 {
		return "", lifecycle.ErrPreflight
	}
	file, err := os.Open(path)
	if err != nil {
		return "", lifecycle.ErrPreflight
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512*1024*1024 {
		return "", lifecycle.ErrPreflight
	}
	digest := sha256.New()
	destination := filepath.Join(directory, name)
	copy, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", lifecycle.ErrPreflight
	}
	_, copyErr := io.Copy(io.MultiWriter(copy, digest), io.LimitReader(file, 512*1024*1024+1))
	closeErr := copy.Close()
	if copyErr != nil || closeErr != nil || hex.EncodeToString(digest.Sum(nil)) != expected {
		return "", lifecycle.ErrPreflight
	}
	mode := os.FileMode(0400)
	if executable {
		mode = 0500
	}
	if os.Chmod(destination, mode) != nil {
		return "", lifecycle.ErrPreflight
	}
	return destination, nil
}

type boundedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4*1024*1024 {
		b.exceeded = true
		return 0, errors.New("bounded output exceeded")
	}
	return b.Buffer.Write(p)
}

func (r *terraformRollout) command(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, r.binary, args...)
	command.Dir = r.directory
	command.Env = r.applyEnvironment
	var stdout boundedOutput
	command.Stdout, command.Stderr = &stdout, io.Discard
	if err := command.Run(); err != nil || stdout.exceeded {
		return nil, errors.New("reviewed Terraform operation failed; lock retained")
	}
	return stdout.Bytes(), nil
}

// validateRolloutPlan never accepts -target as proof of isolation. It checks the
// actual saved plan's entire change set and rejects every unrelated mutation.
func validateRolloutPlan(payload []byte, replica string) (string, error) {
	if strictjson.Validate(payload, 4*1024*1024) != nil {
		return "", lifecycle.ErrPreflight
	}
	var plan struct {
		FormatVersion    string `json:"format_version"`
		TerraformVersion string `json:"terraform_version"`
		Errored          bool   `json:"errored"`
		ResourceChanges  []struct {
			Address string `json:"address"`
			Mode    string `json:"mode"`
			Change  struct {
				Actions []string       `json:"actions"`
				Before  map[string]any `json:"before"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if json.Unmarshal(payload, &plan) != nil || plan.Errored || plan.FormatVersion != "1.2" || plan.TerraformVersion != "1.10.5" {
		return "", lifecycle.ErrPreflight
	}
	quoted, _ := json.Marshal(replica)
	instance := "aws_instance.controller[" + string(quoted) + "]"
	attachment := "aws_volume_attachment.observer_state[" + string(quoted) + "]"
	oldID := ""
	seen := map[string]bool{}
	for _, change := range plan.ResourceChanges {
		if seen[change.Address] {
			return "", lifecycle.ErrPreflight
		}
		seen[change.Address] = true
		if reflect.DeepEqual(change.Change.Actions, []string{"no-op"}) || (change.Mode == "data" && reflect.DeepEqual(change.Change.Actions, []string{"read"})) {
			continue
		}
		if change.Mode != "managed" || (change.Address != instance && change.Address != attachment) ||
			!reflect.DeepEqual(change.Change.Actions, []string{"delete", "create"}) {
			return "", lifecycle.ErrPreflight
		}
		if change.Address == instance {
			id, ok := change.Change.Before["id"].(string)
			if !ok || id == "" {
				return "", lifecycle.ErrPreflight
			}
			oldID = id
		}
	}
	if oldID == "" {
		return "", lifecycle.ErrPreflight
	}
	return oldID, nil
}

func (r *terraformRollout) Validate(ctx context.Context) error {
	payload, err := r.command(ctx, "show", "-json", r.plan)
	if err != nil {
		return err
	}
	r.oldInstance, err = validateRolloutPlan(payload, r.replica)
	return err
}

func (r *terraformRollout) Apply(ctx context.Context) error {
	_, err := r.command(ctx, "apply", "-input=false", "-auto-approve", r.plan)
	return err
}

func (r *terraformRollout) Healthy(ctx context.Context, after time.Time) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	hash, _ := r.topology.Hash()
	for {
		payload, err := r.command(deadline, "output", "-json", "controller_instances")
		if err != nil {
			return err
		}
		var instances map[string]struct {
			InstanceID string `json:"instance_id"`
		}
		if strictjson.Validate(payload, 4*1024*1024) != nil || json.Unmarshal(payload, &instances) != nil || len(instances) != len(r.topology.ControllerIDs) {
			return lifecycle.ErrPreflight
		}
		ids := make([]string, 0, len(instances))
		unique := map[string]bool{}
		for _, id := range r.topology.ControllerIDs {
			instance := instances[id].InstanceID
			if instance == "" || unique[instance] {
				return lifecycle.ErrPreflight
			}
			unique[instance] = true
			ids = append(ids, instance)
			if !after.IsZero() && id != r.replica && (r.beforeInstances == nil || r.beforeInstances[id] != instance) {
				return lifecycle.ErrPreflight
			}
		}
		if after.IsZero() && instances[r.replica].InstanceID != r.oldInstance {
			return lifecycle.ErrPreflight
		}
		if !after.IsZero() && instances[r.replica].InstanceID == r.oldInstance {
			return lifecycle.ErrPreflight
		}
		result, err := r.ec2.DescribeInstanceStatus(deadline, &ec2.DescribeInstanceStatusInput{InstanceIds: ids, IncludeAllInstances: aws.Bool(true)})
		if err != nil {
			return lifecycle.ErrPreflight
		}
		healthy := result != nil && len(result.InstanceStatuses) == len(ids)
		if !after.IsZero() {
			old, err := r.ec2.DescribeInstances(deadline, &ec2.DescribeInstancesInput{InstanceIds: []string{r.oldInstance}})
			if err != nil || old == nil || len(old.Reservations) != 1 || len(old.Reservations[0].Instances) != 1 ||
				aws.ToString(old.Reservations[0].Instances[0].InstanceId) != r.oldInstance || old.Reservations[0].Instances[0].State == nil || old.Reservations[0].Instances[0].State.Name != types.InstanceStateNameTerminated {
				healthy = false
			}
		}
		seen := map[string]bool{}
		if result != nil {
			for _, status := range result.InstanceStatuses {
				id := aws.ToString(status.InstanceId)
				if !unique[id] || seen[id] || status.InstanceState == nil || status.InstanceState.Name != types.InstanceStateNameRunning || status.InstanceStatus == nil || status.InstanceStatus.Status != types.SummaryStatusOk || status.SystemStatus == nil || status.SystemStatus.Status != types.SummaryStatusOk {
					healthy = false
				}
				seen[id] = true
			}
		}
		observations, err := r.durable.ListObservations(deadline, store.ObservationScope{DeploymentID: r.topology.DeploymentID, TopologyHash: hash})
		if err != nil {
			return lifecycle.ErrPreflight
		}
		now := time.Now()
		seenObservers := map[string]bool{}
		for _, observation := range observations {
			if observation == nil || observation.Validate() != nil || !r.topology.HasControllerID(observation.ControllerID) || seenObservers[observation.ControllerID] || !observation.BackendHealthy || observation.CapturedAt.After(now) || !observation.ExpiresAt.After(now) ||
				!observation.CapturedAt.Add(r.topology.Policy.ObservationFreshness.Duration()).After(now) || (!after.IsZero() && !observation.CapturedAt.After(after)) {
				healthy = false
				continue
			}
			seenObservers[observation.ControllerID] = true
		}
		if healthy && len(seenObservers) == len(r.topology.ControllerIDs) {
			if after.IsZero() {
				r.beforeInstances = map[string]string{}
				for id, instance := range instances {
					r.beforeInstances[id] = instance.InstanceID
				}
			}
			return nil
		}
		if err := store.Wait(deadline, store.RealClock{}, r.topology.Policy.ObservationInterval.Duration()); err != nil {
			return lifecycle.ErrPreflight
		}
	}
}
