package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jaxxstorm/envelope/internal/controller/attestation"
)

type seedFixture struct {
	value, name          string
	lost, bad, overwrite bool
}

func (f *seedFixture) PutParameter(_ context.Context, input *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.overwrite = aws.ToBool(input.Overwrite)
	f.value, f.name = aws.ToString(input.Value), aws.ToString(input.Name)
	if f.lost {
		return nil, context.DeadlineExceeded
	}
	return &ssm.PutParameterOutput{Version: 1}, nil
}
func (f *seedFixture) GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	value := f.value
	if f.bad {
		value = "foreign-value"
	}
	return &ssm.GetParameterOutput{Parameter: &types.Parameter{ARN: aws.String("arn:aws:ssm:us-west-2:123456789012:parameter" + f.name), Name: aws.String(f.name), Version: 1, Type: types.ParameterTypeSecureString, Value: aws.String(value)}}, nil
}

func TestSeedProvisioningIsNonOverwritingAndSecretSafe(t *testing.T) {
	for _, mode := range []string{"confirmed", "lost-response", "foreign-readback"} {
		t.Run(mode, func(t *testing.T) {
			f := &seedFixture{lost: mode == "lost-response", bad: mode == "foreign-readback"}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := provisionSeed(ctx, f, "/envelope/test/seed", "arn:aws:kms:us-west-2:123456789012:key/test")
			if mode == "foreign-readback" {
				if !errors.Is(err, attestation.ErrRejected) {
					t.Fatal("foreign parameter adopted")
				}
				return
			}
			if err != nil || f.overwrite {
				t.Fatalf("provision=%v overwrite=%t", err, f.overwrite)
			}
			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte(f.value)) || len(result) != 3 {
				t.Fatal("private seed escaped public receipt")
			}
		})
	}
}

func TestAtomicEnrollmentNeverOverwritesAndBindsIdentity(t *testing.T) {
	file, err := os.Open("../../internal/controller/attestation/testdata/router-config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	c, err := attestation.ParseCollectorConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	_, owner, _ := c.Authority()
	hash, _ := c.Hash()
	canonical, _ := c.CanonicalJSON()
	b := bootstrapConfig{RouterID: c.RouterID, PublicKey: c.PublicKey, AuthorityRegion: "us-west-2", ConfigurationParameterARN: "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/enrollment", SeedParameterARN: "arn:aws:ssm:us-west-2:123456789012:parameter/envelope/test/seed", SeedVersion: 1}
	identity := keyBinding{InstanceID: owner.InstanceID, ENIID: owner.ENIID, StableNodeID: owner.StableNodeID, ConfigurationHash: hash, PublicKey: c.PublicKey, SeedARN: b.SeedParameterARN, SeedVersion: 1}
	binding, _ := json.Marshal(identity)
	if verifyBinding(binding, c, b) != nil {
		t.Fatal("valid key binding rejected")
	}
	identity.InstanceID = "i-other"
	wrong, _ := json.Marshal(identity)
	if verifyBinding(wrong, c, b) == nil {
		t.Fatal("key reassignment accepted")
	}
	parent := t.TempDir()
	seed := bytes.Repeat([]byte("a"), 64)
	if err := installEnrollment(parent, canonical, seed, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(parent, "router-attestor"), 0700) })
	for name, mode := range map[string]os.FileMode{"config.json": 0444, "signing-key": 0400, "binding.json": 0444} {
		info, err := os.Stat(filepath.Join(parent, "router-attestor", name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("immutable %s mode: %v", name, err)
		}
	}
	if err := installEnrollment(parent, []byte("changed"), seed, binding); err == nil {
		t.Fatal("existing immutable enrollment overwritten")
	}
	actual, err := os.ReadFile(filepath.Join(parent, "router-attestor", "config.json"))
	if err != nil || !bytes.Equal(actual, canonical) {
		t.Fatal("existing configuration changed")
	}
}
