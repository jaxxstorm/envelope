package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/godbus/dbus/v5"
	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
	"tailscale.com/client/tailscale"
)

const enrollmentDirectory = "/etc/envelope/router-attestor"

type bootstrapConfig struct {
	RouterID                  string `json:"router_id"`
	PublicKey                 string `json:"ed25519_public_key"`
	AuthorityRegion           string `json:"authority_region"`
	ConfigurationParameterARN string `json:"configuration_parameter_arn"`
	SeedParameterARN          string `json:"seed_parameter_arn"`
	SeedVersion               int64  `json:"seed_version"`
}

type configurationPointer struct {
	Bucket  string `json:"bucket"`
	Key     string `json:"key"`
	Version string `json:"version_id"`
	SHA256  string `json:"sha256"`
}

type keyBinding struct {
	InstanceID        string `json:"instance_id"`
	ENIID             string `json:"eni_id"`
	StableNodeID      string `json:"stable_node_id"`
	ConfigurationHash string `json:"configuration_sha256"`
	PublicKey         string `json:"ed25519_public_key"`
	SeedARN           string `json:"seed_parameter_arn"`
	SeedVersion       int64  `json:"seed_version"`
}

func verifyBinding(payload []byte, c attestation.CollectorConfig, b bootstrapConfig) error {
	var binding keyBinding
	if decodeStrict(payload, &binding, 8192) != nil {
		return attestation.ErrRejected
	}
	_, owner, err := c.Authority()
	if err != nil {
		return err
	}
	digest, _ := c.Hash()
	if binding.InstanceID != owner.InstanceID || binding.ENIID != owner.ENIID || binding.StableNodeID != owner.StableNodeID || binding.ConfigurationHash != digest || binding.PublicKey != b.PublicKey || binding.SeedARN != b.SeedParameterARN || binding.SeedVersion != b.SeedVersion {
		return attestation.ErrRejected
	}
	return nil
}

func decodeStrict(payload []byte, target any, maximum int) error {
	if strictjson.Validate(payload, maximum) != nil {
		return attestation.ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return attestation.ErrRejected
	}
	return nil
}

func configurationIdentity(args []string) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "reviewed nonsecret collector configuration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" {
		return attestation.ErrRejected
	}
	file, err := os.Open(*path)
	if err != nil {
		return attestation.ErrRejected
	}
	defer file.Close()
	configuration, err := attestation.ParseCollectorConfig(file)
	if err != nil {
		return err
	}
	canonical, err := configuration.CanonicalJSON()
	if err != nil {
		return err
	}
	digest, _ := configuration.Hash()
	topology, _ := configuration.Topology.Hash()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "component": "envelope-router-attestor", "version": version, "revision": revision, "source_modified": sourceModified != "false", "go_version": runtime.Version(), "canonical_json_base64": base64.StdEncoding.EncodeToString(canonical), "canonical_sha256": digest, "topology_sha256": topology, "router_id": configuration.RouterID, "ed25519_public_key": configuration.PublicKey})
}

type seedAPI interface {
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// provisionSeed never prints or persists a plaintext seed locally and never
// overwrites an existing parameter. Lost responses are reconciled only against
// this invocation's unpredictable seed; uncertainty does not authorize cleanup.
func provisionSeed(ctx context.Context, client seedAPI, name, kms string, tags ...ssmtypes.Tag) (map[string]any, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, attestation.ErrRejected
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	value := hex.EncodeToString(seed)
	_, putErr := client.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(name), Value: aws.String(value), KeyId: aws.String(kms), Type: ssmtypes.ParameterTypeSecureString, Overwrite: aws.Bool(false), Tier: ssmtypes.ParameterTierStandard, Tags: tags})
	var parameter *ssmtypes.Parameter
	for attempt := 0; attempt < 2; attempt++ {
		read, err := client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name + ":1"), WithDecryption: aws.Bool(true)})
		if err != nil || read == nil || read.Parameter == nil || read.Parameter.Version != 1 || read.Parameter.Type != ssmtypes.ParameterTypeSecureString || aws.ToString(read.Parameter.Name) != name ||
			subtle.ConstantTimeCompare([]byte(aws.ToString(read.Parameter.Value)), []byte(value)) != 1 {
			_ = putErr
			return nil, attestation.ErrRejected
		}
		if aws.ToString(read.Parameter.ARN) == "" || (parameter != nil && aws.ToString(parameter.ARN) != aws.ToString(read.Parameter.ARN)) {
			return nil, attestation.ErrRejected
		}
		parameter = read.Parameter
		if attempt == 0 {
			select {
			case <-ctx.Done():
				return nil, attestation.ErrRejected
			case <-time.After(time.Second):
			}
		}
	}
	return map[string]any{"parameter_arn": aws.ToString(parameter.ARN), "version": int64(1), "ed25519_public_key": hex.EncodeToString(private.Public().(ed25519.PublicKey))}, nil
}

func provisionKey(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("provision-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	region := flags.String("region", "", "seed authority region")
	name := flags.String("parameter", "", "new unique per-router SecureString name")
	kms := flags.String("kms-key-arn", "", "reviewed customer-managed key")
	runID := flags.String("run-id", "", "optional protected deployment ownership")
	invocation := flags.String("invocation-id", "", "protected invocation identity")
	expires := flags.String("expires-at", "", "protected UTC expiry")
	purpose := flags.String("purpose", "", "protected seed purpose")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !regexp.MustCompile(`^[a-z0-9-]+-[0-9]+$`).MatchString(*region) || !regexp.MustCompile(`^/envelope/[A-Za-z0-9/_-]+$`).MatchString(*name) || !regexp.MustCompile(`^arn:aws:kms:`+regexp.QuoteMeta(*region)+`:[0-9]{12}:key/[a-z0-9-]+$`).MatchString(*kms) {
		return attestation.ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	configuration, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(*region))
	if err != nil {
		return attestation.ErrRejected
	}
	var tags []ssmtypes.Tag
	if *runID != "" || *invocation != "" || *expires != "" || *purpose != "" {
		expiry, err := time.Parse(time.RFC3339, *expires)
		if err != nil || !expiry.After(time.Now()) || expiry.After(time.Now().Add(24*time.Hour)) || !regexp.MustCompile(`^[a-z][a-z0-9-]{2,19}$`).MatchString(*runID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(*invocation) || !regexp.MustCompile(`^[a-z0-9-]{1,128}$`).MatchString(*purpose) || !strings.HasPrefix(*name, "/envelope/"+*runID+"/") {
			return attestation.ErrRejected
		}
		for key, value := range map[string]string{"EnvelopeRun": *runID, "EnvelopeInvocation": *invocation, "ExpiresAt": *expires, "Purpose": *purpose} {
			tags = append(tags, ssmtypes.Tag{Key: aws.String(key), Value: aws.String(value)})
		}
	}
	result, err := provisionSeed(ctx, ssm.NewFromConfig(configuration), *name, *kms, tags...)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func validateBootstrap(b bootstrapConfig) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`).MatchString(b.RouterID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(b.PublicKey) || b.SeedVersion < 1 || b.SeedVersion > 100 || !regexp.MustCompile(`^[a-z0-9-]+-[0-9]+$`).MatchString(b.AuthorityRegion) {
		return attestation.ErrRejected
	}
	pattern := regexp.MustCompile(`^arn:aws:ssm:` + regexp.QuoteMeta(b.AuthorityRegion) + `:[0-9]{12}:parameter/envelope/[A-Za-z0-9/_-]+$`)
	if !pattern.MatchString(b.ConfigurationParameterARN) || !pattern.MatchString(b.SeedParameterARN) || b.ConfigurationParameterARN == b.SeedParameterARN || strings.Split(b.ConfigurationParameterARN, ":")[4] != strings.Split(b.SeedParameterARN, ":")[4] {
		return attestation.ErrRejected
	}
	return nil
}

func parameterValue(ctx context.Context, client *ssm.Client, arn string, version int64, secret bool) ([]byte, error) {
	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(arn + ":" + strconv.FormatInt(version, 10)), WithDecryption: aws.Bool(secret)})
	if err != nil || result == nil || result.Parameter == nil || result.Parameter.Version != version || aws.ToString(result.Parameter.ARN) != arn || result.Parameter.Value == nil || len(*result.Parameter.Value) > 8192 {
		return nil, attestation.ErrRejected
	}
	want := ssmtypes.ParameterTypeString
	if secret {
		want = ssmtypes.ParameterTypeSecureString
	}
	if result.Parameter.Type != want {
		return nil, attestation.ErrRejected
	}
	return []byte(*result.Parameter.Value), nil
}

func verifyLocalEnrollment(ctx context.Context, metadata *imds.Client, c attestation.CollectorConfig, b bootstrapConfig) error {
	_, owner, err := c.Authority()
	if err != nil || c.RouterID != b.RouterID || c.PublicKey != b.PublicKey {
		return attestation.ErrRejected
	}
	identity, err := metadata.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil || identity == nil || identity.InstanceID != owner.InstanceID || identity.Region != owner.Region || identity.AvailabilityZone != owner.AvailabilityZone || !strings.Contains(b.SeedParameterARN, ":"+identity.AccountID+":parameter/") {
		return attestation.ErrRejected
	}
	underlay, err := net.InterfaceByName(c.UnderlayInterface)
	if err != nil {
		return attestation.ErrRejected
	}
	eni, err := metadata.GetMetadata(ctx, &imds.GetMetadataInput{Path: "network/interfaces/macs/" + underlay.HardwareAddr.String() + "/interface-id"})
	if err != nil || eni == nil || eni.Content == nil {
		return attestation.ErrRejected
	}
	data, err := io.ReadAll(io.LimitReader(eni.Content, 129))
	_ = eni.Content.Close()
	if err != nil || len(data) > 128 || strings.TrimSpace(string(data)) != owner.ENIID {
		return attestation.ErrRejected
	}
	local := tailscale.LocalClient{Socket: "/var/run/tailscale/tailscaled.sock", UseSocketOnly: true}
	status, err := local.StatusWithoutPeers(ctx)
	if err != nil || status == nil || status.Self == nil || string(status.Self.ID) != owner.StableNodeID {
		return attestation.ErrRejected
	}
	return nil
}

func installEnrollment(parent string, canonical, seed, binding []byte) error {
	destination := filepath.Join(parent, "router-attestor")
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return attestation.ErrRejected
	}
	stage, err := os.MkdirTemp(parent, ".router-attestor-")
	if err != nil {
		return attestation.ErrRejected
	}
	defer func() { _ = os.Chmod(stage, 0700); _ = os.RemoveAll(stage) }()
	for name, data := range map[string][]byte{"config.json": canonical, "signing-key": seed, "binding.json": binding} {
		file, err := os.OpenFile(filepath.Join(stage, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return attestation.ErrRejected
		}
		_, writeErr := file.Write(data)
		syncErr := file.Sync()
		mode := os.FileMode(0444)
		if name == "signing-key" {
			mode = 0400
		}
		chmodErr := file.Chmod(mode)
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || chmodErr != nil || closeErr != nil {
			return attestation.ErrRejected
		}
	}
	if os.Chmod(stage, 0500) != nil {
		return attestation.ErrRejected
	}
	directory, err := os.Open(stage)
	if err != nil {
		return attestation.ErrRejected
	}
	syncErr := directory.Sync()
	_ = directory.Close()
	if syncErr != nil {
		return attestation.ErrRejected
	}
	if os.Rename(stage, destination) != nil {
		return attestation.ErrRejected
	}
	directory, err = os.Open(parent)
	if err != nil {
		return attestation.ErrRejected
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return attestation.ErrRejected
	}
	return nil
}

func startEnrolledService(ctx context.Context) error {
	bus, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return attestation.ErrRejected
	}
	defer bus.Close()
	manager := bus.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	if manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StartUnit", 0, "envelope-router-attestor.service", "replace").Err != nil {
		return attestation.ErrRejected
	}
	if manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StopUnit", 0, "envelope-router-attestor-enroll.timer", "replace").Err != nil {
		return attestation.ErrRejected
	}
	return nil
}

func enroll(ctx context.Context, args []string) error {
	if runtime.GOOS != "linux" {
		return attestation.ErrRejected
	}
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("bootstrap", "/etc/envelope/router-attestor-bootstrap.json", "immutable public enrollment references")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return attestation.ErrRejected
	}
	payload, err := immutableRead(*path, 8192, false)
	if err != nil {
		return err
	}
	var bootstrap bootstrapConfig
	if decodeStrict(payload, &bootstrap, 8192) != nil || validateBootstrap(bootstrap) != nil {
		return attestation.ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	metadataTransport := http.DefaultTransport.(*http.Transport).Clone()
	metadataTransport.Proxy = nil
	metadata := imds.New(imds.Options{Endpoint: "http://169.254.169.254", EnableFallback: aws.FalseTernary, ClientEnableState: imds.ClientEnabled, HTTPClient: &http.Client{Transport: metadataTransport, Timeout: 5 * time.Second}})
	if _, err := os.Lstat(enrollmentDirectory); err == nil {
		canonical, err := immutableRead(enrollmentDirectory+"/config.json", 4*1024*1024, false)
		if err != nil {
			return err
		}
		configuration, err := attestation.ParseCollectorConfig(bytes.NewReader(canonical))
		if err != nil {
			return err
		}
		binding, err := immutableRead(enrollmentDirectory+"/binding.json", 8192, false)
		if err != nil || verifyBinding(binding, configuration, bootstrap) != nil {
			return attestation.ErrRejected
		}
		seed, err := immutableRead(enrollmentDirectory+"/signing-key", 64, true)
		if err != nil {
			return err
		}
		defer clear(seed)
		decoded, err := hex.DecodeString(string(seed))
		if err != nil || len(decoded) != 32 {
			return attestation.ErrRejected
		}
		private := ed25519.NewKeyFromSeed(decoded)
		defer clear(decoded)
		defer clear(private)
		if hex.EncodeToString(private.Public().(ed25519.PublicKey)) != bootstrap.PublicKey || verifyLocalEnrollment(ctx, metadata, configuration, bootstrap) != nil {
			return attestation.ErrRejected
		}
		return startEnrolledService(ctx)
	} else if !os.IsNotExist(err) {
		return attestation.ErrRejected
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	awsConfiguration := aws.Config{Region: bootstrap.AuthorityRegion, Credentials: aws.NewCredentialsCache(ec2rolecreds.New(func(o *ec2rolecreds.Options) { o.Client = metadata })), HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	parameters := ssm.NewFromConfig(awsConfiguration, func(o *ssm.Options) {
		o.BaseEndpoint = aws.String("https://ssm." + bootstrap.AuthorityRegion + ".amazonaws.com")
	})
	pointerJSON, err := parameterValue(ctx, parameters, bootstrap.ConfigurationParameterARN, 1, false)
	if err != nil {
		return err
	}
	var pointer configurationPointer
	if decodeStrict(pointerJSON, &pointer, 8192) != nil || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,62}$`).MatchString(pointer.Bucket) || !regexp.MustCompile(`^[A-Za-z0-9/_-]+\.json$`).MatchString(pointer.Key) || strings.Contains(pointer.Key, "..") || pointer.Version == "" || pointer.Version == "null" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pointer.SHA256) {
		return attestation.ErrRejected
	}
	objects := s3.NewFromConfig(awsConfiguration, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("https://s3." + bootstrap.AuthorityRegion + ".amazonaws.com")
	})
	object, err := objects.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(pointer.Bucket), Key: aws.String(pointer.Key), VersionId: aws.String(pointer.Version)})
	if err != nil || object == nil || object.Body == nil || aws.ToString(object.VersionId) != pointer.Version {
		return attestation.ErrRejected
	}
	canonical, err := io.ReadAll(io.LimitReader(object.Body, 4*1024*1024+1))
	_ = object.Body.Close()
	if err != nil || len(canonical) > 4*1024*1024 {
		return attestation.ErrRejected
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != pointer.SHA256 {
		return attestation.ErrRejected
	}
	configuration, err := attestation.ParseCollectorConfig(bytes.NewReader(canonical))
	if err != nil {
		return err
	}
	canonicalHash, err := configuration.Hash()
	if err != nil || canonicalHash != pointer.SHA256 || verifyLocalEnrollment(ctx, metadata, configuration, bootstrap) != nil {
		return attestation.ErrRejected
	}
	bindingARN := strings.Split(bootstrap.ConfigurationParameterARN, ":parameter/")[0] + ":parameter/envelope/attestor-bindings/" + bootstrap.PublicKey
	binding, err := parameterValue(ctx, parameters, bindingARN, 1, false)
	if err != nil || verifyBinding(binding, configuration, bootstrap) != nil {
		return attestation.ErrRejected
	}
	seedHex, err := parameterValue(ctx, parameters, bootstrap.SeedParameterARN, bootstrap.SeedVersion, true)
	if err != nil {
		return err
	}
	defer clear(seedHex)
	seed, err := hex.DecodeString(string(seedHex))
	if err != nil || len(seed) != 32 {
		return attestation.ErrRejected
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if hex.EncodeToString(private.Public().(ed25519.PublicKey)) != bootstrap.PublicKey {
		return attestation.ErrRejected
	}
	if installEnrollment("/etc/envelope", canonical, seedHex, binding) != nil {
		return attestation.ErrRejected
	}
	return startEnrolledService(ctx)
}
