package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"

	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
)

const component = "envelope-controller-topology"

var (
	version        = "dev"
	revision       = "unknown"
	buildDate      = "unknown"
	sourceModified = "unknown"
)

type topologyIdentity struct {
	Schema              int               `json:"schema"`
	Component           string            `json:"component"`
	Version             string            `json:"version"`
	Revision            string            `json:"revision"`
	GoVersion           string            `json:"go_version"`
	VCSModified         bool              `json:"vcs_modified"`
	CanonicalSHA256     string            `json:"canonical_sha256"`
	CanonicalJSONBase64 string            `json:"canonical_json_base64"`
	PolicyDurations     map[string]string `json:"policy_durations"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "topology identity:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Printf("%s %s revision=%s modified=%s built=%s go=%s\n", component, version, revision, sourceModified, buildDate, runtime.Version())
		return nil
	}
	if len(args) == 0 {
		return errors.New("expected canonicalize, identity, or verify command")
	}

	switch args[0] {
	case "canonicalize":
		input, _, err := parseFlags(args[0], args[1:], false)
		if err != nil {
			return err
		}
		_, canonical, _, err := loadCanonical(input)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(canonical)
		return err
	case "identity":
		input, _, err := parseFlags(args[0], args[1:], false)
		if err != nil {
			return err
		}
		topology, canonical, digest, err := loadCanonical(input)
		if err != nil {
			return err
		}
		modified, err := strconv.ParseBool(sourceModified)
		if err != nil {
			return errors.New("binary has no release VCS-modified identity")
		}
		encoded, err := json.Marshal(topologyIdentity{
			Schema:              1,
			Component:           component,
			Version:             version,
			Revision:            revision,
			GoVersion:           runtime.Version(),
			VCSModified:         modified,
			CanonicalSHA256:     digest,
			CanonicalJSONBase64: base64.StdEncoding.EncodeToString(canonical),
			PolicyDurations: map[string]string{
				"observation_interval":      topology.Policy.ObservationInterval.String(),
				"observation_freshness":     topology.Policy.ObservationFreshness.String(),
				"failover_stability":        topology.Policy.FailoverStability.String(),
				"failback_stability":        topology.Policy.FailbackStability.String(),
				"cooldown":                  topology.Policy.Cooldown.String(),
				"lease_duration":            topology.Policy.LeaseDuration.String(),
				"lease_renew_interval":      topology.Policy.LeaseRenewInterval.String(),
				"lease_danger_window":       topology.Policy.LeaseDangerWindow.String(),
				"api_timeout":               topology.Policy.APITimeout.String(),
				"route_convergence_timeout": topology.Policy.RouteConvergenceTimeout.String(),
			},
		})
		if err != nil {
			return fmt.Errorf("encode topology identity: %w", err)
		}
		_, err = os.Stdout.Write(encoded)
		return err
	case "verify":
		input, expected, err := parseFlags(args[0], args[1:], true)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("read topology: %w", err)
		}
		_, canonical, digest, err := canonicalize(raw)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, canonical) {
			return errors.New("topology is valid but is not exact Go-canonical JSON")
		}
		if digest != expected {
			return errors.New("canonical topology SHA-256 does not match deployment identity")
		}
		return nil
	default:
		return fmt.Errorf("unsupported command %q", args[0])
	}
}

func parseFlags(command string, args []string, requireHash bool) (string, string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	input := flags.String("input", "", "topology JSON path")
	expected := flags.String("sha256", "", "expected lowercase canonical SHA-256")
	if err := flags.Parse(args); err != nil {
		return "", "", err
	}
	if flags.NArg() != 0 || *input == "" {
		return "", "", errors.New("--input is required and positional arguments are not accepted")
	}
	if requireHash {
		decoded, err := hex.DecodeString(*expected)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != *expected {
			return "", "", errors.New("--sha256 must be one lowercase SHA-256")
		}
	} else if *expected != "" {
		return "", "", errors.New("--sha256 is accepted only by verify")
	}
	return *input, *expected, nil
}

func loadCanonical(path string) (*controllerconfig.Topology, []byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read topology: %w", err)
	}
	return canonicalize(raw)
}

func canonicalize(raw []byte) (*controllerconfig.Topology, []byte, string, error) {
	topology, err := controllerconfig.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, "", err
	}
	canonical, err := topology.CanonicalJSON()
	if err != nil {
		return nil, nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return topology, canonical, hex.EncodeToString(digest[:]), nil
}
