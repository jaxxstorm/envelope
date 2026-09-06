// Package config parses and validates the production controller topology.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

const (
	TopologySchemaVersion = 1
	maxTopologyJSONBytes  = 4 * 1024 * 1024
)

// Duration is a JSON string containing a Go duration, such as "30s".
type Duration time.Duration

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("duration must be a JSON string")
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return errors.New("invalid duration string")
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

type Policy struct {
	ReplicaCount            int      `json:"replica_count"`
	ObservationQuorum       int      `json:"observation_quorum"`
	ObservationInterval     Duration `json:"observation_interval"`
	ObservationFreshness    Duration `json:"observation_freshness"`
	FailoverStability       Duration `json:"failover_stability"`
	FailbackStability       Duration `json:"failback_stability"`
	Cooldown                Duration `json:"cooldown"`
	LeaseDuration           Duration `json:"lease_duration"`
	LeaseRenewInterval      Duration `json:"lease_renew_interval"`
	LeaseDangerWindow       Duration `json:"lease_danger_window"`
	APITimeout              Duration `json:"api_timeout"`
	RouteConvergenceTimeout Duration `json:"route_convergence_timeout"`
}

type DynamoDBConfig struct {
	Table  string `json:"table"`
	Region string `json:"region"`
}

type TailnetConfig struct {
	Name            string `json:"name"`
	ControlURL      string `json:"control_url,omitempty"`
	TSNetAuthKeyEnv string `json:"tsnet_auth_key_env"`
	AdminAPIKeyEnv  string `json:"admin_api_key_env"`
	StateBaseDir    string `json:"state_base_dir"`
}

type Site struct {
	ID            string   `json:"id"`
	VPCID         string   `json:"vpc_id"`
	Region        string   `json:"region"`
	LocalPrefixes []string `json:"local_prefixes"`
}

type Router struct {
	ID               string `json:"id"`
	SiteID           string `json:"site_id"`
	StableNodeID     string `json:"stable_node_id"`
	InstanceID       string `json:"instance_id"`
	ENIID            string `json:"eni_id"`
	VPCID            string `json:"vpc_id"`
	SubnetID         string `json:"subnet_id"`
	AvailabilityZone string `json:"availability_zone"`
	Region           string `json:"region"`
}

// Domain.PreferredOwner is a router ID. DomainAuthority resolves it to the
// router's stable Tailnet node ID for durable state.
type Domain struct {
	ID                      string   `json:"id"`
	SiteID                  string   `json:"site_id"`
	SourcePrefix            string   `json:"source_prefix"`
	RouteTableID            string   `json:"route_table_id"`
	GWLBESubnetID           string   `json:"gwlbe_subnet_id"`
	RouteTableAssociationID string   `json:"route_table_association_id"`
	RemotePrefixes          []string `json:"remote_prefixes"`
	PreferredOwner          string   `json:"preferred_owner"`
}

type Topology struct {
	SchemaVersion int            `json:"schema_version"`
	DeploymentID  string         `json:"deployment_id"`
	ControllerIDs []string       `json:"controller_ids"`
	Policy        Policy         `json:"policy"`
	DynamoDB      DynamoDBConfig `json:"dynamodb"`
	Tailnet       TailnetConfig  `json:"tailnet"`
	Sites         []Site         `json:"sites"`
	Routers       []Router       `json:"routers"`
	Domains       []Domain       `json:"domains"`
}

// ProcessConfig contains values that identify one disposable controller
// process and locate its shared immutable topology.
type ProcessConfig struct {
	ControllerID string
	TopologyPath string
}

// Parse decodes exactly one strict JSON topology and validates it.
func Parse(r io.Reader) (*Topology, error) {
	if r == nil {
		return nil, errors.New("topology reader is nil")
	}
	payload, err := io.ReadAll(io.LimitReader(r, maxTopologyJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decode topology: %w", err)
	}
	if err := strictjson.Validate(payload, maxTopologyJSONBytes); err != nil {
		switch {
		case errors.Is(err, strictjson.ErrTrailingValue):
			return nil, fmt.Errorf("decode topology: trailing JSON content: %w", err)
		case errors.Is(err, strictjson.ErrTrailingData):
			return nil, fmt.Errorf("decode topology trailing content: %w", err)
		default:
			return nil, fmt.Errorf("decode topology: %w", err)
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	var topology Topology
	if err := decoder.Decode(&topology); err != nil {
		return nil, fmt.Errorf("decode topology: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode topology: trailing JSON content")
		}
		return nil, fmt.Errorf("decode topology trailing content: %w", err)
	}
	if err := topology.Validate(); err != nil {
		return nil, fmt.Errorf("validate topology: %w", err)
	}
	return &topology, nil
}

func ParseFile(path string) (*Topology, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open topology: %w", err)
	}
	defer file.Close()
	return Parse(file)
}

// HasControllerID reports whether id is an explicitly allowed replica.
func (t *Topology) HasControllerID(id string) bool {
	if t == nil {
		return false
	}
	for _, allowed := range t.ControllerIDs {
		if id == allowed {
			return true
		}
	}
	return false
}

// ResolveTSNetAuthKey obtains the embedded tsnet auth key through environment
// indirection without including its value in an error.
func (c TailnetConfig) ResolveTSNetAuthKey(lookup func(string) (string, bool)) (string, error) {
	return resolveSecret("tsnet auth key", c.TSNetAuthKeyEnv, lookup)
}

// ResolveAuthKey is the concise alias for ResolveTSNetAuthKey.
func (c TailnetConfig) ResolveAuthKey(lookup func(string) (string, bool)) (string, error) {
	return c.ResolveTSNetAuthKey(lookup)
}

// ResolveAdminAPIKey obtains the read-only Admin API key through environment
// indirection without including its value in an error.
func (c TailnetConfig) ResolveAdminAPIKey(lookup func(string) (string, bool)) (string, error) {
	return resolveSecret("Admin API key", c.AdminAPIKeyEnv, lookup)
}

// StateDirForController returns the private tsnet state directory for one
// replica. Controller IDs cannot contain path separators.
func (c TailnetConfig) StateDirForController(controllerID string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if err := validateControllerID(controllerID); err != nil {
		return "", err
	}
	stateDir := filepath.Join(c.StateBaseDir, controllerID)
	if filepath.Dir(stateDir) != c.StateBaseDir {
		return "", errors.New("controller state directory escapes its base directory")
	}
	return stateDir, nil
}

func resolveSecret(label, environmentName string, lookup func(string) (string, bool)) (string, error) {
	if !environmentNamePattern.MatchString(environmentName) || looksLikeSecret(environmentName) {
		return "", fmt.Errorf("%s environment variable name is invalid", label)
	}
	if lookup == nil {
		return "", fmt.Errorf("%s environment lookup is nil", label)
	}
	secret, found := lookup(environmentName)
	if !found || strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("%s environment variable %s is not set", label, environmentName)
	}
	if secret != strings.TrimSpace(secret) {
		return "", fmt.Errorf("%s environment variable %s contains surrounding whitespace", label, environmentName)
	}
	return secret, nil
}
