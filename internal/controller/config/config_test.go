package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseStrictJSON(t *testing.T) {
	valid := validTopologyJSON(t)
	duplicateTopLevel := strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
	if duplicateTopLevel == string(valid) {
		t.Fatal("failed to construct duplicate top-level topology field")
	}
	duplicateNested := strings.Replace(string(valid), `"replica_count":3`, `"replica_count":3,"replica_count":3`, 1)
	if duplicateNested == string(valid) {
		t.Fatal("failed to construct duplicate nested topology field")
	}

	var withUnknownTop map[string]any
	if err := json.Unmarshal(valid, &withUnknownTop); err != nil {
		t.Fatal(err)
	}
	withUnknownTop["unexpected"] = true
	unknownTop, err := json.Marshal(withUnknownTop)
	if err != nil {
		t.Fatal(err)
	}

	var withUnknownPolicy map[string]any
	if err := json.Unmarshal(valid, &withUnknownPolicy); err != nil {
		t.Fatal(err)
	}
	withUnknownPolicy["policy"].(map[string]any)["settlement_timeout"] = "1m"
	unknownPolicy, err := json.Marshal(withUnknownPolicy)
	if err != nil {
		t.Fatal(err)
	}

	var withLiteralSecret map[string]any
	if err := json.Unmarshal(valid, &withLiteralSecret); err != nil {
		t.Fatal(err)
	}
	withLiteralSecret["tailnet"].(map[string]any)["auth_key"] = "ts" + "key-auth-must-not-leak"
	literalSecret, err := json.Marshal(withLiteralSecret)
	if err != nil {
		t.Fatal(err)
	}

	var withNumericDuration map[string]any
	if err := json.Unmarshal(valid, &withNumericDuration); err != nil {
		t.Fatal(err)
	}
	withNumericDuration["policy"].(map[string]any)["lease_duration"] = 50
	numericDuration, err := json.Marshal(withNumericDuration)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "valid", input: string(valid)},
		{name: "surrounding whitespace", input: " \n" + string(valid) + "\t"},
		{name: "duplicate top-level field", input: duplicateTopLevel, wantErr: "duplicate JSON object member"},
		{name: "duplicate nested field", input: duplicateNested, wantErr: "duplicate JSON object member"},
		{name: "unknown top-level field", input: string(unknownTop), wantErr: "unknown field"},
		{name: "unknown nested field", input: string(unknownPolicy), wantErr: "unknown field"},
		{name: "literal secret field", input: string(literalSecret), wantErr: `unknown field "auth_key"`},
		{name: "numeric duration", input: string(numericDuration), wantErr: "duration must be a JSON string"},
		{name: "second document", input: string(valid) + `{}`, wantErr: "trailing JSON content"},
		{name: "trailing token", input: string(valid) + ` nope`, wantErr: "trailing content"},
		{name: "empty", input: "", wantErr: "decode topology"},
		{name: "malformed", input: `{`, wantErr: "decode topology"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topology, err := Parse(strings.NewReader(test.input))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if topology.DeploymentID != "deployment-a" {
					t.Fatalf("deployment ID = %q", topology.DeploymentID)
				}
				if len(topology.ControllerIDs) != topology.Policy.ReplicaCount {
					t.Fatalf("controller IDs = %v, replica count = %d", topology.ControllerIDs, topology.Policy.ReplicaCount)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Parse() error = %v, want substring %q", err, test.wantErr)
			}
			if test.name == "literal secret field" && strings.Contains(err.Error(), "must-not-leak") {
				t.Fatalf("Parse() leaked secret: %v", err)
			}
		})
	}

	if _, err := Parse(nil); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("Parse(nil) error = %v", err)
	}
}

func TestParseBoundsTopologyJSON(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat(" ", maxTopologyJSONBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds byte limit") {
		t.Fatalf("Parse() oversize error = %v", err)
	}
}

func TestParseFile(t *testing.T) {
	path := t.TempDir() + "/topology.json"
	if err := os.WriteFile(path, validTopologyJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	topology, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}
	if topology.SchemaVersion != TopologySchemaVersion {
		t.Fatalf("schema version = %d", topology.SchemaVersion)
	}
	if _, err := ParseFile(path + ".missing"); err == nil || !strings.Contains(err.Error(), "open topology") {
		t.Fatalf("missing ParseFile() error = %v", err)
	}
}

func TestDurationJSON(t *testing.T) {
	var duration Duration
	if err := json.Unmarshal([]byte(`"2000ms"`), &duration); err != nil {
		t.Fatal(err)
	}
	if got, want := duration.Duration(), 2*time.Second; got != want {
		t.Fatalf("duration = %s, want %s", got, want)
	}
	encoded, err := json.Marshal(duration)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `"2s"`; got != want {
		t.Fatalf("encoded duration = %s, want %s", got, want)
	}
	for _, input := range []string{`2`, `null`, `"forever"`} {
		if err := json.Unmarshal([]byte(input), &duration); err == nil {
			t.Fatalf("duration %s unexpectedly decoded", input)
		}
	}
	secret := `"ts` + `key-auth-must-not-leak"`
	if err := json.Unmarshal([]byte(secret), &duration); err == nil || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("secret duration error = %v", err)
	}
}

func TestTopologyValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Topology)
		wantErr string
	}{
		{name: "valid", mutate: func(*Topology) {}},
		{name: "schema", mutate: func(topology *Topology) { topology.SchemaVersion = 2 }, wantErr: "schema version"},
		{name: "too few controller IDs", mutate: func(topology *Topology) { topology.ControllerIDs = topology.ControllerIDs[:2] }, wantErr: "does not match policy replica count"},
		{name: "too many controller IDs", mutate: func(topology *Topology) { topology.ControllerIDs = append(topology.ControllerIDs, "controller-d") }, wantErr: "does not match policy replica count"},
		{name: "duplicate controller ID", mutate: func(topology *Topology) { topology.ControllerIDs[1] = topology.ControllerIDs[0] }, wantErr: "duplicate controller ID"},
		{name: "unsafe controller ID", mutate: func(topology *Topology) { topology.ControllerIDs[0] = "../controller-a" }, wantErr: "contain only"},
		{name: "site overlap", mutate: func(topology *Topology) { topology.Sites[1].LocalPrefixes[0] = "10.0.0.128/25" }, wantErr: "overlaps"},
		{name: "same-site overlap", mutate: func(topology *Topology) { topology.Sites[0].LocalPrefixes[1] = "10.0.1.128/25" }, wantErr: "overlaps"},
		{name: "noncanonical site prefix", mutate: func(topology *Topology) { topology.Sites[0].LocalPrefixes[0] = "10.0.0.1/24" }, wantErr: "not canonical"},
		{name: "IPv6 site prefix", mutate: func(topology *Topology) { topology.Sites[0].LocalPrefixes[0] = "2001:db8::/64" }, wantErr: "not IPv4"},
		{name: "duplicate site ID", mutate: func(topology *Topology) { topology.Sites[1].ID = topology.Sites[0].ID }, wantErr: "duplicate site ID"},
		{name: "duplicate VPC", mutate: func(topology *Topology) { topology.Sites[1].VPCID = topology.Sites[0].VPCID }, wantErr: "share VPC ID"},
		{name: "duplicate router ID", mutate: func(topology *Topology) { topology.Routers[1].ID = topology.Routers[0].ID }, wantErr: "duplicate router ID"},
		{name: "duplicate stable node", mutate: func(topology *Topology) { topology.Routers[1].StableNodeID = topology.Routers[0].StableNodeID }, wantErr: "share stable node ID"},
		{name: "duplicate instance", mutate: func(topology *Topology) { topology.Routers[1].InstanceID = topology.Routers[0].InstanceID }, wantErr: "share instance ID"},
		{name: "duplicate ENI", mutate: func(topology *Topology) { topology.Routers[1].ENIID = topology.Routers[0].ENIID }, wantErr: "share ENI ID"},
		{name: "unknown router site", mutate: func(topology *Topology) { topology.Routers[0].SiteID = "missing" }, wantErr: "unknown site"},
		{name: "router VPC mismatch", mutate: func(topology *Topology) { topology.Routers[0].VPCID = "vpc-other" }, wantErr: "does not match site VPC"},
		{name: "router region mismatch", mutate: func(topology *Topology) { topology.Routers[0].Region = "eu-west-1" }, wantErr: "does not match site region"},
		{name: "router AZ mismatch", mutate: func(topology *Topology) { topology.Routers[0].AvailabilityZone = "us-east-1a" }, wantErr: "does not belong to site region"},
		{name: "router local zone", mutate: func(topology *Topology) { topology.Routers[0].AvailabilityZone = "us-west-2-lax-1a" }, wantErr: "does not belong to site region"},
		{name: "router AZ extra suffix", mutate: func(topology *Topology) { topology.Routers[0].AvailabilityZone = "us-west-2aa" }, wantErr: "does not belong to site region"},
		{name: "router AZ uppercase suffix", mutate: func(topology *Topology) { topology.Routers[0].AvailabilityZone = "us-west-2A" }, wantErr: "does not belong to site region"},
		{name: "insufficient site routers", mutate: func(topology *Topology) { topology.Routers = append(topology.Routers[:1], topology.Routers[2:]...) }, wantErr: "requires at least two routers"},
		{name: "routers not AZ spread", mutate: func(topology *Topology) { topology.Routers[1].AvailabilityZone = topology.Routers[0].AvailabilityZone }, wantErr: "span at least two"},
		{name: "duplicate domain ID", mutate: func(topology *Topology) { topology.Domains[1].ID = topology.Domains[0].ID }, wantErr: "duplicate domain ID"},
		{name: "unknown domain site", mutate: func(topology *Topology) { topology.Domains[0].SiteID = "missing" }, wantErr: "references unknown site"},
		{name: "source outside site", mutate: func(topology *Topology) { topology.Domains[0].SourcePrefix = "10.1.0.0/24" }, wantErr: "not a local prefix"},
		{name: "duplicate source authority", mutate: func(topology *Topology) { topology.Domains[1].SourcePrefix = topology.Domains[0].SourcePrefix }, wantErr: "share source prefix"},
		{name: "local prefix without domain", mutate: func(topology *Topology) {
			topology.Domains = append(topology.Domains[:1], topology.Domains[2:]...)
		}, wantErr: "has no domain"},
		{name: "shared route table", mutate: func(topology *Topology) { topology.Domains[1].RouteTableID = topology.Domains[0].RouteTableID }, wantErr: "share route table"},
		{name: "missing GWLBE subnet", mutate: func(topology *Topology) { topology.Domains[0].GWLBESubnetID = "" }, wantErr: "GWLBE subnet ID"},
		{name: "shared GWLBE subnet", mutate: func(topology *Topology) { topology.Domains[1].GWLBESubnetID = topology.Domains[0].GWLBESubnetID }, wantErr: "share GWLBE subnet"},
		{name: "missing route table association", mutate: func(topology *Topology) { topology.Domains[0].RouteTableAssociationID = "" }, wantErr: "route table association ID"},
		{name: "shared route table association", mutate: func(topology *Topology) {
			topology.Domains[1].RouteTableAssociationID = topology.Domains[0].RouteTableAssociationID
		}, wantErr: "share route table association"},
		{name: "unknown remote prefix", mutate: func(topology *Topology) { topology.Domains[0].RemotePrefixes[0] = "10.1.0.0/25" }, wantErr: "does not exactly match"},
		{name: "local prefix used as remote", mutate: func(topology *Topology) { topology.Domains[0].RemotePrefixes[0] = "10.0.1.0/24" }, wantErr: "belongs to its local site"},
		{name: "duplicate remote prefix", mutate: func(topology *Topology) {
			topology.Domains[0].RemotePrefixes[1] = topology.Domains[0].RemotePrefixes[0]
		}, wantErr: "duplicate remote prefix"},
		{name: "missing other-site prefix", mutate: func(topology *Topology) {
			topology.Domains[0].RemotePrefixes = topology.Domains[0].RemotePrefixes[:1]
		}, wantErr: "does not manage other-site prefix"},
		{name: "unknown preferred owner", mutate: func(topology *Topology) { topology.Domains[0].PreferredOwner = "missing" }, wantErr: "not a configured router"},
		{name: "cross-site preferred owner", mutate: func(topology *Topology) { topology.Domains[0].PreferredOwner = "east-a" }, wantErr: "not a member of site"},
		{name: "missing tailnet name", mutate: func(topology *Topology) { topology.Tailnet.Name = "" }, wantErr: "tailnet name"},
		{name: "invalid control URL", mutate: func(topology *Topology) { topology.Tailnet.ControlURL = "http://control.example.com" }, wantErr: "absolute HTTPS"},
		{name: "relative state base directory", mutate: func(topology *Topology) { topology.Tailnet.StateBaseDir = "state" }, wantErr: "absolute clean path"},
		{name: "noncanonical state base directory", mutate: func(topology *Topology) { topology.Tailnet.StateBaseDir = "/var/lib/../state" }, wantErr: "absolute clean path"},
		{name: "invalid tsnet auth environment", mutate: func(topology *Topology) { topology.Tailnet.TSNetAuthKeyEnv = "tailscale_auth_key" }, wantErr: "uppercase environment variable"},
		{name: "invalid Admin API environment", mutate: func(topology *Topology) { topology.Tailnet.AdminAPIKeyEnv = "tailscale_admin_key" }, wantErr: "uppercase environment variable"},
		{name: "shared secret environment", mutate: func(topology *Topology) { topology.Tailnet.AdminAPIKeyEnv = topology.Tailnet.TSNetAuthKeyEnv }, wantErr: "different environment variables"},
		{name: "auth key instead of environment", mutate: func(topology *Topology) { topology.Tailnet.TSNetAuthKeyEnv = "ts" + "key-auth-secret" }, wantErr: "environment indirection"},
		{name: "secret in another field", mutate: func(topology *Topology) { topology.DeploymentID = "deployment-ts" + "key-auth-secret" }, wantErr: "contains a secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topology := validTopology()
			test.mutate(&topology)
			err := topology.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
			if test.name == "secret in another field" && strings.Contains(err.Error(), "ts"+"key-auth-secret") {
				t.Fatalf("Validate() leaked secret: %v", err)
			}
		})
	}

	var nilTopology *Topology
	if err := nilTopology.Validate(); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil topology error = %v", err)
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Policy)
		wantErr string
	}{
		{name: "valid", mutate: func(*Policy) {}},
		{name: "too few replicas", mutate: func(policy *Policy) { policy.ReplicaCount = 2 }, wantErr: "replica count"},
		{name: "too many replicas", mutate: func(policy *Policy) { policy.ReplicaCount = MaxReplicaCount + 1 }, wantErr: "replica count"},
		{name: "quorum exceeds replicas", mutate: func(policy *Policy) { policy.ObservationQuorum = 4 }, wantErr: "cannot exceed"},
		{name: "quorum is not majority", mutate: func(policy *Policy) { policy.ObservationQuorum = 1 }, wantErr: "strict majority"},
		{name: "duration below bound", mutate: func(policy *Policy) { policy.Cooldown = 0 }, wantErr: "cooldown must be between"},
		{name: "duration above bound", mutate: func(policy *Policy) { policy.Cooldown = Duration(MaxPolicyDuration + time.Second) }, wantErr: "cooldown must be between"},
		{name: "freshness too short", mutate: func(policy *Policy) { policy.ObservationFreshness = Duration(3 * time.Second) }, wantErr: "two observation intervals"},
		{name: "failover shorter than sample", mutate: func(policy *Policy) { policy.FailoverStability = Duration(time.Second) }, wantErr: "shorter than the observation interval"},
		{name: "failback not longer", mutate: func(policy *Policy) { policy.FailbackStability = policy.FailoverStability }, wantErr: "longer than failover"},
		{name: "renewal after expiry", mutate: func(policy *Policy) { policy.LeaseRenewInterval = policy.LeaseDuration }, wantErr: "shorter than lease duration"},
		{name: "danger misses deadline", mutate: func(policy *Policy) { policy.LeaseDangerWindow = Duration(20 * time.Second) }, wantErr: "cover the API and route convergence"},
		{name: "renewal enters danger window", mutate: func(policy *Policy) { policy.LeaseDuration = Duration(40 * time.Second) }, wantErr: "before the lease danger window"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			err := policy.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestCanonicalHashIsDeterministic(t *testing.T) {
	topology := validTopology()
	original := cloneTopology(t, topology)
	want, err := topology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 64 {
		t.Fatalf("hash length = %d", len(want))
	}
	if _, err := hex.DecodeString(want); err != nil {
		t.Fatalf("hash is not hexadecimal: %v", err)
	}
	if !reflect.DeepEqual(topology, original) {
		t.Fatal("Hash mutated topology")
	}

	reordered := cloneTopology(t, topology)
	slices.Reverse(reordered.ControllerIDs)
	slices.Reverse(reordered.Sites)
	slices.Reverse(reordered.Routers)
	slices.Reverse(reordered.Domains)
	for index := range reordered.Sites {
		slices.Reverse(reordered.Sites[index].LocalPrefixes)
	}
	for index := range reordered.Domains {
		slices.Reverse(reordered.Domains[index].RemotePrefixes)
	}
	got, err := reordered.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("reordered hash = %s, want %s", got, want)
	}

	semanticDuration := cloneTopology(t, topology)
	raw := strings.Replace(string(validTopologyJSON(t)), `"observation_interval":"2s"`, `"observation_interval":"2000ms"`, 1)
	parsed, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err = parsed.Hash()
	if err != nil {
		t.Fatal(err)
	}
	semanticWant, err := semanticDuration.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if got != semanticWant {
		t.Fatalf("equivalent duration hash = %s, want %s", got, semanticWant)
	}

	changed := cloneTopology(t, topology)
	changed.DeploymentID = "deployment-b"
	got, err = changed.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if got == want {
		t.Fatal("authority change did not change hash")
	}

	for name, mutate := range map[string]func(*Topology){
		"GWLBE subnet": func(topology *Topology) { topology.Domains[0].GWLBESubnetID = "subnet-gwlbe-west-c" },
		"route table association": func(topology *Topology) {
			topology.Domains[0].RouteTableAssociationID = "rtbassoc-gwlbe-west-c"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTopology(t, topology)
			mutate(&changed)
			got, err := changed.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s authority change did not change hash", name)
			}
		})
	}
}

func TestCanonicalHashIncludesControllerAndTailnetConfiguration(t *testing.T) {
	baselineTopology := validTopology()
	baseline, err := baselineTopology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Topology)
	}{
		{name: "controller identity", mutate: func(topology *Topology) { topology.ControllerIDs[0] = "controller-d" }},
		{name: "tailnet name", mutate: func(topology *Topology) { topology.Tailnet.Name = "other.example.com" }},
		{name: "control URL", mutate: func(topology *Topology) { topology.Tailnet.ControlURL = "https://other-control.example.com" }},
		{name: "tsnet auth environment", mutate: func(topology *Topology) { topology.Tailnet.TSNetAuthKeyEnv = "OTHER_TS_AUTH_KEY" }},
		{name: "Admin API environment", mutate: func(topology *Topology) { topology.Tailnet.AdminAPIKeyEnv = "OTHER_TS_ADMIN_API_KEY" }},
		{name: "state base directory", mutate: func(topology *Topology) { topology.Tailnet.StateBaseDir = "/srv/envelope-controller" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topology := cloneTopology(t, baselineTopology)
			test.mutate(&topology)
			got, err := topology.Hash()
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			if got == baseline {
				t.Fatal("configuration change did not change hash")
			}
		})
	}
}

func TestHashIgnoresJSONFieldOrder(t *testing.T) {
	topology := validTopology()
	baseline, err := topology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	policy := topology.Policy
	policyJSON := fmt.Sprintf(`{
        "route_convergence_timeout": %q,
        "api_timeout": %q,
        "lease_danger_window": %q,
        "lease_renew_interval": %q,
        "lease_duration": %q,
        "cooldown": %q,
        "failback_stability": %q,
        "failover_stability": %q,
        "observation_freshness": %q,
        "observation_interval": %q,
        "observation_quorum": %d,
        "replica_count": %d
    }`, policy.RouteConvergenceTimeout, policy.APITimeout, policy.LeaseDangerWindow,
		policy.LeaseRenewInterval, policy.LeaseDuration, policy.Cooldown,
		policy.FailbackStability, policy.FailoverStability, policy.ObservationFreshness,
		policy.ObservationInterval, policy.ObservationQuorum, policy.ReplicaCount)
	sites, err := json.Marshal(topology.Sites)
	if err != nil {
		t.Fatal(err)
	}
	routers, err := json.Marshal(topology.Routers)
	if err != nil {
		t.Fatal(err)
	}
	domains, err := json.Marshal(topology.Domains)
	if err != nil {
		t.Fatal(err)
	}
	controllerIDs, err := json.Marshal(topology.ControllerIDs)
	if err != nil {
		t.Fatal(err)
	}
	reorderedJSON := fmt.Sprintf(`{
        "domains": %s,
        "routers": %s,
        "sites": %s,
        "tailnet": {
            "state_base_dir": %q,
            "admin_api_key_env": %q,
            "tsnet_auth_key_env": %q,
            "control_url": %q,
            "name": %q
        },
        "dynamodb": {"region": %q, "table": %q},
        "policy": %s,
        "controller_ids": %s,
        "deployment_id": %q,
        "schema_version": %d
	}`, domains, routers, sites, topology.Tailnet.StateBaseDir, topology.Tailnet.AdminAPIKeyEnv,
		topology.Tailnet.TSNetAuthKeyEnv, topology.Tailnet.ControlURL, topology.Tailnet.Name,
		topology.DynamoDB.Region, topology.DynamoDB.Table, policyJSON,
		controllerIDs, topology.DeploymentID, topology.SchemaVersion)
	reordered, err := Parse(strings.NewReader(reorderedJSON))
	if err != nil {
		t.Fatal(err)
	}
	got, err := reordered.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if got != baseline {
		t.Fatalf("field-reordered hash = %s, want %s", got, baseline)
	}
}

func TestDomainAuthority(t *testing.T) {
	topology := validTopology()
	authority, err := topology.DomainAuthority("west-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Validate(); err != nil {
		t.Fatalf("authority validation: %v", err)
	}
	if authority.PreferredOwner != "node-west-a" {
		t.Fatalf("preferred stable node = %q", authority.PreferredOwner)
	}
	if authority.GWLBESubnetID != "subnet-gwlbe-west-a" || authority.RouteTableAssociationID != "rtbassoc-gwlbe-west-a" || authority.VPCID != "vpc-west" {
		t.Fatalf("GWLBE association authority = subnet %q association %q VPC %q", authority.GWLBESubnetID, authority.RouteTableAssociationID, authority.VPCID)
	}
	if len(authority.Owners) != 2 || authority.Owners[0].RouterID != "west-a" || authority.Owners[1].RouterID != "west-b" {
		t.Fatalf("owners = %#v", authority.Owners)
	}
	if !slices.IsSorted(authority.RemotePrefixes) {
		t.Fatalf("remote prefixes are not sorted: %v", authority.RemotePrefixes)
	}
	hash, err := topology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if authority.TopologyHash != hash {
		t.Fatalf("authority hash = %q, want %q", authority.TopologyHash, hash)
	}
	if _, err := topology.DomainAuthority("missing"); err == nil || !strings.Contains(err.Error(), "unknown domain") {
		t.Fatalf("unknown domain error = %v", err)
	}
}

func TestTailnetConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TailnetConfig)
		wantErr string
	}{
		{name: "valid", mutate: func(*TailnetConfig) {}},
		{name: "default control URL", mutate: func(config *TailnetConfig) { config.ControlURL = "" }},
		{name: "missing name", mutate: func(config *TailnetConfig) { config.Name = "" }, wantErr: "tailnet name"},
		{name: "HTTP control URL", mutate: func(config *TailnetConfig) { config.ControlURL = "http://control.example.com" }, wantErr: "absolute HTTPS"},
		{name: "relative control URL", mutate: func(config *TailnetConfig) { config.ControlURL = "control.example.com" }, wantErr: "absolute HTTPS"},
		{name: "control URL credentials", mutate: func(config *TailnetConfig) { config.ControlURL = "https://user@control.example.com" }, wantErr: "without credentials"},
		{name: "control URL query", mutate: func(config *TailnetConfig) { config.ControlURL = "https://control.example.com?key=value" }, wantErr: "query"},
		{name: "control URL fragment", mutate: func(config *TailnetConfig) { config.ControlURL = "https://control.example.com#fragment" }, wantErr: "fragment"},
		{name: "missing tsnet environment", mutate: func(config *TailnetConfig) { config.TSNetAuthKeyEnv = "" }, wantErr: "tsnet auth key"},
		{name: "missing Admin environment", mutate: func(config *TailnetConfig) { config.AdminAPIKeyEnv = "" }, wantErr: "Admin API key"},
		{name: "shared environments", mutate: func(config *TailnetConfig) { config.AdminAPIKeyEnv = config.TSNetAuthKeyEnv }, wantErr: "different environment"},
		{name: "relative state base", mutate: func(config *TailnetConfig) { config.StateBaseDir = "state" }, wantErr: "absolute clean path"},
		{name: "unclean state base", mutate: func(config *TailnetConfig) { config.StateBaseDir = "/var/lib/controller/../state" }, wantErr: "absolute clean path"},
		{name: "literal secret", mutate: func(config *TailnetConfig) { config.AdminAPIKeyEnv = "ts" + "key-api-secret" }, wantErr: "environment indirection"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validTopology().Tailnet
			test.mutate(&config)
			err := config.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
			if test.name == "literal secret" && strings.Contains(err.Error(), "ts"+"key-api-secret") {
				t.Fatalf("Validate() leaked secret: %v", err)
			}
		})
	}
}

func TestTailnetSecretIndirection(t *testing.T) {
	config := validTopology().Tailnet
	tsnetSecret := "fixture-tsnet-auth-not-logged"
	adminSecret := "fixture-admin-api-not-logged"
	lookup := func(name string) (string, bool) {
		switch name {
		case config.TSNetAuthKeyEnv:
			return tsnetSecret, true
		case config.AdminAPIKeyEnv:
			return adminSecret, true
		default:
			return "", false
		}
	}
	for name, resolve := range map[string]func(func(string) (string, bool)) (string, error){
		"tsnet":      config.ResolveTSNetAuthKey,
		"auth alias": config.ResolveAuthKey,
		"Admin API":  config.ResolveAdminAPIKey,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolve(lookup)
			if err != nil {
				t.Fatalf("resolve secret: %v", err)
			}
			want := tsnetSecret
			if name == "Admin API" {
				want = adminSecret
			}
			if got != want {
				t.Fatalf("secret = %q, want expected value", got)
			}
		})
	}

	type resolverFunc func(TailnetConfig, func(string) (string, bool)) (string, error)
	resolvers := []struct {
		name       string
		resolve    resolverFunc
		setEnvName func(*TailnetConfig, string)
	}{
		{
			name: "tsnet",
			resolve: func(config TailnetConfig, lookup func(string) (string, bool)) (string, error) {
				return config.ResolveTSNetAuthKey(lookup)
			},
			setEnvName: func(config *TailnetConfig, name string) { config.TSNetAuthKeyEnv = name },
		},
		{
			name: "Admin API",
			resolve: func(config TailnetConfig, lookup func(string) (string, bool)) (string, error) {
				return config.ResolveAdminAPIKey(lookup)
			},
			setEnvName: func(config *TailnetConfig, name string) { config.AdminAPIKeyEnv = name },
		},
	}
	secretValue := "ts" + "key-auth-must-not-leak"
	secretName := "AK" + "IA1234567890123456"
	for _, resolver := range resolvers {
		for _, test := range []struct {
			name    string
			prepare func(*TailnetConfig) func(string) (string, bool)
		}{
			{name: "nil lookup", prepare: func(*TailnetConfig) func(string) (string, bool) { return nil }},
			{name: "missing", prepare: func(*TailnetConfig) func(string) (string, bool) {
				return func(string) (string, bool) { return "", false }
			}},
			{name: "empty", prepare: func(*TailnetConfig) func(string) (string, bool) {
				return func(string) (string, bool) { return "  ", true }
			}},
			{name: "secret environment name", prepare: func(config *TailnetConfig) func(string) (string, bool) {
				resolver.setEnvName(config, secretName)
				return func(string) (string, bool) { return secretValue, true }
			}},
			{name: "secret with whitespace", prepare: func(*TailnetConfig) func(string) (string, bool) {
				return func(string) (string, bool) { return "\n" + secretValue, true }
			}},
		} {
			t.Run(resolver.name+"/"+test.name, func(t *testing.T) {
				config := validTopology().Tailnet
				lookup := test.prepare(&config)
				_, err := resolver.resolve(config, lookup)
				if err == nil {
					t.Fatal("secret resolver unexpectedly succeeded")
				}
				if strings.Contains(err.Error(), secretValue) || strings.Contains(err.Error(), secretName) {
					t.Fatalf("resolver error leaked secret: %v", err)
				}
			})
		}
	}
}

func TestTailnetStateDirForController(t *testing.T) {
	config := validTopology().Tailnet
	got, err := config.StateDirForController("controller-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/var/lib/envelope-controller/controller-a"; got != want {
		t.Fatalf("state directory = %q, want %q", got, want)
	}
	for _, controllerID := range []string{"", ".", "..", "../controller-a", "controller/a"} {
		if _, err := config.StateDirForController(controllerID); err == nil {
			t.Fatalf("controller ID %q unexpectedly produced a state directory", controllerID)
		}
	}
	config.StateBaseDir = "relative"
	if _, err := config.StateDirForController("controller-a"); err == nil || !strings.Contains(err.Error(), "state base") {
		t.Fatalf("invalid base error = %v", err)
	}
}

func TestProcessConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  ProcessConfig
		wantErr string
	}{
		{name: "valid", config: ProcessConfig{ControllerID: "controller-a", TopologyPath: "/etc/envelope/topology.json"}},
		{name: "missing controller", config: ProcessConfig{TopologyPath: "topology.json"}, wantErr: "controller ID"},
		{name: "missing topology", config: ProcessConfig{ControllerID: "controller-a"}, wantErr: "topology path"},
		{name: "whitespace topology", config: ProcessConfig{ControllerID: "controller-a", TopologyPath: " topology.json"}, wantErr: "whitespace"},
		{name: "unsafe controller", config: ProcessConfig{ControllerID: "../controller-a", TopologyPath: "topology.json"}, wantErr: "contain only"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestProcessConfigValidationForTopology(t *testing.T) {
	topology := validTopology()
	process := ProcessConfig{ControllerID: "controller-a", TopologyPath: "/etc/envelope/topology.json"}
	if err := process.ValidateForTopology(&topology); err != nil {
		t.Fatalf("ValidateForTopology() error = %v", err)
	}
	if !topology.HasControllerID("controller-a") || topology.HasControllerID("controller-unknown") {
		t.Fatal("HasControllerID returned an incorrect result")
	}
	var nilTopology *Topology
	if nilTopology.HasControllerID("controller-a") {
		t.Fatal("nil topology allowed a controller")
	}

	tests := []struct {
		name     string
		process  ProcessConfig
		topology *Topology
		wantErr  string
	}{
		{name: "unknown controller", process: ProcessConfig{ControllerID: "controller-x", TopologyPath: "topology.json"}, topology: &topology, wantErr: "not allowed"},
		{name: "invalid process", process: ProcessConfig{ControllerID: "../controller", TopologyPath: "topology.json"}, topology: &topology, wantErr: "contain only"},
		{name: "nil topology", process: process, wantErr: "topology is nil"},
		{name: "invalid topology", process: process, topology: func() *Topology {
			invalid := cloneTopology(t, topology)
			invalid.ControllerIDs = invalid.ControllerIDs[:2]
			return &invalid
		}(), wantErr: "does not match policy replica count"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.process.ValidateForTopology(test.topology)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateForTopology() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestStandardAvailabilityZoneValidation(t *testing.T) {
	tests := []struct {
		region string
		zone   string
		valid  bool
	}{
		{region: "us-west-2", zone: "us-west-2a", valid: true},
		{region: "us-gov-west-1", zone: "us-gov-west-1f", valid: true},
		{region: "us-iso-east-1", zone: "us-iso-east-1b", valid: true},
		{region: "us-west-2", zone: "us-east-1a"},
		{region: "us-west-2", zone: "us-west-2"},
		{region: "us-west-2", zone: "us-west-2aa"},
		{region: "us-west-2", zone: "us-west-2A"},
		{region: "us-west-2", zone: "us-west-2-lax-1a"},
		{region: "invalid", zone: "invalida"},
	}
	for _, test := range tests {
		t.Run(test.region+"/"+test.zone, func(t *testing.T) {
			if got := availabilityZoneMatchesRegion(test.zone, test.region); got != test.valid {
				t.Fatalf("availabilityZoneMatchesRegion(%q, %q) = %t, want %t", test.zone, test.region, got, test.valid)
			}
		})
	}
}

func validTopologyJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(validTopology())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneTopology(t *testing.T, topology Topology) Topology {
	t.Helper()
	data, err := json.Marshal(topology)
	if err != nil {
		t.Fatal(err)
	}
	var clone Topology
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func validPolicy() Policy {
	return Policy{
		ReplicaCount:            3,
		ObservationQuorum:       2,
		ObservationInterval:     Duration(2 * time.Second),
		ObservationFreshness:    Duration(6 * time.Second),
		FailoverStability:       Duration(10 * time.Second),
		FailbackStability:       Duration(30 * time.Second),
		Cooldown:                Duration(time.Minute),
		LeaseDuration:           Duration(50 * time.Second),
		LeaseRenewInterval:      Duration(10 * time.Second),
		LeaseDangerWindow:       Duration(30 * time.Second),
		APITimeout:              Duration(5 * time.Second),
		RouteConvergenceTimeout: Duration(20 * time.Second),
	}
}

func validTopology() Topology {
	return Topology{
		SchemaVersion: TopologySchemaVersion,
		DeploymentID:  "deployment-a",
		ControllerIDs: []string{"controller-c", "controller-a", "controller-b"},
		Policy:        validPolicy(),
		DynamoDB:      DynamoDBConfig{Table: "envelope-controller", Region: "us-west-2"},
		Tailnet: TailnetConfig{
			Name:            "example.com",
			ControlURL:      "https://control.example.com",
			TSNetAuthKeyEnv: "ENVELOPE_TS_AUTH_KEY",
			AdminAPIKeyEnv:  "ENVELOPE_TS_ADMIN_API_KEY",
			StateBaseDir:    "/var/lib/envelope-controller",
		},
		Sites: []Site{
			{ID: "west", VPCID: "vpc-west", Region: "us-west-2", LocalPrefixes: []string{"10.0.1.0/24", "10.0.0.0/24"}},
			{ID: "east", VPCID: "vpc-east", Region: "us-east-1", LocalPrefixes: []string{"10.1.1.0/24", "10.1.0.0/24"}},
		},
		Routers: []Router{
			{ID: "west-b", SiteID: "west", StableNodeID: "node-west-b", InstanceID: "i-west-b", ENIID: "eni-west-b", VPCID: "vpc-west", SubnetID: "subnet-west-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
			{ID: "west-a", SiteID: "west", StableNodeID: "node-west-a", InstanceID: "i-west-a", ENIID: "eni-west-a", VPCID: "vpc-west", SubnetID: "subnet-west-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{ID: "east-b", SiteID: "east", StableNodeID: "node-east-b", InstanceID: "i-east-b", ENIID: "eni-east-b", VPCID: "vpc-east", SubnetID: "subnet-east-b", AvailabilityZone: "us-east-1b", Region: "us-east-1"},
			{ID: "east-a", SiteID: "east", StableNodeID: "node-east-a", InstanceID: "i-east-a", ENIID: "eni-east-a", VPCID: "vpc-east", SubnetID: "subnet-east-a", AvailabilityZone: "us-east-1a", Region: "us-east-1"},
		},
		Domains: []Domain{
			{ID: "west-b", SiteID: "west", SourcePrefix: "10.0.1.0/24", RouteTableID: "rtb-west-b", GWLBESubnetID: "subnet-gwlbe-west-b", RouteTableAssociationID: "rtbassoc-gwlbe-west-b", RemotePrefixes: []string{"10.1.1.0/24", "10.1.0.0/24"}, PreferredOwner: "west-b"},
			{ID: "west-a", SiteID: "west", SourcePrefix: "10.0.0.0/24", RouteTableID: "rtb-west-a", GWLBESubnetID: "subnet-gwlbe-west-a", RouteTableAssociationID: "rtbassoc-gwlbe-west-a", RemotePrefixes: []string{"10.1.1.0/24", "10.1.0.0/24"}, PreferredOwner: "west-a"},
			{ID: "east-b", SiteID: "east", SourcePrefix: "10.1.1.0/24", RouteTableID: "rtb-east-b", GWLBESubnetID: "subnet-gwlbe-east-b", RouteTableAssociationID: "rtbassoc-gwlbe-east-b", RemotePrefixes: []string{"10.0.1.0/24", "10.0.0.0/24"}, PreferredOwner: "east-b"},
			{ID: "east-a", SiteID: "east", SourcePrefix: "10.1.0.0/24", RouteTableID: "rtb-east-a", GWLBESubnetID: "subnet-gwlbe-east-a", RouteTableAssociationID: "rtbassoc-gwlbe-east-a", RemotePrefixes: []string{"10.0.1.0/24", "10.0.0.0/24"}, PreferredOwner: "east-a"},
		},
	}
}

func validTopologyWithDomainCount(count int) Topology {
	topology := validTopology()
	westCount := (count + 1) / 2
	eastCount := count - westCount
	westPrefixes := make([]string, westCount)
	for index := range westPrefixes {
		westPrefixes[index] = fmt.Sprintf("10.0.%d.0/24", index)
	}
	eastPrefixes := make([]string, eastCount)
	for index := range eastPrefixes {
		eastPrefixes[index] = fmt.Sprintf("10.1.%d.0/24", index)
	}
	topology.Sites[0].LocalPrefixes = westPrefixes
	topology.Sites[1].LocalPrefixes = eastPrefixes
	topology.Domains = nil
	for index, prefix := range westPrefixes {
		topology.Domains = append(topology.Domains, Domain{
			ID:                      fmt.Sprintf("west-domain-%d", index),
			SiteID:                  "west",
			SourcePrefix:            prefix,
			RouteTableID:            fmt.Sprintf("rtb-west-%d", index),
			GWLBESubnetID:           fmt.Sprintf("subnet-gwlbe-west-%d", index),
			RouteTableAssociationID: fmt.Sprintf("rtbassoc-gwlbe-west-%d", index),
			RemotePrefixes:          append([]string(nil), eastPrefixes...),
			PreferredOwner:          "west-a",
		})
	}
	for index, prefix := range eastPrefixes {
		topology.Domains = append(topology.Domains, Domain{
			ID:                      fmt.Sprintf("east-domain-%d", index),
			SiteID:                  "east",
			SourcePrefix:            prefix,
			RouteTableID:            fmt.Sprintf("rtb-east-%d", index),
			GWLBESubnetID:           fmt.Sprintf("subnet-gwlbe-east-%d", index),
			RouteTableAssociationID: fmt.Sprintf("rtbassoc-gwlbe-east-%d", index),
			RemotePrefixes:          append([]string(nil), westPrefixes...),
			PreferredOwner:          "east-a",
		})
	}
	return topology
}
