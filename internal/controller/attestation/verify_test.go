package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/config"
)

func TestVerifierTrustFreshnessAndChecks(t *testing.T) {
	topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := topology.DomainAuthority(topology.Domains[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	owner := authority.Owners[0]
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"valid", func(*Report) {}},
		{"schema", func(r *Report) { r.SchemaVersion++ }},
		{"deployment", func(r *Report) { r.DeploymentID += "-other" }},
		{"topology", func(r *Report) { r.TopologyHash = strings.Repeat("f", 64) }},
		{"missing-configuration", func(r *Report) { r.ConfigurationHash = "" }},
		{"wrong-configuration", func(r *Report) { r.ConfigurationHash = strings.Repeat("f", 64) }},
		{"instance", func(r *Report) { r.Owner.InstanceID += "-other" }},
		{"eni", func(r *Report) { r.Owner.ENIID += "-other" }},
		{"stable-node", func(r *Report) { r.Owner.StableNodeID += "-other" }},
		{"router", func(r *Report) { r.Owner.RouterID += "-other" }},
		{"region", func(r *Report) { r.Owner.Region += "-other" }},
		{"vpc", func(r *Report) { r.Owner.VPCID += "-other" }},
		{"subnet", func(r *Report) { r.Owner.SubnetID += "-other" }},
		{"az", func(r *Report) { r.Owner.AvailabilityZone += "-other" }},
		{"challenge", func(r *Report) { r.Challenge = strings.Repeat("0", 64) }},
		{"old-capture", func(r *Report) { r.CapturedAt = now.Add(-time.Nanosecond) }},
		{"future-capture", func(r *Report) { r.CapturedAt = now.Add(time.Nanosecond) }},
		{"expired", func(r *Report) { r.ExpiresAt = now }},
		{"excess-lifetime", func(r *Report) { r.ExpiresAt = now.Add(time.Minute) }},
		{"unsupported-firewall", func(r *Report) { r.Checks.Firewall = "unsupported" }},
		{"missing-forwarding", func(r *Report) { r.Checks.Forwarding = "" }},
		{"failed-no-nat", func(r *Report) { r.Checks.NoNAT = "fail" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, err := NewVerifier(authority, owner, key, 10*time.Second, time.Second, authority.TopologyHash)
			if err != nil {
				t.Fatal(err)
			}
			v.now = func() time.Time { return now }
			deadline, err := v.Verify(context.Background(), func(_ context.Context, challenge string) ([]byte, []byte, error) {
				r := Report{SchemaVersion: 1, DeploymentID: authority.DeploymentID, TopologyHash: authority.TopologyHash,
					ConfigurationHash: authority.TopologyHash,
					Owner:             owner, Challenge: challenge, CapturedAt: now, ExpiresAt: now.Add(5 * time.Second),
					Checks: Checks{"pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass"}}
				test.mutate(&r)
				payload, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				return payload, ed25519.Sign(private, append([]byte("envelope-router-attestation-v1\n"), payload...)), nil
			})
			if test.name == "valid" {
				if err != nil || !deadline.Equal(now.Add(5*time.Second)) {
					t.Fatalf("valid report: %v %v", deadline, err)
				}
			} else if !errors.Is(err, ErrRejected) || !deadline.IsZero() {
				t.Fatalf("accepted invalid report: %v %v", deadline, err)
			}
		})
	}

	v, err := NewVerifier(authority, owner, key, 10*time.Second, time.Second, authority.TopologyHash)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	var payload, signature []byte
	fetch := func(_ context.Context, challenge string) ([]byte, []byte, error) {
		r := Report{1, authority.DeploymentID, authority.TopologyHash, authority.TopologyHash, owner, challenge, now, now.Add(5 * time.Second),
			Checks{"pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass"}}
		payload, _ = json.Marshal(r)
		signature = ed25519.Sign(private, append([]byte("envelope-router-attestation-v1\n"), payload...))
		return payload, signature, nil
	}
	if _, err := v.Verify(context.Background(), fetch); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), func(context.Context, string) ([]byte, []byte, error) { return payload, signature, nil }); !errors.Is(err, ErrRejected) {
		t.Fatal("accepted replay")
	}
	restarted, _ := NewVerifier(authority, owner, key, 10*time.Second, time.Second, authority.TopologyHash)
	restarted.now = v.now
	if _, err := restarted.Verify(context.Background(), func(context.Context, string) ([]byte, []byte, error) { return payload, signature, nil }); !errors.Is(err, ErrRejected) {
		t.Fatal("accepted replay after verifier restart")
	}
	for _, name := range []string{"wrong-key", "tampered", "unknown-field", "duplicate-field", "oversized", "timeout", "fetch-error"} {
		t.Run(name, func(t *testing.T) {
			v.now = func() time.Time { return now }
			_, err := v.Verify(context.Background(), func(ctx context.Context, challenge string) ([]byte, []byte, error) {
				p, s, _ := fetch(ctx, challenge)
				switch name {
				case "wrong-key":
					_, wrong, _ := ed25519.GenerateKey(rand.Reader)
					s = ed25519.Sign(wrong, append([]byte("envelope-router-attestation-v1\n"), p...))
				case "tampered":
					p[0] = '['
				case "unknown-field", "duplicate-field":
					field := `,"unknown":true}`
					if name == "duplicate-field" {
						field = `,"schema_version":1}`
					}
					p = append(p[:len(p)-1], []byte(field)...)
					s = ed25519.Sign(private, append([]byte("envelope-router-attestation-v1\n"), p...))
				case "oversized":
					p = make([]byte, maxReportBytes+1)
				case "timeout":
					v.now = func() time.Time { return now.Add(time.Second) }
				case "fetch-error":
					return nil, nil, errors.New("secret-bearing transport error")
				}
				return p, s, nil
			})
			if err != ErrRejected {
				t.Fatalf("unredacted or accepted result: %v", err)
			}
		})
	}
}
