// Package attestation verifies router reports, not router-supplied identity
// claims. Key enrollment and live forwarding collection are separate boundaries.
package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

var ErrRejected = errors.New("router attestation rejected")

const maxReportBytes = 16 * 1024

// Checks must describe live observations, never expected configuration or boot
// markers. Unknown, unsupported, and failed results are all ineligible.
type Checks struct {
	Backend        string `json:"backend"`
	Advertisements string `json:"advertisements"`
	RemoteRoutes   string `json:"remote_routes"`
	LocalPolicy    string `json:"local_policy"`
	Underlay       string `json:"underlay"`
	Forwarding     string `json:"forwarding"`
	ReversePath    string `json:"reverse_path"`
	Firewall       string `json:"firewall"`
	NoNAT          string `json:"no_nat"`
	MSS            string `json:"mss"`
	Peers          string `json:"peers"`
}

func (c Checks) passed() bool {
	for _, check := range []string{c.Backend, c.Advertisements, c.RemoteRoutes,
		c.LocalPolicy, c.Underlay, c.Forwarding, c.ReversePath, c.Firewall,
		c.NoNAT, c.MSS, c.Peers} {
		if check != "pass" {
			return false
		}
	}
	return true
}

type Report struct {
	SchemaVersion     int                  `json:"schema_version"`
	DeploymentID      string               `json:"deployment_id"`
	TopologyHash      string               `json:"topology_hash"`
	ConfigurationHash string               `json:"configuration_sha256"`
	Owner             model.OwnerAuthority `json:"owner"`
	Challenge         string               `json:"challenge"`
	CapturedAt        time.Time            `json:"captured_at"`
	ExpiresAt         time.Time            `json:"expires_at"`
	Checks            Checks               `json:"checks"`
}

// Fetch receives a new unpredictable challenge. It must bound response bytes
// before allocation and honor cancellation; errors are never exposed as reports.
type Fetch func(context.Context, string) (payload, signature []byte, err error)

// Verifier's key must be enrolled independently for this exact instance and
// topology. A key or identity supplied in a response is never trusted. Enrollment
// must prevent one key from representing multiple router instances.
type Verifier struct {
	deployment    string
	topology      string
	configuration string
	owner         model.OwnerAuthority
	key           ed25519.PublicKey
	freshness     time.Duration
	timeout       time.Duration
	now           func() time.Time
}

func NewVerifier(authority model.DomainAuthority, owner model.OwnerAuthority, key ed25519.PublicKey, freshness, timeout time.Duration, configurationHash string) (*Verifier, error) {
	configured, found := authority.OwnerByStableNode(owner.StableNodeID)
	if authority.Validate() != nil || !found || configured != owner || len(key) != ed25519.PublicKeySize || !validDigest(configurationHash) ||
		freshness <= 0 || freshness > time.Minute || timeout <= 0 || timeout >= freshness {
		return nil, ErrRejected
	}
	return &Verifier{deployment: authority.DeploymentID, topology: authority.TopologyHash,
		configuration: configurationHash,
		owner:         owner, key: append(ed25519.PublicKey(nil), key...), freshness: freshness,
		timeout: timeout, now: time.Now}, nil
}

// Verify performs a fresh challenge exchange for every call, including after
// process restart. No cached report or sequence reset can satisfy a new call.
// The returned deadline must still be valid when eligibility is consumed.
func (v *Verifier) Verify(ctx context.Context, fetch Fetch) (time.Time, error) {
	if v == nil || ctx == nil || fetch == nil || ctx.Err() != nil {
		return time.Time{}, ErrRejected
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return time.Time{}, ErrRejected
	}
	challenge := hex.EncodeToString(nonce[:])
	started := v.now()
	call, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	payload, signature, err := fetch(call, challenge)
	now := v.now()
	if err != nil || call.Err() != nil || now.Before(started) || now.Sub(started) >= v.timeout ||
		len(payload) > maxReportBytes || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(v.key, append([]byte("envelope-router-attestation-v1\n"), payload...), signature) ||
		strictjson.Validate(payload, maxReportBytes) != nil {
		return time.Time{}, ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var report Report
	if decoder.Decode(&report) != nil || report.SchemaVersion != 1 || report.DeploymentID != v.deployment ||
		report.TopologyHash != v.topology || report.ConfigurationHash != v.configuration || report.Owner != v.owner || report.Challenge != challenge ||
		report.CapturedAt.IsZero() || report.CapturedAt.Before(started) || report.CapturedAt.After(now) ||
		!report.ExpiresAt.After(now) || report.ExpiresAt.Sub(report.CapturedAt) > v.freshness || !report.Checks.passed() {
		return time.Time{}, ErrRejected
	}
	return report.ExpiresAt, nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
