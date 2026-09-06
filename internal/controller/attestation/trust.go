package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

const RuntimeTrustPath = "/etc/envelope/controller-router-trust.json"

// Trust is an immutable, independently supplied public-key authority. Reports
// never enroll keys. A key may represent only one exact configured router.
type Trust struct {
	authorities        map[string]model.DomainAuthority
	keys               map[string]ed25519.PublicKey
	configurations     map[string]string
	fetches            map[string]Fetch
	freshness, timeout time.Duration
}

func LoadTrust(path string, topology *config.Topology) (*Trust, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrRejected
	}
	defer file.Close()
	return ParseTrust(file, topology)
}

func ParseTrust(reader io.Reader, topology *config.Topology) (*Trust, error) {
	if reader == nil || topology == nil || topology.Validate() != nil {
		return nil, ErrRejected
	}
	payload, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	if err != nil || strictjson.Validate(payload, 64*1024) != nil {
		return nil, ErrRejected
	}
	var document struct {
		SchemaVersion int    `json:"schema_version"`
		DeploymentID  string `json:"deployment_id"`
		TopologyHash  string `json:"topology_hash"`
		Routers       []struct {
			RouterID          string `json:"router_id"`
			PublicKey         string `json:"ed25519_public_key"`
			URL               string `json:"url"`
			ConfigurationHash string `json:"configuration_sha256"`
		} `json:"routers"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil {
		return nil, ErrRejected
	}
	hash, _ := topology.Hash()
	if document.SchemaVersion != 1 || document.DeploymentID != topology.DeploymentID || document.TopologyHash != hash || len(document.Routers) != len(topology.Routers) {
		return nil, ErrRejected
	}
	trust := &Trust{authorities: map[string]model.DomainAuthority{}, keys: map[string]ed25519.PublicKey{}, fetches: map[string]Fetch{}, freshness: topology.Policy.ObservationFreshness.Duration(), timeout: topology.Policy.APITimeout.Duration()}
	trust.configurations = map[string]string{}
	if trust.freshness > time.Minute || trust.timeout <= 0 || trust.timeout >= trust.freshness {
		return nil, ErrRejected
	}
	usedKeys, usedURLs := map[string]bool{}, map[string]bool{}
	for _, router := range document.Routers {
		key, err := hex.DecodeString(router.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != router.PublicKey || trust.keys[router.RouterID] != nil || usedKeys[router.PublicKey] || usedURLs[router.URL] || !validDigest(router.ConfigurationHash) {
			return nil, ErrRejected
		}
		fetch, err := PinnedHTTPSFetch(router.URL, key)
		if err != nil {
			return nil, err
		}
		trust.keys[router.RouterID], trust.fetches[router.RouterID] = key, fetch
		trust.configurations[router.RouterID] = router.ConfigurationHash
		usedKeys[router.PublicKey], usedURLs[router.URL] = true, true
	}
	for _, router := range topology.Routers {
		if trust.keys[router.ID] == nil {
			return nil, ErrRejected
		}
	}
	for _, domain := range topology.Domains {
		authority, err := topology.DomainAuthority(domain.ID)
		if err != nil {
			return nil, ErrRejected
		}
		trust.authorities[domain.ID] = authority
	}
	return trust, nil
}

func (t *Trust) Check(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (time.Time, error) {
	if t == nil || !reflect.DeepEqual(t.authorities[authority.DomainID], authority) {
		return time.Time{}, ErrRejected
	}
	verifier, err := NewVerifier(authority, owner, t.keys[owner.RouterID], t.freshness, t.timeout, t.configurations[owner.RouterID])
	if err != nil {
		return time.Time{}, err
	}
	return verifier.Verify(ctx, t.fetches[owner.RouterID])
}
