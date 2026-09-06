package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

type Collector interface {
	Collect(context.Context) (Checks, error)
}

func NewHandler(authority model.DomainAuthority, owner model.OwnerAuthority, private ed25519.PrivateKey, collector Collector, freshness, timeout time.Duration, configurationHash string) (http.Handler, error) {
	configured, ok := authority.OwnerByStableNode(owner.StableNodeID)
	if authority.Validate() != nil || !ok || configured != owner || len(private) != ed25519.PrivateKeySize || collector == nil || timeout <= 0 || timeout >= freshness || freshness > time.Minute || !validDigest(configurationHash) {
		return nil, ErrRejected
	}
	key := append(ed25519.PrivateKey(nil), private...)
	slot := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/attestation", func(w http.ResponseWriter, r *http.Request) {
		values, parseErr := url.ParseQuery(r.URL.RawQuery)
		query := values["challenge"]
		if parseErr != nil || r.Method != http.MethodGet || len(values) != 1 || len(query) != 1 || len(query[0]) != 64 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded, err := hex.DecodeString(query[0])
		if err != nil || hex.EncodeToString(decoded) != query[0] {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		captured := time.Now()
		checks, err := collector.Collect(ctx)
		if err != nil || ctx.Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		report := Report{SchemaVersion: 1, DeploymentID: authority.DeploymentID, TopologyHash: authority.TopologyHash, ConfigurationHash: configurationHash, Owner: owner, Challenge: query[0], CapturedAt: captured, ExpiresAt: captured.Add(freshness), Checks: checks}
		payload, err := json.Marshal(report)
		if err != nil || len(payload) > maxReportBytes || !report.ExpiresAt.After(time.Now()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		signature := ed25519.Sign(key, append([]byte("envelope-router-attestation-v1\n"), payload...))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Envelope-Attestation-Signature", base64.StdEncoding.EncodeToString(signature))
		_, _ = w.Write(payload)
	})
	return mux, nil
}

// ServerTLS creates a short-lived per-process certificate in memory. The enrolled public key
// authenticates the TLS handshake; no network certificate service is required.
func ServerTLS(key ed25519.PrivateKey) (*tls.Config, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrRejected
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrRejected
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, ErrRejected
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: append(ed25519.PrivateKey(nil), key...)}}}, nil
}
