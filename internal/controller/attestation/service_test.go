package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/config"
)

type serviceCollector struct {
	unsupported atomic.Bool
	fail        atomic.Bool
	calls       atomic.Int32
}

func (c *serviceCollector) Collect(context.Context) (Checks, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return Checks{}, errors.New("credential-bearing collector failure")
	}
	checks := Checks{"pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass"}
	if c.unsupported.Load() {
		checks.Firewall = "unsupported"
	}
	return checks, nil
}

func TestSignedServiceAndEnrolledTLSKey(t *testing.T) {
	topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := topology.DomainAuthority(topology.Domains[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	owner := authority.Owners[0]
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collector := &serviceCollector{}
	handler, err := NewHandler(authority, owner, private, collector, 6*time.Second, 2*time.Second, authority.TopologyHash)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := ServerTLS(private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()
	fetch, err := PinnedHTTPSFetch(server.URL+"/attestation", public)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(authority, owner, public, 6*time.Second, 2*time.Second, authority.TopologyHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), fetch); err != nil {
		t.Fatal(err)
	}
	collector.unsupported.Store(true)
	if _, err := verifier.Verify(context.Background(), fetch); !errors.Is(err, ErrRejected) {
		t.Fatal("signed unsupported check authorized eligibility")
	}
	collector.fail.Store(true)
	if _, err := verifier.Verify(context.Background(), fetch); err != ErrRejected {
		t.Fatal("collector error leaked or was accepted")
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongFetch, _ := PinnedHTTPSFetch(server.URL+"/attestation", wrong)
	before := collector.calls.Load()
	if _, err := verifier.Verify(context.Background(), wrongFetch); err != ErrRejected || collector.calls.Load() != before {
		t.Fatal("wrong enrollment key reached collector")
	}
}

func TestAttestorHTTPHasNoMutationSurface(t *testing.T) {
	topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := topology.DomainAuthority(topology.Domains[0].ID)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	collector := &serviceCollector{}
	handler, err := NewHandler(authority, authority.Owners[0], private, collector, 6*time.Second, 2*time.Second, authority.TopologyHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/attestation", "/attestation?challenge=bad", "/attestation?challenge=" + strings.Repeat("a", 64) + "&extra=1", "/attestation?challenge=" + strings.Repeat("a", 64) + "&bad=%zz", "/mutate"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusOK {
			t.Fatalf("accepted invalid request: %s", path)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/attestation?challenge="+strings.Repeat("a", 64), nil))
	if response.Code == http.StatusOK || collector.calls.Load() != 0 {
		t.Fatal("mutation request reached collector")
	}
}
