package attestation

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSFetchRejectsUntrustedEndpoints(t *testing.T) {
	for _, endpoint := range []string{"", "http://router.example/", "https://user:password@router.example/", "https://router.example/?challenge=old", "https://router.example/#fragment"} {
		if _, err := HTTPSFetch(endpoint); err != ErrRejected {
			t.Fatalf("accepted endpoint %q: %v", endpoint, err)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS endpoint received request") }))
	defer server.Close()
	fetch, err := HTTPSFetch(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := fetch(ctx, "challenge"); err != ErrRejected {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
}

func TestHTTPSFetchBoundsAndRedirects(t *testing.T) {
	for _, name := range []string{"valid", "redirect", "duplicate-signature", "bad-signature", "oversized", "unhealthy"} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Query().Get("challenge") != "fresh-challenge" {
					t.Error("challenge missing")
				}
				w.Header().Set("Envelope-Attestation-Signature", base64.StdEncoding.EncodeToString([]byte("signature")))
				switch name {
				case "redirect":
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(http.StatusFound)
					return
				case "duplicate-signature":
					w.Header().Add("Envelope-Attestation-Signature", "duplicate")
				case "bad-signature":
					w.Header().Set("Envelope-Attestation-Signature", "invalid-base64")
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", maxReportBytes+1)))
					return
				case "unhealthy":
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte("payload"))
			}))
			defer server.Close()
			// Trust only this local test CA. Production uses the ordinary system
			// roots; it never disables certificate verification.
			original := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = original }()
			fetch, err := HTTPSFetch(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			payload, signature, err := fetch(ctx, "fresh-challenge")
			if name == "valid" {
				if err != nil || string(payload) != "payload" || string(signature) != "signature" {
					t.Fatalf("fetch = %q %q %v", payload, signature, err)
				}
			} else if err != ErrRejected {
				t.Fatalf("accepted unsafe response: %v", err)
			}
			if requests.Load() != 1 {
				t.Fatalf("redirected or retried request: %d", requests.Load())
			}
		})
	}
}
