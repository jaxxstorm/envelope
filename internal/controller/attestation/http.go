package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPSFetch uses normal TLS server authentication in addition to the enrolled
// report signature. Redirects and environment proxies cannot redirect challenges
// to another endpoint. The detached signature is base64 in a bounded header.
func HTTPSFetch(endpoint string) (Fetch, error) {
	return httpsFetch(endpoint, nil)
}

// PinnedHTTPSFetch authenticates the TLS handshake with the independently
// enrolled Ed25519 key. This permits short-lived self-signed server certificates
// without introducing a certificate issuer or trusting keys from responses.
func PinnedHTTPSFetch(endpoint string, key ed25519.PublicKey) (Fetch, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrRejected
	}
	pin := append(ed25519.PublicKey(nil), key...)
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} // Enrollment pin verification replaces CA verification below.
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return ErrRejected
		}
		certificate := state.PeerCertificates[0]
		observed, ok := certificate.PublicKey.(ed25519.PublicKey)
		now := time.Now()
		if !ok || !bytes.Equal(observed, pin) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return ErrRejected
		}
		return nil
	}
	return httpsFetch(endpoint, configuration)
}

func httpsFetch(endpoint string, configuration *tls.Config) (Fetch, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrRejected
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if configuration != nil {
		transport.TLSClientConfig = configuration.Clone()
	}
	transport.MaxResponseHeaderBytes = 4096
	transport.DisableKeepAlives = true
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}
	return func(ctx context.Context, challenge string) ([]byte, []byte, error) {
		requestURL := *u
		requestURL.RawQuery = url.Values{"challenge": {challenge}}.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return nil, nil, ErrRejected
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, nil, ErrRejected
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || len(response.Header.Values("Envelope-Attestation-Signature")) != 1 {
			return nil, nil, ErrRejected
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(response.Header.Get("Envelope-Attestation-Signature"))
		if err != nil {
			return nil, nil, ErrRejected
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, maxReportBytes+1))
		if err != nil || len(payload) > maxReportBytes {
			return nil, nil, ErrRejected
		}
		return payload, signature, nil
	}, nil
}
