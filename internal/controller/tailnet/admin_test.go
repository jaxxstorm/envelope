package tailnet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminHTTPClientListsAllDeviceRouteFieldsReadOnly(t *testing.T) {
	apiKey := "fixture-admin-http-secret"
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", request.Method)
		}
		if request.URL.Path != "/api/v2/tailnet/user@example.com/devices" || request.URL.Query().Get("fields") != "all" {
			t.Errorf("request URL = %q", request.URL.String())
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != apiKey || password != "" {
			t.Errorf("BasicAuth() = %q, %q, %t", username, password, ok)
		}
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != "envelope-controller" {
			t.Errorf("headers = %#v", request.Header)
		}
		if request.Body != nil {
			body, err := io.ReadAll(request.Body)
			if err != nil || len(body) != 0 {
				t.Errorf("request body = %q, %v", body, err)
			}
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{
			"devices": [{
				"id": "device-a",
				"nodeId": "node-a",
				"hostname": "router-a",
				"nodeKey": "redacted-node-key",
				"machineKey": "redacted-machine-key",
				"advertisedRoutes": ["10.0.1.0/24", "10.0.0.0/24"],
				"enabledRoutes": ["10.0.0.0/24", "10.0.1.0/24"]
			}]
		}`)
	}))
	defer server.Close()

	client, err := newAdminHTTPClient(server.URL, "user@example.com", apiKey, server.Client())
	if err != nil {
		t.Fatalf("newAdminHTTPClient() error = %v", err)
	}
	devices, err := client.devices(context.Background())
	if err != nil {
		t.Fatalf("devices() error = %v", err)
	}
	if requestCount.Load() != 1 || len(devices) != 1 {
		t.Fatalf("request/device count = %d/%d", requestCount.Load(), len(devices))
	}
	device := devices[0]
	if device.nodeID != "node-a" || !device.advertisedPresent || !device.enabledPresent {
		t.Fatalf("device identity/presence = %#v", device)
	}
	if strings.Join(device.advertisedRoutes, ",") != "10.0.1.0/24,10.0.0.0/24" || strings.Join(device.enabledRoutes, ",") != "10.0.0.0/24,10.0.1.0/24" {
		t.Fatalf("device routes = %v/%v", device.advertisedRoutes, device.enabledRoutes)
	}
	formatted := strings.Join(append(append([]string{device.nodeID}, device.advertisedRoutes...), device.enabledRoutes...), " ")
	if strings.Contains(formatted, apiKey) || strings.Contains(formatted, "redacted-node-key") || strings.Contains(formatted, "redacted-machine-key") {
		t.Fatal("devices() retained a credential-bearing API field")
	}
}

func TestObserverUsesHTTPAdminAdapterWithFakeLocalClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"devices":[
			{"nodeId":"node-a","advertisedRoutes":["10.0.0.0/24","10.0.1.0/24"],"enabledRoutes":["10.0.1.0/24","10.0.0.0/24"]},
			{"nodeId":"node-b","advertisedRoutes":["10.0.1.0/24","10.0.0.0/24"],"enabledRoutes":["10.0.0.0/24","10.0.1.0/24"]}
		]}`)
	}))
	defer server.Close()
	admin, err := newAdminHTTPClient(server.URL, "example.com", "fixture-api-key", server.Client())
	if err != nil {
		t.Fatalf("newAdminHTTPClient() error = %v", err)
	}
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: validStatus()}}
	observer, err := newStartedObserver(context.Background(), testPlan(t), testOptions(), node, admin, func() time.Time { return observerTestTime })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()
	observation, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if err := observation.Validate(); err != nil || len(observation.Domains) != 2 {
		t.Fatalf("observation = %#v, validation error %v", observation, err)
	}
}

func TestAdminHTTPClientRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid JSON", body: `{"devices":`},
		{name: "missing devices", body: `{}`},
		{name: "null devices", body: `{"devices":null}`},
		{name: "null device", body: `{"devices":[null]}`},
		{name: "missing node ID", body: `{"devices":[{"advertisedRoutes":[],"enabledRoutes":[]}]}`},
		{name: "trailing JSON", body: `{"devices":[]} {}`},
		{name: "oversized", body: strings.Repeat(" ", maxAdminResponseSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(response, test.body)
			}))
			defer server.Close()
			client, err := newAdminHTTPClient(server.URL, "example.com", "fixture-api-key", server.Client())
			if err != nil {
				t.Fatalf("newAdminHTTPClient() error = %v", err)
			}
			devices, err := client.devices(context.Background())
			if devices != nil {
				t.Fatalf("devices() = %#v, want nil", devices)
			}
			requireErrorIs(t, err, ErrMalformedAdminResponse)
		})
	}
}

func TestAdminHTTPClientRetainsDeviceIdentityForRouteShapeFailures(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		advertisedPresent bool
		enabledPresent    bool
	}{
		{name: "missing advertised routes", body: `{"devices":[{"nodeId":"node-a","enabledRoutes":[]}]}`, enabledPresent: true},
		{name: "null enabled routes", body: `{"devices":[{"nodeId":"node-a","advertisedRoutes":[],"enabledRoutes":null}]}`, advertisedPresent: true},
		{name: "wrong routes type", body: `{"devices":[{"nodeId":"node-a","advertisedRoutes":"10.0.0.0/24","enabledRoutes":[]}]}`, enabledPresent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(response, test.body)
			}))
			defer server.Close()
			client, err := newAdminHTTPClient(server.URL, "example.com", "fixture-api-key", server.Client())
			if err != nil {
				t.Fatalf("newAdminHTTPClient() error = %v", err)
			}
			devices, err := client.devices(context.Background())
			if err != nil || len(devices) != 1 {
				t.Fatalf("devices() = %#v, %v", devices, err)
			}
			device := devices[0]
			if device.nodeID != "node-a" || device.advertisedPresent != test.advertisedPresent || device.enabledPresent != test.enabledPresent {
				t.Fatalf("device route shape = %#v", device)
			}
		})
	}
}

func TestAdminHTTPClientRedactsHTTPAndTransportFailures(t *testing.T) {
	apiKey := "fixture-api-http-failure-secret"
	t.Run("HTTP error body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(response, apiKey)
		}))
		defer server.Close()
		client, err := newAdminHTTPClient(server.URL, "example.com", apiKey, server.Client())
		if err != nil {
			t.Fatalf("newAdminHTTPClient() error = %v", err)
		}
		_, err = client.devices(context.Background())
		requireErrorIs(t, err, ErrAdminUnavailable)
		if strings.Contains(err.Error(), apiKey) {
			t.Fatal("devices() returned the API error body")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New(apiKey)
		})}
		client, err := newAdminHTTPClient("https://api.example.com", "example.com", apiKey, httpClient)
		if err != nil {
			t.Fatalf("newAdminHTTPClient() error = %v", err)
		}
		_, err = client.devices(context.Background())
		requireErrorIs(t, err, ErrAdminUnavailable)
		if strings.Contains(err.Error(), apiKey) {
			t.Fatal("devices() returned transport error contents")
		}
	})
}

func TestBoundedAdminHTTPClientDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	client, err := newAdminHTTPClient(source.URL, "example.com", "fixture-api-key", boundedAdminHTTPClient(time.Second))
	if err != nil {
		t.Fatalf("newAdminHTTPClient() error = %v", err)
	}
	_, err = client.devices(context.Background())
	requireErrorIs(t, err, ErrAdminUnavailable)
	if redirected.Load() {
		t.Fatal("Admin API client followed a redirect")
	}
}

func TestAdminHTTPClientHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	client, err := newAdminHTTPClient(server.URL, "example.com", "fixture-api-key", boundedAdminHTTPClient(time.Second))
	if err != nil {
		t.Fatalf("newAdminHTTPClient() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = client.devices(ctx)
	requireErrorIs(t, err, ErrAdminUnavailable)
	if time.Since(started) > time.Second {
		t.Fatal("devices() did not honor its context")
	}
}

func TestAdminHTTPClientValidatesConstruction(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		tailnet string
		apiKey  string
		client  *http.Client
	}{
		{name: "relative URL", baseURL: "/api", tailnet: "example.com", apiKey: "key", client: http.DefaultClient},
		{name: "unsupported URL scheme", baseURL: "ftp://api.example.com", tailnet: "example.com", apiKey: "key", client: http.DefaultClient},
		{name: "URL credentials", baseURL: "https://user@api.example.com", tailnet: "example.com", apiKey: "key", client: http.DefaultClient},
		{name: "URL query", baseURL: "https://api.example.com?secret=value", tailnet: "example.com", apiKey: "key", client: http.DefaultClient},
		{name: "empty tailnet", baseURL: "https://api.example.com", apiKey: "key", client: http.DefaultClient},
		{name: "empty API key", baseURL: "https://api.example.com", tailnet: "example.com", client: http.DefaultClient},
		{name: "API key whitespace", baseURL: "https://api.example.com", tailnet: "example.com", apiKey: " key", client: http.DefaultClient},
		{name: "API key control character", baseURL: "https://api.example.com", tailnet: "example.com", apiKey: "key\nvalue", client: http.DefaultClient},
		{name: "API key too long", baseURL: "https://api.example.com", tailnet: "example.com", apiKey: strings.Repeat("x", 4097), client: http.DefaultClient},
		{name: "nil HTTP client", baseURL: "https://api.example.com", tailnet: "example.com", apiKey: "key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newAdminHTTPClient(test.baseURL, test.tailnet, test.apiKey, test.client)
			if client != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("newAdminHTTPClient() = %#v, %v", client, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
