package tailnet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAdminAPIBase  = "https://api.tailscale.com"
	maxAdminResponseSize = 4 << 20
)

type adminDevice struct {
	nodeID            string
	advertisedRoutes  []string
	enabledRoutes     []string
	advertisedPresent bool
	enabledPresent    bool
}

func (d *adminDevice) UnmarshalJSON(data []byte) error {
	var wire struct {
		NodeID           json.RawMessage `json:"nodeId"`
		AdvertisedRoutes json.RawMessage `json:"advertisedRoutes"`
		EnabledRoutes    json.RawMessage `json:"enabledRoutes"`
	}
	if err := json.Unmarshal(data, &wire); err != nil || len(wire.NodeID) == 0 || bytes.Equal(wire.NodeID, []byte("null")) {
		return ErrMalformedAdminResponse
	}
	if err := json.Unmarshal(wire.NodeID, &d.nodeID); err != nil {
		return ErrMalformedAdminResponse
	}
	d.advertisedPresent = decodeAdminRoutes(wire.AdvertisedRoutes, &d.advertisedRoutes)
	d.enabledPresent = decodeAdminRoutes(wire.EnabledRoutes, &d.enabledRoutes)
	return nil
}

func decodeAdminRoutes(raw json.RawMessage, routes *[]string) bool {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return false
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded == nil {
		return false
	}
	*routes = append([]string(nil), decoded...)
	return true
}

type adminHTTPClient struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

func newAdminHTTPClient(baseURL, tailnetName, apiKey string, client *http.Client) (*adminHTTPClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !validIdentifier(tailnetName) || !validSecretArgument(apiKey) || client == nil {
		return nil, ErrInvalidConfiguration
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/v2/tailnet/" + url.PathEscape(tailnetName) + "/devices?fields=all"
	return &adminHTTPClient{endpoint: endpoint, apiKey: apiKey, client: client}, nil
}

func boundedAdminHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *adminHTTPClient) devices(ctx context.Context) ([]adminDevice, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, ErrAdminUnavailable
	}
	req.SetBasicAuth(c.apiKey, "")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "envelope-controller")

	response, err := c.client.Do(req)
	if err != nil {
		return nil, ErrAdminUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrAdminUnavailable
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxAdminResponseSize+1))
	if err != nil || len(body) > maxAdminResponseSize {
		return nil, ErrMalformedAdminResponse
	}
	var payload struct {
		Devices *[]adminDevice `json:"devices"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil || payload.Devices == nil {
		return nil, ErrMalformedAdminResponse
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrMalformedAdminResponse
	}
	return append([]adminDevice(nil), (*payload.Devices)...), nil
}
