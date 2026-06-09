package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMetricsExposed(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	required := []string{
		"geneve_rx_packets",
		"geneve_rx_bytes",
		"geneve_tx_packets",
		"geneve_tx_bytes",
		"decap_errors",
		"encap_errors",
		"tun_rx_packets",
		"tun_tx_packets",
		"drops",
		"routing_apply_attempts",
		"routing_apply_failures",
		"routing_drift_repairs",
	}
	for _, name := range required {
		if !strings.Contains(body, name) {
			t.Fatalf("missing metric %s", name)
		}
	}
}
