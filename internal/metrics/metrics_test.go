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
		"decap_errors",
		"tun_rx_packets",
		"tun_tx_packets",
		"drops",
		"geneve_options_validation_errors",
		"gwlb_profile_rejections",
		"gwlb_receive_drops",
		"gwlb_unsupported_inner",
		"symmetric_unexpected_egress",
		"datapath_component_healthy",
		"datapath_liveness_transitions",
		"gwlb_mtu_drops",
		"routing_apply_attempts",
		"routing_apply_failures",
		"routing_drift_repairs",
		"routing_validation_failures",
		"routing_ownership_decisions",
		"routing_ready",
	}
	for _, name := range required {
		if !strings.Contains(body, name) {
			t.Fatalf("missing metric %s", name)
		}
	}
	for _, name := range []string{
		"geneve_tx_packets",
		"geneve_tx_bytes",
		"encap_errors",
		"gwlb_send_failures",
		"gwlb_missing_contexts",
		"gwlb_conflicted_contexts",
		"gwlb_possible_loops",
		"gwlb_context_expirations",
		"gwlb_context_evictions",
		"gwlb_context_collisions",
	} {
		if strings.Contains(body, name) {
			t.Fatalf("obsolete metric %s is exposed", name)
		}
	}
}
