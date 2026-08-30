package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestTargetMetricsExposed(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewTarget(reg)
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
		"drops",
		"geneve_options_validation_errors",
		"gwlb_profile_rejections",
		"gwlb_receive_drops",
		"gwlb_return_build_failures",
		"gwlb_send_failures",
		"gwlb_inner_validation_failures",
		"gwlb_target_ready",
		"gwlb_target_component_ready",
		"gwlb_target_readiness_transitions",
		"gwlb_sender_reinitializations",
		"gwlb_mtu_drops",
	}
	for _, name := range required {
		if !strings.Contains(body, name) {
			t.Fatalf("missing metric %s", name)
		}
	}
	for _, name := range []string{
		"decap_errors",
		"encap_errors",
		"tun_rx_packets",
		"tun_tx_packets",
		"symmetric_unexpected_egress",
		"routing_apply_attempts",
		"routing_apply_failures",
		"routing_drift_repairs",
		"routing_validation_failures",
		"routing_ownership_decisions",
		"routing_ready",
		"gwlb_missing_contexts",
		"gwlb_conflicted_contexts",
		"gwlb_possible_loops",
		"gwlb_context_expirations",
		"gwlb_context_evictions",
		"gwlb_context_collisions",
		"gwlb_unsupported_inner",
		"datapath_component_healthy",
		"datapath_liveness_transitions",
	} {
		if strings.Contains(body, name) {
			t.Fatalf("obsolete metric %s is exposed", name)
		}
	}
	for _, component := range []string{ReadinessComponentReceiver, ReadinessComponentValidation, ReadinessComponentSender} {
		if !strings.Contains(body, `component="`+component+`"`) {
			t.Fatalf("missing explicit readiness component %q", component)
		}
	}
	if !strings.Contains(body, `geneve_options_validation_errors{reason="`+OptionValidationReasonAWSReserved+`"}`) {
		t.Fatal("reserved option validation reason is not initialized")
	}
}
