package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestControllerMetricsUseIsolatedRegistries(t *testing.T) {
	authority := testAuthority()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	first := prometheus.NewRegistry()
	second := prometheus.NewRegistry()
	if _, err := New(first, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now }); err != nil {
		t.Fatalf("first New() error = %v", err)
	}
	if _, err := New(second, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now }); err != nil {
		t.Fatalf("second New() error = %v", err)
	}
	if _, err := New(first, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now }); err == nil {
		t.Fatal("duplicate registration in one registry unexpectedly succeeded")
	}

	families, err := first.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "go_") || strings.HasPrefix(family.GetName(), "process_") {
			t.Fatalf("isolated registry contains default collector %q", family.GetName())
		}
	}
}

func TestControllerMetricsMapOwnersAndCoverStatusFields(t *testing.T) {
	authority := testAuthority()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics, err := New(registry, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	metrics.SetProcessLive(true)
	metrics.SetObserverRunning(true)
	metrics.RecordSnapshot(true)
	observation := testObservation(now, authority)
	metrics.RecordPublication(observation)
	metrics.RecordStatus(reconcile.Status{
		ControllerID:    "controller-a",
		DomainID:        authority.DomainID,
		Mode:            reconcile.ModeActive,
		Role:            reconcile.RoleLeader,
		Phase:           model.PhaseRoutesConverging,
		Reason:          reconcile.ReasonReconciling,
		StableOwner:     "stable-node-secret-a",
		ObservedOwner:   "stable-node-secret-b",
		ConsensusOwner:  "stable-node-secret-b",
		FenceTerm:       9,
		LeaseExpiresAt:  now.Add(time.Minute),
		Quorum:          true,
		RouteAgreement:  false,
		CompletedRoutes: 1,
		TotalRoutes:     2,
		UpdatedAt:       now,
	})

	body := gatherText(t, registry)
	if strings.Contains(body, "stable-node-secret") {
		t.Fatalf("metrics exposed a raw stable-node ID:\n%s", body)
	}
	for _, expected := range []string{
		`router="router-a"`, `router="router-b"`,
		`envelope_controller_domain_mode{domain="domain-a",mode="active"} 1`,
		`envelope_controller_domain_role{domain="domain-a",role="leader"} 1`,
		`envelope_controller_domain_phase{domain="domain-a",phase="routes-converging"} 1`,
		`envelope_controller_domain_reason{domain="domain-a",reason="reconciling"} 1`,
		`envelope_controller_lease_fence_term{domain="domain-a"} 9`,
		`envelope_controller_observation_quorum{domain="domain-a"} 1`,
		`envelope_controller_route_agreement{domain="domain-a"} 0`,
		`envelope_controller_routes_completed{domain="domain-a"} 1`,
		`envelope_controller_routes_total{domain="domain-a"} 2`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q:\n%s", expected, body)
		}
	}
}

func TestControllerMetricsRecordTransitionsAndBoundUnknownLabels(t *testing.T) {
	authority := testAuthority()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics, err := New(registry, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	status := reconcile.Status{
		ControllerID:   "controller-a",
		DomainID:       authority.DomainID,
		Mode:           reconcile.ModeActive,
		Role:           reconcile.RoleLeader,
		Phase:          model.PhaseStable,
		Reason:         reconcile.ReasonStable,
		StableOwner:    authority.PreferredOwner,
		ConsensusOwner: authority.PreferredOwner,
		LeaseExpiresAt: now.Add(time.Minute),
		Quorum:         true,
		RouteAgreement: true,
		TotalRoutes:    2,
		UpdatedAt:      now,
	}
	metrics.RecordStatus(status)
	status.Phase = model.PhaseOwnerObserved
	status.Reason = reconcile.ReasonStabilityWindow
	status.ObservedOwner = "stable-node-secret-b"
	status.ConsensusOwner = "stable-node-secret-b"
	status.UpdatedAt = now.Add(time.Second)
	metrics.RecordStatus(status)
	status.Phase = model.PhaseStable
	status.Reason = reconcile.ReasonStable
	status.StableOwner = "stable-node-secret-b"
	status.ObservedOwner = ""
	status.UpdatedAt = now.Add(2 * time.Second)
	metrics.RecordStatus(status)
	status.StableOwner = authority.PreferredOwner
	status.ConsensusOwner = authority.PreferredOwner
	status.UpdatedAt = now.Add(3 * time.Second)
	metrics.RecordStatus(status)
	status.Phase = model.PhaseDegraded
	status.Reason = reconcile.ReasonRouteAmbiguous
	status.ErrorCode = model.ErrorRouteAmbiguous
	status.StableOwner = "unbounded-stable-node-value"
	status.UpdatedAt = now.Add(4 * time.Second)
	metrics.RecordStatus(status)

	body := gatherText(t, registry)
	for _, expected := range []string{
		`envelope_controller_failovers_total{domain="domain-a"} 1`,
		`envelope_controller_failbacks_total{domain="domain-a"} 1`,
		`envelope_controller_ambiguous_calls_total{domain="domain-a"} 1`,
		`router="unknown"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "unbounded-stable-node-value") {
		t.Fatalf("unknown owner was used as a label:\n%s", body)
	}
}

func TestControllerMetricsExposeIntentionalPublicationAndVerifiedFollowerEvidence(t *testing.T) {
	authority := testAuthority()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics, err := New(registry, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	metrics.SetObservationPublicationEnabled(false)
	metrics.RecordPublicationSkipped()
	metrics.RecordStatus(reconcile.Status{
		ControllerID:   "controller-a",
		DomainID:       authority.DomainID,
		Mode:           reconcile.ModeActive,
		Role:           reconcile.RoleFollower,
		Phase:          model.PhaseStable,
		Reason:         reconcile.ReasonLeaseHeld,
		StableOwner:    authority.PreferredOwner,
		FenceTerm:      3,
		LeaseExpiresAt: now.Add(time.Minute),
		Quorum:         false,
		TotalRoutes:    len(authority.RemotePrefixes),
		UpdatedAt:      now,
	})
	metrics.RecordReadinessEvidence(authority.DomainID, true, true)

	body := gatherText(t, registry)
	for _, expected := range []string{
		`envelope_controller_observation_publication_enabled 0`,
		`envelope_controller_observer_events_total{result="publish_skipped"} 1`,
		`envelope_controller_observation_quorum{domain="domain-a"} 1`,
		`envelope_controller_lease_holder_confirmed{domain="domain-a"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q:\n%s", expected, body)
		}
	}
}

func TestControllerMetricsReportStoreUnavailableAsDynamoDBError(t *testing.T) {
	authority := testAuthority()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics, err := New(registry, "controller-a", []model.DomainAuthority{authority}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	metrics.RecordStatus(reconcile.Status{
		ControllerID: "controller-a",
		DomainID:     authority.DomainID,
		Mode:         reconcile.ModeActive,
		Role:         reconcile.RoleUnknown,
		Phase:        model.PhaseStable,
		Reason:       reconcile.ReasonStoreUnavailable,
		ErrorCode:    model.ErrorStoreUnavailable,
		StableOwner:  authority.PreferredOwner,
		TotalRoutes:  len(authority.RemotePrefixes),
		UpdatedAt:    now,
	})

	body := gatherText(t, registry)
	for _, expected := range []string{
		`envelope_controller_domain_api_status{api="dynamodb",domain="domain-a",status="error"} 1`,
		`envelope_controller_api_errors_total{api="dynamodb",domain="domain-a"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q:\n%s", expected, body)
		}
	}
}

func TestOperationalHandlerHealthReadinessAndNoMutationRoute(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "isolated_metric", Help: "test"}))
	health := &testHealth{live: true, ready: false, reason: "domain-degraded"}
	handler, err := NewHandler(registry, health)
	if err != nil {
		t.Fatal(err)
	}

	assertHTTPStatus(t, handler, http.MethodGet, "/healthz", http.StatusOK)
	assertHTTPStatus(t, handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	health.ready = true
	assertHTTPStatus(t, handler, http.MethodGet, "/readyz", http.StatusOK)
	assertHTTPStatus(t, handler, http.MethodGet, "/metrics", http.StatusOK)
	assertHTTPStatus(t, handler, http.MethodPost, "/readyz", http.StatusMethodNotAllowed)
	assertHTTPStatus(t, handler, http.MethodPost, "/mutate", http.StatusNotFound)
}

type testHealth struct {
	live   bool
	ready  bool
	reason string
}

func (h *testHealth) Healthy() bool { return h.live }
func (h *testHealth) Readiness() (bool, string) {
	return h.ready, h.reason
}

func assertHTTPStatus(t *testing.T, handler http.Handler, method, path string, want int) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("%s %s status = %d, want %d; body=%q", method, path, recorder.Code, want, recorder.Body.String())
	}
}

func gatherText(t *testing.T, registry *prometheus.Registry) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("gather status = %d: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func testObservation(now time.Time, authority model.DomainAuthority) *model.Observation {
	return &model.Observation{
		ControllerID:   "controller-a",
		TopologyHash:   authority.TopologyHash,
		Sequence:       1,
		CapturedAt:     now,
		ExpiresAt:      now.Add(time.Minute),
		BackendHealthy: true,
		Domains: map[string]model.OwnerObservation{
			authority.DomainID: {
				StableNodeID:       authority.PreferredOwner,
				SolePrimary:        true,
				Online:             true,
				Healthy:            true,
				AdvertisedPrefixes: []string{authority.SourcePrefix},
				EnabledPrefixes:    []string{authority.SourcePrefix},
			},
		},
	}
}

func testAuthority() model.DomainAuthority {
	return model.DomainAuthority{
		TopologyHash:            strings.Repeat("a", 64),
		DeploymentID:            "deployment-a",
		DomainID:                "domain-a",
		SiteID:                  "west",
		VPCID:                   "vpc-west",
		Region:                  "us-west-2",
		SourcePrefix:            "10.0.0.0/24",
		RouteTableID:            "rtb-west",
		GWLBESubnetID:           "subnet-gwlbe-west",
		RouteTableAssociationID: "rtbassoc-gwlbe-west",
		RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
		PreferredOwner:          "stable-node-secret-a",
		Owners: []model.OwnerAuthority{
			{RouterID: "router-a", StableNodeID: "stable-node-secret-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-west", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{RouterID: "router-b", StableNodeID: "stable-node-secret-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-west", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
		},
	}
}
