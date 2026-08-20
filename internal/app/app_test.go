package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/jaxxstorm/envelope/internal/routing"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type fakeRunner struct {
	runCalled   atomic.Bool
	closeCalled atomic.Bool
	unhealthy   atomic.Bool
	reason      string
}

func (f *fakeRunner) Run(ctx context.Context) error {
	f.runCalled.Store(true)
	<-ctx.Done()
	return nil
}

func (f *fakeRunner) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (f *fakeRunner) Ready() bool {
	return !f.unhealthy.Load()
}

func (f *fakeRunner) HealthReason() string {
	if f.reason != "" {
		return f.reason
	}
	return "ok"
}

func (f *fakeRunner) Close() {
	f.closeCalled.Store(true)
}

type fakeRoutingManager struct {
	ready            atomic.Bool
	initializeCalled atomic.Bool
	mode             config.RoutingMode
	reason           string
	initializeErr    error
}

func (f *fakeRoutingManager) Initialize(context.Context) error {
	f.initializeCalled.Store(true)
	if f.initializeErr != nil {
		return f.initializeErr
	}
	if f.mode == "" {
		f.mode = config.RoutingModeOff
	}
	f.ready.Store(true)
	return nil
}

func TestManageInitializationFailurePreventsDatapathStartup(t *testing.T) {
	cfg := &config.Config{RoutingMode: config.RoutingModeManage, TunName: "envelope0", TailscaleIface: "tailscale0"}
	runner := &fakeRunner{}
	startupErr := errors.New("routing ownership conflict")
	rm := &fakeRoutingManager{mode: config.RoutingModeManage, initializeErr: startupErr}
	err := run(context.Background(), cfg, zap.NewNop(),
		func(*config.Config, *zap.Logger, *metrics.Metrics) (Runner, error) { return runner, nil },
		func(*config.Config, *zap.Logger, *metrics.Metrics) (routing.Manager, error) { return rm, nil },
	)
	if !errors.Is(err, startupErr) {
		t.Fatalf("startup error=%v", err)
	}
	if !rm.initializeCalled.Load() || runner.runCalled.Load() {
		t.Fatalf("initialize called=%v datapath run=%v", rm.initializeCalled.Load(), runner.runCalled.Load())
	}
	if !runner.closeCalled.Load() {
		t.Fatal("datapath resources were not closed after routing startup failure")
	}
}

func (f *fakeRoutingManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (f *fakeRoutingManager) Ready() bool {
	return f.ready.Load()
}

func (f *fakeRoutingManager) Mode() config.RoutingMode {
	return f.mode
}

func (f *fakeRoutingManager) HealthReason() string {
	if f.reason != "" {
		return f.reason
	}
	return "ok"
}

func (f *fakeRoutingManager) Status() routing.Status {
	return routing.Status{Mode: string(f.mode), Ready: f.ready.Load(), Reason: f.HealthReason(), GWLBReturnCIDRs: []string{"10.10.0.0/24"}}
}

func TestRunLifecycle(t *testing.T) {
	cfg := &config.Config{
		UDPBind:     "127.0.0.1:0",
		TunName:     "envtest0",
		TunMTU:      1400,
		MetricsAddr: "127.0.0.1:0",
		LogLevel:    "error",
	}

	runner := &fakeRunner{}
	factory := func(_ *config.Config, _ *zap.Logger, _ *metrics.Metrics) (Runner, error) {
		return runner, nil
	}
	routingFactory := func(_ *config.Config, _ *zap.Logger, _ *metrics.Metrics) (routing.Manager, error) {
		return &fakeRoutingManager{mode: config.RoutingModeOff}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg, zap.NewNop(), factory, routingFactory)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}

	if !runner.runCalled.Load() {
		t.Fatalf("expected Run to be called")
	}
	if !runner.closeCalled.Load() {
		t.Fatalf("expected Close to be called")
	}
}

func TestHealthHandlerRoutingReadyStates(t *testing.T) {
	dp := &fakeRunner{}
	rm := &fakeRoutingManager{mode: config.RoutingModeManage, reason: "backend"}
	rm.ready.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newHealthHandler(dp, rm, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when routing is not ready, got %d", rec.Code)
	}
	if rec.Body.String() != "routing not ready: backend" {
		t.Fatalf("unexpected routing health body %q", rec.Body.String())
	}

	rm.ready.Store(true)
	rec = httptest.NewRecorder()
	newHealthHandler(dp, rm, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when routing is ready, got %d", rec.Code)
	}

	rm = &fakeRoutingManager{mode: config.RoutingModeOff}
	rm.ready.Store(false)
	rec = httptest.NewRecorder()
	newHealthHandler(dp, rm, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when routing mode is off, got %d", rec.Code)
	}
}

func TestHealthHandlerDatapathFailureCannotBeMaskedByRouting(t *testing.T) {
	dp := &fakeRunner{reason: "send"}
	dp.unhealthy.Store(true)
	rm := &fakeRoutingManager{mode: config.RoutingModeManage}
	rm.ready.Store(true)
	rec := httptest.NewRecorder()
	newHealthHandler(dp, rm, zap.NewNop()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "datapath not ready: send" {
		t.Fatalf("routing masked datapath failure: %d %q", rec.Code, rec.Body.String())
	}
}

func TestStartupLogReportsDirectionalRoles(t *testing.T) {
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--underlay-interface=eth0",
		"--gwlb-return-cidrs=10.10.0.0/24",
		"--local-delivery-cidrs=10.20.0.0/24",
		"--remote-tailnet-cidrs=10.30.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	core, observed := observer.New(zap.InfoLevel)
	logStartup(cfg, zap.New(core))
	entries := observed.FilterMessage("starting envelope").All()
	if len(entries) != 1 {
		t.Fatalf("startup entries=%d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	for _, name := range []string{"gwlb_return_cidrs", "local_delivery_cidrs", "remote_tailnet_cidrs", "underlay_interface"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("startup log missing %q: %v", name, fields)
		}
	}
	if _, legacy := fields["protected_cidrs"]; legacy {
		t.Fatal("startup log retained legacy protected_cidrs field")
	}
}

func TestRoutingStatusHandlerIsRedactedAndRoleSpecific(t *testing.T) {
	rm := &fakeRoutingManager{mode: config.RoutingModeManage, reason: "route_unaccepted"}
	rec := httptest.NewRecorder()
	newRoutingStatusHandler(rm).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/routing", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	for _, required := range []string{"gwlb_return_cidrs", "route_unaccepted", "10.10.0.0/24"} {
		if !strings.Contains(body, required) {
			t.Fatalf("routing status missing %q: %s", required, body)
		}
	}
	for _, forbidden := range []string{"auth", "cookie", "peer_key"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("routing status exposed forbidden field %q: %s", forbidden, body)
		}
	}
}

func TestHealthHandlerDebugLogsGWLBChecks(t *testing.T) {
	core, obs := observer.New(zap.DebugLevel)
	log := zap.New(core)
	dp := &fakeRunner{}
	rm := &fakeRoutingManager{mode: config.RoutingModeManage}
	rm.ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("User-Agent", "ELB-HealthChecker/2.0")
	rec := httptest.NewRecorder()

	newHealthHandler(dp, rm, log).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	entries := obs.FilterMessage("healthz request").All()
	if len(entries) == 0 {
		t.Fatalf("expected debug healthz log entry")
	}
}
