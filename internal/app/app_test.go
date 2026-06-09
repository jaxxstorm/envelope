package app

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	return true
}

func (f *fakeRunner) Close() {
	f.closeCalled.Store(true)
}

type fakeRoutingManager struct {
	ready atomic.Bool
	mode  config.RoutingMode
}

func (f *fakeRoutingManager) Initialize(context.Context) error {
	if f.mode == "" {
		f.mode = config.RoutingModeOff
	}
	f.ready.Store(true)
	return nil
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
	rm := &fakeRoutingManager{mode: config.RoutingModeManage}
	rm.ready.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newHealthHandler(dp, rm, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when routing is not ready, got %d", rec.Code)
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
