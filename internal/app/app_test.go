package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type fakeRunner struct {
	runCalled   atomic.Bool
	closeCalled atomic.Bool
	closeCalls  atomic.Int32
	unhealthy   atomic.Bool
	reason      string
}

func (f *fakeRunner) Run(ctx context.Context) error {
	f.runCalled.Store(true)
	<-ctx.Done()
	return nil
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
	f.closeCalls.Add(1)
	f.closeCalled.Store(true)
}

type recordingShutdowner struct {
	shutdown func()
}

func (s recordingShutdowner) Shutdown(context.Context) error {
	s.shutdown()
	return nil
}

func targetTestConfig() *config.Config {
	return &config.Config{
		ConfigVersion:            2,
		Mode:                     "packet-return",
		UDPBind:                  "127.0.0.1:6081",
		MaxInnerPacketSize:       1280,
		MetricsAddr:              "127.0.0.1:0",
		LogLevel:                 "error",
		PersistentErrorThreshold: 3,
		GeneveOptionsMaxBytes:    252,
	}
}

func TestRunLifecycleUsesOnlyPacketReturnRunner(t *testing.T) {
	runner := &fakeRunner{}
	factory := func(_ *config.Config, _ *zap.Logger, _ *metrics.Metrics) (Runner, error) {
		return runner, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, targetTestConfig(), zap.NewNop(), factory)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for shutdown")
	}
	if !runner.runCalled.Load() || !runner.closeCalled.Load() {
		t.Fatalf("runner lifecycle: run=%v close=%v", runner.runCalled.Load(), runner.closeCalled.Load())
	}
	if runner.closeCalls.Load() != 1 {
		t.Fatalf("runner close calls = %d, want 1", runner.closeCalls.Load())
	}
}

func TestShutdownClearsRunnerBeforeHTTPServer(t *testing.T) {
	ready := true
	shutdownCalled := false
	shutdownTarget(
		func() { ready = false },
		recordingShutdowner{shutdown: func() {
			if ready {
				t.Error("HTTP shutdown started while the runner still advertised readiness")
			}
			shutdownCalled = true
		}},
	)
	if !shutdownCalled {
		t.Fatal("HTTP shutdown was not called")
	}
}

func TestHealthHandlerReportsPacketReturnHealthOnly(t *testing.T) {
	dp := &fakeRunner{reason: "sender_persistent_failure"}
	dp.unhealthy.Store(true)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newHealthHandler(dp, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "packet return not ready: sender_persistent_failure" {
		t.Fatalf("unhealthy response = %d %q", rec.Code, rec.Body.String())
	}

	dp.unhealthy.Store(false)
	rec = httptest.NewRecorder()
	newHealthHandler(dp, zap.NewNop()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthy response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestTargetHandlerDoesNotExposeRoutingDebugState(t *testing.T) {
	handler := newTargetHandler(&fakeRunner{}, prometheus.NewRegistry(), zap.NewNop())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/routing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("routing debug status = %d, want 404", rec.Code)
	}
}

func TestStartupLogReportsPacketReturnConfiguration(t *testing.T) {
	cfg, err := config.ParseTarget([]string{"--max-inner-packet-size=1400"})
	if err != nil {
		t.Fatal(err)
	}
	core, observed := observer.New(zap.InfoLevel)
	logStartup(cfg, zap.New(core))
	entries := observed.FilterMessage("starting Envelope GWLB packet-return target").All()
	if len(entries) != 1 {
		t.Fatalf("startup entries = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	for _, name := range []string{"config_version", "mode", "udp_bind", "max_inner_packet_size", "metrics_addr", "persistent_error_threshold"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("startup log missing %q: %v", name, fields)
		}
	}
	if fields["mode"] != "packet-return" {
		t.Fatalf("startup mode = %v, want packet-return", fields["mode"])
	}
	for _, name := range []string{
		"tun_name", "tun_mtu", "tailscale_iface", "underlay_interface", "routing_mode", "routing_table_id", "routing_rule_priority",
		"local_site_cidrs", "remote_site_cidrs", "gwlb_return_cidrs", "local_delivery_cidrs", "remote_tailnet_cidrs", "flow_capacity", "flow_timeout",
	} {
		if _, obsolete := fields[name]; obsolete {
			t.Fatalf("startup log retained obsolete field %q", name)
		}
	}
}

func TestHealthHandlerDebugLogsGWLBChecksWithoutRouting(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("User-Agent", "ELB-HealthChecker/2.0")
	rec := httptest.NewRecorder()
	newHealthHandler(&fakeRunner{}, zap.New(core)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	entries := observed.FilterMessage("healthz request").All()
	if len(entries) != 1 {
		t.Fatalf("health debug entries = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["is_gwlb_healthcheck"] != true {
		t.Fatalf("GWLB health check was not identified: %v", fields)
	}
	for name := range fields {
		if strings.Contains(name, "routing") {
			t.Fatalf("health log retained routing field %q", name)
		}
	}
}
