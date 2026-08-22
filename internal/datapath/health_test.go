package datapath

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type receiverResult struct {
	packet   []byte
	metadata PacketMetadata
	err      error
}

type scriptedReceiver struct {
	results chan receiverResult
	closed  chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func newScriptedReceiver() *scriptedReceiver {
	return &scriptedReceiver{results: make(chan receiverResult), closed: make(chan struct{})}
}

func (r *scriptedReceiver) ReadPacket(buffer []byte) (int, PacketMetadata, error) {
	select {
	case result := <-r.results:
		return copy(buffer, result.packet), result.metadata, result.err
	case <-r.closed:
		return 0, PacketMetadata{}, net.ErrClosed
	}
}

func (*scriptedReceiver) SetReadDeadline(time.Time) error { return nil }
func (r *scriptedReceiver) Close() error {
	r.once.Do(func() {
		r.closes.Add(1)
		close(r.closed)
	})
	return nil
}

type tunReadResult struct {
	packet []byte
	err    error
}

type scriptedTun struct {
	reads  chan tunReadResult
	closed chan struct{}
	once   sync.Once
	closes atomic.Int32
}

func newScriptedTun() *scriptedTun {
	return &scriptedTun{reads: make(chan tunReadResult), closed: make(chan struct{})}
}

func (t *scriptedTun) Read(buffer []byte) (int, error) {
	select {
	case result := <-t.reads:
		return copy(buffer, result.packet), result.err
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (*scriptedTun) Write(packet []byte) (int, error) { return len(packet), nil }
func (t *scriptedTun) Close() error {
	t.once.Do(func() {
		t.closes.Add(1)
		close(t.closed)
	})
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "receive timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestHealthHandlerIncludesPersistentFailureReason(t *testing.T) {
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	dp := &Datapath{live: newLivenessTracker(2, metricSet)}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	dp.HealthHandler(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready: not_initialized" {
		t.Fatalf("unexpected uninitialized response: %d %q", rec.Code, rec.Body.String())
	}

	dp.initialized.Store(true)
	dp.live.Failure(metrics.LivenessComponentReceive)
	if !dp.Ready() {
		t.Fatal("one transient error changed readiness")
	}
	dp.live.Failure(metrics.LivenessComponentReceive)
	if dp.Ready() || dp.HealthReason() != metrics.LivenessComponentReceive {
		t.Fatalf("persistent receive error did not change readiness: %q", dp.HealthReason())
	}
	rec = httptest.NewRecorder()
	dp.HealthHandler(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready: receive" {
		t.Fatalf("unexpected unhealthy response: %d %q", rec.Code, rec.Body.String())
	}

	dp.live.Success(metrics.LivenessComponentReceive)
	if !dp.Ready() {
		t.Fatal("successful receive did not restore readiness")
	}
	if got := testutil.ToFloat64(metricSet.DatapathLivenessTransitions.WithLabelValues(metrics.LivenessComponentReceive, "unhealthy")); got != 1 {
		t.Fatalf("unhealthy transitions = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSet.DatapathLivenessTransitions.WithLabelValues(metrics.LivenessComponentReceive, "healthy")); got != 1 {
		t.Fatalf("healthy transitions = %v, want 1", got)
	}
}

func TestLivenessThresholdAndRecoveryForEveryComponent(t *testing.T) {
	if got, want := len(livenessComponents), 2; got != want {
		t.Fatalf("liveness component count = %d, want %d", got, want)
	}
	for _, component := range livenessComponents {
		t.Run(component, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			metricSet := metrics.New(reg)
			tracker := newLivenessTracker(3, metricSet)
			tracker.Failure(component)
			tracker.Failure(component)
			if !tracker.Healthy() {
				t.Fatal("tracker failed before threshold")
			}
			tracker.Failure(component)
			if tracker.Healthy() || tracker.Reason() != component {
				t.Fatalf("component %q did not become unhealthy", component)
			}
			if got := testutil.ToFloat64(metricSet.DatapathComponentHealthy.WithLabelValues(component)); got != 0 {
				t.Fatalf("healthy gauge = %v, want 0", got)
			}
			tracker.Success(component)
			if !tracker.Healthy() || tracker.Reason() != "ok" {
				t.Fatal("successful operation did not recover component")
			}
		})
	}
}

func TestReceiveLoopTimeoutRecoversPersistentFailure(t *testing.T) {
	receiver := newScriptedReceiver()
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	cfg := testConfig(t, "--persistent-error-threshold=2")
	dp := NewWithDevices(cfg, nil, metricSet, receiver, &captureTun{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.ingressLoop(ctx) }()

	receiver.results <- receiverResult{err: errors.New("receive failed once")}
	receiver.results <- receiverResult{err: errors.New("receive failed twice")}
	waitForHealthReason(t, dp, metrics.LivenessComponentReceive)

	receiver.results <- receiverResult{err: timeoutError{}}
	waitForReady(t, dp)
	cancel()
	receiver.Close()
	if err := <-done; err != nil {
		t.Fatalf("ingress loop: %v", err)
	}
}

func TestReceiveLoopTruncatedDatagramsArePeerDrops(t *testing.T) {
	receiver := newScriptedReceiver()
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	dp := NewWithDevices(testConfig(t, "--persistent-error-threshold=1"), nil, metricSet, receiver, &captureTun{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.ingressLoop(ctx) }()

	for range 3 {
		receiver.results <- receiverResult{err: ErrPacketTruncated}
	}
	deadline := time.Now().Add(time.Second)
	for testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)) != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !dp.Ready() || dp.HealthReason() != "ok" {
		t.Fatalf("peer truncation changed liveness: %q", dp.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)); got != 3 {
		t.Fatalf("truncated receive drops = %v, want 3", got)
	}
	if got := testutil.ToFloat64(metricSet.Drops); got != 3 {
		t.Fatalf("drops = %v, want 3", got)
	}
	cancel()
	receiver.Close()
	if err := <-done; err != nil {
		t.Fatalf("ingress loop: %v", err)
	}
}

func TestTunEgressDropsWithoutChangingLiveness(t *testing.T) {
	tunDev := newScriptedTun()
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	cfg := testConfig(t, "--persistent-error-threshold=2")
	dp := NewWithDevices(cfg, nil, metricSet, &testReceiver{}, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.egressLoop(ctx) }()
	tunDev.reads <- tunReadResult{err: errors.New("TUN read failed once")}
	tunDev.reads <- tunReadResult{err: errors.New("TUN read failed twice")}
	if !dp.Ready() {
		t.Fatalf("TUN read failures changed liveness: %q", dp.HealthReason())
	}
	tunDev.reads <- tunReadResult{packet: innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)}
	deadline := time.Now().Add(time.Second)
	for testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress); got != 1 {
		t.Fatalf("unexpected egress drops = %v, want 1", got)
	}
	cancel()
	tunDev.Close()
	if err := <-done; err != nil {
		t.Fatalf("egress loop: %v", err)
	}
}

func TestCloseStopsActiveRunAndIsIdempotent(t *testing.T) {
	receiver := newScriptedReceiver()
	tunDev := newScriptedTun()
	reg := prometheus.NewRegistry()
	dp := NewWithDevices(testConfig(t), nil, metrics.New(reg), receiver, tunDev)
	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()
	waitForRunStarted(t, dp)

	var closes sync.WaitGroup
	for range 8 {
		closes.Add(1)
		go func() {
			defer closes.Done()
			dp.Close()
		}()
	}
	closes.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not terminate active Run")
	}
	if receiver.closes.Load() != 1 || tunDev.closes.Load() != 1 {
		t.Fatalf("devices closed receiver=%d tun=%d", receiver.closes.Load(), tunDev.closes.Load())
	}
	dp.Close()
	if err := dp.Run(context.Background()); err != nil {
		t.Fatalf("Run after closed datapath: %v", err)
	}
}

func TestUnexpectedReceiverTerminationCancelsSiblingsAndReturnsError(t *testing.T) {
	receiver := newScriptedReceiver()
	tunDev := newScriptedTun()
	reg := prometheus.NewRegistry()
	dp := NewWithDevices(testConfig(t), nil, metrics.New(reg), receiver, tunDev)
	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()
	waitForRunStarted(t, dp)
	receiver.results <- receiverResult{err: net.ErrClosed}
	select {
	case err := <-done:
		if !errors.Is(err, ErrReceiveLoopTerminated) {
			t.Fatalf("Run error=%v, want receive termination", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected receive termination did not stop Run")
	}
	if dp.Ready() || dp.HealthReason() != metrics.LivenessComponentReceive {
		t.Fatalf("receive termination readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
	if tunDev.closes.Load() != 1 {
		t.Fatal("receive termination did not cancel and close TUN sibling")
	}
}

func TestUnexpectedTunTerminationCancelsSiblingsAndReturnsError(t *testing.T) {
	receiver := newScriptedReceiver()
	tunDev := newScriptedTun()
	reg := prometheus.NewRegistry()
	dp := NewWithDevices(testConfig(t), nil, metrics.New(reg), receiver, tunDev)
	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()
	waitForRunStarted(t, dp)
	tunDev.reads <- tunReadResult{err: net.ErrClosed}
	select {
	case err := <-done:
		if !errors.Is(err, ErrTunLoopTerminated) {
			t.Fatalf("Run error=%v, want TUN termination", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected TUN termination did not stop Run")
	}
	if !dp.Ready() || dp.HealthReason() != "ok" {
		t.Fatalf("TUN termination changed liveness: readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
	if receiver.closes.Load() != 1 {
		t.Fatal("TUN termination did not cancel and close receive sibling")
	}
}

func waitForHealthReason(t *testing.T, dp *Datapath, reason string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !dp.Ready() && dp.HealthReason() == reason {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("datapath did not become unhealthy for %q", reason)
}

func waitForReady(t *testing.T, dp *Datapath) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if dp.Ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("datapath did not recover, reason=%q", dp.HealthReason())
}

func waitForRunStarted(t *testing.T, dp *Datapath) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		dp.runMu.Lock()
		running := dp.running
		dp.runMu.Unlock()
		if running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("datapath Run did not start")
}
