package datapath

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
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
	results       chan receiverResult
	closed        chan struct{}
	once          sync.Once
	closes        atomic.Int32
	reads         atomic.Int32
	deadlineCalls atomic.Int32
	deadlineErr   error
}

func newScriptedReceiver() *scriptedReceiver {
	return &scriptedReceiver{results: make(chan receiverResult), closed: make(chan struct{})}
}

func (r *scriptedReceiver) ReadPacket(buffer []byte) (int, PacketMetadata, error) {
	r.reads.Add(1)
	select {
	case result := <-r.results:
		return copy(buffer, result.packet), result.metadata, result.err
	case <-r.closed:
		return 0, PacketMetadata{}, net.ErrClosed
	}
}

func (r *scriptedReceiver) SetReadDeadline(time.Time) error {
	r.deadlineCalls.Add(1)
	return r.deadlineErr
}
func (r *scriptedReceiver) Close() error {
	r.once.Do(func() {
		r.closes.Add(1)
		close(r.closed)
	})
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "receive timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type lifecycleSender struct {
	closes atomic.Int32
}

func (*lifecycleSender) SendPacket(SendRequest) error { return nil }
func (s *lifecycleSender) Close() error {
	s.closes.Add(1)
	return nil
}

func TestReadinessIncludesPersistentFailureReason(t *testing.T) {
	reg := prometheus.NewRegistry()
	metricSet := metrics.NewTarget(reg)
	dp := &Datapath{live: newReadinessTracker(2, metricSet)}

	if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
		t.Fatalf("unexpected uninitialized readiness: ready=%v reason=%q", dp.Ready(), dp.HealthReason())
	}

	for _, component := range readinessComponents {
		dp.live.Initialize(component)
	}
	dp.initialized.Store(true)
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 1 {
		t.Fatalf("target ready gauge = %v, want 1", got)
	}
	dp.live.Failure(metrics.ReadinessComponentReceiver)
	if !dp.Ready() {
		t.Fatal("one transient error changed readiness")
	}
	dp.live.Failure(metrics.ReadinessComponentReceiver)
	if dp.Ready() || dp.HealthReason() != "receiver_persistent_failure" {
		t.Fatalf("persistent receive error did not change readiness: %q", dp.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 0 {
		t.Fatalf("unhealthy target ready gauge = %v, want 0", got)
	}
	dp.live.Success(metrics.ReadinessComponentReceiver)
	if !dp.Ready() {
		t.Fatal("successful receive did not restore readiness")
	}
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 1 {
		t.Fatalf("recovered target ready gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSet.TargetReadinessTransitions.WithLabelValues(metrics.ReadinessComponentReceiver, metrics.ReadinessStateNotReady)); got != 1 {
		t.Fatalf("unhealthy transitions = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSet.TargetReadinessTransitions.WithLabelValues(metrics.ReadinessComponentReceiver, metrics.ReadinessStateReady)); got != 2 {
		t.Fatalf("ready transitions = %v, want initialization plus recovery", got)
	}
}

func TestReadinessThresholdAndRecoveryForEveryComponent(t *testing.T) {
	if got, want := len(readinessComponents), 3; got != want {
		t.Fatalf("readiness component count = %d, want %d", got, want)
	}
	for _, component := range readinessComponents {
		t.Run(component, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			metricSet := metrics.NewTarget(reg)
			tracker := newReadinessTracker(3, metricSet)
			for _, initialized := range readinessComponents {
				tracker.Initialize(initialized)
			}
			tracker.Failure(component)
			tracker.Failure(component)
			if !tracker.Ready() {
				t.Fatal("tracker failed before threshold")
			}
			tracker.Failure(component)
			if tracker.Ready() || tracker.Reason() != component+"_persistent_failure" {
				t.Fatalf("component %q did not become unhealthy", component)
			}
			if got := testutil.ToFloat64(metricSet.TargetComponentReady.WithLabelValues(component)); got != 0 {
				t.Fatalf("ready gauge = %v, want 0", got)
			}
			tracker.Success(component)
			if !tracker.Ready() || tracker.Reason() != "ok" {
				t.Fatal("successful operation did not recover component")
			}
		})
	}
}

func TestReceiverValidationAndSenderInitializationAreIndependentlyRequired(t *testing.T) {
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	tracker := newReadinessTracker(3, metricSet)
	for _, tc := range []struct {
		initialize string
		wantReason string
	}{
		{initialize: metrics.ReadinessComponentReceiver, wantReason: "validation_not_initialized"},
		{initialize: metrics.ReadinessComponentValidation, wantReason: "sender_not_initialized"},
		{initialize: metrics.ReadinessComponentSender, wantReason: "ok"},
	} {
		tracker.Initialize(tc.initialize)
		if got := tracker.Reason(); got != tc.wantReason {
			t.Fatalf("after initializing %s reason=%q, want %q", tc.initialize, got, tc.wantReason)
		}
	}
	if !tracker.Ready() {
		t.Fatal("all three initialized components did not make the target ready")
	}
}

func TestReceiverTimeoutResetsTransientFailureStreak(t *testing.T) {
	receiver := newScriptedReceiver()
	reg := prometheus.NewRegistry()
	metricSet := metrics.NewTarget(reg)
	cfg := testConfig(t, "--persistent-error-threshold=2")
	dp := newWithPacketIO(cfg, nil, metricSet, receiver, &captureSender{})
	waiting := make(chan struct{})
	retry := make(chan struct{})
	dp.receiverRetryWait = func(ctx context.Context) {
		select {
		case waiting <- struct{}{}:
		case <-ctx.Done():
			return
		}
		select {
		case <-retry:
			return
		case <-ctx.Done():
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)

	receiver.results <- receiverResult{err: errors.New("receive failed once")}
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("transient receive failure did not enter the paced retry wait")
	}
	retry <- struct{}{}
	receiver.results <- receiverResult{err: fmt.Errorf("wrapped transient timeout: %w", timeoutError{})}
	receiver.results <- receiverResult{err: errors.New("receive failed after timeout")}
	select {
	case <-waiting:
	case err := <-done:
		t.Fatalf("timeout did not reset the receiver failure streak: %v", err)
	case <-time.After(time.Second):
		t.Fatal("post-timeout receive failure did not enter the paced retry wait")
	}
	if !dp.Ready() {
		t.Fatalf("transient receiver errors changed readiness: %q", dp.HealthReason())
	}
	select {
	case err := <-done:
		t.Fatalf("transient receiver errors terminated Run: %v", err)
	default:
	}
	retry <- struct{}{}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestPersistentReceiverFailuresTerminateRunAtThreshold(t *testing.T) {
	const threshold = 3
	for _, operation := range []string{"set read deadline", "read packet"} {
		t.Run(operation, func(t *testing.T) {
			receiver := newScriptedReceiver()
			failure := errors.New(operation + " failed")
			if operation == "set read deadline" {
				receiver.deadlineErr = failure
			}
			dp := newWithPacketIO(
				testConfig(t, "--persistent-error-threshold=3"),
				nil,
				metrics.NewTarget(prometheus.NewRegistry()),
				receiver,
				&captureSender{},
			)
			waiting := make(chan struct{})
			retry := make(chan struct{})
			dp.receiverRetryWait = func(ctx context.Context) {
				select {
				case waiting <- struct{}{}:
				case <-ctx.Done():
					return
				}
				select {
				case <-retry:
					return
				case <-ctx.Done():
					return
				}
			}
			done := make(chan error, 1)
			go func() { done <- dp.Run(context.Background()) }()
			waitForReady(t, dp)

			for attempt := 1; attempt <= threshold; attempt++ {
				if operation == "read packet" {
					receiver.results <- receiverResult{err: failure}
				}
				if attempt == threshold {
					break
				}
				select {
				case <-waiting:
				case err := <-done:
					t.Fatalf("Run stopped before threshold on attempt %d: %v", attempt, err)
				case <-time.After(time.Second):
					t.Fatalf("attempt %d did not enter the paced retry wait", attempt)
				}
				select {
				case err := <-done:
					t.Fatalf("Run stopped while a sub-threshold retry was gated: %v", err)
				default:
				}
				retry <- struct{}{}
			}

			select {
			case err := <-done:
				if !errors.Is(err, ErrReceiveLoopTerminated) || !errors.Is(err, ErrReceiverPersistentFailure) || !errors.Is(err, failure) {
					t.Fatalf("Run error = %v, want receive-loop and persistent failure wrapping", err)
				}
			case <-time.After(time.Second):
				t.Fatal("persistent receiver failure did not terminate Run at the threshold")
			}
			if got := receiver.deadlineCalls.Load(); got != threshold {
				t.Fatalf("SetReadDeadline calls = %d, want %d", got, threshold)
			}
			wantReads := int32(threshold)
			if operation == "set read deadline" {
				wantReads = 0
			}
			if got := receiver.reads.Load(); got != wantReads {
				t.Fatalf("ReadPacket calls = %d, want %d", got, wantReads)
			}
			if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
				t.Fatalf("terminated datapath readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
			}
		})
	}
}

func TestReceiveLoopTruncatedDatagramsArePeerDrops(t *testing.T) {
	receiver := newScriptedReceiver()
	reg := prometheus.NewRegistry()
	metricSet := metrics.NewTarget(reg)
	dp := newWithPacketIO(testConfig(t, "--persistent-error-threshold=1"), nil, metricSet, receiver, &captureSender{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)

	for range 3 {
		receiver.results <- receiverResult{err: ErrPacketTruncated}
	}
	deadline := time.Now().Add(time.Second)
	for testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)) != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !dp.Ready() || dp.HealthReason() != "ok" {
		t.Fatalf("peer truncation changed readiness: %q", dp.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)); got != 3 {
		t.Fatalf("truncated receive drops = %v, want 3", got)
	}
	if got := testutil.ToFloat64(metricSet.Drops); got != 3 {
		t.Fatalf("drops = %v, want 3", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestReceiverToSenderMalformedPacketEmitsNothing(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &captureSender{}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	dp := newWithPacketIO(testConfig(t), nil, metricSet, receiver, sender)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)

	receiver.results <- receiverResult{packet: []byte{0}, metadata: testPacketMetadata()}
	deadline := time.Now().Add(time.Second)
	for testutil.ToFloat64(metricSet.GWLBProfileRejections.WithLabelValues(metrics.ProfileReasonDecode)) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sender.Attempts() != 0 || testutil.ToFloat64(metricSet.GeneveRxPackets) != 0 || testutil.ToFloat64(metricSet.GeneveTxPackets) != 0 {
		t.Fatal("malformed receiver input reached the sender or valid packet counters")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestReceiverToSenderValidPacketReturnsExactlyOnce(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &captureSender{}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	dp := newWithPacketIO(testConfig(t), nil, metricSet, receiver, sender)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)
	packet := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443), sanitizedAWSOptions(), nil)

	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	deadline := time.Now().Add(time.Second)
	for sender.Attempts() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	requests := sender.Requests()
	if sender.Attempts() != 1 || len(requests) != 1 || !bytes.Equal(requests[0].Payload, packet) {
		t.Fatal("one valid receiver input did not produce exactly one faithful return")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestPersistentSenderFailureReinitializesWithoutRetryingPacket(t *testing.T) {
	receiver := newScriptedReceiver()
	initialSender := &captureSender{err: errors.New("send failed")}
	replacementSender := &captureSender{}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	factoryCalled := make(chan struct{}, 1)
	dp := newDatapath(
		testConfig(t, "--persistent-error-threshold=1"),
		nil,
		metricSet,
		receiver,
		initialSender,
		func(int) (PacketSender, error) {
			factoryCalled <- struct{}{}
			return replacementSender, nil
		},
	)
	dp.senderRecoveryDelay = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForRunStarted(t, dp)
	packet := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443), sanitizedAWSOptions(), nil)

	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	select {
	case <-factoryCalled:
	case <-time.After(time.Second):
		t.Fatal("persistent sender failure did not trigger reinitialization")
	}
	deadline := time.Now().Add(time.Second)
	for testutil.ToFloat64(metricSet.SenderReinitializations.WithLabelValues(metrics.SenderReinitializationOK)) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if initialSender.Attempts() != 1 || replacementSender.Attempts() != 0 {
		t.Fatal("failed packet was retried during sender reinitialization")
	}
	if initialSender.Closes() != 1 || !dp.Ready() {
		t.Fatalf("sender was not replaced cleanly: closes=%d ready=%v reason=%q", initialSender.Closes(), dp.Ready(), dp.HealthReason())
	}

	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	deadline = time.Now().Add(time.Second)
	for replacementSender.Attempts() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if replacementSender.Attempts() != 1 || len(replacementSender.Requests()) != 1 {
		t.Fatal("a later packet did not use the reinitialized sender exactly once")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after sender recovery: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after sender recovery")
	}
}

func TestPersistentSenderRecoveryExhaustionTerminatesRun(t *testing.T) {
	receiver := newScriptedReceiver()
	initialSender := &captureSender{err: errors.New("send failed")}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	var factoryCalls atomic.Int32
	dp := newDatapath(
		testConfig(t, "--persistent-error-threshold=1"),
		nil,
		metricSet,
		receiver,
		initialSender,
		func(int) (PacketSender, error) {
			factoryCalls.Add(1)
			return nil, errors.New("reopen failed")
		},
	)
	dp.senderRecoveryDelay = time.Millisecond
	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()
	waitForRunStarted(t, dp)
	packet := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443), sanitizedAWSOptions(), nil)
	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}

	select {
	case err := <-done:
		if !errors.Is(err, ErrSenderRecoveryFailed) {
			t.Fatalf("Run error = %v, want sender recovery exhaustion", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded sender recovery did not terminate Run")
	}
	if got := factoryCalls.Load(); got != int32(defaultSenderRecoveryTries) {
		t.Fatalf("sender recovery attempts = %d, want %d", got, defaultSenderRecoveryTries)
	}
	if initialSender.Attempts() != 1 || len(initialSender.Requests()) != 0 {
		t.Fatal("failed packet was retried while recovery attempts were exhausted")
	}
	if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
		t.Fatalf("exhausted sender readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
}

func TestRunStartsPacketReceiverAndSenderLifecycle(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &lifecycleSender{}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	dp := newWithPacketIO(testConfig(t), nil, metricSet, receiver, sender)
	if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
		t.Fatalf("datapath advertised readiness before Run: ready=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 0 {
		t.Fatalf("target ready gauge before Run = %v, want 0", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 1 {
		t.Fatalf("target ready gauge during Run = %v, want 1", got)
	}
	for _, component := range readinessComponents {
		if got := testutil.ToFloat64(metricSet.TargetComponentReady.WithLabelValues(component)); got != 1 {
			t.Fatalf("component %q ready gauge during Run = %v, want 1", component, got)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("packet-only Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet-only Run did not stop")
	}
	if receiver.closes.Load() != 1 || sender.closes.Load() != 1 {
		t.Fatalf("packet devices closed receiver=%d sender=%d", receiver.closes.Load(), sender.closes.Load())
	}
	if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
		t.Fatalf("stopped datapath readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.TargetReady); got != 0 {
		t.Fatalf("target ready gauge after Run = %v, want 0", got)
	}
	for _, component := range readinessComponents {
		if got := testutil.ToFloat64(metricSet.TargetComponentReady.WithLabelValues(component)); got != 0 {
			t.Fatalf("component %q ready gauge after Run = %v, want 0", component, got)
		}
	}
}

func TestCloseStopsActiveRunAndIsIdempotent(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &lifecycleSender{}
	reg := prometheus.NewRegistry()
	dp := newWithPacketIO(testConfig(t), nil, metrics.NewTarget(reg), receiver, sender)
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
	if receiver.closes.Load() != 1 || sender.closes.Load() != 1 {
		t.Fatalf("packet I/O closed receiver=%d sender=%d", receiver.closes.Load(), sender.closes.Load())
	}
	dp.Close()
	if err := dp.Run(context.Background()); err != nil {
		t.Fatalf("Run after closed datapath: %v", err)
	}
}

func TestUnexpectedReceiverTerminationCancelsSiblingsAndReturnsError(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &captureSender{}
	reg := prometheus.NewRegistry()
	dp := newWithPacketIO(testConfig(t), nil, metrics.NewTarget(reg), receiver, sender)
	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()
	waitForRunStarted(t, dp)
	receiver.results <- receiverResult{err: net.ErrClosed}
	select {
	case err := <-done:
		if !errors.Is(err, ErrReceiveLoopTerminated) || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Run error=%v, want receive termination", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected receive termination did not stop Run")
	}
	if dp.Ready() || dp.HealthReason() != "target_not_initialized" {
		t.Fatalf("receive termination readiness=%v reason=%q", dp.Ready(), dp.HealthReason())
	}
	if sender.Closes() != 1 {
		t.Fatal("receive termination did not close the sender")
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
