package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

func TestConformanceLeadershipFencingAndCrashRecovery(t *testing.T) {
	h := newHarness(t)
	leader := h.initializeLeader("controller-a")

	duplicate := h.engine("controller-b", nil)
	if err := duplicate.Reconcile(context.Background()); err != nil {
		t.Fatalf("duplicate leader observation: %v", err)
	}
	if duplicate.Status().Role != reconcile.RoleFollower || len(h.aws.Calls()) != 0 {
		t.Fatalf("duplicate leader status/calls = %+v/%d", duplicate.Status(), len(h.aws.Calls()))
	}

	if err := h.tailnet.LoseRouter("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatalf("record failover owner: %v", err)
	}
	if state := h.state(); state.Phase != model.PhaseOwnerObserved || state.StableOwner != "node-a" {
		t.Fatalf("pre-crash observation state = %+v", state)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}
	crashingStore := &crashAfterCASStore{Store: h.store, target: 1}
	crashingLeader := h.engine("controller-a", crashingStore)
	if err := crashingLeader.Reconcile(context.Background()); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("injected checkpoint crash = %v", err)
	}
	crashedState := h.state()
	if !crashingStore.Triggered() || crashedState.Phase != model.PhaseRouteIntentPersisted || crashedState.Intent == nil || len(h.aws.Calls()) != 0 {
		t.Fatalf("crash checkpoint state/calls = %+v/%d", crashedState, len(h.aws.Calls()))
	}
	staleLease := crashedState.Lease.Clone()

	successor := h.engine("controller-b", nil)
	if err := successor.Reconcile(context.Background()); err != nil {
		t.Fatalf("successor lease observation: %v", err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.LeaseDuration.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := successor.Reconcile(context.Background()); err != nil {
		t.Fatalf("successor recovery: %v", err)
	}
	recovered := h.state()
	if recovered.Phase != model.PhaseStable || recovered.StableOwner != "node-b" || recovered.Lease.HolderID != "controller-b" || recovered.FenceTerm <= staleLease.FenceTerm {
		t.Fatalf("successor state = %+v", recovered)
	}
	if got, want := len(h.aws.Calls()), len(h.authority.RemotePrefixes); got != want {
		t.Fatalf("successor route calls = %d, want %d", got, want)
	}
	if _, err := h.store.RenewLease(context.Background(), store.DomainRefFor(h.authority), store.LeaseTokenFor(staleLease), h.topology.Policy.LeaseDuration.Duration()); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("stale lease renewal = %v", err)
	}
}

func TestConformanceRejectsPausedStaleOperationAfterTakeover(t *testing.T) {
	h := newHarness(t)
	h.prepareInitialOwner()

	originalPause := newPausePoint()
	defer originalPause.resume()
	originalStore := &pauseBeforeMutationCASStore{Store: h.store, point: originalPause}
	originalRoutes := &attributedRoutes{delegate: h.aws}
	original := h.engineWith("controller-a", originalStore, originalRoutes, h.clock)
	h.requireLeader(original, "controller-a")

	if err := h.tailnet.LoseRouter("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := original.Reconcile(context.Background()); err != nil {
		t.Fatalf("record failover owner: %v", err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}

	originalContext, cancelOriginal := context.WithCancel(context.Background())
	defer cancelOriginal()
	originalResult := make(chan error, 1)
	go func() { originalResult <- original.Reconcile(originalContext) }()
	originalPause.await(t, "original leader")
	paused := h.state()
	if paused.Phase != model.PhaseRoutesConverging || paused.Intent == nil || paused.Intent.Progress[0].Attempted() || len(h.aws.Calls()) != 0 {
		t.Fatalf("paused pre-mutation state/calls = %+v/%d", paused, len(h.aws.Calls()))
	}
	staleLease := paused.Lease.Clone()

	successorPause := newPausePoint()
	defer successorPause.resume()
	successorStore := &pauseAfterTakeoverStore{Store: h.store, point: successorPause}
	successorRoutes := &attributedRoutes{delegate: h.aws}
	successor := h.engineWith("controller-b", successorStore, successorRoutes, h.clock)
	successorContext, cancelSuccessor := context.WithCancel(context.Background())
	defer cancelSuccessor()
	if err := successor.Reconcile(successorContext); err != nil {
		t.Fatalf("successor lease observation: %v", err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.LeaseDuration.Duration()); err != nil {
		t.Fatal(err)
	}
	successorResult := make(chan error, 1)
	go func() { successorResult <- successor.Reconcile(successorContext) }()
	successorPause.await(t, "successor takeover")
	takenOver := h.state()
	if takenOver.Lease == nil || takenOver.Lease.HolderID != "controller-b" || takenOver.FenceTerm <= staleLease.FenceTerm {
		t.Fatalf("takeover state = %+v", takenOver)
	}

	originalPause.resume()
	select {
	case err := <-originalResult:
		if !errors.Is(err, store.ErrLeaseLost) {
			t.Fatalf("resumed stale operation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resumed stale operation did not return")
	}
	if status := original.Status(); status.Role != reconcile.RoleFollower || status.Reason != reconcile.ReasonLeaseLost {
		t.Fatalf("resumed stale operation status = %+v", status)
	}
	if originalRoutes.MutationCalls() != 0 || len(h.aws.Calls()) != 0 {
		t.Fatalf("stale operation reached route mutation: attributed/all calls = %d/%d", originalRoutes.MutationCalls(), len(h.aws.Calls()))
	}

	successorPause.resume()
	select {
	case err := <-successorResult:
		if err != nil {
			t.Fatalf("successor reconciliation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("successor reconciliation did not finish")
	}
	recovered := h.state()
	if recovered.Phase != model.PhaseStable || recovered.StableOwner != "node-b" || recovered.Lease.HolderID != "controller-b" {
		t.Fatalf("successor state = %+v", recovered)
	}
	if got, want := successorRoutes.MutationCalls(), len(h.authority.RemotePrefixes); got != want {
		t.Fatalf("successor route calls = %d, want %d", got, want)
	}
	if originalRoutes.MutationCalls() != 0 {
		t.Fatalf("original leader made %d route calls after lease loss", originalRoutes.MutationCalls())
	}
}

func TestConformanceAmbiguousAPIAfterCommitSettlesWithoutReplay(t *testing.T) {
	h := newHarness(t)
	leader := h.initializeLeader("controller-a")
	h.aws.SetAmbiguousCall(1)
	if err := h.tailnet.LoseRouter("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	state := h.state()
	if state.Phase != model.PhaseStable || state.StableOwner != "node-b" || !h.aws.Aligned("node-b") {
		t.Fatalf("settled ambiguous state = %+v", state)
	}
	calls := h.aws.Calls()
	if len(calls) != len(h.authority.RemotePrefixes) || !calls[0].ambiguous {
		t.Fatalf("ambiguous calls = %+v", calls)
	}
	seen := make(map[string]int, len(calls))
	for _, call := range calls {
		seen[call.prefix]++
	}
	for _, prefix := range h.authority.RemotePrefixes {
		if seen[prefix] != 1 {
			t.Fatalf("route %s call count = %d, want 1", prefix, seen[prefix])
		}
	}
	if status := leader.Status(); status.Reason != reconcile.ReasonStable || !status.RouteAgreement {
		t.Fatalf("settled ambiguous status = %+v", status)
	}
}

func TestConformanceObserverDisagreement(t *testing.T) {
	h := newHarness(t)
	leader := h.initializeLeader("controller-a")
	h.tailnet.SetObserverView("controller-c", "node-b")
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.state().Phase != model.PhaseDegraded || len(h.aws.Calls()) != 0 || !h.aws.Aligned("node-a") {
		t.Fatal("disagreement changed routes or was not degraded")
	}
	h.tailnet.SetObserverView("controller-c", "node-a")
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.state().Phase != model.PhaseStable || len(h.aws.Calls()) != 0 {
		t.Fatal("agreement did not recover without mutation")
	}
}

func TestConformanceOwnershipFlapAndAutomaticFailback(t *testing.T) {
	h := newHarness(t)
	leader := h.initializeLeader("controller-a")

	if err := h.tailnet.Select("node-b"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.ObservationInterval.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := h.tailnet.Select("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := h.state(); state.Phase != model.PhaseStable || state.StableOwner != "node-a" || len(h.aws.Calls()) != 0 {
		t.Fatalf("ownership flap changed routes: state=%+v calls=%d", state, len(h.aws.Calls()))
	}

	if err := h.tailnet.Select("node-b"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	failedOver := h.state()
	if failedOver.Phase != model.PhaseStable || failedOver.StableOwner != "node-b" || h.uuids.Count() != 1 {
		t.Fatalf("durable alternate state = %+v transactions=%d", failedOver, h.uuids.Count())
	}
	failoverCalls := len(h.aws.Calls())

	if err := h.tailnet.Select("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.publishObservers(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := h.state(); state.Phase != model.PhaseOwnerObserved || state.StableOwner != "node-b" || len(h.aws.Calls()) != failoverCalls {
		t.Fatalf("failback bypassed longer stability: state=%+v calls=%d", state, len(h.aws.Calls()))
	}
	if leader.Status().Reason != reconcile.ReasonStabilityWindow {
		t.Fatalf("early failback status = %+v", leader.Status())
	}

	if err := h.advanceObservers(context.Background(), h.topology.Policy.FailbackStability.Duration()-h.topology.Policy.FailoverStability.Duration()); err != nil {
		t.Fatal(err)
	}
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatalf("automatic failback: %v", err)
	}
	failedBack := h.state()
	if failedBack.Phase != model.PhaseStable || failedBack.StableOwner != "node-a" || !h.aws.Aligned("node-a") || h.uuids.Count() != 2 {
		t.Fatalf("automatic failback state = %+v transactions=%d", failedBack, h.uuids.Count())
	}
	if got, want := len(h.aws.Calls()), 2*len(h.authority.RemotePrefixes); got != want {
		t.Fatalf("failover/failback calls = %d, want %d", got, want)
	}
}
