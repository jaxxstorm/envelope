package reconcile

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

func TestEngineSuccessfulFailoverAndFailback(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe failover: %v", err)
	}
	requireState(t, rig.state(), model.PhaseOwnerObserved, "node-a")
	if status := engine.Status(); status.Phase != model.PhaseOwnerObserved || status.ConsensusOwner != "node-b" || status.RouteAgreement {
		t.Fatalf("transitional leader status = %+v", status)
	}

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("complete failover: %v", err)
	}
	failedOver := rig.state()
	requireState(t, failedOver, model.PhaseStable, "node-b")
	if failedOver.CooldownUntil == nil || rig.routes.callCount() != len(rig.authority.RemotePrefixes) {
		t.Fatalf("failed-over state/calls = %+v/%d", failedOver, rig.routes.callCount())
	}
	for _, call := range rig.routes.callsSnapshot() {
		if call.routeTableID != rig.authority.RouteTableID || call.expectedPrevious != "eni-a" || call.desiredENI != "eni-b" || !call.deadline.Before(failedOver.Lease.ExpiresAt) {
			t.Errorf("failover call escaped authority or lease bound: %+v", call)
		}
	}

	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe failback: %v", err)
	}
	requireState(t, rig.state(), model.PhaseOwnerObserved, "node-b")
	rig.advanceAndPublish(rig.topology.Policy.FailbackStability.Duration(), "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("complete failback: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
	if got, want := rig.routes.callCount(), 2*len(rig.authority.RemotePrefixes); got != want {
		t.Fatalf("route calls = %d, want %d", got, want)
	}
	status := engine.Status()
	if status.Role != RoleLeader || status.Reason != ReasonStable || !status.Quorum || !status.RouteAgreement {
		t.Fatalf("final status = %+v", status)
	}
	assertOnlyBoundedStatus(t, status)
}

func TestEngineResetsOwnerStability(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstObserved := *rig.state().OwnerObservedAt
	rig.advanceAndPublish(200*time.Millisecond, "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondObserved := *rig.state().OwnerObservedAt
	if !secondObserved.After(firstObserved) {
		t.Fatalf("second stability window started at %s, first was %s", secondObserved, firstObserved)
	}
	rig.advanceAndPublish(200*time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.state().Phase != model.PhaseOwnerObserved || rig.routes.callCount() != 0 {
		t.Fatal("route mutation occurred before the reset stability window elapsed")
	}
	rig.advanceAndPublish(100*time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineRejectsOwnershipFlapOverwrittenBetweenReconciles(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.clock.Advance(200 * time.Millisecond)
	// Both samples replace the prior per-controller records before the engine
	// reads them. Durable continuity must still expose the intervening flap.
	rig.publishOwner("node-a")
	rig.publishOwner("node-b")
	rig.clock.Advance(100 * time.Millisecond)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := rig.state(); state.Phase != model.PhaseOwnerObserved || rig.routes.callCount() != 0 {
		t.Fatalf("overwritten flap bypassed stability: state=%+v calls=%d", state, rig.routes.callCount())
	}

	rig.advanceAndPublish(200*time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEnginePostIntentFlapStopsNextRouteMutation(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	state := prepareConvergingIntent(t, rig, engine, "node-b", rig.topology.Policy.FailoverStability.Duration())
	state = reconcileOneRoute(t, engine, state)
	if calls := rig.routes.callCount(); calls != 1 {
		t.Fatalf("partial failover calls = %d, want 1", calls)
	}

	rig.advanceAndPublish(time.Millisecond, "node-a")
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("post-intent flap: %v", err)
	}
	if current := rig.state(); current.Phase != model.PhaseRoutesConverging || rig.routes.callCount() != 1 || engine.Status().Reason != ReasonStabilityWindow {
		t.Fatalf("flap authorized next mutation: state=%+v calls=%d status=%+v", current, rig.routes.callCount(), engine.Status())
	}

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration()-time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("early post-flap reconcile: %v", err)
	}
	if rig.routes.callCount() != 1 {
		t.Fatal("post-intent flap reused the pre-flap stability interval")
	}
	rig.advanceAndPublish(time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("fresh post-flap window: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
	if rig.routes.callCount() != len(rig.authority.RemotePrefixes) {
		t.Fatalf("fresh stability did not complete routes: calls=%d", rig.routes.callCount())
	}
}

func TestEngineRechecksContinuousOwnerAfterPreMutationRenewal(t *testing.T) {
	rig := newTestRig(t)
	flapping := &afterRenewStore{Store: rig.memory, target: 2}
	engine := rig.engine("controller-a", flapping)
	flapping.after = func() {
		rig.publishOwner("node-a")
		rig.publishOwner("node-b")
	}
	rig.initializeLeader(engine)
	state := prepareConvergingIntent(t, rig, engine, "node-b", rig.topology.Policy.FailoverStability.Duration())
	state = reconcileOneRoute(t, engine, state)
	if rig.routes.callCount() != 1 {
		t.Fatalf("partial calls = %d, want 1", rig.routes.callCount())
	}

	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("renewal flap reconcile: %v", err)
	}
	current := rig.state()
	if current.Phase != model.PhaseRoutesConverging || !current.Intent.Progress[1].Attempted() || current.Intent.Progress[1].Completed() || rig.routes.callCount() != 1 {
		t.Fatalf("renewal flap reached route mutation: state=%+v calls=%d", current, rig.routes.callCount())
	}
	if engine.Status().Reason != ReasonStabilityWindow {
		t.Fatalf("renewal flap status = %+v", engine.Status())
	}

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("fresh renewal-flap window: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEnginePostIntentFlapUsesDurableFailbackPolicy(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("establish alternate owner: %v", err)
	}
	rig.advanceAndPublish(rig.topology.Policy.Cooldown.Duration(), "node-b")

	state := prepareConvergingIntent(t, rig, engine, "node-a", rig.topology.Policy.FailbackStability.Duration())
	state = reconcileOneRoute(t, engine, state)
	partialCalls := rig.routes.callCount()
	rig.advanceAndPublish(time.Millisecond, "node-b")
	rig.publishOwner("node-a")
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("short post-flap failback window: %v", err)
	}
	if rig.routes.callCount() != partialCalls || engine.Status().Reason != ReasonStabilityWindow {
		t.Fatalf("failback used failover window: calls=%d want=%d status=%+v", rig.routes.callCount(), partialCalls, engine.Status())
	}

	rig.advanceAndPublish(rig.topology.Policy.FailbackStability.Duration()-rig.topology.Policy.FailoverStability.Duration(), "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("full post-flap failback window: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
}

func TestEngineEnforcesCooldownBeforeFailback(t *testing.T) {
	rig := newTestRig(t, func(policy *config.Policy) {
		policy.Cooldown = config.Duration(2 * time.Second)
	})
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(300*time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	failoverCalls := rig.routes.callCount()

	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(700*time.Millisecond, "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.state().Phase != model.PhaseOwnerObserved || rig.routes.callCount() != failoverCalls || engine.Status().Reason != ReasonCooldown {
		t.Fatalf("cooldown did not stop failback: state=%+v status=%+v", rig.state(), engine.Status())
	}
	rig.advanceAndPublish(1300*time.Millisecond, "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
}

func TestEngineLeaseContentionReturnsUntilUnchangedDurationElapses(t *testing.T) {
	rig := newTestRig(t)
	leader := rig.engine("controller-a", nil)
	rig.initializeLeader(leader)
	initialLease := rig.state().Lease.Clone()
	contender := rig.engine("controller-b", nil)

	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe contention: %v", err)
	}
	if contender.Status().Role != RoleFollower || contender.Status().Reason != ReasonLeaseHeld {
		t.Fatalf("contender status = %+v", contender.Status())
	}
	if rig.clock.PendingTimers() != 0 {
		t.Fatalf("contender registered %d blocking timers", rig.clock.PendingTimers())
	}
	observation := contender.takeoverObservation
	if observation.holderID != initialLease.HolderID || observation.recordVersion != initialLease.RecordVersion ||
		!observation.eligibleAt.Equal(rig.clock.Now().Add(rig.topology.Policy.LeaseDuration.Duration())) {
		t.Fatalf("takeover observation = %+v, lease = %+v", observation, initialLease)
	}
	rig.clock.Advance(rig.topology.Policy.LeaseDuration.Duration() - time.Nanosecond)
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("early contention check: %v", err)
	}
	if state := rig.state(); state.Lease.HolderID != "controller-a" || state.Lease.RecordVersion != initialLease.RecordVersion {
		t.Fatalf("lease was taken before a full unchanged duration: %+v", state.Lease)
	}
	rig.clock.Advance(time.Nanosecond)
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("contender takeover: %v", err)
	}
	state := rig.state()
	if state.Lease.HolderID != "controller-b" || state.Lease.FenceTerm <= initialLease.FenceTerm || state.Lease.RecordVersion <= initialLease.RecordVersion {
		t.Fatalf("takeover lease = %+v, initial = %+v", state.Lease, initialLease)
	}
	if contender.Status().Role != RoleLeader {
		t.Fatalf("contender status = %+v", contender.Status())
	}
	if contender.takeoverObservation != (leaseTakeoverObservation{}) {
		t.Fatalf("successful acquisition retained takeover observation: %+v", contender.takeoverObservation)
	}
}

func TestEngineContenderRejectsChangedLeaseVersion(t *testing.T) {
	rig := newTestRig(t)
	leader := rig.engine("controller-a", nil)
	rig.initializeLeader(leader)
	contender := rig.engine("controller-b", nil)
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe initial lease: %v", err)
	}
	initialDeadline := contender.takeoverObservation.eligibleAt

	rig.clock.Advance(rig.topology.Policy.LeaseRenewInterval.Duration())
	rig.publishOwner("node-a")
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatalf("leader renewal: %v", err)
	}
	renewedVersion := rig.state().Lease.RecordVersion
	rig.clock.Advance(rig.topology.Policy.LeaseDuration.Duration() - rig.topology.Policy.LeaseRenewInterval.Duration())
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("contender result: %v", err)
	}
	state := rig.state()
	if state.Lease.HolderID != "controller-a" || state.Lease.RecordVersion != renewedVersion {
		t.Fatalf("changed lease was taken over: %+v", state.Lease)
	}
	if contender.Status().Reason != ReasonLeaseChanged {
		t.Fatalf("contender status = %+v", contender.Status())
	}
	if contender.takeoverObservation.recordVersion != renewedVersion || !contender.takeoverObservation.eligibleAt.After(initialDeadline) ||
		!contender.takeoverObservation.eligibleAt.Equal(rig.clock.Now().Add(rig.topology.Policy.LeaseDuration.Duration())) {
		t.Fatalf("changed lease did not reset takeover deadline: %+v", contender.takeoverObservation)
	}
	rig.clock.Advance(rig.topology.Policy.LeaseDuration.Duration() - time.Nanosecond)
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("early renewed-version contention check: %v", err)
	}
	if rig.state().Lease.HolderID != "controller-a" {
		t.Fatal("renewed lease was taken before its own full observation duration")
	}
	rig.clock.Advance(time.Nanosecond)
	if err := contender.Reconcile(context.Background()); err != nil {
		t.Fatalf("renewed-version takeover: %v", err)
	}
	if rig.state().Lease.HolderID != "controller-b" {
		t.Fatalf("unchanged renewed lease was not taken over: %+v", rig.state().Lease)
	}
}

func TestEngineFollowerReportsFreshConsensusRouteAgreement(t *testing.T) {
	rig := newTestRig(t)
	leader := rig.engine("controller-a", nil)
	rig.initializeLeader(leader)
	follower := rig.engine("controller-b", nil)

	if err := follower.Reconcile(context.Background()); err != nil {
		t.Fatalf("record follower lease: %v", err)
	}
	if err := follower.Reconcile(context.Background()); err != nil {
		t.Fatalf("aligned follower inspection: %v", err)
	}
	aligned := follower.Status()
	if aligned.Role != RoleFollower || !aligned.Quorum || aligned.ConsensusOwner != "node-a" || !aligned.RouteAgreement {
		t.Fatalf("aligned follower status = %+v", aligned)
	}

	rig.routes.setTarget(rig.authority.RemotePrefixes[0], "eni-b")
	if err := follower.Reconcile(context.Background()); err != nil {
		t.Fatalf("disagreeing follower inspection: %v", err)
	}
	disagreeing := follower.Status()
	if disagreeing.Role != RoleFollower || !disagreeing.Quorum || disagreeing.ConsensusOwner != "node-a" || disagreeing.RouteAgreement {
		t.Fatalf("disagreeing follower status = %+v", disagreeing)
	}
	if rig.routes.callCount() != 0 || rig.state().Lease.HolderID != "controller-a" {
		t.Fatal("follower route inspection mutated authority")
	}
}

func TestEngineRenewsLeaseAndSerializesConcurrentReconcile(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	version := rig.state().Lease.RecordVersion
	rig.advanceAndPublish(rig.topology.Policy.LeaseRenewInterval.Duration(), "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.state().Lease.RecordVersion <= version {
		t.Fatal("lease was not renewed at the configured interval")
	}

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	entered := make(chan struct{})
	block := make(chan struct{})
	rig.routes.mu.Lock()
	rig.routes.entered = entered
	rig.routes.block = block
	rig.routes.mu.Unlock()

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- engine.Reconcile(context.Background()) }()
	<-entered
	go func() { second <- engine.Reconcile(context.Background()) }()
	time.Sleep(10 * time.Millisecond)
	if rig.routes.callCount() != 1 {
		t.Fatalf("concurrent reconciliation reached route controller: calls=%d", rig.routes.callCount())
	}
	close(block)
	if err := <-first; err != nil {
		t.Fatalf("first reconciliation: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second reconciliation: %v", err)
	}
	if rig.routes.maximumConcurrency() != 1 {
		t.Fatalf("route mutation concurrency = %d", rig.routes.maximumConcurrency())
	}
}

func TestEngineCrashRecoveryAfterEveryCASCheckpoint(t *testing.T) {
	const checkpoints = 8
	for checkpoint := 1; checkpoint <= checkpoints; checkpoint++ {
		t.Run(string(rune('0'+checkpoint)), func(t *testing.T) {
			rig := newTestRig(t)
			crashing := &crashAfterCASStore{Store: rig.memory, target: checkpoint}
			rig.createInitial()
			engine := rig.engine("controller-a", crashing)
			rig.publishOwner("node-a")
			if err := engine.Reconcile(context.Background()); err != nil {
				t.Fatalf("initialize: %v", err)
			}
			rig.publishOwner("node-b")
			err := engine.Reconcile(context.Background())
			if checkpoint > 1 && err != nil {
				t.Fatalf("initial owner observation: %v", err)
			}
			rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
			if err == nil {
				err = engine.Reconcile(context.Background())
			}
			if !errors.Is(err, errInjectedCrash) || !crashing.triggered {
				t.Fatalf("checkpoint %d error/trigger = %v/%v", checkpoint, err, crashing.triggered)
			}

			restarted := rig.engine("controller-a", rig.memory)
			if err := restarted.Reconcile(context.Background()); err != nil {
				t.Fatalf("restart checkpoint %d: %v", checkpoint, err)
			}
			requireState(t, rig.state(), model.PhaseStable, "node-b")
			if got, want := rig.routes.callCount(), len(rig.authority.RemotePrefixes); got != want {
				t.Fatalf("checkpoint %d replayed or omitted a route call: got %d want %d", checkpoint, got, want)
			}
		})
	}
}

func TestEngineLeaseLossBeforeEveryCASCheckpoint(t *testing.T) {
	const checkpoints = 8
	for checkpoint := 1; checkpoint <= checkpoints; checkpoint++ {
		t.Run(string(rune('0'+checkpoint)), func(t *testing.T) {
			rig := newTestRig(t)
			losing := &loseBeforeCASStore{
				Store:     rig.memory,
				clock:     rig.clock,
				duration:  rig.topology.Policy.LeaseDuration.Duration(),
				target:    checkpoint,
				newHolder: "controller-b",
			}
			engine := rig.engine("controller-a", losing)
			rig.createInitial()
			rig.publishOwner("node-a")
			if err := engine.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			rig.publishOwner("node-b")
			err := engine.Reconcile(context.Background())
			if checkpoint > 1 && err != nil {
				t.Fatalf("owner observation: %v", err)
			}
			if err == nil {
				rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
				err = engine.Reconcile(context.Background())
			}
			if !errors.Is(err, store.ErrLeaseLost) || !losing.triggered {
				t.Fatalf("checkpoint %d error/trigger = %v/%v", checkpoint, err, losing.triggered)
			}
			callsAtLoss := rig.routes.callCount()
			if rig.state().Lease.HolderID != "controller-b" {
				t.Fatalf("checkpoint %d holder = %s", checkpoint, rig.state().Lease.HolderID)
			}
			// The stale engine strongly reloads the new holder, records a takeover
			// deadline, and returns without performing follower mutations.
			if err := engine.Reconcile(context.Background()); err != nil {
				t.Fatalf("stale follower reconcile = %v", err)
			}
			if rig.routes.callCount() != callsAtLoss {
				t.Fatal("stale holder performed a route call after lease loss")
			}
			if rig.clock.PendingTimers() != 0 {
				t.Fatalf("stale follower registered %d blocking timers", rig.clock.PendingTimers())
			}

			successor := rig.engine("controller-b", losing)
			if err := successor.Reconcile(context.Background()); err != nil {
				t.Fatalf("successor recovery: %v", err)
			}
			if rig.state().Phase == model.PhaseOwnerObserved {
				rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
				if err := successor.Reconcile(context.Background()); err != nil {
					t.Fatalf("successor stability recovery: %v", err)
				}
			}
			requireState(t, rig.state(), model.PhaseStable, "node-b")
		})
	}
}

func TestEngineLosesLeaseOnImmediatePreMutationRenewal(t *testing.T) {
	rig := newTestRig(t)
	rig.createInitial()
	losing := &loseOnRenewStore{
		Store:     rig.memory,
		clock:     rig.clock,
		duration:  rig.topology.Policy.LeaseDuration.Duration(),
		target:    2,
		newHolder: "controller-b",
	}
	engine := rig.engine("controller-a", losing)
	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	err := engine.Reconcile(context.Background())
	if !errors.Is(err, store.ErrLeaseLost) || !losing.triggered {
		t.Fatalf("pre-mutation renewal error/trigger = %v/%v", err, losing.triggered)
	}
	if rig.routes.callCount() != 0 {
		t.Fatalf("route call began after failed immediate renewal: %d", rig.routes.callCount())
	}
	state := rig.state()
	if state.Lease.HolderID != "controller-b" || state.Phase != model.PhaseRoutesConverging || !state.Intent.Progress[0].Attempted() {
		t.Fatalf("durable checkpoint after lease loss = %+v", state)
	}
}

func TestEngineSuccessorPersistsCurrentFenceBeforeRouteCall(t *testing.T) {
	rig := newTestRig(t)
	leader := rig.engine("controller-a", nil)
	rig.initializeLeader(leader)
	rig.publishOwner("node-b")
	if err := leader.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")

	state, advanced, err := leader.reconcileObserved(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseRouteIntentPersisted {
		t.Fatalf("persist intent: state=%+v advanced=%v err=%v", state, advanced, err)
	}
	state, advanced, err = leader.reconcileIntent(context.Background(), state)
	if err != nil || !advanced || state.Phase != model.PhaseRoutesConverging || state.Intent.FenceTerm != 1 {
		t.Fatalf("prepare converging intent: state=%+v advanced=%v err=%v", state, advanced, err)
	}

	entered := make(chan struct{})
	block := make(chan struct{})
	rig.routes.mu.Lock()
	rig.routes.entered = entered
	rig.routes.block = block
	rig.routes.mu.Unlock()
	successor := rig.engine("controller-b", nil)
	if err := successor.Reconcile(context.Background()); err != nil {
		t.Fatalf("successor observation: %v", err)
	}
	rig.clock.Advance(rig.topology.Policy.LeaseDuration.Duration())
	result := make(chan error, 1)
	go func() { result <- successor.Reconcile(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("successor did not reach route call")
	}

	claimed := rig.state()
	if claimed.FenceTerm != 2 || claimed.Intent == nil || claimed.Intent.FenceTerm != claimed.FenceTerm || claimed.Lease.HolderID != "controller-b" {
		t.Fatalf("successor called route adapter before persisting its fence: %+v", claimed)
	}
	if calls := rig.routes.callsSnapshot(); len(calls) != 1 || calls[0].expectedPrevious != "eni-a" {
		t.Fatalf("successor route call lost durable previous target: %+v", calls)
	}
	close(block)
	if err := <-result; err != nil {
		t.Fatalf("successor reconciliation: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineStopsMutationInsideLeaseDangerWindow(t *testing.T) {
	rig := newTestRig(t)
	rig.createInitial()
	duration := rig.topology.Policy.LeaseDuration.Duration()
	danger := rig.topology.Policy.LeaseDangerWindow.Duration()
	delayed := &advanceAfterRenewStore{
		Store:   rig.memory,
		clock:   rig.clock,
		target:  2,
		advance: duration - danger,
	}
	engine := rig.engine("controller-a", delayed)
	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err == nil {
		t.Fatal("danger-window reconciliation unexpectedly succeeded")
	}
	state := rig.state()
	if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorLeaseUnsafe || rig.routes.callCount() != 0 {
		t.Fatalf("danger-window state/calls = %+v/%d", state, rig.routes.callCount())
	}
	if engine.Status().Reason != ReasonLeaseUnsafe {
		t.Fatalf("danger-window status = %+v", engine.Status())
	}
}

func TestEngineObserverSplitDegradesAndRecovers(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishViews(map[string]string{
		"controller-a": "node-a",
		"controller-b": "node-b",
		"controller-c": "node-b",
	})
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("split observation: %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorObservationQuorum || rig.routes.callCount() != 0 {
		t.Fatalf("split state/calls = %+v/%d", state, rig.routes.callCount())
	}
	if engine.Status().Reason != ReasonObservationDisagreement {
		t.Fatalf("split status = %+v", engine.Status())
	}

	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("recover split: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
}

func TestEngineIntentFreeDegradedObservesChangedConsensusAfterStableReadback(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishViews(map[string]string{
		"controller-a": "node-a",
		"controller-b": "node-b",
		"controller-c": "node-b",
	})
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("degrade split observation: %v", err)
	}
	requireState(t, rig.state(), model.PhaseDegraded, "node-a")

	rig.publishOwner("node-b")
	stableTargets := map[string]string{
		rig.authority.RemotePrefixes[0]: "eni-a",
		rig.authority.RemotePrefixes[1]: "eni-a",
	}
	changedTargets := map[string]string{
		rig.authority.RemotePrefixes[0]: "eni-b",
		rig.authority.RemotePrefixes[1]: "eni-b",
	}
	rig.routes.queueSnapshotTargets(stableTargets, changedTargets)
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("unstable degraded readback: %v", err)
	}
	if state := rig.state(); state.Phase != model.PhaseDegraded || rig.routes.callCount() != 0 || engine.Status().Reason != ReasonRouteOscillation {
		t.Fatalf("one route read recovered degraded state: state=%+v calls=%d status=%+v", state, rig.routes.callCount(), engine.Status())
	}

	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe changed consensus: %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseOwnerObserved || state.StableOwner != "node-a" || state.ObservedOwner != "node-b" || state.OwnerObservedAt == nil {
		t.Fatalf("intent-free degraded recovery wedged: %+v", state)
	}
	if rig.routes.callCount() != 0 {
		t.Fatal("owner observation mutated a route")
	}

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("complete failover after degraded recovery: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineDegradedPartialIntentResumesAfterEligibilityReturns(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.routes.mu.Lock()
	rig.routes.ownerErrorAfterCall = 1
	rig.routes.ownerErrorsAfterCall["node-b"] = &awscontrol.IneligibleError{Resource: "i-b", Check: "status", Expected: "ok", Observed: "impaired"}
	rig.routes.mu.Unlock()
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); !errors.Is(err, awscontrol.ErrOwnerIneligible) {
		t.Fatalf("partial eligibility loss = %v, want ineligible", err)
	}
	partial := rig.state()
	if partial.Phase != model.PhaseDegraded || partial.Intent == nil || !partial.Intent.Progress[0].Completed() || partial.Intent.Progress[1].Attempted() || rig.routes.callCount() != 1 {
		t.Fatalf("partial intent was not durable: state=%+v calls=%d", partial, rig.routes.callCount())
	}

	rig.routes.mu.Lock()
	rig.routes.ownerErrorAfterCall = 0
	delete(rig.routes.ownerErrorsAfterCall, "node-b")
	rig.routes.mu.Unlock()
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("resume partial intent: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
	if calls := rig.routes.callsSnapshot(); len(calls) != 2 || calls[0].prefix == calls[1].prefix || calls[1].expectedPrevious != "eni-a" {
		t.Fatalf("partial recovery replayed or lost durable before-image: %+v", calls)
	}
}

func TestEngineDegradedMixedRouteReversalSupersedesStableIntent(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	state := prepareConvergingIntent(t, rig, engine, "node-b", rig.topology.Policy.FailoverStability.Duration())
	state = reconcileOneRoute(t, engine, state)
	oldTransaction := state.Intent.TransactionID
	mixedTargets := map[string]string{
		rig.authority.RemotePrefixes[0]: "eni-b",
		rig.authority.RemotePrefixes[1]: "eni-a",
	}

	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err == nil {
		t.Fatal("owner reversal did not interrupt the old intent")
	}
	degraded := rig.state()
	if degraded.Phase != model.PhaseDegraded || degraded.Intent == nil || degraded.Intent.TransactionID != oldTransaction || rig.routes.callCount() != 1 {
		t.Fatalf("reversal did not preserve partial intent: state=%+v calls=%d", degraded, rig.routes.callCount())
	}

	rig.routes.queueSnapshotTargets(mixedTargets, map[string]string{
		rig.authority.RemotePrefixes[0]: "eni-a",
		rig.authority.RemotePrefixes[1]: "eni-a",
	})
	state, advanced, err := engine.reconcileDegraded(context.Background(), rig.state())
	if err != nil || advanced || state.Intent == nil || state.Intent.TransactionID != oldTransaction || rig.routes.callCount() != 1 {
		t.Fatalf("ambiguous readback superseded intent: state=%+v advanced=%v calls=%d err=%v", state, advanced, rig.routes.callCount(), err)
	}
	if engine.Status().Reason != ReasonRouteOscillation {
		t.Fatalf("ambiguous reversal status = %+v", engine.Status())
	}

	state, advanced, err = engine.reconcileDegraded(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseOwnerObserved || state.Intent != nil || state.ObservedOwner != "node-a" || state.OwnerObservedAt == nil {
		t.Fatalf("durably observe stable reversal snapshot: state=%+v advanced=%v err=%v", state, advanced, err)
	}
	observedAt := *state.OwnerObservedAt
	if rig.routes.callCount() != 1 {
		t.Fatal("durably observing the reversed owner mutated a route")
	}
	engine = rig.engine("controller-a", nil)

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration()-time.Millisecond, "node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("early reversal recovery: %v", err)
	}
	if current := rig.state(); current.Phase != model.PhaseOwnerObserved || current.Intent != nil || !current.OwnerObservedAt.Equal(observedAt) || rig.routes.callCount() != 1 {
		t.Fatalf("reversal mutated or superseded before stability: state=%+v calls=%d", current, rig.routes.callCount())
	}
	rig.advanceAndPublish(time.Millisecond, "node-a")
	state, advanced, err = engine.reconcileObserved(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseRouteIntentPersisted || state.Intent == nil {
		t.Fatalf("stable reversal supersession: state=%+v advanced=%v err=%v", state, advanced, err)
	}
	if state.Intent.TransactionID == oldTransaction || state.Intent.DesiredOwner != "node-a" || state.Intent.FenceTerm != state.FenceTerm || state.ObservedOwner != "node-a" || state.OwnerObservedAt == nil {
		t.Fatalf("new reversal intent was not freshly fenced and observed: %+v", state)
	}
	for _, progress := range state.Intent.Progress {
		if progress.Attempted() || progress.Completed() {
			t.Fatalf("superseding intent adopted old progress: %+v", state.Intent.Progress)
		}
	}
	for prefix, target := range mixedTargets {
		route, found := snapshotRoute(state.Intent.Before, prefix)
		if !found || route.TargetENIID != target {
			t.Fatalf("superseding before-image lost mixed route %s=%s: %+v", prefix, target, state.Intent.Before)
		}
	}
	if rig.routes.callCount() != 1 {
		t.Fatal("intent supersession mutated a route")
	}

	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile superseding intent: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
	if calls := rig.routes.callsSnapshot(); len(calls) != 2 || calls[1].prefix != calls[0].prefix || calls[1].desiredENI != "eni-a" || calls[1].expectedPrevious != "eni-b" {
		t.Fatalf("mixed reversal calls = %+v", calls)
	}
}

func TestEngineDegradedMixedFailbackReversalUsesFailoverWindow(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("establish alternate owner: %v", err)
	}
	rig.advanceAndPublish(rig.topology.Policy.Cooldown.Duration(), "node-b")

	state := prepareConvergingIntent(t, rig, engine, "node-a", rig.topology.Policy.FailbackStability.Duration())
	state = reconcileOneRoute(t, engine, state)
	oldTransaction := state.Intent.TransactionID
	baselineCalls := rig.routes.callCount()
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err == nil {
		t.Fatal("failback reversal did not interrupt the old intent")
	}
	state, advanced, err := engine.reconcileDegraded(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseOwnerObserved || state.Intent != nil || state.ObservedOwner != "node-b" || state.OwnerObservedAt == nil {
		t.Fatalf("durably observe failback reversal: state=%+v advanced=%v err=%v", state, advanced, err)
	}
	if rig.topology.Policy.FailoverStability.Duration() >= rig.topology.Policy.FailbackStability.Duration() {
		t.Fatal("fixture does not prove the shorter durable-owner failover policy")
	}
	if rig.routes.callCount() != baselineCalls {
		t.Fatal("failback reversal mutated while being observed")
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration()-time.Millisecond, "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("early failback reversal recovery: %v", err)
	}
	if current := rig.state(); current.Phase != model.PhaseOwnerObserved || current.Intent != nil || rig.routes.callCount() != baselineCalls {
		t.Fatalf("failback reversal bypassed stability: state=%+v calls=%d", current, rig.routes.callCount())
	}
	rig.advanceAndPublish(time.Millisecond, "node-b")
	state, advanced, err = engine.reconcileObserved(context.Background(), rig.state())
	if err != nil || !advanced || state.Intent == nil || state.Intent.TransactionID == oldTransaction || state.Intent.DesiredOwner != "node-b" {
		t.Fatalf("failback reversal supersession: state=%+v advanced=%v err=%v", state, advanced, err)
	}
	if rig.routes.callCount() != baselineCalls {
		t.Fatal("failback reversal mutated while superseding")
	}

	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("complete failback reversal: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
	if calls := rig.routes.callsSnapshot(); len(calls) != baselineCalls+1 || calls[len(calls)-1].desiredENI != "eni-b" || calls[len(calls)-1].expectedPrevious != "eni-a" {
		t.Fatalf("failback reversal calls = %+v", calls)
	}
}

func TestEngineReversalRecoveryFollowsLatestStableTailnetOwner(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	state := prepareConvergingIntent(t, rig, engine, "node-b", rig.topology.Policy.FailoverStability.Duration())
	_ = reconcileOneRoute(t, engine, state)

	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err == nil {
		t.Fatal("owner reversal did not interrupt the old intent")
	}
	state, advanced, err := engine.reconcileDegraded(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseOwnerObserved || state.ObservedOwner != "node-a" || state.Intent != nil {
		t.Fatalf("observe reversed owner: state=%+v advanced=%v err=%v", state, advanced, err)
	}

	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe latest Tailnet owner: %v", err)
	}
	state = rig.state()
	if state.Phase != model.PhaseOwnerObserved || state.ObservedOwner != "node-b" || state.Intent != nil || rig.routes.callCount() != 1 {
		t.Fatalf("latest owner caused premature rollback: state=%+v calls=%d", state, rig.routes.callCount())
	}
	for _, call := range rig.routes.callsSnapshot() {
		if call.desiredENI != "eni-b" {
			t.Fatalf("route rolled toward unselected owner: %+v", call)
		}
	}

	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("converge latest Tailnet owner: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
	if calls := rig.routes.callsSnapshot(); len(calls) != len(rig.authority.RemotePrefixes) {
		t.Fatalf("latest-owner route calls = %+v", calls)
	} else {
		for _, call := range calls {
			if call.desiredENI != "eni-b" {
				t.Fatalf("route rolled toward unselected owner: %+v", call)
			}
		}
	}
}

func TestEngineStaleObservationsDegradeWithSpecificReason(t *testing.T) {
	rig := newTestRig(t, func(policy *config.Policy) {
		policy.ObservationFreshness = config.Duration(400 * time.Millisecond)
	})
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.clock.Advance(rig.topology.Policy.ObservationFreshness.Duration())
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("stale observation reconciliation: %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorObservationQuorum || engine.Status().Reason != ReasonObservationStale {
		t.Fatalf("stale observation state/status = %+v/%+v", state, engine.Status())
	}
	if rig.routes.callCount() != 0 {
		t.Fatal("stale observations authorized a route mutation")
	}
}

func TestEngineIneligibleOwnerDegradesWithoutMutation(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.routes.mu.Lock()
	rig.routes.ownerErrors["node-b"] = &awscontrol.IneligibleError{Resource: "i-b", Check: "status", Expected: "ok", Observed: "impaired"}
	rig.routes.mu.Unlock()
	rig.publishOwner("node-b")
	err := engine.Reconcile(context.Background())
	if !errors.Is(err, awscontrol.ErrOwnerIneligible) {
		t.Fatalf("ineligible error = %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorOwnerIneligible || rig.routes.callCount() != 0 {
		t.Fatalf("ineligible state/calls = %+v/%d", state, rig.routes.callCount())
	}

	rig.routes.mu.Lock()
	delete(rig.routes.ownerErrors, "node-b")
	rig.routes.mu.Unlock()
	rig.publishOwner("node-a")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("recover eligibility: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-a")
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe owner after eligibility recovery: %v", err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("complete recovered failover: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineAmbiguousCallRecoversFromStablePreviousReadback(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.routes.mu.Lock()
	rig.routes.replaceErrAt = 1
	rig.routes.replaceErr = &awscontrol.AmbiguousError{
		DestinationPrefix: rig.authority.RemotePrefixes[0],
		PreviousENIID:     "eni-a",
		DesiredENIID:      "eni-b",
		Reason:            "injected timeout",
		CallFailed:        true,
	}
	rig.routes.mu.Unlock()
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	err := engine.Reconcile(context.Background())
	if !errors.Is(err, awscontrol.ErrAmbiguous) {
		t.Fatalf("ambiguous route error = %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorRouteAmbiguous || !state.Intent.Progress[0].Ambiguous {
		t.Fatalf("ambiguous durable state = %+v", state)
	}
	calls := rig.routes.callCount()
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("authoritative previous recovery: %v", err)
	}
	if rig.routes.callCount() != calls+len(rig.authority.RemotePrefixes) || rig.state().Phase != model.PhaseStable {
		t.Fatalf("ambiguous settlement did not resume: state/calls = %+v/%d", rig.state(), rig.routes.callCount())
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineDurablyRecordsPreviousSettlementBeforeRetry(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.routes.mu.Lock()
	rig.routes.replaceErrAt = 1
	rig.routes.settlePreviousAt = 1
	rig.routes.replaceErr = &awscontrol.AmbiguousError{
		DestinationPrefix: rig.authority.RemotePrefixes[0],
		PreviousENIID:     "eni-a",
		DesiredENIID:      "eni-b",
		Reason:            "injected timeout",
		CallFailed:        true,
	}
	rig.routes.mu.Unlock()
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); !errors.Is(err, awscontrol.ErrAmbiguous) {
		t.Fatalf("previous settlement error = %v, want ambiguous call error", err)
	}
	settled := rig.state()
	progress := settled.Intent.Progress[0]
	if settled.Phase != model.PhaseRoutesConverging || settled.Error != nil || !progress.Attempted() || progress.Completed() || progress.ObservedENIID != "eni-a" || progress.Error == nil {
		t.Fatalf("previous settlement was not durably recorded: %+v", settled)
	}

	rig.routes.mu.Lock()
	rig.routes.replaceErrAt = 0
	rig.routes.settlePreviousAt = 0
	rig.routes.replaceErr = nil
	rig.routes.mu.Unlock()
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("retry previous settlement: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
	if calls := rig.routes.callsSnapshot(); len(calls) != 3 || calls[1].prefix != calls[0].prefix || calls[1].expectedPrevious != "eni-a" {
		t.Fatalf("previous settlement retry did not preserve intent: %+v", calls)
	}
}

func TestEngineSettlesAmbiguousSuccessfulCall(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.routes.mu.Lock()
	rig.routes.ambiguousOK[1] = true
	rig.routes.mu.Unlock()
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(rig.topology.Policy.FailoverStability.Duration(), "node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("settled timeout-after-commit: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineRouteDriftAndUnauthorizedSnapshotDegrade(t *testing.T) {
	t.Run("mixed authorized drift", func(t *testing.T) {
		rig := newTestRig(t)
		engine := rig.engine("controller-a", nil)
		rig.initializeLeader(engine)
		rig.routes.setTarget(rig.authority.RemotePrefixes[0], "eni-b")
		if err := engine.Reconcile(context.Background()); err != nil {
			t.Fatalf("route drift: %v", err)
		}
		state := rig.state()
		if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorRouteOscillation || rig.routes.callCount() != 0 {
			t.Fatalf("drift state/calls = %+v/%d", state, rig.routes.callCount())
		}
		rig.routes.setAllTargets(rig.authority, "eni-a")
		if err := engine.Reconcile(context.Background()); err != nil {
			t.Fatalf("route drift recovery: %v", err)
		}
		requireState(t, rig.state(), model.PhaseStable, "node-a")
	})

	t.Run("unauthorized target", func(t *testing.T) {
		rig := newTestRig(t)
		rig.createInitial()
		engine := rig.engine("controller-a", nil)
		rig.publishOwner("node-a")
		rig.routes.mu.Lock()
		rig.routes.snapshotErr = &awscontrol.UnauthorizedError{DestinationPrefix: rig.authority.RemotePrefixes[0], TargetENIID: "eni-unknown"}
		rig.routes.mu.Unlock()
		err := engine.Reconcile(context.Background())
		if !errors.Is(err, awscontrol.ErrUnauthorized) {
			t.Fatalf("unauthorized snapshot error = %v", err)
		}
		state := rig.state()
		if state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorRouteUnauthorized || rig.routes.callCount() != 0 {
			t.Fatalf("unauthorized state/calls = %+v/%d", state, rig.routes.callCount())
		}
	})
}

func TestEngineOscillatingCallDegrades(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.routes.mu.Lock()
	rig.routes.replaceErrAt = 1
	rig.routes.replaceErr = &awscontrol.OscillationError{DestinationPrefix: rig.authority.RemotePrefixes[0], PreviousENIID: "eni-a", DesiredENIID: "eni-b"}
	rig.routes.mu.Unlock()
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(300*time.Millisecond, "node-b")
	err := engine.Reconcile(context.Background())
	if !errors.Is(err, awscontrol.ErrOscillation) {
		t.Fatalf("oscillation error = %v", err)
	}
	if state := rig.state(); state.Phase != model.PhaseDegraded || state.Error.Code != model.ErrorRouteOscillation {
		t.Fatalf("oscillation state = %+v", state)
	}
	calls := rig.routes.callCount()
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("oscillation hold: %v", err)
	}
	if state := rig.state(); state.Phase != model.PhaseDegraded || rig.routes.callCount() != calls {
		t.Fatalf("oscillating intent resumed automatically: state=%+v calls=%d", state, rig.routes.callCount())
	}
}

func TestEngineReadOnlyAndDryRunNeverMutate(t *testing.T) {
	for _, test := range []struct {
		name   string
		option func(*Options)
		mode   Mode
	}{
		{name: "read-only", option: func(options *Options) { options.ReadOnly = true; options.UUIDs = nil }, mode: ModeReadOnly},
		{name: "dry-run", option: func(options *Options) { options.DryRun = true; options.UUIDs = nil }, mode: ModeDryRun},
	} {
		t.Run(test.name+" missing domain", func(t *testing.T) {
			rig := newTestRig(t)
			engine := rig.engine("controller-a", nil, test.option)
			if err := engine.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := rig.memory.LoadDomain(context.Background(), store.DomainRefFor(rig.authority)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("read-only initialized a domain: %v", err)
			}
			if engine.Status().Mode != test.mode || engine.Status().Reason != ReasonDomainNotInitialized {
				t.Fatalf("read-only missing status = %+v", engine.Status())
			}
		})

		t.Run(test.name+" existing domain", func(t *testing.T) {
			rig := newTestRig(t)
			rig.createInitial()
			rig.publishOwner("node-b")
			engine := rig.engine("controller-a", nil, test.option)
			if err := engine.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := rig.state()
			if state.Revision != 1 || state.Lease != nil || state.Phase != model.PhaseStable || rig.routes.callCount() != 0 {
				t.Fatalf("read-only mutated state/routes: %+v/%d", state, rig.routes.callCount())
			}
			if engine.Status().Role != RoleReadOnly || engine.Status().Mode != test.mode {
				t.Fatalf("read-only status = %+v", engine.Status())
			}
		})
	}
}

func TestEngineReportsStoreAPITimeoutAsUnavailable(t *testing.T) {
	rig := newTestRig(t)
	rig.createInitial()
	timeout := &store.APITimeoutError{Operation: "DynamoDB GetItem"}
	engine := rig.engine("controller-a", observationFailureStore{Store: rig.memory, err: timeout})

	err := engine.Reconcile(context.Background())
	if !errors.Is(err, store.ErrAPITimeout) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reconcile() error = %v, want store-local API timeout", err)
	}
	status := engine.Status()
	if status.Role != RoleUnknown || status.Reason != ReasonStoreUnavailable {
		t.Fatalf("store API timeout status = %+v", status)
	}
}

func TestEngineCancellationStopsWaitAndRunLoop(t *testing.T) {
	t.Run("lease contention", func(t *testing.T) {
		rig := newTestRig(t)
		leader := rig.engine("controller-a", nil)
		rig.initializeLeader(leader)
		contender := rig.engine("controller-b", nil)
		if err := contender.Reconcile(context.Background()); err != nil {
			t.Fatalf("observe contention: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := contender.Reconcile(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled contention = %v", err)
		}
		if rig.clock.PendingTimers() != 0 {
			t.Fatalf("contender registered %d blocking timers", rig.clock.PendingTimers())
		}
		if rig.state().Lease.HolderID != "controller-a" || rig.routes.callCount() != 0 {
			t.Fatal("canceled contender changed authority")
		}
	})

	t.Run("run loop", func(t *testing.T) {
		rig := newTestRig(t)
		rig.publishOwner("node-a")
		engine := rig.engine("controller-a", nil)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- engine.Run(ctx) }()
		waitForTimers(t, rig.clock, 1)
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Run cancellation = %v", err)
		}
		if engine.Status().Reason != ReasonCanceled {
			t.Fatalf("canceled run status = %+v", engine.Status())
		}
	})
}

func TestEngineCancellationAfterAttemptRecoversWithoutBlindReplay(t *testing.T) {
	rig := newTestRig(t)
	engine := rig.engine("controller-a", nil)
	rig.initializeLeader(engine)
	rig.publishOwner("node-b")
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.advanceAndPublish(300*time.Millisecond, "node-b")
	entered := make(chan struct{})
	block := make(chan struct{})
	rig.routes.mu.Lock()
	rig.routes.entered = entered
	rig.routes.block = block
	rig.routes.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- engine.Reconcile(ctx) }()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("route cancellation = %v", err)
	}
	state := rig.state()
	if state.Phase != model.PhaseRoutesConverging || !state.Intent.Progress[0].Attempted() || state.Intent.Progress[0].Completed() {
		t.Fatalf("canceled route checkpoint = %+v", state)
	}
	close(block)
	rig.routes.mu.Lock()
	rig.routes.block = nil
	rig.routes.mu.Unlock()
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("restart attempted route: %v", err)
	}
	requireState(t, rig.state(), model.PhaseStable, "node-b")
}

func TestEngineStatusCallbackIsReentrantAndConcurrencySafe(t *testing.T) {
	rig := newTestRig(t)
	rig.createInitial()
	var engine *Engine
	var mu sync.Mutex
	callbacks := 0
	engine = rig.engine("controller-a", nil, func(options *Options) {
		options.StatusCallback = func(status Status) {
			assertOnlyBoundedStatus(t, status)
			_ = engine.Status()
			mu.Lock()
			callbacks++
			mu.Unlock()
		}
	})
	rig.publishOwner("node-a")
	var readers sync.WaitGroup
	for range 16 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				assertOnlyBoundedStatus(t, engine.Status())
			}
		}()
	}
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	engine.SetStatusCallback(func(status Status) { _ = engine.Status() })
	mu.Lock()
	count := callbacks
	mu.Unlock()
	if count == 0 {
		t.Fatal("status callback was not invoked")
	}
}

func TestActiveEngineCannotInitializeMissingJournal(t *testing.T) {
	rig := newTestRig(t)
	rig.publishOwner("node-b")
	rig.routes.setAllTargets(rig.authority, "eni-b")
	engine := rig.engine("controller-a", nil)
	if err := engine.Reconcile(context.Background()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing journal error = %v", err)
	}
	if _, err := rig.memory.LoadDomain(context.Background(), store.DomainRefFor(rig.authority)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("active engine created a journal: %v", err)
	}
	if rig.routes.callCount() != 0 || engine.Status().Reason != ReasonDomainNotInitialized {
		t.Fatalf("missing journal did not fail closed: %+v", engine.Status())
	}
}

func TestActiveEngineCannotAcquireInactiveJournal(t *testing.T) {
	rig := newTestRig(t)
	now := rig.clock.Now()
	initial := &model.DomainState{Authority: rig.authority, Revision: 1, Phase: model.PhaseStable,
		StableOwner: rig.authority.PreferredOwner, LastTransitionAt: now, UpdatedAt: now}
	if _, err := rig.memory.CreateDomain(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	rig.publishOwner("node-b")
	engine := rig.engine("controller-a", nil)
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := rig.state(); state.Lease != nil || state.Revision != 1 || state.Activated || state.Intent != nil || state.StableOwner != initial.StableOwner {
		t.Fatalf("inactive journal changed: %+v", state)
	}
	if rig.routes.callCount() != 0 || engine.Status().Reason != ReasonDomainNotActivated {
		t.Fatalf("inactive journal did not fail closed: %+v", engine.Status())
	}
}

func TestNewEngineRejectsInvalidDependencies(t *testing.T) {
	rig := newTestRig(t)
	valid := Options{
		Topology:     rig.topology,
		DomainID:     rig.authority.DomainID,
		ControllerID: "controller-a",
		Store:        rig.memory,
		Routes:       rig.routes,
		Clock:        rig.clock,
		UUIDs:        rig.uuids,
	}
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "nil topology", mutate: func(options *Options) { options.Topology = nil }},
		{name: "unknown controller", mutate: func(options *Options) { options.ControllerID = "controller-x" }},
		{name: "unknown domain", mutate: func(options *Options) { options.DomainID = "domain-x" }},
		{name: "nil store", mutate: func(options *Options) { options.Store = nil }},
		{name: "nil routes", mutate: func(options *Options) { options.Routes = nil }},
		{name: "nil clock", mutate: func(options *Options) { options.Clock = nil }},
		{name: "nil UUIDs", mutate: func(options *Options) { options.UUIDs = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := NewEngine(options); err == nil {
				t.Fatal("NewEngine unexpectedly succeeded")
			}
		})
	}
}

func prepareConvergingIntent(t *testing.T, rig *testRig, engine *Engine, owner string, window time.Duration) *model.DomainState {
	t.Helper()
	rig.publishOwner(owner)
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("observe %s: %v", owner, err)
	}
	rig.advanceAndPublish(window, owner)
	state, advanced, err := engine.reconcileObserved(context.Background(), rig.state())
	if err != nil || !advanced || state.Phase != model.PhaseRouteIntentPersisted {
		t.Fatalf("persist %s intent: state=%+v advanced=%v err=%v", owner, state, advanced, err)
	}
	state, advanced, err = engine.reconcileIntent(context.Background(), state)
	if err != nil || !advanced || state.Phase != model.PhaseRoutesConverging {
		t.Fatalf("prepare %s intent: state=%+v advanced=%v err=%v", owner, state, advanced, err)
	}
	return state
}

func reconcileOneRoute(t *testing.T, engine *Engine, state *model.DomainState) *model.DomainState {
	t.Helper()
	next, advanced, err := engine.reconcileRoutes(context.Background(), state)
	if err != nil || !advanced || next.Phase != model.PhaseRoutesConverging || next.Intent == nil || !next.Intent.Progress[0].Completed() {
		t.Fatalf("reconcile one route: state=%+v advanced=%v err=%v", next, advanced, err)
	}
	return next
}
