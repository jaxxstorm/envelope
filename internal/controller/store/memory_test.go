package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

var (
	testTime     = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	topologyHash = strings.Repeat("a", 64)
	otherHash    = strings.Repeat("b", 64)
)

func TestMemoryStoreConditionalCreateAndStrongCloneLoad(t *testing.T) {
	memory := newMemoryStore(t, store.NewFakeClock(testTime))
	initial := validInitialState()
	want := initial.Clone()

	created, err := memory.CreateDomain(context.Background(), &initial)
	if err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}
	initial.Authority.RemotePrefixes[0] = "192.0.2.0/24"
	created.Authority.Owners[0].ENIID = "eni-mutated"

	loaded, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("LoadDomain() = %#v, want %#v", loaded, want)
	}
	loaded.Authority.RemotePrefixes[0] = "198.51.100.0/24"
	reloaded, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("second LoadDomain() error = %v", err)
	}
	if !reflect.DeepEqual(reloaded, want) {
		t.Fatal("LoadDomain() returned storage shared with a previous result")
	}

	duplicate := validInitialState()
	_, err = memory.CreateDomain(context.Background(), &duplicate)
	requireTypedError[*store.ConflictError](t, err, store.ErrConflict)

	differentTopology := validInitialState()
	differentTopology.Authority.TopologyHash = otherHash
	_, err = memory.CreateDomain(context.Background(), &differentTopology)
	requireTypedError[*store.TopologyMismatchError](t, err, store.ErrTopologyMismatch)

	wrongRef := domainRef()
	wrongRef.TopologyHash = otherHash
	_, err = memory.LoadDomain(context.Background(), wrongRef)
	requireTypedError[*store.TopologyMismatchError](t, err, store.ErrTopologyMismatch)

	missingRef := domainRef()
	missingRef.DomainID = "missing"
	_, err = memory.LoadDomain(context.Background(), missingRef)
	requireTypedError[*store.NotFoundError](t, err, store.ErrNotFound)
}

func TestMemoryStoreLeaseLifecycle(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	createDomain(t, memory)
	ctx := context.Background()
	duration := time.Minute

	lease, err := memory.AcquireLease(ctx, domainRef(), "controller-a", duration)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	if lease.HolderID != "controller-a" || lease.FenceTerm != 1 || lease.RecordVersion != 1 {
		t.Fatalf("AcquireLease() = %#v", lease)
	}
	if !lease.AcquiredAt.Equal(testTime) || !lease.ExpiresAt.Equal(testTime.Add(duration)) {
		t.Fatalf("AcquireLease() timestamps = %#v", lease)
	}

	_, err = memory.AcquireLease(ctx, domainRef(), "controller-b", duration)
	held := requireTypedError[*store.LeaseHeldError](t, err, store.ErrLeaseHeld)
	if held.Lease == nil || held.Lease.RecordVersion != 1 {
		t.Fatalf("LeaseHeldError.Lease = %#v", held.Lease)
	}
	held.Lease.HolderID = "mutated"

	clock.Advance(10 * time.Second)
	renewed, err := memory.RenewLease(ctx, domainRef(), store.LeaseTokenFor(lease), duration)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if renewed.FenceTerm != lease.FenceTerm || renewed.RecordVersion != lease.RecordVersion+1 {
		t.Fatalf("RenewLease() = %#v, previous = %#v", renewed, lease)
	}
	if !renewed.RenewedAt.Equal(testTime.Add(10*time.Second)) || !renewed.ExpiresAt.Equal(testTime.Add(70*time.Second)) {
		t.Fatalf("RenewLease() timestamps = %#v", renewed)
	}

	_, err = memory.RenewLease(ctx, domainRef(), store.LeaseTokenFor(lease), duration)
	requireTypedError[*store.LeaseLostError](t, err, store.ErrLeaseLost)

	clock.Advance(time.Minute)
	_, err = memory.RenewLease(ctx, domainRef(), store.LeaseTokenFor(renewed), duration)
	requireTypedError[*store.LeaseLostError](t, err, store.ErrLeaseLost)

	taken, err := memory.TakeoverLease(ctx, domainRef(), "controller-b", renewed.RecordVersion, duration)
	if err != nil {
		t.Fatalf("TakeoverLease() error = %v", err)
	}
	if taken.HolderID != "controller-b" || taken.FenceTerm != 2 || taken.RecordVersion != 3 {
		t.Fatalf("TakeoverLease() = %#v", taken)
	}
	renewed.HolderID = "mutated"
	taken.HolderID = "mutated"
	state, err := memory.LoadDomain(ctx, domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if state.Lease.HolderID != "controller-b" || state.Lease.RecordVersion != 3 {
		t.Fatalf("stored lease shares returned storage: %#v", state.Lease)
	}
}

func TestMemoryStoreTwoContendersHaveOneWinner(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	createDomain(t, memory)
	lease, err := memory.AcquireLease(context.Background(), domainRef(), "controller-original", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	type result struct {
		lease *model.Lease
		err   error
	}
	results := make(chan result, 2)
	for _, controllerID := range []string{"controller-a", "controller-b"} {
		controllerID := controllerID
		go func() {
			if err := store.Wait(context.Background(), clock, time.Minute); err != nil {
				results <- result{err: err}
				return
			}
			taken, err := memory.TakeoverLease(context.Background(), domainRef(), controllerID, lease.RecordVersion, time.Minute)
			results <- result{lease: taken, err: err}
		}()
	}
	waitForTimers(t, clock, 2)
	clock.Advance(time.Minute)

	var winner *model.Lease
	conflicts := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner != nil {
				t.Fatal("both contenders acquired the lease")
			}
			winner = result.lease
			continue
		}
		if !errors.Is(result.err, store.ErrConflict) {
			t.Fatalf("losing TakeoverLease() error = %v, want conflict", result.err)
		}
		conflicts++
	}
	if winner == nil || conflicts != 1 {
		t.Fatalf("winner = %#v, conflicts = %d", winner, conflicts)
	}
	if winner.FenceTerm != 2 || winner.RecordVersion != 2 {
		t.Fatalf("winning lease = %#v", winner)
	}

	state, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if state.Lease.HolderID != winner.HolderID || state.FenceTerm != winner.FenceTerm {
		t.Fatalf("stored lease = %#v, winner = %#v", state.Lease, winner)
	}
}

func TestMemoryStoreTakeoverRequiresUnchangedVersionAfterCallerWait(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	createDomain(t, memory)
	lease, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	clock.Advance(30 * time.Second)
	renewed, err := memory.RenewLease(context.Background(), domainRef(), store.LeaseTokenFor(lease), time.Minute)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	clock.Advance(30 * time.Second)

	_, err = memory.TakeoverLease(context.Background(), domainRef(), "controller-b", lease.RecordVersion, time.Minute)
	requireTypedError[*store.ConflictError](t, err, store.ErrConflict)

	// A new wait starts from the renewed version; takeover does not trust or
	// compare wall-clock expiry from the prior holder.
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- store.Wait(context.Background(), clock, time.Minute)
	}()
	waitForTimers(t, clock, 1)
	clock.Advance(time.Minute)
	if err := <-waitDone; err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	taken, err := memory.TakeoverLease(context.Background(), domainRef(), "controller-b", renewed.RecordVersion, time.Minute)
	if err != nil {
		t.Fatalf("TakeoverLease() after renewed expiry error = %v", err)
	}
	if taken.FenceTerm != 2 || taken.RecordVersion != 3 {
		t.Fatalf("TakeoverLease() = %#v", taken)
	}
}

func TestMemoryStoreRejectsStaleFence(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	createDomain(t, memory)
	oldLease, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	staleState, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}

	clock.Advance(time.Minute)
	newLease, err := memory.TakeoverLease(context.Background(), domainRef(), "controller-b", oldLease.RecordVersion, time.Minute)
	if err != nil {
		t.Fatalf("TakeoverLease() error = %v", err)
	}
	makeOwnerObserved(staleState, clock.Now())

	_, err = memory.CompareAndSwapDomain(context.Background(), domainRef(), staleState.Revision, store.LeaseTokenFor(oldLease), staleState)
	requireTypedError[*store.LeaseLostError](t, err, store.ErrLeaseLost)
	_, err = memory.RenewLease(context.Background(), domainRef(), store.LeaseTokenFor(oldLease), time.Minute)
	requireTypedError[*store.LeaseLostError](t, err, store.ErrLeaseLost)

	current, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if current.Revision != 1 || current.Phase != model.PhaseStable || current.FenceTerm != newLease.FenceTerm {
		t.Fatalf("stale write changed state: %#v", current)
	}
}

func TestMemoryStoreDomainCASConflictAndDeepCopy(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	createDomain(t, memory)
	lease, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	first, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("first LoadDomain() error = %v", err)
	}
	second := first.Clone()
	makeOwnerObserved(first, testTime.Add(time.Second))
	makeOwnerObserved(second, testTime.Add(2*time.Second))

	saved, err := memory.CompareAndSwapDomain(context.Background(), domainRef(), first.Revision, store.LeaseTokenFor(lease), first)
	if err != nil {
		t.Fatalf("first CompareAndSwapDomain() error = %v", err)
	}
	if saved.Revision != 2 || saved.Phase != model.PhaseOwnerObserved {
		t.Fatalf("first CompareAndSwapDomain() = %#v", saved)
	}
	_, err = memory.CompareAndSwapDomain(context.Background(), domainRef(), second.Revision, store.LeaseTokenFor(lease), second)
	requireTypedError[*store.ConflictError](t, err, store.ErrConflict)

	saved.Authority.Owners[0].ENIID = "eni-mutated"
	*saved.OwnerObservedAt = saved.OwnerObservedAt.Add(time.Hour)
	current, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if current.Authority.Owners[0].ENIID != "eni-a" || !current.OwnerObservedAt.Equal(testTime.Add(time.Second)) {
		t.Fatal("CompareAndSwapDomain() result shares storage with the durable state")
	}
}

func TestMemoryStoreObservationMonotonicityScopeAndFreshness(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock,
		observerIdentity("deployment-a", topologyHash, "controller-a"),
		observerIdentity("deployment-a", topologyHash, "controller-b"),
		observerIdentity("deployment-a", otherHash, "controller-c"),
		observerIdentity("deployment-b", topologyHash, "controller-d"),
	)
	ctx := context.Background()

	first := validObservation("controller-a", topologyHash, 1, testTime)
	published, err := memory.PublishObservation(ctx, "deployment-a", &first)
	if err != nil {
		t.Fatalf("PublishObservation(sequence 1) error = %v", err)
	}
	first.Domains["domain-a"] = model.OwnerObservation{}
	published.Domains["domain-a"] = model.OwnerObservation{}

	second := validObservation("controller-a", topologyHash, 2, testTime.Add(time.Second))
	if _, err := memory.PublishObservation(ctx, "deployment-a", &second); err != nil {
		t.Fatalf("PublishObservation(sequence 2) error = %v", err)
	}
	_, err = memory.PublishObservation(ctx, "deployment-a", &second)
	requireTypedError[*store.ConflictError](t, err, store.ErrConflict)
	older := validObservation("controller-a", topologyHash, 1, testTime.Add(2*time.Second))
	_, err = memory.PublishObservation(ctx, "deployment-a", &older)
	requireTypedError[*store.ConflictError](t, err, store.ErrConflict)

	for _, publication := range []struct {
		deploymentID string
		observation  model.Observation
	}{
		{deploymentID: "deployment-a", observation: validObservation("controller-b", topologyHash, 1, testTime)},
		{deploymentID: "deployment-a", observation: validObservation("controller-c", otherHash, 1, testTime)},
		{deploymentID: "deployment-b", observation: validObservation("controller-d", topologyHash, 1, testTime)},
	} {
		observation := publication.observation
		if _, err := memory.PublishObservation(ctx, publication.deploymentID, &observation); err != nil {
			t.Fatalf("PublishObservation(%s/%s) error = %v", publication.deploymentID, observation.ControllerID, err)
		}
	}

	listed, err := memory.ListObservations(ctx, observationScope("deployment-a", topologyHash))
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(listed) != 2 || listed[0].ControllerID != "controller-a" || listed[1].ControllerID != "controller-b" {
		t.Fatalf("ListObservations() = %#v", listed)
	}
	if listed[0].Sequence != 2 {
		t.Fatalf("controller-a sequence = %d, want 2", listed[0].Sequence)
	}
	if got := listed[0].Domains["domain-a"].StableNodeID; got != "node-a" {
		t.Fatalf("stored observation was mutated through input/result: stable node ID = %q", got)
	}
	listed[0].Domains["domain-a"] = model.OwnerObservation{}
	relisted, err := memory.ListObservations(ctx, observationScope("deployment-a", topologyHash))
	if err != nil {
		t.Fatalf("second ListObservations() error = %v", err)
	}
	if got := relisted[0].Domains["domain-a"].StableNodeID; got != "node-a" {
		t.Fatalf("listed observation shares storage: stable node ID = %q", got)
	}

	clock.Advance(2 * time.Minute)
	stale, err := memory.ListObservations(ctx, observationScope("deployment-a", topologyHash))
	if err != nil {
		t.Fatalf("stale ListObservations() error = %v", err)
	}
	if len(stale) != 2 {
		t.Fatalf("ListObservations() filtered stale records: got %d, want 2", len(stale))
	}
	fresh := 0
	for _, observation := range stale {
		if observation.ExpiresAt.After(clock.Now()) {
			fresh++
		}
	}
	if fresh != 0 {
		t.Fatalf("caller freshness filter retained %d observations, want 0", fresh)
	}

	wrongTopology := validObservation("controller-a", otherHash, 3, testTime)
	_, err = memory.PublishObservation(ctx, "deployment-a", &wrongTopology)
	requireTypedError[*store.TopologyMismatchError](t, err, store.ErrTopologyMismatch)
	unknown := validObservation("controller-unknown", topologyHash, 1, testTime)
	if _, err := memory.PublishObservation(ctx, "deployment-a", &unknown); err == nil {
		t.Fatal("PublishObservation() allowed an unknown controller")
	}
}

func TestMemoryStoreCancellationDoesNotMutate(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock, observerIdentity("deployment-a", topologyHash, "controller-a"))
	createDomain(t, memory)
	lease, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	next, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	makeOwnerObserved(next, testTime.Add(time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := memory.LoadDomain(ctx, domainRef()); !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadDomain(canceled) error = %v", err)
	}
	if _, err := memory.CompareAndSwapDomain(ctx, domainRef(), next.Revision, store.LeaseTokenFor(lease), next); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompareAndSwapDomain(canceled) error = %v", err)
	}
	if _, err := memory.RenewLease(ctx, domainRef(), store.LeaseTokenFor(lease), time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("RenewLease(canceled) error = %v", err)
	}
	observation := validObservation("controller-a", topologyHash, 1, testTime)
	if _, err := memory.PublishObservation(ctx, "deployment-a", &observation); !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishObservation(canceled) error = %v", err)
	}

	current, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if current.Revision != 1 || current.Phase != model.PhaseStable || current.Lease.RecordVersion != 1 {
		t.Fatalf("canceled operation mutated domain: %#v", current)
	}
	observations, err := memory.ListObservations(context.Background(), observationScope("deployment-a", topologyHash))
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("canceled publication stored %d observations", len(observations))
	}
}

func TestMemoryStoreValidatesInputs(t *testing.T) {
	if _, err := store.NewMemoryStore(nil); err == nil {
		t.Fatal("NewMemoryStore(nil) unexpectedly succeeded")
	}
	if _, err := store.NewMemoryStore(store.NewFakeClock(testTime), observerIdentity("deployment-a", "bad-hash", "controller-a")); err == nil {
		t.Fatal("NewMemoryStore() accepted an invalid observer")
	}

	clock := store.NewFakeClock(testTime)
	memory := newMemoryStore(t, clock)
	invalid := validInitialState()
	invalid.Revision = 2
	if _, err := memory.CreateDomain(context.Background(), &invalid); err == nil {
		t.Fatal("CreateDomain() accepted a non-initial revision")
	}
	createDomain(t, memory)
	if _, err := memory.AcquireLease(context.Background(), domainRef(), "", time.Minute); err == nil {
		t.Fatal("AcquireLease() accepted an empty holder")
	}
	if _, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", 0); err == nil {
		t.Fatal("AcquireLease() accepted a zero duration")
	}
	if _, err := memory.AcquireLease(context.Background(), domainRef(), "controller-a", time.Minute); err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	if _, err := memory.TakeoverLease(context.Background(), domainRef(), "controller-b", 0, time.Minute); err == nil {
		t.Fatal("TakeoverLease() accepted a zero record version")
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	const (
		writers    = 12
		iterations = 100
	)
	clock := store.NewFakeClock(testTime)
	identities := make([]store.ObserverIdentity, 0, writers)
	for index := range writers {
		identities = append(identities, observerIdentity("deployment-a", topologyHash, fmt.Sprintf("controller-%02d", index)))
	}
	memory := newMemoryStore(t, clock, identities...)
	createDomain(t, memory)
	lease, err := memory.AcquireLease(context.Background(), domainRef(), "lease-holder", time.Hour)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	start := make(chan struct{})
	errCh := make(chan error, writers*iterations*2)
	var wg sync.WaitGroup
	for index := range writers {
		controllerID := fmt.Sprintf("controller-%02d", index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for sequence := 1; sequence <= iterations; sequence++ {
				capturedAt := testTime.Add(time.Duration(sequence) * time.Second)
				observation := validObservation(controllerID, topologyHash, uint64(sequence), capturedAt)
				if _, err := memory.PublishObservation(context.Background(), "deployment-a", &observation); err != nil {
					errCh <- fmt.Errorf("publish %s sequence %d: %w", controllerID, sequence, err)
					return
				}
				listed, err := memory.ListObservations(context.Background(), observationScope("deployment-a", topologyHash))
				if err != nil {
					errCh <- fmt.Errorf("list for %s: %w", controllerID, err)
					return
				}
				if len(listed) > 0 {
					listed[0].ControllerID = "mutated-copy"
				}
				state, err := memory.LoadDomain(context.Background(), domainRef())
				if err != nil {
					errCh <- fmt.Errorf("load for %s: %w", controllerID, err)
					return
				}
				state.Authority.RemotePrefixes[0] = "192.0.2.0/24"
				_ = clock.Now()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		current := lease
		for range iterations {
			clock.Advance(time.Millisecond)
			renewed, err := memory.RenewLease(context.Background(), domainRef(), store.LeaseTokenFor(current), time.Hour)
			if err != nil {
				errCh <- fmt.Errorf("renew: %w", err)
				return
			}
			current = renewed
		}
	}()

	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	observations, err := memory.ListObservations(context.Background(), observationScope("deployment-a", topologyHash))
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(observations) != writers {
		t.Fatalf("ListObservations() count = %d, want %d", len(observations), writers)
	}
	for index, observation := range observations {
		if observation.ControllerID != fmt.Sprintf("controller-%02d", index) || observation.Sequence != iterations {
			t.Fatalf("observation %d = %#v", index, observation)
		}
	}
	state, err := memory.LoadDomain(context.Background(), domainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if state.Authority.RemotePrefixes[0] != "10.1.0.0/24" || state.Lease.RecordVersion != iterations+1 {
		t.Fatalf("concurrent access corrupted state: %#v", state)
	}
}

func newMemoryStore(t *testing.T, clock store.Clock, identities ...store.ObserverIdentity) *store.MemoryStore {
	t.Helper()
	memory, err := store.NewMemoryStore(clock, identities...)
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	return memory
}

func createDomain(t *testing.T, memory *store.MemoryStore) {
	t.Helper()
	initial := validInitialState()
	if _, err := memory.CreateDomain(context.Background(), &initial); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}
}

func requireTypedError[T error](t *testing.T, err, target error) T {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(%v)", err, target)
	}
	var typed T
	if !errors.As(err, &typed) {
		t.Fatalf("error type = %T, want %T", err, typed)
	}
	return typed
}

func domainRef() store.DomainRef {
	return store.DomainRef{DeploymentID: "deployment-a", DomainID: "domain-a", TopologyHash: topologyHash}
}

func observationScope(deploymentID, hash string) store.ObservationScope {
	return store.ObservationScope{DeploymentID: deploymentID, TopologyHash: hash}
}

func observerIdentity(deploymentID, hash, controllerID string) store.ObserverIdentity {
	return store.ObserverIdentity{DeploymentID: deploymentID, TopologyHash: hash, ControllerID: controllerID}
}

func validAuthority() model.DomainAuthority {
	return model.DomainAuthority{
		TopologyHash:            topologyHash,
		DeploymentID:            "deployment-a",
		DomainID:                "domain-a",
		SiteID:                  "site-a",
		VPCID:                   "vpc-a",
		Region:                  "us-west-2",
		SourcePrefix:            "10.0.0.0/24",
		RouteTableID:            "rtb-a",
		GWLBESubnetID:           "subnet-gwlbe-a",
		RouteTableAssociationID: "rtbassoc-gwlbe-a",
		RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
		PreferredOwner:          "node-a",
		Owners: []model.OwnerAuthority{
			{RouterID: "router-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{RouterID: "router-b", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
		},
	}
}

func validInitialState() model.DomainState {
	return model.DomainState{
		Activated:        true,
		Authority:        validAuthority(),
		Revision:         1,
		Phase:            model.PhaseStable,
		StableOwner:      "node-a",
		LastTransitionAt: testTime,
		UpdatedAt:        testTime,
	}
}

func validObservation(controllerID, hash string, sequence uint64, capturedAt time.Time) model.Observation {
	return model.Observation{
		ControllerID:   controllerID,
		TopologyHash:   hash,
		Sequence:       sequence,
		CapturedAt:     capturedAt,
		ExpiresAt:      capturedAt.Add(time.Minute),
		BackendHealthy: true,
		Domains: map[string]model.OwnerObservation{
			"domain-a": {
				StableNodeID:       "node-a",
				SolePrimary:        true,
				Online:             true,
				Healthy:            true,
				AdvertisedPrefixes: []string{"10.0.0.0/24"},
				EnabledPrefixes:    []string{"10.0.0.0/24"},
			},
		},
	}
}

func makeOwnerObserved(state *model.DomainState, at time.Time) {
	state.Phase = model.PhaseOwnerObserved
	state.ObservedOwner = "node-b"
	state.OwnerObservedAt = &at
	state.LastTransitionAt = at
	state.UpdatedAt = at
}
