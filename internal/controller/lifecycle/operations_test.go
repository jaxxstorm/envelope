package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

type advancingClock struct{ *store.FakeClock }

func (c advancingClock) After(duration time.Duration) <-chan time.Time {
	c.Advance(duration)
	result := make(chan time.Time, 1)
	result <- c.Now()
	return result
}

type operationStore struct {
	mu                 sync.Mutex
	clock              store.Clock
	topology           *config.Topology
	states             map[string]*model.DomainState
	lock               *store.DeploymentLock
	lostWrite          bool
	observationFailure bool
}

func (s *operationStore) LoadDomain(_ context.Context, ref store.DomainRef) (*model.DomainState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[ref.DomainID]
	if state == nil {
		return nil, store.ErrNotFound
	}
	if state.Authority.TopologyHash != ref.TopologyHash {
		return nil, store.ErrTopologyMismatch
	}
	return state.Clone(), nil
}
func (s *operationStore) CreateDomain(_ context.Context, initial *model.DomainState) (*model.DomainState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[initial.Authority.DomainID] != nil {
		return nil, store.ErrConflict
	}
	s.states[initial.Authority.DomainID] = initial.Clone()
	return initial.Clone(), nil
}
func (s *operationStore) ListObservations(_ context.Context, scope store.ObservationScope) ([]*model.Observation, error) {
	if s.observationFailure {
		return nil, errors.New("observers unavailable")
	}
	var result []*model.Observation
	now := s.clock.Now()
	since := now.Add(-time.Hour)
	for _, id := range s.topology.ControllerIDs {
		o := &model.Observation{ControllerID: id, TopologyHash: scope.TopologyHash, Sequence: 2, CapturedAt: now, ExpiresAt: now.Add(6 * time.Second), BackendHealthy: true, Domains: map[string]model.OwnerObservation{}}
		for _, domain := range s.topology.Domains {
			authority, _ := s.topology.DomainAuthority(domain.ID)
			o.Domains[domain.ID] = model.OwnerObservation{StableNodeID: authority.PreferredOwner, SolePrimary: true, Online: true, Healthy: true, OwnerSince: &since, OwnerChangeGeneration: 1, AdvertisedPrefixes: []string{authority.SourcePrefix}, EnabledPrefixes: []string{authority.SourcePrefix}}
		}
		result = append(result, o)
	}
	return result, nil
}
func (s *operationStore) BeginDeployment(_ context.Context, lock store.DeploymentLock) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil && s.lock.Phase != "complete" {
		return store.ErrConflict
	}
	s.lock = &lock
	return nil
}
func (s *operationStore) ReadDeployment(context.Context, string) (store.DeploymentLock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return store.DeploymentLock{}, store.ErrNotFound
	}
	return *s.lock, nil
}
func (s *operationStore) AdvanceDeployment(_ context.Context, before, after store.DeploymentLock) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || *s.lock != before {
		return store.ErrConflict
	}
	s.lock = &after
	return nil
}
func (s *operationStore) RewriteDeploymentDomains(_ context.Context, lock store.DeploymentLock, before, after []*model.DomainState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || *s.lock != lock {
		return store.ErrConflict
	}
	for _, old := range before {
		if !reflect.DeepEqual(s.states[old.Authority.DomainID], old) {
			return store.ErrConflict
		}
	}
	for _, next := range after {
		copy := next.Clone()
		copy.Revision++
		s.states[next.Authority.DomainID] = copy
	}
	if s.lostWrite {
		return ErrUncertain
	}
	return nil
}

type operationCloud struct{ clock store.Clock }

func (c operationCloud) ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return awscontrol.OwnerValidation{ValidatedAt: c.clock.Now()}, nil
}
func (c operationCloud) StableSnapshot(_ context.Context, a model.DomainAuthority, _ time.Time) (model.RouteSnapshot, error) {
	o, _ := a.OwnerByStableNode(a.PreferredOwner)
	s := model.RouteSnapshot{RouteTableID: a.RouteTableID, CapturedAt: c.clock.Now()}
	for _, prefix := range a.RemotePrefixes {
		s.Routes = append(s.Routes, model.RouteSnapshotEntry{DestinationPrefix: prefix, TargetENIID: o.ENIID, State: "active", Origin: "CreateRoute"})
	}
	return s, nil
}

func operationFixture(t *testing.T) (Deployment, *operationStore) {
	t.Helper()
	topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	clock := advancingClock{store.NewFakeClock(time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))}
	durable := &operationStore{clock: clock, topology: topology, states: map[string]*model.DomainState{}}
	d := Deployment{Topology: topology, Store: durable, Cloud: map[string]Inspector{}, Clock: clock, Forwarding: func(context.Context, model.DomainAuthority, model.OwnerAuthority) (time.Time, error) {
		return clock.Now().Add(5 * time.Second), nil
	}}
	for _, site := range topology.Sites {
		d.Cloud[site.Region] = operationCloud{clock}
	}
	for _, domain := range topology.Domains {
		if _, err := Initialize(context.Background(), topology, domain.ID, durable, d.Cloud[func() string { a, _ := topology.DomainAuthority(domain.ID); return a.Region }()], d.Forwarding, clock); err != nil {
			t.Fatal(err)
		}
	}
	return d, durable
}

func TestActivationDeactivationAndMigration(t *testing.T) {
	d, s := operationFixture(t)
	domain := d.Topology.Domains[0].ID
	if err := d.Activate(context.Background(), "activate-a", domain); err != nil {
		t.Fatal(err)
	}
	if !s.states[domain].Activated || s.lock.Phase != "complete" {
		t.Fatal("activation not committed")
	}
	if err := d.Deactivate(context.Background(), "deactivate-a"); err != nil {
		t.Fatal(err)
	}
	if s.states[domain].Activated || s.lock.Phase != "complete" {
		t.Fatal("deactivation not quiescent")
	}
	next := *d.Topology
	next.Policy.Cooldown = config.Duration(time.Minute)
	oldFence := s.states[domain].FenceTerm
	if err := d.Migrate(context.Background(), "migrate-a", &next, d.Forwarding); err != nil {
		t.Fatal(err)
	}
	hash, _ := next.Hash()
	for _, state := range s.states {
		if state.Authority.TopologyHash != hash || state.Activated || state.Lease != nil || state.FenceTerm != oldFence {
			t.Fatalf("migration state=%+v", state)
		}
	}
	if s.lock.Phase != "complete" {
		t.Fatal("verified migration lock retained")
	}
}

func TestLifecycleFailuresRetainLockAndJournal(t *testing.T) {
	for _, mode := range []string{"lost-activation", "observation-failure", "active-journal", "changed-domain-set"} {
		t.Run(mode, func(t *testing.T) {
			d, s := operationFixture(t)
			domain := d.Topology.Domains[0].ID
			var err error
			switch mode {
			case "lost-activation":
				s.lostWrite = true
				err = d.Activate(context.Background(), "activate-a", domain)
			case "observation-failure":
				s.observationFailure = true
				err = d.Activate(context.Background(), "activate-a", domain)
			case "active-journal":
				state := s.states[domain]
				state.Phase = model.PhaseDegraded
				state.Error = &model.StateError{Code: model.ErrorRouteAmbiguous, Message: "ambiguous", At: d.Clock.Now(), Ambiguous: true}
				err = d.Deactivate(context.Background(), "deactivate-a")
				if s.states[domain].Error == nil || !s.states[domain].Error.Ambiguous {
					t.Fatal("lost ambiguous journal")
				}
			case "changed-domain-set":
				next := *d.Topology
				next.Domains = next.Domains[:1]
				err = d.Migrate(context.Background(), "migrate-a", &next, d.Forwarding)
			}
			if err == nil {
				t.Fatal("unsafe operation succeeded")
			}
			if mode == "changed-domain-set" {
				if s.lock != nil {
					t.Fatal("invalid topology acquired lock")
				}
				return
			}
			if s.lock == nil || s.lock.Phase == "complete" {
				t.Fatal("failed operation released lock")
			}
			if d.Activate(context.Background(), "another", domain) == nil {
				t.Fatal("second deployment bypassed lock")
			}
		})
	}
}

type rolloutAction struct {
	calls []string
	fail  string
}

func (a *rolloutAction) Validate(context.Context) error {
	a.calls = append(a.calls, "validate")
	if a.fail == "validate" {
		return ErrPreflight
	}
	return nil
}
func (a *rolloutAction) Apply(context.Context) error {
	a.calls = append(a.calls, "apply")
	if a.fail == "apply" {
		return ErrUncertain
	}
	return nil
}
func (a *rolloutAction) Healthy(_ context.Context, after time.Time) error {
	name := "before"
	if !after.IsZero() {
		name = "after"
	}
	a.calls = append(a.calls, name)
	if a.fail == name {
		return ErrPreflight
	}
	return nil
}
func TestRolloutHoldsLockThroughHealthGates(t *testing.T) {
	for _, failure := range []string{"", "validate", "before", "apply", "after"} {
		t.Run(failure, func(t *testing.T) {
			d, s := operationFixture(t)
			action := &rolloutAction{fail: failure}
			err := d.Rollout(context.Background(), "rollout-a", d.Topology.ControllerIDs[0], action)
			if (err == nil) != (failure == "") {
				t.Fatalf("rollout=%v", err)
			}
			if failure == "validate" {
				if s.lock != nil {
					t.Fatal("invalid plan acquired lock")
				}
				return
			}
			if failure == "" {
				if !reflect.DeepEqual(action.calls, []string{"validate", "before", "apply", "after"}) || s.lock.Phase != "complete" {
					t.Fatalf("rollout order=%v lock=%+v", action.calls, s.lock)
				}
			} else if s.lock == nil || s.lock.Phase == "complete" {
				t.Fatal("failed rollout released lock")
			}
		})
	}
}
