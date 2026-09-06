package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

var reconcileTestTime = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

type testRig struct {
	t             *testing.T
	topology      *config.Topology
	authority     model.DomainAuthority
	clock         *store.FakeClock
	memory        *store.MemoryStore
	routes        *fakeRouteController
	uuids         *sequenceUUIDs
	sequences     map[string]uint64
	observedOwner map[string]string
	ownerSince    map[string]time.Time
	ownerChange   map[string]uint64
	controllerIDs []string
}

func newTestRig(t *testing.T, mutatePolicy ...func(*config.Policy)) *testRig {
	t.Helper()
	topology := testTopology()
	for _, mutate := range mutatePolicy {
		mutate(&topology.Policy)
	}
	if err := topology.Validate(); err != nil {
		t.Fatalf("test topology is invalid: %v", err)
	}
	authority, err := topology.DomainAuthority("domain-a")
	if err != nil {
		t.Fatalf("DomainAuthority: %v", err)
	}
	clock := store.NewFakeClock(reconcileTestTime)
	identities := make([]store.ObserverIdentity, 0, len(topology.ControllerIDs))
	for _, controllerID := range topology.ControllerIDs {
		identities = append(identities, store.ObserverIdentity{
			DeploymentID: topology.DeploymentID,
			TopologyHash: authority.TopologyHash,
			ControllerID: controllerID,
		})
	}
	memory, err := store.NewMemoryStore(clock, identities...)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return &testRig{
		t:             t,
		topology:      topology,
		authority:     authority,
		clock:         clock,
		memory:        memory,
		routes:        newFakeRouteController(clock, authority, topology.Policy.ObservationInterval.Duration()),
		uuids:         &sequenceUUIDs{},
		sequences:     make(map[string]uint64),
		observedOwner: make(map[string]string),
		ownerSince:    make(map[string]time.Time),
		ownerChange:   make(map[string]uint64),
		controllerIDs: append([]string(nil), topology.ControllerIDs...),
	}
}

func (r *testRig) engine(controllerID string, durability store.Store, options ...func(*Options)) *Engine {
	r.t.Helper()
	if durability == nil {
		durability = r.memory
	}
	configuration := Options{
		Topology:     r.topology,
		DomainID:     r.authority.DomainID,
		ControllerID: controllerID,
		Store:        durability,
		Routes:       r.routes,
		Clock:        r.clock,
		UUIDs:        r.uuids,
	}
	for _, option := range options {
		option(&configuration)
	}
	engine, err := NewEngine(configuration)
	if err != nil {
		r.t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func (r *testRig) publishOwner(owner string) {
	r.t.Helper()
	views := make(map[string]string, len(r.controllerIDs))
	for _, controllerID := range r.controllerIDs {
		views[controllerID] = owner
	}
	r.publishViews(views)
}

func (r *testRig) publishViews(views map[string]string) {
	r.t.Helper()
	for _, controllerID := range r.controllerIDs {
		owner, found := views[controllerID]
		if !found {
			continue
		}
		r.sequences[controllerID]++
		if owner == "" {
			delete(r.observedOwner, controllerID)
			delete(r.ownerSince, controllerID)
			delete(r.ownerChange, controllerID)
		} else if r.observedOwner[controllerID] != owner {
			r.observedOwner[controllerID] = owner
			r.ownerSince[controllerID] = r.clock.Now()
			r.ownerChange[controllerID] = r.sequences[controllerID]
		}
		ownerObservation := model.OwnerObservation{
			StableNodeID:       owner,
			SolePrimary:        owner != "",
			Online:             owner != "",
			Healthy:            owner != "",
			AdvertisedPrefixes: []string{r.authority.SourcePrefix},
			EnabledPrefixes:    []string{r.authority.SourcePrefix},
		}
		if owner != "" {
			since := r.ownerSince[controllerID]
			ownerObservation.OwnerSince = &since
			ownerObservation.OwnerChangeGeneration = r.ownerChange[controllerID]
		}
		observation := &model.Observation{
			ControllerID:   controllerID,
			TopologyHash:   r.authority.TopologyHash,
			Sequence:       r.sequences[controllerID],
			CapturedAt:     r.clock.Now(),
			ExpiresAt:      r.clock.Now().Add(r.topology.Policy.ObservationFreshness.Duration()),
			BackendHealthy: true,
			Domains: map[string]model.OwnerObservation{
				r.authority.DomainID: ownerObservation,
			},
		}
		if _, err := r.memory.PublishObservation(context.Background(), r.topology.DeploymentID, observation); err != nil {
			r.t.Fatalf("PublishObservation(%s): %v", controllerID, err)
		}
	}
}

func (r *testRig) advanceAndPublish(duration time.Duration, owner string) {
	r.t.Helper()
	r.clock.Advance(duration)
	r.publishOwner(owner)
}

func (r *testRig) state() *model.DomainState {
	r.t.Helper()
	state, err := r.memory.LoadDomain(context.Background(), store.DomainRefFor(r.authority))
	if err != nil {
		r.t.Fatalf("LoadDomain: %v", err)
	}
	return state
}

func (r *testRig) createInitial() {
	r.t.Helper()
	now := r.clock.Now()
	initial := &model.DomainState{
		Authority:        r.authority.Clone(),
		Activated:        true,
		Revision:         1,
		Phase:            model.PhaseStable,
		StableOwner:      r.authority.PreferredOwner,
		LastTransitionAt: now,
		UpdatedAt:        now,
	}
	if _, err := r.memory.CreateDomain(context.Background(), initial); err != nil {
		r.t.Fatalf("CreateDomain: %v", err)
	}
}

func (r *testRig) initializeLeader(engine *Engine) {
	r.t.Helper()
	r.createInitial()
	r.publishOwner(r.authority.PreferredOwner)
	if err := engine.Reconcile(context.Background()); err != nil {
		r.t.Fatalf("initial Reconcile: %v", err)
	}
	state := r.state()
	if state.Lease == nil || state.Lease.HolderID != engine.controllerID || state.Phase != model.PhaseStable {
		r.t.Fatalf("initial state = %+v", state)
	}
}

func testTopology() *config.Topology {
	return &config.Topology{
		SchemaVersion: config.TopologySchemaVersion,
		DeploymentID:  "deployment-a",
		ControllerIDs: []string{"controller-a", "controller-b", "controller-c"},
		Policy: config.Policy{
			ReplicaCount:            3,
			ObservationQuorum:       2,
			ObservationInterval:     config.Duration(100 * time.Millisecond),
			ObservationFreshness:    config.Duration(10 * time.Second),
			FailoverStability:       config.Duration(300 * time.Millisecond),
			FailbackStability:       config.Duration(700 * time.Millisecond),
			Cooldown:                config.Duration(500 * time.Millisecond),
			LeaseDuration:           config.Duration(2 * time.Second),
			LeaseRenewInterval:      config.Duration(200 * time.Millisecond),
			LeaseDangerWindow:       config.Duration(500 * time.Millisecond),
			APITimeout:              config.Duration(100 * time.Millisecond),
			RouteConvergenceTimeout: config.Duration(200 * time.Millisecond),
		},
		DynamoDB: config.DynamoDBConfig{Table: "controller-state", Region: "us-west-2"},
		Tailnet: config.TailnetConfig{
			Name:            "example.test",
			TSNetAuthKeyEnv: "TS_AUTH_KEY",
			AdminAPIKeyEnv:  "TS_ADMIN_KEY",
			StateBaseDir:    "/var/lib/envelope-controller",
		},
		Sites: []config.Site{
			{ID: "site-a", VPCID: "vpc-a", Region: "us-west-2", LocalPrefixes: []string{"10.0.0.0/24"}},
			{ID: "site-b", VPCID: "vpc-b", Region: "us-east-2", LocalPrefixes: []string{"10.1.0.0/24", "10.1.1.0/24"}},
		},
		Routers: []config.Router{
			{ID: "router-a", SiteID: "site-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{ID: "router-b", SiteID: "site-a", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
			{ID: "router-c", SiteID: "site-b", StableNodeID: "node-c", InstanceID: "i-c", ENIID: "eni-c", VPCID: "vpc-b", SubnetID: "subnet-c", AvailabilityZone: "us-east-2a", Region: "us-east-2"},
			{ID: "router-d", SiteID: "site-b", StableNodeID: "node-d", InstanceID: "i-d", ENIID: "eni-d", VPCID: "vpc-b", SubnetID: "subnet-d", AvailabilityZone: "us-east-2b", Region: "us-east-2"},
		},
		Domains: []config.Domain{
			{ID: "domain-a", SiteID: "site-a", SourcePrefix: "10.0.0.0/24", RouteTableID: "rtb-a", GWLBESubnetID: "subnet-gwlbe-a", RouteTableAssociationID: "rtbassoc-gwlbe-a", RemotePrefixes: []string{"10.1.0.0/24", "10.1.1.0/24"}, PreferredOwner: "router-a"},
			{ID: "domain-b-0", SiteID: "site-b", SourcePrefix: "10.1.0.0/24", RouteTableID: "rtb-b-0", GWLBESubnetID: "subnet-gwlbe-b-0", RouteTableAssociationID: "rtbassoc-gwlbe-b-0", RemotePrefixes: []string{"10.0.0.0/24"}, PreferredOwner: "router-c"},
			{ID: "domain-b-1", SiteID: "site-b", SourcePrefix: "10.1.1.0/24", RouteTableID: "rtb-b-1", GWLBESubnetID: "subnet-gwlbe-b-1", RouteTableAssociationID: "rtbassoc-gwlbe-b-1", RemotePrefixes: []string{"10.0.0.0/24"}, PreferredOwner: "router-c"},
		},
	}
}

type sequenceUUIDs struct {
	mu   sync.Mutex
	next int
}

type observationFailureStore struct {
	store.Store
	err error
}

func (s observationFailureStore) ListObservations(context.Context, store.ObservationScope) ([]*model.Observation, error) {
	return nil, s.err
}

func (s *sequenceUUIDs) NewUUID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", s.next)
}

type replaceCall struct {
	routeTableID     string
	prefix           string
	expectedPrevious string
	desiredENI       string
	deadline         time.Time
}

type fakeRouteController struct {
	mu sync.Mutex

	clock                store.Clock
	readbackInterval     time.Duration
	targets              map[string]string
	ownerErrors          map[string]error
	ownerErrorAfterCall  int
	ownerErrorsAfterCall map[string]error
	snapshotErr          error
	snapshotTargets      []map[string]string
	replaceErrAt         int
	replaceErr           error
	settlePreviousAt     int
	ambiguousOK          map[int]bool
	invalidAt            int
	calls                []replaceCall
	validations          int
	snapshots            int
	stableReadbacks      int
	active               int
	maxActive            int
	entered              chan struct{}
	enterOnce            sync.Once
	block                <-chan struct{}
}

var _ stableRouteReader = (*fakeRouteController)(nil)

func newFakeRouteController(clock store.Clock, authority model.DomainAuthority, readbackInterval time.Duration) *fakeRouteController {
	targets := make(map[string]string, len(authority.RemotePrefixes))
	preferred, _ := authority.OwnerByStableNode(authority.PreferredOwner)
	for _, prefix := range authority.RemotePrefixes {
		targets[prefix] = preferred.ENIID
	}
	return &fakeRouteController{
		clock:                clock,
		readbackInterval:     readbackInterval,
		targets:              targets,
		ownerErrors:          make(map[string]error),
		ownerErrorsAfterCall: make(map[string]error),
		ambiguousOK:          make(map[int]bool),
	}
}

func (f *fakeRouteController) ValidateOwner(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	if err := ctx.Err(); err != nil {
		return awscontrol.OwnerValidation{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validations++
	if err := f.ownerErrors[owner.StableNodeID]; err != nil {
		return awscontrol.OwnerValidation{}, err
	}
	if f.ownerErrorAfterCall > 0 && len(f.calls) >= f.ownerErrorAfterCall {
		if err := f.ownerErrorsAfterCall[owner.StableNodeID]; err != nil {
			return awscontrol.OwnerValidation{}, err
		}
	}
	configured, found := authority.OwnerByStableNode(owner.StableNodeID)
	if !found || configured != owner {
		return awscontrol.OwnerValidation{}, &awscontrol.IneligibleError{Resource: owner.RouterID, Check: "authority", Expected: "configured", Observed: "unknown"}
	}
	return awscontrol.OwnerValidation{
		ValidatedAt:      f.clock.Now(),
		Region:           owner.Region,
		InstanceID:       owner.InstanceID,
		InstanceState:    "running",
		SystemStatus:     "ok",
		InstanceStatus:   "ok",
		ENIID:            owner.ENIID,
		ENIStatus:        "in-use",
		AttachmentStatus: "attached",
		VPCID:            owner.VPCID,
		SubnetID:         owner.SubnetID,
		AvailabilityZone: owner.AvailabilityZone,
	}, nil
}

func (f *fakeRouteController) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.RouteSnapshot{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots++
	if f.snapshotErr != nil {
		return model.RouteSnapshot{}, f.snapshotErr
	}
	if len(f.snapshotTargets) > 0 {
		targets := f.snapshotTargets[0]
		f.snapshotTargets = f.snapshotTargets[1:]
		return f.snapshotForTargetsLocked(authority, targets), nil
	}
	return f.snapshotLocked(authority), nil
}

func (f *fakeRouteController) StableSnapshot(ctx context.Context, authority model.DomainAuthority, deadline time.Time) (model.RouteSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.RouteSnapshot{}, err
	}
	f.mu.Lock()
	f.stableReadbacks++
	interval := f.readbackInterval
	f.mu.Unlock()
	candidate, err := f.Snapshot(ctx, authority)
	if err != nil {
		return model.RouteSnapshot{}, err
	}
	advancing, ok := f.clock.(interface{ Advance(time.Duration) })
	if !ok {
		return model.RouteSnapshot{}, &awscontrol.UnstableReadbackError{Reason: "deterministic clock cannot advance"}
	}
	stableReads := 1
	transitions := 0
	for stableReads < 2 {
		if interval <= 0 || !f.clock.Now().Add(interval).Before(deadline) {
			return model.RouteSnapshot{}, &awscontrol.UnstableReadbackError{Reason: "deterministic readback deadline reached"}
		}
		advancing.Advance(interval)
		if err := ctx.Err(); err != nil {
			return model.RouteSnapshot{}, err
		}
		next, readErr := f.Snapshot(ctx, authority)
		if readErr != nil {
			return model.RouteSnapshot{}, readErr
		}
		if !next.CapturedAt.After(candidate.CapturedAt) {
			return model.RouteSnapshot{}, &awscontrol.UnstableReadbackError{Reason: "readbacks were not time-spaced"}
		}
		if matchingRouteSnapshots(authority, candidate, next) == nil {
			candidate = next
			stableReads++
			continue
		}
		transitions++
		if transitions >= 2 {
			return model.RouteSnapshot{}, &awscontrol.UnstableReadbackError{Reason: "route snapshot changed repeatedly"}
		}
		candidate = next
		stableReads = 1
	}
	return candidate, nil
}

func (f *fakeRouteController) ReplaceAndWait(ctx context.Context, authority model.DomainAuthority, prefix, expectedPrevious, desiredENI string, deadline time.Time) (awscontrol.ReplaceResult, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.maxActive {
		f.maxActive = f.active
	}
	f.calls = append(f.calls, replaceCall{routeTableID: authority.RouteTableID, prefix: prefix, expectedPrevious: expectedPrevious, desiredENI: desiredENI, deadline: deadline})
	callNumber := len(f.calls)
	previous := f.targets[prefix]
	entered := f.entered
	block := f.block
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	if entered != nil {
		f.enterOnce.Do(func() { close(entered) })
	}
	if block != nil {
		select {
		case <-ctx.Done():
			return awscontrol.ReplaceResult{
				DestinationPrefix: prefix,
				DesiredENIID:      desiredENI,
				PreviousENIID:     expectedPrevious,
				ObservedENIID:     previous,
				CallAttempted:     true,
			}, ctx.Err()
		case <-block:
		}
	}
	if err := ctx.Err(); err != nil {
		return awscontrol.ReplaceResult{}, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	result := awscontrol.ReplaceResult{
		StartedAt:         f.clock.Now(),
		CompletedAt:       f.clock.Now(),
		DestinationPrefix: prefix,
		DesiredENIID:      desiredENI,
		PreviousENIID:     expectedPrevious,
		ObservedENIID:     previous,
		Before:            f.snapshotLocked(authority),
	}
	if previous != expectedPrevious && previous != desiredENI {
		return result, &awscontrol.OscillationError{DestinationPrefix: prefix, PreviousENIID: expectedPrevious, DesiredENIID: desiredENI}
	}
	if previous == desiredENI {
		result.Settlement = awscontrol.SettlementDesired
		return result, nil
	}
	result.CallAttempted = true
	if f.replaceErrAt == callNumber && f.replaceErr != nil {
		if f.settlePreviousAt == callNumber {
			result.Settlement = awscontrol.SettlementPrevious
			result.ObservedENIID = expectedPrevious
			result.CallAmbiguous = true
		}
		return result, f.replaceErr
	}
	f.targets[prefix] = desiredENI
	result.ObservedENIID = desiredENI
	result.Settlement = awscontrol.SettlementDesired
	result.CallAmbiguous = f.ambiguousOK[callNumber]
	if f.invalidAt == callNumber {
		result.ObservedENIID = previous
	}
	return result, nil
}

func (f *fakeRouteController) snapshotLocked(authority model.DomainAuthority) model.RouteSnapshot {
	return f.snapshotForTargetsLocked(authority, f.targets)
}

func (f *fakeRouteController) snapshotForTargetsLocked(authority model.DomainAuthority, targets map[string]string) model.RouteSnapshot {
	snapshot := model.RouteSnapshot{RouteTableID: authority.RouteTableID, CapturedAt: f.clock.Now()}
	for _, prefix := range authority.RemotePrefixes {
		snapshot.Routes = append(snapshot.Routes, model.RouteSnapshotEntry{
			DestinationPrefix: prefix,
			TargetENIID:       targets[prefix],
			State:             "active",
			Origin:            "CreateRoute",
		})
	}
	return snapshot
}

func (f *fakeRouteController) queueSnapshotTargets(targets ...map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, targetSet := range targets {
		cloned := make(map[string]string, len(targetSet))
		for prefix, target := range targetSet {
			cloned[prefix] = target
		}
		f.snapshotTargets = append(f.snapshotTargets, cloned)
	}
}

func (f *fakeRouteController) setAllTargets(authority model.DomainAuthority, eni string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, prefix := range authority.RemotePrefixes {
		f.targets[prefix] = eni
	}
}

func (f *fakeRouteController) setTarget(prefix, eni string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets[prefix] = eni
}

func (f *fakeRouteController) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRouteController) callsSnapshot() []replaceCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]replaceCall(nil), f.calls...)
}

func (f *fakeRouteController) maximumConcurrency() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxActive
}

type crashAfterCASStore struct {
	store.Store
	mu        sync.Mutex
	target    int
	count     int
	triggered bool
}

var errInjectedCrash = errors.New("injected process crash")

func (s *crashAfterCASStore) CompareAndSwapDomain(ctx context.Context, ref store.DomainRef, revision model.DocumentRevision, token store.LeaseToken, next *model.DomainState) (*model.DomainState, error) {
	saved, err := s.Store.CompareAndSwapDomain(ctx, ref, revision, token, next)
	if err != nil {
		return saved, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	if s.count == s.target {
		s.triggered = true
		return nil, errInjectedCrash
	}
	return saved, nil
}

type loseBeforeCASStore struct {
	store.Store
	clock     *store.FakeClock
	duration  time.Duration
	target    int
	count     int
	triggered bool
	newHolder string
}

func (s *loseBeforeCASStore) CompareAndSwapDomain(ctx context.Context, ref store.DomainRef, revision model.DocumentRevision, token store.LeaseToken, next *model.DomainState) (*model.DomainState, error) {
	s.count++
	if s.count == s.target {
		s.triggered = true
		s.clock.Advance(s.duration)
		if _, err := s.Store.TakeoverLease(context.Background(), ref, s.newHolder, token.RecordVersion, s.duration); err != nil {
			return nil, fmt.Errorf("injected takeover: %w", err)
		}
	}
	return s.Store.CompareAndSwapDomain(ctx, ref, revision, token, next)
}

type loseOnRenewStore struct {
	store.Store
	clock     *store.FakeClock
	duration  time.Duration
	target    int
	count     int
	triggered bool
	newHolder string
}

func (s *loseOnRenewStore) RenewLease(ctx context.Context, ref store.DomainRef, token store.LeaseToken, duration time.Duration) (*model.Lease, error) {
	s.count++
	if s.count == s.target {
		s.triggered = true
		s.clock.Advance(s.duration)
		if _, err := s.Store.TakeoverLease(context.Background(), ref, s.newHolder, token.RecordVersion, s.duration); err != nil {
			return nil, fmt.Errorf("injected takeover: %w", err)
		}
	}
	return s.Store.RenewLease(ctx, ref, token, duration)
}

type advanceAfterRenewStore struct {
	store.Store
	clock   *store.FakeClock
	target  int
	count   int
	advance time.Duration
}

func (s *advanceAfterRenewStore) RenewLease(ctx context.Context, ref store.DomainRef, token store.LeaseToken, duration time.Duration) (*model.Lease, error) {
	lease, err := s.Store.RenewLease(ctx, ref, token, duration)
	if err != nil {
		return lease, err
	}
	s.count++
	if s.count == s.target {
		s.clock.Advance(s.advance)
	}
	return lease, nil
}

type afterRenewStore struct {
	store.Store
	mu     sync.Mutex
	target int
	count  int
	after  func()
}

func (s *afterRenewStore) RenewLease(ctx context.Context, ref store.DomainRef, token store.LeaseToken, duration time.Duration) (*model.Lease, error) {
	lease, err := s.Store.RenewLease(ctx, ref, token, duration)
	if err != nil {
		return lease, err
	}
	s.mu.Lock()
	s.count++
	trigger := s.count == s.target
	after := s.after
	s.mu.Unlock()
	if trigger && after != nil {
		after()
	}
	return lease, nil
}

func waitForTimers(t *testing.T, clock *store.FakeClock, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for clock.PendingTimers() < count {
		if time.Now().After(deadline) {
			t.Fatalf("pending timers = %d, want at least %d", clock.PendingTimers(), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func requireState(t *testing.T, state *model.DomainState, phase model.Phase, owner string) {
	t.Helper()
	if state.Phase != phase || state.StableOwner != owner {
		t.Fatalf("state phase/owner = %s/%s, want %s/%s; state=%+v", state.Phase, state.StableOwner, phase, owner, state)
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("durable state is invalid: %v", err)
	}
}

func assertOnlyBoundedStatus(t *testing.T, status Status) {
	t.Helper()
	for name, value := range map[string]string{
		"controller": status.ControllerID,
		"domain":     status.DomainID,
		"stable":     status.StableOwner,
		"observed":   status.ObservedOwner,
		"consensus":  status.ConsensusOwner,
		"reason":     string(status.Reason),
		"error code": string(status.ErrorCode),
	} {
		if len(value) > 256 {
			t.Errorf("status %s is unbounded: %d bytes", name, len(value))
		}
		if strings.Contains(strings.ToLower(value), "secret") {
			t.Errorf("status %s contains secret text: %q", name, value)
		}
	}
}
