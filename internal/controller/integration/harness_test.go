package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/resilience"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

var (
	integrationEpoch   = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	errPathUnavailable = errors.New("integration: converged application path unavailable")
	errInjectedCrash   = errors.New("integration: injected process crash after durable checkpoint")
)

type harness struct {
	t            *testing.T
	topology     *config.Topology
	authority    model.DomainAuthority
	clock        *integrationClock
	store        *store.MemoryStore
	tailnet      *fakeTailnet
	observers    []*fakeObserverReplica
	observerRuns []*runningObserver
	aws          *fakeAWS
	network      *fakeApplicationNetwork
	uuids        *sequenceUUIDs
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	topology := integrationTopology()
	if err := topology.Validate(); err != nil {
		t.Fatalf("integration topology: %v", err)
	}
	authority, err := topology.DomainAuthority("domain-a")
	if err != nil {
		t.Fatalf("domain authority: %v", err)
	}
	clock := newIntegrationClock(integrationEpoch)
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
		t.Fatalf("memory store: %v", err)
	}
	tailnet := newFakeTailnet(authority)
	cloud := newFakeAWS(clock, authority)
	network, err := newFakeApplicationNetwork(tailnet, cloud)
	if err != nil {
		t.Fatalf("application network: %v", err)
	}
	h := &harness{
		t:         t,
		topology:  topology,
		authority: authority,
		clock:     clock,
		store:     memory,
		tailnet:   tailnet,
		aws:       cloud,
		network:   network,
		uuids:     &sequenceUUIDs{},
	}
	for _, controllerID := range topology.ControllerIDs {
		h.observers = append(h.observers, &fakeObserverReplica{
			controllerID: controllerID,
			clock:        clock.Track(),
			publisher:    memory,
			topology:     topology,
			authority:    authority,
			tailnet:      tailnet,
		})
	}
	return h
}

func (h *harness) engine(controllerID string, durability store.Store) *reconcile.Engine {
	return h.engineWith(controllerID, durability, h.aws, h.clock)
}

func (h *harness) engineWith(controllerID string, durability store.Store, routes reconcile.RouteController, clock store.Clock) *reconcile.Engine {
	h.t.Helper()
	if durability == nil {
		durability = h.store
	}
	if routes == nil {
		routes = h.aws
	}
	if clock == nil {
		clock = h.clock
	}
	engine, err := reconcile.NewEngine(reconcile.Options{
		Topology:     h.topology,
		DomainID:     h.authority.DomainID,
		ControllerID: controllerID,
		Store:        durability,
		Routes:       routes,
		Clock:        clock,
		UUIDs:        h.uuids,
	})
	if err != nil {
		h.t.Fatalf("new engine %s: %v", controllerID, err)
	}
	return engine
}

func (h *harness) initializeLeader(controllerID string) *reconcile.Engine {
	h.t.Helper()
	h.prepareInitialOwner()
	engine := h.engine(controllerID, nil)
	h.requireLeader(engine, controllerID)
	return engine
}

func (h *harness) prepareInitialOwner() {
	h.t.Helper()
	now := h.clock.Now()
	if _, err := h.store.CreateDomain(context.Background(), &model.DomainState{
		Authority: h.authority.Clone(), Activated: true, Revision: 1, Phase: model.PhaseStable,
		StableOwner: h.authority.PreferredOwner, LastTransitionAt: now, UpdatedAt: now,
	}); err != nil {
		h.t.Fatalf("deployment initializes journal: %v", err)
	}
	if err := h.tailnet.Select(h.authority.PreferredOwner); err != nil {
		h.t.Fatalf("select initial Tailnet owner: %v", err)
	}
	h.startObservers()
}

func (h *harness) requireLeader(engine *reconcile.Engine, controllerID string) {
	h.t.Helper()
	if err := engine.Reconcile(context.Background()); err != nil {
		h.t.Fatalf("initialize leader: %v", err)
	}
	state := h.state()
	if state.Phase != model.PhaseStable || state.StableOwner != h.authority.PreferredOwner || state.Lease == nil || state.Lease.HolderID != controllerID {
		h.t.Fatalf("initialized state = %+v", state)
	}
}

func (h *harness) initializeAutonomousLeader(controllerID string) *runningEngine {
	h.t.Helper()
	h.prepareInitialOwner()
	controllerClock := h.clock.Track()
	engine := h.engineWith(controllerID, nil, h.aws, controllerClock)
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningEngine{
		engine: engine,
		clock:  controllerClock,
		cancel: cancel,
		done:   make(chan error, 1),
	}
	go func() { running.done <- engine.Run(ctx) }()
	if duration := controllerClock.awaitTimer(h.t); duration != h.reconcileInterval() {
		h.t.Fatalf("controller loop interval = %s, want %s", duration, h.reconcileInterval())
	}
	state := h.state()
	if state.Phase != model.PhaseStable || state.StableOwner != h.authority.PreferredOwner || state.Lease == nil || state.Lease.HolderID != controllerID {
		h.t.Fatalf("autonomously initialized state = %+v", state)
	}
	h.t.Cleanup(func() { running.stop(h.t) })
	return running
}

func (h *harness) startObservers() {
	h.t.Helper()
	if len(h.observerRuns) != 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	for _, observer := range h.observers {
		run := &runningObserver{observer: observer, done: make(chan error, 1)}
		h.observerRuns = append(h.observerRuns, run)
		go func() { run.done <- observer.Run(ctx) }()
	}
	for _, run := range h.observerRuns {
		if duration := run.observer.clock.awaitTimer(h.t); duration != h.topology.Policy.ObservationInterval.Duration() {
			h.t.Fatalf("observer %s interval = %s", run.observer.controllerID, duration)
		}
	}
	h.t.Cleanup(func() {
		cancel()
		for _, run := range h.observerRuns {
			select {
			case err := <-run.done:
				if !errors.Is(err, context.Canceled) {
					h.t.Errorf("observer %s stopped: %v", run.observer.controllerID, err)
				}
			case <-time.After(time.Second):
				h.t.Errorf("observer %s did not stop", run.observer.controllerID)
			}
		}
	})
}

func (h *harness) publishObservers() error {
	for _, observer := range h.observers {
		if err := observer.Publish(context.Background()); err != nil {
			return fmt.Errorf("publish observer %s: %w", observer.controllerID, err)
		}
	}
	return nil
}

func (h *harness) advanceObservers(ctx context.Context, duration time.Duration) error {
	h.clock.Advance(duration)
	for _, run := range h.observerRuns {
		observed, err := run.observer.clock.awaitTimerContext(ctx)
		if err != nil {
			return fmt.Errorf("wait for observer %s: %w", run.observer.controllerID, err)
		}
		if expected := h.topology.Policy.ObservationInterval.Duration(); observed != expected {
			return fmt.Errorf("observer %s interval = %s, want %s", run.observer.controllerID, observed, expected)
		}
	}
	return nil
}

func (h *harness) advanceRuntime(ctx context.Context, duration time.Duration, controller *runningEngine) error {
	if err := h.advanceObservers(ctx, duration); err != nil {
		return err
	}
	observed, err := controller.clock.awaitTimerContext(ctx)
	if err != nil {
		return fmt.Errorf("wait for controller loop: %w", err)
	}
	if expected := h.reconcileInterval(); observed != expected {
		return fmt.Errorf("controller loop interval = %s, want %s", observed, expected)
	}
	return nil
}

func (h *harness) advanceUntilReady(ctx context.Context, controller *runningEngine) error {
	interval := h.reconcileInterval()
	maxTicks := int(h.topology.Policy.FailoverStability.Duration()/interval) + 4
	for range maxTicks {
		if h.network.Ready() {
			return nil
		}
		if err := h.advanceRuntime(ctx, interval, controller); err != nil {
			return err
		}
	}
	if h.network.Ready() {
		return nil
	}
	return errPathUnavailable
}

func (h *harness) reconcileInterval() time.Duration {
	return min(h.topology.Policy.ObservationInterval.Duration(), h.topology.Policy.LeaseRenewInterval.Duration())
}

func (h *harness) state() *model.DomainState {
	h.t.Helper()
	state, err := h.store.LoadDomain(context.Background(), store.DomainRefFor(h.authority))
	if err != nil {
		h.t.Fatalf("load domain: %v", err)
	}
	return state
}

func integrationTopology() *config.Topology {
	return &config.Topology{
		SchemaVersion: config.TopologySchemaVersion,
		DeploymentID:  "integration-deployment",
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
		DynamoDB: config.DynamoDBConfig{Table: "integration-authority", Region: "us-west-2"},
		Tailnet: config.TailnetConfig{
			Name:            "integration.example",
			TSNetAuthKeyEnv: "TAILNET_AUTH_KEY",
			AdminAPIKeyEnv:  "TAILNET_ADMIN_KEY",
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
			{
				ID:                      "domain-a",
				SiteID:                  "site-a",
				SourcePrefix:            "10.0.0.0/24",
				RouteTableID:            "rtb-a",
				GWLBESubnetID:           "subnet-gwlbe-a",
				RouteTableAssociationID: "rtbassoc-gwlbe-a",
				RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
				PreferredOwner:          "router-a",
			},
			{ID: "domain-b-0", SiteID: "site-b", SourcePrefix: "10.1.0.0/24", RouteTableID: "rtb-b-0", GWLBESubnetID: "subnet-gwlbe-b-0", RouteTableAssociationID: "rtbassoc-gwlbe-b-0", RemotePrefixes: []string{"10.0.0.0/24"}, PreferredOwner: "router-c"},
			{ID: "domain-b-1", SiteID: "site-b", SourcePrefix: "10.1.1.0/24", RouteTableID: "rtb-b-1", GWLBESubnetID: "subnet-gwlbe-b-1", RouteTableAssociationID: "rtbassoc-gwlbe-b-1", RemotePrefixes: []string{"10.0.0.0/24"}, PreferredOwner: "router-c"},
		},
	}
}

type integrationClock struct {
	inner      *store.FakeClock
	registered chan time.Duration
}

type trackedClock struct {
	inner      *store.FakeClock
	registered chan time.Duration
}

type runningEngine struct {
	engine *reconcile.Engine
	clock  *trackedClock
	cancel context.CancelFunc
	done   chan error
}

type runningObserver struct {
	observer *fakeObserverReplica
	done     chan error
}

func newIntegrationClock(start time.Time) *integrationClock {
	return &integrationClock{
		inner:      store.NewFakeClock(start),
		registered: make(chan time.Duration, 32),
	}
}

func (c *integrationClock) Now() time.Time { return c.inner.Now() }

func (c *integrationClock) After(duration time.Duration) <-chan time.Time {
	timer := c.inner.After(duration)
	c.registered <- duration
	return timer
}

func (c *integrationClock) Advance(duration time.Duration) { c.inner.Advance(duration) }

func (c *integrationClock) Track() *trackedClock {
	return &trackedClock{inner: c.inner, registered: make(chan time.Duration, 32)}
}

func (c *integrationClock) awaitTimer(t *testing.T) time.Duration {
	t.Helper()
	select {
	case duration := <-c.registered:
		return duration
	case <-time.After(time.Second):
		t.Fatal("controller did not register the expected fake-clock timer")
		return 0
	}
}

func (c *trackedClock) Now() time.Time { return c.inner.Now() }

func (c *trackedClock) After(duration time.Duration) <-chan time.Time {
	timer := c.inner.After(duration)
	c.registered <- duration
	return timer
}

func (c *trackedClock) awaitTimer(t *testing.T) time.Duration {
	t.Helper()
	duration, err := c.awaitTimerContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return duration
}

func (c *trackedClock) awaitTimerContext(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		return 0, errors.New("integration: timer wait context is nil")
	}
	select {
	case duration := <-c.registered:
		return duration, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(time.Second):
		return 0, errors.New("integration: component did not register its next fake-clock timer")
	}
}

func (r *runningEngine) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("controller loop stopped: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("controller loop did not stop")
	}
}

type fakeTailnet struct {
	mu        sync.RWMutex
	authority model.DomainAuthority
	selected  string
	online    map[string]bool
	views     map[string]string
}

func newFakeTailnet(authority model.DomainAuthority) *fakeTailnet {
	online := make(map[string]bool, len(authority.Owners))
	for _, owner := range authority.Owners {
		online[owner.StableNodeID] = true
	}
	return &fakeTailnet{
		authority: authority,
		online:    online,
	}
}

func (f *fakeTailnet) Select(owner string) error {
	f.mu.Lock()
	if _, found := f.online[owner]; !found {
		f.mu.Unlock()
		return fmt.Errorf("unknown Tailnet owner %q", owner)
	}
	f.online[owner] = true
	f.selected = owner
	f.mu.Unlock()
	return nil
}

func (f *fakeTailnet) LoseRouter(owner string) error {
	f.mu.Lock()
	if _, found := f.online[owner]; !found {
		f.mu.Unlock()
		return fmt.Errorf("unknown Tailnet router %q", owner)
	}
	f.online[owner] = false
	if f.selected == owner {
		f.selected = ""
		for _, candidate := range f.authority.Owners {
			if f.online[candidate.StableNodeID] {
				f.selected = candidate.StableNodeID
				break
			}
		}
	}
	f.mu.Unlock()
	return nil
}

func (f *fakeTailnet) Selected() (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.selected, f.online[f.selected]
}

func (f *fakeTailnet) ObserverView(id string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	owner := f.selected
	if view, ok := f.views[id]; ok {
		owner = view
	}
	return owner, f.online[owner]
}

func (f *fakeTailnet) SetObserverView(id, owner string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.views == nil {
		f.views = map[string]string{}
	}
	f.views[id] = owner
}

type fakeObserverReplica struct {
	mu sync.Mutex

	controllerID string
	clock        *trackedClock
	publisher    store.ObservationStore
	topology     *config.Topology
	authority    model.DomainAuthority
	tailnet      *fakeTailnet

	sequence    uint64
	observed    string
	ownerSince  time.Time
	ownerChange uint64
}

func (r *fakeObserverReplica) Run(ctx context.Context) error {
	for {
		if err := r.Publish(ctx); err != nil {
			return err
		}
		if err := store.Wait(ctx, r.clock, r.topology.Policy.ObservationInterval.Duration()); err != nil {
			return err
		}
	}
}

func (r *fakeObserverReplica) Publish(ctx context.Context) error {
	owner, online := r.tailnet.ObserverView(r.controllerID)
	now := r.clock.Now()
	r.mu.Lock()
	r.sequence++
	continuityOwner := owner
	if !online {
		continuityOwner = ""
	}
	if continuityOwner == "" {
		r.observed = ""
		r.ownerSince = time.Time{}
		r.ownerChange = 0
	} else if r.observed != continuityOwner {
		r.observed = continuityOwner
		r.ownerSince = now
		r.ownerChange = r.sequence
	}
	ownerObservation := model.OwnerObservation{
		StableNodeID:       owner,
		SolePrimary:        owner != "",
		Online:             online,
		Healthy:            online,
		AdvertisedPrefixes: []string{r.authority.SourcePrefix},
		EnabledPrefixes:    []string{r.authority.SourcePrefix},
	}
	if continuityOwner != "" {
		since := r.ownerSince
		ownerObservation.OwnerSince = &since
		ownerObservation.OwnerChangeGeneration = r.ownerChange
	}
	observation := &model.Observation{
		ControllerID:   r.controllerID,
		TopologyHash:   r.authority.TopologyHash,
		Sequence:       r.sequence,
		CapturedAt:     now,
		ExpiresAt:      now.Add(r.topology.Policy.ObservationFreshness.Duration()),
		BackendHealthy: true,
		Domains:        map[string]model.OwnerObservation{r.authority.DomainID: ownerObservation},
	}
	r.mu.Unlock()
	_, err := r.publisher.PublishObservation(ctx, r.topology.DeploymentID, observation)
	return err
}

type routeCall struct {
	prefix     string
	desiredENI string
	deadline   time.Time
	ambiguous  bool
}

type fakeAWS struct {
	mu          sync.Mutex
	clock       store.Clock
	authority   model.DomainAuthority
	targets     map[string]string
	healthy     map[string]bool
	ambiguousAt map[int]bool
	calls       []routeCall
}

func newFakeAWS(clock store.Clock, authority model.DomainAuthority) *fakeAWS {
	preferred, _ := authority.OwnerByStableNode(authority.PreferredOwner)
	targets := make(map[string]string, len(authority.RemotePrefixes))
	for _, prefix := range authority.RemotePrefixes {
		targets[prefix] = preferred.ENIID
	}
	healthy := make(map[string]bool, len(authority.Owners))
	for _, owner := range authority.Owners {
		healthy[owner.StableNodeID] = true
	}
	return &fakeAWS{
		clock:       clock,
		authority:   authority,
		targets:     targets,
		healthy:     healthy,
		ambiguousAt: make(map[int]bool),
	}
}

func (f *fakeAWS) ValidateOwner(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	if err := ctx.Err(); err != nil {
		return awscontrol.OwnerValidation{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	configured, found := authority.OwnerByStableNode(owner.StableNodeID)
	if !found || !reflect.DeepEqual(configured, owner) || !f.healthy[owner.StableNodeID] {
		return awscontrol.OwnerValidation{}, &awscontrol.IneligibleError{
			Resource: owner.RouterID,
			Check:    "integration-owner",
			Expected: "configured and healthy",
			Observed: "unknown or unhealthy",
		}
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

func (f *fakeAWS) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.RouteSnapshot{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshotLocked(authority), nil
}

func (f *fakeAWS) ReplaceAndWait(ctx context.Context, authority model.DomainAuthority, prefix, expectedPreviousENI, desiredENI string, deadline time.Time) (awscontrol.ReplaceResult, error) {
	if err := ctx.Err(); err != nil {
		return awscontrol.ReplaceResult{}, err
	}
	if !f.clock.Now().Before(deadline) {
		return awscontrol.ReplaceResult{}, &awscontrol.UnsafeDeadlineError{Deadline: deadline}
	}
	if !authority.AllowsENI(desiredENI) {
		return awscontrol.ReplaceResult{}, &awscontrol.UnauthorizedError{DestinationPrefix: prefix, TargetENIID: desiredENI}
	}
	allowedPrefix := false
	for _, candidate := range authority.RemotePrefixes {
		if candidate == prefix {
			allowedPrefix = true
			break
		}
	}
	if !allowedPrefix {
		return awscontrol.ReplaceResult{}, &awscontrol.InputError{Field: "destination prefix", Problem: "outside integration authority"}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	before := f.snapshotLocked(authority)
	previous := f.targets[prefix]
	if previous != expectedPreviousENI {
		return awscontrol.ReplaceResult{}, &awscontrol.AmbiguousError{
			DestinationPrefix: prefix,
			PreviousENIID:     expectedPreviousENI,
			DesiredENIID:      desiredENI,
			Reason:            "integration before-image mismatch",
		}
	}
	callNumber := len(f.calls) + 1
	ambiguous := f.ambiguousAt[callNumber]
	f.targets[prefix] = desiredENI
	f.calls = append(f.calls, routeCall{prefix: prefix, desiredENI: desiredENI, deadline: deadline, ambiguous: ambiguous})
	now := f.clock.Now()
	return awscontrol.ReplaceResult{
		StartedAt:         now,
		CompletedAt:       now,
		DestinationPrefix: prefix,
		DesiredENIID:      desiredENI,
		PreviousENIID:     previous,
		ObservedENIID:     desiredENI,
		CallAttempted:     true,
		CallAmbiguous:     ambiguous,
		Settlement:        awscontrol.SettlementDesired,
		Before:            before,
	}, nil
}

func (f *fakeAWS) snapshotLocked(authority model.DomainAuthority) model.RouteSnapshot {
	snapshot := model.RouteSnapshot{RouteTableID: authority.RouteTableID, CapturedAt: f.clock.Now()}
	for _, prefix := range authority.RemotePrefixes {
		snapshot.Routes = append(snapshot.Routes, model.RouteSnapshotEntry{
			DestinationPrefix: prefix,
			TargetENIID:       f.targets[prefix],
			State:             "active",
			Origin:            "CreateRoute",
		})
	}
	return snapshot
}

func (f *fakeAWS) SetAmbiguousCall(call int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ambiguousAt[call] = true
}

func (f *fakeAWS) Calls() []routeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]routeCall(nil), f.calls...)
}

func (f *fakeAWS) Aligned(owner string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	configured, found := f.authority.OwnerByStableNode(owner)
	if !found {
		return false
	}
	for _, target := range f.targets {
		if target != configured.ENIID {
			return false
		}
	}
	return true
}

type sequenceUUIDs struct {
	mu   sync.Mutex
	next int
}

func (s *sequenceUUIDs) NewUUID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", s.next)
}

func (s *sequenceUUIDs) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

type crashAfterCASStore struct {
	store.Store
	mu        sync.Mutex
	target    int
	count     int
	triggered bool
}

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

func (s *crashAfterCASStore) Triggered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.triggered
}

type pausePoint struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newPausePoint() *pausePoint {
	return &pausePoint{entered: make(chan struct{}), release: make(chan struct{})}
}

func (p *pausePoint) block(ctx context.Context) error {
	p.enteredOnce.Do(func() { close(p.entered) })
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pausePoint) await(t *testing.T, label string) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatalf("%s did not reach pause point", label)
	}
}

func (p *pausePoint) resume() {
	p.releaseOnce.Do(func() { close(p.release) })
}

type pauseBeforeMutationCASStore struct {
	store.Store
	mu     sync.Mutex
	paused bool
	point  *pausePoint
}

func (s *pauseBeforeMutationCASStore) CompareAndSwapDomain(ctx context.Context, ref store.DomainRef, revision model.DocumentRevision, token store.LeaseToken, next *model.DomainState) (*model.DomainState, error) {
	shouldPause := false
	if next != nil && next.Phase == model.PhaseRoutesConverging && next.Intent != nil {
		for _, progress := range next.Intent.Progress {
			if progress.Attempted() && !progress.Completed() {
				s.mu.Lock()
				if !s.paused {
					s.paused = true
					shouldPause = true
				}
				s.mu.Unlock()
				break
			}
		}
	}
	if shouldPause {
		if err := s.point.block(ctx); err != nil {
			return nil, err
		}
	}
	return s.Store.CompareAndSwapDomain(ctx, ref, revision, token, next)
}

type pauseAfterTakeoverStore struct {
	store.Store
	point *pausePoint
}

func (s *pauseAfterTakeoverStore) TakeoverLease(ctx context.Context, ref store.DomainRef, holderID string, expectedRecordVersion uint64, duration time.Duration) (*model.Lease, error) {
	lease, err := s.Store.TakeoverLease(ctx, ref, holderID, expectedRecordVersion, duration)
	if err != nil {
		return lease, err
	}
	if err := s.point.block(ctx); err != nil {
		return nil, err
	}
	return lease, nil
}

type attributedRoutes struct {
	delegate  *fakeAWS
	mu        sync.Mutex
	mutations int
}

func (r *attributedRoutes) ValidateOwner(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return r.delegate.ValidateOwner(ctx, authority, owner)
}

func (r *attributedRoutes) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	return r.delegate.Snapshot(ctx, authority)
}

func (r *attributedRoutes) ReplaceAndWait(ctx context.Context, authority model.DomainAuthority, prefix, expectedPreviousENI, desiredENI string, deadline time.Time) (awscontrol.ReplaceResult, error) {
	r.mu.Lock()
	r.mutations++
	r.mu.Unlock()
	return r.delegate.ReplaceAndWait(ctx, authority, prefix, expectedPreviousENI, desiredENI, deadline)
}

func (r *attributedRoutes) MutationCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutations
}

type fakeApplicationNetwork struct {
	mu sync.Mutex

	tailnet *fakeTailnet
	aws     *fakeAWS

	tcpTable      resilience.TCPIdempotencyTable
	tcpDials      int
	tcpEffects    int
	tcpServerDone chan error

	udpReceiver *resilience.UDPReceiver
	udpSent     []resilience.UDPFrame
	udpEffects  int
}

func newFakeApplicationNetwork(tailnet *fakeTailnet, cloud *fakeAWS) (*fakeApplicationNetwork, error) {
	receiver, err := resilience.NewUDPReceiver(32)
	if err != nil {
		return nil, err
	}
	return &fakeApplicationNetwork{
		tailnet:       tailnet,
		aws:           cloud,
		tcpServerDone: make(chan error, 8),
		udpReceiver:   receiver,
	}, nil
}

func (n *fakeApplicationNetwork) Ready() bool {
	owner, online := n.tailnet.Selected()
	return online && n.aws.Aligned(owner)
}

func (n *fakeApplicationNetwork) DialTCP(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.tcpDials++
	n.mu.Unlock()
	if !n.Ready() {
		return nil, errPathUnavailable
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		var request resilience.TCPRequest
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			n.tcpServerDone <- err
			return
		}
		response, err := n.tcpTable.Execute("integration-client", request, func(resilience.TCPRequest) ([]byte, error) {
			n.mu.Lock()
			n.tcpEffects++
			n.mu.Unlock()
			return []byte("tcp-committed"), nil
		})
		if err == nil {
			err = json.NewEncoder(server).Encode(response)
		}
		n.tcpServerDone <- err
	}()
	return client, nil
}

func (n *fakeApplicationNetwork) AwaitTCPServer(t *testing.T) {
	t.Helper()
	select {
	case err := <-n.tcpServerDone:
		if err != nil {
			t.Fatalf("integration TCP server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("integration TCP server did not finish")
	}
}

func (n *fakeApplicationNetwork) TCPStats() (dials, effects int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.tcpDials, n.tcpEffects
}

func (n *fakeApplicationNetwork) ExchangeUDP(ctx context.Context, frame resilience.UDPFrame) (resilience.UDPFrame, error) {
	if err := ctx.Err(); err != nil {
		return resilience.UDPFrame{}, err
	}
	n.mu.Lock()
	copyOfFrame := frame
	copyOfFrame.Payload = append([]byte(nil), frame.Payload...)
	n.udpSent = append(n.udpSent, copyOfFrame)
	n.mu.Unlock()
	if !n.Ready() {
		return resilience.UDPFrame{}, resilience.ErrNoAcknowledgement
	}
	return n.udpReceiver.Handle(frame, func(resilience.UDPFrame) ([]byte, error) {
		n.mu.Lock()
		n.udpEffects++
		n.mu.Unlock()
		return []byte("udp-accepted"), nil
	})
}

func (n *fakeApplicationNetwork) UDPStats() ([]resilience.UDPFrame, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	sent := make([]resilience.UDPFrame, len(n.udpSent))
	for index, frame := range n.udpSent {
		sent[index] = frame
		sent[index].Payload = append([]byte(nil), frame.Payload...)
	}
	return sent, n.udpEffects
}
