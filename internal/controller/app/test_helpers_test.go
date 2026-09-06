package app

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

type fakeObserver struct {
	mu         sync.Mutex
	snapshot   func(int) (*model.Observation, error)
	calls      int
	active     int
	maxActive  int
	closeCalls int
	closeErr   error
}

func (o *fakeObserver) Snapshot(context.Context) (*model.Observation, error) {
	o.mu.Lock()
	o.calls++
	call := o.calls
	o.active++
	if o.active > o.maxActive {
		o.maxActive = o.active
	}
	snapshot := o.snapshot
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.active--
		o.mu.Unlock()
	}()
	if snapshot == nil {
		return nil, errors.New("snapshot not configured")
	}
	return snapshot(call)
}

func (o *fakeObserver) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeCalls++
	return o.closeErr
}

func (o *fakeObserver) stats() (calls, maximum, closes int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls, o.maxActive, o.closeCalls
}

type fakePublisher struct {
	mu           sync.Mutex
	failures     []error
	calls        int
	last         *model.Observation
	observations map[string]*model.Observation
	states       map[string]*model.DomainState
	listErr      error
	loadErr      error
}

func (p *fakePublisher) PublishObservation(_ context.Context, _ string, observation *model.Observation) (*model.Observation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if len(p.failures) > 0 {
		err := p.failures[0]
		p.failures = p.failures[1:]
		if err != nil {
			return nil, err
		}
	}
	p.last = observation.Clone()
	if p.observations == nil {
		p.observations = make(map[string]*model.Observation)
	}
	p.observations[observation.ControllerID] = observation.Clone()
	return observation.Clone(), nil
}

func (p *fakePublisher) ListObservations(context.Context, store.ObservationScope) ([]*model.Observation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listErr != nil {
		return nil, p.listErr
	}
	controllerIDs := make([]string, 0, len(p.observations))
	for controllerID := range p.observations {
		controllerIDs = append(controllerIDs, controllerID)
	}
	sort.Strings(controllerIDs)
	observations := make([]*model.Observation, 0, len(controllerIDs))
	for _, controllerID := range controllerIDs {
		observations = append(observations, p.observations[controllerID].Clone())
	}
	return observations, nil
}

func (p *fakePublisher) LoadDomain(_ context.Context, ref store.DomainRef) (*model.DomainState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loadErr != nil {
		return nil, p.loadErr
	}
	state := p.states[ref.DomainID]
	if state == nil {
		return nil, store.ErrNotFound
	}
	return state.Clone(), nil
}

func (p *fakePublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type fakeRunner struct {
	mu        sync.Mutex
	status    reconcile.Status
	callback  func(reconcile.Status)
	runCalls  int
	stopped   chan struct{}
	stopOnce  sync.Once
	runErr    error
	reconcile func(context.Context, int) error
}

func newFakeRunner(status reconcile.Status) *fakeRunner {
	return &fakeRunner{status: status, stopped: make(chan struct{})}
}

func (r *fakeRunner) Run(ctx context.Context) error {
	r.mu.Lock()
	r.runCalls++
	runErr := r.runErr
	r.mu.Unlock()
	if runErr != nil {
		return runErr
	}
	<-ctx.Done()
	r.stopOnce.Do(func() { close(r.stopped) })
	return ctx.Err()
}

func (r *fakeRunner) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	r.runCalls++
	call := r.runCalls
	runErr := r.runErr
	reconcile := r.reconcile
	r.mu.Unlock()
	if reconcile != nil {
		return reconcile(ctx, call)
	}
	if runErr != nil {
		return runErr
	}
	return ctx.Err()
}

func (r *fakeRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runCalls
}

func (r *fakeRunner) Status() reconcile.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *fakeRunner) SetStatusCallback(callback func(reconcile.Status)) {
	r.mu.Lock()
	r.callback = callback
	status := r.status
	r.mu.Unlock()
	if callback != nil {
		callback(status)
	}
}

func (r *fakeRunner) setStatus(status reconcile.Status) {
	r.mu.Lock()
	r.status = status
	callback := r.callback
	r.mu.Unlock()
	if callback != nil {
		callback(status)
	}
}

type fakeRouteController struct{}

func (fakeRouteController) ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return awscontrol.OwnerValidation{}, nil
}

func (fakeRouteController) Snapshot(context.Context, model.DomainAuthority) (model.RouteSnapshot, error) {
	return model.RouteSnapshot{}, nil
}

func (fakeRouteController) ReplaceAndWait(context.Context, model.DomainAuthority, string, string, string, time.Time) (awscontrol.ReplaceResult, error) {
	return awscontrol.ReplaceResult{}, nil
}

func testTopology() *controllerconfig.Topology {
	return &controllerconfig.Topology{
		SchemaVersion: controllerconfig.TopologySchemaVersion,
		DeploymentID:  "deployment-a",
		ControllerIDs: []string{"controller-a", "controller-b", "controller-c"},
		Policy: controllerconfig.Policy{
			ReplicaCount:            3,
			ObservationQuorum:       2,
			ObservationInterval:     controllerconfig.Duration(100 * time.Millisecond),
			ObservationFreshness:    controllerconfig.Duration(300 * time.Millisecond),
			FailoverStability:       controllerconfig.Duration(100 * time.Millisecond),
			FailbackStability:       controllerconfig.Duration(200 * time.Millisecond),
			Cooldown:                controllerconfig.Duration(100 * time.Millisecond),
			LeaseDuration:           controllerconfig.Duration(600 * time.Millisecond),
			LeaseRenewInterval:      controllerconfig.Duration(100 * time.Millisecond),
			LeaseDangerWindow:       controllerconfig.Duration(300 * time.Millisecond),
			APITimeout:              controllerconfig.Duration(100 * time.Millisecond),
			RouteConvergenceTimeout: controllerconfig.Duration(100 * time.Millisecond),
		},
		DynamoDB: controllerconfig.DynamoDBConfig{Table: "controller-state", Region: "us-east-2"},
		Tailnet: controllerconfig.TailnetConfig{
			Name:            "example.com",
			ControlURL:      "https://control.example.com",
			TSNetAuthKeyEnv: "CONTROLLER_TSNET_AUTH_KEY",
			AdminAPIKeyEnv:  "CONTROLLER_ADMIN_API_KEY",
			StateBaseDir:    "/var/lib/envelope-controller",
		},
		Sites: []controllerconfig.Site{
			{ID: "west", VPCID: "vpc-west", Region: "us-west-2", LocalPrefixes: []string{"10.0.0.0/24"}},
			{ID: "east", VPCID: "vpc-east", Region: "us-east-1", LocalPrefixes: []string{"10.1.0.0/24"}},
		},
		Routers: []controllerconfig.Router{
			{ID: "west-a", SiteID: "west", StableNodeID: "node-west-a", InstanceID: "i-west-a", ENIID: "eni-west-a", VPCID: "vpc-west", SubnetID: "subnet-west-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{ID: "west-b", SiteID: "west", StableNodeID: "node-west-b", InstanceID: "i-west-b", ENIID: "eni-west-b", VPCID: "vpc-west", SubnetID: "subnet-west-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
			{ID: "east-a", SiteID: "east", StableNodeID: "node-east-a", InstanceID: "i-east-a", ENIID: "eni-east-a", VPCID: "vpc-east", SubnetID: "subnet-east-a", AvailabilityZone: "us-east-1a", Region: "us-east-1"},
			{ID: "east-b", SiteID: "east", StableNodeID: "node-east-b", InstanceID: "i-east-b", ENIID: "eni-east-b", VPCID: "vpc-east", SubnetID: "subnet-east-b", AvailabilityZone: "us-east-1b", Region: "us-east-1"},
		},
		Domains: []controllerconfig.Domain{
			{ID: "west-domain", SiteID: "west", SourcePrefix: "10.0.0.0/24", RouteTableID: "rtb-west", GWLBESubnetID: "subnet-gwlbe-west", RouteTableAssociationID: "rtbassoc-gwlbe-west", RemotePrefixes: []string{"10.1.0.0/24"}, PreferredOwner: "west-a"},
			{ID: "east-domain", SiteID: "east", SourcePrefix: "10.1.0.0/24", RouteTableID: "rtb-east", GWLBESubnetID: "subnet-gwlbe-east", RouteTableAssociationID: "rtbassoc-gwlbe-east", RemotePrefixes: []string{"10.0.0.0/24"}, PreferredOwner: "east-a"},
		},
	}
}

func testObservation(t *testing.T, topology *controllerconfig.Topology, now time.Time, sequence uint64) *model.Observation {
	t.Helper()
	hash, err := topology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	domains := make(map[string]model.OwnerObservation, len(topology.Domains))
	for _, domain := range topology.Domains {
		authority, err := topology.DomainAuthority(domain.ID)
		if err != nil {
			t.Fatal(err)
		}
		domains[authority.DomainID] = model.OwnerObservation{
			StableNodeID:       authority.PreferredOwner,
			SolePrimary:        true,
			Online:             true,
			Healthy:            true,
			AdvertisedPrefixes: []string{authority.SourcePrefix},
			EnabledPrefixes:    []string{authority.SourcePrefix},
		}
	}
	return &model.Observation{
		ControllerID:   "controller-a",
		TopologyHash:   hash,
		Sequence:       sequence,
		CapturedAt:     now,
		ExpiresAt:      now.Add(topology.Policy.ObservationFreshness.Duration()),
		BackendHealthy: true,
		Domains:        domains,
	}
}

func safeLeaderStatus(topology *controllerconfig.Topology, now time.Time) reconcile.Status {
	return safeLeaderStatusForDomain(topology, "west-domain", now)
}

func safeLeaderStatusForDomain(topology *controllerconfig.Topology, domainID string, now time.Time) reconcile.Status {
	authority, err := topology.DomainAuthority(domainID)
	if err != nil {
		panic(err)
	}
	return reconcile.Status{
		ControllerID:   "controller-a",
		DomainID:       authority.DomainID,
		Mode:           reconcile.ModeActive,
		Role:           reconcile.RoleLeader,
		Phase:          model.PhaseStable,
		Reason:         reconcile.ReasonStable,
		StableOwner:    authority.PreferredOwner,
		ConsensusOwner: authority.PreferredOwner,
		FenceTerm:      1,
		LeaseExpiresAt: now.Add(topology.Policy.LeaseDuration.Duration()),
		Quorum:         true,
		RouteAgreement: true,
		TotalRoutes:    len(authority.RemotePrefixes),
		UpdatedAt:      now,
	}
}

func runnerSet(topology *controllerconfig.Topology, now time.Time, west DomainRunner, mode reconcile.Mode) map[string]DomainRunner {
	runners := make(map[string]DomainRunner, len(topology.Domains))
	template := reconcile.Status{}
	if west != nil {
		template = west.Status()
	}
	for _, domain := range topology.Domains {
		if domain.ID == "west-domain" && west != nil {
			runners[domain.ID] = west
			continue
		}
		status := safeLeaderStatusForDomain(topology, domain.ID, now)
		if mode != reconcile.ModeActive {
			status.Mode = mode
			status.Role = reconcile.RoleReadOnly
			status.Reason = reconcile.ReasonReadOnly
			status.LeaseExpiresAt = time.Time{}
		} else if template.Role == reconcile.RoleFollower {
			status.Role = reconcile.RoleFollower
			status.Reason = reconcile.ReasonLeaseHeld
		}
		runners[domain.ID] = newFakeRunner(status)
	}
	return runners
}

func readyDurability(t *testing.T, topology *controllerconfig.Topology, now time.Time, leaseHolder string) *fakePublisher {
	t.Helper()
	first := testObservation(t, topology, now, 1)
	second := first.Clone()
	second.ControllerID = "controller-b"
	states := make(map[string]*model.DomainState, len(topology.Domains))
	for _, domain := range topology.Domains {
		authority, err := topology.DomainAuthority(domain.ID)
		if err != nil {
			t.Fatal(err)
		}
		state := &model.DomainState{
			Authority:        authority,
			Activated:        true,
			Revision:         1,
			Phase:            model.PhaseStable,
			StableOwner:      authority.PreferredOwner,
			LastTransitionAt: now,
			UpdatedAt:        now,
		}
		if leaseHolder != "" {
			state.FenceTerm = 1
			state.Lease = &model.Lease{
				HolderID:      leaseHolder,
				FenceTerm:     1,
				RecordVersion: 1,
				AcquiredAt:    now,
				RenewedAt:     now,
				ExpiresAt:     now.Add(topology.Policy.LeaseDuration.Duration()),
			}
		}
		states[authority.DomainID] = state
	}
	return &fakePublisher{
		observations: map[string]*model.Observation{
			first.ControllerID:  first,
			second.ControllerID: second,
		},
		states: states,
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}
