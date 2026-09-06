package app

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
	"github.com/jaxxstorm/envelope/internal/controller/tailnet"
	"github.com/prometheus/client_golang/prometheus"
)

func TestProductionBootstrapWiresAllAuthoritiesRegionsAndModes(t *testing.T) {
	topology := testTopology()
	capture := &bootstrapCapture{
		topology: topology,
		existing: []*model.Observation{{ControllerID: "controller-a", Sequence: 41}},
	}
	factories := testFactories(capture)
	runtimeConfig := testRuntimeConfig()
	runtimeConfig.ReadOnly = true
	service, err := NewProductionService(context.Background(), runtimeConfig, nil, factories)
	if err != nil {
		t.Fatalf("NewProductionService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	if want := []string{"us-east-2", "us-east-1", "us-west-2"}; !reflect.DeepEqual(capture.awsRegions, want) {
		t.Fatalf("AWS configuration Regions = %v, want %v", capture.awsRegions, want)
	}
	if capture.storeTable != topology.DynamoDB.Table || capture.storeRegion != topology.DynamoDB.Region {
		t.Fatalf("store table/Region = %q/%q", capture.storeTable, capture.storeRegion)
	}
	if capture.storeAPITimeout != topology.Policy.APITimeout.Duration() {
		t.Fatalf("store API timeout = %s, want %s", capture.storeAPITimeout, topology.Policy.APITimeout.Duration())
	}
	if len(capture.allowedObservers) != len(topology.ControllerIDs) {
		t.Fatalf("allowed observers = %d, want %d", len(capture.allowedObservers), len(topology.ControllerIDs))
	}
	hash, hashErr := topology.Hash()
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	for index, identity := range capture.allowedObservers {
		if identity.ControllerID != topology.ControllerIDs[index] || identity.DeploymentID != topology.DeploymentID || identity.TopologyHash != hash {
			t.Errorf("allowed observer %d = %+v", index, identity)
		}
	}
	if want := []string{"us-east-1", "us-west-2"}; !reflect.DeepEqual(capture.routeRegions, want) {
		t.Fatalf("route controller Regions = %v, want %v", capture.routeRegions, want)
	}
	if capture.observerController != "controller-a" || capture.observerAuthorityCount != len(topology.Domains) || capture.observerInitialSequence != 41 ||
		capture.observerContinuityGap != topology.Policy.ObservationInterval.Duration()+controllerconfig.MinPolicyDuration {
		t.Fatalf("observer wiring = controller %q, authorities %d, sequence %d, continuity gap %s", capture.observerController, capture.observerAuthorityCount, capture.observerInitialSequence, capture.observerContinuityGap)
	}
	if capture.tsnetKey != "tsnet-secret" || capture.adminKey != "admin-secret" {
		t.Fatal("observer did not receive both resolved credentials")
	}
	if len(capture.runnerOptions) != len(topology.Domains) || capture.uuidCalls != len(topology.Domains) {
		t.Fatalf("runner/UUID counts = %d/%d", len(capture.runnerOptions), capture.uuidCalls)
	}
	for _, options := range capture.runnerOptions {
		if !options.ReadOnly || options.DryRun || options.Store == capture.store || options.Routes == nil || options.Topology != topology || options.ControllerID != "controller-a" {
			t.Errorf("runner options = %+v", options)
		}
		if _, err := options.Store.AcquireLease(context.Background(), store.DomainRef{}, "controller-a", time.Second); !errors.Is(err, ErrRunnerMutationDisabled) {
			t.Errorf("read-only runner AcquireLease() error = %v", err)
		}
		if _, found := reflect.TypeOf(options.Routes).MethodByName("ReplaceAndWait"); found {
			t.Error("read-only runner retained a route mutation method")
		}
	}
	if service.mode != reconcile.ModeReadOnly || !service.publishObservations {
		t.Fatalf("service mode/publication = %q/%t", service.mode, service.publishObservations)
	}
	capture.observer.snapshot = func(call int) (*model.Observation, error) {
		return testObservation(t, topology, factories.Clock.Now(), uint64(call)), nil
	}
	if _, _, err := service.observeAndPublish(context.Background()); err != nil {
		t.Fatalf("read-only observation publication error = %v", err)
	}
	if capture.store.publishCalls != 1 {
		t.Fatalf("read-only observation publications = %d, want 1", capture.store.publishCalls)
	}
}

func TestProductionBootstrapDryRunWithholdsEveryRunnerWriteCapability(t *testing.T) {
	topology := testTopology()
	capture := &bootstrapCapture{topology: topology}
	factories := testFactories(capture)
	runtimeConfig := testRuntimeConfig()
	runtimeConfig.DryRun = true

	service, err := NewProductionService(context.Background(), runtimeConfig, nil, factories)
	if err != nil {
		t.Fatalf("NewProductionService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if service.mode != reconcile.ModeDryRun || service.publishObservations || service.publisher != nil {
		t.Fatalf("dry-run service mode/publication/publisher = %q/%t/%v", service.mode, service.publishObservations, service.publisher)
	}
	for _, options := range capture.runnerOptions {
		if !options.DryRun || options.ReadOnly || options.Store == capture.store {
			t.Fatalf("dry-run runner options = %+v", options)
		}
		if _, err := options.Store.CreateDomain(context.Background(), &model.DomainState{}); !errors.Is(err, ErrRunnerMutationDisabled) {
			t.Fatalf("CreateDomain() error = %v", err)
		}
		if _, err := options.Store.PublishObservation(context.Background(), topology.DeploymentID, &model.Observation{}); !errors.Is(err, ErrRunnerMutationDisabled) {
			t.Fatalf("PublishObservation() error = %v", err)
		}
		if _, found := reflect.TypeOf(options.Routes).MethodByName("ReplaceAndWait"); found {
			t.Fatal("dry-run runner retained a route mutation method")
		}
	}

	capture.observer.snapshot = func(call int) (*model.Observation, error) {
		return testObservation(t, topology, factories.Clock.Now(), uint64(call)), nil
	}
	if _, _, err := service.observeAndPublish(context.Background()); err != nil {
		t.Fatalf("dry-run observation error = %v", err)
	}
	if capture.store.publishCalls != 0 {
		t.Fatalf("dry-run observation publications = %d, want 0", capture.store.publishCalls)
	}
}

func TestProductionBootstrapSeedsLocallyHeldLeases(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	durability := readyDurability(t, topology, now, "controller-a")
	capture := &bootstrapCapture{topology: topology, domainStates: durability.states}
	factories := testFactories(capture)
	factories.NewDomainRunner = unknownBootstrapRunnerFactory(capture)
	service, err := NewProductionService(context.Background(), testRuntimeConfig(), nil, factories)
	if err != nil {
		t.Fatalf("NewProductionService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	for _, domain := range topology.Domains {
		hint, found := service.localLeaseHint(domain.ID, 0, now)
		if !found || hint.fenceTerm != 1 || !hint.expiresAt.Equal(now.Add(topology.Policy.LeaseDuration.Duration())) {
			t.Fatalf("initial lease hint for %q = %+v, %t", domain.ID, hint, found)
		}
	}
}

func TestProductionBootstrapIgnoresExpiredLocallyHeldLeases(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	durability := readyDurability(t, topology, now, "controller-a")
	for _, state := range durability.states {
		state.Lease.AcquiredAt = now.Add(-2 * topology.Policy.LeaseDuration.Duration())
		state.Lease.RenewedAt = now.Add(-topology.Policy.LeaseDuration.Duration())
		state.Lease.ExpiresAt = now
	}
	capture := &bootstrapCapture{topology: topology, domainStates: durability.states}
	factories := testFactories(capture)
	factories.NewDomainRunner = unknownBootstrapRunnerFactory(capture)
	service, err := NewProductionService(context.Background(), testRuntimeConfig(), nil, factories)
	if err != nil {
		t.Fatalf("NewProductionService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	for _, domain := range topology.Domains {
		if hint, found := service.localLeaseHint(domain.ID, 0, now); found {
			t.Fatalf("expired local lease for %q remained a scheduler hint: %+v", domain.ID, hint)
		}
	}
}

func TestObserverContinuityGapStaysInsideMinimumFreshness(t *testing.T) {
	policy := testTopology().Policy
	policy.ObservationFreshness = controllerconfig.Duration(2 * policy.ObservationInterval.Duration())
	want := policy.ObservationFreshness.Duration() - time.Nanosecond
	if got := observerContinuityGap(policy); got != want {
		t.Fatalf("observerContinuityGap() = %s, want %s", got, want)
	}
}

func TestProductionBootstrapValidatesBeforeExternalConstruction(t *testing.T) {
	topology := testTopology()
	capture := &bootstrapCapture{topology: topology}
	factories := testFactories(capture)
	runtimeConfig := testRuntimeConfig()
	runtimeConfig.ControllerID = "controller-unknown"
	service, err := NewProductionService(context.Background(), runtimeConfig, nil, factories)
	if service != nil || err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unknown controller result = service %v, error %v", service, err)
	}
	if len(capture.envLookups) != 0 || len(capture.awsRegions) != 0 || capture.observerController != "" || len(capture.runnerOptions) != 0 {
		t.Fatalf("external factories ran before identity validation: %+v", capture)
	}

	if _, err := NewProductionService(context.Background(), testRuntimeConfig(), nil, Factories{}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete factory error = %v", err)
	}
}

func TestProductionBootstrapRejectsActiveDomainCapacityBeforeExternalConstruction(t *testing.T) {
	topology := testTopologyWithDomainCounts(controllerconfig.MaxActiveDomains/2+1, (controllerconfig.MaxActiveDomains+1)/2)
	if err := topology.Validate(); err != nil {
		t.Fatalf("over-capacity passive topology is invalid: %v", err)
	}
	capture := &bootstrapCapture{topology: topology}
	factories := testFactories(capture)

	service, err := NewProductionService(context.Background(), testRuntimeConfig(), nil, factories)
	if service != nil || err == nil || !strings.Contains(err.Error(), "active domain count exceeds worker capacity") {
		t.Fatalf("NewProductionService() = %v, %v; want active capacity error", service, err)
	}
	if capture.topologyLoads != 1 || len(capture.envLookups) != 0 || len(capture.awsRegions) != 0 ||
		capture.store != nil || len(capture.routeRegions) != 0 || capture.observerController != "" ||
		len(capture.runnerOptions) != 0 || capture.uuidCalls != 0 {
		t.Fatalf("external construction ran before active capacity validation: %+v", capture)
	}
}

func TestProductionBootstrapFailsClosedAndCleansObserver(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Factories, *bootstrapCapture)
		wantErr string
		closed  bool
	}{
		{
			name: "store access",
			mutate: func(_ *Factories, capture *bootstrapCapture) {
				capture.listErr = errors.New("store unavailable")
			},
			wantErr: "access durable observations",
		},
		{
			name: "wrong AWS Region",
			mutate: func(factories *Factories, _ *bootstrapCapture) {
				factories.LoadAWSConfig = func(context.Context, string) (aws.Config, error) {
					return aws.Config{Region: "us-west-1"}, nil
				}
			},
			wantErr: "wrong Region",
		},
		{
			name: "nil UUID source",
			mutate: func(factories *Factories, _ *bootstrapCapture) {
				factories.NewUUIDSource = func() reconcile.UUIDSource { return nil }
			},
			wantErr: "UUID source",
			closed:  true,
		},
		{
			name: "nil registry",
			mutate: func(factories *Factories, _ *bootstrapCapture) {
				factories.NewRegistry = func() *prometheus.Registry { return nil }
			},
			wantErr: "registry",
			closed:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &bootstrapCapture{topology: testTopology()}
			factories := testFactories(capture)
			test.mutate(&factories, capture)
			service, err := NewProductionService(context.Background(), testRuntimeConfig(), nil, factories)
			if service != nil || err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("result = service %v, error %v; want %q", service, err, test.wantErr)
			}
			_, _, closes := capture.observer.stats()
			if got := closes > 0; got != test.closed {
				t.Fatalf("observer closed = %t, want %t", got, test.closed)
			}
		})
	}
}

func TestSafeErrorReasonNeverReturnsErrorText(t *testing.T) {
	secret := "fixture-secret-must-not-appear"
	if got := SafeErrorReason(errors.New(secret)); got != "controller-failure" || strings.Contains(got, secret) {
		t.Fatalf("SafeErrorReason() = %q", got)
	}
	if got := SafeErrorReason(context.Canceled); got != "canceled" {
		t.Fatalf("canceled reason = %q", got)
	}
	if got := SafeErrorReason(context.DeadlineExceeded); got != "canceled" {
		t.Fatalf("caller deadline reason = %q", got)
	}
	if got := SafeErrorReason(&store.APITimeoutError{Operation: "DynamoDB GetItem"}); got != "controller-failure" {
		t.Fatalf("store API timeout reason = %q", got)
	}
}

type bootstrapCapture struct {
	topology                *controllerconfig.Topology
	topologyLoads           int
	existing                []*model.Observation
	domainStates            map[string]*model.DomainState
	listErr                 error
	awsRegions              []string
	storeTable              string
	storeRegion             string
	storeAPITimeout         time.Duration
	allowedObservers        []store.ObserverIdentity
	store                   *bootstrapStore
	routeRegions            []string
	observer                *fakeObserver
	observerController      string
	observerAuthorityCount  int
	observerInitialSequence uint64
	observerContinuityGap   time.Duration
	tsnetKey                string
	adminKey                string
	envLookups              []string
	runnerOptions           []reconcile.Options
	uuidCalls               int
}

type bootstrapStore struct {
	store.Store
	existing     []*model.Observation
	domainStates map[string]*model.DomainState
	listErr      error
	publishCalls int
}

func (s *bootstrapStore) ListObservations(context.Context, store.ObservationScope) ([]*model.Observation, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return append([]*model.Observation(nil), s.existing...), nil
}

func (s *bootstrapStore) PublishObservation(_ context.Context, _ string, observation *model.Observation) (*model.Observation, error) {
	s.publishCalls++
	return observation.Clone(), nil
}

func (s *bootstrapStore) LoadDomain(_ context.Context, ref store.DomainRef) (*model.DomainState, error) {
	state := s.domainStates[ref.DomainID]
	if state == nil {
		return nil, store.ErrNotFound
	}
	return state.Clone(), nil
}

func testFactories(capture *bootstrapCapture) Factories {
	clock := store.NewFakeClock(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	capture.observer = &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }}
	return Factories{
		LoadTopology: func(string) (*controllerconfig.Topology, error) {
			capture.topologyLoads++
			return capture.topology, nil
		},
		LoadAWSConfig: func(_ context.Context, region string) (aws.Config, error) {
			capture.awsRegions = append(capture.awsRegions, region)
			return aws.Config{Region: region}, nil
		},
		NewStore: func(configuration aws.Config, table string, _ store.Clock, apiTimeout time.Duration, allowed []store.ObserverIdentity) (store.Store, error) {
			capture.storeTable = table
			capture.storeRegion = configuration.Region
			capture.storeAPITimeout = apiTimeout
			capture.allowedObservers = append([]store.ObserverIdentity(nil), allowed...)
			capture.store = &bootstrapStore{existing: capture.existing, domainStates: capture.domainStates, listErr: capture.listErr}
			return capture.store, nil
		},
		NewRouteController: func(configuration aws.Config, region string, _ controllerconfig.Policy, _ store.Clock) (reconcile.RouteController, error) {
			if configuration.Region != region {
				return nil, errors.New("Region mismatch")
			}
			capture.routeRegions = append(capture.routeRegions, region)
			return fakeRouteController{}, nil
		},
		NewObserver: func(
			_ context.Context,
			_ controllerconfig.TailnetConfig,
			controllerID string,
			authorities []model.DomainAuthority,
			tsnetKey string,
			adminKey string,
			options tailnet.Options,
		) (Observer, error) {
			capture.observerController = controllerID
			capture.observerAuthorityCount = len(authorities)
			capture.observerInitialSequence = options.InitialSequence
			capture.observerContinuityGap = options.ContinuityGap
			capture.tsnetKey = tsnetKey
			capture.adminKey = adminKey
			return capture.observer, nil
		},
		NewDomainRunner: func(options reconcile.Options) (DomainRunner, error) {
			capture.runnerOptions = append(capture.runnerOptions, options)
			status := safeLeaderStatusForDomain(capture.topology, options.DomainID, clock.Now())
			if options.ReadOnly || options.DryRun {
				status.Role = reconcile.RoleReadOnly
				status.Reason = reconcile.ReasonReadOnly
				status.LeaseExpiresAt = time.Time{}
				if options.DryRun {
					status.Mode = reconcile.ModeDryRun
				} else {
					status.Mode = reconcile.ModeReadOnly
				}
			}
			return newFakeRunner(status), nil
		},
		NewUUIDSource: func() reconcile.UUIDSource {
			capture.uuidCalls++
			return reconcile.UUIDFunc(func() string { return "transaction-id" })
		},
		NewRegistry: prometheus.NewRegistry,
		LookupEnv: func(name string) (string, bool) {
			capture.envLookups = append(capture.envLookups, name)
			switch name {
			case "CONTROLLER_TSNET_AUTH_KEY":
				return "tsnet-secret", true
			case "CONTROLLER_ADMIN_API_KEY":
				return "admin-secret", true
			default:
				return "", false
			}
		},
		Clock:  clock,
		Listen: net.Listen,
	}
}

func unknownBootstrapRunnerFactory(capture *bootstrapCapture) DomainRunnerFactory {
	return func(options reconcile.Options) (DomainRunner, error) {
		capture.runnerOptions = append(capture.runnerOptions, options)
		return newFakeRunner(reconcile.Status{
			ControllerID: options.ControllerID,
			DomainID:     options.DomainID,
			Mode:         reconcile.ModeActive,
			Role:         reconcile.RoleUnknown,
			Reason:       reconcile.ReasonStarting,
			UpdatedAt:    options.Clock.Now(),
		}), nil
	}
}

func testRuntimeConfig() *controllerconfig.RuntimeConfig {
	return &controllerconfig.RuntimeConfig{
		ControllerID: "controller-a",
		TopologyPath: "/etc/envelope/controller.json",
		MetricsAddr:  controllerconfig.DefaultMetricsAddress,
		LogLevel:     "info",
	}
}
