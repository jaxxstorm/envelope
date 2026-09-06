package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
	"github.com/jaxxstorm/envelope/internal/controller/tailnet"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var ErrRunnerMutationDisabled = errors.New("controller runner mutation is disabled")

type AWSConfigLoader func(context.Context, string) (aws.Config, error)
type StoreFactory func(aws.Config, string, store.Clock, time.Duration, []store.ObserverIdentity) (store.Store, error)
type RouteControllerFactory func(aws.Config, string, controllerconfig.Policy, store.Clock) (reconcile.RouteController, error)
type ObserverFactory func(context.Context, controllerconfig.TailnetConfig, string, []model.DomainAuthority, string, string, tailnet.Options) (Observer, error)
type DomainRunnerFactory func(reconcile.Options) (DomainRunner, error)
type UUIDSourceFactory func() reconcile.UUIDSource

// Factories are the complete test seams around production I/O construction.
// NewProductionService rejects partial sets rather than silently mixing fakes
// with production clients.
type Factories struct {
	LoadTopology       func(string) (*controllerconfig.Topology, error)
	LoadAWSConfig      AWSConfigLoader
	NewStore           StoreFactory
	NewRouteController RouteControllerFactory
	NewObserver        ObserverFactory
	NewDomainRunner    DomainRunnerFactory
	NewUUIDSource      UUIDSourceFactory
	NewRegistry        func() *prometheus.Registry
	LookupEnv          func(string) (string, bool)
	Clock              store.Clock
	Listen             ListenFunc
}

// ProductionFactories loads normal AWS configuration separately for the
// authority Region and each site Region, then creates regional SDK clients.
func ProductionFactories() Factories {
	return Factories{
		LoadTopology: controllerconfig.ParseFile,
		LoadAWSConfig: func(ctx context.Context, region string) (aws.Config, error) {
			return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		},
		NewStore: func(configuration aws.Config, table string, clock store.Clock, apiTimeout time.Duration, observers []store.ObserverIdentity) (store.Store, error) {
			client := dynamodb.NewFromConfig(configuration)
			return store.NewDynamoDBStore(client, table, clock, apiTimeout, observers...)
		},
		NewRouteController: func(configuration aws.Config, region string, policy controllerconfig.Policy, clock store.Clock) (reconcile.RouteController, error) {
			client := ec2.NewFromConfig(configuration)
			return awscontrol.New(
				client,
				region,
				awscontrol.WithClock(clock),
				awscontrol.WithAPITimeout(policy.APITimeout.Duration()),
			)
		},
		NewObserver: func(
			ctx context.Context,
			configuration controllerconfig.TailnetConfig,
			controllerID string,
			authorities []model.DomainAuthority,
			tsnetAuthKey string,
			adminAPIKey string,
			options tailnet.Options,
		) (Observer, error) {
			return tailnet.New(ctx, configuration, controllerID, authorities, tsnetAuthKey, adminAPIKey, options)
		},
		NewDomainRunner: func(options reconcile.Options) (DomainRunner, error) {
			trust, err := attestation.LoadTrust(attestation.RuntimeTrustPath, options.Topology)
			if err != nil {
				return nil, err
			}
			options.Routes = attestedRoutes{RouteController: options.Routes, check: trust.Check}
			return reconcile.NewEngine(options)
		},
		NewUUIDSource: func() reconcile.UUIDSource {
			return NewRandomUUIDSource(rand.Reader)
		},
		NewRegistry: prometheus.NewRegistry,
		LookupEnv:   os.LookupEnv,
		Clock:       store.RealClock{},
		Listen:      net.Listen,
	}
}

// NewProductionService constructs every production dependency while retaining
// narrow factories for deterministic wiring tests.
func NewProductionService(
	ctx context.Context,
	runtimeConfig *controllerconfig.RuntimeConfig,
	logger *zap.Logger,
	factories Factories,
) (*Service, error) {
	if ctx == nil {
		return nil, errors.New("controller bootstrap: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtimeConfig == nil {
		return nil, errors.New("controller bootstrap: runtime configuration is nil")
	}
	if err := runtimeConfig.Validate(); err != nil {
		return nil, fmt.Errorf("controller bootstrap: runtime configuration: %w", err)
	}
	if err := factories.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	topology, err := factories.LoadTopology(runtimeConfig.TopologyPath)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: load topology: %w", err)
	}
	if err := runtimeConfig.ValidateForTopology(topology); err != nil {
		return nil, fmt.Errorf("controller bootstrap: validate process authority: %w", err)
	}
	topologyHash, err := topology.Hash()
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: topology hash: %w", err)
	}

	authorities := make([]model.DomainAuthority, 0, len(topology.Domains))
	for _, domain := range topology.Domains {
		authority, authorityErr := topology.DomainAuthority(domain.ID)
		if authorityErr != nil {
			return nil, fmt.Errorf("controller bootstrap: domain authority: %w", authorityErr)
		}
		authorities = append(authorities, authority)
	}

	tsnetAuthKey, err := topology.Tailnet.ResolveTSNetAuthKey(factories.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: resolve tsnet credentials: %w", err)
	}
	adminAPIKey, err := topology.Tailnet.ResolveAdminAPIKey(factories.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: resolve Admin API credentials: %w", err)
	}

	authorityAWS, err := factories.LoadAWSConfig(ctx, topology.DynamoDB.Region)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: load authority AWS configuration: %w", err)
	}
	if authorityAWS.Region != topology.DynamoDB.Region {
		return nil, errors.New("controller bootstrap: authority AWS configuration has the wrong Region")
	}
	allowedObservers := make([]store.ObserverIdentity, 0, len(topology.ControllerIDs))
	for _, controllerID := range topology.ControllerIDs {
		allowedObservers = append(allowedObservers, store.ObserverIdentity{
			DeploymentID: topology.DeploymentID,
			TopologyHash: topologyHash,
			ControllerID: controllerID,
		})
	}
	durableStore, err := factories.NewStore(
		authorityAWS,
		topology.DynamoDB.Table,
		factories.Clock,
		topology.Policy.APITimeout.Duration(),
		allowedObservers,
	)
	if err != nil || isNil(durableStore) {
		if err == nil {
			err = errors.New("factory returned a nil store")
		}
		return nil, fmt.Errorf("controller bootstrap: create durable store: %w", err)
	}

	scope := store.ObservationScope{DeploymentID: topology.DeploymentID, TopologyHash: topologyHash}
	existingObservations, err := durableStore.ListObservations(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap: access durable observations: %w", err)
	}
	initialSequence := uint64(0)
	for _, observation := range existingObservations {
		if observation != nil && observation.ControllerID == runtimeConfig.ControllerID && observation.Sequence > initialSequence {
			initialSequence = observation.Sequence
		}
	}
	initialLeases := make(map[string]*model.Lease)
	if !runtimeConfig.ReadOnly && !runtimeConfig.DryRun {
		for _, authority := range authorities {
			state, loadErr := durableStore.LoadDomain(ctx, store.DomainRefFor(authority))
			if errors.Is(loadErr, store.ErrNotFound) {
				continue
			}
			if loadErr != nil {
				return nil, fmt.Errorf("controller bootstrap: access durable domain %q: %w", authority.DomainID, loadErr)
			}
			if state == nil || state.Validate() != nil || !reflect.DeepEqual(state.Authority, authority) {
				return nil, fmt.Errorf("controller bootstrap: durable domain %q is invalid", authority.DomainID)
			}
			if state.Lease != nil && state.Lease.HolderID == runtimeConfig.ControllerID && state.Lease.ExpiresAt.After(factories.Clock.Now()) {
				initialLeases[authority.DomainID] = state.Lease.Clone()
			}
		}
	}

	regions := make(map[string]struct{}, len(topology.Sites))
	for _, site := range topology.Sites {
		regions[site.Region] = struct{}{}
	}
	orderedRegions := make([]string, 0, len(regions))
	for region := range regions {
		orderedRegions = append(orderedRegions, region)
	}
	sort.Strings(orderedRegions)
	routesByRegion := make(map[string]reconcile.RouteController, len(orderedRegions))
	for _, region := range orderedRegions {
		regionalAWS, loadErr := factories.LoadAWSConfig(ctx, region)
		if loadErr != nil {
			return nil, fmt.Errorf("controller bootstrap: load site AWS configuration: %w", loadErr)
		}
		if regionalAWS.Region != region {
			return nil, errors.New("controller bootstrap: site AWS configuration has the wrong Region")
		}
		routes, routeErr := factories.NewRouteController(regionalAWS, region, topology.Policy, factories.Clock)
		if routeErr != nil || isNil(routes) {
			if routeErr == nil {
				routeErr = errors.New("factory returned a nil route controller")
			}
			return nil, fmt.Errorf("controller bootstrap: create regional route controller: %w", routeErr)
		}
		routesByRegion[region] = routes
	}

	observer, err := factories.NewObserver(
		ctx,
		topology.Tailnet,
		runtimeConfig.ControllerID,
		authorities,
		tsnetAuthKey,
		adminAPIKey,
		tailnet.Options{
			StartupTimeout:  topology.Policy.RouteConvergenceTimeout.Duration(),
			SnapshotTimeout: topology.Policy.APITimeout.Duration(),
			ObservationTTL:  topology.Policy.ObservationFreshness.Duration(),
			PeerStaleAfter:  topology.Policy.ObservationFreshness.Duration(),
			ContinuityGap:   observerContinuityGap(topology.Policy),
			InitialSequence: initialSequence,
		},
	)
	// Do not retain resolved keys past observer construction.
	tsnetAuthKey, adminAPIKey = "", ""
	if err != nil || isNil(observer) {
		if err == nil {
			err = errors.New("factory returned a nil observer")
		}
		return nil, fmt.Errorf("controller bootstrap: start Tailnet observer: %w", err)
	}

	runners := make(map[string]DomainRunner, len(authorities))
	runnerStore := store.Store(durableStore)
	runnerRoutes := routesByRegion
	if runtimeConfig.ReadOnly || runtimeConfig.DryRun {
		runnerStore = readOnlyRunnerStore{reader: durableStore}
		runnerRoutes = make(map[string]reconcile.RouteController, len(routesByRegion))
		for region, routes := range routesByRegion {
			runnerRoutes[region] = readOnlyRunnerRoutes{reader: routes}
		}
	}
	for _, authority := range authorities {
		uuidSource := factories.NewUUIDSource()
		if isNil(uuidSource) {
			return nil, bootstrapObserverFailure(observer, errors.New("controller bootstrap: UUID source factory returned nil"))
		}
		runner, runnerErr := factories.NewDomainRunner(reconcile.Options{
			Topology:     topology,
			DomainID:     authority.DomainID,
			ControllerID: runtimeConfig.ControllerID,
			Store:        runnerStore,
			Routes:       runnerRoutes[authority.Region],
			Clock:        factories.Clock,
			UUIDs:        uuidSource,
			ReadOnly:     runtimeConfig.ReadOnly,
			DryRun:       runtimeConfig.DryRun,
		})
		if runnerErr != nil || isNil(runner) {
			if runnerErr == nil {
				runnerErr = errors.New("factory returned a nil domain runner")
			}
			return nil, bootstrapObserverFailure(observer, fmt.Errorf("controller bootstrap: create domain runner: %w", runnerErr))
		}
		runners[authority.DomainID] = runner
	}

	registry := factories.NewRegistry()
	if registry == nil {
		return nil, bootstrapObserverFailure(observer, errors.New("controller bootstrap: registry factory returned nil"))
	}
	mode := reconcileMode(runtimeConfig)
	publishObservations := !runtimeConfig.DryRun
	var publisher ObservationPublisher
	if publishObservations {
		// Read-only replicas intentionally publish observations so they can
		// contribute to quorum without giving their runners mutation authority.
		publisher = durableStore
	}
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        runtimeConfig.ControllerID,
		Mode:                mode,
		MetricsAddress:      runtimeConfig.MetricsAddr,
		Observer:            observer,
		DurableReader:       durableStore,
		Publisher:           publisher,
		PublishObservations: publishObservations,
		DomainRunners:       runners,
		Clock:               factories.Clock,
		Registry:            registry,
		Logger:              logger,
		Listen:              factories.Listen,
		InitialLeases:       initialLeases,
	})
	if err != nil {
		closeErr := observer.Close()
		return nil, errors.Join(err, closeErr)
	}
	return service, nil
}

// readOnlyRunnerStore preserves the complete Store type required by the
// reconciler factory while denying every write. Observation publication uses
// the original store only through the service's explicit publication path.
type readOnlyRunnerStore struct {
	reader store.Store
}

var _ store.Store = readOnlyRunnerStore{}

func (s readOnlyRunnerStore) CreateDomain(context.Context, *model.DomainState) (*model.DomainState, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) LoadDomain(ctx context.Context, ref store.DomainRef) (*model.DomainState, error) {
	return s.reader.LoadDomain(ctx, ref)
}

func (s readOnlyRunnerStore) CompareAndSwapDomain(context.Context, store.DomainRef, model.DocumentRevision, store.LeaseToken, *model.DomainState) (*model.DomainState, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) AcquireLease(context.Context, store.DomainRef, string, time.Duration) (*model.Lease, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) TakeoverLease(context.Context, store.DomainRef, string, uint64, time.Duration) (*model.Lease, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) RenewLease(context.Context, store.DomainRef, store.LeaseToken, time.Duration) (*model.Lease, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) PublishObservation(context.Context, string, *model.Observation) (*model.Observation, error) {
	return nil, ErrRunnerMutationDisabled
}

func (s readOnlyRunnerStore) ListObservations(ctx context.Context, scope store.ObservationScope) ([]*model.Observation, error) {
	return s.reader.ListObservations(ctx, scope)
}

type readOnlyRunnerRoutes struct {
	reader reconcile.RouteController
}

var _ reconcile.RouteController = readOnlyRunnerRoutes{}

func (r readOnlyRunnerRoutes) ValidateOwner(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return r.reader.ValidateOwner(ctx, authority, owner)
}

func (r readOnlyRunnerRoutes) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	return r.reader.Snapshot(ctx, authority)
}

func (r readOnlyRunnerRoutes) StableSnapshot(ctx context.Context, authority model.DomainAuthority, deadline time.Time) (model.RouteSnapshot, error) {
	reader, ok := r.reader.(interface {
		StableSnapshot(context.Context, model.DomainAuthority, time.Time) (model.RouteSnapshot, error)
	})
	if !ok {
		return model.RouteSnapshot{}, ErrRunnerMutationDisabled
	}
	return reader.StableSnapshot(ctx, authority, deadline)
}

func (f Factories) validate() error {
	if f.LoadTopology == nil || f.LoadAWSConfig == nil || f.NewStore == nil ||
		f.NewRouteController == nil || f.NewObserver == nil || f.NewDomainRunner == nil ||
		f.NewUUIDSource == nil || f.NewRegistry == nil || f.LookupEnv == nil ||
		isNil(f.Clock) || f.Listen == nil {
		return errors.New("controller bootstrap: factory set is incomplete")
	}
	return nil
}

func bootstrapObserverFailure(observer Observer, failure error) error {
	if isNil(observer) {
		return failure
	}
	return errors.Join(failure, observer.Close())
}

func observerContinuityGap(policy controllerconfig.Policy) time.Duration {
	// One minimum policy quantum tolerates ordinary wake-up jitter. Cap it so
	// continuity always expires before an observation can reach its freshness
	// boundary, including a policy configured at the minimum two intervals.
	jitter := controllerconfig.MinPolicyDuration
	if maximum := policy.ObservationFreshness.Duration() - policy.ObservationInterval.Duration() - time.Nanosecond; jitter > maximum {
		jitter = maximum
	}
	return policy.ObservationInterval.Duration() + jitter
}

// Run builds and serves the production controller until ctx is canceled.
func Run(ctx context.Context, runtimeConfig *controllerconfig.RuntimeConfig, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	service, err := NewProductionService(ctx, runtimeConfig, logger, ProductionFactories())
	if err != nil {
		return err
	}
	defer service.Close()
	logger.Info("starting Envelope production failover controller",
		zap.String("controller_id", runtimeConfig.ControllerID),
		zap.String("deployment_id", service.topology.DeploymentID),
		zap.String("topology_hash", service.topologyHash),
		zap.Int("domains", len(service.domainIDs)),
		zap.String("mode", runtimeMode(runtimeConfig)),
		zap.Bool("observation_publication", service.publishObservations),
		zap.Int("reconcile_concurrency", service.reconcileConcurrency),
		zap.String("metrics_addr", runtimeConfig.MetricsAddr),
	)
	return service.Run(ctx)
}

func runtimeMode(runtimeConfig *controllerconfig.RuntimeConfig) string {
	return string(reconcileMode(runtimeConfig))
}

func reconcileMode(runtimeConfig *controllerconfig.RuntimeConfig) reconcile.Mode {
	if runtimeConfig == nil {
		return reconcile.Mode("unknown")
	}
	if runtimeConfig.DryRun {
		return reconcile.ModeDryRun
	}
	if runtimeConfig.ReadOnly {
		return reconcile.ModeReadOnly
	}
	return reconcile.ModeActive
}

// SafeErrorReason deliberately returns only fixed strings suitable for
// production logs. The original error remains available to callers and tests.
func SafeErrorReason(err error) string {
	switch {
	case err == nil:
		return "none"
	case isContextError(err):
		return "canceled"
	case errors.Is(err, ErrInvalidService):
		return "invalid-service"
	case errors.Is(err, ErrServiceClosed):
		return "service-closed"
	case errors.Is(err, ErrHTTPServerStopped):
		return "http-server-stopped"
	default:
		return "controller-failure"
	}
}
