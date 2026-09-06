// Package app wires the standalone production controller and owns its process
// lifecycle. It intentionally has no dependency on packet-target code or
// repository scripts.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/health"
	controllermetrics "github.com/jaxxstorm/envelope/internal/controller/metrics"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	ErrInvalidService      = errors.New("controller service configuration is invalid")
	ErrServiceClosed       = errors.New("controller service is closed")
	ErrServiceAlreadyRun   = errors.New("controller service has already run")
	ErrPublicationRejected = errors.New("controller observation publication was rejected")
	ErrHTTPServerStopped   = errors.New("controller HTTP server stopped unexpectedly")
)

const (
	defaultShutdownTimeout      = 5 * time.Second
	defaultReconcileConcurrency = 4
	maxServiceDomains           = 4096
)

const (
	ReadinessReady                  = "ready"
	ReadinessProcessNotLive         = "process-not-live"
	ReadinessObserverNotRunning     = "observer-not-running"
	ReadinessObserverUnhealthy      = "observer-unhealthy"
	ReadinessStoreUnavailable       = "store-unavailable"
	ReadinessObservationUnavailable = "observation-unavailable"
	ReadinessObservationStale       = "observation-stale"
	ReadinessDomainMissing          = "domain-status-missing"
	ReadinessDomainUnknown          = "domain-status-unknown"
	ReadinessDomainStale            = "domain-status-stale"
	ReadinessDomainDegraded         = "domain-degraded"
	ReadinessDomainUnsafe           = "domain-unsafe"
)

// Observer is the complete Tailnet surface required by the service.
type Observer interface {
	Snapshot(context.Context) (*model.Observation, error)
	Close() error
}

// ObservationPublisher is the only durable operation performed by the
// observer loop.
type ObservationPublisher interface {
	PublishObservation(context.Context, string, *model.Observation) (*model.Observation, error)
}

// DurableReader is the read-only store surface used to establish readiness.
// It is separate from ObservationPublisher so dry-run services retain no
// durable write path.
type DurableReader interface {
	LoadDomain(context.Context, store.DomainRef) (*model.DomainState, error)
	ListObservations(context.Context, store.ObservationScope) ([]*model.Observation, error)
}

// DomainRunner performs independently serialized reconciliation passes. The
// service owns cross-domain scheduling and its process-wide concurrency bound.
type DomainRunner interface {
	Reconcile(context.Context) error
	Status() reconcile.Status
	SetStatusCallback(func(reconcile.Status))
}

type ListenFunc func(network, address string) (net.Listener, error)

type ServiceOptions struct {
	Topology             *controllerconfig.Topology
	ControllerID         string
	Mode                 reconcile.Mode
	MetricsAddress       string
	Observer             Observer
	DurableReader        DurableReader
	Publisher            ObservationPublisher
	PublishObservations  bool
	DomainRunners        map[string]DomainRunner
	ReconcileConcurrency int
	Clock                store.Clock
	Registry             *prometheus.Registry
	Logger               *zap.Logger
	Listen               ListenFunc
	ShutdownTimeout      time.Duration
	InitialLeases        map[string]*model.Lease
}

type durableDomainEvidence struct {
	checkedAt             time.Time
	quorumValidUntil      time.Time
	quorum                bool
	reason                reconcile.StatusReason
	consensusOwner        string
	stateValid            bool
	transactionStable     bool
	stableOwner           string
	leaseHolder           string
	leaseFenceTerm        model.FenceTerm
	leaseExpiresAt        time.Time
	leaseHolderConfirmed  bool
	leaseHolderValidUntil time.Time
}

type localLeaseHint struct {
	fenceTerm model.FenceTerm
	expiresAt time.Time
}

type serviceState struct {
	mu                    sync.RWMutex
	live                  bool
	observerRunning       bool
	observerHealthy       bool
	storeHealthy          bool
	publicationHealthy    bool
	lastObservedCaptured  time.Time
	lastObservedExpires   time.Time
	lastPublishedCaptured time.Time
	lastPublishedExpires  time.Time
	domains               map[string]reconcile.Status
	durableDomains        map[string]durableDomainEvidence
}

// Service owns one observer loop, one bounded domain scheduler, and the private
// operational HTTP server.
type Service struct {
	topology             *controllerconfig.Topology
	controllerID         string
	topologyHash         string
	mode                 reconcile.Mode
	metricsAddress       string
	observer             Observer
	durableReader        DurableReader
	publisher            ObservationPublisher
	publishObservations  bool
	domainRunners        map[string]DomainRunner
	domainIDs            []string
	authorities          map[string]model.DomainAuthority
	reconcileConcurrency int
	clock                store.Clock
	registry             *prometheus.Registry
	metrics              *controllermetrics.Metrics
	handler              http.Handler
	logger               *zap.Logger
	listen               ListenFunc
	shutdownTimeout      time.Duration
	state                serviceState
	leaseHintMu          sync.Mutex
	leaseHints           map[string]localLeaseHint

	lifecycleMu sync.Mutex
	runStarted  bool
	closed      bool
	runCancel   context.CancelFunc
	server      *http.Server
	listener    net.Listener

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Topology == nil {
		return nil, fmt.Errorf("%w: topology is nil", ErrInvalidService)
	}
	if err := options.Topology.Validate(); err != nil {
		return nil, fmt.Errorf("%w: topology: %v", ErrInvalidService, err)
	}
	if !options.Topology.HasControllerID(options.ControllerID) {
		return nil, fmt.Errorf("%w: controller ID is not allowlisted", ErrInvalidService)
	}
	switch options.Mode {
	case reconcile.ModeActive, reconcile.ModeReadOnly, reconcile.ModeDryRun:
	default:
		return nil, fmt.Errorf("%w: reconcile mode is invalid", ErrInvalidService)
	}
	if options.MetricsAddress == "" {
		return nil, fmt.Errorf("%w: metrics address is empty", ErrInvalidService)
	}
	if isNil(options.Observer) {
		return nil, fmt.Errorf("%w: observer is nil", ErrInvalidService)
	}
	if isNil(options.DurableReader) {
		return nil, fmt.Errorf("%w: durable reader is nil", ErrInvalidService)
	}
	if options.Mode == reconcile.ModeDryRun && options.PublishObservations {
		return nil, fmt.Errorf("%w: dry-run cannot publish observations", ErrInvalidService)
	}
	if options.Mode == reconcile.ModeActive && !options.PublishObservations {
		return nil, fmt.Errorf("%w: active mode must publish observations", ErrInvalidService)
	}
	if options.PublishObservations != !isNil(options.Publisher) {
		return nil, fmt.Errorf("%w: observation publisher does not match publication policy", ErrInvalidService)
	}
	if isNil(options.Clock) {
		return nil, fmt.Errorf("%w: clock is nil", ErrInvalidService)
	}
	if options.Mode == reconcile.ModeActive && len(options.Topology.Domains) > controllerconfig.MaxActiveDomains {
		return nil, fmt.Errorf("%w: active domain count exceeds worker capacity %d", ErrInvalidService, controllerconfig.MaxActiveDomains)
	}
	shutdownTimeout := options.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = defaultShutdownTimeout
	}
	if shutdownTimeout < 0 || shutdownTimeout > time.Minute {
		return nil, fmt.Errorf("%w: shutdown timeout is outside its bound", ErrInvalidService)
	}
	reconcileConcurrency := options.ReconcileConcurrency
	if reconcileConcurrency == 0 {
		if options.Mode == reconcile.ModeActive {
			reconcileConcurrency = len(options.Topology.Domains)
		} else {
			reconcileConcurrency = defaultReconcileConcurrency
		}
	}
	if reconcileConcurrency < 1 || reconcileConcurrency > controllerconfig.MaxActiveDomains {
		return nil, fmt.Errorf("%w: reconcile concurrency must be between 1 and %d", ErrInvalidService, controllerconfig.MaxActiveDomains)
	}
	if len(options.Topology.Domains) > maxServiceDomains {
		return nil, fmt.Errorf("%w: domain count exceeds %d", ErrInvalidService, maxServiceDomains)
	}
	// A route call cannot be safely preempted after it may have committed. One
	// slot per active domain keeps another held lease independent of that call.
	if options.Mode == reconcile.ModeActive && reconcileConcurrency < len(options.Topology.Domains) {
		return nil, fmt.Errorf("%w: active reconcile concurrency must cover every domain", ErrInvalidService)
	}
	if len(options.DomainRunners) != len(options.Topology.Domains) {
		return nil, fmt.Errorf("%w: expected one runner for each domain", ErrInvalidService)
	}

	authorityList := make([]model.DomainAuthority, 0, len(options.Topology.Domains))
	authorities := make(map[string]model.DomainAuthority, len(options.Topology.Domains))
	domainIDs := make([]string, 0, len(options.Topology.Domains))
	domainRunners := make(map[string]DomainRunner, len(options.DomainRunners))
	for _, domain := range options.Topology.Domains {
		runner, found := options.DomainRunners[domain.ID]
		if !found || isNil(runner) {
			return nil, fmt.Errorf("%w: domain %q has no runner", ErrInvalidService, domain.ID)
		}
		if runner.Status().Mode != options.Mode {
			return nil, fmt.Errorf("%w: domain %q runner mode does not match service mode", ErrInvalidService, domain.ID)
		}
		authority, err := options.Topology.DomainAuthority(domain.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: domain authority: %v", ErrInvalidService, err)
		}
		authorityList = append(authorityList, authority)
		authorities[domain.ID] = authority
		domainRunners[domain.ID] = runner
		domainIDs = append(domainIDs, domain.ID)
	}
	for domainID := range options.DomainRunners {
		if _, found := authorities[domainID]; !found {
			return nil, fmt.Errorf("%w: runner for unknown domain %q", ErrInvalidService, domainID)
		}
	}
	sort.Strings(domainIDs)
	leaseHints := make(map[string]localLeaseHint, len(options.InitialLeases))
	hintNow := options.Clock.Now()
	for domainID, lease := range options.InitialLeases {
		if _, found := authorities[domainID]; !found {
			return nil, fmt.Errorf("%w: initial lease for unknown domain %q", ErrInvalidService, domainID)
		}
		if lease == nil || lease.Validate() != nil || lease.HolderID != options.ControllerID {
			return nil, fmt.Errorf("%w: initial lease for domain %q is invalid or not locally held", ErrInvalidService, domainID)
		}
		if lease.ExpiresAt.After(hintNow) {
			leaseHints[domainID] = localLeaseHint{fenceTerm: lease.FenceTerm, expiresAt: lease.ExpiresAt}
		}
	}

	registry := options.Registry
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	metrics, err := controllermetrics.New(registry, options.ControllerID, authorityList, options.Clock.Now)
	if err != nil {
		return nil, fmt.Errorf("%w: metrics: %v", ErrInvalidService, err)
	}

	logger := options.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	listen := options.Listen
	if listen == nil {
		listen = net.Listen
	}
	topologyHash, err := options.Topology.Hash()
	if err != nil {
		return nil, fmt.Errorf("%w: topology hash: %v", ErrInvalidService, err)
	}

	service := &Service{
		topology:             options.Topology,
		controllerID:         options.ControllerID,
		topologyHash:         topologyHash,
		mode:                 options.Mode,
		metricsAddress:       options.MetricsAddress,
		observer:             options.Observer,
		durableReader:        options.DurableReader,
		publisher:            options.Publisher,
		publishObservations:  options.PublishObservations,
		domainRunners:        domainRunners,
		domainIDs:            domainIDs,
		authorities:          authorities,
		reconcileConcurrency: min(reconcileConcurrency, len(domainIDs)),
		clock:                options.Clock,
		registry:             registry,
		metrics:              metrics,
		logger:               logger,
		listen:               listen,
		shutdownTimeout:      shutdownTimeout,
		leaseHints:           leaseHints,
		closeDone:            make(chan struct{}),
	}
	service.state.domains = make(map[string]reconcile.Status, len(domainIDs))
	service.state.durableDomains = make(map[string]durableDomainEvidence, len(domainIDs))
	service.metrics.SetObservationPublicationEnabled(service.publishObservations)
	handler, err := controllermetrics.NewHandler(registry, service)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP handler: %v", ErrInvalidService, err)
	}
	service.handler = handler

	for _, domainID := range domainIDs {
		runner := service.domainRunners[domainID]
		service.recordDomainStatus(domainID, runner.Status())
		id := domainID
		runner.SetStatusCallback(func(status reconcile.Status) {
			service.recordDomainStatus(id, status)
		})
	}
	return service, nil
}

// Run starts every bounded loop and the private HTTP server. Expected parent
// cancellation is normalized to a nil result after clean shutdown.
func (s *Service) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return fmt.Errorf("%w: service or context is nil", ErrInvalidService)
	}
	if ctx.Err() != nil {
		return s.Close()
	}

	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return ErrServiceClosed
	}
	if s.runStarted {
		s.lifecycleMu.Unlock()
		return ErrServiceAlreadyRun
	}
	s.runStarted = true
	s.lifecycleMu.Unlock()

	listener, err := s.listen("tcp", s.metricsAddress)
	if err != nil {
		closeErr := s.Close()
		return errors.Join(fmt.Errorf("controller HTTP listen: %w", err), closeErr)
	}
	runContext, cancel := context.WithCancel(ctx)
	server := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		cancel()
		_ = listener.Close()
		return ErrServiceClosed
	}
	s.runCancel = cancel
	s.server = server
	s.listener = listener
	s.setLive(true)
	s.lifecycleMu.Unlock()
	defer s.setLive(false)

	group, groupContext := errgroup.WithContext(runContext)
	group.Go(func() error {
		return s.runObserver(groupContext)
	})
	group.Go(func() error {
		return s.runDurableProbe(groupContext)
	})
	group.Go(func() error {
		return s.runReconciler(groupContext)
	})
	group.Go(func() error {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) && groupContext.Err() != nil {
			return nil
		}
		if err == nil {
			return ErrHTTPServerStopped
		}
		return fmt.Errorf("controller HTTP server: %w", err)
	})
	group.Go(func() error {
		<-groupContext.Done()
		_ = s.Close()
		return nil
	})

	runErr := group.Wait()
	closeErr := s.Close()
	if isContextError(runErr) {
		runErr = nil
	}
	return errors.Join(runErr, closeErr)
}

func (s *Service) runReconciler(ctx context.Context) error {
	type reconcileJob struct {
		domainID string
		runner   DomainRunner
	}
	type reconcileResult struct {
		domainID string
		runner   DomainRunner
		err      error
	}

	jobs := make(chan reconcileJob, s.reconcileConcurrency)
	results := make(chan reconcileResult, s.reconcileConcurrency)
	var workers sync.WaitGroup
	for range s.reconcileConcurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				var job reconcileJob
				var open bool
				select {
				case <-ctx.Done():
					return
				case job, open = <-jobs:
					if !open {
						return
					}
				}
				err := job.runner.Reconcile(ctx)
				select {
				case results <- reconcileResult{domainID: job.domainID, runner: job.runner, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	defer func() {
		close(jobs)
		workers.Wait()
	}()

	inFlight := make(map[string]bool, len(s.domainIDs))
	pending := make(map[string]bool, len(s.domainIDs))
	active := 0
	nextDomain := 0
	dangerEpoch := uint64(1)
	dangerDispatched := make(map[string]uint64, len(s.domainIDs))
	dangerNeedsFairDispatch := false
	// Ticks coalesce behind the currently open generation. A domain cannot be
	// made pending again until every domain in that generation was dispatched.
	generationOpen := false
	generationQueued := false
	startGeneration := func() {
		for _, domainID := range s.domainIDs {
			pending[domainID] = true
		}
		generationOpen = true
	}
	nextPending := func() (int, leasePriority, bool) {
		start := nextDomain
		now := s.clock.Now()
		for _, priority := range []leasePriority{leasePriorityDanger, leasePriorityRenewal, leasePriorityNone} {
			for checked := 0; checked < len(s.domainIDs); checked++ {
				index := (start + checked) % len(s.domainIDs)
				domainID := s.domainIDs[index]
				runner := s.domainRunners[domainID]
				if !pending[domainID] || inFlight[domainID] || s.leasePriority(domainID, runner.Status(), now) != priority {
					continue
				}
				return index, priority, true
			}
		}
		return 0, leasePriorityNone, false
	}
	nextDangerBypass := func() (int, bool) {
		start := nextDomain
		now := s.clock.Now()
		for checked := 0; checked < len(s.domainIDs); checked++ {
			index := (start + checked) % len(s.domainIDs)
			domainID := s.domainIDs[index]
			if pending[domainID] || inFlight[domainID] || dangerDispatched[domainID] == dangerEpoch {
				continue
			}
			if s.leasePriority(domainID, s.domainRunners[domainID].Status(), now) == leasePriorityDanger {
				return index, true
			}
		}
		return 0, false
	}
	dispatch := func() {
		for {
			for active < s.reconcileConcurrency {
				index := 0
				priority := leasePriorityNone
				found := false
				bypass := false
				if dangerNeedsFairDispatch {
					index, priority, found = nextPending()
				}
				if !found && !dangerNeedsFairDispatch {
					index, found = nextDangerBypass()
					bypass = found
				}
				if !found {
					index, priority, found = nextPending()
				}
				if !found && dangerNeedsFairDispatch {
					index, found = nextDangerBypass()
					bypass = found
				}
				if !found {
					break
				}
				domainID := s.domainIDs[index]
				runner := s.domainRunners[domainID]
				select {
				case jobs <- reconcileJob{domainID: domainID, runner: runner}:
					if bypass {
						dangerNeedsFairDispatch = true
					} else {
						pending[domainID] = false
						dangerNeedsFairDispatch = false
					}
					if bypass || priority == leasePriorityDanger {
						dangerDispatched[domainID] = dangerEpoch
					}
					inFlight[domainID] = true
					active++
					nextDomain = (index + 1) % len(s.domainIDs)
				case <-ctx.Done():
					return
				default:
					return
				}
			}

			if !generationOpen {
				return
			}
			for _, domainID := range s.domainIDs {
				if pending[domainID] {
					return
				}
			}
			generationOpen = false
			if !generationQueued {
				return
			}
			generationQueued = false
			startGeneration()
		}
	}

	startGeneration()
	dispatch()
	interval := min(s.topology.Policy.ObservationInterval.Duration(), s.topology.Policy.LeaseRenewInterval.Duration())
	wake := s.clock.After(interval)
	for {
		select {
		case result := <-results:
			inFlight[result.domainID] = false
			active--
			if result.err != nil && ctx.Err() == nil {
				s.logger.Warn("controller domain reconciliation failed",
					zap.String("domain_id", result.domainID),
					zap.String("reason", safeReadinessFailureReason(result.runner.Status().Reason, "reconcile-failed")),
				)
			}
			dispatch()
		case <-wake:
			dangerEpoch++
			if dangerEpoch == 0 {
				clear(dangerDispatched)
				dangerEpoch = 1
			}
			if generationOpen {
				generationQueued = true
			} else {
				startGeneration()
			}
			dispatch()
			wake = s.clock.After(interval)
		case <-ctx.Done():
			return nil
		}
	}
}

type leasePriority uint8

const (
	leasePriorityNone leasePriority = iota
	leasePriorityRenewal
	leasePriorityDanger
)

func (s *Service) leasePriority(domainID string, status reconcile.Status, now time.Time) leasePriority {
	if status.Mode != reconcile.ModeActive {
		return leasePriorityNone
	}
	expiresAt := time.Time{}
	unknownLease := false
	switch status.Role {
	case reconcile.RoleLeader:
		expiresAt = status.LeaseExpiresAt
	case reconcile.RoleUnknown:
		hint, found := s.localLeaseHint(domainID, status.FenceTerm, now)
		if !found {
			return leasePriorityNone
		}
		expiresAt = hint.expiresAt
		unknownLease = true
	default:
		return leasePriorityNone
	}
	if expiresAt.IsZero() {
		return leasePriorityNone
	}
	if !expiresAt.After(now) || expiresAt.Sub(now) <= s.topology.Policy.LeaseDangerWindow.Duration() {
		return leasePriorityDanger
	}
	if unknownLease {
		return leasePriorityRenewal
	}
	duration := s.topology.Policy.LeaseDuration.Duration()
	renewalDueAt := expiresAt.Add(-duration + s.topology.Policy.LeaseRenewInterval.Duration())
	if !now.Before(renewalDueAt) {
		return leasePriorityRenewal
	}
	return leasePriorityNone
}

func (s *Service) updateLocalLeaseHint(domainID string, status reconcile.Status, trusted bool) {
	now := s.clock.Now()
	s.leaseHintMu.Lock()
	defer s.leaseHintMu.Unlock()

	if !trusted || status.Mode != reconcile.ModeActive {
		delete(s.leaseHints, domainID)
		return
	}
	switch status.Role {
	case reconcile.RoleLeader:
		if status.FenceTerm == 0 || !status.LeaseExpiresAt.After(now) {
			delete(s.leaseHints, domainID)
			return
		}
		s.leaseHints[domainID] = localLeaseHint{fenceTerm: status.FenceTerm, expiresAt: status.LeaseExpiresAt}
	case reconcile.RoleFollower, reconcile.RoleReadOnly:
		delete(s.leaseHints, domainID)
	case reconcile.RoleUnknown:
		hint, found := s.leaseHints[domainID]
		if found && (!hint.expiresAt.After(now) || status.FenceTerm != 0 && status.FenceTerm != hint.fenceTerm) {
			delete(s.leaseHints, domainID)
		}
	default:
		delete(s.leaseHints, domainID)
	}
}

func (s *Service) localLeaseHint(domainID string, fenceTerm model.FenceTerm, now time.Time) (localLeaseHint, bool) {
	s.leaseHintMu.Lock()
	defer s.leaseHintMu.Unlock()
	hint, found := s.leaseHints[domainID]
	if !found {
		return localLeaseHint{}, false
	}
	if !hint.expiresAt.After(now) || fenceTerm != 0 && fenceTerm != hint.fenceTerm {
		delete(s.leaseHints, domainID)
		return localLeaseHint{}, false
	}
	return hint, true
}

func (s *Service) leaseRenewalUrgent(status reconcile.Status, now time.Time) bool {
	return s.leasePriority("", status, now) >= leasePriorityRenewal
}

func (s *Service) runObserver(ctx context.Context) error {
	s.setObserverRunning(true)
	defer s.setObserverRunning(false)
	interval := s.topology.Policy.ObservationInterval.Duration()
	nextAttempt := s.clock.Now()
	for {
		stage, reason, err := s.observeAndPublish(ctx)
		if err != nil && ctx.Err() == nil {
			s.logger.Warn("controller observation attempt failed",
				zap.String("stage", stage),
				zap.String("reason", reason),
			)
		}
		nextAttempt = nextAttempt.Add(interval)
		now := s.clock.Now()
		if nextAttempt.Before(now) {
			nextAttempt = now
		}
		if err := store.Wait(ctx, s.clock, nextAttempt.Sub(now)); err != nil {
			return nil
		}
	}
}

func (s *Service) observeAndPublish(ctx context.Context) (string, string, error) {
	observation, err := s.observer.Snapshot(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.setObserverHealthy(false)
			s.metrics.RecordSnapshot(false)
		}
		return "snapshot", ReadinessObserverUnhealthy, err
	}
	if err := s.validateObservation(observation); err != nil {
		s.setObserverHealthy(false)
		s.metrics.RecordSnapshot(false)
		return "validation", string(reconcile.ReasonObservationInvalid), err
	}
	s.setObserverHealthy(true)
	s.recordObservation(observation)
	s.metrics.RecordSnapshot(true)
	if !s.publishObservations {
		s.metrics.RecordPublicationSkipped()
		return "none", "none", nil
	}

	published, err := s.publisher.PublishObservation(ctx, s.topology.DeploymentID, observation)
	if err != nil {
		if ctx.Err() == nil {
			s.setPublicationHealthy(false)
			s.setStoreHealthy(false)
			s.metrics.RecordPublishFailure()
		}
		return "publication", string(reconcile.ReasonStoreUnavailable), err
	}
	if err := s.validatePublication(observation, published); err != nil {
		s.setPublicationHealthy(false)
		s.setStoreHealthy(false)
		s.metrics.RecordPublishFailure()
		return "publication-validation", string(reconcile.ReasonObservationInvalid), err
	}
	s.recordPublication(published)
	s.metrics.RecordPublication(published)
	return "none", "none", nil
}

func (s *Service) runDurableProbe(ctx context.Context) error {
	for {
		if err := s.refreshDurableEvidence(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("controller durable readiness check failed",
				zap.String("stage", "durable-read"),
				zap.String("reason", string(reconcile.ReasonStoreUnavailable)),
			)
		}
		if err := store.Wait(ctx, s.clock, s.topology.Policy.ObservationInterval.Duration()); err != nil {
			return nil
		}
	}
}

func (s *Service) refreshDurableEvidence(ctx context.Context) error {
	now := s.clock.Now()
	listed, err := s.durableReader.ListObservations(ctx, store.ObservationScope{
		DeploymentID: s.topology.DeploymentID,
		TopologyHash: s.topologyHash,
	})
	if err != nil {
		if ctx.Err() == nil {
			s.recordDurableEvidence(now, false, nil)
		}
		return err
	}
	observations := make([]model.Observation, 0, len(listed))
	for _, observation := range listed {
		if observation != nil {
			observations = append(observations, *observation.Clone())
		}
	}

	evidenceByDomain := make(map[string]durableDomainEvidence, len(s.domainIDs))
	storeHealthy := true
	var accessErrors []error
	for _, domainID := range s.domainIDs {
		authority := s.authorities[domainID]
		evidence := durableDomainEvidence{checkedAt: now}
		result := health.Evaluate(now, authority, observations, health.QuorumPolicy{
			AllowedControllerIDs: s.topology.ControllerIDs,
			Quorum:               s.topology.Policy.ObservationQuorum,
			Freshness:            s.topology.Policy.ObservationFreshness.Duration(),
		})
		if result.Consensus == nil {
			evidence.reason = statusReasonForHealth(result.Reason)
		} else {
			evidence.quorum = true
			evidence.consensusOwner = result.Consensus.Owner
			evidence.quorumValidUntil = quorumValidUntil(observations, result.Consensus, s.topology.Policy.ObservationQuorum, s.topology.Policy.ObservationFreshness.Duration())
		}

		state, loadErr := s.durableReader.LoadDomain(ctx, store.DomainRefFor(authority))
		switch {
		case errors.Is(loadErr, store.ErrNotFound):
			evidence.reason = reconcile.ReasonDomainNotInitialized
		case loadErr != nil:
			storeHealthy = false
			evidence.reason = reconcile.ReasonStoreUnavailable
			accessErrors = append(accessErrors, loadErr)
		case state == nil || state.Validate() != nil || !reflect.DeepEqual(state.Authority, authority):
			evidence.reason = reconcile.ReasonInvariant
		default:
			evidence.stateValid = true
			evidence.transactionStable = state.Phase == model.PhaseStable && state.Intent == nil && state.Error == nil && (s.mode != reconcile.ModeActive || state.Activated)
			evidence.stableOwner = state.StableOwner
			if state.Lease != nil {
				evidence.leaseHolder = state.Lease.HolderID
				evidence.leaseFenceTerm = state.Lease.FenceTerm
				evidence.leaseExpiresAt = state.Lease.ExpiresAt
				evidence.leaseHolderValidUntil = s.confirmedLeaseHolderUntil(now, state.Lease, result.Consensus, observations)
				evidence.leaseHolderConfirmed = !evidence.leaseHolderValidUntil.IsZero()
			}
		}
		evidenceByDomain[domainID] = evidence
	}
	s.recordDurableEvidence(now, storeHealthy, evidenceByDomain)
	return errors.Join(accessErrors...)
}

func (s *Service) confirmedLeaseHolderUntil(now time.Time, lease *model.Lease, consensus *health.Consensus, observations []model.Observation) time.Time {
	if lease == nil || lease.Validate() != nil || s.leaseInDangerWindow(now, lease.ExpiresAt) || !s.topology.HasControllerID(lease.HolderID) || consensus == nil {
		return time.Time{}
	}
	contributes := false
	for _, controllerID := range consensus.ContributingControllerIDs {
		if controllerID == lease.HolderID {
			contributes = true
			break
		}
	}
	if !contributes {
		return time.Time{}
	}

	matches := 0
	validUntil := time.Time{}
	for index := range observations {
		observation := observations[index]
		if observation.ControllerID != lease.HolderID {
			continue
		}
		matches++
		validUntil = observation.CapturedAt.Add(s.topology.Policy.ObservationFreshness.Duration())
		if observation.ExpiresAt.Before(validUntil) {
			validUntil = observation.ExpiresAt
		}
	}
	if matches != 1 || !validUntil.After(now) {
		return time.Time{}
	}
	return validUntil
}

func (s *Service) validateObservation(observation *model.Observation) error {
	if observation == nil || observation.Validate() != nil {
		return ErrPublicationRejected
	}
	if observation.ControllerID != s.controllerID || observation.TopologyHash != s.topologyHash || len(observation.Domains) != len(s.authorities) {
		return ErrPublicationRejected
	}
	for domainID := range s.authorities {
		if _, found := observation.Domains[domainID]; !found {
			return ErrPublicationRejected
		}
	}
	return nil
}

func (s *Service) validatePublication(sent, published *model.Observation) error {
	if published == nil || published.Validate() != nil {
		return ErrPublicationRejected
	}
	if !reflect.DeepEqual(sent, published) {
		return ErrPublicationRejected
	}
	return nil
}

func quorumValidUntil(observations []model.Observation, consensus *health.Consensus, quorum int, freshness time.Duration) time.Time {
	if consensus == nil || quorum <= 0 {
		return time.Time{}
	}
	contributors := make(map[string]struct{}, len(consensus.ContributingControllerIDs))
	for _, controllerID := range consensus.ContributingControllerIDs {
		contributors[controllerID] = struct{}{}
	}
	deadlines := make([]time.Time, 0, len(contributors))
	for index := range observations {
		observation := observations[index]
		if _, found := contributors[observation.ControllerID]; !found {
			continue
		}
		deadline := observation.CapturedAt.Add(freshness)
		if observation.ExpiresAt.Before(deadline) {
			deadline = observation.ExpiresAt
		}
		deadlines = append(deadlines, deadline)
	}
	if len(deadlines) < quorum {
		return time.Time{}
	}
	sort.Slice(deadlines, func(first, second int) bool {
		return deadlines[first].After(deadlines[second])
	})
	return deadlines[quorum-1]
}

func statusReasonForHealth(reason health.Reason) reconcile.StatusReason {
	switch reason {
	case health.ReasonNoQuorum:
		return reconcile.ReasonObservationNoQuorum
	case health.ReasonStaleObservation:
		return reconcile.ReasonObservationStale
	case health.ReasonInvalidInput:
		return reconcile.ReasonObservationInvalid
	case health.ReasonDisagreement:
		return reconcile.ReasonObservationDisagreement
	case health.ReasonUnknownOwner:
		return reconcile.ReasonOwnerUnknown
	case health.ReasonUnhealthyOwner:
		return reconcile.ReasonOwnerUnhealthy
	default:
		return reconcile.ReasonObservationQuorum
	}
}

func (s *Service) recordDomainStatus(domainID string, status reconcile.Status) {
	authority := s.authorities[domainID]
	trusted := status.DomainID == domainID && status.ControllerID == s.controllerID && status.Mode == s.mode
	if !trusted {
		status = reconcile.Status{
			ControllerID: s.controllerID,
			DomainID:     domainID,
			Mode:         s.mode,
			Role:         reconcile.RoleUnknown,
			Reason:       reconcile.ReasonInvariant,
			TotalRoutes:  len(authority.RemotePrefixes),
			UpdatedAt:    s.clock.Now(),
		}
	}
	s.updateLocalLeaseHint(domainID, status, trusted)
	s.state.mu.Lock()
	previous, exists := s.state.domains[domainID]
	if exists && previous == status {
		s.state.mu.Unlock()
		return
	}
	s.state.domains[domainID] = status
	s.state.mu.Unlock()
	s.metrics.RecordStatus(status)
}

func (s *Service) setLive(live bool) {
	s.state.mu.Lock()
	s.state.live = live
	s.state.mu.Unlock()
	s.metrics.SetProcessLive(live)
}

func (s *Service) setObserverRunning(running bool) {
	s.state.mu.Lock()
	s.state.observerRunning = running
	s.state.mu.Unlock()
	s.metrics.SetObserverRunning(running)
}

func (s *Service) setObserverHealthy(healthy bool) {
	s.state.mu.Lock()
	s.state.observerHealthy = healthy
	s.state.mu.Unlock()
}

func (s *Service) setStoreHealthy(healthy bool) {
	s.state.mu.Lock()
	s.state.storeHealthy = healthy
	s.state.mu.Unlock()
	s.metrics.SetStoreHealthy(healthy)
}

func (s *Service) setPublicationHealthy(healthy bool) {
	s.state.mu.Lock()
	s.state.publicationHealthy = healthy
	s.state.mu.Unlock()
}

func (s *Service) recordObservation(observation *model.Observation) {
	s.state.mu.Lock()
	s.state.lastObservedCaptured = observation.CapturedAt
	s.state.lastObservedExpires = observation.ExpiresAt
	s.state.mu.Unlock()
}

func (s *Service) recordPublication(observation *model.Observation) {
	s.state.mu.Lock()
	s.state.storeHealthy = true
	s.state.publicationHealthy = true
	s.state.lastPublishedCaptured = observation.CapturedAt
	s.state.lastPublishedExpires = observation.ExpiresAt
	s.state.mu.Unlock()
	s.metrics.SetStoreHealthy(true)
}

func (s *Service) recordDurableEvidence(checkedAt time.Time, healthy bool, evidence map[string]durableDomainEvidence) {
	if evidence == nil {
		evidence = make(map[string]durableDomainEvidence, len(s.domainIDs))
		for _, domainID := range s.domainIDs {
			evidence[domainID] = durableDomainEvidence{checkedAt: checkedAt, reason: reconcile.ReasonStoreUnavailable}
		}
	}
	s.state.mu.Lock()
	s.state.storeHealthy = healthy
	s.state.durableDomains = evidence
	s.state.mu.Unlock()
	s.metrics.SetStoreHealthy(healthy)
	for _, domainID := range s.domainIDs {
		domainEvidence := evidence[domainID]
		s.metrics.RecordReadinessEvidence(domainID, domainEvidence.quorum, domainEvidence.leaseHolderConfirmed)
	}
}

// Healthy reports process liveness only. Degraded control state is expressed
// by Readiness and metrics, not by the liveness endpoint.
func (s *Service) Healthy() bool {
	if s == nil {
		return false
	}
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	return s.state.live
}

// Readiness requires a fresh local observation, current durable evidence, and
// one independently confirmed safe status for every configured domain.
func (s *Service) Readiness() (bool, string) {
	if s == nil {
		return false, ReadinessProcessNotLive
	}
	s.state.mu.RLock()
	live := s.state.live
	observerRunning := s.state.observerRunning
	observerHealthy := s.state.observerHealthy
	storeHealthy := s.state.storeHealthy
	publicationHealthy := s.state.publicationHealthy
	observedCapturedAt := s.state.lastObservedCaptured
	observedExpiresAt := s.state.lastObservedExpires
	publishedCapturedAt := s.state.lastPublishedCaptured
	publishedExpiresAt := s.state.lastPublishedExpires
	statuses := make(map[string]reconcile.Status, len(s.state.domains))
	for domainID, status := range s.state.domains {
		statuses[domainID] = status
	}
	durableDomains := make(map[string]durableDomainEvidence, len(s.state.durableDomains))
	for domainID, evidence := range s.state.durableDomains {
		durableDomains[domainID] = evidence
	}
	s.state.mu.RUnlock()

	if !live {
		return false, ReadinessProcessNotLive
	}
	if !observerRunning {
		return false, ReadinessObserverNotRunning
	}
	if !observerHealthy {
		return false, ReadinessObserverUnhealthy
	}
	now := s.clock.Now()
	if !s.observationFresh(now, observedCapturedAt, observedExpiresAt) {
		if observedCapturedAt.IsZero() || observedExpiresAt.IsZero() {
			return false, ReadinessObservationUnavailable
		}
		return false, ReadinessObservationStale
	}
	if s.publishObservations {
		if !publicationHealthy || publishedCapturedAt.IsZero() || publishedExpiresAt.IsZero() {
			return false, ReadinessObservationUnavailable
		}
		if !s.observationFresh(now, publishedCapturedAt, publishedExpiresAt) {
			return false, ReadinessObservationStale
		}
	}
	if !storeHealthy {
		return false, ReadinessStoreUnavailable
	}
	for _, domainID := range s.domainIDs {
		status, found := statuses[domainID]
		if !found {
			return false, ReadinessDomainMissing
		}
		evidence, found := durableDomains[domainID]
		if !found || evidence.checkedAt.IsZero() || evidence.checkedAt.After(now) || !evidence.checkedAt.Add(s.topology.Policy.ObservationFreshness.Duration()).After(now) {
			return false, ReadinessStoreUnavailable
		}
		ready, reason := s.domainReady(now, s.authorities[domainID], status, evidence)
		if !ready {
			return false, reason
		}
	}
	return true, ReadinessReady
}

func (s *Service) observationFresh(now, capturedAt, expiresAt time.Time) bool {
	if capturedAt.IsZero() || expiresAt.IsZero() || capturedAt.After(now) {
		return false
	}
	freshUntil := capturedAt.Add(s.topology.Policy.ObservationFreshness.Duration())
	if expiresAt.Before(freshUntil) {
		freshUntil = expiresAt
	}
	return freshUntil.After(now)
}

func (s *Service) domainReady(now time.Time, authority model.DomainAuthority, status reconcile.Status, evidence durableDomainEvidence) (bool, string) {
	if status.Reason == reconcile.ReasonDomainNotActivated {
		return false, string(reconcile.ReasonDomainNotActivated)
	}
	if status.ControllerID != s.controllerID || status.DomainID != authority.DomainID || status.Mode != s.mode || status.Role == reconcile.RoleUnknown || status.Phase.Validate() != nil {
		return false, ReadinessDomainUnknown
	}
	if status.Phase == model.PhaseDegraded || status.ErrorCode != "" {
		return false, safeReadinessFailureReason(status.Reason, ReadinessDomainDegraded)
	}
	if status.UpdatedAt.IsZero() || status.UpdatedAt.After(now) {
		return false, ReadinessDomainStale
	}
	if now.Sub(status.UpdatedAt) >= s.topology.Policy.ObservationFreshness.Duration() {
		return false, ReadinessDomainStale
	}
	if status.TotalRoutes != len(authority.RemotePrefixes) || status.CompletedRoutes < 0 || status.CompletedRoutes > status.TotalRoutes {
		return false, ReadinessDomainUnknown
	}
	if status.StableOwner != "" {
		if _, found := authority.OwnerByStableNode(status.StableOwner); !found {
			return false, ReadinessDomainUnknown
		}
	}
	if !evidence.stateValid {
		return false, safeReadinessFailureReason(evidence.reason, ReadinessDomainUnknown)
	}
	if !evidence.transactionStable {
		return false, ReadinessDomainUnsafe
	}
	if !evidence.quorum {
		return false, safeReadinessFailureReason(evidence.reason, string(reconcile.ReasonObservationNoQuorum))
	}
	if evidence.quorumValidUntil.IsZero() || !evidence.quorumValidUntil.After(now) {
		return false, string(reconcile.ReasonObservationStale)
	}
	if _, found := authority.OwnerByStableNode(evidence.consensusOwner); !found {
		return false, string(reconcile.ReasonOwnerUnknown)
	}
	if status.Phase != model.PhaseStable {
		return false, ReadinessDomainUnsafe
	}
	if !status.Quorum || status.ConsensusOwner != evidence.consensusOwner || status.StableOwner != evidence.consensusOwner || evidence.stableOwner != evidence.consensusOwner {
		return false, string(reconcile.ReasonObservationDisagreement)
	}
	if !status.RouteAgreement {
		return false, string(reconcile.ReasonRouteDisagreement)
	}
	if status.CompletedRoutes != 0 {
		return false, ReadinessDomainUnsafe
	}

	switch status.Role {
	case reconcile.RoleFollower:
		if status.Mode != reconcile.ModeActive || status.Reason != reconcile.ReasonLeaseHeld && status.Reason != reconcile.ReasonLeaseChanged ||
			s.leaseInDangerWindow(now, status.LeaseExpiresAt) {
			return false, string(reconcile.ReasonLeaseUnsafe)
		}
		if !evidence.leaseHolderConfirmed || evidence.leaseHolder == s.controllerID || evidence.leaseFenceTerm != status.FenceTerm ||
			!evidence.leaseHolderValidUntil.After(now) || s.leaseInDangerWindow(now, evidence.leaseExpiresAt) {
			return false, string(reconcile.ReasonLeaseUnsafe)
		}
		return true, ReadinessReady
	case reconcile.RoleLeader:
		if status.Mode != reconcile.ModeActive || s.leaseInDangerWindow(now, status.LeaseExpiresAt) ||
			!evidence.leaseHolderConfirmed || evidence.leaseHolder != s.controllerID || evidence.leaseFenceTerm != status.FenceTerm ||
			!evidence.leaseHolderValidUntil.After(now) || s.leaseInDangerWindow(now, evidence.leaseExpiresAt) {
			return false, string(reconcile.ReasonLeaseUnsafe)
		}
		if status.Reason != reconcile.ReasonStable {
			return false, ReadinessDomainUnsafe
		}
		return true, ReadinessReady
	case reconcile.RoleReadOnly:
		if status.Mode != reconcile.ModeReadOnly && status.Mode != reconcile.ModeDryRun || status.Reason != reconcile.ReasonReadOnly ||
			!status.Quorum || !status.RouteAgreement {
			return false, string(reconcile.ReasonRouteDisagreement)
		}
		return true, ReadinessReady
	default:
		return false, ReadinessDomainUnknown
	}
}

func (s *Service) leaseInDangerWindow(now, expiresAt time.Time) bool {
	return expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) <= s.topology.Policy.LeaseDangerWindow.Duration()
}

// Handler returns the operational-only HTTP surface.
func (s *Service) Handler() http.Handler {
	if s == nil {
		return nil
	}
	return s.handler
}

func (s *Service) Registry() *prometheus.Registry {
	if s == nil {
		return nil
	}
	return s.registry
}

// Address reports the bound HTTP listener after Run has started.
func (s *Service) Address() net.Addr {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Close is idempotent and concurrently safe.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closed = true
		cancel := s.runCancel
		server := s.server
		listener := s.listener
		s.lifecycleMu.Unlock()

		s.setLive(false)
		s.setObserverRunning(false)
		if cancel != nil {
			cancel()
		}
		var closeErrors []error
		if err := s.observer.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close observer: %w", err))
		}
		if server != nil {
			shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
			if err := server.Shutdown(shutdownContext); err != nil {
				closeErrors = append(closeErrors, fmt.Errorf("shutdown HTTP server: %w", err))
				if listener != nil {
					_ = listener.Close()
				}
			}
			shutdownCancel()
		} else if listener != nil {
			_ = listener.Close()
		}
		s.closeErr = errors.Join(closeErrors...)
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
}

func safeReadinessFailureReason(reason reconcile.StatusReason, fallback string) string {
	switch reason {
	case reconcile.ReasonDomainNotInitialized, reconcile.ReasonDomainNotActivated, reconcile.ReasonLeaseLost,
		reconcile.ReasonLeaseUnsafe, reconcile.ReasonStoreUnavailable,
		reconcile.ReasonObservationQuorum, reconcile.ReasonObservationNoQuorum, reconcile.ReasonObservationStale,
		reconcile.ReasonObservationInvalid, reconcile.ReasonObservationDisagreement,
		reconcile.ReasonOwnerUnknown, reconcile.ReasonOwnerUnhealthy,
		reconcile.ReasonOwnerIneligible, reconcile.ReasonRouteUnauthorized,
		reconcile.ReasonRouteAmbiguous, reconcile.ReasonRouteOscillation,
		reconcile.ReasonRouteDisagreement, reconcile.ReasonCanceled, reconcile.ReasonInvariant:
		return string(reason)
	default:
		return fallback
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
