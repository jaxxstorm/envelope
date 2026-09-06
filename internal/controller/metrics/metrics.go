// Package metrics exposes controller-only Prometheus instrumentation without
// using the process-global registry.
package metrics

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "envelope_controller"

const (
	observerEventSnapshotSuccess = "snapshot_success"
	observerEventSnapshotError   = "snapshot_error"
	observerEventPublishSuccess  = "publish_success"
	observerEventPublishError    = "publish_error"
	observerEventPublishSkipped  = "publish_skipped"

	metricNone    = "none"
	metricUnknown = "unknown"
	apiStatusOK   = "ok"
	apiStatusErr  = "error"
)

type domainMetadata struct {
	owners         map[string]string
	preferredOwner string
}

type metricStatus struct {
	mode           string
	role           string
	phase          string
	reason         string
	errorCode      string
	stableOwner    string
	observedOwner  string
	consensusOwner string
	dynamoStatus   string
	ec2Status      string
}

type statusRecord struct {
	raw          reconcile.Status
	metric       metricStatus
	phaseStarted time.Time
	ambiguous    bool
}

type readinessEvidence struct {
	quorum               bool
	leaseHolderConfirmed bool
}

// Metrics owns all collectors for one controller process. Stable Tailnet node
// IDs are retained only in the private authority lookup and are always emitted
// as their bounded topology router IDs.
type Metrics struct {
	ReplicaInfo                   *prometheus.GaugeVec
	ProcessLive                   prometheus.Gauge
	ObserverRunning               prometheus.Gauge
	ObserverHealthy               prometheus.Gauge
	StoreHealthy                  prometheus.Gauge
	ObservationPublicationEnabled prometheus.Gauge
	ObservationPublished          prometheus.Gauge
	ObservationLastTime           prometheus.Gauge
	ObserverEvents                *prometheus.CounterVec

	DomainMode           *prometheus.GaugeVec
	DomainRole           *prometheus.GaugeVec
	DomainPhase          *prometheus.GaugeVec
	DomainReason         *prometheus.GaugeVec
	DomainError          *prometheus.GaugeVec
	DomainOwner          *prometheus.GaugeVec
	DomainAPIStatus      *prometheus.GaugeVec
	LeaseKnown           *prometheus.GaugeVec
	LeaseHolderConfirmed *prometheus.GaugeVec
	FenceTerm            *prometheus.GaugeVec
	LeaseExpires         *prometheus.GaugeVec
	ObservationQuorum    *prometheus.GaugeVec
	RouteAgreement       *prometheus.GaugeVec
	RoutesCompleted      *prometheus.GaugeVec
	RoutesTotal          *prometheus.GaugeVec
	StatusUpdated        *prometheus.GaugeVec
	PhaseStarted         *prometheus.GaugeVec
	DomainDegraded       *prometheus.GaugeVec
	StatusEvents         *prometheus.CounterVec
	PhaseTransitions     *prometheus.CounterVec
	PhaseDuration        *prometheus.HistogramVec
	Failovers            *prometheus.CounterVec
	Failbacks            *prometheus.CounterVec
	AmbiguousCalls       *prometheus.CounterVec
	APIErrors            *prometheus.CounterVec

	mu              sync.Mutex
	controllerID    string
	now             func() time.Time
	lastPublishedAt time.Time
	domains         map[string]domainMetadata
	statuses        map[string]statusRecord
	readiness       map[string]readinessEvidence
}

// New registers a complete controller metric set in reg. Callers must provide
// an isolated registry and a clock function so age metrics remain testable.
func New(reg prometheus.Registerer, controllerID string, authorities []model.DomainAuthority, now func() time.Time) (*Metrics, error) {
	if reg == nil {
		return nil, errors.New("controller metrics: registry is nil")
	}
	if !validLabel(controllerID) {
		return nil, errors.New("controller metrics: controller ID is invalid")
	}
	if now == nil {
		return nil, errors.New("controller metrics: clock is nil")
	}
	if len(authorities) == 0 {
		return nil, errors.New("controller metrics: domain authorities are required")
	}

	m := &Metrics{
		controllerID: controllerID,
		now:          now,
		domains:      make(map[string]domainMetadata, len(authorities)),
		statuses:     make(map[string]statusRecord, len(authorities)),
		readiness:    make(map[string]readinessEvidence, len(authorities)),
	}
	for index := range authorities {
		authority := authorities[index]
		if err := authority.Validate(); err != nil {
			return nil, fmt.Errorf("controller metrics: authority %d: %w", index, err)
		}
		if _, exists := m.domains[authority.DomainID]; exists {
			return nil, fmt.Errorf("controller metrics: duplicate domain %q", authority.DomainID)
		}
		owners := make(map[string]string, len(authority.Owners))
		for _, owner := range authority.Owners {
			owners[owner.StableNodeID] = owner.RouterID
		}
		m.domains[authority.DomainID] = domainMetadata{owners: owners, preferredOwner: authority.PreferredOwner}
	}

	m.ReplicaInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "replica_info",
		Help:      "Static identity of this configured controller replica.",
	}, []string{"controller_id"})
	m.ProcessLive = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "process_live", Help: "Whether the controller service lifecycle is running."})
	m.ObserverRunning = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "observer_running", Help: "Whether the bounded Tailnet publication loop is running."})
	m.ObserverHealthy = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "observer_healthy", Help: "Whether the latest Tailnet snapshot completed successfully."})
	m.StoreHealthy = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "store_healthy", Help: "Whether the latest durable store access succeeded."})
	m.ObservationPublicationEnabled = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "observation_publication_enabled", Help: "Whether this process is intentionally configured to publish observations."})
	m.ObservationPublished = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "observation_published", Help: "Whether this process has successfully published an observation."})
	m.ObservationLastTime = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "observation_last_published_timestamp_seconds", Help: "Capture timestamp of the latest successfully published observation."})
	m.ObserverEvents = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "observer_events_total", Help: "Bounded observer and publication outcomes."}, []string{"result"})

	m.DomainMode = newDomainStateGauge("domain_mode", "Configured reconcile mode by domain.", "mode")
	m.DomainRole = newDomainStateGauge("domain_role", "Current lease relationship by domain.", "role")
	m.DomainPhase = newDomainStateGauge("domain_phase", "Current durable reconcile phase by domain.", "phase")
	m.DomainReason = newDomainStateGauge("domain_reason", "Current bounded status reason by domain.", "reason")
	m.DomainError = newDomainStateGauge("domain_error", "Current bounded durable error code by domain.", "error_code")
	m.DomainOwner = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "domain_owner", Help: "Mapped topology router for each owner status field."}, []string{"domain", "kind", "router"})
	m.DomainAPIStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "domain_api_status", Help: "Bounded API status inferred from reconcile outcomes."}, []string{"domain", "api", "status"})
	m.LeaseKnown = newDomainGauge("lease_known", "Whether status contains a leader or follower lease.")
	m.LeaseHolderConfirmed = newDomainGauge("lease_holder_confirmed", "Whether durable readiness checks confirmed an active allowlisted lease holder with a fresh observation.")
	m.FenceTerm = newDomainGauge("lease_fence_term", "Latest observed fencing term.")
	m.LeaseExpires = newDomainGauge("lease_expires_timestamp_seconds", "Latest observed lease expiration timestamp.")
	m.ObservationQuorum = newDomainGauge("observation_quorum", "Whether status has a fresh authoritative observation quorum.")
	m.RouteAgreement = newDomainGauge("route_agreement", "Whether authoritative routes agree with the selected owner.")
	m.RoutesCompleted = newDomainGauge("routes_completed", "Number of acknowledged routes in the active intent.")
	m.RoutesTotal = newDomainGauge("routes_total", "Number of exact routes in the domain.")
	m.StatusUpdated = newDomainGauge("status_updated_timestamp_seconds", "Timestamp of the latest domain status.")
	m.PhaseStarted = newDomainGauge("phase_started_timestamp_seconds", "Timestamp at which the current observed phase began.")
	m.DomainDegraded = newDomainGauge("domain_degraded", "Whether the durable domain phase is degraded.")
	m.StatusEvents = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "status_events_total", Help: "Domain status publications by bounded state."}, []string{"domain", "role", "phase", "reason"})
	m.PhaseTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "phase_transitions_total", Help: "Observed durable phase transitions."}, []string{"domain", "from", "to"})
	m.PhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: namespace, Name: "phase_duration_seconds", Help: "Observed duration of completed durable phases.", Buckets: prometheus.DefBuckets}, []string{"domain", "phase"})
	m.Failovers = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "failovers_total", Help: "Stable owner transitions away from the preferred router."}, []string{"domain"})
	m.Failbacks = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "failbacks_total", Help: "Stable owner transitions to the preferred router."}, []string{"domain"})
	m.AmbiguousCalls = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "ambiguous_calls_total", Help: "Transitions into a route-ambiguity state."}, []string{"domain"})
	m.APIErrors = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "api_errors_total", Help: "Transitions into a bounded API error state."}, []string{"domain", "api"})

	observationAge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "observation_age_seconds",
		Help:      "Age of the latest successfully published observation, or zero before first publication.",
	}, func() float64 {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.lastPublishedAt.IsZero() {
			return 0
		}
		age := m.now().Sub(m.lastPublishedAt).Seconds()
		if age < 0 {
			return 0
		}
		return age
	})

	collectors := []prometheus.Collector{
		m.ReplicaInfo, m.ProcessLive, m.ObserverRunning, m.ObserverHealthy,
		m.StoreHealthy, m.ObservationPublicationEnabled, m.ObservationPublished, m.ObservationLastTime,
		observationAge, m.ObserverEvents, m.DomainMode, m.DomainRole,
		m.DomainPhase, m.DomainReason, m.DomainError, m.DomainOwner,
		m.DomainAPIStatus, m.LeaseKnown, m.LeaseHolderConfirmed, m.FenceTerm, m.LeaseExpires,
		m.ObservationQuorum, m.RouteAgreement, m.RoutesCompleted,
		m.RoutesTotal, m.StatusUpdated, m.PhaseStarted, m.DomainDegraded,
		m.StatusEvents, m.PhaseTransitions, m.PhaseDuration, m.Failovers,
		m.Failbacks, m.AmbiguousCalls, m.APIErrors,
	}
	registered := make([]prometheus.Collector, 0, len(collectors))
	for _, collector := range collectors {
		if err := reg.Register(collector); err != nil {
			for _, previous := range registered {
				reg.Unregister(previous)
			}
			return nil, fmt.Errorf("controller metrics: register: %w", err)
		}
		registered = append(registered, collector)
	}

	m.ReplicaInfo.WithLabelValues(controllerID).Set(1)
	for _, result := range []string{observerEventSnapshotSuccess, observerEventSnapshotError, observerEventPublishSuccess, observerEventPublishError, observerEventPublishSkipped} {
		m.ObserverEvents.WithLabelValues(result)
	}
	return m, nil
}

func newDomainGauge(name, help string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, []string{"domain"})
}

func newDomainStateGauge(name, help, stateLabel string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, []string{"domain", stateLabel})
}

func (m *Metrics) SetProcessLive(live bool) {
	m.ProcessLive.Set(boolFloat(live))
}

func (m *Metrics) SetObserverRunning(running bool) {
	m.ObserverRunning.Set(boolFloat(running))
}

func (m *Metrics) SetStoreHealthy(healthy bool) {
	m.StoreHealthy.Set(boolFloat(healthy))
}

func (m *Metrics) SetObservationPublicationEnabled(enabled bool) {
	m.ObservationPublicationEnabled.Set(boolFloat(enabled))
}

func (m *Metrics) RecordSnapshot(success bool) {
	m.ObserverHealthy.Set(boolFloat(success))
	result := observerEventSnapshotError
	if success {
		result = observerEventSnapshotSuccess
	}
	m.ObserverEvents.WithLabelValues(result).Inc()
}

func (m *Metrics) RecordPublishFailure() {
	m.StoreHealthy.Set(0)
	m.ObserverEvents.WithLabelValues(observerEventPublishError).Inc()
}

func (m *Metrics) RecordPublicationSkipped() {
	m.ObserverEvents.WithLabelValues(observerEventPublishSkipped).Inc()
}

func (m *Metrics) RecordPublication(observation *model.Observation) {
	if observation == nil {
		m.RecordPublishFailure()
		return
	}
	m.mu.Lock()
	m.lastPublishedAt = observation.CapturedAt
	m.mu.Unlock()
	m.StoreHealthy.Set(1)
	m.ObservationPublished.Set(1)
	m.ObservationLastTime.Set(float64(observation.CapturedAt.UnixNano()) / float64(time.Second))
	m.ObserverEvents.WithLabelValues(observerEventPublishSuccess).Inc()
}

// RecordReadinessEvidence records the bounded results of an independent
// durable read. It lets follower metrics report verified quorum rather than
// inheriting the runner's intentionally unevaluated follower status.
func (m *Metrics) RecordReadinessEvidence(domain string, quorum, leaseHolderConfirmed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, configured := m.domains[domain]; !configured {
		return
	}
	m.readiness[domain] = readinessEvidence{quorum: quorum, leaseHolderConfirmed: leaseHolderConfirmed}
	m.ObservationQuorum.WithLabelValues(domain).Set(boolFloat(quorum))
	m.LeaseHolderConfirmed.WithLabelValues(domain).Set(boolFloat(leaseHolderConfirmed))
}

// RecordStatus updates every field in reconcile.Status and derives bounded
// transition, failover/failback, ambiguity, and API event counters.
func (m *Metrics) RecordStatus(status reconcile.Status) {
	metadata, configured := m.domains[status.DomainID]
	if !configured {
		return
	}
	current := m.normalizeStatus(status, metadata)

	m.mu.Lock()
	defer m.mu.Unlock()
	previous, hadPrevious := m.statuses[status.DomainID]
	if hadPrevious && previous.raw == status {
		return
	}
	if hadPrevious && !status.UpdatedAt.IsZero() && status.UpdatedAt.Before(previous.raw.UpdatedAt) {
		return
	}
	if hadPrevious {
		m.deleteStatus(status.DomainID, previous.metric)
	}

	domain := status.DomainID
	m.DomainMode.WithLabelValues(domain, current.mode).Set(1)
	m.DomainRole.WithLabelValues(domain, current.role).Set(1)
	m.DomainPhase.WithLabelValues(domain, current.phase).Set(1)
	m.DomainReason.WithLabelValues(domain, current.reason).Set(1)
	m.DomainError.WithLabelValues(domain, current.errorCode).Set(1)
	m.DomainOwner.WithLabelValues(domain, "stable", current.stableOwner).Set(1)
	m.DomainOwner.WithLabelValues(domain, "observed", current.observedOwner).Set(1)
	m.DomainOwner.WithLabelValues(domain, "consensus", current.consensusOwner).Set(1)
	m.DomainAPIStatus.WithLabelValues(domain, "dynamodb", current.dynamoStatus).Set(1)
	m.DomainAPIStatus.WithLabelValues(domain, "ec2", current.ec2Status).Set(1)
	m.LeaseKnown.WithLabelValues(domain).Set(boolFloat((status.Role == reconcile.RoleLeader || status.Role == reconcile.RoleFollower) && !status.LeaseExpiresAt.IsZero()))
	m.FenceTerm.WithLabelValues(domain).Set(float64(status.FenceTerm))
	m.LeaseExpires.WithLabelValues(domain).Set(unixSeconds(status.LeaseExpiresAt))
	quorum := status.Quorum
	if evidence, found := m.readiness[domain]; found {
		quorum = evidence.quorum
		m.LeaseHolderConfirmed.WithLabelValues(domain).Set(boolFloat(evidence.leaseHolderConfirmed))
	}
	m.ObservationQuorum.WithLabelValues(domain).Set(boolFloat(quorum))
	m.RouteAgreement.WithLabelValues(domain).Set(boolFloat(status.RouteAgreement))
	m.RoutesCompleted.WithLabelValues(domain).Set(float64(status.CompletedRoutes))
	m.RoutesTotal.WithLabelValues(domain).Set(float64(status.TotalRoutes))
	m.StatusUpdated.WithLabelValues(domain).Set(unixSeconds(status.UpdatedAt))
	m.DomainDegraded.WithLabelValues(domain).Set(boolFloat(status.Phase == model.PhaseDegraded))
	m.StatusEvents.WithLabelValues(domain, current.role, current.phase, current.reason).Inc()

	phaseStarted := status.UpdatedAt
	if hadPrevious && current.phase == previous.metric.phase {
		phaseStarted = previous.phaseStarted
	} else if hadPrevious {
		m.PhaseTransitions.WithLabelValues(domain, previous.metric.phase, current.phase).Inc()
		if !previous.phaseStarted.IsZero() && !status.UpdatedAt.IsZero() {
			duration := status.UpdatedAt.Sub(previous.phaseStarted).Seconds()
			if duration >= 0 {
				m.PhaseDuration.WithLabelValues(domain, previous.metric.phase).Observe(duration)
			}
		}
	}
	m.PhaseStarted.WithLabelValues(domain).Set(unixSeconds(phaseStarted))

	if hadPrevious && status.Phase == model.PhaseStable && status.Reason == reconcile.ReasonStable && status.RouteAgreement &&
		status.StableOwner != "" && status.StableOwner != previous.raw.StableOwner {
		if status.StableOwner == metadata.preferredOwner {
			m.Failbacks.WithLabelValues(domain).Inc()
		} else {
			m.Failovers.WithLabelValues(domain).Inc()
		}
	}
	ambiguous := status.Reason == reconcile.ReasonRouteAmbiguous || status.ErrorCode == model.ErrorRouteAmbiguous
	if ambiguous && (!hadPrevious || !previous.ambiguous) {
		m.AmbiguousCalls.WithLabelValues(domain).Inc()
	}
	if current.dynamoStatus == apiStatusErr && (!hadPrevious || previous.metric.dynamoStatus != apiStatusErr) {
		m.APIErrors.WithLabelValues(domain, "dynamodb").Inc()
	}
	if current.ec2Status == apiStatusErr && (!hadPrevious || previous.metric.ec2Status != apiStatusErr) {
		m.APIErrors.WithLabelValues(domain, "ec2").Inc()
	}

	m.statuses[domain] = statusRecord{raw: status, metric: current, phaseStarted: phaseStarted, ambiguous: ambiguous}
}

func (m *Metrics) deleteStatus(domain string, status metricStatus) {
	m.DomainMode.DeleteLabelValues(domain, status.mode)
	m.DomainRole.DeleteLabelValues(domain, status.role)
	m.DomainPhase.DeleteLabelValues(domain, status.phase)
	m.DomainReason.DeleteLabelValues(domain, status.reason)
	m.DomainError.DeleteLabelValues(domain, status.errorCode)
	m.DomainOwner.DeleteLabelValues(domain, "stable", status.stableOwner)
	m.DomainOwner.DeleteLabelValues(domain, "observed", status.observedOwner)
	m.DomainOwner.DeleteLabelValues(domain, "consensus", status.consensusOwner)
	m.DomainAPIStatus.DeleteLabelValues(domain, "dynamodb", status.dynamoStatus)
	m.DomainAPIStatus.DeleteLabelValues(domain, "ec2", status.ec2Status)
}

func (m *Metrics) normalizeStatus(status reconcile.Status, metadata domainMetadata) metricStatus {
	if status.ControllerID != m.controllerID {
		status.Role = reconcile.RoleUnknown
		status.Reason = reconcile.ReasonInvariant
	}
	return metricStatus{
		mode:           boundedMode(status.Mode),
		role:           boundedRole(status.Role),
		phase:          boundedPhase(status.Phase),
		reason:         boundedReason(status.Reason),
		errorCode:      boundedError(status.ErrorCode),
		stableOwner:    mappedOwner(metadata, status.StableOwner),
		observedOwner:  mappedOwner(metadata, status.ObservedOwner),
		consensusOwner: mappedOwner(metadata, status.ConsensusOwner),
		dynamoStatus:   dynamoStatus(status),
		ec2Status:      ec2Status(status),
	}
}

func mappedOwner(metadata domainMetadata, stableNodeID string) string {
	if stableNodeID == "" {
		return metricNone
	}
	if routerID, found := metadata.owners[stableNodeID]; found {
		return routerID
	}
	return metricUnknown
}

func boundedMode(value reconcile.Mode) string {
	switch value {
	case reconcile.ModeActive, reconcile.ModeReadOnly, reconcile.ModeDryRun:
		return string(value)
	default:
		return metricUnknown
	}
}

func boundedRole(value reconcile.Role) string {
	switch value {
	case reconcile.RoleLeader, reconcile.RoleFollower, reconcile.RoleReadOnly, reconcile.RoleUnknown:
		return string(value)
	default:
		return metricUnknown
	}
}

func boundedPhase(value model.Phase) string {
	if value.Validate() == nil {
		return string(value)
	}
	return metricUnknown
}

func boundedReason(value reconcile.StatusReason) string {
	switch value {
	case reconcile.ReasonStarting, reconcile.ReasonStable, reconcile.ReasonReadOnly,
		reconcile.ReasonDomainNotInitialized, reconcile.ReasonDomainNotActivated, reconcile.ReasonLeaseHeld,
		reconcile.ReasonLeaseChanged, reconcile.ReasonLeaseLost,
		reconcile.ReasonLeaseUnsafe, reconcile.ReasonStoreUnavailable,
		reconcile.ReasonObservationQuorum, reconcile.ReasonObservationNoQuorum,
		reconcile.ReasonObservationStale, reconcile.ReasonObservationInvalid,
		reconcile.ReasonObservationDisagreement, reconcile.ReasonOwnerUnknown,
		reconcile.ReasonOwnerUnhealthy, reconcile.ReasonOwnerIneligible,
		reconcile.ReasonStabilityWindow, reconcile.ReasonCooldown,
		reconcile.ReasonRouteUnauthorized, reconcile.ReasonRouteAmbiguous,
		reconcile.ReasonRouteOscillation, reconcile.ReasonRouteDisagreement,
		reconcile.ReasonReconciling, reconcile.ReasonCanceled,
		reconcile.ReasonInvariant:
		return string(value)
	default:
		return metricUnknown
	}
}

func boundedError(value model.ErrorCode) string {
	if value == "" {
		return metricNone
	}
	switch value {
	case model.ErrorObservationQuorum, model.ErrorOwnerIneligible,
		model.ErrorLeaseUnsafe, model.ErrorRouteUnauthorized,
		model.ErrorRouteAmbiguous, model.ErrorRouteOscillation,
		model.ErrorStoreUnavailable, model.ErrorInvariant:
		return string(value)
	default:
		return metricUnknown
	}
}

func dynamoStatus(status reconcile.Status) string {
	switch status.Reason {
	case reconcile.ReasonStoreUnavailable:
		return apiStatusErr
	case reconcile.ReasonStarting, reconcile.ReasonCanceled:
		return metricUnknown
	default:
		return apiStatusOK
	}
}

func ec2Status(status reconcile.Status) string {
	if status.Role == reconcile.RoleFollower || status.Role == reconcile.RoleUnknown {
		return metricUnknown
	}
	switch status.Reason {
	case reconcile.ReasonOwnerIneligible, reconcile.ReasonRouteUnauthorized,
		reconcile.ReasonRouteAmbiguous, reconcile.ReasonRouteOscillation,
		reconcile.ReasonRouteDisagreement:
		return apiStatusErr
	case reconcile.ReasonStable, reconcile.ReasonReadOnly,
		reconcile.ReasonStabilityWindow, reconcile.ReasonCooldown,
		reconcile.ReasonReconciling:
		return apiStatusOK
	default:
		return metricUnknown
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func unixSeconds(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / float64(time.Second)
}

func validLabel(value string) bool {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
