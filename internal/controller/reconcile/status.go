package reconcile

import (
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// Mode identifies whether an engine may write durable state and cloud routes.
type Mode string

const (
	ModeActive   Mode = "active"
	ModeReadOnly Mode = "read-only"
	ModeDryRun   Mode = "dry-run"
)

// Role is the engine's current relationship to the domain lease.
type Role string

const (
	RoleUnknown  Role = "unknown"
	RoleLeader   Role = "leader"
	RoleFollower Role = "follower"
	RoleReadOnly Role = "read-only"
)

// StatusReason is a bounded, machine-readable operational reason. Status never
// includes provider errors or unbounded responses.
type StatusReason string

const (
	ReasonStarting                StatusReason = "starting"
	ReasonStable                  StatusReason = "stable"
	ReasonReadOnly                StatusReason = "read-only"
	ReasonDomainNotInitialized    StatusReason = "domain-not-initialized"
	ReasonDomainNotActivated      StatusReason = "domain-not-activated"
	ReasonLeaseHeld               StatusReason = "lease-held"
	ReasonLeaseChanged            StatusReason = "lease-changed"
	ReasonLeaseLost               StatusReason = "lease-lost"
	ReasonLeaseUnsafe             StatusReason = "lease-unsafe"
	ReasonStoreUnavailable        StatusReason = "store-unavailable"
	ReasonObservationQuorum       StatusReason = "observation-quorum"
	ReasonObservationNoQuorum     StatusReason = "observation-no-quorum"
	ReasonObservationStale        StatusReason = "observation-stale"
	ReasonObservationInvalid      StatusReason = "observation-invalid"
	ReasonObservationDisagreement StatusReason = "observation-disagreement"
	ReasonOwnerUnknown            StatusReason = "owner-unknown"
	ReasonOwnerUnhealthy          StatusReason = "owner-unhealthy"
	ReasonOwnerIneligible         StatusReason = "owner-ineligible"
	ReasonStabilityWindow         StatusReason = "stability-window"
	ReasonCooldown                StatusReason = "cooldown"
	ReasonRouteUnauthorized       StatusReason = "route-unauthorized"
	ReasonRouteAmbiguous          StatusReason = "route-ambiguous"
	ReasonRouteOscillation        StatusReason = "route-oscillation"
	ReasonRouteDisagreement       StatusReason = "route-disagreement"
	ReasonReconciling             StatusReason = "reconciling"
	ReasonCanceled                StatusReason = "canceled"
	ReasonInvariant               StatusReason = "invariant-violation"
)

// Status is a fixed-size snapshot suitable for application health and metrics.
// Owner and domain strings are topology-validated identifiers; no errors or
// observation collections are retained.
type Status struct {
	ControllerID    string
	DomainID        string
	Mode            Mode
	Role            Role
	Phase           model.Phase
	Reason          StatusReason
	ErrorCode       model.ErrorCode
	StableOwner     string
	ObservedOwner   string
	ConsensusOwner  string
	FenceTerm       model.FenceTerm
	LeaseExpiresAt  time.Time
	Quorum          bool
	RouteAgreement  bool
	CompletedRoutes int
	TotalRoutes     int
	UpdatedAt       time.Time
}

type statusState struct {
	mu       sync.RWMutex
	status   Status
	callback func(Status)
}

func (s *statusState) snapshot() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *statusState) setCallback(callback func(Status)) Status {
	s.mu.Lock()
	s.callback = callback
	status := s.status
	s.mu.Unlock()
	return status
}

func (s *statusState) publish(status Status) {
	s.mu.Lock()
	s.status = status
	callback := s.callback
	s.mu.Unlock()
	if callback != nil {
		callback(status)
	}
}
