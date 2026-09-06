package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// MemoryStore is a deterministic, concurrency-safe Store implementation for
// controller unit and integration tests.
type MemoryStore struct {
	mu               sync.RWMutex
	clock            Clock
	domains          map[domainKey]*model.DomainState
	observations     map[observationKey]*model.Observation
	allowedObservers map[observationKey]struct{}
}

type domainKey struct {
	deploymentID string
	domainID     string
}

type observationKey struct {
	deploymentID string
	topologyHash string
	controllerID string
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore creates an empty store. Only explicitly allowlisted observer
// identities may publish; domain records remain conditionally self-registering.
func NewMemoryStore(clock Clock, allowedObservers ...ObserverIdentity) (*MemoryStore, error) {
	if clock == nil {
		return nil, errors.New("store: clock is nil")
	}
	allowed := make(map[observationKey]struct{}, len(allowedObservers))
	for index, observer := range allowedObservers {
		if err := observer.Validate(); err != nil {
			return nil, fmt.Errorf("store: allowed observer %d: %w", index, err)
		}
		key := observationKey{
			deploymentID: observer.DeploymentID,
			topologyHash: observer.TopologyHash,
			controllerID: observer.ControllerID,
		}
		if _, exists := allowed[key]; exists {
			return nil, fmt.Errorf("store: duplicate allowed observer %q for deployment %q and topology %q", observer.ControllerID, observer.DeploymentID, observer.TopologyHash)
		}
		allowed[key] = struct{}{}
	}
	return &MemoryStore{
		clock:            clock,
		domains:          make(map[domainKey]*model.DomainState),
		observations:     make(map[observationKey]*model.Observation),
		allowedObservers: allowed,
	}, nil
}

func (s *MemoryStore) CreateDomain(ctx context.Context, initial *model.DomainState) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, errors.New("store: initial domain state is nil")
	}
	candidate := initial.Clone()
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate initial domain state: %w", err)
	}
	if candidate.Revision != 1 {
		return nil, errors.New("store: initial domain revision must be one")
	}
	if candidate.FenceTerm != 0 || candidate.Lease != nil {
		return nil, errors.New("store: initial domain state must be lease-free at fence zero")
	}
	if candidate.Phase != model.PhaseStable {
		return nil, errors.New("store: initial domain state must be stable")
	}

	ref := DomainRefFor(candidate.Authority)
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate initial domain identity: %w", err)
	}
	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if current, exists := s.domains[key]; exists {
		if current.Authority.TopologyHash != ref.TopologyHash {
			return nil, topologyMismatch("domain "+ref.String(), current.Authority.TopologyHash, ref.TopologyHash)
		}
		return nil, &ConflictError{Resource: "domain " + ref.String()}
	}
	s.domains[key] = candidate
	return candidate.Clone(), nil
}

func (s *MemoryStore) LoadDomain(ctx context.Context, ref DomainRef) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}
	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	current, exists := s.domains[key]
	if !exists {
		return nil, &NotFoundError{Resource: "domain", Key: ref.String()}
	}
	if current.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), current.Authority.TopologyHash, ref.TopologyHash)
	}
	return current.Clone(), nil
}

func (s *MemoryStore) CompareAndSwapDomain(ctx context.Context, ref DomainRef, expectedRevision model.DocumentRevision, token LeaseToken, next *model.DomainState) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}
	if expectedRevision == 0 {
		return nil, errors.New("store: expected domain revision must be positive")
	}
	if err := token.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease token: %w", err)
	}
	if next == nil {
		return nil, errors.New("store: next domain state is nil")
	}
	candidate := next.Clone()
	if candidate.Revision != expectedRevision {
		return nil, &ConflictError{
			Resource: "candidate domain revision",
			Expected: fmt.Sprint(expectedRevision),
			Actual:   fmt.Sprint(candidate.Revision),
		}
	}
	if candidate.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("candidate domain "+ref.String(), ref.TopologyHash, candidate.Authority.TopologyHash)
	}
	if candidate.Authority.DeploymentID != ref.DeploymentID || candidate.Authority.DomainID != ref.DomainID {
		return nil, errors.New("store: candidate domain identity does not match its reference")
	}

	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	current, exists := s.domains[key]
	if !exists {
		return nil, &NotFoundError{Resource: "domain", Key: ref.String()}
	}
	if current.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), current.Authority.TopologyHash, ref.TopologyHash)
	}
	if current.Revision != expectedRevision {
		return nil, &ConflictError{
			Resource: "domain " + ref.String() + " revision",
			Expected: fmt.Sprint(expectedRevision),
			Actual:   fmt.Sprint(current.Revision),
		}
	}
	if !current.Activated || candidate.Activated != current.Activated {
		return nil, ErrDomainInactive
	}
	now := s.clock.Now()
	if !leaseMatches(current.Lease, token) || !leaseActive(current.Lease, now) {
		return nil, leaseLost(ref, token, current.Lease)
	}
	if !reflect.DeepEqual(candidate.Authority, current.Authority) {
		return nil, &ConflictError{Resource: "immutable authority for domain " + ref.String()}
	}
	if candidate.FenceTerm != current.FenceTerm || !reflect.DeepEqual(candidate.Lease, current.Lease) {
		return nil, leaseLost(ref, token, current.Lease)
	}
	if candidate.UpdatedAt.Before(current.UpdatedAt) {
		return nil, &ConflictError{
			Resource: "domain " + ref.String() + " update timestamp",
			Expected: "at or after " + current.UpdatedAt.Format(time.RFC3339Nano),
			Actual:   candidate.UpdatedAt.Format(time.RFC3339Nano),
		}
	}
	if current.Revision == model.DocumentRevision(math.MaxUint64) {
		return nil, errors.New("store: domain revision exhausted")
	}
	candidate.Revision = current.Revision + 1
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain update: %w", err)
	}
	s.domains[key] = candidate
	return candidate.Clone(), nil
}

func (s *MemoryStore) AcquireLease(ctx context.Context, ref DomainRef, holderID string, duration time.Duration) (*model.Lease, error) {
	if err := validateLeaseRequest(ctx, ref, holderID, duration); err != nil {
		return nil, err
	}
	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	current, err := s.domainForWrite(key, ref)
	if err != nil {
		return nil, err
	}
	if current.Lease != nil {
		return nil, leaseHeld(ref, current.Lease)
	}
	if current.FenceTerm == model.FenceTerm(math.MaxUint64) {
		return nil, errors.New("store: lease fence term exhausted")
	}
	now := s.clock.Now()
	lease := &model.Lease{
		HolderID:      holderID,
		FenceTerm:     current.FenceTerm + 1,
		RecordVersion: 1,
		AcquiredAt:    now,
		RenewedAt:     now,
		ExpiresAt:     now.Add(duration),
	}
	return s.storeLease(key, current, lease)
}

func (s *MemoryStore) TakeoverLease(ctx context.Context, ref DomainRef, holderID string, expectedRecordVersion uint64, duration time.Duration) (*model.Lease, error) {
	if err := validateLeaseRequest(ctx, ref, holderID, duration); err != nil {
		return nil, err
	}
	if expectedRecordVersion == 0 {
		return nil, errors.New("store: expected lease record version must be positive")
	}
	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	current, err := s.domainForWrite(key, ref)
	if err != nil {
		return nil, err
	}
	if current.Lease == nil {
		return nil, &NotFoundError{Resource: "lease", Key: ref.String()}
	}
	if current.Lease.RecordVersion != expectedRecordVersion {
		return nil, &ConflictError{
			Resource: "lease " + ref.String() + " record version",
			Expected: fmt.Sprint(expectedRecordVersion),
			Actual:   fmt.Sprint(current.Lease.RecordVersion),
		}
	}
	if current.FenceTerm == model.FenceTerm(math.MaxUint64) {
		return nil, errors.New("store: lease fence term exhausted")
	}
	if current.Lease.RecordVersion == math.MaxUint64 {
		return nil, errors.New("store: lease record version exhausted")
	}
	now := s.clock.Now()
	lease := &model.Lease{
		HolderID:      holderID,
		FenceTerm:     current.FenceTerm + 1,
		RecordVersion: current.Lease.RecordVersion + 1,
		AcquiredAt:    now,
		RenewedAt:     now,
		ExpiresAt:     now.Add(duration),
	}
	return s.storeLease(key, current, lease)
}

func (s *MemoryStore) RenewLease(ctx context.Context, ref DomainRef, token LeaseToken, duration time.Duration) (*model.Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}
	if err := token.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease token: %w", err)
	}
	if duration <= 0 {
		return nil, errors.New("store: lease duration must be positive")
	}
	key := domainKey{deploymentID: ref.DeploymentID, domainID: ref.DomainID}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	current, err := s.domainForWrite(key, ref)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if !leaseMatches(current.Lease, token) || !leaseActive(current.Lease, now) {
		return nil, leaseLost(ref, token, current.Lease)
	}
	if current.Lease.RecordVersion == math.MaxUint64 {
		return nil, errors.New("store: lease record version exhausted")
	}
	lease := current.Lease.Clone()
	lease.RecordVersion++
	lease.RenewedAt = now
	lease.ExpiresAt = now.Add(duration)
	return s.storeLease(key, current, lease)
}

func (s *MemoryStore) PublishObservation(ctx context.Context, deploymentID string, observation *model.Observation) (*model.Observation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateIdentifier("deployment ID", deploymentID); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if observation == nil {
		return nil, errors.New("store: observation is nil")
	}
	candidate := observation.Clone()
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate observation: %w", err)
	}
	key := observationKey{
		deploymentID: deploymentID,
		topologyHash: candidate.TopologyHash,
		controllerID: candidate.ControllerID,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if _, allowed := s.allowedObservers[key]; !allowed {
		if expected, found := s.allowedTopology(deploymentID, candidate.ControllerID); found {
			return nil, topologyMismatch("observation from controller "+candidate.ControllerID, expected, candidate.TopologyHash)
		}
		return nil, fmt.Errorf("store: controller %q is not allowed to publish observations for deployment %q and topology %q", candidate.ControllerID, deploymentID, candidate.TopologyHash)
	}
	if current, exists := s.observations[key]; exists && candidate.Sequence <= current.Sequence {
		return nil, &ConflictError{
			Resource: "observation sequence for controller " + candidate.ControllerID,
			Expected: fmt.Sprintf(">%d", current.Sequence),
			Actual:   fmt.Sprint(candidate.Sequence),
		}
	}
	s.observations[key] = candidate
	return candidate.Clone(), nil
}

func (s *MemoryStore) ListObservations(ctx context.Context, scope ObservationScope) ([]*model.Observation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate observation scope: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	result := make([]*model.Observation, 0)
	for key, observation := range s.observations {
		if key.deploymentID != scope.DeploymentID || key.topologyHash != scope.TopologyHash {
			continue
		}
		result = append(result, observation.Clone())
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ControllerID < result[j].ControllerID
	})
	return result, nil
}

func (s *MemoryStore) domainForWrite(key domainKey, ref DomainRef) (*model.DomainState, error) {
	current, exists := s.domains[key]
	if !exists {
		return nil, &NotFoundError{Resource: "domain", Key: ref.String()}
	}
	if current.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), current.Authority.TopologyHash, ref.TopologyHash)
	}
	if !current.Activated {
		return nil, ErrDomainInactive
	}
	return current, nil
}

func (s *MemoryStore) storeLease(key domainKey, current *model.DomainState, lease *model.Lease) (*model.Lease, error) {
	if err := lease.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease: %w", err)
	}
	candidate := current.Clone()
	candidate.FenceTerm = lease.FenceTerm
	candidate.Lease = lease.Clone()
	if candidate.UpdatedAt.Before(lease.RenewedAt) {
		candidate.UpdatedAt = lease.RenewedAt
	}
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate leased domain state: %w", err)
	}
	s.domains[key] = candidate
	return lease.Clone(), nil
}

func (s *MemoryStore) allowedTopology(deploymentID, controllerID string) (string, bool) {
	topologies := make([]string, 0, 1)
	for key := range s.allowedObservers {
		if key.deploymentID == deploymentID && key.controllerID == controllerID {
			topologies = append(topologies, key.topologyHash)
		}
	}
	if len(topologies) == 0 {
		return "", false
	}
	sort.Strings(topologies)
	return topologies[0], true
}

func validateLeaseRequest(ctx context.Context, ref DomainRef, holderID string, duration time.Duration) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	var errs []error
	if err := ref.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("domain reference: %w", err))
	}
	if err := validateIdentifier("lease holder", holderID); err != nil {
		errs = append(errs, err)
	}
	if duration <= 0 {
		errs = append(errs, errors.New("lease duration must be positive"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("store: validate lease request: %w", err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("store: context is nil")
	}
	return ctx.Err()
}

func leaseActive(lease *model.Lease, now time.Time) bool {
	return lease != nil && lease.ExpiresAt.After(now)
}

func leaseMatches(lease *model.Lease, token LeaseToken) bool {
	return lease != nil &&
		lease.HolderID == token.HolderID &&
		lease.FenceTerm == token.FenceTerm &&
		lease.RecordVersion == token.RecordVersion
}

func leaseHeld(ref DomainRef, lease *model.Lease) error {
	return &LeaseHeldError{Domain: ref, Lease: lease.Clone()}
}

func leaseLost(ref DomainRef, token LeaseToken, lease *model.Lease) error {
	return &LeaseLostError{Domain: ref, Expected: token, Actual: lease.Clone()}
}

func topologyMismatch(resource, expected, actual string) error {
	return &TopologyMismatchError{Resource: resource, Expected: expected, Actual: actual}
}
