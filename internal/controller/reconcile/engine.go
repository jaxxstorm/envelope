// Package reconcile implements one fenced reconciliation state machine per
// isolated source-prefix route domain.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/health"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

// RouteController is the cloud inspection surface used by the reconciler.
// Active engines additionally require the durableBeforeRouteMutator contract.
type RouteController interface {
	ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error)
	Snapshot(context.Context, model.DomainAuthority) (model.RouteSnapshot, error)
}

var _ RouteController = (*awscontrol.Controller)(nil)

type stableRouteReader interface {
	StableSnapshot(context.Context, model.DomainAuthority, time.Time) (model.RouteSnapshot, error)
}

var _ stableRouteReader = (*awscontrol.Controller)(nil)

type durableBeforeRouteMutator interface {
	ReplaceAndWait(context.Context, model.DomainAuthority, string, string, string, time.Time) (awscontrol.ReplaceResult, error)
}

var _ durableBeforeRouteMutator = (*awscontrol.Controller)(nil)

// UUIDSource supplies deterministic transaction IDs. Production callers can
// adapt their UUID implementation with UUIDFunc; tests should inject a fixed
// sequence.
type UUIDSource interface {
	NewUUID() string
}

// UUIDFunc adapts a function to UUIDSource.
type UUIDFunc func() string

func (f UUIDFunc) NewUUID() string { return f() }

// Options constructs one domain engine from an already validated topology.
// ReadOnly and DryRun both prohibit every durable and cloud mutation; DryRun is
// retained separately in status so operators can distinguish intent.
type Options struct {
	Topology       *config.Topology
	DomainID       string
	ControllerID   string
	Store          store.Store
	Routes         RouteController
	Clock          store.Clock
	UUIDs          UUIDSource
	ReadOnly       bool
	DryRun         bool
	StatusCallback func(Status)
}

// Engine serializes lease renewal and reconciliation for one route domain.
// A single engine is safe for concurrent Reconcile, Run, Status, and callback
// registration calls.
type Engine struct {
	controllerID string
	authority    model.DomainAuthority
	policy       config.Policy
	controllers  []string
	store        store.Store
	routes       RouteController
	stableRoutes stableRouteReader
	mutator      durableBeforeRouteMutator
	clock        store.Clock
	uuids        UUIDSource
	mode         Mode

	operationMu         chan struct{}
	takeoverObservation leaseTakeoverObservation
	status              statusState
}

type leaseTakeoverObservation struct {
	holderID      string
	recordVersion uint64
	// eligibleAt is process-local elapsed-time evidence; lease wall timestamps
	// are never used to shorten the takeover wait.
	eligibleAt time.Time
}

// NewEngine validates dependencies and creates a per-domain engine. It does not
// access the store or cloud until Reconcile or Run is called.
func NewEngine(options Options) (*Engine, error) {
	if options.Topology == nil {
		return nil, errors.New("reconcile: topology is nil")
	}
	if err := options.Topology.Validate(); err != nil {
		return nil, fmt.Errorf("reconcile: topology: %w", err)
	}
	if !options.Topology.HasControllerID(options.ControllerID) {
		return nil, fmt.Errorf("reconcile: controller ID %q is not allowed by topology", options.ControllerID)
	}
	if isNil(options.Store) {
		return nil, errors.New("reconcile: store is nil")
	}
	if isNil(options.Routes) {
		return nil, errors.New("reconcile: route controller is nil")
	}
	if isNil(options.Clock) {
		return nil, errors.New("reconcile: clock is nil")
	}
	mode := ModeActive
	if options.DryRun {
		mode = ModeDryRun
	} else if options.ReadOnly {
		mode = ModeReadOnly
	}
	if mode == ModeActive && isNil(options.UUIDs) {
		return nil, errors.New("reconcile: UUID source is nil")
	}
	var mutator durableBeforeRouteMutator
	if mode == ModeActive {
		var found bool
		mutator, found = options.Routes.(durableBeforeRouteMutator)
		if !found || isNil(mutator) {
			return nil, errors.New("reconcile: route controller does not support durable before-image mutation")
		}
	}
	stableRoutes, _ := options.Routes.(stableRouteReader)
	authority, err := options.Topology.DomainAuthority(options.DomainID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: domain authority: %w", err)
	}

	engine := &Engine{
		controllerID: options.ControllerID,
		authority:    authority,
		policy:       options.Topology.Policy,
		controllers:  append([]string(nil), options.Topology.ControllerIDs...),
		store:        options.Store,
		routes:       options.Routes,
		stableRoutes: stableRoutes,
		mutator:      mutator,
		clock:        options.Clock,
		uuids:        options.UUIDs,
		mode:         mode,
		operationMu:  make(chan struct{}, 1),
	}
	engine.operationMu <- struct{}{}
	engine.status.status = Status{
		ControllerID: options.ControllerID,
		DomainID:     authority.DomainID,
		Mode:         mode,
		Role:         RoleUnknown,
		Reason:       ReasonStarting,
		TotalRoutes:  len(authority.RemotePrefixes),
		UpdatedAt:    options.Clock.Now(),
	}
	engine.status.callback = options.StatusCallback
	return engine, nil
}

// Status returns a concurrency-safe, fixed-size copy of the latest status.
func (e *Engine) Status() Status {
	if e == nil {
		return Status{}
	}
	return e.status.snapshot()
}

// SetStatusCallback replaces the synchronous status callback and immediately
// supplies its caller with the current snapshot. Callbacks must return quickly;
// they may safely call Status.
func (e *Engine) SetStatusCallback(callback func(Status)) {
	if e == nil {
		return
	}
	status := e.status.setCallback(callback)
	if callback != nil {
		callback(status)
	}
}

// Reconcile performs one serialized reconciliation pass. It may advance
// through multiple durable phases, but returns whenever it must wait for owner
// stability, cooldown, lease contention, or operator-safe degraded recovery.
func (e *Engine) Reconcile(ctx context.Context) error {
	if e == nil {
		return errors.New("reconcile: engine is nil")
	}
	if ctx == nil {
		return errors.New("reconcile: context is nil")
	}
	select {
	case <-ctx.Done():
		e.publishWithoutState(RoleUnknown, ReasonCanceled, model.ErrorCode(""))
		return ctx.Err()
	case <-e.operationMu:
	}
	defer func() { e.operationMu <- struct{}{} }()

	if e.mode != ModeActive {
		return e.inspectReadOnly(ctx)
	}
	state, err := e.loadDomain(ctx)
	if err != nil {
		e.publishWithoutState(RoleUnknown, statusReasonForStore(err), model.ErrorStoreUnavailable)
		return err
	}
	state, leader, err := e.ensureLease(ctx, state)
	if err != nil {
		return err
	}
	if !leader {
		return nil
	}

	// Every transition consumes at least one durable checkpoint. The bound is
	// deliberately above the maximum path through all ordered route entries and
	// prevents an adapter bug from producing an in-process spin.
	limit := 2*len(e.authority.RemotePrefixes) + 12
	for range limit {
		if !state.Activated {
			e.publishState(state, RoleUnknown, ReasonDomainNotActivated, "", false, false)
			return nil
		}
		if state.Intent != nil && state.Intent.FenceTerm != state.FenceTerm {
			state, err = e.persistCurrentIntentFence(ctx, state)
			if err != nil {
				return err
			}
			continue
		}
		var advanced bool
		switch state.Phase {
		case model.PhaseStable:
			state, advanced, err = e.reconcileStable(ctx, state)
		case model.PhaseOwnerObserved:
			state, advanced, err = e.reconcileObserved(ctx, state)
		case model.PhaseRouteIntentPersisted:
			state, advanced, err = e.reconcileIntent(ctx, state)
		case model.PhaseRoutesConverging:
			state, advanced, err = e.reconcileRoutes(ctx, state)
		case model.PhaseDegraded:
			state, advanced, err = e.reconcileDegraded(ctx, state)
		default:
			err = fmt.Errorf("reconcile: unsupported durable phase %q", state.Phase)
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				e.publishState(state, RoleLeader, ReasonCanceled, "", false, false)
			}
			return err
		}
		if !advanced {
			return nil
		}
	}

	stateError := e.newStateError(model.ErrorInvariant, "reconciliation transition bound exceeded", false)
	_, _, saveErr := e.saveDegraded(ctx, state, stateError, ReasonInvariant, nil)
	if saveErr != nil {
		return saveErr
	}
	return errors.New("reconcile: reconciliation transition bound exceeded")
}

// Run reconciles until ctx is canceled. Operational errors are reflected in
// Status and retried after a bounded policy interval; cancellation is returned
// to the caller.
func (e *Engine) Run(ctx context.Context) error {
	if e == nil {
		return errors.New("reconcile: engine is nil")
	}
	if ctx == nil {
		return errors.New("reconcile: context is nil")
	}
	interval := minDuration(e.policy.ObservationInterval.Duration(), e.policy.LeaseRenewInterval.Duration())
	for {
		_ = e.Reconcile(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := store.Wait(ctx, e.clock, interval); err != nil {
			e.publishWithoutState(RoleUnknown, ReasonCanceled, "")
			return err
		}
	}
}

func (e *Engine) loadDomain(ctx context.Context) (*model.DomainState, error) {
	ref := store.DomainRefFor(e.authority)
	state, err := e.store.LoadDomain(ctx, ref)
	if err == nil {
		return e.validateLoaded(state)
	}
	// Initialization is a deployment operation under route-denied credentials.
	// A missing journal is never permission to invent a preferred stable owner.
	return nil, fmt.Errorf("reconcile: load deployment-initialized domain: %w", err)
}

func (e *Engine) validateLoaded(state *model.DomainState) (*model.DomainState, error) {
	if state == nil {
		return nil, errors.New("reconcile: store returned a nil domain")
	}
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("reconcile: invalid durable domain: %w", err)
	}
	if !reflect.DeepEqual(state.Authority, e.authority) {
		return nil, errors.New("reconcile: durable domain authority differs from configured authority")
	}
	return state, nil
}

func (e *Engine) ensureLease(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	if !state.Activated {
		e.resetTakeoverObservation()
		e.publishState(state, RoleUnknown, ReasonDomainNotActivated, "", false, false)
		return state, false, nil
	}
	ref := store.DomainRefFor(e.authority)
	if state.Lease == nil {
		e.resetTakeoverObservation()
		lease, err := e.store.AcquireLease(ctx, ref, e.controllerID, e.policy.LeaseDuration.Duration())
		if err != nil {
			if errors.Is(err, store.ErrLeaseHeld) || errors.Is(err, store.ErrConflict) {
				current, loadErr := e.store.LoadDomain(ctx, ref)
				if loadErr != nil {
					return state, false, e.storeFailure(state, loadErr)
				}
				return e.contendForLease(ctx, current)
			}
			return state, false, e.storeFailure(state, fmt.Errorf("acquire lease: %w", err))
		}
		if lease.FenceTerm == 0 {
			return state, false, errors.New("reconcile: acquired lease has a zero fence")
		}
		e.resetTakeoverObservation()
		state, err = e.reloadHeldLease(ctx, lease)
		if err != nil {
			return state, false, err
		}
		e.publishState(state, RoleLeader, ReasonReconciling, "", false, false)
		return state, true, nil
	}

	now := e.clock.Now()
	if state.Lease.HolderID == e.controllerID && state.Lease.ExpiresAt.After(now) {
		e.resetTakeoverObservation()
		due := !now.Before(state.Lease.RenewedAt.Add(e.policy.LeaseRenewInterval.Duration()))
		unsafe := state.Lease.ExpiresAt.Sub(now) <= e.policy.LeaseDangerWindow.Duration()
		if due || unsafe {
			var err error
			state, err = e.renew(ctx, state)
			if err != nil {
				return state, false, err
			}
		}
		e.publishState(state, RoleLeader, ReasonReconciling, "", false, false)
		return state, true, nil
	}
	return e.contendForLease(ctx, state)
}

func (e *Engine) contendForLease(ctx context.Context, observed *model.DomainState) (*model.DomainState, bool, error) {
	if observed == nil || observed.Lease == nil {
		e.resetTakeoverObservation()
		return observed, false, errors.New("reconcile: contender did not observe a lease record")
	}
	version := observed.Lease.RecordVersion
	fence := observed.FenceTerm
	firstObservation, changed := e.observeContendedLease(observed.Lease)
	waitReason := ReasonLeaseHeld
	if changed {
		waitReason = ReasonLeaseChanged
	}
	if e.clock.Now().Before(e.takeoverObservation.eligibleAt) {
		if firstObservation || changed {
			e.publishState(observed, RoleFollower, waitReason, "", false, false)
			return observed, false, nil
		}
		return observed, false, e.inspectFollower(ctx, observed, waitReason)
	}

	ref := store.DomainRefFor(e.authority)
	lease, err := e.store.TakeoverLease(ctx, ref, e.controllerID, version, e.policy.LeaseDuration.Duration())
	if err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrLeaseHeld) || errors.Is(err, store.ErrLeaseLost) || errors.Is(err, store.ErrNotFound) {
			e.resetTakeoverObservation()
			e.publishState(observed, RoleFollower, ReasonLeaseChanged, "", false, false)
			return observed, false, nil
		}
		return observed, false, e.storeFailure(observed, fmt.Errorf("take over lease: %w", err))
	}
	if lease.FenceTerm <= fence || lease.RecordVersion <= version {
		e.resetTakeoverObservation()
		return observed, false, errors.New("reconcile: takeover did not increase the fence and record version")
	}
	e.resetTakeoverObservation()
	current, err := e.reloadHeldLease(ctx, lease)
	if err != nil {
		return observed, false, err
	}
	e.publishState(current, RoleLeader, ReasonReconciling, "", false, false)
	return current, true, nil
}

func (e *Engine) observeContendedLease(lease *model.Lease) (bool, bool) {
	previous := e.takeoverObservation
	if lease != nil && previous.holderID == lease.HolderID && previous.recordVersion == lease.RecordVersion && !previous.eligibleAt.IsZero() {
		return false, false
	}
	e.takeoverObservation = leaseTakeoverObservation{
		holderID:      lease.HolderID,
		recordVersion: lease.RecordVersion,
		eligibleAt:    e.clock.Now().Add(e.policy.LeaseDuration.Duration()),
	}
	first := previous.holderID == "" && previous.recordVersion == 0 && previous.eligibleAt.IsZero()
	return first, !first
}

func (e *Engine) resetTakeoverObservation() {
	e.takeoverObservation = leaseTakeoverObservation{}
}

func (e *Engine) inspectFollower(ctx context.Context, state *model.DomainState, leaseReason StatusReason) error {
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		e.publishState(state, RoleFollower, ReasonStoreUnavailable, "", false, false)
		return err
	}
	if result.Consensus == nil {
		_, reason := e.quorumError(result.Reason)
		e.publishState(state, RoleFollower, reason, "", false, false)
		return nil
	}
	owner, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		e.publishState(state, RoleFollower, ReasonOwnerUnknown, result.Consensus.Owner, true, false)
		return nil
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, owner); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.publishState(state, RoleFollower, ReasonOwnerIneligible, result.Consensus.Owner, true, false)
		return err
	}
	snapshot, err := e.routes.Snapshot(ctx, state.Authority)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, reason := e.routeError(err, "authoritative route snapshot failed")
		e.publishState(state, RoleFollower, reason, result.Consensus.Owner, true, false)
		return err
	}
	routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)
	e.publishState(state, RoleFollower, leaseReason, result.Consensus.Owner, true, agreementErr == nil && routeOwner == result.Consensus.Owner)
	return nil
}

func (e *Engine) reloadHeldLease(ctx context.Context, lease *model.Lease) (*model.DomainState, error) {
	if lease == nil {
		return nil, errors.New("reconcile: store returned a nil lease")
	}
	state, err := e.store.LoadDomain(ctx, store.DomainRefFor(e.authority))
	if err != nil {
		return nil, e.storeFailure(nil, fmt.Errorf("load leased domain: %w", err))
	}
	state, err = e.validateLoaded(state)
	if err != nil {
		return nil, err
	}
	if state.Lease == nil || store.LeaseTokenFor(state.Lease) != store.LeaseTokenFor(lease) || state.FenceTerm != lease.FenceTerm {
		return state, errors.New("reconcile: leased domain does not contain the returned lease")
	}
	return state, nil
}

func (e *Engine) renew(ctx context.Context, state *model.DomainState) (*model.DomainState, error) {
	if state == nil || state.Lease == nil {
		return state, errors.New("reconcile: cannot renew an absent lease")
	}
	oldToken := store.LeaseTokenFor(state.Lease)
	lease, err := e.store.RenewLease(ctx, store.DomainRefFor(e.authority), oldToken, e.policy.LeaseDuration.Duration())
	if err != nil {
		if errors.Is(err, store.ErrLeaseLost) || errors.Is(err, store.ErrConflict) {
			e.publishState(state, RoleFollower, ReasonLeaseLost, "", false, false)
			return state, fmt.Errorf("reconcile: renew lease: %w", err)
		}
		return state, e.storeFailure(state, fmt.Errorf("renew lease: %w", err))
	}
	if lease == nil || lease.HolderID != e.controllerID || lease.FenceTerm != oldToken.FenceTerm || lease.RecordVersion <= oldToken.RecordVersion {
		return state, errors.New("reconcile: renewal returned an invalid lease")
	}
	next := state.Clone()
	next.Lease = lease.Clone()
	next.FenceTerm = lease.FenceTerm
	if next.UpdatedAt.Before(lease.RenewedAt) {
		next.UpdatedAt = lease.RenewedAt
	}
	return next, nil
}

func (e *Engine) reconcileStable(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		return state, false, e.storeFailure(state, err)
	}
	if result.Consensus == nil {
		stateError, reason := e.quorumError(result.Reason)
		return e.saveDegraded(ctx, state, stateError, reason, nil)
	}
	owner, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		stateError := e.newStateError(model.ErrorObservationQuorum, "observer quorum selected an unknown owner", false)
		return e.saveDegraded(ctx, state, stateError, ReasonOwnerUnknown, nil)
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, owner); err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError := e.newStateError(model.ErrorOwnerIneligible, "candidate cloud owner is not eligible", false)
		return e.saveDegraded(ctx, state, stateError, ReasonOwnerIneligible, err)
	}
	snapshot, err := e.routes.Snapshot(ctx, state.Authority)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.routeError(err, "authoritative route snapshot failed")
		return e.saveDegraded(ctx, state, stateError, reason, err)
	}
	routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)
	if agreementErr != nil || routeOwner != state.StableOwner {
		stateError := e.newStateError(model.ErrorRouteOscillation, "stable routes do not agree with the durable owner", false)
		return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, nil)
	}
	if result.Consensus.Owner == state.StableOwner {
		e.publishState(state, RoleLeader, ReasonStable, result.Consensus.Owner, true, true)
		return state, false, nil
	}

	now := e.clock.Now()
	next := state.Clone()
	next.Phase = model.PhaseOwnerObserved
	next.ObservedOwner = result.Consensus.Owner
	next.OwnerObservedAt = timePointer(now)
	next.Intent = nil
	next.Error = nil
	next.LastTransitionAt = now
	next.UpdatedAt = now
	saved, err := e.cas(ctx, state, next)
	if err != nil {
		return state, false, err
	}
	e.publishState(saved, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, routeOwner == result.Consensus.Owner)
	return saved, true, nil
}

func (e *Engine) reconcileObserved(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		return state, false, e.storeFailure(state, err)
	}
	if result.Consensus == nil {
		stateError, reason := e.quorumError(result.Reason)
		return e.saveDegraded(ctx, state, stateError, reason, nil)
	}
	owner, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		stateError := e.newStateError(model.ErrorObservationQuorum, "observer quorum selected an unknown owner", false)
		return e.saveDegraded(ctx, state, stateError, ReasonOwnerUnknown, nil)
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, owner); err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError := e.newStateError(model.ErrorOwnerIneligible, "candidate cloud owner is not eligible", false)
		return e.saveDegraded(ctx, state, stateError, ReasonOwnerIneligible, err)
	}
	snapshot, err := e.routes.Snapshot(ctx, state.Authority)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.routeError(err, "authoritative route snapshot failed")
		return e.saveDegraded(ctx, state, stateError, reason, err)
	}
	routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)
	routeAgreement := agreementErr == nil && routeOwner == result.Consensus.Owner
	if result.Consensus.Owner == state.StableOwner && agreementErr == nil && routeOwner == state.StableOwner {
		now := e.clock.Now()
		next := state.Clone()
		makeStable(next, state.StableOwner, now, false, e.policy.Cooldown.Duration())
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStable, result.Consensus.Owner, true, true)
		return saved, true, nil
	}
	if result.Consensus.Owner != state.ObservedOwner {
		now := e.clock.Now()
		next := state.Clone()
		next.ObservedOwner = result.Consensus.Owner
		next.OwnerObservedAt = timePointer(now)
		next.LastTransitionAt = now
		next.UpdatedAt = now
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, routeAgreement)
		return saved, false, nil
	}

	now := e.clock.Now()
	window := e.ownerStabilityWindow(state.StableOwner, state.ObservedOwner)
	if state.OwnerObservedAt == nil || now.Sub(*state.OwnerObservedAt) < window ||
		result.Consensus.OldestObservationAt.Before(*state.OwnerObservedAt) || !result.Consensus.StableFor(now, window) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, routeAgreement)
		return state, false, nil
	}
	if state.CooldownUntil != nil && now.Before(*state.CooldownUntil) {
		e.publishState(state, RoleLeader, ReasonCooldown, result.Consensus.Owner, true, routeAgreement)
		return state, false, nil
	}

	snapshot, err = e.stableSnapshot(ctx, state)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.routeError(err, "authoritative route snapshot failed")
		return e.saveDegraded(ctx, state, stateError, reason, err)
	}
	routeOwner, agreementErr = exactRouteOwner(state.Authority, snapshot)
	if result.Consensus.Owner == state.StableOwner && agreementErr == nil && routeOwner == state.StableOwner {
		now = e.clock.Now()
		next := state.Clone()
		makeStable(next, state.StableOwner, now, false, e.policy.Cooldown.Duration())
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStable, result.Consensus.Owner, true, true)
		return saved, true, nil
	}
	return e.persistRouteIntent(ctx, state, owner, snapshot)
}

func (e *Engine) reconcileIntent(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	result, snapshot, err := e.authorizeIntent(ctx, state)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.authorizationError(err)
		return e.saveDegraded(ctx, state, stateError, reason, err)
	}
	if !e.intentOwnerStable(state, result.Consensus) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	if err := validateIntentSnapshot(state, snapshot); err != nil {
		stateError := e.newStateError(model.ErrorRouteOscillation, "route state changed after intent was persisted", false)
		return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, err)
	}
	now := e.clock.Now()
	next := state.Clone()
	next.Phase = model.PhaseRoutesConverging
	next.LastTransitionAt = now
	next.UpdatedAt = now
	saved, saveErr := e.cas(ctx, state, next)
	if saveErr != nil {
		return state, false, saveErr
	}
	e.publishState(saved, RoleLeader, ReasonReconciling, result.Consensus.Owner, true, false)
	return saved, true, nil
}

func (e *Engine) reconcileRoutes(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	result, snapshot, err := e.authorizeIntent(ctx, state)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.authorizationError(err)
		return e.saveDegraded(ctx, state, stateError, reason, err)
	}
	if !e.intentOwnerStable(state, result.Consensus) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	if err := validateConvergingSnapshot(state, snapshot); err != nil {
		stateError := e.newStateError(model.ErrorRouteOscillation, "route progress disagrees with authoritative state", false)
		return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, err)
	}

	index := firstIncomplete(state.Intent.Progress)
	if index < 0 {
		snapshot, err = e.stableSnapshot(ctx, state)
		if err != nil {
			return e.degradeUnstableReadback(ctx, state, err)
		}
		if err := validateConvergingSnapshot(state, snapshot); err != nil {
			stateError := e.newStateError(model.ErrorRouteOscillation, "route progress changed during stable readback", false)
			return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, err)
		}
		routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)
		if agreementErr != nil || routeOwner != state.Intent.DesiredOwner {
			stateError := e.newStateError(model.ErrorRouteOscillation, "completed routes do not agree with the selected owner", false)
			return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, nil)
		}
		now := e.clock.Now()
		next := state.Clone()
		makeStable(next, state.Intent.DesiredOwner, now, true, e.policy.Cooldown.Duration())
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStable, result.Consensus.Owner, true, true)
		return saved, true, nil
	}

	prefix := state.Intent.Progress[index].DestinationPrefix
	route, found := snapshotRoute(snapshot, prefix)
	if !found {
		stateError := e.newStateError(model.ErrorInvariant, "authoritative snapshot omitted an intended route", false)
		return e.saveDegraded(ctx, state, stateError, ReasonInvariant, nil)
	}
	before, found := snapshotRoute(state.Intent.Before, prefix)
	if !found {
		stateError := e.newStateError(model.ErrorInvariant, "durable before-snapshot omitted an intended route", false)
		return e.saveDegraded(ctx, state, stateError, ReasonInvariant, nil)
	}
	if route.TargetENIID != state.Intent.DesiredENIID && route.TargetENIID != before.TargetENIID {
		stateError := e.newStateError(model.ErrorRouteOscillation, "route settled on neither its previous nor desired owner", false)
		return e.saveDegraded(ctx, state, stateError, ReasonRouteOscillation, nil)
	}

	if !state.Intent.Progress[index].Attempted() {
		now := e.clock.Now()
		next := state.Clone()
		next.Intent.Progress[index].AttemptedAt = timePointer(now)
		next.Intent.Progress[index].Ambiguous = false
		next.Intent.Progress[index].Error = nil
		next.UpdatedAt = now
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		state = saved
		e.publishState(state, RoleLeader, ReasonReconciling, result.Consensus.Owner, true, false)
	}

	if route.TargetENIID == state.Intent.DesiredENIID {
		confirmed, confirmErr := e.stableSnapshot(ctx, state)
		if confirmErr != nil {
			return e.degradeUnstableReadback(ctx, state, confirmErr)
		}
		if err := validateConvergingSnapshot(state, confirmed); err != nil {
			stateError := e.newStateError(model.ErrorRouteOscillation, "route progress changed during stable readback", false)
			return e.saveDegraded(ctx, state, stateError, ReasonRouteDisagreement, err)
		}
		confirmedRoute, found := snapshotRoute(confirmed, prefix)
		if !found || confirmedRoute.TargetENIID != state.Intent.DesiredENIID {
			stateError := e.newStateError(model.ErrorRouteOscillation, "desired route was not stable across authoritative reads", false)
			return e.saveDegraded(ctx, state, stateError, ReasonRouteOscillation, nil)
		}
		saved, saveErr := e.completeRoute(ctx, state, index, false)
		if saveErr != nil {
			return state, false, saveErr
		}
		return saved, true, nil
	}

	state, deadline, renewErr := e.renewForMutation(ctx, state)
	if renewErr != nil {
		return state, false, renewErr
	}
	result, renewErr = e.authorizeIntentOwner(ctx, state)
	if renewErr != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.authorizationError(renewErr)
		return e.saveDegraded(ctx, state, stateError, reason, renewErr)
	}
	if !e.intentOwnerStable(state, result.Consensus) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	result, renewErr = e.authorizeIntentConsensus(ctx, state)
	if renewErr != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.authorizationError(renewErr)
		return e.saveDegraded(ctx, state, stateError, reason, renewErr)
	}
	if !e.intentOwnerStable(state, result.Consensus) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	resultValue, replaceErr := e.mutator.ReplaceAndWait(
		ctx,
		state.Authority,
		prefix,
		before.TargetENIID,
		state.Intent.DesiredENIID,
		deadline,
	)
	if replaceErr != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		stateError, reason := e.routeError(replaceErr, "route mutation did not settle on the desired owner")
		if resultValue.Settlement == awscontrol.SettlementPrevious && errors.Is(replaceErr, awscontrol.ErrAmbiguous) && !errors.Is(replaceErr, awscontrol.ErrOscillation) {
			if resultValue.DestinationPrefix != prefix || resultValue.DesiredENIID != state.Intent.DesiredENIID ||
				resultValue.PreviousENIID != before.TargetENIID || resultValue.ObservedENIID != before.TargetENIID {
				invariant := e.newStateError(model.ErrorInvariant, "route controller returned an invalid previous settlement", true)
				next := state.Clone()
				next.Intent.Progress[index].Ambiguous = true
				next.Intent.Progress[index].Error = invariant.Clone()
				return e.saveDegraded(ctx, state, invariant, ReasonInvariant, nil, next)
			}
			now := e.clock.Now()
			next := state.Clone()
			next.Intent.Progress[index].ObservedENIID = before.TargetENIID
			next.Intent.Progress[index].Ambiguous = resultValue.CallAmbiguous
			next.Intent.Progress[index].Error = stateError.Clone()
			next.UpdatedAt = now
			saved, saveErr := e.cas(ctx, state, next)
			if saveErr != nil {
				return state, false, saveErr
			}
			e.publishState(saved, RoleLeader, reason, result.Consensus.Owner, true, false)
			return saved, false, replaceErr
		}
		next := state.Clone()
		next.Intent.Progress[index].Ambiguous = resultValue.CallAttempted || errors.Is(replaceErr, awscontrol.ErrAmbiguous)
		next.Intent.Progress[index].Error = stateError.Clone()
		return e.saveDegraded(ctx, state, stateError, reason, replaceErr, next)
	}
	if resultValue.DestinationPrefix != prefix || resultValue.DesiredENIID != state.Intent.DesiredENIID ||
		resultValue.PreviousENIID != before.TargetENIID ||
		resultValue.Settlement != awscontrol.SettlementDesired || resultValue.ObservedENIID != state.Intent.DesiredENIID {
		stateError := e.newStateError(model.ErrorInvariant, "route controller returned an invalid desired settlement", true)
		next := state.Clone()
		next.Intent.Progress[index].Ambiguous = true
		next.Intent.Progress[index].Error = stateError.Clone()
		return e.saveDegraded(ctx, state, stateError, ReasonRouteAmbiguous, nil, next)
	}
	saved, saveErr := e.completeRoute(ctx, state, index, resultValue.CallAmbiguous)
	if saveErr != nil {
		return state, false, saveErr
	}
	return saved, true, nil
}

func (e *Engine) reconcileDegraded(ctx context.Context, state *model.DomainState) (*model.DomainState, bool, error) {
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		return state, false, e.storeFailure(state, err)
	}
	if result.Consensus == nil {
		_, reason := e.quorumError(result.Reason)
		e.publishState(state, RoleLeader, reason, "", false, false)
		return state, false, nil
	}
	candidate, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		e.publishState(state, RoleLeader, ReasonOwnerUnknown, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, candidate); err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		e.publishState(state, RoleLeader, ReasonOwnerIneligible, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	now := e.clock.Now()
	ownerReversed := state.Intent != nil && result.Consensus.Owner != state.Intent.DesiredOwner
	if state.Intent != nil && !ownerReversed && !e.ownerStableFor(state.StableOwner, result.Consensus) {
		e.publishState(state, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return state, false, nil
	}

	snapshot, err := e.stableSnapshot(ctx, state)
	if err != nil {
		if ctx.Err() != nil {
			return state, false, ctx.Err()
		}
		if errors.Is(err, awscontrol.ErrUnstableReadback) {
			e.publishState(state, RoleLeader, ReasonRouteOscillation, result.Consensus.Owner, true, false)
			return state, false, nil
		}
		_, reason := e.routeError(err, "authoritative route snapshot failed")
		e.publishState(state, RoleLeader, reason, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	if ownerReversed {
		if err := validateIntentSnapshot(state, snapshot); err != nil {
			e.publishState(state, RoleLeader, ReasonRouteDisagreement, result.Consensus.Owner, true, false)
			return state, false, nil
		}
		now = e.clock.Now()
		next := state.Clone()
		next.Phase = model.PhaseOwnerObserved
		next.ObservedOwner = candidate.StableNodeID
		next.OwnerObservedAt = timePointer(now)
		next.Intent = nil
		next.Error = nil
		next.LastTransitionAt = now
		next.UpdatedAt = now
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, false)
		return saved, true, nil
	}
	routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)

	now = e.clock.Now()
	if agreementErr == nil && routeOwner == result.Consensus.Owner {
		next := state.Clone()
		transitioned := routeOwner != state.StableOwner
		makeStable(next, routeOwner, now, transitioned, e.policy.Cooldown.Duration())
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStable, result.Consensus.Owner, true, true)
		return saved, true, nil
	}
	if state.Intent == nil {
		if agreementErr != nil || routeOwner != state.StableOwner {
			e.publishState(state, RoleLeader, ReasonRouteDisagreement, result.Consensus.Owner, true, false)
			return state, false, nil
		}
		next := state.Clone()
		next.Phase = model.PhaseOwnerObserved
		next.ObservedOwner = result.Consensus.Owner
		next.OwnerObservedAt = timePointer(now)
		next.Error = nil
		next.LastTransitionAt = now
		next.UpdatedAt = now
		saved, saveErr := e.cas(ctx, state, next)
		if saveErr != nil {
			return state, false, saveErr
		}
		e.publishState(saved, RoleLeader, ReasonStabilityWindow, result.Consensus.Owner, true, routeOwner == result.Consensus.Owner)
		return saved, true, nil
	}
	if !resumableIntentError(state.Error.Code) {
		e.publishState(state, RoleLeader, ReasonRouteDisagreement, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	if err := validateConvergingSnapshot(state, snapshot); err != nil {
		e.publishState(state, RoleLeader, ReasonRouteDisagreement, result.Consensus.Owner, true, false)
		return state, false, nil
	}
	next := state.Clone()
	next.Phase = model.PhaseRoutesConverging
	next.Error = nil
	if index := firstIncomplete(next.Intent.Progress); index >= 0 && next.Intent.Progress[index].Attempted() {
		if route, found := snapshotRoute(snapshot, next.Intent.Progress[index].DestinationPrefix); found {
			next.Intent.Progress[index].ObservedENIID = route.TargetENIID
		}
	}
	next.LastTransitionAt = now
	next.UpdatedAt = now
	saved, saveErr := e.cas(ctx, state, next)
	if saveErr != nil {
		return state, false, saveErr
	}
	e.publishState(saved, RoleLeader, ReasonReconciling, result.Consensus.Owner, true, false)
	return saved, true, nil
}

func (e *Engine) persistCurrentIntentFence(ctx context.Context, state *model.DomainState) (*model.DomainState, error) {
	if state == nil || state.Intent == nil || state.Lease == nil {
		return state, errors.New("reconcile: cannot fence an absent route intent or lease")
	}
	now := e.clock.Now()
	next := state.Clone()
	next.Intent.FenceTerm = state.FenceTerm
	next.UpdatedAt = now
	saved, err := e.cas(ctx, state, next)
	if err != nil {
		return state, err
	}
	e.publishState(saved, RoleLeader, ReasonReconciling, saved.Intent.DesiredOwner, true, false)
	return saved, nil
}

func (e *Engine) persistRouteIntent(
	ctx context.Context,
	state *model.DomainState,
	owner model.OwnerAuthority,
	snapshot model.RouteSnapshot,
) (*model.DomainState, bool, error) {
	transactionID := e.uuids.NewUUID()
	if !validTransactionID(transactionID) {
		stateError := e.newStateError(model.ErrorInvariant, "UUID source returned an invalid transaction ID", false)
		return e.saveDegraded(ctx, state, stateError, ReasonInvariant, nil)
	}
	now := e.clock.Now()
	progress := make([]model.RouteProgress, len(state.Authority.RemotePrefixes))
	for index, prefix := range state.Authority.RemotePrefixes {
		progress[index].DestinationPrefix = prefix
	}
	next := state.Clone()
	next.Phase = model.PhaseRouteIntentPersisted
	if next.ObservedOwner != owner.StableNodeID || next.OwnerObservedAt == nil {
		next.OwnerObservedAt = timePointer(now)
	}
	next.ObservedOwner = owner.StableNodeID
	next.Intent = &model.RouteIntent{
		TransactionID: transactionID,
		FenceTerm:     state.FenceTerm,
		DesiredOwner:  owner.StableNodeID,
		DesiredENIID:  owner.ENIID,
		CreatedAt:     now,
		Before:        snapshot.Clone(),
		Progress:      progress,
	}
	next.Error = nil
	next.LastTransitionAt = now
	next.UpdatedAt = now
	saved, err := e.cas(ctx, state, next)
	if err != nil {
		return state, false, err
	}
	e.publishState(saved, RoleLeader, ReasonReconciling, owner.StableNodeID, true, false)
	return saved, true, nil
}

func (e *Engine) authorizeIntentConsensus(ctx context.Context, state *model.DomainState) (health.Result, error) {
	if state.Intent == nil {
		return health.Result{}, errors.New("reconcile: durable route phase has no intent")
	}
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		return result, err
	}
	if result.Consensus == nil {
		return result, &quorumFailure{reason: result.Reason}
	}
	if result.Consensus.Owner != state.Intent.DesiredOwner {
		return result, &quorumFailure{reason: health.ReasonDisagreement}
	}
	return result, nil
}

func (e *Engine) authorizeIntentOwner(ctx context.Context, state *model.DomainState) (health.Result, error) {
	result, err := e.authorizeIntentConsensus(ctx, state)
	if err != nil {
		return result, err
	}
	owner, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		return result, &quorumFailure{reason: health.ReasonUnknownOwner}
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, owner); err != nil {
		return result, &ownerFailure{cause: err}
	}
	return result, nil
}

func (e *Engine) authorizeIntent(ctx context.Context, state *model.DomainState) (health.Result, model.RouteSnapshot, error) {
	result, err := e.authorizeIntentOwner(ctx, state)
	if err != nil {
		return result, model.RouteSnapshot{}, err
	}
	snapshot, err := e.routes.Snapshot(ctx, state.Authority)
	if err != nil {
		return result, model.RouteSnapshot{}, &snapshotFailure{cause: err}
	}
	if err := snapshot.Validate(state.Authority); err != nil {
		return result, model.RouteSnapshot{}, &snapshotFailure{cause: err}
	}
	return result, snapshot, nil
}

func (e *Engine) stableSnapshot(ctx context.Context, state *model.DomainState) (model.RouteSnapshot, error) {
	if state == nil {
		return model.RouteSnapshot{}, errors.New("reconcile: stable route readback requires durable state")
	}
	now := e.clock.Now()
	deadline := now.Add(e.policy.APITimeout.Duration() + e.policy.RouteConvergenceTimeout.Duration())
	if state.Lease != nil && state.Lease.ExpiresAt.Before(deadline) {
		deadline = state.Lease.ExpiresAt
	}
	if !deadline.After(now) {
		return model.RouteSnapshot{}, &awscontrol.UnstableReadbackError{Reason: "lease-safe readback deadline reached"}
	}

	var (
		snapshot model.RouteSnapshot
		err      error
	)
	if !isNil(e.stableRoutes) {
		snapshot, err = e.stableRoutes.StableSnapshot(ctx, state.Authority, deadline)
	} else {
		// Compatibility adapters outside the production AWS path may not yet
		// expose stable readback; their Snapshot contract remains bounded.
		snapshot, err = e.routes.Snapshot(ctx, state.Authority)
	}
	if err != nil {
		return model.RouteSnapshot{}, err
	}
	if err := snapshot.Validate(state.Authority); err != nil {
		return model.RouteSnapshot{}, err
	}
	return snapshot, nil
}

func (e *Engine) degradeUnstableReadback(
	ctx context.Context,
	state *model.DomainState,
	err error,
) (*model.DomainState, bool, error) {
	if ctx.Err() != nil {
		return state, false, ctx.Err()
	}
	if errors.Is(err, awscontrol.ErrUnstableReadback) {
		stateError := e.newStateError(model.ErrorRouteOscillation, "route state changed during authoritative readback", false)
		return e.saveDegraded(ctx, state, stateError, ReasonRouteOscillation, nil)
	}
	stateError, reason := e.routeError(err, "authoritative route snapshot failed")
	return e.saveDegraded(ctx, state, stateError, reason, err)
}

func (e *Engine) evaluate(ctx context.Context, authority model.DomainAuthority) (health.Result, error) {
	listed, err := e.store.ListObservations(ctx, store.ObservationScope{
		DeploymentID: authority.DeploymentID,
		TopologyHash: authority.TopologyHash,
	})
	if err != nil {
		return health.Result{}, fmt.Errorf("reconcile: list observations: %w", err)
	}
	observations := make([]model.Observation, 0, len(listed))
	for _, observation := range listed {
		if observation != nil {
			observations = append(observations, *observation.Clone())
		}
	}
	return health.Evaluate(e.clock.Now(), authority, observations, health.QuorumPolicy{
		AllowedControllerIDs: e.controllers,
		Quorum:               e.policy.ObservationQuorum,
		Freshness:            e.policy.ObservationFreshness.Duration(),
	}), nil
}

func (e *Engine) renewForMutation(ctx context.Context, state *model.DomainState) (*model.DomainState, time.Time, error) {
	renewed, err := e.renew(ctx, state)
	if err != nil {
		return state, time.Time{}, err
	}
	now := e.clock.Now()
	remaining := renewed.Lease.ExpiresAt.Sub(now)
	operationBound := e.policy.APITimeout.Duration() + e.policy.RouteConvergenceTimeout.Duration()
	if remaining <= e.policy.LeaseDangerWindow.Duration() || operationBound > e.policy.LeaseDangerWindow.Duration() || operationBound <= 0 {
		stateError := e.newStateError(model.ErrorLeaseUnsafe, "lease cannot safely bound a route mutation", false)
		degraded, _, saveErr := e.saveDegraded(ctx, renewed, stateError, ReasonLeaseUnsafe, nil)
		if saveErr != nil {
			return renewed, time.Time{}, saveErr
		}
		return degraded, time.Time{}, errors.New("reconcile: lease is inside the mutation danger window")
	}
	deadline := now.Add(operationBound)
	if !deadline.Before(renewed.Lease.ExpiresAt) {
		stateError := e.newStateError(model.ErrorLeaseUnsafe, "route deadline reaches the lease expiry", false)
		degraded, _, saveErr := e.saveDegraded(ctx, renewed, stateError, ReasonLeaseUnsafe, nil)
		if saveErr != nil {
			return renewed, time.Time{}, saveErr
		}
		return degraded, time.Time{}, errors.New("reconcile: route deadline is not lease safe")
	}
	return renewed, deadline, nil
}

func (e *Engine) completeRoute(ctx context.Context, state *model.DomainState, index int, ambiguous bool) (*model.DomainState, error) {
	if state.Intent == nil || index < 0 || index >= len(state.Intent.Progress) {
		return state, errors.New("reconcile: invalid route completion index")
	}
	now := e.clock.Now()
	next := state.Clone()
	next.Intent.Progress[index].CompletedAt = timePointer(now)
	next.Intent.Progress[index].ObservedENIID = next.Intent.DesiredENIID
	next.Intent.Progress[index].Ambiguous = ambiguous
	next.Intent.Progress[index].Error = nil
	next.UpdatedAt = now
	saved, err := e.cas(ctx, state, next)
	if err != nil {
		return state, err
	}
	e.publishState(saved, RoleLeader, ReasonReconciling, saved.Intent.DesiredOwner, true, false)
	return saved, nil
}

func (e *Engine) cas(ctx context.Context, current, next *model.DomainState) (*model.DomainState, error) {
	if current == nil || current.Lease == nil {
		return current, errors.New("reconcile: state CAS requires a held lease")
	}
	saved, err := e.store.CompareAndSwapDomain(
		ctx,
		store.DomainRefFor(e.authority),
		current.Revision,
		store.LeaseTokenFor(current.Lease),
		next,
	)
	if err != nil {
		if errors.Is(err, store.ErrLeaseLost) || errors.Is(err, store.ErrConflict) {
			e.publishState(current, RoleFollower, ReasonLeaseLost, "", false, false)
			return current, fmt.Errorf("reconcile: domain CAS lost authority: %w", err)
		}
		return current, e.storeFailure(current, fmt.Errorf("domain CAS: %w", err))
	}
	return saved, nil
}

func (e *Engine) saveDegraded(
	ctx context.Context,
	current *model.DomainState,
	stateError *model.StateError,
	reason StatusReason,
	cause error,
	overlay ...*model.DomainState,
) (*model.DomainState, bool, error) {
	if ctx.Err() != nil {
		return current, false, ctx.Err()
	}
	next := current.Clone()
	if len(overlay) > 0 && overlay[0] != nil {
		next = overlay[0].Clone()
	}
	now := e.clock.Now()
	next.Phase = model.PhaseDegraded
	next.Error = stateError.Clone()
	next.LastTransitionAt = now
	next.UpdatedAt = now
	saved, err := e.cas(ctx, current, next)
	if err != nil {
		return current, false, err
	}
	consensus := ""
	if saved.ObservedOwner != "" {
		consensus = saved.ObservedOwner
	}
	e.publishState(saved, RoleLeader, reason, consensus, false, false)
	if cause != nil {
		return saved, true, cause
	}
	return saved, true, nil
}

func (e *Engine) inspectReadOnly(ctx context.Context) error {
	state, err := e.store.LoadDomain(ctx, store.DomainRefFor(e.authority))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.publishWithoutState(RoleReadOnly, ReasonDomainNotInitialized, "")
			return nil
		}
		e.publishWithoutState(RoleReadOnly, ReasonStoreUnavailable, model.ErrorStoreUnavailable)
		return fmt.Errorf("reconcile: read-only load: %w", err)
	}
	state, err = e.validateLoaded(state)
	if err != nil {
		e.publishState(state, RoleReadOnly, ReasonInvariant, "", false, false)
		return err
	}
	result, err := e.evaluate(ctx, state.Authority)
	if err != nil {
		e.publishState(state, RoleReadOnly, ReasonStoreUnavailable, "", false, false)
		return err
	}
	if result.Consensus == nil {
		_, reason := e.quorumError(result.Reason)
		e.publishState(state, RoleReadOnly, reason, "", false, false)
		return nil
	}
	owner, found := state.Authority.OwnerByStableNode(result.Consensus.Owner)
	if !found {
		e.publishState(state, RoleReadOnly, ReasonOwnerUnknown, result.Consensus.Owner, true, false)
		return nil
	}
	if _, err := e.routes.ValidateOwner(ctx, state.Authority, owner); err != nil {
		e.publishState(state, RoleReadOnly, ReasonOwnerIneligible, result.Consensus.Owner, true, false)
		return err
	}
	snapshot, err := e.routes.Snapshot(ctx, state.Authority)
	if err != nil {
		_, reason := e.routeError(err, "authoritative route snapshot failed")
		e.publishState(state, RoleReadOnly, reason, result.Consensus.Owner, true, false)
		return err
	}
	routeOwner, agreementErr := exactRouteOwner(state.Authority, snapshot)
	agreement := agreementErr == nil && routeOwner == result.Consensus.Owner
	e.publishState(state, RoleReadOnly, ReasonReadOnly, result.Consensus.Owner, true, agreement)
	return nil
}

func (e *Engine) publishState(state *model.DomainState, role Role, reason StatusReason, consensus string, quorum, routeAgreement bool) {
	status := Status{
		ControllerID:   e.controllerID,
		DomainID:       e.authority.DomainID,
		Mode:           e.mode,
		Role:           role,
		Reason:         reason,
		ConsensusOwner: consensus,
		Quorum:         quorum,
		RouteAgreement: routeAgreement,
		TotalRoutes:    len(e.authority.RemotePrefixes),
		UpdatedAt:      e.clock.Now(),
	}
	if state != nil {
		status.Phase = state.Phase
		status.StableOwner = state.StableOwner
		status.ObservedOwner = state.ObservedOwner
		status.FenceTerm = state.FenceTerm
		if state.Lease != nil {
			status.LeaseExpiresAt = state.Lease.ExpiresAt
		}
		if state.Error != nil {
			status.ErrorCode = state.Error.Code
		}
		if state.Intent != nil {
			for _, progress := range state.Intent.Progress {
				if progress.Completed() {
					status.CompletedRoutes++
				}
			}
		}
	}
	e.status.publish(status)
}

func (e *Engine) publishWithoutState(role Role, reason StatusReason, code model.ErrorCode) {
	status := e.Status()
	status.Role = role
	status.Reason = reason
	status.ErrorCode = code
	status.UpdatedAt = e.clock.Now()
	e.status.publish(status)
}

func (e *Engine) storeFailure(state *model.DomainState, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		e.publishState(state, RoleUnknown, ReasonCanceled, "", false, false)
		return err
	}
	e.publishState(state, RoleUnknown, ReasonStoreUnavailable, "", false, false)
	return fmt.Errorf("reconcile: durable store unavailable: %w", err)
}

func (e *Engine) quorumError(reason health.Reason) (*model.StateError, StatusReason) {
	statusReason := ReasonObservationQuorum
	switch reason {
	case health.ReasonNoQuorum:
		statusReason = ReasonObservationNoQuorum
	case health.ReasonStaleObservation:
		statusReason = ReasonObservationStale
	case health.ReasonInvalidInput:
		statusReason = ReasonObservationInvalid
	case health.ReasonDisagreement:
		statusReason = ReasonObservationDisagreement
	case health.ReasonUnknownOwner:
		statusReason = ReasonOwnerUnknown
	case health.ReasonUnhealthyOwner:
		statusReason = ReasonOwnerUnhealthy
	}
	message := "observer quorum is not authoritative"
	if reason != "" {
		message += ": " + string(reason)
	}
	return e.newStateError(model.ErrorObservationQuorum, message, false), statusReason
}

func (e *Engine) authorizationError(err error) (*model.StateError, StatusReason) {
	var quorumErr *quorumFailure
	if errors.As(err, &quorumErr) {
		return e.quorumError(quorumErr.reason)
	}
	var ownerErr *ownerFailure
	if errors.As(err, &ownerErr) {
		return e.newStateError(model.ErrorOwnerIneligible, "candidate cloud owner is not eligible", false), ReasonOwnerIneligible
	}
	var snapshotErr *snapshotFailure
	if errors.As(err, &snapshotErr) {
		return e.routeError(snapshotErr.cause, "authoritative route snapshot failed")
	}
	return e.newStateError(model.ErrorInvariant, "intent authorization failed", false), ReasonInvariant
}

func (e *Engine) routeError(err error, fallback string) (*model.StateError, StatusReason) {
	switch {
	case errors.Is(err, awscontrol.ErrUnauthorized):
		return e.newStateError(model.ErrorRouteUnauthorized, "route selected a target outside immutable authority", false), ReasonRouteUnauthorized
	case errors.Is(err, awscontrol.ErrUnstableReadback):
		return e.newStateError(model.ErrorRouteOscillation, "route state changed during authoritative readback", false), ReasonRouteOscillation
	case errors.Is(err, awscontrol.ErrOscillation):
		return e.newStateError(model.ErrorRouteOscillation, "route target did not settle", true), ReasonRouteOscillation
	case errors.Is(err, awscontrol.ErrAmbiguous):
		return e.newStateError(model.ErrorRouteAmbiguous, "route mutation outcome remains ambiguous", true), ReasonRouteAmbiguous
	case errors.Is(err, awscontrol.ErrUnsafeDeadline):
		return e.newStateError(model.ErrorLeaseUnsafe, "route mutation deadline was not lease safe", false), ReasonLeaseUnsafe
	case errors.Is(err, awscontrol.ErrOwnerIneligible):
		return e.newStateError(model.ErrorOwnerIneligible, "authoritative route or owner is ineligible", false), ReasonOwnerIneligible
	default:
		return e.newStateError(model.ErrorRouteAmbiguous, fallback, true), ReasonRouteAmbiguous
	}
}

func (e *Engine) newStateError(code model.ErrorCode, message string, ambiguous bool) *model.StateError {
	return &model.StateError{Code: code, Message: message, At: e.clock.Now(), Ambiguous: ambiguous}
}

func (e *Engine) ownerStabilityWindow(stableOwner, candidate string) time.Duration {
	if candidate == e.authority.PreferredOwner && stableOwner != e.authority.PreferredOwner {
		return e.policy.FailbackStability.Duration()
	}
	return e.policy.FailoverStability.Duration()
}

func (e *Engine) ownerStableFor(stableOwner string, consensus *health.Consensus) bool {
	if consensus == nil {
		return false
	}
	return consensus.StableFor(e.clock.Now(), e.ownerStabilityWindow(stableOwner, consensus.Owner))
}

func (e *Engine) intentOwnerStable(state *model.DomainState, consensus *health.Consensus) bool {
	return state != nil && state.Intent != nil && consensus != nil &&
		consensus.Owner == state.Intent.DesiredOwner && e.ownerStableFor(state.StableOwner, consensus)
}

func exactRouteOwner(authority model.DomainAuthority, snapshot model.RouteSnapshot) (string, error) {
	if err := snapshot.Validate(authority); err != nil {
		return "", err
	}
	owner := ""
	for _, route := range snapshot.Routes {
		candidate, found := ownerByENI(authority, route.TargetENIID)
		if !found {
			return "", fmt.Errorf("route %q has an unauthorized target", route.DestinationPrefix)
		}
		if owner == "" {
			owner = candidate.StableNodeID
			continue
		}
		if owner != candidate.StableNodeID {
			return "", errors.New("domain routes select multiple authorized owners")
		}
	}
	if owner == "" {
		return "", errors.New("domain route snapshot is empty")
	}
	return owner, nil
}

func matchingRouteSnapshots(authority model.DomainAuthority, first, second model.RouteSnapshot) error {
	if err := first.Validate(authority); err != nil {
		return fmt.Errorf("first snapshot: %w", err)
	}
	if err := second.Validate(authority); err != nil {
		return fmt.Errorf("second snapshot: %w", err)
	}
	if second.CapturedAt.Before(first.CapturedAt) {
		return errors.New("second snapshot predates the first")
	}
	for _, prefix := range authority.RemotePrefixes {
		firstRoute, firstFound := snapshotRoute(first, prefix)
		secondRoute, secondFound := snapshotRoute(second, prefix)
		if !firstFound || !secondFound || firstRoute != secondRoute {
			return fmt.Errorf("route %q changed between consecutive reads", prefix)
		}
	}
	return nil
}

func validateIntentSnapshot(state *model.DomainState, snapshot model.RouteSnapshot) error {
	if state == nil || state.Intent == nil {
		return errors.New("route intent is absent")
	}
	for _, route := range snapshot.Routes {
		before, found := snapshotRoute(state.Intent.Before, route.DestinationPrefix)
		if !found {
			return fmt.Errorf("route %q is absent from the before-snapshot", route.DestinationPrefix)
		}
		if route.TargetENIID != before.TargetENIID && route.TargetENIID != state.Intent.DesiredENIID {
			return fmt.Errorf("route %q selects neither its previous nor desired target", route.DestinationPrefix)
		}
	}
	return nil
}

func validateConvergingSnapshot(state *model.DomainState, snapshot model.RouteSnapshot) error {
	if err := validateIntentSnapshot(state, snapshot); err != nil {
		return err
	}
	for _, progress := range state.Intent.Progress {
		if !progress.Completed() {
			continue
		}
		route, found := snapshotRoute(snapshot, progress.DestinationPrefix)
		if !found || route.TargetENIID != state.Intent.DesiredENIID {
			return fmt.Errorf("completed route %q no longer selects the desired target", progress.DestinationPrefix)
		}
	}
	return nil
}

func snapshotRoute(snapshot model.RouteSnapshot, prefix string) (model.RouteSnapshotEntry, bool) {
	for _, route := range snapshot.Routes {
		if route.DestinationPrefix == prefix {
			return route, true
		}
	}
	return model.RouteSnapshotEntry{}, false
}

func ownerByENI(authority model.DomainAuthority, eniID string) (model.OwnerAuthority, bool) {
	for _, owner := range authority.Owners {
		if owner.ENIID == eniID {
			return owner, true
		}
	}
	return model.OwnerAuthority{}, false
}

func firstIncomplete(progress []model.RouteProgress) int {
	for index := range progress {
		if !progress[index].Completed() {
			return index
		}
	}
	return -1
}

func resumableIntentError(code model.ErrorCode) bool {
	switch code {
	case model.ErrorObservationQuorum, model.ErrorOwnerIneligible, model.ErrorLeaseUnsafe, model.ErrorRouteAmbiguous:
		return true
	default:
		return false
	}
}

func makeStable(state *model.DomainState, owner string, now time.Time, transitioned bool, cooldown time.Duration) {
	state.Phase = model.PhaseStable
	state.StableOwner = owner
	state.ObservedOwner = ""
	state.OwnerObservedAt = nil
	state.Intent = nil
	state.Error = nil
	if transitioned {
		state.CooldownUntil = timePointer(now.Add(cooldown))
	}
	state.LastTransitionAt = now
	state.UpdatedAt = now
}

func validTransactionID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func timePointer(value time.Time) *time.Time { return &value }

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func statusReasonForStore(err error) StatusReason {
	if errors.Is(err, store.ErrNotFound) {
		return ReasonDomainNotInitialized
	}
	return ReasonStoreUnavailable
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

type quorumFailure struct{ reason health.Reason }

func (e *quorumFailure) Error() string { return "reconcile: owner quorum is not authoritative" }

type ownerFailure struct{ cause error }

func (e *ownerFailure) Error() string { return "reconcile: candidate owner is not eligible" }
func (e *ownerFailure) Unwrap() error { return e.cause }

type snapshotFailure struct{ cause error }

func (e *snapshotFailure) Error() string { return "reconcile: authoritative route snapshot failed" }
func (e *snapshotFailure) Unwrap() error { return e.cause }
