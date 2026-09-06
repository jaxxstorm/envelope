// Package lifecycle implements deployment-only journal operations. It is not
// imported by the production reconciliation loop and has no route actuator.
package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/health"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

var (
	ErrPreflight = errors.New("deployment initialization preflight failed")
	ErrExists    = errors.New("deployment journal already exists; initialization cannot adopt or replace it")
	ErrUncertain = errors.New("deployment initialization outcome uncertain; inspect retained journal before retry")
)

type InitialStore interface {
	LoadDomain(context.Context, store.DomainRef) (*model.DomainState, error)
	ListObservations(context.Context, store.ObservationScope) ([]*model.Observation, error)
	CreateDomain(context.Context, *model.DomainState) (*model.DomainState, error)
}

// Inspector must verify the exact GWLBE association on every stable route read.
type Inspector interface {
	ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error)
	StableSnapshot(context.Context, model.DomainAuthority, time.Time) (model.RouteSnapshot, error)
}

// Forwarding verifies a freshly challenged, independently authenticated router
// report and returns its expiry. There is intentionally no permissive default.
type Forwarding func(context.Context, model.DomainAuthority, model.OwnerAuthority) (time.Time, error)

// Initialize is conditional-create only. The caller must supply explicitly
// route-denied credentials; the narrow interfaces are not an IAM boundary.
// It never acquires a controller lease, activates a domain, or repairs a route.
func Initialize(ctx context.Context, topology *config.Topology, domainID string, durable InitialStore, cloud Inspector, forwarding Forwarding, clock store.Clock) (*model.DomainState, error) {
	if ctx == nil || topology == nil || topology.Validate() != nil || durable == nil || cloud == nil || forwarding == nil || clock == nil {
		return nil, ErrPreflight
	}
	authority, err := topology.DomainAuthority(domainID)
	if err != nil {
		return nil, ErrPreflight
	}
	ref := store.DomainRefFor(authority)
	if _, err := durable.LoadDomain(ctx, ref); !errors.Is(err, store.ErrNotFound) {
		if err == nil {
			return nil, ErrExists
		}
		return nil, ErrPreflight
	}
	initial, err := CheckAgreement(ctx, topology, domainID, durable, cloud, forwarding, clock)
	if err != nil {
		return nil, err
	}
	created, err := durable.CreateDomain(ctx, initial)
	if errors.Is(err, store.ErrConflict) {
		return nil, ErrExists
	}
	if err != nil || !reflect.DeepEqual(created, initial) {
		return nil, ErrUncertain
	}
	return created.Clone(), nil
}

// CheckAgreement performs the same live preflight for initialization, activation,
// rollout health gates, and both sides of a topology migration, without writes.
func CheckAgreement(ctx context.Context, topology *config.Topology, domainID string, durable InitialStore, cloud Inspector, forwarding Forwarding, clock store.Clock) (*model.DomainState, error) {
	if ctx == nil || topology == nil || topology.Validate() != nil || durable == nil || cloud == nil || forwarding == nil || clock == nil {
		return nil, ErrPreflight
	}
	authority, err := topology.DomainAuthority(domainID)
	if err != nil {
		return nil, ErrPreflight
	}
	policy := topology.Policy
	call, cancel := context.WithTimeout(ctx, policy.RouteConvergenceTimeout.Duration()+3*policy.APITimeout.Duration())
	defer cancel()
	quorumPolicy := health.QuorumPolicy{AllowedControllerIDs: topology.ControllerIDs,
		Quorum: policy.ObservationQuorum, Freshness: policy.ObservationFreshness.Duration()}
	readConsensus := func() (*health.Consensus, error) {
		listed, err := durable.ListObservations(call, store.ObservationScope{DeploymentID: authority.DeploymentID, TopologyHash: authority.TopologyHash})
		if err != nil {
			return nil, ErrPreflight
		}
		observations := make([]model.Observation, 0, len(listed))
		for _, observation := range listed {
			if observation == nil || observation.Validate() != nil {
				return nil, ErrPreflight
			}
			observations = append(observations, *observation.Clone())
		}
		result := health.Evaluate(clock.Now(), authority, observations, quorumPolicy)
		if result.Consensus == nil || !result.Consensus.StableFor(clock.Now(), policy.FailbackStability.Duration()) {
			return nil, ErrPreflight
		}
		return result.Consensus, nil
	}
	consensus, err := readConsensus()
	if err != nil {
		return nil, err
	}
	owner, found := authority.OwnerByStableNode(consensus.Owner)
	if !found {
		return nil, ErrPreflight
	}
	validation, err := cloud.ValidateOwner(call, authority, owner)
	if err != nil {
		return nil, ErrPreflight
	}
	expires, err := forwarding(call, authority, owner)
	if err != nil {
		return nil, ErrPreflight
	}
	snapshot, err := cloud.StableSnapshot(call, authority, clock.Now().Add(policy.RouteConvergenceTimeout.Duration()))
	if err != nil || snapshot.RouteTableID != authority.RouteTableID || len(snapshot.Routes) != len(authority.RemotePrefixes) {
		return nil, ErrPreflight
	}
	seen := make(map[string]bool, len(snapshot.Routes))
	for _, route := range snapshot.Routes {
		if seen[route.DestinationPrefix] || route.TargetENIID != owner.ENIID || route.State != "active" || route.Origin != "CreateRoute" {
			return nil, ErrPreflight
		}
		seen[route.DestinationPrefix] = true
	}
	for _, prefix := range authority.RemotePrefixes {
		if !seen[prefix] {
			return nil, ErrPreflight
		}
	}
	// Recheck quorum after cloud I/O; a fresh timestamp alone cannot hide an
	// intervening owner change because continuity generations must also match.
	confirmed, err := readConsensus()
	now := clock.Now()
	if err != nil || confirmed.Owner != consensus.Owner || !reflect.DeepEqual(confirmed.OwnerChangeGenerations, consensus.OwnerChangeGenerations) ||
		call.Err() != nil || !expires.After(now) || validation.ValidatedAt.IsZero() || validation.ValidatedAt.After(now) ||
		!validation.ValidatedAt.Add(policy.ObservationFreshness.Duration()).After(now) || snapshot.CapturedAt.IsZero() || snapshot.CapturedAt.After(now) ||
		!snapshot.CapturedAt.Add(policy.ObservationFreshness.Duration()).After(now) {
		return nil, ErrPreflight
	}
	initial := &model.DomainState{Authority: authority.Clone(), Revision: 1, Phase: model.PhaseStable,
		StableOwner: owner.StableNodeID, LastTransitionAt: now, UpdatedAt: now}
	return initial, nil
}
