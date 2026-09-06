package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

type DeploymentStore interface {
	InitialStore
	BeginDeployment(context.Context, store.DeploymentLock) error
	ReadDeployment(context.Context, string) (store.DeploymentLock, error)
	AdvanceDeployment(context.Context, store.DeploymentLock, store.DeploymentLock) error
	RewriteDeploymentDomains(context.Context, store.DeploymentLock, []*model.DomainState, []*model.DomainState) error
}

// Deployment has no route mutation interface. External rollout is explicitly
// passed only to Rollout; state operations never execute deployment commands.
type Deployment struct {
	Topology   *config.Topology
	Store      DeploymentStore
	Cloud      map[string]Inspector
	Forwarding Forwarding
	Clock      store.Clock
}

func (d Deployment) validate() error {
	if d.Topology == nil || d.Topology.Validate() != nil || len(d.Topology.Domains) > 32 || d.Store == nil || d.Clock == nil || d.Forwarding == nil {
		return ErrPreflight
	}
	if d.Topology.Policy.LeaseDuration.Duration()+d.Topology.Policy.APITimeout.Duration()+d.Topology.Policy.RouteConvergenceTimeout.Duration() >= 12*time.Minute {
		return ErrPreflight
	}
	for _, site := range d.Topology.Sites {
		if d.Cloud[site.Region] == nil {
			return ErrPreflight
		}
	}
	return nil
}

func (d Deployment) begin(ctx context.Context, operation, kind, replica string) (store.DeploymentLock, error) {
	if d.validate() != nil {
		return store.DeploymentLock{}, ErrPreflight
	}
	hash, err := d.Topology.Hash()
	if err != nil {
		return store.DeploymentLock{}, err
	}
	lock := store.DeploymentLock{DeploymentID: d.Topology.DeploymentID, TopologyHash: hash, OperationID: operation, Kind: kind, Phase: "locked", ReplicaID: replica}
	if err := d.Store.BeginDeployment(ctx, lock); err != nil {
		return lock, err
	}
	return lock, nil
}

func (d Deployment) advance(ctx context.Context, lock *store.DeploymentLock, phase string) error {
	next := *lock
	next.Phase = phase
	if err := d.Store.AdvanceDeployment(ctx, *lock, next); err != nil {
		return err
	}
	*lock = next
	return nil
}

func (d Deployment) states(ctx context.Context) ([]*model.DomainState, error) {
	states := make([]*model.DomainState, 0, len(d.Topology.Domains))
	for _, domain := range d.Topology.Domains {
		authority, err := d.Topology.DomainAuthority(domain.ID)
		if err != nil {
			return nil, ErrPreflight
		}
		state, err := d.Store.LoadDomain(ctx, store.DomainRefFor(authority))
		if err != nil || state == nil || state.Validate() != nil || !reflect.DeepEqual(state.Authority, authority) {
			return nil, ErrPreflight
		}
		states = append(states, state)
	}
	return states, nil
}

func (d Deployment) agreement(ctx context.Context, topology *config.Topology, domain string) (*model.DomainState, error) {
	authority, err := topology.DomainAuthority(domain)
	if err != nil {
		return nil, ErrPreflight
	}
	return CheckAgreement(ctx, topology, domain, d.Store, d.Cloud[authority.Region], d.Forwarding, d.Clock)
}

func (d Deployment) Activate(ctx context.Context, operation, domain string) error {
	if d.validate() != nil {
		return ErrPreflight
	}
	authority, err := d.Topology.DomainAuthority(domain)
	if err != nil {
		return ErrPreflight
	}
	lock, err := d.begin(ctx, operation, "activate", "")
	if err != nil {
		return err
	}
	old, err := d.Store.LoadDomain(ctx, store.DomainRefFor(authority))
	if err != nil || old == nil || old.Validate() != nil || old.Activated || old.Phase != model.PhaseStable || (old.Lease != nil && old.Lease.ExpiresAt.After(d.Clock.Now())) {
		return ErrPreflight
	}
	agreement, err := d.agreement(ctx, d.Topology, domain)
	if err != nil || agreement.StableOwner != old.StableOwner || !reflect.DeepEqual(old.Authority, agreement.Authority) {
		return ErrPreflight
	}
	next := old.Clone()
	next.Activated, next.UpdatedAt = true, d.Clock.Now()
	next.Lease = nil
	if err := d.Store.RewriteDeploymentDomains(ctx, lock, []*model.DomainState{old}, []*model.DomainState{next}); err != nil {
		return err
	}
	return d.advance(ctx, &lock, "complete")
}

// quiesce never discards in-progress intent. Inactive gates stop future lease
// acquisitions; the full lease/action bound drains already-started operations.
func (d Deployment) quiesce(ctx context.Context, lock *store.DeploymentLock) ([]*model.DomainState, error) {
	before, err := d.states(ctx)
	if err != nil {
		return nil, err
	}
	after := make([]*model.DomainState, len(before))
	for i, old := range before {
		after[i] = old.Clone()
		after[i].Activated = false
		after[i].UpdatedAt = d.Clock.Now()
	}
	// In the locked migration phase the store permits only deactivation, never
	// authority replacement. Authority changes require the quiescent phase.
	if err := d.Store.RewriteDeploymentDomains(ctx, *lock, before, after); err != nil {
		return nil, err
	}
	first, err := d.states(ctx)
	if err != nil {
		return nil, err
	}
	bound := d.Topology.Policy.LeaseDuration.Duration() + d.Topology.Policy.APITimeout.Duration() + d.Topology.Policy.RouteConvergenceTimeout.Duration()
	var second []*model.DomainState
	for {
		if err := store.Wait(ctx, d.Clock, bound); err != nil {
			return nil, err
		}
		second, err = d.states(ctx)
		if err != nil {
			return nil, err
		}
		if reflect.DeepEqual(first, second) {
			break
		}
		first = second
	}
	for _, state := range second {
		if state.Activated || state.Phase != model.PhaseStable || state.Intent != nil || state.Error != nil || (state.Lease != nil && state.Lease.ExpiresAt.After(d.Clock.Now())) {
			return nil, errors.New("journal requires recovery before migration; lock retained")
		}
	}
	if err := d.advance(ctx, lock, "quiescent"); err != nil {
		return nil, err
	}
	return second, nil
}

func (d Deployment) Deactivate(ctx context.Context, operation string) error {
	lock, err := d.begin(ctx, operation, "deactivate", "")
	if err != nil {
		return err
	}
	if _, err := d.quiesce(ctx, &lock); err != nil {
		return err
	}
	return d.advance(ctx, &lock, "complete")
}

// Migrate updates the complete existing domain set atomically. It intentionally
// rejects regional table moves and domain additions/removals instead of losing
// records. Both old and new observers must publish independently bound evidence.
func (d Deployment) Migrate(ctx context.Context, operation string, next *config.Topology, nextForwarding Forwarding) error {
	if d.validate() != nil || next == nil || next.Validate() != nil || nextForwarding == nil || next.DeploymentID != d.Topology.DeploymentID || next.DynamoDB != d.Topology.DynamoDB || len(next.Domains) != len(d.Topology.Domains) {
		return ErrPreflight
	}
	oldHash, _ := d.Topology.Hash()
	newHash, _ := next.Hash()
	if oldHash == newHash {
		return ErrPreflight
	}
	for _, domain := range d.Topology.Domains {
		if _, err := next.DomainAuthority(domain.ID); err != nil {
			return ErrPreflight
		}
	}
	for _, site := range next.Sites {
		if d.Cloud[site.Region] == nil {
			return ErrPreflight
		}
	}
	lock, err := d.begin(ctx, operation, "migrate", "")
	if err != nil {
		return err
	}
	before, err := d.quiesce(ctx, &lock)
	if err != nil {
		return err
	}
	after := make([]*model.DomainState, len(before))
	for i, old := range before {
		oldAgreement, err := d.agreement(ctx, d.Topology, old.Authority.DomainID)
		if err != nil || oldAgreement.StableOwner != old.StableOwner {
			return ErrPreflight
		}
		newDeployment := d
		newDeployment.Forwarding = nextForwarding
		newAgreement, err := newDeployment.agreement(ctx, next, old.Authority.DomainID)
		if err != nil {
			return err
		}
		newAgreement.Revision, newAgreement.FenceTerm = old.Revision, old.FenceTerm
		newAgreement.CooldownUntil = old.CooldownUntil
		after[i] = newAgreement
	}
	if err := d.Store.RewriteDeploymentDomains(ctx, lock, before, after); err != nil {
		return err
	}
	return d.advance(ctx, &lock, "complete")
}

type RolloutAction interface {
	Validate(context.Context) error
	Apply(context.Context) error
	Healthy(context.Context, time.Time) error
}

// Rollout holds its durable lock through both health gates and the complete
// external action. Never defer unlock: any failure retains exclusion.
func (d Deployment) Rollout(ctx context.Context, operation, replica string, action RolloutAction) error {
	if d.validate() != nil || !d.Topology.HasControllerID(replica) || action == nil {
		return ErrPreflight
	}
	if err := action.Validate(ctx); err != nil {
		return err
	}
	lock, err := d.begin(ctx, operation, "rollout", replica)
	if err != nil {
		return err
	}
	if err := action.Healthy(ctx, time.Time{}); err != nil {
		return err
	}
	states, err := d.states(ctx)
	if err != nil {
		return err
	}
	for _, state := range states {
		agreement, err := d.agreement(ctx, d.Topology, state.Authority.DomainID)
		if err != nil || state.Phase != model.PhaseStable || agreement.StableOwner != state.StableOwner || (state.Activated && (state.Lease == nil || !state.Lease.ExpiresAt.After(d.Clock.Now().Add(d.Topology.Policy.LeaseDangerWindow.Duration())))) {
			return ErrPreflight
		}
	}
	if err := d.advance(ctx, &lock, "applying"); err != nil {
		return err
	}
	started := d.Clock.Now()
	if err := action.Apply(ctx); err != nil {
		return err
	}
	if err := action.Healthy(ctx, started); err != nil {
		return err
	}
	states, err = d.states(ctx)
	if err != nil {
		return err
	}
	for _, state := range states {
		agreement, err := d.agreement(ctx, d.Topology, state.Authority.DomainID)
		if err != nil || state.Phase != model.PhaseStable || agreement.StableOwner != state.StableOwner || (state.Activated && (state.Lease == nil || !state.Lease.ExpiresAt.After(d.Clock.Now().Add(d.Topology.Policy.LeaseDangerWindow.Duration())))) {
			return ErrPreflight
		}
	}
	if err := d.advance(ctx, &lock, "verified"); err != nil {
		return err
	}
	return d.advance(ctx, &lock, "complete")
}
