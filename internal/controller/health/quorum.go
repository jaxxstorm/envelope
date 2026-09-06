// Package health evaluates provider-independent controller health observations.
package health

import (
	"sort"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// Reason is a bounded, machine-readable explanation for a failed evaluation.
// Values contain no observation data or provider error text.
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonInvalidInput     Reason = "invalid-input"
	ReasonNoQuorum         Reason = "no-quorum"
	ReasonDisagreement     Reason = "disagreement"
	ReasonUnknownOwner     Reason = "unknown-owner"
	ReasonUnhealthyOwner   Reason = "unhealthy-owner"
	ReasonStaleObservation Reason = "stale-observation"
)

// QuorumPolicy defines which replicas may contribute and how recently they
// must have captured an observation.
type QuorumPolicy struct {
	AllowedControllerIDs []string
	Quorum               int
	Freshness            time.Duration
}

// Consensus is the agreed sole owner and the observations that established it.
// Owner is a stable Tailnet node ID.
type Consensus struct {
	Owner                     string            `json:"owner"`
	ContributingControllerIDs []string          `json:"contributing_controller_ids"`
	OldestObservationAt       time.Time         `json:"oldest_observation_at"`
	NewestObservationAt       time.Time         `json:"newest_observation_at"`
	ContinuousSince           time.Time         `json:"continuous_since"`
	OwnerChangeGenerations    map[string]uint64 `json:"owner_change_generations"`
}

// StableFor reports whether the quorum's current agreement is proven to have
// remained uninterrupted for window at now.
func (c *Consensus) StableFor(now time.Time, window time.Duration) bool {
	if c == nil || now.IsZero() || window <= 0 || c.ContinuousSince.IsZero() || c.ContinuousSince.After(now) {
		return false
	}
	return now.Sub(c.ContinuousSince) >= window
}

// Result contains either Consensus or a non-empty Reason.
type Result struct {
	Consensus *Consensus `json:"consensus,omitempty"`
	Reason    Reason     `json:"reason,omitempty"`
}

type assessedObservation struct {
	controllerID          string
	owner                 string
	capturedAt            time.Time
	ownerSince            time.Time
	ownerChangeGeneration uint64
	solePrimary           bool
	ownerHealthy          bool
}

// Evaluate deterministically evaluates observations for one domain at now.
// Duplicate records for an allowed controller disqualify that controller, so
// one identity can never contribute more than one quorum vote.
func Evaluate(now time.Time, authority model.DomainAuthority, observations []model.Observation, policy QuorumPolicy) Result {
	allowed, valid := validateInputs(now, authority, policy)
	if !valid {
		return failed(ReasonInvalidInput)
	}

	byController := make(map[string][]int, len(allowed))
	for index := range observations {
		controllerID := observations[index].ControllerID
		if _, ok := allowed[controllerID]; ok {
			byController[controllerID] = append(byController[controllerID], index)
		}
	}

	fresh := make([]assessedObservation, 0, len(allowed))
	stale := 0
	oldestAllowed := now.Add(-policy.Freshness)
	for controllerID, indexes := range byController {
		if len(indexes) != 1 {
			continue
		}

		observation := observations[indexes[0]]
		if observation.TopologyHash != authority.TopologyHash || !observation.BackendHealthy || observation.Sequence == 0 {
			continue
		}
		if observation.CapturedAt.IsZero() || observation.ExpiresAt.IsZero() || !observation.ExpiresAt.After(observation.CapturedAt) {
			continue
		}
		domain, ok := observation.Domains[authority.DomainID]
		if !ok || domain.Validate() != nil || domain.OwnerChangeGeneration > observation.Sequence {
			continue
		}
		if observation.CapturedAt.After(now) || observation.CapturedAt.Before(oldestAllowed) || !observation.ExpiresAt.After(now) {
			stale++
			continue
		}

		ownerSince := observation.CapturedAt
		ownerGeneration := observation.Sequence
		if domain.Healthy && (domain.OwnerSince != nil || domain.OwnerChangeGeneration != 0) {
			if domain.OwnerSince == nil || domain.OwnerChangeGeneration == 0 || domain.OwnerSince.After(observation.CapturedAt) {
				continue
			}
			if domain.OwnerChangeGeneration == observation.Sequence && !domain.OwnerSince.Equal(observation.CapturedAt) {
				continue
			}
			ownerSince = *domain.OwnerSince
			ownerGeneration = domain.OwnerChangeGeneration
		}

		solePrimary := domain.SolePrimary && domain.StableNodeID != ""
		fresh = append(fresh, assessedObservation{
			controllerID:          controllerID,
			owner:                 domain.StableNodeID,
			capturedAt:            observation.CapturedAt,
			ownerSince:            ownerSince,
			ownerChangeGeneration: ownerGeneration,
			solePrimary:           solePrimary,
			ownerHealthy: solePrimary && domain.Online && !domain.Expired && domain.Healthy &&
				hasExactPrefix(domain.AdvertisedPrefixes, authority.SourcePrefix) &&
				hasExactPrefix(domain.EnabledPrefixes, authority.SourcePrefix),
		})
	}

	if len(fresh) < policy.Quorum {
		if stale > 0 && len(fresh)+stale >= policy.Quorum {
			return failed(ReasonStaleObservation)
		}
		return failed(ReasonNoQuorum)
	}

	owner := ""
	for _, observation := range fresh {
		if !observation.solePrimary {
			return failed(ReasonDisagreement)
		}
		if owner == "" {
			owner = observation.owner
			continue
		}
		if observation.owner != owner {
			return failed(ReasonDisagreement)
		}
	}
	if _, ok := authority.OwnerByStableNode(owner); !ok {
		return failed(ReasonUnknownOwner)
	}

	contributors := make([]string, 0, len(fresh))
	continuous := make([]assessedObservation, 0, len(fresh))
	generations := make(map[string]uint64, len(fresh))
	var oldest, newest time.Time
	for _, observation := range fresh {
		if !observation.ownerHealthy {
			continue
		}
		contributors = append(contributors, observation.controllerID)
		continuous = append(continuous, observation)
		generations[observation.controllerID] = observation.ownerChangeGeneration
		if oldest.IsZero() || observation.capturedAt.Before(oldest) {
			oldest = observation.capturedAt
		}
		if newest.IsZero() || observation.capturedAt.After(newest) {
			newest = observation.capturedAt
		}
	}
	if len(contributors) < policy.Quorum {
		return failed(ReasonUnhealthyOwner)
	}

	sort.Strings(contributors)
	sort.Slice(continuous, func(i, j int) bool {
		if continuous[i].ownerSince.Equal(continuous[j].ownerSince) {
			return continuous[i].controllerID < continuous[j].controllerID
		}
		return continuous[i].ownerSince.Before(continuous[j].ownerSince)
	})
	// The quorum-th oldest start is the earliest point at which at least a
	// complete quorum of the current healthy observations overlaps.
	return Result{Consensus: &Consensus{
		Owner:                     owner,
		ContributingControllerIDs: contributors,
		OldestObservationAt:       oldest,
		NewestObservationAt:       newest,
		ContinuousSince:           continuous[policy.Quorum-1].ownerSince,
		OwnerChangeGenerations:    generations,
	}}
}

func validateInputs(now time.Time, authority model.DomainAuthority, policy QuorumPolicy) (map[string]struct{}, bool) {
	if now.IsZero() || policy.Freshness <= 0 || policy.Quorum <= 0 || authority.Validate() != nil {
		return nil, false
	}
	allowed := make(map[string]struct{}, len(policy.AllowedControllerIDs))
	for _, controllerID := range policy.AllowedControllerIDs {
		if controllerID == "" {
			return nil, false
		}
		if _, exists := allowed[controllerID]; exists {
			return nil, false
		}
		allowed[controllerID] = struct{}{}
	}
	if policy.Quorum > len(allowed) {
		return nil, false
	}
	return allowed, true
}

func hasExactPrefix(prefixes []string, expected string) bool {
	matches := 0
	for _, prefix := range prefixes {
		if prefix == expected {
			matches++
		}
	}
	return matches == 1
}

func failed(reason Reason) Result {
	return Result{Reason: reason}
}
