package health

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

var quorumTestTime = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

func TestEvaluate(t *testing.T) {
	policy := QuorumPolicy{
		AllowedControllerIDs: []string{"controller-a", "controller-b", "controller-c"},
		Quorum:               2,
		Freshness:            30 * time.Second,
	}
	wrongHash := strings.Repeat("b", 64)

	tests := []struct {
		name            string
		observations    []model.Observation
		previous        []model.Observation
		wantReason      Reason
		wantOwner       string
		wantControllers []string
		wantOldest      time.Time
		wantNewest      time.Time
		wantContinuous  time.Time
	}{
		{
			name: "sole owner",
			observations: []model.Observation{
				testObservation("controller-c", "node-a", quorumTestTime.Add(-2*time.Second)),
				testObservation("controller-a", "node-a", quorumTestTime.Add(-4*time.Second)),
				testObservation("controller-b", "node-a", quorumTestTime.Add(-3*time.Second)),
			},
			wantOwner:       "node-a",
			wantControllers: []string{"controller-a", "controller-b", "controller-c"},
			wantOldest:      quorumTestTime.Add(-4 * time.Second),
			wantNewest:      quorumTestTime.Add(-2 * time.Second),
			wantContinuous:  quorumTestTime.Add(-3 * time.Second),
		},
		{
			name: "offline owner",
			observations: mutateOwner(
				testObservations("node-a", "controller-a", "controller-b"),
				func(owner *model.OwnerObservation) {
					owner.Online = false
					owner.Healthy = false
				},
			),
			wantReason: ReasonUnhealthyOwner,
		},
		{
			name:         "unknown owner",
			observations: testObservations("node-unknown", "controller-a", "controller-b"),
			wantReason:   ReasonUnknownOwner,
		},
		{
			name: "stale observations",
			observations: []model.Observation{
				testObservation("controller-a", "node-a", quorumTestTime.Add(-31*time.Second)),
				testObservation("controller-b", "node-a", quorumTestTime.Add(-time.Minute)),
			},
			wantReason: ReasonStaleObservation,
		},
		{
			name: "duplicate controller",
			observations: []model.Observation{
				testObservation("controller-a", "node-a", quorumTestTime.Add(-2*time.Second)),
				testObservation("controller-a", "node-a", quorumTestTime.Add(-time.Second)),
			},
			wantReason: ReasonNoQuorum,
		},
		{
			name: "split observations",
			observations: []model.Observation{
				testObservation("controller-a", "node-a", quorumTestTime.Add(-2*time.Second)),
				testObservation("controller-b", "node-b", quorumTestTime.Add(-time.Second)),
			},
			wantReason: ReasonDisagreement,
		},
		{
			name: "wrong topology",
			observations: mutateObservations(
				testObservations("node-a", "controller-a", "controller-b"),
				func(observation *model.Observation) { observation.TopologyHash = wrongHash },
			),
			wantReason: ReasonNoQuorum,
		},
		{
			name:         "automatic return to preferred owner",
			previous:     testObservations("node-b", "controller-a", "controller-b"),
			observations: testObservations("node-a", "controller-a", "controller-b"),
			wantOwner:    "node-a",
			wantControllers: []string{
				"controller-a",
				"controller-b",
			},
			wantOldest:     quorumTestTime.Add(-2 * time.Second),
			wantNewest:     quorumTestTime.Add(-time.Second),
			wantContinuous: quorumTestTime.Add(-time.Second),
		},
		{
			name: "unallowed controllers",
			observations: []model.Observation{
				testObservation("controller-a", "node-a", quorumTestTime.Add(-time.Second)),
				testObservation("controller-x", "node-a", quorumTestTime.Add(-time.Second)),
			},
			wantReason: ReasonNoQuorum,
		},
		{
			name: "unhealthy backend",
			observations: mutateObservations(
				testObservations("node-a", "controller-a", "controller-b"),
				func(observation *model.Observation) { observation.BackendHealthy = false },
			),
			wantReason: ReasonNoQuorum,
		},
		{
			name: "future capture",
			observations: []model.Observation{
				testObservation("controller-a", "node-a", quorumTestTime.Add(time.Second)),
				testObservation("controller-b", "node-a", quorumTestTime.Add(2*time.Second)),
			},
			wantReason: ReasonStaleObservation,
		},
		{
			name: "expired observations",
			observations: mutateObservations(
				testObservations("node-a", "controller-a", "controller-b"),
				func(observation *model.Observation) { observation.ExpiresAt = quorumTestTime },
			),
			wantReason: ReasonStaleObservation,
		},
		{
			name: "no sole primary",
			observations: mutateOwner(
				testObservations("node-a", "controller-a", "controller-b"),
				func(owner *model.OwnerObservation) { owner.SolePrimary = false },
			),
			wantReason: ReasonDisagreement,
		},
		{
			name: "source prefix not advertised",
			observations: mutateOwner(
				testObservations("node-a", "controller-a", "controller-b"),
				func(owner *model.OwnerObservation) {
					owner.AdvertisedPrefixes = []string{"10.0.1.0/24"}
					owner.EnabledPrefixes = []string{"10.0.1.0/24"}
				},
			),
			wantReason: ReasonUnhealthyOwner,
		},
		{
			name: "source prefix not enabled",
			observations: mutateOwner(
				testObservations("node-a", "controller-a", "controller-b"),
				func(owner *model.OwnerObservation) {
					owner.AdvertisedPrefixes = []string{"10.0.0.0/24", "10.0.1.0/24"}
					owner.EnabledPrefixes = []string{"10.0.1.0/24"}
				},
			),
			wantReason: ReasonUnhealthyOwner,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.previous != nil {
				previous := Evaluate(quorumTestTime, testAuthority(), test.previous, policy)
				if previous.Consensus == nil || previous.Consensus.Owner != "node-b" {
					t.Fatalf("previous Evaluate() = %#v, want node-b consensus", previous)
				}
			}

			got := Evaluate(quorumTestTime, testAuthority(), test.observations, policy)
			if got.Reason != test.wantReason {
				t.Fatalf("Evaluate() reason = %q, want %q", got.Reason, test.wantReason)
			}
			if test.wantOwner == "" {
				if got.Consensus != nil {
					t.Fatalf("Evaluate() consensus = %#v, want nil", got.Consensus)
				}
				return
			}
			if got.Consensus == nil {
				t.Fatalf("Evaluate() consensus = nil, reason %q", got.Reason)
			}
			if got.Consensus.Owner != test.wantOwner {
				t.Errorf("Evaluate() owner = %q, want %q", got.Consensus.Owner, test.wantOwner)
			}
			if !reflect.DeepEqual(got.Consensus.ContributingControllerIDs, test.wantControllers) {
				t.Errorf("Evaluate() controllers = %v, want %v", got.Consensus.ContributingControllerIDs, test.wantControllers)
			}
			if !got.Consensus.OldestObservationAt.Equal(test.wantOldest) {
				t.Errorf("Evaluate() oldest = %s, want %s", got.Consensus.OldestObservationAt, test.wantOldest)
			}
			if !got.Consensus.NewestObservationAt.Equal(test.wantNewest) {
				t.Errorf("Evaluate() newest = %s, want %s", got.Consensus.NewestObservationAt, test.wantNewest)
			}
			if !got.Consensus.ContinuousSince.Equal(test.wantContinuous) {
				t.Errorf("Evaluate() continuous since = %s, want %s", got.Consensus.ContinuousSince, test.wantContinuous)
			}
		})
	}
}

func TestEvaluateOverwrittenOwnershipFlapDoesNotSatisfyStability(t *testing.T) {
	policy := QuorumPolicy{
		AllowedControllerIDs: []string{"controller-a", "controller-b", "controller-c"},
		Quorum:               2,
		Freshness:            time.Minute,
	}
	candidateAt := quorumTestTime.Add(-20 * time.Second)
	first := testObservations("node-b", "controller-a", "controller-b")
	for index := range first {
		first[index].Sequence = 10
		first[index].CapturedAt = candidateAt
		owner := first[index].Domains["domain-a"]
		owner.OwnerSince = timePointer(candidateAt)
		owner.OwnerChangeGeneration = 10
		first[index].Domains["domain-a"] = owner
	}
	initial := Evaluate(candidateAt, testAuthority(), first, policy)
	if initial.Consensus == nil || initial.Consensus.Owner != "node-b" {
		t.Fatalf("initial Evaluate() = %#v, want node-b consensus", initial)
	}

	// The intervening node-a records have been overwritten by newer node-b
	// records. Their generation and owner-since values still preserve the flap.
	latest := testObservations("node-b", "controller-a", "controller-b")
	flappedAt := quorumTestTime.Add(-5 * time.Second)
	for index := range latest {
		latest[index].Sequence = 13
		latest[index].CapturedAt = quorumTestTime.Add(-time.Second)
		owner := latest[index].Domains["domain-a"]
		owner.OwnerSince = timePointer(flappedAt)
		owner.OwnerChangeGeneration = 12
		latest[index].Domains["domain-a"] = owner
	}
	result := Evaluate(quorumTestTime, testAuthority(), latest, policy)
	if result.Consensus == nil || result.Consensus.Owner != "node-b" {
		t.Fatalf("latest Evaluate() = %#v, want node-b consensus", result)
	}
	if !result.Consensus.ContinuousSince.Equal(flappedAt) {
		t.Fatalf("continuous since = %s, want post-flap %s", result.Consensus.ContinuousSince, flappedAt)
	}
	if result.Consensus.StableFor(quorumTestTime, 10*time.Second) {
		t.Fatal("overwritten B -> A -> B flap satisfied the uninterrupted stability window")
	}
	if !reflect.DeepEqual(result.Consensus.OwnerChangeGenerations, map[string]uint64{"controller-a": 12, "controller-b": 12}) {
		t.Fatalf("owner generations = %v", result.Consensus.OwnerChangeGenerations)
	}
}

func TestEvaluateUsesOldestProvableContinuousQuorum(t *testing.T) {
	policy := QuorumPolicy{
		AllowedControllerIDs: []string{"controller-a", "controller-b", "controller-c"},
		Quorum:               2,
		Freshness:            time.Minute,
	}
	observations := testObservations("node-a", "controller-a", "controller-b", "controller-c")
	ownerSince := []time.Time{
		quorumTestTime.Add(-20 * time.Second),
		quorumTestTime.Add(-10 * time.Second),
		quorumTestTime.Add(-2 * time.Second),
	}
	for index := range observations {
		observations[index].Sequence = uint64(20 + index)
		owner := observations[index].Domains["domain-a"]
		owner.OwnerSince = timePointer(ownerSince[index])
		owner.OwnerChangeGeneration = uint64(5 + index)
		observations[index].Domains["domain-a"] = owner
	}

	result := Evaluate(quorumTestTime, testAuthority(), observations, policy)
	if result.Consensus == nil {
		t.Fatalf("Evaluate() = %#v, want consensus", result)
	}
	if !result.Consensus.ContinuousSince.Equal(ownerSince[1]) {
		t.Fatalf("continuous since = %s, want second-oldest quorum boundary %s", result.Consensus.ContinuousSince, ownerSince[1])
	}
	if !result.Consensus.StableFor(quorumTestTime, 10*time.Second) {
		t.Fatal("continuous quorum did not satisfy its exact stability boundary")
	}
	if result.Consensus.StableFor(quorumTestTime, 10*time.Second+time.Nanosecond) || result.Consensus.StableFor(time.Time{}, time.Second) || result.Consensus.StableFor(quorumTestTime, 0) {
		t.Fatal("StableFor accepted an unproven or invalid window")
	}
}

func TestEvaluateRejectsMalformedOwnerContinuity(t *testing.T) {
	policy := QuorumPolicy{
		AllowedControllerIDs: []string{"controller-a", "controller-b"},
		Quorum:               2,
		Freshness:            time.Minute,
	}
	tests := []struct {
		name   string
		mutate func(*model.Observation, *model.OwnerObservation)
	}{
		{name: "missing owner since", mutate: func(_ *model.Observation, owner *model.OwnerObservation) {
			owner.OwnerChangeGeneration = 1
		}},
		{name: "owner since after capture", mutate: func(observation *model.Observation, owner *model.OwnerObservation) {
			owner.OwnerSince = timePointer(observation.CapturedAt.Add(time.Second))
			owner.OwnerChangeGeneration = 1
		}},
		{name: "generation after sequence", mutate: func(observation *model.Observation, owner *model.OwnerObservation) {
			owner.OwnerSince = timePointer(observation.CapturedAt)
			owner.OwnerChangeGeneration = observation.Sequence + 1
		}},
		{name: "current generation has old start", mutate: func(observation *model.Observation, owner *model.OwnerObservation) {
			owner.OwnerSince = timePointer(observation.CapturedAt.Add(-time.Second))
			owner.OwnerChangeGeneration = observation.Sequence
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observations := testObservations("node-a", "controller-a", "controller-b")
			for index := range observations {
				owner := observations[index].Domains["domain-a"]
				test.mutate(&observations[index], &owner)
				observations[index].Domains["domain-a"] = owner
			}
			result := Evaluate(quorumTestTime, testAuthority(), observations, policy)
			if result.Consensus != nil || result.Reason != ReasonNoQuorum {
				t.Fatalf("Evaluate() = %#v, want malformed continuity excluded", result)
			}
		})
	}
}

func TestEvaluateInvalidInput(t *testing.T) {
	validPolicy := QuorumPolicy{
		AllowedControllerIDs: []string{"controller-a", "controller-b"},
		Quorum:               2,
		Freshness:            30 * time.Second,
	}
	tests := []struct {
		name      string
		now       time.Time
		authority model.DomainAuthority
		policy    QuorumPolicy
	}{
		{name: "zero time", authority: testAuthority(), policy: validPolicy},
		{name: "invalid authority", now: quorumTestTime, authority: model.DomainAuthority{}, policy: validPolicy},
		{name: "no allowed controllers", now: quorumTestTime, authority: testAuthority(), policy: QuorumPolicy{Quorum: 1, Freshness: time.Second}},
		{name: "duplicate allowed controller", now: quorumTestTime, authority: testAuthority(), policy: QuorumPolicy{AllowedControllerIDs: []string{"controller-a", "controller-a"}, Quorum: 1, Freshness: time.Second}},
		{name: "quorum exceeds controllers", now: quorumTestTime, authority: testAuthority(), policy: QuorumPolicy{AllowedControllerIDs: []string{"controller-a"}, Quorum: 2, Freshness: time.Second}},
		{name: "zero quorum", now: quorumTestTime, authority: testAuthority(), policy: QuorumPolicy{AllowedControllerIDs: []string{"controller-a"}, Freshness: time.Second}},
		{name: "zero freshness", now: quorumTestTime, authority: testAuthority(), policy: QuorumPolicy{AllowedControllerIDs: []string{"controller-a"}, Quorum: 1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Evaluate(test.now, test.authority, nil, test.policy)
			if got.Consensus != nil || got.Reason != ReasonInvalidInput {
				t.Fatalf("Evaluate() = %#v, want invalid input", got)
			}
		})
	}
}

func testAuthority() model.DomainAuthority {
	return model.DomainAuthority{
		TopologyHash:            strings.Repeat("a", 64),
		DeploymentID:            "deployment-a",
		DomainID:                "domain-a",
		SiteID:                  "site-a",
		VPCID:                   "vpc-a",
		Region:                  "us-west-2",
		SourcePrefix:            "10.0.0.0/24",
		RouteTableID:            "rtb-a",
		GWLBESubnetID:           "subnet-gwlbe-a",
		RouteTableAssociationID: "rtbassoc-gwlbe-a",
		RemotePrefixes:          []string{"10.1.0.0/24"},
		PreferredOwner:          "node-a",
		Owners: []model.OwnerAuthority{
			{RouterID: "router-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{RouterID: "router-b", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
		},
	}
}

func testObservations(owner string, controllerIDs ...string) []model.Observation {
	observations := make([]model.Observation, len(controllerIDs))
	for index, controllerID := range controllerIDs {
		observations[index] = testObservation(controllerID, owner, quorumTestTime.Add(-time.Duration(len(controllerIDs)-index)*time.Second))
	}
	return observations
}

func testObservation(controllerID, owner string, capturedAt time.Time) model.Observation {
	return model.Observation{
		ControllerID:   controllerID,
		TopologyHash:   strings.Repeat("a", 64),
		Sequence:       1,
		CapturedAt:     capturedAt,
		ExpiresAt:      quorumTestTime.Add(time.Minute),
		BackendHealthy: true,
		Domains: map[string]model.OwnerObservation{
			"domain-a": {
				StableNodeID:       owner,
				SolePrimary:        true,
				Online:             true,
				Healthy:            true,
				AdvertisedPrefixes: []string{"10.0.0.0/24"},
				EnabledPrefixes:    []string{"10.0.0.0/24"},
			},
		},
	}
}

func mutateObservations(observations []model.Observation, mutate func(*model.Observation)) []model.Observation {
	for index := range observations {
		mutate(&observations[index])
	}
	return observations
}

func mutateOwner(observations []model.Observation, mutate func(*model.OwnerObservation)) []model.Observation {
	for index := range observations {
		owner := observations[index].Domains["domain-a"]
		mutate(&owner)
		observations[index].Domains["domain-a"] = owner
	}
	return observations
}

func timePointer(value time.Time) *time.Time {
	return &value
}
