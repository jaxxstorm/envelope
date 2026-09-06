package model

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

func TestPhaseValidation(t *testing.T) {
	tests := []struct {
		phase Phase
		valid bool
	}{
		{phase: PhaseStable, valid: true},
		{phase: PhaseOwnerObserved, valid: true},
		{phase: PhaseRouteIntentPersisted, valid: true},
		{phase: PhaseRoutesConverging, valid: true},
		{phase: PhaseDegraded, valid: true},
		{phase: ""},
		{phase: "unknown"},
	}
	for _, test := range tests {
		t.Run(string(test.phase), func(t *testing.T) {
			err := test.phase.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestDomainAuthorityValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DomainAuthority)
		wantErr string
	}{
		{name: "valid", mutate: func(*DomainAuthority) {}},
		{name: "bad hash", mutate: func(authority *DomainAuthority) { authority.TopologyHash = "hash" }, wantErr: "topology hash"},
		{name: "missing GWLBE subnet", mutate: func(authority *DomainAuthority) { authority.GWLBESubnetID = "" }, wantErr: "GWLBE subnet ID"},
		{name: "missing route table association", mutate: func(authority *DomainAuthority) { authority.RouteTableAssociationID = "" }, wantErr: "route table association ID"},
		{name: "noncanonical source", mutate: func(authority *DomainAuthority) { authority.SourcePrefix = "10.0.0.1/24" }, wantErr: "not canonical"},
		{name: "IPv6 remote", mutate: func(authority *DomainAuthority) { authority.RemotePrefixes[0] = "2001:db8::/64" }, wantErr: "not IPv4"},
		{name: "overlapping remote", mutate: func(authority *DomainAuthority) { authority.RemotePrefixes[1] = "10.1.0.0/25" }, wantErr: "overlaps"},
		{name: "duplicate remote", mutate: func(authority *DomainAuthority) { authority.RemotePrefixes[1] = authority.RemotePrefixes[0] }, wantErr: "duplicate remote"},
		{name: "one owner", mutate: func(authority *DomainAuthority) { authority.Owners = authority.Owners[:1] }, wantErr: "at least two"},
		{name: "duplicate stable node", mutate: func(authority *DomainAuthority) { authority.Owners[1].StableNodeID = authority.Owners[0].StableNodeID }, wantErr: "duplicate owner stable node"},
		{name: "duplicate instance", mutate: func(authority *DomainAuthority) { authority.Owners[1].InstanceID = authority.Owners[0].InstanceID }, wantErr: "duplicate owner instance"},
		{name: "duplicate ENI", mutate: func(authority *DomainAuthority) { authority.Owners[1].ENIID = authority.Owners[0].ENIID }, wantErr: "duplicate owner ENI"},
		{name: "VPC mismatch", mutate: func(authority *DomainAuthority) { authority.Owners[0].VPCID = "vpc-other" }, wantErr: "does not match domain VPC"},
		{name: "region mismatch", mutate: func(authority *DomainAuthority) { authority.Owners[0].Region = "eu-west-1" }, wantErr: "does not match domain region"},
		{name: "AZ mismatch", mutate: func(authority *DomainAuthority) { authority.Owners[0].AvailabilityZone = "us-east-1a" }, wantErr: "does not belong to domain region"},
		{name: "same AZ", mutate: func(authority *DomainAuthority) {
			authority.Owners[1].AvailabilityZone = authority.Owners[0].AvailabilityZone
		}, wantErr: "availability zones"},
		{name: "unknown preferred", mutate: func(authority *DomainAuthority) { authority.PreferredOwner = "node-missing" }, wantErr: "not an authority owner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := validAuthority()
			test.mutate(&authority)
			err := authority.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if owner, found := authority.OwnerByStableNode("node-a"); !found || owner.ENIID != "eni-a" {
					t.Fatalf("OwnerByStableNode() = %#v, %t", owner, found)
				}
				if !authority.AllowsENI("eni-b") || authority.AllowsENI("eni-unknown") {
					t.Fatal("AllowsENI returned an incorrect result")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestLeaseValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Lease)
		wantErr string
	}{
		{name: "valid", mutate: func(*Lease) {}},
		{name: "holder", mutate: func(lease *Lease) { lease.HolderID = "" }, wantErr: "holder"},
		{name: "fence", mutate: func(lease *Lease) { lease.FenceTerm = 0 }, wantErr: "fence"},
		{name: "version", mutate: func(lease *Lease) { lease.RecordVersion = 0 }, wantErr: "record version"},
		{name: "renewal before acquisition", mutate: func(lease *Lease) { lease.RenewedAt = lease.AcquiredAt.Add(-time.Second) }, wantErr: "precedes acquisition"},
		{name: "expiry at renewal", mutate: func(lease *Lease) { lease.ExpiresAt = lease.RenewedAt }, wantErr: "expiry"},
		{name: "zero timestamp", mutate: func(lease *Lease) { lease.AcquiredAt = time.Time{} }, wantErr: "timestamps"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease := validLease()
			test.mutate(&lease)
			err := lease.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestRouteSnapshotValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RouteSnapshot)
		wantErr string
	}{
		{name: "valid", mutate: func(*RouteSnapshot) {}},
		{name: "wrong table", mutate: func(snapshot *RouteSnapshot) { snapshot.RouteTableID = "rtb-other" }, wantErr: "does not match"},
		{name: "missing route", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes = snapshot.Routes[:1] }, wantErr: "missing authoritative route"},
		{name: "duplicate route", mutate: func(snapshot *RouteSnapshot) {
			snapshot.Routes[1].DestinationPrefix = snapshot.Routes[0].DestinationPrefix
		}, wantErr: "duplicate snapshot"},
		{name: "unknown route", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes[0].DestinationPrefix = "192.0.2.0/24" }, wantErr: "outside domain authority"},
		{name: "noncanonical route", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes[0].DestinationPrefix = "10.1.0.1/24" }, wantErr: "not canonical"},
		{name: "unauthorized target", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes[0].TargetENIID = "eni-unknown" }, wantErr: "unauthorized ENI"},
		{name: "missing route state", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes[0].State = "" }, wantErr: "state is required"},
		{name: "missing origin", mutate: func(snapshot *RouteSnapshot) { snapshot.Routes[0].Origin = "" }, wantErr: "origin is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validSnapshot()
			test.mutate(&snapshot)
			err := snapshot.Validate(validAuthority())
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestRouteIntentValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RouteIntent)
		wantErr string
	}{
		{name: "pending", mutate: func(*RouteIntent) {}},
		{name: "first attempted", mutate: func(intent *RouteIntent) { intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute)) }},
		{name: "first completed", mutate: func(intent *RouteIntent) {
			intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
			intent.Progress[0].CompletedAt = timePtr(testTime.Add(6 * time.Minute))
			intent.Progress[0].ObservedENIID = "eni-b"
		}},
		{name: "unknown desired owner", mutate: func(intent *RouteIntent) { intent.DesiredOwner = "node-unknown" }, wantErr: "outside domain authority"},
		{name: "owner ENI mismatch", mutate: func(intent *RouteIntent) { intent.DesiredENIID = "eni-a" }, wantErr: "does not belong"},
		{name: "snapshot after intent", mutate: func(intent *RouteIntent) { intent.CreatedAt = intent.Before.CapturedAt.Add(-time.Second) }, wantErr: "precedes before snapshot"},
		{name: "wrong progress count", mutate: func(intent *RouteIntent) { intent.Progress = intent.Progress[:1] }, wantErr: "expected 2"},
		{name: "wrong progress order", mutate: func(intent *RouteIntent) {
			intent.Progress[0], intent.Progress[1] = intent.Progress[1], intent.Progress[0]
		}, wantErr: "ordered authority"},
		{name: "later route attempted first", mutate: func(intent *RouteIntent) { intent.Progress[1].AttemptedAt = timePtr(testTime.Add(5 * time.Minute)) }, wantErr: "before an earlier route completed"},
		{name: "completion after pending", mutate: func(intent *RouteIntent) {
			intent.Progress[1].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
			intent.Progress[1].CompletedAt = timePtr(testTime.Add(6 * time.Minute))
			intent.Progress[1].ObservedENIID = "eni-b"
		}, wantErr: "completed after an incomplete"},
		{name: "wrong completed ENI", mutate: func(intent *RouteIntent) {
			intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
			intent.Progress[0].CompletedAt = timePtr(testTime.Add(6 * time.Minute))
			intent.Progress[0].ObservedENIID = "eni-a"
		}, wantErr: "instead of desired ENI"},
		{name: "attempt before intent", mutate: func(intent *RouteIntent) {
			intent.Progress[0].AttemptedAt = timePtr(intent.CreatedAt.Add(-time.Second))
		}, wantErr: "attempt precedes intent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := validIntent()
			test.mutate(&intent)
			err := intent.Validate(validAuthority())
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestRouteProgressValidation(t *testing.T) {
	attempted := testTime
	completed := attempted.Add(time.Second)
	tests := []struct {
		name     string
		progress RouteProgress
		wantErr  string
	}{
		{name: "pending", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24"}},
		{name: "attempted ambiguous", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24", AttemptedAt: &attempted, Ambiguous: true, ObservedENIID: "eni-a"}},
		{name: "complete", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24", AttemptedAt: &attempted, CompletedAt: &completed, ObservedENIID: "eni-b"}},
		{name: "noncanonical", progress: RouteProgress{DestinationPrefix: "10.1.0.1/24"}, wantErr: "not canonical"},
		{name: "completion without attempt", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24", CompletedAt: &completed, ObservedENIID: "eni-b"}, wantErr: "was not attempted"},
		{name: "completion before attempt", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24", AttemptedAt: &completed, CompletedAt: &attempted, ObservedENIID: "eni-b"}, wantErr: "precedes attempt"},
		{name: "pending outcome", progress: RouteProgress{DestinationPrefix: "10.1.0.0/24", Ambiguous: true}, wantErr: "pending route"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.progress.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestObservationValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Observation)
		wantErr string
	}{
		{name: "valid", mutate: func(*Observation) {}},
		{name: "bad hash", mutate: func(observation *Observation) { observation.TopologyHash = "hash" }, wantErr: "topology hash"},
		{name: "zero sequence", mutate: func(observation *Observation) { observation.Sequence = 0 }, wantErr: "sequence"},
		{name: "expired at capture", mutate: func(observation *Observation) { observation.ExpiresAt = observation.CapturedAt }, wantErr: "expiry"},
		{name: "no domains", mutate: func(observation *Observation) { observation.Domains = nil }, wantErr: "domains"},
		{name: "sole owner missing identity", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.StableNodeID = ""
			observation.Domains["domain-a"] = domain
		}, wantErr: "stable node ID"},
		{name: "healthy offline owner", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.Online = false
			observation.Domains["domain-a"] = domain
		}, wantErr: "online and non-expired"},
		{name: "noncanonical advertised prefix", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.AdvertisedPrefixes[0] = "10.0.0.1/24"
			observation.Domains["domain-a"] = domain
		}, wantErr: "not canonical"},
		{name: "enabled but not advertised", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.EnabledPrefixes = []string{"10.0.1.0/24"}
			observation.Domains["domain-a"] = domain
		}, wantErr: "not advertised"},
		{name: "owner since without generation", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.OwnerChangeGeneration = 0
			observation.Domains["domain-a"] = domain
		}, wantErr: "positive owner change generation"},
		{name: "generation without owner since", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.OwnerSince = nil
			observation.Domains["domain-a"] = domain
		}, wantErr: "requires an owner since"},
		{name: "owner since after capture", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.OwnerSince = timePtr(observation.CapturedAt.Add(time.Second))
			observation.Domains["domain-a"] = domain
		}, wantErr: "follows observation capture"},
		{name: "owner generation after sequence", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.OwnerChangeGeneration = observation.Sequence + 1
			observation.Domains["domain-a"] = domain
		}, wantErr: "exceeds observation sequence"},
		{name: "current generation with old owner since", mutate: func(observation *Observation) {
			domain := observation.Domains["domain-a"]
			domain.OwnerSince = timePtr(observation.CapturedAt.Add(-time.Second))
			observation.Domains["domain-a"] = domain
		}, wantErr: "must begin at observation capture"},
		{name: "backend error required", mutate: func(observation *Observation) { observation.BackendHealthy = false }, wantErr: "requires an error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			test.mutate(&observation)
			err := observation.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestDomainStatePhases(t *testing.T) {
	tests := []struct {
		name  string
		state DomainState
	}{
		{name: "stable", state: validStableState()},
		{name: "owner observed", state: ownerObservedState()},
		{name: "intent persisted", state: intentState(PhaseRouteIntentPersisted)},
		{name: "routes converging pending", state: intentState(PhaseRoutesConverging)},
		{name: "routes converging progress", state: convergingState()},
		{name: "degraded without intent", state: degradedState(false)},
		{name: "degraded with intent", state: degradedState(true)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.state.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestDomainStateValidation(t *testing.T) {
	tests := []struct {
		name    string
		state   func() DomainState
		mutate  func(*DomainState)
		wantErr string
	}{
		{name: "zero revision", state: validStableState, mutate: func(state *DomainState) { state.Revision = 0 }, wantErr: "revision"},
		{name: "unknown stable owner", state: validStableState, mutate: func(state *DomainState) { state.StableOwner = "unknown" }, wantErr: "outside domain authority"},
		{name: "lease fence mismatch", state: validStableState, mutate: func(state *DomainState) { state.Lease.FenceTerm++ }, wantErr: "does not match state fence"},
		{name: "stable retains observation", state: validStableState, mutate: func(state *DomainState) { state.ObservedOwner = "node-b" }, wantErr: "stable phase"},
		{name: "owner observed missing timestamp", state: ownerObservedState, mutate: func(state *DomainState) { state.OwnerObservedAt = nil }, wantErr: "observation time"},
		{name: "intent phase missing intent", state: func() DomainState { return intentState(PhaseRouteIntentPersisted) }, mutate: func(state *DomainState) { state.Intent = nil }, wantErr: "requires owner observation and intent"},
		{name: "persisted phase attempted route", state: func() DomainState { return intentState(PhaseRouteIntentPersisted) }, mutate: func(state *DomainState) {
			state.Intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
		}, wantErr: "cannot contain attempted"},
		{name: "intent owner mismatch", state: func() DomainState { return intentState(PhaseRoutesConverging) }, mutate: func(state *DomainState) { state.ObservedOwner = "node-a" }, wantErr: "does not match observed owner"},
		{name: "intent from future fence", state: func() DomainState { return intentState(PhaseRoutesConverging) }, mutate: func(state *DomainState) { state.Intent.FenceTerm = state.FenceTerm + 1 }, wantErr: "exceeds state fence"},
		{name: "degraded without error", state: func() DomainState { return degradedState(false) }, mutate: func(state *DomainState) { state.Error = nil }, wantErr: "requires an error"},
		{name: "nondegraded error", state: validStableState, mutate: func(state *DomainState) { state.Error = validStateError() }, wantErr: "stable phase"},
		{name: "update before transition", state: validStableState, mutate: func(state *DomainState) { state.UpdatedAt = state.LastTransitionAt.Add(-time.Second) }, wantErr: "precedes last transition"},
		{name: "zero cooldown", state: validStableState, mutate: func(state *DomainState) { state.CooldownUntil = &time.Time{} }, wantErr: "cooldown deadline"},
		{name: "future domain error", state: func() DomainState { return degradedState(false) }, mutate: func(state *DomainState) { state.Error.At = state.UpdatedAt.Add(time.Second) }, wantErr: "precedes its error"},
		{name: "future route progress", state: convergingState, mutate: func(state *DomainState) {
			state.Intent.Progress[0].CompletedAt = timePtr(state.UpdatedAt.Add(time.Second))
		}, wantErr: "precedes route progress"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := test.state()
			test.mutate(&state)
			err := state.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestStateErrorValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*StateError)
		wantErr string
	}{
		{name: "valid", mutate: func(*StateError) {}},
		{name: "bad code", mutate: func(stateError *StateError) { stateError.Code = "Bad Code" }, wantErr: "error code"},
		{name: "empty message", mutate: func(stateError *StateError) { stateError.Message = "" }, wantErr: "message"},
		{name: "long message", mutate: func(stateError *StateError) { stateError.Message = strings.Repeat("x", maxErrorMessageLength+1) }, wantErr: "exceeds"},
		{name: "missing timestamp", mutate: func(stateError *StateError) { stateError.At = time.Time{} }, wantErr: "timestamp"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateError := validStateError()
			test.mutate(stateError)
			err := stateError.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestDomainStateCloneIsDeep(t *testing.T) {
	original := degradedState(true)
	original.CooldownUntil = timePtr(testTime.Add(time.Hour))
	original.Intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
	original.Intent.Progress[0].Ambiguous = true
	original.Intent.Progress[0].ObservedENIID = "eni-a"
	original.Intent.Progress[0].Error = &StateError{Code: ErrorRouteAmbiguous, Message: "settling", At: testTime.Add(5 * time.Minute), Ambiguous: true}
	clone := original.Clone()
	if !reflect.DeepEqual(&original, clone) {
		t.Fatal("clone differs before mutation")
	}

	clone.Authority.RemotePrefixes[0] = "192.0.2.0/24"
	clone.Authority.Owners[0].ENIID = "eni-changed"
	clone.Lease.HolderID = "changed"
	*clone.OwnerObservedAt = clone.OwnerObservedAt.Add(time.Hour)
	clone.Intent.Before.Routes[0].TargetENIID = "eni-changed"
	*clone.Intent.Progress[0].AttemptedAt = clone.Intent.Progress[0].AttemptedAt.Add(time.Hour)
	clone.Intent.Progress[0].Error.Message = "changed"
	*clone.CooldownUntil = clone.CooldownUntil.Add(time.Hour)
	clone.Error.Message = "changed"

	if original.Authority.RemotePrefixes[0] != "10.1.0.0/24" || original.Authority.Owners[0].ENIID != "eni-a" {
		t.Fatal("authority shares clone storage")
	}
	if original.Lease.HolderID != "controller-a" || original.Intent.Before.Routes[0].TargetENIID != "eni-a" {
		t.Fatal("lease or intent shares clone storage")
	}
	if original.Intent.Progress[0].Error.Message != "settling" || original.Error.Message != "degraded" {
		t.Fatal("errors share clone storage")
	}
	if original.OwnerObservedAt.Equal(*clone.OwnerObservedAt) || original.CooldownUntil.Equal(*clone.CooldownUntil) {
		t.Fatal("time pointers share clone storage")
	}

	var nilState *DomainState
	if nilState.Clone() != nil {
		t.Fatal("nil state clone is non-nil")
	}
}

func TestObservationCloneIsDeep(t *testing.T) {
	original := validObservation()
	domain := original.Domains["domain-a"]
	domain.Error = validStateError()
	original.Domains["domain-a"] = domain
	original.Error = validStateError()
	clone := original.Clone()
	clonedDomain := clone.Domains["domain-a"]
	clonedDomain.StableNodeID = "changed"
	*clonedDomain.OwnerSince = clonedDomain.OwnerSince.Add(time.Hour)
	clonedDomain.AdvertisedPrefixes[0] = "192.0.2.0/24"
	clonedDomain.Error.Message = "changed"
	clone.Domains["domain-a"] = clonedDomain
	clone.Error.Message = "changed"

	originalDomain := original.Domains["domain-a"]
	if originalDomain.StableNodeID != "node-a" || !originalDomain.OwnerSince.Equal(testTime) || originalDomain.AdvertisedPrefixes[0] != "10.0.0.0/24" || originalDomain.Error.Message != "degraded" {
		t.Fatal("observation domain shares clone storage")
	}
	if original.Error.Message != "degraded" {
		t.Fatal("observation error shares clone storage")
	}
	var nilObservation *Observation
	if nilObservation.Clone() != nil {
		t.Fatal("nil observation clone is non-nil")
	}
}

func validAuthority() DomainAuthority {
	return DomainAuthority{
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
		RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
		PreferredOwner:          "node-a",
		Owners: []OwnerAuthority{
			{RouterID: "router-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
			{RouterID: "router-b", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
		},
	}
}

func validLease() Lease {
	return Lease{
		HolderID:      "controller-a",
		FenceTerm:     2,
		RecordVersion: 4,
		AcquiredAt:    testTime,
		RenewedAt:     testTime.Add(time.Minute),
		ExpiresAt:     testTime.Add(2 * time.Minute),
	}
}

func validSnapshot() RouteSnapshot {
	return RouteSnapshot{
		RouteTableID: "rtb-a",
		CapturedAt:   testTime.Add(3 * time.Minute),
		Routes: []RouteSnapshotEntry{
			{DestinationPrefix: "10.1.0.0/24", TargetENIID: "eni-a", State: "active", Origin: "CreateRoute"},
			{DestinationPrefix: "10.1.1.0/24", TargetENIID: "eni-a", State: "active", Origin: "CreateRoute"},
		},
	}
}

func validIntent() RouteIntent {
	return RouteIntent{
		TransactionID: "transaction-a",
		FenceTerm:     2,
		DesiredOwner:  "node-b",
		DesiredENIID:  "eni-b",
		CreatedAt:     testTime.Add(4 * time.Minute),
		Before:        validSnapshot(),
		Progress: []RouteProgress{
			{DestinationPrefix: "10.1.0.0/24"},
			{DestinationPrefix: "10.1.1.0/24"},
		},
	}
}

func validStateError() *StateError {
	return &StateError{Code: ErrorInvariant, Message: "degraded", At: testTime.Add(6 * time.Minute)}
}

func validObservation() Observation {
	return Observation{
		ControllerID:   "controller-a",
		TopologyHash:   strings.Repeat("a", 64),
		Sequence:       1,
		CapturedAt:     testTime,
		ExpiresAt:      testTime.Add(time.Minute),
		BackendHealthy: true,
		Domains: map[string]OwnerObservation{
			"domain-a": {
				StableNodeID:          "node-a",
				SolePrimary:           true,
				Online:                true,
				Healthy:               true,
				OwnerSince:            timePtr(testTime),
				OwnerChangeGeneration: 1,
				AdvertisedPrefixes:    []string{"10.0.0.0/24"},
				EnabledPrefixes:       []string{"10.0.0.0/24"},
			},
		},
	}
}

func validStableState() DomainState {
	lease := validLease()
	return DomainState{
		Authority:        validAuthority(),
		Revision:         1,
		FenceTerm:        2,
		Lease:            &lease,
		Phase:            PhaseStable,
		StableOwner:      "node-a",
		LastTransitionAt: testTime.Add(2 * time.Minute),
		UpdatedAt:        testTime.Add(2 * time.Minute),
	}
}

func ownerObservedState() DomainState {
	state := validStableState()
	state.Phase = PhaseOwnerObserved
	state.ObservedOwner = "node-b"
	state.OwnerObservedAt = timePtr(testTime.Add(3 * time.Minute))
	state.LastTransitionAt = testTime.Add(3 * time.Minute)
	state.UpdatedAt = testTime.Add(3 * time.Minute)
	return state
}

func intentState(phase Phase) DomainState {
	state := ownerObservedState()
	intent := validIntent()
	state.Phase = phase
	state.Intent = &intent
	state.LastTransitionAt = intent.CreatedAt
	state.UpdatedAt = intent.CreatedAt
	return state
}

func convergingState() DomainState {
	state := intentState(PhaseRoutesConverging)
	state.Intent.Progress[0].AttemptedAt = timePtr(testTime.Add(5 * time.Minute))
	state.Intent.Progress[0].CompletedAt = timePtr(testTime.Add(6 * time.Minute))
	state.Intent.Progress[0].ObservedENIID = "eni-b"
	state.UpdatedAt = testTime.Add(6 * time.Minute)
	return state
}

func degradedState(withIntent bool) DomainState {
	var state DomainState
	if withIntent {
		state = intentState(PhaseRoutesConverging)
	} else {
		state = validStableState()
	}
	state.Phase = PhaseDegraded
	state.Error = validStateError()
	state.LastTransitionAt = testTime.Add(6 * time.Minute)
	state.UpdatedAt = testTime.Add(6 * time.Minute)
	return state
}

func timePtr(value time.Time) *time.Time {
	return &value
}
