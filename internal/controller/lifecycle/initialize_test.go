package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

type initialCloud struct {
	clock    *store.FakeClock
	snapshot model.RouteSnapshot
	err      error
	after    func()
}

func (c *initialCloud) ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return awscontrol.OwnerValidation{ValidatedAt: c.clock.Now()}, c.err
}

func (c *initialCloud) StableSnapshot(context.Context, model.DomainAuthority, time.Time) (model.RouteSnapshot, error) {
	if c.after != nil {
		c.after()
	}
	return c.snapshot, c.err
}

type uncertainStore struct{ InitialStore }

func (s uncertainStore) CreateDomain(ctx context.Context, initial *model.DomainState) (*model.DomainState, error) {
	if _, err := s.InitialStore.CreateDomain(ctx, initial); err != nil {
		return nil, err
	}
	return nil, context.DeadlineExceeded
}

func TestInitializationAgreementAndFailureBoundaries(t *testing.T) {
	for _, name := range []string{"alternate", "existing", "cloud-error", "mixed-target", "unknown-prefix", "missing-route", "duplicate-route", "wrong-table", "wrong-origin", "blackhole", "stale-route", "future-route", "no-attestation", "expired-attestation", "changed-owner", "lost-response", "canceled"} {
		t.Run(name, func(t *testing.T) {
			topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
			if err != nil {
				t.Fatal(err)
			}
			authority, err := topology.DomainAuthority(topology.Domains[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			var owner model.OwnerAuthority
			for _, candidate := range authority.Owners {
				if candidate.StableNodeID != authority.PreferredOwner {
					owner = candidate
				}
			}
			clock := store.NewFakeClock(time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
			identities := make([]store.ObserverIdentity, 0, 3)
			for _, id := range topology.ControllerIDs {
				identities = append(identities, store.ObserverIdentity{DeploymentID: authority.DeploymentID, TopologyHash: authority.TopologyHash, ControllerID: id})
			}
			memory, err := store.NewMemoryStore(clock, identities...)
			if err != nil {
				t.Fatal(err)
			}
			publish := func(node string, sequence uint64) {
				t.Helper()
				since := clock.Now().Add(-time.Minute)
				for _, id := range topology.ControllerIDs {
					_, err := memory.PublishObservation(context.Background(), authority.DeploymentID, &model.Observation{
						ControllerID: id, TopologyHash: authority.TopologyHash, Sequence: sequence, CapturedAt: clock.Now(),
						ExpiresAt: clock.Now().Add(topology.Policy.ObservationFreshness.Duration()), BackendHealthy: true,
						Domains: map[string]model.OwnerObservation{authority.DomainID: {StableNodeID: node, SolePrimary: true, Online: true, Healthy: true,
							OwnerSince: &since, OwnerChangeGeneration: 1, AdvertisedPrefixes: []string{authority.SourcePrefix}, EnabledPrefixes: []string{authority.SourcePrefix}}},
					})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			publish(owner.StableNodeID, 2)
			cloud := &initialCloud{clock: clock, snapshot: model.RouteSnapshot{RouteTableID: authority.RouteTableID, CapturedAt: clock.Now()}}
			for _, prefix := range authority.RemotePrefixes {
				cloud.snapshot.Routes = append(cloud.snapshot.Routes, model.RouteSnapshotEntry{DestinationPrefix: prefix, TargetENIID: owner.ENIID, State: "active", Origin: "CreateRoute"})
			}
			forwarding := Forwarding(func(context.Context, model.DomainAuthority, model.OwnerAuthority) (time.Time, error) {
				return clock.Now().Add(time.Second), nil
			})
			var durable InitialStore = memory
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var existing *model.DomainState
			switch name {
			case "existing":
				existing, err = memory.CreateDomain(ctx, &model.DomainState{Authority: authority, Revision: 1, Phase: model.PhaseStable, StableOwner: authority.PreferredOwner, LastTransitionAt: clock.Now(), UpdatedAt: clock.Now()})
				if err != nil {
					t.Fatal(err)
				}
			case "cloud-error":
				cloud.err = errors.New("cloud unavailable")
			case "mixed-target":
				cloud.snapshot.Routes[0].TargetENIID = "eni-unknown"
			case "unknown-prefix":
				cloud.snapshot.Routes[0].DestinationPrefix = "192.0.2.0/24"
			case "missing-route":
				cloud.snapshot.Routes = nil
			case "duplicate-route":
				cloud.snapshot.Routes = append(cloud.snapshot.Routes, cloud.snapshot.Routes[0])
			case "wrong-table":
				cloud.snapshot.RouteTableID += "-other"
			case "wrong-origin":
				cloud.snapshot.Routes[0].Origin = "EnableVgwRoutePropagation"
			case "blackhole":
				cloud.snapshot.Routes[0].State = "blackhole"
			case "stale-route":
				cloud.snapshot.CapturedAt = clock.Now().Add(-time.Minute)
			case "future-route":
				cloud.snapshot.CapturedAt = clock.Now().Add(time.Second)
			case "no-attestation":
				forwarding = nil
			case "expired-attestation":
				forwarding = func(context.Context, model.DomainAuthority, model.OwnerAuthority) (time.Time, error) {
					return clock.Now(), nil
				}
			case "changed-owner":
				cloud.after = func() { publish(authority.PreferredOwner, 3) }
			case "lost-response":
				durable = uncertainStore{memory}
			case "canceled":
				cancel()
			}
			created, err := Initialize(ctx, topology, authority.DomainID, durable, cloud, forwarding, clock)
			loaded, loadErr := memory.LoadDomain(context.Background(), store.DomainRefFor(authority))
			switch name {
			case "alternate":
				if err != nil || created.StableOwner != owner.StableNodeID || created.Lease != nil || created.FenceTerm != 0 || !reflect.DeepEqual(created, loaded) {
					t.Fatalf("initialization: %+v %v", created, err)
				}
			case "existing":
				if !errors.Is(err, ErrExists) || !reflect.DeepEqual(loaded, existing) {
					t.Fatalf("replaced existing journal: %+v %v", loaded, err)
				}
			case "lost-response":
				if !errors.Is(err, ErrUncertain) || loadErr != nil || loaded.StableOwner != owner.StableNodeID {
					t.Fatalf("lost response: %+v %v", loaded, err)
				}
			default:
				if !errors.Is(err, ErrPreflight) || !errors.Is(loadErr, store.ErrNotFound) {
					t.Fatalf("preflight wrote state: %+v %v %v", loaded, err, loadErr)
				}
			}
		})
	}
}
