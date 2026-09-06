package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
	"github.com/jaxxstorm/envelope/internal/controller/store"
)

func TestServiceReadinessForLeaderFollowerAndReadOnly(t *testing.T) {
	tests := []struct {
		name        string
		mode        reconcile.Mode
		leaseHolder string
		status      func(*testing.T, time.Time) reconcile.Status
	}{
		{
			name:        "leader",
			mode:        reconcile.ModeActive,
			leaseHolder: "controller-a",
			status: func(_ *testing.T, now time.Time) reconcile.Status {
				return safeLeaderStatus(testTopology(), now)
			},
		},
		{
			name:        "follower",
			mode:        reconcile.ModeActive,
			leaseHolder: "controller-b",
			status: func(t *testing.T, now time.Time) reconcile.Status {
				topology := testTopology()
				status := safeLeaderStatus(topology, now)
				status.Role = reconcile.RoleFollower
				status.Reason = reconcile.ReasonLeaseHeld
				return status
			},
		},
		{
			name: "read-only",
			mode: reconcile.ModeReadOnly,
			status: func(t *testing.T, now time.Time) reconcile.Status {
				topology := testTopology()
				status := safeLeaderStatus(topology, now)
				status.Mode = reconcile.ModeReadOnly
				status.Role = reconcile.RoleReadOnly
				status.Reason = reconcile.ReasonReadOnly
				status.LeaseExpiresAt = time.Time{}
				return status
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			topology := testTopology()
			clock := store.NewFakeClock(now)
			observer := &fakeObserver{}
			observer.snapshot = func(call int) (*model.Observation, error) {
				return testObservation(t, topology, clock.Now(), uint64(call)), nil
			}
			publisher := readyDurability(t, topology, now, test.leaseHolder)
			status := test.status(t, now)
			runner := newFakeRunner(status)
			service, err := NewService(ServiceOptions{
				Topology:            topology,
				ControllerID:        "controller-a",
				Mode:                test.mode,
				MetricsAddress:      "127.0.0.1:0",
				Observer:            observer,
				DurableReader:       publisher,
				Publisher:           publisher,
				PublishObservations: true,
				DomainRunners:       runnerSet(topology, now, runner, test.mode),
				Clock:               clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- service.Run(ctx) }()
			waitFor(t, func() bool { return publisher.callCount() == 1 })
			waitFor(t, func() bool {
				ready, _ := service.Readiness()
				return ready
			})
			if ready, reason := service.Readiness(); !ready || reason != ReadinessReady {
				t.Fatalf("Readiness() = %t, %q", ready, reason)
			}
			cancel()
			if err := <-result; err != nil {
				t.Fatalf("Run() cancellation error = %v", err)
			}
		})
	}
}

func TestServiceFollowerReadinessRequiresVerifiedDurability(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(*fakePublisher, time.Time, *controllerconfig.Topology)
		mutateStatus func(*reconcile.Status, *controllerconfig.Topology)
		wantReady    bool
		wantReason   string
		wantReadErr  bool
	}{
		{name: "confirmed holder", wantReady: true, wantReason: ReadinessReady},
		{
			name: "no durable quorum",
			mutate: func(durability *fakePublisher, _ time.Time, _ *controllerconfig.Topology) {
				delete(durability.observations, "controller-b")
			},
			wantReason: string(reconcile.ReasonObservationNoQuorum),
		},
		{
			name: "stale durable quorum",
			mutate: func(durability *fakePublisher, now time.Time, topology *controllerconfig.Topology) {
				for _, observation := range durability.observations {
					observation.CapturedAt = now.Add(-topology.Policy.ObservationFreshness.Duration() - time.Nanosecond)
					observation.ExpiresAt = now.Add(time.Second)
				}
			},
			wantReason: string(reconcile.ReasonObservationStale),
		},
		{
			name: "holder has no fresh vote",
			mutate: func(durability *fakePublisher, _ time.Time, _ *controllerconfig.Topology) {
				third := durability.observations["controller-b"].Clone()
				third.ControllerID = "controller-c"
				delete(durability.observations, "controller-b")
				durability.observations["controller-c"] = third
			},
			wantReason: string(reconcile.ReasonLeaseUnsafe),
		},
		{
			name: "holder is not allowlisted",
			mutate: func(durability *fakePublisher, _ time.Time, _ *controllerconfig.Topology) {
				for _, state := range durability.states {
					state.Lease.HolderID = "controller-unknown"
				}
			},
			wantReason: string(reconcile.ReasonLeaseUnsafe),
		},
		{
			name: "holder lease expired",
			mutate: func(durability *fakePublisher, now time.Time, _ *controllerconfig.Topology) {
				for _, state := range durability.states {
					state.Lease.AcquiredAt = now.Add(-2 * time.Second)
					state.Lease.RenewedAt = now.Add(-time.Second)
					state.Lease.ExpiresAt = now
				}
			},
			wantReason: string(reconcile.ReasonLeaseUnsafe),
		},
		{
			name: "holder lease entered danger window",
			mutate: func(durability *fakePublisher, now time.Time, topology *controllerconfig.Topology) {
				for _, state := range durability.states {
					state.Lease.ExpiresAt = now.Add(topology.Policy.LeaseDangerWindow.Duration())
				}
			},
			wantReason: string(reconcile.ReasonLeaseUnsafe),
		},
		{
			name: "AWS routes disagree with consensus",
			mutateStatus: func(status *reconcile.Status, _ *controllerconfig.Topology) {
				status.RouteAgreement = false
			},
			wantReason: string(reconcile.ReasonRouteDisagreement),
		},
		{
			name: "runner consensus differs from durable consensus",
			mutateStatus: func(status *reconcile.Status, topology *controllerconfig.Topology) {
				authority, err := topology.DomainAuthority(status.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				status.ConsensusOwner = authority.Owners[1].StableNodeID
			},
			wantReason: string(reconcile.ReasonObservationDisagreement),
		},
		{
			name: "follower transaction is transitional",
			mutateStatus: func(status *reconcile.Status, _ *controllerconfig.Topology) {
				status.Phase = model.PhaseOwnerObserved
				status.Reason = reconcile.ReasonStabilityWindow
			},
			wantReason: ReadinessDomainUnsafe,
		},
		{
			name: "durable transaction is transitional",
			mutate: func(durability *fakePublisher, now time.Time, topology *controllerconfig.Topology) {
				for domainID, state := range durability.states {
					authority, err := topology.DomainAuthority(domainID)
					if err != nil {
						t.Fatal(err)
					}
					state.Phase = model.PhaseOwnerObserved
					state.ObservedOwner = authority.Owners[1].StableNodeID
					state.OwnerObservedAt = &now
					state.LastTransitionAt = now
					state.UpdatedAt = now
				}
			},
			wantReason: ReadinessDomainUnsafe,
		},
		{
			name: "domain read unavailable",
			mutate: func(durability *fakePublisher, _ time.Time, _ *controllerconfig.Topology) {
				durability.loadErr = errors.New("injected durable read failure")
			},
			wantReason:  ReadinessStoreUnavailable,
			wantReadErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			topology := testTopology()
			clock := store.NewFakeClock(now)
			durability := readyDurability(t, topology, now, "controller-b")
			observer := &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
				return testObservation(t, topology, now, uint64(call)), nil
			}}
			west := safeLeaderStatus(topology, now)
			west.Role = reconcile.RoleFollower
			west.Reason = reconcile.ReasonLeaseHeld
			if test.mutateStatus != nil {
				test.mutateStatus(&west, topology)
			}
			service, err := NewService(ServiceOptions{
				Topology:            topology,
				ControllerID:        "controller-a",
				Mode:                reconcile.ModeActive,
				MetricsAddress:      "127.0.0.1:0",
				Observer:            observer,
				DurableReader:       durability,
				Publisher:           durability,
				PublishObservations: true,
				DomainRunners:       runnerSet(topology, now, newFakeRunner(west), reconcile.ModeActive),
				Clock:               clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			service.setLive(true)
			service.setObserverRunning(true)
			if _, _, err := service.observeAndPublish(context.Background()); err != nil {
				t.Fatal(err)
			}
			durability.mu.Lock()
			if test.mutate != nil {
				test.mutate(durability, now, topology)
			}
			durability.mu.Unlock()
			readErr := service.refreshDurableEvidence(context.Background())
			if (readErr != nil) != test.wantReadErr {
				t.Fatalf("refreshDurableEvidence() error = %v", readErr)
			}
			ready, reason := service.Readiness()
			if ready != test.wantReady || reason != test.wantReason {
				t.Fatalf("Readiness() = %t, %q; want %t, %q", ready, reason, test.wantReady, test.wantReason)
			}
		})
	}
}

func TestServiceFollowerReadinessExpiresWithLeaseHolderObservation(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	durability := readyDurability(t, topology, now, "controller-b")
	holder := durability.observations["controller-b"]
	holder.ExpiresAt = now.Add(50 * time.Millisecond)
	third := durability.observations["controller-a"].Clone()
	third.ControllerID = "controller-c"
	durability.observations[third.ControllerID] = third

	status := safeLeaderStatus(topology, now)
	status.Role = reconcile.RoleFollower
	status.Reason = reconcile.ReasonLeaseHeld
	service, err := NewService(ServiceOptions{
		Topology:       topology,
		ControllerID:   "controller-a",
		Mode:           reconcile.ModeActive,
		MetricsAddress: "127.0.0.1:0",
		Observer: &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
			return testObservation(t, topology, clock.Now(), uint64(call)), nil
		}},
		DurableReader:       durability,
		Publisher:           durability,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, newFakeRunner(status), reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	service.setLive(true)
	service.setObserverRunning(true)
	if _, _, err := service.observeAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.refreshDurableEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ready, reason := service.Readiness(); !ready || reason != ReadinessReady {
		t.Fatalf("initial Readiness() = %t, %q", ready, reason)
	}

	clock.Advance(50 * time.Millisecond)
	if ready, reason := service.Readiness(); ready || reason != string(reconcile.ReasonLeaseUnsafe) {
		t.Fatalf("Readiness() after holder observation expiry = %t, %q; want false, %q", ready, reason, reconcile.ReasonLeaseUnsafe)
	}
}

func TestServiceDegradedDomainIsLiveButNotReady(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	observer := &fakeObserver{}
	observer.snapshot = func(call int) (*model.Observation, error) {
		return testObservation(t, topology, clock.Now(), uint64(call)), nil
	}
	publisher := readyDurability(t, topology, now, "controller-a")
	status := safeLeaderStatus(topology, now)
	status.Phase = model.PhaseDegraded
	status.Reason = reconcile.ReasonObservationDisagreement
	status.ErrorCode = model.ErrorObservationQuorum
	status.Quorum = false
	status.RouteAgreement = false
	runner := newFakeRunner(status)
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       publisher,
		Publisher:           publisher,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, runner, reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()
	waitFor(t, func() bool { return publisher.callCount() == 1 })

	healthResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status = %d, body %q", healthResponse.Code, healthResponse.Body.String())
	}
	readyResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readyResponse.Code != http.StatusServiceUnavailable || !strings.Contains(readyResponse.Body.String(), string(reconcile.ReasonObservationDisagreement)) {
		t.Fatalf("readiness status/body = %d/%q", readyResponse.Code, readyResponse.Body.String())
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run() cancellation error = %v", err)
	}
}

func TestServiceTransitionalLeaderIsMetricVisibleButNotReady(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	durability := readyDurability(t, topology, now, "controller-a")
	authority, err := topology.DomainAuthority("west-domain")
	if err != nil {
		t.Fatal(err)
	}
	durable := durability.states[authority.DomainID]
	durable.Phase = model.PhaseOwnerObserved
	durable.ObservedOwner = authority.Owners[1].StableNodeID
	durable.OwnerObservedAt = &now
	durable.LastTransitionAt = now
	durable.UpdatedAt = now
	status := safeLeaderStatus(topology, now)
	status.Phase = model.PhaseOwnerObserved
	status.Reason = reconcile.ReasonStabilityWindow
	status.ObservedOwner = authority.Owners[1].StableNodeID
	status.ConsensusOwner = authority.Owners[1].StableNodeID
	status.RouteAgreement = false
	service, err := NewService(ServiceOptions{
		Topology:       topology,
		ControllerID:   "controller-a",
		Mode:           reconcile.ModeActive,
		MetricsAddress: "127.0.0.1:0",
		Observer: &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
			return testObservation(t, topology, now, uint64(call)), nil
		}},
		DurableReader:       durability,
		Publisher:           durability,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, newFakeRunner(status), reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	service.setLive(true)
	service.setObserverRunning(true)
	if _, _, err := service.observeAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.refreshDurableEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ready, reason := service.Readiness(); ready || reason != ReadinessDomainUnsafe {
		t.Fatalf("Readiness() = %t, %q; want false, %q", ready, reason, ReadinessDomainUnsafe)
	}

	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `envelope_controller_domain_phase{domain="west-domain",phase="owner-observed"} 1`) {
		t.Fatalf("transitional metrics status/body = %d/%q", response.Code, response.Body.String())
	}
}

func TestServiceRejectsUnknownDegradedAndStaleDomainStatus(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	observer := &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }}
	runner := newFakeRunner(safeLeaderStatus(topology, now))
	durability := readyDurability(t, topology, now, "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       durability,
		Publisher:           durability,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, runner, reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.refreshDurableEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	authority := service.authorities["west-domain"]
	evidence := service.state.durableDomains["west-domain"]

	tests := []struct {
		name           string
		mutateStatus   func(*reconcile.Status)
		mutateEvidence func(*durableDomainEvidence)
		want           string
	}{
		{name: "unknown role", mutateStatus: func(status *reconcile.Status) { status.Role = reconcile.RoleUnknown }, want: ReadinessDomainUnknown},
		{name: "degraded", mutateStatus: func(status *reconcile.Status) { status.Phase = model.PhaseDegraded }, want: ReadinessDomainDegraded},
		{name: "stale", mutateStatus: func(status *reconcile.Status) {
			status.UpdatedAt = now.Add(-topology.Policy.ObservationFreshness.Duration())
		}, want: ReadinessDomainStale},
		{name: "expired follower", mutateStatus: func(status *reconcile.Status) {
			status.Role = reconcile.RoleFollower
			status.Reason = reconcile.ReasonLeaseHeld
			status.LeaseExpiresAt = now
		}, want: string(reconcile.ReasonLeaseUnsafe)},
		{name: "leader lease in danger window", mutateStatus: func(status *reconcile.Status) {
			status.LeaseExpiresAt = now.Add(topology.Policy.LeaseDangerWindow.Duration())
		}, want: string(reconcile.ReasonLeaseUnsafe)},
		{name: "durable leader lease in danger window", mutateEvidence: func(evidence *durableDomainEvidence) {
			evidence.leaseExpiresAt = now.Add(topology.Policy.LeaseDangerWindow.Duration())
		}, want: string(reconcile.ReasonLeaseUnsafe)},
		{name: "leader route disagreement", mutateStatus: func(status *reconcile.Status) { status.RouteAgreement = false }, want: string(reconcile.ReasonRouteDisagreement)},
		{name: "leader consensus disagreement", mutateStatus: func(status *reconcile.Status) {
			status.ConsensusOwner = authority.Owners[1].StableNodeID
		}, want: string(reconcile.ReasonObservationDisagreement)},
		{name: "leader owner-observed transaction", mutateStatus: func(status *reconcile.Status) {
			status.Phase = model.PhaseOwnerObserved
			status.Reason = reconcile.ReasonStabilityWindow
			status.ObservedOwner = authority.Owners[1].StableNodeID
		}, want: ReadinessDomainUnsafe},
		{name: "leader route-intent transaction", mutateStatus: func(status *reconcile.Status) {
			status.Phase = model.PhaseRouteIntentPersisted
			status.Reason = reconcile.ReasonReconciling
		}, want: ReadinessDomainUnsafe},
		{name: "leader routes-converging transaction", mutateStatus: func(status *reconcile.Status) {
			status.Phase = model.PhaseRoutesConverging
			status.Reason = reconcile.ReasonReconciling
			status.CompletedRoutes = 1
		}, want: ReadinessDomainUnsafe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := safeLeaderStatus(topology, now)
			domainEvidence := evidence
			if test.mutateStatus != nil {
				test.mutateStatus(&status)
			}
			if test.mutateEvidence != nil {
				test.mutateEvidence(&domainEvidence)
			}
			ready, reason := service.domainReady(now, authority, status, domainEvidence)
			if ready || reason != test.want {
				t.Fatalf("domainReady() = %t, %q; want false, %q", ready, reason, test.want)
			}
		})
	}
}

func TestServiceRetriesObserverAndPublicationSerially(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	observer := &fakeObserver{}
	observer.snapshot = func(call int) (*model.Observation, error) {
		if call == 1 {
			return nil, errors.New("transient observer failure")
		}
		return testObservation(t, topology, clock.Now(), uint64(call)), nil
	}
	publisher := readyDurability(t, topology, now, "controller-a")
	publisher.failures = []error{errors.New("transient store failure")}
	runner := newFakeRunner(safeLeaderStatus(topology, now))
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       publisher,
		Publisher:           publisher,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, runner, reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()

	waitFor(t, func() bool {
		calls, _, _ := observer.stats()
		return calls == 1 && clock.PendingTimers() >= 3
	})
	if ready, reason := service.Readiness(); ready || reason != ReadinessObserverUnhealthy {
		t.Fatalf("readiness after snapshot failure = %t, %q", ready, reason)
	}
	clock.Advance(topology.Policy.ObservationInterval.Duration())
	waitFor(t, func() bool { return publisher.callCount() == 1 && clock.PendingTimers() >= 3 })
	if ready, reason := service.Readiness(); ready || reason != ReadinessObservationUnavailable {
		t.Fatalf("readiness after publication failure = %t, %q", ready, reason)
	}
	clock.Advance(topology.Policy.ObservationInterval.Duration())
	waitFor(t, func() bool {
		ready, _ := service.Readiness()
		return publisher.callCount() == 2 && ready
	})
	if ready, reason := service.Readiness(); !ready || reason != ReadinessReady {
		t.Fatalf("readiness after retry = %t, %q", ready, reason)
	}
	if calls, maximum, _ := observer.stats(); calls != 3 || maximum != 1 {
		t.Fatalf("observer calls/concurrency = %d/%d, want 3/1", calls, maximum)
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run() cancellation error = %v", err)
	}
}

func TestServiceObserverRunsAtFixedRateAcrossPublicationLatency(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	captures := make(chan time.Time, 2)
	observer := &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
		capturedAt := clock.Now()
		captures <- capturedAt
		return testObservation(t, topology, capturedAt, uint64(call)), nil
	}}
	durability := readyDurability(t, topology, now, "controller-a")
	publisher := &advancingPublisher{
		fakePublisher: durability,
		clock:         clock,
		latency:       40 * time.Millisecond,
	}
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       durability,
		Publisher:           publisher,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, newFakeRunner(safeLeaderStatus(topology, now)), reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.runObserver(ctx) }()
	if capturedAt := <-captures; !capturedAt.Equal(now) {
		t.Fatalf("first capture = %s, want %s", capturedAt, now)
	}
	waitFor(t, func() bool { return clock.PendingTimers() == 1 })
	remaining := topology.Policy.ObservationInterval.Duration() - publisher.latency
	clock.Advance(remaining - time.Nanosecond)
	select {
	case capturedAt := <-captures:
		t.Fatalf("second capture ran early at %s", capturedAt)
	case <-time.After(20 * time.Millisecond):
	}
	clock.Advance(time.Nanosecond)
	select {
	case capturedAt := <-captures:
		if want := now.Add(topology.Policy.ObservationInterval.Duration()); !capturedAt.Equal(want) {
			t.Fatalf("second capture = %s, want fixed-rate %s", capturedAt, want)
		}
	case <-time.After(time.Second):
		t.Fatal("second fixed-rate observation did not run")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("runObserver() error = %v", err)
	}
}

func TestServiceValidatesModePublicationAndReconcileConcurrency(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	durability := readyDurability(t, topology, now, "controller-a")
	observer := &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }}
	base := func() ServiceOptions {
		return ServiceOptions{
			Topology:            topology,
			ControllerID:        "controller-a",
			Mode:                reconcile.ModeActive,
			MetricsAddress:      "127.0.0.1:0",
			Observer:            observer,
			DurableReader:       durability,
			Publisher:           durability,
			PublishObservations: true,
			DomainRunners:       runnerSet(topology, now, newFakeRunner(safeLeaderStatus(topology, now)), reconcile.ModeActive),
			Clock:               store.NewFakeClock(now),
		}
	}
	tests := []struct {
		name   string
		mutate func(*ServiceOptions)
	}{
		{name: "negative concurrency", mutate: func(options *ServiceOptions) { options.ReconcileConcurrency = -1 }},
		{name: "excessive concurrency", mutate: func(options *ServiceOptions) { options.ReconcileConcurrency = controllerconfig.MaxActiveDomains + 1 }},
		{name: "undersized active concurrency", mutate: func(options *ServiceOptions) { options.ReconcileConcurrency = 1 }},
		{name: "runner mode mismatch", mutate: func(options *ServiceOptions) { options.Mode = reconcile.ModeReadOnly }},
		{name: "dry-run publication", mutate: func(options *ServiceOptions) {
			options.Mode = reconcile.ModeDryRun
			options.DomainRunners = runnerSet(topology, now, nil, reconcile.ModeDryRun)
		}},
		{name: "active publication disabled", mutate: func(options *ServiceOptions) {
			options.Publisher = nil
			options.PublishObservations = false
		}},
		{name: "initial lease for unknown domain", mutate: func(options *ServiceOptions) {
			options.InitialLeases = map[string]*model.Lease{"unknown-domain": durability.states["west-domain"].Lease.Clone()}
		}},
		{name: "initial lease held by another controller", mutate: func(options *ServiceOptions) {
			lease := durability.states["west-domain"].Lease.Clone()
			lease.HolderID = "controller-b"
			options.InitialLeases = map[string]*model.Lease{"west-domain": lease}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base()
			test.mutate(&options)
			service, err := NewService(options)
			if service != nil || !errors.Is(err, ErrInvalidService) {
				t.Fatalf("NewService() = %v, %v", service, err)
			}
		})
	}
}

func TestServiceRejectsActiveDomainCountAboveWorkerCapacity(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopologyWithDomainCounts(controllerconfig.MaxActiveDomains/2+1, (controllerconfig.MaxActiveDomains+1)/2)
	durability := readyDurability(t, topology, now, "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:       durability,
		Publisher:           durability,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, nil, reconcile.ModeActive),
		Clock:               store.NewFakeClock(now),
	})
	if service != nil || !errors.Is(err, ErrInvalidService) || !strings.Contains(err.Error(), "active domain count exceeds worker capacity") {
		t.Fatalf("NewService() = %v, %v; want active worker-capacity error", service, err)
	}
}

func TestServiceAllowsPassiveDomainCountAboveActiveWorkerCapacity(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopologyWithDomainCounts(controllerconfig.MaxActiveDomains/2+1, (controllerconfig.MaxActiveDomains+1)/2)
	durability := readyDurability(t, topology, now, "controller-a")
	for _, mode := range []reconcile.Mode{reconcile.ModeReadOnly, reconcile.ModeDryRun} {
		t.Run(string(mode), func(t *testing.T) {
			publish := mode == reconcile.ModeReadOnly
			var publisher ObservationPublisher
			if publish {
				publisher = durability
			}
			service, err := NewService(ServiceOptions{
				Topology:            topology,
				ControllerID:        "controller-a",
				Mode:                mode,
				MetricsAddress:      "127.0.0.1:0",
				Observer:            &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
				DurableReader:       durability,
				Publisher:           publisher,
				PublishObservations: publish,
				DomainRunners:       runnerSet(topology, now, nil, mode),
				Clock:               store.NewFakeClock(now),
			})
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			if service.reconcileConcurrency != defaultReconcileConcurrency {
				t.Fatalf("passive reconcile concurrency = %d, want %d", service.reconcileConcurrency, defaultReconcileConcurrency)
			}
			if err := service.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestServiceBoundsReconcileConcurrencyWithoutBlockingOtherDomains(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	durability := readyDurability(t, topology, now, "controller-a")
	observer := &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
		return testObservation(t, topology, now, uint64(call)), nil
	}}

	const concurrency = 2
	entered := make(chan struct{}, len(topology.Domains))
	releaseDomains := make(chan struct{})
	var trackerMu sync.Mutex
	active := 0
	maximum := 0
	runners := make(map[string]DomainRunner, len(topology.Domains))
	for _, domain := range topology.Domains {
		domainID := domain.ID
		runner := newFakeRunner(safeLeaderStatusForDomain(topology, domainID, now))
		runner.reconcile = func(ctx context.Context, _ int) error {
			trackerMu.Lock()
			active++
			if active > maximum {
				maximum = active
			}
			trackerMu.Unlock()
			entered <- struct{}{}
			select {
			case <-releaseDomains:
			case <-ctx.Done():
			}
			trackerMu.Lock()
			active--
			trackerMu.Unlock()
			return ctx.Err()
		}
		runners[domainID] = runner
	}
	service, err := NewService(ServiceOptions{
		Topology:             topology,
		ControllerID:         "controller-a",
		Mode:                 reconcile.ModeActive,
		MetricsAddress:       "127.0.0.1:0",
		Observer:             observer,
		DurableReader:        durability,
		Publisher:            durability,
		PublishObservations:  true,
		DomainRunners:        runners,
		ReconcileConcurrency: concurrency,
		Clock:                clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()
	for range len(topology.Domains) {
		select {
		case <-entered:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("configured domain concurrency was not reached")
		}
	}
	trackerMu.Lock()
	observedMaximum := maximum
	trackerMu.Unlock()
	if observedMaximum != concurrency {
		t.Fatalf("maximum reconcile concurrency = %d, want %d", observedMaximum, concurrency)
	}
	close(releaseDomains)
	waitFor(t, func() bool {
		trackerMu.Lock()
		defer trackerMu.Unlock()
		return active == 0
	})
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run() cancellation error = %v", err)
	}
}

func TestServiceContendedDomainsDoNotStarveHeldLeaseRenewal(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := expandedTestTopology()
	clock := store.NewFakeClock(now)
	topologyHash, err := topology.Hash()
	if err != nil {
		t.Fatal(err)
	}
	identities := make([]store.ObserverIdentity, 0, len(topology.ControllerIDs))
	for _, controllerID := range topology.ControllerIDs {
		identities = append(identities, store.ObserverIdentity{
			DeploymentID: topology.DeploymentID,
			TopologyHash: topologyHash,
			ControllerID: controllerID,
		})
	}
	memory, err := store.NewMemoryStore(clock, identities...)
	if err != nil {
		t.Fatal(err)
	}
	first := testObservation(t, topology, now, 1)
	second := first.Clone()
	second.ControllerID = "controller-b"
	for _, observation := range []*model.Observation{first, second} {
		if _, err := memory.PublishObservation(context.Background(), topology.DeploymentID, observation); err != nil {
			t.Fatal(err)
		}
	}

	const heldDomain = "west-domain-2"
	routes := &schedulerRouteController{
		clock:          clock,
		heldDomain:     heldDomain,
		blockContended: make(chan struct{}),
		snapshots:      make(map[string]int),
	}
	runners := make(map[string]DomainRunner, len(topology.Domains))
	var heldAuthority model.DomainAuthority
	for _, domain := range topology.Domains {
		authority, err := topology.DomainAuthority(domain.ID)
		if err != nil {
			t.Fatal(err)
		}
		initial := &model.DomainState{
			Authority:        authority,
			Activated:        true,
			Revision:         1,
			Phase:            model.PhaseStable,
			StableOwner:      authority.PreferredOwner,
			LastTransitionAt: now,
			UpdatedAt:        now,
		}
		if _, err := memory.CreateDomain(context.Background(), initial); err != nil {
			t.Fatal(err)
		}
		holder := "controller-b"
		if domain.ID == heldDomain {
			holder = "controller-a"
			heldAuthority = authority
		}
		if _, err := memory.AcquireLease(context.Background(), store.DomainRefFor(authority), holder, topology.Policy.LeaseDuration.Duration()); err != nil {
			t.Fatal(err)
		}
		engine, err := reconcile.NewEngine(reconcile.Options{
			Topology:     topology,
			DomainID:     domain.ID,
			ControllerID: "controller-a",
			Store:        memory,
			Routes:       routes,
			Clock:        clock,
			UUIDs:        reconcile.UUIDFunc(func() string { return "00000000-0000-4000-8000-000000000001" }),
		})
		if err != nil {
			t.Fatal(err)
		}
		runners[domain.ID] = engine
	}
	clock.Advance(topology.Policy.LeaseRenewInterval.Duration())
	service, err := NewService(ServiceOptions{
		Topology:             topology,
		ControllerID:         "controller-a",
		Mode:                 reconcile.ModeActive,
		MetricsAddress:       "127.0.0.1:0",
		Observer:             &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:        memory,
		Publisher:            memory,
		PublishObservations:  true,
		DomainRunners:        runners,
		ReconcileConcurrency: len(topology.Domains),
		Clock:                clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.runReconciler(ctx) }()
	waitFor(t, func() bool {
		state, loadErr := memory.LoadDomain(context.Background(), store.DomainRefFor(heldAuthority))
		return loadErr == nil && state.Lease != nil && state.Lease.RecordVersion > 1 && routes.snapshotCount(heldDomain) > 0
	})
	firstRenewal := func() uint64 {
		state, loadErr := memory.LoadDomain(context.Background(), store.DomainRefFor(heldAuthority))
		if loadErr != nil || state.Lease == nil {
			t.Fatalf("load held lease after first renewal: state=%+v error=%v", state, loadErr)
		}
		return state.Lease.RecordVersion
	}()
	clock.Advance(topology.Policy.LeaseRenewInterval.Duration())
	waitFor(t, func() bool {
		state, loadErr := memory.LoadDomain(context.Background(), store.DomainRefFor(heldAuthority))
		return loadErr == nil && state.Lease != nil && state.Lease.RecordVersion > firstRenewal
	})
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("runReconciler() error = %v", err)
	}
	if calls := routes.snapshotCount(heldDomain); calls == 0 {
		t.Fatal("locally held domain performed no reconciliation work")
	}
}

func TestServiceFairGenerationCoalescesWhileReadOnlyWorkerIsBlocked(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := expandedTestTopology()
	clock := store.NewFakeClock(now)
	const firstDomain = "east-domain"
	firstCalls := make(chan int, 4)
	releaseFirst := make(chan struct{})
	var eventMu sync.Mutex
	events := make([]string, 0, len(topology.Domains)+1)
	recordEvent := func(event string) {
		eventMu.Lock()
		events = append(events, event)
		eventMu.Unlock()
	}
	runners := make(map[string]DomainRunner, len(topology.Domains))
	for _, domain := range topology.Domains {
		domainID := domain.ID
		status := safeLeaderStatusForDomain(topology, domainID, now)
		status.Mode = reconcile.ModeReadOnly
		status.Role = reconcile.RoleReadOnly
		status.Reason = reconcile.ReasonReadOnly
		status.LeaseExpiresAt = time.Time{}
		runner := newFakeRunner(status)
		if domainID == firstDomain {
			runner.reconcile = func(ctx context.Context, call int) error {
				recordEvent(fmt.Sprintf("%s#%d", domainID, call))
				firstCalls <- call
				if call == 1 {
					select {
					case <-releaseFirst:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}
		} else {
			runner.reconcile = func(context.Context, int) error {
				recordEvent(domainID + "#1")
				return nil
			}
		}
		runners[domainID] = runner
	}
	durability := readyDurability(t, topology, now, "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:             topology,
		ControllerID:         "controller-a",
		Mode:                 reconcile.ModeReadOnly,
		MetricsAddress:       "127.0.0.1:0",
		Observer:             &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:        durability,
		Publisher:            durability,
		PublishObservations:  true,
		DomainRunners:        runners,
		ReconcileConcurrency: 1,
		Clock:                clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.runReconciler(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("runReconciler() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("runReconciler() did not stop after cancellation")
		}
	}()

	select {
	case call := <-firstCalls:
		if call != 1 {
			t.Fatalf("first domain call = %d", call)
		}
	case <-time.After(time.Second):
		t.Fatal("first generation did not start")
	}
	interval := min(topology.Policy.ObservationInterval.Duration(), topology.Policy.LeaseRenewInterval.Duration())
	for range 3 {
		waitFor(t, func() bool { return clock.PendingTimers() == 1 })
		clock.Advance(interval)
	}
	close(releaseFirst)

	waitFor(t, func() bool {
		eventMu.Lock()
		defer eventMu.Unlock()
		seen := make(map[string]bool, len(topology.Domains))
		for _, event := range events {
			domainID, _, _ := strings.Cut(event, "#")
			seen[domainID] = true
			if event == firstDomain+"#2" && len(seen) == len(topology.Domains) {
				return true
			}
		}
		return false
	})
	eventMu.Lock()
	observedEvents := append([]string(nil), events...)
	eventMu.Unlock()
	indexOf := func(want string) int {
		for index, event := range observedEvents {
			if event == want {
				return index
			}
		}
		return -1
	}
	repeatedFirstIndex := indexOf(firstDomain + "#2")
	for _, domain := range topology.Domains {
		event := domain.ID + "#1"
		if index := indexOf(event); index < 0 || index > repeatedFirstIndex {
			t.Fatalf("generation dispatch order starved %q: %v", domain.ID, observedEvents)
		}
	}
}

func TestServiceActiveCapacityDoesNotShareWorkersBetweenDomains(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := expandedTestTopology()
	clock := store.NewFakeClock(now)
	const renewalDomain = "west-domain-2"
	renewalEntered := make(chan struct{})
	blockersEntered := make(chan string, len(topology.Domains)-1)
	runners := make(map[string]DomainRunner, len(topology.Domains))
	for _, domain := range topology.Domains {
		domainID := domain.ID
		status := safeLeaderStatusForDomain(topology, domainID, now)
		runner := newFakeRunner(status)
		if domainID == renewalDomain {
			status.LeaseExpiresAt = now.Add(topology.Policy.LeaseDuration.Duration() - topology.Policy.LeaseRenewInterval.Duration())
			runner.setStatus(status)
			runner.reconcile = func(ctx context.Context, _ int) error {
				close(renewalEntered)
				<-ctx.Done()
				return ctx.Err()
			}
		} else {
			runner.reconcile = func(ctx context.Context, _ int) error {
				blockersEntered <- domainID
				<-ctx.Done()
				return ctx.Err()
			}
		}
		runners[domainID] = runner
	}
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:       readyDurability(t, topology, now, "controller-a"),
		Publisher:           readyDurability(t, topology, now, "controller-a"),
		PublishObservations: true,
		DomainRunners:       runners,
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.reconcileConcurrency != len(topology.Domains) {
		t.Fatalf("active reconcile concurrency = %d, want one slot per %d domains", service.reconcileConcurrency, len(topology.Domains))
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.runReconciler(ctx) }()
	for range len(topology.Domains) - 1 {
		select {
		case <-blockersEntered:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("not every unrelated domain occupied its worker")
		}
	}
	select {
	case <-renewalEntered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("renewal-due domain did not retain independent worker capacity")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("runReconciler() error = %v", err)
	}
}

func TestServiceInitialLeaseHintPrioritizesUnknownLocalHolder(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := expandedTestTopology()
	clock := store.NewFakeClock(now)
	const heldDomain = "west-domain-2"
	runners := make(map[string]DomainRunner, len(topology.Domains))
	for _, domain := range topology.Domains {
		domainID := domain.ID
		runner := newFakeRunner(reconcile.Status{
			ControllerID: "controller-a",
			DomainID:     domainID,
			Mode:         reconcile.ModeActive,
			Role:         reconcile.RoleUnknown,
			Reason:       reconcile.ReasonStarting,
			UpdatedAt:    now,
		})
		runners[domainID] = runner
	}
	initialLease := &model.Lease{
		HolderID:      "controller-a",
		FenceTerm:     1,
		RecordVersion: 1,
		AcquiredAt:    now,
		RenewedAt:     now,
		ExpiresAt:     now.Add(topology.Policy.LeaseDuration.Duration()),
	}
	durability := readyDurability(t, topology, now, "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:             topology,
		ControllerID:         "controller-a",
		Mode:                 reconcile.ModeActive,
		MetricsAddress:       "127.0.0.1:0",
		Observer:             &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:        durability,
		Publisher:            durability,
		PublishObservations:  true,
		DomainRunners:        runners,
		ReconcileConcurrency: len(topology.Domains),
		Clock:                clock,
		InitialLeases:        map[string]*model.Lease{heldDomain: initialLease},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if priority := service.leasePriority(heldDomain, runners[heldDomain].Status(), now); priority != leasePriorityRenewal {
		t.Fatalf("startup lease priority = %d, want renewal", priority)
	}
}

func TestServicePostStartLeaseHintSurvivesTransientUnknownStatus(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := expandedTestTopology()
	clock := store.NewFakeClock(now)
	const heldDomain = "west-domain-2"
	runners := make(map[string]DomainRunner, len(topology.Domains))
	var heldRunner *fakeRunner
	for _, domain := range topology.Domains {
		domainID := domain.ID
		status := reconcile.Status{
			ControllerID: "controller-a",
			DomainID:     domainID,
			Mode:         reconcile.ModeActive,
			Role:         reconcile.RoleUnknown,
			Reason:       reconcile.ReasonStarting,
			UpdatedAt:    now,
		}
		if domainID == heldDomain {
			status = safeLeaderStatusForDomain(topology, domainID, now)
			status.Role = reconcile.RoleFollower
			status.Reason = reconcile.ReasonLeaseHeld
		}
		runner := newFakeRunner(status)
		if domainID == heldDomain {
			heldRunner = runner
		}
		runners[domainID] = runner
	}
	durability := readyDurability(t, topology, now, "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:             topology,
		ControllerID:         "controller-a",
		Mode:                 reconcile.ModeActive,
		MetricsAddress:       "127.0.0.1:0",
		Observer:             &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
		DurableReader:        durability,
		Publisher:            durability,
		PublishObservations:  true,
		DomainRunners:        runners,
		ReconcileConcurrency: len(topology.Domains),
		Clock:                clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	leader := safeLeaderStatusForDomain(topology, heldDomain, now)
	heldRunner.setStatus(leader)
	unknown := leader
	unknown.Role = reconcile.RoleUnknown
	unknown.Reason = reconcile.ReasonStoreUnavailable
	heldRunner.setStatus(unknown)
	if hint, found := service.localLeaseHint(heldDomain, unknown.FenceTerm, now); !found || !hint.expiresAt.Equal(leader.LeaseExpiresAt) {
		t.Fatalf("post-start local lease hint = %+v, %t", hint, found)
	}
	if priority := service.leasePriority(heldDomain, unknown, now); priority != leasePriorityRenewal {
		t.Fatalf("transient unknown lease priority = %d, want renewal", priority)
	}
}

func TestServiceExpiredAndForeignLeaseHintsDoNotRetainPriority(t *testing.T) {
	tests := []struct {
		name        string
		lease       func(time.Time, *controllerconfig.Topology) *model.Lease
		advance     time.Duration
		markForeign bool
	}{
		{
			name:    "expired startup hint",
			advance: 50 * time.Millisecond,
			lease: func(now time.Time, _ *controllerconfig.Topology) *model.Lease {
				return &model.Lease{
					HolderID:      "controller-a",
					FenceTerm:     1,
					RecordVersion: 1,
					AcquiredAt:    now,
					RenewedAt:     now,
					ExpiresAt:     now.Add(50 * time.Millisecond),
				}
			},
		},
		{
			name:        "observed foreign lease",
			markForeign: true,
			lease: func(now time.Time, topology *controllerconfig.Topology) *model.Lease {
				return &model.Lease{
					HolderID:      "controller-a",
					FenceTerm:     1,
					RecordVersion: 1,
					AcquiredAt:    now,
					RenewedAt:     now,
					ExpiresAt:     now.Add(topology.Policy.LeaseDuration.Duration()),
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			topology := expandedTestTopology()
			clock := store.NewFakeClock(now)
			const staleDomain = "west-domain-2"
			runners := make(map[string]DomainRunner, len(topology.Domains))
			var staleRunner *fakeRunner
			for _, domain := range topology.Domains {
				domainID := domain.ID
				runner := newFakeRunner(reconcile.Status{
					ControllerID: "controller-a",
					DomainID:     domainID,
					Mode:         reconcile.ModeActive,
					Role:         reconcile.RoleUnknown,
					Reason:       reconcile.ReasonStarting,
					UpdatedAt:    now,
				})
				if domainID == staleDomain {
					staleRunner = runner
				}
				runners[domainID] = runner
			}
			durability := readyDurability(t, topology, now, "controller-a")
			service, err := NewService(ServiceOptions{
				Topology:             topology,
				ControllerID:         "controller-a",
				Mode:                 reconcile.ModeActive,
				MetricsAddress:       "127.0.0.1:0",
				Observer:             &fakeObserver{snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }},
				DurableReader:        durability,
				Publisher:            durability,
				PublishObservations:  true,
				DomainRunners:        runners,
				ReconcileConcurrency: len(topology.Domains),
				Clock:                clock,
				InitialLeases:        map[string]*model.Lease{staleDomain: test.lease(now, topology)},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			clock.Advance(test.advance)
			if test.markForeign {
				follower := safeLeaderStatusForDomain(topology, staleDomain, now)
				follower.Role = reconcile.RoleFollower
				follower.Reason = reconcile.ReasonLeaseHeld
				follower.FenceTerm = 2
				staleRunner.setStatus(follower)
				unknown := follower
				unknown.Role = reconcile.RoleUnknown
				unknown.Reason = reconcile.ReasonStoreUnavailable
				staleRunner.setStatus(unknown)
			}
			if hint, found := service.localLeaseHint(staleDomain, 0, clock.Now()); found {
				t.Fatalf("stale lease hint remained active: %+v", hint)
			}
			if priority := service.leasePriority(staleDomain, staleRunner.Status(), clock.Now()); priority != leasePriorityNone {
				t.Fatalf("stale lease priority = %d, want none", priority)
			}
		})
	}
}

func TestServiceLeaseRenewalUrgencyUsesLeaseTiming(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	service := &Service{topology: topology}
	status := safeLeaderStatus(topology, now)
	if service.leaseRenewalUrgent(status, now) {
		t.Fatal("fresh leader lease was treated as renewal-urgent")
	}
	dueAt := status.LeaseExpiresAt.Add(-topology.Policy.LeaseDuration.Duration() + topology.Policy.LeaseRenewInterval.Duration())
	if !service.leaseRenewalUrgent(status, dueAt) {
		t.Fatal("renewal-due leader lease was not treated as urgent")
	}
	status.Role = reconcile.RoleFollower
	if service.leaseRenewalUrgent(status, dueAt) {
		t.Fatal("foreign-held follower lease was treated as local renewal work")
	}
}

func TestServiceCancellationClosesObserverAndHTTP(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	topology := testTopology()
	clock := store.NewFakeClock(now)
	observer := &fakeObserver{}
	observer.snapshot = func(call int) (*model.Observation, error) {
		return testObservation(t, topology, clock.Now(), uint64(call)), nil
	}
	publisher := readyDurability(t, topology, now, "controller-a")
	runner := newFakeRunner(safeLeaderStatus(topology, now))
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       publisher,
		Publisher:           publisher,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, now, runner, reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()
	waitFor(t, func() bool { return service.Address() != nil && publisher.callCount() == 1 })
	address := service.Address().String()
	response, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatalf("GET health before shutdown: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run() cancellation error = %v", err)
	}
	if runner.callCount() == 0 {
		t.Fatal("domain runner was never reconciled")
	}
	if _, _, closes := observer.stats(); closes != 1 {
		t.Fatalf("observer closes = %d, want 1", closes)
	}
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	if response, err := client.Get("http://" + address + "/healthz"); err == nil {
		_ = response.Body.Close()
		t.Fatal("HTTP server still accepted requests after shutdown")
	}
	if service.Healthy() {
		t.Fatal("service remained live after shutdown")
	}
}

func TestServiceConcurrentRunAndCloseCannotResurrectLiveness(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
		topology := testTopology()
		clock := store.NewFakeClock(now)
		durability := readyDurability(t, topology, now, "controller-a")
		service, err := NewService(ServiceOptions{
			Topology:       topology,
			ControllerID:   "controller-a",
			Mode:           reconcile.ModeActive,
			MetricsAddress: "127.0.0.1:0",
			Observer: &fakeObserver{snapshot: func(call int) (*model.Observation, error) {
				return testObservation(t, topology, now, uint64(call)), nil
			}},
			DurableReader:       durability,
			Publisher:           durability,
			PublishObservations: true,
			DomainRunners:       runnerSet(topology, now, newFakeRunner(safeLeaderStatus(topology, now)), reconcile.ModeActive),
			Clock:               clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		runResult := make(chan error, 1)
		closeResult := make(chan error, 1)
		go func() {
			<-start
			runResult <- service.Run(context.Background())
		}()
		go func() {
			<-start
			closeResult <- service.Close()
		}()
		close(start)
		if err := <-closeResult; err != nil {
			t.Fatalf("iteration %d Close() error = %v", iteration, err)
		}
		if err := <-runResult; err != nil && !errors.Is(err, ErrServiceClosed) {
			t.Fatalf("iteration %d Run() error = %v", iteration, err)
		}
		if service.Healthy() {
			t.Fatalf("iteration %d resurrected service liveness", iteration)
		}
	}
}

func TestServiceCloseIsConcurrentAndIdempotent(t *testing.T) {
	topology := testTopology()
	clock := store.NewFakeClock(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	closeFailure := errors.New("injected close failure")
	observer := &fakeObserver{closeErr: closeFailure, snapshot: func(int) (*model.Observation, error) { return nil, errors.New("unused") }}
	runner := newFakeRunner(safeLeaderStatus(topology, clock.Now()))
	durability := readyDurability(t, topology, clock.Now(), "controller-a")
	service, err := NewService(ServiceOptions{
		Topology:            topology,
		ControllerID:        "controller-a",
		Mode:                reconcile.ModeActive,
		MetricsAddress:      "127.0.0.1:0",
		Observer:            observer,
		DurableReader:       durability,
		Publisher:           durability,
		PublishObservations: true,
		DomainRunners:       runnerSet(topology, clock.Now(), runner, reconcile.ModeActive),
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 12
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- service.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, closeFailure) {
			t.Errorf("Close() error = %v, want injected failure", err)
		}
	}
	if _, _, closes := observer.stats(); closes != 1 {
		t.Fatalf("observer closes = %d, want 1", closes)
	}
	if err := service.Run(context.Background()); !errors.Is(err, ErrServiceClosed) {
		t.Fatalf("Run() after Close() error = %v", err)
	}
}

func expandedTestTopology() *controllerconfig.Topology {
	return testTopologyWithDomainCounts(3, 3)
}

func testTopologyWithDomainCounts(westCount, eastCount int) *controllerconfig.Topology {
	topology := testTopology()
	westPrefixes := make([]string, westCount)
	for index := range westPrefixes {
		westPrefixes[index] = fmt.Sprintf("10.0.%d.0/24", index)
	}
	eastPrefixes := make([]string, eastCount)
	for index := range eastPrefixes {
		eastPrefixes[index] = fmt.Sprintf("10.1.%d.0/24", index)
	}
	topology.Sites[0].LocalPrefixes = westPrefixes
	topology.Sites[1].LocalPrefixes = eastPrefixes
	topology.Domains = nil
	for index, prefix := range westPrefixes {
		domainID := fmt.Sprintf("west-domain-%d", index)
		if index == 0 {
			domainID = "west-domain"
		}
		topology.Domains = append(topology.Domains, controllerconfig.Domain{
			ID:                      domainID,
			SiteID:                  "west",
			SourcePrefix:            prefix,
			RouteTableID:            fmt.Sprintf("rtb-west-%d", index),
			GWLBESubnetID:           fmt.Sprintf("subnet-gwlbe-west-%d", index),
			RouteTableAssociationID: fmt.Sprintf("rtbassoc-gwlbe-west-%d", index),
			RemotePrefixes:          append([]string(nil), eastPrefixes...),
			PreferredOwner:          "west-a",
		})
	}
	for index, prefix := range eastPrefixes {
		domainID := fmt.Sprintf("east-domain-%d", index)
		if index == 0 {
			domainID = "east-domain"
		}
		topology.Domains = append(topology.Domains, controllerconfig.Domain{
			ID:                      domainID,
			SiteID:                  "east",
			SourcePrefix:            prefix,
			RouteTableID:            fmt.Sprintf("rtb-east-%d", index),
			GWLBESubnetID:           fmt.Sprintf("subnet-gwlbe-east-%d", index),
			RouteTableAssociationID: fmt.Sprintf("rtbassoc-gwlbe-east-%d", index),
			RemotePrefixes:          append([]string(nil), westPrefixes...),
			PreferredOwner:          "east-a",
		})
	}
	return topology
}

type schedulerRouteController struct {
	clock          store.Clock
	heldDomain     string
	blockContended <-chan struct{}
	mu             sync.Mutex
	snapshots      map[string]int
}

type advancingPublisher struct {
	*fakePublisher
	clock   *store.FakeClock
	latency time.Duration
}

func (p *advancingPublisher) PublishObservation(ctx context.Context, deploymentID string, observation *model.Observation) (*model.Observation, error) {
	published, err := p.fakePublisher.PublishObservation(ctx, deploymentID, observation)
	p.clock.Advance(p.latency)
	return published, err
}

func (c *schedulerRouteController) ValidateOwner(context.Context, model.DomainAuthority, model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	return awscontrol.OwnerValidation{ValidatedAt: c.clock.Now()}, nil
}

func (c *schedulerRouteController) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	c.mu.Lock()
	c.snapshots[authority.DomainID]++
	c.mu.Unlock()
	if authority.DomainID != c.heldDomain && c.blockContended != nil {
		select {
		case <-c.blockContended:
		case <-ctx.Done():
			return model.RouteSnapshot{}, ctx.Err()
		}
	}
	owner, found := authority.OwnerByStableNode(authority.PreferredOwner)
	if !found {
		return model.RouteSnapshot{}, errors.New("preferred owner missing")
	}
	snapshot := model.RouteSnapshot{RouteTableID: authority.RouteTableID, CapturedAt: c.clock.Now()}
	for _, prefix := range authority.RemotePrefixes {
		snapshot.Routes = append(snapshot.Routes, model.RouteSnapshotEntry{
			DestinationPrefix: prefix,
			TargetENIID:       owner.ENIID,
			State:             "active",
			Origin:            "CreateRoute",
		})
	}
	return snapshot, nil
}

func (c *schedulerRouteController) ReplaceAndWait(context.Context, model.DomainAuthority, string, string, string, time.Time) (awscontrol.ReplaceResult, error) {
	return awscontrol.ReplaceResult{}, errors.New("unexpected route mutation")
}

func (c *schedulerRouteController) snapshotCount(domainID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshots[domainID]
}
