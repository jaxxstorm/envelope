package tailnet

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/health"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestObserverSnapshotMapsAllDomainsAndSequences(t *testing.T) {
	local := &fakeLocalClient{status: validStatus()}
	admin := &fakeAdminClient{deviceList: validAdminDevices()}
	observer, node := newTestObserver(t, local, admin)
	t.Cleanup(func() { _ = observer.Close() })

	first, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("Snapshot().Validate() error = %v", err)
	}
	if first.ControllerID != "controller-a" || first.TopologyHash != strings.Repeat("a", 64) {
		t.Fatalf("Snapshot() identity = %q, %q", first.ControllerID, first.TopologyHash)
	}
	if first.Sequence != 41 {
		t.Fatalf("Snapshot() sequence = %d, want 41", first.Sequence)
	}
	if !first.CapturedAt.Equal(observerTestTime) || !first.ExpiresAt.Equal(observerTestTime.Add(time.Minute)) {
		t.Fatalf("Snapshot() times = %s to %s", first.CapturedAt, first.ExpiresAt)
	}
	if !first.BackendHealthy || len(first.Domains) != 2 {
		t.Fatalf("Snapshot() backend/domains = %t/%d", first.BackendHealthy, len(first.Domains))
	}
	wantRoutes := []string{"10.0.0.0/24", "10.0.1.0/24"}
	for _, domainID := range []string{"domain-a", "domain-b"} {
		domain, exists := first.Domains[domainID]
		if !exists {
			t.Fatalf("Snapshot() missing %q", domainID)
		}
		if domain.StableNodeID != "node-a" || !domain.SolePrimary || !domain.Online || domain.Expired || !domain.Healthy {
			t.Errorf("Snapshot() domain %q = %#v", domainID, domain)
		}
		if domain.OwnerSince == nil || !domain.OwnerSince.Equal(observerTestTime) || domain.OwnerChangeGeneration != 41 {
			t.Errorf("Snapshot() domain %q continuity = %v/%d", domainID, domain.OwnerSince, domain.OwnerChangeGeneration)
		}
		if !reflect.DeepEqual(domain.AdvertisedPrefixes, wantRoutes) || !reflect.DeepEqual(domain.EnabledPrefixes, wantRoutes) {
			t.Errorf("Snapshot() domain %q routes = %v/%v", domainID, domain.AdvertisedPrefixes, domain.EnabledPrefixes)
		}
	}

	firstDomain := first.Domains["domain-a"]
	firstDomain.AdvertisedPrefixes[0] = "192.0.2.0/24"
	first.Domains["domain-a"] = firstDomain
	second, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("second Snapshot() error = %v", err)
	}
	if second.Sequence != 42 || second.Domains["domain-a"].AdvertisedPrefixes[0] != wantRoutes[0] {
		t.Fatalf("second Snapshot() sequence/routes = %d/%v", second.Sequence, second.Domains["domain-a"].AdvertisedPrefixes)
	}

	if calls, deadline := local.stats(); calls != 2 || !deadline {
		t.Errorf("LocalClient calls/deadline = %d/%t", calls, deadline)
	}
	if calls, deadline := admin.stats(); calls != 2 || !deadline {
		t.Errorf("Admin calls/deadline = %d/%t", calls, deadline)
	}
	if starts, _, deadline := node.stats(); starts != 1 || !deadline {
		t.Errorf("node starts/deadline = %d/%t", starts, deadline)
	}
}

func TestObserverConcurrentSnapshotsHaveUniqueSequences(t *testing.T) {
	local := &fakeLocalClient{status: validStatus()}
	admin := &fakeAdminClient{deviceList: validAdminDevices()}
	observer, _ := newTestObserver(t, local, admin)
	t.Cleanup(func() { _ = observer.Close() })

	const count = 24
	sequences := make(chan uint64, count)
	errorsSeen := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			observation, err := observer.Snapshot(context.Background())
			if err != nil {
				errorsSeen <- err
				return
			}
			sequences <- observation.Sequence
		}()
	}
	wait.Wait()
	close(sequences)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("Snapshot() error = %v", err)
	}

	got := make([]int, 0, count)
	for sequence := range sequences {
		got = append(got, int(sequence))
	}
	sort.Ints(got)
	if len(got) != count {
		t.Fatalf("successful snapshots = %d, want %d", len(got), count)
	}
	for index, sequence := range got {
		if sequence != 41+index {
			t.Fatalf("sorted sequence %d = %d, want %d", index, sequence, 41+index)
		}
	}
}

func TestObserverConcurrentSnapshotsFollowCaptureOrder(t *testing.T) {
	type snapshotResult struct {
		observation *model.Observation
		err         error
	}

	var clockMu sync.Mutex
	now := observerTestTime
	clockNow := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	setNow := func(value time.Time) {
		clockMu.Lock()
		now = value
		clockMu.Unlock()
	}

	secondStatusEntered := make(chan struct{})
	var localMu sync.Mutex
	localCalls := 0
	local := &fakeLocalClient{statusFunc: func(context.Context) (*ipnstate.Status, error) {
		localMu.Lock()
		localCalls++
		if localCalls == 2 {
			close(secondStatusEntered)
		}
		localMu.Unlock()
		return validStatus(), nil
	}}

	firstAdminEntered := make(chan struct{})
	releaseFirstAdmin := make(chan struct{})
	var adminMu sync.Mutex
	adminCalls := 0
	admin := &fakeAdminClient{devicesFunc: func(ctx context.Context) ([]adminDevice, error) {
		adminMu.Lock()
		adminCalls++
		call := adminCalls
		adminMu.Unlock()
		if call == 1 {
			close(firstAdminEntered)
			select {
			case <-releaseFirstAdmin:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return validAdminDevices(), nil
	}}

	options := testOptions()
	options.SnapshotTimeout = 2 * time.Second
	node := &fakeEmbeddedNode{local: local}
	observer, err := newStartedObserver(context.Background(), testPlan(t), options, node, admin, clockNow)
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()

	firstResult := make(chan snapshotResult, 1)
	go func() {
		observation, snapshotErr := observer.Snapshot(context.Background())
		firstResult <- snapshotResult{observation: observation, err: snapshotErr}
	}()
	select {
	case <-firstAdminEntered:
	case <-time.After(time.Second):
		t.Fatal("first Snapshot() did not enter Admin API")
	}

	secondAt := observerTestTime.Add(time.Second)
	setNow(secondAt)
	secondStarted := make(chan struct{})
	secondResult := make(chan snapshotResult, 1)
	go func() {
		close(secondStarted)
		observation, snapshotErr := observer.Snapshot(context.Background())
		secondResult <- snapshotResult{observation: observation, err: snapshotErr}
	}()
	<-secondStarted
	select {
	case <-secondStatusEntered:
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirstAdmin)

	first := <-firstResult
	second := <-secondResult
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent Snapshot() errors = %v/%v", first.err, second.err)
	}
	if first.observation.Sequence != 41 || !first.observation.CapturedAt.Equal(observerTestTime) {
		t.Fatalf("first Snapshot() sequence/capture = %d/%s", first.observation.Sequence, first.observation.CapturedAt)
	}
	if second.observation.Sequence != 42 || !second.observation.CapturedAt.Equal(secondAt) {
		t.Fatalf("second Snapshot() sequence/capture = %d/%s", second.observation.Sequence, second.observation.CapturedAt)
	}
	secondDomain := second.observation.Domains["domain-a"]
	if secondDomain.OwnerSince == nil || !secondDomain.OwnerSince.Equal(observerTestTime) || secondDomain.OwnerChangeGeneration != 41 {
		t.Fatalf("second Snapshot() continuity = %v/%d", secondDomain.OwnerSince, secondDomain.OwnerChangeGeneration)
	}
}

func TestObserverMapsDifferentPrimaryOwnersPerDomain(t *testing.T) {
	status := validStatus()
	peerByID(status, "node-a").PrimaryRoutes = routeView("10.0.0.0/24")
	peerByID(status, "node-b").PrimaryRoutes = routeView("10.0.1.0/24")
	observer, _ := newTestObserver(t, &fakeLocalClient{status: status}, &fakeAdminClient{deviceList: validAdminDevices()})
	defer observer.Close()

	observation, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if observation.Domains["domain-a"].StableNodeID != "node-a" || observation.Domains["domain-b"].StableNodeID != "node-b" {
		t.Fatalf("Snapshot() owners = %q/%q", observation.Domains["domain-a"].StableNodeID, observation.Domains["domain-b"].StableNodeID)
	}
}

func TestObserverRejectsInvalidLocalStatus(t *testing.T) {
	secret := "fixture-local-status-secret"
	tests := []struct {
		name          string
		status        func() *ipnstate.Status
		want          error
		unhealthy     string
		healthyBeside string
	}{
		{
			name:   "nil status",
			status: func() *ipnstate.Status { return nil },
			want:   ErrMalformedStatus,
		},
		{
			name: "backend not running",
			status: func() *ipnstate.Status {
				status := validStatus()
				status.BackendState = "Starting"
				return status
			},
			want: ErrBackendUnhealthy,
		},
		{
			name: "redacted health condition",
			status: func() *ipnstate.Status {
				status := validStatus()
				status.Health = []string{secret}
				return status
			},
			want: ErrBackendUnhealthy,
		},
		{
			name: "missing primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").PrimaryRoutes = routeView("10.0.1.0/24")
				return status
			},
			want:          ErrPrimaryMissing,
			unhealthy:     "domain-a",
			healthyBeside: "domain-b",
		},
		{
			name: "duplicate primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-b").PrimaryRoutes = routeView("10.0.0.0/24")
				return status
			},
			want:          ErrPrimaryDuplicate,
			unhealthy:     "domain-a",
			healthyBeside: "domain-b",
		},
		{
			name: "unknown primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				status.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
					ID:            tailcfg.StableNodeID("node-unknown"),
					Online:        true,
					PrimaryRoutes: routeView("10.0.0.0/24"),
				}
				return status
			},
			want:          ErrPrimaryUnknown,
			unhealthy:     "domain-a",
			healthyBeside: "domain-b",
		},
		{
			name: "offline primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").Online = false
				return status
			},
			want:      ErrPeerUnavailable,
			unhealthy: "domain-a",
		},
		{
			name: "expired primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").Expired = true
				return status
			},
			want:      ErrPeerExpired,
			unhealthy: "domain-a",
		},
		{
			name: "expired primary key",
			status: func() *ipnstate.Status {
				status := validStatus()
				expiry := observerTestTime
				peerByID(status, "node-a").KeyExpiry = &expiry
				return status
			},
			want:      ErrPeerExpired,
			unhealthy: "domain-a",
		},
		{
			name: "stale primary",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").LastSeen = observerTestTime.Add(-time.Minute)
				return status
			},
			want:      ErrPeerStale,
			unhealthy: "domain-a",
		},
		{
			name: "future last seen",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").LastSeen = observerTestTime.Add(time.Second)
				return status
			},
			want:      ErrMalformedStatus,
			unhealthy: "domain-a",
		},
		{
			name: "nil peer",
			status: func() *ipnstate.Status {
				status := validStatus()
				status.Peer[key.NewNode().Public()] = nil
				return status
			},
			want: ErrMalformedStatus,
		},
		{
			name: "duplicate stable peer identity",
			status: func() *ipnstate.Status {
				status := validStatus()
				status.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{ID: tailcfg.StableNodeID("node-a"), Online: true}
				return status
			},
			want:      ErrMalformedStatus,
			unhealthy: "domain-a",
		},
		{
			name: "invalid primary prefix",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").PrimaryRoutes = rawRouteView(netip.Prefix{})
				return status
			},
			want: ErrMalformedStatus,
		},
		{
			name: "duplicate primary prefix entry",
			status: func() *ipnstate.Status {
				status := validStatus()
				peerByID(status, "node-a").PrimaryRoutes = routeView("10.0.0.0/24", "10.0.0.0/24", "10.0.1.0/24")
				return status
			},
			want: ErrMalformedStatus,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local := &fakeLocalClient{status: test.status()}
			admin := &fakeAdminClient{deviceList: validAdminDevices()}
			observer, _ := newTestObserver(t, local, admin)
			defer observer.Close()

			observation, err := observer.Snapshot(context.Background())
			if test.unhealthy != "" {
				if err != nil || observation == nil {
					t.Fatalf("Snapshot() = %#v, %v, want per-domain observation", observation, err)
				}
				if validationErr := observation.Validate(); validationErr != nil {
					t.Fatalf("Snapshot().Validate() error = %v", validationErr)
				}
				domain := observation.Domains[test.unhealthy]
				if domain.Healthy || domain.Error == nil || domain.Error.Code != model.ErrorObservationQuorum {
					t.Fatalf("Snapshot() unhealthy domain = %#v", domain)
				}
				if want := domainStateError(test.want, observerTestTime).Message; domain.Error.Message != want {
					t.Fatalf("Snapshot() domain error = %q, want %q", domain.Error.Message, want)
				}
				if test.healthyBeside != "" && !observation.Domains[test.healthyBeside].Healthy {
					t.Fatalf("Snapshot() unrelated domain = %#v, want healthy", observation.Domains[test.healthyBeside])
				}
				if calls, _ := admin.stats(); calls != 1 {
					t.Fatalf("Admin calls = %d, want 1", calls)
				}
				return
			}
			if observation != nil {
				t.Fatalf("Snapshot() observation = %#v, want nil", observation)
			}
			requireErrorIs(t, err, test.want)
			if strings.Contains(err.Error(), secret) {
				t.Fatal("Snapshot() returned a health value")
			}
			if calls, _ := admin.stats(); calls != 0 {
				t.Fatalf("Admin calls = %d, want 0 after rejected status", calls)
			}
			if observer.sequence != testOptions().InitialSequence {
				t.Fatalf("sequence advanced to %d after failed snapshot", observer.sequence)
			}
		})
	}
}

func TestObserverRejectsLocalStatusFailuresAndTimeouts(t *testing.T) {
	secret := "fixture-status-error-secret"
	t.Run("error is redacted", func(t *testing.T) {
		local := &fakeLocalClient{err: errors.New(secret)}
		observer, _ := newTestObserver(t, local, &fakeAdminClient{deviceList: validAdminDevices()})
		defer observer.Close()
		_, err := observer.Snapshot(context.Background())
		requireErrorIs(t, err, ErrStatusUnavailable)
		if strings.Contains(err.Error(), secret) {
			t.Fatal("Snapshot() returned LocalAPI error contents")
		}
	})

	t.Run("bounded timeout", func(t *testing.T) {
		local := &fakeLocalClient{statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			<-ctx.Done()
			return nil, errors.New(secret)
		}}
		observer, _ := newTestObserver(t, local, &fakeAdminClient{deviceList: validAdminDevices()})
		observer.options.SnapshotTimeout = 30 * time.Millisecond
		defer observer.Close()
		started := time.Now()
		_, err := observer.Snapshot(context.Background())
		requireErrorIs(t, err, ErrSnapshotTimeout)
		if time.Since(started) > time.Second || strings.Contains(err.Error(), secret) {
			t.Fatalf("Snapshot() was not bounded/redacted: %v", err)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		local := &fakeLocalClient{statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		observer, _ := newTestObserver(t, local, &fakeAdminClient{deviceList: validAdminDevices()})
		defer observer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := observer.Snapshot(ctx)
		requireErrorIs(t, err, context.Canceled)
	})
}

func TestObserverMapsAdminDeviceAndRouteFailuresToDomains(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*[]adminDevice)
		wantErr error
		global  bool
	}{
		{
			name:    "configured device missing",
			mutate:  func(devices *[]adminDevice) { *devices = (*devices)[1:] },
			wantErr: ErrAdminDeviceMissing,
		},
		{
			name:    "duplicate device identity",
			mutate:  func(devices *[]adminDevice) { *devices = append(*devices, (*devices)[0]) },
			wantErr: ErrMalformedAdminResponse,
		},
		{
			name:    "empty device identity",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].nodeID = "" },
			wantErr: ErrMalformedAdminResponse,
			global:  true,
		},
		{
			name:    "advertised route missing",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedRoutes = (*devices)[0].advertisedRoutes[:1] },
			wantErr: ErrRouteSetMismatch,
		},
		{
			name:    "enabled route missing",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].enabledRoutes = (*devices)[0].enabledRoutes[:1] },
			wantErr: ErrRouteSetMismatch,
		},
		{
			name: "extra route",
			mutate: func(devices *[]adminDevice) {
				(*devices)[0].advertisedRoutes = append((*devices)[0].advertisedRoutes, "192.0.2.0/24")
				(*devices)[0].enabledRoutes = append((*devices)[0].enabledRoutes, "192.0.2.0/24")
			},
			wantErr: ErrRouteSetMismatch,
		},
		{
			name:    "broader route",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedRoutes[0] = "10.0.0.0/16" },
			wantErr: ErrRouteSetMismatch,
		},
		{
			name:    "malformed route",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedRoutes[0] = "not-a-prefix" },
			wantErr: ErrMalformedAdminResponse,
		},
		{
			name:    "noncanonical route",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedRoutes[0] = "10.0.1.1/24" },
			wantErr: ErrMalformedAdminResponse,
		},
		{
			name:    "duplicate route",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedRoutes[1] = (*devices)[0].advertisedRoutes[0] },
			wantErr: ErrMalformedAdminResponse,
		},
		{
			name:    "route field omitted",
			mutate:  func(devices *[]adminDevice) { (*devices)[0].advertisedPresent = false },
			wantErr: ErrMalformedAdminResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			devices := validAdminDevices()
			test.mutate(&devices)
			observer, _ := newTestObserver(t, &fakeLocalClient{status: validStatus()}, &fakeAdminClient{deviceList: devices})
			defer observer.Close()
			observation, err := observer.Snapshot(context.Background())
			if test.global {
				if observation != nil {
					t.Fatalf("Snapshot() observation = %#v, want nil", observation)
				}
				requireErrorIs(t, err, test.wantErr)
				if observer.sequence != testOptions().InitialSequence {
					t.Fatalf("sequence advanced to %d after failed snapshot", observer.sequence)
				}
				return
			}
			if err != nil || observation == nil {
				t.Fatalf("Snapshot() = %#v, %v, want per-domain observation", observation, err)
			}
			if validationErr := observation.Validate(); validationErr != nil {
				t.Fatalf("Snapshot().Validate() error = %v", validationErr)
			}
			domain := observation.Domains["domain-a"]
			if domain.Healthy || domain.Error == nil || domain.Error.Message != domainStateError(test.wantErr, observerTestTime).Message {
				t.Fatalf("Snapshot() domain = %#v", domain)
			}
		})
	}
}

func TestObserverInvalidCandidateRoutesDegradeEverySiteDomain(t *testing.T) {
	secret := "fixture-invalid-admin-route-secret"
	status := validStatus()
	peerByID(status, "node-a").PrimaryRoutes = routeView("10.0.0.0/24")
	peerByID(status, "node-b").PrimaryRoutes = routeView("10.0.1.0/24")
	devices := validAdminDevices()
	devices[0].advertisedRoutes[0] = secret
	observer, _ := newTestObserver(t, &fakeLocalClient{status: status}, &fakeAdminClient{deviceList: devices})
	defer observer.Close()

	observation, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("Snapshot().Validate() error = %v", err)
	}
	for _, domainID := range []string{"domain-a", "domain-b"} {
		domain := observation.Domains[domainID]
		if domain.Healthy || domain.Error == nil || domain.OwnerSince != nil {
			t.Fatalf("domain %q retained health with an invalid site candidate: %#v", domainID, domain)
		}
		if strings.Contains(domain.Error.Message, secret) || strings.Contains(domain.Error.Message, "node-a") || len(domain.Error.Message) > 1024 {
			t.Fatalf("domain %q error was not bounded and redacted: %q", domainID, domain.Error.Message)
		}
	}
}

func TestObserverRequiresValidAdminRoutesForEveryCandidateOwner(t *testing.T) {
	t.Run("both candidates valid", func(t *testing.T) {
		observer, _ := newTestObserver(t, &fakeLocalClient{status: validStatus()}, &fakeAdminClient{deviceList: validAdminDevices()})
		defer observer.Close()

		observation, err := observer.Snapshot(context.Background())
		if err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
		for _, domainID := range []string{"domain-a", "domain-b"} {
			if domain := observation.Domains[domainID]; !domain.Healthy || domain.Error != nil {
				t.Fatalf("domain %q = %#v, want healthy", domainID, domain)
			}
		}
	})

	standbyTests := []struct {
		name    string
		mutate  func(*[]adminDevice)
		wantErr error
	}{
		{
			name: "route mismatch",
			mutate: func(devices *[]adminDevice) {
				(*devices)[1].enabledRoutes = (*devices)[1].enabledRoutes[:1]
			},
			wantErr: ErrRouteSetMismatch,
		},
		{
			name: "malformed routes",
			mutate: func(devices *[]adminDevice) {
				(*devices)[1].advertisedRoutes[0] = "not-a-prefix"
			},
			wantErr: ErrMalformedAdminResponse,
		},
		{
			name: "device missing",
			mutate: func(devices *[]adminDevice) {
				*devices = (*devices)[:1]
			},
			wantErr: ErrAdminDeviceMissing,
		},
	}
	for _, test := range standbyTests {
		t.Run("selected healthy standby "+test.name, func(t *testing.T) {
			status := validStatus()
			devices := validAdminDevices()
			test.mutate(&devices)
			observer, _ := newTestObserver(t, &fakeLocalClient{status: status}, &fakeAdminClient{deviceList: devices})
			defer observer.Close()

			selected, err := observer.Snapshot(context.Background())
			if err != nil {
				t.Fatalf("selected-owner Snapshot() error = %v", err)
			}
			for _, domainID := range []string{"domain-a", "domain-b"} {
				domain := selected.Domains[domainID]
				if domain.StableNodeID != "node-a" || domain.Healthy || domain.Error == nil || domain.Error.Message != domainStateError(test.wantErr, observerTestTime).Message {
					t.Fatalf("domain %q with invalid standby = %#v", domainID, domain)
				}
				if strings.Contains(domain.Error.Message, "node-a") || strings.Contains(domain.Error.Message, "node-b") {
					t.Fatalf("domain %q error leaked a stable ID: %q", domainID, domain.Error.Message)
				}
			}

			peerByID(status, "node-a").PrimaryRoutes = nil
			peerByID(status, "node-b").PrimaryRoutes = routeView("10.0.0.0/24", "10.0.1.0/24")
			standbySelected, err := observer.Snapshot(context.Background())
			if err != nil {
				t.Fatalf("standby-owner Snapshot() error = %v", err)
			}
			for _, authority := range testAuthorities() {
				domain := standbySelected.Domains[authority.DomainID]
				if domain.StableNodeID != "node-b" || domain.Healthy || domain.Error == nil {
					t.Fatalf("selected invalid standby domain %q = %#v", authority.DomainID, domain)
				}
				result := health.Evaluate(observerTestTime, authority, []model.Observation{*standbySelected}, health.QuorumPolicy{
					AllowedControllerIDs: []string{"controller-a"},
					Quorum:               1,
					Freshness:            time.Minute,
				})
				if result.Consensus != nil || result.Reason != health.ReasonUnhealthyOwner {
					t.Fatalf("invalid standby became eligible for domain %q: %+v", authority.DomainID, result)
				}
			}
		})
	}
}

func TestObserverCarriesOwnerContinuityAcrossOverwrittenFlap(t *testing.T) {
	status := validStatus()
	setPrimaryOwner := func(stableNodeID string) {
		peerByID(status, "node-a").PrimaryRoutes = nil
		peerByID(status, "node-b").PrimaryRoutes = nil
		peerByID(status, stableNodeID).PrimaryRoutes = routeView("10.0.0.0/24", "10.0.1.0/24")
	}
	setPrimaryOwner("node-b")
	now := observerTestTime
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: status}}
	observer, err := newStartedObserver(context.Background(), testPlan(t), testOptions(), node, &fakeAdminClient{deviceList: validAdminDevices()}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()

	first, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first Snapshot() error = %v", err)
	}
	firstDomain := first.Domains["domain-a"]
	if firstDomain.OwnerSince == nil || !firstDomain.OwnerSince.Equal(now) || firstDomain.OwnerChangeGeneration != 41 {
		t.Fatalf("first continuity = %v/%d", firstDomain.OwnerSince, firstDomain.OwnerChangeGeneration)
	}

	now = now.Add(5 * time.Second)
	setPrimaryOwner("node-a")
	intermediate, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("intermediate Snapshot() error = %v", err)
	}
	if got := intermediate.Domains["domain-a"].OwnerChangeGeneration; got != 42 {
		t.Fatalf("intermediate owner generation = %d, want 42", got)
	}

	now = now.Add(5 * time.Second)
	setPrimaryOwner("node-b")
	latest, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("latest Snapshot() error = %v", err)
	}
	latestDomain := latest.Domains["domain-a"]
	if latestDomain.StableNodeID != firstDomain.StableNodeID || latestDomain.OwnerSince == nil || !latestDomain.OwnerSince.Equal(now) || latestDomain.OwnerChangeGeneration != 43 {
		t.Fatalf("latest continuity after B -> A -> B = %#v", latestDomain)
	}
}

func TestObserverResetsOwnerContinuityJustAfterConfiguredCaptureGap(t *testing.T) {
	options := testOptions()
	options.ObservationTTL = time.Minute
	options.PeerStaleAfter = time.Minute
	options.ContinuityGap = 10 * time.Second
	now := observerTestTime
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: validStatus()}}
	observer, err := newStartedObserver(context.Background(), testPlan(t), options, node, &fakeAdminClient{deviceList: validAdminDevices()}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()

	first, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first Snapshot() error = %v", err)
	}
	now = now.Add(options.ContinuityGap)
	atBoundary, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("boundary Snapshot() error = %v", err)
	}
	boundaryDomain := atBoundary.Domains["domain-a"]
	if boundaryDomain.OwnerSince == nil || !boundaryDomain.OwnerSince.Equal(first.CapturedAt) || boundaryDomain.OwnerChangeGeneration != first.Sequence {
		t.Fatalf("boundary Snapshot() continuity = %v/%d", boundaryDomain.OwnerSince, boundaryDomain.OwnerChangeGeneration)
	}

	now = now.Add(options.ContinuityGap + time.Nanosecond)
	afterGap, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("post-gap Snapshot() error = %v", err)
	}
	for _, domainID := range []string{"domain-a", "domain-b"} {
		domain := afterGap.Domains[domainID]
		if domain.OwnerSince == nil || !domain.OwnerSince.Equal(afterGap.CapturedAt) || domain.OwnerChangeGeneration != afterGap.Sequence {
			t.Fatalf("post-gap Snapshot() domain %q continuity = %v/%d", domainID, domain.OwnerSince, domain.OwnerChangeGeneration)
		}
	}
}

func TestObserverUsesLocalStatusCaptureTimeAcrossDelayedAdminCall(t *testing.T) {
	options := testOptions()
	statusAt := observerTestTime
	postAdminAt := statusAt.Add(options.ObservationTTL + time.Second)
	now := statusAt
	status := validStatus()
	peerByID(status, "node-a").LastSeen = statusAt
	admin := &fakeAdminClient{devicesFunc: func(context.Context) ([]adminDevice, error) {
		now = postAdminAt
		return validAdminDevices(), nil
	}}
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: status}}
	observer, err := newStartedObserver(context.Background(), testPlan(t), options, node, admin, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()

	observation, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if !observation.CapturedAt.Equal(statusAt) || !observation.ExpiresAt.Equal(statusAt.Add(options.ObservationTTL)) {
		t.Fatalf("Snapshot() times = %s to %s, want status capture %s", observation.CapturedAt, observation.ExpiresAt, statusAt)
	}
	if !observation.ExpiresAt.Before(postAdminAt) {
		t.Fatalf("Snapshot() expiry = %s, want before post-Admin time %s", observation.ExpiresAt, postAdminAt)
	}
	for domainID, domain := range observation.Domains {
		if !domain.Healthy || domain.OwnerSince == nil || !domain.OwnerSince.Equal(statusAt) {
			t.Fatalf("Snapshot() domain %q = %#v", domainID, domain)
		}
	}
}

func TestObserverRejectsUnexpectedSelfAndTailnetIdentity(t *testing.T) {
	secret := "fixture-unexpected-tailnet-secret"
	tests := []struct {
		name   string
		mutate func(*ipnstate.Status)
		want   error
	}{
		{name: "node key flag absent", mutate: func(status *ipnstate.Status) { status.HaveNodeKey = false }, want: ErrObserverIdentity},
		{name: "self absent", mutate: func(status *ipnstate.Status) { status.Self = nil }, want: ErrObserverIdentity},
		{name: "self node key absent", mutate: func(status *ipnstate.Status) { status.Self.PublicKey = key.NodePublic{} }, want: ErrObserverIdentity},
		{name: "self stable identity absent", mutate: func(status *ipnstate.Status) { status.Self.ID = "" }, want: ErrObserverIdentity},
		{name: "unexpected hostname", mutate: func(status *ipnstate.Status) { status.Self.HostName = secret }, want: ErrObserverIdentity},
		{name: "self offline", mutate: func(status *ipnstate.Status) { status.Self.Online = false }, want: ErrObserverUnavailable},
		{name: "self expired", mutate: func(status *ipnstate.Status) { status.Self.Expired = true }, want: ErrObserverExpired},
		{name: "self key expired", mutate: func(status *ipnstate.Status) {
			expiry := observerTestTime
			status.Self.KeyExpiry = &expiry
		}, want: ErrObserverExpired},
		{name: "current Tailnet absent", mutate: func(status *ipnstate.Status) { status.CurrentTailnet = nil }, want: ErrTailnetMismatch},
		{name: "unexpected Tailnet", mutate: func(status *ipnstate.Status) { status.CurrentTailnet.Name = secret }, want: ErrTailnetMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := validStatus()
			test.mutate(status)
			admin := &fakeAdminClient{deviceList: validAdminDevices()}
			observer, _ := newTestObserver(t, &fakeLocalClient{status: status}, admin)
			defer observer.Close()
			observation, err := observer.Snapshot(context.Background())
			if observation != nil {
				t.Fatalf("Snapshot() observation = %#v, want nil", observation)
			}
			requireErrorIs(t, err, test.want)
			if strings.Contains(err.Error(), secret) {
				t.Fatal("Snapshot() leaked unexpected identity")
			}
			if calls, _ := admin.stats(); calls != 0 {
				t.Fatalf("Admin calls = %d, want 0", calls)
			}
		})
	}
}

func TestObserverAdminErrorsAreRedacted(t *testing.T) {
	secret := "fixture-admin-error-secret"
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "transport error", err: errors.New(secret), want: ErrAdminUnavailable},
		{name: "malformed response", err: errors.Join(ErrMalformedAdminResponse, errors.New(secret)), want: ErrMalformedAdminResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer, _ := newTestObserver(t, &fakeLocalClient{status: validStatus()}, &fakeAdminClient{err: test.err})
			defer observer.Close()
			_, err := observer.Snapshot(context.Background())
			requireErrorIs(t, err, test.want)
			if strings.Contains(err.Error(), secret) {
				t.Fatal("Snapshot() returned Admin API error contents")
			}
		})
	}
}

func TestObserverAdminCallIsBounded(t *testing.T) {
	secret := "fixture-admin-timeout-secret"
	admin := &fakeAdminClient{devicesFunc: func(ctx context.Context) ([]adminDevice, error) {
		<-ctx.Done()
		return nil, errors.New(secret)
	}}
	observer, _ := newTestObserver(t, &fakeLocalClient{status: validStatus()}, admin)
	observer.options.SnapshotTimeout = 30 * time.Millisecond
	defer observer.Close()
	started := time.Now()
	_, err := observer.Snapshot(context.Background())
	requireErrorIs(t, err, ErrSnapshotTimeout)
	if time.Since(started) > time.Second || strings.Contains(err.Error(), secret) {
		t.Fatalf("Snapshot() Admin call was not bounded/redacted: %v", err)
	}
}

func TestObserverIgnoresUnconfiguredAdminDevices(t *testing.T) {
	devices := validAdminDevices()
	devices = append(devices, adminDevice{
		nodeID:            "unconfigured-node",
		advertisedPresent: true,
		enabledPresent:    true,
	})
	observer, _ := newTestObserver(t, &fakeLocalClient{status: validStatus()}, &fakeAdminClient{deviceList: devices})
	defer observer.Close()
	if _, err := observer.Snapshot(context.Background()); err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
}

func TestObserverSequenceExhaustion(t *testing.T) {
	options := testOptions()
	options.InitialSequence = math.MaxUint64 - 1
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: validStatus()}}
	observer, err := newStartedObserver(context.Background(), testPlan(t), options, node, &fakeAdminClient{deviceList: validAdminDevices()}, func() time.Time { return observerTestTime })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	defer observer.Close()
	observation, err := observer.Snapshot(context.Background())
	if err != nil || observation.Sequence != math.MaxUint64 {
		t.Fatalf("first Snapshot() = sequence %d, error %v", observation.Sequence, err)
	}
	if observation, err = observer.Snapshot(context.Background()); observation != nil || !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("second Snapshot() = %#v, %v", observation, err)
	}
}

func TestBuildObservationPlanRejectsInconsistentAuthority(t *testing.T) {
	tests := []struct {
		name         string
		controllerID string
		mutate       func(*[]model.DomainAuthority)
	}{
		{name: "missing authority", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) { *authorities = nil }},
		{name: "invalid controller", controllerID: " controller-a", mutate: func(*[]model.DomainAuthority) {}},
		{name: "different topology", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) { (*authorities)[1].TopologyHash = strings.Repeat("b", 64) }},
		{name: "different deployment", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) { (*authorities)[1].DeploymentID = "deployment-b" }},
		{name: "duplicate domain", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) { (*authorities)[1].DomainID = (*authorities)[0].DomainID }},
		{name: "duplicate source", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) {
			(*authorities)[1].SourcePrefix = (*authorities)[0].SourcePrefix
		}},
		{name: "inconsistent site owners", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) {
			owner := &(*authorities)[1].Owners[1]
			owner.RouterID = "router-c"
			owner.StableNodeID = "node-c"
			owner.InstanceID = "i-c"
			owner.ENIID = "eni-c"
		}},
		{name: "inconsistent node metadata", controllerID: "controller-a", mutate: func(authorities *[]model.DomainAuthority) { (*authorities)[1].Owners[0].ENIID = "eni-other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorities := testAuthorities()
			test.mutate(&authorities)
			plan, err := buildObservationPlan(test.controllerID, "example.com", authorities)
			if plan != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("buildObservationPlan() = %#v, %v", plan, err)
			}
		})
	}
	if plan, err := buildObservationPlan("controller-a", " example.com", testAuthorities()); plan != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("buildObservationPlan(invalid Tailnet) = %#v, %v", plan, err)
	}
}

func TestOptionsValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "zero startup", mutate: func(options *Options) { options.StartupTimeout = 0 }},
		{name: "zero snapshot", mutate: func(options *Options) { options.SnapshotTimeout = 0 }},
		{name: "zero expiry", mutate: func(options *Options) { options.ObservationTTL = 0 }},
		{name: "zero peer freshness", mutate: func(options *Options) { options.PeerStaleAfter = 0 }},
		{name: "zero continuity gap", mutate: func(options *Options) { options.ContinuityGap = 0 }},
		{name: "continuity reaches expiry", mutate: func(options *Options) { options.ContinuityGap = options.ObservationTTL }},
		{name: "unbounded duration", mutate: func(options *Options) { options.StartupTimeout = maxBoundedDuration + time.Nanosecond }},
		{name: "exhausted sequence", mutate: func(options *Options) { options.InitialSequence = math.MaxUint64 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := testOptions()
			test.mutate(&options)
			requireErrorIs(t, options.validate(), ErrInvalidConfiguration)
		})
	}
}

func TestObserverStartupIsBoundedAndRedacted(t *testing.T) {
	secret := "fixture-startup-secret"
	tests := []struct {
		name      string
		startFunc func(context.Context) (localStatusClient, error)
		startErr  error
		want      error
	}{
		{
			name: "timeout",
			startFunc: func(ctx context.Context) (localStatusClient, error) {
				<-ctx.Done()
				return nil, errors.New(secret)
			},
			want: ErrStartupTimeout,
		},
		{name: "startup failure", startErr: errors.New(secret), want: ErrStartup},
		{name: "nil client", want: ErrStartup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := &fakeEmbeddedNode{startFunc: test.startFunc, startErr: test.startErr}
			options := testOptions()
			options.StartupTimeout = 30 * time.Millisecond
			started := time.Now()
			observer, err := newStartedObserver(context.Background(), testPlan(t), options, node, &fakeAdminClient{}, func() time.Time { return observerTestTime })
			if observer != nil {
				t.Fatalf("newStartedObserver() = %#v, want nil", observer)
			}
			requireErrorIs(t, err, test.want)
			if strings.Contains(err.Error(), secret) || time.Since(started) > time.Second {
				t.Fatalf("newStartedObserver() was not bounded/redacted: %v", err)
			}
			starts, closes, deadline := node.stats()
			if starts != 1 || closes != 1 || !deadline {
				t.Fatalf("node starts/closes/deadline = %d/%d/%t", starts, closes, deadline)
			}
		})
	}
}

func TestObserverCloseCancelsSnapshotAndIsIdempotent(t *testing.T) {
	entered := make(chan struct{})
	local := &fakeLocalClient{statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	node := &fakeEmbeddedNode{local: local}
	observer, err := newStartedObserver(context.Background(), testPlan(t), testOptions(), node, &fakeAdminClient{}, func() time.Time { return observerTestTime })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}

	snapshotErr := make(chan error, 1)
	go func() {
		_, err := observer.Snapshot(context.Background())
		snapshotErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Snapshot() did not enter LocalAPI")
	}
	if err := observer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-snapshotErr:
		requireErrorIs(t, err, ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close() did not release Snapshot()")
	}
	if err := observer.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := observer.Snapshot(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Snapshot() after Close error = %v", err)
	}
	_, closes, _ := node.stats()
	if closes != 1 {
		t.Fatalf("node close calls = %d, want 1", closes)
	}
}

func TestObserverCloseErrorIsRedacted(t *testing.T) {
	secret := "fixture-close-secret"
	node := &fakeEmbeddedNode{local: &fakeLocalClient{status: validStatus()}, closeErr: errors.New(secret)}
	observer, err := newStartedObserver(context.Background(), testPlan(t), testOptions(), node, &fakeAdminClient{deviceList: validAdminDevices()}, func() time.Time { return observerTestTime })
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	err = observer.Close()
	requireErrorIs(t, err, ErrClose)
	if strings.Contains(err.Error(), secret) {
		t.Fatal("Close() returned embedded node error contents")
	}
	if err := observer.Close(); !errors.Is(err, ErrClose) {
		t.Fatalf("second Close() error = %v", err)
	}
}
