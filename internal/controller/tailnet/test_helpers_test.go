package tailnet

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

var observerTestTime = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

type fakeLocalClient struct {
	mu          sync.Mutex
	status      *ipnstate.Status
	err         error
	statusFunc  func(context.Context) (*ipnstate.Status, error)
	calls       int
	sawDeadline bool
}

func (f *fakeLocalClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	f.mu.Lock()
	f.calls++
	_, f.sawDeadline = ctx.Deadline()
	statusFunc := f.statusFunc
	status := f.status
	err := f.err
	f.mu.Unlock()
	if statusFunc != nil {
		return statusFunc(ctx)
	}
	return status, err
}

func (f *fakeLocalClient) stats() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.sawDeadline
}

type fakeAdminClient struct {
	mu          sync.Mutex
	deviceList  []adminDevice
	err         error
	devicesFunc func(context.Context) ([]adminDevice, error)
	calls       int
	sawDeadline bool
}

func (f *fakeAdminClient) devices(ctx context.Context) ([]adminDevice, error) {
	f.mu.Lock()
	f.calls++
	_, f.sawDeadline = ctx.Deadline()
	devicesFunc := f.devicesFunc
	devices := f.deviceList
	err := f.err
	f.mu.Unlock()
	if devicesFunc != nil {
		return devicesFunc(ctx)
	}
	return devices, err
}

func (f *fakeAdminClient) stats() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.sawDeadline
}

type fakeEmbeddedNode struct {
	mu          sync.Mutex
	local       localStatusClient
	startErr    error
	startFunc   func(context.Context) (localStatusClient, error)
	closeErr    error
	startCalls  int
	closeCalls  int
	sawDeadline bool
}

func (f *fakeEmbeddedNode) start(ctx context.Context) (localStatusClient, error) {
	f.mu.Lock()
	f.startCalls++
	_, f.sawDeadline = ctx.Deadline()
	startFunc := f.startFunc
	local := f.local
	err := f.startErr
	f.mu.Unlock()
	if startFunc != nil {
		return startFunc(ctx)
	}
	return local, err
}

func (f *fakeEmbeddedNode) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	return f.closeErr
}

func (f *fakeEmbeddedNode) stats() (startCalls, closeCalls int, sawDeadline bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls, f.closeCalls, f.sawDeadline
}

func testOptions() Options {
	return Options{
		StartupTimeout:  200 * time.Millisecond,
		SnapshotTimeout: 200 * time.Millisecond,
		ObservationTTL:  time.Minute,
		PeerStaleAfter:  30 * time.Second,
		ContinuityGap:   1100 * time.Millisecond,
		InitialSequence: 40,
	}
}

func testAuthorities() []model.DomainAuthority {
	owners := []model.OwnerAuthority{
		{RouterID: "router-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
		{RouterID: "router-b", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
	}
	newAuthority := func(domainID, sourcePrefix, routeTable string) model.DomainAuthority {
		return model.DomainAuthority{
			TopologyHash:            strings.Repeat("a", 64),
			DeploymentID:            "deployment-a",
			DomainID:                domainID,
			SiteID:                  "site-a",
			VPCID:                   "vpc-a",
			Region:                  "us-west-2",
			SourcePrefix:            sourcePrefix,
			RouteTableID:            routeTable,
			GWLBESubnetID:           "subnet-gwlbe-" + domainID,
			RouteTableAssociationID: "rtbassoc-" + domainID,
			RemotePrefixes:          []string{"10.1.0.0/24"},
			PreferredOwner:          "node-a",
			Owners:                  append([]model.OwnerAuthority(nil), owners...),
		}
	}
	return []model.DomainAuthority{
		newAuthority("domain-b", "10.0.1.0/24", "rtb-b"),
		newAuthority("domain-a", "10.0.0.0/24", "rtb-a"),
	}
}

func testPlan(t *testing.T) *observationPlan {
	t.Helper()
	plan, err := buildObservationPlan("controller-a", "example.com", testAuthorities())
	if err != nil {
		t.Fatalf("buildObservationPlan() error = %v", err)
	}
	return plan
}

func validStatus() *ipnstate.Status {
	selfKey := key.NewNode().Public()
	return &ipnstate.Status{
		BackendState: "Running",
		HaveNodeKey:  true,
		Self: &ipnstate.PeerStatus{
			ID:        tailcfg.StableNodeID("observer-node-a"),
			PublicKey: selfKey,
			HostName:  "controller-a",
			Online:    true,
		},
		CurrentTailnet: &ipnstate.TailnetStatus{Name: "example.com"},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				ID:            tailcfg.StableNodeID("node-a"),
				Online:        true,
				PrimaryRoutes: routeView("10.0.1.0/24", "10.0.0.0/24"),
			},
			key.NewNode().Public(): {
				ID:     tailcfg.StableNodeID("node-b"),
				Online: true,
			},
		},
	}
}

func routeView(routes ...string) *views.Slice[netip.Prefix] {
	prefixes := make([]netip.Prefix, len(routes))
	for index, route := range routes {
		prefixes[index] = netip.MustParsePrefix(route)
	}
	view := views.SliceOf(prefixes)
	return &view
}

func rawRouteView(routes ...netip.Prefix) *views.Slice[netip.Prefix] {
	view := views.SliceOf(routes)
	return &view
}

func peerByID(status *ipnstate.Status, stableNodeID string) *ipnstate.PeerStatus {
	for _, peer := range status.Peer {
		if string(peer.ID) == stableNodeID {
			return peer
		}
	}
	return nil
}

func validAdminDevices() []adminDevice {
	routes := []string{"10.0.1.0/24", "10.0.0.0/24"}
	return []adminDevice{
		{
			nodeID:            "node-a",
			advertisedRoutes:  append([]string(nil), routes...),
			enabledRoutes:     append([]string(nil), routes...),
			advertisedPresent: true,
			enabledPresent:    true,
		},
		{
			nodeID:            "node-b",
			advertisedRoutes:  append([]string(nil), routes...),
			enabledRoutes:     append([]string(nil), routes...),
			advertisedPresent: true,
			enabledPresent:    true,
		},
	}
}

func newTestObserver(t *testing.T, local *fakeLocalClient, admin *fakeAdminClient) (*Observer, *fakeEmbeddedNode) {
	t.Helper()
	node := &fakeEmbeddedNode{local: local}
	observer, err := newStartedObserver(context.Background(), testPlan(t), testOptions(), node, admin, func() time.Time {
		return observerTestTime
	})
	if err != nil {
		t.Fatalf("newStartedObserver() error = %v", err)
	}
	return observer, node
}

func requireErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}
