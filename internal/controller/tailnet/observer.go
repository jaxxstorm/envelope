// Package tailnet provides a read-only Tailscale observer for the standalone
// production controller. It does not expose router or Tailnet mutation.
package tailnet

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"tailscale.com/ipn/ipnstate"
)

var (
	ErrInvalidConfiguration   = errors.New("tailnet observer configuration is invalid")
	ErrStateDirectory         = errors.New("tailnet observer state directory is unavailable")
	ErrStartup                = errors.New("tailnet observer startup failed")
	ErrStartupTimeout         = errors.New("tailnet observer startup timed out")
	ErrClosed                 = errors.New("tailnet observer is closed")
	ErrClose                  = errors.New("tailnet observer shutdown failed")
	ErrSnapshotTimeout        = errors.New("tailnet observation timed out")
	ErrStatusUnavailable      = errors.New("tailnet local status is unavailable")
	ErrBackendUnhealthy       = errors.New("tailnet backend is unhealthy")
	ErrMalformedStatus        = errors.New("tailnet local status is malformed")
	ErrObserverIdentity       = errors.New("tailnet observer identity does not match configuration")
	ErrObserverUnavailable    = errors.New("tailnet observer self node is offline")
	ErrObserverExpired        = errors.New("tailnet observer self node is expired")
	ErrTailnetMismatch        = errors.New("tailnet observer is connected to the wrong Tailnet")
	ErrPrimaryMissing         = errors.New("tailnet primary owner is missing")
	ErrPrimaryDuplicate       = errors.New("tailnet primary owner is duplicated")
	ErrPrimaryUnknown         = errors.New("tailnet primary owner is not configured")
	ErrPeerUnavailable        = errors.New("tailnet primary peer is offline")
	ErrPeerStale              = errors.New("tailnet primary peer is stale")
	ErrPeerExpired            = errors.New("tailnet primary peer is expired")
	ErrAdminUnavailable       = errors.New("Tailscale Admin API is unavailable")
	ErrMalformedAdminResponse = errors.New("Tailscale Admin API response is malformed")
	ErrAdminDeviceMissing     = errors.New("configured Tailscale device is missing")
	ErrRouteSetMismatch       = errors.New("configured Tailscale device route set does not match authority")
	ErrSequenceExhausted      = errors.New("tailnet observation sequence is exhausted")
	ErrInvalidObservation     = errors.New("tailnet observation failed validation")
)

const (
	maxBoundedDuration = 24 * time.Hour
	maxDomains         = 4096
	maxPeers           = 16384
	maxRoutesPerDevice = 4096
)

// Options supplies the explicit bounds and freshness policy for an Observer.
// InitialSequence is the last sequence already used by this controller ID.
type Options struct {
	StartupTimeout  time.Duration
	SnapshotTimeout time.Duration
	ObservationTTL  time.Duration
	PeerStaleAfter  time.Duration
	// ContinuityGap is the largest interval between successful captures that
	// may retain an owner's uninterrupted-since evidence.
	ContinuityGap   time.Duration
	InitialSequence uint64
}

type localStatusClient interface {
	Status(context.Context) (*ipnstate.Status, error)
}

type embeddedNode interface {
	start(context.Context) (localStatusClient, error)
	close() error
}

type adminDeviceClient interface {
	devices(context.Context) ([]adminDevice, error)
}

type domainPlan struct {
	id           string
	sourcePrefix string
	owners       map[string]struct{}
	ownerIDs     []string
}

type observationPlan struct {
	controllerID   string
	tailnetName    string
	topologyHash   string
	domains        []domainPlan
	expectedRoutes map[string][]string
}

type primaryPeer struct {
	stableNodeID string
	online       bool
	expired      bool
	lastSeen     time.Time
	keyExpiry    *time.Time
}

type primarySelection struct {
	peer primaryPeer
	sole bool
	err  error
}

type ownerContinuity struct {
	owner       string
	since       time.Time
	generation  uint64
	lastCapture time.Time
}

// Observer owns one embedded observer node and creates complete Tailnet
// observations. It is safe to call Snapshot and Close concurrently.
type Observer struct {
	plan           *observationPlan
	options        Options
	node           embeddedNode
	local          localStatusClient
	admin          adminDeviceClient
	now            func() time.Time
	lifetime       context.Context
	cancelLifetime context.CancelFunc

	mu           sync.Mutex
	closed       bool
	closeDone    chan struct{}
	closeErr     error
	inFlight     sync.WaitGroup
	snapshotGate chan struct{}

	sequenceMu sync.Mutex
	sequence   uint64
	continuity map[string]ownerContinuity
}

func (o Options) validate() error {
	for _, value := range []time.Duration{o.StartupTimeout, o.SnapshotTimeout, o.ObservationTTL, o.PeerStaleAfter, o.ContinuityGap} {
		if value <= 0 || value > maxBoundedDuration {
			return ErrInvalidConfiguration
		}
	}
	if o.InitialSequence == math.MaxUint64 {
		return ErrInvalidConfiguration
	}
	if o.ContinuityGap >= o.ObservationTTL {
		return ErrInvalidConfiguration
	}
	return nil
}

func buildObservationPlan(controllerID, tailnetName string, authorities []model.DomainAuthority) (*observationPlan, error) {
	if !validIdentifier(controllerID) || !validIdentifier(tailnetName) || len(authorities) == 0 || len(authorities) > maxDomains {
		return nil, ErrInvalidConfiguration
	}

	plan := &observationPlan{controllerID: controllerID, tailnetName: tailnetName}
	domainIDs := make(map[string]struct{}, len(authorities))
	sourcePrefixes := make(map[string]struct{}, len(authorities))
	sitePrefixes := make(map[string]map[string]struct{})
	siteOwners := make(map[string]map[string]struct{})
	nodeSites := make(map[string]string)
	nodeAuthorities := make(map[string]model.OwnerAuthority)
	deploymentID := ""

	for index := range authorities {
		authority := authorities[index]
		if err := authority.Validate(); err != nil {
			return nil, ErrInvalidConfiguration
		}
		if index == 0 {
			plan.topologyHash = authority.TopologyHash
			deploymentID = authority.DeploymentID
		} else if authority.TopologyHash != plan.topologyHash || authority.DeploymentID != deploymentID {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := domainIDs[authority.DomainID]; exists {
			return nil, ErrInvalidConfiguration
		}
		domainIDs[authority.DomainID] = struct{}{}
		if _, exists := sourcePrefixes[authority.SourcePrefix]; exists {
			return nil, ErrInvalidConfiguration
		}
		sourcePrefixes[authority.SourcePrefix] = struct{}{}

		prefixes := sitePrefixes[authority.SiteID]
		if prefixes == nil {
			prefixes = make(map[string]struct{})
			sitePrefixes[authority.SiteID] = prefixes
		}
		prefixes[authority.SourcePrefix] = struct{}{}

		owners := make(map[string]struct{}, len(authority.Owners))
		ownerIDs := make([]string, 0, len(authority.Owners))
		for _, owner := range authority.Owners {
			owners[owner.StableNodeID] = struct{}{}
			ownerIDs = append(ownerIDs, owner.StableNodeID)
			if site, exists := nodeSites[owner.StableNodeID]; exists && site != authority.SiteID {
				return nil, ErrInvalidConfiguration
			}
			nodeSites[owner.StableNodeID] = authority.SiteID
			if previous, exists := nodeAuthorities[owner.StableNodeID]; exists && previous != owner {
				return nil, ErrInvalidConfiguration
			}
			nodeAuthorities[owner.StableNodeID] = owner
		}
		sort.Strings(ownerIDs)
		if expected, exists := siteOwners[authority.SiteID]; exists {
			if !sameSet(expected, owners) {
				return nil, ErrInvalidConfiguration
			}
		} else {
			siteOwners[authority.SiteID] = owners
		}

		plan.domains = append(plan.domains, domainPlan{
			id:           authority.DomainID,
			sourcePrefix: authority.SourcePrefix,
			owners:       owners,
			ownerIDs:     ownerIDs,
		})
	}

	if len(nodeSites) > maxPeers {
		return nil, ErrInvalidConfiguration
	}
	plan.expectedRoutes = make(map[string][]string, len(nodeSites))
	for stableNodeID, siteID := range nodeSites {
		prefixSet := sitePrefixes[siteID]
		prefixes := make([]string, 0, len(prefixSet))
		for prefix := range prefixSet {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		plan.expectedRoutes[stableNodeID] = prefixes
	}
	sort.Slice(plan.domains, func(i, j int) bool { return plan.domains[i].id < plan.domains[j].id })
	return plan, nil
}

func newStartedObserver(
	ctx context.Context,
	plan *observationPlan,
	options Options,
	node embeddedNode,
	admin adminDeviceClient,
	now func() time.Time,
) (*Observer, error) {
	if ctx == nil || plan == nil || node == nil || admin == nil || now == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := options.validate(); err != nil {
		return nil, err
	}

	startupCtx, cancel := context.WithTimeout(ctx, options.StartupTimeout)
	local, err := node.start(startupCtx)
	cancel()
	if err != nil || local == nil {
		_ = node.close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if startupCtx.Err() == context.DeadlineExceeded {
			return nil, ErrStartupTimeout
		}
		return nil, ErrStartup
	}

	lifetime, cancelLifetime := context.WithCancel(context.Background())
	return &Observer{
		plan:           plan,
		options:        options,
		node:           node,
		local:          local,
		admin:          admin,
		now:            now,
		lifetime:       lifetime,
		cancelLifetime: cancelLifetime,
		closeDone:      make(chan struct{}),
		snapshotGate:   make(chan struct{}, 1),
		sequence:       options.InitialSequence,
		continuity:     make(map[string]ownerContinuity, len(plan.domains)),
	}, nil
}

// Snapshot obtains one bounded LocalAPI and Admin API view and returns one
// validated observation containing every configured authority domain.
func (o *Observer) Snapshot(ctx context.Context) (*model.Observation, error) {
	if o == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := o.beginSnapshot(); err != nil {
		return nil, err
	}
	defer o.inFlight.Done()

	callCtx, cancel := context.WithTimeout(ctx, o.options.SnapshotTimeout)
	stopCloseCancellation := context.AfterFunc(o.lifetime, cancel)
	defer func() {
		stopCloseCancellation()
		cancel()
	}()
	if o.lifetime.Err() != nil {
		cancel()
	}
	select {
	case o.snapshotGate <- struct{}{}:
		defer func() { <-o.snapshotGate }()
	case <-callCtx.Done():
		return nil, o.snapshotCallError(ctx, callCtx, ErrSnapshotTimeout)
	}
	completed := false
	defer func() {
		if !completed {
			o.resetContinuity()
		}
	}()

	status, err := o.local.Status(callCtx)
	if err != nil {
		return nil, o.snapshotCallError(ctx, callCtx, ErrStatusUnavailable)
	}
	statusAt := o.now().UTC()
	if err := validateBackend(status, o.plan, statusAt); err != nil {
		return nil, err
	}
	primaries, err := selectPrimaryPeers(status, o.plan, statusAt, o.options.PeerStaleAfter)
	if err != nil {
		return nil, err
	}

	devices, err := o.admin.devices(callCtx)
	if err != nil {
		if errors.Is(err, ErrMalformedAdminResponse) {
			return nil, ErrMalformedAdminResponse
		}
		return nil, o.snapshotCallError(ctx, callCtx, ErrAdminUnavailable)
	}
	routes, err := validateAdminDevices(devices, o.plan)
	if err != nil {
		return nil, err
	}
	if err := callCtx.Err(); err != nil {
		return nil, o.snapshotCallError(ctx, callCtx, ErrSnapshotTimeout)
	}

	capturedAt := statusAt
	expiresAt := capturedAt.Add(o.options.ObservationTTL)
	if capturedAt.IsZero() || !expiresAt.After(capturedAt) {
		return nil, ErrInvalidObservation
	}
	observation := &model.Observation{
		ControllerID:   o.plan.controllerID,
		TopologyHash:   o.plan.topologyHash,
		CapturedAt:     capturedAt,
		ExpiresAt:      expiresAt,
		BackendHealthy: true,
		Domains:        make(map[string]model.OwnerObservation, len(o.plan.domains)),
	}
	for _, domain := range o.plan.domains {
		observation.Domains[domain.id] = domainObservation(domain, primaries[domain.id], routes, capturedAt)
	}

	o.sequenceMu.Lock()
	defer o.sequenceMu.Unlock()
	if o.sequence == math.MaxUint64 {
		return nil, ErrSequenceExhausted
	}
	observation.Sequence = o.sequence + 1
	o.applyContinuityLocked(observation)
	if err := observation.Validate(); err != nil {
		return nil, ErrInvalidObservation
	}
	o.sequence = observation.Sequence
	completed = true
	return observation, nil
}

func (o *Observer) beginSnapshot() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return ErrClosed
	}
	o.inFlight.Add(1)
	return nil
}

func (o *Observer) snapshotCallError(caller, call context.Context, fallback error) error {
	if caller.Err() != nil {
		return caller.Err()
	}
	if o.lifetime.Err() != nil {
		return ErrClosed
	}
	if call.Err() == context.DeadlineExceeded {
		return ErrSnapshotTimeout
	}
	return fallback
}

// Close cancels in-flight snapshots, waits for them to leave the adapters, and
// closes the embedded tsnet node. It is idempotent.
func (o *Observer) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.closed {
		done := o.closeDone
		o.mu.Unlock()
		<-done
		return o.closeErr
	}
	o.closed = true
	o.cancelLifetime()
	done := o.closeDone
	o.mu.Unlock()

	o.inFlight.Wait()
	var closeErr error
	if err := o.node.close(); err != nil {
		closeErr = ErrClose
	}

	o.mu.Lock()
	o.closeErr = closeErr
	close(done)
	o.mu.Unlock()
	return closeErr
}

func validateBackend(status *ipnstate.Status, plan *observationPlan, now time.Time) error {
	if status == nil || plan == nil || now.IsZero() {
		return ErrMalformedStatus
	}
	if status.BackendState != "Running" || len(status.Health) != 0 {
		return ErrBackendUnhealthy
	}
	if len(status.Peer) > maxPeers {
		return ErrMalformedStatus
	}
	if !status.HaveNodeKey || status.Self == nil || status.Self.PublicKey.IsZero() ||
		!validIdentifier(string(status.Self.ID)) || status.Self.HostName != plan.controllerID {
		return ErrObserverIdentity
	}
	if status.Self.Expired || status.Self.KeyExpiry != nil && !status.Self.KeyExpiry.After(now) {
		return ErrObserverExpired
	}
	if !status.Self.Online {
		return ErrObserverUnavailable
	}
	if status.CurrentTailnet == nil || status.CurrentTailnet.Name != plan.tailnetName {
		return ErrTailnetMismatch
	}
	return nil
}

func selectPrimaryPeers(status *ipnstate.Status, plan *observationPlan, now time.Time, staleAfter time.Duration) (map[string]primarySelection, error) {
	if status == nil || plan == nil || now.IsZero() || staleAfter <= 0 {
		return nil, ErrMalformedStatus
	}
	domainByPrefix := make(map[string]int, len(plan.domains))
	owners := make([][]primaryPeer, len(plan.domains))
	domainErrors := make([]error, len(plan.domains))
	domainsByOwner := make(map[string][]int)
	for index, domain := range plan.domains {
		domainByPrefix[domain.sourcePrefix] = index
		for stableNodeID := range domain.owners {
			domainsByOwner[stableNodeID] = append(domainsByOwner[stableNodeID], index)
		}
	}

	seenPeerIDs := make(map[string]struct{}, len(status.Peer))
	for _, peer := range status.Peer {
		if peer == nil {
			return nil, ErrMalformedStatus
		}
		stableNodeID := string(peer.ID)
		if stableNodeID != "" {
			if _, exists := seenPeerIDs[stableNodeID]; exists {
				domainIndexes := domainsByOwner[stableNodeID]
				if len(domainIndexes) == 0 {
					return nil, ErrMalformedStatus
				}
				for _, domainIndex := range domainIndexes {
					domainErrors[domainIndex] = ErrMalformedStatus
				}
				continue
			}
			seenPeerIDs[stableNodeID] = struct{}{}
		}
		if peer.PrimaryRoutes == nil {
			continue
		}
		primaryRoutes := peer.PrimaryRoutes.AsSlice()
		if len(primaryRoutes) > maxRoutesPerDevice {
			return nil, ErrMalformedStatus
		}
		seenRoutes := make(map[string]struct{}, len(primaryRoutes))
		for _, prefix := range primaryRoutes {
			if !validPrefix(prefix) {
				return nil, ErrMalformedStatus
			}
			raw := prefix.String()
			if _, exists := seenRoutes[raw]; exists {
				return nil, ErrMalformedStatus
			}
			seenRoutes[raw] = struct{}{}
			domainIndex, observed := domainByPrefix[raw]
			if !observed {
				continue
			}
			if _, configured := plan.domains[domainIndex].owners[stableNodeID]; !configured {
				domainErrors[domainIndex] = ErrPrimaryUnknown
				continue
			}
			owners[domainIndex] = append(owners[domainIndex], primaryPeer{
				stableNodeID: stableNodeID,
				online:       peer.Online,
				expired:      peer.Expired,
				lastSeen:     peer.LastSeen,
				keyExpiry:    cloneTime(peer.KeyExpiry),
			})
		}
	}

	result := make(map[string]primarySelection, len(plan.domains))
	for index, domain := range plan.domains {
		selection := primarySelection{}
		if len(owners[index]) == 1 {
			selection.peer = owners[index][0]
		}
		if domainErrors[index] != nil {
			selection.err = domainErrors[index]
			result[domain.id] = selection
			continue
		}
		if len(owners[index]) == 0 {
			selection.err = ErrPrimaryMissing
			result[domain.id] = selection
			continue
		}
		if len(owners[index]) != 1 {
			selection.err = ErrPrimaryDuplicate
			result[domain.id] = selection
			continue
		}
		peer := owners[index][0]
		selection.sole = true
		if peer.expired || peer.keyExpiry != nil && !peer.keyExpiry.After(now) {
			selection.err = ErrPeerExpired
			result[domain.id] = selection
			continue
		}
		if !peer.lastSeen.IsZero() {
			if peer.lastSeen.After(now) {
				selection.err = ErrMalformedStatus
				result[domain.id] = selection
				continue
			}
			if now.Sub(peer.lastSeen) > staleAfter {
				selection.err = ErrPeerStale
				result[domain.id] = selection
				continue
			}
		}
		if !peer.online {
			selection.err = ErrPeerUnavailable
			result[domain.id] = selection
			continue
		}
		result[domain.id] = selection
	}
	return result, nil
}

type validatedRoutes struct {
	advertised []string
	enabled    []string
}

type routeValidation struct {
	routes validatedRoutes
	err    error
}

func validateAdminDevices(devices []adminDevice, plan *observationPlan) (map[string]routeValidation, error) {
	if plan == nil {
		return nil, ErrMalformedAdminResponse
	}
	if len(devices) > maxPeers {
		return nil, ErrMalformedAdminResponse
	}
	seen := make(map[string]struct{}, len(devices))
	result := make(map[string]routeValidation, len(plan.expectedRoutes))
	for stableNodeID := range plan.expectedRoutes {
		result[stableNodeID] = routeValidation{err: ErrAdminDeviceMissing}
	}
	for _, device := range devices {
		if !validIdentifier(device.nodeID) {
			return nil, ErrMalformedAdminResponse
		}
		expected, configured := plan.expectedRoutes[device.nodeID]
		if !configured {
			continue
		}
		if _, exists := seen[device.nodeID]; exists {
			result[device.nodeID] = routeValidation{err: ErrMalformedAdminResponse}
			continue
		}
		seen[device.nodeID] = struct{}{}

		advertised, err := canonicalRouteSet(device.advertisedRoutes, device.advertisedPresent)
		if err != nil {
			result[device.nodeID] = routeValidation{err: err}
			continue
		}
		enabled, err := canonicalRouteSet(device.enabledRoutes, device.enabledPresent)
		if err != nil {
			result[device.nodeID] = routeValidation{err: err}
			continue
		}
		if !sameStrings(advertised, expected) || !sameStrings(enabled, expected) {
			result[device.nodeID] = routeValidation{err: ErrRouteSetMismatch}
			continue
		}
		result[device.nodeID] = routeValidation{routes: validatedRoutes{advertised: advertised, enabled: enabled}}
	}
	return result, nil
}

func domainObservation(domain domainPlan, selection primarySelection, routes map[string]routeValidation, at time.Time) model.OwnerObservation {
	observation := model.OwnerObservation{
		StableNodeID: selection.peer.stableNodeID,
		SolePrimary:  selection.sole,
		Online:       selection.peer.online,
		Expired:      selection.peer.expired,
	}
	if selection.err != nil {
		observation.Error = domainStateError(selection.err, at)
		return observation
	}
	for _, stableNodeID := range domain.ownerIDs {
		candidateRoutes, exists := routes[stableNodeID]
		if !exists {
			candidateRoutes.err = ErrAdminDeviceMissing
		}
		if candidateRoutes.err != nil {
			observation.Error = domainStateError(candidateRoutes.err, at)
			return observation
		}
	}
	routeResult, exists := routes[selection.peer.stableNodeID]
	if !exists {
		routeResult.err = ErrAdminDeviceMissing
	}
	if routeResult.err != nil {
		observation.Error = domainStateError(routeResult.err, at)
		return observation
	}
	observation.Healthy = true
	observation.AdvertisedPrefixes = append([]string(nil), routeResult.routes.advertised...)
	observation.EnabledPrefixes = append([]string(nil), routeResult.routes.enabled...)
	return observation
}

func domainStateError(err error, at time.Time) *model.StateError {
	message := "Tailnet domain observation is invalid"
	switch {
	case errors.Is(err, ErrPrimaryMissing):
		message = "Tailnet primary owner is missing"
	case errors.Is(err, ErrPrimaryDuplicate):
		message = "Tailnet primary owner is duplicated"
	case errors.Is(err, ErrPrimaryUnknown):
		message = "Tailnet primary owner is not configured"
	case errors.Is(err, ErrPeerUnavailable):
		message = "Tailnet primary owner is offline"
	case errors.Is(err, ErrPeerStale):
		message = "Tailnet primary owner is stale"
	case errors.Is(err, ErrPeerExpired):
		message = "Tailnet primary owner is expired"
	case errors.Is(err, ErrAdminDeviceMissing):
		message = "configured Tailscale device is missing"
	case errors.Is(err, ErrRouteSetMismatch):
		message = "configured Tailscale device route set does not match authority"
	case errors.Is(err, ErrMalformedAdminResponse):
		message = "configured Tailscale device route data is malformed"
	}
	return &model.StateError{Code: model.ErrorObservationQuorum, Message: message, At: at}
}

func (o *Observer) applyContinuityLocked(observation *model.Observation) {
	for domainID, domain := range observation.Domains {
		owner := ""
		if domain.Healthy && domain.SolePrimary && domain.StableNodeID != "" {
			owner = domain.StableNodeID
		}
		continuity, exists := o.continuity[domainID]
		captureGap := exists && (observation.CapturedAt.Before(continuity.lastCapture) ||
			observation.CapturedAt.Sub(continuity.lastCapture) > o.options.ContinuityGap)
		if !exists || continuity.owner != owner || captureGap {
			continuity = ownerContinuity{owner: owner, generation: observation.Sequence}
			if owner != "" {
				continuity.since = observation.CapturedAt
			}
		}
		continuity.lastCapture = observation.CapturedAt
		o.continuity[domainID] = continuity
		domain.OwnerChangeGeneration = continuity.generation
		if owner != "" {
			domain.OwnerSince = cloneTime(&continuity.since)
		}
		observation.Domains[domainID] = domain
	}
}

func (o *Observer) resetContinuity() {
	o.sequenceMu.Lock()
	defer o.sequenceMu.Unlock()
	clear(o.continuity)
}

func canonicalRouteSet(routes []string, present bool) ([]string, error) {
	if !present || len(routes) > maxRoutesPerDevice {
		return nil, ErrMalformedAdminResponse
	}
	result := append([]string(nil), routes...)
	seen := make(map[string]struct{}, len(result))
	for _, raw := range result {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !validPrefix(prefix) || prefix.String() != raw {
			return nil, ErrMalformedAdminResponse
		}
		if _, exists := seen[raw]; exists {
			return nil, ErrMalformedAdminResponse
		}
		seen[raw] = struct{}{}
	}
	sort.Strings(result)
	return result, nil
}

func validIdentifier(value string) bool {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validSecretArgument(value string) bool {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 4096 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func validPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix == prefix.Masked()
}

func sameSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
