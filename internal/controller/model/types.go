// Package model defines the controller's durable, provider-independent state.
package model

import "time"

// Phase is a durable reconciliation checkpoint.
type Phase string

const (
	PhaseStable               Phase = "stable"
	PhaseOwnerObserved        Phase = "owner-observed"
	PhaseRouteIntentPersisted Phase = "route-intent-persisted"
	PhaseRoutesConverging     Phase = "routes-converging"
	PhaseDegraded             Phase = "degraded"
)

// FenceTerm increases whenever a new lease holder takes authority.
type FenceTerm uint64

// DocumentRevision is the compare-and-swap revision of a durable domain record.
type DocumentRevision uint64

// ErrorCode is a bounded, machine-readable failure reason.
type ErrorCode string

const (
	ErrorObservationQuorum ErrorCode = "observation-quorum"
	ErrorOwnerIneligible   ErrorCode = "owner-ineligible"
	ErrorLeaseUnsafe       ErrorCode = "lease-unsafe"
	ErrorRouteUnauthorized ErrorCode = "route-unauthorized"
	ErrorRouteAmbiguous    ErrorCode = "route-ambiguous"
	ErrorRouteOscillation  ErrorCode = "route-oscillation"
	ErrorStoreUnavailable  ErrorCode = "store-unavailable"
	ErrorInvariant         ErrorCode = "invariant-violation"
)

// StateError is safe durable context for an operational failure. Message must
// remain bounded and secret-free at the call site.
type StateError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	At        time.Time `json:"at"`
	Ambiguous bool      `json:"ambiguous"`
}

// Lease is the last strongly consistent lease record observed for a domain.
type Lease struct {
	HolderID      string    `json:"holder_id"`
	FenceTerm     FenceTerm `json:"fence_term"`
	RecordVersion uint64    `json:"record_version"`
	AcquiredAt    time.Time `json:"acquired_at"`
	RenewedAt     time.Time `json:"renewed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// OwnerAuthority binds one Tailnet identity to its allowlisted cloud identity.
type OwnerAuthority struct {
	RouterID         string `json:"router_id"`
	StableNodeID     string `json:"stable_node_id"`
	InstanceID       string `json:"instance_id"`
	ENIID            string `json:"eni_id"`
	VPCID            string `json:"vpc_id"`
	SubnetID         string `json:"subnet_id"`
	AvailabilityZone string `json:"availability_zone"`
	Region           string `json:"region"`
}

// DomainAuthority is the immutable mutation boundary bound by TopologyHash.
// PreferredOwner and all state owner fields contain stable Tailnet node IDs.
type DomainAuthority struct {
	TopologyHash            string           `json:"topology_hash"`
	DeploymentID            string           `json:"deployment_id"`
	DomainID                string           `json:"domain_id"`
	SiteID                  string           `json:"site_id"`
	VPCID                   string           `json:"vpc_id"`
	Region                  string           `json:"region"`
	SourcePrefix            string           `json:"source_prefix"`
	RouteTableID            string           `json:"route_table_id"`
	GWLBESubnetID           string           `json:"gwlbe_subnet_id"`
	RouteTableAssociationID string           `json:"route_table_association_id"`
	RemotePrefixes          []string         `json:"remote_prefixes"`
	PreferredOwner          string           `json:"preferred_owner"`
	Owners                  []OwnerAuthority `json:"owners"`
}

// OwnerByStableNode returns the configured authority for a stable Tailnet node.
func (a DomainAuthority) OwnerByStableNode(stableNodeID string) (OwnerAuthority, bool) {
	for _, owner := range a.Owners {
		if owner.StableNodeID == stableNodeID {
			return owner, true
		}
	}
	return OwnerAuthority{}, false
}

// AllowsENI reports whether an ENI is a configured target for this domain.
func (a DomainAuthority) AllowsENI(eniID string) bool {
	for _, owner := range a.Owners {
		if owner.ENIID == eniID {
			return true
		}
	}
	return false
}

// RouteSnapshotEntry records one authoritative route read without SDK types.
type RouteSnapshotEntry struct {
	DestinationPrefix string `json:"destination_prefix"`
	TargetENIID       string `json:"target_eni_id"`
	State             string `json:"state"`
	Origin            string `json:"origin"`
}

// RouteSnapshot is the complete before-image for one domain route table.
type RouteSnapshot struct {
	RouteTableID string               `json:"route_table_id"`
	CapturedAt   time.Time            `json:"captured_at"`
	Routes       []RouteSnapshotEntry `json:"routes"`
}

// RouteProgress is one entry in the ordered route mutation intent. A nil
// AttemptedAt is pending; a non-nil CompletedAt is authoritatively acknowledged.
type RouteProgress struct {
	DestinationPrefix string      `json:"destination_prefix"`
	AttemptedAt       *time.Time  `json:"attempted_at,omitempty"`
	CompletedAt       *time.Time  `json:"completed_at,omitempty"`
	ObservedENIID     string      `json:"observed_eni_id,omitempty"`
	Ambiguous         bool        `json:"ambiguous,omitempty"`
	Error             *StateError `json:"error,omitempty"`
}

func (p RouteProgress) Attempted() bool {
	return p.AttemptedAt != nil
}

func (p RouteProgress) Completed() bool {
	return p.CompletedAt != nil
}

// RouteIntent is persisted before any external route mutation.
type RouteIntent struct {
	TransactionID string          `json:"transaction_id"`
	FenceTerm     FenceTerm       `json:"fence_term"`
	DesiredOwner  string          `json:"desired_owner"`
	DesiredENIID  string          `json:"desired_eni_id"`
	CreatedAt     time.Time       `json:"created_at"`
	Before        RouteSnapshot   `json:"before"`
	Progress      []RouteProgress `json:"progress"`
}

// OwnerObservation describes one observer's view of a domain's sole primary.
type OwnerObservation struct {
	StableNodeID string `json:"stable_node_id,omitempty"`
	SolePrimary  bool   `json:"sole_primary"`
	Online       bool   `json:"online"`
	Expired      bool   `json:"expired"`
	Healthy      bool   `json:"healthy"`
	// OwnerSince is when this observer first saw the current uninterrupted
	// healthy owner. OwnerChangeGeneration is that transition's observation
	// sequence and remains fixed until ownership or health changes.
	OwnerSince            *time.Time  `json:"owner_since,omitempty"`
	OwnerChangeGeneration uint64      `json:"owner_change_generation,omitempty"`
	AdvertisedPrefixes    []string    `json:"advertised_prefixes,omitempty"`
	EnabledPrefixes       []string    `json:"enabled_prefixes,omitempty"`
	Error                 *StateError `json:"error,omitempty"`
}

// Observation is one bounded, topology-bound Tailnet snapshot from a replica.
// Domains is keyed by domain ID.
type Observation struct {
	ControllerID   string                      `json:"controller_id"`
	TopologyHash   string                      `json:"topology_hash"`
	Sequence       uint64                      `json:"sequence"`
	CapturedAt     time.Time                   `json:"captured_at"`
	ExpiresAt      time.Time                   `json:"expires_at"`
	BackendHealthy bool                        `json:"backend_healthy"`
	Domains        map[string]OwnerObservation `json:"domains"`
	Error          *StateError                 `json:"error,omitempty"`
}

// DomainState is the complete durable state for one isolated route domain.
type DomainState struct {
	Authority        DomainAuthority  `json:"authority"`
	Activated        bool             `json:"activated"`
	Revision         DocumentRevision `json:"revision"`
	FenceTerm        FenceTerm        `json:"fence_term"`
	Lease            *Lease           `json:"lease,omitempty"`
	Phase            Phase            `json:"phase"`
	StableOwner      string           `json:"stable_owner"`
	ObservedOwner    string           `json:"observed_owner,omitempty"`
	OwnerObservedAt  *time.Time       `json:"owner_observed_at,omitempty"`
	Intent           *RouteIntent     `json:"intent,omitempty"`
	CooldownUntil    *time.Time       `json:"cooldown_until,omitempty"`
	Error            *StateError      `json:"error,omitempty"`
	LastTransitionAt time.Time        `json:"last_transition_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}
