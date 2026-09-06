// Package store defines provider-independent durable state contracts for the
// production controller.
package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

const maxIdentifierLength = 256

// DomainRef is the immutable storage identity of one failover domain.
type DomainRef struct {
	DeploymentID string
	DomainID     string
	TopologyHash string
}

func (r DomainRef) Validate() error {
	var errs []error
	if err := validateIdentifier("deployment ID", r.DeploymentID); err != nil {
		errs = append(errs, err)
	}
	if err := validateIdentifier("domain ID", r.DomainID); err != nil {
		errs = append(errs, err)
	}
	if err := validateTopologyHash(r.TopologyHash); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (r DomainRef) String() string {
	return r.DeploymentID + "/" + r.DomainID
}

// DomainRefFor returns the storage identity carried by an authority record.
func DomainRefFor(authority model.DomainAuthority) DomainRef {
	return DomainRef{
		DeploymentID: authority.DeploymentID,
		DomainID:     authority.DomainID,
		TopologyHash: authority.TopologyHash,
	}
}

// LeaseToken is the exact lease identity required by renewal and state CAS.
// Excluding timestamps prevents callers from treating lease expiry as a
// fencing mechanism.
type LeaseToken struct {
	HolderID      string
	FenceTerm     model.FenceTerm
	RecordVersion uint64
}

func (t LeaseToken) Validate() error {
	var errs []error
	if err := validateIdentifier("lease holder", t.HolderID); err != nil {
		errs = append(errs, err)
	}
	if t.FenceTerm == 0 {
		errs = append(errs, errors.New("lease fence term must be positive"))
	}
	if t.RecordVersion == 0 {
		errs = append(errs, errors.New("lease record version must be positive"))
	}
	return errors.Join(errs...)
}

// LeaseTokenFor returns the conditional-write identity of lease. A nil lease
// produces the zero token, which fails validation when used.
func LeaseTokenFor(lease *model.Lease) LeaseToken {
	if lease == nil {
		return LeaseToken{}
	}
	return LeaseToken{
		HolderID:      lease.HolderID,
		FenceTerm:     lease.FenceTerm,
		RecordVersion: lease.RecordVersion,
	}
}

// ObservationScope selects the configured controller partitions for one
// immutable deployment topology. Listing does not apply time-based freshness
// filtering.
type ObservationScope struct {
	DeploymentID string
	TopologyHash string
}

func (s ObservationScope) Validate() error {
	var errs []error
	if err := validateIdentifier("deployment ID", s.DeploymentID); err != nil {
		errs = append(errs, err)
	}
	if err := validateTopologyHash(s.TopologyHash); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ObserverIdentity is an allowlisted observation writer. Controller identity,
// deployment, and topology are all part of the durable observation key.
type ObserverIdentity struct {
	DeploymentID string
	TopologyHash string
	ControllerID string
}

func (i ObserverIdentity) Validate() error {
	var errs []error
	if err := (ObservationScope{DeploymentID: i.DeploymentID, TopologyHash: i.TopologyHash}).Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := validateIdentifier("controller ID", i.ControllerID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// DomainStore owns creation, strongly consistent reads, and fenced state CAS.
type DomainStore interface {
	// CreateDomain conditionally creates a revision-one, lease-free stable state.
	CreateDomain(ctx context.Context, initial *model.DomainState) (*model.DomainState, error)
	// LoadDomain returns a strongly consistent deep copy of the complete state.
	LoadDomain(ctx context.Context, ref DomainRef) (*model.DomainState, error)
	// CompareAndSwapDomain stores next only at the exact revision and while token
	// identifies the current unexpired lease. The store increments the revision.
	CompareAndSwapDomain(ctx context.Context, ref DomainRef, expectedRevision model.DocumentRevision, token LeaseToken, next *model.DomainState) (*model.DomainState, error)
}

// LeaseStore owns conditional fenced lease operations.
type LeaseStore interface {
	// AcquireLease acquires only a domain whose lease is absent.
	AcquireLease(ctx context.Context, ref DomainRef, holderID string, duration time.Duration) (*model.Lease, error)
	// TakeoverLease replaces a lease only if its record version is the one
	// observed before the caller waited a complete lease duration. The caller's
	// monotonic wait, rather than the prior holder's wall expiry, provides the
	// elapsed-time guarantee.
	TakeoverLease(ctx context.Context, ref DomainRef, holderID string, expectedRecordVersion uint64, duration time.Duration) (*model.Lease, error)
	// RenewLease renews the exact current, unexpired holder/fence/version tuple.
	RenewLease(ctx context.Context, ref DomainRef, token LeaseToken, duration time.Duration) (*model.Lease, error)
}

// ObservationStore publishes latest-per-controller observations and strongly
// reads each configured controller partition in an exact deployment/topology
// scope. Callers decide freshness from the returned CapturedAt and ExpiresAt
// values.
type ObservationStore interface {
	PublishObservation(ctx context.Context, deploymentID string, observation *model.Observation) (*model.Observation, error)
	ListObservations(ctx context.Context, scope ObservationScope) ([]*model.Observation, error)
}

// Store is the complete controller durability contract. Consumers should
// depend on the narrow component interface they need.
type Store interface {
	DomainStore
	LeaseStore
	ObservationStore
}

func validateIdentifier(label, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", label)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have surrounding whitespace", label)
	}
	if len(value) > maxIdentifierLength {
		return fmt.Errorf("%s exceeds %d bytes", label, maxIdentifierLength)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateTopologyHash(hash string) error {
	if len(hash) != 64 || hash != strings.ToLower(hash) {
		return errors.New("topology hash must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return errors.New("topology hash must be 64 lowercase hexadecimal characters")
	}
	return nil
}
