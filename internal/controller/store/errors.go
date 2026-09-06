package store

import (
	"errors"
	"fmt"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

var (
	ErrDomainInactive   = errors.New("store: domain is not activated")
	ErrNotFound         = errors.New("store: not found")
	ErrConflict         = errors.New("store: conflict")
	ErrLeaseHeld        = errors.New("store: lease held")
	ErrLeaseLost        = errors.New("store: lease lost")
	ErrTopologyMismatch = errors.New("store: topology mismatch")
	ErrAPITimeout       = errors.New("store: API timeout")
)

// APITimeoutError identifies a deadline imposed by the store adapter while
// the caller's context remained active. It deliberately does not unwrap to
// context.DeadlineExceeded so callers can distinguish availability failures
// from cancellation of their own operation.
type APITimeoutError struct {
	Operation string
}

func (e *APITimeoutError) Error() string {
	if e == nil || e.Operation == "" {
		return ErrAPITimeout.Error()
	}
	return fmt.Sprintf("store: %s API timeout", e.Operation)
}

func (e *APITimeoutError) Unwrap() error { return ErrAPITimeout }

// NotFoundError identifies a missing durable resource.
type NotFoundError struct {
	Resource string
	Key      string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("store: %s %q not found", e.Resource, e.Key)
}

func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// ConflictError reports a failed non-lease conditional write.
type ConflictError struct {
	Resource string
	Expected string
	Actual   string
}

func (e *ConflictError) Error() string {
	if e.Expected == "" && e.Actual == "" {
		return fmt.Sprintf("store: %s conflict", e.Resource)
	}
	return fmt.Sprintf("store: %s conflict: expected %s, got %s", e.Resource, e.Expected, e.Actual)
}

func (e *ConflictError) Unwrap() error { return ErrConflict }

// LeaseHeldError returns the current lease so a contender can record its
// version before performing the required local wait.
type LeaseHeldError struct {
	Domain DomainRef
	Lease  *model.Lease
}

func (e *LeaseHeldError) Error() string {
	if e.Lease == nil {
		return fmt.Sprintf("store: lease for %s is held", e.Domain)
	}
	return fmt.Sprintf("store: lease for %s is held by %q at fence %d version %d", e.Domain, e.Lease.HolderID, e.Lease.FenceTerm, e.Lease.RecordVersion)
}

func (e *LeaseHeldError) Unwrap() error { return ErrLeaseHeld }

// LeaseLostError reports that the expected lease is absent, expired, or no
// longer the exact active holder/fence/version tuple.
type LeaseLostError struct {
	Domain   DomainRef
	Expected LeaseToken
	Actual   *model.Lease
}

func (e *LeaseLostError) Error() string {
	if e.Actual == nil {
		return fmt.Sprintf("store: lease for %s was lost: no active lease", e.Domain)
	}
	return fmt.Sprintf("store: lease for %s was lost: expected holder %q fence %d version %d, got holder %q fence %d version %d", e.Domain, e.Expected.HolderID, e.Expected.FenceTerm, e.Expected.RecordVersion, e.Actual.HolderID, e.Actual.FenceTerm, e.Actual.RecordVersion)
}

func (e *LeaseLostError) Unwrap() error { return ErrLeaseLost }

// TopologyMismatchError prevents a durable record from being adopted by a
// different immutable topology.
type TopologyMismatchError struct {
	Resource string
	Expected string
	Actual   string
}

func (e *TopologyMismatchError) Error() string {
	return fmt.Sprintf("store: %s topology mismatch: expected %q, got %q", e.Resource, e.Expected, e.Actual)
}

func (e *TopologyMismatchError) Unwrap() error { return ErrTopologyMismatch }
