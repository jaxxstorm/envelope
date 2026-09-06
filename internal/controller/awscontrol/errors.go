package awscontrol

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxErrorMessageLength is the maximum byte length returned by package error
	// strings.
	MaxErrorMessageLength = 512
	// MaxObservedRoutes bounds route data retained by a result or typed error.
	MaxObservedRoutes      = 32
	maxObservedFieldLength = 96
)

var (
	ErrInvalidInput     = errors.New("awscontrol: invalid input")
	ErrOwnerIneligible  = errors.New("awscontrol: owner or route is ineligible")
	ErrUnauthorized     = errors.New("awscontrol: unauthorized route target")
	ErrAmbiguous        = errors.New("awscontrol: ambiguous route outcome")
	ErrOscillation      = errors.New("awscontrol: route oscillation")
	ErrUnstableReadback = errors.New("awscontrol: authoritative route readback was not stable")
	ErrUnsafeDeadline   = errors.New("awscontrol: unsafe mutation deadline")
	ErrAPI              = errors.New("awscontrol: EC2 API failure")
)

// InputError reports rejected caller-controlled mutation scope.
type InputError struct {
	Field   string
	Problem string
}

func (e *InputError) Error() string {
	return boundedErrorf("awscontrol: invalid %s: %s", e.Field, e.Problem)
}

func (e *InputError) Unwrap() error { return ErrInvalidInput }

// IneligibleError identifies a failed cloud eligibility or route-shape check.
type IneligibleError struct {
	Resource string
	Check    string
	Expected string
	Observed string
}

func (e *IneligibleError) Error() string {
	return boundedErrorf(
		"awscontrol: resource %s failed %s check: expected %s, observed %s",
		e.Resource,
		e.Check,
		e.Expected,
		e.Observed,
	)
}

func (e *IneligibleError) Unwrap() error { return ErrOwnerIneligible }

// UnauthorizedError reports an observed or requested target outside immutable
// authority. Observations contain only bounded route fields.
type UnauthorizedError struct {
	DestinationPrefix string
	TargetENIID       string
	Observations      []RouteObservation
}

func (e *UnauthorizedError) Error() string {
	return boundedErrorf(
		"awscontrol: route %s selected unauthorized ENI %s (%d bounded observations)",
		e.DestinationPrefix,
		e.TargetENIID,
		len(e.Observations),
	)
}

func (e *UnauthorizedError) Unwrap() error { return ErrUnauthorized }

// AmbiguousError reports that a called mutation did not settle on the desired
// target. It can additionally unwrap to context cancellation or deadline
// expiry when either prevented settlement.
type AmbiguousError struct {
	DestinationPrefix string
	PreviousENIID     string
	DesiredENIID      string
	Reason            string
	CallFailed        bool
	Observations      []RouteObservation
	cause             error
}

func (e *AmbiguousError) Error() string {
	return boundedErrorf(
		"awscontrol: route %s outcome is ambiguous between previous ENI %s and desired ENI %s: %s (%d bounded observations)",
		e.DestinationPrefix,
		e.PreviousENIID,
		e.DesiredENIID,
		e.Reason,
		len(e.Observations),
	)
}

func (e *AmbiguousError) Unwrap() []error {
	errors := []error{ErrAmbiguous}
	if e.cause != nil {
		errors = append(errors, e.cause)
	}
	return errors
}

// OscillationError reports repeated target reversals or an authorized target
// that is neither the operation's previous nor desired target.
type OscillationError struct {
	DestinationPrefix string
	PreviousENIID     string
	DesiredENIID      string
	Observations      []RouteObservation
}

func (e *OscillationError) Error() string {
	return boundedErrorf(
		"awscontrol: route %s oscillated between previous ENI %s and desired ENI %s (%d bounded observations)",
		e.DestinationPrefix,
		e.PreviousENIID,
		e.DesiredENIID,
		len(e.Observations),
	)
}

func (e *OscillationError) Unwrap() error { return ErrOscillation }

// UnstableReadbackError reports that a complete route snapshot did not remain
// identical across the configured number of time-spaced authoritative reads.
type UnstableReadbackError struct {
	Reason string
}

func (e *UnstableReadbackError) Error() string {
	return boundedErrorf("awscontrol: authoritative route readback was not stable: %s", e.Reason)
}

func (e *UnstableReadbackError) Unwrap() error { return ErrUnstableReadback }

// UnsafeDeadlineError guarantees no ReplaceRoute call started after its
// caller-provided lease-safe deadline.
type UnsafeDeadlineError struct {
	Deadline time.Time
}

func (e *UnsafeDeadlineError) Error() string {
	return "awscontrol: mutation was not started because its lease-safe deadline was reached"
}

func (e *UnsafeDeadlineError) Unwrap() error { return ErrUnsafeDeadline }

// APIError redacts the complete cloud error and retains only the fixed
// operation name.
type APIError struct {
	Operation string
}

func (e *APIError) Error() string {
	return boundedErrorf("awscontrol: EC2 %s request failed", e.Operation)
}

func (e *APIError) Unwrap() error { return ErrAPI }

func boundedErrorf(format string, values ...any) string {
	redacted := make([]any, len(values))
	for index, value := range values {
		switch typed := value.(type) {
		case string:
			redacted[index] = safeField(typed)
		default:
			redacted[index] = typed
		}
	}
	message := fmt.Sprintf(format, redacted...)
	if len(message) <= MaxErrorMessageLength {
		return message
	}
	return message[:MaxErrorMessageLength-3] + "..."
}

func safeField(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			builder.WriteByte('?')
		} else {
			builder.WriteByte(byte(character))
		}
		if builder.Len() >= maxObservedFieldLength {
			break
		}
	}
	result := builder.String()
	if len(value) > len(result) && len(result) >= 3 {
		result = result[:len(result)-3] + "..."
	}
	return result
}

func sanitizedObservation(observation RouteObservation) RouteObservation {
	observation.DestinationPrefix = safeField(observation.DestinationPrefix)
	observation.TargetENIID = safeField(observation.TargetENIID)
	observation.State = safeField(observation.State)
	observation.Origin = safeField(observation.Origin)
	return observation
}

func appendObservations(current []RouteObservation, additions ...RouteObservation) []RouteObservation {
	for _, observation := range additions {
		current = append(current, sanitizedObservation(observation))
		if len(current) > MaxObservedRoutes {
			copy(current, current[len(current)-MaxObservedRoutes:])
			current = current[:MaxObservedRoutes]
		}
	}
	return current
}

func cloneObservations(observations []RouteObservation) []RouteObservation {
	cloned := make([]RouteObservation, 0, min(len(observations), MaxObservedRoutes))
	return appendObservations(cloned, observations...)
}
