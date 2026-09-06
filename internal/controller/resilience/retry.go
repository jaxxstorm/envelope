// Package resilience provides executable reference behavior for applications
// that need to recover after controller-driven route convergence.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const maxReferenceAttempts = 64

var (
	// ErrInvalidInput identifies an invalid reference-protocol configuration or
	// frame. It is not retryable without changing the caller's input.
	ErrInvalidInput = errors.New("resilience: invalid input")
	// ErrNotAcknowledged means the bounded retry policy ended without a matching
	// TCP response or UDP acknowledgement. The operation outcome may be unknown.
	ErrNotAcknowledged = errors.New("resilience: operation not acknowledged")
)

// RetryPolicy bounds both individual attempts and the total number of
// attempts. The parent context supplies the overall elapsed-time bound.
type RetryPolicy struct {
	MaxAttempts    int
	AttemptTimeout time.Duration
}

// WaitFunc applies caller-selected bounded backoff after a failed attempt. The
// argument is the one-based number of the attempt that just failed.
type WaitFunc func(context.Context, int) error

func (p RetryPolicy) validate(wait WaitFunc) error {
	if p.MaxAttempts < 1 || p.MaxAttempts > maxReferenceAttempts {
		return fmt.Errorf("%w: max attempts must be between 1 and %d", ErrInvalidInput, maxReferenceAttempts)
	}
	if p.AttemptTimeout <= 0 || p.AttemptTimeout > time.Minute {
		return fmt.Errorf("%w: attempt timeout must be between zero and one minute", ErrInvalidInput)
	}
	if p.MaxAttempts > 1 && wait == nil {
		return fmt.Errorf("%w: retry wait function is required", ErrInvalidInput)
	}
	return nil
}

func waitAfterFailure(ctx context.Context, wait WaitFunc, attempt int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := wait(ctx, attempt); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("resilience: retry wait: %w", err)
	}
	return ctx.Err()
}

func exhausted(protocol string, lastErr error) error {
	return fmt.Errorf("%w: %s retry bound exhausted: %v", ErrNotAcknowledged, protocol, lastErr)
}
