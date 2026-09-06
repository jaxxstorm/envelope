package resilience

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

var (
	// ErrResponseMismatch means a peer returned a response for a different
	// idempotency key. Retrying that protocol violation is unsafe.
	ErrResponseMismatch = errors.New("resilience: TCP response idempotency key mismatch")
	// ErrIdempotencyConflict means a principal reused a key for different
	// operation bytes.
	ErrIdempotencyConflict = errors.New("resilience: idempotency key conflict")
)

// TCPRequest is one newline-delimited JSON reference request. The same value,
// including IdempotencyKey, must be used on every reconnect.
type TCPRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	Operation      string `json:"operation"`
	Payload        []byte `json:"payload,omitempty"`
}

// TCPResponse acknowledges the request identified by IdempotencyKey.
type TCPResponse struct {
	IdempotencyKey string `json:"idempotency_key"`
	Result         []byte `json:"result,omitempty"`
}

// TCPDialFunc must return a newly dialed connection for each invocation.
type TCPDialFunc func(context.Context) (net.Conn, error)

// CallTCP retries a request on a fresh connection after dial, write, or read
// failure. It never changes the idempotency key or request bytes.
func CallTCP(ctx context.Context, request TCPRequest, policy RetryPolicy, dial TCPDialFunc, wait WaitFunc) (TCPResponse, error) {
	if ctx == nil {
		return TCPResponse{}, fmt.Errorf("%w: context is nil", ErrInvalidInput)
	}
	if err := validateTCPRequest(request); err != nil {
		return TCPResponse{}, err
	}
	if err := policy.validate(wait); err != nil {
		return TCPResponse{}, err
	}
	if dial == nil {
		return TCPResponse{}, fmt.Errorf("%w: TCP dial function is nil", ErrInvalidInput)
	}
	request.Payload = append([]byte(nil), request.Payload...)

	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return TCPResponse{}, err
		}
		attemptContext, cancel := context.WithTimeout(ctx, policy.AttemptTimeout)
		response, err := callTCPAttempt(attemptContext, request, dial)
		cancel()
		if err == nil {
			if response.IdempotencyKey != request.IdempotencyKey {
				return TCPResponse{}, ErrResponseMismatch
			}
			return response, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return TCPResponse{}, contextErr
		}
		lastErr = err
		if attempt < policy.MaxAttempts {
			if err := waitAfterFailure(ctx, wait, attempt); err != nil {
				return TCPResponse{}, err
			}
		}
	}
	return TCPResponse{}, exhausted("TCP", lastErr)
}

func callTCPAttempt(ctx context.Context, request TCPRequest, dial TCPDialFunc) (TCPResponse, error) {
	connection, err := dial(ctx)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return TCPResponse{}, err
	}
	if connection == nil {
		return TCPResponse{}, fmt.Errorf("%w: TCP dial returned a nil connection", ErrInvalidInput)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return TCPResponse{}, err
		}
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return TCPResponse{}, err
	}
	var response TCPResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return TCPResponse{}, err
	}
	return response, nil
}

func validateTCPRequest(request TCPRequest) error {
	if strings.TrimSpace(request.IdempotencyKey) == "" || request.IdempotencyKey != strings.TrimSpace(request.IdempotencyKey) {
		return fmt.Errorf("%w: TCP idempotency key is required without surrounding whitespace", ErrInvalidInput)
	}
	if strings.TrimSpace(request.Operation) == "" || request.Operation != strings.TrimSpace(request.Operation) {
		return fmt.Errorf("%w: TCP operation is required without surrounding whitespace", ErrInvalidInput)
	}
	return nil
}

type tcpIdempotencyKey struct {
	principal string
	key       string
}

type tcpIdempotencyRecord struct {
	requestHash [sha256.Size]byte
	response    TCPResponse
}

// TCPIdempotencyTable is an in-memory executable model of server-side
// idempotency. Production applications need the same comparison and atomic
// side-effect boundary in durable storage.
type TCPIdempotencyTable struct {
	mu      sync.Mutex
	records map[tcpIdempotencyKey]tcpIdempotencyRecord
}

// Execute applies a request once for a principal and returns the cached result
// for an exact replay. apply runs while the key is serialized.
func (t *TCPIdempotencyTable) Execute(principal string, request TCPRequest, apply func(TCPRequest) ([]byte, error)) (TCPResponse, error) {
	if t == nil {
		return TCPResponse{}, fmt.Errorf("%w: idempotency table is nil", ErrInvalidInput)
	}
	if strings.TrimSpace(principal) == "" || principal != strings.TrimSpace(principal) {
		return TCPResponse{}, fmt.Errorf("%w: principal is required without surrounding whitespace", ErrInvalidInput)
	}
	if err := validateTCPRequest(request); err != nil {
		return TCPResponse{}, err
	}
	if apply == nil {
		return TCPResponse{}, fmt.Errorf("%w: TCP apply function is nil", ErrInvalidInput)
	}

	request.Payload = append([]byte(nil), request.Payload...)
	requestHash := hashTCPRequest(request)
	key := tcpIdempotencyKey{principal: principal, key: request.IdempotencyKey}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.records == nil {
		t.records = make(map[tcpIdempotencyKey]tcpIdempotencyRecord)
	}
	if prior, found := t.records[key]; found {
		if prior.requestHash != requestHash {
			return TCPResponse{}, ErrIdempotencyConflict
		}
		return cloneTCPResponse(prior.response), nil
	}

	result, err := apply(request)
	if err != nil {
		return TCPResponse{}, err
	}
	response := TCPResponse{
		IdempotencyKey: request.IdempotencyKey,
		Result:         append([]byte(nil), result...),
	}
	t.records[key] = tcpIdempotencyRecord{requestHash: requestHash, response: response}
	return cloneTCPResponse(response), nil
}

func hashTCPRequest(request TCPRequest) [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Operation string `json:"operation"`
		Payload   []byte `json:"payload"`
	}{Operation: request.Operation, Payload: request.Payload})
	return sha256.Sum256(encoded)
}

func cloneTCPResponse(response TCPResponse) TCPResponse {
	response.Result = append([]byte(nil), response.Result...)
	return response
}
