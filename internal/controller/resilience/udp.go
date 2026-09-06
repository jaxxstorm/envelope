package resilience

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	UDPVersion uint8 = 1

	// DefaultUDPRetryHorizon and DefaultUDPReplayWindow keep the compact
	// constructor useful for integration examples. Applications should configure
	// their measured retry horizon explicitly with NewUDPReceiverWithConfig.
	DefaultUDPRetryHorizon = 5 * time.Minute
	DefaultUDPReplayWindow = uint64(64)
)

// UDPKind distinguishes application data from its acknowledgement.
type UDPKind uint8

const (
	UDPKindData UDPKind = iota + 1
	UDPKindACK
)

var (
	// ErrNoAcknowledgement is returned by a transport when a sent datagram did
	// not produce an ACK before its attempt deadline.
	ErrNoAcknowledgement = errors.New("resilience: UDP acknowledgement absent")
	// ErrInvalidAcknowledgement means a received ACK did not identify the sent
	// client, message, and sequence.
	ErrInvalidAcknowledgement = errors.New("resilience: invalid UDP acknowledgement")
	// ErrMessageIDConflict means a client reused a message ID with different
	// sequence or payload bytes.
	ErrMessageIDConflict = errors.New("resilience: UDP message ID conflict")
	// ErrUDPCapacity means a new message or client cannot be admitted without
	// forgetting state that the receiver is still required to retain.
	ErrUDPCapacity = errors.New("resilience: UDP receiver capacity exhausted")
	// ErrUDPStaleSequence means a non-duplicate message is older than the
	// client's replay window or its cached ACK has expired.
	ErrUDPStaleSequence = errors.New("resilience: UDP stale sequence")
	// ErrUDPSequenceConflict means a client assigned a different message ID to
	// a sequence that is already present in its replay window.
	ErrUDPSequenceConflict = errors.New("resilience: UDP sequence conflict")
)

// UDPID is a fixed-width client or message identifier.
type UDPID [16]byte

// UDPFrame is the bounded reference protocol frame. Authentication and wire
// encoding are transport concerns and must cover every field in production.
type UDPFrame struct {
	Version   uint8
	Kind      UDPKind
	ClientID  UDPID
	MessageID UDPID
	Sequence  uint64
	Payload   []byte
}

// UDPExchangeFunc sends one DATA frame and waits for an authenticated ACK from
// the expected peer until ctx ends.
type UDPExchangeFunc func(context.Context, UDPFrame) (UDPFrame, error)

// SendUDP retransmits an unchanged DATA frame until a matching ACK arrives or
// the attempt/context bound is exhausted.
func SendUDP(ctx context.Context, data UDPFrame, policy RetryPolicy, exchange UDPExchangeFunc, wait WaitFunc) (UDPFrame, error) {
	if ctx == nil {
		return UDPFrame{}, fmt.Errorf("%w: context is nil", ErrInvalidInput)
	}
	if err := validateUDPData(data); err != nil {
		return UDPFrame{}, err
	}
	if err := policy.validate(wait); err != nil {
		return UDPFrame{}, err
	}
	if exchange == nil {
		return UDPFrame{}, fmt.Errorf("%w: UDP exchange function is nil", ErrInvalidInput)
	}
	data = cloneUDPFrame(data)

	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return UDPFrame{}, err
		}
		attemptContext, cancel := context.WithTimeout(ctx, policy.AttemptTimeout)
		ack, err := exchange(attemptContext, cloneUDPFrame(data))
		cancel()
		if err == nil {
			if acknowledgementMatches(data, ack) {
				return cloneUDPFrame(ack), nil
			}
			err = ErrInvalidAcknowledgement
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return UDPFrame{}, contextErr
		}
		lastErr = err
		if attempt < policy.MaxAttempts {
			if err := waitAfterFailure(ctx, wait, attempt); err != nil {
				return UDPFrame{}, err
			}
		}
	}
	return UDPFrame{}, exhausted("UDP", lastErr)
}

type udpDedupKey struct {
	clientID  UDPID
	messageID UDPID
}

type udpDedupRecord struct {
	sequence      uint64
	payloadHash   [sha256.Size]byte
	ack           UDPFrame
	retainedUntil time.Time
}

type udpSequenceRecord struct {
	messageID   UDPID
	payloadHash [sha256.Size]byte
}

type udpClientWindow struct {
	highest   uint64
	sequences map[uint64]udpSequenceRecord
}

// UDPReceiverConfig explicitly bounds receiver storage and replay semantics.
// RetryHorizon starts when applying a message completes. ReplayWindow is the
// number of sequence positions, including the highest accepted sequence, in
// which unseen out-of-order messages may be accepted.
type UDPReceiverConfig struct {
	Capacity     int
	RetryHorizon time.Duration
	ReplayWindow uint64
	Now          func() time.Time
}

// UDPReceiver is a bounded in-memory executable model of receiver-side
// deduplication and replay protection. Durable commands require equivalent
// state in durable storage.
type UDPReceiver struct {
	mu           sync.Mutex
	capacity     int
	retryHorizon time.Duration
	replayWindow uint64
	now          func() time.Time
	records      map[udpDedupKey]udpDedupRecord
	clients      map[UDPID]*udpClientWindow
}

// NewUDPReceiver creates a receiver with the documented reference defaults.
// Use NewUDPReceiverWithConfig when matching a concrete sender retry horizon.
func NewUDPReceiver(capacity int) (*UDPReceiver, error) {
	return NewUDPReceiverWithConfig(UDPReceiverConfig{
		Capacity:     capacity,
		RetryHorizon: DefaultUDPRetryHorizon,
		ReplayWindow: DefaultUDPReplayWindow,
		Now:          time.Now,
	})
}

// NewUDPReceiverWithConfig creates a receiver that never evicts an unexpired
// deduplication record. Capacity also bounds the number of client windows; a
// full receiver rejects new work before invoking its side effect.
func NewUDPReceiverWithConfig(config UDPReceiverConfig) (*UDPReceiver, error) {
	if config.Capacity <= 0 {
		return nil, fmt.Errorf("%w: UDP dedup capacity must be positive", ErrInvalidInput)
	}
	if config.RetryHorizon <= 0 {
		return nil, fmt.Errorf("%w: UDP retry horizon must be positive", ErrInvalidInput)
	}
	if config.ReplayWindow == 0 {
		return nil, fmt.Errorf("%w: UDP replay window must be positive", ErrInvalidInput)
	}
	if config.Now == nil {
		return nil, fmt.Errorf("%w: UDP clock is nil", ErrInvalidInput)
	}
	return &UDPReceiver{
		capacity:     config.Capacity,
		retryHorizon: config.RetryHorizon,
		replayWindow: config.ReplayWindow,
		now:          config.Now,
		records:      make(map[udpDedupKey]udpDedupRecord, config.Capacity),
		clients:      make(map[UDPID]*udpClientWindow, config.Capacity),
	}, nil
}

// Handle applies a DATA frame at most once while its ID remains retained.
// Exact retained duplicates receive the original cached ACK, including when
// their sequence has since fallen behind the active replay window.
func (r *UDPReceiver) Handle(data UDPFrame, apply func(UDPFrame) ([]byte, error)) (UDPFrame, error) {
	if r == nil || r.capacity <= 0 || r.retryHorizon <= 0 || r.replayWindow == 0 || r.now == nil {
		return UDPFrame{}, fmt.Errorf("%w: UDP receiver is nil or uninitialized", ErrInvalidInput)
	}
	if err := validateUDPData(data); err != nil {
		return UDPFrame{}, err
	}
	if apply == nil {
		return UDPFrame{}, fmt.Errorf("%w: UDP apply function is nil", ErrInvalidInput)
	}

	data = cloneUDPFrame(data)
	key := udpDedupKey{clientID: data.ClientID, messageID: data.MessageID}
	payloadHash := sha256.Sum256(data.Payload)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.pruneExpired(now)
	if prior, found := r.records[key]; found {
		if prior.sequence != data.Sequence || prior.payloadHash != payloadHash {
			return UDPFrame{}, ErrMessageIDConflict
		}
		return cloneUDPFrame(prior.ack), nil
	}

	client, clientFound := r.clients[data.ClientID]
	if clientFound {
		if err := r.validateSequence(client, data, payloadHash); err != nil {
			return UDPFrame{}, err
		}
	} else if len(r.clients) == r.capacity {
		return UDPFrame{}, fmt.Errorf("%w: client window limit %d reached", ErrUDPCapacity, r.capacity)
	}
	if len(r.records) == r.capacity {
		return UDPFrame{}, fmt.Errorf("%w: %d ACK records remain retained", ErrUDPCapacity, r.capacity)
	}

	result, err := apply(data)
	if err != nil {
		return UDPFrame{}, err
	}
	ack := UDPFrame{
		Version:   UDPVersion,
		Kind:      UDPKindACK,
		ClientID:  data.ClientID,
		MessageID: data.MessageID,
		Sequence:  data.Sequence,
		Payload:   append([]byte(nil), result...),
	}
	retainedFrom := r.now()
	if retainedFrom.Before(now) {
		retainedFrom = now
	}
	if !clientFound {
		client = &udpClientWindow{sequences: make(map[uint64]udpSequenceRecord)}
		r.clients[data.ClientID] = client
	}
	r.recordSequence(client, data, payloadHash)
	r.records[key] = udpDedupRecord{
		sequence:      data.Sequence,
		payloadHash:   payloadHash,
		ack:           ack,
		retainedUntil: retainedFrom.Add(r.retryHorizon),
	}
	return cloneUDPFrame(ack), nil
}

// Entries reports the current bounded dedup-window size.
func (r *UDPReceiver) Entries() int {
	if r == nil || r.now == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpired(r.now())
	return len(r.records)
}

func (r *UDPReceiver) validateSequence(client *udpClientWindow, data UDPFrame, payloadHash [sha256.Size]byte) error {
	if client.highest != 0 && data.Sequence <= client.highest && client.highest-data.Sequence >= r.replayWindow {
		return ErrUDPStaleSequence
	}
	if prior, found := client.sequences[data.Sequence]; found {
		if prior.messageID != data.MessageID {
			return ErrUDPSequenceConflict
		}
		if prior.payloadHash != payloadHash {
			return ErrMessageIDConflict
		}
		// The ACK record has expired, otherwise the dedup lookup returned it.
		return ErrUDPStaleSequence
	}
	for sequence, prior := range client.sequences {
		if prior.messageID == data.MessageID && sequence != data.Sequence {
			return ErrMessageIDConflict
		}
	}
	return nil
}

func (r *UDPReceiver) recordSequence(client *udpClientWindow, data UDPFrame, payloadHash [sha256.Size]byte) {
	if data.Sequence > client.highest {
		client.highest = data.Sequence
		lowest := uint64(1)
		if client.highest >= r.replayWindow {
			lowest = client.highest - r.replayWindow + 1
		}
		for sequence := range client.sequences {
			if sequence < lowest {
				delete(client.sequences, sequence)
			}
		}
	}
	client.sequences[data.Sequence] = udpSequenceRecord{messageID: data.MessageID, payloadHash: payloadHash}
}

func (r *UDPReceiver) pruneExpired(now time.Time) {
	for key, record := range r.records {
		if !now.Before(record.retainedUntil) {
			delete(r.records, key)
		}
	}
}

func validateUDPData(data UDPFrame) error {
	if data.Version != UDPVersion {
		return fmt.Errorf("%w: unsupported UDP frame version", ErrInvalidInput)
	}
	if data.Kind != UDPKindData {
		return fmt.Errorf("%w: UDP sender requires a DATA frame", ErrInvalidInput)
	}
	if data.ClientID == (UDPID{}) || data.MessageID == (UDPID{}) {
		return fmt.Errorf("%w: UDP client and message IDs are required", ErrInvalidInput)
	}
	if data.Sequence == 0 {
		return fmt.Errorf("%w: UDP sequence must be positive", ErrInvalidInput)
	}
	return nil
}

func acknowledgementMatches(data, ack UDPFrame) bool {
	return ack.Version == UDPVersion && ack.Kind == UDPKindACK &&
		ack.ClientID == data.ClientID && ack.MessageID == data.MessageID &&
		ack.Sequence == data.Sequence
}

func cloneUDPFrame(frame UDPFrame) UDPFrame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}
