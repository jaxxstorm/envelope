package resilience

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestTCPReconnectReusesIdempotencyKeyAfterResponseLoss(t *testing.T) {
	request := TCPRequest{
		IdempotencyKey: "principal-7:create:42",
		Operation:      "create",
		Payload:        []byte(`{"value":42}`),
	}
	expectedRequest := request
	expectedRequest.Payload = append([]byte(nil), request.Payload...)
	table := &TCPIdempotencyTable{}
	serverDone := make(chan error, 2)
	seen := make(chan TCPRequest, 2)
	connections := make([]net.Conn, 0, 2)
	dials := 0
	sideEffects := 0
	dial := func(context.Context) (net.Conn, error) {
		dials++
		client, server := net.Pipe()
		connections = append(connections, client)
		dropResponse := dials == 1
		go func() {
			defer server.Close()
			var received TCPRequest
			if err := json.NewDecoder(server).Decode(&received); err != nil {
				serverDone <- err
				return
			}
			seen <- received
			response, err := table.Execute("principal-7", received, func(TCPRequest) ([]byte, error) {
				sideEffects++
				return []byte("created-42"), nil
			})
			if err == nil && !dropResponse {
				err = json.NewEncoder(server).Encode(response)
			}
			serverDone <- err
		}()
		return client, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := CallTCP(ctx, request, RetryPolicy{MaxAttempts: 3, AttemptTimeout: time.Second}, dial, func(ctx context.Context, _ int) error {
		copy(request.Payload, []byte(`{"value":99}`))
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("CallTCP: %v", err)
	}
	for range 2 {
		if err := <-serverDone; err != nil {
			t.Fatalf("reference server: %v", err)
		}
	}
	first, second := <-seen, <-seen
	if !reflect.DeepEqual(first, expectedRequest) || !reflect.DeepEqual(second, expectedRequest) {
		t.Fatalf("requests changed across reconnect: first=%+v second=%+v", first, second)
	}
	if dials != 2 || connections[0] == connections[1] {
		t.Fatalf("connections were not freshly dialed: dials=%d", dials)
	}
	if sideEffects != 1 {
		t.Fatalf("side effects = %d, want 1", sideEffects)
	}
	if response.IdempotencyKey != request.IdempotencyKey || string(response.Result) != "created-42" {
		t.Fatalf("response = %+v", response)
	}
}

func TestTCPIdempotencyRejectsKeyReuseWithDifferentPayload(t *testing.T) {
	table := &TCPIdempotencyTable{}
	request := TCPRequest{IdempotencyKey: "key-1", Operation: "set", Payload: []byte("one")}
	if _, err := table.Execute("principal", request, func(TCPRequest) ([]byte, error) {
		return []byte("ok"), nil
	}); err != nil {
		t.Fatal(err)
	}
	request.Payload = []byte("two")
	if _, err := table.Execute("principal", request, func(TCPRequest) ([]byte, error) {
		t.Fatal("conflicting replay applied a second side effect")
		return nil, nil
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
}

func TestTCPReconnectStopsAtAttemptBound(t *testing.T) {
	attempts := 0
	waits := 0
	_, err := CallTCP(
		context.Background(),
		TCPRequest{IdempotencyKey: "key-1", Operation: "read"},
		RetryPolicy{MaxAttempts: 3, AttemptTimeout: time.Second},
		func(context.Context) (net.Conn, error) {
			attempts++
			return nil, errors.New("peer unavailable")
		},
		func(context.Context, int) error {
			waits++
			return nil
		},
	)
	if !errors.Is(err, ErrNotAcknowledged) {
		t.Fatalf("CallTCP error = %v", err)
	}
	if attempts != 3 || waits != 2 {
		t.Fatalf("attempts/waits = %d/%d, want 3/2", attempts, waits)
	}
}

func TestTCPDialErrorClosesReturnedConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	connection := &closeTrackingConn{Conn: client}
	_, err := CallTCP(
		context.Background(),
		TCPRequest{IdempotencyKey: "key-1", Operation: "read"},
		RetryPolicy{MaxAttempts: 1, AttemptTimeout: time.Second},
		func(context.Context) (net.Conn, error) {
			return connection, errors.New("dial completed ambiguously")
		},
		nil,
	)
	if !errors.Is(err, ErrNotAcknowledged) {
		t.Fatalf("CallTCP error = %v", err)
	}
	if !connection.closed {
		t.Fatal("connection returned with dial error was not closed")
	}
}

func TestUDPACKLossSurvivesInterveningCapacityPressure(t *testing.T) {
	clock := newUDPTestClock()
	receiver := newUDPTestReceiver(t, clock, 1, 8, time.Minute)
	data := UDPFrame{
		Version:   UDPVersion,
		Kind:      UDPKindData,
		ClientID:  testID(1),
		MessageID: testID(2),
		Sequence:  17,
		Payload:   []byte("apply-once"),
	}
	var sent []UDPFrame
	var firstACK UDPFrame
	sideEffects := 0
	pressureEffects := 0
	waits := 0
	ack, err := SendUDP(
		context.Background(),
		data,
		RetryPolicy{MaxAttempts: 4, AttemptTimeout: time.Second},
		func(_ context.Context, frame UDPFrame) (UDPFrame, error) {
			sent = append(sent, frame)
			response, handleErr := receiver.Handle(frame, func(UDPFrame) ([]byte, error) {
				sideEffects++
				return []byte("accepted"), nil
			})
			if handleErr != nil {
				return UDPFrame{}, handleErr
			}
			if len(sent) == 1 {
				firstACK = response
				pressure := data
				pressure.MessageID = testID(7)
				pressure.Sequence++
				if _, pressureErr := receiver.Handle(pressure, func(UDPFrame) ([]byte, error) {
					pressureEffects++
					return []byte("must-not-apply"), nil
				}); !errors.Is(pressureErr, ErrUDPCapacity) {
					t.Fatalf("capacity pressure error = %v", pressureErr)
				}
				return UDPFrame{}, ErrNoAcknowledgement
			}
			return response, nil
		},
		func(context.Context, int) error {
			waits++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SendUDP: %v", err)
	}
	if len(sent) != 2 || !reflect.DeepEqual(sent[0], data) || !reflect.DeepEqual(sent[1], data) {
		t.Fatalf("UDP frame changed across retransmission: %+v", sent)
	}
	if sideEffects != 1 || pressureEffects != 0 || waits != 1 {
		t.Fatalf("side effects/pressure effects/waits = %d/%d/%d, want 1/0/1", sideEffects, pressureEffects, waits)
	}
	if !reflect.DeepEqual(ack, firstACK) || ack.Kind != UDPKindACK || string(ack.Payload) != "accepted" {
		t.Fatalf("cached ACK mismatch: first=%+v final=%+v", firstACK, ack)
	}
}

func TestUDPReceiverDeduplicatesDuplicateDeliveryAndRejectsIDConflict(t *testing.T) {
	receiver := newUDPTestReceiver(t, newUDPTestClock(), 4, 8, time.Minute)
	data := UDPFrame{
		Version:   UDPVersion,
		Kind:      UDPKindData,
		ClientID:  testID(3),
		MessageID: testID(4),
		Sequence:  1,
		Payload:   []byte("command"),
	}
	sideEffects := 0
	apply := func(UDPFrame) ([]byte, error) {
		sideEffects++
		return []byte("ack-body"), nil
	}
	first, err := receiver.Handle(data, apply)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := receiver.Handle(data, apply)
	if err != nil {
		t.Fatal(err)
	}
	if sideEffects != 1 || !reflect.DeepEqual(first, duplicate) || receiver.Entries() != 1 {
		t.Fatalf("duplicate handling: effects=%d first=%+v duplicate=%+v entries=%d", sideEffects, first, duplicate, receiver.Entries())
	}
	data.Payload = []byte("different-command")
	if _, err := receiver.Handle(data, apply); !errors.Is(err, ErrMessageIDConflict) {
		t.Fatalf("message ID conflict error = %v", err)
	}
	if sideEffects != 1 {
		t.Fatalf("conflicting duplicate applied side effect: %d", sideEffects)
	}
	data.Payload = []byte("command")
	data.Sequence++
	if _, err := receiver.Handle(data, apply); !errors.Is(err, ErrMessageIDConflict) {
		t.Fatalf("message ID sequence conflict error = %v", err)
	}
	data.MessageID = testID(8)
	data.Sequence--
	if _, err := receiver.Handle(data, apply); !errors.Is(err, ErrUDPSequenceConflict) {
		t.Fatalf("sequence ownership conflict error = %v", err)
	}
	if sideEffects != 1 {
		t.Fatalf("ID conflicts applied side effects: %d", sideEffects)
	}
}

func TestUDPReceiverAcceptsBoundedReorderingAndRejectsStaleSequence(t *testing.T) {
	receiver := newUDPTestReceiver(t, newUDPTestClock(), 8, 4, time.Minute)
	clientID := testID(20)
	sequences := []uint64{10, 13, 11, 12, 14}
	frames := make([]UDPFrame, 0, len(sequences))
	applied := make([]uint64, 0, len(sequences))
	var firstACK UDPFrame
	for index, sequence := range sequences {
		frame := UDPFrame{
			Version:   UDPVersion,
			Kind:      UDPKindData,
			ClientID:  clientID,
			MessageID: testID(byte(21 + index)),
			Sequence:  sequence,
			Payload:   []byte{byte(sequence)},
		}
		frames = append(frames, frame)
		ack, err := receiver.Handle(frame, func(frame UDPFrame) ([]byte, error) {
			applied = append(applied, frame.Sequence)
			return []byte{byte(frame.Sequence)}, nil
		})
		if err != nil {
			t.Fatalf("Handle sequence %d: %v", sequence, err)
		}
		if index == 0 {
			firstACK = ack
		}
	}
	if !reflect.DeepEqual(applied, sequences) {
		t.Fatalf("application order = %v, want accepted arrival order %v", applied, sequences)
	}
	window := receiver.clients[clientID]
	if window.highest != 14 || len(window.sequences) != 4 {
		t.Fatalf("client replay state = highest %d, entries %d; want 14/4", window.highest, len(window.sequences))
	}

	// Sequence 10 is now outside [11, 14], but its retained exact duplicate
	// still receives the original ACK without another side effect.
	replayedACK, err := receiver.Handle(frames[0], func(UDPFrame) ([]byte, error) {
		t.Fatal("retained duplicate applied a second side effect")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("retained ACK replay: %v", err)
	}
	if !reflect.DeepEqual(replayedACK, firstACK) {
		t.Fatalf("replayed ACK = %+v, want %+v", replayedACK, firstACK)
	}

	stale := frames[0]
	stale.MessageID = testID(30)
	if _, err := receiver.Handle(stale, func(UDPFrame) ([]byte, error) {
		t.Fatal("stale sequence applied a side effect")
		return nil, nil
	}); !errors.Is(err, ErrUDPStaleSequence) {
		t.Fatalf("stale sequence error = %v", err)
	}
}

func TestUDPReceiverRetainsRecordsForExplicitRetryHorizon(t *testing.T) {
	clock := newUDPTestClock()
	horizon := 10 * time.Second
	receiver := newUDPTestReceiver(t, clock, 1, 4, horizon)
	first := UDPFrame{
		Version:   UDPVersion,
		Kind:      UDPKindData,
		ClientID:  testID(31),
		MessageID: testID(32),
		Sequence:  1,
		Payload:   []byte("first"),
	}
	second := first
	second.MessageID = testID(33)
	second.Sequence = 2
	second.Payload = []byte("second")
	effects := 0
	apply := func(UDPFrame) ([]byte, error) {
		effects++
		return []byte("accepted"), nil
	}
	if _, err := receiver.Handle(first, apply); err != nil {
		t.Fatal(err)
	}
	clock.Advance(horizon - time.Nanosecond)
	if _, err := receiver.Handle(second, apply); !errors.Is(err, ErrUDPCapacity) {
		t.Fatalf("capacity before retry horizon = %v", err)
	}
	clock.Advance(time.Nanosecond)
	otherClient := second
	otherClient.ClientID = testID(34)
	if _, err := receiver.Handle(otherClient, apply); !errors.Is(err, ErrUDPCapacity) {
		t.Fatalf("remembered client capacity error = %v", err)
	}
	if _, err := receiver.Handle(second, apply); err != nil {
		t.Fatalf("admit after retry horizon: %v", err)
	}
	if effects != 2 || receiver.Entries() != 1 {
		t.Fatalf("effects/entries = %d/%d, want 2/1", effects, receiver.Entries())
	}
	if _, err := receiver.Handle(first, apply); !errors.Is(err, ErrUDPStaleSequence) {
		t.Fatalf("expired ACK replay error = %v", err)
	}
	if effects != 2 {
		t.Fatalf("expired replay applied side effect: %d", effects)
	}
}

func TestUDPRetransmissionStopsAtBoundWithStableIDs(t *testing.T) {
	data := UDPFrame{
		Version:   UDPVersion,
		Kind:      UDPKindData,
		ClientID:  testID(5),
		MessageID: testID(6),
		Sequence:  99,
		Payload:   []byte("important"),
	}
	var sent []UDPFrame
	waits := 0
	_, err := SendUDP(
		context.Background(),
		data,
		RetryPolicy{MaxAttempts: 3, AttemptTimeout: time.Second},
		func(_ context.Context, frame UDPFrame) (UDPFrame, error) {
			sent = append(sent, cloneUDPFrame(frame))
			frame.Payload[0] = 'x'
			return UDPFrame{}, ErrNoAcknowledgement
		},
		func(context.Context, int) error {
			waits++
			return nil
		},
	)
	if !errors.Is(err, ErrNotAcknowledged) {
		t.Fatalf("SendUDP error = %v", err)
	}
	if len(sent) != 3 || waits != 2 {
		t.Fatalf("attempts/waits = %d/%d, want 3/2", len(sent), waits)
	}
	for index, frame := range sent {
		if !reflect.DeepEqual(frame, data) {
			t.Fatalf("attempt %d changed IDs, sequence, or payload: %+v", index+1, frame)
		}
	}
}

func TestUDPRetransmissionStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	waits := 0
	_, err := SendUDP(
		ctx,
		UDPFrame{
			Version:   UDPVersion,
			Kind:      UDPKindData,
			ClientID:  testID(40),
			MessageID: testID(41),
			Sequence:  1,
			Payload:   []byte("bounded"),
		},
		RetryPolicy{MaxAttempts: 3, AttemptTimeout: time.Second},
		func(context.Context, UDPFrame) (UDPFrame, error) {
			attempts++
			cancel()
			return UDPFrame{}, ErrNoAcknowledgement
		},
		func(context.Context, int) error {
			waits++
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendUDP cancellation error = %v", err)
	}
	if attempts != 1 || waits != 0 {
		t.Fatalf("attempts/waits after cancellation = %d/%d, want 1/0", attempts, waits)
	}
}

func testID(last byte) UDPID {
	var id UDPID
	id[len(id)-1] = last
	return id
}

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

type udpTestClock struct {
	now time.Time
}

func newUDPTestClock() *udpTestClock {
	return &udpTestClock{now: time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC)}
}

func (c *udpTestClock) Now() time.Time {
	return c.now
}

func (c *udpTestClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

func newUDPTestReceiver(t *testing.T, clock *udpTestClock, capacity int, replayWindow uint64, retryHorizon time.Duration) *UDPReceiver {
	t.Helper()
	receiver, err := NewUDPReceiverWithConfig(UDPReceiverConfig{
		Capacity:     capacity,
		RetryHorizon: retryHorizon,
		ReplayWindow: replayWindow,
		Now:          clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return receiver
}
