# Application Resilience Across Failover

Envelope aligns future packet paths after control-plane convergence. It does not transparently repair an established flow, replicate TCP or UDP state, preserve a five-tuple, or replay application data. Failover is not atomic or hitless, and UDP is not lossless. Reconnect, idempotency, acknowledgement, deduplication, and retransmission are application responsibilities.

Use the [production-controller SLO boundaries](production-controller.md#proposed-slo-boundaries) to size retry deadlines. The initial composite network objective is 105 seconds pending protected controller evidence, so an application retry horizon must exceed that interval plus its own service time. A shorter deadline can fail correctly before the network is expected to recover.

## TCP Contract

An established connection can reset, stall until its deadline, or remain unusable after the route changes. On `EOF`, reset, timeout, or failed health check, close that socket and dial a fresh connection. The new connection, not reuse of the old `net.Conn`, is the recovery attempt.

Retrying a side-effecting request creates an unknown-outcome problem: the server may have committed the operation even when the response was lost. Generate one idempotency key before the first attempt and reuse that same key and request body on every reconnect. Snapshot mutable request bytes before the first attempt so caller mutation cannot change a later retry. Never generate a new key per connection attempt.

The following Go-oriented pattern uses a bounded context, fresh TCP connections, exponential backoff with jitter, and one stable idempotency key. For the initial controller objectives, the caller should normally give `ctx` at least a 135-second deadline; use a shorter product deadline only when failing before network recovery is acceptable.

```go
type Request struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Operation      string          `json:"operation"`
	Payload        json.RawMessage `json:"payload"`
}

type Response struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Result         json.RawMessage `json:"result"`
}

func CallTCP(ctx context.Context, address string, request Request) (Response, error) {
	if request.IdempotencyKey == "" {
		return Response{}, errors.New("idempotency key is required")
	}
	request.Payload = append(json.RawMessage(nil), request.Payload...)

	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 32; attempt++ {
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
		if err == nil {
			deadline := time.Now().Add(5 * time.Second)
			if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
				deadline = contextDeadline
			}
			err = conn.SetDeadline(deadline)
			if err == nil {
				err = json.NewEncoder(conn).Encode(request)
			}
			var response Response
			if err == nil {
				err = json.NewDecoder(bufio.NewReader(conn)).Decode(&response)
			}
			_ = conn.Close()
			if err == nil {
				if response.IdempotencyKey != request.IdempotencyKey {
					return Response{}, errors.New("response idempotency key mismatch")
				}
				return response, nil
			}
		}
		lastErr = err

		if attempt == 31 {
			break
		}
		if err := waitContext(ctx, jitter(backoff)); err != nil {
			return Response{}, err
		}
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
	return Response{}, fmt.Errorf("TCP operation was not acknowledged: %w", lastErr)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func jitter(limit time.Duration) time.Duration {
	if limit <= time.Millisecond {
		return limit
	}
	var random [8]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return limit
	}
	half := limit / 2
	return half + time.Duration(binary.LittleEndian.Uint64(random[:])%uint64(half+1))
}
```

The application imports `bufio`, `context`, `crypto/rand` as `cryptorand`, `encoding/binary`, `encoding/json`, `errors`, `fmt`, `net`, and `time`. Use TLS or another authenticated transport in production; authentication and framing were omitted from the pattern, not from the security requirement.

### Server-Side Idempotency

Bind the key to the authenticated caller and a hash of the canonical operation and payload. Store the side effect and the completed response atomically with the idempotency record. Keep that record longer than the maximum client retry horizon. A repeated key with the same hash returns the stored response; the same key with a different hash is a conflict.

```text
BEGIN TRANSACTION
  prior = SELECT result, payload_hash
          FROM idempotency
          WHERE principal = P AND idempotency_key = K
          FOR UPDATE

  if prior exists:
      require prior.payload_hash == SHA256(canonical_request)
      COMMIT
      return prior.result

  result = apply_side_effect_or_append_to_outbox()
  INSERT idempotency(P, K, SHA256(canonical_request), result, expires_at)
COMMIT
return result
```

The side effect and idempotency row must share one transactional boundary. A cache write after an external side effect still permits duplicates after a crash. When the side effect cannot share a transaction, use a durable command queue, transactional outbox, or downstream idempotency key.

Read-only operations may be retried without a side-effect key, but they still need bounded attempts, per-attempt deadlines, jitter, and an overall context. Do not retry permanent authentication, validation, or authorization failures.

## Retryable UDP Contract

Raw UDP has no connection recovery, delivery acknowledgement, ordering, duplicate suppression, or retransmission. A retryable application protocol must add all of them for important messages.

Use an authenticated frame with at least:

```go
type Datagram struct {
	Version   uint8
	Kind      uint8 // data or ACK
	ClientID  [16]byte
	MessageID [16]byte
	Sequence  uint64
	Payload   []byte
}
```

- `ClientID` identifies a stable authenticated sender-session namespace. Never reuse it with reset sequence state; preserve its high-water state durably or authenticate a new random session ID after a deliberate reset.
- `MessageID` is generated once with cryptographic randomness and remains unchanged across retransmissions.
- `Sequence` is positive and monotonic within the sender session and supports replay-window and ordering policy; it is not a substitute for `MessageID`. Start a new authenticated session before `uint64` exhaustion rather than wrapping it.
- An ACK echoes `ClientID`, `MessageID`, and `Sequence` and is accepted only from the authenticated expected peer.
- The receiver's deduplication key is at least `(ClientID, MessageID)`, with its sequence, canonical payload hash, original ACK, and retention deadline stored atomically.

Choose an explicit replay width `W`. For a client whose highest accepted sequence is `H`, this reference accepts an unseen sequence greater than `H` and advances the window. It also accepts an unseen out-of-order sequence in `[max(1, H-W+1), H]` and applies accepted messages in arrival order; it does not buffer them for sequence order. A new message below that interval is stale. A different message ID claiming an accepted sequence is a sequence conflict, and one message ID claiming different sequence or payload data is a message-ID conflict while that evidence is retained. This bounded replay policy complements the time-based deduplication window; neither bound may silently weaken the other.

An exact retained `(ClientID, MessageID, Sequence, payload hash)` duplicate is special: look it up before the replay-window and capacity checks and return its cached ACK without applying it. This remains true if newer traffic has moved its sequence below the active replay interval. Once its ACK retention ends, a sequence still known by the client window is rejected as stale rather than applied again.

### Bounded Sender

```text
message = DATA(client_id, random_message_id_once(), next_sequence(), payload)
deadline = min(application_overall_deadline, now + 135s)
rto = 250ms

for attempt in 1..32:
    authenticate_and_send(message)
    attempt_wait = jitter(rto)
    until min(now + attempt_wait, deadline):
        frame = receive_with_deadline()
        if authenticated_expected_peer(frame) and
           frame.kind == ACK and
           frame.client_id == message.client_id and
           frame.message_id == message.message_id and
           frame.sequence == message.sequence:
            return ACKNOWLEDGED

    rto = min(2 * rto, 5s)

return NOT_ACKNOWLEDGED
```

Retransmit the same semantic message and ID, not a newly identified copy. Bound both attempts and elapsed time. If the bound expires, return an unknown outcome to the caller or retain the command in a durable outbox; do not continue an infinite retry loop.

The sender's maximum overall deadline is its retry horizon, including failover wait, backoff, attempt time, processing, and any durable redelivery. Every exchange and backoff implementation must honor its supplied context. The receiver retention setting must be at least that maximum retransmission horizon plus clock and processing margin, not merely one attempt timeout. For the 135-second example above, three minutes is a reasonable illustrative receiver setting; applications must use their own measured bound.

### Receiver Deduplication And ACK

The executable model in `internal/controller/resilience` requires the retention and replay bounds explicitly. It uses an injected monotonic clock in tests and returns `ErrUDPCapacity` before calling the side effect when no record can be admitted.

```go
receiver, err := resilience.NewUDPReceiverWithConfig(resilience.UDPReceiverConfig{
	Capacity:     4096,
	RetryHorizon: 3 * time.Minute,
	ReplayWindow: 64,
	Now:          time.Now,
})
```

`Capacity` bounds retained ACK records and the number of remembered client namespaces in this in-memory model. The compact `NewUDPReceiver(capacity)` constructor uses the exported five-minute and 64-sequence reference defaults for the integration harness; production adaptations should use explicit values. The model never evicts client replay state during its lifetime. A production service may instead use an authenticated client allowlist or durable, explicitly expired session state, but it must not silently forget a live namespace and then accept its old sequence as new.

```text
on authenticated DATA message:
    validate version, size, client_id, message_id, sequence, and payload hash

    BEGIN TRANSACTION
      remove only ACK records whose explicit retention deadline has ended
      prior = lookup(client_id, message_id)
      if prior exists:
          require prior.sequence == message.sequence
          require prior.payload_hash == SHA256(message.payload)
          ack = prior.ack
      else:
          require sequence is unseen and inside the client's replay policy
          require message_id does not conflict with retained client-window state
          if ACK or client capacity is still full:
              reject BUSY before applying a side effect
          result = apply_side_effect_or_append_to_outbox(message.payload)
          ack = ACK(client_id, message_id, sequence, result_digest)
          atomically store dedup record and ACK with replay-state advancement
          retain_until = apply_completion_time + configured_retry_horizon
    COMMIT

    authenticate_and_send(ack)
```

If DATA is duplicated, the receiver returns the cached ACK without repeating the side effect. If the first ACK is lost, retransmission elicits the same ACK even when unrelated messages filled the receiver afterward. Capacity pressure must reject, drop, or return an authenticated retryable `BUSY` response for new work; it must never evict an unexpired record to make room. Exact duplicates remain serviceable while capacity is full. Size capacity for the maximum admitted rate multiplied by the retention horizon, reserve headroom for retry bursts, and apply admission control before exhaustion.

Use durable storage when receiver restart must not permit duplicate effects. The side effect, replay-window update, dedup record, and ACK must share one transactional boundary, or the operation must use a transactional outbox/downstream idempotency key. Cap payloads and per-client rates as well as ACK records, client namespaces, and replay width.

For commands that must survive an exhausted retry bound, use a durable queue or outbox rather than relying on raw UDP. QUIC can provide transport-level loss recovery and connection migration, but it remains an application transport and does not turn Envelope failover into transparent or hitless flow repair.

## Fault-Oriented Application Tests

Run these cases in the application's own test suite with a deterministic fake clock and packet/connection fault injector:

| Case | Required assertion |
| --- | --- |
| TCP response loss | Commit the request, drop the first response, reconnect with the same idempotency key, and assert one side effect plus the stored response. |
| TCP partial exchange | Reset the first socket after request bytes, require a fresh connection, and assert bounded attempts and one side effect. |
| TCP retry exhaustion | Keep the peer unavailable and assert the overall context ends the loop with no unbounded goroutine or socket. |
| UDP DATA loss | Drop initial DATA frames, deliver a retransmission, and assert the message ID and sequence never change. |
| UDP ACK loss under capacity pressure | Apply once, drop the first ACK, fill remaining capacity with intervening traffic, and assert pressure cannot evict the record, the duplicate causes no side effect, and the original matching ACK is replayed. |
| UDP duplication | Deliver an exact frame more than once and assert one side effect plus byte-identical cached ACKs. |
| UDP in-window reordering | Deliver unseen sequences out of order inside `[H-W+1, H]` and assert each is accepted once in documented arrival order. |
| UDP stale replay | Move the high-water sequence beyond an older frame, submit a new ID at that old sequence, and assert rejection without a side effect. |
| UDP ID conflict | Reuse a message ID with changed sequence or payload and claim one sequence with a different message ID; assert both forms are rejected. |
| UDP retention and capacity | Fill capacity, advance a fake clock to immediately before and then to the explicit retry horizon, and assert rejection before expiry and admission only after expiry. |
| UDP retry exhaustion | Drop every frame and assert retransmission stops at the attempt or elapsed-time bound, preserves immutable frame bytes, and surfaces an unknown outcome. |

These tests validate the application's recovery semantics. They do not prove Envelope route convergence, and Envelope controller tests do not prove application idempotency.
