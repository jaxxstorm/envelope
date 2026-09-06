package integration

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/resilience"
)

func TestRouterLossConvergesRoutesBeforeFreshApplicationRetry(t *testing.T) {
	t.Run("TCP reconnect", func(t *testing.T) {
		h := newHarness(t)
		controller := h.initializeAutonomousLeader("controller-a")
		if !h.network.Ready() {
			t.Fatal("initial application path is not aligned")
		}
		if err := h.tailnet.LoseRouter("node-a"); err != nil {
			t.Fatal(err)
		}
		if h.network.Ready() {
			t.Fatal("application path remained available before AWS route convergence")
		}

		waits := 0
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		request := resilience.TCPRequest{
			IdempotencyKey: "integration:create:42",
			Operation:      "create",
			Payload:        []byte("value-42"),
		}
		response, err := resilience.CallTCP(
			ctx,
			request,
			resilience.RetryPolicy{MaxAttempts: 2, AttemptTimeout: time.Second},
			h.network.DialTCP,
			func(ctx context.Context, _ int) error {
				waits++
				return h.advanceUntilReady(ctx, controller)
			},
		)
		if err != nil {
			t.Fatalf("TCP recovery: %v", err)
		}
		h.network.AwaitTCPServer(t)
		state := h.state()
		if state.Phase != model.PhaseStable || state.StableOwner != "node-b" || !h.network.Ready() {
			t.Fatalf("post-failover state/path = %+v/%t", state, h.network.Ready())
		}
		calls := h.aws.Calls()
		if len(calls) != len(h.authority.RemotePrefixes) {
			t.Fatalf("route calls = %d, want %d", len(calls), len(h.authority.RemotePrefixes))
		}
		for _, call := range calls {
			if call.desiredENI != "eni-b" || !call.deadline.Before(state.Lease.ExpiresAt) {
				t.Fatalf("route call escaped selected owner or lease bound: %+v", call)
			}
		}
		dials, effects := h.network.TCPStats()
		if dials != 2 || waits != 1 || effects != 1 {
			t.Fatalf("TCP dials/waits/effects = %d/%d/%d, want 2/1/1", dials, waits, effects)
		}
		if response.IdempotencyKey != request.IdempotencyKey || string(response.Result) != "tcp-committed" {
			t.Fatalf("TCP response = %+v", response)
		}
	})

	t.Run("UDP retransmission", func(t *testing.T) {
		h := newHarness(t)
		controller := h.initializeAutonomousLeader("controller-a")
		if err := h.tailnet.LoseRouter("node-a"); err != nil {
			t.Fatal(err)
		}
		if h.network.Ready() {
			t.Fatal("application path remained available before AWS route convergence")
		}

		data := resilience.UDPFrame{
			Version:   resilience.UDPVersion,
			Kind:      resilience.UDPKindData,
			ClientID:  integrationID(1),
			MessageID: integrationID(2),
			Sequence:  9,
			Payload:   []byte("important-datagram"),
		}
		waits := 0
		ack, err := resilience.SendUDP(
			context.Background(),
			data,
			resilience.RetryPolicy{MaxAttempts: 2, AttemptTimeout: time.Second},
			h.network.ExchangeUDP,
			func(ctx context.Context, _ int) error {
				waits++
				return h.advanceUntilReady(ctx, controller)
			},
		)
		if err != nil {
			t.Fatalf("UDP recovery: %v", err)
		}
		sent, effects := h.network.UDPStats()
		if len(sent) != 2 || !reflect.DeepEqual(sent[0], data) || !reflect.DeepEqual(sent[1], data) {
			t.Fatalf("UDP IDs or payload changed across convergence: %+v", sent)
		}
		if waits != 1 || effects != 1 {
			t.Fatalf("UDP waits/effects = %d/%d, want 1/1", waits, effects)
		}
		if ack.Kind != resilience.UDPKindACK || ack.ClientID != data.ClientID || ack.MessageID != data.MessageID || ack.Sequence != data.Sequence {
			t.Fatalf("UDP ACK does not identify the sent message: %+v", ack)
		}
		state := h.state()
		if state.Phase != model.PhaseStable || state.StableOwner != "node-b" || !h.network.Ready() {
			t.Fatalf("post-failover state/path = %+v/%t", state, h.network.Ready())
		}
	})
}

func integrationID(last byte) resilience.UDPID {
	var id resilience.UDPID
	id[len(id)-1] = last
	return id
}
