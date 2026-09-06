package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/store"
)

func TestFakeClockAdvancesTimersDeterministically(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	later := clock.After(2 * time.Minute)
	earlier := clock.After(time.Minute)

	if got := clock.Now(); !got.Equal(testTime) {
		t.Fatalf("Now() = %v, want %v", got, testTime)
	}
	if got := clock.PendingTimers(); got != 2 {
		t.Fatalf("PendingTimers() = %d, want 2", got)
	}

	clock.Advance(time.Minute)
	if got := <-earlier; !got.Equal(testTime.Add(time.Minute)) {
		t.Fatalf("earlier timer = %v, want %v", got, testTime.Add(time.Minute))
	}
	select {
	case got := <-later:
		t.Fatalf("later timer fired early at %v", got)
	default:
	}

	clock.Advance(time.Minute)
	if got := <-later; !got.Equal(testTime.Add(2 * time.Minute)) {
		t.Fatalf("later timer = %v, want %v", got, testTime.Add(2*time.Minute))
	}
	if got := clock.PendingTimers(); got != 0 {
		t.Fatalf("PendingTimers() = %d, want 0", got)
	}

	immediate := clock.After(0)
	if got := <-immediate; !got.Equal(testTime.Add(2 * time.Minute)) {
		t.Fatalf("immediate timer = %v, want current time", got)
	}
}

func TestWaitUsesClockAndCancellation(t *testing.T) {
	t.Run("advance", func(t *testing.T) {
		clock := store.NewFakeClock(testTime)
		done := make(chan error, 1)
		go func() {
			done <- store.Wait(context.Background(), clock, time.Minute)
		}()
		waitForTimers(t, clock, 1)
		clock.Advance(time.Minute)
		if err := <-done; err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
	})

	t.Run("canceled while waiting", func(t *testing.T) {
		clock := store.NewFakeClock(testTime)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- store.Wait(ctx, clock, time.Hour)
		}()
		waitForTimers(t, clock, 1)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait() error = %v, want context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Wait() did not return after cancellation")
		}
	})

	t.Run("already canceled", func(t *testing.T) {
		clock := store.NewFakeClock(testTime)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := store.Wait(ctx, clock, time.Hour); !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait() error = %v, want context.Canceled", err)
		}
		if got := clock.PendingTimers(); got != 0 {
			t.Fatalf("PendingTimers() = %d, want 0", got)
		}
	})
}

func TestFakeClockRejectsBackwardAdvance(t *testing.T) {
	clock := store.NewFakeClock(testTime)
	defer func() {
		if recover() == nil {
			t.Fatal("Advance() did not panic for a negative duration")
		}
	}()
	clock.Advance(-time.Nanosecond)
}

func waitForTimers(t *testing.T, clock *store.FakeClock, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for clock.PendingTimers() != count {
		if time.Now().After(deadline) {
			t.Fatalf("PendingTimers() = %d, want %d", clock.PendingTimers(), count)
		}
		time.Sleep(time.Millisecond)
	}
}
