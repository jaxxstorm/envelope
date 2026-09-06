package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Clock supplies wall timestamps and monotonic waits. Controller code should
// use the channel only as a wake-up signal rather than as lease authority.
type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

// RealClock delegates to the process clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) After(duration time.Duration) <-chan time.Time {
	return time.After(duration)
}

// Wait blocks on an injected clock and remains cancelable.
func Wait(ctx context.Context, clock Clock, duration time.Duration) error {
	if ctx == nil {
		return errors.New("store: context is nil")
	}
	if clock == nil {
		return errors.New("store: clock is nil")
	}
	if duration < 0 {
		return errors.New("store: wait duration cannot be negative")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clock.After(duration):
		return nil
	}
}

// FakeClock is a manually advanced, concurrency-safe clock. Timers due in one
// advance fire in deadline and registration order.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	nextID  uint64
	waiters []fakeWaiter
}

type fakeWaiter struct {
	deadline time.Time
	id       uint64
	ch       chan time.Time
}

func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) After(duration time.Duration) <-chan time.Time {
	c.mu.Lock()
	deadline := c.now.Add(duration)
	ch := make(chan time.Time, 1)
	if duration <= 0 {
		now := c.now
		c.mu.Unlock()
		ch <- now
		return ch
	}
	c.nextID++
	c.waiters = append(c.waiters, fakeWaiter{deadline: deadline, id: c.nextID, ch: ch})
	c.mu.Unlock()
	return ch
}

// Advance moves time forward and wakes all newly due timers. It panics for a
// negative duration because a manual monotonic clock cannot move backward.
func (c *FakeClock) Advance(duration time.Duration) {
	if duration < 0 {
		panic("store: fake clock cannot move backward")
	}

	c.mu.Lock()
	c.now = c.now.Add(duration)
	now := c.now
	due := make([]fakeWaiter, 0, len(c.waiters))
	pending := c.waiters[:0]
	for _, waiter := range c.waiters {
		if waiter.deadline.After(now) {
			pending = append(pending, waiter)
			continue
		}
		due = append(due, waiter)
	}
	c.waiters = pending
	sort.Slice(due, func(i, j int) bool {
		if due[i].deadline.Equal(due[j].deadline) {
			return due[i].id < due[j].id
		}
		return due[i].deadline.Before(due[j].deadline)
	})
	c.mu.Unlock()

	for _, waiter := range due {
		waiter.ch <- waiter.deadline
	}
}

// PendingTimers reports timers not yet fired. It is intended for deterministic
// test synchronization before calling Advance.
func (c *FakeClock) PendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}
