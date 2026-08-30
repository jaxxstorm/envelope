package datapath

import (
	"sync"

	"github.com/jaxxstorm/envelope/internal/metrics"
)

var readinessComponents = [...]string{
	metrics.ReadinessComponentReceiver,
	metrics.ReadinessComponentValidation,
	metrics.ReadinessComponentSender,
}

type componentState struct {
	initialized bool
	failures    int
	unhealthy   bool
}

type readinessTracker struct {
	mu        sync.RWMutex
	threshold int
	states    map[string]componentState
	metrics   *metrics.Metrics
}

func newReadinessTracker(threshold int, metricSet *metrics.Metrics) *readinessTracker {
	states := make(map[string]componentState, len(readinessComponents))
	for _, component := range readinessComponents {
		states[component] = componentState{}
	}
	return &readinessTracker{threshold: threshold, states: states, metrics: metricSet}
}

func (l *readinessTracker) Initialize(component string) {
	l.mu.Lock()
	state := l.states[component]
	wasReady := componentReady(state)
	state.initialized = true
	state.failures = 0
	state.unhealthy = false
	l.states[component] = state
	l.recordTransitionLocked(component, wasReady, componentReady(state))
	l.mu.Unlock()
}

func (l *readinessTracker) Shutdown() {
	l.mu.Lock()
	for _, component := range readinessComponents {
		state := l.states[component]
		wasReady := componentReady(state)
		state.initialized = false
		state.failures = 0
		state.unhealthy = false
		l.states[component] = state
		l.recordTransitionLocked(component, wasReady, false)
	}
	l.mu.Unlock()
}

func (l *readinessTracker) Failure(component string) bool {
	l.mu.Lock()
	state := l.states[component]
	wasReady := componentReady(state)
	state.failures++
	becameUnhealthy := !state.unhealthy && state.failures >= l.threshold
	if becameUnhealthy {
		state.unhealthy = true
	}
	l.states[component] = state
	isReady := componentReady(state)
	l.recordTransitionLocked(component, wasReady, isReady)
	l.mu.Unlock()
	return becameUnhealthy
}

func (l *readinessTracker) Fatal(component string) {
	l.mu.Lock()
	state := l.states[component]
	wasReady := componentReady(state)
	state.failures = l.threshold
	state.unhealthy = true
	l.states[component] = state
	l.recordTransitionLocked(component, wasReady, false)
	l.mu.Unlock()
}

func (l *readinessTracker) Success(component string) {
	l.mu.Lock()
	state := l.states[component]
	wasReady := componentReady(state)
	state.failures = 0
	state.unhealthy = false
	l.states[component] = state
	l.recordTransitionLocked(component, wasReady, componentReady(state))
	l.mu.Unlock()
}

func (l *readinessTracker) Ready() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.readyLocked()
}

func (l *readinessTracker) readyLocked() bool {
	for _, component := range readinessComponents {
		if !componentReady(l.states[component]) {
			return false
		}
	}
	return true
}

func (l *readinessTracker) Reason() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, component := range readinessComponents {
		state := l.states[component]
		if !state.initialized {
			return component + "_not_initialized"
		}
		if state.unhealthy {
			return component + "_persistent_failure"
		}
	}
	return "ok"
}

func (l *readinessTracker) recordTransitionLocked(component string, wasReady, isReady bool) {
	if wasReady != isReady {
		value := 0.0
		state := metrics.ReadinessStateNotReady
		if isReady {
			value = 1
			state = metrics.ReadinessStateReady
		}
		l.metrics.TargetComponentReady.WithLabelValues(component).Set(value)
		l.metrics.TargetReadinessTransitions.WithLabelValues(component, state).Inc()
	}
	if l.readyLocked() {
		l.metrics.TargetReady.Set(1)
	} else {
		l.metrics.TargetReady.Set(0)
	}
}

func componentReady(state componentState) bool {
	return state.initialized && !state.unhealthy
}
