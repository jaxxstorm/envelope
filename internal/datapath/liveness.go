package datapath

import (
	"sync"

	"github.com/jaxxstorm/envelope/internal/metrics"
)

var livenessComponents = [...]string{
	metrics.LivenessComponentReceive,
	metrics.LivenessComponentTunWrite,
}

type componentState struct {
	failures  int
	unhealthy bool
}

type livenessTracker struct {
	mu        sync.RWMutex
	threshold int
	states    map[string]componentState
	metrics   *metrics.Metrics
}

func newLivenessTracker(threshold int, metricSet *metrics.Metrics) *livenessTracker {
	states := make(map[string]componentState, len(livenessComponents))
	for _, component := range livenessComponents {
		states[component] = componentState{}
	}
	return &livenessTracker{threshold: threshold, states: states, metrics: metricSet}
}

func (l *livenessTracker) Failure(component string) {
	l.mu.Lock()
	state := l.states[component]
	state.failures++
	transitioned := !state.unhealthy && state.failures >= l.threshold
	if transitioned {
		state.unhealthy = true
	}
	l.states[component] = state
	if transitioned {
		l.metrics.DatapathComponentHealthy.WithLabelValues(component).Set(0)
		l.metrics.DatapathLivenessTransitions.WithLabelValues(component, "unhealthy").Inc()
	}
	l.mu.Unlock()
}

func (l *livenessTracker) Fatal(component string) {
	l.mu.Lock()
	state := l.states[component]
	transitioned := !state.unhealthy
	state.failures = l.threshold
	state.unhealthy = true
	l.states[component] = state
	if transitioned {
		l.metrics.DatapathComponentHealthy.WithLabelValues(component).Set(0)
		l.metrics.DatapathLivenessTransitions.WithLabelValues(component, "unhealthy").Inc()
	}
	l.mu.Unlock()
}

func (l *livenessTracker) Success(component string) {
	l.mu.Lock()
	state := l.states[component]
	transitioned := state.unhealthy
	state.failures = 0
	state.unhealthy = false
	l.states[component] = state
	if transitioned {
		l.metrics.DatapathComponentHealthy.WithLabelValues(component).Set(1)
		l.metrics.DatapathLivenessTransitions.WithLabelValues(component, "healthy").Inc()
	}
	l.mu.Unlock()
}

func (l *livenessTracker) Healthy() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, component := range livenessComponents {
		if l.states[component].unhealthy {
			return false
		}
	}
	return true
}

func (l *livenessTracker) Reason() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, component := range livenessComponents {
		if l.states[component].unhealthy {
			return component
		}
	}
	return "ok"
}
