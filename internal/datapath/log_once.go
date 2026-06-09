package datapath

import "sync"

type logOnce struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newLogOnce() *logOnce {
	return &logOnce{seen: make(map[string]struct{})}
}

func (l *logOnce) ShouldLog(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[key]; ok {
		return false
	}
	l.seen[key] = struct{}{}
	return true
}
