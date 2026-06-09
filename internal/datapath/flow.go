package datapath

import (
	"net"
	"sync"
	"time"
)

type flowKey struct {
	srcIP    [16]byte
	dstIP    [16]byte
	srcPort  uint16
	dstPort  uint16
	proto    uint8
	ipFamily uint8
}

func (k flowKey) Reverse() flowKey {
	r := k
	r.srcIP = k.dstIP
	r.dstIP = k.srcIP
	r.srcPort = k.dstPort
	r.dstPort = k.srcPort
	return r
}

type flowEntry struct {
	addr     *net.UDPAddr
	vni      uint32
	options  []byte
	lastSeen time.Time
}

type flowSnapshot struct {
	addr    *net.UDPAddr
	vni     uint32
	options []byte
}

type flowTable struct {
	mu      sync.RWMutex
	entries map[flowKey]*flowEntry
	timeout time.Duration
	now     func() time.Time
}

func newFlowTable(timeout time.Duration) *flowTable {
	return &flowTable{
		entries: make(map[flowKey]*flowEntry),
		timeout: timeout,
		now:     time.Now,
	}
}

func (f *flowTable) Update(key flowKey, addr *net.UDPAddr, vni uint32, options []byte) {
	if addr == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.entries[key]
	if !ok {
		entry = &flowEntry{}
		f.entries[key] = entry
	}
	entry.addr = addr
	entry.vni = vni
	entry.lastSeen = f.now()
	if len(options) > cap(entry.options) {
		entry.options = make([]byte, len(options))
	}
	entry.options = entry.options[:len(options)]
	copy(entry.options, options)
}

func (f *flowTable) Lookup(key flowKey) (flowSnapshot, bool) {
	f.mu.RLock()
	entry, ok := f.entries[key]
	if !ok {
		f.mu.RUnlock()
		return flowSnapshot{}, false
	}
	if f.timeout > 0 && f.now().Sub(entry.lastSeen) > f.timeout {
		f.mu.RUnlock()
		f.mu.Lock()
		delete(f.entries, key)
		f.mu.Unlock()
		return flowSnapshot{}, false
	}
	snap := flowSnapshot{
		addr: entry.addr,
		vni:  entry.vni,
	}
	if len(entry.options) > 0 {
		snap.options = append([]byte(nil), entry.options...)
	}
	f.mu.RUnlock()
	return snap, true
}

func (f *flowTable) Sweep() {
	if f.timeout <= 0 {
		return
	}
	cutoff := f.now().Add(-f.timeout)
	f.mu.Lock()
	for key, entry := range f.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(f.entries, key)
		}
	}
	f.mu.Unlock()
}
