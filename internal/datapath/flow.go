package datapath

import (
	"bytes"
	"container/heap"
	"container/list"
	"net/netip"
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/geneve"
)

const maxConflictIdentities = 4

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

type returnIdentity struct {
	peerIP     netip.Addr
	localIP    netip.Addr
	flowPort   uint16
	ifIndex    int
	vni        uint32
	protocol   uint16
	fixedFlags uint8
	flowCookie [geneve.AWSFlowCookieLength]byte
	options    []byte
}

func newReturnIdentity(metadata PacketMetadata, header geneve.Header, optionMetadata geneve.OptionMetadata) returnIdentity {
	identity := returnIdentity{
		peerIP:     metadata.Peer.Addr().Unmap(),
		localIP:    metadata.Local.Addr().Unmap(),
		flowPort:   metadata.Peer.Port(),
		ifIndex:    metadata.IfIndex,
		vni:        header.VNI,
		protocol:   header.Protocol,
		fixedFlags: header.FixedFlags(),
		flowCookie: optionMetadata.FlowCookie,
	}
	identity.options = append([]byte(nil), header.Options...)
	return identity
}

// sameWireIdentity deliberately excludes ifIndex. The interface is a mutable
// route hint, not metadata supplied by GWLB for return-packet fidelity.
func (i returnIdentity) sameWireIdentity(other returnIdentity) bool {
	return i.peerIP == other.peerIP &&
		i.localIP == other.localIP &&
		i.flowPort == other.flowPort &&
		i.vni == other.vni &&
		i.protocol == other.protocol &&
		i.fixedFlags == other.fixedFlags &&
		i.flowCookie == other.flowCookie &&
		bytes.Equal(i.options, other.options)
}

type identityActivity struct {
	identity     returnIdentity
	lastActivity time.Time
}

type returnContext struct {
	key                  flowKey
	identities           [maxConflictIdentities]identityActivity
	identityCount        int
	overflowLastActivity time.Time
	innerProtocol        uint8
	lastActivity         time.Time
	generation           uint64
	lruElement           *list.Element
	heapIndex            int
	nextExpiry           time.Time
}

func (c *returnContext) conflicted() bool {
	active := c.identityCount
	if !c.overflowLastActivity.IsZero() {
		active++
	}
	return active != 1 || c.identityCount != 1
}

type flowHandle struct {
	key        flowKey
	generation uint64
}

type flowSnapshot struct {
	identity returnIdentity
}

type flowTableConfig struct {
	capacity     int
	tcpTimeout   time.Duration
	udpTimeout   time.Duration
	otherTimeout time.Duration
}

type flowUpdateResult struct {
	expired   int
	evicted   int
	collision bool
}

type flowLookupStatus uint8

const (
	flowLookupMissing flowLookupStatus = iota
	flowLookupFound
	flowLookupConflicted
	flowLookupPossibleLoop
)

type flowLookupResult struct {
	handle   flowHandle
	snapshot flowSnapshot
	status   flowLookupStatus
	expired  int
}

type contextExpiryHeap []*returnContext

func (h contextExpiryHeap) Len() int { return len(h) }
func (h contextExpiryHeap) Less(i, j int) bool {
	return h[i].nextExpiry.Before(h[j].nextExpiry)
}
func (h contextExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}
func (h *contextExpiryHeap) Push(value any) {
	entry := value.(*returnContext)
	entry.heapIndex = len(*h)
	*h = append(*h, entry)
}
func (h *contextExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.heapIndex = -1
	*h = old[:last]
	return entry
}

type flowTable struct {
	mu             sync.Mutex
	entries        map[flowKey]*returnContext
	lru            list.List
	expiries       contextExpiryHeap
	config         flowTableConfig
	now            func() time.Time
	nextGeneration uint64
}

func newFlowTable(config flowTableConfig) *flowTable {
	return &flowTable{
		entries: make(map[flowKey]*returnContext),
		config:  config,
		now:     time.Now,
	}
}

func (f *flowTable) Update(key flowKey, identity returnIdentity) flowUpdateResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	result := flowUpdateResult{expired: f.expireDueLocked(now)}
	if entry, ok := f.entries[key]; ok {
		for index := 0; index < entry.identityCount; index++ {
			candidate := &entry.identities[index]
			if !candidate.identity.sameWireIdentity(identity) {
				continue
			}
			if candidate.identity.ifIndex != identity.ifIndex {
				candidate.identity.ifIndex = identity.ifIndex
				entry.generation = f.generation()
			}
			candidate.lastActivity = now
			f.touchLocked(entry, now)
			f.scheduleLocked(entry)
			return result
		}

		if entry.identityCount < maxConflictIdentities {
			entry.identities[entry.identityCount] = identityActivity{identity: identity, lastActivity: now}
			entry.identityCount++
			result.collision = true
		} else {
			result.collision = entry.overflowLastActivity.IsZero()
			entry.overflowLastActivity = now
		}
		entry.generation = f.generation()
		f.touchLocked(entry, now)
		f.scheduleLocked(entry)
		return result
	}

	if len(f.entries) >= f.config.capacity {
		if oldest := f.lru.Front(); oldest != nil {
			f.removeEntryLocked(oldest.Value.(*returnContext))
			result.evicted++
		}
	}
	entry := &returnContext{
		key:           key,
		identityCount: 1,
		innerProtocol: key.proto,
		lastActivity:  now,
		generation:    f.generation(),
		heapIndex:     -1,
	}
	entry.identities[0] = identityActivity{identity: identity, lastActivity: now}
	entry.lruElement = f.lru.PushBack(entry)
	f.entries[key] = entry
	f.scheduleLocked(entry)
	return result
}

func (f *flowTable) LookupEgress(key flowKey) flowLookupResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	result := flowLookupResult{status: flowLookupMissing, expired: f.expireDueLocked(now)}
	if _, ok := f.entries[key]; ok {
		result.status = flowLookupPossibleLoop
		return result
	}

	reverseKey := key.Reverse()
	entry, ok := f.entries[reverseKey]
	if !ok {
		return result
	}
	if entry.conflicted() {
		result.status = flowLookupConflicted
		return result
	}
	result.status = flowLookupFound
	result.handle = flowHandle{key: reverseKey, generation: entry.generation}
	result.snapshot = flowSnapshot{identity: entry.identities[0].identity}
	return result
}

func (f *flowTable) Refresh(handle flowHandle) (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	expired := f.expireDueLocked(now)
	entry, ok := f.entries[handle.key]
	if !ok || entry.conflicted() || entry.generation != handle.generation {
		return false, expired
	}
	entry.identities[0].lastActivity = now
	f.touchLocked(entry, now)
	f.scheduleLocked(entry)
	return true, expired
}

func (f *flowTable) Sweep() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.expireDueLocked(f.now())
}

func (f *flowTable) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func (f *flowTable) generation() uint64 {
	f.nextGeneration++
	return f.nextGeneration
}

func (f *flowTable) timeout(protocol uint8) time.Duration {
	switch protocol {
	case 6:
		return f.config.tcpTimeout
	case 17:
		return f.config.udpTimeout
	default:
		return f.config.otherTimeout
	}
}

func (f *flowTable) touchLocked(entry *returnContext, now time.Time) {
	entry.lastActivity = now
	f.lru.MoveToBack(entry.lruElement)
}

func (f *flowTable) scheduleLocked(entry *returnContext) {
	timeout := f.timeout(entry.innerProtocol)
	var next time.Time
	for index := 0; index < entry.identityCount; index++ {
		expiry := entry.identities[index].lastActivity.Add(timeout)
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}
	if !entry.overflowLastActivity.IsZero() {
		expiry := entry.overflowLastActivity.Add(timeout)
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}
	entry.nextExpiry = next
	if entry.heapIndex < 0 {
		heap.Push(&f.expiries, entry)
		return
	}
	heap.Fix(&f.expiries, entry.heapIndex)
}

func (f *flowTable) expireDueLocked(now time.Time) int {
	expired := 0
	for len(f.expiries) > 0 {
		entry := f.expiries[0]
		if !now.After(entry.nextExpiry) {
			break
		}
		expired += f.pruneEntryLocked(entry, now)
		if entry.identityCount == 0 && entry.overflowLastActivity.IsZero() {
			f.removeEntryLocked(entry)
			continue
		}
		f.scheduleLocked(entry)
	}
	return expired
}

func (f *flowTable) pruneEntryLocked(entry *returnContext, now time.Time) int {
	timeout := f.timeout(entry.innerProtocol)
	expired := 0
	write := 0
	for read := 0; read < entry.identityCount; read++ {
		candidate := entry.identities[read]
		if now.Sub(candidate.lastActivity) > timeout {
			expired++
			continue
		}
		entry.identities[write] = candidate
		write++
	}
	for index := write; index < entry.identityCount; index++ {
		entry.identities[index] = identityActivity{}
	}
	entry.identityCount = write
	if !entry.overflowLastActivity.IsZero() && now.Sub(entry.overflowLastActivity) > timeout {
		entry.overflowLastActivity = time.Time{}
		expired++
	}
	if expired > 0 {
		entry.generation = f.generation()
	}
	return expired
}

func (f *flowTable) removeEntryLocked(entry *returnContext) {
	delete(f.entries, entry.key)
	if entry.lruElement != nil {
		f.lru.Remove(entry.lruElement)
		entry.lruElement = nil
	}
	if entry.heapIndex >= 0 {
		heap.Remove(&f.expiries, entry.heapIndex)
	}
}
