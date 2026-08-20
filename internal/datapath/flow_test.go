package datapath

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/geneve"
)

var identityAllocationSink returnIdentity

func testFlowKey(protocol uint8, id byte) flowKey {
	key := flowKey{proto: protocol, ipFamily: 4, srcPort: 1000 + uint16(id), dstPort: 443}
	key.srcIP[15] = id
	key.dstIP[15] = id + 100
	return key
}

func testReturnIdentity(id byte) returnIdentity {
	return returnIdentity{
		peerIP:     netip.AddrFrom4([4]byte{192, 0, 2, id}),
		localIP:    netip.AddrFrom4([4]byte{198, 51, 100, id}),
		flowPort:   40000 + uint16(id),
		ifIndex:    int(id),
		vni:        0,
		protocol:   geneve.ProtoIPv4,
		fixedFlags: geneve.FlagCritical,
		flowCookie: [4]byte{0, 0, 0, id},
		options:    []byte{0x01, 0x08, 0x03, 0x01, 0, 0, 0, id},
	}
}

func testFlowTable(capacity int) *flowTable {
	return newFlowTable(flowTableConfig{
		capacity:     capacity,
		tcpTimeout:   350 * time.Second,
		udpTimeout:   120 * time.Second,
		otherTimeout: 120 * time.Second,
	})
}

func TestFlowTableReverseOnlyLookupAndRefresh(t *testing.T) {
	table := testFlowTable(4)
	now := time.Unix(100, 0)
	table.now = func() time.Time { return now }
	key := testFlowKey(17, 1)
	identity := testReturnIdentity(1)
	table.Update(key, identity)

	if got := table.LookupEgress(key); got.status != flowLookupPossibleLoop {
		t.Fatalf("same-orientation status = %d, want possible loop", got.status)
	}
	lookup := table.LookupEgress(key.Reverse())
	if lookup.status != flowLookupFound || !lookup.snapshot.identity.sameWireIdentity(identity) {
		t.Fatalf("reverse lookup failed: %+v", lookup)
	}
	now = now.Add(100 * time.Second)
	refreshed, expired := table.Refresh(lookup.handle)
	if !refreshed || expired != 0 {
		t.Fatalf("successful egress refresh = %v, expired = %d", refreshed, expired)
	}
	now = now.Add(30 * time.Second)
	if got := table.LookupEgress(key.Reverse()); got.status != flowLookupFound {
		t.Fatalf("return-only activity did not retain context: %+v", got)
	}
}

func TestFlowTableStaleEgressDoesNotRefreshConflict(t *testing.T) {
	table := testFlowTable(2)
	now := time.Unix(100, 0)
	table.now = func() time.Time { return now }
	key := testFlowKey(17, 1)
	table.Update(key, testReturnIdentity(1))
	handle := table.LookupEgress(key.Reverse()).handle

	conflict := testReturnIdentity(1)
	conflict.peerIP = netip.MustParseAddr("192.0.2.99")
	table.Update(key, conflict)
	if refreshed, _ := table.Refresh(handle); refreshed {
		t.Fatal("stale generation refreshed a conflicted context")
	}
	now = now.Add(121 * time.Second)
	if got := table.LookupEgress(key.Reverse()); got.status != flowLookupMissing || got.expired != 2 {
		t.Fatalf("conflicted identities did not expire: %+v", got)
	}
}

func TestFlowTableConflictsOnEveryAuthoritativeIdentityField(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*returnIdentity)
	}{
		{name: "peer IP", mutate: func(i *returnIdentity) { i.peerIP = netip.MustParseAddr("192.0.2.99") }},
		{name: "local IP", mutate: func(i *returnIdentity) { i.localIP = netip.MustParseAddr("198.51.100.99") }},
		{name: "flow port", mutate: func(i *returnIdentity) { i.flowPort++ }},
		{name: "VNI", mutate: func(i *returnIdentity) { i.vni++ }},
		{name: "protocol", mutate: func(i *returnIdentity) { i.protocol = geneve.ProtoIPv6 }},
		{name: "fixed flags", mutate: func(i *returnIdentity) { i.fixedFlags = 0 }},
		{name: "flow cookie", mutate: func(i *returnIdentity) { i.flowCookie[0]++ }},
		{name: "ordered options", mutate: func(i *returnIdentity) { i.options = append([]byte(nil), i.options...); i.options[0]++ }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			table := testFlowTable(2)
			key := testFlowKey(6, 1)
			table.Update(key, testReturnIdentity(1))
			changed := testReturnIdentity(1)
			tc.mutate(&changed)
			if result := table.Update(key, changed); !result.collision {
				t.Fatal("wire-identity difference did not create collision")
			}
			if lookup := table.LookupEgress(key.Reverse()); lookup.status != flowLookupConflicted {
				t.Fatalf("lookup status = %d, want conflicted", lookup.status)
			}
		})
	}
}

func TestFlowTableIfIndexIsMutableRouteHint(t *testing.T) {
	table := testFlowTable(2)
	key := testFlowKey(17, 1)
	identity := testReturnIdentity(1)
	table.Update(key, identity)
	identity.ifIndex = 99
	if result := table.Update(key, identity); result.collision {
		t.Fatal("ifindex-only change created a wire-identity conflict")
	}
	lookup := table.LookupEgress(key.Reverse())
	if lookup.status != flowLookupFound || lookup.snapshot.identity.ifIndex != 99 {
		t.Fatalf("route hint was not updated: %+v", lookup)
	}
}

func TestFlowTableConflictRecoversToSurvivingIdentity(t *testing.T) {
	table := testFlowTable(2)
	base := time.Unix(100, 0)
	now := base
	table.now = func() time.Time { return now }
	key := testFlowKey(17, 1)
	survivor := testReturnIdentity(1)
	other := testReturnIdentity(2)
	table.Update(key, survivor)
	now = base.Add(time.Second)
	table.Update(key, other)
	if table.LookupEgress(key.Reverse()).status != flowLookupConflicted {
		t.Fatal("two live identities were not conflicted")
	}

	now = base.Add(60 * time.Second)
	table.Update(key, survivor)
	now = base.Add(122 * time.Second)
	lookup := table.LookupEgress(key.Reverse())
	if lookup.status != flowLookupFound || lookup.expired != 1 || !lookup.snapshot.identity.sameWireIdentity(survivor) {
		t.Fatalf("surviving identity did not recover automatically: %+v", lookup)
	}
}

func TestFlowTableConflictPersistsWhileBothIdentitiesAreActive(t *testing.T) {
	table := testFlowTable(2)
	base := time.Unix(100, 0)
	now := base
	table.now = func() time.Time { return now }
	key := testFlowKey(17, 1)
	first := testReturnIdentity(1)
	second := testReturnIdentity(2)
	table.Update(key, first)
	table.Update(key, second)
	for cycle := 1; cycle <= 5; cycle++ {
		now = base.Add(time.Duration(cycle*100) * time.Second)
		table.Update(key, first)
		table.Update(key, second)
		if lookup := table.LookupEgress(key.Reverse()); lookup.status != flowLookupConflicted {
			t.Fatalf("cycle %d unexpectedly recovered conflict: %+v", cycle, lookup)
		}
	}
}

func TestFlowTableConflictTrackingIsBoundedAndRecovers(t *testing.T) {
	table := testFlowTable(2)
	base := time.Unix(100, 0)
	now := base
	table.now = func() time.Time { return now }
	key := testFlowKey(17, 1)
	for id := byte(1); id <= 12; id++ {
		table.Update(key, testReturnIdentity(id))
	}
	entry := table.entries[key]
	if entry.identityCount != maxConflictIdentities || entry.overflowLastActivity.IsZero() {
		t.Fatalf("conflict tracking is not bounded: identities=%d overflow=%v", entry.identityCount, entry.overflowLastActivity)
	}

	now = base.Add(60 * time.Second)
	survivor := testReturnIdentity(1)
	table.Update(key, survivor)
	now = base.Add(121 * time.Second)
	lookup := table.LookupEgress(key.Reverse())
	if lookup.status != flowLookupFound || !lookup.snapshot.identity.sameWireIdentity(survivor) {
		t.Fatalf("bounded conflict did not recover to survivor: %+v", lookup)
	}
}

func TestFlowTableProtocolTimeouts(t *testing.T) {
	table := testFlowTable(4)
	now := time.Unix(100, 0)
	table.now = func() time.Time { return now }
	tcpKey := testFlowKey(6, 1)
	udpKey := testFlowKey(17, 2)
	otherKey := testFlowKey(1, 3)
	table.Update(tcpKey, testReturnIdentity(1))
	table.Update(udpKey, testReturnIdentity(2))
	table.Update(otherKey, testReturnIdentity(3))

	now = now.Add(121 * time.Second)
	if lookup := table.LookupEgress(tcpKey.Reverse()); lookup.status != flowLookupFound || lookup.expired != 2 {
		t.Fatalf("TCP/short-protocol expiry result unexpected: %+v", lookup)
	}
	if got := table.LookupEgress(udpKey.Reverse()); got.status != flowLookupMissing || got.expired != 0 {
		t.Fatal("UDP context did not expire at 120 seconds")
	}
	if got := table.LookupEgress(otherKey.Reverse()); got.status != flowLookupMissing || got.expired != 0 {
		t.Fatal("other context did not expire at 120 seconds")
	}
	now = time.Unix(100, 0).Add(351 * time.Second)
	if got := table.LookupEgress(tcpKey.Reverse()); got.status != flowLookupMissing || got.expired != 1 {
		t.Fatal("TCP context did not expire at 350 seconds")
	}
}

func TestFlowTableExpiredFirstThenLRUEviction(t *testing.T) {
	table := testFlowTable(2)
	now := time.Unix(100, 0)
	table.now = func() time.Time { return now }
	first := testFlowKey(17, 1)
	second := testFlowKey(6, 2)
	third := testFlowKey(6, 3)
	table.Update(first, testReturnIdentity(1))
	now = now.Add(time.Second)
	table.Update(second, testReturnIdentity(2))
	now = now.Add(120 * time.Second)
	result := table.Update(third, testReturnIdentity(3))
	if result.expired != 1 || result.evicted != 0 || table.Len() != 2 {
		t.Fatalf("expired-first insertion = %+v, len=%d", result, table.Len())
	}

	fourth := testFlowKey(6, 4)
	now = now.Add(time.Second)
	result = table.Update(fourth, testReturnIdentity(4))
	if result.evicted != 1 || table.Len() != 2 {
		t.Fatalf("LRU insertion = %+v, len=%d", result, table.Len())
	}
	if table.LookupEgress(second.Reverse()).status != flowLookupMissing {
		t.Fatal("oldest inactive context was not evicted")
	}
	if len(table.expiries) != table.Len() || table.lru.Len() != table.Len() {
		t.Fatal("expiry/LRU indexes diverged from flow map")
	}
}

func TestFlowTableConcurrentAccess(t *testing.T) {
	table := testFlowTable(64)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 1000; iteration++ {
				id := byte((worker+iteration)%63 + 1)
				key := testFlowKey(17, id)
				table.Update(key, testReturnIdentity(id))
				lookup := table.LookupEgress(key.Reverse())
				if lookup.status == flowLookupFound {
					table.Refresh(lookup.handle)
				}
				if iteration%100 == 0 {
					table.Sweep()
				}
			}
		}(worker)
	}
	wait.Wait()
	if table.Len() > 64 {
		t.Fatalf("flow table exceeded capacity: %d", table.Len())
	}
	if len(table.expiries) != table.Len() || table.lru.Len() != table.Len() {
		t.Fatal("concurrent expiry/LRU indexes diverged")
	}
}

func TestContextAllocationBudgets(t *testing.T) {
	table := testFlowTable(2)
	key := testFlowKey(17, 1)
	table.Update(key, testReturnIdentity(1))
	lookupAllocations := testing.AllocsPerRun(1000, func() {
		flowLookupSink = table.LookupEgress(key.Reverse())
	})
	if lookupAllocations != 0 {
		t.Fatalf("context lookup allocated %.2f objects, want 0", lookupAllocations)
	}

	metadata := testPacketMetadata()
	header := geneve.Header{Protocol: geneve.ProtoIPv4, Options: sanitizedAWSOptions()}
	optionMetadata, err := geneve.ValidateAWSProfile(header, []byte{0x45}, geneve.MaxOptionsLen)
	if err != nil {
		t.Fatal(err)
	}
	copyAllocations := testing.AllocsPerRun(1000, func() {
		identityAllocationSink = newReturnIdentity(metadata, header, optionMetadata)
	})
	if copyAllocations > 1 {
		t.Fatalf("return identity copy allocated %.2f objects, want at most 1", copyAllocations)
	}
}
