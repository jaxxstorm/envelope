package datapath

import (
	"net"
	"testing"
	"time"
)

func TestFlowTableUpdateLookup(t *testing.T) {
	ft := newFlowTable(5 * time.Minute)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6081}
	key := flowKey{proto: 17, ipFamily: 4}
	ft.Update(key, addr, 42, []byte{0x01, 0x02, 0x03, 0x04})

	snap, ok := ft.Lookup(key)
	if !ok {
		t.Fatalf("expected lookup")
	}
	if snap.addr.String() != addr.String() {
		t.Fatalf("unexpected addr")
	}
	if snap.vni != 42 {
		t.Fatalf("unexpected vni")
	}
	if len(snap.options) != 4 {
		t.Fatalf("unexpected options length")
	}
}

func TestFlowTableExpiry(t *testing.T) {
	ft := newFlowTable(1 * time.Second)
	now := time.Now()
	ft.now = func() time.Time { return now }
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6081}
	key := flowKey{proto: 6, ipFamily: 4}
	ft.Update(key, addr, 1, nil)

	now = now.Add(2 * time.Second)
	if _, ok := ft.Lookup(key); ok {
		t.Fatalf("expected expired entry")
	}
}

func TestFlowKeyParsingIPv4(t *testing.T) {
	pkt := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x00, 0x35, 0x12, 0x34,
	}
	key, ok := flowKeyFromPacket(pkt)
	if !ok {
		t.Fatalf("expected key")
	}
	if key.proto != 17 || key.srcPort != 0x0035 || key.dstPort != 0x1234 {
		t.Fatalf("unexpected key fields")
	}
}
