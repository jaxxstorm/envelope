//go:build linux

package datapath

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPv4PacketInfoControl(t *testing.T) {
	request := SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
		IfIndex:     17,
	}
	oob, err := ipv4PacketInfoControl(request)
	if err != nil {
		t.Fatalf("build packet info: %v", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse packet info: messages=%d err=%v", len(messages), err)
	}
	message := messages[0]
	if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO {
		t.Fatalf("unexpected control header: %+v", message.Header)
	}
	if got := binary.NativeEndian.Uint32(message.Data[0:4]); got != 17 {
		t.Fatalf("ifindex = %d, want 17", got)
	}
	if got := [4]byte(message.Data[4:8]); got != [4]byte{198, 51, 100, 20} {
		t.Fatalf("source hint = %v", got)
	}
}
