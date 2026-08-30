package datapath

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jaxxstorm/envelope/internal/geneve"
)

var packetBuildSink int

func TestBuildIPv4UDPPacket(t *testing.T) {
	inner := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	for _, optionsLength := range []int{0, 40, geneve.MaxOptionsLen} {
		t.Run(fmt.Sprintf("options_%d", optionsLength), func(t *testing.T) {
			options := make([]byte, optionsLength)
			for offset := 0; offset < len(options); offset += 4 {
				options[offset] = 0x22
				options[offset+1] = 0x22
			}
			genevePayload := make([]byte, geneve.BaseHeaderLen+len(options)+len(inner))
			n, err := geneve.Encode(genevePayload, geneve.Header{Options: options}, inner)
			if err != nil {
				t.Fatalf("encode GENEVE: %v", err)
			}
			request := SendRequest{
				Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
				Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
				IfIndex:     7,
				Payload:     genevePayload[:n],
			}
			packet := make([]byte, 65535)
			packetLength, err := BuildIPv4UDPPacket(packet, request)
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			packet = packet[:packetLength]
			if packet[0] != 0x45 || packet[9] != 17 || packet[8] != 64 {
				t.Fatalf("invalid IPv4 fixed header: %x", packet[:20])
			}
			if got := int(binary.BigEndian.Uint16(packet[2:4])); got != len(packet) {
				t.Fatalf("IPv4 length = %d, want %d", got, len(packet))
			}
			if got := referenceChecksum(packet[:20]); got != 0 {
				t.Fatalf("IPv4 checksum residual = %#x", got)
			}
			if got := netip.AddrFrom4([4]byte(packet[12:16])); got.String() != "198.51.100.20" {
				t.Fatalf("source IP = %s", got)
			}
			if got := netip.AddrFrom4([4]byte(packet[16:20])); got.String() != "192.0.2.10" {
				t.Fatalf("destination IP = %s", got)
			}
			udp := packet[20:]
			if binary.BigEndian.Uint16(udp[0:2]) != 40000 || binary.BigEndian.Uint16(udp[2:4]) != 6081 {
				t.Fatalf("invalid UDP orientation: %x", udp[:8])
			}
			if got := int(binary.BigEndian.Uint16(udp[4:6])); got != len(udp) {
				t.Fatalf("UDP length = %d, want %d", got, len(udp))
			}
			pseudo := make([]byte, 12+len(udp))
			copy(pseudo[0:4], packet[12:16])
			copy(pseudo[4:8], packet[16:20])
			pseudo[9] = 17
			binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
			copy(pseudo[12:], udp)
			if got := referenceChecksum(pseudo); got != 0 {
				t.Fatalf("UDP checksum residual = %#x", got)
			}
			if !bytes.Equal(udp[8:], request.Payload) {
				t.Fatal("UDP payload changed")
			}
		})
	}
}

func TestBuildIPv4UDPPacketRejectsInvalidRequests(t *testing.T) {
	valid := SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
	}
	cases := []SendRequest{
		{Source: netip.MustParseAddrPort("[2001:db8::1]:40000"), Destination: valid.Destination},
		{Source: valid.Source, Destination: netip.MustParseAddrPort("[2001:db8::2]:6081")},
		{Source: netip.AddrPortFrom(valid.Source.Addr(), 0), Destination: valid.Destination},
		{Source: valid.Source, Destination: netip.AddrPortFrom(valid.Destination.Addr(), 0)},
	}
	for _, request := range cases {
		if _, err := BuildIPv4UDPPacket(make([]byte, 128), request); err == nil {
			t.Fatalf("invalid request unexpectedly succeeded: %+v", request)
		}
	}
	if _, err := BuildIPv4UDPPacket(make([]byte, outerHeaderLen-1), valid); err == nil {
		t.Fatal("undersized destination buffer unexpectedly succeeded")
	}
	valid.Payload = make([]byte, 65535-outerHeaderLen+1)
	if _, err := BuildIPv4UDPPacket(make([]byte, 65535), valid); err == nil {
		t.Fatal("oversized packet unexpectedly succeeded")
	}
}

func TestBuildIPv4UDPPacketLengthAndPortBoundaries(t *testing.T) {
	for _, ports := range [][2]uint16{{1, 1}, {65535, 65535}} {
		request := SendRequest{
			Source:      netip.AddrPortFrom(netip.MustParseAddr("198.51.100.20"), ports[0]),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), ports[1]),
			Payload:     make([]byte, 65535-outerHeaderLen),
		}
		packet := make([]byte, 65535)
		n, err := BuildIPv4UDPPacket(packet, request)
		if err != nil {
			t.Fatalf("build maximum IPv4 packet with ports %v: %v", ports, err)
		}
		if n != len(packet) || binary.BigEndian.Uint16(packet[20:22]) != ports[0] || binary.BigEndian.Uint16(packet[22:24]) != ports[1] {
			t.Fatalf("maximum packet boundary mismatch for ports %v", ports)
		}
	}
}

func TestBuildIPv4UDPPacketAllocations(t *testing.T) {
	request := SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
		Payload:     make([]byte, 1280),
	}
	buffer := make([]byte, 1500)
	allocations := testing.AllocsPerRun(1000, func() {
		packetBuildSink, _ = BuildIPv4UDPPacket(buffer, request)
	})
	if allocations != 0 {
		t.Fatalf("packet builder allocated %.2f objects, want 0", allocations)
	}
}

func BenchmarkPacketConstruction(b *testing.B) {
	request := SendRequest{
		Source:      netip.MustParseAddrPort("198.51.100.20:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.10:6081"),
		Payload:     make([]byte, 1280),
	}
	buffer := make([]byte, 1500)
	b.ReportAllocs()
	b.SetBytes(int64(len(request.Payload)))
	for range b.N {
		packetBuildSink, _ = BuildIPv4UDPPacket(buffer, request)
	}
}
