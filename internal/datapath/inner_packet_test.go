package datapath

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestInnerPacketValidation(t *testing.T) {
	ipv4 := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 53, 0x1234)
	if err := validateInnerPacket(ipv4); err != nil {
		t.Fatalf("validate IPv4: %v", err)
	}

	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], 8)
	ipv6[6] = 17
	ipv6[7] = 64
	ipv6[23], ipv6[39] = 1, 2
	binary.BigEndian.PutUint16(ipv6[40:42], 1234)
	binary.BigEndian.PutUint16(ipv6[42:44], 443)
	binary.BigEndian.PutUint16(ipv6[44:46], 8)
	if err := validateInnerPacket(ipv6); err != nil {
		t.Fatalf("validate IPv6: %v", err)
	}
}

func TestInnerPacketFragmentsExtensionsAndTransportRemainOpaque(t *testing.T) {
	baseIPv4 := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	fragmentMF := append([]byte(nil), baseIPv4...)
	binary.BigEndian.PutUint16(fragmentMF[6:8], 0x2000)
	fragmentOffset := append([]byte(nil), baseIPv4...)
	binary.BigEndian.PutUint16(fragmentOffset[6:8], 1)
	truncatedUDP := append([]byte(nil), baseIPv4[:27]...)
	binary.BigEndian.PutUint16(truncatedUDP[2:4], uint16(len(truncatedUDP)))

	truncatedTCP := make([]byte, 39)
	copy(truncatedTCP, baseIPv4[:20])
	binary.BigEndian.PutUint16(truncatedTCP[2:4], uint16(len(truncatedTCP)))
	truncatedTCP[9] = 6

	ipv6Fragment := make([]byte, 48)
	ipv6Fragment[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Fragment[4:6], 8)
	ipv6Fragment[6] = 44

	ipv6Extension := make([]byte, 68)
	ipv6Extension[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Extension[4:6], 28)
	ipv6Extension[6] = 0
	ipv6Extension[40] = 6
	ipv6Extension[41] = 0
	ipv6Extension[60] = 0x50

	ipv6ExtensionThenFragment := make([]byte, 56)
	ipv6ExtensionThenFragment[0] = 0x60
	binary.BigEndian.PutUint16(ipv6ExtensionThenFragment[4:6], 16)
	ipv6ExtensionThenFragment[6] = 0
	ipv6ExtensionThenFragment[40] = 44
	ipv6ExtensionThenFragment[41] = 0

	cases := []struct {
		name   string
		packet []byte
	}{
		{name: "IPv4 MF", packet: fragmentMF},
		{name: "IPv4 offset", packet: fragmentOffset},
		{name: "short opaque UDP payload", packet: truncatedUDP},
		{name: "short opaque TCP payload", packet: truncatedTCP},
		{name: "IPv6 fragment", packet: ipv6Fragment},
		{name: "IPv6 extension", packet: ipv6Extension},
		{name: "IPv6 extension then fragment", packet: ipv6ExtensionThenFragment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateInnerPacket(tc.packet); err != nil {
				t.Fatalf("opaque packet rejected: %v", err)
			}
		})
	}
}

func TestMalformedInnerPacketBounds(t *testing.T) {
	validIPv4 := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	badIPv4IHL := append([]byte(nil), validIPv4...)
	badIPv4IHL[0] = 0x44
	longIPv4IHL := append([]byte(nil), validIPv4...)
	longIPv4IHL[0] = 0x4f
	badIPv4Length := append([]byte(nil), validIPv4...)
	binary.BigEndian.PutUint16(badIPv4Length[2:4], uint16(len(badIPv4Length)-1))

	validIPv6 := innerIPv6UDP(1234, 443)
	badIPv6Length := append([]byte(nil), validIPv6...)
	binary.BigEndian.PutUint16(badIPv6Length[4:6], 7)

	for _, tc := range []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "unknown version", packet: []byte{0x70}},
		{name: "short IPv4", packet: []byte{0x45}},
		{name: "small IPv4 IHL", packet: badIPv4IHL},
		{name: "IPv4 IHL beyond packet", packet: longIPv4IHL},
		{name: "IPv4 total length mismatch", packet: badIPv4Length},
		{name: "short IPv6", packet: []byte{0x60}},
		{name: "IPv6 payload length mismatch", packet: badIPv6Length},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateInnerPacket(tc.packet); !errors.Is(err, ErrInnerMalformed) {
				t.Fatalf("validation error = %v, want %v", err, ErrInnerMalformed)
			}
		})
	}
}

func FuzzValidateInnerPacket(f *testing.F) {
	f.Add(innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443))
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_ = validateInnerPacket(packet)
	})
}
