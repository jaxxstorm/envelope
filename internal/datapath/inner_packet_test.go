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

func TestUnsupportedInnerPacketMatrix(t *testing.T) {
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
		name    string
		packet  []byte
		wantErr error
	}{
		{name: "IPv4 MF", packet: fragmentMF, wantErr: ErrIPv4Fragment},
		{name: "IPv4 offset", packet: fragmentOffset, wantErr: ErrIPv4Fragment},
		{name: "truncated UDP", packet: truncatedUDP, wantErr: ErrTransportTruncated},
		{name: "truncated TCP", packet: truncatedTCP, wantErr: ErrTransportTruncated},
		{name: "IPv6 fragment", packet: ipv6Fragment, wantErr: ErrIPv6Fragment},
		{name: "IPv6 extension", packet: ipv6Extension, wantErr: ErrIPv6Extension},
		{name: "IPv6 extension then fragment", packet: ipv6ExtensionThenFragment, wantErr: ErrIPv6Fragment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateInnerPacket(tc.packet); !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
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
