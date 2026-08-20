package datapath

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/gopacket/pcapgo"
	"github.com/jaxxstorm/envelope/internal/geneve"
)

type decodedOuterFixture struct {
	source      netip.AddrPort
	destination netip.AddrPort
	payload     []byte
}

func TestFullGWLBPacketFixtures(t *testing.T) {
	cases := []struct {
		name       string
		wantReason string
	}{
		{name: "gwlb-valid-ipv4.pcap"},
		{name: "gwlb-nonzero-vni.pcap", wantReason: "vni"},
		{name: "gwlb-oam.pcap", wantReason: "oam"},
		{name: "gwlb-option-reserved.pcap", wantReason: "option_reserved"},
		{name: "gwlb-missing-cookie.pcap", wantReason: "aws_cardinality"},
		{name: "gwlb-duplicate-cookie.pcap", wantReason: "aws_cardinality"},
		{name: "gwlb-protocol-mismatch.pcap", wantReason: "protocol"},
		{name: "gwlb-wrong-destination-port.pcap", wantReason: "listener"},
		{name: "gwlb-bad-ip-checksum.pcap", wantReason: "outer_checksum"},
		{name: "gwlb-bad-udp-checksum.pcap", wantReason: "outer_checksum"},
		{name: "gwlb-inner-ipv4-fragment.pcap", wantReason: "ipv4_fragment"},
		{name: "gwlb-inner-udp-truncated.pcap", wantReason: "transport_truncated"},
		{name: "gwlb-inner-ipv6-fragment.pcap", wantReason: "ipv6_fragment"},
		{name: "gwlb-inner-ipv6-extension.pcap", wantReason: "ipv6_extension"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := readFixtureFrame(t, tc.name)
			outer, reason := decodeOuterFixture(frame)
			if reason == "" && outer.destination.Port() != awsGenevePort {
				reason = "listener"
			}
			var header geneve.Header
			var inner []byte
			if reason == "" {
				var err error
				header, inner, err = geneve.Decode(outer.payload)
				if err != nil {
					reason = "decode"
				} else if _, err = geneve.ValidateAWSProfile(header, inner, geneve.MaxOptionsLen); err != nil {
					switch {
					case errors.Is(err, geneve.ErrAWSOptionCardinality):
						reason = "aws_cardinality"
					case errors.Is(err, geneve.ErrAWSOptionReserved):
						reason = "option_reserved"
					default:
						reason = profileValidationReason(err)
					}
				} else if _, err = flowKeyFromPacket(inner); err != nil {
					reason = unsupportedReason(err)
				}
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
			if tc.wantReason != "" {
				return
			}

			if outer.source != netip.MustParseAddrPort("192.0.2.10:40000") || outer.destination != netip.MustParseAddrPort("198.51.100.20:6081") {
				t.Fatalf("unexpected ingress tuple: %s -> %s", outer.source, outer.destination)
			}
			roundTrip := make([]byte, len(outer.payload))
			n, err := geneve.Encode(roundTrip, header, inner)
			if err != nil {
				t.Fatalf("encode round trip: %v", err)
			}
			if !bytes.Equal(roundTrip[:n], outer.payload) {
				t.Fatal("valid fixture did not round trip byte-for-byte")
			}
		})
	}
}

func readFixtureFrame(t *testing.T, name string) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	file, err := os.Open(filepath.Join(root, "testdata", "pcap", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	frame, _, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	return frame
}

func decodeOuterFixture(frame []byte) (decodedOuterFixture, string) {
	if len(frame) < 14+20+8 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return decodedOuterFixture{}, "outer_checksum"
	}
	ip := frame[14:]
	if ip[0] != 0x45 || ip[9] != 17 {
		return decodedOuterFixture{}, "outer_checksum"
	}
	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLength != len(ip) || referenceChecksum(ip[:20]) != 0 {
		return decodedOuterFixture{}, "outer_checksum"
	}
	udp := ip[20:]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength != len(udp) {
		return decodedOuterFixture{}, "outer_checksum"
	}
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], ip[12:16])
	copy(pseudo[4:8], ip[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	if referenceChecksum(pseudo) != 0 {
		return decodedOuterFixture{}, "outer_checksum"
	}
	sourceIP := netip.AddrFrom4([4]byte(ip[12:16]))
	destinationIP := netip.AddrFrom4([4]byte(ip[16:20]))
	return decodedOuterFixture{
		source:      netip.AddrPortFrom(sourceIP, binary.BigEndian.Uint16(udp[0:2])),
		destination: netip.AddrPortFrom(destinationIP, binary.BigEndian.Uint16(udp[2:4])),
		payload:     udp[8:],
	}, ""
}
