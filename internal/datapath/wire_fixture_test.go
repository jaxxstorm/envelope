package datapath

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type decodedOuterFixture struct {
	source      netip.AddrPort
	destination netip.AddrPort
	payload     []byte
}

func TestSanitizedAWSFixturesThroughReceiverToSender(t *testing.T) {
	cases := []struct {
		name              string
		fixture           string
		mutateMetadata    func(PacketMetadata) PacketMetadata
		wantProfileReason string
		wantOptionReason  string
	}{
		{name: "valid IPv4", fixture: "gwlb-valid-ipv4.pcap"},
		{name: "nonzero VNI", fixture: "gwlb-nonzero-vni.pcap", wantProfileReason: metrics.ProfileReasonVNI},
		{name: "OAM", fixture: "gwlb-oam.pcap", wantProfileReason: metrics.ProfileReasonOAM},
		{name: "reserved option bits", fixture: "gwlb-option-reserved.pcap", wantProfileReason: metrics.ProfileReasonOptionReserved, wantOptionReason: metrics.OptionValidationReasonAWSReserved},
		{name: "missing cookie", fixture: "gwlb-missing-cookie.pcap", wantProfileReason: metrics.ProfileReasonOptions, wantOptionReason: metrics.OptionValidationReasonAWSCardinality},
		{name: "duplicate cookie", fixture: "gwlb-duplicate-cookie.pcap", wantProfileReason: metrics.ProfileReasonOptions, wantOptionReason: metrics.OptionValidationReasonAWSCardinality},
		{name: "malformed options", fixture: "geneve-options-malformed.pcap", wantProfileReason: metrics.ProfileReasonOptions, wantOptionReason: metrics.OptionValidationReasonStructural},
		{name: "unknown critical option", fixture: "geneve-options-unknown-critical.pcap", wantProfileReason: metrics.ProfileReasonOptions, wantOptionReason: metrics.OptionValidationReasonCritical},
		{name: "protocol mismatch", fixture: "gwlb-protocol-mismatch.pcap", wantProfileReason: metrics.ProfileReasonProtocol},
		{name: "wrong destination port", fixture: "gwlb-wrong-destination-port.pcap", wantProfileReason: metrics.ProfileReasonListener},
		{name: "opaque IPv4 fragment", fixture: "gwlb-inner-ipv4-fragment.pcap"},
		{name: "opaque short UDP", fixture: "gwlb-inner-udp-truncated.pcap"},
		{name: "opaque IPv6 fragment", fixture: "gwlb-inner-ipv6-fragment.pcap"},
		{name: "opaque IPv6 extension", fixture: "gwlb-inner-ipv6-extension.pcap"},
		{
			name:    "zero source port",
			fixture: "gwlb-valid-ipv4.pcap",
			mutateMetadata: func(metadata PacketMetadata) PacketMetadata {
				metadata.Peer = netip.AddrPortFrom(metadata.Peer.Addr(), 0)
				return metadata
			},
			wantProfileReason: metrics.ProfileReasonOuterIPv4,
		},
		{
			name:    "source port upper bound",
			fixture: "gwlb-valid-ipv4.pcap",
			mutateMetadata: func(metadata PacketMetadata) PacketMetadata {
				metadata.Peer = netip.AddrPortFrom(metadata.Peer.Addr(), 65535)
				return metadata
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer, err := decodeOuterFixture(readFixtureFrame(t, tc.fixture))
			if err != nil {
				t.Fatalf("decode fixture outer packet: %v", err)
			}
			metadata := PacketMetadata{Peer: outer.source, Local: outer.destination, IfIndex: 7}
			if tc.mutateMetadata != nil {
				metadata = tc.mutateMetadata(metadata)
			}

			receiver := newScriptedReceiver()
			sender := &captureSender{}
			metricSet := metrics.NewTarget(prometheus.NewRegistry())
			dp := newWithPacketIO(testConfig(t), nil, metricSet, receiver, sender)
			done := make(chan error, 1)
			go func() { done <- dp.Run(context.Background()) }()
			waitForReady(t, dp)

			receiver.results <- receiverResult{packet: outer.payload, metadata: metadata}
			if tc.wantProfileReason == "" {
				waitForMetricValue(t, metricSet.GeneveTxPackets, 1)
			} else {
				waitForMetricValue(t, metricSet.Drops, 1)
			}
			dp.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Run did not stop")
			}

			if tc.wantProfileReason != "" {
				if sender.Attempts() != 0 || len(sender.Requests()) != 0 {
					t.Fatal("invalid fixture emitted a packet")
				}
				if got := testutil.ToFloat64(metricSet.GWLBProfileRejections.WithLabelValues(tc.wantProfileReason)); got != 1 {
					t.Fatalf("profile rejection %q = %v, want 1", tc.wantProfileReason, got)
				}
				if tc.wantOptionReason != "" {
					if got := testutil.ToFloat64(metricSet.GeneveOptionsValidationErrors.WithLabelValues(tc.wantOptionReason)); got != 1 {
						t.Fatalf("option rejection %q = %v, want 1", tc.wantOptionReason, got)
					}
				}
				if testutil.ToFloat64(metricSet.GeneveRxPackets) != 0 || testutil.ToFloat64(metricSet.GeneveTxPackets) != 0 {
					t.Fatal("invalid fixture changed valid packet counters")
				}
				return
			}

			requests := sender.Requests()
			if sender.Attempts() != 1 || len(requests) != 1 {
				t.Fatalf("send attempts=%d successful sends=%d, want exactly one", sender.Attempts(), len(requests))
			}
			request := requests[0]
			wantSource := netip.AddrPortFrom(metadata.Local.Addr(), metadata.Peer.Port())
			wantDestination := netip.AddrPortFrom(metadata.Peer.Addr(), awsGenevePort)
			if request.Source != wantSource || request.Destination != wantDestination || request.IfIndex != metadata.IfIndex {
				t.Fatalf("return tuple = %s -> %s ifindex=%d, want %s -> %s ifindex=%d", request.Source, request.Destination, request.IfIndex, wantSource, wantDestination, metadata.IfIndex)
			}
			if !bytes.Equal(request.Payload, outer.payload) {
				t.Fatal("return changed the fixture GENEVE packet")
			}
			if testutil.ToFloat64(metricSet.GeneveRxPackets) != 1 || testutil.ToFloat64(metricSet.GeneveTxPackets) != 1 || testutil.ToFloat64(metricSet.Drops) != 0 {
				t.Fatal("valid fixture counters do not describe exactly one return")
			}
		})
	}
}

func TestCorruptOuterFixturesAreKernelBoundaryCases(t *testing.T) {
	valid := readFixtureFrame(t, "gwlb-valid-ipv4.pcap")
	cases := []struct {
		name  string
		frame []byte
	}{
		{name: "bad IPv4 checksum", frame: readFixtureFrame(t, "gwlb-bad-ip-checksum.pcap")},
		{name: "bad UDP checksum", frame: readFixtureFrame(t, "gwlb-bad-udp-checksum.pcap")},
		{name: "bad IPv4 declared length", frame: mutateFixtureUint16(valid, 14+2, uint16(len(valid)-14-1))},
		{name: "bad UDP declared length", frame: mutateFixtureUint16(valid, 14+20+4, uint16(len(valid)-(14+20)-1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receiver := newScriptedReceiver()
			sender := &captureSender{}
			dp := newWithPacketIO(testConfig(t), nil, metrics.NewTarget(prometheus.NewRegistry()), receiver, sender)
			done := make(chan error, 1)
			go func() { done <- dp.Run(context.Background()) }()
			waitForReady(t, dp)

			if _, err := decodeOuterFixture(tc.frame); err == nil {
				t.Fatal("corrupt outer packet unexpectedly passed the fixture boundary check")
			}
			dp.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Run did not stop")
			}
			if sender.Attempts() != 0 || len(sender.Requests()) != 0 {
				t.Fatal("kernel-rejected outer fixture emitted a packet")
			}
		})
	}
}

func mutateFixtureUint16(frame []byte, offset int, value uint16) []byte {
	mutated := append([]byte(nil), frame...)
	binary.BigEndian.PutUint16(mutated[offset:offset+2], value)
	return mutated
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

// Linux validates and strips these IPv4 and UDP headers before ReadMsgUDPAddrPort
// returns. This decoder only converts valid PCAP input into the metadata and UDP
// payload that the production receiver supplies to the platform-neutral loop.
func decodeOuterFixture(frame []byte) (decodedOuterFixture, error) {
	if len(frame) < 14+20+8 {
		return decodedOuterFixture{}, fmt.Errorf("outer frame is too short: %d", len(frame))
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return decodedOuterFixture{}, fmt.Errorf("outer frame is not IPv4")
	}
	ip := frame[14:]
	headerLength := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || headerLength < 20 || headerLength > len(ip) || ip[9] != 17 {
		return decodedOuterFixture{}, fmt.Errorf("invalid outer IPv4 header")
	}
	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLength != len(ip) || totalLength < headerLength+8 {
		return decodedOuterFixture{}, fmt.Errorf("invalid outer IPv4 length %d", totalLength)
	}
	if referenceChecksum(ip[:headerLength]) != 0 {
		return decodedOuterFixture{}, fmt.Errorf("invalid outer IPv4 checksum")
	}
	udp := ip[headerLength:totalLength]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength != len(udp) || udpLength < 8 {
		return decodedOuterFixture{}, fmt.Errorf("invalid outer UDP length %d", udpLength)
	}
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], ip[12:16])
	copy(pseudo[4:8], ip[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	if binary.BigEndian.Uint16(udp[6:8]) != 0 && referenceChecksum(pseudo) != 0 {
		return decodedOuterFixture{}, fmt.Errorf("invalid outer UDP checksum")
	}
	sourceIP := netip.AddrFrom4([4]byte(ip[12:16]))
	destinationIP := netip.AddrFrom4([4]byte(ip[16:20]))
	return decodedOuterFixture{
		source:      netip.AddrPortFrom(sourceIP, binary.BigEndian.Uint16(udp[0:2])),
		destination: netip.AddrPortFrom(destinationIP, binary.BigEndian.Uint16(udp[2:4])),
		payload:     udp[8:],
	}, nil
}

func referenceChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
