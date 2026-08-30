package datapath

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/bufferpool"
	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type testReceiver struct{}

func (*testReceiver) ReadPacket([]byte) (int, PacketMetadata, error) {
	return 0, PacketMetadata{}, net.ErrClosed
}
func (*testReceiver) SetReadDeadline(time.Time) error { return nil }
func (*testReceiver) Close() error                    { return nil }

type captureSender struct {
	mu       sync.Mutex
	requests []SendRequest
	attempts int
	closes   int
	err      error
}

func (s *captureSender) SendPacket(request SendRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.err != nil {
		return s.err
	}
	request.Payload = append([]byte(nil), request.Payload...)
	s.requests = append(s.requests, request)
	return nil
}

func (s *captureSender) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	return nil
}

func (s *captureSender) Requests() []SendRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SendRequest(nil), s.requests...)
}

func (s *captureSender) Attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func (s *captureSender) SetError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *captureSender) Closes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func testConfig(t testing.TB, extra ...string) *config.Config {
	t.Helper()
	args := []string{"--udp-bind=:6081", "--metrics-addr=:9090", "--max-inner-packet-size=1500"}
	args = append(args, extra...)
	cfg, err := config.ParseTarget(args)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func newTestDatapath(t testing.TB, cfg *config.Config, log *zap.Logger, sender PacketSender) (*Datapath, *metrics.Metrics) {
	t.Helper()
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	return newWithPacketIO(cfg, log, metricSet, &testReceiver{}, sender), metricSet
}

func geneveTestTLV(class uint16, rawType, reserved uint8, data []byte) []byte {
	if len(data)%4 != 0 {
		panic("test TLV data must be word aligned")
	}
	tlv := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(tlv[0:2], class)
	tlv[2] = rawType
	tlv[3] = reserved<<5 | byte(len(data)/4)
	copy(tlv[4:], data)
	return tlv
}

func sanitizedAWSOptions() []byte {
	options := geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeFlowCookie, 0, []byte{0xde, 0xad, 0xbe, 0xef})
	options = append(options, geneveTestTLV(geneve.AWSOptionClass, 0x7e, 0, []byte{1, 2, 3, 4})...)
	options = append(options, geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeAttachment, 0, []byte{0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28})...)
	options = append(options, geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeVPCE, 0, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})...)
	return options
}

func testPacketMetadata() PacketMetadata {
	return PacketMetadata{
		Peer:    netip.MustParseAddrPort("192.0.2.10:40000"),
		Local:   netip.MustParseAddrPort("198.51.100.20:6081"),
		IfIndex: 7,
	}
}

func innerIPv4UDP(source, destination [4]byte, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	return packet
}

func innerIPv6UDP(sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = 17
	packet[7] = 64
	packet[23], packet[39] = 1, 2
	binary.BigEndian.PutUint16(packet[40:42], sourcePort)
	binary.BigEndian.PutUint16(packet[42:44], destinationPort)
	binary.BigEndian.PutUint16(packet[44:46], 8)
	return packet
}

func encodeAWSGeneve(t testing.TB, payload, options []byte, mutate func(*geneve.Header)) []byte {
	t.Helper()
	header := geneve.Header{VNI: 0, Options: options}
	if mutate != nil {
		mutate(&header)
	}
	packet := make([]byte, geneve.BaseHeaderLen+geneve.MaxOptionsLen+len(payload))
	n, err := geneve.Encode(packet, header, payload)
	if err != nil {
		t.Fatalf("encode GENEVE: %v", err)
	}
	return packet[:n]
}

func TestIngressReturnsExactPacketWithAWSOuterTuple(t *testing.T) {
	sender := &captureSender{}
	dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
	inner := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	options := sanitizedAWSOptions()
	options[2] |= geneve.OptionTypeCriticalMask
	packet := encodeAWSGeneve(t, inner, options, func(header *geneve.Header) { header.Critical = true })

	dp.processIngress(packet, testPacketMetadata())

	requests := sender.Requests()
	if sender.Attempts() != 1 || len(requests) != 1 {
		t.Fatalf("send attempts=%d successful requests=%d, want exactly one", sender.Attempts(), len(requests))
	}
	request := requests[0]
	if request.Source != netip.MustParseAddrPort("198.51.100.20:40000") {
		t.Fatalf("source = %s, want 198.51.100.20:40000", request.Source)
	}
	if request.Destination != netip.MustParseAddrPort("192.0.2.10:6081") {
		t.Fatalf("destination = %s, want 192.0.2.10:6081", request.Destination)
	}
	if request.IfIndex != 7 {
		t.Fatalf("ifindex = %d, want 7", request.IfIndex)
	}
	header, returnedInner, err := geneve.Decode(request.Payload)
	if err != nil {
		t.Fatalf("decode return packet: %v", err)
	}
	if header.VNI != 0 || header.Protocol != geneve.ProtoIPv4 || !header.Critical {
		t.Fatalf("return header = %+v", header)
	}
	if !bytes.Equal(header.Options, options) || !bytes.Equal(returnedInner, inner) || !bytes.Equal(request.Payload, packet) {
		t.Fatal("return changed the GENEVE options, cookie, protocol, VNI, or inner packet")
	}
	if got := testutil.ToFloat64(metricSet.GeneveRxPackets); got != 1 {
		t.Fatalf("valid GENEVE RX packets = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSet.GeneveTxPackets); got != 1 {
		t.Fatalf("GENEVE TX packets = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSet.GeneveTxBytes); got != float64(len(packet)) {
		t.Fatalf("GENEVE TX bytes = %v, want %d", got, len(packet))
	}
}

func TestIngressReturnsUseOnlyCurrentPacketMetadata(t *testing.T) {
	sender := &captureSender{}
	dp, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
	innerA := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	innerB := innerIPv6UDP(443, 1234)
	optionsA := sanitizedAWSOptions()
	optionsB := sanitizedAWSOptions()
	copy(optionsB[4:8], []byte{1, 2, 3, 4})
	packetA := encodeAWSGeneve(t, innerA, optionsA, nil)
	packetB := encodeAWSGeneve(t, innerB, optionsB, nil)
	metadataA := testPacketMetadata()
	metadataB := PacketMetadata{
		Peer:    netip.MustParseAddrPort("203.0.113.30:51000"),
		Local:   netip.MustParseAddrPort("198.51.100.21:6081"),
		IfIndex: 11,
	}

	dp.processIngress(packetA, metadataA)
	dp.processIngress(packetB, metadataB)

	requests := sender.Requests()
	if len(requests) != 2 || sender.Attempts() != 2 {
		t.Fatalf("send attempts=%d successful requests=%d, want two", sender.Attempts(), len(requests))
	}
	if requests[0].Source != netip.MustParseAddrPort("198.51.100.20:40000") ||
		requests[0].Destination != netip.MustParseAddrPort("192.0.2.10:6081") ||
		!bytes.Equal(requests[0].Payload, packetA) {
		t.Fatal("first return did not use only the first packet metadata")
	}
	if requests[1].Source != netip.MustParseAddrPort("198.51.100.21:51000") ||
		requests[1].Destination != netip.MustParseAddrPort("203.0.113.30:6081") ||
		requests[1].IfIndex != 11 || !bytes.Equal(requests[1].Payload, packetB) {
		t.Fatal("second return retained metadata from another packet")
	}
	headerB, returnedInnerB, err := geneve.Decode(requests[1].Payload)
	if err != nil || headerB.Protocol != geneve.ProtoIPv6 || !bytes.Equal(returnedInnerB, innerB) {
		t.Fatalf("second return protocol or payload changed: header=%+v err=%v", headerB, err)
	}
}

func TestOpaqueInnerPacketsReturnByteForByte(t *testing.T) {
	ipv4Fragment := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	binary.BigEndian.PutUint16(ipv4Fragment[6:8], 0x2000)

	ipv6Extension := make([]byte, 56)
	ipv6Extension[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Extension[4:6], 16)
	ipv6Extension[6] = 0
	ipv6Extension[40] = 17
	binary.BigEndian.PutUint16(ipv6Extension[52:54], 8)

	ipv6Fragment := make([]byte, 48)
	ipv6Fragment[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Fragment[4:6], 8)
	ipv6Fragment[6] = 44
	ipv6Fragment[40] = 17
	binary.BigEndian.PutUint16(ipv6Fragment[42:44], 1)

	for _, tc := range []struct {
		name  string
		inner []byte
	}{
		{name: "IPv4 fragment", inner: ipv4Fragment},
		{name: "IPv6 extension", inner: ipv6Extension},
		{name: "IPv6 fragment", inner: ipv6Fragment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &captureSender{}
			dp, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
			packet := encodeAWSGeneve(t, tc.inner, sanitizedAWSOptions(), nil)
			dp.processIngress(packet, testPacketMetadata())

			requests := sender.Requests()
			if sender.Attempts() != 1 || len(requests) != 1 || !bytes.Equal(requests[0].Payload, packet) {
				t.Fatal("opaque inner packet was not returned exactly once byte-for-byte")
			}
		})
	}
}

func TestConcurrentIdenticalInnerTupleIsolation(t *testing.T) {
	const packetCount = 64
	sender := &captureSender{}
	dp, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
	inner := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	type expectedReturn struct {
		ifIndex int
		payload []byte
	}
	expected := make(map[uint16]expectedReturn, packetCount)

	var workers sync.WaitGroup
	for i := range packetCount {
		port := uint16(40000 + i)
		options := sanitizedAWSOptions()
		binary.BigEndian.PutUint32(options[4:8], uint32(i+1))
		packet := encodeAWSGeneve(t, inner, options, nil)
		metadata := PacketMetadata{
			Peer:    netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port),
			Local:   netip.MustParseAddrPort("198.51.100.20:6081"),
			IfIndex: i + 1,
		}
		expected[port] = expectedReturn{ifIndex: metadata.IfIndex, payload: packet}
		workers.Add(1)
		go func() {
			defer workers.Done()
			dp.processIngress(packet, metadata)
		}()
	}
	workers.Wait()

	requests := sender.Requests()
	if sender.Attempts() != packetCount || len(requests) != packetCount {
		t.Fatalf("send attempts=%d returns=%d, want %d exactly once returns", sender.Attempts(), len(requests), packetCount)
	}
	seen := make(map[uint16]bool, packetCount)
	for _, request := range requests {
		port := request.Source.Port()
		want, ok := expected[port]
		if !ok || seen[port] {
			t.Fatalf("unexpected or duplicate packet identity for source port %d", port)
		}
		seen[port] = true
		if request.Source.Addr() != netip.MustParseAddr("198.51.100.20") ||
			request.Destination != netip.MustParseAddrPort("192.0.2.10:6081") ||
			request.IfIndex != want.ifIndex || !bytes.Equal(request.Payload, want.payload) {
			t.Fatalf("packet identity %d was mixed with another concurrent packet", port)
		}
	}
}

func TestTargetRestartNeedsNoRestoredState(t *testing.T) {
	oldSender := &captureSender{}
	oldTarget, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), oldSender)
	oldPacket := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443), sanitizedAWSOptions(), nil)
	oldTarget.processIngress(oldPacket, testPacketMetadata())
	oldTarget.Close()

	restartedSender := &captureSender{}
	restartedTarget, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), restartedSender)
	postRestartPacket := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 1, 0, 1}, [4]byte{10, 0, 0, 1}, 443, 1234), sanitizedAWSOptions(), nil)
	restartedTarget.processIngress(postRestartPacket, testPacketMetadata())
	requests := restartedSender.Requests()
	if len(requests) != 1 || !bytes.Equal(requests[0].Payload, postRestartPacket) {
		t.Fatalf("post-restart returns = %d, want one independent return", len(requests))
	}
}

func TestProductionConstructorOpensOnlyPacketReceiverAndSender(t *testing.T) {
	receiver := &testReceiver{}
	sender := &captureSender{}
	dp, err := newWithPacketIOFactories(
		testConfig(t),
		zap.NewNop(),
		metrics.NewTarget(prometheus.NewRegistry()),
		func(bind string) (PacketReceiver, error) {
			if bind != ":6081" {
				t.Fatalf("receiver bind = %q, want :6081", bind)
			}
			return receiver, nil
		},
		func(maxPacket int) (PacketSender, error) {
			if maxPacket <= 0 {
				t.Fatalf("sender packet size = %d", maxPacket)
			}
			return sender, nil
		},
	)
	if err != nil {
		t.Fatalf("construct production datapath: %v", err)
	}
	dp.Close()
}

func TestProductionConstructorRejectsInvalidModeBeforePacketIO(t *testing.T) {
	cfg := testConfig(t)
	cfg.Mode = "direct-forward"
	opened := false
	_, err := newWithPacketIOFactories(
		cfg,
		zap.NewNop(),
		metrics.NewTarget(prometheus.NewRegistry()),
		func(string) (PacketReceiver, error) {
			opened = true
			return &testReceiver{}, nil
		},
		func(int) (PacketSender, error) {
			opened = true
			return &captureSender{}, nil
		},
	)
	if err == nil {
		t.Fatal("invalid target mode unexpectedly accepted")
	}
	if opened {
		t.Fatal("packet I/O opened before invalid target mode was rejected")
	}
}

func TestAWSProfileRejectionMatrix(t *testing.T) {
	validPayload := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	validOptions := sanitizedAWSOptions()
	cases := []struct {
		name     string
		packet   func(*testing.T) []byte
		metadata PacketMetadata
		reason   string
	}{
		{name: "decode", packet: func(*testing.T) []byte { return []byte{0} }, metadata: testPacketMetadata(), reason: metrics.ProfileReasonDecode},
		{name: "nonzero VNI", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.VNI = 1 })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonVNI},
		{name: "OAM", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.OAM = true })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOAM},
		{name: "missing cookie", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeVPCE, 0, make([]byte, 8)), nil)
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOptions},
		{name: "protocol mismatch", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.Protocol = geneve.ProtoIPv6 })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonProtocol},
		{name: "wrong local port", packet: func(t *testing.T) []byte { return encodeAWSGeneve(t, validPayload, validOptions, nil) }, metadata: func() PacketMetadata {
			m := testPacketMetadata()
			m.Local = netip.AddrPortFrom(m.Local.Addr(), 6080)
			return m
		}(), reason: metrics.ProfileReasonListener},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &captureSender{}
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
			dp.processIngress(tc.packet(t), tc.metadata)
			if sender.Attempts() != 0 {
				t.Fatal("invalid packet emitted a return")
			}
			if got := testutil.ToFloat64(metricSet.GeneveRxPackets); got != 0 {
				t.Fatalf("valid receive packets = %v, want 0", got)
			}
			if got := testutil.ToFloat64(metricSet.GWLBProfileRejections.WithLabelValues(tc.reason)); got != 1 {
				t.Fatalf("profile reason %q = %v, want 1", tc.reason, got)
			}
		})
	}
}

func TestInvalidInnerPacketsEmitNoReturn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner []byte
	}{
		{name: "short IPv4", inner: []byte{0x45}},
		{name: "short IPv6", inner: []byte{0x60}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &captureSender{}
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
			dp.processIngress(encodeAWSGeneve(t, tc.inner, sanitizedAWSOptions(), nil), testPacketMetadata())
			if sender.Attempts() != 0 || testutil.ToFloat64(metricSet.GeneveRxPackets) != 0 || testutil.ToFloat64(metricSet.GeneveTxPackets) != 0 {
				t.Fatal("invalid inner packet was counted as valid or emitted a return")
			}
			if got := testutil.ToFloat64(metricSet.GWLBInnerValidationFailures.WithLabelValues(metrics.InnerValidationReasonMalformed)); got != 1 {
				t.Fatalf("inner validation failures = %v, want 1", got)
			}
		})
	}
}

func TestSendFailureMetricsHealthAndRecovery(t *testing.T) {
	receiver := newScriptedReceiver()
	sender := &captureSender{err: errors.New("send failed")}
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	dp := newWithPacketIO(testConfig(t, "--persistent-error-threshold=1"), zap.NewNop(), metricSet, receiver, sender)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	waitForReady(t, dp)
	payload := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	packet := encodeAWSGeneve(t, payload, sanitizedAWSOptions(), nil)
	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	waitForHealthReason(t, dp, "sender_persistent_failure")
	waitForMetricValue(t, metricSet.GWLBSendFailures, 1)
	if sender.Attempts() != 1 || len(sender.Requests()) != 0 {
		t.Fatal("failed return had unexpected side effects")
	}
	if testutil.ToFloat64(metricSet.GWLBSendFailures) != 1 ||
		testutil.ToFloat64(metricSet.GWLBReturnBuildFailures) != 0 ||
		testutil.ToFloat64(metricSet.Drops) != 1 ||
		testutil.ToFloat64(metricSet.GeneveTxPackets) != 0 {
		t.Fatal("send failure metrics were not recorded")
	}
	sender.SetError(nil)
	receiver.results <- receiverResult{packet: packet, metadata: testPacketMetadata()}
	waitForReady(t, dp)
	waitForMetricValue(t, metricSet.GeneveTxPackets, 1)
	if sender.Attempts() != 2 || len(sender.Requests()) != 1 || testutil.ToFloat64(metricSet.GeneveTxPackets) != 1 {
		t.Fatal("successful retry did not emit exactly one counted return")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func waitForMetricValue(t *testing.T, collector prometheus.Collector, want float64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(collector) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("metric value = %v, want %v", testutil.ToFloat64(collector), want)
}

func TestPacketReturnBuildFailureEmitsNothing(t *testing.T) {
	sender := &captureSender{}
	dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender)
	dp.udpPool = bufferpool.New(1)
	packet := encodeAWSGeneve(t, innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443), sanitizedAWSOptions(), nil)

	dp.processIngress(packet, testPacketMetadata())

	if sender.Attempts() != 0 ||
		testutil.ToFloat64(metricSet.GWLBReturnBuildFailures) != 1 ||
		testutil.ToFloat64(metricSet.GWLBSendFailures) != 0 ||
		testutil.ToFloat64(metricSet.Drops) != 1 {
		t.Fatal("packet-return build failure was emitted or not counted")
	}
}

func TestTLVParsingLogsAllowedAndRedacted(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	dp, _ := newTestDatapath(t, testConfig(t, "--geneve-tlv-parse", "--geneve-tlv-allowlist=0x0108:1,0x0108:3"), zap.New(core), &captureSender{})
	dp.logAllowedTLVs(sanitizedAWSOptions())
	entries := observed.FilterMessage("geneve tlvs parsed").All()
	if len(entries) != 1 {
		t.Fatalf("TLV log entries = %d, want 1", len(entries))
	}
	logged, ok := entries[0].ContextMap()["tlvs"].([]tlvLogEntry)
	if !ok || len(logged) != 2 {
		t.Fatalf("unexpected logged TLVs: %#v", entries[0].ContextMap()["tlvs"])
	}
	for _, entry := range logged {
		if entry.Value != redactedOptionValue {
			t.Fatalf("AWS option was not redacted: %+v", entry)
		}
	}
}
