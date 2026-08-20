package datapath

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

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
	err      error
}

func (s *captureSender) SendPacket(request SendRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	request.Payload = append([]byte(nil), request.Payload...)
	s.requests = append(s.requests, request)
	return nil
}

func (s *captureSender) Close() error { return nil }

func (s *captureSender) Requests() []SendRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SendRequest(nil), s.requests...)
}

type captureTun struct {
	writes   [][]byte
	writeErr error
}

func (*captureTun) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (t *captureTun) Write(packet []byte) (int, error) {
	if t.writeErr != nil {
		return 0, t.writeErr
	}
	t.writes = append(t.writes, append([]byte(nil), packet...))
	return len(packet), nil
}
func (*captureTun) Close() error { return nil }

func testConfig(t testing.TB, extra ...string) *config.Config {
	t.Helper()
	args := []string{"--udp-bind=:6081", "--metrics-addr=:9090", "--tun-mtu=1500"}
	args = append(args, extra...)
	cfg, err := config.Parse(args)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func newTestDatapath(t *testing.T, cfg *config.Config, log *zap.Logger, sender *captureSender, tunDev *captureTun) (*Datapath, *metrics.Metrics) {
	t.Helper()
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	return NewWithDevices(cfg, log, metricSet, &testReceiver{}, sender, tunDev), metricSet
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

func TestAWSIngressAndReverseOnlyEgress(t *testing.T) {
	cfg := testConfig(t)
	sender := &captureSender{}
	tunDev := &captureTun{}
	dp, metricSet := newTestDatapath(t, cfg, zap.NewNop(), sender, tunDev)

	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	options := sanitizedAWSOptions()
	dp.processIngress(encodeAWSGeneve(t, forward, options, nil), testPacketMetadata())
	if len(tunDev.writes) != 1 || !bytes.Equal(tunDev.writes[0], forward) {
		t.Fatalf("valid ingress was not written to TUN")
	}
	if dp.flows.Len() != 1 {
		t.Fatalf("flow table length = %d, want 1", dp.flows.Len())
	}

	// Same-orientation traffic is a possible routing loop and must not escape.
	dp.processEgress(forward)
	if len(sender.Requests()) != 0 {
		t.Fatal("same-orientation packet was sent")
	}
	if got := testutil.ToFloat64(metricSet.GWLBPossibleLoops); got != 1 {
		t.Fatalf("possible-loop metric = %v, want 1", got)
	}

	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	dp.processEgress(reverse)
	requests := sender.Requests()
	if len(requests) != 1 {
		t.Fatalf("send requests = %d, want 1", len(requests))
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
	header, gotPayload, err := geneve.Decode(request.Payload)
	if err != nil {
		t.Fatalf("decode egress GENEVE: %v", err)
	}
	if header.VNI != 0 || header.Protocol != geneve.ProtoIPv4 || header.OAM {
		t.Fatalf("unexpected egress header: %+v", header)
	}
	if !bytes.Equal(header.Options, options) || !bytes.Equal(gotPayload, reverse) {
		t.Fatal("egress options or payload changed")
	}
}

func TestReturnIdentityIsCompleteAndImmutable(t *testing.T) {
	options := geneveTestTLV(geneve.AWSOptionClass, geneve.OptionTypeCriticalMask|geneve.AWSOptionTypeFlowCookie, 0, []byte{0xde, 0xad, 0xbe, 0xef})
	header := geneve.Header{Options: options, Protocol: geneve.ProtoIPv4, Critical: true}
	metadata := testPacketMetadata()
	optionMetadata, err := geneve.ValidateAWSProfile(header, []byte{0x45}, geneve.MaxOptionsLen)
	if err != nil {
		t.Fatalf("validate profile: %v", err)
	}
	identity := newReturnIdentity(metadata, header, optionMetadata)
	options[0] ^= 0xff
	header.Options[1] ^= 0xff
	if identity.peerIP != metadata.Peer.Addr() || identity.localIP != metadata.Local.Addr() ||
		identity.flowPort != metadata.Peer.Port() || identity.ifIndex != metadata.IfIndex ||
		identity.vni != 0 || identity.protocol != geneve.ProtoIPv4 ||
		identity.fixedFlags != geneve.FlagCritical || identity.flowCookie != [4]byte{0xde, 0xad, 0xbe, 0xef} {
		t.Fatalf("incomplete return identity: %+v", identity)
	}
	if identity.options[0] != 0x01 || identity.options[1] != 0x08 {
		t.Fatal("return identity retained mutable option storage")
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
		{name: "nonzero VNI", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.VNI = 1 })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonVNI},
		{name: "OAM", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.OAM = true })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOAM},
		{name: "missing cookie", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeVPCE, 0, make([]byte, 8)), nil)
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOptions},
		{name: "duplicate cookie", packet: func(t *testing.T) []byte {
			cookie := geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeFlowCookie, 0, []byte{1, 2, 3, 4})
			return encodeAWSGeneve(t, validPayload, append(cookie, cookie...), nil)
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOptions},
		{name: "reserved option bits", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, geneveTestTLV(geneve.AWSOptionClass, geneve.AWSOptionTypeFlowCookie, 1, []byte{1, 2, 3, 4}), nil)
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonOptionReserved},
		{name: "protocol mismatch", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, func(h *geneve.Header) { h.Protocol = geneve.ProtoIPv6 })
		}, metadata: testPacketMetadata(), reason: metrics.ProfileReasonProtocol},
		{name: "wrong local port", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, nil)
		}, metadata: func() PacketMetadata {
			m := testPacketMetadata()
			m.Local = netip.AddrPortFrom(m.Local.Addr(), 6080)
			return m
		}(), reason: metrics.ProfileReasonListener},
		{name: "outer IPv6", packet: func(t *testing.T) []byte {
			return encodeAWSGeneve(t, validPayload, validOptions, nil)
		}, metadata: func() PacketMetadata {
			m := testPacketMetadata()
			m.Peer = netip.MustParseAddrPort("[2001:db8::1]:40000")
			return m
		}(), reason: metrics.ProfileReasonOuterIPv4},
	}
	allReasons := []string{
		metrics.ProfileReasonDecode,
		metrics.ProfileReasonOuterIPv4,
		metrics.ProfileReasonListener,
		metrics.ProfileReasonVNI,
		metrics.ProfileReasonOAM,
		metrics.ProfileReasonProtocol,
		metrics.ProfileReasonOptionReserved,
		metrics.ProfileReasonOptions,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &captureSender{}
			tunDev := &captureTun{}
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender, tunDev)
			dp.processIngress(tc.packet(t), tc.metadata)
			if len(tunDev.writes) != 0 || dp.flows.Len() != 0 {
				t.Fatal("invalid profile packet reached TUN or installed context")
			}
			for _, reason := range allReasons {
				want := float64(0)
				if reason == tc.reason {
					want = 1
				}
				if got := testutil.ToFloat64(metricSet.GWLBProfileRejections.WithLabelValues(reason)); got != want {
					t.Fatalf("profile reason %q = %v, want %v", reason, got, want)
				}
			}
			if got := testutil.ToFloat64(metricSet.Drops); got != 1 {
				t.Fatalf("drops = %v, want 1", got)
			}
		})
	}
}

func TestConflictMissingAndSendFailureMetrics(t *testing.T) {
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	packet := encodeAWSGeneve(t, forward, sanitizedAWSOptions(), nil)

	t.Run("missing", func(t *testing.T) {
		dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), &captureSender{}, &captureTun{})
		dp.processEgress(reverse)
		if testutil.ToFloat64(metricSet.GWLBMissingContexts) != 1 || testutil.ToFloat64(metricSet.Drops) != 1 {
			t.Fatal("missing-context metrics did not increment")
		}
	})

	t.Run("conflict", func(t *testing.T) {
		dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), &captureSender{}, &captureTun{})
		dp.processIngress(packet, testPacketMetadata())
		other := testPacketMetadata()
		other.Peer = netip.MustParseAddrPort("192.0.2.11:40000")
		dp.processIngress(packet, other)
		dp.processEgress(reverse)
		if testutil.ToFloat64(metricSet.GWLBContextCollisions) != 1 || testutil.ToFloat64(metricSet.GWLBConflictedContexts) != 1 {
			t.Fatal("conflict metrics did not increment")
		}
	})

	t.Run("send failure", func(t *testing.T) {
		sender := &captureSender{err: errors.New("send failed")}
		dp, metricSet := newTestDatapath(t, testConfig(t, "--persistent-error-threshold=1"), zap.NewNop(), sender, &captureTun{})
		dp.processIngress(packet, testPacketMetadata())
		dp.processEgress(reverse)
		if testutil.ToFloat64(metricSet.GWLBSendFailures) != 1 || dp.Ready() {
			t.Fatal("send failure did not update metrics and liveness")
		}
		if dp.HealthReason() != metrics.LivenessComponentSend {
			t.Fatalf("health reason = %q", dp.HealthReason())
		}
		sender.err = nil
		dp.processEgress(reverse)
		if !dp.Ready() {
			t.Fatal("successful compliant send did not recover liveness")
		}
	})
}

func TestDatapathRefreshesOnlySuccessfulEgress(t *testing.T) {
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	packet := encodeAWSGeneve(t, forward, sanitizedAWSOptions(), nil)

	t.Run("failed send", func(t *testing.T) {
		sender := &captureSender{err: errors.New("send failed")}
		dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), sender, &captureTun{})
		now := time.Unix(100, 0)
		dp.flows.now = func() time.Time { return now }
		dp.processIngress(packet, testPacketMetadata())
		now = now.Add(100 * time.Second)
		dp.processEgress(reverse)
		now = time.Unix(100, 0).Add(121 * time.Second)
		sender.err = nil
		dp.processEgress(reverse)
		if len(sender.Requests()) != 0 {
			t.Fatal("failed send refreshed an expired context")
		}
		if testutil.ToFloat64(metricSet.GWLBContextExpirations) != 1 {
			t.Fatal("failed-send context did not expire")
		}
	})

	t.Run("successful send", func(t *testing.T) {
		sender := &captureSender{}
		dp, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), sender, &captureTun{})
		now := time.Unix(100, 0)
		dp.flows.now = func() time.Time { return now }
		dp.processIngress(packet, testPacketMetadata())
		now = now.Add(100 * time.Second)
		dp.processEgress(reverse)
		now = time.Unix(100, 0).Add(219 * time.Second)
		dp.processEgress(reverse)
		if len(sender.Requests()) != 2 {
			t.Fatalf("successful egress did not refresh context: sends=%d", len(sender.Requests()))
		}
	})
}

func TestTunWritePersistentFailureAndRecovery(t *testing.T) {
	tunDev := &captureTun{writeErr: errors.New("TUN write failed")}
	dp, _ := newTestDatapath(t, testConfig(t, "--persistent-error-threshold=1"), zap.NewNop(), &captureSender{}, tunDev)
	payload := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	packet := encodeAWSGeneve(t, payload, sanitizedAWSOptions(), nil)
	dp.processIngress(packet, testPacketMetadata())
	if dp.Ready() || dp.HealthReason() != metrics.LivenessComponentTunWrite {
		t.Fatal("persistent TUN write failure did not change liveness")
	}
	tunDev.writeErr = nil
	dp.processIngress(packet, testPacketMetadata())
	if !dp.Ready() {
		t.Fatal("successful TUN write did not recover liveness")
	}
}

func TestContextExpiryAndEvictionMetrics(t *testing.T) {
	first := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1001, 443)
	second := innerIPv4UDP([4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 4}, 1002, 443)
	dp, metricSet := newTestDatapath(t, testConfig(t, "--flow-capacity=1"), zap.NewNop(), &captureSender{}, &captureTun{})
	now := time.Unix(100, 0)
	dp.flows.now = func() time.Time { return now }
	dp.processIngress(encodeAWSGeneve(t, first, sanitizedAWSOptions(), nil), testPacketMetadata())
	now = now.Add(time.Second)
	dp.processIngress(encodeAWSGeneve(t, second, sanitizedAWSOptions(), nil), testPacketMetadata())
	if got := testutil.ToFloat64(metricSet.GWLBContextEvictions); got != 1 {
		t.Fatalf("evictions = %v, want 1", got)
	}
	now = now.Add(121 * time.Second)
	dp.recordExpirations(dp.flows.Sweep())
	if got := testutil.ToFloat64(metricSet.GWLBContextExpirations); got != 1 {
		t.Fatalf("expirations = %v, want 1", got)
	}
}

func TestMTUDropsRemainFailClosedAndReasoned(t *testing.T) {
	ipv4 := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], 8)
	ipv6[6] = 17
	for _, tt := range []struct {
		name    string
		payload []byte
		family  string
	}{
		{name: "IPv4", payload: ipv4, family: metrics.MTUDropFamilyIPv4},
		{name: "IPv6", payload: ipv6, family: metrics.MTUDropFamilyIPv6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.TunMTU = len(tt.payload) - 1
			sender := &captureSender{}
			tunDev := &captureTun{}
			dp, metricSet := newTestDatapath(t, cfg, zap.NewNop(), sender, tunDev)
			dp.processIngress(encodeAWSGeneve(t, tt.payload, sanitizedAWSOptions(), nil), testPacketMetadata())
			if dp.flows.Len() != 0 || len(tunDev.writes) != 0 {
				t.Fatal("oversized ingress reached state or TUN")
			}
			dp.processEgress(tt.payload)
			if len(sender.Requests()) != 0 || testutil.ToFloat64(metricSet.Drops) != 2 {
				t.Fatal("MTU drops did not fail closed")
			}
			if got := testutil.ToFloat64(metricSet.MTUDrops.WithLabelValues(tt.family, metrics.MTUDropDirectionIngress)); got != 1 {
				t.Fatalf("ingress MTU reason = %v, want 1", got)
			}
			if got := testutil.ToFloat64(metricSet.MTUDrops.WithLabelValues(tt.family, metrics.MTUDropDirectionEgress)); got != 1 {
				t.Fatalf("egress MTU reason = %v, want 1", got)
			}
			if testutil.ToFloat64(metricSet.DecapErrors) != 0 || testutil.ToFloat64(metricSet.EncapErrors) != 0 {
				t.Fatal("MTU drop was incorrectly reported as a codec error")
			}
		})
	}
}

func TestUnsupportedInnerReasonMetrics(t *testing.T) {
	ipv4Fragment := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	binary.BigEndian.PutUint16(ipv4Fragment[6:8], 0x2000)
	truncatedTransport := append([]byte(nil), ipv4Fragment...)
	binary.BigEndian.PutUint16(truncatedTransport[6:8], 0)
	truncatedTransport = truncatedTransport[:27]
	binary.BigEndian.PutUint16(truncatedTransport[2:4], uint16(len(truncatedTransport)))
	ipv6Fragment := make([]byte, 48)
	ipv6Fragment[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Fragment[4:6], 8)
	ipv6Fragment[6] = 44
	ipv6Extension := make([]byte, 68)
	ipv6Extension[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Extension[4:6], 28)
	ipv6Extension[6] = 0
	ipv6Extension[40] = 6

	cases := []struct {
		name    string
		payload []byte
		reason  string
	}{
		{name: "malformed", payload: []byte{0x45}, reason: metrics.UnsupportedReasonMalformed},
		{name: "IPv4 fragment", payload: ipv4Fragment, reason: metrics.UnsupportedReasonIPv4Fragment},
		{name: "IPv6 fragment", payload: ipv6Fragment, reason: metrics.UnsupportedReasonIPv6Fragment},
		{name: "IPv6 extension", payload: ipv6Extension, reason: metrics.UnsupportedReasonIPv6Extension},
		{name: "truncated transport", payload: truncatedTransport, reason: metrics.UnsupportedReasonTransportTruncated},
	}
	allReasons := []string{
		metrics.UnsupportedReasonMalformed,
		metrics.UnsupportedReasonIPv4Fragment,
		metrics.UnsupportedReasonIPv6Fragment,
		metrics.UnsupportedReasonIPv6Extension,
		metrics.UnsupportedReasonTransportTruncated,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), &captureSender{}, &captureTun{})
			dp.processIngress(encodeAWSGeneve(t, tc.payload, sanitizedAWSOptions(), nil), testPacketMetadata())
			if dp.flows.Len() != 0 {
				t.Fatal("unsupported packet installed context")
			}
			for _, reason := range allReasons {
				want := float64(0)
				if reason == tc.reason {
					want = 1
				}
				if got := testutil.ToFloat64(metricSet.GWLBUnsupportedInner.WithLabelValues(reason)); got != want {
					t.Fatalf("reason %q = %v, want %v", reason, got, want)
				}
			}
			if testutil.ToFloat64(metricSet.Drops) != 1 {
				t.Fatal("unsupported packet did not increment drops")
			}
		})
	}
}

func TestOptionsPreservedWithLoggingOnAndOff(t *testing.T) {
	options := sanitizedAWSOptions()
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	var outputs [][]byte
	for _, extra := range [][]string{
		nil,
		{"--geneve-tlv-parse", "--geneve-tlv-allowlist=0x0108:1,0x0108:3"},
	} {
		sender := &captureSender{}
		dp, _ := newTestDatapath(t, testConfig(t, extra...), zap.NewNop(), sender, &captureTun{})
		dp.processIngress(encodeAWSGeneve(t, forward, options, nil), testPacketMetadata())
		dp.processEgress(reverse)
		header, _, err := geneve.Decode(sender.Requests()[0].Payload)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, append([]byte(nil), header.Options...))
	}
	if !bytes.Equal(outputs[0], options) || !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatal("option logging changed ordered option fidelity")
	}
}

func TestTLVParsingLogsAllowedAndRedacted(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	dp, _ := newTestDatapath(t, testConfig(t, "--geneve-tlv-parse", "--geneve-tlv-allowlist=0x0108:1,0x0108:3"), zap.New(core), &captureSender{}, &captureTun{})
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
