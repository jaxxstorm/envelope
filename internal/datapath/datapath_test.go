package datapath

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
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

func newTestDatapath(t testing.TB, cfg *config.Config, log *zap.Logger, tunDev *captureTun) (*Datapath, *metrics.Metrics) {
	t.Helper()
	metricSet := metrics.New(prometheus.NewRegistry())
	return NewWithDevices(cfg, log, metricSet, &testReceiver{}, tunDev), metricSet
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

func TestSymmetricIngressIsIndependentOfFlowHistory(t *testing.T) {
	packetA := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	packetB := innerIPv4UDP([4]byte{10, 1, 0, 1}, [4]byte{10, 0, 0, 1}, 443, 1234)
	for _, payload := range [][]byte{packetA, packetB} {
		t.Run("independent healthy target", func(t *testing.T) {
			tunDev := &captureTun{}
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), tunDev)
			dp.processIngress(encodeAWSGeneve(t, payload, sanitizedAWSOptions(), nil), testPacketMetadata())
			if len(tunDev.writes) != 1 || !bytes.Equal(tunDev.writes[0], payload) {
				t.Fatal("valid packet was not injected into TUN")
			}
			if got := testutil.ToFloat64(metricSet.TunTxPackets); got != 1 {
				t.Fatalf("TUN injection metric = %v, want 1", got)
			}
		})
	}
}

func TestTargetRestartNeedsNoRestoredState(t *testing.T) {
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 1, 0, 1}, [4]byte{10, 0, 0, 1}, 443, 1234)
	oldTarget, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), &captureTun{})
	oldTarget.processIngress(encodeAWSGeneve(t, forward, sanitizedAWSOptions(), nil), testPacketMetadata())

	tunDev := &captureTun{}
	restartedTarget, _ := newTestDatapath(t, testConfig(t), zap.NewNop(), tunDev)
	restartedTarget.processIngress(encodeAWSGeneve(t, reverse, sanitizedAWSOptions(), nil), testPacketMetadata())
	if got := len(tunDev.writes); got != 1 {
		t.Fatalf("post-restart packet injections = %d, want 1", got)
	}
}

func TestUnexpectedTunEgressIsDroppedWithoutGeneveEmission(t *testing.T) {
	payload := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 1, 0, 1}, 1234, 443)
	core, observed := observer.New(zap.WarnLevel)
	dp, metricSet := newTestDatapath(t, testConfig(t), zap.New(core), &captureTun{})
	dp.processEgress(payload)
	dp.processEgress(payload)
	if got := testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress); got != 2 {
		t.Fatalf("unexpected egress metric = %v, want 2", got)
	}
	if got := testutil.ToFloat64(metricSet.Drops); got != 2 {
		t.Fatalf("drops = %v, want 2", got)
	}
	if entries := observed.FilterMessage("unexpected TUN egress dropped").All(); len(entries) != 1 {
		t.Fatalf("unexpected egress logs = %d, want 1", len(entries))
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
		{name: "wrong local port", packet: func(t *testing.T) []byte { return encodeAWSGeneve(t, validPayload, validOptions, nil) }, metadata: func() PacketMetadata {
			m := testPacketMetadata()
			m.Local = netip.AddrPortFrom(m.Local.Addr(), 6080)
			return m
		}(), reason: metrics.ProfileReasonListener},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp, metricSet := newTestDatapath(t, testConfig(t), zap.NewNop(), &captureTun{})
			dp.processIngress(tc.packet(t), tc.metadata)
			if got := testutil.ToFloat64(metricSet.GWLBProfileRejections.WithLabelValues(tc.reason)); got != 1 {
				t.Fatalf("profile reason %q = %v, want 1", tc.reason, got)
			}
		})
	}
}

func TestTunWritePersistentFailureAndRecovery(t *testing.T) {
	tunDev := &captureTun{writeErr: errors.New("TUN write failed")}
	dp, _ := newTestDatapath(t, testConfig(t, "--persistent-error-threshold=1"), zap.NewNop(), tunDev)
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

func TestTLVParsingLogsAllowedAndRedacted(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	dp, _ := newTestDatapath(t, testConfig(t, "--geneve-tlv-parse", "--geneve-tlv-allowlist=0x0108:1,0x0108:3"), zap.New(core), &captureTun{})
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
