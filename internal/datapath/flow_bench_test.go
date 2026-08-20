package datapath

import (
	"net"
	"testing"

	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	flowLookupSink flowLookupResult
	flowUpdateSink flowUpdateResult
	packetSizeSink int
)

type benchmarkPacketSender struct{}

func (*benchmarkPacketSender) SendPacket(request SendRequest) error {
	packetSizeSink = len(request.Payload)
	return nil
}

func (*benchmarkPacketSender) Close() error { return nil }

type benchmarkTunDevice struct{}

func (*benchmarkTunDevice) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (*benchmarkTunDevice) Write(packet []byte) (int, error) {
	packetSizeSink = len(packet)
	return len(packet), nil
}
func (*benchmarkTunDevice) Close() error { return nil }

func BenchmarkContextLookup(b *testing.B) {
	table := testFlowTable(1024)
	key := testFlowKey(17, 1)
	table.Update(key, testReturnIdentity(1))
	b.ReportAllocs()
	for range b.N {
		flowLookupSink = table.LookupEgress(key.Reverse())
	}
}

func BenchmarkContextOptionsCopy(b *testing.B) {
	options := make([]byte, 252)
	metadata := testPacketMetadata()
	header := geneve.Header{Protocol: geneve.ProtoIPv4, Options: options}
	optionMetadata := geneve.OptionMetadata{HasFlowCookie: true}
	b.ReportAllocs()
	b.SetBytes(int64(len(options)))
	for range b.N {
		identityAllocationSink = newReturnIdentity(metadata, header, optionMetadata)
	}
}

func BenchmarkContextEviction(b *testing.B) {
	table := testFlowTable(64)
	for id := byte(1); id <= 64; id++ {
		table.Update(testFlowKey(17, id), testReturnIdentity(id))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		id := byte(iteration%190 + 65)
		flowUpdateSink = table.Update(testFlowKey(17, id), testReturnIdentity(id))
	}
}

func BenchmarkContextDefaultCapacityChurn(b *testing.B) {
	const capacity = 65536
	table := testFlowTable(capacity)
	identity := testReturnIdentity(1)
	for index := uint64(0); index < capacity; index++ {
		table.Update(benchmarkFlowKey(index), identity)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		flowUpdateSink = table.Update(benchmarkFlowKey(capacity+uint64(index)), identity)
	}
	b.ReportMetric(capacity, "contexts")
}

func BenchmarkDirectionalPacketPath(b *testing.B) {
	cfg := testConfig(b)
	metricSet := metrics.New(prometheus.NewRegistry())
	dp := NewWithDevices(cfg, nil, metricSet, &testReceiver{}, &benchmarkPacketSender{}, &benchmarkTunDevice{})
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	packet := encodeAWSGeneve(b, forward, sanitizedAWSOptions(), nil)
	metadata := testPacketMetadata()
	b.ReportAllocs()
	b.SetBytes(int64(len(forward) + len(reverse)))
	b.ResetTimer()
	for range b.N {
		dp.processIngress(packet, metadata)
		dp.processEgress(reverse)
	}
}

func benchmarkFlowKey(id uint64) flowKey {
	key := flowKey{proto: 17, ipFamily: 4, srcPort: uint16(id), dstPort: 443}
	for index := 0; index < 8; index++ {
		key.srcIP[8+index] = byte(id >> (index * 8))
	}
	key.dstIP[15] = 1
	return key
}
