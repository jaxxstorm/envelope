//go:build linux && integration

package datapath

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const rawSenderHelperEnvironment = "ENVELOPE_RAW_SENDER_NETNS_HELPER"

func TestLinuxRawSenderGWLBPacketInNetworkNamespace(t *testing.T) {
	if os.Getenv(rawSenderHelperEnvironment) == "1" {
		runRawSenderCapture(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_NET_ADMIN/CAP_NET_RAW")
	}
	ipCommand, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("requires iproute2 ip command")
	}
	namespace := "env-gwlb-" + strconv.Itoa(os.Getpid())
	runIP := func(args ...string) {
		t.Helper()
		command := exec.Command(ipCommand, args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	runIP("netns", "add", namespace)
	defer exec.Command(ipCommand, "netns", "delete", namespace).Run()
	runIP("-n", namespace, "link", "set", "lo", "up")

	command := exec.Command(ipCommand, "netns", "exec", namespace, os.Args[0], "-test.run=^TestLinuxRawSenderGWLBPacketInNetworkNamespace$", "-test.v")
	command.Env = append(os.Environ(), rawSenderHelperEnvironment+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("network namespace helper failed: %v\n%s", err, output)
	}
}

func runRawSenderCapture(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("resolve loopback: %v", err)
	}
	packetFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		t.Fatalf("open packet capture: %v", err)
	}
	defer unix.Close(packetFD)
	if err := unix.Bind(packetFD, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: loopback.Index}); err != nil {
		t.Fatalf("bind packet capture: %v", err)
	}
	if err := unix.SetsockoptTimeval(packetFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatalf("set capture timeout: %v", err)
	}

	packetSender, err := newPacketSender(2048)
	if err != nil {
		t.Fatalf("open raw sender: %v", err)
	}
	defer packetSender.Close()
	sender := packetSender

	// Drive the complete context and reverse-only datapath path with the real
	// raw sender while receiver and TUN I/O remain deterministic.
	metricDP := newIntegrationDatapath(t, sender)
	options := sanitizedAWSOptions()
	forward := innerIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 443)
	reverse := innerIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 1234)
	metadata := PacketMetadata{
		Peer:    netip.MustParseAddrPort("127.0.0.2:40000"),
		Local:   netip.MustParseAddrPort("127.0.0.1:6081"),
		IfIndex: loopback.Index,
	}
	metricDP.processIngress(encodeAWSGeneve(t, forward, options, nil), metadata)
	metricDP.processEgress(reverse)

	buffer := make([]byte, 4096)
	for attempts := 0; attempts < 8; attempts++ {
		n, _, err := unix.Recvfrom(packetFD, buffer, 0)
		if err != nil {
			t.Fatalf("capture return packet: %v", err)
		}
		ipPacket, ok := capturedIPv4(buffer[:n])
		if !ok || len(ipPacket) < 28 || ipPacket[9] != 17 {
			continue
		}
		udp := ipPacket[20:]
		if binary.BigEndian.Uint16(udp[0:2]) != 40000 || binary.BigEndian.Uint16(udp[2:4]) != 6081 {
			continue
		}
		if [4]byte(ipPacket[12:16]) != [4]byte{127, 0, 0, 1} || [4]byte(ipPacket[16:20]) != [4]byte{127, 0, 0, 2} {
			t.Fatalf("outer addresses were not swapped: %v -> %v", ipPacket[12:16], ipPacket[16:20])
		}
		if referenceChecksum(ipPacket[:20]) != 0 {
			t.Fatal("captured IPv4 checksum is invalid")
		}
		pseudo := make([]byte, 12+len(udp))
		copy(pseudo[0:4], ipPacket[12:16])
		copy(pseudo[4:8], ipPacket[16:20])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
		copy(pseudo[12:], udp)
		if referenceChecksum(pseudo) != 0 {
			t.Fatal("captured UDP checksum is invalid")
		}
		header, payload, err := geneve.Decode(udp[8:])
		if err != nil {
			t.Fatalf("decode captured GENEVE: %v", err)
		}
		if header.VNI != 0 || !bytes.Equal(header.Options, options) || !bytes.Equal(payload, reverse) {
			t.Fatal("captured GENEVE metadata or payload changed")
		}
		return
	}
	t.Fatal("did not capture mapped return packet")
}

// newIntegrationDatapath keeps the real PacketSender while using deterministic
// receiver and TUN fakes for the packet-level namespace test.
func newIntegrationDatapath(t *testing.T, sender PacketSender) *Datapath {
	t.Helper()
	cfg := testConfig(t)
	metricSet := newTestMetrics(t)
	return NewWithDevices(cfg, zap.NewNop(), metricSet, &testReceiver{}, sender, &captureTun{})
}

func newTestMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	return metrics.New(prometheus.NewRegistry())
}

func capturedIPv4(frame []byte) ([]byte, bool) {
	if len(frame) >= 14 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP {
		frame = frame[14:]
	}
	if len(frame) < 20 || frame[0]>>4 != 4 {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(frame[2:4]))
	if total < 20 || total > len(frame) {
		return nil, false
	}
	return frame[:total], true
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}
