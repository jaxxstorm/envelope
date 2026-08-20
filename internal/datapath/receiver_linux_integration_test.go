//go:build linux && integration

package datapath

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxReceiverCapturesExactLocalIPv4(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("0.0.0.0:6081")
	if err != nil {
		t.Fatalf("listen packet receiver: %v", err)
	}
	defer receiver.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()

	for _, destination := range []string{"127.0.0.1", "127.0.0.2"} {
		if _, err := client.WriteToUDP([]byte(destination), &net.UDPAddr{IP: net.ParseIP(destination), Port: 6081}); err != nil {
			t.Fatalf("send to %s: %v", destination, err)
		}
		if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		buffer := make([]byte, 128)
		n, metadata, err := receiver.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("receive from %s: %v", destination, err)
		}
		if string(buffer[:n]) != destination {
			t.Fatalf("payload = %q, want %q", buffer[:n], destination)
		}
		if metadata.Local != netip.AddrPortFrom(netip.MustParseAddr(destination), 6081) {
			t.Fatalf("local tuple = %s, want %s:6081", metadata.Local, destination)
		}
		if metadata.Peer.Addr() != netip.MustParseAddr("127.0.0.3") || metadata.Peer.Port() == 0 {
			t.Fatalf("unexpected peer tuple: %s", metadata.Peer)
		}
		if metadata.IfIndex <= 0 {
			t.Fatalf("invalid ingress ifindex: %d", metadata.IfIndex)
		}
	}
}

func TestLinuxReceiverDoesNotReceiveOtherPorts(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("127.0.0.1:6081")
	if err != nil {
		t.Fatalf("listen packet receiver: %v", err)
	}
	defer receiver.Close()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6080})
	if err != nil {
		t.Fatalf("dial unbound port: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("not geneve")); err != nil {
		t.Fatalf("send to other port: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.ReadPacket(make([]byte, 128)); err == nil {
		t.Fatal("listener on 6081 received traffic sent to 6080")
	}
}

func TestLinuxReceiverReportsOversizedDatagramAsPacketTruncation(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("127.0.0.1:6081")
	if err != nil {
		t.Fatalf("listen packet receiver: %v", err)
	}
	defer receiver.Close()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6081})
	if err != nil {
		t.Fatalf("dial receiver: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(make([]byte, 512)); err != nil {
		t.Fatalf("send oversized datagram: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.ReadPacket(make([]byte, 64)); !errors.Is(err, ErrPacketTruncated) {
		t.Fatalf("receive error = %v, want ErrPacketTruncated", err)
	}
}

func lockIntegrationGenevePort(t *testing.T) {
	t.Helper()
	path := "/tmp/envelope-integration-udp-6081-" + strconv.Itoa(os.Getuid()) + ".lock"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open integration port lock: %v", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		file.Close()
		t.Fatalf("lock integration port: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})
}
