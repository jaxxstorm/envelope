package datapath

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestDecapErrorIncrements(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 1500}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	dp := NewWithDevices(cfg, zap.NewNop(), m, udpConn, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	client, err := net.DialUDP("udp", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	// Malformed packet: too short
	if _, err := client.Write([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if got := testutil.ToFloat64(m.DecapErrors); got == 0 {
		t.Fatalf("expected decap_errors to increment")
	}
	if got := testutil.ToFloat64(m.Drops); got == 0 {
		t.Fatalf("expected drops to increment")
	}
}

func TestEncapErrorIncrements(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 1500}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	dp := NewWithDevices(cfg, zap.NewNop(), m, udpConn, tunDev)

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp peer: %v", err)
	}
	defer peerConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	payload := make([]byte, 20)
	payload[0] = 0x45
	// Invalid options length to force encode error.
	key, ok := flowKeyFromPacket(payload)
	if !ok {
		t.Fatalf("failed to build flow key")
	}
	dp.flows.Update(key, peerConn.LocalAddr().(*net.UDPAddr), 2, []byte{0x01, 0x02, 0x03})
	tunDev.readCh <- payload

	time.Sleep(100 * time.Millisecond)

	if got := testutil.ToFloat64(m.EncapErrors); got == 0 {
		t.Fatalf("expected encap_errors to increment")
	}
	if got := testutil.ToFloat64(m.Drops); got == 0 {
		t.Fatalf("expected drops to increment")
	}
}

func TestUnsupportedProtocolType(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 1500}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	dp := NewWithDevices(cfg, zap.NewNop(), m, udpConn, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	// Build a GENEVE packet with an unsupported protocol type (0x0806).
	buf := make([]byte, 16)
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x08
	buf[3] = 0x06
	buf[4] = 0x00
	buf[5] = 0x00
	buf[6] = 0x01
	buf[7] = 0x00

	client, err := net.DialUDP("udp", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(buf[:8]); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if got := testutil.ToFloat64(m.DecapErrors); got == 0 {
		t.Fatalf("expected decap_errors to increment")
	}
}

func TestOptionsValidationDrop(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 1500, GeneveOptionsMaxBytes: 4}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	dp := NewWithDevices(cfg, zap.NewNop(), m, udpConn, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	payload := make([]byte, 20)
	payload[0] = 0x45
	payload[9] = 0x11
	copy(payload[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(payload[16:20], net.IPv4(10, 0, 0, 2).To4())

	options := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	buf := make([]byte, 128)
	n, err := geneve.Encode(buf, geneve.Header{VNI: 1, Options: options}, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	client, err := net.DialUDP("udp", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(buf[:n]); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if got := testutil.ToFloat64(m.DecapErrors); got == 0 {
		t.Fatalf("expected decap_errors to increment")
	}
	if got := testutil.ToFloat64(m.Drops); got == 0 {
		t.Fatalf("expected drops to increment")
	}

	select {
	case <-tunDev.writeCh:
		t.Fatalf("unexpected tun write for invalid options")
	default:
	}
}
