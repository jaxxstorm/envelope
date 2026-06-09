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

func TestIngressMTUDrop(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 8}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	dp := NewWithDevices(cfg, zap.NewNop(), m, udpConn, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	payload := make([]byte, 20)
	payload[0] = 0x45
	buf := make([]byte, 128)
	n, err := geneve.Encode(buf, geneve.Header{VNI: 1}, payload)
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

	select {
	case <-tunDev.writeCh:
		t.Fatalf("unexpected tun write")
	case <-time.After(200 * time.Millisecond):
	}

	if got := testutil.ToFloat64(m.Drops); got == 0 {
		t.Fatalf("expected drops to increment")
	}
}

func TestEgressMTUDrop(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 8}
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
	key, ok := flowKeyFromPacket(payload)
	if !ok {
		t.Fatalf("failed to build flow key")
	}
	dp.flows.Update(key, peerConn.LocalAddr().(*net.UDPAddr), 2, nil)
	tunDev.readCh <- payload

	buf := make([]byte, 2048)
	peerConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := peerConn.ReadFromUDP(buf); err == nil {
		t.Fatalf("expected no udp output")
	}

	if got := testutil.ToFloat64(m.Drops); got == 0 {
		t.Fatalf("expected drops to increment")
	}
}
