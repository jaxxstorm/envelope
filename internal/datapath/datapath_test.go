package datapath

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type chanTun struct {
	readCh  chan []byte
	writeCh chan []byte
}

func newChanTun() *chanTun {
	return &chanTun{readCh: make(chan []byte, 1), writeCh: make(chan []byte, 1)}
}

func (t *chanTun) Read(p []byte) (int, error) {
	data := <-t.readCh
	n := copy(p, data)
	return n, nil
}

func (t *chanTun) Write(p []byte) (int, error) {
	b := append([]byte(nil), p...)
	t.writeCh <- b
	return len(p), nil
}

func (t *chanTun) Close() error {
	return nil
}

func TestIngressUDPToTun(t *testing.T) {
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

	payload := make([]byte, 20)
	payload[0] = 0x45
	payload[9] = 0x11
	copy(payload[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(payload[16:20], net.IPv4(10, 0, 0, 2).To4())
	buf := make([]byte, 64)
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
	case got := <-tunDev.writeCh:
		if string(got) != string(payload) {
			t.Fatalf("payload mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for tun write")
	}
}

func TestEgressTunToUDP(t *testing.T) {
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

	// Seed flow mapping with a local UDP listener.
	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp peer: %v", err)
	}
	defer peerConn.Close()
	payload := make([]byte, 20)
	payload[0] = 0x45
	payload[9] = 0x11
	copy(payload[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(payload[16:20], net.IPv4(10, 0, 0, 2).To4())
	key, ok := flowKeyFromPacket(payload)
	if !ok {
		t.Fatalf("failed to build flow key")
	}
	dp.flows.Update(key, peerConn.LocalAddr().(*net.UDPAddr), 2, nil)
	tunDev.readCh <- payload

	buf := make([]byte, 2048)
	peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read from peer: %v", err)
	}
	_, decPayload, err := geneve.Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decPayload) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestEgressTunToUDPReverseFlowLookup(t *testing.T) {
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

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp peer: %v", err)
	}
	defer peerConn.Close()

	ingress := make([]byte, 20)
	ingress[0] = 0x45
	ingress[9] = 0x01
	copy(ingress[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ingress[16:20], net.IPv4(10, 0, 0, 2).To4())
	key, ok := flowKeyFromPacket(ingress)
	if !ok {
		t.Fatalf("failed to build flow key")
	}
	dp.flows.Update(key, peerConn.LocalAddr().(*net.UDPAddr), 2, nil)

	reply := make([]byte, 20)
	reply[0] = 0x45
	reply[9] = 0x01
	copy(reply[12:16], net.IPv4(10, 0, 0, 2).To4())
	copy(reply[16:20], net.IPv4(10, 0, 0, 1).To4())
	tunDev.readCh <- reply

	buf := make([]byte, 2048)
	peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read from peer: %v", err)
	}
	_, decPayload, err := geneve.Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decPayload) != string(reply) {
		t.Fatalf("payload mismatch")
	}
}

func TestOptionsPreservedEgress(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp peer: %v", err)
	}
	defer peerConn.Close()

	tunDev := newChanTun()
	cfg := &config.Config{TunMTU: 1500}
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

	options := []byte{0x01, 0x02, 0x03, 0x01, 0xde, 0xad, 0xbe, 0xef}
	buf := make([]byte, 128)
	n, err := geneve.Encode(buf, geneve.Header{VNI: 1, Options: options}, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := peerConn.WriteToUDP(buf[:n], udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	select {
	case <-tunDev.writeCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for tun write")
	}

	tunDev.readCh <- payload

	resp := make([]byte, 2048)
	peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	nn, _, err := peerConn.ReadFromUDP(resp)
	if err != nil {
		t.Fatalf("read from peer: %v", err)
	}
	decHdr, decPayload, err := geneve.Decode(resp[:nn])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decPayload, payload) {
		t.Fatalf("payload mismatch")
	}
	if !bytes.Equal(decHdr.Options, options) {
		t.Fatalf("options mismatch")
	}
}

func TestTLVParsingLogsAllowed(t *testing.T) {
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--tun-mtu=1500",
		"--geneve-tlv-parse",
		"--geneve-tlv-allowlist=0x0102:0x03",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp peer: %v", err)
	}
	defer peerConn.Close()

	tunDev := newChanTun()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	core, obs := observer.New(zap.DebugLevel)
	log := zap.New(core)
	dp := NewWithDevices(cfg, log, m, udpConn, tunDev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dp.Run(ctx) }()

	payload := make([]byte, 20)
	payload[0] = 0x45
	payload[9] = 0x11
	copy(payload[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(payload[16:20], net.IPv4(10, 0, 0, 2).To4())

	options := []byte{
		0x01, 0x02, 0x03, 0x01,
		0xde, 0xad, 0xbe, 0xef,
	}
	buf := make([]byte, 128)
	n, err := geneve.Encode(buf, geneve.Header{VNI: 1, Options: options}, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := peerConn.WriteToUDP(buf[:n], udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	select {
	case <-tunDev.writeCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for tun write")
	}

	entries := obs.FilterMessage("geneve tlvs parsed").All()
	if len(entries) == 0 {
		t.Fatalf("expected tlv parsed log")
	}
}
