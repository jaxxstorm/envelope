//go:build linux && integration

package datapath

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLinuxIngressMTUBoundsReturnOnlyCompletePackets(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("127.0.0.1:6081")
	if err != nil {
		t.Fatalf("listen receiver: %v", err)
	}
	cfg := testConfig(t, "--max-inner-packet-size=1280")
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	sender := &captureSender{}
	dp := newWithPacketIO(cfg, nil, metricSet, receiver, sender)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = receiver.Close()
	})
	done := make(chan error, 1)
	go func() { done <- dp.ingressLoop(ctx) }()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6081})
	if err != nil {
		t.Fatalf("dial receiver: %v", err)
	}
	defer client.Close()
	for _, version := range []byte{0x45, 0x60} {
		payload := make([]byte, cfg.MaxInnerPacketSize+1)
		payload[0] = version
		packet := encodeAWSGeneve(t, payload, sanitizedAWSOptions(), nil)
		if _, err := client.Write(packet); err != nil {
			t.Fatalf("send oversized packet: %v", err)
		}
	}
	maxOptions := sanitizedAWSOptions()
	maxOptions = append(maxOptions, geneveTestTLV(0x2222, 1, 0, make([]byte, 124))...)
	maxOptions = append(maxOptions, geneveTestTLV(0x2222, 2, 0, make([]byte, 80))...)
	if len(maxOptions) != geneve.MaxOptionsLen {
		t.Fatalf("maximum options fixture length=%d", len(maxOptions))
	}
	maximumPayload := cfg.MaxUDPReceiveSize() - geneve.BaseHeaderLen - len(maxOptions)
	for _, payloadSize := range []int{cfg.MaxInnerPacketSize + 1, cfg.MaxInnerPacketSize + 2, cfg.MaxInnerPacketSize + 4096, maximumPayload} {
		payload := make([]byte, payloadSize)
		payload[0] = 0x45
		packet := encodeAWSGeneve(t, payload, maxOptions, nil)
		if payloadSize == maximumPayload && len(packet) != cfg.MaxUDPReceiveSize() {
			t.Fatalf("maximum valid datagram=%d, receive capacity=%d", len(packet), cfg.MaxUDPReceiveSize())
		}
		if _, err := client.Write(packet); err != nil {
			t.Fatalf("send maximum-options oversized packet size %d: %v", payloadSize, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(metricSet.Drops) != 6 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := testutil.ToFloat64(metricSet.Drops); got != 6 {
		t.Fatalf("total drops=%v, want 6", got)
	}
	if got := testutil.ToFloat64(metricSet.MTUDrops.WithLabelValues(metrics.MTUDropFamilyIPv4, metrics.MTUDropDirectionIngress)); got != 5 {
		t.Fatalf("IPv4 MTU drops=%v, want 5", got)
	}
	if got := testutil.ToFloat64(metricSet.MTUDrops.WithLabelValues(metrics.MTUDropFamilyIPv6, metrics.MTUDropDirectionIngress)); got != 1 {
		t.Fatalf("IPv6 MTU drops=%v, want 1", got)
	}
	if testutil.ToFloat64(metricSet.GWLBReturnBuildFailures) != 0 || testutil.ToFloat64(metricSet.GWLBSendFailures) != 0 || sender.Attempts() != 0 {
		t.Fatal("oversized packet was misclassified or returned")
	}
	if got := testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)); got != 0 {
		t.Fatalf("maximum-options MTU probe was reported as UDP truncation: %v", got)
	}

	maximumInner := make([]byte, cfg.MaxInnerPacketSize)
	maximumInner[0] = 0x45
	binary.BigEndian.PutUint16(maximumInner[2:4], uint16(len(maximumInner)))
	maximumInner[8] = 64
	maximumInner[9] = 1
	copy(maximumInner[12:16], []byte{10, 10, 0, 1})
	copy(maximumInner[16:20], []byte{10, 20, 0, 1})
	maximumPacket := encodeAWSGeneve(t, maximumInner, maxOptions, nil)
	if _, err := client.Write(maximumPacket); err != nil {
		t.Fatalf("send maximum accepted packet: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for sender.Attempts() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	requests := sender.Requests()
	if sender.Attempts() != 1 || len(requests) != 1 || !bytes.Equal(requests[0].Payload, maximumPacket) {
		t.Fatal("maximum accepted packet was not returned once, complete and byte-identical")
	}
	cancel()
	_ = receiver.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ingress loop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ingress loop did not stop")
	}
}

func TestLinuxOpaqueNonInitialFragmentIsReturned(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("127.0.0.1:6081")
	if err != nil {
		t.Fatalf("listen receiver: %v", err)
	}
	cfg := testConfig(t)
	metricSet := metrics.NewTarget(prometheus.NewRegistry())
	sender := &captureSender{}
	dp := newWithPacketIO(cfg, nil, metricSet, receiver, sender)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = receiver.Close()
	})
	done := make(chan error, 1)
	go func() { done <- dp.ingressLoop(ctx) }()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6081})
	if err != nil {
		t.Fatalf("dial receiver: %v", err)
	}
	defer client.Close()
	inner := make([]byte, 28)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint16(inner[4:6], 0x7a31)
	binary.BigEndian.PutUint16(inner[6:8], 1)
	inner[8] = 64
	inner[9] = 17
	copy(inner[12:16], []byte{10, 10, 0, 10})
	copy(inner[16:20], []byte{10, 20, 0, 10})
	copy(inner[20:], []byte{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8})
	packet := encodeAWSGeneve(t, inner, sanitizedAWSOptions(), nil)
	if _, err := client.Write(packet); err != nil {
		t.Fatalf("send opaque non-initial fragment: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for sender.Attempts() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	requests := sender.Requests()
	if sender.Attempts() != 1 || len(requests) != 1 || !bytes.Equal(requests[0].Payload, packet) {
		t.Fatal("otherwise valid non-initial fragment was not returned once and byte-identically")
	}
	if testutil.ToFloat64(metricSet.Drops) != 0 {
		t.Fatal("opaque fragment was dropped")
	}

	cancel()
	_ = receiver.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ingress loop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ingress loop did not stop")
	}
}
