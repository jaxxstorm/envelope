//go:build linux && integration

package datapath

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/jaxxstorm/envelope/internal/tun"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLinuxIngressMTUDropReasons(t *testing.T) {
	lockIntegrationGenevePort(t)
	receiver, err := listenPacketReceiver("127.0.0.1:6081")
	if err != nil {
		t.Fatalf("listen receiver: %v", err)
	}
	cfg := testConfig(t, "--tun-mtu=1280")
	metricSet := metrics.New(prometheus.NewRegistry())
	tunDev := &captureTun{}
	dp := NewWithDevices(cfg, nil, metricSet, receiver, tunDev)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.ingressLoop(ctx) }()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6081})
	if err != nil {
		t.Fatalf("dial receiver: %v", err)
	}
	defer client.Close()
	for _, version := range []byte{0x45, 0x60} {
		payload := make([]byte, cfg.TunMTU+1)
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
	for _, payloadSize := range []int{cfg.TunMTU + 1, cfg.TunMTU + 2, cfg.TunMTU + 4096, maximumPayload} {
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
	if testutil.ToFloat64(metricSet.DecapErrors) != 0 || len(tunDev.writes) != 0 {
		t.Fatal("oversized packet was misclassified or reached TUN")
	}
	if got := testutil.ToFloat64(metricSet.GWLBReceiveDrops.WithLabelValues(metrics.ReceiveDropReasonDatagramTruncated)); got != 0 {
		t.Fatalf("maximum-options MTU probe was reported as UDP truncation: %v", got)
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

func TestLinuxRealTunUnexpectedEgressDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires iproute2")
	}
	name := fmt.Sprintf("envmtu%d", os.Getpid()%100000)
	tunDev, err := tun.Open(name, 1500)
	if err != nil {
		t.Fatalf("open real TUN: %v", err)
	}
	defer tunDev.Close()
	for _, args := range [][]string{
		{"addr", "add", "198.18.0.1/32", "dev", "lo"},
		{"route", "add", "198.18.1.0/24", "dev", name},
	} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "route", "del", "198.18.1.0/24", "dev", name).Run()
		_ = exec.Command("ip", "addr", "del", "198.18.0.1/32", "dev", "lo").Run()
	})

	cfg := testConfig(t, "--tun-mtu=1280")
	metricSet := metrics.New(prometheus.NewRegistry())
	dp := NewWithDevices(cfg, nil, metricSet, &testReceiver{}, tunDev)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.egressLoop(ctx) }()
	// Bringing up a real TUN can emit unrelated kernel traffic (for example,
	// IPv6 interface setup). Assert the test packet's counter deltas.
	time.Sleep(50 * time.Millisecond)
	baselineDrops := testutil.ToFloat64(metricSet.Drops)
	baselineUnexpected := testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress)

	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1")}, &net.UDPAddr{IP: net.ParseIP("198.18.1.1"), Port: 20000})
	if err != nil {
		cancel()
		tunDev.Close()
		t.Fatalf("dial routed TUN destination: %v", err)
	}
	if _, err := client.Write(make([]byte, cfg.TunMTU+1-20-8)); err != nil {
		client.Close()
		cancel()
		tunDev.Close()
		t.Fatalf("write one-byte oversized inner packet: %v", err)
	}
	client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress) != baselineUnexpected+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := testutil.ToFloat64(metricSet.SymmetricUnexpectedEgress); got != baselineUnexpected+1 {
		t.Fatalf("real-TUN unexpected egress drops=%v, want baseline %v + 1", got, baselineUnexpected)
	}
	if got := testutil.ToFloat64(metricSet.Drops); got != baselineDrops+1 {
		t.Fatalf("unexpected TUN packet drops=%v, want baseline %v + 1", got, baselineDrops)
	}

	cancel()
	_ = tunDev.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("egress loop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("real TUN egress loop did not stop")
	}
}
