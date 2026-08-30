//go:build linux && integration

package app

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func TestRunStartStopWithoutTargetForwardingState(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		t.Skipf("requires CAP_NET_RAW: %v", err)
	}
	_ = unix.Close(fd)
	lockIntegrationGenevePort(t)
	before := readTargetNetworkState(t)
	cfg := &config.Config{
		ConfigVersion:            2,
		Mode:                     "packet-return",
		UDPBind:                  "127.0.0.1:6081",
		MaxInnerPacketSize:       1400,
		MetricsAddr:              "127.0.0.1:0",
		LogLevel:                 "error",
		PersistentErrorThreshold: 3,
		GeneveOptionsMaxBytes:    252,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, cfg, zap.NewNop())
	}()

	time.Sleep(300 * time.Millisecond)
	if during := readTargetNetworkState(t); during != before {
		cancel()
		t.Fatalf("packet-return target mutated forwarding, routes, or interfaces\nbefore: %+v\nduring: %+v", before, during)
	}
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}
	if after := readTargetNetworkState(t); after != before {
		t.Fatalf("packet-return target left forwarding, route, or interface state behind\nbefore: %+v\nafter: %+v", before, after)
	}
}

type targetNetworkState struct {
	forwarding string
	routes     string
	interfaces string
}

func readTargetNetworkState(t *testing.T) targetNetworkState {
	t.Helper()
	read := func(path string) string {
		t.Helper()
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(value)
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Fatalf("read network interfaces: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return targetNetworkState{
		forwarding: read("/proc/sys/net/ipv4/ip_forward"),
		routes:     read("/proc/net/route"),
		interfaces: strings.Join(names, ","),
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
