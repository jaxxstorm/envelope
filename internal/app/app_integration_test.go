//go:build linux && integration

package app

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func TestRunStartStop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	lockIntegrationGenevePort(t)
	cfg := &config.Config{
		UDPBind:                  "127.0.0.1:6081",
		TunName:                  "envtest0",
		TunMTU:                   1400,
		MetricsAddr:              "127.0.0.1:0",
		LogLevel:                 "error",
		FlowCapacity:             1024,
		TCPFlowTimeout:           350 * time.Second,
		UDPFlowTimeout:           120 * time.Second,
		OtherFlowTimeout:         120 * time.Second,
		PersistentErrorThreshold: 3,
		GeneveOptionsMaxBytes:    252,
		RoutingTableID:           100,
		RoutingRulePriority:      100,
		RoutingMode:              config.RoutingModeOff,
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, cfg, zap.NewNop())
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
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
