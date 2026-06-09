//go:build linux && integration

package app

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"go.uber.org/zap"
)

func TestRunStartStop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	cfg := &config.Config{
		UDPBind:     "127.0.0.1:0",
		TunName:     "envtest0",
		TunMTU:      1400,
		MetricsAddr: "127.0.0.1:0",
		LogLevel:    "error",
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
