package routing

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecCommandRunnerBoundsExecution(t *testing.T) {
	runner := execCommandRunner{timeout: 20 * time.Millisecond}
	started := time.Now()
	_, err := runner.Run(context.Background(), "/bin/sh", "-c", "sleep 1")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected bounded command error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("bounded command took %s", elapsed)
	}
}

func TestExecCommandRunnerCancellationKillsChildProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "orphan-ran")
	runner := execCommandRunner{timeout: 20 * time.Millisecond}
	command := "(sleep 0.2; touch " + marker + ") & wait"
	if _, err := runner.Run(context.Background(), "/bin/sh", "-c", command); err == nil {
		t.Fatal("expected command timeout")
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed-out child survived process-group cancellation: %v", err)
	}
}

func TestExecCommandRunnerRejectsPATHLookupAndUsesMinimalEnvironment(t *testing.T) {
	runner := execCommandRunner{}
	if _, err := runner.Run(context.Background(), "sh", "-c", "true"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative executable was accepted: %v", err)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ip")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	out, err := runner.Run(context.Background(), "/bin/sh", "-c", "printf '%s' \"$PATH\"")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Fatalf("command inherited unsafe PATH: %q", out)
	}
}

func TestExecCommandRunnerBoundsOutputFlood(t *testing.T) {
	runner := execCommandRunner{timeout: time.Second, outputLimit: 1024}
	started := time.Now()
	_, err := runner.Run(context.Background(), "/bin/sh", "-c", "while :; do printf 0123456789abcdef; done")
	if !errors.Is(err, ErrCommandOutputLimit) {
		t.Fatalf("output flood error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("output flood was not terminated promptly: %s", elapsed)
	}
}
