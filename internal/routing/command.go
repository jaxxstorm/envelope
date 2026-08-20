package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	systemCommandTimeout = 3 * time.Second
	commandWaitDelay     = 250 * time.Millisecond
	commandOutputLimit   = 64 * 1024
)

var ErrCommandOutputLimit = errors.New("command output exceeded limit")

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execCommandRunner struct {
	timeout     time.Duration
	outputLimit int
}

func (r execCommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("command path must be fixed and absolute: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect command %s: %w", path, err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("command is not executable: %s", path)
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = systemCommandTimeout
	}
	limit := r.outputLimit
	if limit <= 0 {
		limit = commandOutputLimit
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := commandCtx.Err(); err != nil {
		return nil, fmt.Errorf("%s command exceeded %s: %w", path, timeout, err)
	}

	output := &boundedCommandOutput{limit: limit, cancel: cancel}
	cmd := exec.CommandContext(commandCtx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = commandWaitDelay
	err = cmd.Run()
	data, exceeded := output.Result()
	if exceeded {
		return nil, fmt.Errorf("%w (%d bytes retained) from %s", ErrCommandOutputLimit, len(data), path)
	}
	if commandCtx.Err() != nil {
		return nil, fmt.Errorf("%s command exceeded %s: %w", path, timeout, commandCtx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return data, nil
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedCommandOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	writeLength := min(remaining, len(data))
	if writeLength > 0 {
		_, _ = b.buffer.Write(data[:writeLength])
	}
	if len(data) > remaining && !b.exceeded {
		b.exceeded = true
		b.cancel()
	}
	return len(data), nil
}

func (b *boundedCommandOutput) Result() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes()), b.exceeded
}
