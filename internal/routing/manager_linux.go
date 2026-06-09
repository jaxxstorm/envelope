//go:build linux

package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type systemOpsLinux struct{}

func newSystemOps() systemOps {
	return &systemOpsLinux{}
}

func (s *systemOpsLinux) InterfaceExists(name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("lookup interface %s: %w", name, err)
	}
	return true, nil
}

func (s *systemOpsLinux) SysctlEnabled(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

func (s *systemOpsLinux) RuleExists(ctx context.Context, family string, priority int, iif, cidr string, table int) (bool, error) {
	out, err := runIP(ctx, family, "rule", "show")
	if err != nil {
		return false, err
	}
	priorityPrefix := fmt.Sprintf("%d:", priority)
	priorityToken := fmt.Sprintf("pref %d", priority)
	lookup := fmt.Sprintf("lookup %d", table)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, priorityPrefix) && !strings.Contains(line, priorityToken) {
			continue
		}
		if strings.Contains(line, "iif "+iif) && strings.Contains(line, "to "+cidr) && strings.Contains(line, lookup) {
			return true, nil
		}
	}
	return false, nil
}

func (s *systemOpsLinux) AddRule(ctx context.Context, family string, priority int, iif, cidr string, table int) error {
	_, err := runIP(ctx, family, "rule", "add", "priority", fmt.Sprintf("%d", priority), "iif", iif, "to", cidr, "table", fmt.Sprintf("%d", table))
	if err != nil {
		return fmt.Errorf("add rule for %s: %w", cidr, err)
	}
	return nil
}

func (s *systemOpsLinux) DeleteRule(ctx context.Context, family string, priority int, iif, cidr string, table int) error {
	_, err := runIP(ctx, family, "rule", "del", "priority", fmt.Sprintf("%d", priority), "iif", iif, "to", cidr, "table", fmt.Sprintf("%d", table))
	if err != nil {
		if isMissingRouteStateErr(err) {
			return nil
		}
		return fmt.Errorf("delete rule for %s: %w", cidr, err)
	}
	return nil
}

func (s *systemOpsLinux) RouteExists(ctx context.Context, family string, table int, cidr, dev string) (bool, error) {
	out, err := runIP(ctx, family, "route", "show", "table", fmt.Sprintf("%d", table), cidr)
	if err != nil {
		if isMissingFIBTableErr(err) {
			return false, nil
		}
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, cidr) && strings.Contains(line, "dev "+dev) {
			return true, nil
		}
	}
	return false, nil
}

func isMissingFIBTableErr(err error) bool {
	return strings.Contains(err.Error(), "FIB table does not exist")
}

func (s *systemOpsLinux) AddRoute(ctx context.Context, family string, table int, cidr, dev string) error {
	_, err := runIP(ctx, family, "route", "replace", "table", fmt.Sprintf("%d", table), cidr, "dev", dev)
	if err != nil {
		return fmt.Errorf("add route for %s: %w", cidr, err)
	}
	return nil
}

func (s *systemOpsLinux) DeleteRoute(ctx context.Context, family string, table int, cidr, dev string) error {
	_, err := runIP(ctx, family, "route", "del", "table", fmt.Sprintf("%d", table), cidr, "dev", dev)
	if err != nil {
		if isMissingFIBTableErr(err) || isMissingRouteStateErr(err) {
			return nil
		}
		return fmt.Errorf("delete route for %s: %w", cidr, err)
	}
	return nil
}

func isMissingRouteStateErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "Cannot find device")
}

func runIP(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
