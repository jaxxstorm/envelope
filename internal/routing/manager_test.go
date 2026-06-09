package routing

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type fakeOps struct {
	ifaces  map[string]bool
	sysctls map[string]bool
	rules   map[string]struct{}
	routes  map[string]struct{}
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		ifaces:  map[string]bool{},
		sysctls: map[string]bool{},
		rules:   map[string]struct{}{},
		routes:  map[string]struct{}{},
	}
}

func ruleKey(family string, priority int, iif, cidr string, table int) string {
	return fmt.Sprintf("%s|%d|%s|%s|%d", family, priority, iif, cidr, table)
}

func routeKey(family string, table int, cidr, dev string) string {
	return fmt.Sprintf("%s|%d|%s|%s", family, table, cidr, dev)
}

func (f *fakeOps) InterfaceExists(name string) (bool, error) {
	return f.ifaces[name], nil
}

func (f *fakeOps) SysctlEnabled(path string) (bool, error) {
	return f.sysctls[path], nil
}

func (f *fakeOps) RuleExists(_ context.Context, family string, priority int, iif, cidr string, table int) (bool, error) {
	_, ok := f.rules[ruleKey(family, priority, iif, cidr, table)]
	return ok, nil
}

func (f *fakeOps) AddRule(_ context.Context, family string, priority int, iif, cidr string, table int) error {
	f.rules[ruleKey(family, priority, iif, cidr, table)] = struct{}{}
	return nil
}

func (f *fakeOps) DeleteRule(_ context.Context, family string, priority int, iif, cidr string, table int) error {
	delete(f.rules, ruleKey(family, priority, iif, cidr, table))
	return nil
}

func (f *fakeOps) RouteExists(_ context.Context, family string, table int, cidr, dev string) (bool, error) {
	_, ok := f.routes[routeKey(family, table, cidr, dev)]
	return ok, nil
}

func (f *fakeOps) AddRoute(_ context.Context, family string, table int, cidr, dev string) error {
	f.routes[routeKey(family, table, cidr, dev)] = struct{}{}
	return nil
}

func (f *fakeOps) DeleteRoute(_ context.Context, family string, table int, cidr, dev string) error {
	delete(f.routes, routeKey(family, table, cidr, dev))
	return nil
}

func managedConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--protected-cidrs=172.16.0.0/16",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func TestManagedInitializeAppliesState(t *testing.T) {
	cfg := managedConfig(t)
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)

	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if !mgr.Ready() {
		t.Fatalf("expected manager ready")
	}
	if len(ops.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(ops.rules))
	}
	if len(ops.routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(ops.routes))
	}

	changed, err := mgr.ensureManaged(context.Background(), false)
	if err != nil {
		t.Fatalf("ensure managed: %v", err)
	}
	if changed {
		t.Fatalf("expected no changes on idempotent reconcile")
	}
}

func TestManagedReconcilesDrift(t *testing.T) {
	cfg := managedConfig(t)
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)

	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	for k := range ops.rules {
		delete(ops.rules, k)
	}
	changed, err := mgr.ensureManaged(context.Background(), false)
	if err != nil {
		t.Fatalf("ensure managed: %v", err)
	}
	if !changed {
		t.Fatalf("expected drift reconcile to report changes")
	}
	if len(ops.rules) != 1 {
		t.Fatalf("expected rule to be restored")
	}
}

func TestVerifyModeNotReadyWhenStateMissing(t *testing.T) {
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=verify",
		"--protected-cidrs=172.16.0.0/16",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)

	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if mgr.Ready() {
		t.Fatalf("expected verify mode to be not ready when routes are missing")
	}

	for _, rt := range buildTargets(cfg.EffectiveProtectedCIDRs()) {
		ops.rules[ruleKey(rt.family, cfg.RoutingRulePriority, cfg.TailscaleIface, rt.cidr, cfg.RoutingTableID)] = struct{}{}
		ops.routes[routeKey(rt.family, cfg.RoutingTableID, rt.cidr, cfg.TunName)] = struct{}{}
	}
	if err := mgr.verify(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestManagedModeUsesDistinctInterfaces(t *testing.T) {
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--tun-name=envelope-test0",
		"--tailscale-iface=tailscale-test0",
		"--routing-mode=manage",
		"--protected-cidrs=172.16.0.0/16",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	foundRuleIface := false
	for key := range ops.rules {
		if strings.Contains(key, cfg.TailscaleIface) {
			foundRuleIface = true
			break
		}
	}
	if !foundRuleIface {
		t.Fatalf("expected routing rules to reference tailscale interface %q", cfg.TailscaleIface)
	}

	foundRouteIface := false
	for key := range ops.routes {
		if strings.HasSuffix(key, "|"+cfg.TunName) {
			foundRouteIface = true
			break
		}
	}
	if !foundRouteIface {
		t.Fatalf("expected routes to reference envelope tun interface %q", cfg.TunName)
	}
}

func TestManageModeFailsWhenIPv4ForwardingDisabled(t *testing.T) {
	cfg := managedConfig(t)
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = false

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)
	if err := mgr.Initialize(context.Background()); err == nil {
		t.Fatalf("expected initialize to fail when ipv4 forwarding is disabled")
	}
}

func TestManagedRunCleansUpStateOnCancel(t *testing.T) {
	cfg := managedConfig(t)
	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)

	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if len(ops.rules) == 0 || len(ops.routes) == 0 {
		t.Fatalf("expected initialized rule and route state")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- mgr.Run(ctx)
	}()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for manager shutdown")
	}

	if len(ops.rules) != 0 {
		t.Fatalf("expected rules cleaned up on shutdown")
	}
	if len(ops.routes) != 0 {
		t.Fatalf("expected routes cleaned up on shutdown")
	}
}
