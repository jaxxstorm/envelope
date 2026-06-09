package routing

import (
	"context"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func BenchmarkEnsureManagedIdempotent(b *testing.B) {
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--protected-cidrs=172.16.0.0/16",
	})
	if err != nil {
		b.Fatalf("parse config: %v", err)
	}

	ops := newFakeOps()
	ops.ifaces[cfg.TunName] = true
	ops.ifaces[cfg.TailscaleIface] = true
	ops.sysctls[ipv4ForwardingPath] = true
	for _, rt := range buildTargets(cfg.EffectiveProtectedCIDRs()) {
		ops.rules[ruleKey(rt.family, cfg.RoutingRulePriority, cfg.TailscaleIface, rt.cidr, cfg.RoutingTableID)] = struct{}{}
		ops.routes[routeKey(rt.family, cfg.RoutingTableID, rt.cidr, cfg.TunName)] = struct{}{}
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), m, ops, time.Millisecond)
	if err != nil {
		b.Fatalf("new manager: %v", err)
	}
	mgr := rm.(*manager)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mgr.ensureManaged(ctx, false); err != nil {
			b.Fatalf("ensure managed: %v", err)
		}
	}
}
