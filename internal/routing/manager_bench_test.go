package routing

import (
	"context"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
)

func BenchmarkEnsureManagedIdempotent(b *testing.B) {
	cfg := routingConfig(b, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	ops.recordQueries = false
	mgr, _ := newTestManager(b, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		b.Fatalf("initialize: %v (%s)", err, mgr.HealthReason())
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := mgr.ensureManaged(ctx, false); err != nil {
			b.Fatalf("ensure managed: %v", err)
		}
	}
}

func BenchmarkEffectiveRouteValidation(b *testing.B) {
	cfg := routingConfig(b, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	ops.recordQueries = false
	addEquivalentReturnState(cfg, ops)
	mgr, _ := newTestManager(b, cfg, ops, time.Hour)

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := mgr.verify(ctx); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}
