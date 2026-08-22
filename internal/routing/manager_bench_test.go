package routing

import (
	"context"
	"testing"

	"github.com/jaxxstorm/envelope/internal/config"
)

func BenchmarkEnsureManagedIdempotent(b *testing.B) {
	cfg := routingConfig(b, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	mgr := newTestManager(b, cfg, ops)
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
	mgr := newTestManager(b, cfg, ops)

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := mgr.verify(ctx); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}
