package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"go.uber.org/zap"
)

const (
	defaultReconcileInterval = 30 * time.Second
	ipv4ForwardingPath       = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardingPath       = "/proc/sys/net/ipv6/conf/all/forwarding"
)

type Manager interface {
	Initialize(context.Context) error
	Run(context.Context) error
	Ready() bool
	Mode() config.RoutingMode
}

type systemOps interface {
	InterfaceExists(name string) (bool, error)
	SysctlEnabled(path string) (bool, error)
	RuleExists(ctx context.Context, family string, priority int, iif, cidr string, table int) (bool, error)
	AddRule(ctx context.Context, family string, priority int, iif, cidr string, table int) error
	DeleteRule(ctx context.Context, family string, priority int, iif, cidr string, table int) error
	RouteExists(ctx context.Context, family string, table int, cidr, dev string) (bool, error)
	AddRoute(ctx context.Context, family string, table int, cidr, dev string) error
	DeleteRoute(ctx context.Context, family string, table int, cidr, dev string) error
}

type targetRoute struct {
	family string
	cidr   string
	isIPv6 bool
}

type manager struct {
	cfg            *config.Config
	log            *zap.Logger
	metrics        *metrics.Metrics
	op             systemOps
	reconcileEvery time.Duration
	routingMode    config.RoutingMode
	ready          atomic.Bool
}

func New(cfg *config.Config, log *zap.Logger, m *metrics.Metrics) (Manager, error) {
	mode := cfg.RoutingMode
	if mode == "" {
		mode = config.RoutingModeOff
	}
	if mode != config.RoutingModeOff && runtime.GOOS != "linux" {
		return nil, errors.New("routing integration is only supported on linux")
	}
	return newManager(cfg, log, m, newSystemOps(), defaultReconcileInterval)
}

func newManager(cfg *config.Config, log *zap.Logger, m *metrics.Metrics, op systemOps, interval time.Duration) (Manager, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if log == nil {
		log = zap.NewNop()
	}
	if m == nil {
		return nil, errors.New("metrics is required")
	}
	mode := cfg.RoutingMode
	if mode == "" {
		mode = config.RoutingModeOff
	}
	mgr := &manager{
		cfg:            cfg,
		log:            log,
		metrics:        m,
		op:             op,
		reconcileEvery: interval,
		routingMode:    mode,
	}
	if mode == config.RoutingModeOff {
		mgr.ready.Store(true)
	}
	return mgr, nil
}

func (m *manager) Mode() config.RoutingMode {
	return m.routingMode
}

func (m *manager) Ready() bool {
	return m.ready.Load()
}

func (m *manager) Initialize(ctx context.Context) error {
	switch m.routingMode {
	case config.RoutingModeOff:
		m.ready.Store(true)
		return nil
	case config.RoutingModeManage:
		if _, err := m.ensureManaged(ctx, true); err != nil {
			m.ready.Store(false)
			return err
		}
		m.ready.Store(true)
		return nil
	case config.RoutingModeVerify:
		if err := m.verify(ctx); err != nil {
			m.ready.Store(false)
			m.log.Warn("routing verify check failed", zap.Error(err))
			return nil
		}
		m.ready.Store(true)
		return nil
	default:
		return fmt.Errorf("unsupported routing mode %q", m.routingMode)
	}
}

func (m *manager) Run(ctx context.Context) error {
	if m.routingMode == config.RoutingModeOff {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(m.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if m.routingMode == config.RoutingModeManage {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := m.cleanupManaged(shutdownCtx); err != nil {
					m.log.Warn("routing cleanup failed", zap.Error(err))
				}
				m.ready.Store(false)
			}
			return nil
		case <-ticker.C:
			switch m.routingMode {
			case config.RoutingModeManage:
				if _, err := m.ensureManaged(ctx, false); err != nil {
					m.ready.Store(false)
					m.log.Warn("routing reconcile failed", zap.Error(err))
					continue
				}
				m.ready.Store(true)
			case config.RoutingModeVerify:
				if err := m.verify(ctx); err != nil {
					m.ready.Store(false)
					m.log.Warn("routing verify check failed", zap.Error(err))
					continue
				}
				m.ready.Store(true)
			}
		}
	}
}

func (m *manager) cleanupManaged(ctx context.Context) error {
	for _, route := range buildTargets(m.cfg.EffectiveProtectedCIDRs()) {
		if err := m.op.DeleteRule(ctx, route.family, m.cfg.RoutingRulePriority, m.cfg.TailscaleIface, route.cidr, m.cfg.RoutingTableID); err != nil {
			return err
		}
		if err := m.op.DeleteRoute(ctx, route.family, m.cfg.RoutingTableID, route.cidr, m.cfg.TunName); err != nil {
			return err
		}
	}
	return nil
}

func (m *manager) ensureManaged(ctx context.Context, initial bool) (bool, error) {
	m.metrics.RoutingApplyAttempts.Inc()
	if err := m.checkInterfacesAndForwarding(); err != nil {
		m.metrics.RoutingApplyFailures.Inc()
		return false, err
	}
	changed := false
	for _, route := range buildTargets(m.cfg.EffectiveProtectedCIDRs()) {
		ruleExists, err := m.op.RuleExists(ctx, route.family, m.cfg.RoutingRulePriority, m.cfg.TailscaleIface, route.cidr, m.cfg.RoutingTableID)
		if err != nil {
			m.metrics.RoutingApplyFailures.Inc()
			return false, err
		}
		if !ruleExists {
			if err := m.op.AddRule(ctx, route.family, m.cfg.RoutingRulePriority, m.cfg.TailscaleIface, route.cidr, m.cfg.RoutingTableID); err != nil {
				m.metrics.RoutingApplyFailures.Inc()
				return false, err
			}
			changed = true
		}

		routeExists, err := m.op.RouteExists(ctx, route.family, m.cfg.RoutingTableID, route.cidr, m.cfg.TunName)
		if err != nil {
			m.metrics.RoutingApplyFailures.Inc()
			return false, err
		}
		if !routeExists {
			if err := m.op.AddRoute(ctx, route.family, m.cfg.RoutingTableID, route.cidr, m.cfg.TunName); err != nil {
				m.metrics.RoutingApplyFailures.Inc()
				return false, err
			}
			changed = true
		}
	}
	if changed && !initial {
		m.metrics.RoutingDriftRepairs.Inc()
	}
	return changed, nil
}

func (m *manager) verify(ctx context.Context) error {
	if err := m.checkInterfacesAndForwarding(); err != nil {
		return err
	}
	for _, route := range buildTargets(m.cfg.EffectiveProtectedCIDRs()) {
		ruleExists, err := m.op.RuleExists(ctx, route.family, m.cfg.RoutingRulePriority, m.cfg.TailscaleIface, route.cidr, m.cfg.RoutingTableID)
		if err != nil {
			return err
		}
		if !ruleExists {
			return fmt.Errorf("required routing rule missing for %s", route.cidr)
		}
		routeExists, err := m.op.RouteExists(ctx, route.family, m.cfg.RoutingTableID, route.cidr, m.cfg.TunName)
		if err != nil {
			return err
		}
		if !routeExists {
			return fmt.Errorf("required route missing for %s", route.cidr)
		}
	}
	return nil
}

func (m *manager) checkInterfacesAndForwarding() error {
	tunExists, err := m.op.InterfaceExists(m.cfg.TunName)
	if err != nil {
		return err
	}
	if !tunExists {
		return fmt.Errorf("interface %s not found", m.cfg.TunName)
	}
	if m.routingMode == config.RoutingModeOff {
		return nil
	}
	tailscaleExists, err := m.op.InterfaceExists(m.cfg.TailscaleIface)
	if err != nil {
		return err
	}
	if !tailscaleExists {
		return fmt.Errorf("interface %s not found", m.cfg.TailscaleIface)
	}
	v4Enabled, err := m.op.SysctlEnabled(ipv4ForwardingPath)
	if err != nil {
		return err
	}
	if !v4Enabled {
		return fmt.Errorf("%s must be enabled", ipv4ForwardingPath)
	}

	for _, route := range buildTargets(m.cfg.EffectiveProtectedCIDRs()) {
		if !route.isIPv6 {
			continue
		}
		v6Enabled, err := m.op.SysctlEnabled(ipv6ForwardingPath)
		if err != nil {
			return err
		}
		if !v6Enabled {
			return fmt.Errorf("%s must be enabled for ipv6 routes", ipv6ForwardingPath)
		}
		break
	}
	return nil
}

func buildTargets(cidrs []string) []targetRoute {
	targets := make([]targetRoute, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		t := targetRoute{cidr: ipNet.String(), family: "-4"}
		if ipNet.IP.To4() == nil {
			t.family = "-6"
			t.isIPv6 = true
		}
		targets = append(targets, t)
	}
	return targets
}
