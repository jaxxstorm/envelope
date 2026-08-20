package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/datapath"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/jaxxstorm/envelope/internal/routing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Runner interface {
	Run(context.Context) error
	HealthHandler(http.ResponseWriter, *http.Request)
	Ready() bool
	HealthReason() string
	Close()
}

type runnerFactory func(*config.Config, *zap.Logger, *metrics.Metrics) (Runner, error)
type routingFactory func(*config.Config, *zap.Logger, *metrics.Metrics) (routing.Manager, error)

func Run(ctx context.Context, cfg *config.Config, log *zap.Logger) error {
	return run(ctx, cfg, log, newDatapathRunner, newRoutingManager)
}

func run(ctx context.Context, cfg *config.Config, log *zap.Logger, factory runnerFactory, newRouting routingFactory) error {
	logStartup(cfg, log)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	dp, err := factory(cfg, log, m)
	if err != nil {
		return err
	}
	defer dp.Close()

	routeMgr, err := newRouting(cfg, log, m)
	if err != nil {
		return err
	}
	log.Info("interface ownership model",
		zap.String("envelope_tun_iface", cfg.TunName),
		zap.String("tailscale_iface", cfg.TailscaleIface),
		zap.String("routing_mode", string(routeMgr.Mode())),
	)
	if err := routeMgr.Initialize(ctx); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", newHealthHandler(dp, routeMgr, log))
	mux.HandleFunc("/debug/routing", newRoutingStatusHandler(routeMgr))

	srv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := dp.Run(ctx); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		return routeMgr.Run(ctx)
	})
	g.Go(func() error {
		err := srv.ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics server: %w", err)
	})

	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	})

	return g.Wait()
}

func newRoutingStatusHandler(routeMgr routing.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(routeMgr.Status()); err != nil {
			http.Error(w, "encode routing status", http.StatusInternalServerError)
		}
	}
}

func logStartup(cfg *config.Config, log *zap.Logger) {
	log.Info("starting envelope",
		zap.String("udp_bind", cfg.UDPBind),
		zap.String("tun_name", cfg.TunName),
		zap.Int("tun_mtu", cfg.TunMTU),
		zap.String("tailscale_iface", cfg.TailscaleIface),
		zap.String("underlay_interface", cfg.UnderlayIface),
		zap.String("routing_mode", string(cfg.RoutingMode)),
		zap.Strings("gwlb_return_cidrs", cfg.EffectiveGWLBReturnCIDRs()),
		zap.Strings("local_delivery_cidrs", cfg.EffectiveLocalDeliveryCIDRs()),
		zap.Strings("remote_tailnet_cidrs", cfg.EffectiveRemoteTailnetCIDRs()),
		zap.Int("routing_table_id", cfg.RoutingTableID),
		zap.Int("routing_rule_priority", cfg.RoutingRulePriority),
		zap.String("metrics_addr", cfg.MetricsAddr),
		zap.Any("vni", cfg.VNI),
		zap.Int("flow_capacity", cfg.FlowCapacity),
		zap.Duration("tcp_flow_timeout", cfg.TCPFlowTimeout),
		zap.Duration("udp_flow_timeout", cfg.UDPFlowTimeout),
		zap.Duration("other_flow_timeout", cfg.OtherFlowTimeout),
		zap.Int("persistent_error_threshold", cfg.PersistentErrorThreshold),
	)
}

type datapathRunner struct {
	*datapath.Datapath
}

func newDatapathRunner(cfg *config.Config, log *zap.Logger, m *metrics.Metrics) (Runner, error) {
	dp, err := datapath.New(cfg, log, m)
	if err != nil {
		return nil, err
	}
	return &datapathRunner{Datapath: dp}, nil
}

func newRoutingManager(cfg *config.Config, log *zap.Logger, m *metrics.Metrics) (routing.Manager, error) {
	return routing.New(cfg, log, m)
}

func newHealthHandler(dp Runner, routeMgr routing.Manager, log *zap.Logger) http.HandlerFunc {
	if log == nil {
		log = zap.NewNop()
	}
	debug := log.Core().Enabled(zap.DebugLevel)
	return func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		body := "ok"
		reason := "ok"
		if !dp.Ready() {
			status = http.StatusServiceUnavailable
			reason = dp.HealthReason()
			body = "datapath not ready: " + reason
		} else if routeMgr.Mode() != config.RoutingModeOff && !routeMgr.Ready() {
			status = http.StatusServiceUnavailable
			reason = routeMgr.HealthReason()
			body = "routing not ready: " + reason
		}

		if debug {
			ua := r.UserAgent()
			log.Debug("healthz request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", ua),
				zap.Bool("is_gwlb_healthcheck", strings.Contains(strings.ToLower(ua), "elb-healthchecker")),
				zap.String("routing_mode", string(routeMgr.Mode())),
				zap.Int("status", status),
				zap.String("reason", reason),
			)
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}
