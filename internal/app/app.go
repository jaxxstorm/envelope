package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/datapath"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Runner interface {
	Run(context.Context) error
	Ready() bool
	HealthReason() string
	Close()
}

type runnerFactory func(*config.Config, *zap.Logger, *metrics.Metrics) (Runner, error)

type serverShutdowner interface {
	Shutdown(context.Context) error
}

func Run(ctx context.Context, cfg *config.Config, log *zap.Logger) error {
	return run(ctx, cfg, log, newDatapathRunner)
}

func run(ctx context.Context, cfg *config.Config, log *zap.Logger, factory runnerFactory) error {
	logStartup(cfg, log)

	reg := prometheus.NewRegistry()
	m := metrics.NewTarget(reg)

	dp, err := factory(cfg, log, m)
	if err != nil {
		return err
	}
	var closeOnce sync.Once
	closeRunner := func() {
		closeOnce.Do(dp.Close)
	}
	defer closeRunner()

	srv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           newTargetHandler(dp, reg, log),
		ReadHeaderTimeout: 5 * time.Second,
	}

	g, groupCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := dp.Run(groupCtx); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		err := srv.ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics server: %w", err)
	})

	g.Go(func() error {
		<-groupCtx.Done()
		shutdownTarget(closeRunner, srv)
		return nil
	})

	return g.Wait()
}

func shutdownTarget(closeRunner func(), srv serverShutdowner) {
	closeRunner()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func newTargetHandler(dp Runner, reg *prometheus.Registry, log *zap.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", newHealthHandler(dp, log))
	return mux
}

func logStartup(cfg *config.Config, log *zap.Logger) {
	log.Info("starting Envelope GWLB packet-return target",
		zap.Int("config_version", cfg.ConfigVersion),
		zap.String("mode", cfg.Mode),
		zap.String("udp_bind", cfg.UDPBind),
		zap.Int("max_inner_packet_size", cfg.MaxInnerPacketSize),
		zap.String("metrics_addr", cfg.MetricsAddr),
		zap.Any("vni", cfg.VNI),
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

func newHealthHandler(dp Runner, log *zap.Logger) http.HandlerFunc {
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
			body = "packet return not ready: " + reason
		}

		if debug {
			ua := r.UserAgent()
			log.Debug("healthz request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", ua),
				zap.Bool("is_gwlb_healthcheck", strings.Contains(strings.ToLower(ua), "elb-healthchecker")),
				zap.Int("status", status),
				zap.String("reason", reason),
			)
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}
