package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HealthProvider supplies process liveness and fail-closed readiness without
// exposing a mutation surface.
type HealthProvider interface {
	Healthy() bool
	Readiness() (bool, string)
}

// NewHandler exposes only private operational endpoints from gatherer.
func NewHandler(gatherer prometheus.Gatherer, health HealthProvider) (http.Handler, error) {
	if gatherer == nil {
		return nil, errors.New("controller metrics: gatherer is nil")
	}
	if health == nil {
		return nil, errors.New("controller metrics: health provider is nil")
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError}))
	mux.HandleFunc("/healthz", statusHandler(func() (bool, string) {
		return health.Healthy(), "not live"
	}))
	mux.HandleFunc("/readyz", statusHandler(health.Readiness))
	return mux, nil
}

func statusHandler(status func() (bool, string)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ok, reason := status()
		code := http.StatusOK
		body := "ok\n"
		if !ok {
			code = http.StatusServiceUnavailable
			if reason == "" {
				reason = "unavailable"
			}
			body = reason + "\n"
		}
		writer.WriteHeader(code)
		if request.Method != http.MethodHead {
			_, _ = writer.Write([]byte(body))
		}
	}
}
