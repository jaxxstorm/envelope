package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	GeneveRxPackets      prometheus.Counter
	GeneveRxBytes        prometheus.Counter
	GeneveTxPackets      prometheus.Counter
	GeneveTxBytes        prometheus.Counter
	DecapErrors          prometheus.Counter
	EncapErrors          prometheus.Counter
	TunRxPackets         prometheus.Counter
	TunTxPackets         prometheus.Counter
	Drops                prometheus.Counter
	RoutingApplyAttempts prometheus.Counter
	RoutingApplyFailures prometheus.Counter
	RoutingDriftRepairs  prometheus.Counter
}

func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	m := &Metrics{
		GeneveRxPackets:      prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_packets", Help: "GENEVE packets received"}),
		GeneveRxBytes:        prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_bytes", Help: "GENEVE bytes received"}),
		GeneveTxPackets:      prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_packets", Help: "GENEVE packets sent"}),
		GeneveTxBytes:        prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_bytes", Help: "GENEVE bytes sent"}),
		DecapErrors:          prometheus.NewCounter(prometheus.CounterOpts{Name: "decap_errors", Help: "GENEVE decapsulation errors"}),
		EncapErrors:          prometheus.NewCounter(prometheus.CounterOpts{Name: "encap_errors", Help: "GENEVE encapsulation errors"}),
		TunRxPackets:         prometheus.NewCounter(prometheus.CounterOpts{Name: "tun_rx_packets", Help: "TUN packets read"}),
		TunTxPackets:         prometheus.NewCounter(prometheus.CounterOpts{Name: "tun_tx_packets", Help: "TUN packets written"}),
		Drops:                prometheus.NewCounter(prometheus.CounterOpts{Name: "drops", Help: "Packets dropped"}),
		RoutingApplyAttempts: prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_apply_attempts", Help: "Routing apply attempts"}),
		RoutingApplyFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_apply_failures", Help: "Routing apply failures"}),
		RoutingDriftRepairs:  prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_drift_repairs", Help: "Routing drift repairs"}),
	}
	reg.MustRegister(
		m.GeneveRxPackets,
		m.GeneveRxBytes,
		m.GeneveTxPackets,
		m.GeneveTxBytes,
		m.DecapErrors,
		m.EncapErrors,
		m.TunRxPackets,
		m.TunTxPackets,
		m.Drops,
		m.RoutingApplyAttempts,
		m.RoutingApplyFailures,
		m.RoutingDriftRepairs,
	)
	return m
}
