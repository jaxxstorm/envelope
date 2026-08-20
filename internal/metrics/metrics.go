package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	OptionValidationReasonStructural     = "structural"
	OptionValidationReasonCritical       = "critical"
	OptionValidationReasonSize           = "size"
	OptionValidationReasonAWSLength      = "aws_length"
	OptionValidationReasonAWSCardinality = "aws_cardinality"

	ProfileReasonDecode         = "decode"
	ProfileReasonOuterIPv4      = "outer_ipv4"
	ProfileReasonListener       = "listener"
	ProfileReasonVNI            = "vni"
	ProfileReasonOAM            = "oam"
	ProfileReasonProtocol       = "protocol"
	ProfileReasonOptionReserved = "option_reserved"
	ProfileReasonOptions        = "options"

	ReceiveDropReasonDatagramTruncated = "datagram_truncated"
	ReceiveDropReasonControlTruncated  = "control_truncated"
	ReceiveDropReasonPacketInfo        = "packet_info"

	UnsupportedReasonMalformed          = "malformed"
	UnsupportedReasonIPv4Fragment       = "ipv4_fragment"
	UnsupportedReasonIPv6Fragment       = "ipv6_fragment"
	UnsupportedReasonIPv6Extension      = "ipv6_extension"
	UnsupportedReasonTransportTruncated = "transport_truncated"

	LivenessComponentReceive  = "receive"
	LivenessComponentTunRead  = "tun_read"
	LivenessComponentTunWrite = "tun_write"
	LivenessComponentSend     = "send"

	RoutingFailureReasonInterface        = "interface"
	RoutingFailureReasonBackend          = "backend"
	RoutingFailureReasonRouteUnapproved  = "route_unapproved"
	RoutingFailureReasonRouteUnavailable = "route_unavailable"
	RoutingFailureReasonRouteUnaccepted  = "route_unaccepted"
	RoutingFailureReasonRouteWithdrawn   = "route_withdrawn"
	RoutingFailureReasonReturnRoute      = "return_route"
	RoutingFailureReasonDeliveryRoute    = "delivery_route"
	RoutingFailureReasonRemoteRoute      = "remote_route"
	RoutingFailureReasonSysctl           = "sysctl"
	RoutingFailureReasonForwarding       = RoutingFailureReasonSysctl
	RoutingFailureReasonRPFilter         = "rp_filter"
	RoutingFailureReasonFirewall         = "firewall"
	RoutingFailureReasonMSS              = "mss"
	RoutingFailureReasonApply            = "apply"
	RoutingFailureReasonOwnership        = "ownership"
	RoutingFailureReasonDrift            = "drift"
	RoutingOwnershipCreated              = "created"
	RoutingOwnershipPreserved            = "preserved"
	RoutingOwnershipRemoved              = "removed"
	RoutingOwnershipRolledBack           = "rolled_back"
	RoutingOwnershipCleanupFailure       = "cleanup_failure"
	MTUDropFamilyIPv4                    = "ipv4"
	MTUDropFamilyIPv6                    = "ipv6"
	MTUDropFamilyUnknown                 = "unknown"
	MTUDropDirectionIngress              = "ingress"
	MTUDropDirectionEgress               = "egress"
)

type Metrics struct {
	GeneveRxPackets               prometheus.Counter
	GeneveRxBytes                 prometheus.Counter
	GeneveTxPackets               prometheus.Counter
	GeneveTxBytes                 prometheus.Counter
	DecapErrors                   prometheus.Counter
	EncapErrors                   prometheus.Counter
	TunRxPackets                  prometheus.Counter
	TunTxPackets                  prometheus.Counter
	Drops                         prometheus.Counter
	GeneveOptionsValidationErrors *prometheus.CounterVec
	GWLBProfileRejections         *prometheus.CounterVec
	GWLBReceiveDrops              *prometheus.CounterVec
	GWLBSendFailures              prometheus.Counter
	GWLBMissingContexts           prometheus.Counter
	GWLBConflictedContexts        prometheus.Counter
	GWLBPossibleLoops             prometheus.Counter
	GWLBUnsupportedInner          *prometheus.CounterVec
	GWLBContextExpirations        prometheus.Counter
	GWLBContextEvictions          prometheus.Counter
	GWLBContextCollisions         prometheus.Counter
	DatapathComponentHealthy      *prometheus.GaugeVec
	DatapathLivenessTransitions   *prometheus.CounterVec
	MTUDrops                      *prometheus.CounterVec
	RoutingApplyAttempts          prometheus.Counter
	RoutingApplyFailures          prometheus.Counter
	RoutingDriftRepairs           prometheus.Counter
	RoutingValidationFailures     *prometheus.CounterVec
	RoutingOwnershipDecisions     *prometheus.CounterVec
	RoutingReady                  prometheus.Gauge
}

func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	m := &Metrics{
		GeneveRxPackets: prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_packets", Help: "GENEVE packets received"}),
		GeneveRxBytes:   prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_bytes", Help: "GENEVE bytes received"}),
		GeneveTxPackets: prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_packets", Help: "GENEVE packets sent"}),
		GeneveTxBytes:   prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_bytes", Help: "GENEVE bytes sent"}),
		DecapErrors:     prometheus.NewCounter(prometheus.CounterOpts{Name: "decap_errors", Help: "GENEVE decapsulation errors"}),
		EncapErrors:     prometheus.NewCounter(prometheus.CounterOpts{Name: "encap_errors", Help: "GENEVE encapsulation errors"}),
		TunRxPackets:    prometheus.NewCounter(prometheus.CounterOpts{Name: "tun_rx_packets", Help: "TUN packets read"}),
		TunTxPackets:    prometheus.NewCounter(prometheus.CounterOpts{Name: "tun_tx_packets", Help: "TUN packets written"}),
		Drops:           prometheus.NewCounter(prometheus.CounterOpts{Name: "drops", Help: "Packets dropped"}),
		GeneveOptionsValidationErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "geneve_options_validation_errors",
			Help: "GENEVE option validation errors by rejection reason",
		}, []string{"reason"}),
		GWLBProfileRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_profile_rejections_total",
			Help: "AWS GWLB profile rejections by reason",
		}, []string{"reason"}),
		GWLBReceiveDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_receive_drops_total",
			Help: "Packets dropped at the receive boundary by reason",
		}, []string{"reason"}),
		GWLBSendFailures:       prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_send_failures_total", Help: "AWS-compliant packet send failures"}),
		GWLBMissingContexts:    prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_missing_contexts_total", Help: "Return packets dropped without a live context"}),
		GWLBConflictedContexts: prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_conflicted_contexts_total", Help: "Return packets dropped for conflicted contexts"}),
		GWLBPossibleLoops:      prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_possible_loops_total", Help: "Forward-orientation TUN packets dropped as possible loops"}),
		GWLBUnsupportedInner: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_unsupported_inner_total",
			Help: "Unsupported inner packets by reason",
		}, []string{"reason"}),
		GWLBContextExpirations: prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_context_expirations_total", Help: "Expired GWLB return contexts"}),
		GWLBContextEvictions:   prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_context_evictions_total", Help: "Capacity-evicted GWLB return contexts"}),
		GWLBContextCollisions:  prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_context_collisions_total", Help: "Conflicting GWLB return identities observed"}),
		DatapathComponentHealthy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "datapath_component_healthy",
			Help: "Whether a persistent-error-tracked datapath component is healthy",
		}, []string{"component"}),
		DatapathLivenessTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "datapath_liveness_transitions_total",
			Help: "Datapath component liveness transitions",
		}, []string{"component", "state"}),
		MTUDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_mtu_drops_total",
			Help: "Oversized inner packets dropped by IP family and datapath direction",
		}, []string{"family", "direction"}),
		RoutingApplyAttempts: prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_apply_attempts", Help: "Routing apply attempts"}),
		RoutingApplyFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_apply_failures", Help: "Routing apply failures"}),
		RoutingDriftRepairs:  prometheus.NewCounter(prometheus.CounterOpts{Name: "routing_drift_repairs", Help: "Routing drift repairs"}),
		RoutingValidationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "routing_validation_failures_total",
			Help: "Routing readiness validation failures by bounded reason",
		}, []string{"reason"}),
		RoutingOwnershipDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "routing_ownership_decisions_total",
			Help: "Managed routing ownership decisions",
		}, []string{"decision"}),
		RoutingReady: prometheus.NewGauge(prometheus.GaugeOpts{Name: "routing_ready", Help: "Whether routing integration is currently ready"}),
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
		m.GeneveOptionsValidationErrors,
		m.GWLBProfileRejections,
		m.GWLBReceiveDrops,
		m.GWLBSendFailures,
		m.GWLBMissingContexts,
		m.GWLBConflictedContexts,
		m.GWLBPossibleLoops,
		m.GWLBUnsupportedInner,
		m.GWLBContextExpirations,
		m.GWLBContextEvictions,
		m.GWLBContextCollisions,
		m.DatapathComponentHealthy,
		m.DatapathLivenessTransitions,
		m.MTUDrops,
		m.RoutingApplyAttempts,
		m.RoutingApplyFailures,
		m.RoutingDriftRepairs,
		m.RoutingValidationFailures,
		m.RoutingOwnershipDecisions,
		m.RoutingReady,
	)
	for _, reason := range []string{
		OptionValidationReasonStructural,
		OptionValidationReasonCritical,
		OptionValidationReasonSize,
		OptionValidationReasonAWSLength,
		OptionValidationReasonAWSCardinality,
	} {
		m.GeneveOptionsValidationErrors.WithLabelValues(reason)
	}
	for _, reason := range []string{
		ProfileReasonDecode,
		ProfileReasonOuterIPv4,
		ProfileReasonListener,
		ProfileReasonVNI,
		ProfileReasonOAM,
		ProfileReasonProtocol,
		ProfileReasonOptionReserved,
		ProfileReasonOptions,
	} {
		m.GWLBProfileRejections.WithLabelValues(reason)
	}
	for _, reason := range []string{
		ReceiveDropReasonDatagramTruncated,
		ReceiveDropReasonControlTruncated,
		ReceiveDropReasonPacketInfo,
	} {
		m.GWLBReceiveDrops.WithLabelValues(reason)
	}
	for _, reason := range []string{
		UnsupportedReasonMalformed,
		UnsupportedReasonIPv4Fragment,
		UnsupportedReasonIPv6Fragment,
		UnsupportedReasonIPv6Extension,
		UnsupportedReasonTransportTruncated,
	} {
		m.GWLBUnsupportedInner.WithLabelValues(reason)
	}
	for _, component := range []string{
		LivenessComponentReceive,
		LivenessComponentTunRead,
		LivenessComponentTunWrite,
		LivenessComponentSend,
	} {
		m.DatapathComponentHealthy.WithLabelValues(component).Set(1)
		m.DatapathLivenessTransitions.WithLabelValues(component, "healthy")
		m.DatapathLivenessTransitions.WithLabelValues(component, "unhealthy")
	}
	for _, family := range []string{MTUDropFamilyIPv4, MTUDropFamilyIPv6, MTUDropFamilyUnknown} {
		for _, direction := range []string{MTUDropDirectionIngress, MTUDropDirectionEgress} {
			m.MTUDrops.WithLabelValues(family, direction)
		}
	}
	for _, reason := range []string{
		RoutingFailureReasonInterface,
		RoutingFailureReasonBackend,
		RoutingFailureReasonRouteUnapproved,
		RoutingFailureReasonRouteUnavailable,
		RoutingFailureReasonRouteUnaccepted,
		RoutingFailureReasonRouteWithdrawn,
		RoutingFailureReasonReturnRoute,
		RoutingFailureReasonDeliveryRoute,
		RoutingFailureReasonRemoteRoute,
		RoutingFailureReasonSysctl,
		RoutingFailureReasonRPFilter,
		RoutingFailureReasonFirewall,
		RoutingFailureReasonMSS,
		RoutingFailureReasonApply,
		RoutingFailureReasonOwnership,
		RoutingFailureReasonDrift,
	} {
		m.RoutingValidationFailures.WithLabelValues(reason)
	}
	for _, decision := range []string{
		RoutingOwnershipCreated,
		RoutingOwnershipPreserved,
		RoutingOwnershipRemoved,
		RoutingOwnershipRolledBack,
		RoutingOwnershipCleanupFailure,
	} {
		m.RoutingOwnershipDecisions.WithLabelValues(decision)
	}
	return m
}
