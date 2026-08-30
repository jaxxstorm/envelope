package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	OptionValidationReasonStructural     = "structural"
	OptionValidationReasonCritical       = "critical"
	OptionValidationReasonSize           = "size"
	OptionValidationReasonAWSLength      = "aws_length"
	OptionValidationReasonAWSCardinality = "aws_cardinality"
	OptionValidationReasonAWSReserved    = "aws_reserved"

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

	InnerValidationReasonMalformed = "malformed"

	ReadinessComponentReceiver   = "receiver"
	ReadinessComponentValidation = "validation"
	ReadinessComponentSender     = "sender"
	ReadinessStateReady          = "ready"
	ReadinessStateNotReady       = "not_ready"
	SenderReinitializationOK     = "success"
	SenderReinitializationFailed = "failure"

	MTUDropFamilyIPv4       = "ipv4"
	MTUDropFamilyIPv6       = "ipv6"
	MTUDropFamilyUnknown    = "unknown"
	MTUDropDirectionIngress = "ingress"
)

type Metrics struct {
	GeneveRxPackets               prometheus.Counter
	GeneveRxBytes                 prometheus.Counter
	GeneveTxPackets               prometheus.Counter
	GeneveTxBytes                 prometheus.Counter
	Drops                         prometheus.Counter
	GeneveOptionsValidationErrors *prometheus.CounterVec
	GWLBProfileRejections         *prometheus.CounterVec
	GWLBReceiveDrops              *prometheus.CounterVec
	GWLBReturnBuildFailures       prometheus.Counter
	GWLBSendFailures              prometheus.Counter
	GWLBInnerValidationFailures   *prometheus.CounterVec
	TargetReady                   prometheus.Gauge
	TargetComponentReady          *prometheus.GaugeVec
	TargetReadinessTransitions    *prometheus.CounterVec
	SenderReinitializations       *prometheus.CounterVec
	MTUDrops                      *prometheus.CounterVec
}

// NewTarget registers the production packet-return target metrics.
func NewTarget(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	m := &Metrics{
		GeneveRxPackets: prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_packets", Help: "Valid AWS GENEVE packets received"}),
		GeneveRxBytes:   prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_rx_bytes", Help: "Valid AWS GENEVE bytes received"}),
		GeneveTxPackets: prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_packets", Help: "Packet-scoped AWS GENEVE returns sent"}),
		GeneveTxBytes:   prometheus.NewCounter(prometheus.CounterOpts{Name: "geneve_tx_bytes", Help: "Packet-scoped AWS GENEVE return bytes sent"}),
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
		GWLBReturnBuildFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gwlb_return_build_failures_total",
			Help: "Validated packet returns dropped because the GENEVE return could not be built",
		}),
		GWLBSendFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "gwlb_send_failures_total", Help: "AWS-compliant packet send failures"}),
		GWLBInnerValidationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_inner_validation_failures_total",
			Help: "Inner IP framing and declared-length validation failures by reason",
		}, []string{"reason"}),
		TargetReady: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gwlb_target_ready",
			Help: "Whether the packet-turnaround target is ready",
		}),
		TargetComponentReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gwlb_target_component_ready",
			Help: "Whether a required packet-turnaround component is initialized and ready",
		}, []string{"component"}),
		TargetReadinessTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_target_readiness_transitions_total",
			Help: "Packet-turnaround component readiness transitions",
		}, []string{"component", "state"}),
		SenderReinitializations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_sender_reinitializations_total",
			Help: "Raw packet sender reinitialization attempts by result",
		}, []string{"result"}),
		MTUDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gwlb_mtu_drops_total",
			Help: "Oversized inner packets dropped by IP family and datapath direction",
		}, []string{"family", "direction"}),
	}
	reg.MustRegister(
		m.GeneveRxPackets,
		m.GeneveRxBytes,
		m.GeneveTxPackets,
		m.GeneveTxBytes,
		m.Drops,
		m.GeneveOptionsValidationErrors,
		m.GWLBProfileRejections,
		m.GWLBReceiveDrops,
		m.GWLBReturnBuildFailures,
		m.GWLBSendFailures,
		m.GWLBInnerValidationFailures,
		m.TargetReady,
		m.TargetComponentReady,
		m.TargetReadinessTransitions,
		m.SenderReinitializations,
		m.MTUDrops,
	)
	for _, reason := range []string{
		OptionValidationReasonStructural,
		OptionValidationReasonCritical,
		OptionValidationReasonSize,
		OptionValidationReasonAWSLength,
		OptionValidationReasonAWSCardinality,
		OptionValidationReasonAWSReserved,
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
	m.GWLBInnerValidationFailures.WithLabelValues(InnerValidationReasonMalformed)
	m.TargetReady.Set(0)
	for _, component := range []string{
		ReadinessComponentReceiver,
		ReadinessComponentValidation,
		ReadinessComponentSender,
	} {
		m.TargetComponentReady.WithLabelValues(component).Set(0)
		m.TargetReadinessTransitions.WithLabelValues(component, ReadinessStateReady)
		m.TargetReadinessTransitions.WithLabelValues(component, ReadinessStateNotReady)
	}
	m.SenderReinitializations.WithLabelValues(SenderReinitializationOK)
	m.SenderReinitializations.WithLabelValues(SenderReinitializationFailed)
	for _, family := range []string{MTUDropFamilyIPv4, MTUDropFamilyIPv6, MTUDropFamilyUnknown} {
		m.MTUDrops.WithLabelValues(family, MTUDropDirectionIngress)
	}
	return m
}
