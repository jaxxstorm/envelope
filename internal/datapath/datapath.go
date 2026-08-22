package datapath

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaxxstorm/envelope/internal/bufferpool"
	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/jaxxstorm/envelope/internal/tun"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type tlvLogEntry struct {
	Class  uint16 `json:"class"`
	Type   uint8  `json:"type"`
	Length int    `json:"length"`
	Value  string `json:"value"`
}

const (
	maxLoggedTLVs             = 16
	maxLoggedOptionValueBytes = 16
	redactedOptionValue       = "[REDACTED]"
)

var ErrDatapathRunning = errors.New("datapath is already running")

var (
	ErrReceiveLoopTerminated = errors.New("receive loop terminated unexpectedly")
	ErrTunLoopTerminated     = errors.New("TUN loop terminated unexpectedly")
)

type Datapath struct {
	cfg     *config.Config
	log     *zap.Logger
	debug   bool
	metrics *metrics.Metrics

	receiver PacketReceiver
	tun      TunDevice

	udpPool *bufferpool.Pool
	tunPool *bufferpool.Pool

	once *logOnce
	live *livenessTracker

	initialized atomic.Bool
	closing     atomic.Bool
	closeOnce   sync.Once
	runMu       sync.Mutex
	runCancel   context.CancelFunc
	running     bool
}

func New(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics) (*Datapath, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate datapath configuration: %w", err)
	}
	receiver, err := newPacketReceiver(cfg.UDPBind)
	if err != nil {
		return nil, err
	}
	tunDev, err := tun.Open(cfg.TunName, cfg.TunMTU)
	if err != nil {
		_ = receiver.Close()
		return nil, err
	}
	return newDatapath(cfg, log, metricSet, receiver, tunDev), nil
}

func NewWithDevices(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics, receiver PacketReceiver, tunDev TunDevice) *Datapath {
	return newDatapath(cfg, log, metricSet, receiver, tunDev)
}

func newDatapath(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics, receiver PacketReceiver, tunDev TunDevice) *Datapath {
	if log == nil {
		log = zap.NewNop()
	}
	dp := &Datapath{
		cfg:      cfg,
		log:      log,
		debug:    log.Core().Enabled(zap.DebugLevel),
		metrics:  metricSet,
		receiver: receiver,
		tun:      tunDev,
		udpPool:  bufferpool.New(cfg.MaxUDPReceiveSize()),
		tunPool:  bufferpool.New(cfg.TunMTU + 1),
		once:     newLogOnce(),
		live:     newLivenessTracker(cfg.PersistentErrorThreshold, metricSet),
	}
	dp.initialized.Store(true)
	return dp
}

func (d *Datapath) Close() {
	d.closing.Store(true)
	d.initialized.Store(false)
	d.runMu.Lock()
	if d.runCancel != nil {
		d.runCancel()
	}
	d.runMu.Unlock()
	d.closeDevices()
}

func (d *Datapath) closeDevices() {
	d.closeOnce.Do(func() {
		if d.receiver != nil {
			_ = d.receiver.Close()
		}
		if d.tun != nil {
			_ = d.tun.Close()
		}
	})
}

func (d *Datapath) Ready() bool {
	return d.initialized.Load() && d.live != nil && d.live.Healthy()
}

func (d *Datapath) HealthReason() string {
	if !d.initialized.Load() || d.live == nil {
		return "not_initialized"
	}
	return d.live.Reason()
}

func (d *Datapath) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	if !d.Ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "not ready: %s", d.HealthReason())
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (d *Datapath) Run(ctx context.Context) error {
	d.runMu.Lock()
	if !d.initialized.Load() {
		d.runMu.Unlock()
		return nil
	}
	if d.running {
		d.runMu.Unlock()
		return ErrDatapathRunning
	}
	runCtx, cancel := context.WithCancel(ctx)
	d.runCancel = cancel
	d.running = true
	d.runMu.Unlock()

	g, groupCtx := errgroup.WithContext(runCtx)
	g.Go(func() error {
		return d.runLoop(groupCtx, metrics.LivenessComponentReceive, ErrReceiveLoopTerminated, d.ingressLoop)
	})
	g.Go(func() error {
		return d.runLoop(groupCtx, "", ErrTunLoopTerminated, d.egressLoop)
	})
	closed := make(chan struct{})
	go func() {
		<-groupCtx.Done()
		d.closeDevices()
		close(closed)
	}()
	err := g.Wait()
	cancel()
	<-closed
	d.runMu.Lock()
	d.runCancel = nil
	d.running = false
	d.runMu.Unlock()
	return err
}

func (d *Datapath) runLoop(ctx context.Context, component string, termination error, loop func(context.Context) error) error {
	err := loop(ctx)
	if ctx.Err() != nil || d.closing.Load() {
		return nil
	}
	if component != "" {
		d.live.Fatal(component)
	}
	if err == nil {
		return termination
	}
	return fmt.Errorf("%w: %v", termination, err)
}

func (d *Datapath) ingressLoop(ctx context.Context) error {
	for {
		if err := d.receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				if ctx.Err() != nil || d.closing.Load() {
					return nil
				}
				return fmt.Errorf("%w: %v", ErrReceiveLoopTerminated, err)
			}
			d.live.Failure(metrics.LivenessComponentReceive)
			if d.once.ShouldLog("receive_deadline") {
				d.log.Warn("packet receive deadline failed", zap.Error(err))
			}
			continue
		}
		buf := d.udpPool.Get()
		n, metadata, err := d.receiver.ReadPacket(buf)
		if err != nil {
			d.udpPool.Put(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				d.live.Success(metrics.LivenessComponentReceive)
				continue
			}
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				if ctx.Err() != nil || d.closing.Load() {
					return nil
				}
				return fmt.Errorf("%w: %v", ErrReceiveLoopTerminated, err)
			}
			if errors.Is(err, ErrPacketTruncated) {
				d.live.Success(metrics.LivenessComponentReceive)
				d.recordReceiveDrop(metrics.ReceiveDropReasonDatagramTruncated)
				continue
			}
			if errors.Is(err, ErrControlTruncated) {
				d.recordReceiveDrop(metrics.ReceiveDropReasonControlTruncated)
			} else if errors.Is(err, ErrPacketInfoMissing) {
				d.recordReceiveDrop(metrics.ReceiveDropReasonPacketInfo)
			}
			d.live.Failure(metrics.LivenessComponentReceive)
			if d.once.ShouldLog("receive") {
				d.log.Warn("packet receive failed", zap.Error(err))
			}
			continue
		}
		d.live.Success(metrics.LivenessComponentReceive)
		d.processIngress(buf[:n], metadata)
		d.udpPool.Put(buf)
	}
}

func (d *Datapath) processIngress(packet []byte, metadata PacketMetadata) {
	d.metrics.GeneveRxPackets.Inc()
	d.metrics.GeneveRxBytes.Add(float64(len(packet)))
	if !validPacketMetadata(metadata) {
		d.rejectProfile(metrics.ProfileReasonOuterIPv4, ErrInvalidOuterPacket, "outer")
		return
	}
	if metadata.Local.Port() != awsGenevePort {
		d.rejectProfile(metrics.ProfileReasonListener, ErrInvalidOuterPacket, "listener")
		return
	}

	header, payload, err := geneve.Decode(packet)
	if err != nil {
		if errors.Is(err, geneve.ErrOptionsStructure) {
			d.metrics.GeneveOptionsValidationErrors.WithLabelValues(metrics.OptionValidationReasonStructural).Inc()
		}
		d.rejectProfile(metrics.ProfileReasonDecode, err, "decode")
		return
	}
	_, err = geneve.ValidateAWSProfile(header, payload, d.cfg.EffectiveGeneveOptionsMax())
	if err != nil {
		if isOptionValidationError(err) {
			d.metrics.GeneveOptionsValidationErrors.WithLabelValues(optionValidationReason(err)).Inc()
		}
		d.rejectProfile(profileValidationReason(err), err, "profile")
		return
	}
	if len(payload) > d.cfg.TunMTU {
		d.metrics.Drops.Inc()
		d.metrics.MTUDrops.WithLabelValues(mtuDropFamily(payload), metrics.MTUDropDirectionIngress).Inc()
		if d.once.ShouldLog("mtu_ingress") {
			d.log.Warn("ingress packet exceeds MTU", zap.Int("size", len(payload)), zap.Int("mtu", d.cfg.TunMTU))
		}
		return
	}
	if err := validateInnerPacket(payload); err != nil {
		d.rejectUnsupported(err, true)
		return
	}
	if d.cfg.GeneveTLVParse && d.cfg.HasTLVAllowlist() && len(header.Options) > 0 {
		d.logAllowedTLVs(header.Options)
	}

	if err := writeTunPacket(d.tun, payload); err != nil {
		d.live.Failure(metrics.LivenessComponentTunWrite)
		d.metrics.DecapErrors.Inc()
		d.metrics.Drops.Inc()
		if d.once.ShouldLog("tun_write") {
			d.log.Warn("tun write failed", zap.Error(err))
		}
		return
	}
	d.live.Success(metrics.LivenessComponentTunWrite)
	d.metrics.TunTxPackets.Inc()
	if d.debug {
		fields := []zap.Field{
			zap.String("direction", "gwlb_to_tun"),
			zap.String("peer", metadata.Peer.String()),
			zap.String("local", metadata.Local.String()),
			zap.Int("ifindex", metadata.IfIndex),
			zap.Int("geneve_size", len(packet)),
			zap.Int("inner_size", len(payload)),
			zap.Int("options_len", len(header.Options)),
		}
		d.log.Debug("packet in", fields...)
	}
}

func (d *Datapath) egressLoop(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		buf, n, err := readTunPacket(d.tun, d.tunPool)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				if ctx.Err() != nil || d.closing.Load() {
					return nil
				}
				return fmt.Errorf("%w: %v", ErrTunLoopTerminated, err)
			}
			if d.once.ShouldLog("tun_read") {
				d.log.Warn("tun read failed", zap.Error(err))
			}
			continue
		}
		d.processEgress(buf[:n])
		d.tunPool.Put(buf)
	}
}

func (d *Datapath) processEgress(payload []byte) {
	d.metrics.TunRxPackets.Inc()
	d.metrics.SymmetricUnexpectedEgress.Inc()
	if d.once.ShouldLog("unexpected_tun_egress") {
		d.log.Warn("unexpected TUN egress dropped", zap.Int("inner_size", len(payload)))
	}
	d.metrics.Drops.Inc()
}

func mtuDropFamily(packet []byte) string {
	if len(packet) == 0 {
		return metrics.MTUDropFamilyUnknown
	}
	switch packet[0] >> 4 {
	case 4:
		return metrics.MTUDropFamilyIPv4
	case 6:
		return metrics.MTUDropFamilyIPv6
	default:
		return metrics.MTUDropFamilyUnknown
	}
}

func validPacketMetadata(metadata PacketMetadata) bool {
	return metadata.Peer.IsValid() && metadata.Local.IsValid() &&
		metadata.Peer.Addr().Unmap().Is4() && metadata.Local.Addr().Unmap().Is4() &&
		metadata.Peer.Port() != 0 && metadata.IfIndex > 0
}

func (d *Datapath) rejectProfile(reason string, err error, logKey string) {
	d.metrics.DecapErrors.Inc()
	d.metrics.Drops.Inc()
	d.metrics.GWLBProfileRejections.WithLabelValues(reason).Inc()
	if d.once.ShouldLog("profile_" + logKey + "_" + reason) {
		d.log.Warn("AWS GWLB profile rejected packet", zap.String("reason", reason), zap.Error(err))
	}
}

func (d *Datapath) rejectUnsupported(err error, ingress bool) {
	reason := unsupportedReason(err)
	d.metrics.GWLBUnsupportedInner.WithLabelValues(reason).Inc()
	d.metrics.Drops.Inc()
	if ingress {
		d.metrics.DecapErrors.Inc()
	}
}

func (d *Datapath) recordReceiveDrop(reason string) {
	d.metrics.DecapErrors.Inc()
	d.metrics.Drops.Inc()
	d.metrics.GWLBReceiveDrops.WithLabelValues(reason).Inc()
}

func (d *Datapath) logAllowedTLVs(options []byte) {
	entries := make([]tlvLogEntry, 0, maxLoggedTLVs)
	omitted := 0
	it := geneve.NewTLVIterator(options)
	for it.Next() {
		tlv := it.TLV()
		if !d.cfg.TLVAllowed(geneve.TLVKey{Class: tlv.Class, Type: tlv.Type}) {
			continue
		}
		if len(entries) == maxLoggedTLVs {
			omitted++
			continue
		}
		entries = append(entries, tlvLogEntry{
			Class:  tlv.Class,
			Type:   tlv.Type,
			Length: tlv.Length,
			Value:  loggedOptionValue(tlv),
		})
	}
	if len(entries) == 0 {
		return
	}
	d.log.Debug("geneve tlvs parsed",
		zap.Int("count", len(entries)),
		zap.Int("omitted", omitted),
		zap.Any("tlvs", entries),
	)
}

func loggedOptionValue(tlv geneve.TLV) string {
	if tlv.Class == geneve.AWSOptionClass {
		return redactedOptionValue
	}
	value := tlv.Data
	truncated := len(value) > maxLoggedOptionValueBytes
	if truncated {
		value = value[:maxLoggedOptionValueBytes]
	}
	encoded := hex.EncodeToString(value)
	if truncated {
		encoded += "..."
	}
	return encoded
}

func isOptionValidationError(err error) bool {
	return errors.Is(err, geneve.ErrOptionsStructure) ||
		errors.Is(err, geneve.ErrOptionsSize) ||
		errors.Is(err, geneve.ErrCriticalOptions) ||
		errors.Is(err, geneve.ErrAWSOptionLength) ||
		errors.Is(err, geneve.ErrAWSOptionCardinality) ||
		errors.Is(err, geneve.ErrAWSOptionReserved)
}

func optionValidationReason(err error) string {
	switch {
	case errors.Is(err, geneve.ErrCriticalOptions):
		return metrics.OptionValidationReasonCritical
	case errors.Is(err, geneve.ErrOptionsSize):
		return metrics.OptionValidationReasonSize
	case errors.Is(err, geneve.ErrAWSOptionLength):
		return metrics.OptionValidationReasonAWSLength
	case errors.Is(err, geneve.ErrAWSOptionCardinality):
		return metrics.OptionValidationReasonAWSCardinality
	default:
		return metrics.OptionValidationReasonStructural
	}
}

func profileValidationReason(err error) string {
	switch {
	case errors.Is(err, geneve.ErrAWSVNI):
		return metrics.ProfileReasonVNI
	case errors.Is(err, geneve.ErrAWSOAM):
		return metrics.ProfileReasonOAM
	case errors.Is(err, geneve.ErrProtocolMismatch), errors.Is(err, geneve.ErrUnknownProtocol):
		return metrics.ProfileReasonProtocol
	case errors.Is(err, geneve.ErrAWSOptionReserved):
		return metrics.ProfileReasonOptionReserved
	default:
		return metrics.ProfileReasonOptions
	}
}

func unsupportedReason(err error) string {
	switch {
	case errors.Is(err, ErrIPv4Fragment):
		return metrics.UnsupportedReasonIPv4Fragment
	case errors.Is(err, ErrIPv6Fragment):
		return metrics.UnsupportedReasonIPv6Fragment
	case errors.Is(err, ErrIPv6Extension):
		return metrics.UnsupportedReasonIPv6Extension
	case errors.Is(err, ErrTransportTruncated):
		return metrics.UnsupportedReasonTransportTruncated
	default:
		return metrics.UnsupportedReasonMalformed
	}
}
