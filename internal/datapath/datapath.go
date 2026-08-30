package datapath

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaxxstorm/envelope/internal/bufferpool"
	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/geneve"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type tlvLogEntry struct {
	Class  uint16 `json:"class"`
	Type   uint8  `json:"type"`
	Length int    `json:"length"`
	Value  string `json:"value"`
}

const (
	maxLoggedTLVs              = 16
	maxLoggedOptionValueBytes  = 16
	redactedOptionValue        = "[REDACTED]"
	defaultReceiverRetryDelay  = 100 * time.Millisecond
	defaultSenderRecoveryTries = 3
	defaultSenderRecoveryDelay = time.Second
)

var ErrDatapathRunning = errors.New("datapath is already running")

var (
	ErrReceiveLoopTerminated     = errors.New("receive loop terminated unexpectedly")
	ErrReceiverPersistentFailure = errors.New("persistent receiver failure")
	ErrSenderRecoveryFailed      = errors.New("packet sender recovery exhausted")
)

type packetSenderFactory func(int) (PacketSender, error)

type Datapath struct {
	cfg     *config.Config
	log     *zap.Logger
	debug   bool
	metrics *metrics.Metrics

	receiver  PacketReceiver
	senderMu  sync.Mutex
	sender    PacketSender
	newSender packetSenderFactory

	udpPool *bufferpool.Pool

	once *logOnce
	live *readinessTracker

	senderRecovery      chan struct{}
	senderRecoveryDelay time.Duration
	senderRecoveryTries int
	receiverRetryWait   func(context.Context)

	initialized atomic.Bool
	closing     atomic.Bool
	closeOnce   sync.Once
	runMu       sync.Mutex
	runCancel   context.CancelFunc
	running     bool
}

func New(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics) (*Datapath, error) {
	return newWithPacketIOFactories(cfg, log, metricSet, newPacketReceiver, newPacketSender)
}

func newWithPacketIOFactories(
	cfg *config.Config,
	log *zap.Logger,
	metricSet *metrics.Metrics,
	openReceiver func(string) (PacketReceiver, error),
	openSender packetSenderFactory,
) (*Datapath, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate datapath configuration: %w", err)
	}
	receiver, err := openReceiver(cfg.UDPBind)
	if err != nil {
		return nil, err
	}
	sender, err := openSender(cfg.MaxOuterPacketSize())
	if err != nil {
		_ = receiver.Close()
		return nil, err
	}
	return newDatapath(cfg, log, metricSet, receiver, sender, openSender), nil
}

func newWithPacketIO(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics, receiver PacketReceiver, sender PacketSender) *Datapath {
	return newDatapath(cfg, log, metricSet, receiver, sender, nil)
}

func newDatapath(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics, receiver PacketReceiver, sender PacketSender, newSender packetSenderFactory) *Datapath {
	if log == nil {
		log = zap.NewNop()
	}
	dp := &Datapath{
		cfg:                 cfg,
		log:                 log,
		debug:               log.Core().Enabled(zap.DebugLevel),
		metrics:             metricSet,
		receiver:            receiver,
		sender:              sender,
		newSender:           newSender,
		udpPool:             bufferpool.New(cfg.MaxUDPReceiveSize()),
		once:                newLogOnce(),
		live:                newReadinessTracker(cfg.PersistentErrorThreshold, metricSet),
		senderRecovery:      make(chan struct{}, 1),
		senderRecoveryDelay: defaultSenderRecoveryDelay,
		senderRecoveryTries: defaultSenderRecoveryTries,
	}
	return dp
}

func (d *Datapath) Close() {
	d.runMu.Lock()
	d.closing.Store(true)
	d.clearReadinessLocked()
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
		d.senderMu.Lock()
		sender := d.sender
		d.sender = nil
		d.senderMu.Unlock()
		if sender != nil {
			_ = sender.Close()
		}
	})
}

func (d *Datapath) Ready() bool {
	return d.initialized.Load() && d.live != nil && d.live.Ready()
}

func (d *Datapath) HealthReason() string {
	if !d.initialized.Load() || d.live == nil {
		return "target_not_initialized"
	}
	return d.live.Reason()
}

func (d *Datapath) Run(ctx context.Context) error {
	d.runMu.Lock()
	if d.closing.Load() || ctx.Err() != nil {
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
	d.initialized.Store(true)
	d.live.Initialize(metrics.ReadinessComponentReceiver)
	d.live.Initialize(metrics.ReadinessComponentValidation)
	d.live.Initialize(metrics.ReadinessComponentSender)
	d.runMu.Unlock()

	g, groupCtx := errgroup.WithContext(runCtx)
	g.Go(func() error {
		return d.runLoop(groupCtx, metrics.ReadinessComponentReceiver, ErrReceiveLoopTerminated, d.ingressLoop)
	})
	if d.newSender != nil {
		g.Go(func() error {
			return d.senderRecoveryLoop(groupCtx)
		})
	}
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
	d.closing.Store(true)
	d.clearReadinessLocked()
	d.runCancel = nil
	d.running = false
	d.runMu.Unlock()
	return err
}

func (d *Datapath) clearReadinessLocked() {
	d.initialized.Store(false)
	if d.live != nil {
		d.live.Shutdown()
	}
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
	return fmt.Errorf("%w: %w", termination, err)
}

func (d *Datapath) ingressLoop(ctx context.Context) error {
	for {
		if err := d.receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				if ctx.Err() != nil || d.closing.Load() {
					return nil
				}
				return err
			}
			if d.once.ShouldLog("receive_deadline") {
				d.log.Warn("packet receive deadline failed", zap.Error(err))
			}
			if err := d.handleReceiverFailure(ctx, "set read deadline", err); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		buf := d.udpPool.Get()
		n, metadata, err := d.receiver.ReadPacket(buf)
		if err != nil {
			d.udpPool.Put(buf)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				d.live.Success(metrics.ReadinessComponentReceiver)
				continue
			}
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				if ctx.Err() != nil || d.closing.Load() {
					return nil
				}
				return err
			}
			if errors.Is(err, ErrPacketTruncated) {
				d.live.Success(metrics.ReadinessComponentReceiver)
				d.recordReceiveDrop(metrics.ReceiveDropReasonDatagramTruncated)
				continue
			}
			if errors.Is(err, ErrControlTruncated) {
				d.recordReceiveDrop(metrics.ReceiveDropReasonControlTruncated)
			} else if errors.Is(err, ErrPacketInfoMissing) {
				d.recordReceiveDrop(metrics.ReceiveDropReasonPacketInfo)
			}
			if d.once.ShouldLog("receive") {
				d.log.Warn("packet receive failed", zap.Error(err))
			}
			if err := d.handleReceiverFailure(ctx, "read packet", err); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		d.live.Success(metrics.ReadinessComponentReceiver)
		d.processIngress(buf[:n], metadata)
		d.udpPool.Put(buf)
	}
}

func (d *Datapath) handleReceiverFailure(ctx context.Context, operation string, err error) error {
	if d.live.Failure(metrics.ReadinessComponentReceiver) {
		return fmt.Errorf("%w: %s failed %d consecutive times: %w", ErrReceiverPersistentFailure, operation, d.cfg.PersistentErrorThreshold, err)
	}
	if d.receiverRetryWait != nil {
		d.receiverRetryWait(ctx)
		return nil
	}
	timer := time.NewTimer(defaultReceiverRetryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return nil
}

func (d *Datapath) processIngress(packet []byte, metadata PacketMetadata) {
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
	if len(payload) > d.cfg.MaxInnerPacketSize {
		d.metrics.Drops.Inc()
		d.metrics.MTUDrops.WithLabelValues(mtuDropFamily(payload), metrics.MTUDropDirectionIngress).Inc()
		if d.once.ShouldLog("mtu_ingress") {
			d.log.Warn("inner packet exceeds configured maximum", zap.Int("size", len(payload)), zap.Int("maximum", d.cfg.MaxInnerPacketSize))
		}
		return
	}
	if err := validateInnerPacket(payload); err != nil {
		d.rejectInner()
		return
	}
	d.metrics.GeneveRxPackets.Inc()
	d.metrics.GeneveRxBytes.Add(float64(len(packet)))
	if d.cfg.GeneveTLVParse && d.cfg.HasTLVAllowlist() && len(header.Options) > 0 {
		d.logAllowedTLVs(header.Options)
	}

	out := d.udpPool.Get()
	n, err := geneve.Encode(out, header, payload)
	if err != nil {
		d.metrics.GWLBReturnBuildFailures.Inc()
		d.metrics.Drops.Inc()
		d.udpPool.Put(out)
		return
	}
	request := SendRequest{
		Source:      netip.AddrPortFrom(metadata.Local.Addr().Unmap(), metadata.Peer.Port()),
		Destination: netip.AddrPortFrom(metadata.Peer.Addr().Unmap(), awsGenevePort),
		IfIndex:     metadata.IfIndex,
		Payload:     out[:n],
	}
	if err := d.sendPacket(request); err != nil {
		if d.live.Failure(metrics.ReadinessComponentSender) {
			d.requestSenderRecovery()
		}
		d.metrics.GWLBSendFailures.Inc()
		d.metrics.Drops.Inc()
		if d.once.ShouldLog("packet_send") {
			d.log.Warn("AWS-compliant packet send failed", zap.Error(err))
		}
		d.udpPool.Put(out)
		return
	}
	d.live.Success(metrics.ReadinessComponentSender)
	d.metrics.GeneveTxPackets.Inc()
	d.metrics.GeneveTxBytes.Add(float64(n))
	if d.debug {
		fields := []zap.Field{
			zap.String("direction", "gwlb_return"),
			zap.String("source", request.Source.String()),
			zap.String("destination", request.Destination.String()),
			zap.Int("ifindex", request.IfIndex),
			zap.Int("inner_size", len(payload)),
			zap.Int("geneve_size", n),
			zap.Int("options_len", len(header.Options)),
		}
		d.log.Debug("packet returned", fields...)
	}
	d.udpPool.Put(out)
}

func (d *Datapath) sendPacket(request SendRequest) error {
	d.senderMu.Lock()
	defer d.senderMu.Unlock()
	if d.sender == nil {
		return net.ErrClosed
	}
	return d.sender.SendPacket(request)
}

func (d *Datapath) requestSenderRecovery() {
	if d.newSender == nil {
		return
	}
	select {
	case d.senderRecovery <- struct{}{}:
	default:
	}
}

func (d *Datapath) senderRecoveryLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-d.senderRecovery:
		}

		var lastErr error
		for attempt := 1; attempt <= d.senderRecoveryTries; attempt++ {
			if attempt > 1 {
				timer := time.NewTimer(d.senderRecoveryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
			}

			replacement, err := d.newSender(d.cfg.MaxOuterPacketSize())
			if err != nil {
				lastErr = err
				d.metrics.SenderReinitializations.WithLabelValues(metrics.SenderReinitializationFailed).Inc()
				continue
			}
			d.senderMu.Lock()
			if d.closing.Load() || ctx.Err() != nil {
				d.senderMu.Unlock()
				_ = replacement.Close()
				return nil
			}
			previous := d.sender
			d.sender = replacement
			d.senderMu.Unlock()
			if previous != nil {
				_ = previous.Close()
			}
			d.metrics.SenderReinitializations.WithLabelValues(metrics.SenderReinitializationOK).Inc()
			d.live.Success(metrics.ReadinessComponentSender)
			d.log.Info("raw packet sender reinitialized", zap.Int("attempt", attempt))
			lastErr = nil
			break
		}
		if lastErr != nil {
			return fmt.Errorf("%w after %d attempts: %v", ErrSenderRecoveryFailed, d.senderRecoveryTries, lastErr)
		}
	}
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
	d.metrics.Drops.Inc()
	d.metrics.GWLBProfileRejections.WithLabelValues(reason).Inc()
	if d.once.ShouldLog("profile_" + logKey + "_" + reason) {
		d.log.Warn("AWS GWLB profile rejected packet", zap.String("reason", reason), zap.Error(err))
	}
}

func (d *Datapath) rejectInner() {
	d.metrics.GWLBInnerValidationFailures.WithLabelValues(metrics.InnerValidationReasonMalformed).Inc()
	d.metrics.Drops.Inc()
}

func (d *Datapath) recordReceiveDrop(reason string) {
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
	case errors.Is(err, geneve.ErrAWSOptionReserved):
		return metrics.OptionValidationReasonAWSReserved
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
