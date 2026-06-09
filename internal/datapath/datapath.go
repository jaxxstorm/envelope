package datapath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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

type UDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
}

type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type tlvLogEntry struct {
	Class  uint16 `json:"class"`
	Type   uint8  `json:"type"`
	Length int    `json:"length"`
}

type Datapath struct {
	cfg     *config.Config
	log     *zap.Logger
	debug   bool
	metrics *metrics.Metrics

	udp UDPConn
	tun TunDevice

	udpPool *bufferpool.Pool
	tunPool *bufferpool.Pool

	flows *flowTable
	once  *logOnce

	ready atomic.Bool
}

func New(cfg *config.Config, log *zap.Logger, metrics *metrics.Metrics) (*Datapath, error) {
	if log == nil {
		log = zap.NewNop()
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.UDPBind)
	if err != nil {
		return nil, fmt.Errorf("resolve udp bind: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	tunDev, err := tun.Open(cfg.TunName, cfg.TunMTU)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	dp := &Datapath{
		cfg:     cfg,
		log:     log,
		debug:   log.Core().Enabled(zap.DebugLevel),
		metrics: metrics,
		udp:     udpConn,
		tun:     tunDev,
		udpPool: bufferpool.New(cfg.MaxUDPPacketSize()),
		tunPool: bufferpool.New(cfg.TunMTU + 1),
		flows:   newFlowTable(cfg.FlowTimeout),
		once:    newLogOnce(),
	}
	dp.ready.Store(true)
	return dp, nil
}

func NewWithDevices(cfg *config.Config, log *zap.Logger, metrics *metrics.Metrics, udp UDPConn, tun TunDevice) *Datapath {
	if log == nil {
		log = zap.NewNop()
	}
	dp := &Datapath{
		cfg:     cfg,
		log:     log,
		debug:   log.Core().Enabled(zap.DebugLevel),
		metrics: metrics,
		udp:     udp,
		tun:     tun,
		udpPool: bufferpool.New(cfg.MaxUDPPacketSize()),
		tunPool: bufferpool.New(cfg.TunMTU + 1),
		flows:   newFlowTable(cfg.FlowTimeout),
		once:    newLogOnce(),
	}
	dp.ready.Store(true)
	return dp
}

func (d *Datapath) Close() {
	if d.udp != nil {
		_ = d.udp.Close()
	}
	if d.tun != nil {
		_ = d.tun.Close()
	}
	if d.log != nil {
		_ = d.log.Sync()
	}
}

func (d *Datapath) Ready() bool {
	return d.ready.Load()
}

func (d *Datapath) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	if !d.Ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (d *Datapath) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return d.ingressLoop(ctx)
	})
	g.Go(func() error {
		return d.egressLoop(ctx)
	})
	g.Go(func() error {
		return d.flowSweepLoop(ctx)
	})
	// Ensure resources close on context cancellation
	go func() {
		<-ctx.Done()
		d.ready.Store(false)
		d.Close()
	}()
	return g.Wait()
}

func (d *Datapath) flowSweepLoop(ctx context.Context) error {
	interval := time.Minute
	if d.cfg.FlowTimeout > 0 && d.cfg.FlowTimeout < interval {
		interval = d.cfg.FlowTimeout / 2
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.flows.Sweep()
		}
	}
}

func (d *Datapath) ingressLoop(ctx context.Context) error {
	for {
		if err := d.udp.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		buf := d.udpPool.Get()
		n, addr, err := d.udp.ReadFromUDP(buf)
		if err != nil {
			d.udpPool.Put(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if d.once.ShouldLog("udp_read") {
				d.log.Warn("udp read error", zap.Error(err))
			}
			continue
		}

		d.metrics.GeneveRxPackets.Inc()
		d.metrics.GeneveRxBytes.Add(float64(n))

		hdr, payload, err := geneve.Decode(buf[:n])
		if err != nil {
			d.metrics.DecapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("decap") {
				d.log.Warn("geneve decode failed", zap.Error(err))
			}
			d.udpPool.Put(buf)
			continue
		}
		if err := geneve.ValidateOptions(hdr.Options, d.cfg.EffectiveGeneveOptionsMax()); err != nil {
			d.metrics.DecapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("opts_validate") {
				d.log.Warn("geneve options invalid", zap.Error(err), zap.Int("len", len(hdr.Options)))
			}
			d.udpPool.Put(buf)
			continue
		}
		if hdr.Protocol != geneve.ProtoIPv4 && hdr.Protocol != geneve.ProtoIPv6 {
			d.metrics.DecapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("proto") {
				d.log.Warn("unsupported geneve protocol", zap.Uint16("proto", hdr.Protocol))
			}
			d.udpPool.Put(buf)
			continue
		}
		if d.cfg.GeneveTLVParse && d.cfg.HasTLVAllowlist() && len(hdr.Options) > 0 {
			tlvs, err := geneve.ParseTLVs(hdr.Options)
			if err != nil {
				if d.once.ShouldLog("tlv_parse") {
					d.log.Warn("geneve tlv parse failed", zap.Error(err))
				}
			} else {
				allowed := make([]tlvLogEntry, 0, len(tlvs))
				for _, tlv := range tlvs {
					if !d.cfg.TLVAllowed(geneve.TLVKey{Class: tlv.Class, Type: tlv.Type}) {
						continue
					}
					allowed = append(allowed, tlvLogEntry{
						Class:  tlv.Class,
						Type:   tlv.Type,
						Length: tlv.Length,
					})
				}
				if len(allowed) > 0 {
					d.log.Debug("geneve tlvs parsed", zap.Int("count", len(allowed)), zap.Any("tlvs", allowed))
				}
			}
		}

		if len(payload) > d.cfg.TunMTU {
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("mtu_ingress") {
				d.log.Warn("ingress packet exceeds MTU", zap.Int("size", len(payload)), zap.Int("mtu", d.cfg.TunMTU))
			}
			d.udpPool.Put(buf)
			continue
		}

		key, ok := flowKeyFromPacket(payload)
		if !ok {
			d.metrics.DecapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("flow_key") {
				d.log.Warn("unable to derive flow key from payload")
			}
			d.udpPool.Put(buf)
			continue
		}
		if d.debug {
			fields := []zap.Field{
				zap.String("direction", "udp_to_tun"),
				zap.String("peer_addr", addr.String()),
				zap.Int("geneve_size", n),
				zap.Int("inner_size", len(payload)),
				zap.Uint32("vni", hdr.VNI),
				zap.Int("options_len", len(hdr.Options)),
			}
			fields = append(fields, flowKeyDebugFields(key)...)
			d.log.Debug("packet in", fields...)
		}
		d.flows.Update(key, addr, hdr.VNI, hdr.Options)
		if err := writeTunPacket(d.tun, payload); err != nil {
			d.metrics.DecapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("tun_write") {
				d.log.Warn("tun write failed", zap.Error(err))
			}
			d.udpPool.Put(buf)
			continue
		}
		d.metrics.TunTxPackets.Inc()
		d.udpPool.Put(buf)
	}
}

func (d *Datapath) egressLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		buf, n, err := readTunPacket(d.tun, d.tunPool)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			if d.once.ShouldLog("tun_read") {
				d.log.Warn("tun read failed", zap.Error(err))
			}
			continue
		}
		d.metrics.TunRxPackets.Inc()

		payload := buf[:n]
		if len(payload) > d.cfg.TunMTU {
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("mtu_egress") {
				d.log.Warn("egress packet exceeds MTU", zap.Int("size", len(payload)), zap.Int("mtu", d.cfg.TunMTU))
			}
			d.tunPool.Put(buf)
			continue
		}

		key, ok := flowKeyFromPacket(payload)
		if !ok {
			d.metrics.EncapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("flow_key_egress") {
				d.log.Warn("unable to derive flow key from payload")
			}
			d.tunPool.Put(buf)
			continue
		}

		snap, ok := d.flows.Lookup(key)
		if !ok {
			// Return traffic has src/dst swapped versus ingress, so check reverse tuple too.
			snap, ok = d.flows.Lookup(key.Reverse())
			if !ok {
				d.metrics.Drops.Inc()
				if d.once.ShouldLog("no_flow") {
					d.log.Warn("no flow mapping; dropping packet")
				}
				d.tunPool.Put(buf)
				continue
			}
		}
		outBuf := d.udpPool.Get()
		hdr := geneve.Header{VNI: d.cfg.EffectiveVNI(snap.vni), Options: snap.options}
		nn, err := geneve.Encode(outBuf, hdr, payload)
		if err != nil {
			d.metrics.EncapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("encap") {
				d.log.Warn("geneve encode failed", zap.Error(err))
			}
			d.udpPool.Put(outBuf)
			d.tunPool.Put(buf)
			continue
		}
		if _, err := d.udp.WriteToUDP(outBuf[:nn], snap.addr); err != nil {
			d.metrics.EncapErrors.Inc()
			d.metrics.Drops.Inc()
			if d.once.ShouldLog("udp_write") {
				d.log.Warn("udp write failed", zap.Error(err))
			}
			d.udpPool.Put(outBuf)
			d.tunPool.Put(buf)
			continue
		}
		if d.debug {
			fields := []zap.Field{
				zap.String("direction", "tun_to_udp"),
				zap.String("peer_addr", snap.addr.String()),
				zap.Int("inner_size", len(payload)),
				zap.Int("geneve_size", nn),
				zap.Uint32("vni", d.cfg.EffectiveVNI(snap.vni)),
				zap.Int("options_len", len(snap.options)),
			}
			fields = append(fields, flowKeyDebugFields(key)...)
			d.log.Debug("packet out", fields...)
		}
		d.metrics.GeneveTxPackets.Inc()
		d.metrics.GeneveTxBytes.Add(float64(nn))
		d.udpPool.Put(outBuf)
		d.tunPool.Put(buf)
	}
}

func flowKeyDebugFields(key flowKey) []zap.Field {
	srcIP := net.IP(key.srcIP[:]).String()
	dstIP := net.IP(key.dstIP[:]).String()
	if key.ipFamily == 4 {
		srcIP = net.IP(key.srcIP[12:16]).String()
		dstIP = net.IP(key.dstIP[12:16]).String()
	}
	fields := []zap.Field{
		zap.String("src_ip", srcIP),
		zap.String("dst_ip", dstIP),
		zap.Uint8("proto", key.proto),
		zap.Uint8("ip_family", key.ipFamily),
	}
	if key.proto == 6 || key.proto == 17 {
		fields = append(fields,
			zap.Uint16("src_port", key.srcPort),
			zap.Uint16("dst_port", key.dstPort),
		)
	}
	return fields
}
