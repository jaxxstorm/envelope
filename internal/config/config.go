package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/envelope/internal/geneve"
)

const (
	maxVNI = 0xFFFFFF
)

type RoutingMode string

const (
	RoutingModeOff    RoutingMode = "off"
	RoutingModeManage RoutingMode = "manage"
	RoutingModeVerify RoutingMode = "verify"
)

type Config struct {
	UDPBind               string                     `help:"UDP bind address for GENEVE" default:":6081" env:"ENVELOPE_UDP_BIND"`
	VNI                   *uint32                    `help:"GENEVE VNI (0-16777215). If unset, use last-seen VNI" env:"ENVELOPE_VNI"`
	TunName               string                     `help:"TUN device name" default:"envelope0" env:"ENVELOPE_TUN_NAME"`
	TunMTU                int                        `help:"TUN MTU for inner L3 packets" default:"1280" env:"ENVELOPE_TUN_MTU"`
	TailscaleIface        string                     `help:"Tailscale interface name used for host routing checks" default:"tailscale0" env:"ENVELOPE_TAILSCALE_IFACE"`
	RoutingMode           RoutingMode                `help:"Routing integration mode" default:"off" enum:"off,manage,verify" env:"ENVELOPE_ROUTING_MODE"`
	ProtectedCIDRs        []string                   `name:"protected-cidrs" help:"Protected CIDRs routed between Tailscale and Envelope" sep:"," env:"ENVELOPE_PROTECTED_CIDRS"`
	RoutingTableID        int                        `help:"Linux routing table ID used for policy routes" default:"100" env:"ENVELOPE_ROUTING_TABLE_ID"`
	RoutingRulePriority   int                        `help:"Linux rule priority used for policy routes" default:"100" env:"ENVELOPE_ROUTING_RULE_PRIORITY"`
	MetricsAddr           string                     `help:"Metrics/health bind address" default:":9090" env:"ENVELOPE_METRICS_ADDR"`
	LogLevel              string                     `help:"Log level" default:"info" enum:"debug,info,warn,error" env:"ENVELOPE_LOG_LEVEL"`
	FlowTimeout           time.Duration              `help:"Flow mapping idle timeout" default:"5m" env:"ENVELOPE_FLOW_TIMEOUT"`
	GeneveOptionsMaxBytes int                        `help:"Max total GENEVE options size in bytes" default:"252" env:"ENVELOPE_GENEVE_OPTIONS_MAX_BYTES"`
	GeneveTLVParse        bool                       `help:"Enable GENEVE TLV parsing for allowlisted options" default:"false" env:"ENVELOPE_GENEVE_TLV_PARSE"`
	GeneveTLVAllowlist    []string                   `help:"GENEVE TLV allowlist as class:type (hex or decimal), comma-separated" sep:"," env:"ENVELOPE_GENEVE_TLV_ALLOWLIST"`
	protectedCIDRs        []string                   `kong:"-"`
	tlvAllowlist          map[geneve.TLVKey]struct{} `kong:"-"`
}

func Parse(args []string) (*Config, error) {
	cfg := &Config{}
	parser, err := kong.New(cfg, kong.Name("envelope"), kong.Description("Envelope GENEVE <-> TUN datapath"))
	if err != nil {
		return nil, err
	}
	if _, err := parser.Parse(args); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	var errs []error
	if c.UDPBind == "" {
		errs = append(errs, errors.New("udp bind address is required"))
	}
	if c.TunName == "" {
		errs = append(errs, errors.New("tun name is required"))
	}
	if c.TunMTU <= 0 {
		errs = append(errs, fmt.Errorf("tun MTU must be positive (got %d)", c.TunMTU))
	}
	if c.RoutingTableID <= 0 {
		errs = append(errs, fmt.Errorf("routing table id must be positive (got %d)", c.RoutingTableID))
	}
	if c.RoutingRulePriority <= 0 {
		errs = append(errs, fmt.Errorf("routing rule priority must be positive (got %d)", c.RoutingRulePriority))
	}
	if c.MetricsAddr == "" {
		errs = append(errs, errors.New("metrics address is required"))
	}
	if c.FlowTimeout <= 0 {
		errs = append(errs, errors.New("flow timeout must be positive"))
	}
	if c.GeneveOptionsMaxBytes <= 0 {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be positive (got %d)", c.GeneveOptionsMaxBytes))
	}
	if c.GeneveOptionsMaxBytes > geneve.MaxOptionsLen {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be <= %d", geneve.MaxOptionsLen))
	}
	if c.VNI != nil && *c.VNI > maxVNI {
		errs = append(errs, fmt.Errorf("vni must be <= %d", maxVNI))
	}
	protectedCIDRs, err := normalizeCIDRs(c.ProtectedCIDRs)
	if err != nil {
		errs = append(errs, err)
	} else {
		c.protectedCIDRs = protectedCIDRs
	}
	if c.RoutingMode == RoutingModeManage && len(c.protectedCIDRs) == 0 {
		errs = append(errs, errors.New("protected cidrs are required when routing mode is manage"))
	}
	if c.RoutingMode != RoutingModeOff && c.TailscaleIface == "" {
		errs = append(errs, errors.New("tailscale interface name is required when routing mode is enabled"))
	}
	if len(c.GeneveTLVAllowlist) > 0 {
		allow, err := parseTLVAllowlist(c.GeneveTLVAllowlist)
		if err != nil {
			errs = append(errs, err)
		} else {
			c.tlvAllowlist = allow
		}
	}
	return errors.Join(errs...)
}

func (c *Config) EffectiveVNI(vni uint32) uint32 {
	if c.VNI != nil {
		return *c.VNI
	}
	return vni
}

func (c *Config) EffectiveGeneveOptionsMax() int {
	if c.GeneveOptionsMaxBytes <= 0 || c.GeneveOptionsMaxBytes > geneve.MaxOptionsLen {
		return geneve.MaxOptionsLen
	}
	return c.GeneveOptionsMaxBytes
}

func (c *Config) TLVAllowed(key geneve.TLVKey) bool {
	if len(c.tlvAllowlist) == 0 {
		return false
	}
	_, ok := c.tlvAllowlist[key]
	return ok
}

func (c *Config) HasTLVAllowlist() bool {
	return len(c.tlvAllowlist) > 0
}

func (c *Config) EffectiveProtectedCIDRs() []string {
	out := make([]string, len(c.protectedCIDRs))
	copy(out, c.protectedCIDRs)
	return out
}

func (c *Config) MaxUDPPacketSize() int {
	// 40 (outer IPv6) + 8 (UDP) + 8 (GENEVE) + max options
	overhead := 40 + 8 + 8 + c.EffectiveGeneveOptionsMax()
	return c.TunMTU + overhead
}

func normalizeCIDRs(entries []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		cidr := strings.TrimSpace(entry)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid protected cidr %q", cidr)
		}
		canonical := ipNet.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func parseTLVAllowlist(entries []string) (map[geneve.TLVKey]struct{}, error) {
	allow := make(map[geneve.TLVKey]struct{}, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid geneve tlv allowlist entry %q", entry)
		}
		class, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid geneve tlv class %q", entry)
		}
		typ, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid geneve tlv type %q", entry)
		}
		allow[geneve.TLVKey{Class: uint16(class), Type: uint8(typ)}] = struct{}{}
	}
	return allow, nil
}
