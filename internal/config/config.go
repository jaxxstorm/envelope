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

type RoutingMode string

const (
	RoutingModeOff        RoutingMode = "off"
	RoutingModeManage     RoutingMode = "manage"
	RoutingModeVerify     RoutingMode = "verify"
	TailscaleRouteTableID             = 52
	maxIPv4UDPPayloadSize             = 65507
)

type Config struct {
	UDPBind                  string                     `help:"UDP bind address for GENEVE" default:":6081" env:"ENVELOPE_UDP_BIND"`
	VNI                      *uint32                    `help:"GENEVE VNI; the AWS GWLB profile requires 0" env:"ENVELOPE_VNI"`
	TunName                  string                     `help:"TUN device name" default:"envelope0" env:"ENVELOPE_TUN_NAME"`
	TunMTU                   int                        `help:"TUN MTU for inner L3 packets" default:"1280" env:"ENVELOPE_TUN_MTU"`
	TailscaleIface           string                     `help:"Tailscale interface name used for host routing checks" default:"tailscale0" env:"ENVELOPE_TAILSCALE_IFACE"`
	UnderlayIface            string                     `name:"underlay-interface" help:"Appliance underlay interface used for host routing checks" env:"ENVELOPE_UNDERLAY_INTERFACE"`
	RoutingMode              RoutingMode                `help:"Routing integration mode" default:"off" enum:"off,manage,verify" env:"ENVELOPE_ROUTING_MODE"`
	GWLBReturnCIDRs          []string                   `name:"gwlb-return-cidrs" help:"Local initiator CIDRs whose Tailnet returns enter Envelope" sep:"," env:"ENVELOPE_GWLB_RETURN_CIDRS"`
	LocalDeliveryCIDRs       []string                   `name:"local-delivery-cidrs" help:"Local responder CIDRs delivered without entering Envelope" sep:"," env:"ENVELOPE_LOCAL_DELIVERY_CIDRS"`
	RemoteTailnetCIDRs       []string                   `name:"remote-tailnet-cidrs" help:"Remote CIDRs that must route through Tailscale" sep:"," env:"ENVELOPE_REMOTE_TAILNET_CIDRS"`
	RoutingTableID           int                        `help:"Linux routing table ID used for policy routes" default:"100" env:"ENVELOPE_ROUTING_TABLE_ID"`
	RoutingRulePriority      int                        `help:"Linux rule priority used for policy routes" default:"100" env:"ENVELOPE_ROUTING_RULE_PRIORITY"`
	MetricsAddr              string                     `help:"Metrics/health bind address" default:":9090" env:"ENVELOPE_METRICS_ADDR"`
	LogLevel                 string                     `help:"Log level" default:"info" enum:"debug,info,warn,error" env:"ENVELOPE_LOG_LEVEL"`
	FlowCapacity             int                        `help:"Maximum GWLB return contexts" default:"65536" env:"ENVELOPE_FLOW_CAPACITY"`
	TCPFlowTimeout           time.Duration              `help:"TCP return-context idle timeout" default:"350s" env:"ENVELOPE_TCP_FLOW_TIMEOUT"`
	UDPFlowTimeout           time.Duration              `help:"UDP return-context idle timeout" default:"120s" env:"ENVELOPE_UDP_FLOW_TIMEOUT"`
	OtherFlowTimeout         time.Duration              `help:"Non-TCP/UDP return-context idle timeout" default:"120s" env:"ENVELOPE_OTHER_FLOW_TIMEOUT"`
	PersistentErrorThreshold int                        `help:"Consecutive component errors before readiness fails" default:"3" env:"ENVELOPE_PERSISTENT_ERROR_THRESHOLD"`
	GeneveOptionsMaxBytes    int                        `help:"Max total GENEVE options size in bytes" default:"252" env:"ENVELOPE_GENEVE_OPTIONS_MAX_BYTES"`
	GeneveTLVParse           bool                       `help:"Enable allowlisted GENEVE TLV value logging" default:"false" env:"ENVELOPE_GENEVE_TLV_PARSE"`
	GeneveTLVAllowlist       []string                   `help:"GENEVE TLV value-log allowlist as class:seven-bit-type (hex or decimal), comma-separated" sep:"," env:"ENVELOPE_GENEVE_TLV_ALLOWLIST"`
	gwlbReturnCIDRs          []string                   `kong:"-"`
	localDeliveryCIDRs       []string                   `kong:"-"`
	remoteTailnetCIDRs       []string                   `kong:"-"`
	tlvAllowlist             map[geneve.TLVKey]struct{} `kong:"-"`
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
	if c.RoutingMode == "" {
		c.RoutingMode = RoutingModeOff
	}
	if c.RoutingMode != RoutingModeOff && c.RoutingMode != RoutingModeManage && c.RoutingMode != RoutingModeVerify {
		errs = append(errs, fmt.Errorf("unsupported routing mode %q", c.RoutingMode))
	}
	c.gwlbReturnCIDRs = nil
	c.localDeliveryCIDRs = nil
	c.remoteTailnetCIDRs = nil
	if c.UDPBind == "" {
		errs = append(errs, errors.New("udp bind address is required"))
	} else if err := validateAWSUDPBind(c.UDPBind); err != nil {
		errs = append(errs, err)
	}
	if c.TunName == "" {
		errs = append(errs, errors.New("tun name is required"))
	} else if err := validateInterfaceName("tun name", c.TunName); err != nil {
		errs = append(errs, err)
	}
	if c.TunMTU <= 0 {
		errs = append(errs, fmt.Errorf("tun MTU must be positive (got %d)", c.TunMTU))
	}
	if err := validateRoutingTableID(c.RoutingTableID); err != nil {
		errs = append(errs, err)
	}
	if c.RoutingRulePriority <= 0 {
		errs = append(errs, fmt.Errorf("routing rule priority must be positive (got %d)", c.RoutingRulePriority))
	}
	if c.MetricsAddr == "" {
		errs = append(errs, errors.New("metrics address is required"))
	}
	if c.FlowCapacity <= 0 {
		errs = append(errs, errors.New("flow capacity must be positive"))
	}
	if c.TCPFlowTimeout <= 0 {
		errs = append(errs, errors.New("tcp flow timeout must be positive"))
	}
	if c.UDPFlowTimeout <= 0 {
		errs = append(errs, errors.New("udp flow timeout must be positive"))
	}
	if c.OtherFlowTimeout <= 0 {
		errs = append(errs, errors.New("other flow timeout must be positive"))
	}
	if c.PersistentErrorThreshold <= 0 {
		errs = append(errs, errors.New("persistent error threshold must be positive"))
	}
	if c.GeneveOptionsMaxBytes <= 0 {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be positive (got %d)", c.GeneveOptionsMaxBytes))
	}
	if c.GeneveOptionsMaxBytes > geneve.MaxOptionsLen {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be <= %d", geneve.MaxOptionsLen))
	}
	if c.GeneveOptionsMaxBytes%4 != 0 {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be a multiple of 4 (got %d)", c.GeneveOptionsMaxBytes))
	}
	if c.VNI != nil && *c.VNI != 0 {
		errs = append(errs, errors.New("vni must be 0 for the AWS GWLB profile"))
	}
	roles := []struct {
		name       string
		configured []string
		effective  *[]string
	}{
		{name: "gwlb-return-cidrs", configured: c.GWLBReturnCIDRs, effective: &c.gwlbReturnCIDRs},
		{name: "local-delivery-cidrs", configured: c.LocalDeliveryCIDRs, effective: &c.localDeliveryCIDRs},
		{name: "remote-tailnet-cidrs", configured: c.RemoteTailnetCIDRs, effective: &c.remoteTailnetCIDRs},
	}
	rolesValid := true
	for _, role := range roles {
		cidrs, err := normalizeCIDRs(role.name, role.configured)
		if err != nil {
			errs = append(errs, err)
			rolesValid = false
			continue
		}
		*role.effective = cidrs
	}
	if rolesValid {
		if err := validateDisjointCIDRRoles(roles); err != nil {
			errs = append(errs, err)
		}
	}
	if c.TailscaleIface != "" {
		if err := validateInterfaceName("tailscale interface name", c.TailscaleIface); err != nil {
			errs = append(errs, err)
		}
	}
	if c.TunName != "" && c.TailscaleIface != "" && c.TunName == c.TailscaleIface {
		errs = append(errs, fmt.Errorf("envelope and tailscale interface names must be distinct (both are %q)", c.TunName))
	}
	if c.UnderlayIface != "" {
		if err := validateInterfaceName("underlay interface name", c.UnderlayIface); err != nil {
			errs = append(errs, err)
		}
	}
	if c.RoutingMode != RoutingModeOff {
		if c.TailscaleIface == "" {
			errs = append(errs, errors.New("tailscale interface name is required when routing mode is enabled"))
		}
		if c.UnderlayIface == "" {
			errs = append(errs, errors.New("underlay interface is required when routing mode is enabled"))
		}
	}
	if c.RoutingMode == RoutingModeManage && len(c.gwlbReturnCIDRs) == 0 {
		errs = append(errs, errors.New("gwlb return cidrs are required when routing mode is manage"))
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

func (c *Config) EffectiveGWLBReturnCIDRs() []string {
	return cloneStrings(c.gwlbReturnCIDRs)
}

func (c *Config) EffectiveLocalDeliveryCIDRs() []string {
	return cloneStrings(c.localDeliveryCIDRs)
}

func (c *Config) EffectiveRemoteTailnetCIDRs() []string {
	return cloneStrings(c.remoteTailnetCIDRs)
}

func (c *Config) MaxUDPPacketSize() int {
	return c.TunMTU + geneve.BaseHeaderLen + c.EffectiveGeneveOptionsMax()
}

func (c *Config) MaxUDPReceiveSize() int {
	return maxIPv4UDPPayloadSize
}

func (c *Config) MaxOuterPacketSize() int {
	return 20 + 8 + c.MaxUDPPacketSize()
}

func validateAWSUDPBind(bind string) error {
	addr, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		return fmt.Errorf("invalid udp bind %q: %w", bind, err)
	}
	if addr.Port != 6081 {
		return fmt.Errorf("udp bind port must be 6081 for the AWS GWLB profile (got %d)", addr.Port)
	}
	if addr.IP != nil && addr.IP.To4() == nil {
		return fmt.Errorf("udp bind must resolve to IPv4 for the AWS GWLB profile (got %q)", bind)
	}
	return nil
}

func normalizeCIDRs(role string, entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		cidr := strings.TrimSpace(entry)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s entry %q", role, cidr)
		}
		out = append(out, ipNet.String())
	}
	return out, nil
}

func validateDisjointCIDRRoles(roles []struct {
	name       string
	configured []string
	effective  *[]string
}) error {
	type roleCIDR struct {
		role  string
		value string
		net   *net.IPNet
	}
	var entries []roleCIDR
	for _, role := range roles {
		for _, value := range *role.effective {
			_, network, _ := net.ParseCIDR(value)
			entries = append(entries, roleCIDR{role: role.name, value: value, net: network})
		}
	}
	var errs []error
	for i := range entries {
		for j := i + 1; j < len(entries); j++ {
			left, right := entries[i], entries[j]
			if (left.net.IP.To4() == nil) != (right.net.IP.To4() == nil) {
				continue
			}
			if left.net.Contains(right.net.IP) || right.net.Contains(left.net.IP) {
				errs = append(errs, fmt.Errorf("CIDR overlap: %s %q conflicts with %s %q", left.role, left.value, right.role, right.value))
			}
		}
	}
	return errors.Join(errs...)
}

func validateInterfaceName(field, name string) error {
	if len(name) > 15 || strings.ContainsAny(name, "/ \t\r\n") || name == "." || name == ".." {
		return fmt.Errorf("%s %q is not a valid Linux interface name", field, name)
	}
	return nil
}

func validateRoutingTableID(table int) error {
	switch table {
	case 0:
		return errors.New("routing table id 0 is reserved for unspec")
	case TailscaleRouteTableID:
		return fmt.Errorf("routing table id %d is owned by Tailscale", table)
	case 253:
		return errors.New("routing table id 253 is reserved for default")
	case 254:
		return errors.New("routing table id 254 is reserved for main")
	case 255:
		return errors.New("routing table id 255 is reserved for local")
	}
	if table < 0 || table > 252 {
		return fmt.Errorf("routing table id must be between 1 and 252 excluding %d (got %d)", TailscaleRouteTableID, table)
	}
	return nil
}

func cloneStrings(values []string) []string {
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func parseTLVAllowlist(entries []string) (map[geneve.TLVKey]struct{}, error) {
	allow := make(map[geneve.TLVKey]struct{}, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, errors.New("geneve tlv allowlist entries cannot be empty")
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
		if typ > geneve.OptionTypeMask {
			return nil, fmt.Errorf("invalid geneve tlv type %q: type must be a seven-bit value (0-127)", entry)
		}
		allow[geneve.TLVKey{Class: uint16(class), Type: uint8(typ)}] = struct{}{}
	}
	return allow, nil
}
