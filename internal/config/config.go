package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/envelope/internal/geneve"
)

const (
	packetReturnMode      = "packet-return"
	maxIPv4UDPPayloadSize = 65507
	configVersion         = 2
	geneveTLVHeaderLen    = 4
	// The mandatory AWS flow cookie is one four-byte TLV header plus four data bytes.
	minAWSGeneveOptionsMaxSize = geneveTLVHeaderLen + geneve.AWSFlowCookieLength
)

type Config struct {
	ConfigVersion            int      `name:"config-version" help:"GWLB packet-return target configuration version" default:"2" env:"ENVELOPE_CONFIG_VERSION"`
	Mode                     string   `help:"Target runtime mode" default:"packet-return" enum:"packet-return" env:"ENVELOPE_MODE"`
	UDPBind                  string   `help:"UDP bind address for GENEVE" default:":6081" env:"ENVELOPE_UDP_BIND"`
	VNI                      *uint32  `help:"GENEVE VNI; the AWS GWLB profile requires 0" env:"ENVELOPE_VNI"`
	MaxInnerPacketSize       int      `help:"Maximum accepted inner IP packet size in bytes" default:"1280" env:"ENVELOPE_MAX_INNER_PACKET_SIZE"`
	MetricsAddr              string   `help:"Metrics/health bind address" default:":9090" env:"ENVELOPE_METRICS_ADDR"`
	LogLevel                 string   `help:"Log level" default:"info" enum:"debug,info,warn,error" env:"ENVELOPE_LOG_LEVEL"`
	PersistentErrorThreshold int      `help:"Consecutive receiver or sender errors before persistent-failure handling" default:"3" env:"ENVELOPE_PERSISTENT_ERROR_THRESHOLD"`
	GeneveOptionsMaxBytes    int      `help:"Max total GENEVE options size in bytes" default:"252" env:"ENVELOPE_GENEVE_OPTIONS_MAX_BYTES"`
	GeneveTLVParse           bool     `help:"Enable allowlisted GENEVE TLV value logging" default:"false" env:"ENVELOPE_GENEVE_TLV_PARSE"`
	GeneveTLVAllowlist       []string `help:"GENEVE TLV value-log allowlist as class:seven-bit-type (hex or decimal), comma-separated" sep:"," env:"ENVELOPE_GENEVE_TLV_ALLOWLIST"`

	tlvAllowlist map[geneve.TLVKey]struct{} `kong:"-"`
}

// ParseTarget parses the production version 2 packet-return configuration.
func ParseTarget(args []string) (*Config, error) {
	if err := rejectObsoleteTargetArguments(args); err != nil {
		return nil, err
	}
	if err := rejectObsoleteTargetEnvironmentVariables(); err != nil {
		return nil, err
	}
	cfg := &Config{}
	parser, err := kong.New(cfg, kong.Name("envelope"), kong.Description("Envelope AWS GWLB packet-return target"))
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
	if c.ConfigVersion != configVersion {
		errs = append(errs, fmt.Errorf("unsupported config version %d; expected %d", c.ConfigVersion, configVersion))
	}
	if c.Mode != packetReturnMode {
		errs = append(errs, fmt.Errorf("unsupported target mode %q; expected %q", c.Mode, packetReturnMode))
	}
	if c.UDPBind == "" {
		errs = append(errs, errors.New("udp bind address is required"))
	} else if err := validateAWSUDPBind(c.UDPBind); err != nil {
		errs = append(errs, err)
	}
	if c.MaxInnerPacketSize <= 0 {
		errs = append(errs, fmt.Errorf("max inner packet size must be positive (got %d)", c.MaxInnerPacketSize))
	}
	if c.MetricsAddr == "" {
		errs = append(errs, errors.New("metrics address is required"))
	}
	if c.PersistentErrorThreshold <= 0 {
		errs = append(errs, errors.New("persistent error threshold must be positive"))
	}
	if c.GeneveOptionsMaxBytes < minAWSGeneveOptionsMaxSize {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be >= %d to hold the mandatory AWS flow-cookie TLV (got %d)", minAWSGeneveOptionsMaxSize, c.GeneveOptionsMaxBytes))
	}
	if c.GeneveOptionsMaxBytes > geneve.MaxOptionsLen {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be <= %d", geneve.MaxOptionsLen))
	}
	if c.GeneveOptionsMaxBytes%4 != 0 {
		errs = append(errs, fmt.Errorf("geneve options max bytes must be a multiple of 4 (got %d)", c.GeneveOptionsMaxBytes))
	}
	maxInnerPacketSize := maxIPv4UDPPayloadSize - geneve.BaseHeaderLen - c.EffectiveGeneveOptionsMax()
	if c.MaxInnerPacketSize > maxInnerPacketSize {
		errs = append(errs, fmt.Errorf("max inner packet size %d exceeds the IPv4 UDP packet limit", c.MaxInnerPacketSize))
	}
	if c.VNI != nil && *c.VNI != 0 {
		errs = append(errs, errors.New("vni must be 0 for the AWS GWLB profile"))
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
	if c.GeneveOptionsMaxBytes < minAWSGeneveOptionsMaxSize || c.GeneveOptionsMaxBytes > geneve.MaxOptionsLen {
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

func (c *Config) MaxUDPPacketSize() int {
	return c.MaxInnerPacketSize + geneve.BaseHeaderLen + c.EffectiveGeneveOptionsMax()
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

func rejectObsoleteTargetArguments(args []string) error {
	obsolete := map[string]struct{}{
		"--tun-name": {}, "--tun-mtu": {}, "--tailscale-iface": {}, "--underlay-interface": {},
		"--routing-mode": {}, "--routing-table-id": {}, "--routing-rule-priority": {},
		"--local-site-cidrs": {}, "--remote-site-cidrs": {},
		"--gwlb-return-cidrs": {}, "--local-delivery-cidrs": {}, "--remote-tailnet-cidrs": {},
		"--flow-capacity": {}, "--tcp-flow-timeout": {}, "--udp-flow-timeout": {}, "--other-flow-timeout": {},
		"--protected-cidrs": {}, "--flow-timeout": {},
	}
	for _, arg := range args {
		name := arg
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
		}
		if _, found := obsolete[name]; found {
			return fmt.Errorf("obsolete packet-return target flag %s is not supported by config version 2", name)
		}
	}
	return nil
}

func rejectObsoleteTargetEnvironmentVariables() error {
	for _, name := range []string{
		"ENVELOPE_TUN_NAME",
		"ENVELOPE_TUN_MTU",
		"ENVELOPE_TAILSCALE_IFACE",
		"ENVELOPE_UNDERLAY_INTERFACE",
		"ENVELOPE_ROUTING_MODE",
		"ENVELOPE_ROUTING_TABLE_ID",
		"ENVELOPE_ROUTING_RULE_PRIORITY",
		"ENVELOPE_LOCAL_SITE_CIDRS",
		"ENVELOPE_REMOTE_SITE_CIDRS",
		"ENVELOPE_GWLB_RETURN_CIDRS",
		"ENVELOPE_LOCAL_DELIVERY_CIDRS",
		"ENVELOPE_REMOTE_TAILNET_CIDRS",
		"ENVELOPE_FLOW_CAPACITY",
		"ENVELOPE_TCP_FLOW_TIMEOUT",
		"ENVELOPE_UDP_FLOW_TIMEOUT",
		"ENVELOPE_OTHER_FLOW_TIMEOUT",
		"ENVELOPE_PROTECTED_CIDRS",
		"ENVELOPE_FLOW_TIMEOUT",
	} {
		if _, set := os.LookupEnv(name); set {
			return fmt.Errorf("obsolete packet-return target environment variable %s is not supported by config version 2", name)
		}
	}
	return nil
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
