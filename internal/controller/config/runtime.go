package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
)

const (
	DefaultMetricsAddress = "127.0.0.1:9091"

	// MaxActiveDomains bounds the independent worker capacity required by an
	// active process. Passive modes may inspect larger validated topologies.
	MaxActiveDomains = 32
)

// RuntimeConfig contains process-local controller settings. Shared authority
// and timing policy remain exclusively in the immutable topology document.
type RuntimeConfig struct {
	ControllerID string `name:"controller-id" help:"Controller replica ID allowlisted by the topology" required:"" env:"ENVELOPE_CONTROLLER_ID"`
	TopologyPath string `name:"topology" help:"Path to the immutable controller topology JSON" required:"" env:"ENVELOPE_CONTROLLER_TOPOLOGY_PATH"`
	MetricsAddr  string `name:"metrics-addr" help:"Private metrics and health bind address" default:"127.0.0.1:9091" env:"ENVELOPE_CONTROLLER_METRICS_ADDR"`
	LogLevel     string `name:"log-level" help:"Log level" default:"info" enum:"debug,info,warn,error" env:"ENVELOPE_CONTROLLER_LOG_LEVEL"`
	ReadOnly     bool   `name:"read-only" help:"Observe durable and cloud state without acquiring leases or mutating routes" env:"ENVELOPE_CONTROLLER_READ_ONLY"`
	DryRun       bool   `name:"dry-run" help:"Evaluate controller state without durable or cloud mutation" env:"ENVELOPE_CONTROLLER_DRY_RUN"`
}

// ParseController parses the standalone production controller command line
// and its explicitly named environment variables.
func ParseController(args []string) (*RuntimeConfig, error) {
	runtimeConfig := &RuntimeConfig{}
	parser, err := kong.New(
		runtimeConfig,
		kong.Name("envelope-controller"),
		kong.Description("Envelope autonomous production failover controller"),
	)
	if err != nil {
		return nil, fmt.Errorf("controller configuration: %w", err)
	}
	if _, err := parser.Parse(args); err != nil {
		return nil, err
	}
	if err := runtimeConfig.Validate(); err != nil {
		return nil, err
	}
	return runtimeConfig, nil
}

// Validate checks process-local settings without reading the topology file.
func (c RuntimeConfig) Validate() error {
	var errs []error
	if err := c.ProcessConfig().Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := validatePrivateMetricsAddress(c.MetricsAddr); err != nil {
		errs = append(errs, err)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("unsupported log level %q", c.LogLevel))
	}
	if c.ReadOnly && c.DryRun {
		errs = append(errs, errors.New("read-only and dry-run modes are mutually exclusive"))
	}
	return errors.Join(errs...)
}

// ValidateForTopology binds the process identity to an explicitly allowlisted
// replica and rejects active topologies that cannot receive one worker per
// domain. Read-only and dry-run processes retain bounded shared-worker support
// for larger topologies.
func (c RuntimeConfig) ValidateForTopology(topology *Topology) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := c.ProcessConfig().ValidateForTopology(topology); err != nil {
		return err
	}
	if !c.ReadOnly && !c.DryRun && len(topology.Domains) > MaxActiveDomains {
		return fmt.Errorf("active domain count exceeds worker capacity %d: got %d", MaxActiveDomains, len(topology.Domains))
	}
	return nil
}

func (c RuntimeConfig) ProcessConfig() ProcessConfig {
	return ProcessConfig{ControllerID: c.ControllerID, TopologyPath: c.TopologyPath}
}

func validatePrivateMetricsAddress(address string) error {
	if address == "" || address != strings.TrimSpace(address) {
		return errors.New("metrics address is required without surrounding whitespace")
	}
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil || host == "" || rawPort == "" {
		return errors.New("metrics address must be a private IP and TCP port")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return errors.New("metrics address must contain a non-zero TCP port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || !ip.IsLoopback() && !ip.IsPrivate() {
		return errors.New("metrics address must use a loopback or private IP")
	}
	return nil
}
