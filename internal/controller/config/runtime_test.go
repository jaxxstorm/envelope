package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseControllerFlagsAndDefaults(t *testing.T) {
	clearControllerEnvironment(t)
	configuration, err := ParseController([]string{
		"--controller-id=controller-a",
		"--topology=/etc/envelope/controller.json",
	})
	if err != nil {
		t.Fatalf("ParseController() error = %v", err)
	}
	if configuration.ControllerID != "controller-a" || configuration.TopologyPath != "/etc/envelope/controller.json" {
		t.Fatalf("process configuration = %+v", configuration)
	}
	if configuration.MetricsAddr != DefaultMetricsAddress || configuration.LogLevel != "info" || configuration.ReadOnly || configuration.DryRun {
		t.Fatalf("defaults = %+v", configuration)
	}
}

func TestParseControllerEnvironment(t *testing.T) {
	clearControllerEnvironment(t)
	t.Setenv("ENVELOPE_CONTROLLER_ID", "controller-b")
	t.Setenv("ENVELOPE_CONTROLLER_TOPOLOGY_PATH", "/srv/envelope/topology.json")
	t.Setenv("ENVELOPE_CONTROLLER_METRICS_ADDR", "10.0.0.10:9191")
	t.Setenv("ENVELOPE_CONTROLLER_LOG_LEVEL", "warn")
	t.Setenv("ENVELOPE_CONTROLLER_READ_ONLY", "true")

	configuration, err := ParseController(nil)
	if err != nil {
		t.Fatalf("ParseController() error = %v", err)
	}
	if configuration.ControllerID != "controller-b" || configuration.TopologyPath != "/srv/envelope/topology.json" ||
		configuration.MetricsAddr != "10.0.0.10:9191" || configuration.LogLevel != "warn" || !configuration.ReadOnly {
		t.Fatalf("environment configuration = %+v", configuration)
	}
}

func TestParseControllerRejectsInvalidRuntimeConfiguration(t *testing.T) {
	clearControllerEnvironment(t)
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing controller", args: []string{"--topology=/tmp/topology.json"}, wantErr: "controller ID"},
		{name: "missing topology", args: []string{"--controller-id=controller-a"}, wantErr: "topology"},
		{name: "unsafe controller", args: []string{"--controller-id=../a", "--topology=/tmp/topology.json"}, wantErr: "contain only"},
		{name: "empty metrics", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--metrics-addr="}, wantErr: "metrics address"},
		{name: "wildcard metrics", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--metrics-addr=0.0.0.0:9091"}, wantErr: "loopback or private"},
		{name: "public metrics", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--metrics-addr=203.0.113.10:9091"}, wantErr: "loopback or private"},
		{name: "zero port", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--metrics-addr=127.0.0.1:0"}, wantErr: "non-zero"},
		{name: "hostname", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--metrics-addr=metrics.example.com:9091"}, wantErr: "loopback or private"},
		{name: "invalid log level", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--log-level=trace"}, wantErr: "log-level"},
		{name: "two passive modes", args: []string{"--controller-id=controller-a", "--topology=/tmp/topology.json", "--read-only", "--dry-run"}, wantErr: "mutually exclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseController(test.args)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseController(%v) error = %v, want %q", test.args, err, test.wantErr)
			}
		})
	}
}

func TestRuntimeConfigValidatesControllerAgainstTopology(t *testing.T) {
	topology := validTopology()
	configuration := RuntimeConfig{
		ControllerID: "controller-a",
		TopologyPath: "/etc/envelope/controller.json",
		MetricsAddr:  DefaultMetricsAddress,
		LogLevel:     "info",
	}
	if err := configuration.ValidateForTopology(&topology); err != nil {
		t.Fatalf("ValidateForTopology() error = %v", err)
	}
	configuration.ControllerID = "controller-unknown"
	if err := configuration.ValidateForTopology(&topology); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unknown controller error = %v", err)
	}
}

func TestRuntimeConfigValidatesActiveDomainCapacityByMode(t *testing.T) {
	base := RuntimeConfig{
		ControllerID: "controller-a",
		TopologyPath: "/etc/envelope/controller.json",
		MetricsAddr:  DefaultMetricsAddress,
		LogLevel:     "info",
	}

	atLimit := validTopologyWithDomainCount(MaxActiveDomains)
	if err := base.ValidateForTopology(&atLimit); err != nil {
		t.Fatalf("active ValidateForTopology() at capacity error = %v", err)
	}

	overLimit := validTopologyWithDomainCount(MaxActiveDomains + 1)
	if err := overLimit.Validate(); err != nil {
		t.Fatalf("large passive topology is invalid: %v", err)
	}
	for _, test := range []struct {
		name    string
		mutate  func(*RuntimeConfig)
		wantErr bool
	}{
		{name: "active", mutate: func(*RuntimeConfig) {}, wantErr: true},
		{name: "read-only", mutate: func(configuration *RuntimeConfig) { configuration.ReadOnly = true }},
		{name: "dry-run", mutate: func(configuration *RuntimeConfig) { configuration.DryRun = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := base
			test.mutate(&configuration)
			err := configuration.ValidateForTopology(&overLimit)
			if test.wantErr {
				want := fmt.Sprintf("active domain count exceeds worker capacity %d", MaxActiveDomains)
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("ValidateForTopology() error = %v, want active capacity error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateForTopology() error = %v", err)
			}
		})
	}
}

func TestPrivateMetricsAddressAllowsLoopbackAndPrivateIPs(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9091", "localhost:9091", "10.0.0.1:9091", "[::1]:9091", "[fd00::1]:9091"} {
		if err := validatePrivateMetricsAddress(address); err != nil {
			t.Errorf("validatePrivateMetricsAddress(%q) = %v", address, err)
		}
	}
}

func clearControllerEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ENVELOPE_CONTROLLER_ID",
		"ENVELOPE_CONTROLLER_TOPOLOGY_PATH",
		"ENVELOPE_CONTROLLER_METRICS_ADDR",
		"ENVELOPE_CONTROLLER_LOG_LEVEL",
		"ENVELOPE_CONTROLLER_READ_ONLY",
		"ENVELOPE_CONTROLLER_DRY_RUN",
	} {
		value, found := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if found {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}
