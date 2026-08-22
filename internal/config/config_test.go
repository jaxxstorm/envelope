package config

import (
	"strings"
	"testing"

	"github.com/jaxxstorm/envelope/internal/geneve"
)

func TestParseAndValidate(t *testing.T) {
	_, err := Parse([]string{"--udp-bind=", "--metrics-addr=:9090"})
	if err == nil {
		t.Fatalf("expected error for empty udp bind")
	}

	_, err = Parse([]string{"--udp-bind=:6081", "--tun-name=", "--metrics-addr=:9090"})
	if err == nil {
		t.Fatalf("expected error for empty tun name")
	}

	_, err = Parse([]string{"--udp-bind=:6081", "--tun-mtu=0", "--metrics-addr=:9090"})
	if err == nil {
		t.Fatalf("expected error for invalid MTU")
	}

	_, err = Parse([]string{"--udp-bind=:6081", "--vni=20000000", "--metrics-addr=:9090"})
	if err == nil {
		t.Fatalf("expected error for invalid VNI")
	}

	cfg, err := Parse([]string{"--udp-bind=:6081", "--metrics-addr=:9090"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UDPBind != ":6081" {
		t.Fatalf("unexpected udp bind: %s", cfg.UDPBind)
	}
	if cfg.TunName == "" {
		t.Fatalf("expected default tun name")
	}
	if cfg.TunMTU != 1280 {
		t.Fatalf("expected default tun mtu 1280, got %d", cfg.TunMTU)
	}
	if cfg.ConfigVersion != 2 {
		t.Fatalf("expected default config version 2, got %d", cfg.ConfigVersion)
	}
	if cfg.PersistentErrorThreshold != 3 {
		t.Fatalf("expected default persistent error threshold 3, got %d", cfg.PersistentErrorThreshold)
	}
	if cfg.GeneveOptionsMaxBytes != geneve.MaxOptionsLen {
		t.Fatalf("expected default geneve options max %d, got %d", geneve.MaxOptionsLen, cfg.GeneveOptionsMaxBytes)
	}
	if cfg.GeneveTLVParse {
		t.Fatalf("expected TLV parsing disabled by default")
	}
	if cfg.RoutingMode != RoutingModeOff {
		t.Fatalf("expected routing mode off by default, got %q", cfg.RoutingMode)
	}
	if cfg.TailscaleIface != "tailscale0" {
		t.Fatalf("expected default tailscale iface tailscale0, got %q", cfg.TailscaleIface)
	}
	if cfg.UnderlayIface != "" {
		t.Fatalf("expected no underlay interface while routing is off, got %q", cfg.UnderlayIface)
	}
	if cfg.RoutingTableID != 100 {
		t.Fatalf("expected default routing table id 100, got %d", cfg.RoutingTableID)
	}
	if cfg.RoutingRulePriority != 100 {
		t.Fatalf("expected default routing rule priority 100, got %d", cfg.RoutingRulePriority)
	}
}

func TestAWSProfileConfiguration(t *testing.T) {
	invalid := [][]string{
		{"--udp-bind=:6080", "--metrics-addr=:9090"},
		{"--udp-bind=[::1]:6081", "--metrics-addr=:9090"},
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--vni=1"},
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--persistent-error-threshold=0"},
	}
	for _, args := range invalid {
		if _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", args)
		}
	}

	if _, err := Parse([]string{"--udp-bind=127.0.0.1:6081", "--metrics-addr=:9090", "--vni=0"}); err != nil {
		t.Fatalf("valid explicit AWS profile rejected: %v", err)
	}
}

func TestTLVAllowlistParsing(t *testing.T) {
	cfg, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--geneve-tlv-allowlist=0x0102:0x03,4:5",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.TLVAllowed(geneve.TLVKey{Class: 0x0102, Type: 0x03}) {
		t.Fatalf("expected allowlist to include 0x0102:0x03")
	}
	if !cfg.TLVAllowed(geneve.TLVKey{Class: 4, Type: 5}) {
		t.Fatalf("expected allowlist to include 4:5")
	}
	if cfg.TLVAllowed(geneve.TLVKey{Class: 1, Type: 1}) {
		t.Fatalf("did not expect allowlist to include 1:1")
	}
}

func TestInvalidGeneveOptionConfig(t *testing.T) {
	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--geneve-options-max-bytes=999",
	})
	if err == nil {
		t.Fatalf("expected error for invalid options max bytes")
	}

	_, err = Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--geneve-tlv-allowlist=notvalid",
	})
	if err == nil {
		t.Fatalf("expected error for invalid tlv allowlist entry")
	}

	_, err = Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--geneve-options-max-bytes=250",
	})
	if err == nil {
		t.Fatalf("expected error for non-word-aligned options max")
	}

	_, err = Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--geneve-tlv-allowlist=0x0108:0x80",
	})
	if err == nil {
		t.Fatalf("expected error for type containing the critical bit")
	}
}

func TestRoutingSymmetricRoleConfiguration(t *testing.T) {
	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=eth0",
	})
	if err == nil {
		t.Fatalf("expected error when manage mode has no site cidrs")
	}
	_, err = Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=verify",
		"--underlay-interface=eth0",
	})
	if err == nil {
		t.Fatalf("expected error when verify mode has no site cidrs")
	}

	cfg, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=eth0",
		"--local-site-cidrs=172.16.1.42/16,10.0.0.0/8",
		"--remote-site-cidrs=192.168.0.0/16,100.96.0.0/11",
		"--routing-table-id=123",
		"--routing-rule-priority=321",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RoutingMode != RoutingModeManage {
		t.Fatalf("expected manage mode, got %q", cfg.RoutingMode)
	}
	if got := cfg.EffectiveLocalSiteCIDRs(); len(got) != 2 || got[0] != "172.16.0.0/16" {
		t.Fatalf("unexpected local site cidrs: %v", got)
	}
	if got := cfg.EffectiveRemoteSiteCIDRs(); len(got) != 2 || got[0] != "192.168.0.0/16" {
		t.Fatalf("unexpected remote site cidrs: %v", got)
	}
	if cfg.UnderlayIface != "eth0" {
		t.Fatalf("unexpected underlay interface %q", cfg.UnderlayIface)
	}
}

func TestRoutingSiteEnvironmentInputs(t *testing.T) {
	t.Setenv("ENVELOPE_ROUTING_MODE", "manage")
	t.Setenv("ENVELOPE_UNDERLAY_INTERFACE", "eth0")
	t.Setenv("ENVELOPE_LOCAL_SITE_CIDRS", "10.0.0.0/24")
	t.Setenv("ENVELOPE_REMOTE_SITE_CIDRS", "10.0.1.0/24")
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("parse environment inputs: %v", err)
	}
	if len(cfg.EffectiveLocalSiteCIDRs()) != 1 || len(cfg.EffectiveRemoteSiteCIDRs()) != 1 {
		t.Fatalf("site environment inputs were not independent")
	}
}

func TestRoutingSiteCIDRsMustBePairwiseDisjoint(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		left  string
		right string
	}{
		{name: "local covers remote", flags: []string{"--local-site-cidrs=10.0.0.0/8", "--remote-site-cidrs=10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "same local role overlap", flags: []string{"--local-site-cidrs=10.0.0.0/8,10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "exact remote duplicate", flags: []string{"--remote-site-cidrs=2001:db8::/48,2001:db8::/48"}, left: "2001:db8::/48", right: "2001:db8::/48"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--udp-bind=:6081", "--metrics-addr=:9090"}
			args = append(args, tt.flags...)
			_, err := Parse(args)
			if err == nil {
				t.Fatal("expected overlap error")
			}
			if !strings.Contains(err.Error(), tt.left) || !strings.Contains(err.Error(), tt.right) {
				t.Fatalf("overlap error does not name both values: %v", err)
			}
		})
	}
}

func TestRoutingInterfacesMustBeValidAndDistinct(t *testing.T) {
	tests := [][]string{
		{"--routing-mode=verify"},
		{"--routing-mode=verify", "--underlay-interface=not/a/device"},
		{"--tun-name=shared0", "--tailscale-iface=shared0"},
	}
	for _, flags := range tests {
		args := []string{"--udp-bind=:6081", "--metrics-addr=:9090"}
		args = append(args, flags...)
		if _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", flags)
		}
	}
}

func TestInvalidRoutingConfig(t *testing.T) {
	for _, table := range []string{"0", "52", "253", "254", "255", "256"} {
		_, err := Parse([]string{
			"--udp-bind=:6081",
			"--metrics-addr=:9090",
			"--routing-table-id=" + table,
		})
		if err == nil {
			t.Fatalf("expected error for unsafe routing table id %s", table)
		}
	}

	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-rule-priority=0",
	})
	if err == nil {
		t.Fatalf("expected error for invalid routing rule priority")
	}

	_, err = Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=eth0",
		"--local-site-cidrs=not-a-cidr",
		"--remote-site-cidrs=10.0.0.0/24",
	})
	if err == nil {
		t.Fatalf("expected error for invalid local site cidr")
	}
}

func TestLegacyConfigurationIsRejected(t *testing.T) {
	for _, flag := range []string{
		"--gwlb-return-cidrs=10.0.0.0/24",
		"--local-delivery-cidrs=10.0.0.0/24",
		"--remote-tailnet-cidrs=10.0.0.0/24",
		"--flow-capacity=1",
		"--tcp-flow-timeout=1s",
		"--udp-flow-timeout=1s",
		"--other-flow-timeout=1s",
	} {
		t.Run(flag, func(t *testing.T) {
			if _, err := Parse([]string{flag}); err == nil {
				t.Fatalf("legacy flag %q was accepted", flag)
			}
		})
	}

	for _, name := range []string{
		"ENVELOPE_GWLB_RETURN_CIDRS",
		"ENVELOPE_LOCAL_DELIVERY_CIDRS",
		"ENVELOPE_REMOTE_TAILNET_CIDRS",
		"ENVELOPE_FLOW_CAPACITY",
		"ENVELOPE_TCP_FLOW_TIMEOUT",
		"ENVELOPE_UDP_FLOW_TIMEOUT",
		"ENVELOPE_OTHER_FLOW_TIMEOUT",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "legacy")
			_, err := Parse(nil)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("legacy environment variable %q was not rejected: %v", name, err)
			}
		})
	}
}

func TestConfigVersionMustBeTwo(t *testing.T) {
	_, err := Parse([]string{"--config-version=1"})
	if err == nil || !strings.Contains(err.Error(), "config version") {
		t.Fatalf("unsupported config version was not rejected: %v", err)
	}
}

func TestUDPReceiveCapacityIncludesEveryValidIPv4UDPPayload(t *testing.T) {
	cfg, err := Parse([]string{"--udp-bind=:6081", "--metrics-addr=:9090", "--tun-mtu=1280", "--geneve-options-max-bytes=252"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.MaxUDPReceiveSize(), 65507; got != want {
		t.Fatalf("receive size=%d, want %d", got, want)
	}
	if cfg.MaxUDPReceiveSize() <= cfg.MaxUDPPacketSize() {
		t.Fatalf("receive size=%d does not cover oversized packets above configured maximum=%d", cfg.MaxUDPReceiveSize(), cfg.MaxUDPPacketSize())
	}
}
