package config

import (
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
	if cfg.FlowTimeout == 0 {
		t.Fatalf("expected default flow timeout")
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
	if cfg.RoutingTableID != 100 {
		t.Fatalf("expected default routing table id 100, got %d", cfg.RoutingTableID)
	}
	if cfg.RoutingRulePriority != 100 {
		t.Fatalf("expected default routing rule priority 100, got %d", cfg.RoutingRulePriority)
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
}

func TestRoutingManageModeRequiresProtectedCIDRs(t *testing.T) {
	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
	})
	if err == nil {
		t.Fatalf("expected error when manage mode has no protected cidrs")
	}

	cfg, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--protected-cidrs=172.16.0.0/16,10.0.0.0/8",
		"--routing-table-id=123",
		"--routing-rule-priority=321",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RoutingMode != RoutingModeManage {
		t.Fatalf("expected manage mode, got %q", cfg.RoutingMode)
	}
	if got := cfg.EffectiveProtectedCIDRs(); len(got) != 2 {
		t.Fatalf("expected 2 protected cidrs, got %d", len(got))
	}
}

func TestInvalidRoutingConfig(t *testing.T) {
	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-table-id=0",
	})
	if err == nil {
		t.Fatalf("expected error for invalid routing table id")
	}

	_, err = Parse([]string{
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
		"--protected-cidrs=not-a-cidr",
	})
	if err == nil {
		t.Fatalf("expected error for invalid protected cidr")
	}
}
