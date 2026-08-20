package config

import (
	"strings"
	"testing"
	"time"

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
	if cfg.FlowCapacity != 65536 {
		t.Fatalf("expected default flow capacity 65536, got %d", cfg.FlowCapacity)
	}
	if cfg.TCPFlowTimeout != 350*time.Second {
		t.Fatalf("expected default TCP timeout 350s, got %s", cfg.TCPFlowTimeout)
	}
	if cfg.UDPFlowTimeout != 120*time.Second || cfg.OtherFlowTimeout != 120*time.Second {
		t.Fatalf("expected default UDP/other timeout 120s, got %s/%s", cfg.UDPFlowTimeout, cfg.OtherFlowTimeout)
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
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--flow-capacity=0"},
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--tcp-flow-timeout=0s"},
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--udp-flow-timeout=0s"},
		{"--udp-bind=:6081", "--metrics-addr=:9090", "--other-flow-timeout=0s"},
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

func TestRoutingDirectionalRoleConfiguration(t *testing.T) {
	_, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=eth0",
	})
	if err == nil {
		t.Fatalf("expected error when manage mode has no GWLB return cidrs")
	}

	cfg, err := Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=eth0",
		"--gwlb-return-cidrs=172.16.0.0/16,10.0.0.0/8",
		"--local-delivery-cidrs=192.168.0.0/16",
		"--remote-tailnet-cidrs=100.96.0.0/11",
		"--routing-table-id=123",
		"--routing-rule-priority=321",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RoutingMode != RoutingModeManage {
		t.Fatalf("expected manage mode, got %q", cfg.RoutingMode)
	}
	if got := cfg.EffectiveGWLBReturnCIDRs(); len(got) != 2 {
		t.Fatalf("expected 2 GWLB return cidrs, got %d", len(got))
	}
	if got := cfg.EffectiveLocalDeliveryCIDRs(); len(got) != 1 || got[0] != "192.168.0.0/16" {
		t.Fatalf("unexpected local delivery cidrs: %v", got)
	}
	if got := cfg.EffectiveRemoteTailnetCIDRs(); len(got) != 1 || got[0] != "100.96.0.0/11" {
		t.Fatalf("unexpected remote tailnet cidrs: %v", got)
	}
	if cfg.UnderlayIface != "eth0" {
		t.Fatalf("unexpected underlay interface %q", cfg.UnderlayIface)
	}
}

func TestRoutingRoleEnvironmentInputs(t *testing.T) {
	t.Setenv("ENVELOPE_ROUTING_MODE", "manage")
	t.Setenv("ENVELOPE_UNDERLAY_INTERFACE", "eth0")
	t.Setenv("ENVELOPE_GWLB_RETURN_CIDRS", "10.0.0.0/24")
	t.Setenv("ENVELOPE_LOCAL_DELIVERY_CIDRS", "10.0.1.0/24")
	t.Setenv("ENVELOPE_REMOTE_TAILNET_CIDRS", "10.0.2.0/24")
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("parse environment inputs: %v", err)
	}
	if len(cfg.EffectiveGWLBReturnCIDRs()) != 1 || len(cfg.EffectiveLocalDeliveryCIDRs()) != 1 || len(cfg.EffectiveRemoteTailnetCIDRs()) != 1 {
		t.Fatalf("directional role environment inputs were not independent")
	}
}

func TestRoutingCIDRRolesMustBePairwiseDisjoint(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		left  string
		right string
	}{
		{name: "return covers delivery", flags: []string{"--gwlb-return-cidrs=10.0.0.0/8", "--local-delivery-cidrs=10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "delivery covers remote", flags: []string{"--local-delivery-cidrs=10.0.0.0/8", "--remote-tailnet-cidrs=10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "remote covers return", flags: []string{"--remote-tailnet-cidrs=10.0.0.0/8", "--gwlb-return-cidrs=10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "same role overlap", flags: []string{"--gwlb-return-cidrs=10.0.0.0/8,10.1.0.0/16"}, left: "10.0.0.0/8", right: "10.1.0.0/16"},
		{name: "exact duplicate", flags: []string{"--remote-tailnet-cidrs=2001:db8::/48,2001:db8::/48"}, left: "2001:db8::/48", right: "2001:db8::/48"},
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
		"--gwlb-return-cidrs=not-a-cidr",
	})
	if err == nil {
		t.Fatalf("expected error for invalid GWLB return cidr")
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
