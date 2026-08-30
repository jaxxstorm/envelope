package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jaxxstorm/envelope/internal/geneve"
)

func TestParseTargetDefaultsAndValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--udp-bind="},
		{"--max-inner-packet-size=0"},
		{"--max-inner-packet-size=65507"},
		{"--vni=20000000"},
	} {
		if _, err := ParseTarget(args); err == nil {
			t.Fatalf("ParseTarget(%v) unexpectedly succeeded", args)
		}
	}

	cfg, err := ParseTarget(nil)
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if cfg.ConfigVersion != 2 {
		t.Fatalf("config version = %d, want 2", cfg.ConfigVersion)
	}
	if cfg.Mode != "packet-return" {
		t.Fatalf("mode = %q, want packet-return", cfg.Mode)
	}
	if cfg.UDPBind != ":6081" {
		t.Fatalf("UDP bind = %q, want :6081", cfg.UDPBind)
	}
	if cfg.MaxInnerPacketSize != 1280 {
		t.Fatalf("max inner packet size = %d, want 1280", cfg.MaxInnerPacketSize)
	}
	if cfg.PersistentErrorThreshold != 3 {
		t.Fatalf("persistent error threshold = %d, want 3", cfg.PersistentErrorThreshold)
	}
	if cfg.GeneveOptionsMaxBytes != geneve.MaxOptionsLen {
		t.Fatalf("GENEVE options maximum = %d, want %d", cfg.GeneveOptionsMaxBytes, geneve.MaxOptionsLen)
	}
}

func TestPacketReturnModeCLIAndEnvironment(t *testing.T) {
	if cfg, err := ParseTarget([]string{"--mode=packet-return"}); err != nil || cfg.Mode != "packet-return" {
		t.Fatalf("explicit packet-return CLI mode: cfg=%v err=%v", cfg, err)
	}
	if _, err := ParseTarget([]string{"--mode=direct-forward"}); err == nil {
		t.Fatal("obsolete target mode unexpectedly accepted")
	}

	t.Setenv("ENVELOPE_MODE", "packet-return")
	if cfg, err := ParseTarget(nil); err != nil || cfg.Mode != "packet-return" {
		t.Fatalf("packet-return environment mode: cfg=%v err=%v", cfg, err)
	}
	t.Setenv("ENVELOPE_MODE", "direct-forward")
	if _, err := ParseTarget(nil); err == nil {
		t.Fatal("unsupported environment mode unexpectedly accepted")
	}
}

func TestMaxInnerPacketSizeEnvironment(t *testing.T) {
	t.Setenv("ENVELOPE_MAX_INNER_PACKET_SIZE", "1400")
	cfg, err := ParseTarget(nil)
	if err != nil {
		t.Fatalf("parse max inner packet size: %v", err)
	}
	if cfg.MaxInnerPacketSize != 1400 {
		t.Fatalf("max inner packet size = %d, want 1400", cfg.MaxInnerPacketSize)
	}
}

func TestAWSProfileConfiguration(t *testing.T) {
	invalid := [][]string{
		{"--udp-bind=:6080"},
		{"--udp-bind=[::1]:6081"},
		{"--vni=1"},
		{"--persistent-error-threshold=0"},
	}
	for _, args := range invalid {
		if _, err := ParseTarget(args); err == nil {
			t.Fatalf("ParseTarget(%v) unexpectedly succeeded", args)
		}
	}

	if _, err := ParseTarget([]string{"--udp-bind=127.0.0.1:6081", "--vni=0"}); err != nil {
		t.Fatalf("valid explicit AWS profile rejected: %v", err)
	}
}

func TestTLVAllowlistParsing(t *testing.T) {
	cfg, err := ParseTarget([]string{"--geneve-tlv-allowlist=0x0102:0x03,4:5"})
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	if !cfg.TLVAllowed(geneve.TLVKey{Class: 0x0102, Type: 0x03}) || !cfg.TLVAllowed(geneve.TLVKey{Class: 4, Type: 5}) {
		t.Fatal("configured TLV allowlist entries are missing")
	}
	if cfg.TLVAllowed(geneve.TLVKey{Class: 1, Type: 1}) {
		t.Fatal("unexpected TLV allowlist entry")
	}
}

func TestInvalidGeneveOptionConfig(t *testing.T) {
	for _, args := range [][]string{
		{"--geneve-options-max-bytes=0"},
		{"--geneve-options-max-bytes=4"},
		{"--geneve-options-max-bytes=999"},
		{"--geneve-options-max-bytes=250"},
		{"--geneve-tlv-allowlist=notvalid"},
		{"--geneve-tlv-allowlist=0x0108:0x80"},
	} {
		if _, err := ParseTarget(args); err == nil {
			t.Fatalf("ParseTarget(%v) unexpectedly succeeded", args)
		}
	}
}

func TestGeneveOptionsMaximumFitsMinimumAWSFlowCookieTLV(t *testing.T) {
	cfg, err := ParseTarget([]string{"--geneve-options-max-bytes=8"})
	if err != nil {
		t.Fatalf("minimum flow-cookie option capacity rejected: %v", err)
	}
	if cfg.GeneveOptionsMaxBytes != 8 {
		t.Fatalf("GENEVE options maximum = %d, want 8", cfg.GeneveOptionsMaxBytes)
	}

	_, err = ParseTarget([]string{"--geneve-options-max-bytes=4"})
	if err == nil || !strings.Contains(err.Error(), ">= 8") || !strings.Contains(err.Error(), "flow-cookie TLV") {
		t.Fatalf("undersized flow-cookie capacity was not clearly rejected: %v", err)
	}
}

func TestProductionTargetRejectsObsoleteFlags(t *testing.T) {
	flags := []string{
		"--tun-name=envelope0",
		"--tun-mtu=1280",
		"--tailscale-iface=tailscale0",
		"--underlay-interface=eth0",
		"--routing-mode=off",
		"--routing-table-id=100",
		"--routing-rule-priority=100",
		"--local-site-cidrs=10.0.0.0/24",
		"--remote-site-cidrs=10.0.1.0/24",
		"--gwlb-return-cidrs=10.0.0.0/24",
		"--local-delivery-cidrs=10.0.0.0/24",
		"--remote-tailnet-cidrs=10.0.0.0/24",
		"--flow-capacity=1",
		"--tcp-flow-timeout=1s",
		"--udp-flow-timeout=1s",
		"--other-flow-timeout=1s",
		"--protected-cidrs=10.0.0.0/24",
		"--flow-timeout=1m",
	}
	for _, flag := range flags {
		t.Run(flag, func(t *testing.T) {
			_, err := ParseTarget([]string{flag})
			if err == nil || !strings.Contains(err.Error(), strings.SplitN(flag, "=", 2)[0]) || !strings.Contains(err.Error(), "obsolete") {
				t.Fatalf("obsolete flag %q was not clearly rejected: %v", flag, err)
			}
		})
	}

	_, err := ParseTarget([]string{"--tun-name", "envelope0"})
	if err == nil || !strings.Contains(err.Error(), "--tun-name") {
		t.Fatalf("split obsolete flag was not rejected: %v", err)
	}
}

func TestProductionTargetRejectsObsoleteEnvironment(t *testing.T) {
	names := []string{
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
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "obsolete")
			_, err := ParseTarget(nil)
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "obsolete") {
				t.Fatalf("obsolete environment variable %q was not clearly rejected: %v", name, err)
			}
		})
	}
}

func TestObsoleteInputsAreRejectedBeforeCurrentParsing(t *testing.T) {
	_, err := ParseTarget([]string{"--tun-name=envelope0", "--not-a-current-flag"})
	if err == nil || !strings.Contains(err.Error(), "--tun-name") || strings.Contains(err.Error(), "not-a-current-flag") {
		t.Fatalf("obsolete flag was not rejected first: %v", err)
	}

	t.Setenv("ENVELOPE_FLOW_CAPACITY", "1")
	_, err = ParseTarget([]string{"--udp-bind=:6080"})
	if err == nil || !strings.Contains(err.Error(), "ENVELOPE_FLOW_CAPACITY") || strings.Contains(err.Error(), "udp bind") {
		t.Fatalf("obsolete environment was not rejected first: %v", err)
	}
}

func TestPacketReturnConfigHasNoObsoleteFields(t *testing.T) {
	typeOfConfig := reflect.TypeOf(Config{})
	for _, name := range []string{
		"TunName",
		"TunMTU",
		"TailscaleIface",
		"UnderlayIface",
		"RoutingMode",
		"LocalSiteCIDRs",
		"RemoteSiteCIDRs",
		"RoutingTableID",
		"RoutingRulePriority",
		"GWLBReturnCIDRs",
		"LocalDeliveryCIDRs",
		"RemoteTailnetCIDRs",
		"FlowCapacity",
		"TCPFlowTimeout",
		"UDPFlowTimeout",
		"OtherFlowTimeout",
		"ProtectedCIDRs",
		"FlowTimeout",
	} {
		if _, found := typeOfConfig.FieldByName(name); found {
			t.Fatalf("packet-return Config retained obsolete field %s", name)
		}
	}
}

func TestConfigVersionMustBeTwo(t *testing.T) {
	_, err := ParseTarget([]string{"--config-version=1"})
	if err == nil || !strings.Contains(err.Error(), "config version") {
		t.Fatalf("unsupported config version was not rejected: %v", err)
	}
}

func TestUDPReceiveCapacityIncludesOversizedDatagrams(t *testing.T) {
	cfg, err := ParseTarget([]string{"--max-inner-packet-size=1280", "--geneve-options-max-bytes=252"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.MaxUDPReceiveSize(), 65507; got != want {
		t.Fatalf("receive size = %d, want %d", got, want)
	}
	if cfg.MaxUDPReceiveSize() <= cfg.MaxUDPPacketSize() {
		t.Fatalf("receive size %d does not cover packets above configured maximum %d", cfg.MaxUDPReceiveSize(), cfg.MaxUDPPacketSize())
	}
}
