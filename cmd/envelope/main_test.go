package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const cliHelpHelperEnv = "ENVELOPE_CLI_HELP_TEST"

func TestParseLevel(t *testing.T) {
	cases := map[string]string{
		"debug": "debug",
		"warn":  "warn",
		"error": "error",
		"info":  "info",
		"":      "info",
		"junk":  "info",
	}
	for input, want := range cases {
		got := parseLevel(input).String()
		if got != want {
			t.Fatalf("level %q -> %q, want %q", input, got, want)
		}
	}
}

func TestNewLogger(t *testing.T) {
	logger := newLogger("debug")
	if logger == nil {
		t.Fatalf("expected logger")
	}
}

func TestVersionString(t *testing.T) {
	oldVersion, oldRevision, oldBuildDate, oldSourceModified := version, revision, buildDate, sourceModified
	t.Cleanup(func() {
		version, revision, buildDate, sourceModified = oldVersion, oldRevision, oldBuildDate, oldSourceModified
	})
	version, revision, buildDate, sourceModified = "1.2.3", "0123456789abcdef", "2026-08-19T00:00:00Z", "false"
	got := versionString()
	for _, want := range []string{"envelope 1.2.3", "revision=0123456789abcdef", "modified=false", "built=2026-08-19T00:00:00Z", "go=go"} {
		if !strings.Contains(got, want) {
			t.Fatalf("versionString()=%q, missing %q", got, want)
		}
	}
}

func TestCLIHelpDescribesPacketReturnTarget(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestCLIHelpHelper$")
	command.Env = append(os.Environ(), cliHelpHelperEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run help helper: %v\n%s", err, output)
	}
	help := strings.ToLower(string(output))
	for _, required := range []string{"aws gwlb packet-return target", "--mode", "packet-return", "--max-inner-packet-size", "--udp-bind", "--metrics-addr"} {
		if !strings.Contains(help, required) {
			t.Fatalf("CLI help missing %q:\n%s", required, output)
		}
	}
	for _, obsolete := range []string{
		"geneve <-> tun", "--tun-name", "--tun-mtu", "--tailscale-iface", "--underlay-interface",
		"--routing-mode", "--routing-table-id", "--routing-rule-priority", "--local-site-cidrs", "--remote-site-cidrs",
		"--gwlb-return-cidrs", "--local-delivery-cidrs", "--remote-tailnet-cidrs", "--flow-capacity", "--tcp-flow-timeout",
		"--protected-cidrs", "--flow-timeout",
	} {
		if strings.Contains(help, obsolete) {
			t.Fatalf("CLI help retained obsolete text %q:\n%s", obsolete, output)
		}
	}
}

func TestCLIHelpHelper(t *testing.T) {
	if os.Getenv(cliHelpHelperEnv) != "1" {
		return
	}
	os.Args = []string{"envelope", "--help"}
	main()
}
