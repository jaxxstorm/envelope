package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const controllerCLIHelpEnv = "ENVELOPE_CONTROLLER_CLI_HELP_TEST"

func TestControllerParseLevel(t *testing.T) {
	for input, want := range map[string]string{
		"debug": "debug",
		"info":  "info",
		"warn":  "warn",
		"error": "error",
		"":      "info",
		"other": "info",
	} {
		if got := parseLevel(input).String(); got != want {
			t.Errorf("parseLevel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestControllerProductionLogger(t *testing.T) {
	logger := newLogger("debug")
	if logger == nil || !logger.Core().Enabled(parseLevel("debug")) {
		t.Fatal("debug production logger was not enabled")
	}
	_ = logger.Sync()
}

func TestControllerVersionString(t *testing.T) {
	oldVersion, oldRevision, oldBuildDate, oldSourceModified := version, revision, buildDate, sourceModified
	t.Cleanup(func() {
		version, revision, buildDate, sourceModified = oldVersion, oldRevision, oldBuildDate, oldSourceModified
	})
	version, revision, buildDate, sourceModified = "1.2.3", "0123456789abcdef", "2026-09-04T00:00:00Z", "false"
	got := versionString()
	for _, expected := range []string{
		"envelope-controller 1.2.3",
		"revision=0123456789abcdef",
		"modified=false",
		"built=2026-09-04T00:00:00Z",
		"go=go",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("versionString() = %q, missing %q", got, expected)
		}
	}
}

func TestControllerCLIHelpIsStandalone(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestControllerCLIHelpHelper$")
	command.Env = append(os.Environ(), controllerCLIHelpEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("help subprocess: %v\n%s", err, output)
	}
	help := strings.ToLower(string(output))
	for _, required := range []string{
		"autonomous production failover controller",
		"--controller-id",
		"--topology",
		"--metrics-addr",
		"--log-level",
		"--read-only",
		"--dry-run",
	} {
		if !strings.Contains(help, required) {
			t.Errorf("help missing %q:\n%s", required, output)
		}
	}
	for _, forbidden := range []string{"--udp-bind", "--vni", "packet-return target", "--tun-name"} {
		if strings.Contains(help, forbidden) {
			t.Errorf("standalone help contains packet-target option %q:\n%s", forbidden, output)
		}
	}
}

func TestControllerCLIHelpHelper(t *testing.T) {
	if os.Getenv(controllerCLIHelpEnv) != "1" {
		return
	}
	os.Args = []string{"envelope-controller", "--help"}
	main()
}
