package main

import (
	"strings"
	"testing"
)

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
