package main

import "testing"

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
