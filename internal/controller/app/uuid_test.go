package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRandomUUIDSourceProducesBoundedVersion4IDs(t *testing.T) {
	input := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	source := NewRandomUUIDSource(bytes.NewReader(input))
	first := source.NewUUID()
	second := source.NewUUID()
	if len(first) != 36 || len(second) != 36 || first == second {
		t.Fatalf("UUIDs = %q and %q", first, second)
	}
	if first[14] != '4' || !strings.Contains("89ab", string(first[19])) {
		t.Fatalf("UUID does not have version 4 and RFC 4122 variant bits: %q", first)
	}
}

func TestRandomUUIDSourceFailsClosedOnEntropyError(t *testing.T) {
	source := NewRandomUUIDSource(errorReader{})
	if got := source.NewUUID(); got != "" {
		t.Fatalf("UUID after entropy error = %q, want empty", got)
	}
	var nilSource *RandomUUIDSource
	if got := nilSource.NewUUID(); got != "" {
		t.Fatalf("nil UUID source = %q, want empty", got)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
