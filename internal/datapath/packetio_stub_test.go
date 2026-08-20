//go:build !linux

package datapath

import (
	"errors"
	"testing"
)

func TestProductionPacketIOHasNoNonLinuxFallback(t *testing.T) {
	if _, err := newPacketReceiver(":6081"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("receiver error = %v, want unsupported platform", err)
	}
	if _, err := newPacketSender(1500); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("sender error = %v, want unsupported platform", err)
	}
}
