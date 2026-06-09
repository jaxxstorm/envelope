//go:build linux && integration

package tun

import (
	"os"
	"testing"
)

func TestOpenTun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dev, err := Open("envtest1", 1400)
	if err != nil {
		t.Fatalf("open tun: %v", err)
	}
	defer dev.Close()
	if dev.Name == "" {
		t.Fatalf("expected device name")
	}
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	if _, err := dev.Write(packet); err != nil {
		t.Fatalf("write tun: %v", err)
	}
}
