//go:build !linux

package tun

import "testing"

func TestStubDevice(t *testing.T) {
	dev, err := Open("envtest", 1400)
	if err == nil || dev != nil {
		t.Fatalf("expected error on non-linux")
	}

	var d Device
	if _, err := d.Read(make([]byte, 4)); err == nil {
		t.Fatalf("expected read error")
	}
	if _, err := d.Write([]byte{0x01}); err == nil {
		t.Fatalf("expected write error")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}
