package geneve

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeMinimal(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	hdr := Header{VNI: 0x112233}
	buf := make([]byte, 64)
	n, err := Encode(buf, hdr, payload)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, pl, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.VNI != hdr.VNI {
		t.Fatalf("unexpected VNI: %x", decoded.VNI)
	}
	if len(decoded.Options) != 0 {
		t.Fatalf("expected no options")
	}
	if !bytes.Equal(pl, payload) {
		t.Fatalf("payload mismatch")
	}
	if decoded.Protocol != ProtoIPv4 {
		t.Fatalf("unexpected protocol: %x", decoded.Protocol)
	}
}

func TestEncodeDecodeOptions(t *testing.T) {
	payload := []byte{0x60, 0x00, 0x00, 0x00}
	options := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	hdr := Header{VNI: 0x010203, Options: options}
	buf := make([]byte, 128)
	n, err := Encode(buf, hdr, payload)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, pl, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.VNI != hdr.VNI {
		t.Fatalf("unexpected VNI: %x", decoded.VNI)
	}
	if !bytes.Equal(decoded.Options, options) {
		t.Fatalf("options mismatch")
	}
	if !bytes.Equal(pl, payload) {
		t.Fatalf("payload mismatch")
	}
	if decoded.Protocol != ProtoIPv6 {
		t.Fatalf("unexpected protocol: %x", decoded.Protocol)
	}
}

func TestEncodeInvalidOptions(t *testing.T) {
	buf := make([]byte, 64)
	_, err := Encode(buf, Header{VNI: 1, Options: []byte{0x01, 0x02}}, []byte{0x45})
	if err == nil {
		t.Fatalf("expected error for invalid options length")
	}
}

func TestDecodeOversizedHeader(t *testing.T) {
	pkt := make([]byte, BaseHeaderLen)
	pkt[0] = byte((Version << 6) | 1) // claims 4 bytes of options
	_, _, err := Decode(pkt)
	if err == nil {
		t.Fatalf("expected error for short packet")
	}
}
