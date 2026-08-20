package geneve

import (
	"bytes"
	"errors"
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
	options := []byte{0x01, 0x08, 0x83, 0x01, 0xde, 0xad, 0xbe, 0xef}
	hdr := Header{VNI: 0x010203, Options: options, Critical: true, OAM: true}
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
	if !decoded.Critical {
		t.Fatalf("expected base critical bit")
	}
	if !decoded.OAM || decoded.FixedFlags() != FlagOAM|FlagCritical {
		t.Fatalf("fixed flags were not retained: %#x", decoded.FixedFlags())
	}
}

func TestEncodeInvalidOptions(t *testing.T) {
	buf := make([]byte, 64)
	_, err := Encode(buf, Header{VNI: 1, Options: []byte{0x01, 0x02}}, []byte{0x45})
	if err == nil {
		t.Fatalf("expected error for invalid options length")
	}
}

func TestFixedReservedBitsIgnoredAndZeroed(t *testing.T) {
	packet := []byte{0, 0x3f, 0x08, 0x00, 0, 0, 0, 0xff, 0x45}
	header, payload, err := Decode(packet)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if header.FixedFlags() != 0 {
		t.Fatalf("reserved flags leaked into header: %#x", header.FixedFlags())
	}
	encoded := make([]byte, 32)
	n, err := Encode(encoded, header, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[1] != 0 || encoded[7] != 0 {
		t.Fatalf("reserved bytes were not zeroed: %x", encoded[:n])
	}
}

func TestDecodeOversizedHeader(t *testing.T) {
	pkt := make([]byte, BaseHeaderLen)
	pkt[0] = byte((Version << 6) | 1) // claims 4 bytes of options
	_, _, err := Decode(pkt)
	if !errors.Is(err, ErrOptionsStructure) {
		t.Fatalf("got %v, want options structure error", err)
	}
}
