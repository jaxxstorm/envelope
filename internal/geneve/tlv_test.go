package geneve

import "testing"

func TestValidateOptions(t *testing.T) {
	if err := ValidateOptions([]byte{0x01, 0x02}, MaxOptionsLen); err == nil {
		t.Fatalf("expected error for non-4-byte options length")
	}
	if err := ValidateOptions(make([]byte, 8), 4); err == nil {
		t.Fatalf("expected error for oversized options")
	}
	if err := ValidateOptions(make([]byte, 4), MaxOptionsLen); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseTLVs(t *testing.T) {
	options := []byte{
		0x01, 0x02, 0x03, 0x01,
		0xde, 0xad, 0xbe, 0xef,
		0x04, 0x05, 0x06, 0x00,
	}
	tlvs, err := ParseTLVs(options)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("expected 2 tlvs, got %d", len(tlvs))
	}
	if tlvs[0].Class != 0x0102 || tlvs[0].Type != 0x03 || tlvs[0].Length != 4 {
		t.Fatalf("unexpected tlv[0] header: %+v", tlvs[0])
	}
	if len(tlvs[0].Data) != 4 {
		t.Fatalf("unexpected tlv[0] data length: %d", len(tlvs[0].Data))
	}
	if tlvs[1].Class != 0x0405 || tlvs[1].Type != 0x06 || tlvs[1].Length != 0 {
		t.Fatalf("unexpected tlv[1] header: %+v", tlvs[1])
	}
	if len(tlvs[1].Data) != 0 {
		t.Fatalf("expected empty tlv[1] data")
	}
}

func TestParseTLVsInvalidLength(t *testing.T) {
	options := []byte{0x01, 0x02, 0x03, 0x02}
	if _, err := ParseTLVs(options); err == nil {
		t.Fatalf("expected error for invalid tlv length")
	}
}
