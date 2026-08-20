package geneve

import (
	"bytes"
	"errors"
	"testing"
)

var (
	testVPCEID      = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	testAttachment  = []byte{0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28}
	testFlowCookie  = []byte{0xde, 0xad, 0xbe, 0xef}
	validationSink  OptionMetadata
	validationError error
)

func testTLV(class uint16, rawType, reserved uint8, data []byte) []byte {
	if len(data)%4 != 0 || reserved > 7 {
		panic("invalid test TLV")
	}
	tlv := make([]byte, 4+len(data))
	tlv[0] = byte(class >> 8)
	tlv[1] = byte(class)
	tlv[2] = rawType
	tlv[3] = reserved<<5 | uint8(len(data)/4)
	copy(tlv[4:], data)
	return tlv
}

func testOptions(tlvs ...[]byte) []byte {
	var options []byte
	for _, tlv := range tlvs {
		options = append(options, tlv...)
	}
	return options
}

func TestTLVIteratorUsesLowFiveLengthBits(t *testing.T) {
	options := testOptions(
		testTLV(AWSOptionClass, AWSOptionTypeVPCE, 5, testVPCEID),
		testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie),
	)
	original := append([]byte(nil), options...)

	it := NewTLVIterator(options)
	if !it.Next() {
		t.Fatalf("expected first TLV: %v", it.Err())
	}
	first := it.TLV()
	if first.Class != AWSOptionClass || first.Type != AWSOptionTypeVPCE {
		t.Fatalf("unexpected first TLV: %+v", first)
	}
	if first.Critical || first.Reserved != 5 || first.Length != AWSVPCEIDLength {
		t.Fatalf("unexpected first TLV flags/length: %+v", first)
	}
	if !bytes.Equal(first.Data, testVPCEID) {
		t.Fatalf("unexpected first TLV data: %x", first.Data)
	}
	if !it.Next() || it.TLV().Type != AWSOptionTypeFlowCookie {
		t.Fatalf("expected flow-cookie TLV: %v", it.Err())
	}
	if it.Next() || it.Err() != nil {
		t.Fatalf("unexpected iterator completion error: %v", it.Err())
	}
	if !bytes.Equal(options, original) {
		t.Fatalf("iterator mutated options: got %x want %x", options, original)
	}

	metadata, err := ValidateOptions(options, MaxOptionsLen, false)
	if err != nil {
		t.Fatalf("reserved bits should be tolerated on receive: %v", err)
	}
	if !metadata.AWSProfile || !metadata.HasFlowCookie || !bytes.Equal(metadata.FlowCookie[:], testFlowCookie) {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestTLVIteratorRejectsMalformedBounds(t *testing.T) {
	cases := []struct {
		name    string
		options []byte
	}{
		{name: "short header", options: []byte{0x01, 0x08}},
		{name: "length beyond block", options: []byte{0x01, 0x08, 0x03, 0x02}},
		{name: "trailing header fragment", options: []byte{0x12, 0x34, 0x01, 0x00, 0xaa, 0xbb}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateOptions(tc.options, MaxOptionsLen, false)
			if !errors.Is(err, ErrOptionsStructure) {
				t.Fatalf("got %v, want structural error", err)
			}
		})
	}
}

func TestTLVCriticalSemantics(t *testing.T) {
	cookie := testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie)
	criticalCookie := testTLV(AWSOptionClass, OptionTypeCriticalMask|AWSOptionTypeFlowCookie, 0, testFlowCookie)
	unknown := testTLV(0x2222, 0x7e, 0, nil)
	unknownCritical := testTLV(0x2222, OptionTypeCriticalMask|0x7e, 0, nil)

	cases := []struct {
		name         string
		options      []byte
		baseCritical bool
		wantErr      bool
	}{
		{name: "unknown non-critical", options: unknown},
		{name: "known critical", options: criticalCookie, baseCritical: true},
		{name: "critical option without base bit", options: criticalCookie, wantErr: true},
		{name: "base bit without critical option", options: cookie, baseCritical: true, wantErr: true},
		{name: "unknown critical", options: unknownCritical, baseCritical: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateOptions(tc.options, MaxOptionsLen, tc.baseCritical)
			if tc.wantErr && !errors.Is(err, ErrCriticalOptions) {
				t.Fatalf("got %v, want critical error", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAWSOptionValidation(t *testing.T) {
	vpce := testTLV(AWSOptionClass, AWSOptionTypeVPCE, 0, testVPCEID)
	attachment := testTLV(AWSOptionClass, AWSOptionTypeAttachment, 0, testAttachment)
	cookie := testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie)
	unknown := testTLV(AWSOptionClass, 0x7e, 0, []byte{1, 2, 3, 4})

	cases := []struct {
		name    string
		options []byte
		wantErr error
	}{
		{name: "VPCE and cookie", options: testOptions(vpce, cookie)},
		{name: "attachment and cookie", options: testOptions(attachment, cookie)},
		{name: "reordered with future option", options: testOptions(cookie, unknown, attachment, vpce)},
		{name: "VPCE wrong length", options: testOptions(testTLV(AWSOptionClass, AWSOptionTypeVPCE, 0, testVPCEID[:4]), cookie), wantErr: ErrAWSOptionLength},
		{name: "attachment wrong length", options: testOptions(testTLV(AWSOptionClass, AWSOptionTypeAttachment, 0, testAttachment[:4]), cookie), wantErr: ErrAWSOptionLength},
		{name: "cookie wrong length", options: testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, append(testFlowCookie, testFlowCookie...)), wantErr: ErrAWSOptionLength},
		{name: "missing cookie", options: vpce, wantErr: ErrAWSOptionCardinality},
		{name: "future option missing cookie", options: unknown, wantErr: ErrAWSOptionCardinality},
		{name: "duplicate cookie", options: testOptions(cookie, cookie), wantErr: ErrAWSOptionCardinality},
		{name: "duplicate VPCE", options: testOptions(vpce, cookie, vpce), wantErr: ErrAWSOptionCardinality},
		{name: "duplicate attachment", options: testOptions(attachment, cookie, attachment), wantErr: ErrAWSOptionCardinality},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := ValidateOptions(tc.options, MaxOptionsLen, false)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !metadata.AWSProfile || !metadata.HasFlowCookie {
				t.Fatalf("missing AWS metadata: %+v", metadata)
			}
			if !bytes.Equal(metadata.FlowCookie[:], testFlowCookie) {
				t.Fatalf("flow cookie mismatch: got %x", metadata.FlowCookie)
			}
		})
	}
}

func TestTLVValidationSize(t *testing.T) {
	options := testTLV(0x1234, 1, 0, []byte{1, 2, 3, 4})
	if _, err := ValidateOptions(options, 4, false); !errors.Is(err, ErrOptionsSize) {
		t.Fatalf("got %v, want size error", err)
	}
	if _, err := ValidateOptions(options, 6, false); !errors.Is(err, ErrOptionsSize) {
		t.Fatalf("got %v, want invalid-maximum size error", err)
	}
}

func TestTLVValidationAllocations(t *testing.T) {
	options := testOptions(
		testTLV(AWSOptionClass, AWSOptionTypeVPCE, 0, testVPCEID),
		testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie),
	)
	allocs := testing.AllocsPerRun(1000, func() {
		validationSink, validationError = ValidateOptions(options, MaxOptionsLen, false)
	})
	if validationError != nil {
		t.Fatalf("validation failed: %v", validationError)
	}
	if allocs != 0 {
		t.Fatalf("validation allocated %.2f objects per call, want 0", allocs)
	}
}

func TestValidateAWSProfile(t *testing.T) {
	cookie := testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie)
	ipv4 := []byte{0x45}
	cases := []struct {
		name    string
		header  Header
		payload []byte
		wantErr error
	}{
		{name: "valid", header: Header{Protocol: ProtoIPv4, Options: cookie}, payload: ipv4},
		{name: "valid IPv6", header: Header{Protocol: ProtoIPv6, Options: cookie}, payload: []byte{0x60}},
		{name: "nonzero VNI", header: Header{VNI: 1, Protocol: ProtoIPv4, Options: cookie}, payload: ipv4, wantErr: ErrAWSVNI},
		{name: "OAM", header: Header{Protocol: ProtoIPv4, Options: cookie, OAM: true}, payload: ipv4, wantErr: ErrAWSOAM},
		{name: "missing cookie", header: Header{Protocol: ProtoIPv4}, payload: ipv4, wantErr: ErrAWSOptionCardinality},
		{name: "reserved option bits", header: Header{Protocol: ProtoIPv4, Options: testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 1, testFlowCookie)}, payload: ipv4, wantErr: ErrAWSOptionReserved},
		{name: "protocol mismatch", header: Header{Protocol: ProtoIPv6, Options: cookie}, payload: ipv4, wantErr: ErrProtocolMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateAWSProfile(tc.header, tc.payload, MaxOptionsLen)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func BenchmarkTLVValidationLoggingDisabled(b *testing.B) {
	options := testOptions(
		testTLV(AWSOptionClass, AWSOptionTypeVPCE, 0, testVPCEID),
		testTLV(AWSOptionClass, AWSOptionTypeAttachment, 0, testAttachment),
		testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie),
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(options)))
	b.ResetTimer()
	for range b.N {
		validationSink, validationError = ValidateOptions(options, MaxOptionsLen, false)
	}
	if validationError != nil {
		b.Fatal(validationError)
	}
}
