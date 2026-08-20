package geneve

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestPCAPFixtures(t *testing.T) {
	vpce := testTLV(AWSOptionClass, AWSOptionTypeVPCE, 0, testVPCEID)
	attachment := testTLV(AWSOptionClass, AWSOptionTypeAttachment, 0, testAttachment)
	cookie := testTLV(AWSOptionClass, AWSOptionTypeFlowCookie, 0, testFlowCookie)
	future := testTLV(AWSOptionClass, 0x7e, 0, []byte{1, 2, 3, 4})

	cases := []struct {
		name        string
		max         int
		decodeError bool
		wantError   error
		wantOptions []byte
	}{
		{name: "geneve-minimal.pcap"},
		{name: "geneve-options.pcap", wantOptions: testOptions(vpce, cookie)},
		{name: "geneve-options-reordered.pcap", wantOptions: testOptions(cookie, attachment, future, vpce)},
		{name: "geneve-options-reserved.pcap", wantOptions: testOptions(testTLV(AWSOptionClass, AWSOptionTypeVPCE, 5, testVPCEID), cookie)},
		{name: "geneve-options-known-critical.pcap", wantOptions: testOptions(vpce, testTLV(AWSOptionClass, OptionTypeCriticalMask|AWSOptionTypeFlowCookie, 0, testFlowCookie))},
		{name: "geneve-options-unknown-noncritical.pcap", wantOptions: testOptions(vpce, future, cookie)},
		{name: "geneve-options-malformed.pcap", wantError: ErrOptionsStructure},
		{name: "geneve-options-aws-length.pcap", wantError: ErrAWSOptionLength},
		{name: "geneve-options-missing-cookie.pcap", wantError: ErrAWSOptionCardinality},
		{name: "geneve-options-duplicate-cookie.pcap", wantError: ErrAWSOptionCardinality},
		{name: "geneve-options-duplicate-vpce.pcap", wantError: ErrAWSOptionCardinality},
		{name: "geneve-options-unknown-critical.pcap", wantError: ErrCriticalOptions},
		{name: "geneve-options-critical-without-base.pcap", wantError: ErrCriticalOptions},
		{name: "geneve-options-base-without-critical.pcap", wantError: ErrCriticalOptions},
		{name: "geneve-options-size.pcap", max: 16, wantError: ErrOptionsSize},
		{name: "geneve-oversize.pcap", decodeError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			genevePacket := readPCAPGenevePayload(t, tc.name)
			hdr, _, err := Decode(genevePacket)
			if tc.decodeError {
				if !errors.Is(err, ErrOptionsStructure) {
					t.Fatalf("got %v, want aggregate options structure error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			maximum := tc.max
			if maximum == 0 {
				maximum = MaxOptionsLen
			}
			metadata, err := ValidateOptions(hdr.Options, maximum, hdr.Critical)
			if tc.wantError != nil {
				if !errors.Is(err, tc.wantError) {
					t.Fatalf("got %v, want %v", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !bytes.Equal(hdr.Options, tc.wantOptions) {
				t.Fatalf("options mismatch: got %x want %x", hdr.Options, tc.wantOptions)
			}
			if len(hdr.Options) > 0 && (!metadata.AWSProfile || !metadata.HasFlowCookie) {
				t.Fatalf("missing mandatory AWS flow cookie metadata: %+v", metadata)
			}
		})
	}
}

func readPCAPGenevePayload(t *testing.T, name string) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	f, err := os.Open(filepath.Join(root, "testdata", "pcap", name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader %s: %v", name, err)
	}
	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("read packet %s: %v", name, err)
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("no UDP layer in %s", name)
	}
	return udpLayer.(*layers.UDP).Payload
}
