package geneve

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestPCAPFixtures(t *testing.T) {
	cases := []struct {
		name           string
		expectErr      bool
		expectTLVError bool
	}{
		{"geneve-minimal.pcap", false, false},
		{"geneve-options.pcap", false, false},
		{"geneve-options-malformed.pcap", false, true},
		{"geneve-oversize.pcap", true, false},
	}

	for _, tc := range cases {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatalf("failed to resolve test file path")
		}
		root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
		path := filepath.Join(root, "testdata", "pcap", tc.name)
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", tc.name, err)
		}
		r, err := pcapgo.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatalf("pcap reader %s: %v", tc.name, err)
		}
		data, _, err := r.ReadPacketData()
		f.Close()
		if err != nil {
			t.Fatalf("read packet %s: %v", tc.name, err)
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			t.Fatalf("no UDP layer in %s", tc.name)
		}
		udp := udpLayer.(*layers.UDP)
		hdr, _, err := Decode(udp.Payload)
		if tc.expectErr && err == nil {
			t.Fatalf("expected decode error for %s", tc.name)
		}
		if !tc.expectErr && err != nil {
			t.Fatalf("unexpected decode error for %s: %v", tc.name, err)
		}
		if tc.expectErr || len(hdr.Options) == 0 {
			continue
		}
		_, err = ParseTLVs(hdr.Options)
		if tc.expectTLVError && err == nil {
			t.Fatalf("expected tlv parse error for %s", tc.name)
		}
		if !tc.expectTLVError && err != nil {
			t.Fatalf("unexpected tlv parse error for %s: %v", tc.name, err)
		}
	}
}
