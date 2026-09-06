package attestation

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestFullPrefixHostProofRejectsInteriorAndPolicyBypasses(t *testing.T) {
	for _, mode := range []string{"valid", "shadowed-local", "interior-blackhole", "interior-wrong-device", "interior-wrong-gateway", "local-table", "extra-policy", "mark-mask", "source-rule", "remote-covering", "remote-missing", "duplicate", "remote-gateway", "local-table52-specific"} {
		t.Run(mode, func(t *testing.T) {
			local, remote := []string{"10.0.0.0/24"}, []string{"10.1.0.0/24"}
			rules := expectedRules(local)
			routes := []hostRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Table: 254, Interface: 1, Gateway: netip.MustParseAddr("10.9.0.1"), Type: 1}, {Destination: netip.MustParsePrefix(remote[0]), Table: 52, Interface: 2, Type: 1}}
			switch mode {
			case "shadowed-local":
				routes = append(routes, hostRoute{Destination: netip.MustParsePrefix(local[0]), Table: 52, Interface: 2, Type: 1})
			case "interior-blackhole", "interior-wrong-device", "interior-wrong-gateway":
				route := hostRoute{Destination: netip.MustParsePrefix("10.0.0.64/28"), Table: 254, Interface: 1, Type: 1, Gateway: netip.MustParseAddr("10.9.0.1")}
				if mode == "interior-blackhole" {
					route.Type = 6
				}
				if mode == "interior-wrong-device" {
					route.Interface = 2
				}
				if mode == "interior-wrong-gateway" {
					route.Gateway = netip.MustParseAddr("10.9.0.99")
				}
				routes = append(routes, route)
			case "local-table":
				routes = append(routes, hostRoute{Destination: netip.MustParsePrefix("10.1.0.64/32"), Table: 255, Interface: 1, Type: 2})
			case "extra-policy":
				rules = append(rules, policyRule{Priority: 90, Table: 52, Destination: netip.MustParsePrefix("10.0.0.64/28"), Action: 1})
			case "mark-mask":
				rules[2].Mask = 0
			case "source-rule":
				rules[1].Action = 7
			case "remote-covering":
				routes[1].Destination = netip.MustParsePrefix("10.1.0.0/16")
			case "remote-missing":
				routes = routes[:1]
			case "duplicate":
				routes = append(routes, routes[1])
			case "remote-gateway":
				routes[1].Gateway = netip.MustParseAddr("10.9.0.1")
			case "local-table52-specific":
				routes = append(routes, hostRoute{Destination: netip.MustParsePrefix("10.0.0.64/28"), Table: 52, Interface: 2, Type: 1})
			}
			err := validateHostRoutes(rules, routes, local, remote, 1, 2, netip.MustParseAddr("10.9.0.1"))
			if (err == nil) != (mode == "valid" || mode == "shadowed-local") {
				t.Fatalf("proof=%v", err)
			}
		})
	}
}

func attributeFixture(kind uint16, value []byte) []byte {
	result := make([]byte, (len(value)+7)&^3)
	binary.LittleEndian.PutUint16(result, uint16(len(value)+4))
	binary.LittleEndian.PutUint16(result[2:], kind)
	copy(result[4:], value)
	return result
}

func TestRtnetlinkRejectsUnknownSelectorsAndMalformedAttributes(t *testing.T) {
	rule := make([]byte, 12)
	rule[0], rule[4], rule[7] = 2, 254, 1
	if _, err := decodeRule(rule, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{2, 3, 4, 11, 12, 17, 19, 20, 22, 23, 24, 999} {
		if _, err := decodeRule(append(append([]byte(nil), rule...), attributeFixture(kind, []byte{0, 0, 0, 0})...), binary.LittleEndian); err == nil {
			t.Fatalf("unknown/source/port selector %d accepted", kind)
		}
	}
	route := make([]byte, 12)
	route[0], route[4], route[7] = 2, 254, 1
	for _, kind := range []uint16{2, 3, 9, 18, 21, 22, 30, 999} {
		if _, err := decodeRoute(append(append([]byte(nil), route...), attributeFixture(kind, []byte{0, 0, 0, 0})...), binary.LittleEndian); err == nil {
			t.Fatalf("unknown route decision %d accepted", kind)
		}
	}
	data := append(attributeFixture(6, []byte{1, 0, 0, 0}), attributeFixture(6, []byte{2, 0, 0, 0})...)
	if _, err := attributes(data, binary.LittleEndian); err == nil {
		t.Fatal("duplicate attribute accepted")
	}
	if _, err := attributes([]byte{2, 0, 1, 0}, binary.LittleEndian); err == nil {
		t.Fatal("short attribute accepted")
	}
	data = attributeFixture(1, []byte{1})
	data[len(data)-1] = 1
	if _, err := attributes(data, binary.LittleEndian); err == nil {
		t.Fatal("nonzero padding accepted")
	}
}

func FuzzRtnetlink(f *testing.F) {
	f.Add([]byte{2, 0, 0, 0, 254, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = decodeRule(payload, binary.LittleEndian)
		_, _ = decodeRoute(payload, binary.LittleEndian)
	})
}
