package attestation

import (
	"encoding/binary"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func encodeFirewallFixture(table string, ipv6 bool, graph firewallTable) ([]byte, []byte) {
	order := binary.LittleEndian
	header, targetField := 112, 88
	if ipv6 {
		header, targetField = 168, 140
	}
	all := netip.MustParsePrefix("0.0.0.0/0")
	if ipv6 {
		all = netip.MustParsePrefix("::/0")
	}
	var entries []byte
	count := uint32(0)
	jumps := map[int]string{}
	labels := map[string]int{}
	appendRule := func(r firewallRule, label string) int {
		start := len(entries)
		matchSize := 0
		if r.TCP {
			matchSize = 48
		}
		targetSize := 40
		if label != "" {
			targetSize = 64
		}
		data := make([]byte, header+matchSize+targetSize)
		addressSize, iface := 4, 16
		if ipv6 {
			addressSize, iface = 16, 64
		}
		copy(data, r.Source.Addr().AsSlice())
		copy(data[addressSize:], r.Destination.Addr().AsSlice())
		copy(data[2*addressSize:], net.CIDRMask(r.Source.Bits(), 8*addressSize))
		copy(data[3*addressSize:], net.CIDRMask(r.Destination.Bits(), 8*addressSize))
		for i, name := range []string{r.Input, r.Output} {
			copy(data[iface+i*16:], name)
			if name != "" {
				for j := 0; j <= len(name); j++ {
					data[iface+32+i*16+j] = 255
				}
			}
		}
		if !ipv6 {
			order.PutUint16(data[80:], r.Protocol)
		}
		order.PutUint16(data[targetField:], uint16(header+matchSize))
		order.PutUint16(data[targetField+2:], uint16(len(data)))
		if r.TCP {
			m := data[header:]
			order.PutUint16(m, 48)
			copy(m[2:], "tcp")
			order.PutUint16(m[34:], 65535)
			order.PutUint16(m[38:], 65535)
			m[41], m[42] = 6, 2
		}
		target := data[header+matchSize:]
		order.PutUint16(target, uint16(targetSize))
		if label != "" {
			copy(target[2:], "ERROR")
			copy(target[32:], label)
		} else {
			switch r.Action {
			case "ACCEPT":
				order.PutUint32(target[32:], uint32(0xfffffffe))
			case "DROP":
				order.PutUint32(target[32:], uint32(0xffffffff))
			case "RETURN":
				order.PutUint32(target[32:], uint32(0xfffffffb))
			case "TCPMSS":
				copy(target[2:], "TCPMSS")
				order.PutUint16(target[32:], r.MSS)
			case "JUMP":
				jumps[start+header+matchSize+32] = r.Target
			}
		}
		entries = append(entries, data...)
		count++
		return start
	}
	plain := func(action string) firewallRule { return firewallRule{Source: all, Destination: all, Action: action} }
	info := make([]byte, 84)
	copy(info, table)
	mask := map[string]uint32{"filter": 14, "mangle": 31, "nat": 27, "raw": 9, "security": 14}[table]
	order.PutUint32(info[32:], mask)
	for index, name := range []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"} {
		if mask&(1<<index) == 0 {
			continue
		}
		chain := graph[name]
		order.PutUint32(info[36+4*index:], uint32(len(entries)))
		for _, rule := range chain.Rules {
			appendRule(rule, "")
		}
		end := appendRule(plain(chain.Policy), "")
		order.PutUint32(info[56+4*index:], uint32(end))
	}
	for _, name := range []string{forwardChain, mssChain} {
		if chain, found := graph[name]; found {
			appendRule(plain(""), name)
			labels[name] = len(entries)
			for _, rule := range chain.Rules {
				appendRule(rule, "")
			}
			appendRule(plain("RETURN"), "")
		}
	}
	appendRule(plain(""), "ERROR")
	for offset, name := range jumps {
		order.PutUint32(entries[offset:], uint32(labels[name]))
	}
	order.PutUint32(info[76:], count)
	order.PutUint32(info[80:], uint32(len(entries)))
	return info, entries
}

func TestLegacyUAPIAndExpandedContract(t *testing.T) {
	local, remote := []string{"10.0.0.0/24", "10.0.1.0/24"}, []string{"10.1.0.0/24"}
	observed := map[string]firewallTable{}
	for _, ipv6 := range []bool{false, true} {
		for _, table := range []string{"filter", "mangle", "nat", "raw", "security"} {
			expected := expectedFirewall(table, ipv6, local, remote, "eth0", 1240)
			info, entries := encodeFirewallFixture(table, ipv6, expected)
			parsed, err := decodeFirewall(info, entries, ipv6, binary.LittleEndian)
			if err != nil || !reflect.DeepEqual(parsed, expected) {
				t.Fatalf("%s ipv6=%t decode=%v\ngot=%+v\nwant=%+v", table, ipv6, err, parsed, expected)
			}
			family := "ipv4/"
			if ipv6 {
				family = "ipv6/"
			}
			observed[family+table] = parsed
		}
	}
	if err := validateFirewall(observed, local, remote, "eth0", 9001, 1280, 1240); err != nil {
		t.Fatal(err)
	}
	if validateFirewall(observed, local, remote, "eth0", 1200, 1280, 1240) == nil {
		t.Fatal("stale MSS accepted after MTU changed")
	}
	if validateFirewall(observed, local, remote, "eth0", 9001, 1280, 1200) == nil {
		t.Fatal("wrong configured MSS ceiling accepted")
	}
}

func TestLegacyFirewallRejectsMalformedAndUnapprovedState(t *testing.T) {
	for _, mode := range []string{"truncated", "count", "size", "flags", "wildcard-interface", "unknown-target", "target-revision", "bad-jump", "short-entry", "missing-mss", "wrong-mss", "extra-forward", "nat-rewrite", "ipv6-forward"} {
		t.Run(mode, func(t *testing.T) {
			local, remote := []string{"10.0.0.0/24"}, []string{"10.1.0.0/24"}
			table := "filter"
			ipv6 := false
			if mode == "missing-mss" || mode == "wrong-mss" {
				table = "mangle"
			}
			if mode == "nat-rewrite" {
				table = "nat"
			}
			if mode == "ipv6-forward" {
				ipv6 = true
			}
			graph := expectedFirewall(table, ipv6, local, remote, "eth0", 1240)
			switch mode {
			case "extra-forward":
				chain := graph[forwardChain]
				chain.Rules = append(chain.Rules, chain.Rules[0])
				graph[forwardChain] = chain
			case "missing-mss":
				chain := graph[mssChain]
				chain.Rules = chain.Rules[1:]
				graph[mssChain] = chain
			case "wrong-mss":
				chain := graph[mssChain]
				chain.Rules[0].MSS = 1200
				graph[mssChain] = chain
			case "nat-rewrite":
				chain := graph["PREROUTING"]
				chain.Rules = append(chain.Rules, firewallRule{Source: netip.MustParsePrefix("0.0.0.0/0"), Destination: netip.MustParsePrefix("0.0.0.0/0"), Action: "DROP"})
				graph["PREROUTING"] = chain
			case "ipv6-forward":
				graph["FORWARD"] = firewallChain{Policy: "ACCEPT", Rules: []firewallRule{}}
			}
			info, entries := encodeFirewallFixture(table, ipv6, graph)
			switch mode {
			case "truncated":
				entries = entries[:len(entries)-1]
			case "count":
				binary.LittleEndian.PutUint32(info[76:], 999)
			case "size":
				binary.LittleEndian.PutUint32(info[80:], 1)
			case "flags":
				entries[82] = 1
			case "wildcard-interface":
				copy(entries[16:], "eth+")
				entries[48] = 255
			case "unknown-target":
				copy(entries[114:], "SNAT")
			case "target-revision":
				entries[143] = 1
			case "bad-jump":
				binary.LittleEndian.PutUint32(entries[144:], 1)
			case "short-entry":
				binary.LittleEndian.PutUint16(entries[90:], 8)
			}
			parsed, err := decodeFirewall(info, entries, ipv6, binary.LittleEndian)
			if err == nil && reflect.DeepEqual(parsed, expectedFirewall(table, ipv6, local, remote, "eth0", 1240)) {
				t.Fatal("unapproved state passed")
			}
		})
	}
}

func FuzzLegacyFirewall(f *testing.F) {
	info, entries := encodeFirewallFixture("filter", false, expectedFirewall("filter", false, []string{"10.0.0.0/24"}, []string{"10.1.0.0/24"}, "eth0", 1240))
	f.Add(info, entries, false)
	f.Fuzz(func(t *testing.T, info, entries []byte, v6 bool) {
		_, _ = decodeFirewall(info, entries, v6, binary.LittleEndian)
	})
}
