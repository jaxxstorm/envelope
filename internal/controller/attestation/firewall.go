package attestation

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"sort"
)

const forwardChain = "ENVELOPE-TRANSPORT-FORWARD"
const mssChain = "ENVELOPE-TRANSPORT-MSS"

type firewallRule struct {
	Source, Destination           netip.Prefix
	Input, Output, Action, Target string
	Protocol                      uint16
	TCP                           bool
	MSS                           uint16
}
type firewallChain struct {
	Policy string
	Rules  []firewallRule
}
type firewallTable map[string]firewallChain

func zero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
func cString(data []byte) (string, error) {
	end := bytes.IndexByte(data, 0)
	if end < 0 || !zero(data[end:]) {
		return "", ErrRejected
	}
	for _, b := range data[:end] {
		if b < 33 || b > 126 {
			return "", ErrRejected
		}
	}
	return string(data[:end]), nil
}
func firewallInterface(name, mask []byte) (string, error) {
	text, err := cString(name)
	if err != nil {
		return "", err
	}
	expected := make([]byte, 16)
	if text != "" {
		for i := 0; i <= len(text); i++ {
			expected[i] = 255
		}
	}
	if !bytes.Equal(mask, expected) {
		return "", ErrRejected
	}
	return text, nil
}
func firewallPrefix(address, mask []byte) (netip.Prefix, error) {
	bits := 0
	ended := false
	for _, b := range mask {
		for bit := 7; bit >= 0; bit-- {
			set := b&(1<<bit) != 0
			if set && ended {
				return netip.Prefix{}, ErrRejected
			}
			if set {
				bits++
			} else {
				ended = true
			}
		}
	}
	ip, ok := netip.AddrFromSlice(address)
	if !ok {
		return netip.Prefix{}, ErrRejected
	}
	prefix := netip.PrefixFrom(ip, bits)
	if prefix != prefix.Masked() {
		return netip.Prefix{}, ErrRejected
	}
	return prefix, nil
}

// decodeFirewall uses the Linux LP64 UAPI layouts from ip_tables.h,
// ip6_tables.h and x_tables.h. Only the reviewed grammar is accepted. Counters
// and kernel comefrom bookkeeping are ignored, never matches or actions.
func decodeFirewall(info, entries []byte, ipv6 bool, order binary.ByteOrder) (firewallTable, error) {
	if len(info) != 84 || int(order.Uint32(info[80:])) != len(entries) || len(entries) > 4*1024*1024 {
		return nil, ErrRejected
	}
	table, err := cString(info[:32])
	if err != nil {
		return nil, err
	}
	hooks := map[string]uint32{"filter": 14, "mangle": 31, "nat": 27, "raw": 9, "security": 14}
	mask, known := hooks[table]
	if !known || order.Uint32(info[32:]) != mask {
		return nil, ErrRejected
	}
	header, ipSize, targetField := 112, 84, 88
	if ipv6 {
		header, ipSize, targetField = 168, 136, 140
	}
	type entry struct {
		rule          firewallRule
		next          int
		label         string
		jump          int
		unconditional bool
	}
	parsed := map[int]entry{}
	offsets := []int{}
	labels := map[int]string{}
	for offset := 0; offset < len(entries); {
		data := entries[offset:]
		if len(data) < header {
			return nil, ErrRejected
		}
		targetOffset, next := int(order.Uint16(data[targetField:])), int(order.Uint16(data[targetField+2:]))
		if targetOffset < header || targetOffset%8 != 0 || next < targetOffset+32 || next%8 != 0 || next > len(data) {
			return nil, ErrRejected
		}
		data = data[:next]
		if !zero(data[ipSize:ipSize+4]) || (ipv6 && !zero(data[148:152])) {
			return nil, ErrRejected
		}
		var r firewallRule
		if ipv6 {
			r.Source, err = firewallPrefix(data[:16], data[32:48])
			if err != nil {
				return nil, err
			}
			r.Destination, err = firewallPrefix(data[16:32], data[48:64])
			if err != nil {
				return nil, err
			}
			r.Input, err = firewallInterface(data[64:80], data[96:112])
			if err != nil {
				return nil, err
			}
			r.Output, err = firewallInterface(data[80:96], data[112:128])
			if err != nil {
				return nil, err
			}
			if !zero(data[128:136]) {
				return nil, ErrRejected
			} // IPv6 transit must have no protocol, TOS, inversion or goto selectors.
		} else {
			r.Source, err = firewallPrefix(data[:4], data[8:12])
			if err != nil {
				return nil, err
			}
			r.Destination, err = firewallPrefix(data[4:8], data[12:16])
			if err != nil {
				return nil, err
			}
			r.Input, err = firewallInterface(data[16:32], data[48:64])
			if err != nil {
				return nil, err
			}
			r.Output, err = firewallInterface(data[32:48], data[64:80])
			if err != nil {
				return nil, err
			}
			r.Protocol = order.Uint16(data[80:])
			if !zero(data[82:84]) {
				return nil, ErrRejected
			}
		}
		if targetOffset != header {
			match := data[header:targetOffset]
			if ipv6 || len(match) != 48 || order.Uint16(match) != 48 || match[31] != 0 || r.Protocol != 6 {
				return nil, ErrRejected
			}
			name, err := cString(match[2:31])
			if err != nil || name != "tcp" {
				return nil, ErrRejected
			}
			if order.Uint16(match[32:]) != 0 || order.Uint16(match[34:]) != 65535 || order.Uint16(match[36:]) != 0 || order.Uint16(match[38:]) != 65535 || match[40] != 0 || match[41] != 6 || match[42] != 2 || !zero(match[43:]) {
				return nil, ErrRejected
			}
			r.TCP = true
		}
		target := data[targetOffset:]
		if int(order.Uint16(target)) != len(target) || target[31] != 0 {
			return nil, ErrRejected
		}
		name, err := cString(target[2:31])
		if err != nil {
			return nil, err
		}
		e := entry{rule: r, next: offset + next, jump: -1, unconditional: zero(data[:ipSize]) && targetOffset == header}
		switch name {
		case "":
			if len(target) != 40 || !zero(target[36:]) {
				return nil, ErrRejected
			}
			verdict := int32(order.Uint32(target[32:]))
			switch verdict {
			case -1:
				e.rule.Action = "DROP"
			case -2:
				e.rule.Action = "ACCEPT"
			case -5:
				e.rule.Action = "RETURN"
			default:
				if verdict < 0 {
					return nil, ErrRejected
				}
				e.rule.Action = "JUMP"
				e.jump = int(verdict)
			}
		case "ERROR":
			if len(target) != 64 || !e.unconditional {
				return nil, ErrRejected
			}
			e.label, err = cString(target[32:])
			if err != nil || e.label == "" {
				return nil, ErrRejected
			}
			if e.label != "ERROR" {
				if _, exists := labels[e.next]; exists {
					return nil, ErrRejected
				}
				labels[e.next] = e.label
			}
		case "TCPMSS":
			if len(target) != 40 || !zero(target[34:]) || !r.TCP || r.Protocol != 6 {
				return nil, ErrRejected
			}
			e.rule.Action = "TCPMSS"
			e.rule.MSS = order.Uint16(target[32:])
		default:
			return nil, ErrRejected
		}
		parsed[offset] = e
		offsets = append(offsets, offset)
		offset += next
	}
	if len(offsets) == 0 || uint32(len(offsets)) != order.Uint32(info[76:]) || parsed[offsets[len(offsets)-1]].label != "ERROR" {
		return nil, ErrRejected
	}
	result := firewallTable{}
	used := map[int]bool{}
	hookNames := []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
	for hook, name := range hookNames {
		if mask&(1<<hook) == 0 {
			continue
		}
		start, end := int(order.Uint32(info[36+4*hook:])), int(order.Uint32(info[56+4*hook:]))
		chain := firewallChain{Rules: []firewallRule{}}
		for offset := start; ; {
			e, ok := parsed[offset]
			if !ok || used[offset] || e.label != "" || offset > end {
				return nil, ErrRejected
			}
			used[offset] = true
			if offset == end {
				if !e.unconditional || (e.rule.Action != "ACCEPT" && e.rule.Action != "DROP") {
					return nil, ErrRejected
				}
				chain.Policy = e.rule.Action
				break
			}
			if e.rule.Action == "JUMP" {
				target, ok := labels[e.jump]
				if !ok {
					return nil, ErrRejected
				}
				e.rule.Target = target
			}
			chain.Rules = append(chain.Rules, e.rule)
			offset = e.next
		}
		result[name] = chain
	}
	for start, name := range labels {
		if _, exists := result[name]; exists {
			return nil, ErrRejected
		}
		chain := firewallChain{Rules: []firewallRule{}}
		for offset := start; ; {
			e, ok := parsed[offset]
			if !ok || used[offset] || e.label != "" {
				return nil, ErrRejected
			}
			used[offset] = true
			if e.unconditional && e.rule.Action == "RETURN" && parsed[e.next].label != "" {
				chain.Policy = "RETURN"
				break
			}
			if e.rule.Action == "JUMP" {
				return nil, ErrRejected
			} // No nested or recursive custom-chain graphs.
			chain.Rules = append(chain.Rules, e.rule)
			offset = e.next
		}
		result[name] = chain
	}
	for offset, e := range parsed {
		if !used[offset] && e.label == "" {
			return nil, ErrRejected
		}
	}
	return result, nil
}

func expectedFirewall(table string, ipv6 bool, local, remote []string, underlay string, mss int) firewallTable {
	all := netip.MustParsePrefix("0.0.0.0/0")
	if ipv6 {
		all = netip.MustParsePrefix("::/0")
	}
	plain := func(action, target string) firewallRule {
		return firewallRule{Source: all, Destination: all, Action: action, Target: target}
	}
	result := firewallTable{}
	hooks := map[string][]string{"filter": {"INPUT", "FORWARD", "OUTPUT"}, "mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}, "nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}, "raw": {"PREROUTING", "OUTPUT"}, "security": {"INPUT", "FORWARD", "OUTPUT"}}
	for _, hook := range hooks[table] {
		result[hook] = firewallChain{Policy: "ACCEPT", Rules: []firewallRule{}}
	}
	if table != "filter" && table != "mangle" {
		return result
	}
	custom := forwardChain
	if table == "filter" {
		result["FORWARD"] = firewallChain{Policy: "DROP", Rules: []firewallRule{plain("JUMP", custom)}}
	} else {
		if ipv6 {
			return result
		}
		custom = mssChain
		result["FORWARD"] = firewallChain{Policy: "ACCEPT", Rules: []firewallRule{plain("JUMP", custom)}}
	}
	chain := firewallChain{Policy: "RETURN", Rules: []firewallRule{}}
	if !ipv6 {
		for _, l := range local {
			for _, r := range remote {
				for _, rule := range []firewallRule{
					{Source: netip.MustParsePrefix(l), Destination: netip.MustParsePrefix(r), Input: underlay, Output: "tailscale0", Action: "ACCEPT"},
					{Source: netip.MustParsePrefix(r), Destination: netip.MustParsePrefix(l), Input: "tailscale0", Output: underlay, Action: "ACCEPT"},
				} {
					if table == "mangle" {
						rule.Protocol = 6
						rule.TCP = true
						rule.Action = "TCPMSS"
						rule.MSS = uint16(mss)
					}
					chain.Rules = append(chain.Rules, rule)
				}
			}
		}
	}
	if table == "mangle" {
		chain.Rules = append(chain.Rules, plain("RETURN", ""))
	}
	result[custom] = chain
	return result
}

func validateFirewall(observed map[string]firewallTable, local, remote []string, underlay string, underlayMTU, tunMTU, maximum int) error {
	if underlayMTU < 576 || underlayMTU > 65535 || tunMTU < 576 || tunMTU > 65535 || maximum < 536 || maximum > 1240 {
		return ErrRejected
	}
	mss := min(underlayMTU, tunMTU) - 40
	mss = min(mss, maximum)
	l := append([]string(nil), local...)
	r := append([]string(nil), remote...)
	sort.Strings(l)
	sort.Strings(r)
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"filter", "mangle", "nat"} {
			if observed[family+"/"+table] == nil {
				return ErrRejected
			}
		}
	}
	for key, table := range observed {
		if len(key) < 6 || (key[:5] != "ipv4/" && key[:5] != "ipv6/") {
			return ErrRejected
		}
		name := key[5:]
		if name != "filter" && name != "mangle" && name != "nat" && name != "raw" && name != "security" {
			return ErrRejected
		}
		if !reflect.DeepEqual(table, expectedFirewall(name, key[:4] == "ipv6", l, r, underlay, mss)) {
			return ErrRejected
		}
	}
	return nil
}
