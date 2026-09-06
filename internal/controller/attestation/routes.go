package attestation

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"sort"
)

type policyRule struct {
	Priority, Table, Mark, Mask uint32
	Destination                 netip.Prefix
	Action                      byte
}

type hostRoute struct {
	Destination      netip.Prefix
	Table, Interface uint32
	Gateway          netip.Addr
	Type             byte
	Flags            uint32
}

// Netlink attributes must be decoded without silently dropping new selectors.
func attributes(payload []byte, order binary.ByteOrder) (map[uint16][]byte, error) {
	result := map[uint16][]byte{}
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, ErrRejected
		}
		size, kind := int(order.Uint16(payload)), order.Uint16(payload[2:])
		aligned := (size + 3) &^ 3
		if size < 4 || aligned > len(payload) || result[kind] != nil {
			return nil, ErrRejected
		}
		for _, padding := range payload[size:aligned] {
			if padding != 0 {
				return nil, ErrRejected
			}
		}
		result[kind] = append([]byte{}, payload[4:size]...)
		payload = payload[aligned:]
	}
	return result, nil
}

func ipv4Prefix(address []byte, bits byte) (netip.Prefix, error) {
	if bits > 32 || (len(address) != 0 && len(address) != 4) || (bits != 0 && len(address) == 0) {
		return netip.Prefix{}, ErrRejected
	}
	var raw [4]byte
	copy(raw[:], address)
	prefix := netip.PrefixFrom(netip.AddrFrom4(raw), int(bits))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, ErrRejected
	}
	return prefix, nil
}

func decodeRule(payload []byte, order binary.ByteOrder) (policyRule, error) {
	if len(payload) < 12 || payload[0] != 2 || payload[2] != 0 || payload[3] != 0 || payload[5] != 0 || payload[6] != 0 || order.Uint32(payload[8:12])&^uint32(1) != 0 {
		return policyRule{}, ErrRejected
	}
	attrs, err := attributes(payload[12:], order)
	if err != nil {
		return policyRule{}, err
	}
	rule := policyRule{Table: uint32(payload[4]), Action: payload[7]}
	for kind, value := range attrs {
		switch kind {
		case 1: // FRA_DST
		case 6, 10, 15, 16:
			if len(value) != 4 {
				return policyRule{}, ErrRejected
			}
			number := order.Uint32(value)
			switch kind {
			case 6:
				rule.Priority = number
			case 10:
				rule.Mark = number
			case 16:
				rule.Mask = number
			case 15:
				if rule.Table != 0 && rule.Table != number {
					return policyRule{}, ErrRejected
				}
				rule.Table = number
			}
		case 13, 14: // Unset suppression attributes are emitted on some kernels.
			if len(value) != 4 || order.Uint32(value) != ^uint32(0) {
				return policyRule{}, ErrRejected
			}
		case 21:
			if len(value) != 1 {
				return policyRule{}, ErrRejected
			} // Origin protocol, not a selector.
		default:
			return policyRule{}, ErrRejected
		}
	}
	rule.Destination, err = ipv4Prefix(attrs[1], payload[1])
	if err != nil {
		return policyRule{}, err
	}
	return rule, nil
}

func decodeRoute(payload []byte, order binary.ByteOrder) (hostRoute, error) {
	if len(payload) < 12 || payload[0] != 2 || payload[2] != 0 || payload[3] != 0 {
		return hostRoute{}, ErrRejected
	}
	attrs, err := attributes(payload[12:], order)
	if err != nil {
		return hostRoute{}, err
	}
	route := hostRoute{Table: uint32(payload[4]), Type: payload[7], Flags: order.Uint32(payload[8:12])}
	for kind, value := range attrs {
		switch kind {
		case 1:
		case 4, 6, 15:
			if len(value) != 4 {
				return hostRoute{}, ErrRejected
			}
			number := order.Uint32(value)
			if kind == 4 {
				route.Interface = number
			}
			if kind == 15 {
				if route.Table != 0 && route.Table != number {
					return hostRoute{}, ErrRejected
				}
				route.Table = number
			}
		case 5, 7: // Gateway / preferred source (not source-specific routing).
			if len(value) != 4 {
				return hostRoute{}, ErrRejected
			}
			if kind == 5 {
				route.Gateway = netip.AddrFrom4([4]byte(value))
			}
		case 12:
			if len(value) != 32 {
				return hostRoute{}, ErrRejected
			} // Cache counters.
		case 8, 0x8008: // MTU and TCP metrics cannot change the route decision.
			metrics, err := attributes(value, order)
			if err != nil {
				return hostRoute{}, err
			}
			for metric, data := range metrics {
				if metric < 1 || metric > 17 || len(data) != 4 {
					return hostRoute{}, ErrRejected
				}
			}
		case 23:
			if len(value) != 4 {
				return hostRoute{}, ErrRejected
			} // Expiry; freshness is bounded externally.
		default:
			return hostRoute{}, ErrRejected // Includes source routes, multipath, nexthop objects, encapsulation and policy extensions.
		}
	}
	route.Destination, err = ipv4Prefix(attrs[1], payload[1])
	if err != nil {
		return hostRoute{}, err
	}
	return route, nil
}

func expectedRules(local []string) []policyRule {
	all := netip.MustParsePrefix("0.0.0.0/0")
	rules := []policyRule{{Priority: 0, Table: 255, Destination: all, Action: 1}}
	ordered := append([]string(nil), local...)
	sort.Strings(ordered)
	for index, prefix := range ordered {
		rules = append(rules, policyRule{Priority: uint32(100 + index), Table: 254, Destination: netip.MustParsePrefix(prefix), Action: 1})
	}
	for _, rule := range []policyRule{
		{Priority: 5210, Table: 254, Mark: 524288, Mask: 16711680, Destination: all, Action: 1},
		{Priority: 5230, Table: 253, Mark: 524288, Mask: 16711680, Destination: all, Action: 1},
		{Priority: 5250, Mark: 524288, Mask: 16711680, Destination: all, Action: 7},
		{Priority: 5270, Table: 52, Destination: all, Action: 1},
		{Priority: 32766, Table: 254, Destination: all, Action: 1},
		{Priority: 32767, Table: 253, Destination: all, Action: 1},
	} {
		rules = append(rules, rule)
	}
	return rules
}

// validateHostRoutes proves the complete prefixes by considering every overlap,
// including interior more-specific routes. Sampling a few addresses is not proof.
func validateHostRoutes(rules []policyRule, routes []hostRoute, local, remote []string, underlay, tun uint32, gateway netip.Addr) error {
	ordered := append([]policyRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	if !reflect.DeepEqual(ordered, expectedRules(local)) || underlay == 0 || tun == 0 || underlay == tun || !gateway.Is4() {
		return ErrRejected
	}
	for _, raw := range append(append([]string(nil), local...), remote...) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return ErrRejected
		}
		for _, route := range routes {
			if route.Table == 255 && route.Destination.Overlaps(prefix) {
				return ErrRejected
			}
		}
	}
	for _, raw := range remote {
		prefix := netip.MustParsePrefix(raw)
		matches := 0
		for _, route := range routes {
			if route.Table != 52 || !route.Destination.Overlaps(prefix) {
				continue
			}
			matches++
			if route.Destination != prefix || route.Interface != tun || route.Type != 1 || route.Flags != 0 || route.Gateway.IsValid() {
				return ErrRejected
			}
		}
		if matches != 1 {
			return ErrRejected
		}
	}
	for _, raw := range local {
		prefix := netip.MustParsePrefix(raw)
		overlaps := 0
		longest := -1
		winners := 0
		var winner hostRoute
		for _, route := range routes {
			if !route.Destination.Overlaps(prefix) {
				continue
			}
			if route.Table == 52 {
				overlaps++
				if overlaps > 1 || route.Destination != prefix || route.Interface != tun || route.Type != 1 || route.Flags != 0 || route.Gateway.IsValid() {
					return ErrRejected
				}
			}
			if route.Table != 254 {
				continue
			}
			if route.Destination.Bits() > prefix.Bits() {
				if route.Interface != underlay || route.Type != 1 || route.Flags != 0 || route.Gateway != gateway {
					return ErrRejected
				}
				continue
			}
			if route.Destination.Bits() > longest {
				longest = route.Destination.Bits()
				winners = 0
				winner = route
			}
			if route.Destination.Bits() == longest {
				winners++
			}
		}
		if winners != 1 || winner.Interface != underlay || winner.Type != 1 || winner.Flags != 0 || winner.Gateway != gateway {
			return ErrRejected
		}
	}
	return nil
}
