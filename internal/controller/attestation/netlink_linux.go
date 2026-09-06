//go:build linux

package attestation

import (
	"context"
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

func dumpNetlink(ctx context.Context, protocol int, kind uint16, family byte) ([][]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, ErrRejected
	}
	defer unix.Close(fd)
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrRejected
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, ErrRejected
	}
	port := address.(*unix.SockaddrNetlink).Pid
	if protocol == unix.NETLINK_ROUTE && unix.SetsockoptInt(fd, unix.SOL_NETLINK, 12, 1) != nil {
		return nil, ErrRejected
	} // NETLINK_GET_STRICT_CHK
	dataSize := 12
	if protocol == unix.NETLINK_NETFILTER {
		dataSize = 4
	}
	request := make([]byte, 16+dataSize)
	order := binary.NativeEndian
	order.PutUint32(request, uint32(len(request)))
	order.PutUint16(request[4:], kind)
	order.PutUint16(request[6:], 0x301)
	order.PutUint32(request[8:], 1)
	order.PutUint32(request[12:], port)
	request[16] = family
	if unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrRejected
	}
	var result [][]byte
	size := 0
	buffer := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil, ErrRejected
		}
		wait := 2 * time.Second
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			wait = time.Until(deadline)
		}
		if wait <= 0 {
			return nil, ErrRejected
		}
		timeout := unix.NsecToTimeval(wait.Nanoseconds())
		if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil {
			return nil, ErrRejected
		}
		n, _, flags, source, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil || flags&unix.MSG_TRUNC != 0 || n == 0 {
			return nil, ErrRejected
		}
		origin, ok := source.(*unix.SockaddrNetlink)
		if !ok || origin.Pid != 0 {
			return nil, ErrRejected
		}
		size += n
		if size > 4*1024*1024 {
			return nil, ErrRejected
		}
		for payload := buffer[:n]; len(payload) > 0; {
			if len(payload) < 16 {
				return nil, ErrRejected
			}
			length := int(order.Uint32(payload))
			aligned := (length + 3) &^ 3
			if length < 16 || aligned > len(payload) || order.Uint32(payload[8:]) != 1 || (order.Uint32(payload[12:]) != 0 && order.Uint32(payload[12:]) != port) || order.Uint16(payload[6:])&0x10 != 0 {
				return nil, ErrRejected
			}
			messageType := order.Uint16(payload[4:])
			data := payload[16:length]
			if messageType == 3 {
				if len(data) < 4 || order.Uint32(data) != 0 || aligned != len(payload) {
					return nil, ErrRejected
				}
				return result, nil
			}
			if messageType == 2 {
				return nil, ErrRejected
			}
			expected := kind - 2 // RTM_NEWROUTE / RTM_NEWRULE
			if protocol == unix.NETLINK_NETFILTER {
				expected = uint16(10 << 8)
			} // NFT_MSG_NEWTABLE
			if messageType != expected || len(result) >= 16384 {
				return nil, ErrRejected
			}
			result = append(result, append([]byte(nil), data...))
			payload = payload[aligned:]
		}
	}
}

func readHostRoutes(ctx context.Context) ([]policyRule, []hostRoute, error) {
	rawRules, err := dumpNetlink(ctx, unix.NETLINK_ROUTE, unix.RTM_GETRULE, unix.AF_INET)
	if err != nil {
		return nil, nil, err
	}
	rawRoutes, err := dumpNetlink(ctx, unix.NETLINK_ROUTE, unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return nil, nil, err
	}
	rules := make([]policyRule, 0, len(rawRules))
	routes := make([]hostRoute, 0, len(rawRoutes))
	for _, raw := range rawRules {
		rule, err := decodeRule(raw, binary.NativeEndian)
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rule)
	}
	for _, raw := range rawRoutes {
		route, err := decodeRoute(raw, binary.NativeEndian)
		if err != nil {
			return nil, nil, err
		}
		routes = append(routes, route)
	}
	return rules, routes, nil
}

func emptyNFT(ctx context.Context) error {
	tables, err := dumpNetlink(ctx, unix.NETLINK_NETFILTER, uint16(10<<8|1), unix.AF_UNSPEC)
	if err != nil || len(tables) != 0 {
		return ErrRejected
	}
	return nil
}
