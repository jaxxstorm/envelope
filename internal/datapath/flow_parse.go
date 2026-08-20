package datapath

import (
	"encoding/binary"
	"errors"
)

var (
	ErrInnerMalformed     = errors.New("malformed inner IP packet")
	ErrIPv4Fragment       = errors.New("fragmented inner IPv4 packet")
	ErrIPv6Fragment       = errors.New("inner IPv6 fragment header")
	ErrIPv6Extension      = errors.New("unsupported inner IPv6 extension header")
	ErrTransportTruncated = errors.New("truncated inner TCP or UDP header")
)

func flowKeyFromPacket(pkt []byte) (flowKey, error) {
	if len(pkt) < 1 {
		return flowKey{}, ErrInnerMalformed
	}
	switch pkt[0] >> 4 {
	case 4:
		return flowKeyIPv4(pkt)
	case 6:
		return flowKeyIPv6(pkt)
	default:
		return flowKey{}, ErrInnerMalformed
	}
}

func flowKeyIPv4(pkt []byte) (flowKey, error) {
	if len(pkt) < 20 {
		return flowKey{}, ErrInnerMalformed
	}
	ihl := int(pkt[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || totalLen < ihl || totalLen != len(pkt) {
		return flowKey{}, ErrInnerMalformed
	}
	fragment := binary.BigEndian.Uint16(pkt[6:8])
	if fragment&0x2000 != 0 || fragment&0x1fff != 0 {
		return flowKey{}, ErrIPv4Fragment
	}

	proto := pkt[9]
	key := flowKey{ipFamily: 4, proto: proto}
	copy(key.srcIP[12:], pkt[12:16])
	copy(key.dstIP[12:], pkt[16:20])
	if err := parseTransportPorts(pkt[ihl:totalLen], proto, &key); err != nil {
		return flowKey{}, err
	}
	return key, nil
}

func flowKeyIPv6(pkt []byte) (flowKey, error) {
	if len(pkt) < 40 {
		return flowKey{}, ErrInnerMalformed
	}
	totalLen := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
	if totalLen != len(pkt) {
		return flowKey{}, ErrInnerMalformed
	}

	proto := pkt[6]
	transportOffset, extension, err := inspectIPv6Extensions(pkt[:totalLen], proto)
	if err != nil {
		return flowKey{}, err
	}
	if extension {
		return flowKey{}, ErrIPv6Extension
	}
	key := flowKey{ipFamily: 6, proto: proto}
	copy(key.srcIP[:], pkt[8:24])
	copy(key.dstIP[:], pkt[24:40])
	if err := parseTransportPorts(pkt[transportOffset:totalLen], proto, &key); err != nil {
		return flowKey{}, err
	}
	return key, nil
}

func parseTransportPorts(transport []byte, protocol uint8, key *flowKey) error {
	switch protocol {
	case 6:
		if len(transport) < 20 {
			return ErrTransportTruncated
		}
		headerLen := int(transport[12]>>4) * 4
		if headerLen < 20 || headerLen > len(transport) {
			return ErrTransportTruncated
		}
	case 17:
		if len(transport) < 8 {
			return ErrTransportTruncated
		}
		udpLen := int(binary.BigEndian.Uint16(transport[4:6]))
		if udpLen < 8 || udpLen > len(transport) {
			return ErrTransportTruncated
		}
	default:
		return nil
	}
	key.srcPort = binary.BigEndian.Uint16(transport[0:2])
	key.dstPort = binary.BigEndian.Uint16(transport[2:4])
	return nil
}

func inspectIPv6Extensions(pkt []byte, next uint8) (int, bool, error) {
	offset := 40
	sawExtension := false
	for {
		switch next {
		case 44:
			return 0, true, ErrIPv6Fragment
		case 0, 43, 60, 135, 139, 140:
			sawExtension = true
			if len(pkt)-offset < 2 {
				return 0, true, ErrIPv6Extension
			}
			headerLen := (int(pkt[offset+1]) + 1) * 8
			if headerLen < 8 || len(pkt)-offset < headerLen {
				return 0, true, ErrIPv6Extension
			}
			next = pkt[offset]
			offset += headerLen
		case 51:
			sawExtension = true
			if len(pkt)-offset < 2 {
				return 0, true, ErrIPv6Extension
			}
			headerLen := (int(pkt[offset+1]) + 2) * 4
			if headerLen < 8 || len(pkt)-offset < headerLen {
				return 0, true, ErrIPv6Extension
			}
			next = pkt[offset]
			offset += headerLen
		case 50:
			return 0, true, ErrIPv6Extension
		default:
			return offset, sawExtension, nil
		}
	}
}
