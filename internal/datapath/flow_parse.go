package datapath

import "encoding/binary"

func flowKeyFromPacket(pkt []byte) (flowKey, bool) {
	if len(pkt) < 1 {
		return flowKey{}, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		return flowKeyIPv4(pkt)
	case 6:
		return flowKeyIPv6(pkt)
	default:
		return flowKey{}, false
	}
}

func flowKeyIPv4(pkt []byte) (flowKey, bool) {
	if len(pkt) < 20 {
		return flowKey{}, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return flowKey{}, false
	}
	proto := pkt[9]
	var key flowKey
	key.ipFamily = 4
	key.proto = proto
	copy(key.srcIP[12:], pkt[12:16])
	copy(key.dstIP[12:], pkt[16:20])
	if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
		key.srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		key.dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return key, true
}

func flowKeyIPv6(pkt []byte) (flowKey, bool) {
	if len(pkt) < 40 {
		return flowKey{}, false
	}
	proto := pkt[6]
	var key flowKey
	key.ipFamily = 6
	key.proto = proto
	copy(key.srcIP[:], pkt[8:24])
	copy(key.dstIP[:], pkt[24:40])
	if (proto == 6 || proto == 17) && len(pkt) >= 44 {
		key.srcPort = binary.BigEndian.Uint16(pkt[40:42])
		key.dstPort = binary.BigEndian.Uint16(pkt[42:44])
	}
	return key, true
}
