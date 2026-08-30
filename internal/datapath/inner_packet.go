package datapath

import (
	"encoding/binary"
	"errors"
)

var ErrInnerMalformed = errors.New("malformed inner IP packet")

func validateInnerPacket(pkt []byte) error {
	if len(pkt) < 1 {
		return ErrInnerMalformed
	}
	switch pkt[0] >> 4 {
	case 4:
		return validateIPv4Packet(pkt)
	case 6:
		return validateIPv6Packet(pkt)
	default:
		return ErrInnerMalformed
	}
}

func validateIPv4Packet(pkt []byte) error {
	if len(pkt) < 20 {
		return ErrInnerMalformed
	}
	ihl := int(pkt[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || ihl > len(pkt) || totalLen < ihl || totalLen != len(pkt) {
		return ErrInnerMalformed
	}
	return nil
}

func validateIPv6Packet(pkt []byte) error {
	if len(pkt) < 40 {
		return ErrInnerMalformed
	}
	totalLen := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
	if totalLen != len(pkt) {
		return ErrInnerMalformed
	}

	return nil
}
