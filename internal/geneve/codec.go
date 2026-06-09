package geneve

import (
	"errors"
	"fmt"
)

const (
	Version       = 0
	BaseHeaderLen = 8
	MaxOptionsLen = 252
	MaxVNI        = 0xFFFFFF
	ProtoIPv4     = 0x0800
	ProtoIPv6     = 0x86DD
	protoUnknown  = 0x0000
)

var (
	ErrTooShort           = errors.New("geneve packet too short")
	ErrUnsupportedVersion = errors.New("unsupported geneve version")
	ErrOptionsLength      = errors.New("invalid geneve options length")
	ErrVNI                = errors.New("invalid geneve vni")
	ErrUnknownProtocol    = errors.New("unknown geneve protocol type")
)

type Header struct {
	VNI      uint32
	Options  []byte
	Protocol uint16
}

func Decode(pkt []byte) (Header, []byte, error) {
	if len(pkt) < BaseHeaderLen {
		return Header{}, nil, ErrTooShort
	}
	ver := pkt[0] >> 6
	if ver != Version {
		return Header{}, nil, ErrUnsupportedVersion
	}
	optLenBytes := int(pkt[0]&0x3F) * 4
	if optLenBytes < 0 || optLenBytes > MaxOptionsLen {
		return Header{}, nil, ErrOptionsLength
	}
	headLen := BaseHeaderLen + optLenBytes
	if len(pkt) < headLen {
		return Header{}, nil, ErrTooShort
	}
	vni := (uint32(pkt[4]) << 16) | (uint32(pkt[5]) << 8) | uint32(pkt[6])
	proto := uint16(pkt[2])<<8 | uint16(pkt[3])
	options := pkt[BaseHeaderLen:headLen]
	payload := pkt[headLen:]
	return Header{VNI: vni, Options: options, Protocol: proto}, payload, nil
}

func Encode(dst []byte, hdr Header, payload []byte) (int, error) {
	if hdr.VNI > MaxVNI {
		return 0, ErrVNI
	}
	if len(hdr.Options)%4 != 0 || len(hdr.Options) > MaxOptionsLen {
		return 0, ErrOptionsLength
	}
	headLen := BaseHeaderLen + len(hdr.Options)
	need := headLen + len(payload)
	if len(dst) < need {
		return 0, fmt.Errorf("buffer too small: need %d", need)
	}

	proto := hdr.Protocol
	if proto == 0 {
		proto = protocolFromPayload(payload)
		if proto == protoUnknown {
			return 0, ErrUnknownProtocol
		}
	}

	optsWords := len(hdr.Options) / 4
	dst[0] = byte((Version << 6) | (optsWords & 0x3F))
	dst[1] = 0
	dst[2] = byte(proto >> 8)
	dst[3] = byte(proto)
	dst[4] = byte(hdr.VNI >> 16)
	dst[5] = byte(hdr.VNI >> 8)
	dst[6] = byte(hdr.VNI)
	dst[7] = 0
	copy(dst[BaseHeaderLen:headLen], hdr.Options)
	copy(dst[headLen:need], payload)
	return need, nil
}

func protocolFromPayload(payload []byte) uint16 {
	if len(payload) == 0 {
		return protoUnknown
	}
	version := payload[0] >> 4
	switch version {
	case 4:
		return ProtoIPv4
	case 6:
		return ProtoIPv6
	default:
		return protoUnknown
	}
}
