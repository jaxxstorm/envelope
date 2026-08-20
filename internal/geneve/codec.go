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
	FlagOAM       = 0x80
	FlagCritical  = 0x40
)

var (
	ErrTooShort           = errors.New("geneve packet too short")
	ErrUnsupportedVersion = errors.New("unsupported geneve version")
	ErrOptionsLength      = errors.New("invalid geneve options length")
	ErrVNI                = errors.New("invalid geneve vni")
	ErrUnknownProtocol    = errors.New("unknown geneve protocol type")
	ErrAWSVNI             = errors.New("AWS geneve profile requires VNI 0")
	ErrAWSOAM             = errors.New("AWS geneve profile rejects OAM packets")
	ErrProtocolMismatch   = errors.New("geneve protocol does not match inner IP version")
)

type Header struct {
	VNI      uint32
	Options  []byte
	Protocol uint16
	Critical bool
	OAM      bool
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
		return Header{}, nil, ErrOptionsStructure
	}
	vni := (uint32(pkt[4]) << 16) | (uint32(pkt[5]) << 8) | uint32(pkt[6])
	proto := uint16(pkt[2])<<8 | uint16(pkt[3])
	options := pkt[BaseHeaderLen:headLen]
	payload := pkt[headLen:]
	return Header{
		VNI:      vni,
		Options:  options,
		Protocol: proto,
		Critical: pkt[1]&FlagCritical != 0,
		OAM:      pkt[1]&FlagOAM != 0,
	}, payload, nil
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
	if hdr.Critical {
		dst[1] |= FlagCritical
	}
	if hdr.OAM {
		dst[1] |= FlagOAM
	}
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

// FixedFlags returns the supported fixed-header flags. Reserved bits are
// intentionally ignored on receive and emitted as zero.
func (h Header) FixedFlags() uint8 {
	var flags uint8
	if h.OAM {
		flags |= FlagOAM
	}
	if h.Critical {
		flags |= FlagCritical
	}
	return flags
}

func ValidateAWSProfile(hdr Header, payload []byte, maxOptions int) (OptionMetadata, error) {
	if hdr.VNI != 0 {
		return OptionMetadata{}, ErrAWSVNI
	}
	if hdr.OAM {
		return OptionMetadata{}, ErrAWSOAM
	}
	if hdr.Protocol != ProtoIPv4 && hdr.Protocol != ProtoIPv6 {
		return OptionMetadata{}, ErrUnknownProtocol
	}
	wantProtocol := protocolFromPayload(payload)
	if wantProtocol == protoUnknown || wantProtocol != hdr.Protocol {
		return OptionMetadata{}, ErrProtocolMismatch
	}

	metadata, err := ValidateOptions(hdr.Options, maxOptions, hdr.Critical)
	if err != nil {
		return OptionMetadata{}, err
	}
	if metadata.HasReservedBits {
		return OptionMetadata{}, ErrAWSOptionReserved
	}
	if !metadata.HasFlowCookie {
		return OptionMetadata{}, ErrAWSOptionCardinality
	}
	return metadata, nil
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
