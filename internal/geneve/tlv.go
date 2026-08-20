package geneve

import (
	"errors"
	"fmt"
)

const (
	OptionTypeCriticalMask = 0x80
	OptionTypeMask         = 0x7f
	OptionLengthMask       = 0x1f

	AWSOptionClass          = 0x0108
	AWSOptionTypeVPCE       = 1
	AWSOptionTypeAttachment = 2
	AWSOptionTypeFlowCookie = 3
	AWSVPCEIDLength         = 8
	AWSAttachmentIDLength   = 8
	AWSFlowCookieLength     = 4
)

var (
	ErrOptionsStructure     = errors.New("invalid geneve options structure")
	ErrOptionsSize          = errors.New("geneve options exceed configured size")
	ErrCriticalOptions      = errors.New("invalid geneve critical-option semantics")
	ErrAWSOptionLength      = errors.New("invalid AWS geneve option length")
	ErrAWSOptionCardinality = errors.New("invalid AWS geneve option cardinality")
	ErrAWSOptionReserved    = errors.New("AWS geneve options require zero reserved bits")
)

type TLVKey struct {
	Class uint16
	Type  uint8
}

type TLV struct {
	Class    uint16
	Type     uint8
	Critical bool
	Reserved uint8
	Length   int
	Data     []byte
}

type OptionMetadata struct {
	AWSProfile      bool
	HasFlowCookie   bool
	HasReservedBits bool
	FlowCookie      [AWSFlowCookieLength]byte
}

// TLVIterator exposes zero-copy views over an options block. Callers must not
// retain Data after the packet buffer is released.
type TLVIterator struct {
	options []byte
	offset  int
	current TLV
	err     error
}

func NewTLVIterator(options []byte) TLVIterator {
	return TLVIterator{options: options}
}

func (i *TLVIterator) Next() bool {
	if i.err != nil || i.offset == len(i.options) {
		return false
	}
	if i.offset > len(i.options) || len(i.options)-i.offset < 4 {
		i.err = ErrOptionsStructure
		return false
	}

	lengthByte := i.options[i.offset+3]
	dataLen := int(lengthByte&OptionLengthMask) * 4
	dataStart := i.offset + 4
	dataEnd := dataStart + dataLen
	if dataEnd > len(i.options) {
		i.err = ErrOptionsStructure
		return false
	}

	rawType := i.options[i.offset+2]
	i.current = TLV{
		Class:    uint16(i.options[i.offset])<<8 | uint16(i.options[i.offset+1]),
		Type:     rawType & OptionTypeMask,
		Critical: rawType&OptionTypeCriticalMask != 0,
		Reserved: lengthByte >> 5,
		Length:   dataLen,
		Data:     i.options[dataStart:dataEnd],
	}
	i.offset = dataEnd
	return true
}

func (i *TLVIterator) TLV() TLV {
	return i.current
}

func (i *TLVIterator) Err() error {
	return i.err
}

func ValidateOptions(options []byte, max int, baseCritical bool) (OptionMetadata, error) {
	var metadata OptionMetadata
	if max <= 0 || max > MaxOptionsLen || max%4 != 0 {
		return metadata, fmt.Errorf("%w: invalid maximum %d", ErrOptionsSize, max)
	}
	if len(options)%4 != 0 {
		return metadata, ErrOptionsStructure
	}
	if len(options) > max || len(options) > MaxOptionsLen {
		return metadata, ErrOptionsSize
	}

	var (
		hasCritical      bool
		unknownCritical  bool
		awsLengthInvalid bool
		vpceCount        int
		attachmentCount  int
		flowCookieCount  int
	)
	it := NewTLVIterator(options)
	for it.Next() {
		tlv := it.TLV()
		metadata.HasReservedBits = metadata.HasReservedBits || tlv.Reserved != 0
		if tlv.Critical {
			hasCritical = true
			if !isKnownOption(tlv.Class, tlv.Type) {
				unknownCritical = true
			}
		}
		if tlv.Class != AWSOptionClass {
			continue
		}

		metadata.AWSProfile = true
		switch tlv.Type {
		case AWSOptionTypeVPCE:
			vpceCount++
			awsLengthInvalid = awsLengthInvalid || tlv.Length != AWSVPCEIDLength
		case AWSOptionTypeAttachment:
			attachmentCount++
			awsLengthInvalid = awsLengthInvalid || tlv.Length != AWSAttachmentIDLength
		case AWSOptionTypeFlowCookie:
			flowCookieCount++
			if tlv.Length != AWSFlowCookieLength {
				awsLengthInvalid = true
				continue
			}
			copy(metadata.FlowCookie[:], tlv.Data)
		}
	}
	if err := it.Err(); err != nil {
		return OptionMetadata{}, err
	}
	if hasCritical != baseCritical || unknownCritical {
		return OptionMetadata{}, ErrCriticalOptions
	}
	if awsLengthInvalid {
		return OptionMetadata{}, ErrAWSOptionLength
	}
	if metadata.AWSProfile && (flowCookieCount != 1 || vpceCount > 1 || attachmentCount > 1) {
		return OptionMetadata{}, ErrAWSOptionCardinality
	}
	metadata.HasFlowCookie = flowCookieCount == 1
	return metadata, nil
}

func isKnownOption(class uint16, typ uint8) bool {
	if class != AWSOptionClass {
		return false
	}
	switch typ {
	case AWSOptionTypeVPCE, AWSOptionTypeAttachment, AWSOptionTypeFlowCookie:
		return true
	default:
		return false
	}
}
