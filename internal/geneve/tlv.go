package geneve

import "fmt"

type TLVKey struct {
	Class uint16
	Type  uint8
}

type TLV struct {
	Class  uint16
	Type   uint8
	Length int
	Data   []byte
}

func ValidateOptions(options []byte, max int) error {
	if len(options)%4 != 0 {
		return ErrOptionsLength
	}
	if max <= 0 {
		return fmt.Errorf("invalid geneve options max %d", max)
	}
	if len(options) > max || len(options) > MaxOptionsLen {
		return ErrOptionsLength
	}
	return nil
}

func ParseTLVs(options []byte) ([]TLV, error) {
	if len(options)%4 != 0 {
		return nil, ErrOptionsLength
	}
	tlvs := make([]TLV, 0, len(options)/4)
	for offset := 0; offset < len(options); {
		if len(options)-offset < 4 {
			return nil, ErrOptionsLength
		}
		class := uint16(options[offset])<<8 | uint16(options[offset+1])
		typ := options[offset+2]
		dataLen := int(options[offset+3]) * 4
		total := 4 + dataLen
		if total < 4 || offset+total > len(options) {
			return nil, ErrOptionsLength
		}
		dataStart := offset + 4
		dataEnd := dataStart + dataLen
		tlvs = append(tlvs, TLV{
			Class:  class,
			Type:   typ,
			Length: dataLen,
			Data:   options[dataStart:dataEnd],
		})
		offset += total
	}
	return tlvs, nil
}
