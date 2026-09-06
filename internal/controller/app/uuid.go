package app

import (
	"encoding/hex"
	"io"
)

// RandomUUIDSource generates RFC 4122 version-4 transaction IDs directly from
// the supplied cryptographic reader. A reader failure returns an invalid empty
// ID so reconcile.Engine fails closed before route mutation.
type RandomUUIDSource struct {
	reader io.Reader
}

func NewRandomUUIDSource(reader io.Reader) *RandomUUIDSource {
	return &RandomUUIDSource{reader: reader}
}

func (s *RandomUUIDSource) NewUUID() string {
	if s == nil || s.reader == nil {
		return ""
	}
	var raw [16]byte
	if _, err := io.ReadFull(s.reader, raw[:]); err != nil {
		return ""
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80

	var encoded [36]byte
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded[:])
}
