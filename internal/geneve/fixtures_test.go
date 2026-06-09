package geneve

var (
	fixtureMinimal = func() []byte {
		payload := []byte{0x45, 0x00, 0x00, 0x14}
		buf := make([]byte, 64)
		n, _ := Encode(buf, Header{VNI: 0x000001}, payload)
		return buf[:n]
	}()

	fixtureWithOptions = func() []byte {
		payload := []byte{0x60, 0x00, 0x00, 0x00}
		options := []byte{0x01, 0x02, 0x03, 0x04}
		buf := make([]byte, 64)
		n, _ := Encode(buf, Header{VNI: 0x000002, Options: options}, payload)
		return buf[:n]
	}()

	fixtureOversized = func() []byte {
		// Create a header that claims options but does not include them.
		pkt := make([]byte, BaseHeaderLen)
		pkt[0] = byte((Version << 6) | 1)
		return pkt
	}()
)
