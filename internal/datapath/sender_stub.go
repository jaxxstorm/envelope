//go:build !linux

package datapath

func newPacketSender(int) (PacketSender, error) {
	return nil, ErrUnsupportedPlatform
}
