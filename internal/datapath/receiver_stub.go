//go:build !linux

package datapath

func newPacketReceiver(string) (PacketReceiver, error) {
	return nil, ErrUnsupportedPlatform
}
