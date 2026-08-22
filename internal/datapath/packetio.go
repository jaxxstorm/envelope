package datapath

import (
	"errors"
	"net/netip"
	"time"
)

const awsGenevePort = 6081

var (
	ErrUnsupportedPlatform = errors.New("AWS GWLB receiver is only supported on Linux")
	ErrPacketInfoMissing   = errors.New("IPv4 packet info is missing")
	ErrPacketTruncated     = errors.New("received UDP datagram is truncated")
	ErrControlTruncated    = errors.New("received packet control data is truncated")
	ErrInvalidOuterPacket  = errors.New("invalid outer IPv4/UDP packet request")
)

type PacketMetadata struct {
	Peer    netip.AddrPort
	Local   netip.AddrPort
	IfIndex int
}

type PacketReceiver interface {
	ReadPacket([]byte) (int, PacketMetadata, error)
	SetReadDeadline(time.Time) error
	Close() error
}
