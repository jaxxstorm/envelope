//go:build linux

package datapath

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type linuxPacketReceiver struct {
	conn      *net.UDPConn
	localPort uint16
	oob       []byte
}

func newPacketReceiver(bind string) (PacketReceiver, error) {
	return listenPacketReceiver(bind)
}

func listenPacketReceiver(bind string) (*linuxPacketReceiver, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	packetConn, err := lc.ListenPacket(context.Background(), "udp4", bind)
	if err != nil {
		return nil, fmt.Errorf("listen UDP4 with IP_PKTINFO: %w", err)
	}
	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("unexpected UDP packet connection type %T", packetConn)
	}
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return &linuxPacketReceiver{
		conn:      conn,
		localPort: local.Port(),
		oob:       make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo)),
	}, nil
}

func (r *linuxPacketReceiver) ReadPacket(buf []byte) (int, PacketMetadata, error) {
	n, oobn, flags, peer, err := r.conn.ReadMsgUDPAddrPort(buf, r.oob)
	if err != nil {
		return 0, PacketMetadata{}, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return 0, PacketMetadata{}, ErrPacketTruncated
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return 0, PacketMetadata{}, ErrControlTruncated
	}
	local, ifIndex, ok := parseIPv4PacketInfo(r.oob[:oobn])
	if !ok {
		return 0, PacketMetadata{}, ErrPacketInfoMissing
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	return n, PacketMetadata{
		Peer:    peer,
		Local:   netip.AddrPortFrom(local, r.localPort),
		IfIndex: ifIndex,
	}, nil
}

func parseIPv4PacketInfo(oob []byte) (netip.Addr, int, bool) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO || len(message.Data) < unix.SizeofInet4Pktinfo {
			continue
		}
		ifIndex := int(binary.NativeEndian.Uint32(message.Data[0:4]))
		var destination [4]byte
		copy(destination[:], message.Data[8:12])
		if destination == [4]byte{} {
			copy(destination[:], message.Data[4:8])
		}
		return netip.AddrFrom4(destination), ifIndex, true
	}
	return netip.Addr{}, 0, false
}

func (r *linuxPacketReceiver) SetReadDeadline(deadline time.Time) error {
	return r.conn.SetReadDeadline(deadline)
}

func (r *linuxPacketReceiver) Close() error {
	return r.conn.Close()
}
