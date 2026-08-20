//go:build linux

package datapath

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxPacketSender struct {
	mu          sync.Mutex
	fd          int
	packetPool  sync.Pool
	controlPool sync.Pool
}

func newPacketSender(maxPacket int) (PacketSender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw IPv4 sender: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("enable IP_HDRINCL: %w", err)
	}
	sender := &linuxPacketSender{fd: fd}
	sender.packetPool.New = func() any {
		return make([]byte, maxPacket)
	}
	sender.controlPool.New = func() any {
		return make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	}
	return sender, nil
}

func (s *linuxPacketSender) SendPacket(req SendRequest) error {
	buf := s.packetPool.Get().([]byte)
	defer s.packetPool.Put(buf)
	n, err := BuildIPv4UDPPacket(buf, req)
	if err != nil {
		return err
	}
	destination := req.Destination.Addr().Unmap().As4()
	sockaddr := &unix.SockaddrInet4{Port: int(req.Destination.Port()), Addr: destination}
	oob := s.controlPool.Get().([]byte)
	defer s.controlPool.Put(oob)
	oob, err = fillIPv4PacketInfoControl(oob, req)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return net.ErrClosed
	}
	written, err := unix.SendmsgN(s.fd, buf[:n], oob, sockaddr, 0)
	if err != nil {
		return fmt.Errorf("send raw IPv4 packet: %w", err)
	}
	if written != n {
		return fmt.Errorf("send raw IPv4 packet: wrote %d of %d bytes", written, n)
	}
	return nil
}

func ipv4PacketInfoControl(req SendRequest) ([]byte, error) {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	return fillIPv4PacketInfoControl(oob, req)
}

func fillIPv4PacketInfoControl(oob []byte, req SendRequest) ([]byte, error) {
	source := req.Source.Addr().Unmap()
	if !source.Is4() || req.IfIndex <= 0 || uint64(req.IfIndex) > uint64(^uint32(0)) {
		return nil, ErrInvalidOuterPacket
	}
	controlLength := unix.CmsgSpace(unix.SizeofInet4Pktinfo)
	if len(oob) < controlLength {
		return nil, ErrInvalidOuterPacket
	}
	oob = oob[:controlLength]
	clear(oob)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	dataOffset := unix.CmsgLen(0)
	binary.NativeEndian.PutUint32(oob[dataOffset:dataOffset+4], uint32(req.IfIndex))
	sourceBytes := source.As4()
	copy(oob[dataOffset+4:dataOffset+8], sourceBytes[:])
	return oob, nil
}

func (s *linuxPacketSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}
