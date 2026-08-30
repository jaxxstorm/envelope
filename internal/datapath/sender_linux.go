//go:build linux

package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const linuxRawSendTimeout = 100 * time.Millisecond

type linuxPacketSenderSyscalls interface {
	socket(domain, typ, protocol int) (int, error)
	setsockoptInt(fd, level, option, value int) error
	sendmsgN(fd int, payload, control []byte, destination unix.Sockaddr, flags int) (int, error)
	poll(fds []unix.PollFd, timeout int) (int, error)
	close(fd int) error
}

type systemLinuxPacketSenderSyscalls struct{}

func (systemLinuxPacketSenderSyscalls) socket(domain, typ, protocol int) (int, error) {
	return unix.Socket(domain, typ, protocol)
}

func (systemLinuxPacketSenderSyscalls) setsockoptInt(fd, level, option, value int) error {
	return unix.SetsockoptInt(fd, level, option, value)
}

func (systemLinuxPacketSenderSyscalls) sendmsgN(fd int, payload, control []byte, destination unix.Sockaddr, flags int) (int, error) {
	return unix.SendmsgN(fd, payload, control, destination, flags)
}

func (systemLinuxPacketSenderSyscalls) poll(fds []unix.PollFd, timeout int) (int, error) {
	return unix.Poll(fds, timeout)
}

func (systemLinuxPacketSenderSyscalls) close(fd int) error {
	return unix.Close(fd)
}

type linuxPacketSender struct {
	mu          sync.Mutex
	fd          int
	syscalls    linuxPacketSenderSyscalls
	packetPool  sync.Pool
	controlPool sync.Pool
}

func newPacketSender(maxPacket int) (PacketSender, error) {
	return newLinuxPacketSender(maxPacket, systemLinuxPacketSenderSyscalls{})
}

func newLinuxPacketSender(maxPacket int, syscalls linuxPacketSenderSyscalls) (*linuxPacketSender, error) {
	fd, err := syscalls.socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw IPv4 sender: %w", err)
	}
	if err := syscalls.setsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = syscalls.close(fd)
		return nil, fmt.Errorf("enable IP_HDRINCL: %w", err)
	}
	sender := &linuxPacketSender{fd: fd, syscalls: syscalls}
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
	written, err := s.syscalls.sendmsgN(s.fd, buf[:n], oob, sockaddr, unix.MSG_DONTWAIT)
	if written != 0 || !isWouldBlock(err) {
		return rawSendResult(written, n, err)
	}

	// A zero-byte EAGAIN is the only result that proves the packet was not
	// accepted, so it is the only result safe to retry.
	pollFDs := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLOUT}}
	ready, err := s.syscalls.poll(pollFDs, int(linuxRawSendTimeout/time.Millisecond))
	if err != nil {
		return fmt.Errorf("wait for raw IPv4 sender: %w", err)
	}
	if ready == 0 {
		return fmt.Errorf("send raw IPv4 packet: timed out after %s: %w", linuxRawSendTimeout, unix.EAGAIN)
	}
	if pollFDs[0].Revents&unix.POLLOUT == 0 {
		return fmt.Errorf("wait for raw IPv4 sender: socket not writable (revents=%#x): %w", pollFDs[0].Revents, unix.EIO)
	}

	written, err = s.syscalls.sendmsgN(s.fd, buf[:n], oob, sockaddr, unix.MSG_DONTWAIT)
	return rawSendResult(written, n, err)
}

func isWouldBlock(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

func rawSendResult(written, packetLength int, err error) error {
	if err != nil {
		if written != 0 {
			return fmt.Errorf("send raw IPv4 packet: wrote %d of %d bytes before error: %w", written, packetLength, err)
		}
		return fmt.Errorf("send raw IPv4 packet: %w", err)
	}
	if written != packetLength {
		return fmt.Errorf("send raw IPv4 packet: wrote %d of %d bytes", written, packetLength)
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
	fd := s.fd
	s.fd = -1
	return s.syscalls.close(fd)
}
