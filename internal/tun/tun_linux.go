//go:build linux

package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Device struct {
	File *os.File
	Name string
	MTU  int
}

func Open(name string, mtu int) (*Device, error) {
	if name == "" {
		return nil, fmt.Errorf("tun name required")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr := ifreq{}
	copy(ifr.Name[:], name)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun setiff: %w", errno)
	}
	actualName := ifr.nameString()
	if mtu > 0 {
		if err := setMTU(actualName, mtu); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	if err := setUp(actualName); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), actualName)
	return &Device{File: file, Name: actualName, MTU: mtu}, nil
}

func (d *Device) Read(p []byte) (int, error) {
	return d.File.Read(p)
}

func (d *Device) Write(p []byte) (int, error) {
	return d.File.Write(p)
}

func (d *Device) Close() error {
	return d.File.Close()
}

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

func (i *ifreq) nameString() string {
	name := i.Name[:]
	for idx, b := range name {
		if b == 0 {
			return string(name[:idx])
		}
	}
	return string(name)
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	Pad  [24]byte
}

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

func setMTU(name string, mtu int) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(sock)
	ifr := ifreqMTU{}
	copy(ifr.Name[:], name)
	ifr.MTU = int32(mtu)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("set MTU: %w", errno)
	}
	return nil
}

func setUp(name string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(sock)
	ifr := ifreqFlags{}
	copy(ifr.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("get flags: %w", errno)
	}
	ifr.Flags |= unix.IFF_UP | unix.IFF_RUNNING
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("set flags: %w", errno)
	}
	return nil
}
