//go:build linux && integration

package tun

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOpenTun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dev, err := Open("envtest1", 1400)
	if err != nil {
		t.Fatalf("open tun: %v", err)
	}
	defer dev.Close()
	if dev.Name == "" {
		t.Fatalf("expected device name")
	}
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	if _, err := dev.Write(packet); err != nil {
		t.Fatalf("write tun: %v", err)
	}
}

func TestOpenRejectsPreexistingPersistentTun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	name := fmt.Sprintf("envexcl%d", os.Getpid()%100000)
	first, err := Open(name, 1400)
	if err != nil {
		t.Fatalf("create TUN fixture: %v", err)
	}
	if err := unix.IoctlSetInt(int(first.File.Fd()), unix.TUNSETPERSIST, 1); err != nil {
		first.Close()
		t.Fatalf("make TUN fixture persistent: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close persistent TUN fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := deletePersistentTun(name); err != nil {
			t.Errorf("delete persistent TUN fixture: %v", err)
		}
	})

	second, err := Open(name, 1400)
	if err == nil {
		second.Close()
		t.Fatal("exclusive Open attached to a pre-existing persistent TUN")
	}
}

func deletePersistentTun(name string) error {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	request := ifreq{Flags: unix.IFF_TUN | unix.IFF_NO_PI}
	copy(request.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		return errno
	}
	return unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0)
}
