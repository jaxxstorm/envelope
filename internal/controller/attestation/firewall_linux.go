//go:build linux

package attestation

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func getLegacy(fd, level, option int, data []byte) error {
	length := uint32(len(data))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(option), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&length)), 0)
	runtime.KeepAlive(data)
	if errno != 0 || int(length) != len(data) {
		return ErrRejected
	}
	return nil
}

func readFirewall(ctx context.Context) (map[string]firewallTable, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, ErrRejected
	}
	result := map[string]firewallTable{}
	for _, ipv6 := range []bool{false, true} {
		path, family, level, label := "/proc/net/ip_tables_names", unix.AF_INET, unix.IPPROTO_IP, "ipv4/"
		if ipv6 {
			path, family, level, label = "/proc/net/ip6_tables_names", unix.AF_INET6, unix.IPPROTO_IPV6, "ipv6/"
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, ErrRejected
		}
		names, err := io.ReadAll(io.LimitReader(file, 4097))
		_ = file.Close()
		if err != nil || len(names) > 4096 {
			return nil, ErrRejected
		}
		fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			return nil, ErrRejected
		}
		// Datagram sockets suffice for legacy GET_INFO/GET_ENTRIES; CAP_NET_RAW
		// is not needed. Linux checks CAP_NET_ADMIN for these read operations.
		err = func() error {
			defer unix.Close(fd)
			for _, name := range strings.Fields(string(names)) {
				if ctx.Err() != nil || result[label+name] != nil || (name != "filter" && name != "mangle" && name != "nat" && name != "raw" && name != "security") {
					return ErrRejected
				}
				info := make([]byte, 84)
				copy(info, name)
				if getLegacy(fd, level, 64, info) != nil {
					return ErrRejected
				}
				size := int(binary.NativeEndian.Uint32(info[80:]))
				if size <= 0 || size > 4*1024*1024 {
					return ErrRejected
				}
				entries := make([]byte, 40+size)
				copy(entries, name)
				binary.NativeEndian.PutUint32(entries[32:], uint32(size))
				if getLegacy(fd, level, 65, entries) != nil {
					return ErrRejected
				}
				after := make([]byte, 84)
				copy(after, name)
				if getLegacy(fd, level, 64, after) != nil || !bytes.Equal(info, after) {
					return ErrRejected
				}
				parsed, err := decodeFirewall(info, entries[40:], ipv6, binary.NativeEndian)
				if err != nil {
					return err
				}
				result[label+name] = parsed
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	if emptyNFT(ctx) != nil {
		return nil, ErrRejected
	}
	return result, nil
}
