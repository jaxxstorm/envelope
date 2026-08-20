package datapath

import (
	"encoding/binary"
	"fmt"
)

const (
	ipv4HeaderLen  = 20
	udpHeaderLen   = 8
	outerHeaderLen = ipv4HeaderLen + udpHeaderLen
)

func BuildIPv4UDPPacket(dst []byte, req SendRequest) (int, error) {
	srcAddr := req.Source.Addr().Unmap()
	dstAddr := req.Destination.Addr().Unmap()
	if !srcAddr.Is4() || !dstAddr.Is4() || req.Source.Port() == 0 || req.Destination.Port() == 0 {
		return 0, ErrInvalidOuterPacket
	}
	totalLen := outerHeaderLen + len(req.Payload)
	if totalLen > 65535 || len(dst) < totalLen {
		return 0, fmt.Errorf("%w: packet length %d", ErrInvalidOuterPacket, totalLen)
	}

	packet := dst[:totalLen]
	clear(packet[:outerHeaderLen])
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	// Envelope never fragments inner or outer traffic. Keep DF set so the
	// network reports an MTU problem rather than changing the GWLB datagram.
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	packet[8] = 64
	packet[9] = 17
	src := srcAddr.As4()
	dstIP := dstAddr.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dstIP[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:ipv4HeaderLen]))

	udp := packet[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], req.Source.Port())
	binary.BigEndian.PutUint16(udp[2:4], req.Destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLen:], req.Payload)
	checksum := udpIPv4Checksum(src, dstIP, udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return totalLen, nil
}

func internetChecksum(data []byte) uint16 {
	return finalizeChecksum(checksumBytes(0, data))
}

func udpIPv4Checksum(src, dst [4]byte, udp []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	sum := checksumBytes(0, pseudo[:])
	sum = checksumBytes(sum, udp)
	return finalizeChecksum(sum)
}

func checksumBytes(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func finalizeChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
