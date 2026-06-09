#!/usr/bin/env python3
import os
import socket
import struct
import subprocess
import sys
import time
import shutil

TUN_NAME = os.environ.get("E2E_TUN_NAME", "envelope0")
UDP_ADDR = (
    os.environ.get("E2E_UDP_HOST", "127.0.0.1"),
    int(os.environ.get("E2E_UDP_PORT", "6081")),
)
PCAP_OUT = "/tmp/envelope_ingress.pcap"


def require_root():
    if os.geteuid() != 0:
        sys.exit("root required")


def require_cmd(name):
    if shutil.which(name) is None:
        sys.exit(f"missing required tool: {name}")


def run(cmd, check=True):
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ipv4_header(total_len, proto=17, src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02"):
    ver_ihl = 0x45
    tos = 0
    ident = 0
    flags_frag = 0
    ttl = 64
    hdr = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src, dst
    )
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, csum, src, dst
    )


def geneve_packet(vni, payload, options=b""):
    if len(options) % 4 != 0:
        raise ValueError("options length must be multiple of 4")
    opt_words = len(options) // 4
    b0 = (0 << 6) | opt_words
    hdr = bytes([b0, 0, 0x08, 0x00, (vni >> 16) & 0xff, (vni >> 8) & 0xff, vni & 0xff, 0])
    return hdr + options + payload


def decode_geneve(pkt):
    if len(pkt) < 8:
        raise ValueError("geneve too short")
    ver = pkt[0] >> 6
    if ver != 0:
        raise ValueError("unsupported version")
    opt_len = (pkt[0] & 0x3f) * 4
    hdr_len = 8 + opt_len
    if len(pkt) < hdr_len:
        raise ValueError("geneve header too short")
    return pkt[hdr_len:]


def setup_tun():
    run(["ip", "link", "set", TUN_NAME, "up"], check=False)
    run(["ip", "addr", "add", "10.0.0.1/32", "dev", TUN_NAME], check=False)
    run(["ip", "route", "add", "10.0.0.2/32", "dev", TUN_NAME], check=False)


def main():
    require_root()
    require_cmd("ip")
    require_cmd("tcpdump")
    require_cmd("ping")

    setup_tun()

    if os.path.exists(PCAP_OUT):
        os.unlink(PCAP_OUT)

    tcpdump = subprocess.Popen(["tcpdump", "-i", TUN_NAME, "-c", "1", "-w", PCAP_OUT])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(3)

    # Seed flow mapping using ICMP so the ping flow matches.
    icmp_payload = b"\x08\x00\x00\x00\x00\x00\x00\x00"
    inner = ipv4_header(20 + len(icmp_payload), proto=1) + icmp_payload
    pkt = geneve_packet(1, inner)
    sock.sendto(pkt, UDP_ADDR)

    try:
        tcpdump.wait(timeout=3)
    except subprocess.TimeoutExpired:
        tcpdump.terminate()
        sys.exit("timeout waiting for tun packet capture")

    if not os.path.exists(PCAP_OUT) or os.path.getsize(PCAP_OUT) == 0:
        sys.exit("no packet captured on tun")

    # Trigger egress by sending a routed packet to the TUN interface.
    run(["ping", "-c", "1", "-W", "1", "10.0.0.2"], check=False)

    try:
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        sys.exit("timeout waiting for geneve response")

    try:
        payload = decode_geneve(data)
    except ValueError as e:
        sys.exit(f"invalid geneve response: {e}")

    if len(payload) == 0:
        sys.exit("empty geneve payload")

    print("e2e ok")


if __name__ == "__main__":
    main()
