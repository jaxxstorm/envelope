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
GWLB_PEER_IP = os.environ.get("E2E_GWLB_PEER_IP", "127.0.0.2")
GWLB_FLOW_PORT = int(os.environ.get("E2E_GWLB_FLOW_PORT", "40000"))
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
    vni = int.from_bytes(pkt[4:7], "big")
    return vni, pkt[8:hdr_len], pkt[hdr_len:]


def geneve_tlv(option_class, option_type, data):
    if len(data) % 4:
        raise ValueError("option data must be word aligned")
    return struct.pack("!HBB", option_class, option_type, len(data) // 4) + data


def setup_tun():
    run(["ip", "link", "set", TUN_NAME, "up"], check=False)
    run(["ip", "addr", "add", "10.0.0.1/32", "dev", TUN_NAME], check=False)
    run(["ip", "route", "add", "10.0.0.2/32", "dev", TUN_NAME], check=False)


def main():
    require_root()
    require_cmd("ip")
    require_cmd("tcpdump")

    setup_tun()

    if os.path.exists(PCAP_OUT):
        os.unlink(PCAP_OUT)

    tcpdump = subprocess.Popen(["tcpdump", "-i", TUN_NAME, "-c", "1", "-w", PCAP_OUT])
    time.sleep(0.2)

    ingress = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ingress.bind((GWLB_PEER_IP, GWLB_FLOW_PORT))
    ingress.settimeout(0.1)
    returned = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    returned.bind((GWLB_PEER_IP, 6081))
    returned.settimeout(3)

    # Inject an echo request toward the local TUN address. The kernel emits the
    # reverse echo reply into TUN, which must return on the original GWLB port
    # orientation rather than to this ingress socket.
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    inner = ipv4_header(
        20 + len(icmp),
        proto=1,
        src=b"\x0a\x00\x00\x02",
        dst=b"\x0a\x00\x00\x01",
    ) + icmp
    options = (
        geneve_tlv(0x0108, 1, bytes.fromhex("1122334455667788"))
        + geneve_tlv(0x0108, 3, bytes.fromhex("deadbeef"))
    )
    ingress.sendto(geneve_packet(0, inner, options), UDP_ADDR)

    try:
        tcpdump.wait(timeout=3)
    except subprocess.TimeoutExpired:
        tcpdump.terminate()
        sys.exit("timeout waiting for tun packet capture")

    if not os.path.exists(PCAP_OUT) or os.path.getsize(PCAP_OUT) == 0:
        sys.exit("no packet captured on tun")

    try:
        data, peer = returned.recvfrom(4096)
    except socket.timeout:
        sys.exit("timeout waiting for GWLB-oriented return packet on peer UDP/6081")

    if peer != ("127.0.0.1", GWLB_FLOW_PORT):
        sys.exit(f"wrong return source {peer!r}, want ('127.0.0.1', {GWLB_FLOW_PORT})")

    try:
        ingress.recvfrom(4096)
    except socket.timeout:
        pass
    else:
        sys.exit("received ordinary UDP reply on ingress flow port; GWLB orientation is wrong")

    try:
        vni, returned_options, payload = decode_geneve(data)
    except ValueError as e:
        sys.exit(f"invalid geneve response: {e}")

    if vni != 0 or returned_options != options:
        sys.exit("return packet changed VNI or ordered AWS options")
    if len(payload) < 28 or payload[12:16] != b"\x0a\x00\x00\x01" or payload[16:20] != b"\x0a\x00\x00\x02":
        sys.exit("return inner packet is not the reverse flow")
    if payload[20] != 0:
        sys.exit("return inner packet is not an ICMP echo reply")

    print("e2e ok: 127.0.0.1:%d -> %s:6081" % (GWLB_FLOW_PORT, GWLB_PEER_IP))


if __name__ == "__main__":
    main()
