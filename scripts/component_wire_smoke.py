#!/usr/bin/env python3
import os
import re
import socket
import struct
import sys
import urllib.request

UDP_ADDR = (
    os.environ.get("E2E_UDP_HOST", "127.0.0.1"),
    int(os.environ.get("E2E_UDP_PORT", "6081")),
)
GWLB_PEER_IP = os.environ.get("E2E_GWLB_PEER_IP", "127.0.0.2")
GWLB_FLOW_PORT = int(os.environ.get("E2E_GWLB_FLOW_PORT", "40000"))
METRICS_URL = os.environ.get("E2E_METRICS_URL", "http://127.0.0.1:9090/metrics")


def require_root() -> None:
    if os.geteuid() != 0:
        print("root is required by the component wire smoke runner", file=sys.stderr)
        raise SystemExit(77)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ipv4_packet(
    protocol: int,
    payload: bytes,
    identification: int,
    *,
    fragment: int = 0,
    source: bytes = b"\x0a\x00\x00\x01",
    destination: bytes = b"\x0a\x00\x00\x02",
) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        fragment,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6_packet(next_header: int, payload: bytes) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
    ) + payload


def inner_packets() -> list[tuple[str, int, bytes]]:
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    tcp = struct.pack(
        "!HHIIBBHHH", 12345, 443, 1, 0, 5 << 4, 0x02, 65535, 0, 0
    )
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    ipv6_fragment = struct.pack("!BBHI", 17, 0, 1, 0x12345678)
    ipv6_extension = bytes((6, 0)) + bytes(6) + tcp
    return [
        ("TCP", 0x0800, ipv4_packet(6, tcp, 0x1001)),
        ("UDP", 0x0800, ipv4_packet(17, udp, 0x1002)),
        ("ICMP", 0x0800, ipv4_packet(1, icmp, 0x1003)),
        (
            "non-initial IPv4 fragment",
            0x0800,
            ipv4_packet(17, bytes.fromhex("d1d2d3d4d5d6d7d8"), 0x1004, fragment=1),
        ),
        ("short opaque UDP payload", 0x0800, ipv4_packet(17, udp[:4], 0x1005)),
        ("short opaque TCP payload", 0x0800, ipv4_packet(6, tcp[:19], 0x1006)),
        ("IPv6 fragment", 0x86DD, ipv6_packet(44, ipv6_fragment)),
        ("IPv6 extension", 0x86DD, ipv6_packet(0, ipv6_extension)),
    ]


def geneve_packet(
    vni: int,
    payload: bytes,
    options: bytes = b"",
    *,
    protocol: int = 0x0800,
    critical: bool = False,
) -> bytes:
    if len(options) % 4 != 0:
        raise ValueError("options length must be multiple of 4")
    opt_words = len(options) // 4
    b0 = (0 << 6) | opt_words
    hdr = bytes(
        [
            b0,
            0x40 if critical else 0,
            protocol >> 8,
            protocol & 0xFF,
            (vni >> 16) & 0xFF,
            (vni >> 8) & 0xFF,
            vni & 0xFF,
            0,
        ]
    )
    return hdr + options + payload


def decode_geneve(pkt: bytes) -> tuple[int, bytes, bytes]:
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


def geneve_tlv(option_class: int, option_type: int, data: bytes) -> bytes:
    if len(data) % 4:
        raise ValueError("option data must be word aligned")
    return struct.pack("!HBB", option_class, option_type, len(data) // 4) + data


def options_for(cookie: int) -> bytes:
    return (
        geneve_tlv(0x0108, 1, bytes.fromhex("1122334455667788"))
        + geneve_tlv(0x2222, 0x7E, bytes.fromhex("01020304"))
        + geneve_tlv(0x0108, 2, bytes.fromhex("8877665544332211"))
        + geneve_tlv(0x0108, 3, cookie.to_bytes(4, "big"))
    )


def main() -> None:
    require_root()
    packets = inner_packets()

    gwlb_flow = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gwlb_flow.bind((GWLB_PEER_IP, GWLB_FLOW_PORT))
    gwlb_flow.settimeout(0.2)
    returned = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    returned.bind((GWLB_PEER_IP, 6081))
    returned.settimeout(3)

    for index, (name, protocol, inner) in enumerate(packets, start=1):
        options = options_for(index)
        packet = geneve_packet(0, inner, options, protocol=protocol)
        gwlb_flow.sendto(packet, UDP_ADDR)
        try:
            data, peer = returned.recvfrom(65535)
        except socket.timeout:
            sys.exit(f"timeout waiting for immediate {name} packet turnaround")

        expected_peer = (UDP_ADDR[0], GWLB_FLOW_PORT)
        if peer != expected_peer:
            sys.exit(f"wrong return source {peer!r}, want {expected_peer!r}")
        try:
            vni, returned_options, payload = decode_geneve(data)
        except ValueError as error:
            sys.exit(f"invalid {name} GENEVE response: {error}")
        if vni != 0 or returned_options != options or payload != inner or data != packet:
            sys.exit(f"{name} return changed VNI, ordered options, cookie, or inner bytes")

        returned.settimeout(0.1)
        try:
            returned.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            sys.exit(f"{name} GWLB flow produced more than one return")
        returned.settimeout(3)

    try:
        gwlb_flow.recvfrom(65535)
    except socket.timeout:
        pass
    else:
        sys.exit("received ordinary UDP reply on the GWLB flow port; orientation is wrong")

    invalid_packets = (
        (
            "missing flow cookie",
            geneve_packet(
                0,
                packets[0][2],
                geneve_tlv(0x0108, 1, bytes.fromhex("1122334455667788")),
            ),
        ),
        (
            "malformed option block",
            geneve_packet(0, packets[0][2], bytes.fromhex("12340102aabbccdd")),
        ),
        (
            "unknown critical option",
            geneve_packet(
                0,
                packets[0][2],
                options_for(0xFFFF) + geneve_tlv(0x2222, 0xFE, b""),
                critical=True,
            ),
        ),
    )
    for name, invalid in invalid_packets:
        gwlb_flow.sendto(invalid, UDP_ADDR)
        returned.settimeout(0.25)
        try:
            returned.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            sys.exit(f"{name} produced a return packet")

    metrics = urllib.request.urlopen(METRICS_URL, timeout=1).read().decode()
    packet_values = {}
    readiness_components = {}
    target_ready = None
    obsolete_prefixes = (
        "datapath_",
        "gwlb_conflicted_contexts",
        "gwlb_context_",
        "gwlb_missing_contexts",
        "gwlb_possible_loops",
        "gwlb_unsupported_inner",
        "routing_",
        "symmetric_unexpected_egress",
        "tun_",
    )
    for line in metrics.splitlines():
        if not line or line.startswith("#"):
            continue
        series, raw_value = line.split()
        name = series.split("{", 1)[0]
        if name.startswith(obsolete_prefixes):
            sys.exit(f"target exposed obsolete metric {name}")
        if name in {"geneve_rx_packets", "geneve_tx_packets"}:
            packet_values[name] = float(raw_value)
        elif name == "gwlb_target_ready":
            target_ready = float(raw_value)
        elif name == "gwlb_target_component_ready":
            match = re.search(r'component="([^"]+)"', series)
            if match:
                readiness_components[match.group(1)] = float(raw_value)
    expected_packets = {
        "geneve_rx_packets": float(len(packets)),
        "geneve_tx_packets": float(len(packets)),
    }
    if packet_values != expected_packets:
        sys.exit(f"unexpected packet-turnaround metrics: {packet_values!r}")
    expected_components = {"receiver": 1.0, "validation": 1.0, "sender": 1.0}
    if target_ready != 1.0 or readiness_components != expected_components:
        sys.exit(
            "target readiness metrics are incomplete: "
            f"ready={target_ready!r} components={readiness_components!r}"
        )

    print(
        "packet-turnaround smoke ok: TCP/UDP/ICMP/fragment/short-L4/IPv6 "
        f"{UDP_ADDR[0]}:{GWLB_FLOW_PORT} -> {GWLB_PEER_IP}:6081"
    )


if __name__ == "__main__":
    main()
