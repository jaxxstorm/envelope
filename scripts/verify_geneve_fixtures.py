#!/usr/bin/env python3
"""Generate and independently verify sanitized AWS GENEVE-option PCAPs."""

import argparse
import ipaddress
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "testdata" / "pcap"
AWS_CLASS = 0x0108
AWS_VPCE = 1
AWS_ATTACHMENT = 2
AWS_FLOW_COOKIE = 3
TYPE_CRITICAL = 0x80
MAX_OPTIONS = 252

VPCE_ID = bytes.fromhex("1122334455667788")
ATTACHMENT_ID = bytes.fromhex("9182736455463728")
FLOW_COOKIE = bytes.fromhex("deadbeef")


def tlv(option_class, option_type, data=b"", reserved=0):
    if len(data) % 4 or not 0 <= reserved <= 7:
        raise ValueError("invalid fixture TLV")
    return struct.pack("!HBB", option_class, option_type, (reserved << 5) | (len(data) // 4)) + data


VPCE = tlv(AWS_CLASS, AWS_VPCE, VPCE_ID)
ATTACHMENT = tlv(AWS_CLASS, AWS_ATTACHMENT, ATTACHMENT_ID)
COOKIE = tlv(AWS_CLASS, AWS_FLOW_COOKIE, FLOW_COOKIE)
FUTURE = tlv(AWS_CLASS, 0x7E, bytes.fromhex("01020304"))


FIXTURES = (
    ("geneve-minimal.pcap", b"", False, None, MAX_OPTIONS, None),
    ("geneve-options.pcap", VPCE + COOKIE, False, None, MAX_OPTIONS, None),
    ("geneve-options-reordered.pcap", COOKIE + ATTACHMENT + FUTURE + VPCE, False, None, MAX_OPTIONS, None),
    ("geneve-options-reserved.pcap", tlv(AWS_CLASS, AWS_VPCE, VPCE_ID, reserved=5) + COOKIE, False, None, MAX_OPTIONS, None),
    ("geneve-options-known-critical.pcap", VPCE + tlv(AWS_CLASS, TYPE_CRITICAL | AWS_FLOW_COOKIE, FLOW_COOKIE), True, None, MAX_OPTIONS, None),
    ("geneve-options-unknown-noncritical.pcap", VPCE + FUTURE + COOKIE, False, None, MAX_OPTIONS, None),
    ("geneve-options-malformed.pcap", bytes.fromhex("12340102aabbccdd"), False, None, MAX_OPTIONS, "structural"),
    ("geneve-options-aws-length.pcap", tlv(AWS_CLASS, AWS_VPCE, VPCE_ID[:4]) + COOKIE, False, None, MAX_OPTIONS, "aws_length"),
    ("geneve-options-missing-cookie.pcap", VPCE, False, None, MAX_OPTIONS, "aws_cardinality"),
    ("geneve-options-duplicate-cookie.pcap", VPCE + COOKIE + COOKIE, False, None, MAX_OPTIONS, "aws_cardinality"),
    ("geneve-options-duplicate-vpce.pcap", VPCE + COOKIE + VPCE, False, None, MAX_OPTIONS, "aws_cardinality"),
    ("geneve-options-unknown-critical.pcap", VPCE + COOKIE + tlv(0x2222, TYPE_CRITICAL | 0x7E), True, None, MAX_OPTIONS, "critical"),
    ("geneve-options-critical-without-base.pcap", VPCE + tlv(AWS_CLASS, TYPE_CRITICAL | AWS_FLOW_COOKIE, FLOW_COOKIE), False, None, MAX_OPTIONS, "critical"),
    ("geneve-options-base-without-critical.pcap", VPCE + COOKIE, True, None, MAX_OPTIONS, "critical"),
    ("geneve-options-size.pcap", VPCE + COOKIE, False, None, 16, "size"),
    ("geneve-oversize.pcap", b"", False, 1, MAX_OPTIONS, "decode"),
)

GWLB_FIXTURES = (
    ("gwlb-valid-ipv4.pcap", {}, None),
    ("gwlb-nonzero-vni.pcap", {"vni": 1}, "vni"),
    ("gwlb-oam.pcap", {"oam": True}, "oam"),
    ("gwlb-option-reserved.pcap", {"options": tlv(AWS_CLASS, AWS_VPCE, VPCE_ID, reserved=1) + COOKIE}, "option_reserved"),
    ("gwlb-missing-cookie.pcap", {"options": VPCE}, "aws_cardinality"),
    ("gwlb-duplicate-cookie.pcap", {"options": VPCE + COOKIE + COOKIE}, "aws_cardinality"),
    ("gwlb-protocol-mismatch.pcap", {"protocol": 0x86DD}, "protocol"),
    ("gwlb-wrong-destination-port.pcap", {"destination_port": 6080}, "listener"),
    ("gwlb-bad-ip-checksum.pcap", {"bad_ip_checksum": True}, "outer_checksum"),
    ("gwlb-bad-udp-checksum.pcap", {"bad_udp_checksum": True}, "outer_checksum"),
    ("gwlb-inner-ipv4-fragment.pcap", {"inner": "ipv4_fragment"}, None),
    ("gwlb-inner-udp-truncated.pcap", {"inner": "udp_truncated"}, None),
    ("gwlb-inner-ipv6-fragment.pcap", {"inner": "ipv6_fragment", "protocol": 0x86DD}, None),
    ("gwlb-inner-ipv6-extension.pcap", {"inner": "ipv6_extension", "protocol": 0x86DD}, None),
)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def inner_ipv4():
    src = ipaddress.IPv4Address("10.0.0.1").packed
    dst = ipaddress.IPv4Address("10.0.0.2").packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 1, 0, 64, 1, 0, src, dst)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def inner_ipv4_udp(fragment=0, truncated=False):
    src = ipaddress.IPv4Address("10.0.0.1").packed
    dst = ipaddress.IPv4Address("10.0.0.2").packed
    udp = struct.pack("!HHHH", 1234, 443, 8, 0)
    if truncated:
        udp = udp[:4]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, fragment, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + udp


def inner_ipv6(next_header, extension):
    src = ipaddress.IPv6Address("2001:db8::1").packed
    dst = ipaddress.IPv6Address("2001:db8::2").packed
    header = struct.pack("!IHBB16s16s", 6 << 28, len(extension), next_header, 64, src, dst)
    return header + extension


def frame(
    options,
    base_critical=False,
    claimed_words=None,
    include_inner=True,
    vni=0,
    oam=False,
    protocol=0x0800,
    source_port=40000,
    destination_port=6081,
    inner=None,
    bad_ip_checksum=False,
    bad_udp_checksum=False,
):
    if len(options) % 4:
        raise ValueError("fixture options must be word aligned")
    words = len(options) // 4 if claimed_words is None else claimed_words
    flags = (0x40 if base_critical else 0) | (0x80 if oam else 0)
    if not include_inner:
        payload = b""
    elif inner == "ipv4_fragment":
        payload = inner_ipv4_udp(fragment=0x2000)
    elif inner == "udp_truncated":
        payload = inner_ipv4_udp(truncated=True)
    elif inner == "ipv6_fragment":
        payload = inner_ipv6(44, bytes(8))
    elif inner == "ipv6_extension":
        payload = inner_ipv6(0, bytes((6, 0)) + bytes(6) + bytes(20))
    elif inner == "ipv4_udp":
        payload = inner_ipv4_udp()
    else:
        payload = inner_ipv4()
    geneve = bytes((
        words,
        flags,
        protocol >> 8,
        protocol & 0xFF,
        (vni >> 16) & 0xFF,
        (vni >> 8) & 0xFF,
        vni & 0xFF,
        0,
    )) + options + payload

    src_ip = ipaddress.IPv4Address("192.0.2.10").packed
    dst_ip = ipaddress.IPv4Address("198.51.100.20").packed
    udp_length = 8 + len(geneve)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + geneve
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_length)
    udp_checksum = checksum(pseudo + udp)
    udp = udp[:6] + struct.pack("!H", udp_checksum or 0xFFFF) + udp[8:]
    if bad_udp_checksum:
        udp = udp[:6] + bytes((udp[6] ^ 0xFF, udp[7])) + udp[8:]

    ip_length = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_length, 1, 0, 64, 17, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    if bad_ip_checksum:
        ip = ip[:10] + bytes((ip[10] ^ 0xFF, ip[11])) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + udp


def pcap(packet):
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 1700000000, 0, len(packet), len(packet))
    return global_header + record_header + packet


def read_packet(path):
    data = path.read_bytes()
    if len(data) < 40:
        raise ValueError("pcap too short")
    magic, major, minor, _, _, _, link_type = struct.unpack("<IHHIIII", data[:24])
    if (magic, major, minor, link_type) != (0xA1B2C3D4, 2, 4, 1):
        raise ValueError("unexpected pcap header")
    _, _, captured, original = struct.unpack("<IIII", data[24:40])
    if captured != original or len(data) != 40 + captured:
        raise ValueError("invalid pcap record length")
    return data[40:]


def decode_options(packet):
    if len(packet) < 14 + 20 + 8 + 8 or packet[12:14] != b"\x08\x00":
        raise ValueError("missing Ethernet/IPv4/UDP/GENEVE headers")
    ip = packet[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or checksum(ip[:ihl]) != 0 or ip[9] != 17:
        raise ValueError("invalid IPv4 header")
    ip_length = struct.unpack("!H", ip[2:4])[0]
    udp = ip[ihl:ip_length]
    if len(udp) < 8 or struct.unpack("!H", udp[2:4])[0] != 6081:
        raise ValueError("invalid UDP header")
    udp_length = struct.unpack("!H", udp[4:6])[0]
    if udp_length != len(udp):
        raise ValueError("invalid UDP length")
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, udp_length)
    if checksum(pseudo + udp) != 0:
        raise ValueError("invalid UDP checksum")

    geneve = udp[8:]
    if geneve[0] >> 6 != 0:
        raise ValueError("unsupported GENEVE version")
    options_length = (geneve[0] & 0x3F) * 4
    if len(geneve) < 8 + options_length:
        raise ValueError("decode")
    return geneve[8:8 + options_length], bool(geneve[1] & 0x40)


def validate_options(options, base_critical, maximum):
    if len(options) > maximum:
        return "size"
    offset = 0
    has_critical = False
    unknown_critical = False
    aws_seen = False
    bad_aws_length = False
    counts = {AWS_VPCE: 0, AWS_ATTACHMENT: 0, AWS_FLOW_COOKIE: 0}
    while offset < len(options):
        if len(options) - offset < 4:
            return "structural"
        option_class, raw_type, length_byte = struct.unpack("!HBB", options[offset:offset + 4])
        option_type = raw_type & 0x7F
        critical = bool(raw_type & TYPE_CRITICAL)
        data_length = (length_byte & 0x1F) * 4
        end = offset + 4 + data_length
        if end > len(options):
            return "structural"
        known = option_class == AWS_CLASS and option_type in counts
        has_critical |= critical
        unknown_critical |= critical and not known
        if option_class == AWS_CLASS:
            aws_seen = True
            if option_type in counts:
                counts[option_type] += 1
                expected = 4 if option_type == AWS_FLOW_COOKIE else 8
                bad_aws_length |= data_length != expected
        offset = end
    if has_critical != base_critical or unknown_critical:
        return "critical"
    if bad_aws_length:
        return "aws_length"
    if aws_seen and (counts[AWS_FLOW_COOKIE] != 1 or counts[AWS_VPCE] > 1 or counts[AWS_ATTACHMENT] > 1):
        return "aws_cardinality"
    return None


def write_fixtures():
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, options, critical, claimed_words, _, expected_error in FIXTURES:
        packet = frame(options, critical, claimed_words, include_inner=expected_error != "decode")
        (FIXTURE_DIR / name).write_bytes(pcap(packet))
    for name, overrides, _ in GWLB_FIXTURES:
        arguments = {"options": VPCE + COOKIE, "inner": "ipv4_udp"}
        arguments.update(overrides)
        (FIXTURE_DIR / name).write_bytes(pcap(frame(**arguments)))


def verify_fixtures():
    for name, expected_options, _, _, maximum, expected_error in FIXTURES:
        try:
            options, base_critical = decode_options(read_packet(FIXTURE_DIR / name))
            result = validate_options(options, base_critical, maximum)
        except ValueError as error:
            result = str(error)
            options = b""
        if result != expected_error:
            raise SystemExit(f"{name}: got {result!r}, want {expected_error!r}")
        if expected_error != "decode" and options != expected_options:
            raise SystemExit(f"{name}: options bytes differ from sanitized source")
    verify_gwlb_fixtures()
    print(f"verified {len(FIXTURES) + len(GWLB_FIXTURES)} sanitized GENEVE PCAP fixtures")


def verify_gwlb_fixtures():
    for name, _, expected_error in GWLB_FIXTURES:
        packet = read_packet(FIXTURE_DIR / name)
        result = validate_gwlb_packet(packet)
        if result != expected_error:
            raise SystemExit(f"{name}: got {result!r}, want {expected_error!r}")


def validate_gwlb_packet(packet):
    if len(packet) < 14 + 20 + 8 + 8 or packet[12:14] != b"\x08\x00":
        return "outer_checksum"
    ip = packet[14:]
    ihl = (ip[0] & 0x0F) * 4
    ip_length = struct.unpack("!H", ip[2:4])[0]
    if ip[0] >> 4 != 4 or ihl != 20 or ip_length != len(ip) or checksum(ip[:ihl]) != 0 or ip[9] != 17:
        return "outer_checksum"
    udp = ip[ihl:ip_length]
    udp_length = struct.unpack("!H", udp[4:6])[0]
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, udp_length)
    if udp_length != len(udp) or checksum(pseudo + udp) != 0:
        return "outer_checksum"
    if struct.unpack("!H", udp[2:4])[0] != 6081:
        return "listener"

    geneve = udp[8:]
    options_length = (geneve[0] & 0x3F) * 4
    if len(geneve) < 8 + options_length:
        return "decode"
    flags = geneve[1]
    vni = int.from_bytes(geneve[4:7], "big")
    protocol = struct.unpack("!H", geneve[2:4])[0]
    options = geneve[8:8 + options_length]
    inner = geneve[8 + options_length:]
    if vni != 0:
        return "vni"
    if flags & 0x80:
        return "oam"
    option_error = validate_options(options, bool(flags & 0x40), MAX_OPTIONS)
    if option_error:
        return option_error
    offset = 0
    while offset < len(options):
        length_byte = options[offset + 3]
        if length_byte >> 5:
            return "option_reserved"
        offset += 4 + (length_byte & 0x1F) * 4
    if not inner or (protocol == 0x0800 and inner[0] >> 4 != 4) or (protocol == 0x86DD and inner[0] >> 4 != 6):
        return "protocol"
    if protocol not in (0x0800, 0x86DD):
        return "protocol"
    return validate_inner(inner)


def validate_inner(inner):
    version = inner[0] >> 4
    if version == 4:
        if len(inner) < 20:
            return "protocol"
        ihl = (inner[0] & 0x0F) * 4
        total = struct.unpack("!H", inner[2:4])[0]
        if ihl < 20 or ihl > len(inner) or total < ihl or total != len(inner):
            return "protocol"
        return None
    if version == 6:
        if len(inner) < 40:
            return "protocol"
        total = 40 + struct.unpack("!H", inner[4:6])[0]
        if total != len(inner):
            return "protocol"
        return None
    return "protocol"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate deterministic fixtures before verification")
    args = parser.parse_args()
    if args.write:
        write_fixtures()
    verify_fixtures()


if __name__ == "__main__":
    main()
