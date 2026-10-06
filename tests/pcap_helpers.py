import ipaddress
import struct


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(source, destination, source_port, destination_port, timestamp, packet_id=1):
    source_ip = ipaddress.IPv4Address(source).packed
    destination_ip = ipaddress.IPv4Address(destination).packed
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, packet_id, 0x4000,
                            64, 6, 0, source_ip, destination_ip)
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    tcp_header = struct.pack("!HHIIBBHHH", source_port, destination_port,
                             packet_id, 0, 5 << 4, 0x10, 64240, 0, 0)
    frame = bytes.fromhex("0200000000020200000000010800") + ip_header + tcp_header
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1_000_000)
    return struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)) + frame


def make_pcap(packets=None):
    packets = packets or [
        packet("192.0.2.1", "198.51.100.1", 40000, 443, 1_700_000_000.0, 1),
        packet("198.51.100.1", "192.0.2.1", 443, 40000, 1_700_000_000.5, 2),
    ]
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(packets)

