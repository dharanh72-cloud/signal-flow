"""Create sanitized, deterministic synthetic PCAPs and flow truth labels."""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

from features import FEATURE_NAMES, features_to_row
from flows import flow_key
from pcap_reader import read_capture

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "sample_data"
DATA_DIR = ROOT / "data"
CLASSES = ("browsing", "download", "gaming", "streaming", "video_call")
BASE_TIME = 1_750_000_000


@dataclass
class PacketSpec:
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    protocol: str
    size: int
    tcp_flags: int = 0x10


@dataclass
class FlowSpec:
    flow_id: str
    activity: str
    session_id: str
    attack_type: str | None = None
    packets: list[PacketSpec] = field(default_factory=list)


def _normal_flow(rng: random.Random, index: int, class_name: str, session_id: str,
                 client: str, start: float) -> FlowSpec:
    service_port = {"browsing": 443, "download": 443, "gaming": 3074,
                    "streaming": 443, "video_call": 3478}[class_name]
    protocol = "UDP" if class_name in {"gaming", "video_call"} else "TCP"
    source_port = 20_000 + index
    server = "198.51.100.20"
    flow = FlowSpec(_flow_id(client, server, source_port, service_port, protocol),
                    class_name, session_id)
    elapsed = 0.0

    if class_name == "video_call":
        count = rng.randint(28, 46)
        for packet_index in range(count):
            elapsed += rng.uniform(0.015, 0.075)
            upstream = packet_index % 2 == 0
            flow.packets.append(_packet(start + elapsed, client, server, source_port,
                                        service_port, protocol,
                                        rng.randint(150, 520), upstream))
    elif class_name == "streaming":
        for packet_index in range(rng.randint(34, 58)):
            elapsed += rng.uniform(0.07, 0.15)
            upstream = packet_index % 7 == 0
            flow.packets.append(_packet(start + elapsed, client, server, source_port,
                                        service_port, protocol,
                                        rng.randint(48, 110) if upstream else rng.randint(900, 1450),
                                        upstream))
    elif class_name == "download":
        for packet_index in range(rng.randint(32, 54)):
            elapsed += rng.uniform(0.012, 0.06)
            upstream = packet_index % 12 == 0
            flow.packets.append(_packet(start + elapsed, client, server, source_port,
                                        service_port, protocol,
                                        rng.randint(52, 100) if upstream else rng.randint(1050, 1450),
                                        upstream))
    elif class_name == "gaming":
        for packet_index in range(rng.randint(24, 42)):
            elapsed += rng.uniform(0.025, 0.11)
            upstream = packet_index % 3 == 0
            flow.packets.append(_packet(start + elapsed, client, server, source_port,
                                        service_port, protocol,
                                        rng.randint(60, 220), upstream))
    else:  # Browsing: a few short request/response bursts.
        for packet_index in range(rng.randint(20, 38)):
            elapsed += rng.uniform(0.02, 0.16)
            upstream = packet_index % 3 == 0
            size = rng.randint(70, 450) if upstream else rng.randint(180, 1250)
            flow.packets.append(_packet(start + elapsed, client, server, source_port,
                                        service_port, protocol, size, upstream))
    return flow


def _attack_flows(rng: random.Random, start: float) -> list[FlowSpec]:
    flows = []
    scan_client = "192.0.2.240"
    scan_server = "198.51.100.80"
    for index, port in enumerate(range(20_000, 20_026)):
        source_port = 40_000 + index
        flow = FlowSpec(_flow_id(scan_client, scan_server, source_port, port, "TCP"),
                        "unknown", "attack-port-scan", "port_scan")
        flow.packets = [
            _packet(start + index * 0.09, scan_client, scan_server, source_port, port,
                    "TCP", 60, True, tcp_flags=0x02),
            _packet(start + index * 0.09 + 0.025, scan_server, scan_client, port,
                    source_port, "TCP", 60, True, tcp_flags=0x14),
        ]
        flows.append(flow)

    slow_client = "192.0.2.241"
    slow_server = "198.51.100.81"
    for index, port in enumerate(range(30_000, 30_032)):
        source_port = 41_000 + index
        flow = FlowSpec(_flow_id(slow_client, slow_server, source_port, port, "TCP"),
                        "unknown", "attack-slow-scan", "slow_scan")
        timestamp = start + 5 + index * 3.1
        flow.packets = [
            _packet(timestamp, slow_client, slow_server, source_port, port,
                    "TCP", 60, True, tcp_flags=0x02),
            _packet(timestamp + 0.03, slow_server, slow_client, port,
                    source_port, "TCP", 60, True, tcp_flags=0x14),
        ]
        flows.append(flow)

    client, server, source_port, destination_port = "192.0.2.242", "198.51.100.82", 42_000, 443
    flow = FlowSpec(_flow_id(client, server, source_port, destination_port, "TCP"),
                    "unknown", "attack-exfiltration", "exfiltration")
    for index in range(44):
        timestamp = start + 110 + index * 0.12
        flow.packets.append(_packet(timestamp, client, server, source_port,
                                    destination_port, "TCP", 1400, True))
        if index % 22 == 0:
            flow.packets.append(_packet(timestamp + 0.025, server, client,
                                        destination_port, source_port, "TCP", 70, False))
    flows.append(flow)

    client, server, source_port, destination_port = "192.0.2.243", "198.51.100.83", 43_000, 80
    flow = FlowSpec(_flow_id(client, server, source_port, destination_port, "TCP"),
                    "unknown", "attack-dos", "dos_burst")
    for index in range(180):
        flow.packets.append(_packet(start + 120 + index * 0.0015, client, server,
                                    source_port, destination_port, "TCP", 66, True,
                                    tcp_flags=0x02))
    flows.append(flow)

    client, server, source_port, destination_port = "192.0.2.244", "198.51.100.84", 44_000, 443
    flow = FlowSpec(_flow_id(client, server, source_port, destination_port, "TCP"),
                    "unknown", "attack-beacon", "beaconing")
    for index in range(72):
        flow.packets.append(_packet(start + 125 + index * 0.5, client, server,
                                    source_port, destination_port, "TCP", 72, index % 6 != 5))
    flows.append(flow)

    client, server, source_port, destination_port = "192.0.2.245", "198.51.100.85", 45_000, 53
    flow = FlowSpec(_flow_id(client, server, source_port, destination_port, "UDP"),
                    "unknown", "attack-dns-tunnel", "dns_tunnel")
    for index in range(20):
        timestamp = start + 150 + index * 0.18
        flow.packets.append(_packet(timestamp, client, server, source_port,
                                    destination_port, "UDP", 950, True))
        if index % 5 == 0:
            flow.packets.append(_packet(timestamp + 0.035, server, client,
                                        destination_port, source_port, "UDP", 85, False))
    flows.append(flow)
    return flows


def _flow_id(client, server, client_port, server_port, protocol):
    from hashlib import sha256

    return sha256(repr(flow_key(client, server, client_port, server_port, protocol)).encode()).hexdigest()[:12]


def _packet(timestamp, client, server, client_port, server_port, protocol, size,
            upstream, tcp_flags=0x10):
    if upstream:
        source, destination = client, server
        source_port, destination_port = client_port, server_port
    else:
        source, destination = server, client
        source_port, destination_port = server_port, client_port
    return PacketSpec(timestamp, source, destination, source_port, destination_port,
                      protocol, size, tcp_flags)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(packet: PacketSpec, packet_id: int) -> bytes:
    source_ip = ipaddress.IPv4Address(packet.source).packed
    destination_ip = ipaddress.IPv4Address(packet.destination).packed
    ip_header_length = 20
    transport_header_length = 20 if packet.protocol == "TCP" else 8
    payload_size = max(0, packet.size - 14 - ip_header_length - transport_header_length)
    total_length = ip_header_length + transport_header_length + payload_size
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, packet_id & 0xFFFF,
                            0x4000, 64, 6 if packet.protocol == "TCP" else 17, 0,
                            source_ip, destination_ip)
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    if packet.protocol == "TCP":
        transport = struct.pack("!HHIIBBHHH", packet.source_port, packet.destination_port,
                                packet_id, 0, 5 << 4, packet.tcp_flags, 64240, 0, 0)
    else:
        transport = struct.pack("!HHHH", packet.source_port, packet.destination_port,
                                 transport_header_length + payload_size, 0)
    # Synthetic payload is zero-filled; no real user content is included.
    payload = bytes(payload_size)
    return (bytes.fromhex("0200000000020200000000010800") + ip_header + transport + payload)


def write_pcap(path: Path, flows: list[FlowSpec]) -> None:
    packet_rows = sorted((packet for flow in flows for packet in flow.packets),
                         key=lambda packet: packet.timestamp)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packet_rows):
            frame = _frame(packet, index)
            seconds = int(packet.timestamp)
            microseconds = int((packet.timestamp - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            handle.write(frame)


def _make_flows(seed: int, classes_per_session: int, sessions_per_class: int,
                start_offset: float) -> list[FlowSpec]:
    rng = random.Random(seed)
    flows = []
    counter = 0
    for class_index, class_name in enumerate(CLASSES):
        for session_index in range(sessions_per_class):
            session_id = f"synthetic-{class_name}-{session_index:02d}"
            client = str(ipaddress.IPv4Address(0xC0000201 + class_index * 16 + session_index))
            for _ in range(classes_per_session):
                counter += 1
                start = BASE_TIME + start_offset + rng.uniform(0, 30) + session_index * 90
                flow = _normal_flow(rng, counter, class_name, session_id, client, start)
                # Keep class sessions independently identifiable in the metadata labels.
                flows.append(flow)
    return flows


def _write_labels(capture_path: Path, labels_path: Path, flows: list[FlowSpec]) -> None:
    parsed = read_capture(capture_path.read_bytes())
    packet_counts = {record.flow_id: record.features["packet_count"] for record in parsed.flows}
    labels = {
        "capture": capture_path.name,
        "synthetic": True,
        "ground_truth_scope": "flow-level; truth labels are separate from the PCAP",
        "flows": [
            {
                "flow_id": flow.flow_id,
                "session_id": flow.session_id,
                "activity": flow.activity,
                "attack_type": flow.attack_type,
                "is_attack": flow.attack_type is not None,
                "packets": packet_counts.get(flow.flow_id, 0),
            }
            for flow in flows
        ],
    }
    labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")


def _write_classifier_dataset(path: Path, flows: list[FlowSpec], pcap_path: Path) -> None:
    import csv

    parsed = read_capture(pcap_path.read_bytes())
    labels = {flow.flow_id: flow for flow in flows}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURE_NAMES, "label", "session_id"])
        for record in parsed.flows:
            flow = labels[record.flow_id]
            if flow.attack_type is None:
                writer.writerow([*features_to_row(record.features), flow.activity, flow.session_id])


def generate() -> None:
    # 500 normal flows from 50 independent synthetic sessions (10 per class/session).
    normal = _make_flows(seed=20261004, classes_per_session=10,
                         sessions_per_class=10, start_offset=0)
    normal_path = SAMPLE_DIR / "normal.pcap"
    write_pcap(normal_path, normal)
    _write_labels(normal_path, SAMPLE_DIR / "normal_labels.json", normal)
    _write_classifier_dataset(DATA_DIR / "synthetic_sessions.csv", normal, normal_path)

    # Keep the bundle compact while including enough context for each detector.
    mixed = _make_flows(seed=20261005, classes_per_session=8,
                        sessions_per_class=2, start_offset=5_000)
    attacks = _attack_flows(random.Random(20261006), BASE_TIME + 5_300)
    with_attacks = mixed + attacks
    attack_path = SAMPLE_DIR / "with_attacks.pcap"
    write_pcap(attack_path, with_attacks)
    _write_labels(attack_path, SAMPLE_DIR / "with_attacks_labels.json", with_attacks)


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    generate()
    print(f"Generated {SAMPLE_DIR / 'normal.pcap'}")
    print(f"Generated {SAMPLE_DIR / 'with_attacks.pcap'}")
    print("Separate ground-truth labels and synthetic classifier sessions were written.")


if __name__ == "__main__":
    main()
