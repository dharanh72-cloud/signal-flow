import struct

import pytest

from pcap_reader import CaptureError, read_capture


def test_reads_bundled_normal_capture_into_payload_free_flows():
    from pathlib import Path

    sample = Path(__file__).resolve().parents[1] / "sample_data" / "normal.pcap"
    capture = read_capture(sample.read_bytes(), max_packets=100_000)

    assert len(capture.flows) == 500
    assert capture.transport_packets == capture.packets_read
    assert all(len(record.features) == 34 for record in capture.flows)
    assert all(not hasattr(record.flow, "payload") for record in capture.flows)


def test_malformed_file_is_a_clear_parser_error():
    with pytest.raises(CaptureError):
        read_capture(b"not a capture")


def test_truncated_packet_record_is_rejected():
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1, 0, 100, 100)
    with pytest.raises(CaptureError, match="truncated packet"):
        read_capture(global_header + packet_header + b"short")


def test_packet_and_flow_caps_are_reported():
    from pathlib import Path

    sample = Path(__file__).resolve().parents[1] / "sample_data" / "normal.pcap"
    packet_limited = read_capture(sample.read_bytes(), max_packets=5)
    flow_limited = read_capture(sample.read_bytes(), max_packets=100_000, max_flows=1)

    assert packet_limited.truncated is True
    assert packet_limited.packets_read == 5
    assert len(flow_limited.flows) == 1
    assert flow_limited.skipped_flows > 0


def test_reads_pcapng_file(tmp_path):
    from scapy.all import IP, TCP, Ether
    from scapy.utils import PcapNgWriter

    output = tmp_path / "tiny.pcapng"
    writer = PcapNgWriter(str(output))
    writer.write(Ether() / IP(src="192.0.2.1", dst="198.51.100.1") /
                 TCP(sport=40000, dport=443, flags="A"))
    writer.write(Ether() / IP(src="198.51.100.1", dst="192.0.2.1") /
                 TCP(sport=443, dport=40000, flags="A"))
    writer.close()

    capture = read_capture(output.read_bytes())
    assert len(capture.flows) == 1
    assert capture.flows[0].features["packet_count"] == 2

