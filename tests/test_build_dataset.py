import csv

from scripts.build_dataset_from_pcaps import collect_rows, write_rows

from features import FEATURE_NAMES
from tests.pcap_helpers import make_pcap, packet


def _session_pcap(port, count=8):
    packets = []
    for index in range(count):
        up = index % 2 == 0
        source, destination = ("192.0.2.1", "198.51.100.1") if up else ("198.51.100.1", "192.0.2.1")
        source_port, destination_port = (port, 443) if up else (443, port)
        packets.append(packet(source, destination, source_port, destination_port,
                              1_700_000_000.0 + index * 0.1, index + 1))
    return make_pcap(packets)


def test_each_capture_becomes_its_own_session(tmp_path):
    for label, port in (("browsing", 40001), ("streaming", 40002)):
        folder = tmp_path / "captures" / label
        folder.mkdir(parents=True)
        (folder / "a.pcap").write_bytes(_session_pcap(port))
        (folder / "b.pcap").write_bytes(_session_pcap(port + 10))
    rows, sessions = collect_rows(tmp_path / "captures")
    assert sessions == {"browsing": 2, "streaming": 2}
    assert {row[-1] for row in rows} == {"browsing-a", "browsing-b", "streaming-a", "streaming-b"}

    output = tmp_path / "features.csv"
    write_rows(rows, output, append=False)
    with output.open(newline="") as handle:
        header = next(csv.reader(handle))
    assert header == FEATURE_NAMES + ["label", "session_id"]


def test_short_flows_are_skipped(tmp_path):
    folder = tmp_path / "captures" / "gaming"
    folder.mkdir(parents=True)
    (folder / "tiny.pcap").write_bytes(make_pcap())
    rows, sessions = collect_rows(tmp_path / "captures")
    assert rows == [] and sessions == {}
