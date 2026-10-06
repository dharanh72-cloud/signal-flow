import json
from pathlib import Path

from scripts.evaluate_external import evaluate, render_report
from scripts.prepare_public_captures import label_for
from scripts.slice_pcap import slice_capture

from pcap_reader import read_capture

SAMPLES = Path("sample_data")


def _attacker_ips():
    data = (SAMPLES / "with_attacks.pcap").read_bytes()
    truth = {f["flow_id"] for f in json.loads((SAMPLES / "with_attacks_labels.json").read_text())["flows"]
             if f["is_attack"]}
    return {r.flow.client_ip for r in read_capture(data).flows if r.flow_id in truth}


def test_external_evaluation_scores_the_attack_sample():
    attackers = _attacker_ips()
    assert attackers
    stats = evaluate((SAMPLES / "with_attacks.pcap").read_bytes(), attackers)
    assert stats["attack_flows"] > 0 and stats["recall"] > 0.9
    assert stats["tp"] + stats["fn"] == stats["attack_flows"]
    assert "Recall" in render_report("with_attacks.pcap", attackers, stats)


def test_benign_only_run_reports_false_alarm_rate():
    stats = evaluate((SAMPLES / "normal.pcap").read_bytes(), set())
    assert stats["attack_flows"] == 0 and stats["recall"] is None
    assert 0.0 <= stats["false_alarm_rate"] <= 0.05


def test_slicer_limits_packets_and_filters_by_host(tmp_path):
    source = SAMPLES / "with_attacks.pcap"
    out = tmp_path / "cut.pcap"
    written, scanned = slice_capture(source, out, packets=100)
    assert written == 100 and scanned >= 100
    attacker = sorted(_attacker_ips())[0]
    hosted = tmp_path / "host.pcap"
    count, _ = slice_capture(source, hosted, packets=100_000, host=attacker)
    assert 0 < count < 3395
    assert read_capture(hosted.read_bytes()).flows


def test_public_capture_labels_follow_file_names():
    assert label_for("youtube_A.pcap") == "streaming"
    assert label_for("skype_video1a.pcap") == "video_call"
    assert label_for("ftps_down_1a.pcap") == "download"
    assert label_for("vpn_youtube_A.pcap") is None
    assert label_for("vpn_youtube_A.pcap", include_vpn=True) == "streaming"
    assert label_for("something_else.pcap") is None
