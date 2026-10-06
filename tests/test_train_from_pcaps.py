import json
import shutil

from scripts.train_anomaly import fit_and_save
from scripts.train_anomaly_from_pcaps import backup_current, collect_frame, restore

from artifacts import MODEL_DIR, verify_manifest
from features import FEATURE_NAMES
from tests.pcap_helpers import make_pcap, packet


def _benign_pcap(flows=60):
    packets = []
    for flow in range(flows):
        for index in range(8):
            up = index % 2 == 0
            src, dst = ("192.0.2.1", "198.51.100.1") if up else ("198.51.100.1", "192.0.2.1")
            sport, dport = (40_000 + flow, 443) if up else (443, 40_000 + flow)
            packets.append(packet(src, dst, sport, dport,
                                  1_700_000_000.0 + flow + index * 0.05, 100 + index * 10))
    return make_pcap(packets)


def _write(tmp_path):
    path = tmp_path / "normal.pcap"
    path.write_bytes(_benign_pcap())
    return path


def test_collect_frame_builds_one_row_per_flow(tmp_path):
    frame = collect_frame([_write(tmp_path)], max_packets=100_000)
    assert len(frame) == 60
    assert list(frame.columns) == FEATURE_NAMES + ["session_id"]
    assert set(frame["session_id"]) == {"normal"}


def test_retrain_keeps_hashes_valid_and_restore_works(tmp_path):
    models = tmp_path / "models"
    shutil.copytree(MODEL_DIR, models)
    original = json.loads((models / "anomaly_metadata.json").read_text())["training_source"]
    frame = collect_frame([_write(tmp_path)], max_packets=100_000)

    backup_current(models)
    fit_and_save(frame, source="real test", note="x", model_dir=models)
    verify_manifest(models)
    assert json.loads((models / "anomaly_metadata.json").read_text())["training_source"] == "real test"

    restore(models)
    verify_manifest(models)
    assert json.loads((models / "anomaly_metadata.json").read_text())["training_source"] == original
