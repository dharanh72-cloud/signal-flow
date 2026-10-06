"""Refit the anomaly detector on REAL, benign captures (yours or a client's).

Only normal traffic may go in. Never train on the traffic you later test attack
detection with, or the score is meaningless. Every flow of two or more packets is
used, because the dashboard scores flows that short too.

    python scripts/train_anomaly_from_pcaps.py datasets/traffic.pcap
    python scripts/train_anomaly_from_pcaps.py captures/normal/ --max-packets 1000000

The previous anomaly model files are copied to models/previous_anomaly/ first, so
you can go back with --restore. Only the anomaly model changes; the fixed attack rules
in config/anomaly.toml are not affected by training.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from artifacts import MODEL_DIR, write_manifest  # noqa: E402
from features import FEATURE_NAMES  # noqa: E402
from pcap_reader import MAX_CAPTURE_FLOWS, read_capture  # noqa: E402
from train_anomaly import fit_and_save  # noqa: E402

SUFFIXES = {".pcap", ".pcapng", ".cap"}
ANOMALY_FILES = (
    "anomaly_iforest.joblib", "anomaly_scaler.joblib", "anomaly_metadata.json",
)
MIN_FLOWS = 200


def find_captures(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() in SUFFIXES))
        elif path.is_file():
            found.append(path)
        else:
            raise SystemExit(f"{path} not found.")
    return found


def collect_frame(captures: list[Path], *, max_packets: int, min_packets: int = 2) -> pd.DataFrame:
    rows = []
    for capture in captures:
        data = read_capture(capture.read_bytes(), max_packets=max_packets,
                            max_flows=MAX_CAPTURE_FLOWS)
        kept = 0
        for record in data.flows:
            if record.features["packet_count"] < min_packets:
                continue
            rows.append([record.features[name] for name in FEATURE_NAMES] + [capture.stem])
            kept += 1
        print(f"[train] {capture.name}: {kept:,} flows from {data.packets_read:,} packets"
              + (" (hit the packet cap; slice or raise --max-packets)" if data.truncated else ""))
    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["session_id"])


def backup_current(model_dir: Path) -> Path:
    backup = model_dir / "previous_anomaly"
    backup.mkdir(exist_ok=True)
    for name in ANOMALY_FILES:
        if (model_dir / name).is_file():
            shutil.copy2(model_dir / name, backup / name)
    return backup


def restore(model_dir: Path) -> None:
    backup = model_dir / "previous_anomaly"
    if not backup.is_dir():
        raise SystemExit("No backup found to restore.")
    for name in ANOMALY_FILES:
        shutil.copy2(backup / name, model_dir / name)
    write_manifest(model_dir)
    print(f"[train] Restored the previous anomaly model from {backup}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("captures", nargs="*", type=Path, help="Benign pcap files or folders")
    parser.add_argument("--max-packets", type=int, default=500_000, help="Per capture file")
    parser.add_argument("--models-dir", type=Path, default=MODEL_DIR)
    parser.add_argument("--restore", action="store_true", help="Undo the last retrain")
    args = parser.parse_args()

    if args.restore:
        restore(args.models_dir)
        return
    captures = find_captures(args.captures)
    if not captures:
        raise SystemExit("Give at least one benign capture file or folder.")
    frame = collect_frame(captures, max_packets=args.max_packets)
    if len(frame) < MIN_FLOWS:
        raise SystemExit(
            f"Only {len(frame)} flows found; at least {MIN_FLOWS} are needed for a "
            "usable baseline. Use a longer or busier capture."
        )
    backup = backup_current(args.models_dir)
    names = ", ".join(sorted({path.name for path in captures}))
    metadata = fit_and_save(
        frame, source=f"real benign captures: {names}",
        note="Fitted on operator-supplied benign traffic; only valid for similar networks.",
        model_dir=args.models_dir,
    )
    print(f"\n[train] Trained on {metadata['training_rows']:,} flows from "
          f"{metadata['training_sessions']} capture(s).")
    print(f"[train] Previous model saved in {backup} (undo: --restore).")
    print("[train] Next: re-run evaluate_external.py on a DIFFERENT benign capture, then on the attack capture.")


if __name__ == "__main__":
    main()
