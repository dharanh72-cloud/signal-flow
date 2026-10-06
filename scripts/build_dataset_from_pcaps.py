"""Build data/features.csv from labeled packet captures recorded with any tool.

Put one or more captures per traffic class in a folder per label, for example:

    captures/
      browsing/   session1.pcap  session2.pcapng ...
      streaming/  ...
      video_call/ ...
      download/   ...
      gaming/     ...

Each capture file counts as ONE independent session, so `python src/train.py` can
hold out whole sessions and report an honest accuracy. Record each capture while
doing only that activity (tcpdump, Wireshark, or dumpcap all work). Only packet
sizes, directions, ports, and timing are read; payloads are never kept.

Usage:
    python scripts/build_dataset_from_pcaps.py captures/
    python scripts/build_dataset_from_pcaps.py captures/ --output data/features.csv --append
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from features import FEATURE_NAMES, features_to_row  # noqa: E402
from pcap_reader import MAX_CAPTURE_FLOWS, MAX_CAPTURE_PACKETS, read_capture  # noqa: E402

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
KNOWN_LABELS = ("browsing", "download", "gaming", "streaming", "video_call")
MIN_SESSIONS_PER_CLASS = 4


def collect_rows(root: Path, *, min_packets: int = 6, max_packets: int = MAX_CAPTURE_PACKETS,
                 max_flows: int = MAX_CAPTURE_FLOWS):
    """Return (rows, sessions_by_label) for every capture under root/<label>/."""
    rows = []
    sessions: dict[str, int] = {}
    for label_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        label = label_dir.name
        for capture in sorted(label_dir.rglob("*")):
            if not capture.is_file() or capture.suffix.lower() not in CAPTURE_SUFFIXES:
                continue
            data = read_capture(capture.read_bytes(), max_packets=max_packets, max_flows=max_flows)
            session_id = f"{label}-{capture.stem}"
            kept = 0
            for record in data.flows:
                if record.features["packet_count"] < min_packets:
                    continue
                rows.append(features_to_row(record.features) + [label, session_id])
                kept += 1
            if kept:
                sessions[label] = sessions.get(label, 0) + 1
            print(f"[dataset] {label}/{capture.name}: {kept} flows")
    return rows, sessions


def write_rows(rows, output: Path, *, append: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    exists = output.exists() and append
    with output.open("a" if exists else "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if not exists:
            writer.writerow(FEATURE_NAMES + ["label", "session_id"])
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("captures", type=Path, help="Folder containing one subfolder per label")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "features.csv")
    parser.add_argument("--append", action="store_true", help="Add to an existing CSV")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing CSV")
    parser.add_argument("--min-packets", type=int, default=6)
    args = parser.parse_args()

    if not args.captures.is_dir():
        raise SystemExit(f"{args.captures} is not a folder.")
    if args.output.exists() and not (args.append or args.overwrite):
        raise SystemExit(
            f"{args.output} already exists. Use --append to add the new sessions to it "
            "or --overwrite to replace it."
        )
    rows, sessions = collect_rows(args.captures, min_packets=args.min_packets)
    if not rows:
        raise SystemExit("No usable flows found. Check the folder layout and file extensions.")
    write_rows(rows, args.output, append=args.append)

    print(f"\n[dataset] Wrote {len(rows):,} flows to {args.output}")
    for label, count in sorted(sessions.items()):
        note = "" if count >= MIN_SESSIONS_PER_CLASS else (
            f"  <- record at least {MIN_SESSIONS_PER_CLASS} sessions for a trustworthy held-out score")
        print(f"[dataset]   {label}: {count} session(s){note}")
    unknown = sorted(set(sessions) - set(KNOWN_LABELS))
    if unknown:
        print(f"[dataset] Note: labels outside the app's five classes: {', '.join(unknown)}")
    print("[dataset] Next: python src/train.py")


if __name__ == "__main__":
    main()
