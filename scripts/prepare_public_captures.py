"""Sort a public labeled capture collection (such as ISCXVPN2016) into captures/<label>/.

Each source file becomes one session, trimmed to a manageable number of packets. The
label comes from keywords in the file name; anything that matches nothing is listed
and skipped, so you can check the mapping before training. Use --dry-run first.

    python scripts/prepare_public_captures.py path/to/ISCX-nonVPN captures/ --dry-run
    python scripts/prepare_public_captures.py path/to/ISCX-nonVPN captures/ --max-packets 100000

Edit RULES below if your copy names files differently. VPN-wrapped files are skipped by
default because the classifier is meant for ordinary encrypted traffic.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from slice_pcap import slice_capture  # noqa: E402

# First matching rule wins. Matching is case-insensitive on the file name.
RULES = (
    ("video_call", ("skype_video", "hangouts_video", "facebook_video", "video_call")),
    ("streaming", ("netflix", "youtube", "vimeo", "spotify", "stream")),
    ("download", ("ftps_down", "sftp_down", "scp_down", "scpdown", "sftpdown", "download")),
    ("browsing", ("browsing", "firefox", "chrome", "browse")),
    ("gaming", ("gaming", "game")),
)
SUFFIXES = {".pcap", ".pcapng", ".cap"}


def label_for(name: str, *, include_vpn: bool = False) -> str | None:
    lowered = name.lower()
    if not include_vpn and ("vpn" in lowered and "voipbuster" not in lowered):
        return None
    for label, keywords in RULES:
        if any(keyword in lowered for keyword in keywords):
            return label
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", type=Path, help="Folder holding the downloaded captures")
    parser.add_argument("output", type=Path, help="Usually captures/")
    parser.add_argument("--max-packets", type=int, default=100_000)
    parser.add_argument("--include-vpn", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Only show the mapping")
    args = parser.parse_args()
    if not args.source.is_dir():
        raise SystemExit(f"{args.source} is not a folder.")

    mapped: dict[str, list[Path]] = {}
    unmapped: list[Path] = []
    for path in sorted(args.source.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUFFIXES:
            continue
        label = label_for(path.name, include_vpn=args.include_vpn)
        if label is None:
            unmapped.append(path)
        else:
            mapped.setdefault(label, []).append(path)

    for label, files in sorted(mapped.items()):
        print(f"[prepare] {label}: {len(files)} file(s)")
        for path in files:
            print(f"           {path.name}")
    if unmapped:
        print(f"[prepare] Skipped {len(unmapped)} file(s) that match no rule or are VPN-wrapped, for example:")
        for path in unmapped[:8]:
            print(f"           {path.name}")
    if args.dry_run or not mapped:
        print("[prepare] Dry run: nothing written." if args.dry_run else "[prepare] Nothing matched.")
        return

    for label, files in sorted(mapped.items()):
        for path in files:
            target = args.output / label / f"{path.stem}.pcap"
            written, _ = slice_capture(path, target, packets=args.max_packets)
            print(f"[prepare] {label}/{target.name}: {written:,} packets")
    print("\n[prepare] Next: python scripts/build_dataset_from_pcaps.py captures/ --append")
    print("[prepare] Then:  python src/train.py")
    print("[prepare] Classes with fewer than 4 sessions give an unreliable held-out score.")


if __name__ == "__main__":
    main()
