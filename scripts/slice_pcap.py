"""Cut a small, uploadable piece out of a huge public capture (streaming, low memory).

Public datasets ship multi-GB captures; the dashboard accepts at most 25 MB and 100,000
packets. This copies only the packets you ask for into a new .pcap.

Examples:
    python scripts/slice_pcap.py Friday-WorkingHours.pcap slice.pcap --host 172.16.0.1 --packets 100000
    python scripts/slice_pcap.py big.pcapng part.pcap --packets 50000
    python scripts/slice_pcap.py big.pcap part.pcap --start 1499450000 --end 1499451800
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import IP, IPv6, PcapReader, PcapWriter  # noqa: E402


def slice_capture(source: Path, destination: Path, *, packets: int = 100_000,
                  host: str | None = None, start: float | None = None,
                  end: float | None = None, skip: int = 0) -> tuple[int, int]:
    """Copy matching packets; returns (written, scanned). Never loads the whole file."""
    written = scanned = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(str(destination), sync=False)
    try:
        with PcapReader(str(source)) as reader:
            for packet in reader:
                scanned += 1
                timestamp = float(packet.time)
                if start is not None and timestamp < start:
                    continue
                if end is not None and timestamp > end:
                    break
                if host is not None:
                    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
                    if ip is None or host not in (ip.src, ip.dst):
                        continue
                if scanned <= skip:
                    continue
                writer.write(packet)
                written += 1
                if written >= packets:
                    break
    finally:
        writer.close()
    return written, scanned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--packets", type=int, default=100_000, help="Maximum packets to keep")
    parser.add_argument("--host", help="Keep only packets to or from this IP address")
    parser.add_argument("--start", type=float, help="Unix timestamp to start at")
    parser.add_argument("--end", type=float, help="Unix timestamp to stop at")
    parser.add_argument("--skip", type=int, default=0, help="Skip this many packets first")
    args = parser.parse_args()
    written, scanned = slice_capture(
        args.source, args.destination, packets=args.packets, host=args.host,
        start=args.start, end=args.end, skip=args.skip,
    )
    size = args.destination.stat().st_size / 1e6
    print(f"[slice] Wrote {written:,} packets ({size:.1f} MB) after scanning {scanned:,}")
    if size > 25:
        print("[slice] Note: the dashboard upload limit is 25 MB; use fewer --packets.")


if __name__ == "__main__":
    main()
