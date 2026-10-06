"""
capture.py
----------
Sniff live traffic with scapy, group packets into flows, and once a
flow is idle (or capture ends), extract features and append them
to data/features.csv with the label you specify on the command line.

Usage:
    sudo python src/capture.py --label video_call --duration 120
    sudo python src/capture.py --label youtube --duration 90 --iface eth0

Only headers are inspected -- IP addresses, ports, protocol, packet
length, and arrival time. Payload bytes are never read or stored.
"""

import argparse
import csv
import os
import time
from uuid import uuid4

from scapy.all import IP, TCP, UDP, IPv6, sniff

from features import FEATURE_NAMES, extract_features, features_to_row
from flows import FlowTable

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
FEATURES_CSV = os.path.join(DATA_DIR, "features.csv")


def ensure_features_csv():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(FEATURES_CSV):
        with open(FEATURES_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_NAMES + ["label", "session_id"])
        return

    with open(FEATURES_CSV, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    if not rows or "session_id" in rows[0]:
        return
    # Preserve the old labeled rows and mark their capture session as unknown.
    migrated = rows[0] + ["session_id"]
    temp_path = FEATURES_CSV + ".tmp"
    with open(temp_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(migrated)
        for row in rows[1:]:
            writer.writerow(row + [""])
    os.replace(temp_path, FEATURES_CSV)


def append_flow_features(feats: dict, label: str, session_id: str):
    with open(FEATURES_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(features_to_row(feats) + [label, session_id])


def flush_finished_flows(table: FlowTable, label: str, session_id: str,
                         min_packets: int = 6, idle_timeout: float = 5.0):
    idle_flows = table.pop_idle_flows(timeout=idle_timeout)
    saved = 0
    for flow in idle_flows:
        if flow.packet_count < min_packets:
            continue
        feats = extract_features(flow.packets, proto=flow.proto, server_port=flow.server_port,
                                  max_concurrent_flows=flow.max_concurrent_flows)
        if feats is None:
            continue
        append_flow_features(feats, label, session_id)
        saved += 1
    return saved


def main():
    parser = argparse.ArgumentParser(description="Capture labeled flows for training.")
    parser.add_argument("--label", required=True,
                         help="Ground-truth label for everything captured this run "
                              "(e.g. video_call, streaming, download, browsing, gaming)")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration in seconds")
    parser.add_argument("--iface", default=None, help="Network interface (default: scapy's default)")
    parser.add_argument("--idle-timeout", type=float, default=5.0,
                         help="Seconds of silence before a flow is considered finished")
    parser.add_argument("--min-packets", type=int, default=6,
                         help="Minimum packets in a flow before it's worth saving")
    args = parser.parse_args()

    ensure_features_csv()
    session_id = uuid4().hex
    table = FlowTable()
    total_saved = 0
    start = time.time()

    def handle_packet(pkt):
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            return
        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            return

        flow = table.get_or_create(ip.src, ip.dst, sport, dport, proto)
        direction = table.direction_for(flow, ip.src, sport)
        flow.add_packet(size=len(pkt), direction=direction, ts=pkt.time)
        table.touch_concurrency(flow)

    print(f"[capture] Session {session_id[:8]} · sniffing for {args.duration}s, label='{args.label}'. "
          f"Do ONLY that activity now (e.g. start your Zoom call / YouTube video / download).")
    print("[capture] Payload is never read -- only packet sizes, ports, and timing.")

    sniff(prn=handle_packet, timeout=args.duration, store=False, iface=args.iface)

    for flow in table.all_flows():
        flow.last_seen -= (args.idle_timeout + 1)
    total_saved = flush_finished_flows(table, args.label, session_id,
                                        min_packets=args.min_packets,
                                        idle_timeout=args.idle_timeout)

    elapsed = time.time() - start
    print(f"[capture] Done in {elapsed:.1f}s. Saved {total_saved} labeled flows "
          f"to {FEATURES_CSV}")


if __name__ == "__main__":
    main()
