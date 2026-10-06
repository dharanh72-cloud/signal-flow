"""
features.py
-----------
Turns a Flow (sequence of PacketRecords) into a fixed-length feature
vector. Every feature here comes from packet headers/timing only.
"""

import numpy as np

FEATURE_NAMES = [
    "packet_count", "duration", "total_bytes", "bytes_per_sec", "packets_per_sec",
    "up_packet_count", "down_packet_count", "up_down_packet_ratio",
    "up_bytes", "down_bytes", "up_down_byte_ratio",
    "pkt_size_mean", "pkt_size_median", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "up_pkt_size_mean", "up_pkt_size_std", "down_pkt_size_mean", "down_pkt_size_std",
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_cv",
    "burst_fraction", "longest_burst",
    "small_pkt_fraction", "large_pkt_fraction", "mtu_pkt_fraction",
    "is_udp", "is_well_known_port", "is_high_port",
    "max_concurrent_flows",
]

BURST_IAT_THRESHOLD = 0.020
SMALL_PKT_BYTES = 100
LARGE_PKT_BYTES = 1000
MTU_PKT_BYTES = 1400
WELL_KNOWN_PORT_MAX = 1024
HIGH_PORT_MIN = 49152


def extract_features(packets, proto=None, server_port=None, max_concurrent_flows=1):
    if len(packets) < 2:
        return None

    recs = sorted(packets, key=lambda p: p.timestamp)
    sizes = np.array([p.size for p in recs], dtype=float)
    times = np.array([p.timestamp for p in recs], dtype=float)
    directions = np.array([p.direction for p in recs])

    duration = max(times[-1] - times[0], 1e-6)
    total_bytes = sizes.sum()

    up_mask = directions == "up"
    down_mask = directions == "down"
    up_sizes = sizes[up_mask]
    down_sizes = sizes[down_mask]

    iats = np.diff(times)
    iats = iats[iats >= 0]
    if len(iats) == 0:
        iats = np.array([0.0])

    burst_mask = iats < BURST_IAT_THRESHOLD
    burst_fraction = burst_mask.mean() if len(iats) else 0.0

    longest_burst = 0
    current = 0
    for is_burst in burst_mask:
        current = current + 1 if is_burst else 0
        longest_burst = max(longest_burst, current)

    iat_mean = iats.mean()
    iat_std = iats.std()
    iat_cv = iat_std / iat_mean if iat_mean > 0 else 0.0

    is_udp = 1.0 if (proto or "").upper() == "UDP" else 0.0
    is_well_known_port = 1.0 if (server_port is not None and server_port < WELL_KNOWN_PORT_MAX) else 0.0
    is_high_port = 1.0 if (server_port is not None and server_port > HIGH_PORT_MIN) else 0.0

    feats = {
        "packet_count": len(recs),
        "duration": duration,
        "total_bytes": float(total_bytes),
        "bytes_per_sec": float(total_bytes / duration),
        "packets_per_sec": float(len(recs) / duration),
        "up_packet_count": int(up_mask.sum()),
        "down_packet_count": int(down_mask.sum()),
        "up_down_packet_ratio": float(up_mask.sum() / max(down_mask.sum(), 1)),
        "up_bytes": float(up_sizes.sum()),
        "down_bytes": float(down_sizes.sum()),
        "up_down_byte_ratio": float(up_sizes.sum() / max(down_sizes.sum(), 1)),
        "pkt_size_mean": float(sizes.mean()),
        "pkt_size_median": float(np.median(sizes)),
        "pkt_size_std": float(sizes.std()),
        "pkt_size_min": float(sizes.min()),
        "pkt_size_max": float(sizes.max()),
        "up_pkt_size_mean": float(up_sizes.mean()) if len(up_sizes) else 0.0,
        "up_pkt_size_std": float(up_sizes.std()) if len(up_sizes) else 0.0,
        "down_pkt_size_mean": float(down_sizes.mean()) if len(down_sizes) else 0.0,
        "down_pkt_size_std": float(down_sizes.std()) if len(down_sizes) else 0.0,
        "iat_mean": float(iat_mean),
        "iat_std": float(iat_std),
        "iat_min": float(iats.min()),
        "iat_max": float(iats.max()),
        "iat_cv": float(iat_cv),
        "burst_fraction": float(burst_fraction),
        "longest_burst": float(longest_burst),
        "small_pkt_fraction": float((sizes < SMALL_PKT_BYTES).mean()),
        "large_pkt_fraction": float((sizes > LARGE_PKT_BYTES).mean()),
        "mtu_pkt_fraction": float((sizes >= MTU_PKT_BYTES).mean()),
        "is_udp": is_udp,
        "is_well_known_port": is_well_known_port,
        "is_high_port": is_high_port,
        "max_concurrent_flows": float(max_concurrent_flows),
    }
    return feats


def features_to_row(feats: dict):
    return [feats[name] for name in FEATURE_NAMES]