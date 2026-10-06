"""Show WHICH flows alerted and WHY, so thresholds are tuned on evidence.

    python scripts/inspect_alerts.py slices/my_browsing.pcap
    python scripts/inspect_alerts.py slices/neris.pcap --limit 20

Prints every medium/high flow with its rule hits and key features, plus the score
spread of flows no rule touched (that spread is the anomaly model's own opinion).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pipeline import AnalysisPipeline  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("capture", type=Path)
    parser.add_argument("--limit", type=int, default=30, help="Max alerted flows to print")
    args = parser.parse_args()
    result = AnalysisPipeline().analyze(args.capture.read_bytes(), filename=args.capture.name)
    flows = result["flows"]
    alerted = [f for f in flows if f["severity"] in {"medium", "high"}]
    print(f"{args.capture.name}: {len(flows)} flows, {len(alerted)} alerted\n")
    print(f"{'rules':<22}{'pkts':>7}{'dur_s':>9}{'pps':>9}{'bytes':>11}{'pkt_mean':>9}{'proto':>6}")
    for flow in alerted[: args.limit]:
        feats = flow["features"]
        rules = ",".join(hit["code"] for hit in flow["rule_hits"]) or "model-only"
        print(f"{rules:<22}{flow['packet_count']:>7}{flow['duration']:>9.1f}"
              f"{feats['packets_per_sec']:>9.0f}{flow['bytes']:>11,}"
              f"{feats['pkt_size_mean']:>9.0f}{flow['protocol']:>6}")
    if len(alerted) > args.limit:
        print(f"... {len(alerted) - args.limit} more")
    scores = sorted(f["score"] for f in flows if not f["rule_hits"])
    if scores:
        pick = lambda q: scores[min(len(scores) - 1, int(q * len(scores)))]  # noqa: E731
        print(f"\nFlows with no rule hit: {len(scores)}; model score p50={pick(.5)} "
              f"p90={pick(.9)} p99={pick(.99)} max={scores[-1]}  (medium alert at 30)")


if __name__ == "__main__":
    main()
