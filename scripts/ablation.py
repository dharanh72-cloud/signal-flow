"""Ablation: what do the fixed rules and the learned model each contribute?

Scores every flow of a capture three ways and compares them against the same ground truth
(a flow is an attack when either end is a listed attacker IP):

    rules only   fixed rules, anomaly model ignored
    model only   Isolation Forest score alone, rules ignored
    both         what the dashboard shows

    python scripts/ablation.py slices/neris.pcap --attacker-ip 147.32.84.165
    python scripts/ablation.py slices/my_browsing.pcap          # benign only: false alarms

Writes reports/ablation.md. Report it even if the model adds nothing: that is a finding.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from anomaly import severity_for  # noqa: E402
from pcap_reader import MAX_CAPTURE_FLOWS, MAX_CAPTURE_PACKETS, read_capture  # noqa: E402
from pipeline import AnalysisPipeline  # noqa: E402

VARIANTS = ("rules_only", "model_only", "both")
LABELS = {"rules_only": "Rules only", "model_only": "Model only", "both": "Both (dashboard)"}


def flow_alerts(alert: dict, config: dict) -> dict[str, bool]:
    """Would this flow alert (medium or high) under each variant?"""
    engine = config["engine"]
    model = float(alert["model_score"])
    top_rule = max((hit["score"] for hit in alert["rule_hits"]), default=0)
    model_only_score = int(round(min(100, model + min(20, model * float(engine["rule_model_blend"])))))
    return {
        "rules_only": severity_for(top_rule, config) != "low",
        "model_only": severity_for(model_only_score, config) != "low",
        "both": severity_for(int(alert["score"]), config) != "low",
    }


def evaluate_ablation(capture_bytes: bytes, attacker_ips: set[str]) -> dict:
    pipeline = AnalysisPipeline()
    data = read_capture(capture_bytes, max_packets=MAX_CAPTURE_PACKETS, max_flows=MAX_CAPTURE_FLOWS)
    alerts = pipeline.detector.score_flows(data.flows)
    counts = {variant: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for variant in VARIANTS}
    model_adds_tp = model_adds_fp = 0
    for record, alert in zip(data.flows, alerts, strict=True):
        is_attack = bool({record.flow.client_ip, record.flow.server_ip} & attacker_ips)
        flags = flow_alerts(alert, pipeline.detector.config)
        for variant, alerted in flags.items():
            key = ("tp" if alerted else "fn") if is_attack else ("fp" if alerted else "tn")
            counts[variant][key] += 1
        if flags["both"] and not flags["rules_only"]:
            if is_attack:
                model_adds_tp += 1
            else:
                model_adds_fp += 1
    attacks = counts["both"]["tp"] + counts["both"]["fn"]
    benign = counts["both"]["fp"] + counts["both"]["tn"]
    for c in counts.values():
        c["recall"] = c["tp"] / attacks if attacks else None
        c["false_alarm_rate"] = c["fp"] / benign if benign else None
    return {
        "flows": len(data.flows), "packets": data.packets_read, "truncated": data.truncated,
        "attack_flows": attacks, "benign_flows": benign, "variants": counts,
        "model_adds_tp": model_adds_tp, "model_adds_fp": model_adds_fp,
    }


def _pct(value, missing="n/a") -> str:
    return missing if value is None else f"{100 * value:.1f}%"


def render_report(name: str, attackers: set[str], stats: dict) -> str:
    lines = [
        "# Ablation: rules versus learned model", "",
        f"- Capture: `{name}` ({stats['packets']:,} packets read, {stats['flows']:,} flows"
        + (", truncated at the packet cap" if stats["truncated"] else "") + ")",
        f"- Ground truth: flows touching {', '.join(sorted(attackers)) or 'no attacker IP (benign-only run)'}",
        f"- Attack flows / benign flows: {stats['attack_flows']:,} / {stats['benign_flows']:,}",
        "- Alert = medium or high severity under each variant.", "",
        "| Variant | Recall | False-alarm rate | TP / FP / FN / TN |", "| --- | ---: | ---: | ---: |",
    ]
    for variant in VARIANTS:
        c = stats["variants"][variant]
        recall = "n/a (no attack flows)" if stats["attack_flows"] == 0 else _pct(c["recall"])
        false_alarm = "n/a (no benign flows)" if stats["benign_flows"] == 0 else _pct(c["false_alarm_rate"])
        lines.append(f"| {LABELS[variant]} | {recall} | {false_alarm} | "
                     f"{c['tp']} / {c['fp']} / {c['fn']} / {c['tn']} |")
    lines += [
        "",
        f"- Attack flows alerted only because of the model: {stats['model_adds_tp']}",
        f"- Benign flows alerted only because of the model: {stats['model_adds_fp']}",
        "",
        "How to read it: if \"both\" is no better than \"rules only\" on attack traffic, the learned "
        "model adds nothing there. If it adds attack flows, compare that gain with the benign "
        "flows it also adds. One capture, IP-derived labels; not a benchmark.", "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("capture", type=Path)
    parser.add_argument("--attacker-ip", action="append", default=[], help="Repeat for several")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "ablation.md")
    args = parser.parse_args()
    if not args.capture.is_file():
        raise SystemExit(f"{args.capture} not found.")
    attackers = set(args.attacker_ip)
    stats = evaluate_ablation(args.capture.read_bytes(), attackers)
    report = render_report(args.capture.name, attackers, stats)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(report)
    print(f"[ablation] Wrote {args.output}")


if __name__ == "__main__":
    main()
