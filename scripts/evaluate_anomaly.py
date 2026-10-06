"""Measure anomaly detection on bundled synthetic normal and attack PCAPs."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from artifacts import load_models
from pipeline import AnalysisPipeline

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_data"
REPORTS = ROOT / "reports"
ATTACK_TYPES = ("port_scan", "slow_scan", "exfiltration", "dos_burst", "beaconing", "dns_tunnel")


def _curve_svg(title, x_values, y_values, x_label, y_label, diagonal=False):
    width, height = 620, 410
    left, top, plot_width, plot_height = 68, 43, 510, 300

    def point(x_value, y_value):
        x = left + max(0, min(1, float(x_value))) * plot_width
        y = top + (1 - max(0, min(1, float(y_value)))) * plot_height
        return x, y

    path_points = [point(x, y) for x, y in zip(x_values, y_values, strict=True)]
    path = " ".join(("M" if index == 0 else "L") + f" {x:.1f} {y:.1f}"
                     for index, (x, y) in enumerate(path_points))
    ticks = []
    for value in np.linspace(0, 1, 6):
        x, y = point(value, value)
        ticks.extend([
            f'<path d="M {left} {y:.1f} H {left + plot_width}" stroke="#e4e9ef"/>',
            f'<path d="M {x:.1f} {top} V {top + plot_height}" stroke="#e4e9ef"/>',
            f'<text x="{x:.1f}" y="{top + plot_height + 20}" text-anchor="middle">{value:.1f}</text>',
            f'<text x="{left - 11}" y="{y + 4:.1f}" text-anchor="end">{value:.1f}</text>',
        ])
    diagonal_path = f"M {left} {top + plot_height} L {left + plot_width} {top}" if diagonal else ""
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{title}" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style>text{font:12px system-ui,sans-serif;fill:#65758a}.title{font-size:17px;font-weight:700;fill:#182b42}.axis{stroke:#8392a3;stroke-width:1}.curve{fill:none;stroke:#3475d2;stroke-width:3}.baseline{fill:none;stroke:#b1bac5;stroke-dasharray:5 5}</style>',
        f'<text class="title" x="{left}" y="24">{title}</text>',
        *ticks,
        f'<path class="baseline" d="{diagonal_path}"/>' if diagonal else "",
        f'<path class="curve" d="{path}"/>',
        f'<path class="axis" d="M {left} {top} V {top + plot_height} H {left + plot_width}" fill="none"/>',
        f'<text x="{left + plot_width / 2}" y="{height - 12}" text-anchor="middle">{x_label}</text>',
        f'<text x="18" y="{top + plot_height / 2}" text-anchor="middle" transform="rotate(-90 18 {top + plot_height / 2})">{y_label}</text>',
        "</svg>",
    ])


def _write_curve_data(path, x_values, y_values, threshold_values):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["x", "y", "threshold"])
        for index, (x_value, y_value) in enumerate(zip(x_values, y_values, strict=True)):
            threshold = threshold_values[index] if index < len(threshold_values) else ""
            writer.writerow([float(x_value), float(y_value), threshold])


def _metrics(truth, scores, positive_threshold):
    predicted = np.asarray(scores) >= positive_threshold
    truth = np.asarray(truth, dtype=bool)
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[False, True]).ravel()
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    return {
        "true_positive": int(tp), "false_positive": int(fp),
        "true_negative": int(tn), "false_negative": int(fn),
        "precision": precision, "recall": recall,
        "detection_rate": recall, "false_positive_rate": fpr,
    }


def run_evaluation() -> dict:
    REPORTS.mkdir(parents=True, exist_ok=True)
    pipeline = AnalysisPipeline(load_models())
    results = {}
    for capture_name in ("normal", "with_attacks"):
        capture_path = SAMPLES / f"{capture_name}.pcap"
        labels_path = SAMPLES / f"{capture_name}_labels.json"
        metadata = json.loads(labels_path.read_text(encoding="utf-8"))
        expected = {item["flow_id"]: item for item in metadata["flows"]}
        result = pipeline.analyze(capture_path.read_bytes(), filename=capture_path.name)
        rows = []
        for flow in result["flows"]:
            label = expected.get(flow["flow_id"])
            if label is None:
                raise RuntimeError(f"No truth label exists for flow {flow['flow_id']} in {capture_name}.")
            rows.append({
                "flow_id": flow["flow_id"],
                "attack_type": label["attack_type"],
                "is_attack": bool(label["is_attack"]),
                "score": int(flow["score"]),
                "severity": flow["severity"],
                "rule_codes": [hit["code"] for hit in flow["rule_hits"]],
            })
        results[capture_name] = rows

    attack_rows = results["with_attacks"]
    truths = [row["is_attack"] for row in attack_rows]
    scores = [row["score"] for row in attack_rows]
    medium_metrics = _metrics(truths, scores, 30)
    high_metrics = _metrics(truths, scores, 60)
    fpr_medium_normal = _metrics([False] * len(results["normal"]),
                                 [row["score"] for row in results["normal"]], 30)
    fpr_high_normal = _metrics([False] * len(results["normal"]),
                               [row["score"] for row in results["normal"]], 60)
    fpr, tpr, roc_thresholds = roc_curve(truths, scores)
    precision, recall, pr_thresholds = precision_recall_curve(truths, scores)
    roc_auc = float(roc_auc_score(truths, scores))
    pr_auc = float(average_precision_score(truths, scores))
    _write_curve_data(REPORTS / "anomaly_roc.csv", fpr, tpr, roc_thresholds)
    _write_curve_data(REPORTS / "anomaly_pr.csv", recall, precision, pr_thresholds)
    (REPORTS / "anomaly_roc.svg").write_text(
        _curve_svg("ROC curve · synthetic attack flows", fpr, tpr, "False positive rate", "True positive rate", diagonal=True), encoding="utf-8"
    )
    (REPORTS / "anomaly_pr.svg").write_text(
        _curve_svg("Precision–recall · synthetic attack flows", recall, precision, "Recall", "Precision"), encoding="utf-8"
    )
    matrix = np.asarray([
        [high_metrics["true_negative"], high_metrics["false_positive"]],
        [high_metrics["false_negative"], high_metrics["true_positive"]],
    ])
    _write_confusion(matrix)

    per_attack = {}
    for attack_type in ATTACK_TYPES:
        selected = [row for row in attack_rows if row["attack_type"] == attack_type]
        matched = sum(attack_type in row["rule_codes"] for row in selected)
        caught_high = sum(row["score"] >= 60 for row in selected)
        caught_medium = sum(row["score"] >= 30 for row in selected)
        per_attack[attack_type] = {
            "flows": len(selected),
            "high_severity_detected": caught_high,
            "high_severity_recall": caught_high / max(1, len(selected)),
            "medium_or_high_detected": caught_medium,
            "rule_matched": matched,
            "rule_match_rate": matched / max(1, len(selected)),
            "mean_score": sum(row["score"] for row in selected) / max(1, len(selected)),
        }
    report = {
        "dataset": "bundled synthetic PCAPs",
        "normal_capture_flows": len(results["normal"]),
        "attack_capture_flows": len(attack_rows),
        "attack_flows": sum(truths),
        "benign_flows_in_attack_capture": len(attack_rows) - sum(truths),
        "overall": {
            "threshold_medium_or_high": medium_metrics,
            "threshold_high": high_metrics,
            "normal_capture_false_positive_rate_medium_or_high": fpr_medium_normal["false_positive_rate"],
            "normal_capture_false_positive_rate_high": fpr_high_normal["false_positive_rate"],
            "roc_auc": roc_auc,
            "pr_auc_average_precision": pr_auc,
            "normal_capture_medium_or_high_false_positives": fpr_medium_normal["false_positive"],
        },
        "per_attack": per_attack,
        "method": {
            "high_threshold": 60,
            "medium_threshold": 30,
            "metrics_unit": "flow",
            "labels_file": "separate JSON truth file shipped beside each synthetic PCAP",
            "limitations": [
                "Synthetic attack patterns are intentionally clear and easier to detect than real intrusions.",
                "The normal and attack captures are generated by this repository, not independent network traffic.",
                "Port-scan labels are evaluated per flow; one source-wide scan rule can flag each flow in a scan.",
                "No real public PCAP was evaluated in this report.",
            ],
        },
    }
    (REPORTS / "anomaly_evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (REPORTS / "anomaly_evaluation.md").write_text(_markdown(report), encoding="utf-8")
    print(_markdown(report))
    return report


def _write_confusion(matrix):
    names = ("benign", "attack")
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Anomaly confusion matrix at score 60" width="420" height="260" viewBox="0 0 420 260">',
        '<style>text{font-family:system-ui,sans-serif;fill:#24384f}.muted{fill:#6c7d90;font-size:12px}.title{font-size:17px;font-weight:700}</style>',
        '<text x="20" y="26" class="title">Confusion matrix · score ≥ 60</text>',
        '<text x="160" y="57" class="muted">Predicted</text>',
    ]
    for index, name in enumerate(names):
        x = 185 + index * 100
        lines.append(f'<text x="{x}" y="83" text-anchor="middle" class="muted">{name}</text>')
        y = 100 + index * 66
        lines.append(f'<text x="158" y="{y + 31}" text-anchor="end" class="muted">{name}</text>')
        for column in range(2):
            value = int(matrix[index, column])
            x_cell, y_cell = 170 + column * 100, 91 + index * 66
            fill = "#dceee5" if index == column == 0 else "#f6e8e1" if index == 1 and column == 0 else "#ffe9e6" if column == 1 and index == 0 else "#d8e5fa"
            lines.append(f'<rect x="{x_cell}" y="{y_cell}" width="88" height="54" rx="7" fill="{fill}"/>')
            lines.append(f'<text x="{x_cell + 44}" y="{y_cell + 34}" text-anchor="middle" font-size="18" font-weight="700">{value}</text>')
    lines.append('</svg>')
    (REPORTS / "anomaly_confusion.svg").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with (REPORTS / "anomaly_confusion.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["actual/predicted", *names])
        writer.writerow(["benign", *map(int, matrix[0])])
        writer.writerow(["attack", *map(int, matrix[1])])


def _markdown(report):
    overall = report["overall"]
    high = overall["threshold_high"]
    per_type = "\n".join(
        f"| {name.replace('_', ' ')} | {values['flows']} | {values['high_severity_detected']} ({values['high_severity_recall']:.1%}) | {values['rule_matched']} ({values['rule_match_rate']:.1%}) | {values['mean_score']:.1f} |"
        for name, values in report["per_attack"].items()
    )
    return f"""# Anomaly detector evaluation

Generated with `python scripts/evaluate_anomaly.py` using the bundled synthetic captures and separate truth labels.

## Results

At the high severity threshold (score ≥ 60), the detector found {high['true_positive']} of {report['attack_flows']} injected attack flows ({high['recall']:.1%} recall), with {high['false_positive']} false positives among {report['benign_flows_in_attack_capture']} benign flows mixed into the attack capture. Precision was {high['precision']:.1%}; FPR was {high['false_positive_rate']:.1%}. The separate {report['normal_capture_flows']}-flow normal capture had a {overall['normal_capture_false_positive_rate_medium_or_high']:.1%} medium-or-high false-positive rate ({overall['normal_capture_medium_or_high_false_positives']} alerts).

| Measure | Result |
| --- | ---: |
| Detection rate / recall (score ≥ 60) | {high['recall']:.1%} |
| Precision (score ≥ 60) | {high['precision']:.1%} |
| False-positive rate (score ≥ 60) | {high['false_positive_rate']:.1%} |
| ROC AUC | {overall['roc_auc']:.3f} |
| PR AUC (average precision) | {overall['pr_auc_average_precision']:.3f} |
| Attack capture flows | {report['attack_capture_flows']} |
| Injected attack flows | {report['attack_flows']} |

| Attack type | Flows | High severity detected | Matching rule | Mean score |
| --- | ---: | ---: | ---: | ---: |
{per_type}

![ROC curve](anomaly_roc.svg)

![Precision–recall curve](anomaly_pr.svg)

![Confusion matrix at score 60](anomaly_confusion.svg)

## Method and limits

Metrics are flow-level. A score of 60 or higher is counted as a positive detection; 30–59 is medium severity. The scan rules use capture-wide source context, so each flow from a detected scan can be flagged. The sample PCAPs are generated by this project and the injected patterns are intentionally clear; synthetic attacks are easier to detect than real intrusion traffic. These results do not estimate real-world network performance. No public real-world capture was tested. Rules can miss evasive or distributed activity, and benign backups or unusual applications can trigger alerts. Review every alert in its network context.
"""


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    run_evaluation()
