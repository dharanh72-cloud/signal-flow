"""Compare classifier candidates on whole synthetic capture sessions."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize

from features import FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "synthetic_sessions.csv"
REPORTS = ROOT / "reports"


def _group_splits(X, y, groups):
    labels = set(np.unique(y))
    outer = GroupShuffleSplit(n_splits=100, test_size=0.20, random_state=42)
    for train_cal, test in outer.split(X, y, groups):
        if set(np.unique(y[test])) != labels:
            continue
        inner = GroupShuffleSplit(n_splits=100, test_size=0.20, random_state=2026)
        for train, calibration in inner.split(X[train_cal], y[train_cal], groups[train_cal]):
            train_index, calibration_index = train_cal[train], train_cal[calibration]
            if (set(np.unique(y[train_index])) == labels
                    and set(np.unique(y[calibration_index])) == labels):
                return train_index, calibration_index, test
    raise ValueError("Could not form train, calibration, and test sets with every class represented.")


def _metrics(model, X, y, labels):
    probabilities = model.predict_proba(X)
    predictions = model.classes_[probabilities.argmax(axis=1)]
    one_hot = label_binarize(y, classes=labels)
    brier = float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))
    confidence = probabilities.max(axis=1)
    correct = predictions == y
    ece = 0.0
    for lower in np.linspace(0, 0.9, 10):
        upper = lower + 0.1
        mask = (confidence >= lower) & (confidence < upper if upper < 1 else confidence <= upper)
        if mask.any():
            ece += float(mask.mean() * abs(confidence[mask].mean() - correct[mask].mean()))
    return {
        "accuracy": float(accuracy_score(y, predictions)),
        "macro_f1": float(f1_score(y, predictions, labels=labels, average="macro", zero_division=0)),
        "multiclass_brier": brier,
        "expected_calibration_error": float(ece),
        "probabilities": probabilities,
        "predictions": predictions,
    }


def run() -> dict:
    REPORTS.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(DATA_PATH)
    if "session_id" not in frame or frame["session_id"].isna().any():
        raise ValueError("Synthetic classifier rows must each have a session_id.")
    encoder = LabelEncoder()
    y = encoder.fit_transform(frame["label"].to_numpy())
    X = frame[FEATURE_NAMES].to_numpy(dtype=float)
    groups = frame["session_id"].to_numpy()
    train_index, calibration_index, test_index = _group_splits(X, y, groups)
    if set(groups[train_index]) & set(groups[calibration_index]) or set(groups[train_index]) & set(groups[test_index]) or set(groups[calibration_index]) & set(groups[test_index]):
        raise RuntimeError("A capture session crossed a data split.")
    scaler = StandardScaler().fit(X[train_index])
    X_scaled = scaler.transform(X)
    X_train, X_cal, X_test = X_scaled[train_index], X_scaled[calibration_index], X_scaled[test_index]
    y_train, y_cal, y_test = y[train_index], y[calibration_index], y[test_index]
    labels = np.arange(len(encoder.classes_))

    candidates = {
        "RandomForestClassifier": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=42, n_jobs=-1,
        ),
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier(
            max_iter=140, learning_rate=0.08, max_leaf_nodes=15,
            l2_regularization=1.0, class_weight="balanced", random_state=42,
        ),
    }
    evaluated = {}
    fitted_models = {}
    for name, estimator in candidates.items():
        estimator.fit(X_train, y_train)
        calibrated = CalibratedClassifierCV(FrozenEstimator(estimator), method="sigmoid")
        calibrated.fit(X_cal, y_cal)
        raw_metrics = _metrics(estimator, X_test, y_test, labels)
        calibrated_metrics = _metrics(calibrated, X_test, y_test, labels)
        calibration_probabilities = calibrated.predict_proba(X_cal)
        review_threshold = float(np.quantile(calibration_probabilities.max(axis=1), 0.10))
        test_probabilities = calibrated_metrics["probabilities"]
        test_confidence = test_probabilities.max(axis=1)
        test_predictions = calibrated.classes_[test_probabilities.argmax(axis=1)]
        covered = test_confidence >= review_threshold
        evaluated[name] = {
            "raw": {key: raw_metrics[key] for key in (
                "accuracy", "macro_f1", "multiclass_brier", "expected_calibration_error")},
            "calibrated": {key: calibrated_metrics[key] for key in (
                "accuracy", "macro_f1", "multiclass_brier", "expected_calibration_error")},
            "review_threshold": review_threshold,
            "review_target_coverage": 0.90,
            "test_coverage_at_threshold": float(covered.mean()),
            "selective_accuracy": float((test_predictions[covered] == y_test[covered]).mean()) if covered.any() else 0.0,
            "confusion_matrix": confusion_matrix(y_test, test_predictions, labels=labels).tolist(),
        }
        fitted_models[name] = estimator

    winner = max(evaluated, key=lambda name: evaluated[name]["calibrated"]["macro_f1"])
    rf = fitted_models["RandomForestClassifier"]
    importance = permutation_importance(rf, X_test, y_test, scoring="f1_macro",
                                        n_repeats=5, random_state=42, n_jobs=-1)
    importance_rows = sorted(zip(FEATURE_NAMES, importance.importances_mean, strict=True), key=lambda row: row[1], reverse=True)
    with (REPORTS / "classifier_synthetic_feature_importance.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["feature", "permutation_macro_f1_decrease"])
        writer.writerows(importance_rows)
    confusion = evaluated["RandomForestClassifier"]["confusion_matrix"]
    _write_confusion(np.asarray(confusion), encoder.classes_)

    report = {
        "dataset": "synthetic normal PCAP flows",
        "rows": int(len(frame)),
        "sessions": int(pd.Series(groups).nunique()),
        "train_sessions": int(pd.Series(groups[train_index]).nunique()),
        "calibration_sessions": int(pd.Series(groups[calibration_index]).nunique()),
        "test_sessions": int(pd.Series(groups[test_index]).nunique()),
        "train_rows": int(len(train_index)),
        "calibration_rows": int(len(calibration_index)),
        "test_rows": int(len(test_index)),
        "split": "whole-session GroupShuffleSplit; no session crosses train/calibration/test",
        "candidates": evaluated,
        "higher_macro_f1_candidate": winner,
        "top_features": [{"feature": name, "importance": float(value)} for name, value in importance_rows[:10]],
        "note": "Synthetic class signatures are deliberately generated and do not measure real-network generalization. This experiment does not replace the historical real-capture serving model.",
    }
    (REPORTS / "classifier_synthetic_session_evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (REPORTS / "classifier_synthetic_session_evaluation.md").write_text(_markdown(report), encoding="utf-8")
    print(_markdown(report))
    return report


def _write_confusion(matrix, labels):
    cell = 74
    left, top = 150, 92
    width, height = left + cell * len(labels) + 20, top + cell * len(labels) + 46
    largest = max(1, int(matrix.max()))
    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Synthetic session-held-out classifier confusion matrix" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style>text{font-family:system-ui,sans-serif;fill:#24384f}.muted{fill:#6c7d90;font-size:10px}.title{font-size:16px;font-weight:700}</style>',
        '<text x="18" y="25" class="title">Synthetic session-held-out classifier</text>',
    ]
    for column, label in enumerate(labels):
        x = left + column * cell + cell / 2
        pieces.append(f'<text x="{x}" y="{top - 10}" text-anchor="middle" class="muted">{label}</text>')
    for row, label in enumerate(labels):
        y = top + row * cell
        pieces.append(f'<text x="{left - 9}" y="{y + cell / 2 + 4}" text-anchor="end" class="muted">{label}</text>')
        for column in range(len(labels)):
            value = int(matrix[row, column])
            intensity = int(218 - 85 * value / largest)
            fill = f"#{intensity:02x}{min(238, intensity + 10):02x}{min(255, intensity + 23):02x}"
            x = left + column * cell
            pieces.extend([
                f'<rect x="{x + 2}" y="{y + 2}" width="{cell - 4}" height="{cell - 4}" rx="6" fill="{fill}"/>',
                f'<text x="{x + cell / 2}" y="{y + cell / 2 + 5}" text-anchor="middle" font-size="16" font-weight="700">{value}</text>',
            ])
    pieces.append("</svg>")
    (REPORTS / "classifier_synthetic_confusion.svg").write_text("\n".join(pieces) + "\n", encoding="utf-8")
    with (REPORTS / "classifier_synthetic_confusion.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["actual/predicted", *labels])
        for label, row in zip(labels, matrix, strict=True):
            writer.writerow([label, *map(int, row)])


def _markdown(report):
    rows = []
    for name, result in report["candidates"].items():
        raw, calibrated = result["raw"], result["calibrated"]
        rows.append(
            f"| {name} | {raw['macro_f1']:.3f} | {calibrated['macro_f1']:.3f} | "
            f"{calibrated['multiclass_brier']:.3f} | {calibrated['expected_calibration_error']:.3f} | "
            f"{result['review_threshold']:.3f} | {result['test_coverage_at_threshold']:.1%} | {result['selective_accuracy']:.1%} |"
        )
    features = "\n".join(f"| {item['feature']} | {item['importance']:.4f} |" for item in report["top_features"])
    best = report["higher_macro_f1_candidate"]
    return f"""# Classifier session-held-out experiment

Generated with `python scripts/evaluate_classifier_sessions.py` from {report['rows']} generated normal flows across {report['sessions']} synthetic sessions. Train, calibration, and test partitions contain disjoint session IDs ({report['train_sessions']}, {report['calibration_sessions']}, and {report['test_sessions']} sessions respectively).

| Candidate | Raw macro F1 | Calibrated macro F1 | Multiclass Brier ↓ | ECE ↓ | Review threshold | Test coverage | Selective accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

![Confusion matrix for calibrated Random Forest on held-out synthetic sessions](classifier_synthetic_confusion.svg)

## Feature importance

Permutation importance is the decrease in macro F1 when one feature is shuffled in the held-out set.

| Feature | Macro F1 decrease |
| --- | ---: |
{features}

The alternative with the higher macro F1 on this synthetic split was **{best}**. Gradient boosting and class weighting were tested, and sigmoid probability calibration was fitted on separate synthetic calibration sessions. The review threshold is the tenth percentile of calibration-set maximum confidence (targeting roughly 90% coverage); coverage and accuracy are then measured on the untouched test sessions.

This experiment does not replace or retune the real-capture serving model. The generated classes have visible engineered differences, so this result cannot establish improvement on real encrypted traffic. The existing 1,554-row captured-flow dataset has no session IDs; its historical 62.7% accuracy and 0.632 macro F1 came from a random flow split. `capture.py` now records session IDs; rerun `python src/train.py` after collecting multiple independent sessions per class to produce a valid real session-held-out score.
"""


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    run()
