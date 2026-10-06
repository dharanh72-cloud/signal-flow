"""
train.py
--------
Evaluates the Random Forest recipe on a held-out split, writes a report,
then refits the serving artifacts on the complete labeled feature dataset.

Usage:
    python src/train.py
    python src/train.py --model lstm  # documented extension; needs raw sequences
"""

import argparse
import html
import json
import os
import platform
from datetime import UTC, datetime

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from artifacts import write_manifest
from features import FEATURE_NAMES

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
FEATURES_CSV = os.path.join(DATA_DIR, "features.csv")


def load_dataset():
    if not os.path.exists(FEATURES_CSV):
        raise SystemExit(
            f"No dataset found at {FEATURES_CSV}. Run capture.py to build labeled "
            "flows before training."
        )
    df = pd.read_csv(FEATURES_CSV)
    required = FEATURE_NAMES + ["label"]
    missing = [name for name in required if name not in df.columns]
    if missing:
        raise SystemExit("Dataset is missing required columns: " + ", ".join(missing))
    if df[required].isna().any().any():
        raise SystemExit(
            "Dataset contains missing values in a model feature or label. "
            "Review data/features.csv before training."
        )
    if "session_id" not in df:
        df["session_id"] = ""
    df["session_id"] = df["session_id"].fillna("").astype(str)
    if df["label"].nunique() < 2:
        raise SystemExit(
            "Need at least 2 distinct labels to train a classifier. "
            f"Currently have: {df['label'].unique().tolist()}"
        )
    print("[train] Dataset rows by class:")
    print(df["label"].value_counts().sort_index().to_string())
    return df


def new_classifier():
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


def write_confusion_svg(path, matrix, labels, accuracy):
    """Write a compact confusion matrix without a plotting dependency."""
    cell = 76
    left = 140
    top = 100
    width = left + cell * len(labels) + 16
    height = top + cell * len(labels) + 57
    largest = max(int(matrix.max()), 1)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:system-ui,-apple-system,Segoe UI,sans-serif}.muted{fill:#68778a}.strong{fill:#182a40;font-weight:700}</style>',
        '<text x="20" y="29" font-size="18" class="strong">Held-out classification</text>',
        f'<text x="20" y="51" font-size="12" class="muted">Rows: true class · columns: predicted class · accuracy {accuracy:.1%}</text>',
    ]
    for column, label in enumerate(labels):
        x = left + column * cell + cell / 2
        parts.append(
            f'<text x="{x}" y="{top - 11}" text-anchor="middle" font-size="10" class="muted" transform="rotate(-22 {x} {top - 11})">{html.escape(str(label))}</text>'
        )
    for row, label in enumerate(labels):
        y = top + row * cell
        parts.append(
            f'<text x="{left - 12}" y="{y + cell / 2 + 4}" text-anchor="end" font-size="10" class="muted">{html.escape(str(label))}</text>'
        )
        for column in range(len(labels)):
            value = int(matrix[row, column])
            intensity = int(12 + 34 * value / largest)
            fill = f"#{intensity:02x}{min(136 + intensity, 255):02x}{min(128 + intensity, 255):02x}"
            text_color = "#ffffff" if value / largest > 0.42 else "#18364c"
            x = left + column * cell
            parts.extend([
                f'<rect x="{x + 2}" y="{y + 2}" width="{cell - 4}" height="{cell - 4}" rx="7" fill="{fill}"/>',
                f'<text x="{x + cell / 2}" y="{y + cell / 2 + 5}" text-anchor="middle" font-size="16" font-weight="700" fill="{text_color}">{value}</text>',
            ])
    parts.append(
        f'<text x="{left + cell * len(labels) / 2}" y="{height - 14}" text-anchor="middle" font-size="11" class="muted">Predicted class</text>'
    )
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(parts))


def write_evaluation(df, labels, matrix, report, accuracy, macro_f1, weighted_f1,
                     split_label, session_held_out, train_rows, test_rows):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    write_confusion_svg(
        os.path.join(REPORTS_DIR, "confusion_matrix.svg"), matrix, labels, accuracy
    )
    pd.DataFrame(matrix, index=labels, columns=labels).to_csv(
        os.path.join(REPORTS_DIR, "confusion_matrix.csv")
    )

    counts = df["label"].value_counts().reindex(labels, fill_value=0)
    class_rows = "\n".join(
        f"| {label} | {int(counts[label])} | {report[label]['precision']:.3f} | "
        f"{report[label]['recall']:.3f} | {report[label]['f1-score']:.3f} | "
        f"{int(report[label]['support'])} |"
        for label in labels
    )
    test_rows = int(sum(report[label]["support"] for label in labels))
    split_note = (
        "Whole capture sessions were kept separate across train and test."
        if session_held_out else
        "The source data lacks usable session IDs, so related flows may cross this random split."
    )
    markdown = f"""# Model evaluation

Generated by `python src/train.py` from the labeled aggregate features in `data/features.csv`.

| Measure | Result |
| --- | ---: |
| Accuracy | {accuracy:.1%} |
| Macro F1 | {macro_f1:.3f} |
| Weighted F1 | {weighted_f1:.3f} |
| Held-out flows | {test_rows} |
| Split | {split_label} |
| Whole sessions held out | {"Yes" if session_held_out else "No — session IDs were unavailable or insufficient"} |
| Training flows | {train_rows} |
| Test flows | {test_rows} |

| Class | Dataset flows | Precision | Recall | F1 | Test flows |
| --- | ---: | ---: | ---: | ---: | ---: |
{class_rows}

![Confusion matrix for the held-out split](confusion_matrix.svg)

Rows are actual labels; columns are predictions. {split_note} When whole-session holdout is unavailable, treat this as a baseline check, not an estimate of
performance on a new network or an independent capture. `capture.py` now writes session IDs for
new runs; grouped evaluation is selected automatically once there are enough separate sessions
with every class represented. After reporting the split, the serving model is fit on every row.
"""
    with open(os.path.join(REPORTS_DIR, "evaluation.md"), "w", encoding="utf-8") as handle:
        handle.write(markdown)


def train_random_forest(df: pd.DataFrame):
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    encoder = LabelEncoder()
    y = encoder.fit_transform(df["label"].to_numpy())
    labels = encoder.classes_

    # Keep all flows from an identified capture session on the same side.
    groups = df["session_id"].to_numpy()
    session_held_out = False
    split_label = "Stratified 75% train / 25% test flow split, seed 42"
    indices = np.arange(len(df))
    known_session_indices = np.flatnonzero(groups != "")
    known_groups = groups[known_session_indices]
    if pd.Series(known_groups).nunique() >= 2:
        known_y = y[known_session_indices]
        all_labels = set(np.unique(y))
        for known_train, known_test in GroupShuffleSplit(
            n_splits=100, test_size=0.25, random_state=42
        ).split(X[known_session_indices], known_y, known_groups):
            if set(np.unique(known_y[known_train])) == all_labels and set(np.unique(known_y[known_test])) == all_labels:
                train_index = known_session_indices[known_train]
                test_index = known_session_indices[known_test]
                session_held_out = True
                split_label = "GroupShuffleSplit: 75% train / 25% test by whole identified capture session, seed 42"
                break
    if not session_held_out:
        class_counts = pd.Series(y).value_counts()
        stratify = y if class_counts.min() >= 2 else None
        train_index, test_index = train_test_split(
            indices, test_size=0.25, random_state=42, stratify=stratify
        )
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = y[train_index], y[test_index]
    validation_scaler = StandardScaler().fit(X_train)
    validation_model = new_classifier()
    validation_model.fit(validation_scaler.transform(X_train), y_train)
    y_pred = validation_model.predict(validation_scaler.transform(X_test))

    label_ids = np.arange(len(labels))
    matrix = confusion_matrix(y_test, y_pred, labels=label_ids)
    report = classification_report(
        y_test,
        y_pred,
        labels=label_ids,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    accuracy = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted"))

    print("\n[train] Stratified 25% held-out report (scaler fit on train only):")
    print(classification_report(
        y_test, y_pred, labels=label_ids, target_names=labels, zero_division=0
    ))
    print("[train] Confusion matrix (rows=true, cols=predicted):")
    print(pd.DataFrame(matrix, index=labels, columns=labels))
    print(
        f"[train] Accuracy: {accuracy:.3f}; macro F1: {macro_f1:.3f}; "
        f"weighted F1: {weighted_f1:.3f}"
    )
    write_evaluation(
        df, labels, matrix, report, accuracy, macro_f1, weighted_f1,
        split_label, session_held_out, len(train_index), len(test_index),
    )

    # Evaluate the recipe above, then fit the actual serving bundle on all rows.
    scaler = StandardScaler().fit(X)
    classifier = new_classifier()
    classifier.fit(scaler.transform(X), y)
    importances = pd.Series(
        classifier.feature_importances_, index=FEATURE_NAMES
    ).sort_values(ascending=False)
    print("\n[train] Top feature importances:")
    print(importances.head(10).to_string())

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(classifier, os.path.join(MODELS_DIR, "rf_classifier.joblib"), compress=3)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"), compress=3)
    joblib.dump(encoder, os.path.join(MODELS_DIR, "label_encoder.joblib"), compress=3)
    metadata = {
        "trained_at_utc": datetime.now(UTC).isoformat(),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "dataset_rows": int(len(df)),
        "class_counts": {
            str(label): int(count)
            for label, count in df["label"].value_counts().sort_index().items()
        },
        "feature_names": FEATURE_NAMES,
        "classifier": "RandomForestClassifier",
        "serving_model_fit_rows": int(len(df)),
        "validation": {
            "test_size": 0.25,
            "test_rows": int(len(y_test)),
            "random_state": 42,
            "stratified": not session_held_out and stratify is not None,
            "split_method": split_label,
            "session_held_out": session_held_out,
            "test_sessions": int(pd.Series(groups[test_index]).nunique()) if session_held_out else 0,
            "accuracy": accuracy,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
        },
        "review_threshold": 0.40,
    }
    with open(os.path.join(MODELS_DIR, "training_metadata.json"), "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)
        handle.write("\n")

    importances.to_csv(os.path.join(REPORTS_DIR, "classifier_feature_importance.csv"),
                      header=["impurity_importance"])
    write_manifest()

    print(f"\n[train] Evaluation report: {os.path.join(REPORTS_DIR, 'evaluation.md')}")
    print(f"[train] Serving model fit on all {len(df):,} rows and saved to {MODELS_DIR}/")


def train_lstm(_df: pd.DataFrame):
    raise SystemExit(
        "The LSTM extension needs raw per-packet sequences. This project currently "
        "stores aggregate flow features only; see the README for the current model path."
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["rf", "lstm"], default="rf")
    args = parser.parse_args()

    df = load_dataset()
    if args.model == "rf":
        train_random_forest(df)
    else:
        train_lstm(df)


if __name__ == "__main__":
    main()
