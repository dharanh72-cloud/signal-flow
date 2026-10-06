"""Train the normal-only Isolation Forest and refresh model integrity hashes.

With no arguments this fits the bundled synthetic baseline. To fit on real benign
captures instead, use scripts/train_anomaly_from_pcaps.py.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from artifacts import MODEL_DIR, write_manifest  # noqa: E402
from features import FEATURE_NAMES  # noqa: E402

DATA_PATH = ROOT / "data" / "synthetic_sessions.csv"
SYNTHETIC_SOURCE = "sample_data/normal.pcap (synthetic normal flows)"
SYNTHETIC_NOTE = "Synthetic normal-only baseline; public network behavior may differ."


def fit_and_save(frame: pd.DataFrame, *, source: str, note: str,
                 model_dir: Path = MODEL_DIR) -> dict:
    """Fit scaler + Isolation Forest on frame (needs FEATURE_NAMES and session_id)."""
    features = frame[FEATURE_NAMES].to_numpy(dtype=float)
    scaler = StandardScaler().fit(features)
    scaled = scaler.transform(features)
    model = IsolationForest(
        n_estimators=400,
        max_samples="auto",
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    ).fit(scaled)
    scores = model.score_samples(scaled)
    metadata = {
        "trained_at_utc": datetime.now(UTC).isoformat(),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "training_source": source,
        "training_rows": int(len(frame)),
        "training_sessions": int(frame["session_id"].nunique()),
        "feature_names": FEATURE_NAMES,
        "score_threshold_q01": float(np.quantile(scores, 0.01)),
        "score_min": float(min(scores.min(), np.quantile(scores, 0.01) - 1e-6)),
        "feature_stats": {
            name: {
                "mean": float(frame[name].mean()),
                "std": float(frame[name].std(ddof=0)),
            }
            for name in FEATURE_NAMES
        },
        "note": note,
    }
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "anomaly_iforest.joblib", compress=3)
    joblib.dump(scaler, model_dir / "anomaly_scaler.joblib", compress=3)
    (model_dir / "anomaly_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    write_manifest(model_dir)
    return metadata


def main() -> None:
    frame = pd.read_csv(DATA_PATH)
    fit_and_save(frame, source=SYNTHETIC_SOURCE, note=SYNTHETIC_NOTE)
    print(f"Trained normal-only model on {len(frame)} flows / {frame['session_id'].nunique()} sessions.")
    print(f"Saved model metadata and hashes under {MODEL_DIR}.")


if __name__ == "__main__":
    main()
