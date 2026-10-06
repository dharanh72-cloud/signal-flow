"""Hash checks and loading for the project-owned scikit-learn artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import sklearn

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"
MANIFEST_PATH = MODEL_DIR / "manifest.json"
REQUIRED_ARTIFACTS = (
    "rf_classifier.joblib",
    "scaler.joblib",
    "label_encoder.joblib",
    "anomaly_iforest.joblib",
    "anomaly_scaler.joblib",
)


class ArtifactError(RuntimeError):
    """The checked model bundle is missing, changed, or incompatible."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(model_dir: Path = MODEL_DIR) -> dict:
    hashes = {name: sha256_file(model_dir / name) for name in REQUIRED_ARTIFACTS}
    manifest = {"algorithm": "sha256", "artifacts": hashes}
    (model_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify_manifest(model_dir: Path = MODEL_DIR) -> dict:
    try:
        manifest = json.loads((model_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ArtifactError("The model hash manifest is missing or invalid.") from exc
    if manifest.get("algorithm") != "sha256":
        raise ArtifactError("The model hash manifest uses an unsupported hash algorithm.")
    expected = manifest.get("artifacts", {})
    for name in REQUIRED_ARTIFACTS:
        path = model_dir / name
        if not path.is_file():
            raise ArtifactError(f"The model bundle is incomplete (missing {name}).")
        if expected.get(name) != sha256_file(path):
            raise ArtifactError(f"Hash verification failed for {name}; refusing to load it.")
    return manifest


def load_models(model_dir: Path = MODEL_DIR):
    """Verify hashes before loading joblib files, which can execute code."""
    verify_manifest(model_dir)
    try:
        metadata = json.loads((model_dir / "training_metadata.json").read_text(encoding="utf-8"))
        expected_version = metadata.get("scikit_learn_version")
        if expected_version and expected_version != sklearn.__version__:
            raise ArtifactError(
                f"The classifier was trained with scikit-learn {expected_version}; "
                f"the current version is {sklearn.__version__}."
            )
        classifier = joblib.load(model_dir / "rf_classifier.joblib")
        classifier_scaler = joblib.load(model_dir / "scaler.joblib")
        encoder = joblib.load(model_dir / "label_encoder.joblib")
        anomaly_model = joblib.load(model_dir / "anomaly_iforest.joblib")
        anomaly_scaler = joblib.load(model_dir / "anomaly_scaler.joblib")
        anomaly_metadata = json.loads(
            (model_dir / "anomaly_metadata.json").read_text(encoding="utf-8")
        )
    except ArtifactError:
        raise
    except (OSError, ValueError, EOFError) as exc:
        raise ArtifactError("The verified model bundle could not be loaded.") from exc
    return classifier, classifier_scaler, encoder, anomaly_model, anomaly_scaler, metadata, anomaly_metadata
