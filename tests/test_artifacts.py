import pytest

from artifacts import REQUIRED_ARTIFACTS, ArtifactError, verify_manifest, write_manifest


def test_model_bundle_hashes_are_checked_before_load(tmp_path):
    for index, name in enumerate(REQUIRED_ARTIFACTS):
        (tmp_path / name).write_bytes(f"trusted artifact {index}".encode())
    write_manifest(tmp_path)

    assert verify_manifest(tmp_path)["algorithm"] == "sha256"
    (tmp_path / REQUIRED_ARTIFACTS[0]).write_bytes(b"changed artifact")
    with pytest.raises(ArtifactError, match="Hash verification failed"):
        verify_manifest(tmp_path)


def test_missing_manifest_fails_closed(tmp_path):
    with pytest.raises(ArtifactError, match="manifest"):
        verify_manifest(tmp_path)
