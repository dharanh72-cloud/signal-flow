"""Create a source-and-samples project archive without local or private data."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "signal-flow.zip"
ROOT_FILES = (
    ".env.example", ".gitignore", ".python-version", "Dockerfile", "LICENSE",
    "Makefile", "README.md", "pyproject.toml", "render.yaml", "requirements.txt",
)
DIRECTORIES = (
    ".github", "config", "dashboard", "docs", "models", "reports", "sample_data",
    "scripts", "src", "tests",
)


def _included_file(path: Path) -> bool:
    if path.name in {".DS_Store", "Thumbs.db"}:
        return False
    if any(part in {"__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "venv", ".git"}
           for part in path.parts):
        return False
    if any(part.endswith(".egg-info") for part in path.parts):
        return False
    if path.suffix in {".pyc", ".pyo"} or path.name == ".env":
        return False
    if path.parent.name == "data" and path.name not in {"synthetic_sessions.csv", "features.csv", "README.md"}:
        return False
    return True


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    files = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
    for directory in DIRECTORIES:
        root = ROOT / directory
        if root.exists():
            files.extend(path for path in root.rglob("*") if path.is_file() and _included_file(path))
    for name in ("synthetic_sessions.csv", "features.csv", "README.md"):
        extra = ROOT / "data" / name
        if extra.is_file():
            files.append(extra)

    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(set(files)):
            archive.write(path, f"signal-flow/{path.relative_to(ROOT).as_posix()}")
    print(f"Created {OUTPUT.relative_to(ROOT)} with {len(set(files))} files ({OUTPUT.stat().st_size:,} bytes).")


if __name__ == "__main__":
    main()
