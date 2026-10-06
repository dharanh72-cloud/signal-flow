.PHONY: run train dataset test lint samples anomaly evaluate package

run:
	python src/app.py

# Build data/features.csv from labeled captures: make dataset CAPTURES=captures
dataset:
	python scripts/build_dataset_from_pcaps.py $(CAPTURES) --append

train:
	python src/train.py

test:
	python -m pytest

lint:
	python -m ruff check src scripts tests

samples:
	python scripts/generate_samples.py

anomaly:
	python scripts/train_anomaly.py

evaluate:
	python scripts/evaluate_anomaly.py

package:
	python scripts/package_zip.py
