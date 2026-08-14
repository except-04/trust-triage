# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

TRUST-TRIAGE (트러스트 트리아지) is a confidence-based malware triage system. It combines static PE analysis features with an AI model's calibrated confidence to auto-decide, route for deep analysis, or queue for analyst review. Most in-repo documentation and comments are in Korean; team conventions below are drawn directly from `docs/*.md`.

The repo is currently mid-build across three tracks that share a common feature contract (`docs/feature_schema.md`):
1. **Feature extraction** (`src/trust_triage/feature_extraction/`) — static EMBER2024 v3 feature extraction from PE files.
2. **Data pipeline / baseline model** (`src/preprocessing/`, `src/models/`) — builds the EMBER2024 Win32/Win64 train/calibration/eval/lockbox split and trains a LightGBM baseline.
3. **Calibration / Joint Risk Router / API-dashboard** — designed in `docs/` but not yet implemented in `src/`.

## Environment setup

- Requires Python >=3.10 (pinned by the `speakeasy-emulator` dependency).
- The checked-in virtualenv folder is `trust-triage-env/` (gitignored). Docs and scripts invoke it directly rather than assuming an activated shell:
  ```powershell
  .\trust-triage-env\Scripts\python.exe -m pip install -r requirements.txt
  ```
- `requirements.txt` pins `thrember` (official EMBER2024 feature extractor) to a specific git commit, and `signify==0.7.1` for API compatibility with that pinned commit. Do not upgrade either independently of the other — `EmberV3Extractor` verifies the installed `thrember` package's VCS origin/commit at construction time (`src/trust_triage/feature_extraction/ember_v3.py`) and raises if they don't match `EMBER_V3_SOURCE_COMMIT`.
- MLflow experiment tracking runs locally: `mlflow server --port 5000` (UI at `http://localhost:5000`). `mlflow.db` and `mlruns/` are local/gitignored — don't commit them.

## Common commands

```powershell
# Run the full test suite (pytest.ini sets pythonpath=src, so no install needed for tests)
.\trust-triage-env\Scripts\python.exe -m pytest

# Run a single test file / test
.\trust-triage-env\Scripts\python.exe -m pytest tests/test_feature_extraction.py
.\trust-triage-env\Scripts\python.exe -m pytest tests/test_feature_extraction.py::test_extracts_official_ember_v3_float32_vector

# Extract features from one PE file (full JSON, summary, or model-input subset)
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --summary
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --selection-file .\docs\feature-extraction\feature-selection-ember-v3-top500.json
```

Editable install (`pip install -e . --no-deps --no-build-isolation`) is only needed to use the package outside pytest/this repo root; `pyproject.toml` maps the package under `src/`.

## Architecture

### `src/trust_triage/feature_extraction/` — the only supported feature extractor

- `ember_v3.py` — `EmberV3Extractor` wraps the official `thrember.features.PEFeatureExtractor`. Reads PE bytes statically (never executes/loads them), computes SHA-256, classifies PE32/PE32+/.NET, and produces a fixed-order `float32` vector (2568-dim with the default feature groups). `extract()` runs in-process; `extract_with_timeout()` / `extract_file(..., timeout_seconds=...)` runs extraction in a spawned subprocess with a hard timeout (default 30s) — always use the timeout path for untrusted/external input (CLI, future API).
- `schema.py` — `FeatureSchema`/`FeatureGroup` are immutable and self-validating: they encode feature count, per-group index ranges, and exact name/order, and reject any vector whose feature names/order don't match. The schema version is a fingerprint hash of the thrember feature-group configuration, so any change to feature groups produces a new version automatically.
- `selection.py` — `FeatureSelector` narrows the full schema down to a named, ordered model-input subset (e.g. the model team's top-500) and round-trips through a JSON "selection manifest" (`FEATURE_SELECTION_SCHEMA_VERSION`). Manifests declare `source_schema_version`/`output_schema_version` and are rejected if they don't match the running extractor's schema — this is what keeps training-time and inference-time feature sets from silently diverging.
- `api_groups.py` — separately classifies the PE's Import Table into human-meaningful groups (`registry`, `injection`, `network`) for explanation/evidence, *not* as EMBER model features (EMBER's own import/export features are hashed and not name-recoverable).
- `result.py` — `FeatureExtractionResult` / `ExtractionStatus` (`SUCCESS`, `INVALID_PE`, `PARSE_ERROR`, `UNSUPPORTED`, `FILE_TOO_LARGE`, `TIMEOUT`, `TOOL_ERROR`). Failed files are never zero-filled or silently treated as success — downstream consumers (baseline model, future API) must branch on `status`.
- `cli.py` — argparse entry point; supports full JSON, `--summary`, `--compact`, `--features-file` (thrember feature-group config), and `--selection-file` (model-input subset).

Key invariant repeated throughout this module: **training data and a live extraction must use the identical feature schema (count, names, order, dtype, thrember commit)** — never assume "same dimension" means "same features."

### `src/preprocessing/` — EMBER2024 dataset pipeline (one-time / offline, not part of the shipped service)

Six numbered stage scripts (`01_download.py` … `06_manifest.py`, run via `run_all.ps1`/`run_all.sh`) turn raw EMBER2024 Win32/Win64 data into a reproducible, time-based train/calibration/eval split plus a sealed lockbox (test/challenge). Each stage writes a completion marker under `.state/` so reruns skip finished stages (`--force` to redo). `src/preprocessing/README.md` documents *why* each design choice was made — read it before touching this pipeline; the highlights:

- **Time-based split only**, via `week_id`: weeks 0–39 = train, 40–45 = calibration, 46–51 = eval. Never re-split randomly/by stratification — EMBER2024 is explicitly non-IID over time, and calibration/eval must stay equal-width (6 weeks each) so eval's performance drift is a valid proxy for lockbox drift.
- **Never call `thrember.read_vectorized_features()`** — it materializes the full matrix in RAM (~21GB+). Use `common.open_dat()` / `np.memmap` instead; `common.py`'s `Layout` class centralizes the on-disk directory structure (`dataset/`, `out/dev/`, `out/lockbox/`, `out/index/`, `out/reports/`).
- Metadata (`sha256`, `week_id`, `file_type`, `family`, `label`) is extracted separately in stage 03, in the same row order as the vectorized features, and stored as pandas pickle (not parquet — avoids native DLLs that Windows application-control policies can block). Row-count/label consistency is asserted immediately; a mismatch aborts the pipeline because it would silently invalidate every downstream split.
- **NaN/inf are preserved, never imputed**, because missingness itself is a predictive signal in EMBER features. LightGBM handles NaN natively; only sklearn/neural-net models should impute (train-set median + a missingness-indicator column, to avoid leakage).
- Lockbox (`out/lockbox/`) files are sealed read-only (mode `0o444`) with sha256 recorded in a manifest, and are **never row-filtered** — label `-1` and invalid rows stay in place; a separate `valid_mask_*.npy` is applied at evaluation time instead.
- Official metrics are **ROC-AUC and TPR at a fixed FPR (0.1% target)** — Accuracy/F1 are explicitly banned project-wide because the dataset's 50:50 class ratio doesn't reflect production malware prevalence (see `docs/docs_eval_lockbox_policy.md`).

### `src/models/` — baseline model scripts

Standalone scripts (not a package) that train/compare LightGBM baselines against the preprocessing pipeline's output and log to MLflow (`compare_baseline_models.py`, `check_gain_vs_split.py`, `classify_feature_blocks.py`, `export_baseline_pkl.py`, `export_mlflow_result.py`). These contain **hardcoded local paths** (e.g. `D:\KISIA_laptop\out\dev`, `C:\Users\jyoon\trust-triage\...`) from the original author's machine — treat them as one-off analysis scripts to adapt, not as a stable CLI/library. `docs/500개_특징_선택_근거.md` and `docs/feature_schema.md` explain how the top-500 feature subset (`top_feature_indices_500.npy`, wired into feature-extraction via `docs/feature-extraction/feature-selection-ember-v3-top500.json`) was chosen from the full 2568-dim EMBER vector and how each block maps to hashed vs. exactly-reproducible features.

### `docs/` — cross-team contracts (source of truth over code comments where they conflict)

- `docs/feature_schema.md` — canonical list of every feature name/block the extraction module must produce and the model/calibration/JRR teams consume. Do not introduce feature names not listed here without a full-team doc update first.
- `docs/docs_api_contract.md` — draft REST endpoints for the not-yet-built FastAPI service (`/analyze/file`, `/analyze/hash`, `/queue/*`, `/review/{file_id}/verdict`) and the Slack alert payload shape.
- `docs/docs_eval_lockbox_policy.md` — binding policy: metrics (ROC-AUC + TPR@FPR only), threshold-from-calibration-only rule, lockbox handling, kill-test criteria for the Joint Risk Router and the Speakeasy emulation extension.
- `docs/docs_sqlite_schema.md` — planned SQLite schema (`feature_cache`, `analysis_records`, `emulation_results`) for hash lookup and the review queue, not yet implemented.
- `docs/feature-extraction/` — feature-extraction module docs: `feature-extraction.md` (usage), `feature-selection.md` (selection-manifest contract), `ember-v3-schema.json` (schema manifest asserted against at runtime by `test_documented_ember_schema_matches_runtime_schema`), `plan.md` (module status/roadmap).

## Testing notes

- `tests/test_feature_extraction.py` is the only test module; it exercises real PE fixtures copied from the local Windows install (`sys.executable`, `notepad.exe`, `RegAsm.exe`) and skips gracefully when a fixture isn't available on the machine (e.g. non-Windows, missing `WINDIR`) — don't "fix" a skip by hardcoding a path.
- Some tests assert the checked-in schema/selection JSON docs (`docs/feature-extraction/ember-v3-schema.json`, `feature-selection-ember-v3-top500.json`) match the *runtime* schema produced by the installed `thrember` version — if you change feature groups or the pinned thrember commit, update these JSON files too or the tests will fail by design.
