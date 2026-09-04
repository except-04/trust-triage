"""4분할 모델 데이터 계약과 split 사용을 검증한다."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_ROOT / "src" / "models"
sys.path.insert(0, str(MODELS_DIR))

from data_contract import DataContractError, validate_four_way_contract  # noqa: E402

EXPECTED_TEST_ROWS = {"tr": 4, "val": 3, "calib": 3, "eval": 3}


def write_contract(root: Path, *, feature_dim=3):
    for split, rows in EXPECTED_TEST_ROWS.items():
        np.save(root / f"X_{split}.npy", np.zeros((rows, feature_dim), dtype=np.float32))
        np.save(root / f"y_{split}.npy", np.arange(rows, dtype=np.int8) % 2)


def validate_test_contract(root: Path):
    return validate_four_way_contract(
        root, expected_rows=EXPECTED_TEST_ROWS, expected_feature_dim=3
    )


def test_four_way_contract_accepts_exact_files(tmp_path):
    write_contract(tmp_path)
    splits = validate_test_contract(tmp_path)
    assert tuple(splits) == ("tr", "val", "calib", "eval")


def test_four_way_contract_rejects_xy_row_mismatch(tmp_path):
    write_contract(tmp_path)
    np.save(tmp_path / "y_tr.npy", np.zeros(3, dtype=np.int8))
    with pytest.raises(DataContractError):
        validate_test_contract(tmp_path)


def test_missing_validation_does_not_fallback(tmp_path):
    write_contract(tmp_path)
    (tmp_path / "X_val.npy").unlink()
    with pytest.raises(FileNotFoundError, match="X_val.npy"):
        validate_test_contract(tmp_path)


def names_used_in_function(path: Path, function_name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    return {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}


def test_lightgbm_objective_and_early_stopping_use_validation_only():
    path = MODELS_DIR / "tune_lightgbm.py"
    source = path.read_text(encoding="utf-8")
    names = names_used_in_function(path, "objective")
    assert {"X_tr_500", "y_tr", "X_val_500", "y_val"} <= names
    assert not any("calib" in name or "eval" in name for name in names)
    assert "eval_set=[(X_val_500, y_val)]" in source


def test_feature_count_selection_uses_validation_only():
    path = MODELS_DIR / "compare_baseline_models.py"
    source = path.read_text(encoding="utf-8")
    names = names_used_in_function(path, "main")
    assert {"X_tr", "y_tr", "X_val", "y_val"} <= names
    assert not any("calib" in name or "eval" in name for name in names)
    assert "validation_selection_threshold" in source


def test_xgboost_uses_validation_and_hist():
    source = (MODELS_DIR / "train_xgboost_500.py").read_text(encoding="utf-8")
    assert 'tree_method="hist"' in source
    assert 'eval_metric="auc"' in source
    assert "eval_set=[(X_val_500, y_val)]" in source
    assert "X_calib" not in source and "X_eval" not in source
