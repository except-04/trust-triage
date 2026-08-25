"""train fitting과 validation early stopping만 사용하는 XGBoost 학습 스크립트."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import mlflow
import xgboost as xgb

try:
    from .data_contract import load_top_indices, require_new_output, validate_four_way_contract
except ImportError:  # pragma: no cover - 파일을 직접 실행할 때 사용
    from data_contract import load_top_indices, require_new_output, validate_four_way_contract


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument(
        "--top-indices",
        type=Path,
        default=PROJECT_ROOT / "top_feature_indices_500.npy",
    )
    parser.add_argument("--model-output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    splits = validate_four_way_contract(args.data_dir)
    model_output = require_new_output(args.model_output)
    top_indices = load_top_indices(args.top_indices)

    X_tr_500 = splits["tr"].X[:, top_indices]
    y_tr = splits["tr"].y
    X_val_500 = splits["val"].X[:, top_indices]
    y_val = splits["val"].y

    mlflow.set_experiment("TRUST-Triage-XGBoost-500")
    with mlflow.start_run():
        mlflow.set_tags(
            {
                "fit_split": "train",
                "early_stopping_split": "validation",
                "feature_count": "500",
            }
        )
        model = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=6,
            learning_rate=0.05,
            random_state=42,
            tree_method="hist",
            early_stopping_rounds=50,
        )
        model.fit(
            X_tr_500,
            y_tr,
            eval_set=[(X_val_500, y_val)],
            verbose=True,
        )

        mlflow.log_params(model.get_params())
        if model.best_score is not None:
            mlflow.log_metric("validation_best_auc", float(model.best_score))
        if model.best_iteration is not None:
            mlflow.log_metric("best_iteration", int(model.best_iteration))
        joblib.dump(model, model_output)


if __name__ == "__main__":
    main()
