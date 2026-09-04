"""Validation 전용 Optuna 선택을 사용하는 Top-500 LightGBM 학습."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import lightgbm as lgb
import mlflow
import numpy as np
import optuna
from sklearn.metrics import roc_curve

try:
    from .data_contract import (
        load_top_indices,
        require_new_output,
        validate_four_way_contract,
    )
except ImportError:  # pragma: no cover - 파일을 직접 실행할 때 사용
    from data_contract import (
        load_top_indices,
        require_new_output,
        validate_four_way_contract,
    )

TARGET_FPR = 0.001
N_TRIALS = 20
TUNING_N_ESTIMATORS = 1000
CHUNK = 20_000


def select_columns_chunked(X, col_indices, chunk_size=CHUNK):
    """memmap을 행 청크로 읽은 뒤 선택한 열만 float32 RAM 배열로 만든다."""
    col_indices = np.asarray(col_indices)
    n = X.shape[0]
    out = np.empty((n, len(col_indices)), dtype=np.float32)
    for start in range(0, n, chunk_size):
        stop = min(start + chunk_size, n)
        out[start:stop] = X[start:stop][:, col_indices]
    return out


def validation_tpr_at_fpr(y_true, scores, target_fpr=TARGET_FPR):
    """Validation 내부의 모델 선택 점수와 임시 threshold를 계산한다."""
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    index = np.searchsorted(fpr, target_fpr, side="right") - 1
    index = max(index, 0)
    return float(tpr[index]), float(thresholds[index])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument(
        "--top-indices", type=Path, default=Path("top_feature_indices_500.npy")
    )
    parser.add_argument("--model-output", type=Path, required=True)
    parser.add_argument("--n-trials", type=int, default=N_TRIALS)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    splits = validate_four_way_contract(args.data_dir)
    model_output = require_new_output(args.model_output)
    top_indices = load_top_indices(args.top_indices)

    X_tr_500 = select_columns_chunked(splits["tr"].X, top_indices)
    X_val_500 = select_columns_chunked(splits["val"].X, top_indices)
    y_tr = splits["tr"].y
    y_val = splits["val"].y
    mlflow.set_experiment("trust-triage-baseline")

    def objective(trial):
        params = {
            "objective": "binary",
            "metric": ["auc"],
            "num_leaves": trial.suggest_int("num_leaves", 100, 350),
            "learning_rate": trial.suggest_float("learning_rate", 0.03, 0.15, log=True),
            "min_child_samples": trial.suggest_int("min_child_samples", 50, 3000, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "subsample_freq": 1,
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "random_state": 42,
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-4, 10.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-4, 10.0, log=True),
            "force_col_wise": True,
        }
        with mlflow.start_run(run_name=f"lightgbm_tuning_trial{trial.number}"):
            mlflow.set_tag("model_type", "lightgbm_tuned")
            mlflow.set_tag("feature_set", "reduced")
            mlflow.set_tag("top_n", "500")
            mlflow.set_tag("split_type", "temporal_week_id_4way")
            mlflow.set_tag("selection_split", "validation")
            model = lgb.LGBMClassifier(**params, n_estimators=TUNING_N_ESTIMATORS)
            model.fit(
                X_tr_500,
                y_tr,
                eval_set=[(X_val_500, y_val)],
                callbacks=[lgb.early_stopping(stopping_rounds=100, verbose=False)],
            )
            scores = model.predict_proba(X_val_500)[:, 1]
            selection_tpr, selection_threshold = validation_tpr_at_fpr(y_val, scores)
            trial.set_user_attr("best_iteration", int(model.best_iteration_))
            mlflow.log_params(params)
            mlflow.log_param("n_estimators", TUNING_N_ESTIMATORS)
            mlflow.log_metric("validation_tpr_at_fpr", selection_tpr)
            mlflow.log_metric("validation_selection_threshold", selection_threshold)
            mlflow.log_metric("best_iteration", model.best_iteration_)
        return selection_tpr

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=42),
        study_name="lightgbm_top500_validation_tuning",
    )
    study.optimize(objective, n_trials=args.n_trials)

    best_n_estimators = int(study.best_trial.user_attrs["best_iteration"])
    final_params = {
        "objective": "binary",
        "metric": ["auc"],
        "random_state": 42,
        "subsample_freq": 1,
        "force_col_wise": True,
        **study.best_params,
    }
    with mlflow.start_run(run_name="lightgbm_tuned_500_train_only"):
        mlflow.set_tag("model_type", "lightgbm_tuned")
        mlflow.set_tag("feature_set", "reduced")
        mlflow.set_tag("top_n", "500")
        mlflow.set_tag("split_type", "temporal_week_id_4way")
        mlflow.set_tag("fit_split", "train")
        final_model = lgb.LGBMClassifier(**final_params, n_estimators=best_n_estimators)
        final_model.fit(X_tr_500, y_tr)
        mlflow.log_params(final_params)
        mlflow.log_param("n_estimators", best_n_estimators)
        mlflow.log_metric("best_validation_tpr_at_fpr", study.best_value)
        mlflow.lightgbm.log_model(final_model, "model")

    joblib.dump(final_model, model_output)
    print(f"새 LightGBM artifact 저장 완료: {model_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
