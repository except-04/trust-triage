"""Validation만 사용해 LightGBM feature count를 비교하는 개발용 스크립트."""

from __future__ import annotations

import argparse
from pathlib import Path

import lightgbm as lgb
import mlflow
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

try:
    from .data_contract import validate_four_way_contract
except ImportError:  # pragma: no cover - 파일을 직접 실행할 때 사용
    from data_contract import validate_four_way_contract

TARGET_FPR = 0.001
TOP_N_LIST = (100, 500, 1000)
CHUNK = 20_000


def validation_metrics(y_true, scores, target_fpr=TARGET_FPR):
    """Feature-count 선택에 사용할 validation 지표를 계산한다."""
    auc = roc_auc_score(y_true, scores)
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    index = max(np.searchsorted(fpr, target_fpr, side="right") - 1, 0)
    return float(auc), float(tpr[index]), float(thresholds[index])


def select_columns_chunked(X, col_indices, chunk_size=CHUNK):
    col_indices = np.asarray(col_indices)
    out = np.empty((X.shape[0], len(col_indices)), dtype=np.float32)
    for start in range(0, X.shape[0], chunk_size):
        stop = min(start + chunk_size, X.shape[0])
        out[start:stop] = X[start:stop][:, col_indices]
    return out


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def require_new_output_dir(path):
    output_dir = Path(path).expanduser().resolve()
    if output_dir.exists():
        raise FileExistsError(f"출력 경로가 이미 존재합니다: {output_dir}")
    if not output_dir.parent.is_dir():
        raise FileNotFoundError(f"출력 상위 디렉터리가 없습니다: {output_dir.parent}")
    return output_dir


def fit_model(X_tr, y_tr, X_val, y_val):
    model = lgb.LGBMClassifier(
        objective="binary", metric=["auc"], n_estimators=500,
        learning_rate=0.05, num_leaves=31, min_child_samples=30,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
    )
    model.fit(
        X_tr, y_tr, eval_set=[(X_val, y_val)], eval_metric="auc",
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)],
    )
    return model


def main(argv=None):
    args = parse_args(argv)
    splits = validate_four_way_contract(args.data_dir)
    output_dir = require_new_output_dir(args.output_dir)
    X_tr, y_tr = splits["tr"].X, splits["tr"].y
    X_val, y_val = splits["val"].X, splits["val"].y

    mlflow.set_experiment("TRUST-Triage-Baseline-Feature-Count")
    results = []
    with mlflow.start_run(run_name="feature_count_validation_selection"):
        full_model = fit_model(X_tr, y_tr, X_val, y_val)
        importance = full_model.feature_importances_
        ranked_indices = np.argsort(importance)[::-1]
        scores = full_model.predict_proba(X_val, num_iteration=full_model.best_iteration_)[:, 1]
        auc, tpr, threshold = validation_metrics(y_val, scores)
        results.append({"feature_count": X_tr.shape[1], "validation_auc": auc,
                        "validation_tpr_at_fpr": tpr,
                        "validation_selection_threshold": threshold})

        selected_indices = {}
        for top_n in TOP_N_LIST:
            indices = np.sort(ranked_indices[:top_n])
            selected_indices[top_n] = indices
            X_tr_top = select_columns_chunked(X_tr, indices)
            X_val_top = select_columns_chunked(X_val, indices)
            model = fit_model(X_tr_top, y_tr, X_val_top, y_val)
            scores = model.predict_proba(X_val_top, num_iteration=model.best_iteration_)[:, 1]
            auc, tpr, threshold = validation_metrics(y_val, scores)
            results.append({"feature_count": top_n, "validation_auc": auc,
                            "validation_tpr_at_fpr": tpr,
                            "validation_selection_threshold": threshold})
            mlflow.log_metric(f"validation_auc_top_{top_n}", auc)
            mlflow.log_metric(f"validation_tpr_at_fpr_top_{top_n}", tpr)

        # 모든 계산이 성공한 뒤에만 새 디렉터리에 결과를 기록한다.
        output_dir.mkdir()
        np.save(output_dir / "feature_importance_full.npy", importance)
        for top_n, indices in selected_indices.items():
            np.save(output_dir / f"top_feature_indices_{top_n}.npy", indices)
        pd.DataFrame(results).to_csv(
            output_dir / "baseline_feature_count_validation.csv", index=False
        )


if __name__ == "__main__":
    main()
