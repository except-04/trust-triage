"""
    Optuna 기반 LightGBM 하이퍼파라미터 튜닝 (top500 feature).

    목적 지표는 compare_baseline_models.py의 evaluate()와 동일한 방식으로 계산한다:
    threshold는 calibration에서만 산출하고, tpr_at_fpr은 eval(시간 이동) 세트에
    threshold를 적용만 해서 얻는다 (재산출 금지).

    n_trials=10, 튜닝 단계 n_estimators=200으로 빠르게 탐색한 뒤,
    best_params로 n_estimators=500 최종 모델을 다시 학습한다.
"""

import numpy as np
import lightgbm as lgb
import mlflow
import optuna
import joblib
from sklearn.metrics import roc_curve

DATA_DIR = r"D:\KISIA_laptop\out\dev"
TARGET_FPR = 0.001  # 0.1%
N_TRIALS = 5
TUNING_N_ESTIMATORS = 200
FINAL_N_ESTIMATORS = 500
CHUNK = 20_000  # common.py의 DEFAULT_CHUNK와 동일


# ==============================================================
# 1. 데이터 로드
# ==============================================================
# X_tr[:, top_indices] 처럼 memmap에 바로 fancy indexing을 하면 numpy가
# 원소 단위로 흩어진 디스크 읽기를 시도해 사실상 멈춘 것처럼 느려진다
# (train_xgboost_500.py에서 실제로 걸려서 KeyboardInterrupt로 끊었던 원인).
# 대신 행을 청크 단위로 "통째로" 읽어(memmap이 잘하는 순차 읽기) RAM에 올린
# 뒤, RAM 위에서 열을 골라낸다. common.py의 iter_chunks()와 같은 전략이다.
def select_columns_chunked(X, col_indices, chunk_size=CHUNK):
    col_indices = np.asarray(col_indices)
    n = X.shape[0]
    out = np.empty((n, len(col_indices)), dtype=np.float32)
    for start in range(0, n, chunk_size):
        stop = min(start + chunk_size, n)
        out[start:stop] = X[start:stop][:, col_indices]
    return out


X_tr_full = np.load(f"{DATA_DIR}/X_tr.npy", mmap_mode="r")
y_tr = np.load(f"{DATA_DIR}/y_tr.npy")

X_calib_full = np.load(f"{DATA_DIR}/X_calib.npy", mmap_mode="r")
y_calib = np.load(f"{DATA_DIR}/y_calib.npy")

X_eval_full = np.load(f"{DATA_DIR}/X_eval.npy", mmap_mode="r")
y_eval = np.load(f"{DATA_DIR}/y_eval.npy")

top_indices = np.sort(np.load("top_feature_indices_500.npy"))

print("top500 컬럼 선택 중 (청크 단위)...")
X_tr_500 = select_columns_chunked(X_tr_full, top_indices)
X_calib_500 = select_columns_chunked(X_calib_full, top_indices)
X_eval_500 = select_columns_chunked(X_eval_full, top_indices)

print(f"학습: {X_tr_500.shape} / 보정: {X_calib_500.shape} / 평가: {X_eval_500.shape}")


# ==============================================================
# 2. 지표 계산 - compare_baseline_models.py의 evaluate()와 동일한 방식
# ==============================================================
def find_threshold_at_fpr(y_true, scores, target_fpr):
    """FPR이 target_fpr이 되는 threshold를 찾는다 (calibration에서만 호출)."""
    fpr, _, threshold = roc_curve(y_true, scores)
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    idx = max(idx, 0)
    return threshold[idx]


def tpr_at_threshold(y_true, scores, threshold):
    """주어진 threshold에서 TPR을 계산한다."""
    pred = (scores >= threshold).astype(int)
    tp = ((pred == 1) & (y_true == 1)).sum()
    fn = ((pred == 0) & (y_true == 1)).sum()
    return tp / (tp + fn) if (tp + fn) > 0 else float("nan")


def evaluate(model, X_calib, y_calib, X_eval, y_eval, target_fpr=TARGET_FPR):
    """threshold는 calibration에서 산출하고 eval에는 적용만 한다."""
    calib_scores = model.predict_proba(X_calib)[:, 1]
    threshold = find_threshold_at_fpr(y_calib, calib_scores, target_fpr)

    eval_scores = model.predict_proba(X_eval)[:, 1]
    tpr = tpr_at_threshold(y_eval, eval_scores, threshold)

    return {"tpr_at_fpr": tpr, "threshold": threshold}


# ==============================================================
# 3. Optuna 목적 함수
# ==============================================================
mlflow.set_experiment("trust-triage-baseline")


def objective(trial):
    params = {
        "objective": "binary",
        "metric": ["auc"],
        #"num_leaves": trial.suggest_int("num_leaves", 15, 255),    # trial 1
        #"num_leaves": trial.suggest_int("num_leaves", 130, 220),    # trial 2
        "num_leaves": trial.suggest_int("num_leaves", 160, 220),    # trial 3
        #"learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),    # trial 1, 2
        "learning_rate": trial.suggest_float("learning_rate", 0.12, 0.25, log=True),     # trial 3
        "min_child_samples": trial.suggest_int("min_child_samples", 5, 100),
        "subsample": trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
        "random_state": 42,
    }

    with mlflow.start_run(run_name=f"lightgbm_tuning_trial{trial.number}"):
        mlflow.set_tag("model_type", "lightgbm_tuned")
        mlflow.set_tag("feature_set", "reduced")
        mlflow.set_tag("top_n", "500")
        mlflow.set_tag("split_type", "temporal_week_id")
        mlflow.set_tag("optuna_trial", str(trial.number))

        model = lgb.LGBMClassifier(**params, n_estimators=TUNING_N_ESTIMATORS)
        model.fit(
            X_tr_500, y_tr,
            eval_set=[(X_calib_500, y_calib)],
            callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False)],
        )

        metrics = evaluate(model, X_calib_500, y_calib, X_eval_500, y_eval)

        mlflow.log_params(params)
        mlflow.log_param("n_estimators", TUNING_N_ESTIMATORS)
        mlflow.log_metric("tpr_at_fpr", metrics["tpr_at_fpr"])
        mlflow.log_metric("threshold", metrics["threshold"])
        mlflow.log_metric("target_fpr", TARGET_FPR)

        print(
            f"[trial {trial.number}] tpr_at_fpr={metrics['tpr_at_fpr']:.4f} "
            f"params={params}"
        )

    return metrics["tpr_at_fpr"]


# ==============================================================
# 4. 튜닝 실행
# ==============================================================
study = optuna.create_study(direction="maximize", study_name="lightgbm_top500_tuning")
study.optimize(objective, n_trials=N_TRIALS)

print("\n=== 튜닝 완료 ===")
print(f"Best tpr_at_fpr: {study.best_value:.4f}")
print(f"Best params: {study.best_params}")


# ==============================================================
# 5. best_params로 최종 모델 학습 (n_estimators=500)
# ==============================================================
final_params = {
    "objective": "binary",
    "metric": ["auc"],
    "random_state": 42,
    **study.best_params,
}

with mlflow.start_run(run_name="lightgbm_tuned_500_final"):
    mlflow.set_tag("model_type", "lightgbm_tuned")
    mlflow.set_tag("feature_set", "reduced")
    mlflow.set_tag("top_n", "500")
    mlflow.set_tag("split_type", "temporal_week_id")
    mlflow.set_tag("optuna_final", "true")

    final_model = lgb.LGBMClassifier(**final_params, n_estimators=FINAL_N_ESTIMATORS)
    final_model.fit(
        X_tr_500, y_tr,
        eval_set=[(X_calib_500, y_calib)],
        callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=100)],
    )

    final_metrics = evaluate(final_model, X_calib_500, y_calib, X_eval_500, y_eval)

    mlflow.log_params(final_params)
    mlflow.log_param("n_estimators", FINAL_N_ESTIMATORS)
    mlflow.log_metric("tpr_at_fpr", final_metrics["tpr_at_fpr"])
    mlflow.log_metric("threshold", final_metrics["threshold"])
    mlflow.log_metric("target_fpr", TARGET_FPR)
    mlflow.lightgbm.log_model(final_model, "model")

    print(
        f"\n최종 모델 ㅡ TPR@FPR{TARGET_FPR:.1%}: {final_metrics['tpr_at_fpr']:.4f} "
        f"(threshold={final_metrics['threshold']:.4f})"
    )

joblib.dump(final_model, "baseline_model_lightgbm_tuned_500.pkl")
print("baseline_model_lightgbm_tuned_500.pkl 저장 완료")
