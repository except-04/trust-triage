"""
LightGBM vs XGBoost 500개 모델 성능 비교 (disagreement 계산 전 검증용)

두 모델 성능이 비슷해야 disagreement 신호가 
"진짜 애매한 케이스"를 가리키는 것으로 신뢰할 수 있다. 
한쪽이 확연히 못하면 disagreement가 왜곡될 수 있다.
"""

import numpy as np
import mlflow
from sklearn.metrics import roc_auc_score, roc_curve

TARGET_FPR = 0.001

# --- 데이터 로드 ---
DATA_DIR = "D:\KISIA_laptop\out\dev"  

X_calib = np.load(f"{DATA_DIR}/X_calib.npy", mmap_mode="r")
y_calib = np.load(f"{DATA_DIR}/y_calib.npy")
X_eval = np.load(f"{DATA_DIR}/X_eval.npy", mmap_mode="r")
y_eval = np.load(f"{DATA_DIR}/y_eval.npy")

top_indices = np.load("top_feature_indices_500.npy")
top_indices = np.sort(top_indices)
X_calib_500 = X_calib[:, top_indices]
X_eval_500 = X_eval[:, top_indices]


# --- 지표 계산 함수 ---
def find_threshold_at_fpr(y_true, scores, target_fpr):
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    idx = max(idx, 0)
    return thresholds[idx]


def tpr_at_threshold(y_true, scores, threshold):
    pred = (scores >= threshold).astype(int)
    tp = ((pred == 1) & (y_true == 1)).sum()
    fn = ((pred == 0) & (y_true == 1)).sum()
    return tp / (tp + fn) if (tp + fn) > 0 else float("nan")


def evaluate(model, X_calib, y_calib, X_eval, y_eval, target_fpr=TARGET_FPR):
    calib_scores = model.predict_proba(X_calib)[:, 1]
    threshold = find_threshold_at_fpr(y_calib, calib_scores, target_fpr)
    eval_scores = model.predict_proba(X_eval)[:, 1]
    roc_auc = roc_auc_score(y_eval, eval_scores)
    tpr = tpr_at_threshold(y_eval, eval_scores, threshold)
    return {"roc_auc": roc_auc, "tpr_at_fpr": tpr, "threshold": threshold}


# --- MLflow에서 두 모델 불러오기 ---
mlflow.set_experiment("trust-triage-baseline")
runs = mlflow.search_runs(order_by=["start_time"])
print(runs[["run_id", "tags.feature_set", "tags.top_n", "tags.model_type", "start_time"]])

lgb_run_id = "69a92b2033d346ac930fe2ec889199a2"
xgb_run_id = "4ae56feb534e46f59c78a901c7c89783"

model_lgb = mlflow.lightgbm.load_model(f"runs:/{lgb_run_id}/model")
model_xgb = mlflow.xgboost.load_model(f"runs:/{xgb_run_id}/model")


# --- 비교 ---
metrics_lgb = evaluate(model_lgb, X_calib_500, y_calib, X_eval_500, y_eval)
metrics_xgb = evaluate(model_xgb, X_calib_500, y_calib, X_eval_500, y_eval)

print(f"""
=== LightGBM vs XGBoost 비교 (목표 FPR: {TARGET_FPR:.1%}) ===
LightGBM:  ROC-AUC {metrics_lgb['roc_auc']:.4f} / TPR@FPR {metrics_lgb['tpr_at_fpr']:.4f}
XGBoost:   ROC-AUC {metrics_xgb['roc_auc']:.4f} / TPR@FPR {metrics_xgb['tpr_at_fpr']:.4f}
""")