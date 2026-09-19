"""
LightGBM vs XGBoost 500개 모델 성능 비교 (disagreement 계산 전 검증용)

두 모델 성능이 비슷해야 disagreement 신호가
"진짜 애매한 케이스"를 가리키는 것으로 신뢰할 수 있다.
한쪽이 확연히 못하면 disagreement가 왜곡될 수 있다.
"""

import joblib
import numpy as np
import mlflow
from sklearn.metrics import roc_auc_score, roc_curve

TARGET_FPR = 0.001

# --- 데이터 로드 ---
DATA_DIR = "data"

X_calib = np.load(f"{DATA_DIR}/X_calib.npy", mmap_mode="r")
y_calib = np.load(f"{DATA_DIR}/y_calib.npy")
X_eval = np.load(f"{DATA_DIR}/X_eval.npy", mmap_mode="r")
y_eval = np.load(f"{DATA_DIR}/y_eval.npy")

top_indices = np.load(f"{DATA_DIR}/top_feature_indices_500.npy")
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


# --- 모델 로드 ---
print("로컬 모델 파일을 직접 불러옵니다...")
model_lgb = joblib.load(f"{DATA_DIR}/baseline_model_lightgbm_tuned_500_4way.pkl")
model_xgb = joblib.load(f"{DATA_DIR}/baseline_model_xgb_500_4way_1000cap.pkl")


# --- 비교 ---
metrics_lgb = evaluate(model_lgb, X_calib_500, y_calib, X_eval_500, y_eval)
metrics_xgb = evaluate(model_xgb, X_calib_500, y_calib, X_eval_500, y_eval)

print(f"""
=== LightGBM vs XGBoost 비교 (목표 FPR: {TARGET_FPR:.1%}) ===
LightGBM:  ROC-AUC {metrics_lgb['roc_auc']:.4f} / TPR@FPR {metrics_lgb['tpr_at_fpr']:.4f}
XGBoost:   ROC-AUC {metrics_xgb['roc_auc']:.4f} / TPR@FPR {metrics_xgb['tpr_at_fpr']:.4f}
""")
