import numpy as np
import pandas as pd
import lightgbm as lgb
import mlflow
from sklearn.metrics import roc_auc_score, roc_curve

DATA_DIR = "D:\KISIA_laptop\out\dev"
TARGET_FPR = 0.001 # 0.1%

# ==============================================================
# 1. 데이터 로드
# ==============================================================
X_tr = np.load(f"{DATA_DIR}/X_tr.npy", mmap_mode="r")
y_tr = np.load(f"{DATA_DIR}/y_tr.npy")
arch_tr = np.load(f"{DATA_DIR}/arch_tr.npy")

X_calib = np.load(f"{DATA_DIR}/X_calib.npy", mmap_mode="r")
y_calib = np.load(f"{DATA_DIR}/y_calib.npy")

X_eval = np.load(f"{DATA_DIR}/X_eval.npy", mmap_mode="r")
y_eval = np.load(f"{DATA_DIR}/y_eval.npy")
arch_eval = np.load(f"{DATA_DIR}/arch_eval.npy")

print(f"학습: {X_tr.shape} / 보정: {X_calib.shape} / 평가(시간 이동): {X_eval.shape}")
print(f"특징 차원 D = {X_tr.shape[1]}")


# ==============================================================
# 2. 지표 계산 - 가이드 규칙(ROC-AUC + 고정 FPR에서 TPR)
# ==============================================================
# ==============================================================
# 3. 모델 1 - 전체 특징(2568)
# ==============================================================
# ==============================================================
# 4. 모델 2 - 상위 N개 특징(100)
# ==============================================================
# ==============================================================
# 5. 요약
# ==============================================================