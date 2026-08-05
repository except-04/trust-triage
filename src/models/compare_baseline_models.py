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
# 배경: 모델은 0~1 사이의 "악성일 확률" 점수를 뱉는다.
# 이 점수를 "악성/정상" 둘 중 하나로 확정하려면 기준선(threshold)이 필요하다.
# - 점수 >= threshold -> 악성 판정
# - 점수 <  threshold -> 정상 판정
# threshold를 어디에 긋느냐에 따라 아래 두 값이 "동시에" 변한다(trade-off)
# FPR(False Positive Rate): 정상인데 악성으로 오판한 비율
# TPR(True Positive Rate): 실제 악성을 악성이라고 맞힌 비율(=Recall)
#
# 이 데이터는 정상:악성 = 1:1이라 실제 운영 환경 비율과 다르므로 Accuracy/F1은 쓰지 않는다. 
# 대신 "FPR을 이만큼만 허용하겠다"고 먼저 고정하고, 그 조건에서 TPR이 얼마나 나오는지를 본다.
# 두 모델을 공정하게 비교하려면 같은 FPR 조건에서 TPR을 비교해야 하기 때문이다. 
# ============================================================
def find_threshold_at_fpr(y_true, scores, target_fpr):
    """
    FPR이 target_fpr(현재: 0.001 = 0.1%)이 되는 threshold를 찾는다.
    
    roc_curve가 threshold를 촘촘히 바꿔가며 각 지점의 FPR, TPR을 계산해주면,
    그 중 FPR이 목표치에 가장 가까운(그 이하인 것 중 가장 큰) 지점을 고른다. 
    """
    fpr, tpr, threshold = roc_curve(y_true, scores)
    
    # fpr 배열은 오름차순 정렬 -> target_fpr이 들어갈 위치를 찾고 -1
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    idx = max(idx, 0) # 혹시 -1이 나오면 (target보다 다 크면) 가장 엄격한 threshold로
    
    return threshold[idx]

def tpr_at_threshold(y_true, scores, threshold):
    """주어진 threshold를 적용했을 때 TPR을 계산한다."""
    
    pred = (scores >= threshold).astype(int)
    tp = ((pred == 1) & (y_true == 1)).sum()    # True Positive: 실제 악성을 악성이라고 맞힘
    fn = ((pred == 0) & (y_true == 1)).sum()    # False Negative: 실제 악성을 정상이라고 미판
    
    return tp / (tp + fn) if (tp + fn) > 0 else float("nan")


def evaluate(model, X_calib, y_calib, X_eval, y_eval, target_fpr = TARGET_FPR):
    """
    모델 하나를 평가한다. threshold 산출과 성능 확인에 서로 다른 데이터를 쓰는 게 핵심이다.
    같은 데이터로 하면 "내가 정한 기준으로 나를 채점"하는 셈이라 성능이 실제보다 좋게 나올 수 있다.(누수)   
    """
    
    # 1) threshold는 반드시 calibration 세트에서만 산출
    calib_scores = model.predict_proba(X_calib)[:, 1]
    threshold = find_threshold_at_fpr(y_calib, calib_scores, target_fpr)
    # 2) 위에서 정한 threshold를 다른 데이터(eval)에 적용해 성능 확인
    eval_scores = model.predict_proba(X_eval)[:, 1]
    roc_auc = roc_auc_score(y_eval, eval_scores)    # threshold 무관, 종합 구분 능력
    tpr = tpr_at_threshold(y_eval, eval_scores, threshold)
    
    return {"roc_auc":roc_auc, "tpr_at_fpr":tpr, "threshold":threshold}

    
#def evaluate_bt_arch(model, X_eval, y_eval, arch_eval, threshold, arch_code, arch_name)
# ==============================================================
# 3. 모델 1 - 전체 특징(2568)
# ==============================================================
# ==============================================================
# 4. 모델 2 - 상위 N개 특징(100)
# ==============================================================
# ==============================================================
# 5. 요약
# ==============================================================