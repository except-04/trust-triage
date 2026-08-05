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

    
def evaluate_by_arch(model, X_eval, y_eval, arch_eval, threshold, arch_code, arch_name):
    """
    Win32/Win64를 따로 떼어 같은 threshold로 TPR을 재확인한다.
    Win32:Win64 비율이 약 3:1이라, 전체 집계 지표만 보면 사실상 Win32 성능만 반영되어 
    Win 64 에서만 성능이 나쁜 경우를 놓칠 수 있다. 
    """
    
    mask = arch_eval == arch_code
    if mask.sum() == 0:
        return None
    
    scores = model.predict_proba(X_eval[mask])[:, 1]
    tpr = tpr_at_threshold(y_eval[mask], scores, threshold)
    
    return {"arch": arch_name, "n": int(mask.sum()), "tpr_at_fpr":tpr}
# ==============================================================
# 3. 모델 1 - 전체 특징(2568)
# ==============================================================
mlflow.set_experiment("trust-triage-baseline")

params = {
    "objective":"binary",
    "metric": ["auc"], 
    "num_leaves":31, 
    "learning_rate": 0.05,
    "min_child_samples":30,
    "subsample":0.8,
    "colsample_bytree":0.8,
    "random_state":42,
}

with mlflow.start_run(run_name="week_baseline_full_v1"):
    mlflow.set_tag("dataset_source", "EMBER2024_association_processed")
    mlflow.set_tag("feature_set", "full")
    mlflow.set_tag("split_type", "temporal_week_id")
    
    model_full = lgb.LGBMClassifier(**params, n_estimators=500)
    # NaN 그대로 전달
    model_full.fit(
        X_tr, y_tr,
        eval_set=[(X_calib, y_calib)],
        callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False)],
    )
    
    metrics_full = evaluate(model_full, X_calib, y_calib, X_eval, y_eval)
    mlflow.log_params(params)
    mlflow.log_metric("roc_auc", metrics_full["roc_auc"])
    mlflow.log_metric("tpr_at_fpr", metrics_full["tpr_at_fpr"])
    mlflow.log_metric("threshold", metrics_full["threshold"])
    mlflow.log_metric("target_fpr", TARGET_FPR)
    mlflow.lightgbm.log_model(model_full, "model")
    
    for code, name in [(0, "win32"), (1, "win64")]:
        result = evaluate_by_arch(
            model_full, X_eval, y_eval, arch_eval, metrics_full["threshold"], code, name
        )
        
        if result:
            mlflow.log_metric(f"tpr_at_fpr_{name}", result["tpr_at_fpr"])
            print(f"[{name}] n = {result['n']}, TPR@FPR={result['tpr_at_fpr']:.4f}")
    
    print(
        f"Full model ㅡ ROC-AUC: {metrics_full['roc_auc']:.4f}"
        f"TPR@FPR{TARGET_FPR:.1%}: {metrics_full['tpr_at_fpr']:.4f}"
    )
    
feature_importance = model_full.feature_importances_

# ==============================================================
# 4. 모델 2 - 상위 N개 특징을 여러 값으로 확인
#
# TOP_N 하나만 정해서 비교하면 왜 하필 이 개수인지 근거가 약함.
# 개수별로 여러 개 돌려서 몇 개부터 성능이 꺾이는지 시각적으로 확인하고,
# 그 지점을 기준으로 최종 개수를 정한다. 
# ==============================================================
TOP_N_LIST = [100]

importance_df = pd.DataFrame(
    {"index": range(len(feature_importance)), "importance":feature_importance}
).sort_values("importance", ascending=False)

def train_and_evaluate_reduced(top_n):
    """ 상위 top_n개 특징만으로 모델을 학습, 평가하고 결과를 반환한다."""

    top_indices = importance_df.head(top_n)["index"].values
    np.save(f"top_feature_indices_{top_n}.npy", top_indices)
    
    X_tr_r = X_tr[:, top_indices]
    X_calib_r = X_calib[:, top_indices]
    X_eval_r = X_eval[:, top_indices]
    
    with mlflow.start_run(run_name=f"week_baseline_recuced_top{top_n}_v1"):
        mlflow.set_tag("dataset_source", "EMBER2024_association_processed")
        mlflow.set_tag("feature_set", "reduced")
        mlflow.set_tag("top_n", str(top_n))
        mlflow.set_tag("split_type", "temporal_week_id")
        
        model_r = lgb.LGBMClassifier(**params, n_estimators=500)
        model_r.fit(
            X_tr_r, y_tr,
            eval_set=[(X_calib_r, y_calib)],
            callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False)],
        )
        
        metrics_r = evaluate(model_r, X_calib_r, y_calib, X_eval_r, y_eval)
        mlflow.log_params(params)
        mlflow.log_metric("roc_auc", metrics_r["roc_auc"])
        mlflow.log_metric("tpr_at_fpr", metrics_r["tpr_at_fpr"])
        mlflow.log_metric("threshold", metrics_r["threshold"])
        mlflow.lightgbm.log_model(model_r, "model")
        
        print(
            f"Reduced({top_n}) model ㅡ ROC_AUC: {metrics_r['roc_auc']:.4f}, "
            f"TPR@FPR{TARGET_FPR:.1f}: {metrics_r['tpr_at_fpr']:.4f}"
        )
        
    return {"top_n": top_n, **metrics_r}

results = [{"top_n":X_tr.shape[1], **metrics_full}]     # 전체 특징(2568)도 같은 표에 포함
for n in TOP_N_LIST:
    results.append(train_and_evaluate_reduced(n))

# ==============================================================
# 5. 요약 ㅡ 전체 vs 여러 TOP_N을 한 표로 비교
# ==============================================================

results_df = pd.DataFrame(results)[["top_n", "roc_auc", "tpr_at_fpr", "threshold"]]
results_df = results_df.rename(columns={"top_n":"feature_count"})
results_df.to_csv("baseline_comparision_results.csv", index=False)

print(f"\n === 비교 결과 (목표 FPR : {TARGET_FPR:.1f}) ===")
print(results_df.to_string(index=False))
