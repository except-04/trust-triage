import os
import numpy as np

# 1. 데이터 경로 설정
DATA_DEV_DIR = os.path.join("data", "out", "dev")

print(f"데이터 폴더: {DATA_DEV_DIR}")

# 2. 파일 로드
# 뽑아둔 예측 확률 및 실제 라벨
xgb_prob_path = os.path.join(DATA_DEV_DIR, "y_pred_proba.npy")
y_eval_path = os.path.join(DATA_DEV_DIR, "y_eval.npy")

# 기존 LightGBM 보정 확률 파일 탐색 (data 폴더 또는 dev 폴더)
lgb_candidates = [
    os.path.join("data", "y_pred_proba_calib.npy"),
    os.path.join(DATA_DEV_DIR, "y_pred_proba_calib.npy"),
    os.path.join("data", "y_pred_proba_lgb.npy")
]

lgb_prob_path = None
for path in lgb_candidates:
    if os.path.exists(path):
        lgb_prob_path = path
        break

p_xgb = np.load(xgb_prob_path)
y_true = np.load(y_eval_path)

# 2D 형태(N, 2)인 경우 악성(클래스 1) 확률만 추출
if p_xgb.ndim == 2:
    p_xgb = p_xgb[:, 1]

print(f"XGBoost 예측 샘플 수: {len(p_xgb):,}개")
print(f"실제 라벨 샘플 수: {len(y_true):,}개 (악성 비율: {y_true.mean()*100:.2f}%)")

# LightGBM 파일이 있는 경우 불일치도 계산
if lgb_prob_path:
    print(f"LightGBM 로드: {lgb_prob_path}")
    p_lgb = np.load(lgb_prob_path)
    if p_lgb.ndim == 2:
        p_lgb = p_lgb[:, 1]
    
    # 불일치도 계산 (|P_lgb - P_xgb|)
    disagreement = np.abs(p_lgb - p_xgb)
    
    print("\n" + "="*45)
    print("Model Disagreement 통계 요약")
    print("="*45)
    print(f"평균 Disagreement: {disagreement.mean():.4f}")
    print(f"최대 Disagreement: {disagreement.max():.4f}")
    print(f"불일치 > 0.2 (주의 샘플) 비율: {(disagreement > 0.2).mean() * 100:.2f}% ({(disagreement > 0.2).sum():,}개)")
    print(f"불일치 > 0.5 (위험 갈등 샘플) 비율: {(disagreement > 0.5).mean() * 100:.2f}% ({(disagreement > 0.5).sum():,}개)")
    print("="*45)
    
    # 불일치도 저장
    out_disagree = os.path.join(DATA_DEV_DIR, "model_disagreement.npy")
    np.save(out_disagree, disagreement)
    print(f"Disagreement 파일 저장 완료: {out_disagree}")
else:
    print("LightGBM 보정 확률 파일이 아직 dev 폴더에 없습니다. (XGBoost 단독 확률 정상 로드 확인됨)")