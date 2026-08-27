import os
import numpy as np
import joblib 

# 1. 데이터 경로 설정
DATA_DIR = os.path.join("data")

print(f"데이터 폴더: {DATA_DIR}")

# 2. 파일 로드
# 뽑아둔 원시 예측 확률
xgb_prob_path = os.path.join(DATA_DIR, "y_pred_proba.npy")
lgb_prob_path = os.path.join(DATA_DIR, "y_pred_proba_lgb.npy")

print(f"XGBoost 원시 확률 로드: {xgb_prob_path}")
p_xgb = np.load(xgb_prob_path)

# 2D 형태(N, 2)인 경우 악성(클래스 1) 확률만 추출
if p_xgb.ndim == 2:
    p_xgb = p_xgb[:, 1]

print(f"XGBoost 예측 샘플 수: {len(p_xgb):,}개")

# 실제 라벨 로드 (참고용)
y_eval_path = os.path.join(DATA_DIR, "y_eval.npy")
if os.path.exists(y_eval_path):
    y_true = np.load(y_eval_path)
    print(f"실제 라벨 샘플 수: {len(y_true):,}개 (악성 비율: {y_true.mean()*100:.2f}%)")

# LightGBM 파일이 있는 경우 불일치도 계산
if os.path.exists(lgb_prob_path):
    print(f"\nLightGBM 원시 확률 로드: {lgb_prob_path}")
    p_lgb = np.load(lgb_prob_path)
    if p_lgb.ndim == 2:
        p_lgb = p_lgb[:, 1]
    
    # 불일치도 계산 (|p_lgb_raw - p_xgb_raw|)
    disagreement = np.abs(p_lgb - p_xgb)
    
    print("\n" + "="*45)
    print("Model Disagreement 통계 요약 (Raw Prob 기준)")
    print("="*45)
    print(f"평균 Disagreement: {disagreement.mean():.4f}")
    print(f"최대 Disagreement: {disagreement.max():.4f}")
    print(f"불일치 > 0.2 (주의 샘플) 비율: {(disagreement > 0.2).mean() * 100:.2f}% ({(disagreement > 0.2).sum():,}개)")
    print(f"불일치 > 0.5 (위험 갈등 샘플) 비율: {(disagreement > 0.5).mean() * 100:.2f}% ({(disagreement > 0.5).sum():,}개)")
    print("="*45)
    
    # 불일치도 저장
    out_disagree = os.path.join(DATA_DIR, "model_disagreement.npy")
    np.save(out_disagree, disagreement)
    print(f"Disagreement 파일 저장 완료: {out_disagree}")
else:
    print(f"\nLightGBM 원시 확률 파일({lgb_prob_path})이 없습니다. 불일치 계산 대기 중...")