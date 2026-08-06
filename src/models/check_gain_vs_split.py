"""
    Feature Importance 기준 교차 검증 ㅡ split vs gain
    
    Baseline 500개 선택은 LightGBM 기본값인 split(분기 사용 빈도) 기준으로 뽑았다. 
    gain(오차 감소 기여도) 기준과 비교해 얼마나 겹치는지 확인해, 어느 기준으로 봐도 비슷한 특징이 중요하다는 것을 교차 검증한다.
    저장된 모델을 불러와서 확인한다. 
        
"""

import mlflow
import numpy as np

mlflow.set_experiment("trust-triage-baseline")
runs = mlflow.search_runs(order_by=["start_time"])

run_id = runs[runs["tags.feature_set"] == "full"].iloc[0]["run_id"]
model_full = mlflow.lightgbm.load_model(f"runs:/{run_id}/model")

split_importance = model_full.feature_importances_
gain_importance = model_full.booster_.feature_importance(importance_type='gain')

top500_split = set(np.argsort(-split_importance)[:500])
top500_gain = set(np.argsort(-gain_importance)[:500])

overlap = len(top500_split & top500_gain)
print(f"split 상위 500개 vs gain 상위 500개 - 겹치는 개수: {overlap}/500 ({overlap/500:.1%})")
