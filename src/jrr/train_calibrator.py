#!/usr/bin/env python3
"""
7단계 — JRR(Justified Routing Rule) 확률 보정(Calibration) 파이프라인

수행계획서 목표(FPR 0.1%)를 달성하기 위해, Isotonic Regression을 사용하여
AI 모델의 원시 예측 확률(y_pred_proba)을 실제 신뢰도로 보정하고
최적의 임계값(Threshold)을 산출한다.

데이터 소스
-----------
* y_calib.npy      : 40~45주차 Calibration 정답지
* y_pred_proba.npy : Baseline 모델을 통해 추출한 예측 확률

산출물
------
* jrr_calibrator.pkl : 학습 완료된 보정기 및 임계값 (라우터 연동용)
* MLflow 트래킹 기록 : JRR_Calibration 실험 공간에 메트릭 및 모델 박제
"""

from __future__ import annotations

import os
import joblib
import mlflow
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import roc_curve


# --------------------------------------------------------------------------
# 환경 설정
# --------------------------------------------------------------------------

#구글 드라이브(out.zip)에서 다운로드한 y_calib.npy 및 y_pred_proba.npy 파일은
# 프로젝트 최상위의 'data/' 폴더 아래에 위치시켜야 함
Y_TRUE_PATH = "data/y_calib.npy" #40~45주차 Calibration 정답지 (실제 정상/악성 라벨)
Y_PRED_PATH = "data/y_pred_proba.npy" #Baseline 모델이 추론한 원시 예측 확률값
TARGET_FPR = 0.001  # 계획상 목표 (FPR 0.1%)


#파일을 생성하려면 다음 4개의 파일이 프로젝트 폴더 내부에 있어야 합니다. 경로에 맞게 파일들이 존재하는지 확인해 주십시오.
#data/X_eval.npy (평가용 원본 데이터)
#data/top_feature_indices_500.npy (500개 피처 인덱스)
#baseline_model_lightgbm_tuned_500_v4_9120.pkl (학습된 1차 모델)
#jrr_calibrator.pkl (train_calibrator.py를 실행하여 만든 보정기 모델)
X_EVAL_PATH = "data/X_eval.npy"
TOP_N_PATH = "data/top_feature_indices_500.npy"
MODEL_PATH = "data/baseline_model_lightgbm_tuned_500_v4_9120.pkl"

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    print("[train_calibrator] JRR 확률 보정 모델 학습 시작\n")
    
    if not os.path.exists(Y_TRUE_PATH) or not os.path.exists(Y_PRED_PATH):
        print("에러: 데이터를 찾을 수 없습니다.")
        print(f"경로를 확인해주세요 -> 정답지: {Y_TRUE_PATH}, 예측값: {Y_PRED_PATH}")
        return 1

    # MLflow 실험 공간 설정
    mlflow.set_experiment("JRR_Calibration")
    
    with mlflow.start_run(run_name="07_Isotonic_Calibration_v1"):
        
        # 1. 로컬 데이터 로드
        print("로컬에서 정답지 및 예측 확률 데이터 로드 중...")
        y_calib = np.load(Y_TRUE_PATH)
        y_pred_proba = np.load(Y_PRED_PATH)
        print(f"  -> 총 {len(y_calib):,}개 데이터 장전 완료")
        
        # 2. Isotonic Regression 보정기 학습
        print("\nIsotonic Regression 보정기 학습 중...")
        calibrator = IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(y_pred_proba, y_calib)
        
        # 3. 신뢰도 보정 및 최적 임계값 도출
        print("\n수행계획서 FPR 0.1% 정책 적용 및 최적 임계값 도출 중...")
        calibrated_probs = calibrator.predict(y_pred_proba)
        fpr, tpr, thresholds = roc_curve(y_calib, calibrated_probs)
        
        # FPR이 목표치(0.001) 이하인 구간 중 가장 성적이 좋은(탐지율이 높은) 위치 탐색
        idx = np.where(fpr <= TARGET_FPR)[0][-1]
        
        optimal_threshold = thresholds[idx]
        tpr_at_fpr = tpr[idx]
        fpr_at_fpr = fpr[idx]
        
        print("\n=== [최종 결과] ===")
        print(f"JRR 확정 임계값(Threshold): {optimal_threshold:.6f}")
        print(f"보정 후 악성 탐지율(TPR): {tpr_at_fpr*100:.2f}%")
        print(f"보정 후 정상 오탐률(FPR): {fpr_at_fpr*100:.4f}%")
        print("===================\n")
        # ------------------------------------------------------------------
        # [파트 2] 평가 데이터(48만 건) 로드 및 최종 보정 확률(jrr_calibrated_proba.npy) 생성
        # ------------------------------------------------------------------
        print("\n48만 건 평가 데이터 대상 최종 보정 확률 산출 중...")
        X_eval = np.load(X_EVAL_PATH, mmap_mode="r")
        top_indices = np.load(TOP_N_PATH)
        model = joblib.load(MODEL_PATH)

        X_eval_500 = X_eval[:, top_indices]
        raw_eval_proba = model.predict_proba(X_eval_500)[:, 1]
        final_calibrated_probs = calibrator.predict(raw_eval_proba)

        np.save("data/jrr_calibrated_proba.npy", final_calibrated_probs)
        print("  -> [저장 완료] data/jrr_calibrated_proba.npy 생성 성공!")

        # 4. MLflow 기록
        print("MLflow 서버에 결과 및 보정기 모델 기록 중...")
        mlflow.log_param("step", "07_calibration")
        mlflow.log_param("target_fpr", TARGET_FPR)
        mlflow.log_metric("optimal_threshold", optimal_threshold)
        mlflow.log_metric("tpr_at_fpr", tpr_at_fpr)
        mlflow.sklearn.log_model(calibrator, "07_jrr_calibrator_model")
        
        # 5. 로컬 파일 저장
        print("라우터 연동용 로컬 파일(jrr_calibrator.pkl) 저장 중...")
        joblib.dump({'model': calibrator, 'threshold': optimal_threshold}, 'data/jrr_calibrator.pkl')
        
        print("\n[train_calibrator] 완료되었습니다.")
        
    return 0

if __name__ == "__main__":
    raise SystemExit(main())