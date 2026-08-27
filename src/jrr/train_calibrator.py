#!/usr/bin/env python3
"""
7단계 — JRR(Justified Routing Rule) 확률 보정(Calibration) 파이프라인

수행계획서 목표(FPR 0.1%)를 달성하기 위해, Isotonic Regression을 사용하여
AI 모델의 원시 예측 확률을 실제 신뢰도로 보정하고
최적의 임계값(Threshold)을 산출한다.

데이터 소스 (4분할 기준 - Calibration Set 사용)
-----------
* y_calib.npy      : Calibration 정답지
* X_calib.npy      : Calibration 피처 데이터
* baseline_model_lightgbm_tuned_500_4way.pkl : 학습된 LightGBM 모델
* top_feature_indices_500.npy : 500개 주요 피처 인덱스

산출물
------
* jrr_calibrator_4way.pkl : 학습 완료된 보정기 및 임계값 (라우터 연동용)
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

# 데이터 경로 (4분할)
Y_CALIB_PATH = "data/y_calib.npy"
X_CALIB_PATH = "data/X_calib.npy"
TARGET_FPR = 0.001  # 계획상 목표 (FPR 0.1%)

TOP_N_PATH = "data/top_feature_indices_500.npy"
MODEL_PATH = "data/baseline_model_lightgbm_tuned_500_4way.pkl"
OUT_CALIBRATOR_PATH = "data/jrr_calibrator_4way.pkl"

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    print("[train_calibrator] JRR 확률 보정 모델 학습 시작 (4-way Calibration Set)\n")
    
    if not all(os.path.exists(p) for p in [Y_CALIB_PATH, X_CALIB_PATH, TOP_N_PATH, MODEL_PATH]):
        print("에러: 데이터를 찾을 수 없습니다. 경로를 확인해주세요.")
        return 1

    # MLflow 실험 공간 설정
    mlflow.set_experiment("JRR_Calibration")
    
    with mlflow.start_run(run_name="07_Isotonic_Calibration_4way"):
        
        # 1. 로컬 데이터 및 모델 로드
        print("Calibration 데이터 및 모델 로드 중...")
        y_calib = np.load(Y_CALIB_PATH)
        X_calib = np.load(X_CALIB_PATH, mmap_mode="r")
        top_indices = np.load(TOP_N_PATH)
        model = joblib.load(MODEL_PATH)
        print(f"  -> 총 {len(y_calib):,}개 데이터 및 LightGBM 로드 완료")
        
        # 2. Top 500 피처 추출 및 원시 확률 추론
        print("\nLightGBM을 통한 원시 예측 확률(Raw Proba) 산출 중...")
        X_calib_500 = X_calib[:, top_indices]
        raw_calib_proba = model.predict_proba(X_calib_500)[:, 1]
        
        # 3. Isotonic Regression 보정기 학습
        print("\nIsotonic Regression 보정기 학습 중...")
        calibrator = IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(raw_calib_proba, y_calib)
        
        # 4. 신뢰도 보정 및 최적 임계값 도출 (Calibration Set 기준)
        print("\n수행계획서 FPR 0.1% 정책 적용 및 최적 임계값 도출 중...")
        calibrated_probs = calibrator.predict(raw_calib_proba)
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

        # 5. MLflow 기록
        print("MLflow 서버에 결과 및 보정기 모델 기록 중...")
        mlflow.log_param("step", "07_calibration")
        mlflow.log_param("target_fpr", TARGET_FPR)
        mlflow.log_metric("optimal_threshold", optimal_threshold)
        mlflow.log_metric("tpr_at_fpr", tpr_at_fpr)
        mlflow.sklearn.log_model(calibrator, "07_jrr_calibrator_model")
        
        # 6. 로컬 파일 저장
        print(f"라우터 연동용 로컬 파일({OUT_CALIBRATOR_PATH}) 저장 중...")
        joblib.dump({'model': calibrator, 'threshold': optimal_threshold}, OUT_CALIBRATOR_PATH)
        
        print("\n[train_calibrator] 완료되었습니다.")
        
    return 0

if __name__ == "__main__":
    raise SystemExit(main())