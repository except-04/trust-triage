#!/usr/bin/env python3
"""
8단계 — JRR 다중 위험 신호(Risk Signal) 산출 파이프라인

기획안 및 피처 스키마에 명시된 3가지 다중 위험 신호를 산출하기 위한 모델을 학습하고 뼈대를 구성한다.
1. OOD Score: Isolation Forest를 학습시켜 학습 데이터(X_tr) 분포와의 거리 계산
2. Model Disagreement: 앙상블(LightGBM 등) 간 예측 불일치도 (분산)
3. Analysis Difficulty: PEFormatWarnings 합산 로직 (Top 500 피처 내 동적 인덱스 추출)
"""

from __future__ import annotations

import os
import joblib
import mlflow
import numpy as np
from sklearn.ensemble import IsolationForest

# --------------------------------------------------------------------------
# 환경 및 데이터 경로 설정
# --------------------------------------------------------------------------
# [필수] 구글 드라이브(out.zip)에서 다운로드한 아래 두 데이터 파일을 
# 프로젝트 최상위의 'data/' 폴더 아래에 위치시켜야 합니다.
#
# 1. X_tr.npy : 모델 학습에 사용된 원본 데이터 (OOD 모델의 정상/비정상 기준점 학습용)
# 2. top_feature_indices_500.npy : 상위 500개 피처의 원본 인덱스가 담긴 배열
X_TR_PATH = "data/X_tr.npy"
TOP_N_PATH = "data/top_feature_indices_500.npy"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    print("[train_risk_signals] JRR 다중 위험 신호 산출 모델 학습 시작\n")
    
    if not os.path.exists(X_TR_PATH) or not os.path.exists(TOP_N_PATH):
        print("에러: 데이터를 찾을 수 없습니다.")
        print(f"경로를 확인해주세요 -> 데이터: {X_TR_PATH}, 인덱스: {TOP_N_PATH}")
        return 1

    # MLflow JRR_Calibration 실험 공간에 기록
    mlflow.set_experiment("JRR_Calibration")
    
    with mlflow.start_run(run_name="08_Risk_Signals_v2"):
        
        # 1. 학습 데이터 로드
        print("[1] OOD 탐지 모델(Isolation Forest) 학습을 위해 데이터 로드 중...")
        # 메모리 폭발 방지를 위해 mmap_mode="r" 사용
        X_tr_raw = np.load(X_TR_PATH, mmap_mode="r")
        top_500_idx = np.load(TOP_N_PATH)
        
        # OOD 모델도 실전 라우터와 동일하게 Top 500 피처만 보도록 슬라이싱
        # 데이터가 너무 크므로(약 272만 개) 학습 속도와 시간적 편향(Bias) 방지를 위해 
        # Train 데이터 풀에서 10만 건을 랜덤 유니폼 샘플링합니다. (Eval 등 다른 세트 누수 없음)
        sample_size = min(100000, len(X_tr_raw))
        np.random.seed(42)
        random_indices = np.random.choice(len(X_tr_raw), sample_size, replace=False)
        
        # 행을 먼저 무작위 추출한 뒤, Top 500 열만 슬라이싱
        X_tr_sample = X_tr_raw[random_indices][:, top_500_idx]
        
        # 2. Isolation Forest 학습 (OOD 점수 산출용)
        print(f"\n[2] Isolation Forest 학습 중... (샘플 {sample_size:,}개 사용)")
        # contamination="auto"는 데이터의 정상/비정상 비율을 모델이 자동 추정
        ood_model = IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)
        ood_model.fit(X_tr_sample)
        
        print("  -> OOD 탐지 모델 학습 완료")
        
        # 3. 위험 신호 종합 로직 생성 (동적 인덱스 추출)
        print("\n[3] 분석 난이도(Warning) 피처 동적 인덱스 매핑 중...")
        
        # feature_schema.md 기준 PEFormatWarnings 원본 인덱스 범위: 2480 ~ 2568
        raw_start, raw_end = 2480, 2568
        
        # top_500_idx 배열 안에서, 값이 2480 이상 2568 미만인 원소들의 현재 '위치(Index)'만 골라냄
        difficulty_indices_in_top500 = np.where((top_500_idx >= raw_start) & (top_500_idx < raw_end))[0]
        
        print(f"  -> Top 500 피처 중 분석 난이도 관련 피처는 총 {len(difficulty_indices_in_top500)}개로 확인됨.")

        # 라우터에서 꺼내 쓸 부품들을 딕셔너리로 포장
        risk_signal_components = {
            'ood_model': ood_model,
            'difficulty_indices': difficulty_indices_in_top500, # 버그 픽스: 500차원 기준 동적 인덱스!
            'description': "OOD 모델 및 Top 500 내 분석 난이도 피처 인덱스 정보"
        }
        
        print("\n=== [위험 신호 컴포넌트 준비 완료] ===")
        print("[v] OOD Score: Isolation Forest 모델 세팅 완료")
        print("[v] Analysis Difficulty: 500차원 내 동적 인덱스 맵핑 완료")
        print("[v] Model Disagreement: 라우터 단에서 분산 계산으로 처리 예정")
        print("========================================\n")
        
        # 4. 결과 로컬 및 MLflow 저장
        print("[4] MLflow 서버 기록 및 라우터 연동용 로컬 파일 저장 중...")
        mlflow.sklearn.log_model(ood_model, "08_ood_isolation_forest")
        
        joblib.dump(risk_signal_components, 'data/jrr_risk_signals.pkl')
        
        print("\n[train_risk_signals] 무사히 완료되었습니다. (jrr_risk_signals.pkl 생성)")
        
    return 0

if __name__ == "__main__":
    raise SystemExit(main())