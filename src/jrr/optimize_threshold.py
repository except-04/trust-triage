# src/jrr/optimize_threshold.py
import numpy as np
import mlflow
import joblib
import os
import sys

# jrr_router 모듈 경로 추가
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from jrr_router import JointRiskRouter
from _jrr_eval_core import calculate_review_yield

def calculate_or_load_signals(X_calib_path, y_calib_path):
    print("[데이터 로딩] Calibration 세트 다중 위험 신호 계산 (최초 실행 시 시간 소요)")
    y_true = np.load(y_calib_path)
    
    # 캐시 파일 경로
    p_calib_cache = "data/cache_p_calib.npy"
    disagreement_cache = "data/cache_disagreement_calib.npy"
    ood_cache = "data/cache_ood_calib.npy"
    diff_cache = "data/cache_diff_calib.npy"
    
    if os.path.exists(p_calib_cache) and os.path.exists(disagreement_cache) and os.path.exists(ood_cache) and os.path.exists(diff_cache):
        print("  -> 캐시된 신호 파일(cache_*.npy)을 불러옵니다.")
        return y_true, np.load(p_calib_cache), np.load(disagreement_cache), np.load(ood_cache), np.load(diff_cache)
        
    print("  -> 캐시가 없으므로 Calibration 데이터로 새로 계산합니다.")
    X_calib = np.load(X_calib_path, mmap_mode="r")
    top_500_idx = np.load("data/top_feature_indices_500.npy")
    X_calib_500 = X_calib[:, top_500_idx]
    
    # 1. Probability
    model_lgb = joblib.load("data/baseline_model_lightgbm_tuned_500_4way.pkl" if os.path.exists("data/baseline_model_lightgbm_tuned_500_4way.pkl") else "data/baseline_model_lightgbm_tuned_500_v4_9120.pkl")
    print("  -> [1] LGBM 예측 중...")
    p_lgb_raw = model_lgb.predict_proba(X_calib_500)[:, 1]
    
    calibrator_pack = joblib.load("data/jrr_calibrator_4way.pkl" if os.path.exists("data/jrr_calibrator_4way.pkl") else "data/jrr_calibrator.pkl")
    calibrator = calibrator_pack['model']
    p_calib = calibrator.predict(p_lgb_raw)
    
    # 2. Disagreement
    print("  -> [2] XGB 예측 중 (Disagreement 계산)...")
    model_xgb = joblib.load("data/baseline_model_xgb_500_4way_1000cap.pkl")
    p_xgb_raw = model_xgb.predict_proba(X_calib_500)[:, 1]
    disagreement = np.abs(p_lgb_raw - p_xgb_raw) 
    
    # 3. OOD & Difficulty
    print("  -> [3,4] OOD & Difficulty 계산 중...")
    risk_signals = joblib.load("data/jrr_risk_signals.pkl")
    ood_model = risk_signals['ood_model']
    difficulty_indices = risk_signals['difficulty_indices']
    
    ood_scores = ood_model.decision_function(X_calib_500)
    difficulty_scores = np.sum(X_calib_500[:, difficulty_indices], axis=1)
    
    # 캐시 저장
    np.save(p_calib_cache, p_calib)
    np.save(disagreement_cache, disagreement)
    np.save(ood_cache, ood_scores)
    np.save(diff_cache, difficulty_scores)
    print("  -> 캐시 저장 완료!")
    
    return y_true, p_calib, disagreement, ood_scores, difficulty_scores


def simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores, tau_low, tau_high, tau_disagree, tau_ood, tau_difficulty):
    router = JointRiskRouter(tau_low, tau_high, tau_disagree, tau_ood, tau_difficulty)
    routed = router.route_batch(p_calib, disagreement, ood_scores, difficulty_scores)
    return np.array([r["initial_verdict"] for r in routed])


def optimize_difficulty(y_true, p_calib, disagreement, ood_scores, difficulty_scores, tau_high):
    print(f"\n=========================================================================================")
    print(f" [Phase 1] tau_difficulty 최적화 (Calibration Set)")
    print(f" - 고정 상수: tau_low=0.60, tau_disagree=0.30, tau_ood=0.0")
    print(f" - 목적: 심층 분석 병목 해소 및 타율(Review Yield) 극대화")
    print(f"=========================================================================================")
    print(f"{'tau_diff':^8} | {'심층분석 비율':^13} | {'심층분석 건수':^12} | {'Review Yield':^12} | {'정상 중 악성 누출 건수':^16}")
    print(f"{'-'*8}-+-{'-'*13}-+-{'-'*12}-+-{'-'*12}-+-{'-'*16}")
    
    test_bounds = np.arange(1.0, 11.0, 1.0)
    
    for td in test_bounds:
        routes = simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores, 
                                       tau_low=0.60, tau_high=tau_high, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=td)
        
        n_total = len(routes)
        n_uncertain = np.sum(routes == "HIGH_RISK_UNCERTAIN")
        pct_uncertain = n_uncertain / n_total * 100
        
        auto_benign_mask = (routes == "AUTO_BENIGN")
        leaked_malware = np.sum((y_true == 1) & auto_benign_mask)
        
        yield_score = calculate_review_yield(y_true, routes)
        
        print(f"  {td:^6.1f} | {pct_uncertain:>11.2f}% | {n_uncertain:>10,}건 | {yield_score:>10.2f}% | {leaked_malware:>14,}건")
    print(f"=========================================================================================\n")


def optimize_lower_bound(y_true, p_calib, disagreement, ood_scores, difficulty_scores, tau_high):
    print(f"\n=========================================================================================")
    print(f" [Phase 2] tau_low 최적화 (Calibration Set)")
    print(f" - 고정 상수: tau_difficulty=5.0, tau_disagree=0.30, tau_ood=0.0")
    print(f" - 목적: 확률 그레이존의 최적 하한선 도출 (수용 가능한 Leakage 내에서 타율 방어)")
    print(f"=========================================================================================")
    print(f"{'tau_low':^8} | {'심층분석 비율':^13} | {'심층분석 건수':^12} | {'Review Yield':^12} | {'정상 중 악성 누출 건수':^16}")
    print(f"{'-'*8}-+-{'-'*13}-+-{'-'*12}-+-{'-'*12}-+-{'-'*16}")
    
    test_bounds = np.arange(0.50, 0.98, 0.05)
    test_bounds = np.append(test_bounds, [0.60, 0.98, 0.983]) # 주요 구간 추가
    test_bounds = np.sort(np.unique(test_bounds))
    
    for tl in test_bounds:
        if tl >= tau_high: continue
        routes = simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores, 
                                       tau_low=tl, tau_high=tau_high, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=5.0)
        
        n_total = len(routes)
        n_uncertain = np.sum(routes == "HIGH_RISK_UNCERTAIN")
        pct_uncertain = n_uncertain / n_total * 100
        
        auto_benign_mask = (routes == "AUTO_BENIGN")
        leaked_malware = np.sum((y_true == 1) & auto_benign_mask)
        
        yield_score = calculate_review_yield(y_true, routes)
        
        print(f"  {tl:^6.2f} | {pct_uncertain:>11.2f}% | {n_uncertain:>10,}건 | {yield_score:>10.2f}% | {leaked_malware:>14,}건")
    print(f"=========================================================================================\n")


def main():
    print("[Threshold Optimization] Data Leakage 없는 Calibration 기반 최적화 시작!\n")
    
    # MLflow DB 스키마 에러 임시 회피
    # mlflow.set_experiment("JRR_Threshold_Optimization")
    # with mlflow.start_run(run_name="Calib_Threshold_Tuning"):
    if True:
        calibrator_pack = joblib.load("data/jrr_calibrator_4way.pkl" if os.path.exists("data/jrr_calibrator_4way.pkl") else "data/jrr_calibrator.pkl")
        fixed_upper_bound = float(calibrator_pack.get('threshold', 0.983645))

        
        y_true, p_calib, disagreement, ood_scores, diff_scores = calculate_or_load_signals(
            "data/X_calib.npy", "data/y_calib.npy"
        )
        
        # Phase 1: Difficulty Tuning
        optimize_difficulty(y_true, p_calib, disagreement, ood_scores, diff_scores, fixed_upper_bound)
        
        # Phase 2: tau_low Tuning
        optimize_lower_bound(y_true, p_calib, disagreement, ood_scores, diff_scores, fixed_upper_bound)
        
        # MLflow 기록 (대표값 5.0, 0.60 기준 최종 성능)
        routes_final = simulate_full_routing(p_calib, disagreement, ood_scores, diff_scores, 
                                       tau_low=0.60, tau_high=fixed_upper_bound, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=5.0)
        final_yield = calculate_review_yield(y_true, routes_final)
        # mlflow.log_param("calib_tau_low", 0.60)
        # mlflow.log_param("calib_tau_diff", 5.0)
        # mlflow.log_metric("calib_review_yield_final", final_yield)
        
        print(f"\n[최종 성능] tau_low=0.60, tau_diff=5.0 적용 시 Review Yield: {final_yield:.2f}%")
        print("[완료] 최적화 튜닝 결과를 확인하시고 최종 보고서에 반영하십시오.")

if __name__ == "__main__":
    main()