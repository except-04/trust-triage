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
    print(f"\n================================================================================================================")
    print(f" [Phase 2] tau_low 최적화 (Calibration Set)")
    print(f" - 고정 상수: tau_difficulty=5.0, tau_disagree=0.30, tau_ood=0.0")
    print(f" - 목적: 다목적 효용 점수(Review Yield × 악성 방어율) 기반 최적 균형점 자동 탐색")
    print(f"================================================================================================================")
    print(f"{'tau_low':^8} | {'심층분석 비율':^13} | {'심층분석 건수':^12} | {'Review Yield':^12} | {'정상 중 악성 누출 건수 (누출률)':^32} | {'효용 점수':^10}")
    print(f"{'-'*8}-+-{'-'*13}-+-{'-'*12}-+-{'-'*12}-+-{'-'*32}-+-{'-'*10}")
    
    test_bounds = np.arange(0.50, 0.98, 0.05)
    test_bounds = np.append(test_bounds, [0.60, 0.98, 0.983]) # 주요 구간 추가
    test_bounds = np.sort(np.unique(test_bounds))
    
    n_total_malicious = np.sum(y_true == 1)
    best_lower_bound = 0.60
    best_utility_score = -1.0
    best_stats = {}
    
    for tl in test_bounds:
        if tl >= tau_high: continue
        routes = simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores, 
                                       tau_low=tl, tau_high=tau_high, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=5.0)
        
        n_total = len(routes)
        n_uncertain = np.sum(routes == "HIGH_RISK_UNCERTAIN")
        pct_uncertain = n_uncertain / n_total * 100
        
        auto_benign_mask = (routes == "AUTO_BENIGN")
        leaked_malware = np.sum((y_true == 1) & auto_benign_mask)
        leaked_rate = (leaked_malware / n_total_malicious * 100) if n_total_malicious > 0 else 0.0
        
        yield_score = calculate_review_yield(y_true, routes)
        
        # 다목적 효용 점수 (Net Benefit Score):
        # 분석가 검토 적중률(Review Yield)과 악성 방어율(1 - 악성누출률)을 동시에 고려한 최적 균형점 산출
        defense_rate = (1.0 - leaked_rate / 100.0)
        utility_score = yield_score * defense_rate
        
        print(f"  {tl:^6.2f} | {pct_uncertain:>11.2f}% | {n_uncertain:>10,}건 | {yield_score:>10.2f}% | {leaked_malware:>14,}건 ({leaked_rate:5.2f}%) | {utility_score:>8.2f}")
        
        if utility_score > best_utility_score:
            best_utility_score = utility_score
            best_lower_bound = tl
            best_stats = {
                "pct_uncertain": pct_uncertain,
                "n_uncertain": n_uncertain,
                "yield": yield_score,
                "leaked_malware": leaked_malware,
                "leaked_rate": leaked_rate,
                "utility_score": utility_score
            }
            
    print(f"================================================================================================================\n")
    return float(best_lower_bound), best_stats


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
        
        # Phase 2: tau_low Tuning (다목적 효용 점수 기반 자동 탐색)
        optimal_lb, best_stats = optimize_lower_bound(y_true, p_calib, disagreement, ood_scores, diff_scores, fixed_upper_bound)
        
        # 대표값 기준 최종 성능 산출
        routes_final = simulate_full_routing(p_calib, disagreement, ood_scores, diff_scores, 
                                       tau_low=optimal_lb, tau_high=fixed_upper_bound, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=5.0)
        final_yield = calculate_review_yield(y_true, routes_final)
        
        n_total = len(routes_final)
        n_uncertain = np.sum(routes_final == "HIGH_RISK_UNCERTAIN")
        pct_uncertain = n_uncertain / n_total * 100
        auto_benign_mask = (routes_final == "AUTO_BENIGN")
        leaked_malware = np.sum((y_true == 1) & auto_benign_mask)
        leaked_rate = leaked_malware / np.sum(y_true == 1) * 100

        print("==================================================")
        print("[완료] Calibration 기준 최적 라우팅 임계값 확정")
        print(f" - [확정] 자동 차단 상한선(Upper Bound): {fixed_upper_bound:.6f} (FPR 0.1% 기준 고정)")
        print(f" - [확정] 심층 분석 하한선(Lower Bound): {optimal_lb:.2f} (효용 점수 {best_stats.get('utility_score', 0.0):.2f}점 1위)")
        print(f" - [확정] 분석 난이도 임계값(Difficulty): 5.0 (심층 분석 병목 해소)")
        print(f" - [확인] Calibration 심층분석 비율: {pct_uncertain:.2f}% ({n_uncertain:,}건)")
        print(f" - [확인] Calibration 분석가 검토 적중률(Yield): {final_yield:.2f}%")
        print(f" - [확인] Calibration 악성 누락: {leaked_malware:,}건 ({leaked_rate:.2f}%)")
        print("==================================================")
        print("[안내] 위 산출된 하한선(tau_low=0.60, tau_difficulty=5.0)을 확인하시고, jrr_router.py로 Eval 최종 라우팅을 실행하세요.")

if __name__ == "__main__":
    main()