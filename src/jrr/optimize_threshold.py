# src/jrr/optimize_threshold.py
import numpy as np
import mlflow
import joblib
import os

# 💡 더 이상 11번 파일을 억지로 부르지 않고, 공용 도구함에서 정석적으로 불러옵니다!
from _jrr_eval_core import calculate_review_yield

def simulate_routing(y_prob, lower_bound, upper_bound):
    """
    임계값 조합에 따라 전체 파일을 3개 큐(자동정상, 심층분석, 자동악성)로 분배하는 시뮬레이션 함수
    """
    routes = np.empty(len(y_prob), dtype=object)
    
    # 1. 자동 악성 (절대 차단선 이상)
    routes[y_prob >= upper_bound] = "AUTO_MALICIOUS"
    # 2. 자동 정상 (하한선 미만)
    routes[y_prob < lower_bound] = "AUTO_BENIGN"
    # 3. 심층 분석 (하한선 이상 ~ 절대 차단선 미만)
    routes[(y_prob >= lower_bound) & (y_prob < upper_bound)] = "HIGH_RISK_UNCERTAIN"
    
    return routes

def optimize_lower_bound(y_true, y_prob, upper_bound, daily_budget=100, target_ratio=3.5):
    """
    Calibration 데이터셋을 바탕으로 tau_low 후보별 라우팅 비율(%)과 Review Yield를 시뮬레이션하고,
    팀 목표인 심층분석 라우팅 비율(~3.5%)에 가장 부합하는 최적의 tau_low를 탐색합니다.
    """
    print(f"\n=========================================================================================================================")
    print(f"[Calibration Set 기준] tau_low 후보별 라우팅 비율, Review Yield, 자동정상 누출 악성 시뮬레이션")
    print(f" - 고정 상한선(tau_high): {upper_bound:.6f}")
    print(f" - 분석 대상 총 샘플 수: {len(y_prob):,}건")
    print(f"=========================================================================================================================")
    print(f"{'tau_low':^9} | {'심층분석 비율':^13} | {'심층분석 건수':^12} | {'Review Yield':^12} | {'자동정상 중 악성 누출 건수 (누출률)':^32}")
    print(f"{'-'*9}-+-{'-'*13}-+-{'-'*12}-+-{'-'*12}-+-{'-'*32}")
    
    n_total = len(y_prob)
    n_total_malicious = np.sum(y_true == 1)  # Calibration 전체 악성 수
    test_bounds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.80]
    test_bounds = [b for b in test_bounds if b < upper_bound]
    
    best_lower_bound = test_bounds[0]
    best_diff = 999.0
    best_stats = {}
    
    for lb in test_bounds:
        simulated_routes = simulate_routing(y_prob, lb, upper_bound)
        
        n_benign = np.sum(simulated_routes == "AUTO_BENIGN")
        n_malicious = np.sum(simulated_routes == "AUTO_MALICIOUS")
        n_uncertain = np.sum(simulated_routes == "HIGH_RISK_UNCERTAIN")
        
        pct_benign = n_benign / n_total * 100
        pct_malicious = n_malicious / n_total * 100
        pct_uncertain = n_uncertain / n_total * 100
        
        #악성 누락 개수 & 악성 누락률 (전체 악성 대비)
        auto_benign_mask = (simulated_routes == "AUTO_BENIGN")
        leaked_malware = np.sum((y_true == 1) & auto_benign_mask)
        leaked_rate_of_all_malware = (leaked_malware / n_total_malicious * 100) if n_total_malicious > 0 else 0.0
        
        current_yield = calculate_review_yield(y_true, simulated_routes, daily_budget)
        
        print(f"  {lb:^7.2f} | {pct_uncertain:>11.2f}% | {n_uncertain:>10,}건 | {current_yield:>10.2f}% | {leaked_malware:>10,}건 ({leaked_rate_of_all_malware:5.2f}%)")
        
        # 목표 라우팅 비율(예: 3.5%)에 가장 가까운 tau_low 탐색
        diff = abs(pct_uncertain - target_ratio)
        if diff < best_diff:
            best_diff = diff
            best_lower_bound = lb
            best_stats = {
                "pct_uncertain": pct_uncertain,
                "n_uncertain": n_uncertain,
                "pct_benign": pct_benign,
                "pct_malicious": pct_malicious,
                "yield": current_yield
            }
            
    print(f"==========================================================================================\n")
    return float(best_lower_bound), best_stats

def main():
    print("[Threshold Optimization] 3-Way 라우팅 임계값 최적화 파이프라인 시작!\n")
    
    mlflow.set_experiment("JRR_Threshold_Optimization")
    
    with mlflow.start_run(run_name="Threshold_Simulation"):
        try:
            # 1. Calibration 데이터 및 보정기 로드
            y_true = np.load("data/y_calib.npy")
            
            calib_path = "data/jrr_calibrator_4way.pkl" if os.path.exists("data/jrr_calibrator_4way.pkl") else "data/jrr_calibrator.pkl"
            calibrator_pack = joblib.load(calib_path)
            calibrator = calibrator_pack['model']
            fixed_upper_bound = float(calibrator_pack.get('threshold', 0.983645))
            
            # Calibration 세트의 원시 예측 확률 확보
            if os.path.exists("data/y_pred_proba_calib.npy"):
                y_pred_raw = np.load("data/y_pred_proba_calib.npy")
            else:
                print("[안내] Calibration 세트에 대한 LightGBM 원시 예측 확률 산출 중...")
                X_calib = np.load("data/X_calib.npy", mmap_mode="r")
                top_indices = np.load("data/top_feature_indices_500.npy")
                model_path = "data/baseline_model_lightgbm_tuned_500_4way.pkl" if os.path.exists("data/baseline_model_lightgbm_tuned_500_4way.pkl") else "data/baseline_model_lightgbm_tuned_500_v4_9120.pkl"
                model = joblib.load(model_path)
                y_pred_raw = model.predict_proba(X_calib[:, top_indices])[:, 1]
                np.save("data/y_pred_proba_calib.npy", y_pred_raw)
                print("  -> data/y_pred_proba_calib.npy 생성 완료!")
                
            if y_pred_raw.ndim == 2:
                y_pred_raw = y_pred_raw[:, 1]
            
            # Calibration 세트의 보정 확률 계산
            y_prob = calibrator.predict(y_pred_raw)
            
        except FileNotFoundError as e:
            print(f"[에러] 시뮬레이션에 필요한 데이터를 찾을 수 없습니다: {e}")
            print("[안내] Calibration 데이터(.npy) 및 jrr_calibrator.pkl 파일 경로를 확인해주세요.")
            return

        # 2. 최적화 시뮬레이션 실행 (목표 심층분석 비율: 약 3.5%)
        daily_budget = 100
        target_ratio = 3.5
        optimal_lb, best_stats = optimize_lower_bound(
            y_true, y_prob, fixed_upper_bound, daily_budget, target_ratio=target_ratio
        )
        
        # 3. MLflow에 최종 결과 박제
        mlflow.log_param("daily_budget", daily_budget)
        mlflow.log_param("fixed_upper_bound", fixed_upper_bound)
        mlflow.log_param("target_routing_ratio", target_ratio)
        mlflow.log_metric("optimal_lower_bound", optimal_lb)
        mlflow.log_metric("calib_uncertain_ratio", best_stats.get("pct_uncertain", 0.0))
        mlflow.log_metric("calib_review_yield", best_stats.get("yield", 0.0))
        
        print("==================================================")
        print("[완료] Calibration 기준 최적 라우팅 임계값 확정")
        print(f" - [확정] 자동 차단 상한선(Upper Bound): {fixed_upper_bound:.6f} (FPR 0.1% 기준 고정)")
        print(f" - [확정] 심층 분석 하한선(Lower Bound): {optimal_lb:.2f} (목표 라우팅 비율 {target_ratio}% 기준)")
        print(f" - [확인] Calibration 심층분석 비율: {best_stats.get('pct_uncertain', 0.0):.2f}% ({best_stats.get('n_uncertain', 0):,}건)")
        print(f" - [확인] Calibration 분석가 가성비(Yield): {best_stats.get('yield', 0.0):.2f}%")
        print("==================================================")
        print("[안내] 산출된 하한선(tau_low)을 확인하시고, jrr_router.py로 Eval 최종 라우팅을 실행하세요.")

if __name__ == "__main__":
    main()