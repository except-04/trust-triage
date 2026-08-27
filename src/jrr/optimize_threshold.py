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

def optimize_lower_bound(y_true, y_prob, upper_bound, daily_budget=100):
    """
    분석가의 예산을 초과하지 않으면서 최적의 가성비(Review Yield)를 내는
    '심층분석 하한 임계값'을 탐색합니다.
    """
    print(f"\n[진행] 하한 임계값(Lower Bound) 최적화 시뮬레이션 시작")
    print(f"[안내] 상한 임계값(자동 차단선) 고정: {upper_bound:.6f}")
    
    best_lower_bound = 0.0
    best_yield = 0.0
    best_deep_count = 0
    
    # 탐색할 하한선 후보군 (예: 0.1부터 upper_bound 직전까지 0.05 단위로 테스트)
    test_bounds = np.arange(0.1, upper_bound, 0.05)
    
    for lb in test_bounds:
        # 가상 라우팅 실행
        simulated_routes = simulate_routing(y_prob, lb, upper_bound)
        deep_count = np.sum(simulated_routes == "HIGH_RISK_UNCERTAIN")
        
        # evaluate_jrr.py의 가성비 계산 함수 호출
        current_yield = calculate_review_yield(y_true, simulated_routes, daily_budget)
        
        print(f"  [결과] 하한선 {lb:.2f} 설정 시 -> 심층분석 대상: {deep_count}개 | 가성비: {current_yield:.2f}%")
        
        # 예산을 심각하게 초과하지 않으면서 가성비가 가장 높은 지점 갱신
        if current_yield > best_yield and deep_count <= (daily_budget * 1.5):
            best_yield = current_yield
            best_lower_bound = lb
            best_deep_count = deep_count

    return best_lower_bound, best_yield, best_deep_count

def main():
    print("[Threshold Optimization] 3-Way 라우팅 임계값 최적화 파이프라인 시작!\n")
    
    mlflow.set_experiment("JRR_Threshold_Optimization")
    
    with mlflow.start_run(run_name="Threshold_Simulation"):
        try:
            # 1. 평가용 실제 데이터 및 train_calibrator.py 산출물 로드
            y_true = np.load("data/y_eval.npy") 
            y_prob = np.load("data/jrr_calibrated_proba.npy") 
            
            # 07번 파이프라인에서 생성된 부품 로드 (FPR 0.1% 고정 임계값 추출)
            calibrator_pack = joblib.load("data/jrr_calibrator.pkl")
            fixed_upper_bound = calibrator_pack['threshold']
            
        except FileNotFoundError as e:
            print(f"[에러] 시뮬레이션에 필요한 데이터를 찾을 수 없습니다: {e}")
            print("[안내] 평가 데이터(.npy) 및 jrr_calibrator.pkl 파일 경로를 확인해주세요.")
            return

        # 2. 최적화 시뮬레이션 실행 (예산 100개 가정)
        daily_budget = 100
        optimal_lb, max_yield, final_deep_count = optimize_lower_bound(
            y_true, y_prob, fixed_upper_bound, daily_budget
        )
        
        # 3. MLflow에 최종 결과 박제
        mlflow.log_param("daily_budget", daily_budget)
        mlflow.log_param("fixed_upper_bound", fixed_upper_bound)
        mlflow.log_metric("optimal_lower_bound", optimal_lb)
        mlflow.log_metric("max_review_yield", max_yield)
        
        print("\n==================================================")
        print("[완료] 라우팅 임계값 시뮬레이션 종료")
        print(f" - [확정] 자동 차단 상한선(Upper Bound): {fixed_upper_bound:.6f} (07번 스크립트 산출)")
        print(f" - [확정] 심층 분석 하한선(Lower Bound): {optimal_lb:.2f} (최적화 산출)")
        print(f" - [예상] 일일 심층분석 큐 인입량: {final_deep_count}건")
        print(f" - [예상] 분석가 검토 가성비(Yield): {max_yield:.2f}%")
        print("==================================================")
        print("[안내] 산출된 하한선 값을 jrr_router.py 모듈의 라우팅 분기 조건에 업데이트 해주세요.")

if __name__ == "__main__":
    main()