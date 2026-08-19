import numpy as np
import pandas as pd
import mlflow
import os


def main():
    print("[JRR Evaluation] 라우터 평가 및 검증 파이프라인 시작!\n")
    
    mlflow.set_experiment("JRR_Evaluation_and_KillTest")
    
    with mlflow.start_run(run_name="RealData_JRR_Eval"):
        
        # 1. 실제 데이터 로드
        try:
            # 정답지 (예: Eval 세트 또는 Challenge 세트)
            y_true = np.load("data/y_eval.npy") 
            
            # 09_jrr_router.py가 뱉어낸 실제 결과물 파일들
            y_prob = np.load("data/jrr_calibrated_proba.npy") 
            routes = np.load("data/jrr_routes.npy") 
            
        except FileNotFoundError as e:
            print(f"[에러] 평가에 필요한 데이터를 찾을 수 없습니다: {e}")
            print("[안내]'10_jrr_router.py'를 먼저 실행하여 결과 파일(.npy)을 생성해주세요.")
            return
        
        # 2. 3대 핵심 지표 계산
        ece = calculate_ece(y_true, y_prob)
        r_yield = calculate_review_yield(y_true, routes, daily_budget=100)
        kill_test_fpr = run_kill_test()
        
        # 3. MLflow에 결과 박제
        mlflow.log_metric("ECE_Score", ece)
        mlflow.log_metric("Review_Yield", r_yield)
        mlflow.log_metric("KillTest_FPR", kill_test_fpr)
        
        print("\n==================================================")
        print("[완료] JRR 평가 완료! 결과가 MLflow에 성공적으로 박제되었습니다.")
        print(f" - 최종 ECE 점수: {ece:.4f} (0에 가까울수록 완벽함)")
        print(f" - 최종 Review Yield: {r_yield:.2f}%")
        print(f" - Kill Test 최종 FPR: {kill_test_fpr:.4f}")
        print("==================================================")

if __name__ == "__main__":
    main()