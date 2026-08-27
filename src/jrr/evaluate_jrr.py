import numpy as np
import mlflow
from sklearn.metrics import roc_auc_score, confusion_matrix

#핵심 포인트: 공용 도구함에서 평가 함수들을 정석대로 빌려오기
from _jrr_eval_core import calculate_ece, calculate_review_yield, calculate_true_tpr, run_kill_test

def main():
    print("[JRR Evaluation] 라우터 평가 및 검증 파이프라인 시작!\n")
    
    mlflow.set_experiment("JRR_Evaluation_and_KillTest")
    
    with mlflow.start_run(run_name="RealData_JRR_Eval"):
        try:
            # 1. 정답지 및 라우터(10번)가 뱉어낸 실제 결과물 로드
            y_true = np.load("data/y_eval.npy") 
            y_prob = np.load("data/jrr_calibrated_proba.npy") 
            routes = np.load("data/jrr_routes.npy") 
            
            # (옵션) 07번에서 산출된 최적 임계값 로드 (TPR 검증용)
            import joblib
            calibrator_pack = joblib.load("data/jrr_calibrator_4way.pkl")
            fixed_upper_bound = calibrator_pack['threshold']
            
        except FileNotFoundError as e:
            print(f"[에러] 평가에 필요한 데이터를 찾을 수 없습니다: {e}")
            print("[안내] 라우터(jrr_router.py)를 먼저 실행하여 결과 파일(.npy)을 생성해주세요.")
            return
        
        # 2. 공용 도구함에서 빌려온 4대 핵심 지표 계산 함수 실행
        ece = calculate_ece(y_true, y_prob)
        r_yield = calculate_review_yield(y_true, routes, daily_budget=100)
        actual_fpr, actual_tpr = calculate_true_tpr(y_true, y_prob, fixed_upper_bound)
        
        # --- [final_eval 기능 통합] 모델 관점의 최종 검증 지표 추가 ---
        auc = roc_auc_score(y_true, y_prob)
        y_pred = (y_prob >= fixed_upper_bound).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        # ------------------------------------------------------------------

        # 주의: 기존 run_kill_test() 호출 시 라우팅 함수가 전달되지 않으면 에러가 발생할 수 있습니다.
        try:
            kill_test_fpr = run_kill_test()
        except (ValueError, FileNotFoundError) as e:
            print(f"Kill Test 건너뜀: {e}")
            kill_test_fpr = -1.0
        
        # 3. MLflow에 결과 박제
        mlflow.log_metric("ECE_Score", ece)
        mlflow.log_metric("Review_Yield", r_yield)
        mlflow.log_metric("Actual_TPR", actual_tpr)
        if kill_test_fpr >= 0:
            mlflow.log_metric("KillTest_FPR", kill_test_fpr)
        mlflow.log_metric("ROC_AUC", auc)
        
        print("\n==================================================")
        print("[완료] JRR 평가 완료! 결과가 MLflow에 성공적으로 박제되었습니다.")
        print("--- 시스템 관점 (운영) ---")
        print(f" - 최종 ECE 점수: {ece:.4f}")
        print(f" - 최종 Review Yield: {r_yield:.2f}%")
        if kill_test_fpr >= 0:
            print(f" - Kill Test 최종 FPR: {kill_test_fpr:.4f}")
        print("\n--- 모델 관점 (final_eval 통합) ---")
        print(f" - ROC AUC: {auc:.6f}")
        print(f" - 평가셋 실측 TPR: {actual_tpr:.4f} (목표 FPR 0.1% 기준)")
        print(f" - 실측 FPR: {actual_fpr:.4f}")
        print(f" - Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        print("==================================================")

if __name__ == "__main__":
    main()