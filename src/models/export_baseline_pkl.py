import mlflow
import joblib

print("MLflow에서 최신 4-way 모델의 run_id를 조회합니다...")
mlflow.set_experiment("trust-triage-baseline")

# 최신 4-way 모델(split_type=temporal_week_id_4way)의 Run ID를 자동으로 가져옵니다.
runs = mlflow.search_runs(
    filter_string="tags.split_type = 'temporal_week_id_4way'",
    order_by=["start_time DESC"],
    max_results=1
)

if runs.empty:
    print("해당하는 4-way 모델 기록을 찾을 수 없습니다.")
else:
    run_id = runs.iloc[0].run_id
    print(f"최신 Run ID 발견: {run_id}")
    
    print("모델을 다운로드하고 피클 파일로 저장합니다...")
    model = mlflow.lightgbm.load_model(f"runs:/{run_id}/model")
    joblib.dump(model, "baseline_model_lightgbm_tuned_500_4way.pkl")
    
    print("최신 4-way pkl 파일 생성 완료!")