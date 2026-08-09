import mlflow
import joblib

# MLflow UI에서 500개 모델의 run_id 확인하고
run_id = "69a92b2033d346ac930fe2ec889199a2"

model = mlflow.lightgbm.load_model(f"runs:/{run_id}/model")
joblib.dump(model, "baseline_model_500.pkl")

print("pkl 파일 저장 완료")