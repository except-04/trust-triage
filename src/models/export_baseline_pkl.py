import mlflow
import joblib

print("MLflow에서 최신 4-way 모델의 run_id를 조회합니다...")
mlflow.set_experiment("trust-triage-baseline")

# 최신 4-way 모델(split_type=temporal_week_id_4way)의 Run ID를 자동으로 가져옵니다.
runs = mlflow.search_runs(
    filter_string="tags.split_type = 'temporal_week_id_4way' AND tags.fit_split = 'train'",
    order_by=["start_time DESC"],
)

if runs.empty:
    print("해당하는 4-way 모델 기록을 찾을 수 없습니다.")
else:
    run_id = None
    for _, row in runs.iterrows():
        try:
            print(f"Run ID 확인 중: {row.run_id}")
            # 아티팩트가 존재하는지 시도
            model = mlflow.lightgbm.load_model(f"runs:/{row.run_id}/model")
            run_id = row.run_id
            print(f"최신 유효 Run ID 발견: {run_id}")
            break
        except Exception as e:
            print(f"  -> 모델 로드 실패 (튜닝 런이거나 파일 없음): {e}")
            continue

    if run_id is None:
        print("유효한 모델 파일이 저장된 Run을 찾을 수 없습니다.")
    else:
        joblib.dump(model, "baseline_model_lightgbm_tuned_500_4way.pkl")
        print("최신 4-way pkl 파일 생성 완료!")
