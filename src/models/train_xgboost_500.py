import numpy as np
import xgboost as xgb
import mlflow
import joblib

DATA_DIR = "D:\KISIA_laptop\out\dev" 

X_tr = np.load(f"{DATA_DIR}/X_tr.npy", mmap_mode="r")
y_tr = np.load(f"{DATA_DIR}/y_tr.npy")
X_calib = np.load(f"{DATA_DIR}/X_calib.npy", mmap_mode="r")
y_calib = np.load(f"{DATA_DIR}/y_calib.npy")

top_indices = np.load("top_feature_indices_500.npy")
top_indices = np.sort(top_indices)
X_tr_500 = X_tr[:, top_indices]
X_calib_500 = X_calib[:, top_indices]

mlflow.set_experiment("trust-triage-baseline")

with mlflow.start_run(run_name="xgboost_500_v1"):
    mlflow.set_tag("model_type", "xgboost")
    mlflow.set_tag("feature_set", "reduced")
    mlflow.set_tag("top_n", "500")

    model_xgb = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        random_state=42,
        tree_methon='hist'
    )
    model_xgb.fit(
        X_tr_500, y_tr,
        eval_set=[(X_calib_500, y_calib)],
        early_stopping_rounds=50,
        verbose=50
    )

    mlflow.xgboost.log_model(model_xgb, "model")
    joblib.dump(model_xgb, "baseline_model_xgb_500.pkl")
    print("XGBoost 500개 모델 학습 및 저장 완료")
    
