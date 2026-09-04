import os
import joblib
import numpy as np
import xgboost as xgb

def main():
    print("Loading data...")
    X_EVAL_PATH = "data/X_eval.npy"
    TOP_N_PATH = "data/top_feature_indices_500.npy"
    
    LGB_MODEL_PATH = "data/baseline_model_lightgbm_tuned_500_4way.pkl"
    XGB_MODEL_PATH = "data/baseline_model_xgb_500_4way_1000cap.pkl"
    
    X_eval = np.load(X_EVAL_PATH, mmap_mode="r")
    top_indices = np.load(TOP_N_PATH)
    X_eval_500 = X_eval[:, top_indices]
    
    print("Loading LightGBM model...")
    lgb_model = joblib.load(LGB_MODEL_PATH)
    print("Predicting LightGBM raw probabilities...")
    lgb_raw_proba = lgb_model.predict_proba(X_eval_500)[:, 1]
    np.save("data/y_pred_proba_lgb.npy", lgb_raw_proba)
    print("Saved LightGBM probabilities to data/y_pred_proba_lgb.npy")
    
    print("Loading XGBoost model...")
    xgb_model = joblib.load(XGB_MODEL_PATH)
    
    print("Predicting XGBoost raw probabilities...")
    # joblib loaded sklearn API xgboost model usually has predict_proba
    xgb_raw_proba = xgb_model.predict_proba(X_eval_500)[:, 1]
    np.save("data/y_pred_proba.npy", xgb_raw_proba)
    print("Saved XGBoost probabilities to data/y_pred_proba.npy")
    
    print("Done! Raw probabilities saved.")

if __name__ == "__main__":
    main()
