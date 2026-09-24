import os
import mlflow
import pandas as pd

if "MLFLOW_TRACKING_URI" in os.environ:
    mlflow.set_tracking_uri(os.environ["MLFLOW_TRACKING_URI"])
mlflow.set_experiment("trust-triage-baseline")
runs = mlflow.search_runs(order_by=["start_time"])

results_df = runs[runs["status"] == "FINISHED"][[
    "tags.feature_set", "tags.top_n",
    "metrics.validation_tpr_at_fpr", "metrics.validation_selection_threshold", "metrics.best_validation_tpr_at_fpr"
]]

print(results_df)
results_df.to_csv("baseline_comparison_results.csv", index=False)
