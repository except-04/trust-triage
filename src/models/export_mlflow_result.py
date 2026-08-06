import mlflow
import pandas as pd

mlflow.set_experiment("trust-triage-baseline")
runs = mlflow.search_runs(order_by=["start_time"])

results_df = runs[runs["status"] == "FINISHED"][[
    "tags.feature_set", "tags.top_n",
    "metrics.roc_auc", "metrics.tpr_at_fpr", "metrics.threshold"
]]

print(results_df)
results_df.to_csv("baseline_comparison_results.csv", index=False)
