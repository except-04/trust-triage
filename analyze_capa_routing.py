import json
import numpy as np
import pandas as pd
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    data_dir = root / 'data'
    mapping_dir = data_dir / 'ember2024' / 'mapping'
    
    # Load data
    y_path = data_dir / 'y_eval.npy'
    p_path = data_dir / 'jrr_calibrated_proba.npy'
    mapping_path = mapping_dir / 'eval_row_to_sha256.csv'
    capa_path = mapping_dir / 'eval_capa_results_unique.jsonl'
    
    y = np.load(y_path)
    p = np.load(p_path)
    if p.ndim == 2: p = p[:, 1]
    
    df = pd.read_csv(mapping_path)
    
    # Define routing policies
    tau_low = 0.65
    tau_high = 0.983645
    
    # 1. Prob Model 2-way
    pred_1 = (p >= tau_high).astype(int)
    
    # 2. Prob Model 3-way
    route_2 = np.where(p >= tau_high, 'MALICIOUS', np.where(p <= tau_low, 'BENIGN', 'DEFER'))
    
    # 3. JRR 3-way
    ood = np.load(data_dir / 'jrr_ood_scores.npy')
    diff = np.load(data_dir / 'jrr_difficulty_scores.npy')
    dis = np.load(data_dir / 'model_disagreement.npy')
    
    is_margin = (p > tau_low) & (p < tau_high)
    is_dis = dis >= 0.3
    is_ood = ood < 0
    is_diff = diff >= 6
    has_risk = is_margin | is_dis | is_ood | is_diff
    
    route_3 = np.where(has_risk, 'DEFER', np.where(p >= tau_high, 'MALICIOUS', 'BENIGN'))
    
    # Load CAPA results
    print("Loading CAPA results...")
    capa_preds = {}
    with open(capa_path, 'r', encoding='utf-8') as f:
        for line in f:
            rec = json.loads(line)
            h = rec['sha256']
            # Heuristic: if ttps or mbc are present, flag as malicious
            has_ttp = len(rec.get('ttps', [])) > 0
            has_mbc = len(rec.get('mbc', [])) > 0
            capa_preds[h] = 1 if (has_ttp or has_mbc) else 0
            
    # Map CAPA predictions to rows
    capa_pred_arr = np.zeros(len(df), dtype=int)
    for i, h in enumerate(df['sha256']):
        capa_pred_arr[i] = capa_preds.get(h, 0)
        
    print(f"CAPA base accuracy: {(capa_pred_arr == y).mean():.4f}")
    
    def evaluate_policy(name, route_arr):
        # Base predictions for non-deferred
        final_pred = np.zeros(len(y), dtype=int)
        final_pred[route_arr == 'MALICIOUS'] = 1
        final_pred[route_arr == 'BENIGN'] = 0
        
        # Defer to CAPA
        deferred_mask = (route_arr == 'DEFER')
        final_pred[deferred_mask] = capa_pred_arr[deferred_mask]
        
        acc = (final_pred == y).mean()
        fn = ((y == 1) & (final_pred == 0)).sum()
        fp = ((y == 0) & (final_pred == 1)).sum()
        deferred_cnt = deferred_mask.sum()
        
        print(f"\n--- {name} ---")
        print(f"Accuracy: {acc:.4f}")
        print(f"FN (Missed Malicious): {fn:,}")
        print(f"FP (False Alarms): {fp:,}")
        print(f"Deferred Count: {deferred_cnt:,} ({(deferred_cnt/len(y))*100:.2f}%)")
        
        return acc, fn, fp, deferred_cnt

    evaluate_policy("1. Probability Model (2-way, No Deferral)", np.where(p >= tau_high, 'MALICIOUS', 'BENIGN'))
    evaluate_policy("2. Probability Model (3-way, Margin Deferral)", route_2)
    evaluate_policy("3. JRR (Multi-signal Deferral)", route_3)

if __name__ == "__main__":
    main()
