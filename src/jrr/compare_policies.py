import numpy as np
from pathlib import Path

def main():
    root = Path(__file__).resolve().parents[1]
    data_dir = root / 'data'
    
    y = np.load(data_dir / 'y_eval.npy')
    p = np.load(data_dir / 'jrr_calibrated_proba.npy')
    routes = np.load(data_dir / 'jrr_routes.npy')
    if p.ndim == 2: p = p[:, 1]
    
    tau_low = 0.65
    tau_high = 0.983645
    
    # Policy 1: No Deferral (Direct Prob)
    p1_deferred = 0
    p1_fn = ((y == 1) & (p < tau_high)).sum()
    p1_fp = ((y == 0) & (p >= tau_high)).sum()
    
    # Policy 2: Prob Margin (Grey Zone)
    p2_mask = (p > tau_low) & (p < tau_high)
    p2_deferred = p2_mask.sum()
    p2_fn = ((y == 1) & (p <= tau_low)).sum()
    p2_fp = ((y == 0) & (p >= tau_high)).sum()
    
    # Policy 3: JRR
    p3_deferred = (routes == 'HIGH_RISK_UNCERTAIN').sum()
    p3_fn = ((y == 1) & (routes == 'AUTO_BENIGN')).sum()
    p3_fp = ((y == 0) & (routes == 'AUTO_MALICIOUS')).sum()
    
    print("=== 비교 분석 ===")
    print(f"[Policy 1: No Deferral]")
    print(f"FN (미탐): {p1_fn:,}")
    print(f"FP (오탐): {p1_fp:,}")
    print(f"보류(심층분석): {p1_deferred:,} ({(p1_deferred/len(y)*100):.2f}%)")
    
    print(f"\n[Policy 2: Prob Margin]")
    print(f"FN (미탐): {p2_fn:,}")
    print(f"FP (오탐): {p2_fp:,}")
    print(f"보류(심층분석): {p2_deferred:,} ({(p2_deferred/len(y)*100):.2f}%)")
    
    print(f"\n[Policy 3: JRR]")
    print(f"FN (미탐): {p3_fn:,}")
    print(f"FP (오탐): {p3_fp:,}")
    print(f"보류(심층분석): {p3_deferred:,} ({(p3_deferred/len(y)*100):.2f}%)")

if __name__ == '__main__':
    main()
