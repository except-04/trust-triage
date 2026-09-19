import numpy as np
from pathlib import Path

def main():
    root = Path(__file__).resolve().parents[2]
    data_dir = root / 'data'
    
    y = np.load(data_dir / 'y_eval.npy')
    p = np.load(data_dir / 'jrr_calibrated_proba.npy')
    routes = np.load(data_dir / 'jrr_routes.npy')
    if p.ndim == 2: p = p[:, 1]
    
    # 데이터 유효성 검증
    assert len(y) == len(p) == len(routes), "데이터 배열들의 길이가 일치하지 않습니다."
    assert set(np.unique(y)).issubset({0, 1}), "y_eval 배열은 0과 1로만 구성되어야 합니다."
    assert not np.isnan(p).any(), "확률 배열에 결측치(NaN)가 포함되어 있습니다."
    valid_routes = {'FINAL', 'AUTO_BENIGN', 'AUTO_MALICIOUS', 'HIGH_RISK_UNCERTAIN'}
    assert set(np.unique(routes)).issubset(valid_routes), "routes 배열에 유효하지 않은 값이 있습니다."
    
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
    
    n = len(y)
    n_mal = (y == 1).sum()
    n_ben = (y == 0).sum()
    r_ben = (routes == 'AUTO_BENIGN').sum()
    r_mal = (routes == 'AUTO_MALICIOUS').sum()
    r_unc = (routes == 'HIGH_RISK_UNCERTAIN').sum()
    
    print("=== 데이터 개요 ===")
    print(f"총 평가 데이터: {n:,}건 (악성 {n_mal:,}건, 정상 {n_ben:,}건)")
    print(f"[JRR 라우팅 분배 비율 (Policy 3 기준)]")
    print(f"  AUTO_BENIGN (자동 정상): {r_ben:,}건 ({(r_ben/n*100):.2f}%)")
    print(f"  AUTO_MALICIOUS (자동 악성): {r_mal:,}건 ({(r_mal/n*100):.2f}%)")
    print(f"  HIGH_RISK_UNCERTAIN (심층분석 보류): {r_unc:,}건 ({(r_unc/n*100):.2f}%)\n")
    
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
