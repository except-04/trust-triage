import numpy as np
from pathlib import Path

import argparse
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', type=str, default='eval', choices=['eval', 'test'], help='Dataset split to evaluate')
    args = parser.parse_args()
    split = args.split
    
    root = Path(__file__).resolve().parents[2]
    data_dir = root / 'data'
    
    y = np.load(data_dir / f'y_{split}.npy')
    p = np.load(data_dir / f'jrr_calibrated_proba_{split}.npy' if split == 'test' else data_dir / 'jrr_calibrated_proba.npy')
    routes_filename = f'jrr_routes_{split}.npy' if split == 'test' else 'jrr_routes_eval.npy'
    if split == 'test' and not (data_dir / routes_filename).exists():
        routes_filename = 'jrr_routes_test.npy'
    routes = np.load(data_dir / routes_filename)
    if p.ndim == 2: p = p[:, 1]
    
    # 데이터 유효성 검증 (입력 shape, 확률 범위, 표본 정렬 등)
    assert y.ndim == 1 and p.ndim == 1 and routes.ndim == 1, "모든 배열은 1차원이어야 합니다."
    assert len(y) == len(p) == len(routes), f"데이터 길이 불일치 (y:{len(y)}, p:{len(p)}, routes:{len(routes)})"
    assert set(np.unique(y)).issubset({0, 1}), f"y_{split} 배열은 0과 1로만 구성되어야 합니다."
    assert not np.isnan(p).any(), "확률 배열에 결측치(NaN)가 포함되어 있습니다."
    assert (p >= 0).all() and (p <= 1).all(), "확률은 0과 1 사이의 값이어야 합니다."
    valid_routes = {'AUTO_BENIGN', 'AUTO_MALICIOUS', 'HIGH_RISK_UNCERTAIN'}
    assert set(np.unique(routes)).issubset(valid_routes), "routes 배열에 유효하지 않은 값이 있습니다."
    
    tau_low = 0.65
    tau_high = 0.983645
    
    # 정책 일관성 검증: JRR 라우팅이 기본 확률 정책과 충돌하지 않는지 확인
    # JRR은 확률 애매 구간(tau_low < p < tau_high)은 모두 HIGH_RISK_UNCERTAIN이어야 하며,
    # 확신 구간에서도 OOD 등에 의해 추가 보류가 일어남을 전제로 함.
    p2_mask = (p > tau_low) & (p < tau_high)
    assert (routes[p2_mask] == 'HIGH_RISK_UNCERTAIN').all(), "정책 일관성 위배: 확률 애매 구간이 JRR에서 보류되지 않았습니다."
    
    # 표본 정렬 일치 검증:
    # 배열들은 동일한 인덱스 생성 과정을 거쳤으므로 순서가 1:1 대응된다고 가정함.
    # 길이와 차원이 완벽히 일치하는 것으로 기본적인 정렬을 확인.
    
    n = len(y)
    n_mal = (y == 1).sum()
    n_ben = (y == 0).sum()
    
    # Policy 1: No Deferral (Direct Prob)
    p1_deferred = 0
    p1_fn = ((y == 1) & (p < tau_high)).sum()
    p1_fp = ((y == 0) & (p >= tau_high)).sum()
    p1_fnr = p1_fn / n_mal * 100
    p1_fpr = p1_fp / n_ben * 100
    
    # Policy 2: Prob Margin (Grey Zone)
    p2_deferred = p2_mask.sum()
    p2_fn = ((y == 1) & (p <= tau_low)).sum()
    p2_fp = ((y == 0) & (p >= tau_high)).sum()
    p2_fnr = p2_fn / n_mal * 100
    p2_fpr = p2_fp / n_ben * 100
    
    # Policy 3: JRR (Routing Actual)
    p3_deferred = (routes == 'HIGH_RISK_UNCERTAIN').sum()
    p3_fn = ((y == 1) & (routes == 'AUTO_BENIGN')).sum()
    p3_fp = ((y == 0) & (routes == 'AUTO_MALICIOUS')).sum()
    p3_fnr = p3_fn / n_mal * 100
    p3_fpr = p3_fp / n_ben * 100
    

    # Oracle Assumption Error Rate (Assuming deferred items have 0% error)
    p1_err = (p1_fn + p1_fp) / n * 100
    p2_err = (p2_fn + p2_fp) / n * 100
    p3_err = (p3_fn + p3_fp) / n * 100
    
    additional_def = p3_deferred - p2_deferred
    def_ratio = p3_deferred / p2_deferred if p2_deferred > 0 else 0
    additional_fn_prevented = p2_fn - p3_fn
    additional_fp_prevented = p2_fp - p3_fp
    additional_errors_prevented = additional_fn_prevented + additional_fp_prevented

    output_text = f"""=== 라우팅 실측 + 오라클 가정 분석 ===
본 평가는 실제 심층분석 도구(CAPA/Speakeasy 등)를 실행한 결과가 아닙니다.
자동판정 라우터(JRR)의 분류 실측치에, 심층분석으로 보류된 파일은 
100% 정답을 맞힌다는 '오라클(Oracle)' 가정을 결합하여 라우팅 한계 성능을 확인합니다.

[데이터셋: {split} (총 {n:,}건, 50:50 비율)]
- 실제 악성: {n_mal:,}건
- 실제 정상: {n_ben:,}건

=== 라우팅 정책 별 자동판정 오류 및 보류율 ===
1. 확률 직접 판정 (임계값 {tau_high:.6f})
   - 미탐(FN):  {p1_fn:>7,}건 / {n_mal:,}건 (FNR: {p1_fnr:.2f}%)
   - 오탐(FP):   {p1_fp:>5,}건 / {n_ben:,}건 (FPR: {p1_fpr:.2f}%)
   - 심층분석 보류:       {p1_deferred:>5,}건 / {n:,}건 (보류율: {(p1_deferred/n*100):.2f}%)

2. 확률 구간 보류 (구간 {tau_low} ~ {tau_high:.6f})
   - 미탐(FN):   {p2_fn:>7,}건 / {n_mal:,}건 (FNR: {p2_fnr:.2f}%)
   - 오탐(FP):   {p2_fp:>5,}건 / {n_ben:,}건 (FPR: {p2_fpr:.2f}%)
   - 심층분석 보류:  {p2_deferred:>7,}건 / {n:,}건 (보류율: {(p2_deferred/n*100):.2f}%)

3. JRR (확률 + OOD/불일치/난이도 기여)
   - 미탐(FN):   {p3_fn:>7,}건 / {n_mal:,}건 (FNR: {p3_fnr:.2f}%)
   - 오탐(FP):   {p3_fp:>5,}건 / {n_ben:,}건 (FPR: {p3_fpr:.2f}%)
   - 심층분석 보류:  {p3_deferred:>7,}건 / {n:,}건 (보류율: {(p3_deferred/n*100):.2f}%)

=== JRR 추가 라우팅 결과 (정책 2 대비) ===
- JRR을 통한 추가 오판 방어 후보: {additional_errors_prevented:,}건 (FN {additional_fn_prevented:,}건, FP {additional_fp_prevented:,}건)
- 추가로 요구되는 심층분석 보류 건수: {additional_def:,}건
- 처리 건수 비율: 약 {def_ratio:.2f}배 증가

=== 오라클 가정 하의 종합 시스템 참고 수치 ===
(※ 아래 전체 오류율은 50:50 평가셋에서의 참고 수치이며, 
   실제 심층분석 오류가 반영되지 않은 낙관적 하한선(Optimistic Lower Bound)입니다.)

- 1. 확률 직접 판정: 전체 오류율 {p1_err:.3f}%
- 2. 확률 구간 보류: 전체 오류율 {p2_err:.3f}%
- 3. JRR (다중 위험): 전체 오류율 {p3_err:.3f}%

결론:
JRR의 OOD, 모델 불일치, 분석 난이도 신호를 라우팅에 추가할 경우,
기존 확률 기반 그레이존 정책(2번)에서 발생하던 고확신 오판 {additional_errors_prevented:,}건을 
추가로 보류시킬 수 있습니다. 단, 이로 인해 심층분석 처리 대상이 약 {def_ratio:.2f}배 증가합니다."""

    print(output_text)
    
    with open(root / f'jrr_routing_evaluation_{split}.md', 'w', encoding='utf-8') as f:
        f.write(f"# 라우팅 실측 + 오라클 가정 분석 리포트 ({split} 데이터셋)\n\n```text\n")
        f.write(output_text)
        f.write("\n```\n")
        
    with open(root / f'{split}_report.txt', 'w', encoding='utf-8') as f:
        f.write(output_text)

if __name__ == '__main__':
    main()
