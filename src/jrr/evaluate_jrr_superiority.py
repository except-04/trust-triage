import numpy as np
from pathlib import Path

def main():
    root = Path(__file__).resolve().parents[1]
    data_dir = root / 'data'
    
    # 데이터 로드
    y = np.load(data_dir / 'y_eval.npy')
    p = np.load(data_dir / 'jrr_calibrated_proba.npy')
    routes = np.load(data_dir / 'jrr_routes.npy')
    
    if p.ndim == 2: 
        p = p[:, 1]
    
    tau_low = 0.65
    tau_high = 0.983645
    
    # Policy 1: No Deferral (단순 확률 판정)
    p1_deferred = 0
    p1_fn = ((y == 1) & (p < tau_high)).sum()
    p1_fp = ((y == 0) & (p >= tau_high)).sum()
    
    # Policy 2: Prob Margin (확률 애매 구간만 보류)
    p2_mask = (p > tau_low) & (p < tau_high)
    p2_deferred = p2_mask.sum()
    p2_fn = ((y == 1) & (p <= tau_low)).sum()
    p2_fp = ((y == 0) & (p >= tau_high)).sum()
    
    # Policy 3: JRR (다중 신호 적용)
    p3_deferred = (routes == 'HIGH_RISK_UNCERTAIN').sum()
    p3_fn = ((y == 1) & (routes == 'AUTO_BENIGN')).sum()
    p3_fp = ((y == 0) & (routes == 'AUTO_MALICIOUS')).sum()
    
    n = len(y)
    
    # 마크다운 아티팩트 생성
    md_content = f"""# JRR 자동판정 오류 감소 및 보류율 비교

> [!TIP]
> JRR이 단순히 확률의 애매한 구간을 보류하는 것과 비교하여, 다중 신호(OOD, 불일치, 난이도)를 통해 자동판정 오류를 얼마나 심층분석 대상으로 추가 확보하는지 명확히 구분하기 위한 3단계 비교입니다.

## 평가 결과 비교
| 비교 항목 | ① 단순 확률 판정 (보류 없음) | ② 확률 애매 구간만 보류 (Prob Margin) | ③ 현재 JRR (다중 신호 적용) |
| :--- | :--- | :--- | :--- |
| **자동 정상 오판 (미탐, FN)** | {p1_fn:,}건 | {p2_fn:,}건 | **{p3_fn:,}건** |
| **자동 악성 오판 (오탐, FP)** | {p1_fp:,}건 | {p2_fp:,}건 | **{p3_fp:,}건** |
| **심층분석 보류 (Deferral)** | {p1_deferred:,}건 ({p1_deferred/n*100:.2f}%) | {p2_deferred:,}건 ({p2_deferred/n*100:.2f}%) | {p3_deferred:,}건 ({p3_deferred/n*100:.2f}%) |

## 인사이트
1. **단순 보류의 효과 (① -> ②)**: 확률의 애매한 구간($0.65 < p < 0.983$)만 보류해도, 전체 데이터의 {(p2_deferred/n)*100:.2f}%를 심층분석으로 보내며 자동판정 미탐(FN)을 {p1_fn:,}건에서 {p2_fn:,}건으로 대폭 줄입니다.
2. **JRR 다중 신호의 추가 확보 효과 (② -> ③)**: JRR은 여기에 OOD, 불일치도, 난이도를 추가하여 {(p3_deferred/n)*100:.2f}%를 보류합니다. 그 결과 **단순 보류(②) 정책 대비 악성의 자동 정상 판정 {p2_fn - p3_fn:,}건과 정상의 자동 악성 판정 {p2_fp - p3_fp:,}건을 추가로 방지하고 심층분석 대상으로 확보**했습니다.
3. **결론**: 추가 위험 신호 적용을 통해 보류율은 {(p2_deferred/n)*100:.2f}%에서 {(p3_deferred/n)*100:.2f}%로 증가하지만, 그만큼 AI 모델의 근본적인 맹점에서 발생하는 자동판정 오류를 심층분석 큐로 안전하게 전환하는 효과가 있음을 보여줍니다.
"""
    output_path = Path(__file__).parent / 'jrr_superiority_report.md'
    output_path.write_text(md_content, encoding='utf-8')
    print(f"\n보고서가 생성되었습니다: {output_path}")

if __name__ == '__main__':
    main()
