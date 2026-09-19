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
    
    output_text = f"""=== 평가 목적 ===
확률만으로 판정할 때와 JRR을 사용할 때,
자동판정 오류와 심층분석 대상이 얼마나 달라지는지 비교합니다.

※ 심층분석 실행 전의 라우팅 평가입니다.
   보류된 파일은 정답으로 처리한 것이 아닙니다.
   아래 미탐·오탐은 자동판정된 파일에서 발생한 오류입니다.

=== 평가 데이터 ===
전체 {n:,}건
- 실제 악성: {n_mal:,}건
- 실제 정상: {n_ben:,}건

=== 비교 정책 ===
① 확률로 바로 판정
   악성 확률 ≥ {tau_high:.6f} → 악성, 나머지 → 정상

② 확률의 애매한 구간만 보류
   악성 확률 ≤ {tau_low} → 정상
   {tau_low} < 악성 확률 < {tau_high:.6f} → 심층분석
   악성 확률 ≥ {tau_high:.6f} → 악성

③ JRR
   ②의 확률 기준에 OOD·모델 불일치·분석 난이도를 추가하여,
   위험 신호가 있으면 자동판정 대신 심층분석으로 전환

=== 자동판정 결과 ===
                               ① 확률 판정   ② 확률 구간 보류   ③ JRR
악성을 정상으로 자동판정          {p1_fn:>7,}건          {p2_fn:>7,}건       {p3_fn:>7,}건
정상을 악성으로 자동판정             {p1_fp:>5,}건            {p2_fp:>5,}건         {p3_fp:>5,}건
심층분석으로 보류                      {p1_deferred:>5,}건         {p2_deferred:>7,}건      {p3_deferred:>7,}건
전체 중 보류 비율                    {(p1_deferred/n*100):>4.2f}%            {(p2_deferred/n*100):>4.2f}%        {(p3_deferred/n*100):>5.2f}%

=== JRR이 추가로 보류시킨 자동판정 오류 ===
[① 확률로 바로 판정하는 방식 대비]
- 악성의 자동 정상 판정 {p1_fn - p3_fn:,}건을 심층분석으로 전환
- 정상의 자동 악성 판정 {p1_fp - p3_fp:,}건을 심층분석으로 전환

[② 확률의 애매한 구간만 보류하는 방식 대비]
- 악성의 자동 정상 판정 {p2_fn - p3_fn:,}건을 추가로 심층분석으로 전환
- 정상의 자동 악성 판정 {p2_fp - p3_fp:,}건을 추가로 심층분석으로 전환
- 심층분석 대상은 {p3_deferred - p2_deferred:,}건 증가: 보류율 {(p2_deferred/n*100):.2f}% → {(p3_deferred/n*100):.2f}%

=== 해석 ===
현재 임계값에서 JRR은 확률 단독 정책보다
잘못된 자동판정을 더 많이 보류시켰습니다.

다만 보류된 {p3_deferred:,}건의 최종 판정은 이 평가에 포함되지 않았습니다.
전체 시스템의 최종 미탐·오탐 감소 여부는 심층분석 후 확인해야 합니다."""
    
    print(output_text)

if __name__ == '__main__':
    main()
