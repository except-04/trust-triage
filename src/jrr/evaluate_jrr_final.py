import numpy as np
from pathlib import Path
import json
import hashlib
import time
from datetime import datetime
from sklearn.metrics import roc_auc_score, brier_score_loss, confusion_matrix

def compute_ece(y_true, y_prob, n_bins=10):
    bins = np.linspace(0., 1., n_bins + 1)
    binids = np.digitize(y_prob, bins) - 1
    
    ece = 0.0
    for i in range(n_bins):
        bin_idx = binids == i
        if np.sum(bin_idx) > 0:
            prob_mean = np.mean(y_prob[bin_idx])
            acc_mean = np.mean(y_true[bin_idx])
            ece += np.abs(prob_mean - acc_mean) * (np.sum(bin_idx) / len(y_true))
    return ece

def get_file_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()

def main():
    root = Path(__file__).resolve().parents[2]
    data_dir = root / 'data'
    
    # 1. Data Loading & Validation
    y_path = data_dir / 'y_eval.npy'
    p_path = data_dir / 'jrr_calibrated_proba.npy'
    routes_path = data_dir / 'jrr_routes.npy'
    
    y = np.load(y_path)
    p = np.load(p_path)
    routes = np.load(routes_path)
    ood = np.load(data_dir / 'jrr_ood_scores.npy')
    diff = np.load(data_dir / 'jrr_difficulty_scores.npy')
    dis = np.load(data_dir / 'model_disagreement.npy')
    
    if p.ndim == 2: p = p[:, 1]
    
    n = len(y)
    assert len(p) == n and len(routes) == n and len(ood) == n and len(diff) == n and len(dis) == n, "Array lengths mismatch"
    assert set(np.unique(y)).issubset({0, 1}), "y must be 0 or 1"
    assert not np.isnan(p).any(), "NaN in probabilities"
    
    n_mal = (y == 1).sum()
    n_ben = (y == 0).sum()
    
    # 2. Metric Calculation (Prob Model Performance)
    auc = roc_auc_score(y, p)
    brier = brier_score_loss(y, p)
    ece = compute_ece(y, p)
    
    tau_low = 0.65
    tau_high = 0.983645
    
    pred_high = (p >= tau_high).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred_high).ravel()
    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    
    # 3. Routing Recreation
    p1_fn = ((y == 1) & (p < tau_high)).sum()
    p1_fp = ((y == 0) & (p >= tau_high)).sum()
    p1_def = 0
    
    is_margin = (p > tau_low) & (p < tau_high)
    p2_fn = ((y == 1) & (p <= tau_low)).sum()
    p2_fp = ((y == 0) & (p >= tau_high)).sum()
    p2_def = is_margin.sum()
    
    is_dis = dis >= 0.3
    is_ood = ood < 0
    is_diff = diff >= 6
    
    has_risk = is_margin | is_dis | is_ood | is_diff
    
    recreated_routes = np.where(
        has_risk, 'HIGH_RISK_UNCERTAIN',
        np.where(p >= tau_high, 'AUTO_MALICIOUS', 'AUTO_BENIGN')
    )
    
    # 4. Exact Match Verification
    match_rate = (recreated_routes == routes).mean()
    if match_rate != 1.0:
        print(f"WARNING: Recreated routes do not exactly match stored routes! Match rate: {match_rate:.4f}")
        assert False, f"Row-by-row exact match failed. Match rate: {match_rate:.4f}"
    
    p3_fn = ((y == 1) & (recreated_routes == 'AUTO_BENIGN')).sum()
    p3_fp = ((y == 0) & (recreated_routes == 'AUTO_MALICIOUS')).sum()
    p3_def = (recreated_routes == 'HIGH_RISK_UNCERTAIN').sum()
    
    # 5. Signal Breakdown
    signals = {
        '확률 구간': is_margin,
        'OOD': is_ood,
        '모델 불일치': is_dis,
        '분석 난이도': is_diff
    }
    
    breakdown = {}
    for name, mask in signals.items():
        breakdown[name] = {
            'n_flagged': int(mask.sum()),
            'n_mal': int((mask & (y == 1)).sum()),
            'n_ben': int((mask & (y == 0)).sum()),
            'saved_fn': int((mask & (y == 1) & (p <= tau_low)).sum()),
            'saved_fp': int((mask & (y == 0) & (p >= tau_high)).sum())
        }
        
    bitmask = is_margin.astype(int)*8 + is_ood.astype(int)*4 + is_dis.astype(int)*2 + is_diff.astype(int)*1
    comb_results = {}
    for val in range(1, 16):
        cnt = (bitmask == val).sum()
        if cnt > 0:
            names = []
            if val & 8: names.append('확률 구간')
            if val & 4: names.append('OOD')
            if val & 2: names.append('모델 불일치')
            if val & 1: names.append('분석 난이도')
            comb_results['+'.join(names)] = int(cnt)
            
    # 6. Ablation (Leave-one-out)
    ablation = {}
    for name, _ in signals.items():
        other_masks = [m for n, m in signals.items() if n != name]
        new_risk = np.logical_or.reduce(other_masks)
        abl_routes = np.where(
            new_risk, 'HIGH_RISK_UNCERTAIN',
            np.where(p >= tau_high, 'AUTO_MALICIOUS', 'AUTO_BENIGN')
        )
        ablation[name] = {
            'fn': int(((y == 1) & (abl_routes == 'AUTO_BENIGN')).sum()),
            'fp': int(((y == 0) & (abl_routes == 'AUTO_MALICIOUS')).sum()),
            'def': int((abl_routes == 'HIGH_RISK_UNCERTAIN').sum())
        }
        
    # Output JSON
    output_data = {
        'metadata': {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'n_total': int(n), 'n_mal': int(n_mal), 'n_ben': int(n_ben),
            'hashes': {
                'y_eval': get_file_hash(y_path),
                'proba': get_file_hash(p_path)
            },
            'thresholds': {'tau_low': tau_low, 'tau_high': tau_high, 'dis': 0.3, 'ood': 0, 'diff': 6}
        },
        'model_performance': {
            'auc': float(auc), 'brier': float(brier), 'ece': float(ece),
            'tpr_high': float(tpr), 'fpr_high': float(fpr)
        },
        'policy_comparison': {
            'p1': {'fn': int(p1_fn), 'fp': int(p1_fp), 'def': int(p1_def)},
            'p2': {'fn': int(p2_fn), 'fp': int(p2_fp), 'def': int(p2_def)},
            'p3': {'fn': int(p3_fn), 'fp': int(p3_fp), 'def': int(p3_def)},
            'match_rate': float(match_rate)
        },
        'signal_breakdown': breakdown,
        'combinations': comb_results,
        'ablation': ablation
    }
    
    with open(Path(__file__).parent / 'jrr_final_metrics.json', 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
        
    # Output Markdown
    md = f"""# JRR Final Evaluation & Signal Breakdown

> [!WARNING]
> **평가 한계점 (Limitation)**
> 본 보고서는 이미 모델 개발 및 임계값 튜닝에 사용된 Eval 세트에서의 고정 정책 평가입니다. 따라서 완전히 독립적인 검증 데이터(Test set)에서의 성능을 대변하지 않으며, 보류된 파일들의 실제 동적 심층분석 후 '최종 탐지 성능'을 담고 있지 않습니다. 본 평가는 오직 "JRR이 심층분석 전에 자동판정 오류를 얼마나 안전하게 보류(Deferral)시켰는가"에 집중합니다.

## 1. 평가 개요 및 데이터 확인
* **실행 시각**: {output_data['metadata']['timestamp']}
* **전체 데이터**: {n:,}건 (악성 {n_mal:,}건, 정상 {n_ben:,}건)
* **재현 정보**: 배열 길이 일치({n}건), 결측치 없음 확인 완료.
  * 기존 라우팅(`routes.npy`)과의 일치율: **{match_rate*100:.4f}%**
* **임계값 (Fixed Policy)**:
  * 확률 구간: {tau_low} < p < {tau_high:.6f}
  * OOD: < 0
  * 불일치도: >= 0.3
  * 분석 난이도: >= 6

## 2. 확률 모델 단독 성능
확률값(`p`)만을 기준으로 한 분류기 자체의 통계적 성능입니다.
* **ROC-AUC**: {auc:.4f}
* **Brier Score**: {brier:.4f}
* **ECE (10-bin)**: {ece:.4f}
* 고정 임계값({tau_high:.6f}) 기준: TPR {tpr:.4f} / FPR {fpr:.6f}

## 3. 정책 비교
| 정책 | 자동 정상 오판 (FN) | 자동 악성 오판 (FP) | 심층분석 보류 (Deferral) |
| :--- | :--- | :--- | :--- |
| ① 확률 직접 판정 | {p1_fn:,}건 | {p1_fp:,}건 | {p1_def:,}건 (0.00%) |
| ② 확률 구간 보류 | {p2_fn:,}건 | {p2_fp:,}건 | {p2_def:,}건 ({(p2_def/n)*100:.2f}%) |
| **③ JRR (다중 신호)** | **{p3_fn:,}건** | **{p3_fp:,}건** | **{p3_def:,}건 ({(p3_def/n)*100:.2f}%)** |

## 4. 위험 신호별 분해 (Breakdown)
각 신호가 독립적으로 감지한 전체 파일 수와, 그 중에서 **"단순 확률 정책이었으면 오판했을 오류를 심층분석으로 구출해 낸(방지한) 건수"**입니다.
(한 파일이 여러 신호에 중복으로 걸릴 수 있으므로, 합계는 전체 보류량과 다릅니다.)

| 신호 (Signal) | 해당 파일 수 | 악성 | 정상 | 자동 정상 오판을 보류시킨 악성 (Saved FN) | 자동 악성 오판을 보류시킨 정상 (Saved FP) |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for k, v in breakdown.items():
        md += f"| {k} | {v['n_flagged']:,} | {v['n_mal']:,} | {v['n_ben']:,} | {v['saved_fn']:,} | {v['saved_fp']:,} |\n"
        
    md += """
## 5. 신호 조합별 보류 건수 (Mutually Exclusive)
동시에 여러 신호에 걸린 교집합 내역입니다. (총합은 JRR 전체 보류 건수인 {p3_def:,}건과 일치합니다.)
```text
"""
    for k, v in sorted(comb_results.items(), key=lambda x: -x[1]):
        md += f"{k}: {v:,}건\n"
        
    md += """```

## 6. 신호 제거 비교 (Ablation Study)
현재 JRR에서 **해당 신호 딱 하나만 뺐을 때** 자동판정 오류와 보류율이 어떻게 변하는지 확인합니다. (임계값은 재조정하지 않음)
특정 신호를 뺐을 때 FN/FP가 크게 늘어난다면, 그 신호가 대체 불가능한 맹점을 방어하고 있다는 뜻입니다.

| 제거한 신호 | 미탐 (FN) | 오탐 (FP) | 보류 건수 | FN 증가량 | FP 증가량 |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for k, v in ablation.items():
        fn_diff = v['fn'] - p3_fn
        fp_diff = v['fp'] - p3_fp
        md += f"| {k} 제외 | {v['fn']:,} | {v['fp']:,} | {v['def']:,} ({(v['def']/n)*100:.2f}%) | +{fn_diff:,} | +{fp_diff:,} |\n"
        
    with open(Path(__file__).parent / 'jrr_final_report.md', 'w', encoding='utf-8') as f:
        f.write(md)
        
    print("평가 스크립트 실행 완료. jrr_final_report.md 및 jrr_final_metrics.json 생성됨.")

if __name__ == '__main__':
    main()
