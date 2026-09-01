import numpy as np

def calculate_ece(y_true, y_prob, n_bins=10):
    """
    [평가 지표 1] ECE (Expected Calibration Error) 계산
    AI의 예측 확률과 실제 정답률 사이의 오차를 측정합니다.
    """
    print(f"[진행] ECE(신뢰도 오차) 계산 중... (구간: {n_bins}개)")
    
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece_score = 0.0
    n_total = len(y_true)
    
    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i+1]
        
        if i == 0:
            in_bin = np.where((y_prob >= bin_lower) & (y_prob <= bin_upper))[0]
        else:
            in_bin = np.where((y_prob > bin_lower) & (y_prob <= bin_upper))[0]
            
        if len(in_bin) > 0:
            bin_accuracy = np.mean(y_true[in_bin])
            bin_confidence = np.mean(y_prob[in_bin])
            bin_weight = len(in_bin) / n_total
            ece_score += bin_weight * np.abs(bin_accuracy - bin_confidence)
            
    return ece_score

def calculate_review_yield(y_true, routes, daily_budget=100):
    """
    [평가 지표 2] Review Yield (검토 가성비) 계산
    심층분석 큐로 빠진 파일들이 분석가의 예산을 낭비하지 않고 얼마나 가치 있었는지 측정합니다.
    """
    print(f"\n[진행] Review Yield (일일 검토 예산: {daily_budget}개) 시뮬레이션 중...")
    
    routes = np.array(routes)
    deep_analysis_idx = np.where(routes == "HIGH_RISK_UNCERTAIN")[0]
    total_routed = len(deep_analysis_idx)
    
    if total_routed == 0:
        print("  [안내] 심층분석 큐로 할당된 파일이 없습니다. (Yield: 0)")
        return 0.0

    if total_routed > daily_budget:
        reviewed_idx = np.random.choice(deep_analysis_idx, daily_budget, replace=False)
        print(f"  [경고] 심층분석 대상({total_routed}개)이 예산을 초과하여 {daily_budget}개만 샘플링 검토합니다.")
    else:
        reviewed_idx = deep_analysis_idx
        print(f"  [안내] 심층분석 대상({total_routed}개) 전량 검토 진행.")

    caught_malware_count = np.sum(y_true[reviewed_idx] == 1)
    yield_score = (caught_malware_count / len(reviewed_idx)) * 100
    
    print(f"  [결과] 분석가 검토 결과: 총 {len(reviewed_idx)}개 검토 중 {caught_malware_count}개의 숨은 악성코드 방어 성공!")
    
    return yield_score

def calculate_true_tpr(y_true, y_prob, threshold):
    """
    [평가 지표 3] Eval 데이터 기준 실측 TPR 및 FPR 계산
    데이터 누수를 방지하기 위해, 평가셋(Eval) 환경에서 도출된 임계값의 진짜 성능을 검증합니다.
    """
    print(f"\n[진행] Eval 데이터 기반 실측 TPR/FPR 검증 중... (임계값: {threshold:.4f})")
    
    predictions = (y_prob >= threshold).astype(int)
    
    false_positives = np.sum((y_true == 0) & (predictions == 1))
    actual_fpr = false_positives / np.sum(y_true == 0)
    
    true_positives = np.sum((y_true == 1) & (predictions == 1))
    actual_tpr = true_positives / np.sum(y_true == 1)
    
    print(f"  [결과] 실측 FPR: {actual_fpr:.4f} / 실측 TPR: {actual_tpr:.4f}")
    
    return actual_fpr, actual_tpr

def run_ood_and_kill_test(y_true, routes, disagreement, threshold=0.3):
    """
    [평가 지표 4, 5 통합] OOD 시뮬레이션 및 Kill Test
    X_eval 데이터 내에서 Disagreement 점수가 높은 샘플들을 OOD로 간주하여,
    1. 이들이 안전하게 HIGH_RISK_UNCERTAIN으로 라우팅되는지(방어율) 확인하고,
    2. 그 중 '정상 파일'들이 'AUTO_MALICIOUS'로 잘못 판정(Kill Test FPR)되지 않았는지 검증합니다.
    """
    print(f"\n[진행] OOD 시뮬레이션 및 Kill Test 가동 중... (Disagreement >= {threshold} 기준)")
    
    ood_indices = np.where(disagreement >= threshold)[0]
    n_ood = len(ood_indices)
    
    if n_ood == 0:
        print("  [경고] 설정한 임계값을 넘는 OOD 샘플이 없습니다.")
        return 0.0, 0.0
        
    ood_routes = np.array(routes)[ood_indices]
    ood_y_true = np.array(y_true)[ood_indices]
    
    # 1. OOD 시뮬레이션 (방어율)
    n_uncertain = np.sum(ood_routes == "HIGH_RISK_UNCERTAIN")
    defense_rate = (n_uncertain / n_ood) * 100
    
    print(f"  [OOD 방어율] 총 OOD {n_ood}개 중 {n_uncertain}개 심층분석 격리 성공 ({defense_rate:.2f}%)")
    
    # 2. Kill Test (OOD 정상 파일 중 악성 오탐율)
    benign_ood_indices = np.where(ood_y_true == 0)[0]
    total_benign_kill_test = len(benign_ood_indices)
    
    if total_benign_kill_test == 0:
         print("  [경고] OOD 데이터 중 정상 파일이 없어 Kill Test FPR을 계산할 수 없습니다.")
         return defense_rate, 0.0
         
    benign_ood_routes = ood_routes[benign_ood_indices]
    false_positives = np.sum(benign_ood_routes == "AUTO_MALICIOUS")
    kill_test_fpr = false_positives / total_benign_kill_test
    
    print(f"  [Kill Test] 극한의 OOD 정상 파일 {total_benign_kill_test}개 주입 완료")
    print(f"  [Kill Test] 오탐(False Positive) 발생 건수: {false_positives}건 / 총 {total_benign_kill_test}개 중")
    print(f"  [Kill Test] 실측 Kill Test FPR: {kill_test_fpr:.4f}")
    
    if kill_test_fpr <= 0.001:
        print("  [방어 성공] Kill Test FPR 0.1% 이하 방어선이 유지되었습니다.")
    else:
        print("  [방어 실패] Kill Test FPR 방어선이 붕괴되었습니다. 임계값 재조정이 필요합니다.")
        
    return defense_rate, kill_test_fpr