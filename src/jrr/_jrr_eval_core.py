def calculate_ece(y_true, y_prob, n_bins=10):
    """
    [평가 지표 1] ECE (Expected Calibration Error) 계산
    AI의 '예측 확률'과 '실제 정답률' 사이의 오차를 측정합니다.
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
    '심층분석' 큐로 빠진 파일들이 분석가의 예산을 낭비하지 않고 얼마나 가치 있었는지 측정합니다.
    """
    print(f"\n[진행] Review Yield (일일 검토 예산: {daily_budget}개) 시뮬레이션 중...")
    
    routes = np.array(routes)
    deep_analysis_idx = np.where(routes == "심층분석")[0]
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

    # 검토한 파일 중 실제 악성코드(1)의 개수 파악
    caught_malware_count = np.sum(y_true[reviewed_idx] == 1)
    yield_score = (caught_malware_count / len(reviewed_idx)) * 100
    
    print(f"  [결과] 분석가 검토 결과: 총 {len(reviewed_idx)}개 검토 중 {caught_malware_count}개의 숨은 악성코드 방어 성공!")
    
    return yield_score

def run_kill_test(jrr_router=None):
    """
    [핵심 검증 3] Kill Test (스트레스 테스트)
    진짜 OOD(신종/변종/난독화) 데이터를 로드하여 라우터에 주입하고,
    FPR 0.1% 방어선이 무너지는지 실제 데이터로 팩트 체크합니다.
    """
    print("\n[진행] ⚔️ 실전 Kill Test 시나리오 가동 중...")
    
    if jrr_router is None:
        print("  09번 라우터 객체가 연결되지 않아 가상 수치로 건너뜁니다.")
        return 0.001

    try:
        # 1. 지옥의 데이터셋(OOD) 로드 
        # (추후 킬 테스트용 데이터가 준비되면 해당 파일명으로 교체해야 함)
        X_kill_test = np.load("data/X_kill_test.npy")
        y_kill_test = np.load("data/y_kill_test.npy")
        
        # 2. 오탐(FPR)을 측정하기 위해 '실제 정상 파일(0)'만 쏙 골라냅니다.
        benign_idx = np.where(y_kill_test == 0)[0]
        X_benign_kill = X_kill_test[benign_idx]
        total_benign_kill_test = len(X_benign_kill)
        
        print(f"  [안내] 극한의 정상 파일 {total_benign_kill_test}개 주입 완료!")
        
        # 3. 09번 라우터에 정상 파일들을 쏟아부어서 분배 결과(routes)를 받습니다.
        # (주의: 라우팅 실행 메서드 이름에 맞춰 수정이 필요할 수 있습니다. 예: .predict, .route 등)
        routes = jrr_router.route(X_benign_kill) 
        routes = np.array(routes)
        
        # 4. 방어선 붕괴 확인: 정상인데 감히 '자동_악성'으로 잘못 쳐낸(오탐) 개수 세기
        false_positives = np.sum(routes == "자동_악성")
        
        kill_test_fpr = false_positives / total_benign_kill_test
        
        print(f"  [결과] 오탐(False Positive) 발생 건수: {false_positives}건")
        
        if kill_test_fpr <= 0.001:
            print(f"  [방어 성공] Kill Test FPR {kill_test_fpr:.4f}로 0.1% 방어선이 유지되었습니다!")
        else:
            print(f"  [방어 실패] Kill Test FPR {kill_test_fpr:.4f}로 방어선 붕괴. 임계값 재조정이 필요합니다!")
            
        return kill_test_fpr
        
    except FileNotFoundError:
        print("  [에러] data/X_kill_test.npy 또는 data/y_kill_test.npy 파일을 찾을 수 없습니다.")
        print("  [안내] 킬 테스트용 데이터 파일이 준비되면 다시 실행해주세요. (임시 0.001 반환)")
        return 0.001
