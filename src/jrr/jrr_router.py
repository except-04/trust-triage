import os
import numpy as np

class JointRiskRouter:
    """
    TRUST-Triage 핵심 엔진: Joint Risk Router (jrr_router.py)
    확률값과 Model Disagreement, OOD Score, Analysis Difficulty를 바탕으로 3가지 큐로 분기합니다.
    """
    def __init__(self, tau_low=0.60, tau_high=0.983645, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=1.0):
        self.tau_low = tau_low          # 정상 확신 커트라인 (AUTO_BENIGN / Calibration 최적화 확정: 0.60)
        self.tau_high = tau_high        # 악성 확신 커트라인 (AUTO_MALICIOUS / FPR 0.1% 고정선: 0.983645)
        self.tau_disagree = tau_disagree # 모델 불일치 허용 기준 (고정값 0.3)
        self.tau_ood = tau_ood          # OOD 점수(Isolation Forest) 임계값 (0 미만 이상치)
        self.tau_difficulty = tau_difficulty # 분석 난이도(PEFormatWarnings 합산) 임계값

    def compute_disagreement(self, p_lgb: float, p_xgb: float) -> float:
        """실시간 추론 시 두 모델 간의 불일치도 계산"""
        return abs(p_lgb - p_xgb)

    def route_sample(self, p_calib: float, disagreement: float, ood_score: float, difficulty_score: float) -> dict:
        """단일 파일에 대한 3-Way 분기 판정"""
        
        if np.isnan(p_calib) or np.isnan(disagreement) or np.isnan(ood_score) or np.isnan(difficulty_score):
            return {
                "decision": "HIGH_RISK_UNCERTAIN",
                "calibrated_prob": -1.0,
                "disagreement": -1.0,
                "ood_score": 0.0,
                "difficulty_score": 0.0,
                "reason": "System Error: NaN values detected (Fail-Closed)"
            }
            
        # 1. OOD Score가 낮으면(학습 분포를 벗어남) 심층 분석으로 격상
        if ood_score < self.tau_ood:
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"OOD Detected (Score: {ood_score:.4f})"
        # 2. 불일치도가 크면 고확신 오판 방지를 위해 심층 분석으로 격상
        elif disagreement >= self.tau_disagree:
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"High Model Disagreement ({disagreement:.4f})"
        # 3. 분석 난이도가 높으면(PE 파싱 경고 등) 심층 분석으로 격상
        elif difficulty_score >= self.tau_difficulty:
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"High Analysis Difficulty (Score: {difficulty_score:.1f})"
        # 4. 확률이 애매한 그레이존인 경우
        elif self.tau_low < p_calib < self.tau_high:
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"Uncertain Probability ({p_calib:.4f})"
        # 5. 악성 확신도가 매우 높은 경우
        elif p_calib >= self.tau_high:
            decision = "AUTO_MALICIOUS"
            reason = f"High Malicious Confidence ({p_calib:.4f})"
        # 6. 정상 확신도가 매우 높은 경우
        else:
            decision = "AUTO_BENIGN"
            reason = f"High Benign Confidence ({p_calib:.4f})"

        return {
            "decision": decision,
            "calibrated_prob": round(float(p_calib), 4),
            "disagreement": round(float(disagreement), 4),
            "ood_score": round(float(ood_score), 4),
            "difficulty_score": round(float(difficulty_score), 4),
            "reason": reason
        }

    def route_batch(self, p_calib_arr, disagreement_arr, ood_score_arr, difficulty_score_arr):
        """48만 건 전체 데이터셋 일괄 라우팅"""
        return [self.route_sample(p, d, o, diff) for p, d, o, diff in zip(p_calib_arr, disagreement_arr, ood_score_arr, difficulty_score_arr)]


if __name__ == "__main__":
    import joblib
    DATA_DIR = os.path.join("data")
    
    # 1. 데이터 로드 (Eval 평가 데이터셋)
    p_eval = np.load(os.path.join(DATA_DIR, "jrr_calibrated_proba.npy"))
    disagreement = np.load(os.path.join(DATA_DIR, "model_disagreement.npy"))
    
    if p_eval.ndim == 2:
        p_eval = p_eval[:, 1]
    if disagreement.ndim == 2:
        disagreement = disagreement[:, 1]

    # 1.5 OOD Score 및 Analysis Difficulty 산출
    print("위험 신호(OOD, Difficulty) 계산을 위해 모델과 데이터를 로드 중...")
    risk_signals = joblib.load(os.path.join(DATA_DIR, 'jrr_risk_signals.pkl'))
    ood_model = risk_signals['ood_model']
    difficulty_indices = risk_signals['difficulty_indices']
    
    top_500_idx = np.load(os.path.join(DATA_DIR, 'top_feature_indices_500.npy'))
    X_eval_raw = np.load(os.path.join(DATA_DIR, 'X_eval.npy'), mmap_mode='r')
    X_eval_500 = X_eval_raw[:, top_500_idx]
    
    print("OOD Score (Isolation Forest) 산출 중... (시간이 다소 소요될 수 있습니다)")
    ood_scores = ood_model.decision_function(X_eval_500)
    np.save(os.path.join(DATA_DIR, 'jrr_ood_scores.npy'), ood_scores)
    
    print("Analysis Difficulty Score 산출 중...")
    # PEFormatWarnings 피처들의 값을 합산하여 난이도 점수로 사용
    difficulty_scores = np.sum(X_eval_500[:, difficulty_indices], axis=1)
    np.save(os.path.join(DATA_DIR, 'jrr_difficulty_scores.npy'), difficulty_scores)
    print("[저장 완료] data/jrr_ood_scores.npy 및 jrr_difficulty_scores.npy 생성 성공!")

    print("="*60)
    print("Joint Risk Router (jrr_router.py) 실행")
    print("="*60)

    # 2. 라우터 동작 (tau_high=0.983645, tau_disagree=0.3 고정, tau_low=0.60, tau_ood=0.0, tau_difficulty=1.0)
    router = JointRiskRouter(tau_low=0.60, tau_high=0.983645, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=1.0)
    routed = router.route_batch(p_eval, disagreement, ood_scores, difficulty_scores)

    decisions = [r["decision"] for r in routed]
    n_total = len(decisions)
    n_benign = decisions.count("AUTO_BENIGN")
    n_malicious = decisions.count("AUTO_MALICIOUS")
    n_uncertain = decisions.count("HIGH_RISK_UNCERTAIN")

    # 3. 결과 출력
    print(f"총 평가 파일: {n_total:,}건\n")
    print(f"AUTO_BENIGN (자동 정상)        : {n_benign:>8,}개 ({n_benign/n_total*100:>5.2f}%)")
    print(f"AUTO_MALICIOUS (자동 악성)     : {n_malicious:>8,}개 ({n_malicious/n_total*100:>5.2f}%)")
    print(f"HIGH_RISK_UNCERTAIN (심층 분석): {n_uncertain:>8,}개 ({n_uncertain/n_total*100:>5.2f}%)")
    print("="*60)

    np.save(os.path.join(DATA_DIR, "jrr_routes.npy"), np.array(decisions))
    print("[저장 완료] data/jrr_routes.npy 생성 성공!")