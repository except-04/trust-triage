import os
import numpy as np

class JointRiskRouter:
    """
    TRUST-Triage 핵심 엔진: Joint Risk Router (09_jrr_router.py)
    확률값과 Model Disagreement를 바탕으로 3가지 큐로 분기합니다.
    """
    def __init__(self, tau_low=0.1, tau_high=0.9, tau_disagree=0.3):
        self.tau_low = tau_low          # 정상 확신 커트라인 (AUTO_PASS)
        self.tau_high = tau_high        # 악성 확신 커트라인 (AUTO_QUARANTINE)
        self.tau_disagree = tau_disagree # 모델 불일치 허용 기준

    def compute_disagreement(self, p_lgb: float, p_xgb: float) -> float:
        """실시간 추론 시 두 모델 간의 불일치도 계산"""
        return abs(p_lgb - p_xgb)

    def route_sample(self, p_calib: float, disagreement: float) -> dict:
        """단일 파일에 대한 3-Way 분기 판정"""
        # 1. 불일치도가 크면 고확신 오판 방지를 위해 심층 분석으로 격상
        if disagreement >= self.tau_disagree:
            decision = "MANUAL_REVIEW"
            reason = f"High Model Disagreement ({disagreement:.4f})"
        # 2. 확률이 애매한 그레이존인 경우
        elif self.tau_low < p_calib < self.tau_high:
            decision = "MANUAL_REVIEW"
            reason = f"Uncertain Probability ({p_calib:.4f})"
        # 3. 악성 확신도가 매우 높은 경우
        elif p_calib >= self.tau_high:
            decision = "AUTO_QUARANTINE"
            reason = f"High Malicious Confidence ({p_calib:.4f})"
        # 4. 정상 확신도가 매우 높은 경우
        else:
            decision = "AUTO_PASS"
            reason = f"High Benign Confidence ({p_calib:.4f})"

        return {
            "decision": decision,
            "calibrated_prob": round(float(p_calib), 4),
            "disagreement": round(float(disagreement), 4),
            "reason": reason
        }

    def route_batch(self, p_calib_arr, disagreement_arr):
        """48만 건 전체 데이터셋 일괄 라우팅"""
        return [self.route_sample(p, d) for p, d in zip(p_calib_arr, disagreement_arr)]


if __name__ == "__main__":
    DATA_DEV_DIR = os.path.join("data", "out", "dev")
    
    # 1. 데이터 로드
    p_lgb = np.load(os.path.join(DATA_DEV_DIR, "y_pred_proba_calib.npy"))
    disagreement = np.load(os.path.join(DATA_DEV_DIR, "model_disagreement.npy"))
    
    if p_lgb.ndim == 2:
        p_lgb = p_lgb[:, 1]

    print("="*60)
    print("Joint Risk Router (09_jrr_router.py) 실행")
    print("="*60)

    # 2. 라우터 동작
    router = JointRiskRouter(tau_low=0.1, tau_high=0.9, tau_disagree=0.3)
    routed = router.route_batch(p_lgb, disagreement)

    decisions = [r["decision"] for r in routed]
    n_total = len(decisions)
    n_pass = decisions.count("AUTO_PASS")
    n_quar = decisions.count("AUTO_QUARANTINE")
    n_review = decisions.count("MANUAL_REVIEW")

    # 3. 결과 출력
    print(f"총 평가 파일: {n_total:,}건\n")
    print(f"AUTO_PASS (자동 정상 허용)       : {n_pass:>8,}개 ({n_pass/n_total*100:>5.2f}%)")
    print(f"AUTO_QUARANTINE (자동 악성 차단) : {n_quar:>8,}개 ({n_quar/n_total*100:>5.2f}%)")
    print(f"MANUAL_REVIEW (전문가 검토 큐)   : {n_review:>8,}개 ({n_review/n_total*100:>5.2f}%)")
    print("="*60)