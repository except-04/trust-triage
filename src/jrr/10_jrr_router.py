import os
import numpy as np

class JointRiskRouter:
    """
    TRUST-Triage 핵심 엔진: Joint Risk Router (10_jrr_router.py)
    확률값과 Model Disagreement를 바탕으로 3가지 큐로 분기합니다.
    """
    def __init__(self, tau_low=0.00, tau_high=0.9, tau_disagree=0.3):
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
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"High Model Disagreement ({disagreement:.4f})"
        # 2. 확률이 애매한 그레이존인 경우
        elif self.tau_low < p_calib < self.tau_high:
            decision = "HIGH_RISK_UNCERTAIN"
            reason = f"Uncertain Probability ({p_calib:.4f})"
        # 3. 악성 확신도가 매우 높은 경우
        elif p_calib >= self.tau_high:
            decision = "AUTO_MALICIOUS"
            reason = f"High Malicious Confidence ({p_calib:.4f})"
        # 4. 정상 확신도가 매우 높은 경우
        else:
            decision = "AUTO_BENIGN"
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
    DATA_DIR = os.path.join("data")
    
    # 1. 데이터 로드
    p_lgb = np.load(os.path.join(DATA_DIR, "y_pred_proba_calib.npy"))
    disagreement = np.load(os.path.join(DATA_DIR, "model_disagreement.npy"))
    
    if p_lgb.ndim == 2:
        p_lgb = p_lgb[:, 1]

    print("="*60)
    print("Joint Risk Router (10_jrr_router.py) 실행")
    print("="*60)

    # 2. 라우터 동작
    router = JointRiskRouter(tau_low=0.00, tau_high=0.9, tau_disagree=0.3)
    routed = router.route_batch(p_lgb, disagreement)

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

    np.save("data/jrr_routes.npy", np.array(decisions))