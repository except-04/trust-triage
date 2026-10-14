"""Preserve inconsistent JRR decisions while routing the job to deep analysis."""

from copy import deepcopy


def recover_jrr_inconsistency(value: dict) -> dict:
    if value.get("reason_code") in {
        "SYSTEM_ERROR_FAIL_CLOSED", "JRR_RESULT_INCONSISTENT"
    }:
        return value
    verdict = value.get("initial_verdict")
    signals = value.get("triggered_signals")
    expected_route = "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL"
    if (
        signals is not None
        and (verdict == "HIGH_RISK_UNCERTAIN") == bool(signals)
        and value.get("route") == expected_route
    ):
        return value
    return {
        **value,
        "initial_verdict": "HIGH_RISK_UNCERTAIN",
        "route": "DEEP_ANALYSIS",
        "triggered_signals": [],
        "reason_code": "JRR_RESULT_INCONSISTENT",
        "reason": "초기 판정과 위험 신호 또는 처리 경로가 불일치하여 심층 분석으로 추가 확인합니다.",
        "jrr_error": {
            "code": "JRR_RESULT_INCONSISTENT",
            "message": "초기 JRR 판정의 일관성 검증에 실패했습니다. 분석가 검토가 필요합니다.",
            "original_verdict": verdict,
            "original_route": value.get("route"),
            "original_triggered_signals": deepcopy(signals),
            "original_reason": value.get("reason"),
        },
    }
