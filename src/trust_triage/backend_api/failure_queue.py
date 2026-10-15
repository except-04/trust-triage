"""Expose each failed analysis in ERROR and retain its deep-review placement."""


def expose_failed_candidate(candidate: dict) -> list[dict]:
    error = candidate.get("error") or {}
    prefix = (
        "심층 분석 실패" if candidate["queue_name"] in {"DEEP", "EMERGENCY"}
        else "분석 실패" if candidate.get("has_initial_result")
        else "초기 분석 실패"
    )
    failure = {
        **candidate,
        "queue_name": "ERROR",
        "queue_reason": f"{prefix}: {error.get('code', 'UNKNOWN_ERROR')}",
        "priority_score": -1.0,
        "deep_priority_score": None,
        "score_policy": "error-v1",
        "priority_reason": prefix,
        "selection_reason": "실패한 분석 이력 확인 필요",
        "emergency_level": None,
        "emergency_obs_level": None,
        "_emergency_level": 99,
        "_emergency_obs_level": 99,
    }
    if candidate["queue_name"] in {"DEEP", "EMERGENCY"}:
        return [candidate, failure]
    return [failure]
