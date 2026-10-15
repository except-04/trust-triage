from trust_triage.backend_api.queue_grouping import group_candidates


def item(identity, queue="DEEP", policy="uncertainty-v2", day=1, score=.8):
    return dict(analysis_id=identity, sha256="a" * 64, queue_name=queue,
                score_policy=policy, priority_score=score, calibrated_probability=score,
                created_at=f"2026-10-{day:02}T00:00:00+00:00")


def test_priority_wins_over_recency_and_error_is_independent():
    emergency = item("urgent", "EMERGENCY", day=1)
    emergency.update(emergency_level=1, emergency_obs_level=1)
    risk = item("risk", day=2)
    failure = item("failed", "ERROR", day=3)
    history = {"a" * 64: [dict(x, status="FAILED" if x is failure else "COMPLETED")
                             for x in [emergency, risk, failure]]}
    result = group_candidates([risk, failure, emergency], history)
    assert {x["analysis_id"] for x in result} == {"urgent", "failed"}
    assert all(x["analysis_count"] == 3 and x["failure_count"] == 1 for x in result)
    assert all(len(x["analysis_history"]) == 3 for x in result)


def test_signal_priority_then_score_then_latest_and_preserves_jrr_history():
    rows = [item("old", day=1), item("new", day=2),
            item("jrr", policy="jrr-inconsistent-v1", day=3)]
    history = {"a" * 64: [dict(x, reason_code="JRR_RESULT_INCONSISTENT" if x["analysis_id"] == "jrr" else None) for x in rows]}
    result = group_candidates(rows, history)
    assert len(result) == 1
    assert result[0]["analysis_id"] == "new"
    assert result[0]["jrr_error_count"] == 1
    rows[0]["priority_score"] = rows[0]["calibrated_probability"] = .9
    assert group_candidates(rows, history)[0]["analysis_id"] == "old"
