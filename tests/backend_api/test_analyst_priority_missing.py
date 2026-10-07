from tests.backend_api.fake_repository import MemoryAnalysisRepository
from trust_triage.backend_api.repository import AnalysisRecord


def test_missing_probability_handling():
    repo = MemoryAnalysisRepository()
    # Good
    repo.rows["good"] = AnalysisRecord(
        analysis_id="good",
        sha256="1111",
        file_location="loc1",
        filename="good.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.5},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T00:00:00+00:00",
    )
    # Missing prob
    repo.rows["missing"] = AnalysisRecord(
        analysis_id="missing",
        sha256="2222",
        file_location="loc2",
        filename="missing.exe",
        size_bytes=100,
        initial_result={"other_field": True},
        created_at="2026-10-04T00:00:00+00:00",
    )
    # Invalid prob
    repo.rows["invalid"] = AnalysisRecord(
        analysis_id="invalid",
        sha256="3333",
        file_location="loc3",
        filename="invalid.exe",
        size_bytes=100,
        initial_result={"prediction": {"calibrated_probability": "not_a_number"}},
        created_at="2026-10-04T00:00:00+00:00",
    )

    recs = repo.get_priority_recommendations()
    assert len(recs) == 3
    assert recs[0]["analysis_id"] == "good"

    missing_cands = [r for r in recs if r["analysis_id"] in ("missing", "invalid")]
    assert len(missing_cands) == 2
    for c in missing_cands:
        assert c["priority_score"] == -1.0
        assert "확률" in c["selection_reason"]
