from zoneinfo import ZoneInfo

from tests.backend_api.fake_repository import MemoryAnalysisRepository
from trust_triage.backend_api.repository import AnalysisRecord


def test_analyst_priority_recommendations():
    repo = MemoryAnalysisRepository()

    # 1. Add some initial candidates
    repo.rows["test-1"] = AnalysisRecord(
        analysis_id="test-1",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        file_location="loc1",
        filename="test1.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.8},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T00:00:00+00:00",
    )
    repo.rows["test-2"] = AnalysisRecord(
        analysis_id="test-2",
        sha256="2222222222222222222222222222222222222222222222222222222222222222",
        file_location="loc2",
        filename="test2.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.9},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T01:00:00+00:00",
    )
    repo.rows["test-3"] = AnalysisRecord(
        analysis_id="test-3",
        sha256="3333333333333333333333333333333333333333333333333333333333333333",
        file_location="loc3",
        filename="test3.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.9},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T00:30:00+00:00",
    )
    # Exclude because it's already reviewed
    repo.rows["test-4"] = AnalysisRecord(
        analysis_id="test-4",
        sha256="4444444444444444444444444444444444444444444444444444444444444444",
        file_location="loc4",
        filename="test4.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.95},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        analyst_final_verdict="MALICIOUS",
        review_revision=1,
        created_at="2026-10-04T00:30:00+00:00",
    )
    repo.reviews['rev-test-4'] = {
        'analysis_id': 'test-4',
        'review_status': 'COMPLETED',
        'reviewed_at': '2026-10-04T00:35:00+00:00'
    }
    # Include as error candidate due to missing probability
    repo.rows["test-5"] = AnalysisRecord(
        analysis_id="test-5",
        sha256="5555555555555555555555555555555555555555555555555555555555555555",
        file_location="loc5",
        filename="test5.exe",
        size_bytes=100,
        initial_result={"other_data": "none"},
        created_at="2026-10-04T00:30:00+00:00",
    )


    recs = repo.get_priority_recommendations()
    assert len(recs) == 4

    # Check sorting: exception-v2 policy, priority_score is 0.0 for all, created_at ASC
    assert recs[0]["analysis_id"] == "test-1"  # 00:00
    assert recs[1]["analysis_id"] == "test-3"  # 00:30
    assert recs[2]["analysis_id"] == "test-2"  # 01:00
    assert (
        recs[3]["analysis_id"] == "test-5"
    )  # 00:30 but missing probability -> ERROR queue (error-v1, rank 99)

    assert recs[0]["rank"] == 1
    assert recs[1]["rank"] == 2
    assert recs[2]["rank"] == 3


def test_budget_logic():
    repo = MemoryAnalysisRepository()
    repo.set_daily_budget(2)

    # Simulate some completed reviews today
    now_seoul = repo.now.astimezone(ZoneInfo("Asia/Seoul"))
    repo.reviews["rev1"] = {
        "analysis_id": "test-done",
        "review_status": "COMPLETED",
        "reviewed_at": now_seoul.isoformat(),
    }

    budget = repo.get_budget_config()
    assert budget["daily_budget"] == 2
    assert budget["today_completed_count"] == 1
    assert budget["remaining_budget"] == 1

    # Add pending review - should exclude from candidates
    repo.rows["test-pending"] = AnalysisRecord(
        analysis_id="test-pending",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        file_location="loc1",
        filename="test-pending.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.8},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T00:00:00+00:00",
    )
    repo.reviews["rev2"] = {
        "analysis_id": "test-pending",
        "review_status": "PENDING",
        "reviewed_at": now_seoul.isoformat(),
    }

    recs = repo.get_priority_recommendations()
    assert len(recs) == 1  # Included despite pending review
    assert recs[0]["analysis_id"] == "test-pending"
    assert recs[0]["review_status"] == "검토 보류"

def test_pending_review_lifecycle():
    repo = MemoryAnalysisRepository()
    repo.set_daily_budget(100)

    # 초기 데이터 삽입
    repo.rows["test-lifecycle"] = AnalysisRecord(
        analysis_id="test-lifecycle",
        sha256="6666666666666666666666666666666666666666666666666666666666666666",
        file_location="loc6",
        filename="test6.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.9},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        created_at="2026-10-04T00:00:00+00:00",
        status="COMPLETED",
        phase="DONE",
        completed_at="2026-10-04T00:10:00+00:00",
    )

    budget_init = repo.get_budget_config()
    completed_count_init = budget_init["today_completed_count"]

    # 1. save_review() 로 보류(PENDING) 저장
    repo.save_review(
        analysis_id="test-lifecycle",
        expected_revision=0,
        reviewer_id="tester",
        analyst_notes="Needs more time",
        analyst_final_verdict=None
    )

    # 추천 유지 검증
    recs = repo.get_priority_recommendations()
    assert len(recs) == 1
    assert recs[0]["analysis_id"] == "test-lifecycle"
    assert recs[0]["review_status"] == "검토 보류"

    # 예산 불변 검증
    budget_pending = repo.get_budget_config()
    assert budget_pending["today_completed_count"] == completed_count_init

    # 2. save_review() 로 최종 완료(COMPLETED) 저장
    repo.save_review(
        analysis_id="test-lifecycle",
        expected_revision=1,
        reviewer_id="tester",
        analyst_notes="Finalize",
        analyst_final_verdict="MALICIOUS"
    )

    # 추천 제외 검증
    recs_final = repo.get_priority_recommendations()
    assert len(recs_final) == 0

    # 최초 완료량 증가 검증
    budget_final = repo.get_budget_config()
    assert budget_final["today_completed_count"] == completed_count_init + 1
