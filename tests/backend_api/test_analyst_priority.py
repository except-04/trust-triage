from zoneinfo import ZoneInfo

import pytest

from tests.backend_api.fake_repository import MemoryAnalysisRepository
from trust_triage.backend_api.repository import AnalysisRecord


@pytest.mark.parametrize("repository_kind", ["postgres", "memory"])
@pytest.mark.parametrize("reviewed", [False, True])
def test_failed_analyses_are_not_hidden_by_same_hash_success(repository_kind, reviewed):
    from datetime import datetime, timezone
    from unittest.mock import MagicMock
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    rows = [{
        "analysis_id": identity, "filename": "same.exe", "sha256": "a" * 64,
        "created_at": datetime(2026, 10, 15, hour, tzinfo=timezone.utc),
        "status": "COMPLETED" if identity == "success" else "FAILED",
        "initial_result": {"prediction": {"calibrated_probability": 0.1}, "initial_verdict": "AUTO_BENIGN"} if identity == "success" else None,
        "error": None if identity == "success" else {"code": "PROCESSING_FAILED"},
    } for identity, hour in [("success", 3), ("failure-two", 2), ("failure-one", 1)]]
    if repository_kind == "postgres":
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = rows[1:] if reviewed else rows
        repo = object.__new__(PostgresAnalysisRepository)
        repo._connection = MagicMock()
        repo._connection.return_value.__enter__.return_value = connection
    else:
        repo = MemoryAnalysisRepository()
        for row in rows:
            repo.rows[row["analysis_id"]] = AnalysisRecord(
                **{key: row[key] for key in ("analysis_id", "filename", "sha256", "status", "initial_result", "error")},
                file_location="local", size_bytes=100, created_at=row["created_at"].isoformat(),
            )
        if reviewed:
            repo.reviews["success-review"] = {"analysis_id": "success", "review_status": "COMPLETED"}
    result = repo.get_priority_recommendations()
    assert {item["analysis_id"] for item in result if item["queue_name"] == "ERROR"} == {"failure-one", "failure-two"}
    if not reviewed:
        assert {item["analysis_id"] for item in result if item["queue_name"] == "AUTO"} == {"success"}
    if repository_kind == "postgres":
        assert cursor.execute.call_args.args[0].count("a.status = 'FAILED' OR NOT EXISTS") == 2


def test_deep_failure_is_present_in_both_deep_and_error():
    repo = MemoryAnalysisRepository()
    repo.rows["deep-failure"] = AnalysisRecord(
        analysis_id="deep-failure", filename="deep.exe", sha256="b" * 64,
        file_location="local", size_bytes=100, status="FAILED",
        created_at="2026-10-15T00:00:00+09:00",
        initial_result={"initial_verdict": "HIGH_RISK_UNCERTAIN", "prediction": {"calibrated_probability": 0.8}, "triggered_signals": ["UNCERTAIN_PROBABILITY"]},
        error={"code": "DEEP_REQUIRES_S3"},
    )
    result = repo.get_priority_recommendations()
    assert {item["queue_name"] for item in result} == {"DEEP", "ERROR"}
    assert all(item["analysis_id"] == "deep-failure" for item in result)
    assert all(item["has_initial_result"] for item in result)


@pytest.mark.parametrize("repository_kind", ["postgres", "memory"])
def test_error_queue_is_ordered_by_latest_registration(repository_kind):
    from datetime import datetime, timezone
    from unittest.mock import MagicMock
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    rows = [{
        "analysis_id": identity, "filename": f"{identity}.exe", "sha256": str(hour) * 64,
        "initial_result": None, "status": "FAILED", "error": {"code": "PROCESSING_FAILED"},
        "created_at": datetime(2026, 10, 15, hour, tzinfo=timezone.utc),
    } for identity, hour in [("old", 1), ("new", 3), ("middle", 2)]]
    if repository_kind == "postgres":
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchall.return_value = rows
        repo = object.__new__(PostgresAnalysisRepository)
        repo._connection = MagicMock()
        repo._connection.return_value.__enter__.return_value = connection
    else:
        repo = MemoryAnalysisRepository()
        for row in rows:
            repo.rows[row["analysis_id"]] = AnalysisRecord(
                **{key: row[key] for key in ("analysis_id", "filename", "sha256", "initial_result", "status", "error")},
                file_location="local", size_bytes=100, created_at=row["created_at"].isoformat(),
            )
    result = repo.get_priority_recommendations()
    assert [item["analysis_id"] for item in result] == ["new", "middle", "old"]
    assert [item["rank"] for item in result] == [1, 2, 3]








@pytest.mark.parametrize("signals", [None, []])
@pytest.mark.parametrize("repository_kind", ["postgres", "memory"])
def test_uncertain_verdict_without_signals_is_deep(signals, repository_kind):
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    repository = (
        object.__new__(PostgresAnalysisRepository)
        if repository_kind == "postgres"
        else MemoryAnalysisRepository()
    )
    result = repository._determine_queue(
        0.8, "HIGH_RISK_UNCERTAIN", signals or [], {}, {}
    )
    assert result["queue_name"] == "DEEP"
    assert result["score_policy"] == "jrr-inconsistent-v1"
    assert result["priority_reason"] == "초기 판정 불일치"


@pytest.mark.parametrize("repository_kind", ["postgres", "memory"])
def test_explicit_fail_closed_without_probability_is_deep(repository_kind):
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    repo = (object.__new__(PostgresAnalysisRepository)
            if repository_kind == "postgres" else MemoryAnalysisRepository())
    result = repo._determine_queue(
        -1.0, "HIGH_RISK_UNCERTAIN", [], {"ood_score": None}, {},
        reason_code="SYSTEM_ERROR_FAIL_CLOSED",
    )
    assert result["queue_name"] == "DEEP"
    assert result["score_policy"] == "fail-closed-v1"
    assert result["priority_score"] == 0.0


def test_postgres_query_includes_failed_rows_without_initial_result():
    from datetime import datetime, timezone
    from unittest.mock import MagicMock
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    cursor = MagicMock()
    cursor.fetchall.return_value = [{
        "analysis_id": "early-failure", "filename": "failed.exe", "sha256": "a" * 64,
        "initial_result": None, "status": "FAILED",
        "error": {"code": "JRR_OUTPUT_INVALID", "stage": "JRR"},
        "created_at": datetime.now(timezone.utc),
    }]
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    repo = object.__new__(PostgresAnalysisRepository)
    repo._connection = MagicMock()
    repo._connection.return_value.__enter__.return_value = connection
    candidates = repo.get_priority_recommendations()
    assert "OR a.status = 'FAILED'" in cursor.execute.call_args.args[0]
    assert candidates[0]["queue_name"] == "ERROR"
    assert candidates[0]["initial_verdict"] is None
    assert candidates[0]["error"]["code"] == "JRR_OUTPUT_INVALID"


def test_uncertainty_queue_orders_by_malicious_probability_then_fifo():
    from datetime import datetime, timezone
    from unittest.mock import MagicMock

    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    rows = []
    for index, (analysis_id, probability, hour) in enumerate([
        ("p7784", 0.7784, 0),
        ("p7933", 0.7933, 0),
        ("p8416", 0.8416, 0),
        ("high-new", 0.8525, 2),
        ("high-old", 0.8525, 1),
    ]):
        rows.append({
            "analysis_id": analysis_id,
            "sha256": f"{index:064x}",
            "filename": f"{analysis_id}.exe",
            "initial_result": {
                "initial_verdict": "HIGH_RISK_UNCERTAIN",
                "prediction": {"calibrated_probability": probability},
                "triggered_signals": ["UNCERTAIN_PROBABILITY"],
            },
            "created_at": datetime(2026, 10, 13, hour, tzinfo=timezone.utc),
        })
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = rows
    repo = object.__new__(PostgresAnalysisRepository)
    repo._connection = MagicMock()
    repo._connection.return_value.__enter__.return_value = connection

    result = repo.get_priority_recommendations()
    assert [item["analysis_id"] for item in result] == [
        "high-old", "high-new", "p8416", "p7933", "p7784",
    ]
    assert [item["rank"] for item in result] == [1, 2, 3, 4, 5]


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

    # Inconsistent JRR records are deep candidates; missing probability is ERROR.
    assert recs[0]["analysis_id"] == "test-1"  # 00:00
    assert recs[1]["analysis_id"] == "test-3"  # 00:30
    assert recs[2]["analysis_id"] == "test-2"  # 01:00
    assert (
        recs[3]["analysis_id"] == "test-5"
    )

    assert recs[0]["rank"] == 1
    assert recs[1]["rank"] == 2
    assert recs[2]["rank"] == 3
    assert all(item["queue_name"] == "DEEP" for item in recs[:3])
    assert all(item["score_policy"] == "jrr-inconsistent-v1" for item in recs[:3])
    assert recs[3]["queue_name"] == "ERROR"


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

    # Add pending review - should remain in candidates
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
    assert recs[0]["review_status"] == "검토 중"

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
    assert recs[0]["review_status"] == "검토 중"

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


def test_auto_review_does_not_deduct_budget_and_no_waiting_restriction():
    repo = MemoryAnalysisRepository()
    repo.set_daily_budget(2)

    now_seoul = repo.now.astimezone(ZoneInfo("Asia/Seoul"))
    # DEEP 검토 1건 완료 -> completed 1, remaining 1
    repo.reviews["rev_deep"] = {
        "analysis_id": "test-deep-done",
        "review_status": "COMPLETED",
        "review_queue": "DEEP",
        "reviewed_at": now_seoul.isoformat(),
    }
    b1 = repo.get_budget_config()
    assert b1["today_completed_count"] == 1
    assert b1["remaining_budget"] == 1

    # AUTO 검토 1건 완료 -> completed 2, remaining 1 (AUTO는 예산을 차감하지 않음)
    repo.reviews["rev_auto"] = {
        "analysis_id": "test-auto-done",
        "review_status": "COMPLETED",
        "review_queue": "AUTO",
        "reviewed_at": now_seoul.isoformat(),
    }
    b2 = repo.get_budget_config()
    assert b2["today_completed_count"] == 2
    assert b2["remaining_budget"] == 1

    # 후보 2건 추가
    repo.rows["cand-em"] = AnalysisRecord(
        analysis_id="cand-em",
        sha256="2" * 64,
        file_location="loc-em",
        filename="em.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.99},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "capa",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                }
            ]
        },
        created_at="2026-10-04T00:00:00+00:00",
    )
    repo.rows["cand-deep"] = AnalysisRecord(
        analysis_id="cand-deep",
        sha256="3" * 64,
        file_location="loc-deep",
        filename="deep.exe",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.75},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
            "triggered_signals": ["UNCERTAIN_PROBABILITY"],
        },
        created_at="2026-10-04T00:00:00+00:00",
    )

    from pathlib import Path
    from trust_triage.backend_api.config import BackendConfig
    from trust_triage.backend_api.service import BackendService
    from trust_triage.backend_api.storage import LocalSampleStorage

    svc = BackendService(repo, LocalSampleStorage(Path(".")), BackendConfig())
    res = svc.get_priority_recommendations()

    # 예산 제한이 없으므로 대기열(waiting)로 밀리지 않고 모두 recommendations에 할당
    assert len(res["emergency_recommendations"]) == 1
    assert len(res["deep_recommendations"]) == 1
    assert len(res["emergency_waiting"]) == 0
    assert len(res["deep_waiting"]) == 0
    # 파일 생성 시각(created_at)이 제거되지 않고 유지되는지 확인
    assert res["emergency_recommendations"][0]["created_at"] is not None
    assert res["deep_recommendations"][0]["created_at"] is not None
    # 심층 분석 위험 신호 점수(deep_priority_score)가 산출되어 전달되는지 확인 (위험 신호 부재 시 0.0)
    assert res["emergency_recommendations"][0]["deep_priority_score"] == 0.0
