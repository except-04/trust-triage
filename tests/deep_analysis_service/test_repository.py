"""Request contracts and isolated PostgreSQL deep-analysis persistence tests."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.deep_analysis.models import DeepAnalysisResult, DeepAnalysisStatus
from trust_triage.deep_analysis.service_models import (
    DeepAnalysisPhase,
    DeepAnalysisRecord,
    DeepAnalysisRequest,
)
from trust_triage.deep_analysis.service_repository import PostgresDeepAnalysisRepository
from trust_triage.speakeasy_worker.errors import RetryableError
from trust_triage.speakeasy_worker.models import InvalidJob, JobConflict, failure_result

FINGERPRINT = "config-test-v1"


@pytest.fixture
def analysis_request():
    return DeepAnalysisRequest(
        analysis_id="analysis-001",
        sha256="a" * 64,
        file_location="s3://worker-test-bucket/raw/analysis-001/sample.bin",
        initial_route="HIGH_RISK_UNCERTAIN",
        initial_verdict="UNKNOWN",
        requested_at="2026-09-08T19:00:00+09:00",
    )


def _checkpoint(analysis_request):
    return {
        "schema_version": "deep-checkpoint-v1",
        "static": {
            "sha256": analysis_request.sha256,
            "initial_route": analysis_request.initial_route,
            "initial_verdict": analysis_request.initial_verdict,
            "config_fingerprint": FINGERPRINT,
            "evidence": [{"summary": "persisted static observation"}],
            "tool_statuses": {"CAPA": "SUCCESS", "FLOSS": "SUCCESS"},
            "tool_results": {},
        },
        "worker_result": None,
    }


def _result(analysis_request, status=DeepAnalysisStatus.COMPLETE):
    return DeepAnalysisResult(
        sha256=analysis_request.sha256,
        deep_analysis_status=status,
        initial_route=analysis_request.initial_route,
        initial_verdict=analysis_request.initial_verdict,
    ).to_dict()


def test_request_normalization_and_worker_contract(analysis_request):
    normalized = replace(
        analysis_request,
        sha256=analysis_request.sha256.upper(),
        initial_route="deep_analysis",
        initial_verdict="benign",
    )
    assert normalized.sha256 == analysis_request.sha256
    assert normalized.initial_route == "DEEP_ANALYSIS"
    assert normalized.initial_verdict == "BENIGN"
    assert normalized.requested_at == "2026-09-08T10:00:00+00:00"
    assert normalized.worker_job.requested_stage == "SPEAKEASY"
    assert DeepAnalysisRequest.from_json(json.dumps(normalized.to_dict())) == normalized
    assert normalized.same_input(
        replace(normalized, requested_at="2026-09-09T00:00:00Z")
    )
    assert not normalized.same_input(replace(normalized, initial_verdict="UNKNOWN"))


def test_request_optional_defaults(analysis_request):
    payload = analysis_request.to_dict()
    del payload["initial_verdict"]
    del payload["requested_at"]
    restored = DeepAnalysisRequest.from_json(json.dumps(payload))
    assert restored.initial_verdict == "UNKNOWN"
    assert restored.worker_job.requested_at


@pytest.mark.parametrize(
    "field,value",
    [
        ("analysis_id", "../sample"),
        ("sha256", "invalid"),
        ("file_location", "https://example.invalid/sample.exe"),
        ("initial_route", "심층분석"),
        ("initial_route", "route with spaces"),
        ("initial_route", ""),
        ("initial_route", "é"),
        ("initial_route", 12),
        ("initial_verdict", "ALLOW"),
        ("initial_verdict", None),
        ("requested_at", "2026-09-08T00:00:00"),
    ],
)
def test_request_rejects_invalid_fields(analysis_request, field, value):
    with pytest.raises(InvalidJob):
        replace(analysis_request, **{field: value})


@pytest.mark.parametrize("body", ["{}", "[]", "{", "NaN", '"' + "x" * 17000 + '"'])
def test_request_rejects_invalid_json(body):
    with pytest.raises(InvalidJob):
        DeepAnalysisRequest.from_json(body)


def test_request_rejects_unknown_duplicate_and_nonfinite_fields(analysis_request):
    encoded = json.dumps(analysis_request.to_dict())
    for body in (
        encoded[:-1] + ', "analysis_id": "other"}',
        encoded[:-1] + ', "requested_stage": "SPEAKEASY"}',
        encoded.replace('"UNKNOWN"', "NaN"),
    ):
        with pytest.raises(InvalidJob):
            DeepAnalysisRequest.from_json(body)


def test_record_response_hides_internal_location_and_checkpoint(analysis_request):
    record = DeepAnalysisRecord(analysis_request, FINGERPRINT)
    assert record.to_dict()["status"] == "QUEUED"
    assert replace(record, claimed=True).to_dict()["status"] == "RUNNING"
    waiting = replace(
        record,
        phase=DeepAnalysisPhase.WAITING_SPEAKEASY,
        checkpoint=_checkpoint(analysis_request),
    )
    assert waiting.to_dict()["status"] == "RUNNING"
    assert "file_location" not in waiting.to_dict()
    assert "checkpoint" not in waiting.to_dict()
    for phase in (
        DeepAnalysisPhase.COMPLETED,
        DeepAnalysisPhase.FAILED,
        DeepAnalysisPhase.NOT_REQUIRED,
    ):
        assert phase.terminal
        assert replace(record, phase=phase).to_dict()["status"] == phase.value


@pytest.fixture
def database():
    dsn = os.getenv("WORKER_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set WORKER_TEST_DATABASE_URL to run PostgreSQL integration tests")
    prefix = "deep_service_test_"
    schema = prefix + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_dsn = make_conninfo(dsn, options=f"-c search_path={schema}")
    repository = PostgresDeepAnalysisRepository(scoped_dsn)
    try:
        repository.initialize()
        yield repository, scoped_dsn
    finally:
        assert schema.startswith(prefix) and len(schema) == len(prefix) + 32
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def _expire(dsn, analysis_id):
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE deep_analysis_runs SET lease_until = now() - interval '1 second' WHERE analysis_id = %s",
            (analysis_id,),
        )


def _has_cancellation_check(dsn):
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            """SELECT 1 FROM pg_constraint
               WHERE conrelid = 'deep_analysis_runs'::regclass
                 AND conname = 'deep_analysis_runs_cancellation_object_check'"""
        ).fetchone() is not None


@pytest.mark.postgres
def test_cancellation_check_is_added_to_new_and_upgraded_tables(
    database, analysis_request
):
    repository, dsn = database
    assert _has_cancellation_check(dsn)
    repository.register(analysis_request, FINGERPRINT)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "ALTER TABLE deep_analysis_runs "
            "DROP CONSTRAINT deep_analysis_runs_cancellation_object_check"
        )
    assert not _has_cancellation_check(dsn)

    repository.initialize()
    repository.initialize()
    assert _has_cancellation_check(dsn)
    for invalid_json in ("[]", '"text"', "0"):
        with pytest.raises(psycopg.errors.CheckViolation), psycopg.connect(dsn) as connection:
            connection.execute(
                "UPDATE deep_analysis_runs SET cancellation = %s::jsonb "
                "WHERE analysis_id = %s",
                (invalid_json, analysis_request.analysis_id),
            )


@pytest.mark.postgres
def test_cancellation_migration_rejects_preexisting_invalid_data(
    database, analysis_request
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "ALTER TABLE deep_analysis_runs "
            "DROP CONSTRAINT deep_analysis_runs_cancellation_object_check"
        )
        connection.execute(
            "UPDATE deep_analysis_runs SET cancellation = '[]'::jsonb "
            "WHERE analysis_id = %s",
            (analysis_request.analysis_id,),
        )

    with pytest.raises(RetryableError):
        repository.initialize()
    assert not _has_cancellation_check(dsn)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE deep_analysis_runs SET cancellation = NULL WHERE analysis_id = %s",
            (analysis_request.analysis_id,),
        )
    repository.initialize()
    assert _has_cancellation_check(dsn)


@pytest.mark.postgres
def test_initialize_registration_and_reconnect_are_idempotent(
    database, analysis_request
):
    repository, dsn = database
    original = repository.register(analysis_request, FINGERPRINT)
    repository.initialize()
    repository.check()
    again = repository.register(
        replace(analysis_request, requested_at="2026-09-10T00:00:00Z"), FINGERPRINT
    )
    restored = PostgresDeepAnalysisRepository(dsn).get(analysis_request.analysis_id)
    assert restored == again == original
    assert restored.request == analysis_request
    assert restored.phase is DeepAnalysisPhase.STATIC
    assert restored.to_dict()["status"] == "QUEUED"
    assert repository.get("missing") is None
    with pytest.raises(ValueError, match="not registered"):
        repository.claim("missing", 180)


@pytest.mark.postgres
@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "f" * 64),
        ("file_location", "s3://worker-test-bucket/other.bin"),
        ("initial_route", "DEEP_STATIC"),
        ("initial_verdict", "MALICIOUS"),
    ],
)
def test_registration_rejects_different_input(database, analysis_request, field, value):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    with pytest.raises(JobConflict):
        repository.register(replace(analysis_request, **{field: value}), FINGERPRINT)
    assert repository.get(analysis_request.analysis_id).request == analysis_request


@pytest.mark.postgres
def test_registration_rejects_changed_config(database, analysis_request):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    with pytest.raises(JobConflict):
        repository.register(analysis_request, "different-config")
    assert (
        repository.get(analysis_request.analysis_id).config_fingerprint == FINGERPRINT
    )


@pytest.mark.postgres
def test_concurrent_claims_have_one_owner(database, analysis_request):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(
            pool.map(
                lambda _: PostgresDeepAnalysisRepository(dsn).claim(
                    analysis_request.analysis_id, 180
                ),
                range(4),
            )
        )
    assert sum(claim.token is not None for claim in claims) == 1
    assert repository.get(analysis_request.analysis_id).attempts == 1
    assert repository.get(analysis_request.analysis_id).claimed


@pytest.mark.postgres
def test_expired_owner_is_fenced_for_every_update_and_can_be_reclaimed(
    database, analysis_request
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    previous = repository.claim(analysis_request.analysis_id, 180)
    _expire(dsn, analysis_request.analysis_id)
    assert not repository.get(analysis_request.analysis_id).claimed
    assert not repository.renew(analysis_request.analysis_id, previous.token, 180)
    assert not repository.save_checkpoint(
        analysis_request.analysis_id,
        previous.token,
        _checkpoint(analysis_request),
        DeepAnalysisPhase.WAITING_SPEAKEASY,
    )
    assert not repository.finish(
        analysis_request.analysis_id, previous.token, _result(analysis_request)
    )
    assert not repository.release(analysis_request.analysis_id, previous.token)
    current = repository.claim(analysis_request.analysis_id, 180)
    assert current.token and current.token != previous.token
    assert current.record.attempts == 2
    assert not repository.release(
        analysis_request.analysis_id, previous.token, {"code": "OLD"}
    )
    assert repository.renew(analysis_request.analysis_id, current.token, 180)
    assert repository.finish(
        analysis_request.analysis_id, current.token, _result(analysis_request)
    )


@pytest.mark.postgres
def test_durable_cancellation_fences_owner_and_finishes_after_lease_expiry(
    database, analysis_request
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    previous = repository.claim(analysis_request.analysis_id, 180)
    reason = {"code": "PARENT_TIMEOUT", "message": "parent deadline expired"}

    requested = repository.request_cancel(analysis_request.analysis_id, reason)

    assert requested.cancellation == reason
    assert requested.claimed
    assert not repository.renew(analysis_request.analysis_id, previous.token, 180)
    assert not repository.finish(
        analysis_request.analysis_id, previous.token, _result(analysis_request)
    )
    assert repository.pending_ids() == []
    _expire(dsn, analysis_request.analysis_id)
    assert repository.pending_ids() == [analysis_request.analysis_id]
    current = repository.claim(analysis_request.analysis_id, 180)
    assert current.token and current.token != previous.token
    failed = _result(analysis_request, DeepAnalysisStatus.FAILED)
    assert repository.finish_cancelled(
        analysis_request.analysis_id, current.token, failed
    )
    saved = repository.get(analysis_request.analysis_id)
    assert saved.phase is DeepAnalysisPhase.FAILED
    assert saved.cancellation == reason
    assert saved.result == failed


@pytest.mark.postgres
def test_checkpoint_survives_restart_release_and_resume(database, analysis_request):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    checkpoint = _checkpoint(analysis_request)
    assert repository.save_checkpoint(
        analysis_request.analysis_id,
        claim.token,
        checkpoint,
        DeepAnalysisPhase.WAITING_SPEAKEASY,
    )
    assert repository.release(
        analysis_request.analysis_id, claim.token, {"code": "SQS_UNAVAILABLE"}
    )
    resumed_repository = PostgresDeepAnalysisRepository(dsn)
    restored = resumed_repository.get(analysis_request.analysis_id)
    assert restored.checkpoint == checkpoint
    assert restored.last_error == {"code": "SQS_UNAVAILABLE"}
    assert restored.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert not restored.claimed
    resumed = resumed_repository.claim(analysis_request.analysis_id, 180)
    checkpoint["worker_result"] = failure_result(
        analysis_request.worker_job, "TIMEOUT", "test failure"
    )
    assert resumed_repository.save_checkpoint(
        analysis_request.analysis_id,
        resumed.token,
        checkpoint,
        DeepAnalysisPhase.FINALIZING,
    )
    assert not resumed_repository.save_checkpoint(
        analysis_request.analysis_id,
        resumed.token,
        _checkpoint(analysis_request),
        DeepAnalysisPhase.WAITING_SPEAKEASY,
    )
    assert resumed_repository.get(analysis_request.analysis_id).last_error is None
    assert resumed_repository.get(analysis_request.analysis_id).checkpoint == checkpoint
    assert resumed_repository.get(analysis_request.analysis_id).claimed


@pytest.mark.postgres
@pytest.mark.parametrize(
    "field", ["sha256", "initial_route", "initial_verdict", "config_fingerprint"]
)
def test_sql_rejects_checkpoint_identity_mismatch(database, analysis_request, field):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    checkpoint = _checkpoint(analysis_request)
    checkpoint["static"][field] = "other"
    with pytest.raises(RetryableError) as error:
        repository.save_checkpoint(
            analysis_request.analysis_id,
            claim.token,
            checkpoint,
            DeepAnalysisPhase.WAITING_SPEAKEASY,
        )
    assert isinstance(error.value.__cause__, psycopg.errors.CheckViolation)
    assert repository.get(analysis_request.analysis_id).checkpoint is None
    assert (
        repository.get(analysis_request.analysis_id).phase is DeepAnalysisPhase.STATIC
    )


@pytest.mark.postgres
def test_sql_rejects_worker_result_for_another_job(database, analysis_request):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    checkpoint = _checkpoint(analysis_request)
    checkpoint["worker_result"] = failure_result(
        analysis_request.worker_job, "TEST", "failure"
    )
    checkpoint["worker_result"]["analysis_id"] = "another-analysis"
    with pytest.raises(RetryableError) as error:
        repository.save_checkpoint(
            analysis_request.analysis_id,
            claim.token,
            checkpoint,
            DeepAnalysisPhase.FINALIZING,
        )
    assert isinstance(error.value.__cause__, psycopg.errors.CheckViolation)


@pytest.mark.postgres
@pytest.mark.parametrize("field", ["sha256", "initial_route", "initial_verdict"])
def test_sql_rejects_final_result_identity_mismatch(database, analysis_request, field):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    result = _result(analysis_request)
    result[field] = "other"
    with pytest.raises(RetryableError) as error:
        repository.finish(analysis_request.analysis_id, claim.token, result)
    assert isinstance(error.value.__cause__, psycopg.errors.CheckViolation)
    assert repository.get(analysis_request.analysis_id).result is None
    assert repository.get(analysis_request.analysis_id).claimed


@pytest.mark.postgres
def test_sql_rejects_half_finished_or_waiting_without_checkpoint(
    database, analysis_request
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    for phase in ("COMPLETED", "WAITING_SPEAKEASY", "FINALIZING"):
        with (
            pytest.raises(psycopg.errors.CheckViolation),
            psycopg.connect(dsn) as connection,
        ):
            connection.execute(
                "UPDATE deep_analysis_runs SET phase = %s WHERE analysis_id = %s",
                (phase, analysis_request.analysis_id),
            )
    assert (
        repository.get(analysis_request.analysis_id).phase is DeepAnalysisPhase.STATIC
    )


@pytest.mark.postgres
@pytest.mark.parametrize(
    "status",
    [
        DeepAnalysisStatus.COMPLETE,
        DeepAnalysisStatus.FAILED,
        DeepAnalysisStatus.NOT_REQUIRED,
    ],
)
def test_terminal_result_is_atomic_and_immutable(database, analysis_request, status):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    result = _result(analysis_request, status)
    assert repository.finish(analysis_request.analysis_id, claim.token, result)
    record = PostgresDeepAnalysisRepository(dsn).get(analysis_request.analysis_id)
    assert record.phase.terminal
    assert record.result == result
    assert not record.claimed
    assert repository.claim(analysis_request.analysis_id, 180).token is None
    assert not repository.renew(analysis_request.analysis_id, claim.token, 180)
    assert not repository.release(analysis_request.analysis_id, claim.token)
    assert not repository.finish(
        analysis_request.analysis_id, claim.token, _result(analysis_request)
    )
    assert not repository.save_checkpoint(
        analysis_request.analysis_id,
        claim.token,
        _checkpoint(analysis_request),
        DeepAnalysisPhase.WAITING_SPEAKEASY,
    )
    assert repository.get(analysis_request.analysis_id).result == result


@pytest.mark.postgres
def test_pending_ids_skip_live_and_terminal_but_include_expired_claims(
    database, analysis_request
):
    repository, dsn = database
    other = replace(analysis_request, analysis_id="analysis-002")
    third = replace(analysis_request, analysis_id="analysis-003")
    for item in (analysis_request, other, third):
        repository.register(item, FINGERPRINT)
    assert repository.pending_ids(2) == [
        analysis_request.analysis_id,
        other.analysis_id,
    ]
    live = repository.claim(analysis_request.analysis_id, 180)
    done = repository.claim(third.analysis_id, 180)
    repository.finish(third.analysis_id, done.token, _result(third))
    assert repository.pending_ids() == [other.analysis_id]
    _expire(dsn, analysis_request.analysis_id)
    assert repository.pending_ids() == [other.analysis_id, analysis_request.analysis_id]
    assert not repository.release(analysis_request.analysis_id, live.token)


@pytest.mark.postgres
def test_future_backoff_jobs_do_not_hide_new_ready_jobs(database, analysis_request):
    repository, _ = database
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    for index in range(12):
        delayed = replace(analysis_request, analysis_id=f"old-delayed-{index:02d}")
        repository.register(delayed, FINGERPRINT)
        claim = repository.claim(delayed.analysis_id, 180)
        assert repository.release(
            delayed.analysis_id,
            claim.token,
            {
                "code": "TEMPORARY",
                "next_retry_at": future,
            },
        )
    fresh_ids = []
    for index in range(3):
        fresh = replace(analysis_request, analysis_id=f"new-ready-{index:02d}")
        repository.register(fresh, FINGERPRINT)
        fresh_ids.append(fresh.analysis_id)
    assert repository.pending_ids(3) == fresh_ids
    blocked = repository.claim("old-delayed-00", 180)
    assert blocked.token is None
    assert blocked.record.attempts == 1
    assert not blocked.record.claimed


@pytest.mark.postgres
def test_retry_timestamp_is_stored_as_timezone_aware_value_and_past_retry_is_ready(
    database, analysis_request
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    past = datetime.now(timezone(timedelta(hours=9))) - timedelta(seconds=1)
    error = {"code": "RETRY", "next_retry_at": past.isoformat()}
    assert repository.release(analysis_request.analysis_id, claim.token, error)
    with psycopg.connect(dsn) as connection:
        stored = connection.execute(
            "SELECT next_retry_at FROM deep_analysis_runs WHERE analysis_id = %s",
            (analysis_request.analysis_id,),
        ).fetchone()[0]
    assert stored == past
    assert repository.get(analysis_request.analysis_id).last_error == error
    assert repository.pending_ids() == [analysis_request.analysis_id]
    assert repository.claim(analysis_request.analysis_id, 180).token


@pytest.mark.postgres
@pytest.mark.parametrize("operation", ["checkpoint", "finish", "release"])
def test_successful_progress_clears_error_and_retry_timestamp(
    database, analysis_request, operation
):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    first = repository.claim(analysis_request.analysis_id, 180)
    error = {
        "code": "TEMPORARY",
        "retry_count": 1,
        "next_retry_at": (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat(),
    }
    repository.release(analysis_request.analysis_id, first.token, error)
    resumed = repository.claim(analysis_request.analysis_id, 180)
    if operation == "checkpoint":
        assert repository.save_checkpoint(
            analysis_request.analysis_id,
            resumed.token,
            _checkpoint(analysis_request),
            DeepAnalysisPhase.WAITING_SPEAKEASY,
        )
    elif operation == "finish":
        assert repository.finish(
            analysis_request.analysis_id, resumed.token, _result(analysis_request)
        )
    else:
        assert repository.release(analysis_request.analysis_id, resumed.token)
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT last_error, next_retry_at FROM deep_analysis_runs WHERE analysis_id = %s",
            (analysis_request.analysis_id,),
        ).fetchone()
    assert row == (None, None)


@pytest.mark.postgres
def test_stale_release_cannot_erase_scheduled_retry(database, analysis_request):
    repository, _ = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    error = {
        "code": "TEMPORARY",
        "next_retry_at": (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat(),
    }
    assert repository.release(analysis_request.analysis_id, claim.token, error)
    assert not repository.release(analysis_request.analysis_id, claim.token)
    assert repository.get(analysis_request.analysis_id).last_error == error
    assert repository.pending_ids() == []
    assert repository.claim(analysis_request.analysis_id, 180).token is None


@pytest.mark.postgres
def test_terminal_row_cannot_retain_a_retry_timestamp(database, analysis_request):
    repository, dsn = database
    repository.register(analysis_request, FINGERPRINT)
    claim = repository.claim(analysis_request.analysis_id, 180)
    assert repository.finish(
        analysis_request.analysis_id, claim.token, _result(analysis_request)
    )
    with (
        pytest.raises(psycopg.errors.CheckViolation),
        psycopg.connect(dsn) as connection,
    ):
        connection.execute(
            "UPDATE deep_analysis_runs SET next_retry_at = now() WHERE analysis_id = %s",
            (analysis_request.analysis_id,),
        )


@pytest.mark.parametrize(
    "value", [None, 12, "", "not-a-time", "2026-09-08T10:00:00", "2026-09-08"]
)
def test_release_rejects_invalid_retry_timestamp_before_connecting(
    analysis_request, value
):
    repository = PostgresDeepAnalysisRepository("host=localhost dbname=unused")
    with pytest.raises((TypeError, ValueError)):
        repository.release(
            analysis_request.analysis_id, str(uuid4()), {"next_retry_at": value}
        )


def test_repository_rejects_invalid_parameters_without_connection(analysis_request):
    repository = PostgresDeepAnalysisRepository("host=localhost dbname=unused")
    for value in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            repository.claim(analysis_request.analysis_id, value)
        with pytest.raises(ValueError):
            repository.renew(analysis_request.analysis_id, str(uuid4()), value)
    for value in (0, 101, True, 1.5):
        with pytest.raises(ValueError):
            repository.pending_ids(value)
    for value in ("", "contains space", "x" * 257):
        with pytest.raises(ValueError):
            repository.register(analysis_request, value)
    with pytest.raises(ValueError):
        repository.save_checkpoint(
            analysis_request.analysis_id, str(uuid4()), {}, DeepAnalysisPhase.STATIC
        )
    with pytest.raises(ValueError):
        repository.finish(
            analysis_request.analysis_id,
            str(uuid4()),
            {"deep_analysis_status": "WAITING_SPEAKEASY"},
        )
    for value in (float("nan"), float("inf"), {1, 2}):
        with pytest.raises(ValueError):
            repository.save_checkpoint(
                analysis_request.analysis_id,
                str(uuid4()),
                {"invalid": value},
                DeepAnalysisPhase.FINALIZING,
            )
        with pytest.raises(ValueError):
            repository.release(
                analysis_request.analysis_id, str(uuid4()), {"invalid": value}
            )
