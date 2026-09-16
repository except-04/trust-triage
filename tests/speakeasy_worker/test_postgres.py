"""WORKER_TEST_DATABASE_URL로 지정한 PostgreSQL에 임시 schema를 만들어 검증한다."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.speakeasy_worker.errors import RetryableError
from trust_triage.speakeasy_worker.models import JobConflict, JobStatus, failure_result
from trust_triage.speakeasy_worker.publisher import JobPublisher
from trust_triage.speakeasy_worker.reports import ReportWriter
from trust_triage.speakeasy_worker.repository import PostgresJobRepository
from trust_triage.speakeasy_worker.worker import Outcome, SpeakeasyWorker
from trust_triage.storage import ArtifactReference, LocalArtifactStorage

from .fakes import FakeAnalyzer, FakeSamples, MemoryQueue

pytestmark = pytest.mark.postgres


@pytest.fixture
def database():
    dsn = os.getenv("WORKER_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set WORKER_TEST_DATABASE_URL to run PostgreSQL integration tests")
    schema = "worker_test_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_dsn = make_conninfo(dsn, options=f"-c search_path={schema}")
    repository = PostgresJobRepository(scoped_dsn)
    try:
        repository.initialize()
        yield repository, scoped_dsn
    finally:
        # 이 fixture에서 생성한 임시 schema만 정리한다.
        assert schema.startswith("worker_test_") and len(schema) == 44
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def _expire(dsn, analysis_id):
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE speakeasy_jobs SET lease_until = now() - interval '1 second' WHERE analysis_id = %s",
            (analysis_id,),
        )


def test_registration_survives_reconnect_and_rejects_conflict(database, job):
    repository, dsn = database
    repository.register(job, dispatch_pending=True)
    restored = PostgresJobRepository(dsn).get(job.analysis_id)
    assert restored.job == job
    assert restored.status == JobStatus.QUEUED
    assert restored.dispatch_pending
    with pytest.raises(JobConflict):
        repository.register(replace(job, sha256="f" * 64))
    assert repository.get(job.analysis_id).job == job


def test_initialize_is_repeatable_without_erasing_jobs(database, job):
    repository, _ = database
    repository.register(job)
    repository.initialize()
    repository.check()
    assert repository.get(job.analysis_id) is not None


def test_two_connections_cannot_claim_same_job(database, job):
    repository, dsn = database
    repository.register(job)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(
            pool.map(lambda _: PostgresJobRepository(dsn).claim(job, 180), range(4))
        )
    assert sum(claim.token is not None for claim in claims) == 1
    assert repository.get(job.analysis_id).attempts == 1


def test_expired_claim_can_be_replaced_and_old_token_cannot_save(database, job):
    repository, dsn = database
    previous = repository.claim(job, 180)
    _expire(dsn, job.analysis_id)
    current = repository.claim(job, 180)
    assert current.token and current.token != previous.token
    assert not repository.renew(job.analysis_id, previous.token, 180)
    assert not repository.finish(
        job.analysis_id, previous.token, failure_result(job, "OLD", "old result")
    )
    assert repository.finish(
        job.analysis_id, current.token, failure_result(job, "CURRENT", "current result")
    )
    record = repository.get(job.analysis_id)
    assert record.attempts == 2
    assert record.result["error"]["code"] == "CURRENT"


def test_result_and_terminal_status_are_committed_together(database, job):
    repository, dsn = database
    claim = repository.claim(job, 180)
    result = failure_result(job, "TIMEOUT", "test timeout")
    assert repository.finish(job.analysis_id, claim.token, result)
    record = PostgresJobRepository(dsn).get(job.analysis_id)
    assert record.status == JobStatus.FAILED
    assert record.result == result
    assert record.last_error == result["error"]
    assert repository.claim(job, 180).token is None


def test_sql_constraints_reject_half_finished_state(database, job):
    repository, dsn = database
    repository.register(job)
    with (
        pytest.raises(psycopg.errors.CheckViolation),
        psycopg.connect(dsn) as connection,
    ):
        connection.execute(
            "UPDATE speakeasy_jobs SET status = 'COMPLETED' WHERE analysis_id = %s",
            (job.analysis_id,),
        )
    assert repository.get(job.analysis_id).status == JobStatus.QUEUED


@pytest.mark.parametrize("field,value", [("sha256", "f" * 64), ("tool", "OTHER")])
def test_database_rejects_results_for_another_sample_or_tool(
    database, job, field, value
):
    repository, _ = database
    claim = repository.claim(job, 180)
    result = failure_result(job, "TEST", "invalid result")
    result[field] = value
    with pytest.raises(RetryableError) as error:
        repository.finish(job.analysis_id, claim.token, result)
    assert isinstance(error.value.__cause__, psycopg.errors.CheckViolation)
    record = repository.get(job.analysis_id)
    assert record.status == JobStatus.RUNNING
    assert record.result is None


def test_retry_releases_claim_but_preserves_error_and_attempt_count(database, job):
    repository, _ = database
    claim = repository.claim(job, 180)
    error = {"code": "S3_UNAVAILABLE", "message": "temporary failure"}
    assert repository.retry(job.analysis_id, claim.token, error)
    record = repository.get(job.analysis_id)
    assert record.status == JobStatus.QUEUED
    assert record.last_error == error
    assert record.attempts == 1
    assert repository.claim(job, 180).record.attempts == 2


def test_expired_owner_cannot_release_new_workers_claim(database, job):
    repository, dsn = database
    old = repository.claim(job, 180)
    _expire(dsn, job.analysis_id)
    current = repository.claim(job, 180)
    assert not repository.retry(
        job.analysis_id, old.token, {"code": "OLD", "message": "stale"}
    )
    assert repository.renew(job.analysis_id, current.token, 180)


def test_dead_letter_does_not_override_live_or_terminal_job(database, job):
    repository, dsn = database
    claim = repository.claim(job, 180)
    dlq_result = failure_result(job, "RETRY_EXHAUSTED", "too many deliveries")
    assert not repository.dead_letter(job, dlq_result)
    _expire(dsn, job.analysis_id)
    assert repository.dead_letter(job, dlq_result)
    assert not repository.finish(
        job.analysis_id, claim.token, failure_result(job, "LATE", "late result")
    )
    assert not repository.dead_letter(
        job, failure_result(job, "OTHER", "duplicate DLQ message")
    )
    assert repository.get(job.analysis_id).result == dlq_result


def test_pending_dispatch_survives_failed_sqs_request(database, job):
    repository, _ = database
    queue = MemoryQueue()
    queue.fail_send = True
    publisher = JobPublisher(repository, queue)
    with pytest.raises(RetryableError):
        publisher.submit(job)
    assert repository.pending_jobs() == [job]
    queue.fail_send = False
    assert publisher.dispatch_pending() == 1
    assert repository.pending_jobs() == []


def test_worker_flow_with_actual_postgres(database, job, tmp_path):
    repository, dsn = database
    queue, analyzer = MemoryQueue(), FakeAnalyzer()
    worker = SpeakeasyWorker(
        queue=queue,
        repository=repository,
        samples=FakeSamples(tmp_path),
        analyzer=analyzer,
    )
    JobPublisher(repository, queue).submit(job)
    delivery = queue.receive()
    assert worker.process(delivery) == Outcome.COMPLETED
    assert worker.process(delivery) == Outcome.DUPLICATE
    persisted = PostgresJobRepository(dsn).get(job.analysis_id)
    assert persisted.status == JobStatus.COMPLETED
    assert persisted.result["behavior"]["files"] == [{"path": "test.bin"}]
    assert persisted.result["analysis"]["tool_version"] == "test"
    assert analyzer.calls == 1


def test_report_reference_and_worker_completion_survive_reconnect(
    database, job, tmp_path
):
    repository, dsn = database
    queue, analyzer = MemoryQueue(), FakeAnalyzer()
    storage = LocalArtifactStorage(tmp_path / "reports")
    worker = SpeakeasyWorker(
        queue=queue,
        repository=repository,
        samples=FakeSamples(tmp_path),
        analyzer=analyzer,
        reports=ReportWriter(storage),
    )
    JobPublisher(repository, queue).submit(job)
    assert worker.run_once() == Outcome.COMPLETED
    result = PostgresJobRepository(dsn).get(job.analysis_id).result
    reference = ArtifactReference(**result["artifact"])
    assert reference.analysis_id == job.analysis_id
    assert reference.sha256 == job.sha256
    assert storage.read(reference)


def test_backend_and_worker_share_db_without_overwriting_analysis_state(
    database, job, tmp_path
):
    from trust_triage.backend_api.repository import PostgresAnalysisRepository

    repository, dsn = database
    backend = PostgresAnalysisRepository(dsn)
    backend.initialize()
    backend.register(
        [
            {
                "analysis_id": job.analysis_id,
                "sha256": job.sha256,
                "file_location": job.file_location,
                "filename": "sample.exe",
                "size_bytes": 42,
            }
        ]
    )
    before = backend.get(job.analysis_id)
    queue = MemoryQueue()
    worker = SpeakeasyWorker(
        queue=queue,
        repository=repository,
        samples=FakeSamples(tmp_path),
        analyzer=FakeAnalyzer(),
    )
    JobPublisher(repository, queue).submit(job)
    assert worker.run_once() == Outcome.COMPLETED
    assert backend.get(job.analysis_id) == before
    assert repository.get(job.analysis_id).status == JobStatus.COMPLETED
