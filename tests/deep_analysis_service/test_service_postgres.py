"""Two real PostgreSQL tables with fake sample/tool/queue boundaries only."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.deep_analysis.service_models import DeepAnalysisPhase
from trust_triage.deep_analysis.service_repository import PostgresDeepAnalysisRepository
from trust_triage.speakeasy_worker.models import JobStatus
from trust_triage.speakeasy_worker.repository import PostgresJobRepository
from trust_triage.speakeasy_worker.worker import Outcome, SpeakeasyWorker

from .fakes import FakeDynamicAnalyzer, ServiceHarness

pytestmark = pytest.mark.postgres


@pytest.fixture
def service_database():
    dsn = os.getenv("WORKER_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set WORKER_TEST_DATABASE_URL to run PostgreSQL integration tests")
    schema = "deep_service_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_dsn = make_conninfo(dsn, options=f"-c search_path={schema}")
    try:
        deep = PostgresDeepAnalysisRepository(scoped_dsn)
        worker = PostgresJobRepository(scoped_dsn)
        deep.initialize()
        worker.initialize()
        yield scoped_dsn
    finally:
        assert schema.startswith("deep_service_") and len(schema) == 45
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def _harness(tmp_path, dsn, *, sufficient=False):
    return ServiceHarness(
        tmp_path,
        sufficient=sufficient,
        repository=PostgresDeepAnalysisRepository(dsn),
        worker_repository=PostgresJobRepository(dsn),
    )


def _reconnect(harness, dsn):
    harness.repository = PostgresDeepAnalysisRepository(dsn)
    harness.worker_repository = PostgresJobRepository(dsn)
    return harness.restart()


def _worker(harness):
    analyzer = FakeDynamicAnalyzer()
    worker = SpeakeasyWorker(
        queue=harness.queue,
        repository=harness.worker_repository,
        samples=harness.samples,
        analyzer=analyzer,
    )
    return worker, analyzer


def test_two_tables_round_trip_survives_all_connections_and_service_restart(
    service_database, tmp_path
):
    dsn = service_database
    h = _harness(tmp_path, dsn)
    assert h.service.start(h.request).phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    persisted = PostgresDeepAnalysisRepository(dsn).get(h.request.analysis_id)
    assert persisted.checkpoint["static"]["tool_results"]["CAPA"]["status"] == "SUCCESS"
    assert persisted.result is None
    assert (
        PostgresJobRepository(dsn).get(h.request.analysis_id).status is JobStatus.QUEUED
    )
    assert h.calls == (1, 1, 0, 1)

    _reconnect(h, dsn)
    assert (
        h.service.resume(h.request.analysis_id).phase
        is DeepAnalysisPhase.WAITING_SPEAKEASY
    )
    assert len(h.queue.sent) == 1
    worker, analyzer = _worker(h)
    assert worker.run_once() is Outcome.COMPLETED
    assert analyzer.calls == 1
    assert (
        PostgresJobRepository(dsn).get(h.request.analysis_id).status
        is JobStatus.COMPLETED
    )
    assert (
        PostgresDeepAnalysisRepository(dsn).get(h.request.analysis_id).phase
        is DeepAnalysisPhase.WAITING_SPEAKEASY
    )

    completed = _reconnect(h, dsn).resume_ready()
    assert len(completed) == 1 and completed[0].phase is DeepAnalysisPhase.COMPLETED
    assert completed[0].result["executed_tiers"] == ["CAPA", "FLOSS", "SPEAKEASY"]
    assert h.calls == (1, 1, 1, 2)
    assert {item.source for item in h.llm.inputs[0]} == {"CAPA", "FLOSS", "SPEAKEASY"}
    stable = h.service.get(h.request.analysis_id)
    assert stable["status"] == "COMPLETED"
    assert _reconnect(h, dsn).start(h.request).result == completed[0].result
    assert h.service.get(h.request.analysis_id) == stable
    assert h.calls == (1, 1, 1, 2)


def test_static_sufficient_never_creates_worker_row(service_database, tmp_path):
    h = _harness(tmp_path, service_database, sufficient=True)
    h.service.register(h.request)
    assert h.service.get(h.request.analysis_id)["status"] == "QUEUED"
    results = _reconnect(h, service_database).resume_ready()
    assert results[0].phase is DeepAnalysisPhase.COMPLETED
    assert results[0].result["executed_tiers"] == ["CAPA", "FLOSS"]
    assert PostgresJobRepository(service_database).get(h.request.analysis_id) is None
    assert h.calls == (1, 1, 1, 1)
    assert h.queue.sent == []


def test_publish_error_persists_checkpoint_and_outbox_for_restart(
    service_database, tmp_path
):
    h = _harness(tmp_path, service_database)
    h.queue.fail_send = True
    record = h.service.start(h.request)
    assert record.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert record.last_error["retry_count"] == 1
    assert (
        PostgresJobRepository(service_database)
        .get(h.request.analysis_id)
        .dispatch_pending
    )
    h.queue.fail_send = False
    with psycopg.connect(service_database) as connection:
        connection.execute(
            "UPDATE deep_analysis_runs SET last_error = jsonb_set(last_error, '{next_retry_at}', "
            "to_jsonb('2000-01-01T00:00:00+00:00'::text)), "
            "next_retry_at = '2000-01-01T00:00:00+00:00'::timestamptz WHERE analysis_id = %s",
            (h.request.analysis_id,),
        )
    _reconnect(h, service_database).resume_ready()
    assert len(h.queue.sent) == 1
    assert (
        not PostgresJobRepository(service_database)
        .get(h.request.analysis_id)
        .dispatch_pending
    )
    assert h.calls == (1, 1, 0, 1)
    worker, _ = _worker(h)
    assert worker.run_once() is Outcome.COMPLETED
    assert (
        _reconnect(h, service_database).resume_ready()[0].phase
        is DeepAnalysisPhase.COMPLETED
    )
    assert h.calls == (1, 1, 1, 2)


def test_finalizing_worker_snapshot_survives_worker_row_loss(
    service_database, tmp_path, monkeypatch
):
    h = _harness(tmp_path, service_database)
    h.service.start(h.request)
    worker, _ = _worker(h)
    assert worker.run_once() is Outcome.COMPLETED
    save = h.repository.save_checkpoint

    def save_then_exit(analysis_id, token, checkpoint, phase):
        saved = save(analysis_id, token, checkpoint, phase)
        if saved and phase is DeepAnalysisPhase.FINALIZING:
            raise KeyboardInterrupt(
                "simulated process exit after Worker snapshot commit"
            )
        return saved

    monkeypatch.setattr(h.repository, "save_checkpoint", save_then_exit)
    with pytest.raises(KeyboardInterrupt):
        h.service.resume(h.request.analysis_id)
    record = PostgresDeepAnalysisRepository(service_database).get(h.request.analysis_id)
    assert record.phase is DeepAnalysisPhase.FINALIZING
    assert record.checkpoint["worker_result"]["analysis"]["observed_apis"]
    assert h.llm.calls == 0
    with psycopg.connect(service_database) as connection:
        connection.execute(
            "DELETE FROM speakeasy_jobs WHERE analysis_id = %s",
            (h.request.analysis_id,),
        )
    completed = _reconnect(h, service_database).resume(h.request.analysis_id)
    assert completed.phase is DeepAnalysisPhase.COMPLETED
    assert h.calls == (1, 1, 1, 2)
    view = h.service.get(h.request.analysis_id)
    assert view["speakeasy_result"]["analysis"]["observed_apis"]


def test_other_owner_prevents_tool_execution_until_expiry(service_database, tmp_path):
    h = _harness(tmp_path, service_database)
    h.service.register(h.request)
    owner = PostgresDeepAnalysisRepository(service_database).claim(
        h.request.analysis_id, 600
    )
    assert owner.token
    assert _reconnect(h, service_database).resume(h.request.analysis_id).claimed
    assert h.calls == (0, 0, 0, 0)
    with psycopg.connect(service_database) as connection:
        connection.execute(
            "UPDATE deep_analysis_runs SET lease_until = now() - interval '1 second' WHERE analysis_id = %s",
            (h.request.analysis_id,),
        )
    assert h.service.resume_ready()[0].phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert not h.repository.renew(h.request.analysis_id, owner.token, 600)
    assert h.calls == (1, 1, 0, 1)
