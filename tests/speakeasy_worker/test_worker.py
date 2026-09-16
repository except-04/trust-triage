from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import replace

import pytest

from trust_triage.dynamic_analysis import DynamicAnalysisStatus
from trust_triage.speakeasy_worker.errors import (
    LeaseLost,
    PermanentError,
    RetryableError,
)
from trust_triage.speakeasy_worker.models import JobStatus, failure_result
from trust_triage.speakeasy_worker.publisher import JobPublisher
from trust_triage.speakeasy_worker.worker import LeaseGuard, Outcome, WorkerLimits

from .fakes import MemoryQueue


def test_submit_process_and_read_result(rig, job, monkeypatch):
    publisher = JobPublisher(rig.repository, rig.queue)
    queued = publisher.submit(job)
    assert queued.status == JobStatus.QUEUED
    assert not queued.dispatch_pending
    acknowledge = rig.queue.acknowledge

    def acknowledge_after_commit(delivery):
        assert rig.repository.get(job.analysis_id).status == JobStatus.COMPLETED
        assert rig.repository.get(job.analysis_id).result is not None
        acknowledge(delivery)

    monkeypatch.setattr(rig.queue, "acknowledge", acknowledge_after_commit)
    assert rig.worker.run_once() == Outcome.COMPLETED
    record = rig.repository.get(job.analysis_id)
    assert set(record.result["behavior"]) == {
        "processes",
        "api_calls",
        "files",
        "registry",
        "network",
    }
    assert record.result["analysis"]["tool_version"] == "test"
    assert record.result["analysis"]["sha256"] == job.sha256
    assert "file_location" not in record.to_dict()
    assert "final_verdict" not in record.to_dict()
    assert len(rig.queue.acknowledged) == 1
    assert not list(rig.samples.root.iterdir())


def test_repeated_delivery_does_not_repeat_analysis(rig, delivery):
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert (
        rig.worker.process(replace(delivery, receipt_handle="receipt-002"))
        == Outcome.DUPLICATE
    )
    assert rig.analyzer.calls == 1
    assert rig.samples.calls == 1
    assert len(rig.queue.acknowledged) == 2


def test_live_claim_blocks_another_worker(rig, job, delivery):
    rig.repository.claim(job, 180)
    assert rig.worker.process(delivery) == Outcome.BUSY
    assert rig.analyzer.calls == 0
    assert not rig.queue.acknowledged


def test_expired_worker_cannot_overwrite_replacement_result(rig, job, delivery):
    previous = rig.repository.claim(job, 180)
    rig.repository.now += 181
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert not rig.repository.finish(
        job.analysis_id, previous.token, failure_result(job, "OLD", "old worker")
    )
    assert rig.repository.get(job.analysis_id).status == JobStatus.COMPLETED


@pytest.mark.parametrize(
    "status",
    [
        DynamicAnalysisStatus.TIMEOUT,
        DynamicAnalysisStatus.UNSUPPORTED_API,
        DynamicAnalysisStatus.TOOL_ERROR,
    ],
)
def test_tool_failure_retains_partial_evidence_without_retry(
    rig, delivery, job, status
):
    rig.analyzer.status = status
    assert rig.worker.process(delivery) == Outcome.FAILED
    result = rig.repository.get(job.analysis_id).result
    assert result["error"]["code"] == status.value
    assert result["behavior"]["api_calls"] == [{"api_name": "CreateFileW"}]
    assert result["analysis"]["observed_apis"] == ["CreateFileW"]
    assert rig.worker.process(delivery) == Outcome.DUPLICATE
    assert rig.analyzer.calls == 1


def test_download_rejection_never_calls_analyzer(rig, job, delivery):
    rig.samples.error = PermanentError("HASH_MISMATCH", "wrong bytes")
    assert rig.worker.process(delivery) == Outcome.FAILED
    assert rig.analyzer.calls == 0
    assert (
        rig.repository.get(job.analysis_id).result["error"]["code"] == "HASH_MISMATCH"
    )


def test_temporary_download_failure_can_recover(rig, job, delivery):
    rig.samples.error = RetryableError("S3_UNAVAILABLE", "try later")
    assert rig.worker.process(delivery) == Outcome.RETRY
    assert rig.repository.get(job.analysis_id).status == JobStatus.QUEUED
    assert rig.queue.deferred[-1][1] == 30
    assert not rig.queue.acknowledged
    rig.samples.error = None
    assert rig.worker.process(replace(delivery, receive_count=2)) == Outcome.COMPLETED
    assert rig.analyzer.calls == 1


def test_database_save_retry_reuses_analysis_result(rig, job, delivery, monkeypatch):
    finish = rig.repository.finish
    calls = []

    def flaky_finish(*args):
        calls.append(args)
        if len(calls) < 3:
            raise RetryableError("DATABASE_ERROR", "temporarily offline")
        return finish(*args)

    monkeypatch.setattr(rig.repository, "finish", flaky_finish)
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert len(calls) == 3
    assert rig.analyzer.calls == 1
    assert rig.repository.get(job.analysis_id).status == JobStatus.COMPLETED


def test_commit_response_loss_does_not_repeat_analysis(rig, delivery, monkeypatch):
    finish = rig.repository.finish
    first = True

    def commit_then_disconnect(*args):
        nonlocal first
        saved = finish(*args)
        if first:
            first = False
            raise RetryableError("DATABASE_ERROR", "response lost")
        return saved

    monkeypatch.setattr(rig.repository, "finish", commit_then_disconnect)
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert rig.analyzer.calls == 1
    assert len(rig.queue.acknowledged) == 1


def test_database_save_exhaustion_does_not_delete_message(
    rig, delivery, job, monkeypatch
):
    def unavailable(*args):
        raise RetryableError("DATABASE_ERROR", "offline")

    monkeypatch.setattr(rig.repository, "finish", unavailable)
    assert rig.worker.process(delivery) == Outcome.RETRY
    assert not rig.queue.acknowledged
    record = rig.repository.get(job.analysis_id)
    assert record.status == JobStatus.QUEUED
    assert record.last_error["code"] == "DATABASE_ERROR"


def test_sqs_delete_failure_preserves_committed_result(rig, delivery, job):
    rig.queue.fail_ack = True
    assert rig.worker.process(delivery) == Outcome.RETRY
    assert rig.repository.get(job.analysis_id).status == JobStatus.COMPLETED
    rig.queue.fail_ack = False
    assert rig.worker.process(delivery) == Outcome.DUPLICATE
    assert rig.analyzer.calls == 1


def test_malformed_message_is_not_acknowledged(rig, delivery, caplog):
    secret = "do-not-log-this-message-body"
    with caplog.at_level("INFO"):
        assert rig.worker.process(replace(delivery, body=secret)) == Outcome.REJECTED
    assert secret not in caplog.text
    assert rig.analyzer.calls == 0
    assert not rig.queue.acknowledged


def test_conflicting_input_cannot_change_existing_job(rig, delivery, job):
    rig.repository.register(job)
    conflicting = json.loads(delivery.body)
    conflicting["sha256"] = "f" * 64
    assert (
        rig.worker.process(replace(delivery, body=json.dumps(conflicting)))
        == Outcome.REJECTED
    )
    assert rig.repository.get(job.analysis_id).job == job
    assert rig.analyzer.calls == 0


def test_analyzer_exception_is_a_tool_failure(rig, delivery, job):
    def fail():
        raise RuntimeError("not a classification")

    rig.analyzer.callback = fail
    assert rig.worker.process(delivery) == Outcome.FAILED
    result = rig.repository.get(job.analysis_id).result
    assert result["error"]["code"] == "TOOL_ERROR"
    assert "verdict" not in result


def test_sender_recovers_job_left_between_db_and_sqs(rig, job):
    publisher = JobPublisher(rig.repository, rig.queue)
    rig.queue.fail_send = True
    with pytest.raises(RetryableError):
        publisher.submit(job)
    assert rig.repository.get(job.analysis_id).dispatch_pending
    rig.queue.fail_send = False
    assert publisher.dispatch_pending() == 1
    assert not rig.repository.get(job.analysis_id).dispatch_pending
    assert rig.worker.run_once() == Outcome.COMPLETED


def test_redelivery_after_send_status_loss_is_safe(rig, job, monkeypatch):
    publisher = JobPublisher(rig.repository, rig.queue)
    mark = rig.repository.mark_dispatched

    def fail(analysis_id):
        raise RetryableError("DATABASE_ERROR", "offline")

    monkeypatch.setattr(rig.repository, "mark_dispatched", fail)
    with pytest.raises(RetryableError):
        publisher.submit(job)
    monkeypatch.setattr(rig.repository, "mark_dispatched", mark)
    assert publisher.dispatch_pending() == 1
    assert rig.worker.run_once() == Outcome.COMPLETED
    assert rig.worker.run_once() == Outcome.DUPLICATE
    assert rig.analyzer.calls == 1


def test_dead_letter_updates_unfinished_db_job(rig, job, delivery):
    dlq = MemoryQueue()
    claim = rig.repository.claim(job, 180)
    rig.repository.retry(
        job.analysis_id, claim.token, {"code": "S3_UNAVAILABLE", "message": "offline"}
    )
    assert rig.worker.reconcile_dead_letter(delivery, dlq) == Outcome.FAILED
    record = rig.repository.get(job.analysis_id)
    assert record.status == JobStatus.FAILED
    assert record.result["error"]["code"] == "RETRY_EXHAUSTED"
    assert "S3_UNAVAILABLE" in record.result["error"]["message"]
    assert dlq.acknowledged == [delivery]


def test_dead_letter_preserves_running_and_completed_jobs(rig, job, delivery):
    dlq = MemoryQueue()
    rig.repository.claim(job, 180)
    assert rig.worker.reconcile_dead_letter(delivery, dlq) == Outcome.BUSY
    assert not dlq.acknowledged
    rig.repository.now += 181
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert rig.worker.reconcile_dead_letter(delivery, dlq) == Outcome.DUPLICATE
    assert rig.repository.get(job.analysis_id).status == JobStatus.COMPLETED


def test_invalid_dead_letter_stays_available_for_manual_review(rig, delivery):
    dlq = MemoryQueue()
    bad = replace(delivery, body="{}")
    assert rig.worker.reconcile_dead_letter(bad, dlq) == Outcome.REJECTED
    assert not dlq.acknowledged
    assert dlq.deferred[-1] == (bad, 3600)


def test_heartbeat_extends_both_queues_and_db_lease(rig, job, delivery):
    claim = rig.repository.claim(job, 180)
    guard = LeaseGuard(
        rig.repository, rig.queue, job, delivery, claim.token, WorkerLimits()
    )
    rig.repository.now += 30
    guard.heartbeat()
    assert rig.repository.leases[job.analysis_id][1] == rig.repository.now + 180
    assert rig.queue.deferred[-1] == (delivery, 180)
    rig.repository.now += 181
    with pytest.raises(LeaseLost):
        guard.heartbeat()


def test_heartbeat_failure_prevents_stale_result_save(rig, job, delivery, monkeypatch):
    rig.worker.limits = WorkerLimits(
        visibility_seconds=2, heartbeat_seconds=0.01, job_timeout_seconds=1
    )
    rig.analyzer.callback = lambda: time.sleep(0.06)

    def lose_lease(*args):
        return False

    monkeypatch.setattr(rig.repository, "renew", lose_lease)
    assert rig.worker.process(delivery) == Outcome.RETRY
    assert rig.repository.get(job.analysis_id).result is None
    assert not rig.queue.acknowledged


def test_job_deadline_creates_failed_result(rig, job, delivery):
    rig.worker.limits = WorkerLimits(
        visibility_seconds=2, heartbeat_seconds=0.2, job_timeout_seconds=0.02
    )
    rig.analyzer.callback = lambda: time.sleep(0.04)
    assert rig.worker.process(delivery) == Outcome.FAILED
    assert rig.repository.get(job.analysis_id).result["error"]["code"] == "JOB_TIMEOUT"
    assert rig.repository.get(job.analysis_id).result["analysis"]["observed_apis"] == [
        "CreateFileW"
    ]


def test_completion_response_matches_already_committed_result(
    rig, job, delivery, monkeypatch
):
    finish = rig.repository.finish

    def previous_result(analysis_id, token, result):
        finish(
            analysis_id, token, failure_result(job, "PREVIOUS", "previous completion")
        )
        return False

    monkeypatch.setattr(rig.repository, "finish", previous_result)
    assert rig.worker.process(delivery) == Outcome.FAILED
    assert rig.repository.get(job.analysis_id).result["error"]["code"] == "PREVIOUS"


def test_retry_after_lease_replacement_does_not_shorten_new_delivery(
    rig, job, delivery, monkeypatch
):
    @contextmanager
    def replaced_during_download(*args):
        rig.repository.now += 181
        rig.repository.claim(job, 180)
        raise RetryableError("S3_UNAVAILABLE", "old download failed")
        yield  # pragma: no cover - makes the failing download a context manager

    monkeypatch.setattr(rig.samples, "materialize", replaced_during_download)
    assert rig.worker.process(delivery) == Outcome.RETRY
    assert rig.repository.get(job.analysis_id).status == JobStatus.RUNNING
    assert not rig.queue.deferred
    assert not rig.queue.acknowledged
