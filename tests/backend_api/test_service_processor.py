"""Service/processor integration with detached persistence and header-only input.

The handcrafted bytes below contain only the fields needed by the storage
validator. There is no executable payload. Feature, model, and deep-analysis
execution are replaced by deterministic doubles; no network clients are used.
"""

from __future__ import annotations

import io
import json
import struct
from collections import deque
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from trust_triage.backend_api import processor as processor_module
from trust_triage.backend_api import service as service_module
from trust_triage.backend_api import views
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.processor import BackendProcessor, LeaseLost, _Lease
from trust_triage.backend_api.schemas import ReviewRequest
from trust_triage.backend_api.service import BackendService, stored_sample
from trust_triage.backend_api.storage import LocalSampleStorage

from .fake_repository import MemoryAnalysisRepository


def harmless_pe_header(marker: int = 0) -> bytes:
    """DOS/COFF/optional/section headers only; no entry point or code section."""
    value = bytearray(64 + 24 + 96 + 40)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 0x3C, 64)
    value[64:68] = b"PE\0\0"
    struct.pack_into("<HH", value, 68, 0x14C, 1)
    struct.pack_into("<H", value, 84, 96)
    struct.pack_into("<H", value, 88, 0x10B)
    value[-1] = marker
    return bytes(value)


def initial_result(verdict="AUTO_BENIGN", *, xai_failed=False):
    probability = {
        "AUTO_BENIGN": 0.1,
        "AUTO_MALICIOUS": 0.99,
        "HIGH_RISK_UNCERTAIN": 0.7,
    }[verdict]
    return {
        "prediction": {
            "lgbm_raw_probability": probability,
            "xgb_raw_probability": probability,
            "calibrated_probability": probability,
        },
        "risk_signals": {
            "disagreement": 0.0,
            "ood_score": 0.1,
            "difficulty_score": 0.0,
        },
        "initial_verdict": verdict,
        "route": "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL",
        "reason": "Synthetic initial result.",
        "top_features": [],
        "feature_metadata": {"source_schema_version": "synthetic-v1"},
        "xai_status": "FAILED" if xai_failed else "SUCCESS",
        "xai_error": BackendError(
            "XAI_FAILED", "Synthetic explanation failure.", stage="XAI"
        ).to_dict()
        if xai_failed
        else None,
    }


class FakeInitial:
    def __init__(self):
        self.value = initial_result()
        self.outcomes = deque()
        self.calls = []

    def analyze(self, path, *, sha256, check):
        check()
        self.calls.append((path, sha256))
        outcome = self.outcomes.popleft() if self.outcomes else self.value
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(path, sha256, check)
        return deepcopy(outcome)


def deep_snapshot(record, *, status="COMPLETED", phase="DONE"):
    value = {
        "analysis_id": record.analysis_id,
        "sha256": record.sha256,
        "initial_route": "DEEP_ANALYSIS",
        "initial_verdict": "UNKNOWN",
        "status": status,
        "phase": phase,
        "tool_statuses": {
            "CAPA": "SUCCESS",
            "FLOSS": "SUCCESS",
            "SPEAKEASY": "RUNNING" if status == "RUNNING" else "SUCCESS",
        },
        "evidence": [],
    }
    if status in {"COMPLETED", "FAILED"}:
        value["result"] = {
            "sha256": record.sha256,
            "deep_analysis_status": "COMPLETE" if status == "COMPLETED" else "FAILED",
            "llm_interpretation": {"status": "NOT_REQUIRED"},
        }
    return value


class FakeDeep:
    def __init__(self):
        self.calls = []
        self.outcomes = deque()
        self.read_value = None

    def get(self, analysis_id):
        return deepcopy(self.read_value)

    def advance(self, record):
        self.calls.append(record)
        outcome = self.outcomes.popleft() if self.outcomes else deep_snapshot
        if isinstance(outcome, Exception):
            raise outcome
        return deepcopy(outcome(record) if callable(outcome) else outcome)


class FakeClock:
    def __init__(self, repository):
        self.repository = repository
        self.seconds = 0.0

    def monotonic(self):
        return self.seconds

    def advance(self, seconds):
        self.seconds += seconds
        self.repository.advance(seconds)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    repository = MemoryAnalysisRepository()
    repository.now = datetime(2026, 9, 8, 3, tzinfo=timezone.utc)
    clock = FakeClock(repository)

    class ClockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return (
                repository.now.astimezone(tz)
                if tz
                else repository.now.replace(tzinfo=None)
            )

    monkeypatch.setattr(processor_module, "datetime", ClockDateTime)
    monkeypatch.setattr(service_module, "datetime", ClockDateTime)
    monkeypatch.setattr(
        processor_module, "time", SimpleNamespace(monotonic=clock.monotonic)
    )
    config = BackendConfig(
        storage_root=tmp_path / "samples",
        temp_root=tmp_path / "temp",
        poll_seconds=0.1,
        retry_delay_seconds=2,
    )
    storage = LocalSampleStorage(config.storage_root)
    initial, deep = FakeInitial(), FakeDeep()
    service = BackendService(repository, storage, config)
    processor = BackendProcessor(repository, storage, initial, deep, config)
    return SimpleNamespace(
        repository=repository,
        clock=clock,
        config=config,
        storage=storage,
        initial=initial,
        deep=deep,
        service=service,
        processor=processor,
    )


def submit(harness, *, marker=0, idempotency_key=None):
    return harness.service.submit(
        [(io.BytesIO(harmless_pe_header(marker)), "header-only.exe")],
        idempotency_key=idempotency_key,
    )


def next_step(harness, analysis_id, *, seconds=None):
    harness.clock.advance(
        harness.config.poll_seconds + 0.001 if seconds is None else seconds
    )
    return harness.processor.resume(analysis_id)


def complete(harness, analysis_id):
    for _ in range(8):
        record = next_step(harness, analysis_id)
        if record.terminal:
            return record
    raise AssertionError("the deterministic pipeline did not finish")


@pytest.mark.parametrize(
    ("verdict", "final", "review"),
    [
        ("AUTO_BENIGN", "BENIGN", False),
        ("AUTO_MALICIOUS", "MALICIOUS", True),
    ],
)
def test_initial_final_flow_is_durable_and_does_not_run_deep(
    harness, verdict, final, review
):
    harness.initial.value = initial_result(verdict)
    accepted = submit(harness)
    assert accepted.status == "QUEUED"
    first = harness.processor.resume(accepted.analysis_id)
    assert first.phase == "FINALIZING" and first.status == "RUNNING"
    assert first.initial_result["initial_verdict"] == verdict
    assert first.final_assessment is None
    assert first.claimed is False
    # Poll scheduling is real state: an immediate resume cannot take the lease.
    harness.processor.resume(accepted.analysis_id)
    assert len(harness.initial.calls) == 1
    finished = next_step(harness, accepted.analysis_id)
    assert finished.status == "COMPLETED" and finished.phase == "DONE"
    assert finished.final_assessment["final_verdict"] == final
    assert finished.final_assessment["requires_human_review"] is review
    assert harness.deep.calls == []
    assert views.analysis(finished).deep_analysis_status == {
        "capa": "NOT_REQUIRED",
        "floss": "NOT_REQUIRED",
        "speakeasy": "NOT_REQUIRED",
        "cape": "NOT_REQUIRED",
    }
    # Repeating a terminal resume is idempotent, including after a new processor.
    replacement = BackendProcessor(
        harness.repository,
        harness.storage,
        harness.initial,
        harness.deep,
        harness.config,
    )
    assert (
        replacement.resume(accepted.analysis_id).completed_at == finished.completed_at
    )
    assert len(harness.initial.calls) == 1


def test_high_risk_waits_for_deep_then_finalizes_for_review(harness):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    harness.deep.outcomes.append(
        lambda record: deep_snapshot(
            record, status="RUNNING", phase="WAITING_SPEAKEASY"
        )
    )
    accepted = submit(harness)
    first = harness.processor.resume(accepted.analysis_id)
    assert first.phase == "WAITING_DEEP" and first.current_stage == "CAPA_FLOSS"
    assert harness.deep.calls == []
    waiting = next_step(harness, accepted.analysis_id)
    assert waiting.phase == "WAITING_DEEP" and waiting.current_stage == "SPEAKEASY"
    assert waiting.deep_result["status"] == "RUNNING"
    assert waiting.final_assessment is None
    # A new worker resumes from the saved phase without repeating initial work.
    harness.processor = BackendProcessor(
        harness.repository,
        harness.storage,
        harness.initial,
        harness.deep,
        harness.config,
    )
    finalizing = next_step(harness, accepted.analysis_id)
    assert (
        finalizing.phase == "FINALIZING"
        and finalizing.deep_result["status"] == "COMPLETED"
    )
    finished = next_step(harness, accepted.analysis_id)
    assert finished.status == "COMPLETED"
    assert finished.final_assessment["final_verdict"] == "UNCERTAIN"
    assert finished.final_assessment["disposition"] == "MANUAL_REVIEW"
    assert finished.final_assessment["requires_human_review"] is True
    assert len(harness.initial.calls) == 1 and len(harness.deep.calls) == 2
    assert {row.analysis_id for row in harness.deep.calls} == {accepted.analysis_id}
    assert {row.sha256 for row in harness.deep.calls} == {accepted.sha256}


def test_shap_failure_preserves_initial_jrr_and_requests_review(harness):
    harness.initial.value = initial_result(xai_failed=True)
    accepted = submit(harness)
    finished = complete(harness, accepted.analysis_id)
    assert finished.initial_result["initial_verdict"] == "AUTO_BENIGN"
    assert finished.initial_result["route"] == "FINAL"
    assert finished.initial_result["xai_error"]["code"] == "XAI_FAILED"
    assert finished.final_assessment["requires_human_review"] is True
    assert harness.deep.calls == []


def test_deep_failure_is_not_malicious_evidence(harness):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    harness.deep.outcomes.append(lambda record: deep_snapshot(record, status="FAILED"))
    accepted = submit(harness)
    finished = complete(harness, accepted.analysis_id)
    assert finished.status == "FAILED"
    assert finished.error["code"] == "DEEP_ANALYSIS_FAILED"
    assert finished.final_assessment["final_verdict"] == "UNCERTAIN"
    assert finished.final_assessment["disposition"] == "ANALYSIS_FAILED"
    assert finished.final_assessment["requires_human_review"] is True


def test_mismatched_deep_hash_is_rejected_before_checkpoint(harness):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")

    def wrong_sample(record):
        value = deep_snapshot(record)
        value["sha256"] = "f" * 64
        return value

    harness.deep.outcomes.append(wrong_sample)
    accepted = submit(harness)
    finished = complete(harness, accepted.analysis_id)
    assert (
        finished.status == "FAILED" and finished.error["code"] == "DEEP_RESULT_INVALID"
    )
    assert finished.deep_result is None
    assert harness.repository.calls["save_deep"] == 0


def test_deep_wait_deadline_stops_polling(harness):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    accepted = submit(harness)
    harness.processor.resume(accepted.analysis_id)
    expired = next_step(
        harness, accepted.analysis_id, seconds=harness.config.deep_wait_seconds
    )
    assert expired.status == "FAILED" and expired.error["code"] == "DEEP_WAIT_TIMEOUT"
    assert harness.deep.calls == []


def test_finished_deep_result_is_recovered_even_after_wait_deadline(harness):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    accepted = submit(harness)
    record = harness.processor.resume(accepted.analysis_id)
    harness.deep.read_value = deep_snapshot(record)
    recovered = next_step(
        harness, accepted.analysis_id, seconds=harness.config.deep_wait_seconds
    )
    assert recovered.phase == "FINALIZING" and recovered.error is None
    assert harness.deep.calls == []
    assert next_step(harness, accepted.analysis_id).status == "COMPLETED"


@pytest.mark.parametrize("guard_result", [True, False, None, "error"])
def test_cleanup_preserves_samples_while_linked_job_state_is_uncertain(
    harness, guard_result
):
    harness.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    accepted = submit(harness)
    record = complete(harness, accepted.analysis_id)
    harness.clock.advance(harness.config.retention_hours * 3600 + 1)
    harness.service.config = replace(
        harness.config, storage_mode="s3", s3_bucket="fake-test-bucket"
    )

    def guard(_record):
        if guard_result == "error":
            raise BackendError("DATABASE_ERROR", "test only")
        return guard_result

    harness.service.cleanup_guard = guard if guard_result is not None else None
    outcome = harness.service.cleanup(delete=True)
    if guard_result is True:
        assert outcome["deleted_ids"] == [record.analysis_id]
        assert outcome["skipped_ids"] == []
    else:
        assert outcome["deleted_ids"] == []
        assert outcome["skipped_ids"] == [record.analysis_id]
        assert harness.storage._path(stored_sample(record)).exists()


def test_retryable_initial_failure_obeys_backoff_then_recovers(harness):
    harness.initial.outcomes.append(
        BackendError(
            "TEMPORARY_MODEL_FAILURE", "Synthetic retryable failure.", retryable=True
        )
    )
    accepted = submit(harness)
    retry = harness.processor.resume(accepted.analysis_id)
    assert retry.phase == "INITIAL" and not retry.terminal and not retry.claimed
    assert retry.error["retry_count"] == 1
    assert harness.repository.pending_ids() == []
    # Advancing less than the scheduled backoff must not run another attempt.
    next_step(
        harness, accepted.analysis_id, seconds=harness.config.retry_delay_seconds / 2
    )
    assert len(harness.initial.calls) == 1
    checkpoint = next_step(
        harness, accepted.analysis_id, seconds=harness.config.retry_delay_seconds
    )
    assert checkpoint.phase == "FINALIZING" and checkpoint.error is None
    finished = next_step(harness, accepted.analysis_id)
    assert finished.status == "COMPLETED"
    assert len(harness.initial.calls) == 2


def test_retry_budget_terminates_repeated_component_failure(harness):
    harness.initial.outcomes.extend(
        BackendError(
            "TEMPORARY_MODEL_FAILURE", "Synthetic retryable failure.", retryable=True
        )
        for _ in range(harness.config.max_attempts)
    )
    accepted = submit(harness)
    for attempt in range(harness.config.max_attempts):
        row = next_step(
            harness,
            accepted.analysis_id,
            seconds=harness.config.retry_delay_seconds + 0.01,
        )
        if attempt < harness.config.max_attempts - 1:
            assert not row.terminal
            assert row.error["retry_count"] == attempt + 1
    assert row.status == "FAILED" and row.attempt_count == harness.config.max_attempts
    assert row.error["code"] == "TEMPORARY_MODEL_FAILURE"
    assert row.final_assessment["final_verdict"] == "UNCERTAIN"
    assert harness.repository.pending_ids() == []


def test_unexpected_initial_exception_is_sanitized_without_retry(harness):
    harness.initial.outcomes.append(
        ValueError("postgresql://secret:password@private-host/internal")
    )
    accepted = submit(harness)
    finished = harness.processor.resume(accepted.analysis_id)
    assert finished.status == "FAILED" and finished.error["code"] == "PROCESSING_FAILED"
    assert "secret" not in json.dumps(views.analysis(finished).model_dump(mode="json"))
    assert harness.repository.calls["release"] == 0


def test_initial_route_contract_is_rejected_before_persisting(harness):
    harness.initial.value["route"] = "DEEP_ANALYSIS"
    accepted = submit(harness)
    finished = harness.processor.resume(accepted.analysis_id)
    assert (
        finished.status == "FAILED"
        and finished.error["code"] == "INITIAL_RESULT_INVALID"
    )
    assert finished.initial_result is None
    assert harness.repository.calls["save_initial"] == 0


def test_checkpoint_database_failure_is_retryable_and_preserves_input(harness):
    accepted = submit(harness)
    harness.repository.failures["save_initial"] = 1
    retry = harness.processor.resume(accepted.analysis_id)
    assert retry.phase == "INITIAL" and retry.error["code"] == "DATABASE_ERROR"
    assert retry.error["retry_count"] == 1 and not retry.claimed
    assert (harness.storage.root / accepted.analysis_id / "sample.bin").exists()
    next_step(
        harness, accepted.analysis_id, seconds=harness.config.retry_delay_seconds + 0.01
    )
    finished = next_step(harness, accepted.analysis_id)
    assert finished.status == "COMPLETED" and len(harness.initial.calls) == 2


def test_database_failure_after_initial_commit_resumes_next_phase(harness):
    accepted = submit(harness)
    harness.repository.failures["release"] = 1
    retry = harness.processor.resume(accepted.analysis_id)
    assert retry.phase == "FINALIZING" and retry.initial_result is not None
    assert retry.error["code"] == "DATABASE_ERROR"
    finished = next_step(
        harness, accepted.analysis_id, seconds=harness.config.retry_delay_seconds + 0.01
    )
    assert finished.status == "COMPLETED" and len(harness.initial.calls) == 1


def test_database_outage_during_checkpoint_and_error_save_recovers_after_lease(harness):
    accepted = submit(harness)
    harness.repository.failures.update(save_initial=1, release=1)
    deferred = harness.processor.resume(accepted.analysis_id)
    assert deferred.phase == "INITIAL" and deferred.claimed and not deferred.terminal
    assert harness.repository.pending_ids() == []
    recovered = next_step(
        harness, accepted.analysis_id, seconds=harness.config.lease_seconds + 0.01
    )
    assert recovered.phase == "FINALIZING"
    assert next_step(harness, accepted.analysis_id).status == "COMPLETED"


def test_claim_database_outage_leaves_the_request_pending(harness):
    accepted = submit(harness)
    harness.repository.failures["claim"] = 1
    with pytest.raises(BackendError) as error:
        harness.processor.resume(accepted.analysis_id)
    assert error.value.code == "DATABASE_ERROR"
    assert harness.service.get(accepted.analysis_id).status == "QUEUED"
    assert harness.initial.calls == []


def test_expired_owner_cannot_save_initial_or_finish_new_owners_job(harness):
    accepted = submit(harness)
    new_token = "11111111-1111-1111-1111-111111111111"

    def lose_ownership(path, sha256, check):
        harness.repository.leases[accepted.analysis_id] = (
            new_token,
            harness.repository.now + timedelta(seconds=harness.config.lease_seconds),
        )
        return initial_result()

    harness.initial.outcomes.append(lose_ownership)
    row = harness.processor.resume(accepted.analysis_id)
    assert row.phase == "INITIAL" and row.initial_result is None and not row.terminal
    assert harness.repository.leases[accepted.analysis_id][0] == new_token
    assert harness.repository.calls["finish"] == 0


def test_active_claim_cannot_be_processed_twice(harness):
    accepted = submit(harness)
    claim = harness.repository.claim(accepted.analysis_id, harness.config.lease_seconds)
    assert claim.token
    row = harness.processor.resume(accepted.analysis_id)
    assert row.claimed
    assert harness.initial.calls == []
    assert harness.repository.calls["save_initial"] == 0


def test_resume_ready_respects_stop_and_poll_backoff(harness):
    ids = [submit(harness, marker=index).analysis_id for index in range(3)]
    calls = 0

    def should_stop():
        nonlocal calls
        calls += 1
        return calls > 1

    processed = harness.processor.resume_ready(limit=3, should_stop=should_stop)
    assert [row.analysis_id for row in processed] == [ids[0]]
    assert harness.repository.pending_ids() == ids[1:]
    assert len(harness.initial.calls) == 1


def test_idempotent_replay_discards_only_the_new_upload(harness):
    original = submit(harness, idempotency_key="same-request")
    replay = submit(harness, idempotency_key="same-request")
    assert replay.analysis_id == original.analysis_id
    assert list(harness.repository.rows) == [original.analysis_id]
    assert [path.parent.name for path in harness.storage.root.glob("*/sample.bin")] == [
        original.analysis_id
    ]
    # Equal hashes with a new request are separate analyses with duplicate metadata.
    duplicate = submit(harness)
    assert duplicate.analysis_id != original.analysis_id
    assert duplicate.duplicate_of == original.analysis_id
    assert len(list(harness.storage.root.glob("*/sample.bin"))) == 2


def test_conflicting_idempotency_key_cleans_up_rejected_upload(harness):
    original = submit(harness, idempotency_key="same-request")
    with pytest.raises(BackendError) as error:
        submit(harness, marker=1, idempotency_key="same-request")
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    assert list(harness.repository.rows) == [original.analysis_id]
    assert [path.parent.name for path in harness.storage.root.glob("*/sample.bin")] == [
        original.analysis_id
    ]


def test_batch_upload_is_all_or_none_before_registration(harness):
    with pytest.raises(BackendError) as error:
        harness.service.submit(
            [
                (io.BytesIO(harmless_pe_header()), "header.exe"),
                (io.BytesIO(b"invalid harmless text"), "invalid.exe"),
            ],
            batch=True,
        )
    assert error.value.code == "INVALID_PE"
    assert harness.repository.rows == {} and harness.repository.batches == {}
    assert harness.repository.calls["register"] == 0
    assert list(harness.storage.root.glob("*/sample.bin")) == []


def test_batch_database_failure_removes_all_unregistered_uploads(harness):
    harness.repository.failures["register"] = 1
    with pytest.raises(BackendError) as error:
        harness.service.submit(
            [
                (io.BytesIO(harmless_pe_header(index)), f"header-{index}.exe")
                for index in range(2)
            ],
            batch=True,
        )
    assert error.value.code == "DATABASE_ERROR"
    assert harness.repository.rows == {} and harness.repository.batches == {}
    assert list(harness.storage.root.glob("*/sample.bin")) == []


def test_uncertain_database_commit_does_not_delete_accepted_original(
    harness, monkeypatch
):
    original_register = harness.repository.register

    def commit_then_disconnect(*args, **kwargs):
        original_register(*args, **kwargs)
        raise BackendError(
            "DATABASE_ERROR", "Synthetic connection loss after commit.", retryable=True
        )

    monkeypatch.setattr(harness.repository, "register", commit_then_disconnect)
    with pytest.raises(BackendError):
        submit(harness)
    assert len(harness.repository.rows) == 1
    analysis_id = next(iter(harness.repository.rows))
    assert (harness.storage.root / analysis_id / "sample.bin").exists()
    assert harness.repository.calls["location_referenced"] == 1


def test_database_uncertainty_during_cleanup_keeps_original(harness, caplog):
    harness.repository.failures.update(register=1, location_referenced=1)
    with pytest.raises(BackendError) as error:
        submit(harness)
    assert error.value.code == "DATABASE_ERROR"
    assert harness.repository.rows == {}
    assert len(list(harness.storage.root.glob("*/sample.bin"))) == 1
    assert "upload_cleanup_deferred" in caplog.text


@pytest.mark.parametrize(
    "key", ["", "contains space", "line\nbreak", "한글", "a" * 201]
)
def test_invalid_idempotency_key_is_rejected_before_storage(harness, key):
    with pytest.raises(BackendError) as error:
        submit(harness, idempotency_key=key)
    assert error.value.code == "INVALID_IDEMPOTENCY_KEY"
    assert not harness.storage.root.exists()


def test_batch_status_counts_and_replay_are_consistent(harness):
    def files():
        return [
            (io.BytesIO(harmless_pe_header(index)), f"header-{index}.exe")
            for index in range(2)
        ]

    accepted = harness.service.submit(
        files(), batch=True, idempotency_key="batch-request"
    )
    replay = harness.service.submit(
        files(), batch=True, idempotency_key="batch-request"
    )
    assert replay.batch_id == accepted.batch_id
    assert [row.analysis_id for row in replay.analyses] == [
        row.analysis_id for row in accepted.analyses
    ]
    first, second = accepted.analyses
    complete(harness, first.analysis_id)
    harness.initial.outcomes.append(
        BackendError("PARSE_FAILED", "Synthetic parse failure.")
    )
    harness.processor.resume(second.analysis_id)
    summary = harness.service.get_batch(accepted.batch_id)
    assert summary.total_count == summary.finished_count == 2
    assert summary.status_counts == {
        "QUEUED": 0,
        "RUNNING": 0,
        "COMPLETED": 1,
        "FAILED": 1,
    }
    assert len(list(harness.storage.root.glob("*/sample.bin"))) == 2


def test_review_requires_terminal_state_and_preserves_system_result(harness):
    accepted = submit(harness)
    request = ReviewRequest(
        analyst_final_verdict="MALICIOUS",
        analyst_notes="Synthetic analyst correction.",
        reviewer_id="reviewer-1",
        expected_revision=0,
    )
    with pytest.raises(BackendError) as early:
        harness.service.review(accepted.analysis_id, request)
    assert early.value.code == "ANALYSIS_NOT_FINISHED"
    system = complete(harness, accepted.analysis_id)
    reviewed = harness.service.review(accepted.analysis_id, request)
    assert reviewed.revision == 1 and reviewed.analyst_final_verdict == "MALICIOUS"
    after = harness.service.get(accepted.analysis_id)
    assert after.initial_result == system.initial_result
    assert after.final_assessment == system.final_assessment
    assert views.analysis(after).approval_status == "MODIFIED"
    with pytest.raises(BackendError) as stale:
        harness.service.review(accepted.analysis_id, request)
    assert stale.value.code == "REVIEW_CONFLICT"
    history = harness.service.reviews(accepted.analysis_id)
    assert len(history.items) == 1 and history.items[0].revision == 1


def test_review_deferral_is_append_only_and_returns_pending_approval(harness):
    accepted = submit(harness)
    complete(harness, accepted.analysis_id)
    harness.service.review(
        accepted.analysis_id,
        ReviewRequest(
            analyst_final_verdict="BENIGN",
            reviewer_id="reviewer-1",
            expected_revision=0,
        ),
    )
    deferred = harness.service.review(
        accepted.analysis_id,
        ReviewRequest(
            analyst_final_verdict=None,
            analyst_notes="Need more evidence.",
            reviewer_id="reviewer-2",
            expected_revision=1,
        ),
    )
    assert deferred.revision == 2 and deferred.analyst_final_verdict is None
    assert [
        row.analyst_final_verdict
        for row in harness.service.reviews(accepted.analysis_id).items
    ] == ["BENIGN", None]
    assert (
        views.analysis(harness.service.get(accepted.analysis_id)).approval_status
        == "PENDING"
    )


def test_cleanup_is_previewed_idempotent_and_never_removes_active_input(harness):
    old = submit(harness)
    complete(harness, old.analysis_id)
    harness.clock.advance(harness.config.retention_hours * 3600 + 1)
    active = submit(harness, marker=1)
    old_path = harness.storage.root / old.analysis_id / "sample.bin"
    active_path = harness.storage.root / active.analysis_id / "sample.bin"
    preview = harness.service.cleanup()
    assert (
        preview["candidate_ids"] == [old.analysis_id] and preview["deleted_ids"] == []
    )
    assert old_path.exists()
    deleted = harness.service.cleanup(delete=True)
    assert deleted["deleted_ids"] == [old.analysis_id]
    assert not old_path.exists() and active_path.exists()
    assert harness.service.get(old.analysis_id).initial_result is not None
    assert harness.service.cleanup(delete=True)["candidate_ids"] == []


def test_cleanup_can_retry_after_file_delete_and_marker_database_failure(harness):
    accepted = submit(harness)
    complete(harness, accepted.analysis_id)
    harness.clock.advance(harness.config.retention_hours * 3600 + 1)
    harness.repository.failures["mark_storage_deleted"] = 1
    with pytest.raises(BackendError) as error:
        harness.service.cleanup(delete=True)
    assert error.value.code == "DATABASE_ERROR"
    assert not (harness.storage.root / accepted.analysis_id / "sample.bin").exists()
    assert harness.service.get(accepted.analysis_id).storage_deleted_at is None
    assert harness.service.cleanup(delete=True)["deleted_ids"] == [accepted.analysis_id]


def test_missing_stored_sample_yields_failure_for_review(harness):
    accepted = submit(harness)
    harness.storage.delete(stored_sample(harness.service.get(accepted.analysis_id)))
    finished = harness.processor.resume(accepted.analysis_id)
    assert finished.status == "FAILED" and finished.error["code"] == "FILE_NOT_FOUND"
    assert finished.final_assessment["final_verdict"] == "UNCERTAIN"
    assert harness.initial.calls == []


def test_listing_and_missing_resources_use_public_contracts(harness):
    first, second = submit(harness), submit(harness, marker=1)
    page = harness.service.list_analyses(limit=1, offset=0)
    assert page.total_count == 2 and page.analyses[0].analysis_id == second.analysis_id
    encoded = page.model_dump_json()
    assert "file_location" not in encoded and "local://" not in encoded
    assert harness.service.list_analyses(sha256=first.sha256).total_count == 1
    for operation, code in (
        (lambda: harness.service.get("missing"), "ANALYSIS_NOT_FOUND"),
        (lambda: harness.service.get_batch("missing"), "BATCH_NOT_FOUND"),
        (lambda: harness.service.reviews("missing"), "ANALYSIS_NOT_FOUND"),
    ):
        with pytest.raises(BackendError) as error:
            operation()
        assert error.value.code == code and error.value.http_status == 404


class SingleHeartbeat:
    def __init__(self):
        self.calls = 0

    def wait(self, timeout):
        self.calls += 1
        return self.calls > 1


def test_lease_heartbeat_database_failure_revokes_ownership(harness):
    accepted = submit(harness)
    claim = harness.repository.claim(accepted.analysis_id, harness.config.lease_seconds)
    lease = _Lease(
        harness.repository, accepted.analysis_id, claim.token, harness.config
    )
    lease.stop = SingleHeartbeat()
    harness.repository.failures["renew"] = 1
    lease._heartbeat()
    with pytest.raises(LeaseLost):
        lease.check()
    assert harness.repository.calls["renew"] == 1


def test_operation_deadline_remains_retryable_when_observed_by_heartbeat(harness):
    accepted = submit(harness)
    claim = harness.repository.claim(accepted.analysis_id, harness.config.lease_seconds)
    lease = _Lease(
        harness.repository, accepted.analysis_id, claim.token, harness.config
    )
    lease.stop = SingleHeartbeat()
    harness.clock.advance(harness.config.operation_timeout_seconds + 0.01)
    lease._heartbeat()
    with pytest.raises(BackendError) as error:
        lease.check()
    assert error.value.code == "PROCESSING_TIMEOUT" and error.value.retryable is True
