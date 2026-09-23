"""Resume tests use harmless bytes, real orchestration, and the real Worker publisher."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from trust_triage.deep_analysis import DeepAnalysisConfig
from trust_triage.deep_analysis.service import DeepServiceLimits, _tool_result_preview
from trust_triage.deep_analysis.service_models import DeepAnalysisPhase
from trust_triage.dynamic_analysis import DynamicAnalysisStatus
from trust_triage.speakeasy_worker.models import (
    InvalidJob,
    JobConflict,
    JobStatus,
    failure_result,
    result_from_analysis,
)
from trust_triage.storage import ArtifactError, ArtifactReference

from .fakes import ServiceHarness, complete_worker, detached, dynamic_result


@pytest.fixture
def harness(tmp_path, monkeypatch):
    # Retry writes immediately in tests; there is no timing assertion or external I/O.
    monkeypatch.setattr("trust_triage.deep_analysis.service.time.sleep", lambda _: None)
    return ServiceHarness(tmp_path)


def test_sufficient_static_completes_and_llm_runs_only_once(tmp_path):
    h = ServiceHarness(tmp_path, sufficient=True)
    result = h.service.start(h.request)
    assert result.phase is DeepAnalysisPhase.COMPLETED
    assert result.result["final_verdict"] == "MALICIOUS"
    assert result.result["executed_tiers"] == ["CAPA", "FLOSS"]
    assert {item.source for item in h.llm.inputs[0]} == {"CAPA", "FLOSS"}
    assert h.calls == (1, 1, 1, 1)
    assert h.queue.sent == []
    assert h.worker_repository.get(h.request.analysis_id) is None
    stable = h.service.get(h.request.analysis_id)
    h.restart()
    assert h.service.start(h.request).result == result.result
    assert h.service.resume(h.request.analysis_id).result == result.result
    assert h.service.get(h.request.analysis_id) == stable
    assert h.calls == (1, 1, 1, 1)


def test_large_legacy_checkpoint_get_deduplicates_terminal_evidence(tmp_path):
    h = ServiceHarness(tmp_path, sufficient=True)
    h.service.start(h.request)
    row = h.repository.rows[h.request.analysis_id]
    checkpoint = detached(row.checkpoint)
    result = detached(row.result)
    padding = "x" * (4 * 1024 * 1024)
    checkpoint["static"]["evidence"][0]["details"]["padding"] = padding
    result["evidence"][0]["details"]["padding"] = padding
    h.repository.rows[h.request.analysis_id] = replace(
        row,
        checkpoint=checkpoint,
        result=result,
    )

    view = h.service.get(h.request.analysis_id)
    encoded = json.dumps(view, ensure_ascii=False).encode("utf-8")

    assert len(encoded) < 8 * 1024 * 1024
    assert view["view_schema_version"] == "deep-view-v2"
    assert view["evidence"][0]["details"]["padding"] == padding
    assert "evidence" not in view["result"]
    assert view["result"]["evidence_ref"] == "#/evidence"
    assert "tool_statuses" not in view["result"]
    assert view["result"]["tool_statuses_ref"] == "#/tool_statuses"


def test_large_static_tool_result_is_archived_and_get_returns_a_bounded_summary(
    harness,
):
    h = harness
    original = h.capa.result.to_dict
    h.capa.result.to_dict = lambda: {
        **original(),
        "match_details": [{"tree": "x" * (256 * 1024)}],
    }

    waiting = h.service.start(h.request)
    capa = waiting.checkpoint["static"]["tool_results"]["CAPA"]
    reference = capa["details_reference"]
    artifact = h.artifact_storage.read(ArtifactReference(**reference))
    view = h.service.get(h.request.analysis_id)

    assert len(artifact) > 256 * 1024
    assert json.loads(artifact)["match_details"][0]["tree"] == "x" * (256 * 1024)
    assert "match_details" not in capa
    assert view["static_results"]["CAPA"]["details_reference"] == reference
    assert len(json.dumps(view, ensure_ascii=False).encode("utf-8")) < 1024 * 1024


@pytest.mark.parametrize("tool", ["CAPA", "FLOSS"])
def test_individual_tool_result_over_8_mib_keeps_status_and_size_diagnostic(
    harness, tool
):
    h = harness
    analyzer = h.capa if tool == "CAPA" else h.floss
    original = analyzer.result.to_dict
    detail = (
        {"match_details": [{"tree": "x" * (8 * 1024 * 1024)}]}
        if tool == "CAPA"
        else {"strings": [{"string": "x" * (8 * 1024 * 1024)}]}
    )
    analyzer.result.to_dict = lambda: {**original(), **detail}

    waiting = h.service.start(h.request)
    result = waiting.checkpoint["static"]["tool_results"][tool]

    assert waiting.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert waiting.checkpoint["static"]["tool_statuses"][tool] == "SUCCESS"
    assert result["status"] == "SUCCESS"
    assert result["details_status"] == "OMITTED_TOO_LARGE"
    assert result["details_error"]["code"] == "RESULT_TOO_LARGE"
    assert result["details_error"]["actual_bytes"] > 8 * 1024 * 1024
    assert result["details_error"]["limit_bytes"] == 8 * 1024 * 1024
    assert "details_reference" not in result
    assert h.service.get(h.request.analysis_id)["static_results"][tool] == result


def test_floss_limited_mode_survives_archived_result_preview() -> None:
    result = _tool_result_preview("FLOSS", {
        "status": "SUCCESS",
        "sha256": "a" * 64,
        "analysis_metadata": {
            "limited_mode": True,
            "limited_reason": "INPUT_EXCEEDS_16_MIB",
            "sample_path": "C:/private/sample.exe",
        },
        "warnings": ["FLOSS static-only limited mode selected"],
        "strings": [{"string": "visible static string"}],
    })

    assert result["status"] == "SUCCESS"
    assert result["limited_mode"] is True
    assert result["limited_reason"] == "INPUT_EXCEEDS_16_MIB"
    assert result["warnings"] == ["FLOSS static-only limited mode selected"]
    assert "analysis_metadata" not in result
    assert "C:/private" not in json.dumps(result)


def test_static_archive_failure_preserves_tool_status_and_diagnostic(
    harness, monkeypatch
):
    h = harness
    original = h.capa.result.to_dict
    h.capa.result.to_dict = lambda: {
        **original(),
        "match_details": [{"tree": "x" * (256 * 1024)}],
    }

    def fail_archive(*_args, **_kwargs):
        raise ArtifactError("S3_WRITE_FAILED", "storage unavailable", retryable=True)

    monkeypatch.setattr(h.artifact_storage, "put_json", fail_archive)
    waiting = h.service.start(h.request)
    result = waiting.checkpoint["static"]["tool_results"]["CAPA"]

    assert waiting.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert waiting.checkpoint["static"]["tool_statuses"]["CAPA"] == "SUCCESS"
    assert result["status"] == "SUCCESS"
    assert result["details_status"] == "ARCHIVE_FAILED"
    assert result["details_error"]["code"] == "S3_WRITE_FAILED"
    assert result["details_error"]["actual_bytes"] > 128 * 1024


def test_large_legacy_static_result_is_compacted_without_mutating_checkpoint(tmp_path):
    h = ServiceHarness(tmp_path, sufficient=True)
    h.service.start(h.request)
    row = h.repository.rows[h.request.analysis_id]
    checkpoint = detached(row.checkpoint)
    checkpoint["static"]["tool_results"]["CAPA"]["match_details"] = [
        {"tree": "x" * 8_386_000}
    ]
    h.repository.rows[h.request.analysis_id] = replace(row, checkpoint=checkpoint)

    view = h.service.get(h.request.analysis_id)

    assert view["static_results_compacted"] is True
    assert view["static_results"]["CAPA"]["details_status"] == "INLINE_IN_CHECKPOINT"
    assert "match_details" not in view["static_results"]["CAPA"]
    assert (
        "match_details"
        in h.repository.rows[h.request.analysis_id].checkpoint["static"][
            "tool_results"
        ]["CAPA"]
    )


def test_legacy_waiting_checkpoint_archives_large_result_on_resume(tmp_path):
    h = ServiceHarness(tmp_path)
    waiting = h.service.start(h.request)
    assert waiting.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    row = h.repository.rows[h.request.analysis_id]
    checkpoint = detached(row.checkpoint)
    checkpoint["static"]["tool_results"]["CAPA"]["match_details"] = [
        {"tree": "x" * (256 * 1024)}
    ]
    h.repository.rows[h.request.analysis_id] = replace(row, checkpoint=checkpoint)
    calls_before = h.calls

    resumed = h.service.resume(h.request.analysis_id)
    capa = resumed.checkpoint["static"]["tool_results"]["CAPA"]

    assert resumed.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert "details_reference" in capa
    assert "match_details" not in capa
    assert h.calls == calls_before
    assert (
        h.service.get(h.request.analysis_id)["static_results"]["CAPA"][
            "details_reference"
        ]
        == capa["details_reference"]
    )


def test_waiting_checkpoint_commits_before_queue_send_and_survives_restart(harness):
    h = harness
    original_send = h.queue.send

    def checked_send(job):
        saved = h.repository.get(job.analysis_id)
        assert saved.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
        assert (
            saved.checkpoint["static"]["tool_results"]["FLOSS"]["status"] == "SUCCESS"
        )
        assert h.llm.calls == 0
        return original_send(job)

    h.queue.send = checked_send
    waiting = h.service.start(h.request)
    assert waiting.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    saved = detached(waiting.checkpoint)
    waiting.checkpoint["static"]["tool_results"]["CAPA"]["status"] = "changed by caller"
    assert h.repository.get(h.request.analysis_id).checkpoint == saved
    h.restart()
    for _ in range(3):
        assert h.service.start(h.request).phase is DeepAnalysisPhase.WAITING_SPEAKEASY
        assert (
            h.service.resume(h.request.analysis_id).phase
            is DeepAnalysisPhase.WAITING_SPEAKEASY
        )
        view = h.service.get(h.request.analysis_id)
        assert view["status"] == "RUNNING"
        assert view["tool_statuses"]["SPEAKEASY"] == "QUEUED"
        assert view["static_results"]["CAPA"]["status"] == "SUCCESS"
        assert len(view["evidence"]) == 2
    assert h.calls == (1, 1, 0, 1)
    assert len(h.queue.sent) == 1


def test_transient_publish_failure_restarts_without_repeating_static(harness):
    h = harness
    h.queue.fail_send = True
    waiting = h.service.start(h.request)
    assert waiting.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    assert waiting.last_error["code"] == "SQS_ERROR"
    assert h.worker_repository.get(h.request.analysis_id).dispatch_pending
    assert h.calls == (1, 1, 0, 1)
    h.queue.fail_send = False
    h.restart()
    assert h.service.resume(h.request.analysis_id).last_error == waiting.last_error
    assert not h.queue.sent
    h.repository.retry_due(h.request.analysis_id)
    h.service.resume(h.request.analysis_id)
    assert len(h.queue.sent) == 1
    assert not h.worker_repository.get(h.request.analysis_id).dispatch_pending
    assert h.calls == (1, 1, 0, 1)


@pytest.mark.parametrize("operation", ["save_checkpoint", "finish"])
def test_transient_db_write_retries_reuse_computed_tools_and_llm(harness, operation):
    h = harness
    h.capa.result = type(h.capa.result)("CAPA", sufficient=True)
    h.repository.failures[operation] = 2
    result = h.service.start(h.request)
    assert result.phase is DeepAnalysisPhase.COMPLETED
    assert h.repository.calls[operation] == 3
    assert h.calls == (1, 1, 1, 1)


def test_worker_running_is_waiting_and_get_is_read_only(harness):
    h = harness
    h.service.start(h.request)
    claim = h.worker_repository.claim(h.request.worker_job, 180)
    assert claim.token
    before = (h.calls, len(h.queue.sent), h.repository.calls["claim"])
    for _ in range(3):
        view = h.service.get(h.request.analysis_id)
        assert view["phase"] == "WAITING_SPEAKEASY"
        assert view["tool_statuses"]["SPEAKEASY"] == "RUNNING"
    assert (h.calls, len(h.queue.sent), h.repository.calls["claim"]) == before
    assert (
        h.service.resume(h.request.analysis_id).phase
        is DeepAnalysisPhase.WAITING_SPEAKEASY
    )
    assert h.calls == (1, 1, 0, 1)


def test_parent_cancellation_is_durable_and_cancels_queued_worker(harness):
    h = harness
    h.service.start(h.request)

    cancelled = h.service.cancel(
        h.request.analysis_id,
        code="PARENT_DEEP_WAIT_TIMEOUT",
        message="Parent analysis deadline expired",
    )

    assert cancelled.phase is DeepAnalysisPhase.FAILED
    assert "PARENT_DEEP_WAIT_TIMEOUT" in cancelled.result["reason_codes"]
    worker = h.worker_repository.get(h.request.analysis_id)
    assert worker.status is JobStatus.FAILED
    assert worker.result["error"]["code"] == "PARENT_ANALYSIS_CANCELLED"
    assert h.service.resume_ready() == []


def test_parent_cancellation_fences_active_owner_then_reconciles(harness):
    h = harness
    h.service.register(h.request)
    old = h.repository.claim(h.request.analysis_id, 600)
    assert old.token

    pending = h.service.cancel(
        h.request.analysis_id,
        code="PARENT_DEEP_WAIT_TIMEOUT",
        message="Parent analysis deadline expired",
    )

    assert pending.phase is DeepAnalysisPhase.STATIC
    assert pending.cancellation["code"] == "PARENT_DEEP_WAIT_TIMEOUT"
    assert not h.repository.renew(h.request.analysis_id, old.token, 600)
    h.repository.now += 601
    reconciled = h.service.resume_ready()
    assert len(reconciled) == 1
    assert reconciled[0].phase is DeepAnalysisPhase.FAILED
    assert h.calls == (0, 0, 0, 0)


def test_parent_cancellation_never_overwrites_active_worker(harness):
    h = harness
    h.service.start(h.request)
    active = h.worker_repository.claim(h.request.worker_job, 180)
    assert active.token

    cancelled = h.service.cancel(
        h.request.analysis_id,
        code="PARENT_DEEP_WAIT_TIMEOUT",
        message="Parent analysis deadline expired",
    )

    assert cancelled.phase is DeepAnalysisPhase.FAILED
    worker = h.worker_repository.get(h.request.analysis_id)
    assert worker.status is JobStatus.RUNNING
    assert h.worker_repository.finish(
        h.request.analysis_id,
        active.token,
        result_from_analysis(h.request.worker_job, dynamic_result()),
    )
    assert h.worker_repository.get(h.request.analysis_id).status is JobStatus.COMPLETED


def test_worker_envelope_unwraps_inner_observations_and_finishes_once(harness):
    h = harness
    h.service.start(h.request)
    worker_result = complete_worker(h.worker_repository, h.request)
    assert "observed_apis" not in worker_result
    h.restart()
    completed = h.service.resume(h.request.analysis_id)
    assert completed.phase is DeepAnalysisPhase.COMPLETED
    assert completed.result["executed_tiers"] == ["CAPA", "FLOSS", "SPEAKEASY"]
    assert completed.result["final_verdict"] == "MALICIOUS"
    assert {item.source for item in h.llm.inputs[0]} == {"CAPA", "FLOSS", "SPEAKEASY"}
    assert any(
        technique.technique_id == "T1055"
        for item in h.llm.inputs[0]
        for technique in item.attack_techniques
    )
    assert h.calls == (1, 1, 1, 1)
    view = h.service.get(h.request.analysis_id)
    assert view["speakeasy_result"] == worker_result
    assert view["tool_statuses"]["SPEAKEASY"] == "SUCCESS"
    h.worker_repository.rows.clear()
    h.restart()
    assert h.service.get(h.request.analysis_id) == view
    assert h.service.start(h.request).result == completed.result
    assert h.service.resume_ready() == []
    assert h.calls == (1, 1, 1, 1)


@pytest.mark.parametrize("failure", ["timeout", "infrastructure", "worker_deadline"])
def test_worker_failures_preserve_static_and_never_become_malicious_evidence(
    harness, failure
):
    h = harness
    waiting = h.service.start(h.request)
    static_evidence = waiting.checkpoint["static"]["evidence"]
    if failure == "infrastructure":
        payload = failure_result(
            h.request.worker_job, "S3_ERROR", "Synthetic S3 failure"
        )
        status = "TOOL_ERROR"
    else:
        payload = result_from_analysis(
            h.request.worker_job, dynamic_result(DynamicAnalysisStatus.TIMEOUT)
        )
        status = "TIMEOUT"
        if failure == "worker_deadline":
            payload["analysis"] = dynamic_result().to_dict()
            payload["tool_status"] = "SUCCESS"
            payload["error"] = {
                "code": "JOB_TIMEOUT",
                "message": "Worker deadline expired",
            }
    complete_worker(h.worker_repository, h.request, payload)
    result = h.restart().resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.FAILED
    assert result.result["final_verdict"] == "UNKNOWN"
    assert result.result["requires_human_review"] is True
    assert result.result["evidence"] == static_evidence
    assert result.result["tool_statuses"]["SPEAKEASY"] == status
    assert h.calls == (1, 1, 0, 1)
    assert h.service.get(h.request.analysis_id)["speakeasy_result"] == payload


@pytest.mark.parametrize(
    "corruption", ["outer_sha", "inner_sha", "schema", "worker_job"]
)
def test_mismatched_worker_result_is_rejected_without_llm(harness, corruption):
    h = harness
    h.service.start(h.request)
    complete_worker(h.worker_repository, h.request)
    row = h.worker_repository.rows[h.request.analysis_id]
    payload = detached(row.result)
    if corruption == "outer_sha":
        payload["sha256"] = "f" * 64
    elif corruption == "inner_sha":
        payload["analysis"]["sha256"] = "f" * 64
    elif corruption == "schema":
        payload["schema_version"] = "unsupported-version"
    else:
        row = replace(
            row, job=replace(row.job, file_location="s3://test-bucket/other.bin")
        )
    h.worker_repository.rows[h.request.analysis_id] = replace(row, result=payload)
    result = h.restart().resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.FAILED
    reason = (
        "WORKER_JOB_CONFLICT"
        if corruption == "worker_job"
        else "INVALID_PIPELINE_RESULT"
    )
    assert reason in result.result["reason_codes"]
    assert result.result["final_verdict"] == "UNKNOWN"
    assert {item["source"] for item in result.result["evidence"]} == {"CAPA", "FLOSS"}
    assert h.calls == (1, 1, 0, 1)


def test_changed_config_fails_safely_and_keeps_static_visible(harness):
    h = harness
    h.service.start(h.request)
    h.restart(config=DeepAnalysisConfig(capa_reliability=0.4))
    result = h.service.resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.FAILED
    assert "PIPELINE_CONFIG_CHANGED" in result.result["reason_codes"]
    view = h.service.get(h.request.analysis_id)
    assert view["status"] == "FAILED"
    assert {item["source"] for item in view["evidence"]} == {"CAPA", "FLOSS"}
    assert h.calls == (1, 1, 0, 1)


@pytest.mark.parametrize("tool", ["capa", "floss"])
def test_static_hash_conflict_never_dispatches_worker_or_calls_llm(harness, tool):
    h = harness
    result = getattr(h, tool).result
    result.sha256 = "b" * 64
    result.evidence = replace(result.evidence, sha256=result.sha256)
    completed = h.service.start(h.request)
    assert completed.phase is DeepAnalysisPhase.FAILED
    assert "INVALID_PIPELINE_RESULT" in completed.result["reason_codes"]
    assert completed.result["final_verdict"] == "UNKNOWN"
    assert not h.queue.sent
    assert h.worker_repository.get(h.request.analysis_id) is None
    assert h.llm.calls == 0
    assert all(
        item["sha256"] == h.request.sha256 for item in completed.result["evidence"]
    )


@pytest.mark.parametrize(
    "corruption", ["version", "hash", "assessment", "missing_static"]
)
def test_corrupted_checkpoint_fails_but_get_exposes_terminal_failure(
    harness, corruption
):
    h = harness
    h.service.start(h.request)
    row = h.repository.rows[h.request.analysis_id]
    payload = detached(row.checkpoint)
    if corruption == "version":
        payload["schema_version"] = "unrecognized"
    elif corruption == "hash":
        payload["static"]["sha256"] = "f" * 64
    elif corruption == "assessment":
        payload["static"]["assessment"]["weighted_score"] = 0.95
    else:
        del payload["static"]
    h.repository.rows[h.request.analysis_id] = replace(row, checkpoint=payload)
    assert (
        h.service.get(h.request.analysis_id)["checkpoint_error"] == "INVALID_CHECKPOINT"
    )
    result = h.restart().resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.FAILED
    view = h.service.get(h.request.analysis_id)
    assert view["status"] == "FAILED"
    assert view["result"]["final_verdict"] == "UNKNOWN"
    assert view["evidence"] == []
    assert h.calls == (1, 1, 0, 1)


def test_background_resume_ready_does_static_and_finalization_without_ui(harness):
    h = harness
    assert h.service.register(h.request).phase is DeepAnalysisPhase.STATIC
    assert h.calls == (0, 0, 0, 0)
    assert h.service.get(h.request.analysis_id)["status"] == "QUEUED"
    assert h.service.get("unknown") is None
    assert h.calls == (0, 0, 0, 0)
    waiting = h.restart().resume_ready()
    assert len(waiting) == 1 and waiting[0].phase is DeepAnalysisPhase.WAITING_SPEAKEASY
    complete_worker(h.worker_repository, h.request)
    finished = h.restart().resume_ready()
    assert len(finished) == 1 and finished[0].phase is DeepAnalysisPhase.COMPLETED
    assert h.calls == (1, 1, 1, 1)


def test_finalizing_checkpoint_survives_restart_and_worker_row_loss(
    harness, monkeypatch
):
    h = harness
    h.service.start(h.request)
    payload = complete_worker(h.worker_repository, h.request)

    def stop_after_finalizing(record):
        if record.phase is DeepAnalysisPhase.FINALIZING:
            raise KeyboardInterrupt(
                "simulated process exit after durable Worker checkpoint"
            )

    h.repository.on_save = stop_after_finalizing
    with pytest.raises(KeyboardInterrupt):
        h.service.resume(h.request.analysis_id)
    saved = h.repository.get(h.request.analysis_id)
    assert saved.phase is DeepAnalysisPhase.FINALIZING
    assert saved.checkpoint["worker_result"] == payload
    assert h.llm.calls == 0
    h.repository.on_save = None
    h.worker_repository.rows.clear()
    result = h.restart().resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.COMPLETED
    assert h.calls == (1, 1, 1, 1)


@pytest.mark.parametrize("worker_state", ["absent", "pending", "running"])
def test_expired_wait_deadline_does_not_submit_new_work(harness, worker_state):
    h = harness
    h.service.start(h.request)
    row = h.repository.rows[h.request.analysis_id]
    checkpoint = detached(row.checkpoint)
    checkpoint["waiting_since"] = "2000-01-01T00:00:00+00:00"
    h.repository.rows[h.request.analysis_id] = replace(row, checkpoint=checkpoint)
    if worker_state == "absent":
        h.worker_repository.rows.clear()
    elif worker_state == "pending":
        worker = h.worker_repository.rows[h.request.analysis_id]
        h.worker_repository.rows[h.request.analysis_id] = replace(
            worker, dispatch_pending=True
        )
    else:
        h.worker_repository.claim(h.request.worker_job, 180)
    result = h.restart(limits=DeepServiceLimits(speakeasy_wait_seconds=1)).resume(
        h.request.analysis_id
    )
    assert result.phase is DeepAnalysisPhase.FAILED
    assert "SPEAKEASY_WAIT_TIMEOUT" in result.result["reason_codes"]
    assert len(h.queue.sent) == 1
    assert h.calls == (1, 1, 0, 1)


def test_busy_claim_defers_tools_until_expired_owner_is_replaced(harness):
    h = harness
    h.service.register(h.request)
    old = h.repository.claim(h.request.analysis_id, 600)
    assert h.service.resume(h.request.analysis_id).claimed
    assert h.calls == (0, 0, 0, 0)
    h.repository.now += 601
    assert (
        h.service.resume(h.request.analysis_id).phase
        is DeepAnalysisPhase.WAITING_SPEAKEASY
    )
    assert not h.repository.renew(h.request.analysis_id, old.token, 600)
    assert not h.repository.release(h.request.analysis_id, old.token)
    assert h.calls == (1, 1, 0, 1)


def test_expired_token_during_static_does_not_publish_or_save(harness):
    h = harness
    h.capa.callback = lambda: setattr(h.repository, "now", h.repository.now + 601)
    result = h.service.start(h.request)
    assert result.phase is DeepAnalysisPhase.STATIC
    assert result.checkpoint is None
    assert result.result is None
    assert h.queue.sent == []
    assert h.llm.calls == 0


def test_repeated_publish_failures_end_with_static_evidence_preserved(harness):
    h = harness
    h.queue.fail_send = True
    h.service.start(h.request)
    for _ in range(2):
        h.repository.retry_due(h.request.analysis_id)
        result = h.restart().resume(h.request.analysis_id)
    assert result.phase is DeepAnalysisPhase.FAILED
    assert "DEEP_RETRY_EXHAUSTED" in result.result["reason_codes"]
    assert {item["source"] for item in result.result["evidence"]} == {"CAPA", "FLOSS"}
    assert h.calls == (1, 1, 0, 1)


def test_conflicting_request_and_unknown_route_do_not_start_tools(harness):
    h = harness
    h.service.register(h.request)
    with pytest.raises(JobConflict):
        h.service.start(replace(h.request, initial_verdict="BENIGN"))
    with pytest.raises(InvalidJob):
        h.service.start(replace(h.request, initial_route="UNKNOWN_ROUTE"))
    with pytest.raises(InvalidJob):
        h.service.start(replace(h.request, initial_route="AUTO_BENIGN"))
    assert h.calls == (0, 0, 0, 0)


@pytest.mark.parametrize("verdict", ["BENIGN", "MALICIOUS"])
def test_automatic_route_finishes_without_download_or_tools(harness, verdict):
    h = harness
    request = replace(
        h.request, initial_route=f"AUTO_{verdict}", initial_verdict=verdict
    )
    result = h.service.start(request)
    assert result.phase is DeepAnalysisPhase.NOT_REQUIRED
    assert result.result["final_verdict"] == verdict
    assert h.calls == (0, 0, 0, 0)
    assert h.queue.sent == []
