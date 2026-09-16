"""Verify the real Worker result contract before admitting asynchronous evidence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from trust_triage.deep_analysis.normalizer import normalize_speakeasy_result
from trust_triage.deep_analysis.service_models import DeepAnalysisRequest
from trust_triage.deep_analysis.worker_results import (
    analysis_from_worker,
    validate_worker_record,
)
from trust_triage.dynamic_analysis.models import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
)
from trust_triage.speakeasy_worker.models import (
    JobRecord,
    JobStatus,
    failure_result,
    result_from_analysis,
)
from trust_triage.speakeasy_worker.reports import ReportWriter
from trust_triage.storage import ArtifactIdentity, LocalArtifactStorage


@pytest.fixture
def deep_request():
    return DeepAnalysisRequest(
        analysis_id="analysis-001",
        sha256="a" * 64,
        file_location="s3://worker-test-bucket/raw/analysis-001/sample.bin",
        initial_route="DEEP_ANALYSIS",
        requested_at="2026-09-08T10:00:00Z",
    )


def _analysis(deep_request, status=DynamicAnalysisStatus.SUCCESS, **changes):
    result = DynamicAnalysisResult(
        evidence_id="speakeasy-fixture-001",
        sha256=deep_request.sha256,
        source="SPEAKEASY",
        category="BEHAVIOR",
        status=status,
        summary="Fake dynamic observation from a unit test",
        observed_apis=("kernel32.CreateRemoteThread",),
        behaviors=("Process Injection",),
        events={"api_calls": ({"api_name": "kernel32.CreateRemoteThread"},)},
        warnings=(
            "partial fixture"
            if status is not DynamicAnalysisStatus.SUCCESS
            else "fixture",
        ),
        errors=() if status is DynamicAnalysisStatus.SUCCESS else ("engine limit",),
        raw_report={"excluded": True},
        tool_version="fixture-version",
        started_at="2026-09-08T10:00:01Z",
        completed_at="2026-09-08T10:00:02Z",
    )
    return replace(result, **changes)


@pytest.fixture
def success_payload(deep_request):
    return result_from_analysis(deep_request.worker_job, _analysis(deep_request))


def test_report_reference_is_preserved_in_resumed_checkpoint(
    deep_request, success_payload, tmp_path
):
    writer = ReportWriter(LocalArtifactStorage(tmp_path))
    payload = writer.archive(
        deep_request.worker_job, "run-1", success_payload, lambda: None
    )
    record = JobRecord(deep_request.worker_job, JobStatus.COMPLETED, result=payload)
    assert (
        validate_worker_record(deep_request, record)["artifact"] == payload["artifact"]
    )


@pytest.mark.parametrize(
    "identity",
    [
        ArtifactIdentity("b" * 64, "analysis-001", "SPEAKEASY", "run-1"),
        ArtifactIdentity("a" * 64, "another-analysis", "SPEAKEASY", "run-1"),
        ArtifactIdentity("a" * 64, "analysis-001", "CAPA", "run-1"),
        ArtifactIdentity("a" * 64, "analysis-001", "SPEAKEASY", "another-run"),
    ],
)
def test_unrelated_report_cannot_be_attached_to_worker_result(
    deep_request, success_payload, identity, tmp_path
):
    reference = LocalArtifactStorage(tmp_path).put_json(identity, {"test": "inert"})
    payload = {
        **success_payload,
        "tool_run_id": "run-1",
        "artifact": reference.to_dict(),
    }
    with pytest.raises(ValueError, match="another analysis or execution"):
        analysis_from_worker(deep_request, payload)


def test_successful_real_worker_result_reaches_normalizer_without_mutating_envelope(
    deep_request, success_payload
):
    original = deepcopy(success_payload)
    converted = analysis_from_worker(deep_request, success_payload)
    assert success_payload == original
    assert success_payload["status"] == "COMPLETED"
    assert converted["status"] == "SUCCESS"
    assert converted["raw_report"] is None
    assert converted["tool_version"] == "fixture-version"
    assert converted["observed_apis"] == ["kernel32.CreateRemoteThread"]
    evidence = normalize_speakeasy_result(converted, sha256=deep_request.sha256)
    assert len(evidence) == 1
    assert evidence[0].sha256 == deep_request.sha256
    assert evidence[0].attack_techniques[0].technique_id == "T1055"
    converted["observed_apis"].append("local-change")
    assert success_payload == original


def test_validate_worker_record_matches_request_and_returns_full_immutable_snapshot(
    deep_request, success_payload
):
    record = JobRecord(
        job=deep_request.worker_job, status=JobStatus.COMPLETED, result=success_payload
    )
    copied = validate_worker_record(deep_request, record)
    assert copied == success_payload
    copied["analysis"]["summary"] = "changed outside repository"
    assert copied != record.result
    later_timestamp = replace(
        record, job=replace(record.job, requested_at="2026-09-09T00:00:00Z")
    )
    assert validate_worker_record(deep_request, later_timestamp) == success_payload


@pytest.mark.parametrize("status", [JobStatus.QUEUED, JobStatus.RUNNING])
def test_nonterminal_worker_record_cannot_resume(deep_request, success_payload, status):
    with pytest.raises(ValueError, match="does not match"):
        validate_worker_record(
            deep_request,
            JobRecord(deep_request.worker_job, status, result=success_payload),
        )


def test_worker_record_rejects_job_identity_and_status_conflicts(
    deep_request, success_payload
):
    record = JobRecord(
        deep_request.worker_job, JobStatus.COMPLETED, result=success_payload
    )
    for job in (
        replace(record.job, analysis_id="another-analysis"),
        replace(record.job, sha256="b" * 64),
        replace(record.job, file_location="s3://worker-test-bucket/other.bin"),
    ):
        with pytest.raises(ValueError):
            validate_worker_record(deep_request, replace(record, job=job))
    for changed in (
        replace(record, result=None),
        replace(record, status=JobStatus.FAILED),
    ):
        with pytest.raises(ValueError, match="status and saved result"):
            validate_worker_record(deep_request, changed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "future-schema"),
        ("analysis_id", "another-analysis"),
        ("sha256", "b" * 64),
        ("tool", "CAPA"),
        ("status", "RUNNING"),
        ("status", "SUCCESS"),
    ],
)
def test_result_rejects_invalid_envelope_identity_schema_or_status(
    deep_request, success_payload, field, value
):
    success_payload[field] = value
    with pytest.raises(ValueError, match="identity, schema or status"):
        analysis_from_worker(deep_request, success_payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "future-dynamic-schema"),
        ("source", "CAPA"),
        ("status", "OTHER"),
        ("status", "TIMEOUT"),
        ("sha256", "b" * 64),
        ("sha256", ""),
        ("sha256", None),
        ("raw_report", {"private": True}),
    ],
)
def test_result_rejects_invalid_inner_analysis(
    deep_request, success_payload, field, value
):
    success_payload["analysis"][field] = value
    with pytest.raises(ValueError, match="Nested Speakeasy"):
        analysis_from_worker(deep_request, success_payload)


def test_outer_tool_status_must_match_inner_analysis(deep_request, success_payload):
    success_payload["tool_status"] = "TIMEOUT"
    with pytest.raises(ValueError, match="Nested Speakeasy"):
        analysis_from_worker(deep_request, success_payload)


def test_completed_envelope_cannot_wrap_a_matching_failed_tool_result(deep_request):
    payload = result_from_analysis(
        deep_request.worker_job, _analysis(deep_request, DynamicAnalysisStatus.TIMEOUT)
    )
    payload["status"], payload["error"] = "COMPLETED", None
    with pytest.raises(ValueError, match="requires successful"):
        analysis_from_worker(deep_request, payload)


@pytest.mark.parametrize(
    "error", [{"code": "OTHER", "message": "failure"}, {}, "error"]
)
def test_completed_result_cannot_contain_error(deep_request, success_payload, error):
    success_payload["error"] = error
    with pytest.raises(ValueError, match="cannot contain an error"):
        analysis_from_worker(deep_request, success_payload)


def test_failed_envelope_requires_an_explicit_error(deep_request):
    payload = failure_result(deep_request.worker_job, "S3_UNAVAILABLE", "read failed")
    for error in (
        None,
        {},
        {"code": "", "message": "failed"},
        {"code": "ERROR", "message": 5},
    ):
        payload["error"] = error
        with pytest.raises(ValueError, match="explicit error"):
            analysis_from_worker(deep_request, payload)


def test_infrastructure_failure_has_no_observations_or_attack_evidence(deep_request):
    payload = failure_result(
        deep_request.worker_job, "S3_NOT_FOUND", "sample unavailable"
    )
    record = JobRecord(deep_request.worker_job, JobStatus.FAILED, result=payload)
    assert validate_worker_record(deep_request, record) == payload
    result = analysis_from_worker(deep_request, payload)
    assert result["status"] == "TOOL_ERROR"
    assert result["sha256"] == deep_request.sha256
    assert "S3_NOT_FOUND" in result["errors"][0]
    assert not result.get("observed_apis")
    assert not result.get("events")
    assert normalize_speakeasy_result(result) == ()


def test_missing_analysis_rejects_success_observations_or_tool_status(
    deep_request, success_payload
):
    success_payload["analysis"] = None
    with pytest.raises(ValueError, match="without analysis"):
        analysis_from_worker(deep_request, success_payload)
    payload = failure_result(deep_request.worker_job, "ERROR", "fixture failure")
    payload["behavior"]["api_calls"] = [{"api_name": "fake-api"}]
    with pytest.raises(ValueError, match="without analysis"):
        analysis_from_worker(deep_request, payload)
    payload["behavior"]["api_calls"] = []
    payload["tool_status"] = "TIMEOUT"
    with pytest.raises(ValueError, match="without analysis"):
        analysis_from_worker(deep_request, payload)


@pytest.mark.parametrize(
    "status", [DynamicAnalysisStatus.TIMEOUT, DynamicAnalysisStatus.UNSUPPORTED_API]
)
def test_partial_tool_failure_preserves_observations_but_never_normalizes_as_evidence(
    deep_request, status
):
    payload = result_from_analysis(
        deep_request.worker_job, _analysis(deep_request, status)
    )
    original = deepcopy(payload)
    result = analysis_from_worker(deep_request, payload)
    assert result["status"] == status.value
    assert result["observed_apis"] == ["kernel32.CreateRemoteThread"]
    assert result["events"]["api_calls"] == [
        {"api_name": "kernel32.CreateRemoteThread"}
    ]
    assert "engine limit" in result["errors"]
    assert any(status.value in error for error in result["errors"])
    assert normalize_speakeasy_result(result, sha256=deep_request.sha256) == ()
    assert payload == original


def test_failed_tool_may_have_no_inner_hash_but_cannot_have_a_different_hash(
    deep_request,
):
    payload = result_from_analysis(
        deep_request.worker_job,
        _analysis(deep_request, DynamicAnalysisStatus.INVALID_INPUT, sha256=""),
    )
    assert analysis_from_worker(deep_request, payload)["status"] == "INVALID_INPUT"
    payload["analysis"]["sha256"] = "b" * 64
    with pytest.raises(ValueError, match="Nested Speakeasy"):
        analysis_from_worker(deep_request, payload)


def test_outer_job_timeout_downgrades_success_for_normalization_and_preserves_original(
    deep_request, success_payload
):
    success_payload["status"] = "FAILED"
    success_payload["error"] = {
        "code": "JOB_TIMEOUT",
        "message": "worker total budget exceeded",
    }
    original = deepcopy(success_payload)
    record = JobRecord(
        deep_request.worker_job, JobStatus.FAILED, result=success_payload
    )
    assert validate_worker_record(deep_request, record) == original
    result = analysis_from_worker(deep_request, success_payload)
    assert result["status"] == "TIMEOUT"
    assert result["observed_apis"] == original["analysis"]["observed_apis"]
    assert "JOB_TIMEOUT" in result["errors"][-1]
    assert normalize_speakeasy_result(result) == ()
    assert success_payload == original
    assert success_payload["analysis"]["status"] == "SUCCESS"


def test_failed_envelope_with_success_inner_requires_job_timeout_code(
    deep_request, success_payload
):
    success_payload["status"] = "FAILED"
    success_payload["error"] = {
        "code": "OTHER_FAILURE",
        "message": "inconsistent result",
    }
    with pytest.raises(ValueError, match="contradicts successful"):
        analysis_from_worker(deep_request, success_payload)


@pytest.mark.parametrize("field", ["observed_apis", "behaviors", "warnings", "errors"])
@pytest.mark.parametrize("value", ["not-an-array", [123]])
def test_inner_observation_arrays_reject_non_string_elements(
    deep_request, success_payload, field, value
):
    success_payload["analysis"][field] = value
    with pytest.raises(ValueError, match="string array"):
        analysis_from_worker(deep_request, success_payload)


@pytest.mark.parametrize(
    "events", [[], {"api_calls": "not-an-array"}, {"api_calls": [123]}]
)
def test_inner_event_categories_require_event_object_arrays(
    deep_request, success_payload, events
):
    success_payload["analysis"]["events"] = events
    with pytest.raises(ValueError, match="event objects"):
        analysis_from_worker(deep_request, success_payload)


def test_outer_behavior_categories_must_match_contract(deep_request, success_payload):
    del success_payload["behavior"]["files"]
    with pytest.raises(ValueError, match="behavior categories"):
        analysis_from_worker(deep_request, success_payload)


@pytest.mark.parametrize("value", ["not-an-array", [123]])
def test_outer_behavior_requires_event_object_arrays(
    deep_request, success_payload, value
):
    success_payload["behavior"]["api_calls"] = value
    with pytest.raises(ValueError):
        analysis_from_worker(deep_request, success_payload)
