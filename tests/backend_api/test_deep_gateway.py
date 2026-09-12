"""Boundary contracts mirrored from the optional service; no real service or AWS."""

from __future__ import annotations

import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from trust_triage.backend_api import deep_gateway as module
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.deep_gateway import (
    ExistingDeepGateway,
    current_deep_stage,
    validate_snapshot,
)
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.repository import AnalysisRecord

SHA = "a" * 64


def record():
    return AnalysisRecord(
        analysis_id="analysis-1",
        sha256=SHA,
        file_location="s3://backend-test-only/raw/analysis-1/sample.bin",
        filename="sample.exe",
        size_bytes=512,
        created_at="2026-09-08T01:00:00+00:00",
    )


def snapshot(status="RUNNING"):
    result = None
    if status in {"COMPLETED", "FAILED"}:
        result = {
            "sha256": SHA,
            "deep_analysis_status": "COMPLETE" if status == "COMPLETED" else "FAILED",
            "initial_route": "DEEP_ANALYSIS",
            "initial_verdict": "UNKNOWN",
            "final_verdict": "UNKNOWN",
            "disposition": "MANUAL_REVIEW",
            "evidence": [],
            "tool_statuses": {"CAPA": "SUCCESS", "FLOSS": "TIMEOUT"},
            "errors": ["FLOSS: time limit exceeded"],
        }
    return {
        "analysis_id": "analysis-1",
        "sha256": SHA,
        "initial_route": "DEEP_ANALYSIS",
        "initial_verdict": "UNKNOWN",
        "status": status,
        "phase": "STATIC"
        if status == "QUEUED"
        else "WAITING_SPEAKEASY"
        if status == "RUNNING"
        else status,
        "result": result,
        "last_error": None,
        "evidence": [],
        "tool_statuses": {"CAPA": "SUCCESS", "FLOSS": "TIMEOUT"},
        "static_results": {
            "CAPA": {"sha256": SHA, "status": "SUCCESS"},
            "FLOSS": {"sha256": "", "status": "TIMEOUT"},
        },
        "speakeasy_result": None,
    }


class FakeService:
    def __init__(self, payload=None):
        self.payload = payload or snapshot()
        self.calls = []
        self.failure = None
        self.limits = SimpleNamespace(operation_timeout_seconds=480)

    def register(self, request):
        self.calls.append(("register", request))
        if self.failure:
            raise self.failure

    def resume(self, analysis_id):
        self.calls.append(("resume", analysis_id))

    def get(self, analysis_id):
        self.calls.append(("get", analysis_id))
        return self.payload


def test_advance_registers_same_request_resumes_then_reads():
    service = FakeService()
    gateway = ExistingDeepGateway(
        BackendConfig(), service=service, request_type=SimpleNamespace
    )
    result = gateway.advance(record())
    assert [name for name, _ in service.calls] == ["register", "resume", "get"]
    request = service.calls[0][1]
    assert vars(request) == {
        "analysis_id": "analysis-1",
        "sha256": SHA,
        "file_location": record().file_location,
        "initial_route": "DEEP_ANALYSIS",
        "initial_verdict": "UNKNOWN",
        "requested_at": record().created_at,
    }
    assert result == service.payload
    assert result is not service.payload


@pytest.mark.parametrize("status", ["QUEUED", "RUNNING", "COMPLETED", "FAILED"])
def test_accepts_actual_service_lifecycle_and_failed_tools_without_sha(status):
    value = snapshot(status)
    assert validate_snapshot(value, record()) == value


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("analysis_id",), "other"),
        (("sha256",), "b" * 64),
        (("initial_route",), "AUTO_BENIGN"),
        (("initial_verdict",), "BENIGN"),
        (("status",), "NOT_REQUIRED"),
        (("result",), None),
        (("result", "sha256"), "b" * 64),
        (("result", "deep_analysis_status"), "FAILED"),
        (("evidence",), {}),
        (("evidence",), [{"sha256": "b" * 64}]),
        (("result", "evidence"), [{"sha256": "b" * 64}]),
        (("tool_statuses",), []),
        (("tool_statuses", "CAPA"), []),
        (("result", "errors"), "error"),
        (("result", "errors"), [{}]),
        (("last_error",), "error"),
        (("static_results",), []),
        (("static_results", "CAPA", "sha256"), "b" * 64),
        (("static_results", "CAPA", "sha256"), ""),
        (("static_results", "UNKNOWN"), {}),
        (("speakeasy_result",), {"analysis_id": "other", "sha256": SHA}),
        (
            ("speakeasy_result",),
            {
                "analysis_id": "analysis-1",
                "sha256": SHA,
                "analysis": {"sha256": "b" * 64, "status": "TIMEOUT"},
            },
        ),
    ],
)
def test_invalid_deep_boundary_never_reaches_persistence(path, value):
    payload = snapshot("COMPLETED")
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(BackendError) as failure:
        validate_snapshot(payload, record())
    assert failure.value.code == "DEEP_RESULT_INVALID"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"nonfinite": float("nan")},
        {"text": "\ud800"},
        {"large": "x" * (8 * 1024 * 1024)},
    ],
)
def test_invalid_json_and_oversized_state_are_boundary_errors(payload):
    with pytest.raises(BackendError) as failure:
        validate_snapshot(payload, record())
    assert failure.value.code == "DEEP_RESULT_INVALID"


@pytest.mark.parametrize(
    ("name", "retryable"),
    [("RetryableError", True), ("LeaseLost", True), ("PermanentError", False)],
)
def test_deep_failure_classification_does_not_expose_external_message(name, retryable):
    service = FakeService()
    service.failure = type(name, (Exception,), {"code": "EXPECTED_DEEP_ERROR"})(
        "private path or secret"
    )
    gateway = ExistingDeepGateway(
        BackendConfig(), service=service, request_type=SimpleNamespace
    )
    with pytest.raises(BackendError) as failure:
        gateway.advance(record())
    assert failure.value.code == "EXPECTED_DEEP_ERROR"
    assert failure.value.retryable is retryable
    assert "private" not in str(failure.value)
    assert [name for name, _ in service.calls] == ["register"]


def test_backend_error_is_preserved():
    service = FakeService()
    service.failure = BackendError("LEASE_LOST", "lost", retryable=True)
    with pytest.raises(BackendError) as failure:
        ExistingDeepGateway(
            BackendConfig(), service=service, request_type=SimpleNamespace
        ).advance(record())
    assert failure.value is service.failure


def test_local_storage_reports_explicit_unavailable_integration():
    with pytest.raises(BackendError) as failure:
        ExistingDeepGateway(BackendConfig()).check()
    assert failure.value.code == "DEEP_REQUIRES_S3"


def test_missing_optional_modules_are_explicit(monkeypatch):
    def missing(name):
        raise ImportError(name)

    monkeypatch.setattr(module.importlib, "import_module", missing)
    with pytest.raises(BackendError) as failure:
        ExistingDeepGateway(
            BackendConfig(storage_mode="s3", s3_bucket="backend-test-only")
        ).check()
    assert failure.value.code == "DEEP_INTEGRATION_UNAVAILABLE"


def test_runtime_factory_receives_backend_identity_and_checks_dependencies(
    monkeypatch, tmp_path
):
    service = FakeService()
    captured = []
    checked = []
    runtime = SimpleNamespace(service=service, check=lambda: checked.append(True))

    def create_runtime(config):
        captured.append(config)
        return runtime

    imports = {
        "trust_triage.deep_analysis.service_runtime": SimpleNamespace(
            create_deep_analysis_runtime=create_runtime
        ),
        "trust_triage.deep_analysis.service_models": SimpleNamespace(
            DeepAnalysisRequest=SimpleNamespace
        ),
        "trust_triage.speakeasy_worker.config": SimpleNamespace(
            WorkerConfig=SimpleNamespace(from_env=dict)
        ),
    }
    monkeypatch.setattr(module.importlib, "import_module", imports.__getitem__)
    monkeypatch.setenv("WORKER_DATABASE_URL", "different-worker-db")
    before = copy.copy(module.os.environ)
    config = BackendConfig(
        storage_mode="s3",
        s3_bucket="backend-test-only",
        database_url="backend-db",
        temp_root=tmp_path,
        max_file_bytes=2048,
    )
    gateway = ExistingDeepGateway(config)
    gateway.check()
    gateway.advance(record())
    gateway.check()
    assert len(captured) == 1
    assert checked == [True, True]
    assert captured[0]["WORKER_DATABASE_URL"] == "backend-db"
    assert captured[0]["WORKER_S3_BUCKET"] == config.s3_bucket
    assert captured[0]["WORKER_S3_PREFIX"] == config.s3_prefix
    assert captured[0]["WORKER_MAX_FILE_BYTES"] == "2048"
    assert captured[0]["WORKER_TEMP_DIR"] == str(tmp_path)
    assert captured[0]["WORKER_DOWNLOAD_TIMEOUT_SECONDS"] == str(
        config.download_timeout_seconds
    )
    assert module.os.environ == before
    runtime.check = lambda: (_ for _ in ()).throw(ValueError("private configuration"))
    with pytest.raises(BackendError) as failure:
        gateway.check()
    assert failure.value.code == "DEEP_NOT_READY"


@pytest.mark.parametrize(
    ("payload", "stage"),
    [
        ({"status": "QUEUED", "phase": "STATIC"}, "CAPA_FLOSS"),
        ({"status": "RUNNING", "phase": "WAITING_SPEAKEASY"}, "SPEAKEASY"),
        ({"status": "RUNNING", "phase": "FINALIZING"}, "LLM"),
        ({"status": "COMPLETED", "phase": "COMPLETED"}, "FINAL_ASSESSMENT"),
        ({"status": "FAILED", "phase": "FAILED"}, "FINAL_ASSESSMENT"),
    ],
)
def test_current_stage_follows_deep_phase(payload, stage):
    assert current_deep_stage(payload) == stage


class FakeWorkerJob(SimpleNamespace):
    def same_input(self, other):
        return all(
            getattr(self, name) == getattr(other, name)
            for name in ("analysis_id", "sha256", "file_location")
        )


class FakeRequest(FakeWorkerJob):
    @property
    def worker_job(self):
        return FakeWorkerJob(
            **{
                name: getattr(self, name)
                for name in ("analysis_id", "sha256", "file_location")
            }
        )

    def same_input(self, other):
        return (
            super().same_input(other)
            and self.initial_route == other.initial_route
            and self.initial_verdict == other.initial_verdict
        )


def stored_request(item=None):
    item = item or record()
    return FakeRequest(
        analysis_id=item.analysis_id,
        sha256=item.sha256,
        file_location=item.file_location,
        initial_route="DEEP_ANALYSIS",
        initial_verdict="UNKNOWN",
        requested_at=item.created_at,
    )


def test_existing_immutable_request_resumes_without_re_registering_changed_config():
    service = FakeService(snapshot("FAILED"))
    service.payload["result"]["errors"] = ["PIPELINE_CONFIG_CHANGED"]
    service.repository = SimpleNamespace(
        get=lambda analysis_id: SimpleNamespace(
            request=stored_request(), config_fingerprint="original-config"
        )
    )
    service.failure = ValueError("register would reject the changed configuration")
    gateway = ExistingDeepGateway(
        BackendConfig(), service=service, request_type=FakeRequest
    )
    result = gateway.advance(record())
    assert [name for name, _ in service.calls] == ["resume", "get"]
    assert result["status"] == "FAILED"
    assert result["result"]["errors"] == ["PIPELINE_CONFIG_CHANGED"]


@pytest.mark.parametrize("field", ["analysis_id", "sha256", "file_location"])
def test_existing_request_must_match_original_location_as_well_as_identity(field):
    service = FakeService()
    conflicting = replace(record(), **{field: "conflicting-input"})
    service.repository = SimpleNamespace(
        get=lambda analysis_id: SimpleNamespace(request=stored_request(conflicting))
    )
    with pytest.raises(BackendError) as failure:
        ExistingDeepGateway(
            BackendConfig(), service=service, request_type=FakeRequest
        ).advance(record())
    assert failure.value.code == "DEEP_REQUEST_CONFLICT"
    assert not service.calls


def test_missing_durable_deep_request_is_registered_before_resume():
    service = FakeService()
    service.repository = SimpleNamespace(get=lambda analysis_id: None)
    ExistingDeepGateway(
        BackendConfig(), service=service, request_type=FakeRequest
    ).advance(record())
    assert [name for name, _ in service.calls] == ["register", "resume", "get"]


@pytest.mark.parametrize("deep_terminal", [None, False, True])
@pytest.mark.parametrize("worker_terminal", [None, False, True])
def test_retention_requires_both_linked_jobs_to_be_absent_or_terminal(
    deep_terminal, worker_terminal
):
    request = stored_request()
    deep_record = (
        None
        if deep_terminal is None
        else SimpleNamespace(
            request=request, phase=SimpleNamespace(terminal=deep_terminal)
        )
    )
    worker_record = (
        None
        if worker_terminal is None
        else SimpleNamespace(
            job=request.worker_job, status=SimpleNamespace(terminal=worker_terminal)
        )
    )
    service = FakeService()
    reads = []

    def deep_get(analysis_id):
        reads.append(("deep", analysis_id))
        return deep_record

    def worker_get(analysis_id):
        reads.append(("worker", analysis_id))
        return worker_record

    service.repository = SimpleNamespace(get=deep_get)
    service.publisher = SimpleNamespace(repository=SimpleNamespace(get=worker_get))
    config = BackendConfig(storage_mode="s3", s3_bucket="backend-test-only")
    gateway = ExistingDeepGateway(config, service=service, request_type=FakeRequest)
    assert gateway.can_delete(record()) is (
        deep_terminal is not False and worker_terminal is not False
    )
    assert reads == [("deep", record().analysis_id), ("worker", record().analysis_id)]
    assert not service.calls


@pytest.mark.parametrize("source", ["deep", "worker"])
def test_retention_rejects_mismatched_linked_sample_even_when_terminal(source):
    request = stored_request()
    other = stored_request(
        replace(record(), file_location="s3://backend-test-only/raw/other.bin")
    )
    deep = SimpleNamespace(
        request=other if source == "deep" else request,
        phase=SimpleNamespace(terminal=True),
    )
    worker = SimpleNamespace(
        job=(other if source == "worker" else request).worker_job,
        status=SimpleNamespace(terminal=True),
    )
    service = FakeService()
    service.repository = SimpleNamespace(get=lambda analysis_id: deep)
    service.publisher = SimpleNamespace(
        repository=SimpleNamespace(get=lambda analysis_id: worker)
    )
    gateway = ExistingDeepGateway(
        BackendConfig(storage_mode="s3", s3_bucket="backend-test-only"),
        service=service,
        request_type=FakeRequest,
    )
    with pytest.raises(BackendError) as failure:
        gateway.can_delete(record())
    assert failure.value.code == "DEEP_REQUEST_CONFLICT"


def test_retention_uncertainty_is_a_sanitized_error():
    service = FakeService()

    def unavailable(analysis_id):
        raise RuntimeError("private database details")

    service.repository = SimpleNamespace(get=unavailable)
    gateway = ExistingDeepGateway(
        BackendConfig(storage_mode="s3", s3_bucket="backend-test-only"),
        service=service,
        request_type=FakeRequest,
    )
    with pytest.raises(BackendError) as failure:
        gateway.can_delete(record())
    assert failure.value.code == "DEEP_RETENTION_CHECK_FAILED"
    assert "private" not in str(failure.value)


def test_local_retention_does_not_load_optional_deep_runtime(monkeypatch):
    gateway = ExistingDeepGateway(BackendConfig())

    def forbidden():
        pytest.fail("local samples cannot have S3-only deep jobs")

    monkeypatch.setattr(gateway, "_resolve", forbidden)
    assert gateway.can_delete(record()) is True


@pytest.mark.parametrize("timeout", [780, 1000, float("nan"), float("inf"), -1])
def test_runtime_rejects_conflicting_timeout_without_caching(monkeypatch, timeout):
    service = FakeService()
    service.limits.operation_timeout_seconds = timeout
    runtime = SimpleNamespace(service=service, check=lambda: None)
    created = []

    def create(config):
        created.append(config)
        return runtime

    imports = {
        "trust_triage.deep_analysis.service_runtime": SimpleNamespace(
            create_deep_analysis_runtime=create
        ),
        "trust_triage.deep_analysis.service_models": SimpleNamespace(
            DeepAnalysisRequest=FakeRequest
        ),
        "trust_triage.speakeasy_worker.config": SimpleNamespace(
            WorkerConfig=SimpleNamespace(from_env=dict)
        ),
    }
    monkeypatch.setattr(module.importlib, "import_module", imports.__getitem__)
    gateway = ExistingDeepGateway(
        BackendConfig(storage_mode="s3", s3_bucket="backend-test-only")
    )
    with pytest.raises(BackendError) as failure:
        gateway.check()
    assert failure.value.code == "DEEP_NOT_CONFIGURED"
    assert gateway._runtime is None
    assert gateway._service is None
    service.limits.operation_timeout_seconds = 480
    gateway.check()
    assert len(created) == 2


def test_snapshot_read_preserves_retryable_service_failure():
    service = FakeService()

    def unavailable(analysis_id):
        raise type("RetryableError", (Exception,), {})("private connection detail")

    service.get = unavailable
    gateway = ExistingDeepGateway(
        BackendConfig(), service=service, request_type=FakeRequest
    )
    with pytest.raises(BackendError) as failure:
        gateway.get(record().analysis_id)
    assert failure.value.code == "DEEP_READ_FAILED"
    assert failure.value.retryable
    assert "private" not in str(failure.value)
