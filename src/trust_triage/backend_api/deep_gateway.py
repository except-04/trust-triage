"""백엔드와 별도 심층 분석 구현 사이의 작은 연결부.

feature/deep-analysis는 아직 팀 검토 전이다. 해당 구현이 설치되지 않아도
API 명세/접수/조회는 실행되며, 실제 심층 분석 요청에는 명시적인 오류를 낸다.
"""

from __future__ import annotations

import importlib
import json
import math
import os
from collections.abc import Mapping
from typing import Any, Protocol

from .config import BackendConfig
from .errors import BackendError
from .repository import AnalysisRecord


class DeepGateway(Protocol):
    def advance(self, record: AnalysisRecord) -> dict[str, Any]: ...
    def get(self, analysis_id: str) -> dict[str, Any] | None: ...
    def check(self) -> None: ...
    def can_delete(self, record: AnalysisRecord) -> bool: ...


class ExistingDeepGateway:
    def __init__(
        self, config: BackendConfig, *, service=None, request_type=None
    ) -> None:
        self.config, self._service, self._request_type = config, service, request_type
        self._runtime = None
        if service is not None and request_type is None:
            raise ValueError("an injected deep service requires its request type")

    def _resolve(self):
        if self._service is not None:
            return self._service
        if self.config.storage_mode != "s3":
            raise BackendError(
                "DEEP_REQUIRES_S3",
                "심층 분석 Worker와 원본을 공유하려면 S3 저장소 설정이 필요합니다.",
                http_status=503,
                stage="CAPA_FLOSS",
            )
        try:
            runtime = importlib.import_module(
                "trust_triage.deep_analysis.service_runtime"
            )
            models = importlib.import_module(
                "trust_triage.deep_analysis.service_models"
            )
            worker_config = importlib.import_module(
                "trust_triage.speakeasy_worker.config"
            )
        except ImportError as exc:
            raise BackendError(
                "DEEP_INTEGRATION_UNAVAILABLE",
                "심층 분석 서비스 구현과 실행 의존성이 아직 설치되지 않았습니다.",
                http_status=503,
                stage="CAPA_FLOSS",
            ) from exc
        values = {
            **os.environ,
            "WORKER_DATABASE_URL": self.config.database_url,
            "WORKER_S3_BUCKET": self.config.s3_bucket,
            "WORKER_S3_PREFIX": self.config.s3_prefix,
            "WORKER_TEMP_DIR": str(self.config.temp_root),
            "WORKER_MAX_FILE_BYTES": str(self.config.max_file_bytes),
            "WORKER_DOWNLOAD_TIMEOUT_SECONDS": str(
                self.config.download_timeout_seconds
            ),
            "AWS_REGION": self.config.aws_region,
        }
        try:
            resolved = runtime.create_deep_analysis_runtime(
                worker_config.WorkerConfig.from_env(values)
            )
            operation_timeout = resolved.service.limits.operation_timeout_seconds
            if (
                not math.isfinite(operation_timeout)
                or not 0 < operation_timeout < self.config.operation_timeout_seconds
            ):
                raise ValueError(
                    "deep-analysis operation timeout must be shorter than the backend operation timeout"
                )
            self._runtime = resolved
            self._service = resolved.service
            self._request_type = models.DeepAnalysisRequest
        except (ValueError, OSError) as exc:
            raise BackendError(
                "DEEP_NOT_CONFIGURED",
                "심층 분석 환경 설정을 확인해주세요.",
                http_status=503,
                stage="CAPA_FLOSS",
            ) from exc
        return self._service

    def check(self) -> None:
        self._resolve()
        if self._runtime is not None:
            try:
                self._runtime.check()
            except Exception as exc:
                raise BackendError(
                    "DEEP_NOT_READY",
                    "심층 분석 DB, Queue와 도구 설정을 확인해주세요.",
                    http_status=503,
                    stage="CAPA_FLOSS",
                ) from exc

    def advance(self, record: AnalysisRecord) -> dict[str, Any]:
        service = self._resolve()
        try:
            request = self._request(record)
            # 이 메서드는 HTTP 요청이 아닌 별도 backend run 프로세스에서만 호출한다.
            repository = getattr(service, "repository", None)
            stored = (
                repository.get(record.analysis_id) if repository is not None else None
            )
            if stored is None:
                service.register(request)
            else:
                _assert_same_input(stored.request, request)
                # Resume owns the immutable-config check and persists its failure.
                # Re-registering would reject changed config before that can run.
            service.resume(record.analysis_id)
            payload = service.get(record.analysis_id)
        except Exception as exc:
            if isinstance(exc, BackendError):
                raise
            code = str(getattr(exc, "code", "DEEP_SERVICE_ERROR"))
            retryable = type(exc).__name__ in {"RetryableError", "LeaseLost"}
            raise BackendError(
                code,
                "심층 분석 서비스 처리에 실패했습니다. 저장된 단계에서 재개할 수 있습니다.",
                http_status=503,
                stage="CAPA_FLOSS",
                retryable=retryable,
            ) from exc
        return validate_snapshot(payload, record)

    def get(self, analysis_id: str) -> dict[str, Any] | None:
        try:
            return self._resolve().get(analysis_id)
        except BackendError:
            raise
        except Exception as exc:
            raise BackendError(
                "DEEP_READ_FAILED",
                "심층 분석 상태를 확인할 수 없습니다.",
                http_status=503,
                stage="CAPA_FLOSS",
                retryable=type(exc).__name__ in {"RetryableError", "LeaseLost"},
            ) from exc

    def _request(self, record: AnalysisRecord):
        return self._request_type(
            analysis_id=record.analysis_id,
            sha256=record.sha256,
            file_location=record.file_location,
            initial_route="DEEP_ANALYSIS",
            initial_verdict="UNKNOWN",
            requested_at=record.created_at,
        )

    def can_delete(self, record: AnalysisRecord) -> bool:
        """원본을 참조하는 심층 분석과 Worker가 모두 끝났을 때만 삭제한다."""
        if self.config.storage_mode == "local":
            return True
        try:
            service = self._resolve()
            request = self._request(record)
            deep_record = service.repository.get(record.analysis_id)
            worker_record = service.publisher.repository.get(record.analysis_id)
            if deep_record is not None:
                _assert_same_input(deep_record.request, request)
            if worker_record is not None:
                _assert_same_input(worker_record.job, request.worker_job)
            return (deep_record is None or deep_record.phase.terminal is True) and (
                worker_record is None or worker_record.status.terminal is True
            )
        except BackendError:
            raise
        except Exception as exc:
            raise BackendError(
                "DEEP_RETENTION_CHECK_FAILED",
                "심층 분석과 Worker의 원본 사용 상태를 확인할 수 없습니다.",
                http_status=503,
                stage="STORAGE",
                retryable=True,
            ) from exc


def _assert_same_input(stored, request) -> None:
    if not stored.same_input(request):
        raise BackendError(
            "DEEP_REQUEST_CONFLICT",
            "심층 분석 요청과 저장된 원본 식별자가 일치하지 않습니다.",
            http_status=409,
            stage="CAPA_FLOSS",
        )


def validate_snapshot(payload: Any, record: AnalysisRecord) -> dict[str, Any]:
    try:
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        if len(raw.encode("utf-8")) > 8 * 1024 * 1024:
            raise ValueError("snapshot too large")
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or value.get("analysis_id") != record.analysis_id
            or value.get("sha256") != record.sha256
        ):
            raise ValueError("snapshot identity mismatch")
        status = value.get("status")
        if status not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}:
            raise ValueError("unexpected deep-analysis lifecycle status")
        if (
            value.get("initial_route") != "DEEP_ANALYSIS"
            or value.get("initial_verdict") != "UNKNOWN"
        ):
            raise ValueError("snapshot request differs from the original request")
        result = value.get("result")
        if status in {"COMPLETED", "FAILED"}:
            expected = "COMPLETE" if status == "COMPLETED" else "FAILED"
            if (
                not isinstance(result, dict)
                or result.get("deep_analysis_status") != expected
                or result.get("sha256") != record.sha256
            ):
                raise ValueError("missing or conflicting final deep-analysis result")
        _validate_evidence(value.get("evidence", []), record.sha256)
        _validate_tool_statuses(value.get("tool_statuses", {}))
        if result is not None:
            if not isinstance(result, dict) or result.get("sha256") != record.sha256:
                raise ValueError("invalid deep-analysis result")
            _validate_evidence(result.get("evidence", []), record.sha256)
            _validate_tool_statuses(result.get("tool_statuses", {}))
            errors = result.get("errors", [])
            if not isinstance(errors, list) or any(
                not isinstance(error, str) for error in errors
            ):
                raise ValueError("invalid deep-analysis errors")
        last_error = value.get("last_error")
        if last_error is not None and not isinstance(last_error, dict):
            raise ValueError("invalid deep-analysis last error")
        static_results = value.get("static_results", {})
        if not isinstance(static_results, dict):
            raise TypeError("invalid static results")
        for tool, analysis in static_results.items():
            if tool not in {"CAPA", "FLOSS"}:
                raise ValueError("unexpected static tool")
            _validate_tool_identity(analysis, record.sha256)
        worker = value.get("speakeasy_result")
        if worker is not None and (
            not isinstance(worker, dict)
            or worker.get("analysis_id") != record.analysis_id
            or worker.get("sha256") != record.sha256
        ):
            raise ValueError("worker result belongs to another sample")
        if worker is not None and worker.get("analysis") is not None:
            _validate_tool_identity(worker["analysis"], record.sha256)
        return value
    except (TypeError, ValueError, KeyError, UnicodeError, RecursionError) as exc:
        raise BackendError(
            "DEEP_RESULT_INVALID",
            "심층 분석 결과의 식별자 또는 형식이 맞지 않습니다.",
            stage="CAPA_FLOSS",
        ) from exc


def _validate_evidence(evidence: Any, sha256: str) -> None:
    if not isinstance(evidence, list) or any(
        not isinstance(item, dict) or item.get("sha256") != sha256 for item in evidence
    ):
        raise ValueError("evidence must be an array belonging to the same sample")


def _validate_tool_statuses(statuses: Any) -> None:
    if not isinstance(statuses, dict) or any(
        not isinstance(status, str) for status in statuses.values()
    ):
        raise ValueError("invalid tool statuses")


def _validate_tool_identity(analysis: Any, sha256: str) -> None:
    if not isinstance(analysis, dict):
        raise TypeError("invalid tool result")
    actual_hash = analysis.get("sha256")
    if (actual_hash and actual_hash != sha256) or (
        analysis.get("status") == "SUCCESS" and actual_hash != sha256
    ):
        raise ValueError("tool result belongs to another sample")


def current_deep_stage(snapshot: Mapping[str, Any]) -> str:
    if snapshot.get("status") in {"COMPLETED", "FAILED"}:
        return "FINAL_ASSESSMENT"
    phase = snapshot.get("phase")
    return (
        "SPEAKEASY"
        if phase == "WAITING_SPEAKEASY"
        else "LLM"
        if phase == "FINALIZING"
        else "CAPA_FLOSS"
    )
