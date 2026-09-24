"""DB 체크포인트로 CAPA/FLOSS와 비동기 Speakeasy, LLM 후처리를 연결한다."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from typing_extensions import Self

from ..speakeasy_worker.errors import LeaseLost, PermanentError, RetryableError
from ..speakeasy_worker.models import InvalidJob, JobConflict, failure_result, utc_now
from ..speakeasy_worker.publisher import JobPublisher
from ..speakeasy_worker.storage import SampleStore
from ..storage import ArtifactError, ArtifactIdentity
from .checkpoints import MAX_CHECKPOINT_BYTES, StaticAnalysisCheckpoint, json_snapshot
from .models import DeepAnalysisDisposition, DeepAnalysisResult, DeepAnalysisStatus
from .orchestrator import DeepAnalysisOrchestrator
from .service_models import DeepAnalysisPhase, DeepAnalysisRecord, DeepAnalysisRequest
from .service_repository import DeepAnalysisRepository
from .worker_results import analysis_from_worker, validate_worker_record

LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")
_INLINE_TOOL_RESULT_BYTES = 128 * 1024
_TOOL_RESULT_PREVIEW_ITEMS = 64


@dataclass(frozen=True)
class DeepServiceLimits:
    lease_seconds: int = 600
    heartbeat_seconds: float = 30
    operation_timeout_seconds: float = 480
    speakeasy_wait_seconds: float = 86400
    persistence_attempts: int = 3
    max_transient_failures: int = 3
    retry_delay_seconds: int = 30

    def __post_init__(self) -> None:
        if not 1 <= self.lease_seconds <= 43200:
            raise ValueError("deep-analysis lease must be between 1 and 43200 seconds")
        if not 0 < self.heartbeat_seconds < self.lease_seconds / 2:
            raise ValueError(
                "deep-analysis heartbeat must be shorter than half its lease"
            )
        if not 0 < self.operation_timeout_seconds < self.lease_seconds:
            raise ValueError(
                "deep-analysis operation timeout must be shorter than its lease"
            )
        if not 1 <= self.speakeasy_wait_seconds <= 14 * 86400:
            raise ValueError(
                "Speakeasy wait deadline must be between 1 second and 14 days"
            )
        if (
            not 1 <= self.persistence_attempts <= 5
            or not 1 <= self.max_transient_failures <= 10
        ):
            raise ValueError("invalid deep-analysis retry limits")
        if not 1 <= self.retry_delay_seconds <= 300:
            raise ValueError(
                "deep-analysis retry delay must be between 1 and 300 seconds"
            )


def _log(event: str, request: DeepAnalysisRequest, **fields: Any) -> None:
    LOGGER.info(
        json.dumps(
            {
                "source": "DEEP_ANALYSIS",
                "event": event,
                "analysis_id": request.analysis_id,
                "sha256": request.sha256,
                **fields,
            }
        )
    )


class _ServiceLease:
    def __init__(self, repository, request, token, limits) -> None:
        self.repository, self.request, self.token, self.limits = (
            repository,
            request,
            token,
            limits,
        )
        self.deadline = time.monotonic() + limits.operation_timeout_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="deep-analysis-heartbeat", daemon=True
        )

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        self._thread.join()

    def check_ownership(self) -> None:
        if self._lost.is_set():
            raise LeaseLost()

    def check(self) -> None:
        self.check_ownership()
        if time.monotonic() >= self.deadline:
            raise PermanentError(
                "DEEP_OPERATION_TIMEOUT",
                "Deep-analysis operation exceeded its time limit",
            )

    def _run(self) -> None:
        while not self._stop.wait(self.limits.heartbeat_seconds):
            try:
                self.check()
                if not self.repository.renew(
                    self.request.analysis_id, self.token, self.limits.lease_seconds
                ):
                    self._lost.set()
                    return
            except PermanentError:
                return
            except Exception as exc:  # noqa: BLE001 - DB heartbeat failure fences this owner
                self._lost.set()
                _log("heartbeat_failed", self.request, error_type=type(exc).__name__)
                return


class DeepAnalysisService:
    """Backend는 start/get을, 별도 후처리 프로세스는 resume_ready를 호출한다."""

    def __init__(
        self,
        *,
        repository: DeepAnalysisRepository,
        publisher: JobPublisher,
        samples: SampleStore,
        orchestrator: DeepAnalysisOrchestrator,
        artifact_storage=None,
        limits: DeepServiceLimits | None = None,
    ) -> None:
        if orchestrator.config.enable_ghidra_capa:
            raise ValueError(
                "Asynchronous service supports CAPA/FLOSS and Speakeasy; Ghidra remains disabled"
            )
        self.repository, self.publisher = repository, publisher
        self.samples, self.orchestrator = samples, orchestrator
        self.artifact_storage = artifact_storage
        self.limits = limits or DeepServiceLimits()
        self.config_fingerprint = orchestrator.config.fingerprint()

    def start(self, request: DeepAnalysisRequest) -> DeepAnalysisRecord:
        self._validate_route(request)
        record = self.repository.register(request, self.config_fingerprint)
        return record if record.phase.terminal else self.resume(request.analysis_id)

    def register(self, request: DeepAnalysisRequest) -> DeepAnalysisRecord:
        """API가 즉시 응답해야 할 때 등록만 하고 run 프로세스에 정적 분석을 맡긴다."""

        self._validate_route(request)
        return self.repository.register(request, self.config_fingerprint)

    def cancel(
        self, analysis_id: str, *, code: str, message: str
    ) -> DeepAnalysisRecord:
        """Persist a parent cancellation and fence any active deep-analysis owner."""

        if not isinstance(code, str) or not code or len(code) > 128:
            raise ValueError("cancellation code must contain 1-128 characters")
        if not isinstance(message, str) or not message or len(message) > 1000:
            raise ValueError("cancellation message must contain 1-1000 characters")
        record = self.repository.get(analysis_id)
        if record is None:
            raise ValueError("Deep-analysis request was not found")
        if record.phase.terminal:
            return record
        record = self.repository.request_cancel(
            analysis_id, {"code": code, "message": message}
        )
        self._cancel_worker(record.request)
        return self.resume(analysis_id)

    def _validate_route(self, request: DeepAnalysisRequest) -> None:
        automatic = {"AUTO_BENIGN": "BENIGN", "AUTO_MALICIOUS": "MALICIOUS"}
        if request.initial_route in automatic:
            if request.initial_verdict != automatic[request.initial_route]:
                raise InvalidJob("Automatic route and initial verdict must agree")
        elif not self.orchestrator.config.requires_deep_analysis(request.initial_route):
            raise InvalidJob("Unsupported initial deep-analysis route")

    def resume(self, analysis_id: str) -> DeepAnalysisRecord:
        record = self.repository.get(analysis_id)
        if record is None:
            raise ValueError("Deep-analysis request was not found")
        if record.phase.terminal or not _retry_due(record):
            return record
        claim = self.repository.claim(analysis_id, self.limits.lease_seconds)
        if claim.token is None:
            return claim.record
        record, token = claim.record, claim.token
        try:
            with _ServiceLease(
                self.repository, record.request, token, self.limits
            ) as guard:
                try:
                    if record.cancellation is not None:
                        self._cancel_worker(record.request)
                        return self._save_cancelled(record, token)
                    if record.config_fingerprint != self.config_fingerprint:
                        raise PermanentError(
                            "PIPELINE_CONFIG_CHANGED",
                            "Resume requires the original deep-analysis configuration",
                        )
                    if record.phase is not DeepAnalysisPhase.STATIC:
                        record = self._archive_checkpoint_tool_results(
                            record, token, guard
                        )
                    return self._advance(record, token, guard)
                except LeaseLost:
                    _log("lease_lost", record.request)
                    return self._get_record(analysis_id)
                except RetryableError as exc:
                    return self._retry(record, token, exc, guard)
                except PermanentError as exc:
                    current = self._get_record(analysis_id)
                    return self._save_result(
                        current,
                        token,
                        self._failure(current, exc.code, exc.message),
                        guard,
                    )
                except (TypeError, ValueError, KeyError) as exc:
                    _log(
                        "invalid_pipeline_result",
                        record.request,
                        error_type=type(exc).__name__,
                    )
                    current = self._get_record(analysis_id)
                    return self._save_result(
                        current,
                        token,
                        self._failure(
                            current,
                            "INVALID_PIPELINE_RESULT",
                            "Checkpoint or tool result failed validation",
                        ),
                        guard,
                    )
                except Exception as exc:  # noqa: BLE001 - preserve unexpected service failure for bounded retry
                    _log(
                        "unexpected_service_error",
                        record.request,
                        error_type=type(exc).__name__,
                    )
                    return self._retry(
                        record,
                        token,
                        RetryableError(
                            "DEEP_SERVICE_ERROR",
                            "Unexpected deep-analysis service error",
                        ),
                        guard,
                    )
        finally:
            try:
                self.repository.release(analysis_id, token)
            except RetryableError:
                _log("lease_release_failed", record.request)

    def _advance(
        self, record: DeepAnalysisRecord, token: str, guard: _ServiceLease
    ) -> DeepAnalysisRecord:
        request = record.request
        guard.check()
        if record.phase is DeepAnalysisPhase.STATIC:
            if self.orchestrator.config.requires_deep_analysis(request.initial_route):
                with self.samples.materialize(
                    request.worker_job, guard.check
                ) as sample:
                    prepared = self.orchestrator.prepare(
                        sample,
                        initial_route=request.initial_route,
                        initial_verdict=request.initial_verdict,
                        sha256=request.sha256,
                    )
            else:
                prepared = self.orchestrator.prepare(
                    "",
                    initial_route=request.initial_route,
                    initial_verdict=request.initial_verdict,
                    sha256=request.sha256,
                )
            guard.check()
            if isinstance(prepared, DeepAnalysisResult):
                return self._save_result(record, token, prepared, guard)
            self._validate_checkpoint(request, prepared, record.config_fingerprint)
            prepared = self._archive_large_tool_results(prepared, request, token)
            envelope = {
                "schema_version": "deep-checkpoint-v1",
                "static": prepared.to_dict(),
                "worker_result": None,
                "waiting_since": utc_now(),
            }
            phase = (
                DeepAnalysisPhase.WAITING_SPEAKEASY
                if prepared.needs_speakeasy
                else DeepAnalysisPhase.FINALIZING
            )
            record = self._save_checkpoint(record, token, envelope, phase, guard)
            _log("static_saved", request, phase=phase.value)

        if record.phase is DeepAnalysisPhase.WAITING_SPEAKEASY:
            self._load_checkpoint(record)
            worker = self.publisher.repository.get(request.analysis_id)
            if worker is not None and not worker.job.same_input(request.worker_job):
                raise PermanentError(
                    "WORKER_JOB_CONFLICT",
                    "Analysis ID is registered for another Worker input",
                )
            if worker is None or not worker.status.terminal:
                waiting_since = datetime.fromisoformat(
                    record.checkpoint["waiting_since"]
                )
                elapsed = (datetime.now(timezone.utc) - waiting_since).total_seconds()
                if elapsed >= self.limits.speakeasy_wait_seconds:
                    raise PermanentError(
                        "SPEAKEASY_WAIT_TIMEOUT",
                        "Speakeasy result did not arrive within the waiting deadline",
                    )
                # 기한이 지난 체크포인트를 복구할 때 새 Worker 작업을 보내지 않는다.
                try:
                    if worker is None or worker.dispatch_pending:
                        worker = self.publisher.submit(request.worker_job)
                except JobConflict as exc:
                    raise PermanentError(
                        "WORKER_JOB_CONFLICT",
                        "Analysis ID is registered for another Worker input",
                    ) from exc
            if not worker.status.terminal:
                return record
            payload = validate_worker_record(request, worker)
            envelope = {**record.checkpoint, "worker_result": payload}
            record = self._save_checkpoint(
                record, token, envelope, DeepAnalysisPhase.FINALIZING, guard
            )

        guard.check()
        checkpoint = self._load_checkpoint(record)
        if checkpoint.needs_speakeasy:
            inner = analysis_from_worker(request, record.checkpoint["worker_result"])
            result = self.orchestrator.resume_speakeasy(checkpoint, inner)
        else:
            if record.checkpoint.get("worker_result") is not None:
                raise ValueError(
                    "Static-only checkpoint cannot contain a Worker result"
                )
            result = self.orchestrator.finalize_static(checkpoint)
        try:
            guard.check()
        except PermanentError as exc:
            result = replace(
                result,
                deep_analysis_status=DeepAnalysisStatus.FAILED,
                final_verdict="UNKNOWN",
                disposition=DeepAnalysisDisposition.ANALYSIS_FAILED,
                requires_human_review=True,
                reason_codes=(*result.reason_codes, exc.code),
                errors=(*result.errors, exc.message),
            )
        return self._save_result(record, token, result, guard)

    def _validate_checkpoint(self, request, checkpoint, fingerprint) -> None:
        checkpoint.validate_identity(
            sha256=request.sha256,
            initial_route=request.initial_route,
            initial_verdict=request.initial_verdict,
            config_fingerprint=fingerprint,
        )
        # 복원한 점수도 저장된 Evidence를 다시 평가한 값과 같아야 한다.
        if fingerprint == self.config_fingerprint:
            actual = self.orchestrator.config.evidence_policy.assess(
                checkpoint.evidence
            )
            if actual != checkpoint.assessment:
                raise ValueError(
                    "Checkpoint evidence assessment does not match its evidence"
                )

    def _archive_checkpoint_tool_results(self, record, token, guard):
        checkpoint = self._load_checkpoint(record)
        archived = self._archive_large_tool_results(checkpoint, record.request, token)
        if archived.tool_results == checkpoint.tool_results:
            return record
        envelope = dict(record.checkpoint)
        envelope["static"] = archived.to_dict()
        return self._save_checkpoint(record, token, envelope, record.phase, guard)

    def _archive_large_tool_results(self, checkpoint, request, token):
        results = dict(checkpoint.tool_results)
        changed = False
        for tool, result in checkpoint.tool_results.items():
            if "details_reference" in result:
                continue
            encoded = json.dumps(
                result, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
            if len(encoded) <= _INLINE_TOOL_RESULT_BYTES:
                continue
            if len(encoded) > MAX_CHECKPOINT_BYTES:
                results[tool] = _tool_result_preview(
                    tool,
                    result,
                    details_status="OMITTED_TOO_LARGE",
                    details_error={
                        "code": "RESULT_TOO_LARGE",
                        "actual_bytes": len(encoded),
                        "limit_bytes": MAX_CHECKPOINT_BYTES,
                    },
                )
                changed = True
                continue
            if self.artifact_storage is None:
                # Non-runtime service users retain the durable checkpoint; GET
                # has a legacy compaction path so oversized detail cannot wedge
                # the parent Backend result.
                continue
            version = result.get("capa_version", result.get("floss_version"))
            try:
                reference = self.artifact_storage.put_json(
                    ArtifactIdentity(
                        sha256=request.sha256,
                        analysis_id=request.analysis_id,
                        tool=f"DEEP_{tool}",
                        tool_run_id=token,
                        name="result.json",
                    ),
                    result,
                    tool_version=version if isinstance(version, str) else None,
                    config_sha256=self.config_fingerprint,
                )
            except ArtifactError as exc:
                # Archiving parsed details is supplementary. Preserve the
                # tool's actual status and a bounded diagnostic in the DB.
                results[tool] = _tool_result_preview(
                    tool,
                    result,
                    details_status="ARCHIVE_FAILED",
                    details_error={
                        "code": exc.code,
                        "message": exc.message[:512],
                        "actual_bytes": len(encoded),
                        "limit_bytes": MAX_CHECKPOINT_BYTES,
                    },
                )
                changed = True
                continue
            results[tool] = _tool_result_preview(
                tool, result, details_reference=reference.to_dict()
            )
            changed = True
        return replace(checkpoint, tool_results=results) if changed else checkpoint

    def _load_checkpoint(self, record: DeepAnalysisRecord) -> StaticAnalysisCheckpoint:
        value = record.checkpoint
        if (
            not isinstance(value, Mapping)
            or value.get("schema_version") != "deep-checkpoint-v1"
        ):
            raise ValueError("Missing or unsupported deep-analysis checkpoint")
        checkpoint = StaticAnalysisCheckpoint.from_dict(value["static"])
        self._validate_checkpoint(record.request, checkpoint, record.config_fingerprint)
        if (
            record.phase is DeepAnalysisPhase.WAITING_SPEAKEASY
            and not checkpoint.needs_speakeasy
        ):
            raise ValueError("Waiting checkpoint does not require Speakeasy")
        if (
            record.phase is DeepAnalysisPhase.FINALIZING
            and checkpoint.needs_speakeasy
            and value.get("worker_result") is None
        ):
            raise ValueError("Finalizing checkpoint is missing its Worker result")
        return checkpoint

    def _write(self, operation: Callable[[], _T], guard: _ServiceLease) -> _T:
        for attempt in range(self.limits.persistence_attempts):
            guard.check_ownership()
            try:
                return operation()
            except RetryableError:
                if attempt + 1 == self.limits.persistence_attempts:
                    raise
                time.sleep(0.1 * (2**attempt))
        raise AssertionError("unreachable persistence attempt")

    def _save_checkpoint(
        self, record, token, envelope, phase, guard
    ) -> DeepAnalysisRecord:
        payload = json_snapshot(envelope)

        def save():
            if not self.repository.save_checkpoint(
                record.request.analysis_id, token, payload, phase
            ):
                raise LeaseLost()
            return self._get_record(record.request.analysis_id)

        return self._write(save, guard)

    def _save_result(self, record, token, result, guard) -> DeepAnalysisRecord:
        payload = result.to_dict()
        if (
            result.sha256 != record.request.sha256
            or result.initial_route != record.request.initial_route
            or result.initial_verdict != record.request.initial_verdict
            or any(item.sha256 != record.request.sha256 for item in result.evidence)
        ):
            raise ValueError("Final deep-analysis result belongs to another input")
        json_snapshot(payload)

        def save():
            if not self.repository.finish(record.request.analysis_id, token, payload):
                saved = self._get_record(record.request.analysis_id)
                if saved.phase.terminal and saved.result is not None:
                    return saved
                raise LeaseLost()
            return self._get_record(record.request.analysis_id)

        saved = self._write(save, guard)
        _log("finished", record.request, phase=saved.phase.value)
        return saved

    def _save_cancelled(self, record, token) -> DeepAnalysisRecord:
        cancellation = record.cancellation
        if not isinstance(cancellation, Mapping):
            raise TypeError("Cancelled analysis is missing its durable reason")
        code = cancellation.get("code")
        message = cancellation.get("message")
        if not isinstance(code, str) or not isinstance(message, str):
            raise TypeError("Cancelled analysis has an invalid durable reason")
        result = self._failure(record, code, message)
        payload = result.to_dict()
        json_snapshot(payload)
        for attempt in range(self.limits.persistence_attempts):
            try:
                if self.repository.finish_cancelled(
                    record.request.analysis_id, token, payload
                ):
                    saved = self._get_record(record.request.analysis_id)
                    _log("cancelled", record.request, code=code)
                    return saved
                saved = self._get_record(record.request.analysis_id)
                if saved.phase.terminal:
                    return saved
                raise LeaseLost()
            except RetryableError:
                if attempt + 1 == self.limits.persistence_attempts:
                    raise
                time.sleep(0.1 * (2**attempt))
        raise AssertionError("unreachable cancellation persistence attempt")

    def _cancel_worker(self, request: DeepAnalysisRequest) -> None:
        worker_repository = self.publisher.repository
        worker = worker_repository.get(request.analysis_id)
        if worker is None or worker.status.terminal:
            return
        if not worker.job.same_input(request.worker_job):
            raise JobConflict("Worker cancellation belongs to another input")
        worker_repository.dead_letter(
            request.worker_job,
            failure_result(
                request.worker_job,
                "PARENT_ANALYSIS_CANCELLED",
                "Parent analysis ended before Speakeasy completion",
            ),
        )

    def _failure(self, record, code, message) -> DeepAnalysisResult:
        checkpoint = None
        if record.checkpoint is not None:
            try:
                checkpoint = self._load_checkpoint(record)
            except (ValueError, TypeError, KeyError) as exc:
                # 잘못된 저장 데이터는 DB에 보존하되 신뢰할 Evidence에는 넣지 않는다.
                _log(
                    "checkpoint_rejected", record.request, error_type=type(exc).__name__
                )
        return DeepAnalysisResult(
            sha256=record.request.sha256,
            initial_route=record.request.initial_route,
            initial_verdict=record.request.initial_verdict,
            deep_analysis_status=DeepAnalysisStatus.FAILED,
            final_verdict="UNKNOWN",
            disposition=DeepAnalysisDisposition.ANALYSIS_FAILED,
            last_tier=checkpoint.last_tier if checkpoint else None,
            executed_tiers=checkpoint.executed_tiers if checkpoint else (),
            evidence=checkpoint.evidence if checkpoint else (),
            tool_statuses=checkpoint.tool_statuses if checkpoint else {},
            reason_codes=(*(checkpoint.reason_codes if checkpoint else ()), code),
            errors=(*(checkpoint.errors if checkpoint else ()), message),
            requires_human_review=True,
            evidence_assessment=checkpoint.assessment if checkpoint else None,
        )

    def _retry(self, record, token, error, guard) -> DeepAnalysisRecord:
        current = self._get_record(record.request.analysis_id)
        if current.phase.terminal:
            return current
        count = int((current.last_error or {}).get("retry_count", 0)) + 1
        if count >= self.limits.max_transient_failures:
            return self._save_result(
                current,
                token,
                self._failure(
                    current,
                    "DEEP_RETRY_EXHAUSTED",
                    f"Repeated service failure: {error.code}",
                ),
                guard,
            )
        delay = min(300, self.limits.retry_delay_seconds * (2 ** (count - 1)))
        detail = {
            "code": error.code,
            "message": error.message,
            "retry_count": count,
            "next_retry_at": (
                datetime.now(timezone.utc) + timedelta(seconds=delay)
            ).isoformat(),
        }
        self.repository.release(record.request.analysis_id, token, detail)
        _log("retry_pending", record.request, code=error.code, retry_count=count)
        return self._get_record(record.request.analysis_id)

    def _get_record(self, analysis_id: str) -> DeepAnalysisRecord:
        record = self.repository.get(analysis_id)
        if record is None:
            raise ValueError("Deep-analysis request disappeared")
        return record

    def resume_ready(
        self, limit: int = 10, *, should_stop: Callable[[], bool] | None = None
    ) -> list[DeepAnalysisRecord]:
        """Resume ready work, allowing a process to stop between complete jobs."""

        results = []
        for analysis_id in self.repository.pending_ids(limit):
            if should_stop is not None and should_stop():
                break
            results.append(self.resume(analysis_id))
        return results

    def get(self, analysis_id: str) -> dict[str, Any] | None:
        """읽기 전용 조회. UI polling은 도구 실행·SQS 전송·LLM 호출을 유발하지 않는다."""

        record = self.repository.get(analysis_id)
        if record is None:
            return None
        payload = record.to_dict()
        payload["view_schema_version"] = "deep-view-v2"
        payload.update(
            tool_statuses={}, evidence=[], static_results={}, speakeasy_result=None
        )
        if record.checkpoint is not None:
            try:
                checkpoint = self._load_checkpoint(record)
            except (ValueError, TypeError, KeyError):
                payload["checkpoint_error"] = "INVALID_CHECKPOINT"
            else:
                payload.update(
                    tool_statuses=dict(checkpoint.tool_statuses),
                    evidence=[item.to_dict() for item in checkpoint.evidence],
                    static_results=dict(checkpoint.tool_results),
                )
                stored_worker = record.checkpoint.get("worker_result")
                if stored_worker is not None:
                    payload["speakeasy_result"] = stored_worker
                    payload["tool_statuses"]["SPEAKEASY"] = (
                        stored_worker.get("tool_status") or stored_worker["status"]
                    )
                elif checkpoint.needs_speakeasy and not record.phase.terminal:
                    worker = self.publisher.repository.get(analysis_id)
                    if worker is not None and worker.job.same_input(
                        record.request.worker_job
                    ):
                        tool_status = (worker.result or {}).get("tool_status")
                        payload["tool_statuses"]["SPEAKEASY"] = (
                            tool_status or worker.status.value
                        )
        if record.result is not None:
            payload["tool_statuses"].update(record.result.get("tool_statuses", {}))
            payload["evidence"] = record.result.get("evidence", [])
            compact_result = dict(record.result)
            if "evidence" in compact_result:
                compact_result.pop("evidence")
                compact_result["evidence_ref"] = "#/evidence"
            if "tool_statuses" in compact_result:
                compact_result.pop("tool_statuses")
                compact_result["tool_statuses_ref"] = "#/tool_statuses"
            payload["result"] = compact_result
        try:
            return json_snapshot(payload)
        except ValueError as exc:
            if "exceeds the 8 MiB limit" not in str(exc):
                raise
            # Old checkpoints may contain large inline CAPA/FLOSS details.
            # Keep the full checkpoint untouched while returning a bounded
            # summary to the Backend API.
            payload["static_results"] = {
                tool: _tool_result_preview(
                    tool,
                    result,
                    details_status="INLINE_IN_CHECKPOINT",
                )
                for tool, result in payload["static_results"].items()
            }
            payload["static_results_compacted"] = True
            return json_snapshot(payload)


def _tool_result_preview(
    tool: str,
    result: Mapping[str, Any],
    *,
    details_reference: Mapping[str, Any] | None = None,
    details_status: str | None = None,
    details_error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Expose display fields inline and keep full parsed output by reference."""

    summary = {
        key: result[key]
        for key in (
            "sha256",
            "file_type",
            "status",
            "elapsed_ms",
            "returncode",
            "raw_reference",
        )
        if key in result
    }
    for field in ("warnings", "errors"):
        values = result.get(field)
        if isinstance(values, list):
            summary[field] = [
                value[:512] if isinstance(value, str) else str(value)[:512]
                for value in values[:8]
            ]
            if len(values) > 8:
                summary[f"{field}_truncated"] = True

    if tool == "CAPA":
        for field in ("backend", "capa_version", "rules_version"):
            if field in result:
                summary[field] = result[field]
        capabilities = result.get("capabilities")
        if isinstance(capabilities, list):
            summary["capabilities"] = [
                {
                    key: (
                        value[:512]
                        if key == "description" and isinstance(value, str)
                        else value
                    )
                    for key, value in capability.items()
                    if key
                    in {
                        "rule_name",
                        "namespace",
                        "match_count",
                        "attack",
                        "mbc",
                        "description",
                    }
                }
                for capability in capabilities[:_TOOL_RESULT_PREVIEW_ITEMS]
                if isinstance(capability, Mapping)
            ]
            summary["capabilities_count"] = len(capabilities)
            if len(capabilities) > _TOOL_RESULT_PREVIEW_ITEMS:
                summary["capabilities_truncated"] = True
    else:
        if "floss_version" in result:
            summary["floss_version"] = result["floss_version"]
        metadata = result.get("analysis_metadata")
        if isinstance(metadata, Mapping) and metadata.get("limited_mode") is True:
            summary["limited_mode"] = True
            reason = metadata.get("limited_reason")
            if isinstance(reason, str) and reason in {
                "INPUT_EXCEEDS_16_MIB", "FLOSS_DEOBFUSCATION_SIZE_ERROR"
            }:
                summary["limited_reason"] = reason
        counts = result.get("string_counts")
        if isinstance(counts, Mapping):
            summary["string_counts"] = dict(counts)
        strings = result.get("strings")
        if isinstance(strings, list):
            preview = []
            for item in strings[:_TOOL_RESULT_PREVIEW_ITEMS]:
                if not isinstance(item, Mapping):
                    continue
                value = dict(item)
                if isinstance(value.get("string"), str):
                    value["string"] = value["string"][:2048]
                if isinstance(value.get("tags"), list):
                    value["tags"] = value["tags"][:8]
                preview.append(value)
            summary["strings"] = preview
            summary["strings_count"] = len(strings)
            if len(strings) > _TOOL_RESULT_PREVIEW_ITEMS:
                summary["strings_truncated"] = True

    summary["details_status"] = details_status or "ARCHIVED"
    if details_reference is not None:
        summary["details_reference"] = dict(details_reference)
    if details_error is not None:
        summary["details_error"] = dict(details_error)
    return summary


def _retry_due(record: DeepAnalysisRecord) -> bool:
    next_retry = (record.last_error or {}).get("next_retry_at")
    if not next_retry:
        return True
    try:
        return datetime.now(timezone.utc) >= datetime.fromisoformat(next_retry)
    except (TypeError, ValueError):
        return True
