"""한 번에 한 작업을 처리하는 Speakeasy Worker와 DLQ 상태 복구."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from typing_extensions import Self

from trust_triage.dynamic_analysis.models import DynamicAnalysisResult

from .errors import LeaseLost, PermanentError, RetryableError
from .models import (
    InvalidJob,
    JobConflict,
    SpeakeasyJob,
    failure_result,
    result_from_analysis,
    utc_now,
)
from .queue import Delivery, JobQueue
from .reports import ReportWriter
from .repository import JobRepository
from .storage import SampleStore

LOGGER = logging.getLogger(__name__)


class Analyzer(Protocol):
    def analyze(self, sample_path: Path) -> DynamicAnalysisResult: ...


class Outcome(str, Enum):
    IDLE = "IDLE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DUPLICATE = "DUPLICATE"
    BUSY = "BUSY"
    RETRY = "RETRY"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class WorkerLimits:
    visibility_seconds: int = 180
    heartbeat_seconds: float = 30
    job_timeout_seconds: float = 120
    retry_delay_seconds: int = 30
    persistence_attempts: int = 3

    def __post_init__(self) -> None:
        if not 1 <= self.visibility_seconds <= 43200:
            raise ValueError("visibility_seconds must be between 1 and 43200")
        if not 0 < self.heartbeat_seconds < self.visibility_seconds / 2:
            raise ValueError(
                "heartbeat must be positive and less than half the visibility timeout"
            )
        if not 0 < self.job_timeout_seconds < self.visibility_seconds:
            raise ValueError(
                "job timeout must be positive and shorter than the visibility timeout"
            )
        if (
            not 1 <= self.retry_delay_seconds <= 300
            or not 1 <= self.persistence_attempts <= 5
        ):
            raise ValueError("invalid retry settings")


def log_event(event: str, *, job: SpeakeasyJob | None = None, **fields: Any) -> None:
    payload = {"event": event, "source": "SPEAKEASY", **fields}
    if job is not None:
        payload.update(analysis_id=job.analysis_id, sha256=job.sha256)
    # 메시지 본문, S3 경로, DB URL, 원본 report, 예외 문자열은 로그에 넣지 않는다.
    LOGGER.info(json.dumps(payload, ensure_ascii=False))


class LeaseGuard:
    """DB 점유 기한과 SQS 숨김 시간을 갱신하고 소유권을 잃으면 저장을 막는다."""

    def __init__(
        self,
        repository: JobRepository,
        queue: JobQueue,
        job: SpeakeasyJob,
        delivery: Delivery,
        token: str,
        limits: WorkerLimits,
    ) -> None:
        self.repository, self.queue = repository, queue
        self.job, self.delivery, self.token, self.limits = job, delivery, token, limits
        self.deadline = time.monotonic() + limits.job_timeout_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="speakeasy-heartbeat", daemon=True
        )

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        self._thread.join()

    def check(self) -> None:
        self.check_ownership()
        if time.monotonic() >= self.deadline:
            raise PermanentError("JOB_TIMEOUT", "Worker job exceeded its time limit")

    def check_ownership(self) -> None:
        if self._lost.is_set():
            raise LeaseLost()

    def heartbeat(self) -> None:
        self.check()
        if not self.repository.renew(
            self.job.analysis_id, self.token, self.limits.visibility_seconds
        ):
            self._lost.set()
            raise LeaseLost()
        self.queue.defer(self.delivery, self.limits.visibility_seconds)

    def _run(self) -> None:
        while not self._stop.wait(self.limits.heartbeat_seconds):
            try:
                self.heartbeat()
            except PermanentError:
                # 전체 작업 제한 이후에는 점유 기한을 계속 늘리지 않는다.
                return
            except Exception as exc:  # noqa: BLE001 - 경계 실패 시 점유권을 잃은 것으로 처리
                self._lost.set()
                log_event(
                    "heartbeat_failed", job=self.job, error_type=type(exc).__name__
                )
                return


class SpeakeasyWorker:
    def __init__(
        self,
        *,
        queue: JobQueue,
        repository: JobRepository,
        samples: SampleStore,
        analyzer: Analyzer,
        limits: WorkerLimits | None = None,
        reports: ReportWriter | None = None,
    ) -> None:
        self.queue, self.repository = queue, repository
        self.samples, self.analyzer = samples, analyzer
        self.limits = limits or WorkerLimits()
        self.reports = reports

    def run_once(self) -> Outcome:
        delivery = self.queue.receive()
        return self.process(delivery) if delivery is not None else Outcome.IDLE

    def process(self, delivery: Delivery) -> Outcome:
        job: SpeakeasyJob | None = None
        token: str | None = None
        started_at = utc_now()
        try:
            job = SpeakeasyJob.from_json(delivery.body)
            claim = self.repository.claim(job, self.limits.visibility_seconds)
            token = claim.token
            if claim.record.status.terminal:
                self.queue.acknowledge(delivery)
                log_event(
                    "duplicate_completed_job", job=job, message_id=delivery.message_id
                )
                return Outcome.DUPLICATE
            if token is None:
                self.queue.defer(delivery, self.limits.visibility_seconds)
                log_event(
                    "job_already_running", job=job, message_id=delivery.message_id
                )
                return Outcome.BUSY

            log_event(
                "job_started",
                job=job,
                attempt=claim.record.attempts,
                receive_count=delivery.receive_count,
            )
            with LeaseGuard(
                self.repository, self.queue, job, delivery, token, self.limits
            ) as guard:
                result = None
                try:
                    with self.samples.materialize(job, guard.check) as sample:
                        guard.check()
                        try:
                            analysis = self.analyzer.analyze(sample)
                        except Exception as exc:  # noqa: BLE001 - 기존 도구 호출 경계
                            log_event(
                                "analyzer_error", job=job, error_type=type(exc).__name__
                            )
                            result = failure_result(
                                job,
                                "TOOL_ERROR",
                                "Speakeasy call failed",
                                started_at=started_at,
                            )
                        else:
                            if not isinstance(analysis, DynamicAnalysisResult):
                                raise TypeError(
                                    "Analyzer must return DynamicAnalysisResult"
                                )
                            result = result_from_analysis(job, analysis)
                            guard.check()
                except PermanentError as exc:
                    if result is None:
                        result = failure_result(
                            job, exc.code, exc.message, started_at=started_at
                        )
                    else:
                        # 종료 시한 직전에 받은 관찰 결과도 보존한다.
                        result.update(
                            status="FAILED",
                            error={"code": exc.code, "message": exc.message},
                            completed_at=utc_now(),
                        )
                except (TypeError, ValueError) as exc:
                    log_event(
                        "invalid_analyzer_result",
                        job=job,
                        error_type=type(exc).__name__,
                    )
                    result = failure_result(
                        job,
                        "RESULT_FORMAT_ERROR",
                        "Analyzer result could not be serialized",
                        started_at=started_at,
                    )
                # 실패 결과도 DB commit이 먼저다. 저장 재시도에서는 메모리의 결과를 재사용한다.
                if self.reports is not None:
                    result = self.reports.archive(
                        job, token, result, guard.check_ownership
                    )
                    if result.get("artifact_error"):
                        log_event(
                            "report_archive_failed",
                            job=job,
                            code=result["artifact_error"]["code"],
                        )
                result = self._save_result(job, token, result, guard)

            self.queue.acknowledge(delivery)
            log_event(
                "job_finished",
                job=job,
                status=result["status"],
                tool_status=result["tool_status"],
            )
            return Outcome(result["status"])
        except (InvalidJob, JobConflict) as exc:
            log_event(
                "job_rejected",
                job=job,
                message_id=delivery.message_id,
                error_type=type(exc).__name__,
            )
            self._defer(delivery)
            return Outcome.REJECTED
        except LeaseLost:
            log_event("job_lease_lost", job=job, message_id=delivery.message_id)
            # 다른 Worker의 DB 상태나 메시지 점유 시간을 덮어쓰지 않는다.
            return Outcome.RETRY
        except RetryableError as exc:
            self._retry(job, token, delivery, exc)
            return Outcome.RETRY
        except Exception as exc:  # noqa: BLE001 - 메시지 유실 방지를 위한 Worker 최외곽 경계
            # 예기치 않은 도구/로컬 오류도 숨기지 않고 제한된 SQS 재전달 정책으로 보낸다.
            log_event("unexpected_worker_error", job=job, error_type=type(exc).__name__)
            self._retry(
                job,
                token,
                delivery,
                RetryableError("WORKER_ERROR", "Unexpected worker error"),
            )
            return Outcome.RETRY

    def _save_result(
        self,
        job: SpeakeasyJob,
        token: str,
        result: Mapping[str, Any],
        guard: LeaseGuard,
    ) -> dict[str, Any]:
        for attempt in range(self.limits.persistence_attempts):
            # 작업 시간 제한에 도달한 실패 결과도 남긴다. 저장은 별도 DB 시간 제한이 있다.
            guard.check_ownership()
            try:
                if not self.repository.finish(job.analysis_id, token, result):
                    # 직전 commit 응답만 유실되었을 수도 있다. 동일 요청의 최종 결과를 확인한다.
                    saved = self.repository.get(job.analysis_id)
                    if (
                        saved is not None
                        and saved.job.same_input(job)
                        and saved.status.terminal
                        and saved.result is not None
                    ):
                        return dict(saved.result)
                    raise LeaseLost()
                return dict(result)
            except RetryableError:
                if attempt + 1 == self.limits.persistence_attempts:
                    raise
                time.sleep(0.1 * (2**attempt))

    def _retry(
        self,
        job: SpeakeasyJob | None,
        token: str | None,
        delivery: Delivery,
        error: RetryableError,
    ) -> None:
        log_event("job_retry", job=job, message_id=delivery.message_id, code=error.code)
        if job is not None and token is not None:
            try:
                released = self.repository.retry(
                    job.analysis_id,
                    token,
                    {"code": error.code, "message": error.message},
                )
                if not released:
                    # 완료됐거나 다른 Worker가 소유한다. 그 수신의 숨김 시간을 줄이지 않는다.
                    return
            except RetryableError:
                log_event("retry_status_not_saved", job=job, code="DATABASE_ERROR")
                return
        self._defer(delivery)

    def _defer(self, delivery: Delivery) -> None:
        delay = min(
            300,
            self.limits.retry_delay_seconds * (2 ** min(delivery.receive_count - 1, 4)),
        )
        try:
            self.queue.defer(delivery, delay)
        except RetryableError:
            log_event(
                "message_defer_failed", message_id=delivery.message_id, code="SQS_ERROR"
            )

    def reconcile_dead_letter(self, delivery: Delivery, dlq: JobQueue) -> Outcome:
        """DLQ 이동 후에도 RUNNING/QUEUED로 남은 DB 상태를 정리한다."""

        job: SpeakeasyJob | None = None
        try:
            job = SpeakeasyJob.from_json(delivery.body)
            record = self.repository.register(job)
            if record.status.terminal:
                dlq.acknowledge(delivery)
                return Outcome.DUPLICATE
            message = "SQS delivery limit was reached"
            if record.last_error:
                message += f"; last error: {record.last_error.get('code', 'UNKNOWN')}"
            result = failure_result(job, "RETRY_EXHAUSTED", message)
            if self.repository.dead_letter(job, result):
                dlq.acknowledge(delivery)
                log_event("dead_letter_saved", job=job, code="RETRY_EXHAUSTED")
                return Outcome.FAILED
            # 살아 있는 Worker 또는 방금 완료된 작업의 결과를 건드리지 않는다.
            dlq.defer(delivery, self.limits.visibility_seconds)
            return Outcome.BUSY
        except (InvalidJob, JobConflict) as exc:
            # 요청 번호를 신뢰할 수 없는 메시지는 DLQ에 보존해 운영자가 확인한다.
            log_event(
                "dead_letter_requires_review",
                job=job,
                message_id=delivery.message_id,
                error_type=type(exc).__name__,
            )
            dlq.defer(delivery, 3600)
            return Outcome.REJECTED
        except RetryableError as exc:
            log_event("dead_letter_retry", job=job, code=exc.code)
            return Outcome.RETRY
