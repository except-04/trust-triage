"""PostgreSQL 작업 저장소: 등록, 작업 점유, 결과 저장을 원자적으로 처리한다."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any, Protocol
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .errors import RetryableError
from .models import JobConflict, JobRecord, JobStatus, SpeakeasyJob


@dataclass(frozen=True)
class Claim:
    record: JobRecord
    token: str | None = None


class JobRepository(Protocol):
    def register(
        self, job: SpeakeasyJob, *, dispatch_pending: bool = False
    ) -> JobRecord: ...
    def get(self, analysis_id: str) -> JobRecord | None: ...
    def pending_jobs(self, limit: int = 10) -> list[SpeakeasyJob]: ...
    def mark_dispatched(self, analysis_id: str) -> None: ...
    def claim(self, job: SpeakeasyJob, lease_seconds: int) -> Claim: ...
    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool: ...
    def finish(
        self, analysis_id: str, token: str, result: Mapping[str, Any]
    ) -> bool: ...
    def retry(self, analysis_id: str, token: str, error: Mapping[str, str]) -> bool: ...
    def dead_letter(self, job: SpeakeasyJob, result: Mapping[str, Any]) -> bool: ...


class PostgresJobRepository:
    """연결은 호출마다 열고 닫는다. heartbeat 스레드와 연결을 공유하지 않는다."""

    def __init__(
        self, dsn: str, *, connect_timeout: int = 5, statement_timeout_ms: int = 10000
    ) -> None:
        if not dsn.strip():
            raise ValueError("WORKER_DATABASE_URL is required")
        if connect_timeout <= 0 or statement_timeout_ms <= 0:
            raise ValueError("database timeouts must be positive")
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._statement_timeout_ms = statement_timeout_ms
        try:
            existing_options = conninfo_to_dict(dsn).get("options", "")
        except psycopg.Error as exc:
            raise ValueError(
                "WORKER_DATABASE_URL must be a valid PostgreSQL connection string"
            ) from exc
        self._options = (
            f"{existing_options} -c statement_timeout={statement_timeout_ms}".strip()
        )

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        try:
            with psycopg.connect(
                self._dsn,
                connect_timeout=self._connect_timeout,
                options=self._options,
                row_factory=dict_row,
            ) as connection:
                yield connection
                # context manager가 commit까지 성공해야 호출자에게 반환된다.
        except psycopg.Error as exc:
            raise RetryableError(
                "DATABASE_ERROR", "PostgreSQL operation failed"
            ) from exc

    def initialize(self) -> None:
        """명시적인 init-db 명령에서만 호출한다. 기존 데이터는 변경하지 않는다."""

        schema = files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")
        with self._connection() as connection:
            connection.execute(schema)

    def check(self) -> None:
        with self._connection() as connection:
            connection.execute("SELECT * FROM speakeasy_jobs LIMIT 0")

    def register(
        self, job: SpeakeasyJob, *, dispatch_pending: bool = False
    ) -> JobRecord:
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO speakeasy_jobs
                   (analysis_id, sha256, file_location, requested_at, dispatch_pending)
                   VALUES (%s, %s, %s, %s, %s) ON CONFLICT (analysis_id) DO NOTHING""",
                (
                    job.analysis_id,
                    job.sha256,
                    job.file_location,
                    job.requested_at,
                    dispatch_pending,
                ),
            )
            row = connection.execute(
                "SELECT * FROM speakeasy_jobs WHERE analysis_id = %s",
                (job.analysis_id,),
            ).fetchone()
            record = _record(row)
            if not record.job.same_input(job):
                raise JobConflict(
                    "analysis_id is already registered for different input"
                )
            return record

    def get(self, analysis_id: str) -> JobRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM speakeasy_jobs WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            return _record(row) if row else None

    def pending_jobs(self, limit: int = 10) -> list[SpeakeasyJob]:
        if not 1 <= limit <= 100:
            raise ValueError("pending-job limit must be between 1 and 100")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT * FROM speakeasy_jobs WHERE dispatch_pending AND status = 'QUEUED'
                   ORDER BY created_at LIMIT %s""",
                (limit,),
            ).fetchall()
            return [_record(row).job for row in rows]

    def mark_dispatched(self, analysis_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                """UPDATE speakeasy_jobs SET dispatch_pending = false,
                   dispatched_at = now(), updated_at = now() WHERE analysis_id = %s""",
                (analysis_id,),
            )

    def claim(self, job: SpeakeasyJob, lease_seconds: int) -> Claim:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.register(job)
        token = str(uuid4())
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE speakeasy_jobs SET status = 'RUNNING', lease_token = %s::uuid,
                   lease_until = clock_timestamp() + make_interval(secs => %s),
                   attempt_count = attempt_count + 1, dispatch_pending = false,
                   started_at = coalesce(started_at, now()), updated_at = now()
                   WHERE analysis_id = %s AND status IN ('QUEUED', 'RUNNING')
                   AND (lease_until IS NULL OR lease_until <= clock_timestamp()) RETURNING *""",
                (token, lease_seconds, job.analysis_id),
            ).fetchone()
            if row:
                return Claim(_record(row), token)
            row = connection.execute(
                "SELECT * FROM speakeasy_jobs WHERE analysis_id = %s",
                (job.analysis_id,),
            ).fetchone()
            return Claim(_record(row))

    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool:
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE speakeasy_jobs SET lease_until = clock_timestamp() + make_interval(secs => %s),
                   updated_at = now() WHERE analysis_id = %s AND status = 'RUNNING'
                   AND lease_token = %s::uuid AND lease_until > clock_timestamp()""",
                (lease_seconds, analysis_id, token),
            )
            return cursor.rowcount == 1

    def finish(self, analysis_id: str, token: str, result: Mapping[str, Any]) -> bool:
        status = JobStatus(result["status"])
        if not status.terminal or result["analysis_id"] != analysis_id:
            raise ValueError(
                "finish requires a terminal result for the same analysis_id"
            )
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE speakeasy_jobs SET status = %s, result = %s, last_error = %s,
                   lease_token = NULL, lease_until = NULL, dispatch_pending = false,
                   completed_at = now(), updated_at = now()
                   WHERE analysis_id = %s AND status = 'RUNNING'
                   AND lease_token = %s::uuid AND lease_until > clock_timestamp()""",
                (
                    status.value,
                    Jsonb(dict(result)),
                    Jsonb(result.get("error")),
                    analysis_id,
                    token,
                ),
            )
            return cursor.rowcount == 1

    def retry(self, analysis_id: str, token: str, error: Mapping[str, str]) -> bool:
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE speakeasy_jobs SET status = 'QUEUED', last_error = %s,
                   lease_token = NULL, lease_until = NULL, updated_at = now()
                   WHERE analysis_id = %s AND status = 'RUNNING'
                   AND lease_token = %s::uuid AND lease_until > clock_timestamp()""",
                (Jsonb(dict(error)), analysis_id, token),
            )
            return cursor.rowcount == 1

    def dead_letter(self, job: SpeakeasyJob, result: Mapping[str, Any]) -> bool:
        """DLQ는 미완료이고 점유 기한도 지난 작업만 최종 실패로 바꾼다."""

        if (
            result["status"] != JobStatus.FAILED.value
            or result["analysis_id"] != job.analysis_id
        ):
            raise ValueError(
                "dead_letter requires a failed result for the same analysis_id"
            )
        self.register(job)
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE speakeasy_jobs SET status = 'FAILED', result = %s, last_error = %s,
                   lease_token = NULL, lease_until = NULL, dispatch_pending = false,
                   completed_at = now(), updated_at = now()
                   WHERE analysis_id = %s AND status IN ('QUEUED', 'RUNNING')
                   AND (lease_until IS NULL OR lease_until <= clock_timestamp())""",
                (Jsonb(dict(result)), Jsonb(result.get("error")), job.analysis_id),
            )
            return cursor.rowcount == 1


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _record(row: Mapping[str, Any]) -> JobRecord:
    return JobRecord(
        job=SpeakeasyJob(
            analysis_id=row["analysis_id"],
            sha256=row["sha256"],
            file_location=row["file_location"],
            requested_at=_iso(row["requested_at"]),
        ),
        status=JobStatus(row["status"]),
        attempts=row["attempt_count"],
        result=row["result"],
        last_error=row["last_error"],
        dispatch_pending=row["dispatch_pending"],
        updated_at=_iso(row["updated_at"]),
    )
