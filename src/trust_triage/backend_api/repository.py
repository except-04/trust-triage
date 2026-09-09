"""Durable API requests, fenced processing, and append-only analyst decisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Protocol
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .errors import BackendError
from .schemas import BatchInputReport, CurrentStage, InitialVerdict

MAX_STATE_BYTES = 8 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SELECT = "SELECT *, COALESCE(lease_until > clock_timestamp(), false) AS claimed FROM api_analyses"
_ACTIVE = "status IN ('QUEUED', 'RUNNING')"
_READY = (
    _ACTIVE + " AND (lease_until IS NULL OR lease_until <= clock_timestamp())"
    " AND (next_retry_at IS NULL OR next_retry_at <= clock_timestamp())"
)
_OWNED = (
    "analysis_id = %s AND "
    + _ACTIVE
    + " AND lease_token = %s::uuid AND lease_until > clock_timestamp()"
)


@dataclass(frozen=True)
class AnalysisRecord:
    analysis_id: str
    sha256: str
    file_location: str
    filename: str
    size_bytes: int
    batch_id: str | None = None
    status: str = "QUEUED"
    current_stage: str = "UPLOAD"
    phase: str = "INITIAL"
    initial_result: Mapping[str, Any] | None = None
    deep_result: Mapping[str, Any] | None = None
    final_assessment: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None
    attempt_count: int = 0
    created_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    duplicate_of: str | None = None
    review_revision: int = 0
    analyst_final_verdict: str | None = None
    claimed: bool = False
    storage_deleted_at: str | None = None

    @property
    def terminal(self) -> bool:
        return self.status in {"COMPLETED", "FAILED"}

    def to_dict(self) -> dict[str, Any]:
        """Internal serialization; HTTP responses must exclude storage locations."""
        return asdict(self)


@dataclass(frozen=True)
class Claim:
    record: AnalysisRecord
    token: str | None = None


@dataclass(frozen=True)
class BatchRecord:
    batch_id: str | None
    analyses: list[AnalysisRecord]
    input_report: BatchInputReport | None = None


class AnalysisRepository(Protocol):
    def initialize(self) -> None: ...
    def check(self) -> None: ...
    def register(
        self,
        analyses: list[dict[str, Any]],
        *,
        batch_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[AnalysisRecord]: ...
    def register_batch(
        self,
        analyses,
        *,
        batch_id: str,
        input_report: BatchInputReport,
        idempotency_key: str | None = None,
    ) -> BatchRecord: ...
    def batch_record(self, batch_id: str) -> BatchRecord | None: ...
    def get(self, analysis_id: str) -> AnalysisRecord | None: ...
    def list_analyses(
        self,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        sha256: str | None = None,
        *,
        batch_id: str | None = None,
        verdict: str | None = None,
        sort: str = "newest",
    ) -> tuple[list[AnalysisRecord], int]: ...
    def get_batch(self, batch_id: str) -> list[AnalysisRecord] | None: ...
    def pending_ids(self, limit: int = 10) -> list[str]: ...
    def claim(self, analysis_id: str, lease_seconds: int) -> Claim: ...
    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool: ...
    def release(
        self,
        analysis_id: str,
        token: str,
        error: Mapping[str, Any] | None = None,
        next_retry_at: datetime | str | None = None,
    ) -> bool: ...
    def save_initial(
        self,
        analysis_id: str,
        token: str,
        result: Mapping[str, Any],
        needs_deep: bool,
    ) -> bool: ...
    def save_deep(
        self,
        analysis_id: str,
        token: str,
        snapshot: Mapping[str, Any],
        *,
        finished: bool,
        current_stage: str,
    ) -> bool: ...
    def finish(
        self,
        analysis_id: str,
        token: str,
        final_assessment: Mapping[str, Any],
        *,
        error: Mapping[str, Any] | None = None,
    ) -> bool: ...
    def cleanup_candidates(
        self, before_datetime: datetime, limit: int = 10
    ) -> list[AnalysisRecord]: ...
    def mark_storage_deleted(self, analysis_id: str) -> bool: ...
    def location_referenced(self, location: str) -> bool: ...
    def save_review(
        self,
        analysis_id: str,
        *,
        analyst_final_verdict: str | None,
        analyst_notes: str,
        reviewer_id: str,
        expected_revision: int,
    ) -> dict[str, Any]: ...
    def list_reviews(self, analysis_id: str) -> list[dict[str, Any]]: ...


class PostgresAnalysisRepository:
    """One bounded transaction per call; no network details enter public errors."""

    def __init__(
        self, dsn: str, *, connect_timeout: int = 5, statement_timeout_ms: int = 10000
    ):
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("A PostgreSQL connection string is required")
        _positive_int(connect_timeout, "connect_timeout")
        _positive_int(statement_timeout_ms, "statement_timeout_ms")
        try:
            existing = conninfo_to_dict(dsn).get("options", "")
        except psycopg.Error as exc:
            raise ValueError("Invalid PostgreSQL connection string") from exc
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._options = (
            f"{existing} -c statement_timeout={statement_timeout_ms}".strip()
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
        except psycopg.errors.UniqueViolation as exc:
            raise BackendError(
                "REGISTRATION_CONFLICT",
                "An analysis, batch, or storage location is already registered",
                http_status=409,
            ) from exc
        except psycopg.errors.CheckViolation as exc:
            raise BackendError(
                "INVALID_PERSISTED_STATE",
                "Analysis state failed persistence validation",
                http_status=422,
            ) from exc
        except psycopg.Error as exc:
            raise BackendError(
                "DATABASE_ERROR",
                "Analysis storage is temporarily unavailable",
                http_status=503,
                retryable=True,
            ) from exc

    def initialize(self) -> None:
        schema = files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")
        with self._connection() as connection:
            connection.execute(schema)

    def check(self) -> None:
        with self._connection() as connection:
            for table in ("api_batches", "api_analyses", "api_reviews"):
                # These table names are constants, never user input.
                connection.execute(f"SELECT * FROM {table} LIMIT 0")
            connection.execute("SELECT input_report FROM api_batches LIMIT 0")

    def register(
        self,
        analyses: list[dict[str, Any]],
        *,
        batch_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[AnalysisRecord]:
        return self._register(
            analyses, batch_id=batch_id, idempotency_key=idempotency_key
        ).analyses

    def register_batch(
        self, analyses, *, batch_id, input_report, idempotency_key=None
    ) -> BatchRecord:
        return self._register(
            analyses,
            batch_id=batch_id,
            input_report=input_report,
            idempotency_key=idempotency_key,
        )

    def _register(
        self, analyses, *, batch_id=None, idempotency_key=None, input_report=None
    ) -> BatchRecord:
        inputs, fingerprint, kind = registration_input(
            analyses, batch_id, idempotency_key, input_report
        )
        request_id = str(uuid4())
        with self._connection() as connection:
            row = connection.execute(
                """INSERT INTO api_batches
                   (request_id, batch_id, request_kind, idempotency_key, input_fingerprint, input_report)
                   VALUES (%s::uuid, %s, %s, %s, %s, %s)
                   ON CONFLICT (idempotency_key) DO NOTHING RETURNING request_id""",
                (
                    request_id,
                    batch_id,
                    kind,
                    idempotency_key,
                    fingerprint,
                    Jsonb(input_report.model_dump(mode="json"))
                    if input_report
                    else None,
                ),
            ).fetchone()
            if row is None:
                previous = connection.execute(
                    "SELECT request_id, request_kind, input_fingerprint, batch_id, input_report FROM api_batches WHERE idempotency_key = %s",
                    (idempotency_key,),
                ).fetchone()
                if (
                    previous is None
                    or previous["request_kind"] != kind
                    or previous["input_fingerprint"] != fingerprint
                ):
                    raise BackendError(
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key was already used for a different request",
                        http_status=409,
                    )
                records = [
                    _record(item)
                    for item in connection.execute(
                        _SELECT + " WHERE request_id = %s ORDER BY batch_position",
                        (previous["request_id"],),
                    ).fetchall()
                ]
                return BatchRecord(
                    previous["batch_id"],
                    records,
                    BatchInputReport.model_validate(previous["input_report"])
                    if previous["input_report"]
                    else None,
                )

            # Consistent hash-lock ordering avoids opposite-order batch deadlocks.
            # A concurrent duplicate registration sees the first committed analysis.
            for sample_hash in sorted({item["sha256"] for item in inputs}):
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (sample_hash,),
                )
            for position, item in enumerate(inputs):
                duplicate = connection.execute(
                    "SELECT analysis_id FROM api_analyses WHERE sha256 = %s ORDER BY created_at, analysis_id LIMIT 1",
                    (item["sha256"],),
                ).fetchone()
                connection.execute(
                    """INSERT INTO api_analyses
                       (analysis_id, request_id, batch_id, batch_position, sha256,
                        file_location, filename, size_bytes, duplicate_of)
                       VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        item["analysis_id"],
                        request_id,
                        batch_id,
                        position,
                        item["sha256"],
                        item["file_location"],
                        item["filename"],
                        item["size_bytes"],
                        duplicate["analysis_id"] if duplicate else None,
                    ),
                )
            records = [
                _record(item)
                for item in connection.execute(
                    _SELECT + " WHERE request_id = %s::uuid ORDER BY batch_position",
                    (request_id,),
                ).fetchall()
            ]
            return BatchRecord(
                batch_id,
                records,
                input_report.model_copy(deep=True) if input_report else None,
            )

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            return _record(row) if row else None

    def list_analyses(
        self,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        sha256: str | None = None,
        *,
        batch_id: str | None = None,
        verdict: str | None = None,
        sort: str = "newest",
    ) -> tuple[list[AnalysisRecord], int]:
        _limit(limit)
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        validate_listing(batch_id, verdict, sort)
        conditions, params = [], []
        if status is not None:
            if status not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}:
                raise ValueError("Unknown analysis status")
            conditions.append("status = %s")
            params.append(status)
        if sha256 is not None:
            _hash(sha256)
            conditions.append("sha256 = %s")
            params.append(sha256)
        if batch_id is not None:
            conditions.append("batch_id = %s")
            params.append(batch_id)
        if verdict is not None:
            conditions.append("initial_result ->> 'initial_verdict' = %s")
            params.append(verdict)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._connection() as connection:
            # One MVCC snapshot keeps count and page consistent under concurrent writes.
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            if (
                batch_id is not None
                and connection.execute(
                    "SELECT 1 FROM api_batches WHERE batch_id = %s", (batch_id,)
                ).fetchone()
                is None
            ):
                raise BackendError(
                    "BATCH_NOT_FOUND",
                    "해당 일괄 분석을 찾을 수 없습니다.",
                    http_status=404,
                )
            total = connection.execute(
                "SELECT count(*) AS total FROM api_analyses" + where, params
            ).fetchone()["total"]
            rows = connection.execute(
                _SELECT
                + where
                + " ORDER BY "
                + _LIST_ORDER[sort]
                + " LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
            return [_record(row) for row in rows], total

    def get_batch(self, batch_id: str) -> list[AnalysisRecord] | None:
        result = self.batch_record(batch_id)
        return None if result is None else result.analyses

    def batch_record(self, batch_id: str) -> BatchRecord | None:
        _identifier(batch_id, "batch_id")
        with self._connection() as connection:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            batch = connection.execute(
                "SELECT request_id, input_report FROM api_batches WHERE batch_id = %s",
                (batch_id,),
            ).fetchone()
            if batch is None:
                return None
            records = [
                _record(row)
                for row in connection.execute(
                    _SELECT + " WHERE request_id = %s ORDER BY batch_position",
                    (batch["request_id"],),
                ).fetchall()
            ]
            return BatchRecord(
                batch_id,
                records,
                BatchInputReport.model_validate(batch["input_report"])
                if batch["input_report"]
                else None,
            )

    def pending_ids(self, limit: int = 10) -> list[str]:
        _limit(limit)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT analysis_id FROM api_analyses WHERE "
                + _READY
                + " ORDER BY updated_at, analysis_id LIMIT %s",
                (limit,),
            ).fetchall()
            return [row["analysis_id"] for row in rows]

    def claim(self, analysis_id: str, lease_seconds: int) -> Claim:
        _lease(lease_seconds)
        token = str(uuid4())
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE api_analyses SET lease_token = %s::uuid,
                   lease_until = clock_timestamp() + make_interval(secs => %s),
                   status = 'RUNNING',
                   current_stage = CASE WHEN phase = 'INITIAL' THEN 'INITIAL_ANALYSIS' ELSE current_stage END,
                   attempt_count = attempt_count + 1, updated_at = clock_timestamp()
                   WHERE analysis_id = %s AND """
                + _READY
                + " RETURNING *, true AS claimed",
                (token, lease_seconds, analysis_id),
            ).fetchone()
            if row:
                return Claim(_record(row), token)
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            return Claim(_record(row))

    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool:
        _lease(lease_seconds)
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET lease_until = clock_timestamp() + make_interval(secs => %s),
                   updated_at = clock_timestamp() WHERE """
                    + _OWNED,
                    (lease_seconds, analysis_id, token),
                ).rowcount
                == 1
            )

    def release(
        self,
        analysis_id: str,
        token: str,
        error: Mapping[str, Any] | None = None,
        next_retry_at: datetime | str | None = None,
    ) -> bool:
        payload = json_object(error) if error is not None else None
        retry = _aware_datetime(next_retry_at) if next_retry_at is not None else None
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET lease_token = NULL, lease_until = NULL,
                   error = %s, next_retry_at = %s, updated_at = clock_timestamp() WHERE """
                    + _OWNED,
                    (
                        Jsonb(payload) if payload is not None else None,
                        retry,
                        analysis_id,
                        token,
                    ),
                ).rowcount
                == 1
            )

    def save_initial(
        self,
        analysis_id: str,
        token: str,
        result: Mapping[str, Any],
        needs_deep: bool,
    ) -> bool:
        if not isinstance(needs_deep, bool):
            raise TypeError("needs_deep must be boolean")
        payload = json_object(result)
        phase = "WAITING_DEEP" if needs_deep else "FINALIZING"
        stage = "CAPA_FLOSS" if needs_deep else "FINAL_ASSESSMENT"
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET initial_result = %s, phase = %s, current_stage = %s,
                   error = NULL, next_retry_at = NULL, updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND phase = 'INITIAL'",
                    (Jsonb(payload), phase, stage, analysis_id, token),
                ).rowcount
                == 1
            )

    def save_deep(
        self,
        analysis_id: str,
        token: str,
        snapshot: Mapping[str, Any],
        *,
        finished: bool,
        current_stage: str,
    ) -> bool:
        if not isinstance(finished, bool):
            raise TypeError("finished must be boolean")
        current_stage = CurrentStage(current_stage).value
        payload = json_object(snapshot)
        phase = "FINALIZING" if finished else "WAITING_DEEP"
        stage = "FINAL_ASSESSMENT" if finished else current_stage
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET deep_result = %s, phase = %s, current_stage = %s,
                   error = NULL, next_retry_at = NULL, updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND phase = 'WAITING_DEEP'",
                    (Jsonb(payload), phase, stage, analysis_id, token),
                ).rowcount
                == 1
            )

    def finish(
        self,
        analysis_id: str,
        token: str,
        final_assessment: Mapping[str, Any],
        *,
        error: Mapping[str, Any] | None = None,
    ) -> bool:
        result = json_object(final_assessment)
        failure = json_object(error) if error is not None else None
        status = "FAILED" if failure is not None else "COMPLETED"
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET final_assessment = %s, error = %s,
                   status = %s, phase = 'DONE', current_stage = 'FINAL_ASSESSMENT',
                   lease_token = NULL, lease_until = NULL, next_retry_at = NULL,
                   completed_at = clock_timestamp(), updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND (%s OR phase = 'FINALIZING')",
                    (
                        Jsonb(result),
                        Jsonb(failure) if failure is not None else None,
                        status,
                        analysis_id,
                        token,
                        failure is not None,
                    ),
                ).rowcount
                == 1
            )

    def cleanup_candidates(
        self, before_datetime: datetime, limit: int = 10
    ) -> list[AnalysisRecord]:
        before = _aware_datetime(before_datetime)
        _limit(limit)
        with self._connection() as connection:
            return [
                _record(row)
                for row in connection.execute(
                    _SELECT
                    + " WHERE status IN ('COMPLETED', 'FAILED') AND storage_deleted_at IS NULL"
                    " AND completed_at < %s ORDER BY completed_at, analysis_id LIMIT %s",
                    (before, limit),
                ).fetchall()
            ]

    def mark_storage_deleted(self, analysis_id: str) -> bool:
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET storage_deleted_at = clock_timestamp()
                   WHERE analysis_id = %s AND status IN ('COMPLETED', 'FAILED')
                   AND storage_deleted_at IS NULL""",
                    (analysis_id,),
                ).rowcount
                == 1
            )

    def location_referenced(self, location: str) -> bool:
        with self._connection() as connection:
            return connection.execute(
                "SELECT EXISTS (SELECT 1 FROM api_analyses WHERE file_location = %s AND storage_deleted_at IS NULL) AS found",
                (location,),
            ).fetchone()["found"]

    def save_review(
        self,
        analysis_id: str,
        *,
        analyst_final_verdict: str | None,
        analyst_notes: str,
        reviewer_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        validate_review(
            analyst_final_verdict, analyst_notes, reviewer_id, expected_revision
        )
        with self._connection() as connection:
            row = connection.execute(
                "SELECT status, review_revision FROM api_analyses WHERE analysis_id = %s FOR UPDATE",
                (analysis_id,),
            ).fetchone()
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if row["status"] not in {"COMPLETED", "FAILED"}:
                raise BackendError(
                    "ANALYSIS_NOT_FINISHED",
                    "Analysis must finish before analyst review",
                    http_status=409,
                )
            if row["review_revision"] != expected_revision:
                raise BackendError(
                    "REVIEW_CONFLICT",
                    "A newer analyst review already exists",
                    http_status=409,
                )
            revision = expected_revision + 1
            review = connection.execute(
                """INSERT INTO api_reviews
                   (review_id, analysis_id, revision, analyst_final_verdict, analyst_notes, reviewer_id, review_status)
                   VALUES (%s::uuid, %s, %s, %s, %s, %s, %s) RETURNING *""",
                (
                    str(uuid4()),
                    analysis_id,
                    revision,
                    analyst_final_verdict,
                    analyst_notes,
                    reviewer_id,
                    "PENDING" if analyst_final_verdict is None else "COMPLETED",
                ),
            ).fetchone()
            connection.execute(
                """UPDATE api_analyses SET review_revision = %s, analyst_final_verdict = %s,
                   updated_at = clock_timestamp() WHERE analysis_id = %s""",
                (revision, analyst_final_verdict, analysis_id),
            )
            return _review(review)

    def list_reviews(self, analysis_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            return [
                _review(row)
                for row in connection.execute(
                    "SELECT * FROM api_reviews WHERE analysis_id = %s ORDER BY revision",
                    (analysis_id,),
                ).fetchall()
            ]


def registration_input(analyses, batch_id, idempotency_key, input_report=None):
    """Validate before DB access; IDs/locations intentionally do not define replay identity."""
    minimum = 0 if batch_id is not None and input_report is not None else 1
    if not isinstance(analyses, list) or not minimum <= len(analyses) <= 100:
        raise ValueError("invalid number of registered analyses")
    if batch_id is None and len(analyses) != 1:
        raise ValueError("multiple analyses require a batch_id")
    if batch_id is not None:
        _identifier(batch_id, "batch_id")
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str)
        or not 1 <= len(idempotency_key) <= 200
        or any(ord(char) < 33 or ord(char) > 126 for char in idempotency_key)
    ):
        raise ValueError(
            "idempotency_key must contain 1-200 printable ASCII characters"
        )
    normalized = []
    for value in analyses:
        if not isinstance(value, Mapping) or set(value) != {
            "analysis_id",
            "sha256",
            "file_location",
            "filename",
            "size_bytes",
        }:
            raise ValueError("analysis input has missing or unknown fields")
        item = dict(value)
        _identifier(item["analysis_id"], "analysis_id")
        _hash(item["sha256"])
        for name, maximum in (("file_location", 4096), ("filename", 512)):
            if (
                not isinstance(item[name], str)
                or not 1 <= len(item[name]) <= maximum
                or "\x00" in item[name]
            ):
                raise ValueError(
                    f"{name} must be nonempty text within its length limit"
                )
        size = item["size_bytes"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= 2**63 - 1
        ):
            raise ValueError("size_bytes must be a nonnegative 64-bit integer")
        normalized.append(item)
    if len({item["analysis_id"] for item in normalized}) != len(normalized):
        raise ValueError("analysis IDs must be unique within a request")
    if len({item["file_location"] for item in normalized}) != len(normalized):
        raise ValueError("storage locations must be unique within a request")
    kind = "BATCH" if batch_id is not None else "SINGLE"
    identity = {
        "kind": kind,
        "inputs": [
            {name: item[name] for name in ("sha256", "size_bytes", "filename")}
            for item in normalized
        ],
    }
    if input_report is not None:
        if batch_id is None or not isinstance(input_report, BatchInputReport):
            raise ValueError("input reports require a batch and a validated report")
        report = BatchInputReport.model_validate(input_report.model_dump(mode="json"))
        accepted = [entry for entry in report.entries if entry.status == "ACCEPTED"]
        if not report.entries or len(accepted) != len(normalized):
            raise ValueError("input report must account for every accepted analysis")
        for entry, item in zip(accepted, normalized):
            if (entry.analysis_id, entry.sha256, entry.size_bytes) != (
                item["analysis_id"],
                item["sha256"],
                item["size_bytes"],
            ):
                raise ValueError(
                    "input report identity does not match registered analyses"
                )
        if report.source_type == "ZIP":
            # Archive bytes bind ALL entries, including encrypted/unsupported ones.
            # Admission limits may change between retries; they do not change input identity.
            identity = {
                "kind": kind,
                "archive": {
                    name: getattr(report, name)
                    for name in (
                        "archive_filename",
                        "archive_sha256",
                        "archive_size_bytes",
                    )
                },
            }
        elif any(entry.status == "SKIPPED" for entry in report.entries):
            if any(
                entry.sha256 is None or entry.size_bytes is None
                for entry in report.entries
            ):
                raise ValueError("direct batch entries require content hashes")
            identity["all_inputs"] = [
                {
                    name: getattr(entry, name)
                    for name in ("filename", "sha256", "size_bytes")
                }
                for entry in report.entries
            ]
    encoded = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return normalized, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), kind


_LIST_ORDER = {
    "newest": "created_at DESC, analysis_id DESC",
    "input_order": "batch_position, analysis_id",
    "high_risk_first": """CASE WHEN status = 'FAILED' THEN 4
        WHEN initial_result ->> 'initial_verdict' = 'HIGH_RISK_UNCERTAIN' THEN 0
        WHEN initial_result ->> 'initial_verdict' = 'AUTO_MALICIOUS' THEN 1
        WHEN initial_result ->> 'initial_verdict' = 'AUTO_BENIGN' THEN 2
        ELSE 3 END, created_at DESC, analysis_id DESC""",
}


def validate_listing(batch_id, verdict, sort):
    if batch_id is not None:
        _identifier(batch_id, "batch_id")
    if verdict is not None and verdict not in {item.value for item in InitialVerdict}:
        raise ValueError("unknown initial verdict")
    if sort not in _LIST_ORDER or (sort == "input_order" and batch_id is None):
        raise ValueError("invalid result sort order")


def json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("Analysis state must be a JSON object")
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("Analysis state exceeds the 8 MiB limit")
        return json.loads(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(
            "Analysis state must be finite JSON within the 8 MiB limit"
        ) from exc


def validate_review(verdict, notes, reviewer, revision):
    if verdict is not None and verdict not in {"BENIGN", "MALICIOUS"}:
        raise ValueError("Analyst verdict must be BENIGN, MALICIOUS, or null")
    if not isinstance(notes, str) or len(notes) > 10000 or "\x00" in notes:
        raise ValueError("Analyst notes must be text of at most 10000 characters")
    if (
        not isinstance(reviewer, str)
        or not reviewer.strip()
        or len(reviewer) > 128
        or "\x00" in reviewer
    ):
        raise ValueError("reviewer_id must be nonempty text of at most 128 characters")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise ValueError("expected_revision must be a nonnegative integer")


def _positive_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _limit(value):
    _positive_int(value, "limit")
    if value > 100:
        raise ValueError("limit must not exceed 100")


def _lease(value):
    _positive_int(value, "lease_seconds")
    if value > 43200:
        raise ValueError("lease_seconds must not exceed 43200")


def _identifier(value, name):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be an identifier of 1-128 characters")


def _hash(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


def _aware_datetime(value):
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str)
        else value
    )
    if (
        not isinstance(parsed, datetime)
        or parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise ValueError("A timezone-aware timestamp is required")
    return parsed.astimezone(timezone.utc)


def _iso(value):
    return _aware_datetime(value).isoformat() if value is not None else None


def _record(row):
    keys = AnalysisRecord.__dataclass_fields__
    payload = {name: row[name] for name in keys}
    for name in ("created_at", "updated_at", "completed_at", "storage_deleted_at"):
        payload[name] = _iso(payload[name])
    return AnalysisRecord(**payload)


def _review(row):
    return {
        "review_id": str(row["review_id"]),
        "analysis_id": row["analysis_id"],
        "revision": row["revision"],
        "analyst_final_verdict": row["analyst_final_verdict"],
        "analyst_notes": row["analyst_notes"],
        "reviewer_id": row["reviewer_id"],
        "review_status": row["review_status"],
        "reviewed_at": _iso(row["reviewed_at"]),
    }
