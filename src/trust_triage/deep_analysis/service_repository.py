"""PostgreSQL checkpoints and fenced claims for the complete deep-analysis flow."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Protocol
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from ..speakeasy_worker.errors import RetryableError
from ..speakeasy_worker.models import JobConflict
from .service_models import (
    DeepAnalysisClaim,
    DeepAnalysisPhase,
    DeepAnalysisRecord,
    DeepAnalysisRequest,
)

MAX_STATE_BYTES = 16 * 1024 * 1024
_SELECT = (
    "SELECT *, (lease_until > clock_timestamp()) AS claimed FROM deep_analysis_runs"
)
_NONTERMINAL = "phase IN ('STATIC', 'WAITING_SPEAKEASY', 'FINALIZING')"
_AVAILABLE = (
    "(lease_until IS NULL OR lease_until <= clock_timestamp())"
    " AND (next_retry_at IS NULL OR next_retry_at <= clock_timestamp())"
)
_OWNED = (
    "analysis_id = %s AND "
    + _NONTERMINAL
    + " AND lease_token = %s::uuid AND lease_until > clock_timestamp()"
    " AND cancellation IS NULL"
)
_OWNED_CANCELLED = (
    "analysis_id = %s AND "
    + _NONTERMINAL
    + " AND lease_token = %s::uuid AND lease_until > clock_timestamp()"
    " AND cancellation IS NOT NULL"
)


class DeepAnalysisRepository(Protocol):
    def initialize(self) -> None: ...
    def check(self) -> None: ...
    def register(
        self, request: DeepAnalysisRequest, config_fingerprint: str
    ) -> DeepAnalysisRecord: ...
    def get(self, analysis_id: str) -> DeepAnalysisRecord | None: ...
    def pending_ids(self, limit: int = 10) -> list[str]: ...
    def claim(self, analysis_id: str, lease_seconds: int) -> DeepAnalysisClaim: ...
    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool: ...
    def save_checkpoint(
        self,
        analysis_id: str,
        token: str,
        checkpoint: Mapping[str, Any],
        phase: DeepAnalysisPhase,
    ) -> bool: ...
    def finish(
        self, analysis_id: str, token: str, result: Mapping[str, Any]
    ) -> bool: ...
    def release(
        self, analysis_id: str, token: str, error: Mapping[str, Any] | None = None
    ) -> bool: ...
    def request_cancel(
        self, analysis_id: str, reason: Mapping[str, Any]
    ) -> DeepAnalysisRecord: ...
    def finish_cancelled(
        self, analysis_id: str, token: str, result: Mapping[str, Any]
    ) -> bool: ...


class PostgresDeepAnalysisRepository:
    """Each operation commits before returning and uses its own bounded connection."""

    def __init__(
        self, dsn: str, *, connect_timeout: int = 5, statement_timeout_ms: int = 10000
    ) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("WORKER_DATABASE_URL is required")
        if connect_timeout <= 0 or statement_timeout_ms <= 0:
            raise ValueError("database timeouts must be positive")
        try:
            existing_options = conninfo_to_dict(dsn).get("options", "")
        except psycopg.Error as exc:
            raise ValueError(
                "WORKER_DATABASE_URL must be a PostgreSQL connection string"
            ) from exc
        self._dsn = dsn
        self._connect_timeout = connect_timeout
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
        except psycopg.Error as exc:
            raise RetryableError(
                "DATABASE_ERROR", "PostgreSQL deep-analysis operation failed"
            ) from exc

    def initialize(self) -> None:
        schema = (
            files(__package__)
            .joinpath("service_schema.sql")
            .read_text(encoding="utf-8")
        )
        with self._connection() as connection:
            connection.execute(schema)

    def check(self) -> None:
        with self._connection() as connection:
            connection.execute("SELECT * FROM deep_analysis_runs LIMIT 0")

    def register(
        self, request: DeepAnalysisRequest, config_fingerprint: str
    ) -> DeepAnalysisRecord:
        if (
            not isinstance(config_fingerprint, str)
            or not 1 <= len(config_fingerprint) <= 256
            or any(ord(char) < 33 for char in config_fingerprint)
        ):
            raise ValueError(
                "config_fingerprint must contain 1-256 non-whitespace characters"
            )
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO deep_analysis_runs
                   (analysis_id, sha256, file_location, initial_route,
                    initial_verdict, requested_at, config_fingerprint)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (analysis_id) DO NOTHING""",
                (
                    request.analysis_id,
                    request.sha256,
                    request.file_location,
                    request.initial_route,
                    request.initial_verdict,
                    request.requested_at,
                    config_fingerprint,
                ),
            )
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (request.analysis_id,)
            ).fetchone()
            record = _record(row)
            if (
                not record.request.same_input(request)
                or record.config_fingerprint != config_fingerprint
            ):
                raise JobConflict(
                    "analysis_id is already registered for different input or config"
                )
            return record

    def get(self, analysis_id: str) -> DeepAnalysisRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            return _record(row) if row else None

    def pending_ids(self, limit: int = 10) -> list[str]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise ValueError("pending limit must be between 1 and 100")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT analysis_id FROM deep_analysis_runs WHERE "
                + _NONTERMINAL
                + " AND "
                + _AVAILABLE
                + " ORDER BY (cancellation IS NULL), updated_at, analysis_id LIMIT %s",
                (limit,),
            ).fetchall()
            return [row["analysis_id"] for row in rows]

    def claim(self, analysis_id: str, lease_seconds: int) -> DeepAnalysisClaim:
        _validate_lease(lease_seconds)
        token = str(uuid4())
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE deep_analysis_runs
                   SET lease_token = %s::uuid,
                       lease_until = clock_timestamp() + make_interval(secs => %s),
                       attempt_count = attempt_count + 1, updated_at = clock_timestamp()
                   WHERE analysis_id = %s AND """
                + _NONTERMINAL
                + " AND "
                + _AVAILABLE
                + " RETURNING *, true AS claimed",
                (token, lease_seconds, analysis_id),
            ).fetchone()
            if row:
                return DeepAnalysisClaim(_record(row), token)
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            if row is None:
                raise ValueError("analysis_id is not registered")
            return DeepAnalysisClaim(_record(row))

    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool:
        _validate_lease(lease_seconds)
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE deep_analysis_runs
                   SET lease_until = clock_timestamp() + make_interval(secs => %s),
                       updated_at = clock_timestamp() WHERE """
                + _OWNED,
                (lease_seconds, analysis_id, token),
            )
            return cursor.rowcount == 1

    def save_checkpoint(
        self,
        analysis_id: str,
        token: str,
        checkpoint: Mapping[str, Any],
        phase: DeepAnalysisPhase,
    ) -> bool:
        phase = DeepAnalysisPhase(phase)
        if phase not in {
            DeepAnalysisPhase.WAITING_SPEAKEASY,
            DeepAnalysisPhase.FINALIZING,
        }:
            raise ValueError(
                "checkpoints require WAITING_SPEAKEASY or FINALIZING phase"
            )
        payload = _json_object(checkpoint)
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE deep_analysis_runs SET checkpoint = %s, phase = %s,
                   last_error = NULL, next_retry_at = NULL,
                   updated_at = clock_timestamp() WHERE """
                + _OWNED
                + " AND (phase <> 'FINALIZING' OR %s = 'FINALIZING')",
                (Jsonb(payload), phase.value, analysis_id, token, phase.value),
            )
            return cursor.rowcount == 1

    def finish(self, analysis_id: str, token: str, result: Mapping[str, Any]) -> bool:
        payload = _json_object(result)
        status = payload.get("deep_analysis_status")
        if status not in {"COMPLETE", "FAILED", "NOT_REQUIRED"}:
            raise ValueError("finish requires a terminal DeepAnalysisResult")
        phase = "COMPLETED" if status == "COMPLETE" else status
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE deep_analysis_runs SET phase = %s, result = %s,
                   last_error = NULL, next_retry_at = NULL,
                   lease_token = NULL, lease_until = NULL,
                   completed_at = clock_timestamp(), updated_at = clock_timestamp()
                   WHERE """
                + _OWNED,
                (phase, Jsonb(payload), analysis_id, token),
            )
            return cursor.rowcount == 1

    def release(
        self, analysis_id: str, token: str, error: Mapping[str, Any] | None = None
    ) -> bool:
        payload = _json_object(error) if error is not None else None
        next_retry_at = _retry_timestamp(payload)
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE deep_analysis_runs SET lease_token = NULL, lease_until = NULL,
                   last_error = %s, next_retry_at = %s, updated_at = clock_timestamp()
                   WHERE """
                + _OWNED,
                (
                    Jsonb(payload) if payload is not None else None,
                    next_retry_at,
                    analysis_id,
                    token,
                ),
            )
            return cursor.rowcount == 1

    def request_cancel(
        self, analysis_id: str, reason: Mapping[str, Any]
    ) -> DeepAnalysisRecord:
        payload = _json_object(reason)
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE deep_analysis_runs
                   SET cancellation = coalesce(cancellation, %s),
                       next_retry_at = NULL, updated_at = clock_timestamp()
                   WHERE analysis_id = %s AND """
                + _NONTERMINAL
                + " RETURNING *, (lease_until > clock_timestamp()) AS claimed",
                (Jsonb(payload), analysis_id),
            ).fetchone()
            if row is None:
                row = connection.execute(
                    _SELECT + " WHERE analysis_id = %s", (analysis_id,)
                ).fetchone()
            if row is None:
                raise ValueError("analysis_id is not registered")
            return _record(row)

    def finish_cancelled(
        self, analysis_id: str, token: str, result: Mapping[str, Any]
    ) -> bool:
        payload = _json_object(result)
        if payload.get("deep_analysis_status") != "FAILED":
            raise ValueError("cancelled analysis requires a FAILED result")
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE deep_analysis_runs SET phase = 'FAILED', result = %s,
                   last_error = NULL, next_retry_at = NULL,
                   lease_token = NULL, lease_until = NULL,
                   completed_at = clock_timestamp(), updated_at = clock_timestamp()
                   WHERE """
                + _OWNED_CANCELLED,
                (Jsonb(payload), analysis_id, token),
            )
            return cursor.rowcount == 1


def _retry_timestamp(error: Mapping[str, Any] | None) -> datetime | None:
    """Parse once at the write boundary; queue scans never cast arbitrary JSON."""

    if error is None or "next_retry_at" not in error:
        return None
    value = error["next_retry_at"]
    if not isinstance(value, str):
        raise TypeError("next_retry_at must be an ISO-8601 string with a timezone")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("next_retry_at requires a timezone")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError(
            "next_retry_at must be a valid ISO-8601 timestamp with a timezone"
        ) from exc


def _validate_lease(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("lease_seconds must be a positive integer")


def _json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("state must be a JSON object")
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        if size > MAX_STATE_BYTES:
            raise ValueError("state exceeds the 16 MiB limit")
        return json.loads(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("state must be finite JSON within the 16 MiB limit") from exc


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _record(row: Mapping[str, Any]) -> DeepAnalysisRecord:
    return DeepAnalysisRecord(
        request=DeepAnalysisRequest(
            analysis_id=row["analysis_id"],
            sha256=row["sha256"],
            file_location=row["file_location"],
            initial_route=row["initial_route"],
            initial_verdict=row["initial_verdict"],
            requested_at=_iso(row["requested_at"]),
        ),
        config_fingerprint=row["config_fingerprint"],
        phase=DeepAnalysisPhase(row["phase"]),
        checkpoint=row["checkpoint"],
        result=row["result"],
        last_error=row["last_error"],
        cancellation=row.get("cancellation"),
        attempts=row["attempt_count"],
        updated_at=_iso(row["updated_at"]),
        claimed=bool(row["claimed"]),
    )
