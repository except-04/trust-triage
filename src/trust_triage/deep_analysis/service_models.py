"""Durable request and lifecycle contracts for asynchronous deep analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..speakeasy_worker.models import (
    MAX_MESSAGE_BYTES,
    InvalidJob,
    SpeakeasyJob,
    utc_now,
)

_REQUEST_FIELDS = frozenset(
    {
        "analysis_id",
        "sha256",
        "file_location",
        "initial_route",
        "initial_verdict",
        "requested_at",
    }
)
_REQUIRED_FIELDS = _REQUEST_FIELDS - {"initial_verdict", "requested_at"}


@dataclass(frozen=True)
class DeepAnalysisRequest:
    analysis_id: str
    sha256: str
    file_location: str
    initial_route: str
    initial_verdict: str = "UNKNOWN"
    requested_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        job = self.worker_job
        object.__setattr__(self, "sha256", job.sha256)
        object.__setattr__(self, "requested_at", job.requested_at)
        if not isinstance(self.initial_route, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]{0,127}", self.initial_route
        ):
            raise InvalidJob(
                "initial_route must be an ASCII identifier of 1-128 characters"
            )
        if not isinstance(
            self.initial_verdict, str
        ) or self.initial_verdict.upper() not in {"BENIGN", "MALICIOUS", "UNKNOWN"}:
            raise InvalidJob("initial_verdict must be BENIGN, MALICIOUS, or UNKNOWN")
        object.__setattr__(self, "initial_route", self.initial_route.upper())
        object.__setattr__(self, "initial_verdict", self.initial_verdict.upper())

    @property
    def worker_job(self) -> SpeakeasyJob:
        return SpeakeasyJob(
            analysis_id=self.analysis_id,
            sha256=self.sha256,
            file_location=self.file_location,
            requested_at=self.requested_at,
        )

    def same_input(self, other: DeepAnalysisRequest) -> bool:
        return (
            self.worker_job.same_input(other.worker_job)
            and self.initial_route == other.initial_route
            and self.initial_verdict == other.initial_verdict
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "analysis_id": self.analysis_id,
            "sha256": self.sha256,
            "file_location": self.file_location,
            "initial_route": self.initial_route,
            "initial_verdict": self.initial_verdict,
            "requested_at": self.requested_at,
        }

    @classmethod
    def from_json(cls, body: str) -> DeepAnalysisRequest:
        if not isinstance(body, str):
            raise InvalidJob("request must be a JSON string")
        try:
            size = len(body.encode("utf-8"))
        except UnicodeError as exc:
            raise InvalidJob("request must be valid UTF-8") from exc
        if size > MAX_MESSAGE_BYTES:
            raise InvalidJob("request exceeds the 16 KiB limit")
        try:
            payload = json.loads(
                body, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
            )
        except (ValueError, RecursionError) as exc:
            raise InvalidJob(
                "request must be valid JSON without duplicate fields"
            ) from exc
        if (
            not isinstance(payload, dict)
            or not _REQUIRED_FIELDS <= set(payload) <= _REQUEST_FIELDS
        ):
            raise InvalidJob("request contains missing or undocumented fields")
        return cls(**payload)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {value}")


class DeepAnalysisPhase(str, Enum):
    STATIC = "STATIC"
    WAITING_SPEAKEASY = "WAITING_SPEAKEASY"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_REQUIRED = "NOT_REQUIRED"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.NOT_REQUIRED}


@dataclass(frozen=True)
class DeepAnalysisRecord:
    request: DeepAnalysisRequest
    config_fingerprint: str
    phase: DeepAnalysisPhase = DeepAnalysisPhase.STATIC
    checkpoint: Mapping[str, Any] | None = None
    result: Mapping[str, Any] | None = None
    last_error: Mapping[str, Any] | None = None
    attempts: int = 0
    updated_at: str | None = None
    claimed: bool = False

    def to_dict(self) -> dict[str, Any]:
        status = self.phase.value if self.phase.terminal else "RUNNING"
        if self.phase is DeepAnalysisPhase.STATIC and not self.claimed:
            status = "QUEUED"
        # Checkpoints and S3 locations are internal persistence details.
        return {
            "analysis_id": self.request.analysis_id,
            "sha256": self.request.sha256,
            "initial_route": self.request.initial_route,
            "initial_verdict": self.request.initial_verdict,
            "status": status,
            "phase": self.phase.value,
            "result": dict(self.result) if self.result is not None else None,
            "last_error": dict(self.last_error)
            if self.last_error is not None
            else None,
            "attempt_count": self.attempts,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class DeepAnalysisClaim:
    record: DeepAnalysisRecord
    token: str | None = None
