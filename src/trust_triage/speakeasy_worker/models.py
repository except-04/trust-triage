"""Backend와 Worker가 공유하는 요청 및 Speakeasy 단계 결과."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from trust_triage.dynamic_analysis.models import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
)

MAX_MESSAGE_BYTES = 16 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
RESULT_SCHEMA_VERSION = "speakeasy-result-v1"
_JOB_FIELDS = frozenset(
    {"analysis_id", "sha256", "file_location", "requested_stage", "requested_at"}
)


class InvalidJob(ValueError):
    """메시지가 Worker 요청 규격에 맞지 않는다."""


class JobConflict(ValueError):
    """같은 분석 번호에 다른 파일을 연결하려고 했다."""


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def s3_location(value: str) -> tuple[str, str]:
    """s3://bucket/key만 허용한다. 로컬 경로나 임의 HTTP URL은 받지 않는다."""

    if not isinstance(value, str) or len(value) > 2048:
        raise InvalidJob("file_location must be an S3 URI of at most 2048 characters")
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise InvalidJob("file_location contains invalid characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise InvalidJob("file_location is not a valid S3 URI") from exc
    if (
        parsed.scheme != "s3"
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", parsed.netloc)
        or not parsed.path.startswith("/")
        or len(parsed.path) < 2
        or parsed.query
        or parsed.fragment
        or any(part in {"", ".", ".."} for part in parsed.path[1:].split("/"))
    ):
        raise InvalidJob(
            "file_location must use s3://bucket/key without query or fragment"
        )
    return parsed.netloc, parsed.path[1:]


@dataclass(frozen=True)
class SpeakeasyJob:
    analysis_id: str
    sha256: str
    file_location: str
    requested_stage: str = "SPEAKEASY"
    requested_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.analysis_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", self.analysis_id
        ):
            raise InvalidJob(
                "analysis_id must contain 1-128 letters, digits, '-' or '_'"
            )
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", self.sha256
        ):
            raise InvalidJob("sha256 must contain 64 hexadecimal characters")
        object.__setattr__(self, "sha256", self.sha256.lower())
        s3_location(self.file_location)
        if self.requested_stage != "SPEAKEASY":
            raise InvalidJob("requested_stage must be SPEAKEASY")
        if not isinstance(self.requested_at, str) or not self.requested_at:
            raise InvalidJob(
                "requested_at must be an ISO-8601 timestamp with a timezone"
            )
        try:
            timestamp = datetime.fromisoformat(self.requested_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise InvalidJob("requested_at must be an ISO-8601 timestamp") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise InvalidJob("requested_at must include a timezone")
        object.__setattr__(
            self, "requested_at", timestamp.astimezone(timezone.utc).isoformat()
        )

    @classmethod
    def from_json(cls, body: str) -> SpeakeasyJob:
        if not isinstance(body, str):
            raise InvalidJob("message must be a JSON string")
        try:
            size = len(body.encode("utf-8"))
        except UnicodeError as exc:
            raise InvalidJob("message must be valid UTF-8") from exc
        if size > MAX_MESSAGE_BYTES:
            raise InvalidJob("message exceeds the 16 KiB limit")
        try:
            payload = json.loads(body, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError) as exc:
            raise InvalidJob("message must be valid JSON") from exc
        if not isinstance(payload, dict) or set(payload) != _JOB_FIELDS:
            raise InvalidJob(
                "message must contain exactly the five documented job fields"
            )
        return cls(**payload)

    def to_dict(self) -> dict[str, str]:
        return {
            "analysis_id": self.analysis_id,
            "sha256": self.sha256,
            "file_location": self.file_location,
            "requested_stage": self.requested_stage,
            "requested_at": self.requested_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    def same_input(self, other: SpeakeasyJob) -> bool:
        # 등록 시각은 재전송 때 달라져도 최초 값을 보존한다.
        return (
            self.analysis_id,
            self.sha256,
            self.file_location,
            self.requested_stage,
        ) == (
            other.analysis_id,
            other.sha256,
            other.file_location,
            other.requested_stage,
        )


def failure_result(
    job: SpeakeasyJob, code: str, message: str, *, started_at: str | None = None
) -> dict[str, Any]:
    """입력/인프라 실패도 악성 판정 없이 Speakeasy 단계 실패로 저장한다."""

    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "analysis_id": job.analysis_id,
        "sha256": job.sha256,
        "tool": "SPEAKEASY",
        "status": JobStatus.FAILED.value,
        "tool_status": None,
        "behavior": {
            name: []
            for name in ("processes", "api_calls", "files", "registry", "network")
        },
        "error": {"code": code, "message": message[:1000]},
        "started_at": started_at,
        "completed_at": utc_now(),
        "analysis": None,
        "artifact": None,
        "artifact_error": None,
    }


def result_from_analysis(
    job: SpeakeasyJob, analysis: DynamicAnalysisResult
) -> dict[str, Any]:
    """기존 결과의 상세 상태와 부분 결과를 보존하면서 서비스용 필드를 만든다."""

    if not isinstance(analysis.status, DynamicAnalysisStatus):
        raise TypeError("Analyzer returned an unknown tool status")
    if analysis.sha256 and analysis.sha256 != job.sha256:
        return failure_result(
            job, "RESULT_HASH_MISMATCH", "Analyzer returned a different SHA-256"
        )
    success = analysis.status is DynamicAnalysisStatus.SUCCESS
    if success and not analysis.sha256:
        return failure_result(
            job, "RESULT_HASH_MISSING", "Successful analysis has no SHA-256"
        )

    def events(*names: str) -> list[dict[str, Any]]:
        return [
            dict(event) for name in names for event in analysis.events.get(name, ())
        ]

    payload = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "analysis_id": job.analysis_id,
        "sha256": job.sha256,
        "tool": "SPEAKEASY",
        "status": JobStatus.COMPLETED.value if success else JobStatus.FAILED.value,
        "tool_status": analysis.status.value,
        "behavior": {
            "processes": events("process_events"),
            "api_calls": events("api_calls"),
            "files": events("file_access", "dropped_files"),
            "registry": events("registry_access"),
            "network": events("network_events"),
        },
        "error": None
        if success
        else {
            "code": analysis.status.value,
            "message": (
                "; ".join(analysis.errors or analysis.warnings) or analysis.summary
            )[:1000],
        },
        "started_at": analysis.started_at,
        "completed_at": analysis.completed_at or utc_now(),
        "analysis": analysis.to_dict(),
        "artifact": None,
        "artifact_error": None,
    }
    # Worker는 대형 원본 report를 수집하지 않는다. 요약 및 모든 제한된 이벤트는 유지한다.
    payload["analysis"]["raw_report"] = None
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        return failure_result(
            job, "RESULT_TOO_LARGE", "Analysis result exceeds the 4 MiB limit"
        )
    return json.loads(encoded)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJob("message contains a duplicate JSON field")
        result[key] = value
    return result


@dataclass(frozen=True)
class JobRecord:
    job: SpeakeasyJob
    status: JobStatus
    attempts: int = 0
    result: Mapping[str, Any] | None = None
    last_error: Mapping[str, str] | None = None
    dispatch_pending: bool = False
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        # 원본 위치는 제외한다. artifact의 내부 저장 위치는 HTTP에서 별도 처리한다.
        return {
            "analysis_id": self.job.analysis_id,
            "sha256": self.job.sha256,
            "requested_stage": self.job.requested_stage,
            "status": self.status.value,
            "attempt_count": self.attempts,
            "dispatch_pending": self.dispatch_pending,
            "last_error": self.last_error,
            "updated_at": self.updated_at,
            "result": self.result,
        }
