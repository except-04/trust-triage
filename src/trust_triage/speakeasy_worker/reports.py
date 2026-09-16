"""검증된 Worker 결과를 공통 SHA-256 산출물 규격으로 보관한다.

DB 결과가 기준이다. 보조 리포트 저장에 실패해도 관찰 결과는 DB에 남기고
artifact_error로 누락을 드러낸다. 엔진의 전체 raw report와는 구분한다.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from trust_triage.storage import ArtifactError, ArtifactIdentity, ArtifactReference

from .models import SpeakeasyJob


class ArtifactStore(Protocol):
    def put_json(
        self, identity: ArtifactIdentity, value, **metadata
    ) -> ArtifactReference: ...


class ReportWriter:
    def __init__(self, storage: ArtifactStore, *, config_sha256: str | None = None):
        self.storage = storage
        self.config_sha256 = config_sha256

    def archive(
        self,
        job: SpeakeasyJob,
        tool_run_id: str,
        result: Mapping[str, Any],
        check_ownership: Callable[[], None],
    ) -> dict[str, Any]:
        value = {**result, "tool_run_id": tool_run_id}
        identity = ArtifactIdentity(
            job.sha256, job.analysis_id, "SPEAKEASY", tool_run_id
        )
        report = {"report_kind": "normalized_worker_result", "result": value}
        metadata = {
            "tool_version": (value.get("analysis") or {}).get("tool_version"),
            "config_sha256": self.config_sha256,
        }
        for attempt in range(3):
            check_ownership()
            try:
                reference = self.storage.put_json(identity, report, **metadata)
            except ArtifactError as exc:
                if exc.retryable and attempt < 2:
                    time.sleep(0.1 * (2**attempt))
                    continue
                return {
                    **value,
                    "artifact": None,
                    "artifact_error": {"code": exc.code, "message": exc.message},
                }
            check_ownership()
            return {**value, "artifact": reference.to_dict(), "artifact_error": None}
        raise AssertionError("report retry loop must return or raise")
