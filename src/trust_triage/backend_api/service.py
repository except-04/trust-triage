"""접수·조회·검토 업무. 분석 실행은 processor.py가 별도 프로세스에서 맡는다."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import BinaryIO
from uuid import uuid4

from . import views
from .config import BackendConfig
from .errors import BackendError
from .repository import AnalysisRecord, AnalysisRepository
from .schemas import (
    AnalysisListResponse,
    BatchAccepted,
    BatchResponse,
    ReviewHistoryResponse,
    ReviewRequest,
)
from .storage import SampleStorage, StoredSample

LOGGER = logging.getLogger(__name__)


def stored_sample(record: AnalysisRecord) -> StoredSample:
    return StoredSample(
        **{key: getattr(record, key) for key in StoredSample.__dataclass_fields__}
    )


class BackendService:
    def __init__(
        self,
        repository: AnalysisRepository,
        storage: SampleStorage,
        config: BackendConfig,
        *,
        cleanup_guard=None,
    ):
        self.repository, self.storage, self.config = repository, storage, config
        self.cleanup_guard = cleanup_guard

    def _discard_unreferenced(self, sample: StoredSample) -> None:
        try:
            # DB commit 직후 연결이 끊긴 경우에도 접수된 원본을 삭제하지 않는다.
            if not self.repository.location_referenced(sample.file_location):
                self.storage.delete(sample)
        except Exception:  # noqa: BLE001 - cleanup must not hide the original request failure
            LOGGER.warning("upload_cleanup_deferred analysis_id=%s", sample.analysis_id)

    def submit(
        self,
        files: list[tuple[BinaryIO, str]],
        *,
        batch: bool = False,
        idempotency_key: str | None = None,
    ):
        if (
            not files
            or len(files) > self.config.max_batch_files
            or (not batch and len(files) != 1)
        ):
            raise BackendError(
                "INVALID_FILE_COUNT",
                "업로드 파일 수가 허용 범위를 벗어났습니다.",
                http_status=422,
                stage="UPLOAD",
            )
        if idempotency_key is not None and (
            not 1 <= len(idempotency_key) <= 200
            or any(ord(c) < 33 or ord(c) > 126 for c in idempotency_key)
        ):
            raise BackendError(
                "INVALID_IDEMPOTENCY_KEY",
                "Idempotency-Key는 1~200자의 공백 없는 ASCII 문자열이어야 합니다.",
                http_status=422,
            )
        batch_id = f"batch_{uuid4().hex}" if batch else None
        uploaded: list[StoredSample] = []
        try:
            for stream, filename in files:
                uploaded.append(
                    self.storage.ingest(
                        stream, analysis_id=f"analysis_{uuid4().hex}", filename=filename
                    )
                )
            records = self.repository.register(
                [asdict(sample) for sample in uploaded],
                batch_id=batch_id,
                idempotency_key=idempotency_key,
            )
        except BaseException:
            for sample in uploaded:
                self._discard_unreferenced(sample)
            raise
        retained = {row.file_location for row in records}
        for sample in uploaded:
            if sample.file_location not in retained:
                self._discard_unreferenced(sample)
        if batch:
            return BatchAccepted(
                batch_id=records[0].batch_id,
                total_count=len(records),
                analyses=[views.accepted(row) for row in records],
            )
        return views.accepted(records[0])

    def get(self, analysis_id: str) -> AnalysisRecord:
        record = self.repository.get(analysis_id)
        if record is None:
            raise BackendError(
                "ANALYSIS_NOT_FOUND", "해당 분석을 찾을 수 없습니다.", http_status=404
            )
        return record

    def list_analyses(
        self, *, limit=20, offset=0, status=None, sha256=None
    ) -> AnalysisListResponse:
        rows, total = self.repository.list_analyses(limit, offset, status, sha256)
        return AnalysisListResponse(
            total_count=total,
            limit=limit,
            offset=offset,
            analyses=[views.analysis(row) for row in rows],
        )

    def get_batch(self, batch_id: str) -> BatchResponse:
        rows = self.repository.get_batch(batch_id)
        if rows is None:
            raise BackendError(
                "BATCH_NOT_FOUND", "해당 일괄 분석을 찾을 수 없습니다.", http_status=404
            )
        counts = {state: 0 for state in ("QUEUED", "RUNNING", "COMPLETED", "FAILED")}
        counts.update(Counter(row.status for row in rows))
        return BatchResponse(
            batch_id=batch_id,
            total_count=len(rows),
            finished_count=sum(row.terminal for row in rows),
            status_counts=counts,
            analyses=[views.analysis(row) for row in rows],
        )

    def review(self, analysis_id: str, request: ReviewRequest):
        return views.review(
            self.repository.save_review(analysis_id, **request.model_dump())
        )

    def reviews(self, analysis_id: str) -> ReviewHistoryResponse:
        self.get(analysis_id)
        return ReviewHistoryResponse(
            analysis_id=analysis_id,
            items=[
                views.review(row) for row in self.repository.list_reviews(analysis_id)
            ],
        )

    def cleanup(self, *, limit: int = 100, delete: bool = False) -> dict:
        before = datetime.now(timezone.utc) - timedelta(
            hours=self.config.retention_hours
        )
        rows = self.repository.cleanup_candidates(before, limit)
        deleted, skipped = [], []
        for record in rows:
            if (
                self.config.storage_mode == "s3"
                and (record.initial_result or {}).get("route") == "DEEP_ANALYSIS"
            ):
                try:
                    safe = self.cleanup_guard is not None and self.cleanup_guard(record)
                except Exception:  # noqa: BLE001 - preserve samples when linked job state is uncertain
                    safe = False
                if not safe:
                    skipped.append(record.analysis_id)
                    continue
            if delete:
                self.storage.delete(stored_sample(record))
                if self.repository.mark_storage_deleted(record.analysis_id):
                    deleted.append(record.analysis_id)
        return {
            "candidate_ids": [row.analysis_id for row in rows],
            "deleted_ids": deleted,
            "skipped_ids": skipped,
            "retention_hours": self.config.retention_hours,
        }
