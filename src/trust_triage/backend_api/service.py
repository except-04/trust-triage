"""접수·조회·검토 업무. 분석 실행은 processor.py가 별도 프로세스에서 맡는다."""

from __future__ import annotations

import logging
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import BinaryIO
from uuid import uuid4

from . import batch_results, views
from .batch_inputs import BatchInputHandler
from .config import BackendConfig
from .errors import BackendError
from .repository import AnalysisRecord, AnalysisRepository
from .schemas import (
    AnalysisListResponse,
    BatchAnalysisListResponse,
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


def _validate_idempotency_key(key):
    if key is not None and (
        not isinstance(key, str)
        or not 1 <= len(key) <= 200
        or any(ord(c) < 33 or ord(c) > 126 for c in key)
    ):
        raise BackendError(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key는 1~200자의 공백 없는 ASCII 문자열이어야 합니다.",
            http_status=422,
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
            # Use the same cross-process lock as intake. A commit with a lost
            # response or another request's shared reference must keep the bytes.
            with self.repository.sample_transaction([sample.sha256]) as transaction:
                if not transaction.location_referenced(sample.file_location):
                    self.storage.delete(sample)
                    transaction.mark_sample_deleted(sample.file_location)
        except Exception:  # noqa: BLE001 - cleanup must not hide the original request failure
            LOGGER.warning("upload_cleanup_deferred analysis_id=%s", sample.analysis_id)

    def _publish_new(self, prepared, records, published):
        new_ids = {row.analysis_id for row in records}
        locations = set()
        for item in prepared:
            sample = item.sample
            if sample.analysis_id in new_ids and sample.file_location not in locations:
                published.append(self.storage.publish(item))
                locations.add(sample.file_location)

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
        _validate_idempotency_key(idempotency_key)
        if batch:
            return self._submit_batch(files, idempotency_key=idempotency_key)
        published: list[StoredSample] = []
        try:
            with ExitStack() as staging:
                prepared = [
                    staging.enter_context(
                        self.storage.prepare(
                            stream,
                            analysis_id=f"analysis_{uuid4().hex}",
                            filename=filename,
                        )
                    )
                    for stream, filename in files
                ]
                with self.repository.sample_transaction(
                    [item.sample.sha256 for item in prepared]
                ) as transaction:
                    # Rows are invisible until all new objects have been published.
                    # An idempotency replay publishes nothing, even after expiry.
                    records = transaction.register(
                        [asdict(item.sample) for item in prepared],
                        batch_id=None,
                        idempotency_key=idempotency_key,
                    )
                    self._publish_new(prepared, records, published)
        except BaseException:
            for sample in published:
                self._discard_unreferenced(sample)
            raise
        return views.accepted(records[0])

    def submit_zip(self, files: list[tuple[BinaryIO, str]], *, idempotency_key=None):
        _validate_idempotency_key(idempotency_key)
        return self._submit_batch(files, archive=True, idempotency_key=idempotency_key)

    def _submit_batch(self, files, *, archive=False, idempotency_key=None):
        published: list[StoredSample] = []
        try:
            with ExitStack() as staging:
                inputs = staging.enter_context(
                    BatchInputHandler(self.config).prepare(files, archive=archive)
                )
                report = inputs.report.model_copy(deep=True)
                prepared = []
                for entry in report.entries:
                    if entry.status != "ACCEPTED":
                        continue
                    with inputs.paths[entry.input_index].open("rb") as stream:
                        item = staging.enter_context(
                            self.storage.prepare(
                                stream,
                                analysis_id=f"analysis_{uuid4().hex}",
                                filename=entry.filename,
                            )
                        )
                    prepared.append(item)
                    sample = item.sample
                    if (sample.sha256, sample.size_bytes) != (
                        entry.sha256,
                        entry.size_bytes,
                    ):
                        raise BackendError(
                            "INPUT_CHANGED",
                            "입력 검증 후 파일 내용이 달라졌습니다.",
                            stage="UPLOAD",
                        )
                    entry.analysis_id = sample.analysis_id
                with self.repository.sample_transaction(
                    [item.sample.sha256 for item in prepared]
                ) as transaction:
                    batch = transaction.register_batch(
                        [asdict(item.sample) for item in prepared],
                        batch_id=f"batch_{uuid4().hex}",
                        input_report=report,
                        idempotency_key=idempotency_key,
                    )
                    self._publish_new(prepared, batch.analyses, published)
        except BaseException:
            for sample in published:
                self._discard_unreferenced(sample)
            raise
        return batch_results.accepted(batch)

    def get(self, analysis_id: str) -> AnalysisRecord:
        record = self.repository.get(analysis_id)
        if record is None:
            raise BackendError(
                "ANALYSIS_NOT_FOUND", "해당 분석을 찾을 수 없습니다.", http_status=404
            )
        return record

    def list_analyses(
        self,
        *,
        limit=20,
        offset=0,
        status=None,
        sha256=None,
        batch_id=None,
        verdict=None,
        sort="high_risk_first",
    ) -> AnalysisListResponse:
        rows, total = self.repository.list_analyses(
            limit, offset, status, sha256, batch_id=batch_id, verdict=verdict, sort=sort
        )
        return AnalysisListResponse(
            total_count=total,
            limit=limit,
            offset=offset,
            analyses=[views.analysis(row) for row in rows],
        )

    def list_batch_analyses(
        self, batch_id: str, **filters
    ) -> BatchAnalysisListResponse:
        result = self.list_analyses(batch_id=batch_id, **filters)
        return BatchAnalysisListResponse(batch_id=batch_id, **result.model_dump())

    def get_batch(self, batch_id: str, *, sort="high_risk_first") -> BatchResponse:
        batch = self.repository.batch_record(batch_id)
        if batch is None:
            raise BackendError(
                "BATCH_NOT_FOUND", "해당 일괄 분석을 찾을 수 없습니다.", http_status=404
            )
        return batch_results.response(batch, sort=sort)

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
        deleted, skipped, visited = [], [], set()
        deleted_samples = 0
        for record in rows:
            if record.file_location in visited:
                continue
            visited.add(record.file_location)
            with self.repository.sample_transaction([record.sha256]) as transaction:
                references = transaction.location_records(record.file_location)
                if not references:
                    continue
                if not all(
                    self._can_expire(reference, before) for reference in references
                ):
                    skipped.extend(
                        row.analysis_id
                        for row in rows
                        if row.file_location == record.file_location
                    )
                    continue
                if delete:
                    # Only sample.bin is deleted; per-run reports remain available.
                    self.storage.delete(stored_sample(record))
                    deleted.extend(
                        transaction.mark_sample_deleted(record.file_location)
                    )
                    deleted_samples += 1
        return {
            "candidate_ids": [row.analysis_id for row in rows],
            "deleted_ids": deleted,
            "skipped_ids": skipped,
            "retention_hours": self.config.retention_hours,
            "deleted_sample_count": deleted_samples,
        }

    def _can_expire(self, record, before):
        if (
            not record.terminal
            or record.completed_at is None
            or datetime.fromisoformat(record.completed_at) >= before
        ):
            return False
        if (
            self.config.storage_mode == "s3"
            and (record.initial_result or {}).get("route") == "DEEP_ANALYSIS"
        ):
            try:
                return self.cleanup_guard is not None and self.cleanup_guard(record)
            except Exception:  # noqa: BLE001 - uncertainty preserves shared originals
                return False
        return True
