"""Deterministic, detached persistence for HTTP/processor tests without PostgreSQL."""

from __future__ import annotations

import json
import threading
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.repository import (
    AnalysisRecord,
    Claim,
    json_object,
    registration_input,
    validate_review,
)


def _copy(value):
    return json.loads(json.dumps(value, allow_nan=False))


class MemoryAnalysisRepository:
    def __init__(self):
        self.rows = {}
        self.batches = {}
        self.idempotency = {}
        self.leases = {}
        self.retries = {}
        self.reviews = {}
        self.calls = Counter()
        self.failures = Counter()
        self.now = datetime.now(timezone.utc)
        self._lock = threading.RLock()

    def _fault(self, operation):
        self.calls[operation] += 1
        if self.failures[operation] > 0:
            self.failures[operation] -= 1
            raise BackendError(
                "DATABASE_ERROR",
                "Synthetic temporary storage failure",
                http_status=503,
                retryable=True,
            )

    def _tick(self):
        self.now += timedelta(microseconds=1)
        return self.now.isoformat()

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)

    def initialize(self):
        self._fault("initialize")

    def check(self):
        self._fault("check")

    def register(self, analyses, *, batch_id=None, idempotency_key=None):
        self._fault("register")
        inputs, fingerprint, kind = registration_input(
            analyses, batch_id, idempotency_key
        )
        with self._lock:
            previous = (
                self.idempotency.get(idempotency_key)
                if idempotency_key is not None
                else None
            )
            if previous is not None:
                if previous[:2] != (fingerprint, kind):
                    raise BackendError(
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key was already used for a different request",
                        http_status=409,
                    )
                return [self.get(key) for key in previous[2]]
            locations = {row.file_location for row in self.rows.values()}
            if (batch_id is not None and batch_id in self.batches) or any(
                item["analysis_id"] in self.rows or item["file_location"] in locations
                for item in inputs
            ):
                raise BackendError(
                    "REGISTRATION_CONFLICT",
                    "Analysis registration conflicts with existing input",
                    http_status=409,
                )
            ids = []
            for item in inputs:
                duplicate = next(
                    (
                        row.analysis_id
                        for row in self.rows.values()
                        if row.sha256 == item["sha256"]
                    ),
                    None,
                )
                stamp = self._tick()
                record = AnalysisRecord(
                    **item,
                    batch_id=batch_id,
                    duplicate_of=duplicate,
                    created_at=stamp,
                    updated_at=stamp,
                )
                self.rows[record.analysis_id] = record
                ids.append(record.analysis_id)
            if batch_id is not None:
                self.batches[batch_id] = ids
            if idempotency_key is not None:
                self.idempotency[idempotency_key] = (fingerprint, kind, ids)
            return [self.get(key) for key in ids]

    def get(self, analysis_id):
        self._fault("get")
        with self._lock:
            row = self.rows.get(analysis_id)
            if row is None:
                return None
            lease = self.leases.get(analysis_id)
            return replace(
                row,
                claimed=bool(lease and lease[1] > self.now),
                initial_result=_copy(row.initial_result),
                deep_result=_copy(row.deep_result),
                final_assessment=_copy(row.final_assessment),
                error=_copy(row.error),
            )

    def list_analyses(self, limit=20, offset=0, status=None, sha256=None):
        self._fault("list_analyses")
        with self._lock:
            records = sorted(
                (
                    row
                    for row in self.rows.values()
                    if (status is None or row.status == status)
                    and (sha256 is None or row.sha256 == sha256)
                ),
                key=lambda row: (row.created_at, row.analysis_id),
                reverse=True,
            )
            return [
                self.get(row.analysis_id) for row in records[offset : offset + limit]
            ], len(records)

    def get_batch(self, batch_id):
        self._fault("get_batch")
        with self._lock:
            ids = self.batches.get(batch_id)
            return None if ids is None else [self.get(key) for key in ids]

    def _ready(self, row):
        lease = self.leases.get(row.analysis_id)
        retry = self.retries.get(row.analysis_id)
        return (
            not row.terminal
            and (not lease or lease[1] <= self.now)
            and (retry is None or retry <= self.now)
        )

    def pending_ids(self, limit=10):
        self._fault("pending_ids")
        with self._lock:
            return [
                row.analysis_id
                for row in sorted(
                    self.rows.values(),
                    key=lambda row: (row.updated_at, row.analysis_id),
                )
                if self._ready(row)
            ][:limit]

    def claim(self, analysis_id, lease_seconds):
        self._fault("claim")
        with self._lock:
            row = self.get(analysis_id)
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if not self._ready(row):
                return Claim(row)
            token = str(uuid4())
            self.leases[analysis_id] = (
                token,
                self.now + timedelta(seconds=lease_seconds),
            )
            self.rows[analysis_id] = replace(
                row,
                status="RUNNING",
                current_stage="INITIAL_ANALYSIS"
                if row.phase == "INITIAL"
                else row.current_stage,
                attempt_count=row.attempt_count + 1,
                updated_at=self._tick(),
            )
            return Claim(self.get(analysis_id), token)

    def _owns(self, analysis_id, token):
        row = self.rows.get(analysis_id)
        lease = self.leases.get(analysis_id)
        return bool(
            row
            and not row.terminal
            and lease
            and lease[0] == token
            and lease[1] > self.now
        )

    def renew(self, analysis_id, token, lease_seconds):
        self._fault("renew")
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            self.leases[analysis_id] = (
                token,
                self.now + timedelta(seconds=lease_seconds),
            )
            self.rows[analysis_id] = replace(
                self.rows[analysis_id], updated_at=self._tick()
            )
            return True

    def release(self, analysis_id, token, error=None, next_retry_at=None):
        self._fault("release")
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            retry = (
                datetime.fromisoformat(next_retry_at.replace("Z", "+00:00"))
                if isinstance(next_retry_at, str)
                else next_retry_at
            )
            if retry is not None and (
                not isinstance(retry, datetime) or retry.tzinfo is None
            ):
                raise ValueError("Timezone-aware next_retry_at required")
            payload = json_object(error) if error is not None else None
            self.rows[analysis_id] = replace(
                self.rows[analysis_id], error=payload, updated_at=self._tick()
            )
            self.leases.pop(analysis_id, None)
            self.retries[analysis_id] = retry
            return True

    @staticmethod
    def _identity(row, payload):
        if any(
            key in payload and payload[key] != getattr(row, key)
            for key in ("sha256", "analysis_id")
        ):
            raise BackendError(
                "INVALID_PERSISTED_STATE",
                "Analysis state failed persistence validation",
                http_status=422,
            )

    def save_initial(self, analysis_id, token, result, needs_deep):
        self._fault("save_initial")
        payload = json_object(result)
        with self._lock:
            if (
                not self._owns(analysis_id, token)
                or self.rows[analysis_id].phase != "INITIAL"
            ):
                return False
            row = self.rows[analysis_id]
            self._identity(row, payload)
            self.rows[analysis_id] = replace(
                row,
                initial_result=payload,
                phase="WAITING_DEEP" if needs_deep else "FINALIZING",
                current_stage="CAPA_FLOSS" if needs_deep else "FINAL_ASSESSMENT",
                error=None,
                updated_at=self._tick(),
            )
            self.retries.pop(analysis_id, None)
            return True

    def save_deep(self, analysis_id, token, snapshot, *, finished, current_stage):
        self._fault("save_deep")
        payload = json_object(snapshot)
        with self._lock:
            if (
                not self._owns(analysis_id, token)
                or self.rows[analysis_id].phase != "WAITING_DEEP"
            ):
                return False
            row = self.rows[analysis_id]
            self._identity(row, payload)
            self.rows[analysis_id] = replace(
                row,
                deep_result=payload,
                phase="FINALIZING" if finished else "WAITING_DEEP",
                current_stage="FINAL_ASSESSMENT" if finished else current_stage,
                error=None,
                updated_at=self._tick(),
            )
            self.retries.pop(analysis_id, None)
            return True

    def finish(self, analysis_id, token, final_assessment, *, error=None):
        self._fault("finish")
        payload = json_object(final_assessment)
        failure = json_object(error) if error is not None else None
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            row = self.rows[analysis_id]
            if failure is None and row.phase != "FINALIZING":
                return False
            self._identity(row, payload)
            stamp = self._tick()
            status = "FAILED" if failure is not None else "COMPLETED"
            self.rows[analysis_id] = replace(
                row,
                final_assessment=payload,
                error=failure,
                phase="DONE",
                status=status,
                current_stage="FINAL_ASSESSMENT",
                updated_at=stamp,
                completed_at=stamp,
            )
            self.leases.pop(analysis_id, None)
            self.retries.pop(analysis_id, None)
            return True

    def cleanup_candidates(self, before_datetime, limit=10):
        self._fault("cleanup_candidates")
        with self._lock:
            return [
                self.get(row.analysis_id)
                for row in sorted(
                    self.rows.values(),
                    key=lambda row: (row.completed_at or "", row.analysis_id),
                )
                if row.terminal
                and row.storage_deleted_at is None
                and datetime.fromisoformat(row.completed_at) < before_datetime
            ][:limit]

    def mark_storage_deleted(self, analysis_id):
        self._fault("mark_storage_deleted")
        with self._lock:
            row = self.rows.get(analysis_id)
            if row is None or not row.terminal or row.storage_deleted_at is not None:
                return False
            self.rows[analysis_id] = replace(row, storage_deleted_at=self._tick())
            return True

    def location_referenced(self, location):
        self._fault("location_referenced")
        return any(
            row.file_location == location and row.storage_deleted_at is None
            for row in self.rows.values()
        )

    def save_review(
        self,
        analysis_id,
        *,
        analyst_final_verdict,
        analyst_notes,
        reviewer_id,
        expected_revision,
    ):
        self._fault("save_review")
        validate_review(
            analyst_final_verdict, analyst_notes, reviewer_id, expected_revision
        )
        with self._lock:
            row = self.rows.get(analysis_id)
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if not row.terminal:
                raise BackendError(
                    "ANALYSIS_NOT_FINISHED",
                    "Analysis must finish before analyst review",
                    http_status=409,
                )
            if row.review_revision != expected_revision:
                raise BackendError(
                    "REVIEW_CONFLICT",
                    "A newer analyst review already exists",
                    http_status=409,
                )
            revision, stamp = expected_revision + 1, self._tick()
            review = {
                "review_id": str(uuid4()),
                "analysis_id": analysis_id,
                "revision": revision,
                "analyst_final_verdict": analyst_final_verdict,
                "analyst_notes": analyst_notes,
                "reviewer_id": reviewer_id,
                "review_status": "PENDING"
                if analyst_final_verdict is None
                else "COMPLETED",
                "reviewed_at": stamp,
            }
            self.reviews.setdefault(analysis_id, []).append(review)
            self.rows[analysis_id] = replace(
                row,
                review_revision=revision,
                analyst_final_verdict=analyst_final_verdict,
                updated_at=stamp,
            )
            return _copy(review)

    def list_reviews(self, analysis_id):
        self._fault("list_reviews")
        return _copy(self.reviews.get(analysis_id, []))


# Short alias for application test fixtures.
MemoryRepository = MemoryAnalysisRepository
