from __future__ import annotations

import hashlib
from collections import deque
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from trust_triage.dynamic_analysis import DynamicAnalysisResult, DynamicAnalysisStatus
from trust_triage.speakeasy_worker.errors import RetryableError
from trust_triage.speakeasy_worker.models import JobConflict, JobRecord, JobStatus
from trust_triage.speakeasy_worker.queue import Delivery
from trust_triage.speakeasy_worker.repository import Claim

SAMPLE = b"Harmless worker test data. This is not a PE file.\n"
SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()


class MemoryRepository:
    def __init__(self):
        self.rows = {}
        self.leases = {}
        self.now = 1000

    def register(self, job, *, dispatch_pending=False):
        if job.analysis_id not in self.rows:
            self.rows[job.analysis_id] = JobRecord(
                job, JobStatus.QUEUED, dispatch_pending=dispatch_pending
            )
        row = self.rows[job.analysis_id]
        if not row.job.same_input(job):
            raise JobConflict("different input")
        return row

    def get(self, analysis_id):
        return self.rows.get(analysis_id)

    def pending_jobs(self, limit=10):
        return [
            row.job
            for row in self.rows.values()
            if row.dispatch_pending and row.status == JobStatus.QUEUED
        ][:limit]

    def mark_dispatched(self, analysis_id):
        self.rows[analysis_id] = replace(self.rows[analysis_id], dispatch_pending=False)

    def claim(self, job, lease_seconds):
        row = self.register(job)
        lease = self.leases.get(job.analysis_id)
        if row.status.terminal or (lease and lease[1] > self.now):
            return Claim(row)
        token = str(uuid4())
        self.leases[job.analysis_id] = (token, self.now + lease_seconds)
        row = replace(
            row,
            status=JobStatus.RUNNING,
            attempts=row.attempts + 1,
            dispatch_pending=False,
        )
        self.rows[job.analysis_id] = row
        return Claim(row, token)

    def owns(self, analysis_id, token):
        lease = self.leases.get(analysis_id)
        return lease is not None and lease[0] == token and lease[1] > self.now

    def renew(self, analysis_id, token, lease_seconds):
        if not self.owns(analysis_id, token):
            return False
        self.leases[analysis_id] = (token, self.now + lease_seconds)
        return True

    def finish(self, analysis_id, token, result):
        if not self.owns(analysis_id, token):
            return False
        self.rows[analysis_id] = replace(
            self.rows[analysis_id],
            status=JobStatus(result["status"]),
            result=result,
            last_error=result.get("error"),
            dispatch_pending=False,
        )
        self.leases.pop(analysis_id)
        return True

    def retry(self, analysis_id, token, error):
        if not self.owns(analysis_id, token):
            return False
        self.rows[analysis_id] = replace(
            self.rows[analysis_id], status=JobStatus.QUEUED, last_error=error
        )
        self.leases.pop(analysis_id)
        return True

    def dead_letter(self, job, result):
        row = self.register(job)
        lease = self.leases.get(job.analysis_id)
        if row.status.terminal or (lease and lease[1] > self.now):
            return False
        self.rows[job.analysis_id] = replace(
            row,
            status=JobStatus.FAILED,
            result=result,
            last_error=result["error"],
            dispatch_pending=False,
        )
        self.leases.pop(job.analysis_id, None)
        return True


class MemoryQueue:
    def __init__(self):
        self.messages = deque()
        self.sent = []
        self.acknowledged = []
        self.deferred = []
        self.fail_send = False
        self.fail_ack = False

    def send(self, job):
        if self.fail_send:
            raise RetryableError("SQS_ERROR", "send failed")
        self.sent.append(job)
        self.messages.append(Delivery(job.to_json(), str(len(self.sent)), str(uuid4())))
        return str(len(self.sent))

    def receive(self):
        return self.messages.popleft() if self.messages else None

    def acknowledge(self, delivery):
        if self.fail_ack:
            raise RetryableError("SQS_ERROR", "delete failed")
        self.acknowledged.append(delivery)

    def defer(self, delivery, seconds):
        self.deferred.append((delivery, seconds))


class FakeSamples:
    def __init__(self, root: Path):
        self.root = root
        self.calls = 0
        self.error = None

    @contextmanager
    def materialize(self, job, check_active):
        self.calls += 1
        if self.error:
            raise self.error
        path = self.root / "harmless-sample.bin"
        path.write_bytes(SAMPLE)
        try:
            check_active()
            yield path
        finally:
            path.unlink()


class FakeAnalyzer:
    def __init__(self):
        self.calls = 0
        self.status = DynamicAnalysisStatus.SUCCESS
        self.callback = None

    def analyze(self, path):
        self.calls += 1
        if self.callback:
            self.callback()
        return DynamicAnalysisResult(
            evidence_id="test-evidence",
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            source="SPEAKEASY",
            category="DYNAMIC_ANALYSIS",
            status=self.status,
            summary="Synthetic result from a test double",
            tool_version="test",
            observed_apis=("CreateFileW",),
            api_call_counts={"CreateFileW": 1},
            events={
                "api_calls": ({"api_name": "CreateFileW"},),
                "process_events": ({"pid": 1},),
                "file_access": ({"path": "test.bin"},),
                "registry_access": ({"key": "test-key"},),
                "network_events": ({"host": "example.test"},),
            },
            started_at="2026-09-07T10:00:00+00:00",
            completed_at="2026-09-07T10:00:01+00:00",
        )
