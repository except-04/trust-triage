from __future__ import annotations

from types import SimpleNamespace

import pytest

from trust_triage.speakeasy_worker.models import SpeakeasyJob
from trust_triage.speakeasy_worker.queue import Delivery
from trust_triage.speakeasy_worker.worker import SpeakeasyWorker

from .fakes import (
    SAMPLE_SHA256,
    FakeAnalyzer,
    FakeSamples,
    MemoryQueue,
    MemoryRepository,
)


@pytest.fixture
def job():
    return SpeakeasyJob(
        analysis_id="analysis-001",
        sha256=SAMPLE_SHA256,
        file_location=f"s3://worker-test-bucket/raw/{SAMPLE_SHA256}/sample.bin",
        requested_at="2026-09-07T19:00:00+09:00",
    )


@pytest.fixture
def delivery(job):
    return Delivery(job.to_json(), "message-001", "receipt-001")


@pytest.fixture
def rig(tmp_path):
    repository, queue = MemoryRepository(), MemoryQueue()
    samples, analyzer = FakeSamples(tmp_path), FakeAnalyzer()
    worker = SpeakeasyWorker(
        queue=queue, repository=repository, samples=samples, analyzer=analyzer
    )
    return SimpleNamespace(
        repository=repository,
        queue=queue,
        samples=samples,
        analyzer=analyzer,
        worker=worker,
    )
