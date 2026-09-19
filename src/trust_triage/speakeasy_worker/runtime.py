"""실제 AWS/PostgreSQL 어댑터와 기존 SpeakeasyAnalyzer를 조립한다."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.config import Config

from trust_triage.dynamic_analysis import SpeakeasyAnalyzer
from trust_triage.storage import S3ArtifactStorage

from .config import WorkerConfig
from .publisher import JobPublisher
from .queue import SqsQueue
from .reports import ReportWriter
from .repository import PostgresJobRepository
from .storage import S3SampleStore
from .worker import SpeakeasyWorker


def _sqs_client(config: WorkerConfig):
    return boto3.client(
        "sqs",
        region_name=config.region,
        config=Config(
            connect_timeout=3,
            read_timeout=max(config.poll_seconds + 5, 10),
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    )


def create_publisher(config: WorkerConfig) -> JobPublisher:
    """Backend에서 사용할 전송기. Speakeasy 실행은 하지 않는다."""

    return JobPublisher(
        PostgresJobRepository(config.database_url),
        SqsQueue(_sqs_client(config), config.queue_url),
    )


@dataclass
class WorkerRuntime:
    worker: SpeakeasyWorker
    publisher: JobPublisher
    repository: PostgresJobRepository
    queue: SqsQueue
    dlq: SqsQueue

    def check(self, max_receives: int) -> None:
        self.repository.check()
        self.queue.check_dead_letter_queue(self.dlq, max_receive_count=max_receives)


def create_runtime(config: WorkerConfig) -> WorkerRuntime:
    repository = PostgresJobRepository(config.database_url)
    client = _sqs_client(config)
    queue = SqsQueue(
        client,
        config.queue_url,
        wait_seconds=config.poll_seconds,
        visibility_seconds=config.limits.visibility_seconds,
    )
    dlq = SqsQueue(
        client,
        config.dlq_url,
        wait_seconds=0,
        visibility_seconds=config.limits.visibility_seconds,
    )
    s3 = boto3.client(
        "s3",
        region_name=config.region,
        config=Config(
            connect_timeout=3,
            read_timeout=10,
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    )
    analyzer = SpeakeasyAnalyzer(
        timeout_seconds=config.analysis_timeout_seconds,
        max_file_size_bytes=config.max_file_bytes,
        include_raw_report=False,
    )
    execution_config = {
        name: getattr(analyzer, name)
        for name in (
            "timeout_seconds",
            "max_instructions",
            "max_api_count",
            "max_file_size_bytes",
            "emulate_children",
            "include_raw_report",
        )
    }
    config_sha256 = hashlib.sha256(
        json.dumps(execution_config, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    worker = SpeakeasyWorker(
        queue=queue,
        repository=repository,
        samples=S3SampleStore(
            s3,
            bucket=config.s3_bucket,
            prefix=config.s3_prefix,
            temp_root=config.temp_root,
            max_file_bytes=config.max_file_bytes,
            download_timeout_seconds=config.download_timeout_seconds,
        ),
        analyzer=analyzer,
        limits=config.limits,
        reports=ReportWriter(
            S3ArtifactStorage(
                s3,
                bucket=config.s3_bucket,
                prefix=config.s3_prefix,
                temp_root=Path(config.temp_root),
                max_bytes=5 * 1024 * 1024,
            ),
            config_sha256=config_sha256,
        ),
    )
    return WorkerRuntime(
        worker, JobPublisher(repository, queue), repository, queue, dlq
    )
