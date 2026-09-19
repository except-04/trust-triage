"""Worker 배포 설정. 비밀값은 환경변수로만 받는다."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .models import s3_location
from .storage import validate_prefix
from .worker import WorkerLimits


@dataclass(frozen=True)
class WorkerConfig:
    region: str
    queue_url: str
    dlq_url: str
    database_url: str = field(repr=False)
    s3_bucket: str
    s3_prefix: str = "raw/"
    temp_root: str = "artifacts/worker/tmp"
    poll_seconds: int = 20
    analysis_timeout_seconds: float = 30
    download_timeout_seconds: float = 60
    max_file_bytes: int = 50 * 1024 * 1024
    max_receives: int = 3
    limits: WorkerLimits = field(default_factory=WorkerLimits)

    def __post_init__(self) -> None:
        if not self.region or not self.database_url.strip():
            raise ValueError("AWS_REGION and WORKER_DATABASE_URL are required")
        for name, value in (
            ("SQS_QUEUE_URL", self.queue_url),
            ("SQS_DLQ_URL", self.dlq_url),
        ):
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError(f"{name} must be an HTTPS SQS queue URL")
            if parsed.query or parsed.fragment or not parsed.path.strip("/"):
                raise ValueError(f"{name} must not contain a query or fragment")
        if self.queue_url == self.dlq_url:
            raise ValueError("SQS_QUEUE_URL and SQS_DLQ_URL must differ")
        s3_location(f"s3://{self.s3_bucket}/check")
        validate_prefix(self.s3_prefix)
        if not 0 <= self.poll_seconds <= 20 or not 1 <= self.max_receives <= 1000:
            raise ValueError("invalid polling interval or maximum receive count")
        if self.max_file_bytes <= 0:
            raise ValueError("WORKER_MAX_FILE_BYTES must be positive")
        if not 0 < self.analysis_timeout_seconds < self.limits.job_timeout_seconds:
            raise ValueError(
                "analysis timeout must be positive and shorter than the job timeout"
            )
        if not 0 < self.download_timeout_seconds < self.limits.job_timeout_seconds:
            raise ValueError(
                "download timeout must be positive and shorter than the job timeout"
            )
        if (
            self.download_timeout_seconds + self.analysis_timeout_seconds
            >= self.limits.job_timeout_seconds
        ):
            raise ValueError(
                "job timeout must exceed download and analysis timeouts combined"
            )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WorkerConfig:
        values = os.environ if env is None else env

        def required(name: str) -> str:
            value = values.get(name, "").strip()
            if not value:
                raise ValueError(f"{name} is required; see .env.worker.example")
            return value

        return cls(
            region=required("AWS_REGION"),
            queue_url=required("SQS_QUEUE_URL"),
            dlq_url=required("SQS_DLQ_URL"),
            database_url=required("WORKER_DATABASE_URL"),
            s3_bucket=required("WORKER_S3_BUCKET"),
            s3_prefix=values.get("WORKER_S3_PREFIX", "raw/"),
            temp_root=values.get("WORKER_TEMP_DIR", "artifacts/worker/tmp"),
            poll_seconds=int(values.get("WORKER_POLL_SECONDS", "20")),
            analysis_timeout_seconds=float(
                values.get("WORKER_ANALYSIS_TIMEOUT_SECONDS", "30")
            ),
            download_timeout_seconds=float(
                values.get("WORKER_DOWNLOAD_TIMEOUT_SECONDS", "60")
            ),
            max_file_bytes=int(
                values.get("WORKER_MAX_FILE_BYTES", str(50 * 1024 * 1024))
            ),
            max_receives=int(values.get("WORKER_MAX_RECEIVES", "3")),
            limits=WorkerLimits(
                visibility_seconds=int(values.get("WORKER_VISIBILITY_SECONDS", "180")),
                heartbeat_seconds=float(values.get("WORKER_HEARTBEAT_SECONDS", "30")),
                job_timeout_seconds=float(
                    values.get("WORKER_JOB_TIMEOUT_SECONDS", "120")
                ),
                retry_delay_seconds=int(values.get("WORKER_RETRY_DELAY_SECONDS", "30")),
            ),
        )
