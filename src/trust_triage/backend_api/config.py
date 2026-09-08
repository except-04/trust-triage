"""환경 설정은 이곳에서만 읽는다. .env를 읽는 시점은 CLI가 결정한다."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


def _positive(name: str, default: float) -> float:
    value = float(os.getenv(name, str(default)))
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return value


def _integer(name: str, default: int) -> int:
    value = _positive(name, default)
    if not value.is_integer():
        raise ValueError(f"{name} must be an integer")
    return int(value)


@dataclass(frozen=True)
class BackendConfig:
    database_url: str = field(default="", repr=False)
    storage_mode: Literal["local", "s3"] = "local"
    storage_root: Path = Path("artifacts/backend/samples")
    temp_root: Path = Path("artifacts/backend/tmp")
    aws_region: str = "ap-northeast-2"
    s3_bucket: str = ""
    s3_prefix: str = "raw/"
    api_token: str = field(default="", repr=False)
    reviewer_token: str = field(default="", repr=False)
    host: str = "127.0.0.1"
    port: int = 8000
    max_file_bytes: int = 50 * 1024 * 1024
    max_batch_files: int = 10
    upload_timeout_seconds: float = 120
    download_timeout_seconds: float = 60
    lease_seconds: int = 900
    heartbeat_seconds: float = 30
    operation_timeout_seconds: float = 780
    poll_seconds: float = 3
    retry_delay_seconds: int = 30
    max_attempts: int = 3
    deep_wait_seconds: int = 86400
    retention_hours: int = 24

    def __post_init__(self) -> None:
        if self.storage_mode not in {"local", "s3"}:
            raise ValueError("BACKEND_STORAGE_MODE must be local or s3")
        if self.storage_mode == "s3" and not self.s3_bucket:
            raise ValueError("BACKEND_S3_BUCKET is required for S3 mode")
        if (
            not 1 <= self.max_file_bytes <= 512 * 1024 * 1024
            or not 1 <= self.max_batch_files <= 100
        ):
            raise ValueError("invalid upload limits")
        if not 1 <= self.port <= 65535 or not 1 <= self.retention_hours <= 720:
            raise ValueError("invalid server port or retention hours")
        if not 0 < self.heartbeat_seconds < self.lease_seconds / 2:
            raise ValueError("heartbeat must be shorter than half the job lease")
        if not 0 < self.operation_timeout_seconds < self.lease_seconds <= 43200:
            raise ValueError("operation timeout must be shorter than the job lease")
        if not 0.1 <= self.poll_seconds <= 60 or not 1 <= self.max_attempts <= 10:
            raise ValueError("invalid worker polling or retry count")
        if (
            not 1 <= self.retry_delay_seconds <= 300
            or not 1 <= self.deep_wait_seconds <= 14 * 86400
        ):
            raise ValueError("invalid retry delay or deep-analysis wait deadline")
        if (
            not 0 < self.upload_timeout_seconds <= 600
            or not 0 < self.download_timeout_seconds <= 600
        ):
            raise ValueError("invalid storage timeout")
        if self.host not in {"127.0.0.1", "localhost", "::1"} and not self.api_token:
            raise ValueError(
                "BACKEND_API_TOKEN is required when exposing the API beyond localhost"
            )
        if self.api_token and len(self.api_token) < 24:
            raise ValueError("BACKEND_API_TOKEN must contain at least 24 characters")
        if self.reviewer_token and len(self.reviewer_token) < 24:
            raise ValueError(
                "BACKEND_REVIEWER_TOKEN must contain at least 24 characters"
            )

    @classmethod
    def from_env(cls) -> BackendConfig:
        return cls(
            database_url=os.getenv("BACKEND_DATABASE_URL", ""),
            storage_mode=os.getenv("BACKEND_STORAGE_MODE", "local"),
            storage_root=Path(
                os.getenv("BACKEND_STORAGE_ROOT", "artifacts/backend/samples")
            ),
            temp_root=Path(os.getenv("BACKEND_TEMP_DIR", "artifacts/backend/tmp")),
            aws_region=os.getenv("AWS_REGION", "ap-northeast-2"),
            s3_bucket=os.getenv("BACKEND_S3_BUCKET", os.getenv("WORKER_S3_BUCKET", "")),
            s3_prefix=os.getenv("BACKEND_S3_PREFIX", "raw/"),
            api_token=os.getenv("BACKEND_API_TOKEN", ""),
            reviewer_token=os.getenv("BACKEND_REVIEWER_TOKEN", ""),
            host=os.getenv("BACKEND_HOST", "127.0.0.1"),
            port=_integer("BACKEND_PORT", 8000),
            max_file_bytes=_integer("BACKEND_MAX_FILE_BYTES", 50 * 1024 * 1024),
            max_batch_files=_integer("BACKEND_MAX_BATCH_FILES", 10),
            upload_timeout_seconds=_positive("BACKEND_UPLOAD_TIMEOUT_SECONDS", 120),
            download_timeout_seconds=_positive("BACKEND_DOWNLOAD_TIMEOUT_SECONDS", 60),
            lease_seconds=_integer("BACKEND_LEASE_SECONDS", 900),
            heartbeat_seconds=_positive("BACKEND_HEARTBEAT_SECONDS", 30),
            operation_timeout_seconds=_positive(
                "BACKEND_OPERATION_TIMEOUT_SECONDS", 780
            ),
            poll_seconds=_positive("BACKEND_POLL_SECONDS", 3),
            retry_delay_seconds=_integer("BACKEND_RETRY_DELAY_SECONDS", 30),
            max_attempts=_integer("BACKEND_MAX_ATTEMPTS", 3),
            deep_wait_seconds=_integer("BACKEND_DEEP_WAIT_SECONDS", 86400),
            retention_hours=_integer("BACKEND_RETENTION_HOURS", 24),
        )
