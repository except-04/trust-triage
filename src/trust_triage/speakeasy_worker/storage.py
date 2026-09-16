"""허용된 S3 원본을 임시 폴더로 내려받고 SHA-256/크기/시간을 확인한다."""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

from trust_triage.storage.layout import sample_key

from .errors import PermanentError, RetryableError
from .models import SpeakeasyJob, s3_location


class SampleStore(Protocol):
    def materialize(
        self, job: SpeakeasyJob, check_active: Callable[[], None]
    ) -> AbstractContextManager[Path]: ...


def validate_prefix(prefix: str) -> None:
    if (
        not isinstance(prefix, str)
        or not prefix.endswith("/")
        or prefix.startswith("/")
        or any(part in {"", ".", ".."} for part in prefix[:-1].split("/"))
        or re.search(r"[?#\\\x00-\x20\x7f]", prefix)
    ):
        raise ValueError(
            "WORKER_S3_PREFIX must be a safe relative prefix ending in '/'"
        )


class S3SampleStore:
    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        prefix: str = "raw/",
        temp_root: str | Path = "artifacts/worker/tmp",
        max_file_bytes: int = 50 * 1024 * 1024,
        download_timeout_seconds: float = 60,
    ) -> None:
        s3_location(f"s3://{bucket}/check")
        validate_prefix(prefix)
        if (
            max_file_bytes <= 0
            or not math.isfinite(download_timeout_seconds)
            or download_timeout_seconds <= 0
        ):
            raise ValueError("download size and time limits must be positive")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.temp_root = Path(temp_root).resolve()
        self.max_file_bytes = max_file_bytes
        self.download_timeout_seconds = download_timeout_seconds

    def validate_location(self, job: SpeakeasyJob) -> tuple[str, str]:
        bucket, key = s3_location(job.file_location)
        allowed_keys = {
            self.prefix + sample_key(job.sha256),
            # 이미 접수된 이전 Backend 작업은 원본을 이동하지 않고 읽는다.
            self.prefix + f"{job.analysis_id}/sample.bin",
        }
        if bucket != self.bucket or key not in allowed_keys:
            raise PermanentError(
                "S3_LOCATION_DENIED", "Sample is outside the configured S3 location"
            )
        return bucket, key

    @contextmanager
    def materialize(
        self, job: SpeakeasyJob, check_active: Callable[[], None]
    ) -> Iterator[Path]:
        bucket, key = self.validate_location(job)
        check_active()
        self.temp_root.mkdir(parents=True, exist_ok=True)
        # 파일명/디렉터리에 메시지의 경로를 사용하지 않는다.
        with TemporaryDirectory(prefix="speakeasy-", dir=self.temp_root) as directory:
            sample = Path(directory) / "sample.bin"
            try:
                self._download(bucket, key, sample, job.sha256, check_active)
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                http_status = exc.response.get("ResponseMetadata", {}).get(
                    "HTTPStatusCode", 0
                )
                if (
                    http_status >= 500
                    or http_status == 429
                    or code in {"SlowDown", "RequestTimeout"}
                ):
                    raise RetryableError(
                        "S3_UNAVAILABLE", "S3 is temporarily unavailable"
                    ) from exc
                if code in {"NoSuchKey", "NoSuchBucket", "404"}:
                    raise PermanentError(
                        "SAMPLE_NOT_FOUND", "S3 sample no longer exists"
                    ) from exc
                if code in {"AccessDenied", "403"}:
                    raise PermanentError(
                        "S3_ACCESS_DENIED", "Worker cannot read the S3 sample"
                    ) from exc
                raise PermanentError(
                    "S3_REQUEST_FAILED", "S3 rejected the sample request"
                ) from exc
            except BotoCoreError as exc:
                raise RetryableError(
                    "S3_CONNECTION_ERROR", "S3 download failed"
                ) from exc
            except OSError as exc:
                raise RetryableError(
                    "LOCAL_STORAGE_ERROR", "Cannot write the temporary sample"
                ) from exc
            # 이 yield 바깥의 Speakeasy/DB 오류는 S3 오류로 분류하지 않는다.
            yield sample

    def _download(
        self,
        bucket: str,
        key: str,
        destination: Path,
        expected_sha256: str,
        check_active: Callable[[], None],
    ) -> None:
        deadline = time.monotonic() + self.download_timeout_seconds
        response = self.client.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        try:
            declared_size = response.get("ContentLength")
            if not isinstance(declared_size, int) or declared_size < 0:
                raise RetryableError(
                    "S3_INVALID_RESPONSE", "S3 did not provide a valid content length"
                )
            if declared_size > self.max_file_bytes:
                raise PermanentError(
                    "FILE_TOO_LARGE", "Sample exceeds the configured size limit"
                )
            digest = hashlib.sha256()
            total = 0
            with destination.open("xb") as stream:
                while True:
                    check_active()
                    if time.monotonic() >= deadline:
                        raise RetryableError(
                            "DOWNLOAD_TIMEOUT",
                            "Sample download exceeded its time limit",
                        )
                    chunk = body.read(64 * 1024)
                    check_active()
                    if time.monotonic() >= deadline:
                        raise RetryableError(
                            "DOWNLOAD_TIMEOUT",
                            "Sample download exceeded its time limit",
                        )
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_file_bytes:
                        raise PermanentError(
                            "FILE_TOO_LARGE", "Downloaded sample exceeds its size limit"
                        )
                    stream.write(chunk)
                    digest.update(chunk)
            if total != declared_size:
                raise RetryableError(
                    "INCOMPLETE_DOWNLOAD",
                    "Downloaded size differs from the S3 object size",
                )
            if digest.hexdigest() != expected_sha256:
                raise PermanentError(
                    "HASH_MISMATCH",
                    "Downloaded sample SHA-256 differs from the request",
                )
            check_active()
        finally:
            body.close()
