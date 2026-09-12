"""PE를 실행하지 않고 보관한다. DB에는 파일 내용 대신 이 저장소의 위치만 넣는다."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError

from trust_triage.storage.artifacts import LocalArtifactStorage, S3ArtifactStorage
from trust_triage.storage.layout import local_object_path, sample_key

from .errors import BackendError

LOGGER = logging.getLogger(__name__)
_CHUNK_BYTES = 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


@dataclass(frozen=True)
class StoredSample:
    analysis_id: str
    sha256: str
    size_bytes: int
    file_location: str
    filename: str


@dataclass(frozen=True)
class PreparedSample:
    sample: StoredSample
    path: Path


class SampleStorage(Protocol):
    def artifact_store(self, *, max_bytes: int): ...
    def prepare(self, stream: BinaryIO, *, analysis_id: str, filename: str): ...
    def publish(self, prepared: PreparedSample) -> StoredSample: ...
    def ingest(
        self, stream: BinaryIO, *, analysis_id: str, filename: str
    ) -> StoredSample: ...
    def materialize(
        self, sample: StoredSample, check: Callable[[], None] | None = None
    ): ...
    def delete(self, sample: StoredSample) -> None: ...
    def check(self) -> None: ...


def _safe_id(value: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise BackendError(
            "INVALID_ANALYSIS_ID",
            "분석 번호 형식이 올바르지 않습니다.",
            http_status=422,
        )
    return value


def _filename(value: str) -> str:
    name = str(value).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(
        char for char in name if ord(char) >= 32 and ord(char) != 127
    ).strip()
    suffix = Path(name).suffix.lower()
    if suffix not in {".exe", ".dll"}:
        raise BackendError(
            "UNSUPPORTED_FILE_TYPE",
            ".exe 또는 .dll 파일을 올려주세요.",
            http_status=422,
            stage="UPLOAD",
        )
    return name[: -len(suffix)][:240] + suffix


def _validate_pe(stream: BinaryIO, size: int) -> None:
    """최소 PE 헤더 구조를 검사한다. 실제 Feature 파싱은 분석 모듈이 담당한다."""
    stream.seek(0)
    dos = stream.read(64)
    if len(dos) != 64 or dos[:2] != b"MZ":
        raise BackendError(
            "INVALID_PE",
            "PE 파일 헤더를 확인할 수 없습니다.",
            http_status=422,
            stage="UPLOAD",
        )
    offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if offset < 64 or offset + 26 > size:
        raise BackendError(
            "INVALID_PE",
            "PE 헤더 위치가 파일 범위를 벗어납니다.",
            http_status=422,
            stage="UPLOAD",
        )
    stream.seek(offset)
    header = stream.read(26)
    machine, sections = struct.unpack_from("<HH", header, 4)
    optional_size = struct.unpack_from("<H", header, 20)[0]
    magic = struct.unpack_from("<H", header, 24)[0]
    if header[:4] != b"PE\0\0" or not 1 <= sections <= 96:
        raise BackendError(
            "INVALID_PE",
            "PE 서명 또는 Section 정보가 올바르지 않습니다.",
            http_status=422,
            stage="UPLOAD",
        )
    if (machine, magic) not in {(0x14C, 0x10B), (0x8664, 0x20B)}:
        raise BackendError(
            "UNSUPPORTED_PE_ARCH",
            "현재는 x86/x64 Windows PE 파일을 지원합니다.",
            http_status=422,
            stage="UPLOAD",
        )
    minimum = 96 if magic == 0x10B else 112
    if optional_size < minimum or offset + 24 + optional_size + sections * 40 > size:
        raise BackendError(
            "INVALID_PE",
            "PE Optional Header 또는 Section Table이 잘려 있습니다.",
            http_status=422,
            stage="UPLOAD",
        )
    stream.seek(0)


def _copy(
    stream: BinaryIO, destination: BinaryIO, limit: int, check=None, *, stage="UPLOAD"
) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    while True:
        if check is not None:
            check()
        chunk = stream.read(_CHUNK_BYTES)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise BackendError(
                "INVALID_UPLOAD",
                "파일 데이터는 바이너리여야 합니다.",
                http_status=422,
                stage=stage,
            )
        size += len(chunk)
        if size > limit:
            raise BackendError(
                "FILE_TOO_LARGE",
                "파일이 설정된 최대 크기를 초과했습니다.",
                http_status=413,
                stage=stage,
            )
        digest.update(chunk)
        destination.write(chunk)
    if not size:
        raise BackendError(
            "EMPTY_FILE", "빈 파일은 분석할 수 없습니다.", http_status=422, stage=stage
        )
    return digest.hexdigest(), size


def _verify(path: Path, sample: StoredSample, limit: int, check=None) -> None:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_BYTES):
            if check is not None:
                check()
            size += len(chunk)
            if size > limit:
                raise BackendError(
                    "FILE_TOO_LARGE",
                    "저장된 파일이 최대 크기를 초과했습니다.",
                    stage="STORAGE",
                )
            digest.update(chunk)
    if size != sample.size_bytes or digest.hexdigest() != sample.sha256:
        raise BackendError(
            "FILE_INTEGRITY_ERROR",
            "저장된 파일의 크기 또는 SHA-256이 원래 요청과 다릅니다.",
            stage="STORAGE",
        )


@contextmanager
def _prepare(stream, *, analysis_id, filename, root, limit, location):
    analysis_id, filename = _safe_id(analysis_id), _filename(filename)
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".upload-", dir=root) as directory:
        path = Path(directory) / "sample.bin"
        with path.open("x+b") as temporary:
            sha256, size = _copy(stream, temporary, limit)
            temporary.flush()
            _validate_pe(temporary, size)
            os.fsync(temporary.fileno())
        yield PreparedSample(
            StoredSample(analysis_id, sha256, size, location(sha256), filename), path
        )


class LocalSampleStorage:
    """개발용 저장소. 저장 위치는 외부 API에 노출하지 않는 local:// 참조다."""

    def __init__(self, root: Path, *, max_file_bytes: int = 50 * 1024 * 1024) -> None:
        self.root = Path(root).resolve()
        self.max_file_bytes = max_file_bytes
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")

    def check(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=self.root):
            pass

    def artifact_store(self, *, max_bytes: int):
        return LocalArtifactStorage(self.root, max_bytes=max_bytes)

    def _path(self, sample: StoredSample) -> Path:
        analysis_id = _safe_id(sample.analysis_id)
        try:
            key = sample_key(sample.sha256)
            if sample.file_location == f"local://samples/{key}":
                return local_object_path(self.root, key)
            # Existing requests retain their original immutable location.
            if sample.file_location == f"local://{analysis_id}/sample.bin":
                return local_object_path(self.root, f"{analysis_id}/sample.bin")
        except ValueError as exc:
            raise BackendError(
                "UNSAFE_STORAGE_PATH",
                "파일 저장 경로를 확인할 수 없습니다.",
                stage="STORAGE",
            ) from exc
        raise BackendError(
            "STORAGE_LOCATION_MISMATCH",
            "허용되지 않은 파일 저장 위치입니다.",
            stage="STORAGE",
        )

    def prepare(self, stream, *, analysis_id, filename):
        return _prepare(
            stream,
            analysis_id=analysis_id,
            filename=filename,
            root=self.root,
            limit=self.max_file_bytes,
            location=lambda sha256: f"local://samples/{sample_key(sha256)}",
        )

    def publish(self, prepared: PreparedSample) -> StoredSample:
        sample = prepared.sample
        target = self._path(sample)
        target.parent.mkdir(parents=True, exist_ok=True)
        target = self._path(sample)
        try:
            # Staging lives on the same volume. A hard link atomically publishes
            # the complete, fsynced file and never replaces an existing object.
            os.link(prepared.path, target)
        except FileExistsError:
            _verify(target, sample, self.max_file_bytes)
        return sample

    def ingest(
        self, stream: BinaryIO, *, analysis_id: str, filename: str
    ) -> StoredSample:
        """Storage-only convenience; API intake uses prepare + DB lock + publish."""
        with self.prepare(
            stream, analysis_id=analysis_id, filename=filename
        ) as prepared:
            return self.publish(prepared)

    @contextmanager
    def materialize(self, sample: StoredSample, check=None) -> Iterator[Path]:
        target = self._path(sample)
        try:
            _verify(target, sample, self.max_file_bytes, check)
        except FileNotFoundError as exc:
            raise BackendError(
                "FILE_NOT_FOUND",
                "분석할 원본 파일이 저장소에 없습니다.",
                stage="STORAGE",
            ) from exc
        yield target

    def delete(self, sample: StoredSample) -> None:
        target = self._path(sample)
        target.unlink(missing_ok=True)
        if target.parent.exists():
            try:
                target.parent.rmdir()
            except OSError:
                # Analysis artifacts have a separate lifetime from the original.
                LOGGER.debug("sample_artifacts_retained sha256=%s", sample.sha256)


def _aws_error(exc: Exception, *, stage: str) -> BackendError:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        missing = code in {"NoSuchKey", "NoSuchBucket", "404"}
        permanent = code in {
            "AccessDenied",
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
        }
        return BackendError(
            "S3_OBJECT_MISSING"
            if missing
            else "S3_ACCESS_ERROR"
            if permanent
            else "S3_UNAVAILABLE",
            "S3 원본 파일이 없습니다."
            if missing
            else "S3 접근 설정 또는 연결을 확인해주세요.",
            http_status=503,
            stage=stage,
            retryable=not (missing or permanent),
        )
    return BackendError(
        "S3_UNAVAILABLE",
        "S3 연결을 확인해주세요.",
        http_status=503,
        stage=stage,
        retryable=True,
    )


class S3SampleStorage:
    """Main Server와 Worker가 공유하는 S3. 원본은 SHA-256으로 식별한다."""

    def __init__(
        self,
        client,
        *,
        bucket: str,
        prefix: str = "raw/",
        temp_root: Path,
        max_file_bytes: int = 50 * 1024 * 1024,
        download_timeout_seconds: float = 60,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise ValueError("S3 bucket name is invalid")
        if (
            not prefix.endswith("/")
            or prefix.startswith("/")
            or any(part in {"", ".", ".."} for part in prefix[:-1].split("/"))
            or re.search(r"[?#\\\x00-\x20\x7f]", prefix)
        ):
            raise ValueError("S3 prefix must be a relative prefix ending in /")
        if not 0 < download_timeout_seconds <= 600 or max_file_bytes < 1:
            raise ValueError("invalid storage limits")
        self.client, self.bucket, self.prefix = client, bucket, prefix
        self.temp_root = Path(temp_root).resolve()
        self.max_file_bytes, self.download_timeout_seconds = (
            max_file_bytes,
            download_timeout_seconds,
        )

    def check(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except (BotoCoreError, ClientError) as exc:
            raise _aws_error(exc, stage="STORAGE") from exc

    def artifact_store(self, *, max_bytes: int):
        return S3ArtifactStorage(
            self.client,
            bucket=self.bucket,
            prefix=self.prefix,
            temp_root=self.temp_root,
            max_bytes=max_bytes,
            download_timeout_seconds=self.download_timeout_seconds,
        )

    def _key(self, sample: StoredSample) -> str:
        analysis_id = _safe_id(sample.analysis_id)
        try:
            keys = {
                f"{self.prefix}{sample_key(sample.sha256)}",
                f"{self.prefix}{analysis_id}/sample.bin",
            }
        except ValueError as exc:
            raise BackendError(
                "STORAGE_LOCATION_MISMATCH",
                "원본 식별자가 올바르지 않습니다.",
                stage="STORAGE",
            ) from exc
        parsed = urlsplit(sample.file_location)
        if (
            parsed.scheme != "s3"
            or parsed.netloc != self.bucket
            or parsed.path not in {f"/{key}" for key in keys}
            or parsed.query
            or parsed.fragment
        ):
            raise BackendError(
                "STORAGE_LOCATION_MISMATCH",
                "허용되지 않은 S3 저장 위치입니다.",
                stage="STORAGE",
            )
        return parsed.path[1:]

    def prepare(self, stream, *, analysis_id, filename):
        return _prepare(
            stream,
            analysis_id=analysis_id,
            filename=filename,
            root=self.temp_root,
            limit=self.max_file_bytes,
            location=lambda sha256: (
                f"s3://{self.bucket}/{self.prefix}{sample_key(sha256)}"
            ),
        )

    def publish(self, prepared: PreparedSample) -> StoredSample:
        sample = prepared.sample
        try:
            with prepared.path.open("rb") as temporary:
                self.client.put_object(
                    Bucket=self.bucket,
                    Key=self._key(sample),
                    Body=temporary,
                    ContentLength=sample.size_bytes,
                    ContentType="application/octet-stream",
                    Metadata={"sha256": sample.sha256},
                    IfNoneMatch="*",
                )
        except (BotoCoreError, ClientError) as exc:
            if isinstance(exc, ClientError) and exc.response.get("Error", {}).get(
                "Code"
            ) in {"PreconditionFailed", "412"}:
                # Metadata/ETag alone are not proof that the existing bytes match.
                with self.materialize(sample):
                    pass
            else:
                raise _aws_error(exc, stage="UPLOAD") from exc
        return sample

    def ingest(
        self, stream: BinaryIO, *, analysis_id: str, filename: str
    ) -> StoredSample:
        with self.prepare(
            stream, analysis_id=analysis_id, filename=filename
        ) as prepared:
            return self.publish(prepared)

    @contextmanager
    def materialize(self, sample: StoredSample, check=None) -> Iterator[Path]:
        key, deadline = (
            self._key(sample),
            time.monotonic() + self.download_timeout_seconds,
        )
        self.temp_root.mkdir(parents=True, exist_ok=True)

        def guard():
            if check is not None:
                check()
            if time.monotonic() >= deadline:
                raise BackendError(
                    "DOWNLOAD_TIMEOUT",
                    "S3 다운로드 제한 시간을 초과했습니다.",
                    stage="STORAGE",
                    retryable=True,
                )

        try:
            with tempfile.TemporaryDirectory(
                prefix="download-", dir=self.temp_root
            ) as directory:
                target = Path(directory) / "sample.bin"
                guard()
                response = self.client.get_object(Bucket=self.bucket, Key=key)
                body = response["Body"]
                try:
                    length = response.get("ContentLength")
                    if (
                        length != sample.size_bytes
                        or not 0 < length <= self.max_file_bytes
                    ):
                        raise BackendError(
                            "FILE_INTEGRITY_ERROR",
                            "S3 파일 크기가 원래 요청과 다릅니다.",
                            stage="STORAGE",
                        )
                    with target.open("xb") as destination:
                        sha256, size = _copy(
                            body,
                            destination,
                            self.max_file_bytes,
                            guard,
                            stage="STORAGE",
                        )
                    guard()
                finally:
                    body.close()
                if size != sample.size_bytes or sha256 != sample.sha256:
                    raise BackendError(
                        "FILE_INTEGRITY_ERROR",
                        "S3 파일 SHA-256이 원래 요청과 다릅니다.",
                        stage="STORAGE",
                    )
                yield target
        except (BotoCoreError, ClientError) as exc:
            raise _aws_error(exc, stage="STORAGE") from exc

    def delete(self, sample: StoredSample) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=self._key(sample))
        except (BotoCoreError, ClientError) as exc:
            raise _aws_error(exc, stage="STORAGE") from exc
