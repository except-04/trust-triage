"""Bounded, immutable tool reports; usable without importing the HTTP backend.

An object is published before its reference is committed with the tool checkpoint.
The database remains authoritative for which execution's artifact was accepted.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError

from .layout import LAYOUT_VERSION, artifact_key, local_object_path, validate_sha256

DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class ArtifactError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code, self.message, self.retryable = code, message, retryable


@dataclass(frozen=True)
class ArtifactIdentity:
    sha256: str
    analysis_id: str
    tool: str
    tool_run_id: str
    name: str = "report.json"

    def __post_init__(self):
        if not isinstance(self.tool, str):
            raise TypeError("artifact tool must be a string identifier")
        object.__setattr__(self, "tool", self.tool.upper())
        artifact_key(
            self.sha256, self.analysis_id, self.tool, self.tool_run_id, self.name
        )

    @property
    def key(self) -> str:
        return artifact_key(**asdict(self))


@dataclass(frozen=True)
class ArtifactReference:
    sha256: str
    analysis_id: str
    tool: str
    tool_run_id: str
    name: str
    file_location: str
    content_sha256: str
    size_bytes: int
    created_at: str
    media_type: str = "application/json"
    tool_version: str | None = None
    config_sha256: str | None = None
    schema_version: str = LAYOUT_VERSION

    def __post_init__(self):
        identity = self.identity
        if self.schema_version != LAYOUT_VERSION or self.tool != identity.tool:
            raise ValueError("unsupported artifact schema or noncanonical tool name")
        validate_sha256(self.content_sha256)
        if self.config_sha256 is not None:
            validate_sha256(self.config_sha256)
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
        ):
            raise ValueError("artifact size must be a nonnegative integer")
        stamp = datetime.fromisoformat(self.created_at)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("artifact creation time must have a timezone")
        object.__setattr__(
            self, "created_at", stamp.astimezone(timezone.utc).isoformat()
        )
        if self.tool_version is not None and (
            not isinstance(self.tool_version, str)
            or not 1 <= len(self.tool_version) <= 256
            or "\x00" in self.tool_version
        ):
            raise ValueError("invalid artifact tool version")
        if self.media_type not in {
            "application/json",
            "text/plain",
            "application/octet-stream",
        }:
            raise ValueError("unsupported artifact media type")
        if not isinstance(self.file_location, str) or len(self.file_location) > 4096:
            raise ValueError("invalid artifact location")
        parsed = urlsplit(self.file_location)
        if (
            parsed.scheme not in {"local", "s3"}
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith("/" + identity.key)
            or any(ord(char) < 33 or ord(char) == 127 for char in self.file_location)
        ):
            raise ValueError("artifact location does not match its execution")

    @property
    def identity(self) -> ArtifactIdentity:
        return ArtifactIdentity(
            self.sha256, self.analysis_id, self.tool, self.tool_run_id, self.name
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _reference(identity, location, digest, size, **metadata):
    return ArtifactReference(
        **asdict(identity),
        file_location=location,
        content_sha256=digest,
        size_bytes=size,
        created_at=datetime.now(timezone.utc).isoformat(),
        **metadata,
    )


def _copy(stream, destination, limit, check=None):
    digest, size = hashlib.sha256(), 0
    while True:
        if check is not None:
            check()
        block = stream.read(1024 * 1024)
        if not block:
            break
        if not isinstance(block, bytes):
            raise ArtifactError("INVALID_ARTIFACT", "Artifact data must be binary")
        size += len(block)
        if size > limit:
            raise ArtifactError(
                "ARTIFACT_TOO_LARGE", "Artifact exceeds the configured size limit"
            )
        digest.update(block)
        destination.write(block)
    return digest.hexdigest(), size


def _json_bytes(value, limit):
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactError("INVALID_ARTIFACT", "Artifact is not valid JSON") from exc
    if len(encoded) > limit:
        raise ArtifactError(
            "ARTIFACT_TOO_LARGE", "Artifact exceeds the configured size limit"
        )
    return encoded


def _limits(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 512 * 1024 * 1024
    ):
        raise ValueError("artifact limit must be between 1 byte and 512 MiB")


def _integrity(reference, digest, size):
    if (digest, size) != (reference.content_sha256, reference.size_bytes):
        raise ArtifactError(
            "ARTIFACT_INTEGRITY_ERROR",
            "Artifact bytes do not match the recorded checksum and size",
        )


class LocalArtifactStorage:
    def __init__(self, root: Path, *, max_bytes=DEFAULT_MAX_ARTIFACT_BYTES):
        _limits(max_bytes)
        self.root, self.max_bytes = Path(root).resolve(), max_bytes

    def _path(self, identity):
        try:
            return local_object_path(self.root, identity.key)
        except ValueError as exc:
            raise ArtifactError(
                "UNSAFE_ARTIFACT_PATH", "Artifact path is redirected or invalid"
            ) from exc

    def put_json(
        self, identity: ArtifactIdentity, value, **metadata
    ) -> ArtifactReference:
        return self.put_stream(
            identity, io.BytesIO(_json_bytes(value, self.max_bytes)), **metadata
        )

    def put_stream(
        self, identity: ArtifactIdentity, stream, **metadata
    ) -> ArtifactReference:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix=".artifact-", dir=self.root
            ) as directory:
                temporary = Path(directory) / "body"
                with temporary.open("xb") as output:
                    digest, size = _copy(stream, output, self.max_bytes)
                    output.flush()
                    os.fsync(output.fileno())
                reference = _reference(
                    identity,
                    f"local://samples/{identity.key}",
                    digest,
                    size,
                    **metadata,
                )
                target = self._path(identity)
                target.parent.mkdir(parents=True, exist_ok=True)
                target = self._path(identity)
                try:
                    os.link(temporary, target)
                except FileExistsError:
                    self.read(reference)
                return reference
        except OSError as exc:
            raise ArtifactError(
                "ARTIFACT_STORAGE_ERROR",
                "Cannot persist the analysis artifact",
                retryable=True,
            ) from exc

    def read(self, reference: ArtifactReference) -> bytes:
        if reference.file_location != f"local://samples/{reference.identity.key}":
            raise ArtifactError(
                "ARTIFACT_LOCATION_DENIED", "Artifact is outside this storage"
            )
        output = io.BytesIO()
        try:
            with self._path(reference.identity).open("rb") as source:
                digest, size = _copy(source, output, self.max_bytes)
        except FileNotFoundError as exc:
            raise ArtifactError("ARTIFACT_NOT_FOUND", "Artifact is missing") from exc
        except OSError as exc:
            raise ArtifactError(
                "ARTIFACT_STORAGE_ERROR",
                "Cannot read the analysis artifact",
                retryable=True,
            ) from exc
        _integrity(reference, digest, size)
        return output.getvalue()


def _s3_error(exc):
    code = (
        str(exc.response.get("Error", {}).get("Code", ""))
        if isinstance(exc, ClientError)
        else ""
    )
    if code in {"NoSuchKey", "404"}:
        return ArtifactError("ARTIFACT_NOT_FOUND", "Artifact is missing")
    if code in {"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"}:
        return ArtifactError(
            "ARTIFACT_ACCESS_DENIED", "Artifact storage access was denied"
        )
    return ArtifactError(
        "ARTIFACT_STORAGE_ERROR",
        "Artifact storage is temporarily unavailable",
        retryable=True,
    )


class S3ArtifactStorage:
    def __init__(
        self,
        client,
        *,
        bucket: str,
        prefix: str,
        temp_root: Path,
        max_bytes=DEFAULT_MAX_ARTIFACT_BYTES,
        download_timeout_seconds=60,
    ):
        _limits(max_bytes)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise ValueError("invalid S3 artifact bucket")
        if (
            not prefix.endswith("/")
            or prefix.startswith("/")
            or any(part in {"", ".", ".."} for part in prefix[:-1].split("/"))
            or re.search(r"[?#\\\x00-\x20\x7f]", prefix)
        ):
            raise ValueError("invalid S3 artifact prefix")
        if not 0 < download_timeout_seconds <= 600:
            raise ValueError("invalid artifact download timeout")
        self.client, self.bucket, self.prefix = client, bucket, prefix
        self.temp_root, self.max_bytes = Path(temp_root).resolve(), max_bytes
        self.download_timeout_seconds = download_timeout_seconds

    def _location(self, identity):
        return f"s3://{self.bucket}/{self.prefix}{identity.key}"

    def put_json(
        self, identity: ArtifactIdentity, value, **metadata
    ) -> ArtifactReference:
        return self.put_stream(
            identity, io.BytesIO(_json_bytes(value, self.max_bytes)), **metadata
        )

    def put_stream(
        self, identity: ArtifactIdentity, stream, **metadata
    ) -> ArtifactReference:
        try:
            self.temp_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryFile(dir=self.temp_root) as temporary:
                digest, size = _copy(stream, temporary, self.max_bytes)
                reference = _reference(
                    identity, self._location(identity), digest, size, **metadata
                )
                temporary.seek(0)
                try:
                    self.client.put_object(
                        Bucket=self.bucket,
                        Key=self.prefix + identity.key,
                        Body=temporary,
                        ContentLength=size,
                        ContentType=reference.media_type,
                        IfNoneMatch="*",
                        Metadata={"sha256": identity.sha256, "content-sha256": digest},
                    )
                except ClientError as exc:
                    if str(exc.response.get("Error", {}).get("Code")) not in {
                        "PreconditionFailed",
                        "412",
                    }:
                        raise
                    self.read(reference)
                return reference
        except (BotoCoreError, ClientError) as exc:
            raise _s3_error(exc) from exc
        except OSError as exc:
            raise ArtifactError(
                "ARTIFACT_STORAGE_ERROR",
                "Cannot stage the analysis artifact",
                retryable=True,
            ) from exc

    def read(self, reference: ArtifactReference) -> bytes:
        if reference.file_location != self._location(reference.identity):
            raise ArtifactError(
                "ARTIFACT_LOCATION_DENIED", "Artifact is outside this storage"
            )
        deadline = time.monotonic() + self.download_timeout_seconds

        def guard():
            if time.monotonic() >= deadline:
                raise ArtifactError(
                    "ARTIFACT_DOWNLOAD_TIMEOUT",
                    "Artifact read timed out",
                    retryable=True,
                )

        try:
            guard()
            response = self.client.get_object(
                Bucket=self.bucket, Key=self.prefix + reference.identity.key
            )
            body = response["Body"]
            try:
                if (
                    response.get("ContentLength") != reference.size_bytes
                    or reference.size_bytes > self.max_bytes
                ):
                    raise ArtifactError(
                        "ARTIFACT_INTEGRITY_ERROR",
                        "Artifact size does not match its reference",
                    )
                output = io.BytesIO()
                digest, size = _copy(body, output, self.max_bytes, guard)
                guard()
            finally:
                body.close()
            _integrity(reference, digest, size)
            return output.getvalue()
        except (BotoCoreError, ClientError) as exc:
            raise _s3_error(exc) from exc
