"""Storage checks use inert header-only bytes and in-memory S3; nothing executes."""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import replace

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from trust_triage.backend_api import storage as module
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.storage import LocalSampleStorage, S3SampleStorage


def header_bytes(*, pe64=False):
    """Only DOS/COFF/optional-header markers, without executable code or sections."""
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HH", data, 68, 0x8664 if pe64 else 0x14C, 1)
    struct.pack_into("<H", data, 84, 112 if pe64 else 96)
    struct.pack_into("<H", data, 88, 0x20B if pe64 else 0x10B)
    return bytes(data)


def aws_error(code):
    return ClientError({"Error": {"Code": code, "Message": "private detail"}}, "Test")


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.failure = None
        self.body = None
        self.length_override = None

    def _call(self, operation, arguments):
        self.calls.append((operation, arguments))
        if self.failure is not None:
            raise self.failure

    def head_bucket(self, **kwargs):
        self._call("head", kwargs)

    def put_object(self, **kwargs):
        self._call(
            "put", {key: value for key, value in kwargs.items() if key != "Body"}
        )
        key = kwargs["Key"]
        if kwargs["IfNoneMatch"] == "*" and key in self.objects:
            raise aws_error("PreconditionFailed")
        self.objects[key] = kwargs["Body"].read()

    def get_object(self, **kwargs):
        self._call("get", kwargs)
        data = self.objects[kwargs["Key"]]
        self.body = io.BytesIO(data)
        return {
            "Body": self.body,
            "ContentLength": self.length_override
            if self.length_override is not None
            else len(data),
        }

    def delete_object(self, **kwargs):
        self._call("delete", kwargs)
        self.objects.pop(kwargs["Key"], None)


@pytest.fixture(params=["local", "s3"])
def storage(request, tmp_path):
    if request.param == "local":
        return LocalSampleStorage(tmp_path / "samples", max_file_bytes=1024)
    return S3SampleStorage(
        FakeS3(),
        bucket="backend-test-only",
        prefix="uploads/",
        temp_root=tmp_path / "tmp",
        max_file_bytes=1024,
    )


@pytest.mark.parametrize("pe64", [False, True])
def test_ingest_hash_materialize_and_delete(storage, pe64):
    data = header_bytes(pe64=pe64)
    storage.check()
    sample = storage.ingest(
        io.BytesIO(data), analysis_id="analysis-1", filename=r"C:\upload\sample.EXE"
    )
    assert sample.filename == "sample.exe"
    assert sample.sha256 == hashlib.sha256(data).hexdigest()
    assert sample.size_bytes == len(data)
    checks = []
    with storage.materialize(sample, lambda: checks.append(True)) as target:
        assert target.read_bytes() == data
    assert checks
    if isinstance(storage, S3SampleStorage):
        assert not target.exists()
        assert storage.client.body.closed
        put = next(kwargs for name, kwargs in storage.client.calls if name == "put")
        assert put["Metadata"] == {"sha256": sample.sha256}
        assert put["ContentLength"] == len(data)
    storage.delete(sample)
    storage.delete(sample)


@pytest.mark.parametrize(
    ("data", "filename", "code"),
    [
        (b"", "sample.exe", "EMPTY_FILE"),
        (b"text", "sample.exe", "INVALID_PE"),
        (header_bytes(), "sample.txt", "UNSUPPORTED_FILE_TYPE"),
        (header_bytes() + bytes(1024), "sample.exe", "FILE_TOO_LARGE"),
    ],
)
def test_failed_upload_does_not_leave_an_object(storage, data, filename, code):
    with pytest.raises(BackendError) as failure:
        storage.ingest(io.BytesIO(data), analysis_id="failed", filename=filename)
    assert failure.value.code == code
    if isinstance(storage, LocalSampleStorage):
        assert not (storage.root / "failed").exists()
    else:
        assert not storage.client.objects
        assert not any(name == "put" for name, _ in storage.client.calls)


@pytest.mark.parametrize(
    ("offset", "format", "value", "code"),
    [
        (0x3C, "<I", 9999, "INVALID_PE"),
        (68, "<H", 0xAA64, "UNSUPPORTED_PE_ARCH"),
        (70, "<H", 0, "INVALID_PE"),
        (84, "<H", 1, "INVALID_PE"),
        (88, "<H", 0, "UNSUPPORTED_PE_ARCH"),
    ],
)
def test_malformed_headers_fail_clearly(storage, offset, format, value, code):
    data = bytearray(header_bytes())
    struct.pack_into(format, data, offset, value)
    with pytest.raises(BackendError) as failure:
        storage.ingest(
            io.BytesIO(data), analysis_id="bad-header", filename="sample.dll"
        )
    assert failure.value.code == code


def test_same_id_cannot_replace_original(storage):
    original = storage.ingest(
        io.BytesIO(header_bytes()), analysis_id="same", filename="sample.exe"
    )
    with pytest.raises(BackendError) as failure:
        storage.ingest(
            io.BytesIO(header_bytes(pe64=True)),
            analysis_id="same",
            filename="sample.exe",
        )
    assert failure.value.code == "STORAGE_CONFLICT"
    with storage.materialize(original) as path:
        assert path.read_bytes() == header_bytes()


@pytest.mark.parametrize("analysis_id", ["../outside", "a/b", "a\\b", "", "\x00"])
def test_untrusted_id_rejected_before_storage_access(storage, analysis_id):
    with pytest.raises(BackendError, match="분석 번호"):
        storage.ingest(
            io.BytesIO(header_bytes()), analysis_id=analysis_id, filename="sample.exe"
        )


def test_conflicting_location_and_sha_are_rejected(storage):
    original = storage.ingest(
        io.BytesIO(header_bytes()), analysis_id="integrity", filename="sample.exe"
    )
    with (
        pytest.raises(BackendError) as failure,
        storage.materialize(
            replace(original, file_location=original.file_location + "?other")
        ),
    ):
        pytest.fail("invalid location reached the caller")
    assert failure.value.code == "STORAGE_LOCATION_MISMATCH"
    with (
        pytest.raises(BackendError) as failure,
        storage.materialize(replace(original, sha256="0" * 64)),
    ):
        pytest.fail("invalid digest reached the caller")
    assert failure.value.code == "FILE_INTEGRITY_ERROR"


def test_callback_failure_interrupts_materialization(storage):
    sample = storage.ingest(
        io.BytesIO(header_bytes()), analysis_id="cancel", filename="sample.exe"
    )

    def stop():
        raise BackendError("LEASE_LOST", "stopped")

    with pytest.raises(BackendError) as failure, storage.materialize(sample, stop):
        pytest.fail("cancelled storage reached the caller")
    assert failure.value.code == "LEASE_LOST"
    if isinstance(storage, S3SampleStorage):
        assert not list(storage.temp_root.iterdir())


@pytest.mark.parametrize(
    "prefix", ["", "/raw/", "raw/../", "raw//", "raw?x/", "raw#x/", "raw\\x/", "raw\n/"]
)
def test_ambiguous_s3_prefixes_fail_configuration(tmp_path, prefix):
    with pytest.raises(ValueError):
        S3SampleStorage(
            FakeS3(), bucket="backend-test-only", prefix=prefix, temp_root=tmp_path
        )


@pytest.mark.parametrize(
    ("error", "code", "retryable"),
    [
        (aws_error("NoSuchKey"), "S3_OBJECT_MISSING", False),
        (aws_error("AccessDenied"), "S3_ACCESS_ERROR", False),
        (aws_error("SlowDown"), "S3_UNAVAILABLE", True),
        (
            EndpointConnectionError(endpoint_url="https://test.invalid"),
            "S3_UNAVAILABLE",
            True,
        ),
    ],
)
def test_s3_errors_are_sanitized_and_classified(tmp_path, error, code, retryable):
    client = FakeS3()
    client.failure = error
    storage = S3SampleStorage(client, bucket="backend-test-only", temp_root=tmp_path)
    with pytest.raises(BackendError) as failure:
        storage.check()
    assert failure.value.code == code
    assert failure.value.retryable is retryable
    assert "private detail" not in str(failure.value)


@pytest.mark.parametrize("tamper", ["length", "bytes", "empty"])
def test_s3_corruption_closes_body_and_removes_temp_files(tmp_path, tamper):
    client = FakeS3()
    storage = S3SampleStorage(client, bucket="backend-test-only", temp_root=tmp_path)
    sample = storage.ingest(
        io.BytesIO(header_bytes()), analysis_id="corrupt", filename="sample.exe"
    )
    if tamper == "length":
        client.length_override = 999
    else:
        client.objects["raw/corrupt/sample.bin"] = (
            bytes(512) if tamper == "bytes" else b""
        )
        client.length_override = sample.size_bytes
    with pytest.raises(BackendError) as failure, storage.materialize(sample):
        pytest.fail("corrupt object reached the caller")
    assert failure.value.stage == "STORAGE"
    assert client.body.closed
    assert not list(tmp_path.iterdir())


def test_s3_download_deadline_prevents_processing(tmp_path, monkeypatch):
    client = FakeS3()
    storage = S3SampleStorage(
        client,
        bucket="backend-test-only",
        temp_root=tmp_path,
        download_timeout_seconds=1,
    )
    sample = storage.ingest(
        io.BytesIO(header_bytes()), analysis_id="timeout", filename="sample.exe"
    )
    times = iter([0, 0, 2])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    with pytest.raises(BackendError) as failure, storage.materialize(sample):
        pytest.fail("expired download reached the caller")
    assert failure.value.code == "DOWNLOAD_TIMEOUT"
    assert failure.value.retryable
    assert client.body.closed
    assert not list(tmp_path.iterdir())
