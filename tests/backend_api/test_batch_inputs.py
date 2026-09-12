"""ZIP admission with header-only, non-executable input; no malware/tools/network."""

import hashlib
import io
import stat
import struct
import warnings
import zipfile
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from trust_triage.backend_api import batch_inputs
from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.service import BackendService
from trust_triage.backend_api.storage import LocalSampleStorage

from .fake_repository import MemoryAnalysisRepository
from .test_service_processor import harmless_pe_header


def archive_bytes(entries, *, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name")
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name, data in entries:
                info = (
                    name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name)
                )
                info.compress_type = compression
                archive.writestr(info, data)
    return stream.getvalue()


@pytest.fixture
def setup(tmp_path):
    config = BackendConfig(
        storage_root=tmp_path / "samples",
        temp_root=tmp_path / "temp",
        max_file_bytes=512,
    )
    service = BackendService(
        MemoryAnalysisRepository(),
        LocalSampleStorage(config.storage_root, max_file_bytes=512),
        config,
    )
    return SimpleNamespace(
        config=config, service=service, repository=service.repository
    )


def zip_submit(setup, data, *, key=None):
    return setup.service.submit_zip(
        [(io.BytesIO(data), "inputs.zip")], idempotency_key=key
    )


def assert_clean(setup):
    assert not list(setup.config.temp_root.glob("batch-*"))
    assert not list(setup.config.storage_root.glob("*/sample.bin"))
    assert setup.repository.rows == setup.repository.batches == {}


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_zip_mixed_admission_duplicate_names_and_deterministic_replay(
    setup, compression
):
    header = harmless_pe_header()
    data = archive_bytes(
        [
            ("folder/", b""),
            ("folder/same.exe", header),
            ("folder/same.exe", harmless_pe_header(1)),
            ("upper.DLL", header),
            ("readme.txt", b"documentation"),
            ("nested.zip", b"not decompressed"),
            ("invalid.exe", b"not a PE"),
        ],
        compression=compression,
    )
    first = zip_submit(setup, data, key="zip-repeat")
    assert first.input_count == first.archive_file_count == 6
    assert first.accepted_count == first.total_count == first.skipped_count == 3
    assert [entry.input_index for entry in first.entries] == [1, 2, 3, 4, 5, 6]
    assert [entry.reason_code for entry in first.entries[3:]] == [
        "UNSUPPORTED_FILE_TYPE",
        "NESTED_ZIP_UNSUPPORTED",
        "INVALID_PE",
    ]
    assert first.entries[0].filename == first.entries[1].filename == "folder/same.exe"
    assert first.entries[0].analysis_id != first.entries[1].analysis_id
    assert first.entries[0].sha256 == hashlib.sha256(header).hexdigest()
    assert first.analyses[2].duplicate_of == first.analyses[0].analysis_id
    assert setup.repository.get(first.analyses[0].analysis_id).filename == "same.exe"
    assert zip_submit(setup, data, key="zip-repeat") == first
    restored = setup.service.get_batch(first.batch_id)
    assert restored.entries == first.entries
    assert restored.summary.queued == restored.summary.total == 3
    assert len(list(setup.config.storage_root.glob("*/sample.bin"))) == 2
    assert not list(setup.config.temp_root.glob("batch-*"))
    assert not list(setup.config.storage_root.rglob("*.zip"))
    assert setup.repository.calls["claim"] == 0


@pytest.mark.parametrize("archive", [False, True])
def test_all_skipped_batch_is_persisted_empty_and_replayable(setup, archive):
    def submit(text=b"readme"):
        if archive:
            return zip_submit(
                setup, archive_bytes([("notes.txt", text)]), key="all-skipped"
            )
        return setup.service.submit(
            [(io.BytesIO(text), "notes.txt")], batch=True, idempotency_key="all-skipped"
        )

    first = submit()
    assert first == submit()
    assert first.input_count == first.skipped_count == 1
    assert first.accepted_count == first.total_count == 0 and first.analyses == []
    batch = setup.service.get_batch(first.batch_id)
    assert (
        batch.status == "COMPLETED"
        and batch.finished_count == batch.summary.failed == 0
    )
    assert batch.entries == first.entries and batch.analyses == []
    assert setup.service.list_batch_analyses(first.batch_id).total_count == 0
    with pytest.raises(BackendError, match="Idempotency") as error:
        submit(b"changed")
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    assert len(setup.repository.batches) == 1 and setup.repository.rows == {}
    assert not list(setup.config.storage_root.glob("*/sample.bin"))


@pytest.mark.parametrize(
    "name",
    [
        "../escape.exe",
        "/absolute.exe",
        "C:/absolute.exe",
        "C:stream.exe",
        "folder/../escape.exe",
        "folder//file.exe",
        "./file.exe",
        "folder\\file.exe",
        "//host/file.exe",
        "line\nname.exe",
        "x" * 513,
    ],
)
def test_unsafe_paths_reject_entire_zip_before_storage(setup, name):
    data = archive_bytes(
        [("valid.exe", harmless_pe_header()), (name, harmless_pe_header())]
    )
    # Windows ZipInfo normalizes backslashes when writing. Restore the raw name
    # to exercise an incoming archive produced by an unchecked writer.
    if "\\" in name:
        data = data.replace(name.replace("\\", "/").encode(), name.encode())
    with pytest.raises(BackendError) as error:
        zip_submit(setup, data)
    assert error.value.code == "UNSAFE_ZIP_ENTRY"
    assert_clean(setup)


def test_embedded_nul_is_detected_using_original_zip_name(setup):
    data = archive_bytes([("abc.exe", harmless_pe_header())]).replace(
        b"abc.exe", b"a\x00c.exe"
    )
    with pytest.raises(BackendError) as error:
        zip_submit(setup, data)
    assert error.value.code == "UNSAFE_ZIP_ENTRY"
    assert_clean(setup)


@pytest.mark.parametrize(
    "mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFDIR]
)
def test_links_and_special_files_reject_the_whole_zip(setup, mode):
    info = zipfile.ZipInfo("special.exe")
    info.create_system = 3
    info.external_attr = (mode | 0o600) << 16
    with pytest.raises(BackendError) as error:
        zip_submit(
            setup,
            archive_bytes([("valid.exe", harmless_pe_header()), (info, b"target")]),
        )
    assert error.value.code == "UNSAFE_ZIP_ENTRY"
    assert_clean(setup)


@pytest.mark.parametrize(
    "config_changes,entries,compression,code",
    [
        (
            {"max_zip_bytes": 100},
            [("one.exe", harmless_pe_header())],
            zipfile.ZIP_STORED,
            "ZIP_TOO_LARGE",
        ),
        (
            {"max_zip_entries": 1},
            [("folder/", b""), ("one.exe", harmless_pe_header())],
            zipfile.ZIP_STORED,
            "ZIP_ENTRY_LIMIT",
        ),
        (
            {"max_zip_expanded_bytes": 50},
            [("ignored.txt", b"x" * 51)],
            zipfile.ZIP_STORED,
            "ZIP_EXPANDED_LIMIT",
        ),
        (
            {"max_zip_ratio": 2},
            [("ignored.txt", b"x" * 1000)],
            zipfile.ZIP_DEFLATED,
            "ZIP_RATIO_LIMIT",
        ),
        (
            {"max_batch_files": 1},
            [("one.exe", harmless_pe_header()), ("two.exe", harmless_pe_header())],
            zipfile.ZIP_STORED,
            "INVALID_FILE_COUNT",
        ),
    ],
)
def test_limits_include_skipped_entries_and_leave_no_permanent_state(
    setup, config_changes, entries, compression, code
):
    setup.service.config = replace(setup.config, **config_changes)
    with pytest.raises(BackendError) as error:
        zip_submit(setup, archive_bytes(entries, compression=compression))
    assert error.value.code == code
    assert_clean(setup)


def test_large_pe_is_skipped_while_other_files_are_registered(setup):
    result = zip_submit(
        setup,
        archive_bytes(
            [
                ("large.exe", harmless_pe_header() + b"x" * 512),
                ("valid.exe", harmless_pe_header()),
            ]
        ),
    )
    assert result.entries[0].reason_code == "FILE_TOO_LARGE"
    assert result.entries[1].status == "ACCEPTED"
    assert result.accepted_count == result.skipped_count == 1


def test_zip_replay_preserves_original_receipt_after_admission_limit_change(setup):
    data = archive_bytes([("valid.exe", harmless_pe_header())])
    original = zip_submit(setup, data, key="config-change")
    setup.service.config = replace(setup.config, max_file_bytes=100)
    assert zip_submit(setup, data, key="config-change") == original
    assert len(setup.repository.rows) == 1
    assert len(list(setup.config.storage_root.glob("*/sample.bin"))) == 1


def test_unsupported_architecture_is_skipped(setup):
    data = bytearray(harmless_pe_header())
    struct.pack_into("<H", data, 68, 0xAA64)
    result = zip_submit(setup, archive_bytes([("arm.exe", data)]))
    assert result.entries[0].reason_code == "UNSUPPORTED_PE_ARCH"


@pytest.mark.parametrize("kind", ["encrypted", "strong_encrypted", "bzip2", "lzma"])
def test_unsupported_members_are_reported_without_decompression(
    setup, monkeypatch, kind
):
    compression = {"bzip2": zipfile.ZIP_BZIP2, "lzma": zipfile.ZIP_LZMA}.get(
        kind, zipfile.ZIP_STORED
    )
    data = bytearray(
        archive_bytes([("one.exe", harmless_pe_header())], compression=compression)
    )
    if "encrypted" in kind:
        central = data.index(b"PK\x01\x02")
        bits = 0x41 if kind == "strong_encrypted" else 1
        struct.pack_into("<H", data, 6, bits)
        struct.pack_into("<H", data, central + 8, bits)

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported member must not be opened")

    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden)
    result = zip_submit(setup, data)
    expected = (
        "ENCRYPTED_ENTRY_UNSUPPORTED"
        if "encrypted" in kind
        else "ZIP_COMPRESSION_UNSUPPORTED"
    )
    assert result.entries[0].reason_code == expected and result.analyses == []


def test_patched_data_entry_is_skipped_with_explicit_reason(setup):
    data = bytearray(archive_bytes([("one.exe", harmless_pe_header())]))
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, 6, 0x20)
    struct.pack_into("<H", data, central + 8, 0x20)
    result = zip_submit(setup, data)
    assert result.entries[0].reason_code == "ZIP_FEATURE_UNSUPPORTED"


@pytest.mark.parametrize("version", [45, 100])
def test_unsupported_zip_version_produces_controlled_error(setup, version):
    data = bytearray(archive_bytes([("one.exe", harmless_pe_header())]))
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 6, version)
    with pytest.raises(BackendError) as error:
        zip_submit(setup, data)
    assert error.value.code == "ZIP_FORMAT_UNSUPPORTED"
    assert_clean(setup)


def test_zip_idempotency_key_rejected_before_reading_input(setup):
    class Unreadable:
        def read(self, *args):
            pytest.fail("bad keys must be rejected before receiving file bytes")

    with pytest.raises(BackendError) as error:
        setup.service.submit_zip(
            [(Unreadable(), "inputs.zip")], idempotency_key="contains space"
        )
    assert error.value.code == "INVALID_IDEMPOTENCY_KEY"
    assert_clean(setup)


@pytest.mark.parametrize(
    "kind,code",
    [
        ("not_zip", "INVALID_ZIP"),
        ("truncated", "INVALID_ZIP"),
        ("bad_crc", "INVALID_ZIP"),
        ("empty", "EMPTY_ZIP"),
        ("directories_only", "EMPTY_ZIP"),
        ("split", "ZIP_FORMAT_UNSUPPORTED"),
        ("zip64", "ZIP_FORMAT_UNSUPPORTED"),
    ],
)
def test_malformed_or_empty_archives_fail_without_registration(setup, kind, code):
    data = bytearray(archive_bytes([("valid.exe", harmless_pe_header())]))
    if kind == "not_zip":
        data = b"not a ZIP"
    elif kind == "truncated":
        data = data[:-10]
    elif kind == "bad_crc":
        data[30 + len("valid.exe")] ^= 1
    elif kind == "empty":
        data = archive_bytes([])
    elif kind == "directories_only":
        data = archive_bytes([("folder/", b"")])
    else:
        end = data.index(b"PK\x05\x06")
        struct.pack_into(
            "<H",
            data,
            end + (4 if kind == "split" else 10),
            1 if kind == "split" else 65535,
        )
    with pytest.raises(BackendError) as error:
        zip_submit(setup, data)
    assert error.value.code == code
    assert_clean(setup)


def test_false_declared_entry_count_is_bounded_before_zipinfo_allocation(
    setup, monkeypatch
):
    data = bytearray(archive_bytes([(f"file-{i}.txt", b"") for i in range(3)]))
    end = data.index(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, 1, 1)
    setup.service.config = replace(setup.config, max_zip_entries=2)

    def forbidden(*args, **kwargs):
        pytest.fail("ZipFile must not allocate an unchecked central directory")

    monkeypatch.setattr(zipfile, "ZipFile", forbidden)
    with pytest.raises(BackendError) as error:
        zip_submit(setup, data)
    assert error.value.code == "ZIP_ENTRY_LIMIT"
    assert_clean(setup)


def test_zip_processing_deadline_aborts_and_cleans_temp_files(setup, monkeypatch):
    clock = SimpleNamespace(seconds=0)
    monkeypatch.setattr(
        batch_inputs, "time", SimpleNamespace(monotonic=lambda: clock.seconds)
    )

    class SlowStream(io.BytesIO):
        def read(self, *args):
            clock.seconds += setup.config.zip_timeout_seconds + 1
            return super().read(*args)

    with pytest.raises(BackendError) as error:
        setup.service.submit_zip(
            [
                (
                    SlowStream(archive_bytes([("one.exe", harmless_pe_header())])),
                    "inputs.zip",
                )
            ]
        )
    assert error.value.code == "ZIP_TIMEOUT" and error.value.http_status == 408
    assert_clean(setup)


def test_zip_database_failure_and_uncertain_commit_preserve_correct_files(
    setup, monkeypatch
):
    data = archive_bytes([("valid.exe", harmless_pe_header())])
    setup.repository.failures["register"] = 1
    with pytest.raises(BackendError):
        zip_submit(setup, data)
    assert_clean(setup)
    original = setup.repository.sample_transaction
    calls = 0

    @contextmanager
    def commit_then_disconnect(hashes):
        nonlocal calls
        calls += 1
        with original(hashes) as transaction:
            yield transaction
        if calls == 1:
            raise BackendError("DATABASE_ERROR", "connection lost after commit")

    monkeypatch.setattr(setup.repository, "sample_transaction", commit_then_disconnect)
    with pytest.raises(BackendError):
        zip_submit(setup, data, key="uncertain")
    assert len(setup.repository.rows) == len(setup.repository.batches) == 1
    assert len(list(setup.config.storage_root.glob("*/sample.bin"))) == 1
    assert not list(setup.config.temp_root.glob("batch-*"))


def test_zip_http_contract_and_all_skipped_lookup(setup):
    with TestClient(create_app(setup.service)) as client:
        response = client.post(
            "/batches/zip",
            files={"file": ("inputs.zip", archive_bytes([("notes.txt", b"notes")]))},
        )
        assert response.status_code == 202
        receipt = response.json()
        assert receipt["skipped_count"] == receipt["archive_file_count"] == 1
        result = client.get("/batches/" + receipt["batch_id"])
        assert result.status_code == 200 and result.json()["status"] == "COMPLETED"
        assert result.json()["entries"] == receipt["entries"]
        page = client.get(
            f"/batches/{receipt['batch_id']}/analyses?verdict=HIGH_RISK_UNCERTAIN"
        )
        assert page.status_code == 200 and page.json()["total_count"] == 0
        assert (
            "file_location" not in result.text and "archive_sha256" not in result.text
        )
        assert client.get("/batches/missing/analyses").status_code == 404


def test_zip_http_rejects_wrong_form_and_limits_body_before_admission(setup):
    setup.service.config = replace(setup.config, max_zip_bytes=100)
    with TestClient(create_app(setup.service)) as client:
        wrong = client.post("/batches/zip", files={"files": ("inputs.zip", b"zip")})
        assert wrong.status_code == 422
        oversized = client.post(
            "/batches/zip",
            content=b"x",
            headers={"Content-Length": str(1024 * 1024 + 101)},
        )
        assert oversized.status_code == 413
        pe = client.post("/batches/zip", files={"file": ("one.exe", b"header")})
        assert (
            pe.status_code == 422
            and pe.json()["error"]["code"] == "UNSUPPORTED_ARCHIVE_TYPE"
        )
    assert_clean(setup)
