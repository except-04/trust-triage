"""Bounded batch admission. Archive paths are metadata, never extraction destinations."""

from __future__ import annotations

import hashlib
import stat
import struct
import tempfile
import time
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .config import BackendConfig
from .errors import BackendError
from .schemas import BatchInputEntry, BatchInputReport
from .storage import _validate_pe

_CHUNK = 64 * 1024
_SKIP = {
    "UNSUPPORTED_FILE_TYPE": ".exe와 .dll 파일만 분석합니다.",
    "INVALID_PE": "확장자는 PE이지만 유효한 PE 헤더가 없습니다.",
    "UNSUPPORTED_PE_ARCH": "지원하지 않는 PE 형식입니다.",
    "NESTED_ZIP_UNSUPPORTED": "ZIP 안의 ZIP은 분석하지 않습니다.",
    "ENCRYPTED_ENTRY_UNSUPPORTED": "암호화된 ZIP 항목은 지원하지 않습니다.",
    "ZIP_COMPRESSION_UNSUPPORTED": "이 항목의 압축 방식은 지원하지 않습니다.",
    "ZIP_FEATURE_UNSUPPORTED": "패치 데이터가 포함된 ZIP 항목은 지원하지 않습니다.",
    "FILE_TOO_LARGE": "파일별 분석 크기 제한을 초과했습니다.",
}


def _error(code: str, message: str, status: int = 422) -> BackendError:
    return BackendError(code, message, http_status=status, stage="UPLOAD")


def _display_name(filename: str) -> str:
    name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(
        c
        for c in name
        if ord(c) >= 32 and ord(c) != 127 and not 0xD800 <= ord(c) <= 0xDFFF
    )
    return name.strip()[:512] or "unnamed"


def _archive_path(info: zipfile.ZipInfo) -> str:
    # orig_filename retains embedded NULs which ZipInfo.filename otherwise truncates.
    name = info.orig_filename
    parts = name.rstrip("/").split("/")
    mode = stat.S_IFMT(info.external_attr >> 16)
    if (
        not name
        or len(name) > 512
        or name.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or any(c in name for c in ("\\", ":"))
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in name)
        or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
        or (mode == stat.S_IFDIR and not info.is_dir())
    ):
        raise _error(
            "UNSAFE_ZIP_ENTRY", "ZIP에 허용되지 않는 경로 또는 링크 항목이 있습니다."
        )
    return name


def _copy(stream: BinaryIO, destination, maximum: int, check, *, code: str):
    digest, size = hashlib.sha256(), 0
    while True:
        check()
        chunk = stream.read(min(_CHUNK, maximum - size + 1))
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise _error("INVALID_UPLOAD", "파일 데이터는 바이너리여야 합니다.")
        size += len(chunk)
        if size > maximum:
            raise _error(code, "입력 용량 제한을 초과했습니다.", 413)
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    check()
    return digest.hexdigest(), size


def _preflight_directory(stream: BinaryIO, size: int, config: BackendConfig, check):
    """Bound actual central-directory entries BEFORE ZipFile allocates ZipInfo objects."""
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or len(tail) - pos < 22:
        raise _error("INVALID_ZIP", "ZIP 중앙 디렉터리를 읽을 수 없습니다.")
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment = (
        struct.unpack_from("<4s4H2IH", tail, pos)
    )
    end_offset = max(0, size - 65557) + pos
    if (
        disk
        or cd_disk
        or disk_entries != entries
        or entries == 65535
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
    ):
        raise _error("ZIP_FORMAT_UNSUPPORTED", "분할 ZIP과 ZIP64는 지원하지 않습니다.")
    if pos + 22 + comment != len(tail) or cd_offset + cd_size != end_offset:
        raise _error("INVALID_ZIP", "ZIP 디렉터리 위치 또는 크기가 올바르지 않습니다.")
    if entries > config.max_zip_entries or cd_size > 4 * 1024 * 1024:
        raise _error(
            "ZIP_ENTRY_LIMIT",
            "ZIP 항목 수 또는 디렉터리 크기 제한을 초과했습니다.",
            413,
        )
    stream.seek(cd_offset)
    actual = 0
    while stream.tell() < end_offset:
        check()
        header = stream.read(46)
        actual += 1
        if actual > config.max_zip_entries:
            raise _error("ZIP_ENTRY_LIMIT", "ZIP 항목 수 제한을 초과했습니다.", 413)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise _error("INVALID_ZIP", "ZIP 항목 정보가 손상되었습니다.")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", header, 28)
        if (
            name_size > 2048
            or stream.tell() + name_size + extra_size + comment_size > end_offset
        ):
            raise _error("INVALID_ZIP", "ZIP 항목 정보가 허용 범위를 벗어납니다.")
        stream.seek(name_size + extra_size + comment_size, 1)
    if actual != entries:
        raise _error("INVALID_ZIP", "ZIP의 선언된 항목 수가 실제 항목 수와 다릅니다.")
    stream.seek(0)
    return entries, cd_offset


@dataclass
class PreparedBatch:
    report: BatchInputReport
    paths: dict[int, Path]


def _skip(index, name, code, *, sha256=None, size=None):
    return BatchInputEntry(
        input_index=index,
        filename=name,
        status="SKIPPED",
        reason_code=code,
        reason=_SKIP[code],
        sha256=sha256,
        size_bytes=size,
    )


class BatchInputHandler:
    def __init__(self, config: BackendConfig):
        self.config = config

    @contextmanager
    def prepare(
        self, files: list[tuple[BinaryIO, str]], *, archive: bool = False
    ) -> Iterator[PreparedBatch]:
        config = self.config
        if not files or len(files) > (1 if archive else config.max_batch_files):
            raise _error(
                "INVALID_FILE_COUNT", "업로드 파일 수가 허용 범위를 벗어났습니다."
            )
        timeout = (
            config.zip_timeout_seconds if archive else config.upload_timeout_seconds
        )
        deadline = time.monotonic() + timeout

        def check():
            if time.monotonic() >= deadline:
                raise _error(
                    "ZIP_TIMEOUT" if archive else "UPLOAD_TIMEOUT",
                    "입력 처리 제한 시간을 초과했습니다.",
                    408,
                )

        config.temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="batch-", dir=config.temp_root
        ) as directory:
            root = Path(directory)
            if archive:
                prepared = self._archive(files[0], root, check)
            else:
                entries, paths = [], {}
                for index, (stream, filename) in enumerate(files):
                    name = _display_name(filename)
                    target = root / f"input-{index}.bin"
                    with target.open("xb") as output:
                        sha256, size = _copy(
                            stream,
                            output,
                            config.max_file_bytes,
                            check,
                            code="FILE_TOO_LARGE",
                        )
                    entry = self._entry(index, name, target, sha256, size)
                    entries.append(entry)
                    if entry.status == "ACCEPTED":
                        paths[index] = target
                    else:
                        target.unlink()
                prepared = PreparedBatch(
                    BatchInputReport(source_type="MULTIPLE_FILES", entries=entries),
                    paths,
                )
            check()
            yield prepared

    def _entry(self, index, name, target, sha256, size):
        if PurePosixPath(name).suffix.lower() not in {".exe", ".dll"}:
            return _skip(index, name, "UNSUPPORTED_FILE_TYPE", sha256=sha256, size=size)
        try:
            with target.open("rb") as stream:
                _validate_pe(stream, size)
        except BackendError as exc:
            if exc.code not in {"INVALID_PE", "UNSUPPORTED_PE_ARCH"}:
                raise
            return _skip(index, name, exc.code, sha256=sha256, size=size)
        # This temporary ID is replaced by the durable sample ID before registration.
        return BatchInputEntry(
            input_index=index,
            filename=name,
            status="ACCEPTED",
            analysis_id=f"input_{index}",
            sha256=sha256,
            size_bytes=size,
        )

    def _archive(self, file, root, check):
        stream, filename = file
        name, config = _display_name(filename), self.config
        if PurePosixPath(name).suffix.lower() != ".zip":
            raise _error(
                "UNSUPPORTED_ARCHIVE_TYPE", "ZIP 접수에는 .zip 파일 하나를 사용합니다."
            )
        archive_path = root / "archive.bin"
        with archive_path.open("xb") as output:
            digest, size = _copy(
                stream, output, config.max_zip_bytes, check, code="ZIP_TOO_LARGE"
            )
        entries, paths, expanded = [], {}, 0
        try:
            with archive_path.open("rb") as source:
                count, directory_offset = _preflight_directory(
                    source, size, config, check
                )
                with zipfile.ZipFile(source) as archive:
                    infos = archive.infolist()
                    if len(infos) != count:
                        raise _error("INVALID_ZIP", "ZIP 항목 수가 일치하지 않습니다.")
                    names = [_archive_path(info) for info in infos]
                    declared = sum(info.file_size for info in infos)
                    if declared > config.max_zip_expanded_bytes:
                        raise _error(
                            "ZIP_EXPANDED_LIMIT",
                            "ZIP 해제 후 총 용량 제한을 초과했습니다.",
                            413,
                        )
                    for info in infos:
                        if info.extract_version == 45:
                            raise _error(
                                "ZIP_FORMAT_UNSUPPORTED",
                                "ZIP64 항목은 지원하지 않습니다.",
                            )
                        if (
                            info.file_size
                            > max(1, info.compress_size) * config.max_zip_ratio
                        ):
                            raise _error(
                                "ZIP_RATIO_LIMIT",
                                "ZIP 압축률 제한을 초과했습니다.",
                                413,
                            )
                        if (
                            info.header_offset < 0
                            or info.header_offset >= directory_offset
                            or info.compress_size > size
                        ):
                            raise _error(
                                "INVALID_ZIP",
                                "ZIP 항목의 데이터 위치가 올바르지 않습니다.",
                            )
                    for index, (info, member_name) in enumerate(zip(infos, names)):
                        check()
                        if info.is_dir():
                            continue
                        suffix = PurePosixPath(member_name).suffix.lower()
                        code = (
                            "NESTED_ZIP_UNSUPPORTED"
                            if suffix == ".zip"
                            else "UNSUPPORTED_FILE_TYPE"
                            if suffix not in {".exe", ".dll"}
                            else "ENCRYPTED_ENTRY_UNSUPPORTED"
                            if info.flag_bits & 0x41
                            else "ZIP_FEATURE_UNSUPPORTED"
                            if info.flag_bits & 0x20
                            else "ZIP_COMPRESSION_UNSUPPORTED"
                            if info.compress_type
                            not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                            else "FILE_TOO_LARGE"
                            if info.file_size > config.max_file_bytes
                            else None
                        )
                        if code:
                            entries.append(
                                _skip(index, member_name, code, size=info.file_size)
                            )
                            continue
                        target = root / f"input-{index}.bin"
                        with archive.open(info) as member, target.open("xb") as output:
                            remaining = min(
                                config.max_file_bytes,
                                config.max_zip_expanded_bytes - expanded,
                            )
                            sha256, member_size = _copy(
                                member,
                                output,
                                remaining,
                                check,
                                code="ZIP_EXPANDED_LIMIT",
                            )
                        expanded += member_size
                        if member_size != info.file_size:
                            raise _error(
                                "INVALID_ZIP",
                                "ZIP 항목의 실제 크기가 선언된 크기와 다릅니다.",
                            )
                        entry = self._entry(
                            index, member_name, target, sha256, member_size
                        )
                        entries.append(entry)
                        if entry.status == "ACCEPTED":
                            paths[index] = target
                            if len(paths) > config.max_batch_files:
                                raise _error(
                                    "INVALID_FILE_COUNT",
                                    "ZIP 안의 분석 대상 PE 수가 배치 제한을 초과했습니다.",
                                )
                        else:
                            target.unlink()
        except NotImplementedError as exc:
            raise _error(
                "ZIP_FORMAT_UNSUPPORTED", "지원하지 않는 ZIP 기능 또는 버전입니다."
            ) from exc
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            zlib.error,
            UnicodeError,
            EOFError,
            struct.error,
        ) as exc:
            raise _error(
                "INVALID_ZIP", "ZIP 내용 또는 체크섬이 손상되었습니다."
            ) from exc
        if not entries:
            raise _error("EMPTY_ZIP", "ZIP 안에 파일이 없습니다.")
        return PreparedBatch(
            BatchInputReport(
                source_type="ZIP",
                archive_filename=name,
                archive_sha256=digest,
                archive_size_bytes=size,
                entries=entries,
            ),
            paths,
        )
