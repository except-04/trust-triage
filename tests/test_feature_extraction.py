from __future__ import annotations

import shutil
import sys
from pathlib import Path

import numpy as np
import pytest

from trust_triage.feature_extraction import (
    ExtractionStatus,
    PEExtractor,
    PE_STATIC_FEATURE_SCHEMA,
    extract_file,
)


@pytest.fixture
def benign_pe_fixture(tmp_path: Path) -> Path:
    """현재 Python 실행 파일을 재현 가능한 정상 PE fixture로 사용한다."""

    source = Path(sys.executable)
    if source.read_bytes()[:2] != b"MZ":
        pytest.skip("the test interpreter is not a Windows PE")
    target = tmp_path / "benign-python.exe"
    shutil.copy2(source, target)
    return target


def test_extracts_fixed_float32_vector(benign_pe_fixture: Path) -> None:
    result = PEExtractor().extract(benign_pe_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.file_type in {"PE32", "PE32+"}
    assert len(result.feature_names) == PE_STATIC_FEATURE_SCHEMA.feature_count
    assert result.feature_count == PE_STATIC_FEATURE_SCHEMA.feature_count
    assert len(result.features) == PE_STATIC_FEATURE_SCHEMA.feature_count

    vector = result.to_float32(PE_STATIC_FEATURE_SCHEMA)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()
    assert len(result.sha256) == 64


def test_repeated_extraction_is_deterministic(benign_pe_fixture: Path) -> None:
    extractor = PEExtractor()

    first = extractor.extract(benign_pe_fixture).to_dict()
    second = extractor.extract(benign_pe_fixture).to_dict()

    assert first == second


def test_invalid_pe_is_not_reported_as_success(tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid.exe"
    invalid_file.write_bytes(b"MZ" + b"not-a-valid-pe")

    result = PEExtractor().extract(invalid_file)

    assert result.status is ExtractionStatus.INVALID_PE
    assert result.features == []
    assert result.errors
    with pytest.raises(ValueError):
        result.to_float32(PE_STATIC_FEATURE_SCHEMA)


def test_dispatch_reports_unknown_format(tmp_path: Path) -> None:
    text_file = tmp_path / "sample.txt"
    text_file.write_text("plain text", encoding="utf-8")

    result = extract_file(text_file)

    assert result.status is ExtractionStatus.UNSUPPORTED
    assert result.file_type == "UNKNOWN"
    assert len(result.sha256) == 64


def test_missing_file_is_explicit(tmp_path: Path) -> None:
    result = extract_file(tmp_path / "missing.exe")

    assert result.status is ExtractionStatus.PARSE_ERROR
    assert result.features == []
    assert result.errors


def test_file_size_limit_is_explicit(tmp_path: Path) -> None:
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"0123456789")

    result = PEExtractor(max_file_size_bytes=4).extract(large_file)

    assert result.status is ExtractionStatus.FILE_TOO_LARGE
    assert result.features == []
    assert result.errors
