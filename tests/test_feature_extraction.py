from __future__ import annotations

import json
import shutil
import sys
from types import SimpleNamespace
from pathlib import Path

import numpy as np
import pytest

from trust_triage.feature_extraction.cli import main as cli_main
from trust_triage.feature_extraction import (
    EmberV3Extractor,
    ExtractionStatus,
    FeatureSchema,
    classify_imports,
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


def test_extracts_official_ember_v3_float32_vector(
    benign_pe_fixture: Path,
) -> None:
    extractor = EmberV3Extractor()
    result = extractor.extract(benign_pe_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.file_type in {"PE32", "PE32+"}
    assert result.schema_version.startswith("ember2024-v3-pe-")
    assert result.feature_count == 2568
    assert len(result.features) == 2568

    vector = result.to_float32(extractor.schema)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()
    assert len(result.sha256) == 64
    assert result.api_groups is not None
    assert result.api_groups.schema_version == "api-groups-mvp-v1"
    assert set(result.api_groups.groups) == {"registry", "injection", "network"}


def test_classifies_imports_into_api_groups() -> None:
    fake_pe = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                dll=b"Advapi32.dll",
                imports=[
                    SimpleNamespace(name=b"RegSetValueExW"),
                    SimpleNamespace(name=None, ordinal=1),
                ],
            ),
            SimpleNamespace(
                dll=b"kernel32.dll",
                imports=[SimpleNamespace(name=b"WriteProcessMemory")],
            ),
            SimpleNamespace(
                dll=b"Ws2_32.dll",
                imports=[SimpleNamespace(name=b"CONNECT")],
            ),
        ]
    )

    report = classify_imports(fake_pe)

    assert report.named_import_count == 3
    assert report.ordinal_import_count == 1
    assert report.groups["registry"].matched is True
    assert report.groups["registry"].apis == ("RegSetValueExW",)
    assert report.groups["registry"].dlls == ("Advapi32.dll",)
    assert report.groups["injection"].match_count == 1
    assert report.groups["network"].apis == ("CONNECT",)


def test_api_group_report_is_serialized_with_feature_result(
    benign_pe_fixture: Path,
) -> None:
    result = extract_file(benign_pe_fixture)

    payload = result.to_dict()

    assert payload["api_groups"] is not None
    assert payload["api_groups"]["source"] == "PE_IMPORT_TABLE"
    assert set(payload["api_groups"]["groups"]) == {
        "registry",
        "injection",
        "network",
    }


def test_cli_summary_prints_core_information_without_full_vector(
    benign_pe_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_main([str(benign_pe_fixture), "--summary"])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "[PE 정적 분석 요약]" in output
    assert "Feature 개수: 2568" in output
    assert "API 그룹:" in output
    assert '"features"' not in output


def test_repeated_extraction_is_deterministic(benign_pe_fixture: Path) -> None:
    first = extract_file(benign_pe_fixture).to_dict()
    second = extract_file(benign_pe_fixture).to_dict()

    assert first == second


def test_invalid_pe_is_not_reported_as_success(tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid.exe"
    invalid_file.write_bytes(b"MZ" + b"not-a-valid-pe")

    result = EmberV3Extractor().extract(invalid_file)

    assert result.status is ExtractionStatus.INVALID_PE
    assert result.features == []
    assert result.errors


def test_dispatch_reports_unknown_format(tmp_path: Path) -> None:
    text_file = tmp_path / "sample.txt"
    text_file.write_text("plain text", encoding="utf-8")

    result = extract_file(text_file)

    assert result.status is ExtractionStatus.UNSUPPORTED
    assert result.file_type == "UNKNOWN"
    assert len(result.sha256) == 64


def test_direct_extractor_reports_unknown_format(tmp_path: Path) -> None:
    text_file = tmp_path / "sample.txt"
    text_file.write_text("plain text", encoding="utf-8")

    result = EmberV3Extractor().extract(text_file)

    assert result.status is ExtractionStatus.UNSUPPORTED
    assert len(result.sha256) == 64


def test_missing_file_is_explicit(tmp_path: Path) -> None:
    result = extract_file(tmp_path / "missing.exe")

    assert result.status is ExtractionStatus.PARSE_ERROR
    assert result.features == []
    assert result.errors


def test_file_size_limit_is_explicit(tmp_path: Path) -> None:
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"0123456789")

    result = EmberV3Extractor(max_file_size_bytes=4).extract(large_file)

    assert result.status is ExtractionStatus.FILE_TOO_LARGE
    assert result.features == []
    assert result.errors


def test_ember_feature_group_configuration_changes_schema(
    benign_pe_fixture: Path,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "features.json"
    config_path.write_text(
        json.dumps({"features": {"GeneralFileInfo": True}}),
        encoding="utf-8",
    )

    extractor = EmberV3Extractor(features_file=config_path)
    result = extractor.extract(benign_pe_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.feature_count == 7
    assert result.feature_names == [
        "general[0]",
        "general[1]",
        "general[2]",
        "general[3]",
        "general[4]",
        "general[5]",
        "general[6]",
    ]
    assert np.isfinite(result.to_float32(extractor.schema)).all()


def test_schema_rejects_duplicate_feature_names() -> None:
    with pytest.raises(ValueError, match="feature names must be unique"):
        FeatureSchema(version="test-v1", feature_names=("duplicate", "duplicate"))


def test_missing_feature_configuration_is_explicit(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="configuration does not exist"):
        EmberV3Extractor(features_file=tmp_path / "missing.json")
