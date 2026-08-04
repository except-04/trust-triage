from __future__ import annotations

import json
import os
import shutil
import sys
from types import SimpleNamespace
from pathlib import Path

import numpy as np
import pytest

import trust_triage.feature_extraction.ember_v3 as ember_v3_module
from trust_triage.feature_extraction.cli import main as cli_main
from trust_triage.feature_extraction import (
    ApiImportMatch,
    EmberV3Extractor,
    ExtractionStatus,
    FeatureExtractionResult,
    FeatureSelectionError,
    FeatureSchema,
    FeatureSelector,
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


def _copy_matching_system_binary(
    tmp_path: Path,
    candidates: list[Path],
    *,
    expected_file_types: set[str],
    expected_dotnet: bool,
    target_name: str,
) -> Path:
    """시스템에 있는 정상 PE를 조건에 맞을 때만 테스트 fixture로 복사한다."""

    for source in candidates:
        if not source.is_file():
            continue

        target = tmp_path / target_name
        shutil.copy2(source, target)
        result = EmberV3Extractor().extract(target)
        if (
            result.status is ExtractionStatus.SUCCESS
            and result.file_type in expected_file_types
            and result.is_dotnet is expected_dotnet
        ):
            return target

    pytest.skip(
        "no matching system PE fixture: "
        f"{sorted(expected_file_types)}, dotnet={expected_dotnet}"
    )


@pytest.fixture
def benign_pe32_fixture(tmp_path: Path) -> Path:
    """Windows의 정상 32비트 실행 파일을 임시 fixture로 사용한다."""

    windir_text = os.environ.get("WINDIR")
    if not windir_text:
        pytest.skip("WINDIR is unavailable")

    windir = Path(windir_text)
    return _copy_matching_system_binary(
        tmp_path,
        [
            windir / "SysWOW64" / "notepad.exe",
            windir / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        ],
        expected_file_types={"PE32"},
        expected_dotnet=False,
        target_name="benign-pe32.exe",
    )


@pytest.fixture
def benign_pe32_plus_fixture(tmp_path: Path) -> Path:
    """정상 64비트 실행 파일을 임시 fixture로 사용한다."""

    windir_text = os.environ.get("WINDIR")
    candidates = [Path(sys.executable)]
    if windir_text:
        windir = Path(windir_text)
        candidates.append(windir / "System32" / "notepad.exe")

    return _copy_matching_system_binary(
        tmp_path,
        candidates,
        expected_file_types={"PE32+"},
        expected_dotnet=False,
        target_name="benign-pe32-plus.exe",
    )


@pytest.fixture
def benign_dotnet_fixture(tmp_path: Path) -> Path:
    """Windows에 설치된 정상 .NET Framework 실행 파일을 임시 fixture로 사용한다."""

    windir_text = os.environ.get("WINDIR")
    if not windir_text:
        pytest.skip("WINDIR is unavailable")

    windir = Path(windir_text)
    return _copy_matching_system_binary(
        tmp_path,
        [
            windir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "RegAsm.exe",
            windir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "RegAsm.exe",
        ],
        expected_file_types={"PE32", "PE32+"},
        expected_dotnet=True,
        target_name="benign-dotnet.exe",
    )


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
    assert result.is_dotnet is False
    assert extractor.schema.groups[0].name == "general"
    assert extractor.schema.groups[0].start_index == 0
    assert extractor.schema.groups[-1].end_index_exclusive == 2568
    assert extractor.schema.to_dict()["feature_count"] == 2568

    vector = result.to_float32(extractor.schema)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()
    assert len(result.sha256) == 64
    assert result.api_groups is not None
    assert result.api_groups.schema_version == "api-groups-mvp-v2"
    assert set(result.api_groups.groups) == {"registry", "injection", "network"}
    assert result.metadata["source_verified"] is True
    assert result.metadata["commit"] == ember_v3_module.EMBER_V3_SOURCE_COMMIT


def test_extracts_real_pe32_file(benign_pe32_fixture: Path) -> None:
    result = EmberV3Extractor().extract(benign_pe32_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.file_type == "PE32"
    assert result.is_dotnet is False
    assert result.feature_count == 2568
    assert len(result.to_float32(EmberV3Extractor().schema)) == 2568


def test_extracts_real_pe32_plus_file(benign_pe32_plus_fixture: Path) -> None:
    result = EmberV3Extractor().extract(benign_pe32_plus_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.file_type == "PE32+"
    assert result.is_dotnet is False
    assert result.feature_count == 2568


def test_extracts_real_dotnet_file(benign_dotnet_fixture: Path) -> None:
    result = EmberV3Extractor().extract(benign_dotnet_fixture)

    assert result.status is ExtractionStatus.SUCCESS
    assert result.file_type == "PE32"
    assert result.is_dotnet is True
    assert result.feature_count == 2568


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
    assert report.ordinal_imports[0].dll == "Advapi32.dll"
    assert report.ordinal_imports[0].ordinal == 1
    assert report.to_dict()["ordinal_imports"] == [
        {"dll": "Advapi32.dll", "ordinal": 1, "resolved": False}
    ]
    assert report.groups["registry"].matched is True
    assert report.groups["registry"].apis == ("RegSetValueExW",)
    assert report.groups["registry"].dlls == ("Advapi32.dll",)
    assert report.groups["registry"].matches == (
        ApiImportMatch(dll="Advapi32.dll", api="RegSetValueExW"),
    )
    assert report.groups["injection"].match_count == 1
    assert report.groups["network"].apis == ("CONNECT",)
    assert report.to_dict()["groups"]["registry"]["matches"] == [
        {"dll": "Advapi32.dll", "api": "RegSetValueExW"}
    ]


def test_classifies_pe_without_import_table() -> None:
    report = classify_imports(SimpleNamespace())

    assert report.named_import_count == 0
    assert report.ordinal_import_count == 0
    assert report.ordinal_imports == ()
    assert all(not group.matched for group in report.groups.values())


def test_detects_dotnet_com_descriptor_directory() -> None:
    directories = [
        SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)
    ]
    directories[14] = SimpleNamespace(VirtualAddress=0x2000, Size=72)
    dotnet_pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories)
    )

    assert EmberV3Extractor._is_dotnet(dotnet_pe) is True

    directories[14] = SimpleNamespace(VirtualAddress=0, Size=0)
    native_pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories)
    )
    assert EmberV3Extractor._is_dotnet(native_pe) is False


def test_documented_ember_schema_matches_runtime_schema() -> None:
    manifest_path = (
        Path(__file__).parents[1]
        / "docs"
        / "feature-extraction"
        / "ember-v3-schema.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    runtime_schema = EmberV3Extractor().schema.to_dict()

    assert manifest["schema_version"] == runtime_schema["schema_version"]
    assert manifest["feature_count"] == runtime_schema["feature_count"]
    assert manifest["source"]["package"] == ember_v3_module.EMBER_V3_SOURCE_PACKAGE
    assert manifest["source"]["repository"] == ember_v3_module.EMBER_V3_SOURCE_REPOSITORY
    assert manifest["source"]["commit"] == ember_v3_module.EMBER_V3_SOURCE_COMMIT
    assert [
        {
            key: group[key]
            for key in ("name", "start_index", "end_index_exclusive", "dimension")
        }
        for group in manifest["groups"]
    ] == [
        {
            key: group[key]
            for key in ("name", "start_index", "end_index_exclusive", "dimension")
        }
        for group in runtime_schema["groups"]
    ]


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


def test_timed_extraction_returns_explicit_timeout(benign_pe_fixture: Path) -> None:
    result = extract_file(benign_pe_fixture, timeout_seconds=0.001)

    assert result.status is ExtractionStatus.TIMEOUT
    assert len(result.sha256) == 64
    assert result.metadata["execution_mode"] == "separate_process"
    assert result.errors


def test_thrember_source_verification_rejects_wrong_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeDistribution:
        version = "0.1.0"

        @staticmethod
        def read_text(name: str) -> str:
            assert name == "direct_url.json"
            return json.dumps(
                {
                    "url": "https://github.com/FutureComputing4AI/EMBER2024.git",
                    "vcs_info": {"commit_id": "wrong-commit", "vcs": "git"},
                }
            )

    monkeypatch.setattr(ember_v3_module, "distribution", lambda _: FakeDistribution())

    with pytest.raises(RuntimeError, match="출처 검증"):
        ember_v3_module._load_thrember_source_metadata(verify_source=True)


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


def test_schema_validates_feature_names_and_matrix() -> None:
    schema = FeatureSchema(
        version="test-v1",
        feature_names=("first", "second", "third"),
    )

    assert schema.validate_feature_names(["first", "second", "third"]) == (
        "first",
        "second",
        "third",
    )
    matrix = schema.validate_matrix([[1, 2, 3], [4, 5, 6]])
    assert matrix.shape == (2, 3)
    assert matrix.dtype == np.float32

    with pytest.raises(ValueError, match="feature name/order mismatch"):
        schema.validate_feature_names(["second", "first", "third"])
    with pytest.raises(ValueError, match="expected 3 features per row"):
        schema.validate_matrix([[1, 2]])
    with pytest.raises(ValueError, match="NaN or infinite"):
        schema.validate_matrix([[1, np.nan, 3]])


def test_feature_selector_preserves_explicit_order_and_round_trips_manifest() -> None:
    schema = FeatureSchema(
        version="test-v1",
        feature_names=("first", "second", "third"),
    )
    selector = FeatureSelector.from_feature_names(
        schema,
        ["third", "first"],
        selection_id="demo-subset",
    )

    vector = selector.select_vector(
        [1, 2, 3],
        schema_version="test-v1",
        feature_names=["first", "second", "third"],
    )
    assert vector.tolist() == [3.0, 1.0]
    assert vector.dtype == np.float32
    assert selector.source_indices == (2, 0)
    assert selector.output_schema.feature_names == ("third", "first")
    assert selector.is_all is False

    restored = FeatureSelector.from_manifest(schema, selector.to_dict())
    assert restored.output_schema.version == selector.output_schema.version
    assert restored.select_vector([1, 2, 3]).tolist() == [3.0, 1.0]


def test_feature_selector_rejects_incompatible_selection_inputs() -> None:
    schema = FeatureSchema(version="test-v1", feature_names=("first", "second"))

    with pytest.raises(FeatureSelectionError, match="must be unique"):
        FeatureSelector.from_feature_names(schema, ["first", "first"])
    with pytest.raises(FeatureSelectionError, match="not present"):
        FeatureSelector.from_feature_names(schema, ["missing"])
    with pytest.raises(FeatureSelectionError, match="fewer than all"):
        FeatureSelector.from_manifest(
            schema,
            {
                "selection_schema_version": "feature-selection-v1",
                "source_schema_version": "test-v1",
                "selection_id": "reordered-all",
                "mode": "subset",
                "feature_names": ["second", "first"],
            },
        )

    selector = FeatureSelector.from_feature_names(schema, ["second"])
    with pytest.raises(FeatureSelectionError, match="version mismatch"):
        selector.select_vector([1, 2], schema_version="other-v1")
    with pytest.raises(FeatureSelectionError, match="name/order"):
        selector.select_vector(
            [1, 2],
            schema_version="test-v1",
            feature_names=["second", "first"],
        )
    with pytest.raises(FeatureSelectionError, match="must be float32"):
        FeatureSelector.from_feature_names(schema, ["first"], dtype="float64")


def test_feature_extraction_result_builds_valid_model_input() -> None:
    schema = FeatureSchema(version="test-v1", feature_names=("first", "second"))
    result = FeatureExtractionResult.success(
        schema=schema,
        sha256="a" * 64,
        file_type="PE32",
        values=[1, 2],
    )
    selector = FeatureSelector.all(schema, selection_id="all-features")

    model_input = result.to_model_input(selector)

    assert model_input.dtype == np.float32
    assert model_input.tolist() == [1.0, 2.0]


def test_cli_selection_outputs_only_selected_model_input(
    benign_pe_fixture: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    schema = EmberV3Extractor().schema
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(
        json.dumps(
            {
                "selection_schema_version": "feature-selection-v1",
                "source_schema_version": schema.version,
                "selection_id": "cli-subset",
                "mode": "subset",
                "dtype": "float32",
                "feature_names": list(schema.feature_names[:3]),
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli_main(
        [str(benign_pe_fixture), "--selection-file", str(selection_path)]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["selection_id"] == "cli-subset"
    assert payload["source_schema_version"] == schema.version
    assert payload["dtype"] == "float32"
    assert payload["feature_count"] == 3
    assert payload["feature_names"] == list(schema.feature_names[:3])
    assert len(payload["features"]) == 3


def test_missing_feature_configuration_is_explicit(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="configuration does not exist"):
        EmberV3Extractor(features_file=tmp_path / "missing.json")
