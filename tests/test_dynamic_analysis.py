from __future__ import annotations

import json
from pathlib import Path

from trust_triage.dynamic_analysis import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
    SpeakeasyAnalyzer,
)
from trust_triage.dynamic_analysis.speakeasy_analyzer import (
    _classify_speakeasy_error,
    _summarize_report,
    _status_from_report_warnings,
)


def test_result_is_serialized_as_common_evidence() -> None:
    result = DynamicAnalysisResult(
        evidence_id="speakeasy-test",
        sha256="a" * 64,
        source="SPEAKEASY",
        category="DYNAMIC_ANALYSIS",
        status=DynamicAnalysisStatus.SUCCESS,
        summary="분석 완료",
        observed_apis=("CreateFileW",),
        api_call_counts={"CreateFileW": 2},
        behaviors=("file_access",),
        events={"api_calls": ({"api_name": "CreateFileW"},)},
        tool_version="1.5.11",
        started_at="2026-08-04T00:00:00+00:00",
        completed_at="2026-08-04T00:00:01+00:00",
    )

    payload = result.to_dict()

    assert payload["status"] == "SUCCESS"
    assert payload["source"] == "SPEAKEASY"
    assert payload["observed_apis"] == ["CreateFileW"]
    assert payload["api_call_counts"] == {"CreateFileW": 2}
    assert payload["events"] == {"api_calls": [{"api_name": "CreateFileW"}]}
    assert payload["tool_version"] == "1.5.11"
    assert json.loads(result.to_json())["sha256"] == "a" * 64


def test_non_pe_is_not_sent_to_speakeasy(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("not a PE", encoding="utf-8")

    result = SpeakeasyAnalyzer().analyze(sample)

    assert result.status is DynamicAnalysisStatus.UNSUPPORTED_TARGET
    assert result.sha256 == ""
    assert result.errors == ()


def test_missing_file_is_explicit(tmp_path: Path) -> None:
    result = SpeakeasyAnalyzer().analyze(tmp_path / "missing.exe")

    assert result.status is DynamicAnalysisStatus.INVALID_INPUT
    assert result.errors


def test_file_size_limit_is_explicit(tmp_path: Path) -> None:
    sample = tmp_path / "large.exe"
    sample.write_bytes(b"MZ" + b"0" * 10)

    result = SpeakeasyAnalyzer(max_file_size_bytes=4).analyze(sample)

    assert result.status is DynamicAnalysisStatus.FILE_TOO_LARGE
    assert result.errors


def test_report_summary_extracts_apis_and_behaviors() -> None:
    report = {
        "entry_points": [
            {
                "apis": [
                    {"api_name": "CreateFileW"},
                    {"api_name": "InternetOpenA"},
                    {"api_name": "CreateFileW"},
                ],
                "network_events": {"dns": ["example.test"]},
                "file_access": [{"path": "C:\\temp\\x.bin"}],
                "error": "일부 호출은 처리되지 않음",
            }
        ]
    }

    summary = _summarize_report(report)

    assert summary.observed_apis == ("CreateFileW", "InternetOpenA")
    assert summary.api_call_counts == {"CreateFileW": 2, "InternetOpenA": 1}
    assert summary.behaviors == ("file_access", "network")
    assert summary.events["api_calls"][0]["entry_point"] == 0
    assert summary.events["file_access"][0]["path"] == "C:\\temp\\x.bin"
    assert summary.warnings == ("일부 호출은 처리되지 않음",)


def test_report_error_is_summarized_without_register_dump() -> None:
    report = {
        "entry_points": [
            {
                "apis": [],
                "error": {
                    "type": "unsupported_api",
                    "api_name": "KERNEL32.UnsupportedCall",
                    "regs": {"rax": "0x1"},
                },
            }
        ]
    }

    warnings = _summarize_report(report).warnings

    assert warnings == ("unsupported_api: KERNEL32.UnsupportedCall",)


def test_report_timeout_is_detected_without_discarding_observations() -> None:
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "CreateFileW"}],
                "error": "* Timeout of 4 sec(s) reached.",
            }
        ]
    }

    summary = _summarize_report(report)

    assert summary.observed_apis == ("CreateFileW",)
    assert any("timeout" in warning.casefold() for warning in summary.warnings)
    assert _status_from_report_warnings(summary.warnings) is DynamicAnalysisStatus.TIMEOUT


def test_report_unsupported_api_has_explicit_status() -> None:
    assert _status_from_report_warnings(("unsupported_api",)) is DynamicAnalysisStatus.UNSUPPORTED_API


def test_generic_report_warning_is_tool_error() -> None:
    assert _status_from_report_warnings(("report serialization warning",)) is DynamicAnalysisStatus.TOOL_ERROR


def test_unsupported_dotnet_message_has_explicit_status() -> None:
    assert (
        _classify_speakeasy_error(".NET assemblies are not currently supported")
        == "UNSUPPORTED_TARGET"
    )
