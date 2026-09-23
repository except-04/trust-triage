from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import trust_triage.dynamic_analysis.speakeasy_analyzer as analyzer_module
from trust_triage.dynamic_analysis import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
    SpeakeasyAnalyzer,
)
from trust_triage.dynamic_analysis.speakeasy_analyzer import (
    _classify_speakeasy_error,
    _run_speakeasy_worker,
    _status_from_report_warnings,
    _summarize_report,
)


def test_optional_raw_report_write_error_does_not_change_engine_status(
    monkeypatch, tmp_path
):
    class FakeSpeakeasy:
        def __init__(self):
            self.config = {}

        def load_module(self, *, path):
            return path

        def run_module(self, _module, *, emulate_children):
            return None

        def get_report(self):
            return {"entry_points": [{"apis": [{"api_name": "CreateFileW"}]}]}

    class CaptureQueue:
        def __init__(self):
            self.messages = []

        def put(self, value):
            self.messages.append(json.loads(value))

    def fail_write(*_args, **_kwargs):
        raise OSError("fixture write denied")

    monkeypatch.setitem(sys.modules, "speakeasy", SimpleNamespace(Speakeasy=FakeSpeakeasy))
    monkeypatch.setattr(Path, "write_text", fail_write)
    queue = CaptureQueue()

    _run_speakeasy_worker(
        "harmless-fixture", 2, 100, 100, False,
        str(tmp_path / "report.json"), queue,
    )

    message = queue.messages[0]
    assert message["kind"] == "summary"
    assert message["warnings"] == []
    assert "fixture write denied" in message["raw_report_error"]
    assert _status_from_report_warnings(tuple(message["warnings"])) is DynamicAnalysisStatus.SUCCESS


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


@pytest.mark.parametrize("count", [99, 100, 101, 110])
@pytest.mark.parametrize("service_index", [0, -1])
def test_report_summary_tracks_original_count_and_service_return_across_cap(
    count: int, service_index: int
) -> None:
    calls = [{"api_name": "CreateFileW", "pc": index} for index in range(count)]
    calls[service_index] = {
        "api_name": "advapi32.CreateServiceW",
        "ret_val": "0x00000000",
    }
    summary = _summarize_report({"entry_points": [{"apis": calls}]})

    assert summary.event_counts["api_calls"] == count
    assert len(summary.events["api_calls"]) == min(count, 100)
    assert summary.events_truncated is (count > 100)
    assert summary.service_creation_calls == {
        "calls": [{
            "api_name": "createservicew",
            "event_index": service_index % count,
            "ret_val": "0x00000000",
        }],
        "total": 1,
        "complete": True,
    }


def test_report_summary_counts_multiple_entry_points_in_original_order() -> None:
    summary = _summarize_report({"entry_points": [
        {"apis": [{"api_name": "CreateFileW"} for _ in range(60)]},
        {"apis": [
            *({"api_name": "CreateFileW"} for _ in range(45)),
            {"api_name": "advapi32.CreateServiceA", "ret_val": "0x0"},
        ]},
    ]})

    assert summary.event_counts["api_calls"] == 106
    assert summary.events_truncated is True
    assert summary.events["api_calls"][99]["entry_point"] == 1
    assert summary.service_creation_calls["calls"][0]["event_index"] == 105


def test_analyzer_preserves_child_truncation_metadata(monkeypatch, tmp_path) -> None:
    sample = tmp_path / "harmless-fixture.bin"
    sample.write_bytes(b"MZ" + b"fixture")
    calls = [{"api_name": "CreateFileW"} for _ in range(105)]
    calls.append({"api_name": "advapi32.CreateServiceW", "ret_val": "0x0"})
    summary = _summarize_report({"entry_points": [{"apis": calls}]})
    message = json.dumps({
        "kind": "summary",
        "observed_apis": summary.observed_apis,
        "api_call_counts": summary.api_call_counts,
        "behaviors": summary.behaviors,
        "events": summary.events,
        "event_counts": summary.event_counts,
        "events_truncated": summary.events_truncated,
        "service_creation_calls": summary.service_creation_calls,
        "warnings": summary.warnings,
    })

    class FakeQueue:
        def close(self):
            pass

        def join_thread(self):
            pass

    class FakeProcess:
        def start(self):
            pass

        def is_alive(self):
            return False

        def join(self, _timeout):
            pass

    monkeypatch.setattr(
        analyzer_module.multiprocessing,
        "get_context",
        lambda _method: SimpleNamespace(
            Queue=lambda **_kwargs: FakeQueue(),
            Process=lambda **_kwargs: FakeProcess(),
        ),
    )
    monkeypatch.setattr(
        analyzer_module, "_receive_worker_message", lambda *_args: message
    )

    result = SpeakeasyAnalyzer().analyze(sample)

    assert result.status is DynamicAnalysisStatus.SUCCESS
    assert result.metadata["event_counts"]["api_calls"] == 106
    assert result.metadata["events_truncated"] is True
    assert result.metadata["adapter_events_truncated"] is True
    assert result.metadata["service_creation_calls"]["calls"][0]["ret_val"] == "0x0"


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
