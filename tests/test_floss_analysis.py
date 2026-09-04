from __future__ import annotations

import json
import subprocess
from pathlib import Path

from trust_triage.static_analysis import (
    FlossAnalyzer,
    FlossConfig,
    FlossStatus,
    parse_floss_report,
)
from trust_triage.static_analysis import floss_analyzer as floss_module


def _report(*, strings: dict | None = None) -> dict:
    return {
        "metadata": {
            "version": "3.1.0",
            "sha256": "a" * 64,
            "file_path": "sample.exe",
        },
        "analysis": {
            "enable_static_strings": True,
            "enable_stack_strings": True,
            "enable_tight_strings": True,
            "enable_decoded_strings": True,
        },
        "strings": strings
        if strings is not None
        else {
            "static_strings": [
                {"string": "https://example.invalid/c2", "offset": 4096},
                {"string": "kernel32.dll", "offset": 4100},
            ],
            "stack_strings": [
                {
                    "string": "VirtualAllocEx",
                    "address": 4198400,
                    "encoding": "ASCII",
                }
            ],
            "decoded_strings": [
                {
                    "string": "cmd.exe /c whoami",
                    "decoded_at": 4202496,
                    "tags": ["#decoded"],
                }
            ],
        },
        "layout": {},
    }


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ\x00\x00test fixture")
    return path


def test_build_command_uses_json_and_minimum_length(tmp_path: Path) -> None:
    command = FlossConfig(min_string_length=8).build_command(
        tmp_path / "sample.exe"
    )

    assert command[:3] == ("floss", "-j", "-n")
    assert command[3] == "8"
    assert command[-2] == "--"
    assert command[-1].endswith("sample.exe")


def test_parse_report_extracts_string_groups_and_metadata() -> None:
    parsed = parse_floss_report(_report())

    assert parsed.file_type == "UNKNOWN"
    assert parsed.floss_version == "3.1.0"
    assert parsed.sha256 == "a" * 64
    assert parsed.string_counts == {
        "static_strings": 2,
        "stack_strings": 1,
        "decoded_strings": 1,
    }
    assert len(parsed.strings) == 4
    assert parsed.strings[-1].decoded_at == 4202496


def test_parse_report_deduplicates_identical_string_observations() -> None:
    parsed = parse_floss_report(
        _report(
            strings={
                "static_strings": [
                    {"string": "same", "offset": 10},
                    {"string": "same", "offset": 10},
                ]
            }
        )
    )

    assert parsed.string_counts == {"static_strings": 1}
    assert len(parsed.strings) == 1


def test_analyze_success_returns_string_evidence_without_running_sample(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)
    calls: list[tuple[tuple[str, ...], dict]] = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(_report()),
            stderr="",
        )

    monkeypatch.setattr(floss_module.subprocess, "run", fake_run)
    result = FlossAnalyzer(FlossConfig(executable="floss")).analyze(
        sample,
        raw_reference="reports/floss/sample.json",
    )

    assert result.status is FlossStatus.SUCCESS
    assert result.floss_version == "3.1.0"
    assert len(result.strings) == 4
    evidence = result.to_evidence()
    assert evidence[0].source == "FLOSS"
    assert evidence[0].category == "STRING_SUMMARY"
    assert any(item.category == "OBFUSCATED_STRING" for item in evidence)
    assert any(
        item.details.get("string") == "https://example.invalid/c2"
        for item in evidence
    )
    assert all(not item.attack_techniques for item in evidence)
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 120.0


def test_timeout_is_not_malicious_evidence(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr="timed out")

    monkeypatch.setattr(floss_module.subprocess, "run", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.TIMEOUT
    assert result.errors
    assert result.to_evidence() == []


def test_missing_floss_executable_is_environment_mismatch(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        raise FileNotFoundError("floss")

    monkeypatch.setattr(floss_module.subprocess, "run", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.ENVIRONMENT_MISMATCH
    assert result.to_evidence() == []


def test_invalid_json_is_parse_error(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="not json", stderr="")

    monkeypatch.setattr(floss_module.subprocess, "run", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.errors
    assert result.to_evidence() == []
