from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

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


def _static_report(sample: Path) -> dict:
    report = _report(strings={"static_strings": [
        {"string": "https://example.invalid/static", "offset": 4096}
    ]})
    report["metadata"]["sha256"] = floss_module.sha256_file(sample)
    report["analysis"].update(
        enable_stack_strings=False,
        enable_tight_strings=False,
        enable_decoded_strings=False,
        enable_language_strings=False,
    )
    return report


def test_build_command_uses_json_and_minimum_length(tmp_path: Path) -> None:
    command = FlossConfig(min_string_length=8).build_command(tmp_path / "sample.exe")

    assert command[:3] == ("floss", "-j", "-n")
    assert command[3] == "8"
    assert command[-2] == "--"
    assert command[-1].endswith("sample.exe")


def test_static_only_command_drops_conflicting_extra_args(tmp_path: Path) -> None:
    command = FlossConfig(extra_args=("--string-type", "decoded")).build_command(
        tmp_path / "sample.exe", static_only=True
    )

    assert command == (
        "floss", "-j", "--only", "static", "--language", "none", "--",
        str(tmp_path / "sample.exe"),
    )


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
        report = _report()
        report["metadata"]["sha256"] = floss_module.sha256_file(sample)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(report),
            stderr="",
        )

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
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
        item.details.get("string") == "https://example.invalid/c2" for item in evidence
    )
    assert all(not item.attack_techniques for item in evidence)
    assert calls[0][1]["timeout"] == 120.0


def test_file_over_16_mib_uses_static_only_without_full_attempt(
    monkeypatch, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    with sample.open("r+b") as stream:
        stream.truncate(floss_module.DEFAULT_DEOBFUSCATION_LIMIT_BYTES + 1)
    report = _static_report(sample)
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.SUCCESS
    assert len(calls) == 1
    assert calls[0][2:6] == ("--only", "static", "--language", "none")
    assert result.analysis_metadata["limited_mode"] is True
    assert result.analysis_metadata["limited_reason"] == "INPUT_EXCEEDS_16_MIB"
    assert result.analysis_metadata["file_size_bytes"] == 16 * 1024 * 1024 + 1
    assert any("static-only limited mode" in item for item in result.warnings)
    assert result.string_counts == {"static_strings": 1}
    evidence = result.to_evidence()
    assert evidence[0].details["limited_mode"] is True
    assert all(item.category != "OBFUSCATED_STRING" for item in evidence)


def test_exactly_16_mib_keeps_full_floss_mode(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    with sample.open("r+b") as stream:
        stream.truncate(floss_module.DEFAULT_DEOBFUSCATION_LIMIT_BYTES)
    report = _report()
    report["metadata"]["sha256"] = floss_module.sha256_file(sample)
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.SUCCESS
    assert len(calls) == 1
    assert "--only" not in calls[0]
    assert result.analysis_metadata.get("limited_mode") is None


def test_deobfuscation_size_rejection_retries_static_only_with_remaining_budget(
    monkeypatch, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    report = _static_report(sample)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs["timeout"]))
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 1, stdout="",
                stderr='{"error": "cannot deobfuscate strings from files larger than 0x1000000 bytes"}',
            )
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.SUCCESS
    assert len(calls) == 2
    assert "--only" not in calls[0][0]
    assert calls[1][0][2:6] == ("--only", "static", "--language", "none")
    assert 0 < calls[1][1] <= calls[0][1]
    assert result.analysis_metadata["limited_reason"] == "FLOSS_DEOBFUSCATION_SIZE_ERROR"
    assert result.analysis_metadata["deobfuscation_threshold_bytes"] == 16 * 1024 * 1024
    assert any("static-only limited mode" in item for item in result.warnings)


def test_newer_floss_cli_retries_static_selection_with_supported_option(
    monkeypatch, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    report = _static_report(sample)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs["timeout"]))
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 1, stdout="",
                stderr="cannot deobfuscate strings from files larger than 0x1000000 bytes",
            )
        if len(calls) == 2:
            return subprocess.CompletedProcess(
                command, 1, stdout="floss: error: unrecognized arguments: --only static",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.SUCCESS
    assert len(calls) == 3
    assert calls[1][0][2:6] == ("--only", "static", "--language", "none")
    assert calls[2][0][-4:-2] == ("--string-type", "static")
    assert 0 < calls[2][1] <= calls[1][1] <= calls[0][1]
    assert result.analysis_metadata["limited_reason"] == "FLOSS_DEOBFUSCATION_SIZE_ERROR"


def test_static_only_empty_stdout_is_not_assumed_success(
    monkeypatch, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    with sample.open("r+b") as stream:
        stream.truncate(floss_module.DEFAULT_DEOBFUSCATION_LIMIT_BYTES + 1)
    monkeypatch.setattr(
        floss_module,
        "_run_bounded_floss",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="", stderr=""
        ),
    )

    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.to_evidence() == []
    assert result.analysis_metadata["limited_mode"] is True
    assert any("could not parse FLOSS JSON" in error for error in result.errors)


@pytest.mark.parametrize(
    "contradiction", ["enabled_decoder", "decoded_result", "language_enabled"]
)
def test_static_only_report_rejects_contradictory_scope(
    monkeypatch, tmp_path: Path, contradiction: str
) -> None:
    sample = _sample(tmp_path)
    with sample.open("r+b") as stream:
        stream.truncate(floss_module.DEFAULT_DEOBFUSCATION_LIMIT_BYTES + 1)
    report = _static_report(sample)
    if contradiction == "enabled_decoder":
        report["analysis"]["enable_decoded_strings"] = True
    elif contradiction == "decoded_result":
        report["strings"]["decoded_strings"] = [{"string": "unexpected"}]
    else:
        report["analysis"]["enable_language_strings"] = True
    monkeypatch.setattr(
        floss_module,
        "_run_bounded_floss",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(report), stderr=""
        ),
    )

    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.analysis_metadata["limited_mode"] is True
    assert result.to_evidence() == []


def test_failed_static_only_retry_keeps_limit_diagnostic_without_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        error = (
            "cannot deobfuscate strings from files larger than 0x1000000 bytes"
            if len(calls) == 1 else "static extraction failed"
        )
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=error)

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.TOOL_ERROR
    assert len(calls) == 2
    assert result.analysis_metadata["limited_mode"] is True
    assert any("static-only limited mode" in item for item in result.warnings)
    assert result.to_evidence() == []


def test_other_floss_failure_is_not_retried(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="unsupported file format"
        )

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert len(calls) == 1
    assert result.status is FlossStatus.UNSUPPORTED
    assert result.analysis_metadata.get("limited_mode") is None


def test_report_hash_mismatch_is_rejected_without_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)
    report = _report()
    report["metadata"]["sha256"] = "f" * 64
    monkeypatch.setattr(
        floss_module,
        "_run_bounded_floss",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(report), stderr=""
        ),
    )

    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.to_evidence() == []
    assert any("SHA-256" in error for error in result.errors)


def test_supported_report_without_hash_is_accepted_with_warning(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)
    report = _report()
    report["metadata"].pop("sha256")
    monkeypatch.setattr(
        floss_module,
        "_run_bounded_floss",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(report), stderr=""
        ),
    )

    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.SUCCESS
    assert any("did not include SHA-256" in warning for warning in result.warnings)


def test_timeout_is_not_malicious_evidence(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr="timed out")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
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

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.ENVIRONMENT_MISMATCH
    assert result.to_evidence() == []


def test_invalid_json_is_parse_error(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="not json", stderr="")

    monkeypatch.setattr(floss_module, "_run_bounded_floss", fake_run)
    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.errors
    assert result.to_evidence() == []


def test_empty_json_object_is_not_a_floss_report(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    monkeypatch.setattr(
        floss_module,
        "_run_bounded_floss",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout="{}", stderr=""
        ),
    )

    result = FlossAnalyzer().analyze(sample)

    assert result.status is FlossStatus.PARSE_ERROR
    assert result.to_evidence() == []
