from __future__ import annotations

import json
import subprocess
from pathlib import Path

from trust_triage.static_analysis import (
    CapaAnalyzer,
    CapaBackend,
    CapaConfig,
    CapaStatus,
    parse_capa_report,
)
from trust_triage.static_analysis import capa_analyzer as capa_module


def _report(*, rules: dict | None = None) -> dict:
    return {
        "meta": {
            "version": "9.4.0",
            "analysis": {
                "format": "pe",
                "arch": "amd64",
                "os": "windows",
                "extractor": "vivisect",
            },
            "sample": {"path": "sample.exe"},
        },
        "rules": rules
        if rules is not None
        else {
            "create service": {
                "meta": {
                    "name": "create service",
                    "namespace": "persistence/service",
                    "att&ck": ["Persistence::Create or Modify System Process"],
                    "mbc": ["Persistence::Service"],
                    "description": "Creates a service.",
                },
                "matches": ["0x401000", "0x402000"],
            }
        },
    }


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ\x00\x00test fixture")
    return path


def test_default_and_ghidra_commands_are_explicit(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    default_command = CapaConfig().build_command(sample)
    ghidra_command = CapaConfig(backend=CapaBackend.GHIDRA).build_command(sample)
    module_command = CapaConfig(
        executable="python",
        executable_args=("-m", "capa.main"),
    ).build_command(sample)

    assert "-b" not in default_command
    assert "-j" in default_command
    assert ghidra_command[:3] == ("capa", "-b", "ghidra")
    assert ghidra_command[-1] == str(sample)
    assert module_command[:3] == ("python", "-m", "capa.main")


def test_parse_report_preserves_capability_metadata() -> None:
    parsed = parse_capa_report(_report())

    assert parsed.file_type == "PE"
    assert parsed.capa_version == "9.4.0"
    assert len(parsed.capabilities) == 1
    capability = parsed.capabilities[0]
    assert capability.rule_name == "create service"
    assert capability.namespace == "persistence/service"
    assert capability.match_count == 2
    assert capability.attack == ("Persistence::Create or Modify System Process",)


def test_analyze_success_returns_evidence_without_running_sample(
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

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer(
        CapaConfig(executable="capa", rules_version="v9.4.0")
    ).analyze(
        sample,
        raw_reference="reports/capa/sample.json",
    )

    assert result.status is CapaStatus.SUCCESS
    assert result.file_type == "PE"
    assert result.rules_version == "v9.4.0"
    assert result.analysis_metadata["execution_mode"] == "external_process"
    assert len(result.capabilities) == 1
    assert len(result.to_evidence()) == 1
    evidence = result.to_evidence()[0].to_dict()
    assert evidence["source"] == "CAPA"
    assert evidence["category"] == "CAPABILITY_MATCH"
    assert evidence["raw_reference"] == "reports/capa/sample.json"
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 120.0


def test_ghidra_backend_sets_installation_environment(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)
    ghidra_dir = tmp_path / "ghidra"
    ghidra_dir.mkdir()
    captured: dict = {}

    def fake_run(command, **kwargs):
        captured["command"] = tuple(command)
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(_report(rules={})),
            stderr="",
        )

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer(
        CapaConfig(
            backend=CapaBackend.GHIDRA,
            ghidra_install_dir=ghidra_dir,
        )
    ).analyze(sample)

    assert result.status is CapaStatus.SUCCESS
    assert captured["command"][1:3] == ("-b", "ghidra")
    assert captured["env"]["GHIDRA_INSTALL_DIR"] == str(ghidra_dir)
    assert result.capabilities == []
    assert result.to_evidence() == []


def test_timeout_is_not_malicious_evidence(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr="timed out")

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer().analyze(sample)

    assert result.status is CapaStatus.TIMEOUT
    assert result.errors
    assert result.to_evidence() == []


def test_missing_capa_executable_is_environment_mismatch(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        raise FileNotFoundError("capa")

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer().analyze(sample)

    assert result.status is CapaStatus.ENVIRONMENT_MISMATCH
    assert result.to_evidence() == []


def test_invalid_input_does_not_start_external_process(monkeypatch, tmp_path: Path) -> None:
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("CAPA must not run for a missing input")

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer().analyze(tmp_path / "missing.exe")

    assert result.status is CapaStatus.INVALID_INPUT
    assert called is False


def test_invalid_json_is_parse_error(monkeypatch, tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="not json", stderr="")

    monkeypatch.setattr(capa_module.subprocess, "run", fake_run)
    result = CapaAnalyzer().analyze(sample)

    assert result.status is CapaStatus.PARSE_ERROR
    assert result.errors
    assert result.to_evidence() == []
