"""Bounded FLOSS transport with harmless Python child processes."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from trust_triage.static_analysis import floss_analyzer as floss_module
from trust_triage.static_analysis.floss_analyzer import (
    FlossAnalyzer,
    FlossConfig,
    FlossOutputLimitExceeded,
    FlossStatus,
    _run_bounded_floss,
)


def _child(tmp_path: Path, body: str) -> tuple[str, ...]:
    script = tmp_path / "harmless_child.py"
    script.write_text(body, encoding="utf-8")
    return (sys.executable, str(script))


def _capture_processes(monkeypatch):
    created = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        process = original(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(floss_module.subprocess, "Popen", capture)
    return created


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_oversized_output_kills_child_and_next_run_succeeds(
    monkeypatch, tmp_path: Path, stream_name: str
) -> None:
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDOUT_BYTES", 4096)
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDERR_BYTES", 4096)
    created = _capture_processes(monkeypatch)
    descriptor = 1 if stream_name == "stdout" else 2
    command = _child(
        tmp_path,
        "import os, time\n"
        f"os.write({descriptor}, b'x' * 200000)\n"
        "time.sleep(30)\n",
    )

    with pytest.raises(FlossOutputLimitExceeded) as error:
        _run_bounded_floss(command, cwd=None, env=os.environ, timeout=5)

    assert error.value.stream_name == stream_name
    assert error.value.limit_bytes == 4096
    assert created[0].poll() is not None
    assert not any(thread.name.startswith("floss-") for thread in threading.enumerate())

    next_command = _child(tmp_path, "print('{}')\n")
    next_result = _run_bounded_floss(
        next_command, cwd=None, env=os.environ, timeout=5
    )
    assert next_result.returncode == 0
    assert next_result.stdout.strip() == "{}"
    assert created[1].poll() is not None


def test_simultaneous_output_is_drained_without_deadlock(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDOUT_BYTES", 4096)
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDERR_BYTES", 4096)
    created = _capture_processes(monkeypatch)
    command = _child(
        tmp_path,
        "import os, threading, time\n"
        "threading.Thread(target=lambda: os.write(1, b'x' * 200000)).start()\n"
        "threading.Thread(target=lambda: os.write(2, b'y' * 200000)).start()\n"
        "time.sleep(30)\n",
    )

    with pytest.raises(FlossOutputLimitExceeded):
        _run_bounded_floss(command, cwd=None, env=os.environ, timeout=5)

    assert created[0].poll() is not None
    assert not any(thread.name.startswith("floss-") for thread in threading.enumerate())


def test_timeout_kills_child_and_next_run_succeeds(monkeypatch, tmp_path: Path) -> None:
    created = _capture_processes(monkeypatch)
    command = _child(tmp_path, "import time\ntime.sleep(30)\n")

    with pytest.raises(subprocess.TimeoutExpired):
        _run_bounded_floss(command, cwd=None, env=os.environ, timeout=0.25)

    assert created[0].poll() is not None
    next_command = _child(tmp_path, "print('{}')\n")
    result = _run_bounded_floss(next_command, cwd=None, env=os.environ, timeout=5)
    assert result.stdout.strip() == "{}"
    assert created[1].poll() is not None


def test_exact_output_limit_is_accepted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDOUT_BYTES", 4096)
    command = _child(tmp_path, "import os\nos.write(1, b'x' * 4096)\n")

    result = _run_bounded_floss(command, cwd=None, env=os.environ, timeout=5)

    assert result.returncode == 0
    assert len(result.stdout.encode("utf-8")) == 4096


def test_analyzer_records_output_limit_as_failure_without_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(floss_module, "MAX_FLOSS_STDOUT_BYTES", 4096)
    sample = tmp_path / "harmless_sample.exe"
    sample.write_bytes(b"MZ fixture")
    command = _child(tmp_path, "import os\nos.write(1, b'x' * 200000)\n")
    analyzer = FlossAnalyzer(FlossConfig(
        executable=command[0], executable_args=(command[1],), timeout_seconds=5
    ))

    result = analyzer.analyze(sample)

    assert result.status is FlossStatus.TOOL_ERROR
    assert any("stdout exceeded" in error for error in result.errors)
    assert result.to_evidence() == []
