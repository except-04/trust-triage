"""환경변수·CLI 조립은 외부 연결과 실제 모델 로딩 없이 검증한다."""

from __future__ import annotations

import json
import signal
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from trust_triage.backend_api import __main__ as cli
from trust_triage.backend_api import runtime
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.model_bundle import ModelBundleConfig


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith(("BACKEND_", "WORKER_", "AWS_")):
            monkeypatch.delenv(name)


def test_defaults_and_environment(monkeypatch):
    config = BackendConfig.from_env()
    assert config.storage_mode == "local" and config.host == "127.0.0.1"
    monkeypatch.setenv("BACKEND_MAX_BATCH_FILES", "3")
    monkeypatch.setenv("BACKEND_MAX_FILE_BYTES", "2048")
    monkeypatch.setenv("BACKEND_API_TOKEN", "private-token" * 3)
    actual = BackendConfig.from_env()
    assert actual.max_batch_files == 3 and actual.max_file_bytes == 2048
    assert "private-token" not in repr(actual)


@pytest.mark.parametrize(
    "key,value",
    [
        ("BACKEND_MAX_BATCH_FILES", "NaN"),
        ("BACKEND_MAX_BATCH_FILES", "2.5"),
        ("BACKEND_MAX_FILE_BYTES", "0"),
        ("BACKEND_PORT", "65536"),
        ("BACKEND_HOST", "0.0.0.0"),
        ("BACKEND_API_TOKEN", "short"),
        ("BACKEND_OPERATION_TIMEOUT_SECONDS", "901"),
        ("BACKEND_HEARTBEAT_SECONDS", "500"),
        ("BACKEND_STORAGE_MODE", "other"),
        ("BACKEND_STORAGE_MODE", "s3"),
        ("BACKEND_RETENTION_HOURS", "721"),
    ],
)
def test_invalid_environment_rejected(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        BackendConfig.from_env()


def test_artifact_settings_and_total_stage_budget(monkeypatch, tmp_path):
    for field in ModelBundleConfig.__dataclass_fields__:
        monkeypatch.setenv("BACKEND_" + field.upper(), str(tmp_path / field))
    monkeypatch.setenv("BACKEND_SHAP_TOP_K", "12")
    config = runtime.initial_config(BackendConfig())
    assert config.shap_top_k == 12
    assert Path(config.artifacts.lgbm_path).name == "lgbm_path"
    with pytest.raises(ValueError, match="combined"):
        runtime.initial_config(replace(BackendConfig(), operation_timeout_seconds=300))


def test_create_service_local_wires_no_network(monkeypatch, tmp_path):
    captured = []
    monkeypatch.setattr(
        runtime,
        "PostgresAnalysisRepository",
        lambda dsn: captured.append(dsn) or object(),
    )
    config = BackendConfig(database_url="fake-test-connection", storage_root=tmp_path)
    service = runtime.create_service(config)
    assert service.storage.root == tmp_path and captured == ["fake-test-connection"]
    processor = runtime.create_processor(service)
    assert (
        processor.repository is service.repository
        and processor.storage is service.storage
    )


def test_unconfigured_database_is_explicit():
    with pytest.raises(BackendError, match="BACKEND_DATABASE_URL") as caught:
        runtime.create_service(BackendConfig())
    assert caught.value.code == "DATABASE_NOT_CONFIGURED"


def test_check_basic_and_optional_dependencies(monkeypatch):
    calls = []
    service = SimpleNamespace(
        repository=SimpleNamespace(check=lambda: calls.append("db")),
        storage=SimpleNamespace(check=lambda: calls.append("storage")),
        config=BackendConfig(),
    )
    assert runtime.check(service)["status"] == "ready"
    assert calls == ["db", "storage"]
    with pytest.raises(BackendError) as caught:
        runtime.check(service, analysis=True)
    assert caught.value.code == "MODEL_NOT_CONFIGURED"


def test_explicit_env_file_only_and_shell_environment_wins(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("BACKEND_PORT=1\n", encoding="utf-8")
    chosen = tmp_path / "chosen.env"
    chosen.write_text(
        "BACKEND_PORT=8080\nBACKEND_DATABASE_URL=for-test\n", encoding="utf-8"
    )
    captured = []
    service = SimpleNamespace(repository=SimpleNamespace(initialize=lambda: None))
    monkeypatch.setattr(
        runtime, "create_service", lambda config: captured.append(config) or service
    )
    assert cli.main(["init-db"]) == 0
    assert captured[-1].port == 8000
    monkeypatch.setenv("BACKEND_PORT", "9000")
    assert cli.main(["--env-file", str(chosen), "init-db"]) == 0
    assert captured[-1].port == 9000 and captured[-1].database_url == "for-test"
    assert "for-test" not in capsys.readouterr().out


def test_export_openapi_needs_no_database_or_model(monkeypatch, tmp_path):
    def forbidden(_config):
        pytest.fail("OpenAPI export must not create DB/storage connections")

    monkeypatch.setattr(runtime, "create_service", forbidden)
    target = tmp_path / "openapi.json"
    assert cli.main(["export-openapi", "--output", str(target)]) == 0
    assert "/analyses" in json.loads(target.read_text(encoding="utf-8"))["paths"]


def test_cli_errors_never_print_dsn_or_exception(monkeypatch, capsys):
    def broken(_config):
        raise RuntimeError("password=SECRET internal-network")

    monkeypatch.setattr(runtime, "create_service", broken)
    assert cli.main(["check"]) == 1
    output = capsys.readouterr().out
    assert "SECRET" not in output and "CONFIGURATION_OR_RUNTIME_ERROR" in output


@pytest.mark.parametrize(
    "command",
    [
        ["run", "--limit", "0"],
        ["cleanup", "--limit", "101"],
        ["--env-file", "missing-test-config.env", "check"],
    ],
)
def test_cli_invalid_limits_or_file_fail_before_connect(monkeypatch, command):
    def forbidden(_config):
        pytest.fail("Invalid config must not connect")

    monkeypatch.setattr(runtime, "create_service", forbidden)
    assert cli.main(command) == 1


def test_run_once_and_cleanup_modes(monkeypatch, capsys):
    calls = []
    service = SimpleNamespace(
        repository=SimpleNamespace(check=lambda: calls.append("check")),
        cleanup=lambda **kwargs: calls.append(kwargs) or {"deleted_ids": []},
    )
    processor = SimpleNamespace(
        resume_ready=lambda limit, *, should_stop: (
            calls.append((limit, should_stop())) or []
        )
    )
    monkeypatch.setattr(runtime, "create_service", lambda config: service)
    monkeypatch.setattr(runtime, "create_processor", lambda service: processor)
    previous = signal.getsignal(signal.SIGINT)
    assert cli.main(["run", "--once", "--limit", "2"]) == 0
    assert signal.getsignal(signal.SIGINT) == previous
    assert (2, False) in calls
    assert cli.main(["cleanup"]) == 0
    assert calls[-1] == {"limit": 100, "delete": False}
    assert cli.main(["cleanup", "--delete", "--limit", "3"]) == 0
    assert calls[-1] == {"limit": 3, "delete": True}
    assert "processed" in capsys.readouterr().out


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_run_stops_and_restores_signal_handlers(monkeypatch, sig):
    service = SimpleNamespace(repository=SimpleNamespace(check=lambda: None))
    callbacks, restored = {}, []

    def install(sig, handler):
        if callable(handler):
            callbacks[sig] = handler
        else:
            restored.append((sig, handler))
        return "original"

    def process(limit, *, should_stop):
        callbacks[sig](sig, None)
        assert should_stop()
        return []

    monkeypatch.setattr(signal, "signal", install)
    monkeypatch.setattr(runtime, "create_service", lambda config: service)
    monkeypatch.setattr(
        runtime,
        "create_processor",
        lambda service: SimpleNamespace(resume_ready=process),
    )
    assert cli.main(["run"]) == 0
    assert (sig, "original") in restored
