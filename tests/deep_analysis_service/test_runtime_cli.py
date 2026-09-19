"""Runtime wiring and CLI checks without real AWS, tools, credentials, or LLM."""

from __future__ import annotations

import json
import signal
from types import SimpleNamespace

import pytest
from botocore.exceptions import NoCredentialsError

from trust_triage.deep_analysis import service_cli as cli
from trust_triage.deep_analysis import service_runtime as runtime
from trust_triage.deep_analysis.llm_interpreter import MonoGPTConfig
from trust_triage.deep_analysis.orchestrator import DeepAnalysisOrchestrator
from trust_triage.deep_analysis.service import DeepAnalysisService
from trust_triage.deep_analysis.service_models import (
    DeepAnalysisRecord,
    DeepAnalysisRequest,
)
from trust_triage.speakeasy_worker.config import WorkerConfig


@pytest.fixture
def runtime_setup(monkeypatch, tmp_path):
    for name in tuple(runtime.os.environ):
        if name.startswith(("DEEP_", "CAPA_", "FLOSS_")):
            monkeypatch.delenv(name)
    config = WorkerConfig(
        region="ap-northeast-2",
        queue_url="https://sqs.example/requests",
        dlq_url="https://sqs.example/dead",
        database_url="postgresql://unused",
        s3_bucket="triage-test",
        temp_root=str(tmp_path),
    )
    monkeypatch.setattr(
        runtime.MonoGPTConfig, "from_env", lambda **kw: MonoGPTConfig(enabled=False)
    )
    publisher = SimpleNamespace(repository=object())
    monkeypatch.setattr(runtime, "create_publisher", lambda _: publisher)
    s3 = object()
    monkeypatch.setattr(runtime.boto3, "client", lambda *a, **kw: s3)
    return config, publisher


def test_runtime_wires_service_and_shared_worker_repository(runtime_setup):
    config, publisher = runtime_setup
    built = runtime.create_deep_analysis_runtime(config)
    assert built.worker_repository is publisher.repository
    assert built.service.publisher is publisher
    assert built.service.orchestrator.capa_analyzer.config.timeout_seconds == 120
    assert built.service.orchestrator.floss_analyzer.config.timeout_seconds == 120
    assert not built.service.orchestrator.llm_interpreter.config.is_configured


@pytest.mark.parametrize(
    "name,value",
    [
        ("DEEP_CAPA_TIMEOUT_SECONDS", "nan"),
        ("DEEP_FLOSS_TIMEOUT_SECONDS", "0"),
        ("DEEP_LEASE_SECONDS", "2.5"),
        ("DEEP_OPERATION_TIMEOUT_SECONDS", "300"),
        ("CAPA_EXECUTABLE", " "),
    ],
)
def test_runtime_rejects_invalid_limits_before_connecting(
    runtime_setup, monkeypatch, name, value
):
    config, _ = runtime_setup
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        runtime, "create_publisher", lambda _: pytest.fail("must validate first")
    )
    with pytest.raises(ValueError):
        runtime.create_deep_analysis_runtime(config)


def test_runtime_budget_includes_enabled_llm(runtime_setup, monkeypatch):
    config, _ = runtime_setup
    monkeypatch.setattr(
        runtime.MonoGPTConfig,
        "from_env",
        lambda **kw: MonoGPTConfig(
            api_key="dummy",
            base_url="https://invalid.example",
            model="test",
            timeout_seconds=180,
        ),
    )
    with pytest.raises(ValueError, match="timeouts combined"):
        runtime.create_deep_analysis_runtime(config)


@pytest.fixture
def cli_setup(monkeypatch):
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
    request = DeepAnalysisRequest(
        analysis_id="cli-1",
        sha256="a" * 64,
        file_location="s3://triage-test/raw/a.bin",
        initial_route="DEEP_ANALYSIS",
        initial_verdict="UNKNOWN",
    )
    record = DeepAnalysisRecord(request, "b" * 64)
    return request, record


def test_cli_get_needs_database_only(cli_setup, monkeypatch, capsys):
    _, record = cli_setup
    monkeypatch.setattr(
        cli,
        "PostgresDeepAnalysisRepository",
        lambda _: SimpleNamespace(get=lambda _: record),
    )
    monkeypatch.setattr(
        cli,
        "create_deep_analysis_runtime",
        lambda: pytest.fail("read-only get must not build tools"),
    )
    assert cli.main(["get", "cli-1"]) == 0
    assert json.loads(capsys.readouterr().out)["analysis_id"] == "cli-1"


def test_cli_register_does_not_run_static(cli_setup, monkeypatch, tmp_path, capsys):
    request, record = cli_setup
    calls = []
    service = SimpleNamespace(register=lambda item: (calls.append(item), record)[1])
    monkeypatch.setattr(
        cli, "create_deep_analysis_runtime", lambda: SimpleNamespace(service=service)
    )
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request.to_dict()), encoding="utf-8")
    assert cli.main(["start", str(request_path), "--enqueue-only"]) == 0
    assert calls == [request]
    assert json.loads(capsys.readouterr().out)["status"] == "QUEUED"


def test_cli_once_processes_pending_without_ui(cli_setup, monkeypatch, capsys):
    _, record = cli_setup
    calls = []
    built = SimpleNamespace(
        check=lambda: calls.append("check"),
        service=SimpleNamespace(
            resume_ready=lambda limit, **kw: (calls.append(limit), [record])[1]
        ),
    )
    monkeypatch.setattr(cli, "create_deep_analysis_runtime", lambda: built)
    assert cli.main(["run", "--once", "--limit", "2"]) == 0
    assert calls == ["check", 2]
    assert len(json.loads(capsys.readouterr().out)["processed"]) == 1


def test_cli_aws_error_is_redacted(cli_setup, monkeypatch, capsys):
    def fail():
        raise NoCredentialsError()

    monkeypatch.setattr(cli, "create_deep_analysis_runtime", fail)
    assert cli.main(["check"]) == 2
    assert "IAM credentials" in capsys.readouterr().err


@pytest.mark.parametrize("stop_signal", [signal.SIGINT, signal.SIGTERM])
def test_cli_stop_finishes_current_job_without_starting_remaining_batch(
    cli_setup, monkeypatch, capsys, stop_signal
):
    _, record = cli_setup
    handlers = {}
    calls = []

    def fake_signal(signum, handler):
        previous = handlers.get(signum, signal.SIG_DFL)
        handlers[signum] = handler
        return previous

    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    monkeypatch.setenv("DEEP_POLL_SECONDS", "0.1")
    service = DeepAnalysisService(
        repository=SimpleNamespace(pending_ids=lambda limit: ["first", "second"]),
        publisher=object(),
        samples=object(),
        orchestrator=DeepAnalysisOrchestrator(),
    )

    def resume(analysis_id):
        calls.append(analysis_id)
        # Invoke the installed callback directly; no OS signal or external process is used.
        handlers[stop_signal](stop_signal, None)
        return record

    monkeypatch.setattr(service, "resume", resume)
    built = SimpleNamespace(service=service)
    assert cli._run(built, once=True, limit=2) == 0
    assert calls == ["first"]
    assert len(json.loads(capsys.readouterr().out)["processed"]) == 1
    assert handlers == {signal.SIGINT: signal.SIG_DFL, signal.SIGTERM: signal.SIG_DFL}


def test_resume_ready_without_stop_callback_preserves_existing_batch_api(
    cli_setup, monkeypatch
):
    _, record = cli_setup
    calls = []
    service = DeepAnalysisService(
        repository=SimpleNamespace(pending_ids=lambda limit: ["first", "second"]),
        publisher=object(),
        samples=object(),
        orchestrator=DeepAnalysisOrchestrator(),
    )
    monkeypatch.setattr(
        service, "resume", lambda analysis_id: (calls.append(analysis_id), record)[1]
    )
    assert service.resume_ready(2) == [record, record]
    assert calls == ["first", "second"]


def test_backend_init_db_deep_initializes_all_tables_in_backend_database(
    monkeypatch, capsys
):
    from trust_triage.backend_api import __main__ as backend_cli
    from trust_triage.backend_api import runtime as backend_runtime
    from trust_triage.backend_api.config import BackendConfig
    from trust_triage.deep_analysis import service_repository
    from trust_triage.speakeasy_worker import repository as worker_repository

    calls = []
    dsn = "postgresql://test-only/backend"
    monkeypatch.setattr(
        BackendConfig, "from_env", lambda: BackendConfig(database_url=dsn)
    )
    monkeypatch.setattr(
        backend_runtime,
        "create_service",
        lambda config: SimpleNamespace(
            repository=SimpleNamespace(
                initialize=lambda: calls.append(("backend", config.database_url))
            )
        ),
    )
    monkeypatch.setattr(
        worker_repository,
        "PostgresJobRepository",
        lambda value: SimpleNamespace(
            initialize=lambda: calls.append(("worker", value))
        ),
    )
    monkeypatch.setattr(
        service_repository,
        "PostgresDeepAnalysisRepository",
        lambda value: SimpleNamespace(initialize=lambda: calls.append(("deep", value))),
    )
    monkeypatch.setattr(
        runtime,
        "create_deep_analysis_runtime",
        lambda: pytest.fail("DB setup must not construct remote clients"),
    )
    assert backend_cli.main(["init-db", "--deep"]) == 0
    assert calls == [("backend", dsn), ("worker", dsn), ("deep", dsn)]
    assert json.loads(capsys.readouterr().out)["status"] == "initialized"
