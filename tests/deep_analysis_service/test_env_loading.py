"""An explicit service environment must not fall back to another dotenv file."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from trust_triage.deep_analysis import llm_interpreter as llm
from trust_triage.deep_analysis import service_cli as cli
from trust_triage.deep_analysis import service_runtime as runtime
from trust_triage.deep_analysis.service_models import (
    DeepAnalysisRecord,
    DeepAnalysisRequest,
)
from trust_triage.speakeasy_worker.config import WorkerConfig


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    # Remove inherited settings and replace every dotenv loader before any config is read.
    for name in tuple(os.environ):
        if name.startswith(
            ("MONOGPT_", "LLM_", "DEEP_", "WORKER_", "CAPA_", "FLOSS_", "SQS_", "AWS_")
        ):
            monkeypatch.delenv(name)
    monkeypatch.setattr(
        llm, "load_dotenv", lambda: pytest.fail("unexpected default dotenv loading")
    )
    monkeypatch.setattr(
        cli,
        "load_dotenv",
        lambda *args, **kwargs: pytest.fail("unexpected CLI dotenv loading"),
    )


def test_legacy_llm_config_still_loads_default_environment_when_requested(monkeypatch):
    calls = []

    def fake_default_loader():
        calls.append("default")
        monkeypatch.setenv("MONOGPT_API_KEY", "fake-test-key")
        monkeypatch.setenv("MONOGPT_BASE_URL", "https://example.invalid")
        monkeypatch.setenv("MONOGPT_MODEL", "fake-model")

    monkeypatch.setattr(llm, "load_dotenv", fake_default_loader)
    config = llm.MonoGPTConfig.from_env()
    assert calls == ["default"]
    assert config.is_configured
    assert config.model == "fake-model"


def test_llm_config_can_read_process_environment_without_loading_dotenv(monkeypatch):
    monkeypatch.setenv("MONOGPT_API_KEY", "fake-process-key")
    monkeypatch.setenv("MONOGPT_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("MONOGPT_MODEL", "process-model")
    config = llm.MonoGPTConfig.from_env(load_env_file=False)
    assert config.is_configured
    assert config.model == "process-model"


def test_empty_process_environment_does_not_enable_llm_from_default_file():
    config = llm.MonoGPTConfig.from_env(load_env_file=False)
    assert not config.enabled
    assert not config.is_configured
    assert config.api_key == ""


def _stub_remote_dependencies(monkeypatch):
    monkeypatch.setattr(
        runtime, "create_publisher", lambda _: SimpleNamespace(repository=object())
    )
    monkeypatch.setattr(runtime.boto3, "client", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        runtime,
        "PostgresDeepAnalysisRepository",
        lambda _: SimpleNamespace(
            register=lambda request, fingerprint: DeepAnalysisRecord(
                request, fingerprint
            ),
        ),
    )


def test_runtime_does_not_load_an_implicit_dotenv(monkeypatch, tmp_path):
    _stub_remote_dependencies(monkeypatch)
    config = WorkerConfig(
        region="ap-northeast-2",
        queue_url="https://sqs.example/requests",
        dlq_url="https://sqs.example/dead",
        database_url="postgresql://unused",
        s3_bucket="triage-test",
        temp_root=str(tmp_path),
    )
    built = runtime.create_deep_analysis_runtime(config)
    assert not built.service.orchestrator.llm_interpreter.config.enabled
    assert not built.service.orchestrator.llm_interpreter.config.is_configured


def test_cli_selected_environment_does_not_fall_back_to_default_llm_file(
    monkeypatch, tmp_path, capsys
):
    _stub_remote_dependencies(monkeypatch)
    selected_loads = []
    implicit_loads = []

    def selected_loader(path, *, override):
        selected_loads.append((path, override))
        # Simulate the selected service-only file, without reading a real .env.
        for name, value in {
            "AWS_REGION": "ap-northeast-2",
            "SQS_QUEUE_URL": "https://sqs.example/requests",
            "SQS_DLQ_URL": "https://sqs.example/dead",
            "WORKER_DATABASE_URL": "postgresql://unused",
            "WORKER_S3_BUCKET": "triage-test",
            "WORKER_TEMP_DIR": str(tmp_path),
        }.items():
            monkeypatch.setenv(name, value)

    def implicit_loader():
        implicit_loads.append("default")
        monkeypatch.setenv("MONOGPT_API_KEY", "unexpected-fake-key")
        monkeypatch.setenv("MONOGPT_BASE_URL", "https://example.invalid")
        monkeypatch.setenv("MONOGPT_MODEL", "unexpected-model")

    monkeypatch.setattr(cli, "load_dotenv", selected_loader)
    monkeypatch.setattr(llm, "load_dotenv", implicit_loader)
    request = DeepAnalysisRequest(
        analysis_id="env-test-1",
        sha256="a" * 64,
        file_location="s3://triage-test/raw/sample.bin",
        initial_route="DEEP_ANALYSIS",
    )
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request.to_dict()), encoding="utf-8")
    assert (
        cli.main(
            [
                "--env-file",
                "selected-test.env",
                "start",
                str(request_path),
                "--enqueue-only",
            ]
        )
        == 0
    )
    assert selected_loads == [("selected-test.env", False)]
    assert implicit_loads == []
    assert "MONOGPT_API_KEY" not in os.environ
    assert json.loads(capsys.readouterr().out)["status"] == "QUEUED"
