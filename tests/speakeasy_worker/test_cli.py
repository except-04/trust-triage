from __future__ import annotations

import json

import pytest
from botocore.exceptions import ProxyConnectionError

from trust_triage.speakeasy_worker import cli
from trust_triage.speakeasy_worker.publisher import JobPublisher

from .fakes import MemoryQueue, MemoryRepository


@pytest.fixture(autouse=True)
def ignore_local_environment_file(monkeypatch):
    monkeypatch.setattr(cli, "load_dotenv", lambda *args, **kwargs: None)


def test_init_db_needs_no_aws_configuration(monkeypatch, capsys):
    calls = []

    class Repository:
        def __init__(self, dsn):
            assert dsn == "test-database"

        def initialize(self):
            calls.append("initialize")

    def no_aws():
        pytest.fail("init-db must not initialize AWS")

    monkeypatch.setenv("WORKER_DATABASE_URL", "test-database")
    monkeypatch.setattr(cli, "PostgresJobRepository", Repository)
    monkeypatch.setattr(cli.WorkerConfig, "from_env", no_aws)
    assert cli.main(["init-db"]) == 0
    assert calls == ["initialize"]
    assert "ready" in capsys.readouterr().out


def test_aws_initialization_error_does_not_print_credentials(monkeypatch, capsys):
    def unavailable(config):
        raise ProxyConnectionError(proxy_url="https://user:private-password@proxy.test")

    monkeypatch.setattr(cli.WorkerConfig, "from_env", lambda: object())
    monkeypatch.setattr(cli, "create_runtime", unavailable)
    assert cli.main(["check"]) == 2
    output = capsys.readouterr()
    assert "IAM credentials" in output.err
    assert "private-password" not in output.err
    assert "Traceback" not in output.err


def test_enqueue_accepts_windows_utf8_bom_without_exposing_location(
    monkeypatch, tmp_path, capsys, job
):
    repository, queue = MemoryRepository(), MemoryQueue()
    message_file = tmp_path / "job.json"
    message_file.write_text(job.to_json(), encoding="utf-8-sig")
    monkeypatch.setattr(cli.WorkerConfig, "from_env", lambda: object())
    monkeypatch.setattr(
        cli, "create_publisher", lambda config: JobPublisher(repository, queue)
    )
    assert cli.main(["enqueue", str(message_file)]) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["analysis_id"] == job.analysis_id
    assert record["status"] == "QUEUED"
    assert "file_location" not in record
    assert queue.receive().body == job.to_json()
