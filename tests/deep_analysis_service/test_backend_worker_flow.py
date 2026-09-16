"""HTTP -> real runtime/gateway -> queue Worker -> resumed result, with inert inputs.

Only cloud clients and analysis engines are doubles. PostgreSQL cases reconnect
through the actual repositories; no test executes or emulates a PE.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter, deque
from types import SimpleNamespace
from uuid import uuid4

import boto3
import psycopg
import pytest
from backend_api.fake_repository import MemoryAnalysisRepository
from backend_api.test_service_processor import (
    FakeInitial,
    harmless_pe_header,
    initial_result,
)
from backend_api.test_storage import FakeS3
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo
from speakeasy_worker.fakes import MemoryRepository

from trust_triage.backend_api import runtime as backend_runtime
from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.deep_gateway import ExistingDeepGateway
from trust_triage.deep_analysis import service_runtime as deep_runtime
from trust_triage.deep_analysis.llm_interpreter import MonoGPTClaudeInterpreter
from trust_triage.deep_analysis.models import LLMInterpretation, LLMInterpretationStatus
from trust_triage.deep_analysis.service_repository import PostgresDeepAnalysisRepository
from trust_triage.dynamic_analysis import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
    SpeakeasyAnalyzer,
)
from trust_triage.speakeasy_worker import runtime as worker_runtime
from trust_triage.speakeasy_worker.config import WorkerConfig
from trust_triage.speakeasy_worker.repository import PostgresJobRepository
from trust_triage.speakeasy_worker.worker import Outcome
from trust_triage.static_analysis import CapaAnalyzer, FlossAnalyzer
from trust_triage.static_analysis.floss_analyzer import (
    FlossAnalysisResult,
    FlossStatus,
    FlossString,
)
from trust_triage.static_analysis.models import (
    CapaAnalysisResult,
    CapaBackend,
    CapaCapability,
    CapaStatus,
)
from trust_triage.storage import ArtifactReference

from .fakes import MemoryDeepRepository

QUEUE = "https://sqs.ap-northeast-2.amazonaws.com/123456789012/work"
DLQ = "https://sqs.ap-northeast-2.amazonaws.com/123456789012/dead"
SAMPLE = harmless_pe_header()
SHA = hashlib.sha256(SAMPLE).hexdigest()


class SqsClientDouble:
    def __init__(self):
        self.messages = deque()
        self.sent = []
        self.deleted = []
        self.deferred = []

    def send_message(self, *, QueueUrl, MessageBody):
        assert QueueUrl == QUEUE
        self.sent.append(MessageBody)
        self.messages.append(MessageBody)
        return {"MessageId": str(len(self.sent))}

    def receive_message(self, *, QueueUrl, **kwargs):
        assert QueueUrl == QUEUE
        if not self.messages:
            return {}
        return {
            "Messages": [
                {
                    "Body": self.messages.popleft(),
                    "MessageId": "test-message",
                    "ReceiptHandle": str(uuid4()),
                    "Attributes": {"ApproximateReceiveCount": "1"},
                }
            ]
        }

    def delete_message(self, *, QueueUrl, ReceiptHandle):
        self.deleted.append((QueueUrl, ReceiptHandle))
        return {}

    def change_message_visibility(self, *, QueueUrl, **kwargs):
        self.deferred.append((QueueUrl, kwargs))
        return {}


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def connected(request, monkeypatch, tmp_path):
    database_url = os.getenv("WORKER_TEST_DATABASE_URL")
    use_postgres = request.param == "postgres"
    if use_postgres and not database_url:
        pytest.skip("set WORKER_TEST_DATABASE_URL for PostgreSQL pipeline tests")
    for key in tuple(os.environ):
        if key.startswith(
            (
                "BACKEND_",
                "WORKER_",
                "AWS_",
                "SQS_",
                "DEEP_",
                "CAPA_",
                "FLOSS_",
                "LLM_",
                "MONOGPT_",
            )
        ):
            monkeypatch.delenv(key)

    schema = "worker_flow_" + uuid4().hex
    dsn = "postgresql://unused"
    if use_postgres:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema))
            )
        dsn = make_conninfo(database_url, options=f"-c search_path={schema}")
    else:
        api_repo, worker_repo, deep_repo = (
            MemoryAnalysisRepository(),
            MemoryRepository(),
            MemoryDeepRepository(),
        )
        monkeypatch.setattr(
            backend_runtime, "PostgresAnalysisRepository", lambda _: api_repo
        )
        monkeypatch.setattr(
            worker_runtime, "PostgresJobRepository", lambda _: worker_repo
        )
        monkeypatch.setattr(
            deep_runtime, "PostgresDeepAnalysisRepository", lambda _: deep_repo
        )

    for key, value in {
        "AWS_REGION": "ap-northeast-2",
        "SQS_QUEUE_URL": QUEUE,
        "SQS_DLQ_URL": DLQ,
        "WORKER_DATABASE_URL": dsn,
        "WORKER_S3_BUCKET": "backend-test-only",
        "WORKER_TEMP_DIR": str(tmp_path / "worker"),
        "LLM_ENABLED": "false",
    }.items():
        monkeypatch.setenv(key, value)
    h = SimpleNamespace(
        s3=FakeS3(),
        sqs=SqsClientDouble(),
        calls=Counter(),
        static_sufficient=False,
        dynamic_status=DynamicAnalysisStatus.SUCCESS,
    )

    def cloud_client(service, **kwargs):
        assert service in {"s3", "sqs"}
        return h.s3 if service == "s3" else h.sqs

    monkeypatch.setattr(boto3, "client", cloud_client)
    initial = FakeInitial()
    initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    h.initial = initial
    monkeypatch.setattr(backend_runtime, "InitialAnalysisService", lambda _: initial)

    def capa(_self, path):
        assert path.read_bytes() == SAMPLE
        h.calls["capa"] += 1
        return CapaAnalysisResult(
            SHA,
            "PE32",
            CapaStatus.SUCCESS,
            CapaBackend.DEFAULT,
            capabilities=[
                CapaCapability(
                    "Synthetic capability",
                    namespace="load-code/inject",
                    attack=("Process Injection",) if h.static_sufficient else (),
                )
            ],
            capa_version="fixture-capa",
        )

    def floss(_self, path):
        assert path.read_bytes() == SAMPLE
        h.calls["floss"] += 1
        return FlossAnalysisResult(
            SHA,
            "PE32",
            FlossStatus.SUCCESS,
            strings=[FlossString("decoded", "harmless fixture text")],
            floss_version="fixture-floss",
        )

    def speakeasy(_self, path):
        assert path.read_bytes() == SAMPLE
        h.calls["speakeasy"] += 1
        return DynamicAnalysisResult(
            evidence_id="fixture-emulation",
            sha256=SHA,
            source="SPEAKEASY",
            category="DYNAMIC_ANALYSIS",
            status=h.dynamic_status,
            summary="Synthetic emulation observations",
            observed_apis=(
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ),
            events={"api_calls": ({"api_name": "CreateRemoteThread"},)},
            errors=()
            if h.dynamic_status is DynamicAnalysisStatus.SUCCESS
            else ("Synthetic tool timeout",),
            tool_version="fixture-speakeasy",
        )

    original_interpret = MonoGPTClaudeInterpreter.interpret

    def interpret(interpreter, evidence, **kwargs):
        if not interpreter.config.enabled:
            return original_interpret(interpreter, evidence, **kwargs)
        h.calls["llm"] += 1
        assert all(item.sha256 == SHA for item in evidence)
        return LLMInterpretation(
            LLMInterpretationStatus.SUCCESS,
            verdict="MALICIOUS",
            confidence=0.9,
            supporting_evidence_ids=tuple(item.evidence_id for item in evidence),
            summary="Synthetic analyst summary",
            model="fixture-model",
        )

    monkeypatch.setattr(CapaAnalyzer, "analyze", capa)
    monkeypatch.setattr(FlossAnalyzer, "analyze", floss)
    monkeypatch.setattr(SpeakeasyAnalyzer, "analyze", speakeasy)
    monkeypatch.setattr(MonoGPTClaudeInterpreter, "interpret", interpret)
    config = BackendConfig(
        database_url=dsn,
        storage_mode="s3",
        s3_bucket="backend-test-only",
        temp_root=tmp_path / "backend",
        poll_seconds=0.1,
    )

    def restart():
        h.service = backend_runtime.create_service(config)
        h.processor = backend_runtime.create_processor(h.service)
        h.worker = worker_runtime.create_runtime(WorkerConfig.from_env()).worker
        assert isinstance(h.processor.deep, ExistingDeepGateway)
        # Service resolution must follow the production import path, without injection.
        assert h.processor.deep._service is None

    def tick():
        if use_postgres:
            with psycopg.connect(dsn) as connection:
                connection.execute("UPDATE api_analyses SET next_retry_at = NULL")
        else:
            h.service.repository.advance(1)
        return h.processor.resume_ready()

    h.restart, h.tick = restart, tick
    try:
        restart()
        h.service.repository.initialize()
        if use_postgres:
            PostgresJobRepository(dsn).initialize()
            PostgresDeepAnalysisRepository(dsn).initialize()
        with TestClient(create_app(h.service)) as client:
            h.client = client
            yield h
    finally:
        if use_postgres:
            assert schema.startswith("worker_flow_") and len(schema) == 44
            with psycopg.connect(database_url, autocommit=True) as connection:
                connection.execute(
                    sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
                )


def submit(h):
    response = h.client.post("/analyses", files={"file": ("inert-header.exe", SAMPLE)})
    assert response.status_code == 202, response.text
    return response.json()["analysis_id"]


def test_http_request_dispatches_worker_and_resumes_after_restart(
    connected, monkeypatch
):
    h = connected
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("MONOGPT_API_KEY", "fixture-key")
    monkeypatch.setenv("MONOGPT_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("MONOGPT_MODEL", "fixture-model")
    identity = submit(h)
    assert not h.sqs.sent and not h.calls
    h.tick()  # initial triage -> WAITING_DEEP
    h.tick()  # CAPA/FLOSS -> checkpoint -> real JobPublisher/SqsQueue
    waiting = h.service.repository.get(identity)
    assert waiting.status == "RUNNING" and waiting.current_stage == "SPEAKEASY"
    assert len(h.sqs.sent) == 1
    assert h.calls == {"capa": 1, "floss": 1}
    for _ in range(2):
        assert h.client.get(f"/analyses/{identity}/deep-analysis").status_code == 200
    assert len(h.sqs.sent) == 1 and h.calls["speakeasy"] == 0

    h.restart()
    h.tick()  # still waiting, no repeated static analysis or publish
    assert len(h.sqs.sent) == 1
    assert h.worker.run_once() == Outcome.COMPLETED
    assert h.service.repository.get(identity).status == "RUNNING"
    h.restart()
    h.tick()  # read Worker DB result -> normalize evidence/LLM -> FINALIZING
    assert h.service.repository.get(identity).phase == "FINALIZING"
    h.tick()  # Backend final assessment and durable result

    final = h.client.get(f"/analyses/{identity}").json()
    deep = h.client.get(f"/analyses/{identity}/deep-analysis").json()
    assert final["status"] == "COMPLETED"
    assert final["final_assessment"]["disposition"] == "MANUAL_REVIEW"
    assert deep["deep_analysis_status"]["speakeasy"] == "COMPLETED"
    assert deep["speakeasy"]["behavior"]["api_calls"] == [
        {"api_name": "CreateRemoteThread"}
    ]
    assert deep["llm_summary"]["summary"] == "Synthetic analyst summary"
    assert {item["source"] for item in deep["evidence_details"]} == {
        "CAPA",
        "FLOSS",
        "SPEAKEASY",
    }
    assert "s3://" not in str(deep) and "file_location" not in str(deep)
    stored = h.service.repository.get(identity).deep_result["speakeasy_result"]
    reference = ArtifactReference(**stored["artifact"])
    assert reference.analysis_id == identity and reference.sha256 == SHA
    assert "raw/" + reference.identity.key in h.s3.objects
    h.sqs.messages.append(h.sqs.sent[0])
    assert h.worker.run_once() == Outcome.DUPLICATE
    assert h.tick() == []
    assert h.calls == {"capa": 1, "floss": 1, "speakeasy": 1, "llm": 1}
    assert len(h.initial.calls) == 1


@pytest.mark.parametrize("verdict", ["AUTO_BENIGN", "AUTO_MALICIOUS"])
def test_automatic_initial_route_does_not_dispatch_worker(connected, verdict):
    h = connected
    h.initial.value = initial_result(verdict)
    identity = submit(h)
    h.tick()
    h.tick()
    assert h.client.get(f"/analyses/{identity}").json()["status"] == "COMPLETED"
    assert not h.sqs.sent and not h.calls


def test_sufficient_static_result_completes_without_worker_or_llm_config(connected):
    h = connected
    h.static_sufficient = True
    identity = submit(h)
    h.tick()
    h.tick()
    h.tick()
    assert h.client.get(f"/analyses/{identity}").json()["status"] == "COMPLETED"
    deep = h.client.get(f"/analyses/{identity}/deep-analysis").json()
    assert deep["deep_analysis_status"]["speakeasy"] == "NOT_REQUIRED"
    assert deep["llm_summary"] is None
    assert h.calls == {"capa": 1, "floss": 1} and not h.sqs.sent


def test_worker_failure_reaches_backend_without_becoming_malicious(connected):
    h = connected
    h.dynamic_status = DynamicAnalysisStatus.TIMEOUT
    identity = submit(h)
    h.tick()
    h.tick()
    assert h.worker.run_once() == Outcome.FAILED
    h.restart()
    h.tick()
    h.tick()
    final = h.client.get(f"/analyses/{identity}").json()
    deep = h.client.get(f"/analyses/{identity}/deep-analysis").json()
    assert final["status"] == "FAILED"
    assert final["final_assessment"]["final_verdict"] == "UNCERTAIN"
    assert final["final_assessment"]["disposition"] == "ANALYSIS_FAILED"
    assert deep["speakeasy"]["tool_status"] == "TIMEOUT"
    assert deep["speakeasy"]["behavior"]["api_calls"]
    assert h.calls == {"capa": 1, "floss": 1, "speakeasy": 1}
