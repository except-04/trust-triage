"""실제 HTTP→PostgreSQL→처리기→검토 연결. 모델·심층 도구만 테스트 대역이다."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.processor import BackendProcessor
from trust_triage.backend_api.repository import PostgresAnalysisRepository
from trust_triage.backend_api.service import BackendService
from trust_triage.backend_api.storage import LocalSampleStorage

from .test_batch_inputs import archive_bytes
from .test_service_processor import (
    FakeDeep,
    FakeInitial,
    harmless_pe_header,
    initial_result,
)

pytestmark = pytest.mark.postgres


@pytest.fixture
def flow(tmp_path):
    dsn = os.getenv("BACKEND_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set BACKEND_TEST_DATABASE_URL to run PostgreSQL integration tests")
    dsn = make_conninfo(dsn, connect_timeout=5)
    schema = "backend_flow_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
    try:
        config = BackendConfig(
            database_url=scoped,
            storage_root=tmp_path / "samples",
            temp_root=tmp_path / "temp",
        )
        repository = PostgresAnalysisRepository(scoped)
        repository.initialize()
        storage = LocalSampleStorage(config.storage_root)
        yield BackendService(repository, storage, config), scoped
    finally:
        assert (
            schema.startswith("backend_flow_")
            and len(schema) == len("backend_flow_") + 32
        )
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def test_zip_http_receipt_and_summary_survive_service_restart(flow):
    service, scoped = flow
    data = archive_bytes(
        [("folder/valid.exe", harmless_pe_header()), ("notes.txt", b"notes")]
    )
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/batches/zip",
            files={"file": ("inputs.zip", data)},
            headers={"Idempotency-Key": "zip-http"},
        )
        assert response.status_code == 202, response.text
        accepted = response.json()
        assert (
            accepted["input_count"] == 2
            and accepted["accepted_count"] == accepted["skipped_count"] == 1
        )
    restarted = BackendService(
        PostgresAnalysisRepository(scoped), service.storage, service.config
    )
    with TestClient(create_app(restarted)) as client:
        assert (
            client.post(
                "/batches/zip",
                files={"file": ("inputs.zip", data)},
                headers={"Idempotency-Key": "zip-http"},
            ).json()
            == accepted
        )
        identity = accepted["analyses"][0]["analysis_id"]
        claim = restarted.repository.claim(identity, 600)
        restarted.repository.save_initial(
            identity, claim.token, initial_result("HIGH_RISK_UNCERTAIN"), True
        )
        batch = client.get("/batches/" + accepted["batch_id"]).json()
        assert batch["status"] == "RUNNING"
        assert (
            batch["summary"]["high_risk_uncertain"] == batch["summary"]["running"] == 1
        )
        assert (
            batch["summary"]["failed"] == 0 and batch["entries"] == accepted["entries"]
        )
        page = client.get(
            f"/batches/{accepted['batch_id']}/analyses?verdict=HIGH_RISK_UNCERTAIN"
        ).json()
        assert (
            page["total_count"] == 1 and page["analyses"][0]["analysis_id"] == identity
        )
        all_skipped = client.post(
            "/batches/zip",
            files={
                "file": ("empty-jobs.zip", archive_bytes([("notes.txt", b"notes")]))
            },
        ).json()
        assert (
            client.get("/batches/" + all_skipped["batch_id"]).json()["status"]
            == "COMPLETED"
        )
    assert len(list(service.config.storage_root.glob("*/sample.bin"))) == 1
    assert not list(service.config.temp_root.glob("batch-*"))


@pytest.mark.parametrize(
    "verdict,expected",
    [("AUTO_BENIGN", "BENIGN"), ("HIGH_RISK_UNCERTAIN", "UNCERTAIN")],
)
def test_http_processor_restart_and_analyst_review_with_real_postgres(
    flow, verdict, expected
):
    service, scoped = flow
    initial, deep = FakeInitial(), FakeDeep()
    initial.value = initial_result(verdict)
    with TestClient(create_app(service)) as client:
        upload = client.post(
            "/analyses",
            files={"file": ("header-only.exe", harmless_pe_header())},
            headers={"Idempotency-Key": "flow-test"},
        )
        assert upload.status_code == 202
        identity = upload.json()["analysis_id"]
        for _ in range(3):
            # 매 단계 새 repository/processor를 만들며 재시작 후 이어받기를 검증한다.
            with psycopg.connect(scoped) as connection:
                connection.execute(
                    "UPDATE api_analyses SET next_retry_at = NULL WHERE analysis_id = %s",
                    (identity,),
                )
            processor = BackendProcessor(
                PostgresAnalysisRepository(scoped),
                service.storage,
                initial,
                deep,
                service.config,
            )
            processor.resume(identity)
        result = client.get(f"/analyses/{identity}")
        assert result.status_code == 200
        payload = result.json()
        assert payload["status"] == "COMPLETED" and payload["final_verdict"] == expected
        assert len(initial.calls) == 1
        assert len(deep.calls) == (1 if verdict == "HIGH_RISK_UNCERTAIN" else 0)
        review = client.patch(
            f"/analyses/{identity}/verdict",
            json={
                "analyst_final_verdict": "MALICIOUS",
                "reviewer_id": "test-reviewer",
                "expected_revision": 0,
                "analyst_notes": "synthetic test decision",
            },
        )
        assert review.status_code == 200
        reloaded = PostgresAnalysisRepository(scoped).get(identity)
        assert reloaded.analyst_final_verdict == "MALICIOUS"
        assert reloaded.final_assessment["final_verdict"] == expected
