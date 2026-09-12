"""실제 HTTP→PostgreSQL→처리기→검토 연결. 모델·심층 도구만 테스트 대역이다."""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.processor import BackendProcessor, assess
from trust_triage.backend_api.repository import PostgresAnalysisRepository
from trust_triage.backend_api.service import BackendService, stored_sample
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
        assert payload["triggered_signals"] == initial.value["triggered_signals"]
        assert (
            client.get(f"/analyses/{identity}/triage").json()["triggered_signals"]
            == initial.value["triggered_signals"]
        )
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
        assert (
            reloaded.initial_result["triggered_signals"]
            == initial.value["triggered_signals"]
        )
        artifacts = PostgresAnalysisRepository(scoped).list_artifacts(identity)
        tools = {artifact.tool for artifact in artifacts}
        assert tools == (
            {"INITIAL_ANALYSIS", "FINAL_ASSESSMENT", "DEEP_ANALYSIS"}
            if verdict == "HIGH_RISK_UNCERTAIN"
            else {"INITIAL_ANALYSIS", "FINAL_ASSESSMENT"}
        )
        store = service.storage.artifact_store(
            max_bytes=service.config.max_artifact_bytes
        )
        for artifact in artifacts:
            assert (
                artifact.analysis_id == identity and artifact.sha256 == reloaded.sha256
            )
            assert (
                hashlib.sha256(store.read(artifact)).hexdigest()
                == artifact.content_sha256
            )
            if artifact.tool == "INITIAL_ANALYSIS":
                assert (
                    json.loads(store.read(artifact))["triggered_signals"]
                    == initial.value["triggered_signals"]
                )


def _submit(service, *, name="sample.exe", marker=0):
    return service.submit([(io.BytesIO(harmless_pe_header(marker)), name)])


def _finish_and_expire(service, scoped, analysis_id):
    claim = service.repository.claim(analysis_id, 600)
    assert service.repository.save_initial(
        analysis_id, claim.token, initial_result(), False
    )
    row = service.repository.get(analysis_id)
    assert service.repository.finish(analysis_id, claim.token, assess(row))
    with psycopg.connect(scoped) as connection:
        connection.execute(
            "UPDATE api_analyses SET completed_at = clock_timestamp() - interval '25 hours' WHERE analysis_id = %s",
            (analysis_id,),
        )


@pytest.mark.parametrize("first_operation", ["cleanup", "intake"])
def test_concurrent_intake_and_cleanup_cannot_delete_newly_referenced_bytes(
    flow, monkeypatch, first_operation
):
    service, scoped = flow
    old = _submit(service)
    _finish_and_expire(service, scoped, old.analysis_id)
    paused, release, second_started = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    unpublished_ids = []
    if first_operation == "cleanup":
        original_delete = service.storage.delete

        def pause_delete(sample):
            paused.set()
            assert release.wait(8), "test did not release cleanup"
            return original_delete(sample)

        monkeypatch.setattr(service.storage, "delete", pause_delete)
    else:
        original_publish = service.storage.publish

        def pause_publish(prepared):
            result = original_publish(prepared)
            unpublished_ids.append(result.analysis_id)
            paused.set()
            assert release.wait(8), "test did not release intake"
            return result

        monkeypatch.setattr(service.storage, "publish", pause_publish)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = (
            executor.submit(service.cleanup, delete=True)
            if first_operation == "cleanup"
            else executor.submit(_submit, service)
        )
        try:
            assert paused.wait(5)
            if unpublished_ids:
                # Metadata and artifact references are not visible before publication commits.
                assert service.repository.get(unpublished_ids[0]) is None
            original_transaction = service.repository.sample_transaction

            @contextmanager
            def signal_lock_attempt(hashes):
                second_started.set()
                with original_transaction(hashes) as transaction:
                    yield transaction

            monkeypatch.setattr(
                service.repository, "sample_transaction", signal_lock_attempt
            )
            second = (
                executor.submit(_submit, service)
                if first_operation == "cleanup"
                else executor.submit(service.cleanup, delete=True)
            )
            assert second_started.wait(5)
            with pytest.raises(FutureTimeoutError):
                second.result(timeout=0.2)
        finally:
            release.set()
        first_result, second_result = (
            first.result(timeout=10),
            second.result(timeout=10),
        )
    cleanup, accepted = (
        (first_result, second_result)
        if first_operation == "cleanup"
        else (second_result, first_result)
    )
    expected = [old.analysis_id] if first_operation == "cleanup" else []
    assert cleanup["deleted_ids"] == expected
    new = service.get(accepted.analysis_id)
    assert new.status == "QUEUED" and new.storage_deleted_at is None
    with service.storage.materialize(stored_sample(new)) as path:
        assert path.read_bytes() == harmless_pe_header()


def test_concurrent_duplicate_submissions_share_one_durable_object(flow):
    service, scoped = flow
    barrier = threading.Barrier(4)

    def submit(index):
        barrier.wait(timeout=5)
        return _submit(service, name=f"request-{index}.exe")

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(submit, range(4)))
    assert len({result.analysis_id for result in results}) == 4
    assert sum(result.duplicate_of is None for result in results) == 1
    records = [service.get(result.analysis_id) for result in results]
    assert len({record.file_location for record in records}) == 1
    assert {record.filename for record in records} == {
        f"request-{index}.exe" for index in range(4)
    }
    assert len(list(service.config.storage_root.glob("*/sample.bin"))) == 1
    with psycopg.connect(scoped) as connection:
        assert (
            connection.execute("SELECT count(*) FROM api_sample_objects").fetchone()[0]
            == 1
        )


def test_opposite_order_batch_uploads_share_objects_without_deadlocking(flow):
    service, scoped = flow
    barrier = threading.Barrier(2)

    def submit(reverse):
        indexes = [1, 0] if reverse else [0, 1]
        barrier.wait(timeout=5)
        return service.submit(
            [(io.BytesIO(harmless_pe_header(i)), f"sample-{i}.exe") for i in indexes],
            batch=True,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        batches = list(executor.map(submit, [False, True]))
    assert len({batch.batch_id for batch in batches}) == 2
    assert sum(len(batch.analyses) for batch in batches) == 4
    assert len(list(service.config.storage_root.glob("*/sample.bin"))) == 2
    with psycopg.connect(scoped) as connection:
        assert (
            connection.execute("SELECT count(*) FROM api_sample_objects").fetchone()[0]
            == 2
        )


def test_storage_schema_upgrade_preserves_legacy_requests_and_file_locations(flow):
    service, scoped = flow
    data = harmless_pe_header()
    sha256 = hashlib.sha256(data).hexdigest()
    inputs = []
    for index in range(2):
        identity = f"analysis-old-{index}"
        path = service.config.storage_root / identity / "sample.bin"
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        inputs.append(
            {
                "analysis_id": identity,
                "sha256": sha256,
                "file_location": f"local://{identity}/sample.bin",
                "size_bytes": len(data),
                "filename": f"old-{index}.exe",
            }
        )
    original = service.repository.register(
        inputs, batch_id="old-batch", idempotency_key="old-key"
    )
    # Reconstruct the previous schema only inside this disposable test schema.
    with psycopg.connect(scoped) as connection:
        connection.execute("DROP TABLE api_analysis_artifacts")
        connection.execute(
            "ALTER TABLE api_analyses DROP CONSTRAINT api_analyses_sample_object_fk"
        )
        connection.execute("DROP TABLE api_sample_objects")
        connection.execute(
            "ALTER TABLE api_analyses ADD CONSTRAINT api_analyses_file_location_key UNIQUE (file_location)"
        )
    service.repository.initialize()
    service.repository.initialize()
    service.repository.check()
    assert service.repository.get_batch("old-batch") == original
    assert (
        service.repository.register(
            inputs, batch_id="ignored-replay-batch", idempotency_key="old-key"
        )
        == original
    )
    for record in original:
        with service.storage.materialize(stored_sample(record)) as path:
            assert path.parent.name == record.analysis_id and path.read_bytes() == data
    new = _submit(service)
    assert (
        service.get(new.analysis_id).file_location
        == f"local://samples/{sha256}/sample.bin"
    )
    with psycopg.connect(scoped) as connection:
        assert (
            connection.execute("SELECT count(*) FROM api_sample_objects").fetchone()[0]
            == 3
        )
