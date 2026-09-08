"""API persistence contracts; PostgreSQL cases use a disposable test schema."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.repository import (
    MAX_STATE_BYTES,
    PostgresAnalysisRepository,
)

from .fake_repository import MemoryAnalysisRepository


def _input(index=0, **overrides):
    return {
        "analysis_id": f"analysis-{index}",
        "sha256": f"{index + 1:064x}",
        "file_location": f"s3://backend-test-only/uploads/analysis-{index}/sample.bin",
        "filename": f"harmless-fixture-{index}.bin",
        "size_bytes": 23,
        **overrides,
    }


def _initial(item):
    return {
        "initial_verdict": "HIGH_RISK_UNCERTAIN",
        "route": "DEEP_ANALYSIS",
        "sha256": item["sha256"],
    }


def _final(item):
    return {
        "analysis_id": item["analysis_id"],
        "sha256": item["sha256"],
        "final_verdict": "UNCERTAIN",
    }


@dataclass
class RepositoryCase:
    repository: object
    dsn: str | None = None

    def reconnect(self):
        return PostgresAnalysisRepository(self.dsn) if self.dsn else self.repository

    @property
    def now(self):
        return datetime.now(timezone.utc) if self.dsn else self.repository.now

    def expire(self, analysis_id):
        if self.dsn:
            with psycopg.connect(self.dsn) as connection:
                connection.execute(
                    "UPDATE api_analyses SET lease_until = clock_timestamp() - interval '1 second' WHERE analysis_id = %s",
                    (analysis_id,),
                )
        else:
            self.repository.advance(601)

    def retry_due(self, analysis_id):
        if self.dsn:
            with psycopg.connect(self.dsn) as connection:
                connection.execute(
                    "UPDATE api_analyses SET next_retry_at = clock_timestamp() - interval '1 second' WHERE analysis_id = %s",
                    (analysis_id,),
                )
        else:
            self.repository.retries[analysis_id] = self.now - timedelta(seconds=1)


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def case(request):
    if request.param == "memory":
        yield RepositoryCase(MemoryAnalysisRepository())
        return
    dsn = os.getenv("BACKEND_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set BACKEND_TEST_DATABASE_URL to run PostgreSQL integration tests")
    dsn = make_conninfo(dsn, connect_timeout=5)
    prefix = "backend_repository_"
    schema = prefix + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
    try:
        repository = PostgresAnalysisRepository(scoped)
        repository.initialize()
        yield RepositoryCase(repository, scoped)
    finally:
        assert schema.startswith(prefix) and len(schema) == len(prefix) + 32
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def _finish(case, item=None, *, failed=False):
    item = item or _input()
    repository = case.repository
    repository.register([item])
    claim = repository.claim(item["analysis_id"], 600)
    assert claim.token
    error = (
        {"code": "TEST_FAILURE", "message": "Synthetic analysis failure"}
        if failed
        else None
    )
    if not failed:
        assert repository.save_initial(
            item["analysis_id"], claim.token, _initial(item), False
        )
    assert repository.finish(
        item["analysis_id"], claim.token, _final(item), error=error
    )
    return repository.get(item["analysis_id"])


def test_registration_and_initial_state_survive_reconnect(case):
    repository = case.repository
    item = _input()
    original = repository.register([item])[0]
    repository.initialize()
    repository.check()
    restored = case.reconnect().get(item["analysis_id"])
    assert restored == original
    assert restored.status == "QUEUED"
    assert restored.phase == "INITIAL"
    assert restored.current_stage == "UPLOAD"
    assert restored.batch_id is None and restored.duplicate_of is None
    assert restored.initial_result is None and restored.deep_result is None
    assert restored.final_assessment is None and not restored.claimed
    assert datetime.fromisoformat(restored.created_at).utcoffset() == timedelta(0)
    assert restored.to_dict()["sha256"] == item["sha256"]
    assert repository.location_referenced(item["file_location"])
    assert not repository.location_referenced("s3://backend-test-only/unknown.bin")


def test_batch_preserves_input_order_and_independent_new_duplicates(case):
    repository = case.repository
    first = _input(1)
    repository.register([first])
    inputs = [
        _input(7, sha256=first["sha256"]),
        _input(2),
        _input(4, sha256=first["sha256"]),
    ]
    result = repository.register(inputs, batch_id="batch-example")
    assert [row.analysis_id for row in result] == [
        item["analysis_id"] for item in inputs
    ]
    assert all(
        row.batch_id == "batch-example" and row.status == "QUEUED" for row in result
    )
    assert result[0].duplicate_of == result[2].duplicate_of == first["analysis_id"]
    assert result[1].duplicate_of is None
    assert case.reconnect().get_batch("batch-example") == result
    assert repository.get_batch("missing-batch") is None


@pytest.mark.parametrize("is_batch", [False, True])
def test_idempotency_returns_original_records_ignoring_new_ids_and_locations(
    case, is_batch
):
    repository = case.repository
    item = _input()
    original = repository.register(
        [item], batch_id="first-batch" if is_batch else None, idempotency_key="key-one"
    )
    replay = _input(
        10,
        sha256=item["sha256"],
        filename=item["filename"],
        size_bytes=item["size_bytes"],
    )
    same = case.reconnect().register(
        [replay],
        batch_id="regenerated-batch" if is_batch else None,
        idempotency_key="key-one",
    )
    assert same == original
    assert repository.get(replay["analysis_id"]) is None
    assert not repository.location_referenced(replay["file_location"])
    assert repository.list_analyses()[1] == 1
    if is_batch:
        assert repository.get_batch("regenerated-batch") is None


@pytest.mark.parametrize(
    "changed", ["sha256", "size_bytes", "filename", "kind", "order"]
)
def test_idempotency_conflicts_with_different_content_endpoint_or_order(case, changed):
    repository = case.repository
    inputs = [_input(), _input(1)] if changed == "order" else [_input()]
    original_batch = "batch-original" if changed == "order" else None
    repository.register(inputs, batch_id=original_batch, idempotency_key="same-key")
    replacements = [
        _input(
            index + 10,
            sha256=item["sha256"],
            filename=item["filename"],
            size_bytes=item["size_bytes"],
        )
        for index, item in enumerate(inputs)
    ]
    batch = "batch-replay" if changed in {"order", "kind"} else None
    if changed == "order":
        replacements.reverse()
    elif changed != "kind":
        replacements[0][changed] = {
            "sha256": "f" * 64,
            "size_bytes": 999,
            "filename": "other.bin",
        }[changed]
    with pytest.raises(BackendError) as error:
        repository.register(replacements, batch_id=batch, idempotency_key="same-key")
    assert error.value.http_status == 409
    assert repository.list_analyses()[1] == len(inputs)


def test_registration_collision_rolls_back_entire_batch_and_idempotency_record(case):
    repository = case.repository
    existing = _input()
    repository.register([existing])
    with pytest.raises(BackendError) as error:
        repository.register(
            [_input(1), _input(2, file_location=existing["file_location"])],
            batch_id="atomic-batch",
            idempotency_key="atomic-key",
        )
    assert error.value.http_status == 409
    assert repository.get("analysis-1") is None
    assert repository.get_batch("atomic-batch") is None
    assert repository.list_analyses()[1] == 1
    assert (
        len(
            repository.register(
                [_input(1), _input(2)],
                batch_id="atomic-batch",
                idempotency_key="atomic-key",
            )
        )
        == 2
    )


def test_listing_filters_and_pagination_report_total_before_pagination(case):
    repository = case.repository
    repository.register(
        [_input(0), _input(1), _input(2, sha256=_input()["sha256"])],
        batch_id="batch-list",
    )
    first_page, total = repository.list_analyses(limit=1, offset=0)
    assert total == 3 and [row.analysis_id for row in first_page] == ["analysis-2"]
    assert [
        row.analysis_id for row in repository.list_analyses(limit=1, offset=1)[0]
    ] == ["analysis-1"]
    assert repository.list_analyses(offset=10) == ([], 3)
    assert repository.list_analyses(sha256=_input()["sha256"])[1] == 2
    repository.claim("analysis-1", 600)
    assert repository.list_analyses(status="RUNNING")[1] == 1
    assert repository.list_analyses(status="QUEUED", sha256=_input()["sha256"])[1] == 2
    assert repository.get("missing") is None
    with pytest.raises(BackendError) as error:
        repository.claim("missing", 600)
    assert error.value.http_status == 404


def test_initial_deep_and_final_snapshots_are_durable_and_detached(case):
    repository, item = case.repository, _input()
    repository.register([item])
    owner = repository.claim(item["analysis_id"], 600)
    assert owner.record.current_stage == "INITIAL_ANALYSIS"
    initial = _initial(item)
    assert repository.save_initial(item["analysis_id"], owner.token, initial, True)
    initial["route"] = "changed by caller"
    restored = case.reconnect().get(item["analysis_id"])
    assert restored.initial_result == _initial(item)
    assert restored.phase == "WAITING_DEEP" and restored.current_stage == "CAPA_FLOSS"
    assert repository.save_deep(
        item["analysis_id"],
        owner.token,
        {"phase": "WAITING_SPEAKEASY", "evidence": [{"summary": "test"}]},
        finished=False,
        current_stage="SPEAKEASY",
    )
    assert repository.release(item["analysis_id"], owner.token)
    repository = case.reconnect()
    owner = repository.claim(item["analysis_id"], 600)
    assert owner.record.current_stage == "SPEAKEASY"
    assert owner.record.initial_result == _initial(item)
    snapshot = {
        "analysis_id": item["analysis_id"],
        "sha256": item["sha256"],
        "status": "COMPLETED",
        "evidence": [{"summary": "static remains"}],
    }
    assert repository.save_deep(
        item["analysis_id"], owner.token, snapshot, finished=True, current_stage="LLM"
    )
    snapshot["evidence"].clear()
    assert repository.get(item["analysis_id"]).deep_result["evidence"]
    assert repository.get(item["analysis_id"]).current_stage == "FINAL_ASSESSMENT"
    assert repository.finish(item["analysis_id"], owner.token, _final(item))
    completed = case.reconnect().get(item["analysis_id"])
    assert completed.status == "COMPLETED" and completed.phase == "DONE"
    assert (
        completed.current_stage == "FINAL_ASSESSMENT"
        and completed.completed_at is not None
    )
    assert completed.initial_result == _initial(item)
    assert completed.deep_result["evidence"]
    assert completed.final_assessment == _final(item)
    completed.deep_result["evidence"].clear()
    assert repository.get(item["analysis_id"]).deep_result["evidence"]


@pytest.mark.parametrize("failure", [False, True])
def test_terminal_state_is_atomic_and_fenced_from_all_worker_mutations(case, failure):
    repository, item = case.repository, _input()
    repository.register([item])
    claim = repository.claim(item["analysis_id"], 600)
    if not failure:
        assert not repository.finish(item["analysis_id"], claim.token, _final(item))
        assert repository.save_initial(
            item["analysis_id"], claim.token, _initial(item), False
        )
    assert repository.finish(
        item["analysis_id"],
        claim.token,
        _final(item),
        error={"code": "FAILURE"} if failure else None,
    )
    before = repository.get(item["analysis_id"])
    assert before.status == ("FAILED" if failure else "COMPLETED")
    assert before.final_assessment == _final(item)
    assert not before.claimed
    assert not repository.renew(item["analysis_id"], claim.token, 600)
    assert not repository.release(item["analysis_id"], claim.token, {"code": "LATE"})
    assert not repository.save_initial(
        item["analysis_id"], claim.token, _initial(item), True
    )
    assert not repository.save_deep(
        item["analysis_id"], claim.token, {}, finished=True, current_stage="LLM"
    )
    assert not repository.finish(
        item["analysis_id"], claim.token, {"final_verdict": "BENIGN"}
    )
    assert repository.claim(item["analysis_id"], 600).token is None
    assert repository.get(item["analysis_id"]) == before


def test_phase_progress_cannot_regress_or_overwrite_initial_snapshot(case):
    repository, item = case.repository, _input()
    repository.register([item])
    owner = repository.claim(item["analysis_id"], 600)
    assert not repository.save_deep(
        item["analysis_id"], owner.token, {}, finished=False, current_stage="SPEAKEASY"
    )
    assert repository.save_initial(
        item["analysis_id"], owner.token, _initial(item), True
    )
    assert not repository.save_initial(
        item["analysis_id"], owner.token, {"initial_verdict": "AUTO_BENIGN"}, False
    )
    assert repository.save_deep(
        item["analysis_id"],
        owner.token,
        {"status": "COMPLETED"},
        finished=True,
        current_stage="LLM",
    )
    assert not repository.save_deep(
        item["analysis_id"],
        owner.token,
        {"status": "RUNNING"},
        finished=False,
        current_stage="SPEAKEASY",
    )
    assert repository.get(item["analysis_id"]).phase == "FINALIZING"


def test_expired_owner_cannot_write_and_another_claim_can_resume(case):
    repository, item = case.repository, _input()
    repository.register([item])
    previous = repository.claim(item["analysis_id"], 600)
    assert repository.claim(item["analysis_id"], 600).token is None
    case.expire(item["analysis_id"])
    assert not repository.renew(item["analysis_id"], previous.token, 600)
    assert not repository.release(item["analysis_id"], previous.token)
    assert not repository.save_initial(
        item["analysis_id"], previous.token, _initial(item), True
    )
    assert not repository.save_deep(
        item["analysis_id"], previous.token, {}, finished=True, current_stage="LLM"
    )
    assert not repository.finish(
        item["analysis_id"], previous.token, _final(item), error={"code": "OLD"}
    )
    current = case.reconnect().claim(item["analysis_id"], 600)
    assert current.token and current.token != previous.token
    assert current.record.attempt_count == 2
    assert repository.save_initial(
        item["analysis_id"], current.token, _initial(item), False
    )


def test_concurrent_claims_have_exactly_one_owner(case):
    case.repository.register([_input()])
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(
            pool.map(lambda _: case.reconnect().claim("analysis-0", 600), range(4))
        )
    assert sum(claim.token is not None for claim in claims) == 1
    assert case.repository.get("analysis-0").attempt_count == 1


def test_idempotency_and_duplicate_detection_are_safe_for_concurrent_registration(case):
    def register(index):
        return case.reconnect().register(
            [_input(index, sha256="a" * 64, filename="same.bin")],
            idempotency_key="concurrent-key",
        )[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(register, [0, 1]))
    assert results[0].analysis_id == results[1].analysis_id
    assert case.repository.list_analyses()[1] == 1
    with ThreadPoolExecutor(max_workers=2) as pool:
        independent = list(
            pool.map(
                lambda index: case.reconnect().register(
                    [_input(index, sha256="b" * 64)]
                )[0],
                [2, 3],
            )
        )
    originals = [row for row in independent if row.duplicate_of is None]
    duplicates = [row for row in independent if row.duplicate_of is not None]
    assert len(originals) == len(duplicates) == 1
    assert duplicates[0].duplicate_of == originals[0].analysis_id


def test_future_backoff_and_live_claims_do_not_hide_new_ready_work(case):
    repository = case.repository
    for index in range(12):
        item = _input(index)
        repository.register([item])
        owner = repository.claim(item["analysis_id"], 600)
        assert repository.release(
            item["analysis_id"],
            owner.token,
            {"code": "RETRY", "retry_count": 1},
            case.now + timedelta(minutes=10),
        )
    repository.register([_input(20), _input(21), _input(22)], batch_id="ready")
    repository.claim("analysis-21", 600)
    assert repository.pending_ids(2) == ["analysis-20", "analysis-22"]
    assert repository.claim("analysis-0", 600).token is None
    assert repository.get("analysis-0").attempt_count == 1
    case.retry_due("analysis-0")
    assert repository.pending_ids(1) == ["analysis-0"]
    reclaimed = repository.claim("analysis-0", 600)
    assert reclaimed.token
    assert repository.release("analysis-0", reclaimed.token)
    assert repository.get("analysis-0").error is None
    assert repository.pending_ids(3) == ["analysis-20", "analysis-22", "analysis-0"]


def test_stale_release_cannot_erase_retry_and_successful_snapshot_clears_it(case):
    repository, item = case.repository, _input()
    repository.register([item])
    owner = repository.claim(item["analysis_id"], 600)
    error = {"code": "TEMPORARY", "retry_count": 2}
    assert repository.release(
        item["analysis_id"], owner.token, error, case.now + timedelta(minutes=1)
    )
    assert not repository.release(item["analysis_id"], owner.token)
    assert repository.get(item["analysis_id"]).error == error
    assert repository.pending_ids() == []
    case.retry_due(item["analysis_id"])
    resumed = repository.claim(item["analysis_id"], 600)
    assert repository.save_initial(
        item["analysis_id"], resumed.token, _initial(item), True
    )
    assert repository.get(item["analysis_id"]).error is None
    repository.release(item["analysis_id"], resumed.token)
    assert repository.pending_ids() == [item["analysis_id"]]


@pytest.mark.parametrize("operation", ["initial", "deep", "final"])
@pytest.mark.parametrize("field", ["analysis_id", "sha256"])
def test_snapshot_identity_mismatch_rolls_back_without_erasing_previous_state(
    case, operation, field
):
    repository, item = case.repository, _input()
    repository.register([item])
    owner = repository.claim(item["analysis_id"], 600)
    if operation != "initial":
        repository.save_initial(
            item["analysis_id"], owner.token, _initial(item), operation == "deep"
        )
    before = repository.get(item["analysis_id"])
    payload = {field: "another-analysis" if field == "analysis_id" else "f" * 64}
    with pytest.raises(BackendError) as error:
        if operation == "initial":
            repository.save_initial(item["analysis_id"], owner.token, payload, True)
        elif operation == "deep":
            repository.save_deep(
                item["analysis_id"],
                owner.token,
                payload,
                finished=False,
                current_stage="SPEAKEASY",
            )
        else:
            repository.finish(item["analysis_id"], owner.token, payload)
    assert error.value.http_status == 422
    assert repository.get(item["analysis_id"]) == before


def test_reviews_preserve_model_verdicts_and_append_revision_history(case):
    repository = case.repository
    completed = _finish(case)
    first = repository.save_review(
        "analysis-0",
        analyst_final_verdict="BENIGN",
        analyst_notes="Analyst checked the supplied evidence",
        reviewer_id="reviewer-1",
        expected_revision=0,
    )
    assert first["revision"] == 1 and first["review_status"] == "COMPLETED"
    first["analyst_notes"] = "caller mutation"
    second = case.reconnect().save_review(
        "analysis-0",
        analyst_final_verdict=None,
        analyst_notes="Need additional context",
        reviewer_id="reviewer-2",
        expected_revision=1,
    )
    assert second["revision"] == 2 and second["review_status"] == "PENDING"
    restored = case.reconnect().get("analysis-0")
    assert restored.review_revision == 2 and restored.analyst_final_verdict is None
    assert restored.initial_result == completed.initial_result
    assert restored.deep_result == completed.deep_result
    assert restored.final_assessment == completed.final_assessment
    reviews = repository.list_reviews("analysis-0")
    assert [row["revision"] for row in reviews] == [1, 2]
    assert reviews[0]["analyst_notes"] != "caller mutation"
    with pytest.raises(BackendError) as error:
        repository.save_review(
            "analysis-0",
            analyst_final_verdict="MALICIOUS",
            analyst_notes="stale edit",
            reviewer_id="reviewer-1",
            expected_revision=1,
        )
    assert error.value.http_status == 409
    assert len(repository.list_reviews("analysis-0")) == 2


def test_reviews_require_terminal_analysis_and_concurrent_edit_has_one_winner(case):
    repository = case.repository
    repository.register([_input()])
    fields = {
        "analyst_final_verdict": "BENIGN",
        "analyst_notes": "test",
        "reviewer_id": "test-analyst",
        "expected_revision": 0,
    }
    with pytest.raises(BackendError) as missing:
        repository.save_review("missing", **fields)
    assert missing.value.http_status == 404
    with pytest.raises(BackendError) as active:
        repository.save_review("analysis-0", **fields)
    assert active.value.http_status == 409
    owner = repository.claim("analysis-0", 600)
    repository.finish(
        "analysis-0", owner.token, _final(_input()), error={"code": "TEST_FAILURE"}
    )

    def submit(_):
        try:
            return case.reconnect().save_review("analysis-0", **fields)
        except BackendError as exc:
            return exc.http_status

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert sum(isinstance(value, dict) for value in results) == 1
    assert results.count(409) == 1
    assert repository.get("analysis-0").review_revision == 1
    assert len(repository.list_reviews("analysis-0")) == 1


def test_cleanup_keeps_active_or_new_files_and_marks_only_completed_deletions(case):
    repository = case.repository
    finished = _finish(case, _input(0))
    failed = _finish(case, _input(1), failed=True)
    repository.register([_input(2)])
    assert not repository.mark_storage_deleted("analysis-2")
    assert repository.cleanup_candidates(case.now - timedelta(days=1)) == []
    cutoff = case.now + timedelta(seconds=1)
    candidates = repository.cleanup_candidates(cutoff)
    assert [row.analysis_id for row in candidates] == [
        finished.analysis_id,
        failed.analysis_id,
    ]
    assert repository.location_referenced(finished.file_location)
    assert repository.mark_storage_deleted(finished.analysis_id)
    assert not repository.mark_storage_deleted(finished.analysis_id)
    assert not repository.location_referenced(finished.file_location)
    assert repository.get(finished.analysis_id).storage_deleted_at is not None
    assert [row.analysis_id for row in repository.cleanup_candidates(cutoff)] == [
        failed.analysis_id
    ]


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), {1, 2}, "x" * MAX_STATE_BYTES],
    ids=["nan", "infinity", "set", "oversized"],
)
def test_nonfinite_unserializable_or_oversized_state_rejected_before_database(
    value, monkeypatch
):
    repository = PostgresAnalysisRepository("host=localhost dbname=unused")
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *args, **kwargs: pytest.fail("validation must happen before DB access"),
    )
    token = str(uuid4())
    for operation in (
        lambda: repository.save_initial("analysis-0", token, {"invalid": value}, True),
        lambda: repository.save_deep(
            "analysis-0", token, {"invalid": value}, finished=True, current_stage="LLM"
        ),
        lambda: repository.finish("analysis-0", token, {"invalid": value}),
        lambda: repository.release("analysis-0", token, {"invalid": value}),
    ):
        with pytest.raises(ValueError):
            operation()


def test_invalid_parameters_rejected_before_database(monkeypatch):
    repository = PostgresAnalysisRepository("host=localhost dbname=unused")
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda *args, **kwargs: pytest.fail("validation must happen before DB access"),
    )
    token = str(uuid4())
    for value in (0, -1, True, 1.5, 43201):
        with pytest.raises(ValueError):
            repository.claim("analysis-0", value)
    for value in (0, 101, True, 1.5):
        with pytest.raises(ValueError):
            repository.list_analyses(limit=value)
        with pytest.raises(ValueError):
            repository.pending_ids(value)
    for value in (-1, True, 0.5):
        with pytest.raises(ValueError):
            repository.list_analyses(offset=value)
    for value in ([], [_input(), _input(1)]):
        with pytest.raises(ValueError):
            repository.register(value)
    with pytest.raises(ValueError):
        repository.register([_input(), _input()], batch_id="duplicates")
    with pytest.raises(ValueError):
        repository.register([_input()], idempotency_key="contains space")
    with pytest.raises(ValueError):
        repository.register([_input(sha256="not-a-hash")])
    with pytest.raises(ValueError):
        repository.save_deep(
            "analysis-0", token, {}, finished=True, current_stage="UNSUPPORTED_STAGE"
        )
    with pytest.raises(ValueError):
        repository.release("analysis-0", token, {}, datetime(2026, 1, 1))  # noqa: DTZ001 - deliberately invalid input
    with pytest.raises(ValueError):
        repository.cleanup_candidates(datetime(2026, 1, 1))  # noqa: DTZ001 - deliberately invalid input
    with pytest.raises(ValueError):
        repository.save_review(
            "analysis-0",
            analyst_final_verdict="UNKNOWN",
            analyst_notes="",
            reviewer_id="analyst",
            expected_revision=0,
        )


def test_database_errors_have_generic_public_details(monkeypatch):
    secret = "postgresql://username:secret-password@private-host/private-db"

    def fail(*args, **kwargs):
        raise psycopg.OperationalError(secret)

    monkeypatch.setattr(psycopg, "connect", fail)
    repository = PostgresAnalysisRepository("host=localhost dbname=unused")
    with pytest.raises(BackendError) as error:
        repository.get("analysis-0")
    assert error.value.retryable and error.value.http_status == 503
    assert secret not in str(error.value)
    assert "secret-password" not in json.dumps(error.value.to_dict())


def test_sql_rejects_half_finished_state_and_nonterminal_deleted_storage(case):
    if case.dsn is None:
        pytest.skip("direct SQL constraints are PostgreSQL-specific")
    case.repository.register([_input()])
    for statement in (
        "UPDATE api_analyses SET status = 'COMPLETED' WHERE analysis_id = 'analysis-0'",
        "UPDATE api_analyses SET phase = 'WAITING_DEEP' WHERE analysis_id = 'analysis-0'",
        "UPDATE api_analyses SET storage_deleted_at = clock_timestamp() WHERE analysis_id = 'analysis-0'",
        "UPDATE api_analyses SET current_stage = 'UNSUPPORTED' WHERE analysis_id = 'analysis-0'",
    ):
        with (
            pytest.raises(psycopg.errors.CheckViolation),
            psycopg.connect(case.dsn) as connection,
        ):
            connection.execute(statement)
    assert case.repository.get("analysis-0").status == "QUEUED"
