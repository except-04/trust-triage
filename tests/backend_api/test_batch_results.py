"""Batch progress, initial-verdict filters, and priority before pagination."""

import io
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from trust_triage.backend_api import batch_results
from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.repository import BatchRecord

from .test_service_processor import harmless_pe_header, initial_result
from .test_service_processor import (
    harness as harness,  # noqa: PLC0414 - pytest fixture re-export
)


def submit_batch(harness, count):
    return harness.service.submit(
        [
            (io.BytesIO(harmless_pe_header(index)), f"header-{index}.exe")
            for index in range(count)
        ],
        batch=True,
    )


def populate(harness, *, status, verdict, analysis_id):
    if status == "QUEUED":
        return
    repository = harness.repository
    claim = repository.claim(analysis_id, 600)
    if verdict is not None:
        repository.save_initial(
            analysis_id, claim.token, initial_result(verdict), False
        )
    if status in {"COMPLETED", "FAILED"}:
        repository.finish(
            analysis_id,
            claim.token,
            {
                "final_verdict": "UNCERTAIN",
                "disposition": "MANUAL_REVIEW",
                "requires_human_review": True,
                "reason": "Synthetic result",
            },
            error={"code": "TEST_FAILURE", "message": "test failure"}
            if status == "FAILED"
            else None,
        )


def test_batch_summary_tracks_progress_and_counts_initial_verdict_separately(harness):
    batch = submit_batch(harness, 3)
    ids = [row.analysis_id for row in batch.analyses]
    assert harness.service.get_batch(batch.batch_id).status == "QUEUED"
    populate(
        harness, status="RUNNING", verdict="HIGH_RISK_UNCERTAIN", analysis_id=ids[0]
    )
    result = harness.service.get_batch(batch.batch_id)
    assert result.status == "RUNNING"
    assert result.summary.running == result.summary.high_risk_uncertain == 1
    assert result.summary.queued == result.summary.unclassified == 2
    populate(harness, status="COMPLETED", verdict="AUTO_BENIGN", analysis_id=ids[1])
    assert harness.service.get_batch(batch.batch_id).status == "PARTIALLY_COMPLETED"
    populate(harness, status="FAILED", verdict=None, analysis_id=ids[2])
    result = harness.service.get_batch(batch.batch_id)
    assert result.finished_count == 2 and result.summary.failed == 1
    assert result.summary.model_dump() == {
        "total": 3,
        "queued": 0,
        "running": 1,
        "completed": 1,
        "failed": 1,
        "auto_benign": 1,
        "auto_malicious": 0,
        "high_risk_uncertain": 1,
        "unclassified": 1,
    }
    assert result.status == "PARTIALLY_COMPLETED"


@pytest.mark.parametrize(
    "statuses,expected",
    [
        ([], "COMPLETED"),
        (["QUEUED", "QUEUED"], "QUEUED"),
        (["QUEUED", "RUNNING"], "RUNNING"),
        (["QUEUED", "FAILED"], "PARTIALLY_COMPLETED"),
        (["COMPLETED", "RUNNING"], "PARTIALLY_COMPLETED"),
        (["COMPLETED", "FAILED"], "COMPLETED"),
        (["COMPLETED", "COMPLETED"], "COMPLETED"),
        (["FAILED", "FAILED"], "FAILED"),
    ],
)
def test_batch_status_means_completion_not_maliciousness(harness, statuses, expected):
    original = submit_batch(harness, 1)
    record = harness.repository.get(original.analyses[0].analysis_id)
    result = batch_results.response(
        BatchRecord(
            "batch-example",
            [
                replace(record, status=state, analysis_id=f"analysis-{index}")
                for index, state in enumerate(statuses)
            ],
        )
    )
    assert result.status == expected
    assert result.summary.total == len(statuses)
    assert result.summary.auto_malicious == 0


def test_http_filters_priority_and_pagination_keep_initial_and_final_separate(harness):
    batch = submit_batch(harness, 6)
    ids = [row.analysis_id for row in batch.analyses]
    states = [
        ("RUNNING", "HIGH_RISK_UNCERTAIN"),
        ("COMPLETED", "AUTO_BENIGN"),
        ("RUNNING", "AUTO_MALICIOUS"),
        ("COMPLETED", "HIGH_RISK_UNCERTAIN"),
        ("QUEUED", None),
        ("FAILED", "HIGH_RISK_UNCERTAIN"),
    ]
    for identity, (status, verdict) in zip(ids, states):
        populate(harness, analysis_id=identity, status=status, verdict=verdict)
    # An expert can revise a final decision while the initial HIGH_RISK filter remains valid.
    harness.repository.save_review(
        ids[3],
        analyst_final_verdict="BENIGN",
        analyst_notes="test",
        reviewer_id="test",
        expected_revision=0,
    )
    other = submit_batch(harness, 1)
    populate(
        harness,
        analysis_id=other.analyses[0].analysis_id,
        status="RUNNING",
        verdict="HIGH_RISK_UNCERTAIN",
    )
    before = harness.repository.calls["claim"]
    with TestClient(create_app(harness.service)) as client:
        route = f"/batches/{batch.batch_id}"
        expected = [ids[3], ids[0], ids[2], ids[1], ids[4], ids[5]]
        for url in (route, route + "/analyses", "/analyses?batch_id=" + batch.batch_id):
            response = client.get(url)
            assert response.status_code == 200, response.text
            assert [
                row["analysis_id"] for row in response.json()["analyses"]
            ] == expected
        page = client.get(
            route + "/analyses",
            params={"verdict": "HIGH_RISK_UNCERTAIN", "limit": 1, "offset": 1},
        ).json()
        assert page["total_count"] == 3
        assert [row["analysis_id"] for row in page["analyses"]] == [ids[0]]
        completed = client.get(
            route + "/analyses",
            params={"verdict": "HIGH_RISK_UNCERTAIN", "status": "COMPLETED"},
        ).json()
        assert completed["total_count"] == 1
        assert completed["analyses"][0]["analyst_final_verdict"] == "BENIGN"
        assert completed["analyses"][0]["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
        hashed = client.get(
            route + "/analyses",
            params={
                "verdict": "HIGH_RISK_UNCERTAIN",
                "sha256": batch.analyses[0].sha256,
            },
        ).json()
        assert [row["analysis_id"] for row in hashed["analyses"]] == [ids[0]]
        empty = client.get(route + "/analyses?offset=100").json()
        assert empty["total_count"] == 6 and empty["analyses"] == []
        for sort, order in (("input_order", ids), ("newest", list(reversed(ids)))):
            for suffix in ("", "/analyses"):
                assert [
                    row["analysis_id"]
                    for row in client.get(route + suffix, params={"sort": sort}).json()[
                        "analyses"
                    ]
                ] == order
        assert client.get(route + "/analyses?verdict=MALICIOUS").status_code == 422
        assert client.get(route + "/analyses?sort=unsafe").status_code == 422
        assert client.get("/analyses?batch_id=missing").status_code == 404
        assert client.get("/analyses?sort=input_order").status_code == 422
    assert harness.repository.calls["claim"] == before


def test_direct_multi_input_receipt_is_distinct_from_analysis_failure(harness):
    result = harness.service.submit(
        [
            (io.BytesIO(b"text"), "notes.txt"),
            (io.BytesIO(harmless_pe_header()), "valid.exe"),
        ],
        batch=True,
    )
    populate(
        harness,
        analysis_id=result.analyses[0].analysis_id,
        status="FAILED",
        verdict=None,
    )
    response = harness.service.get_batch(result.batch_id)
    assert response.skipped_count == response.summary.failed == 1
    assert response.summary.total == 1 and response.input_count == 2
    assert response.status == "FAILED"
    assert (
        response.entries[0].status == "SKIPPED"
        and response.entries[0].analysis_id is None
    )
