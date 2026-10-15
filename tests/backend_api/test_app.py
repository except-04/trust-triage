"""실제 HTTP 경계와 공개 응답을 검증한다. 분석 도구/모델은 실행하지 않는다."""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from trust_triage.backend_api.app import RequestBoundary, create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.service import BackendService
from trust_triage.backend_api.storage import LocalSampleStorage

from .fake_repository import MemoryAnalysisRepository
from .test_service_processor import initial_result


def header_bytes():
    # 파서 검사용 헤더일 뿐 실행 코드/실제 PE 샘플이 아니다.
    value = bytearray(256)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 0x3C, 64)
    value[64:68] = b"PE\0\0"
    struct.pack_into("<HH", value, 68, 0x14C, 1)
    struct.pack_into("<HH", value, 84, 96, 0)
    struct.pack_into("<H", value, 88, 0x10B)
    return bytes(value)


@pytest.fixture
def api(tmp_path):
    config = BackendConfig(
        storage_root=tmp_path / "samples", max_file_bytes=512, max_batch_files=2
    )
    repository = MemoryAnalysisRepository()
    service = BackendService(
        repository,
        LocalSampleStorage(config.storage_root, max_file_bytes=config.max_file_bytes),
        config,
    )
    with TestClient(create_app(service), raise_server_exceptions=False) as client:
        yield client, service


def upload(client, **kwargs):
    return client.post(
        "/analyses", files={"file": ("harmless.exe", header_bytes())}, **kwargs
    )


def test_fail_closed_scores_and_reason_survive_http_and_queue(api):
    client, service = api
    identity = upload(client).json()["analysis_id"]
    value = initial_result("HIGH_RISK_UNCERTAIN")
    value.update(reason_code="SYSTEM_ERROR_FAIL_CLOSED", triggered_signals=[])
    value["prediction"] = {key: None for key in value["prediction"]}
    value["risk_signals"] = {key: None for key in value["risk_signals"]}
    service.repository.rows[identity] = replace(
        service.repository.rows[identity], initial_result=value
    )
    for suffix in ("", "/triage"):
        response = client.get(f"/analyses/{identity}{suffix}")
        assert response.status_code == 200, response.text
        assert response.json()["reason_code"] == "SYSTEM_ERROR_FAIL_CLOSED"
        assert response.json()["prediction"]["calibrated_probability"] is None
    response = client.get("/analyst/recommendations")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["error_queue"] == []
    item = (payload["deep_recommendations"] + payload["deep_waiting"])[0]
    assert item["reason_code"] == "SYSTEM_ERROR_FAIL_CLOSED"
    assert item["score_policy"] == "fail-closed-v1"
    assert item["calibrated_probability"] is None


def test_failed_without_initial_result_is_exposed_by_error_queue_http(api):
    client, service = api
    identity = upload(client).json()["analysis_id"]
    service.repository.rows[identity] = replace(
        service.repository.rows[identity], status="FAILED", phase="DONE",
        error={"code": "JRR_OUTPUT_INVALID", "stage": "INITIAL_JRR", "message": "Invalid JRR output"},
    )
    response = client.get("/analyst/recommendations")
    assert response.status_code == 200, response.text
    item = response.json()["error_queue"][0]
    assert item["analysis_id"] == identity
    assert item["initial_verdict"] is None
    assert item["error"]["code"] == "JRR_OUTPUT_INVALID"
    detail = client.get(f"/analyses/{identity}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "FAILED"
    assert detail.json()["prediction"] is None


def test_jrr_inconsistency_history_survives_http_and_deep_queue(api):
    from trust_triage.backend_api.jrr_contract import recover_jrr_inconsistency

    client, service = api
    identity = upload(client).json()["analysis_id"]
    original = initial_result("AUTO_BENIGN")
    original["triggered_signals"] = ["OOD"]
    recovered = recover_jrr_inconsistency(original)
    service.repository.rows[identity] = replace(
        service.repository.rows[identity], initial_result=recovered
    )
    for suffix in ("", "/triage"):
        response = client.get(f"/analyses/{identity}{suffix}")
        assert response.status_code == 200, response.text
        assert response.json()["jrr_error"]["original_verdict"] == "AUTO_BENIGN"
        assert response.json()["jrr_error"]["original_triggered_signals"] == ["OOD"]
    response = client.get("/analyst/recommendations")
    assert response.status_code == 200
    item = response.json()["deep_recommendations"][0]
    assert item["score_policy"] == "jrr-inconsistent-v1"
    assert item["jrr_error"] == recovered["jrr_error"]


@pytest.mark.parametrize("reviewed", [False, True])
def test_failures_survive_same_hash_success_and_review_in_http(api, reviewed):
    client, service = api
    ids = [upload(client).json()["analysis_id"] for _ in range(3)]
    for identity in ids[:2]:
        service.repository.rows[identity] = replace(
            service.repository.rows[identity], status="FAILED", phase="DONE",
            error={"code": "PROCESSING_FAILED", "stage": "INITIAL_ANALYSIS"},
        )
    success = ids[2]
    service.repository.rows[success] = replace(
        service.repository.rows[success], status="COMPLETED", phase="DONE",
        initial_result=initial_result("AUTO_BENIGN"),
    )
    if reviewed:
        review = client.patch(f"/analyses/{success}/verdict", json={
            "analyst_final_verdict": "BENIGN", "reviewer_id": "tester", "expected_revision": 0
        })
        assert review.status_code == 200, review.text
        completed = client.get("/analyses", params={"reviewed_only": True}).json()
        assert any(item["analysis_id"] == success for item in completed["analyses"])
    response = client.get("/analyst/recommendations")
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result["error_queue"]) == 1
    grouped = result["error_queue"][0]
    assert grouped["failure_count"] == 2
    assert grouped["analysis_count"] == 3
    assert {h["analysis_id"] for h in grouped["analysis_history"]} == set(ids)
    assert all(not item["has_initial_result"] for item in result["error_queue"])
    if not reviewed:
        assert any(item["analysis_id"] == success for item in result["auto_queue"])


def test_deep_failure_http_is_visible_in_both_tabs(api):
    client, service = api
    identity = upload(client).json()["analysis_id"]
    service.repository.rows[identity] = replace(
        service.repository.rows[identity], status="FAILED", phase="DONE",
        initial_result=initial_result("HIGH_RISK_UNCERTAIN"),
        error={"code": "DEEP_REQUIRES_S3", "stage": "CAPA_FLOSS"},
    )
    response = client.get("/analyst/recommendations")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["deep_recommendations"][0]["analysis_id"] == identity
    assert result["error_queue"][0]["analysis_id"] == identity
    assert result["error_queue"][0]["has_initial_result"] is True




def test_upload_and_all_read_routes_are_read_only(api):
    client, service = api
    response = upload(client)
    assert response.status_code == 202
    accepted = response.json()
    identity = accepted["analysis_id"]
    calls = service.repository.calls.copy()
    for suffix in ("", "/status", "/triage", "/deep-analysis", "/xai", "/reviews"):
        value = client.get(f"/analyses/{identity}{suffix}")
        assert value.status_code == 200, value.text
        assert value.json()["analysis_id"] == identity
        assert "file_location" not in value.text and "local://" not in value.text
    assert service.repository.calls["claim"] == calls["claim"] == 0
    assert client.get("/analyses").json()["total_count"] == 1
    assert (
        client.get("/analyses", params={"sha256": accepted["sha256"]}).json()[
            "total_count"
        ]
        == 1
    )


def test_batch_replay_and_status_counts(api):
    client, service = api
    files = [
        ("files", ("one.exe", header_bytes())),
        ("files", ("two.dll", header_bytes())),
    ]
    first = client.post("/batches", files=files, headers={"Idempotency-Key": "batch-1"})
    second = client.post(
        "/batches", files=files, headers={"Idempotency-Key": "batch-1"}
    )
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    result = client.get("/batches/" + first.json()["batch_id"]).json()
    assert result["total_count"] == 2 and result["finished_count"] == 0
    assert result["status_counts"]["QUEUED"] == 2
    assert len(service.repository.rows) == 2


@pytest.mark.parametrize(
    "signals",
    [None, [], ["OOD"], ["OOD", "DISAGREEMENT", "DIFFICULTY", "UNCERTAIN_PROBABILITY"]],
)
def test_all_result_routes_preserve_recorded_signals_and_legacy_unknown(api, signals):
    client, service = api
    receipt = client.post(
        "/batches", files=[("files", ("one.exe", header_bytes()))]
    ).json()
    identity = receipt["analyses"][0]["analysis_id"]
    assert (
        client.get(f"/analyses/{identity}/triage").json()["triggered_signals"] is None
    )
    initial = initial_result("HIGH_RISK_UNCERTAIN" if signals else "AUTO_BENIGN")
    if signals is None:
        initial.pop("triggered_signals")
    else:
        initial["triggered_signals"] = signals
    claim = service.repository.claim(identity, 600)
    assert service.repository.save_initial(
        identity, claim.token, initial, bool(signals)
    )
    for suffix in ("", "/triage"):
        result = client.get(f"/analyses/{identity}{suffix}")
        assert result.status_code == 200, result.text
        assert result.json()["triggered_signals"] == signals
        assert result.json()["reason"] == initial["reason"]
    for url in (
        "/analyses",
        f"/batches/{receipt['batch_id']}",
        f"/batches/{receipt['batch_id']}/analyses",
    ):
        response = client.get(url)
        assert response.status_code == 200, response.text
        assert response.json()["analyses"][0]["triggered_signals"] == signals
    assert service.repository.get(identity).initial_result == initial


@pytest.mark.parametrize(
    "stored,expected",
    [
        (
            {"feature_name": "header[9]", "display_name": "Major Linker Version"},
            "Major Linker Version",
        ),
        # display_name 도입 이전에 저장된 기록은 null 로 나간다
        ({"feature_name": "header[9]"}, None),
    ],
    ids=["labeled", "legacy"],
)
def test_top_features_expose_display_name_as_an_additive_field(api, stored, expected):
    client, service = api
    identity = upload(client).json()["analysis_id"]
    initial = initial_result("AUTO_BENIGN")
    initial["top_features"] = [
        {**stored, "feature_value": 14.0, "shap_value": 0.25, "direction": "MALICIOUS"}
    ]
    claim = service.repository.claim(identity, 600)
    assert service.repository.save_initial(identity, claim.token, initial, False)

    for suffix in ("", "/xai"):
        response = client.get(f"/analyses/{identity}{suffix}")
        assert response.status_code == 200, response.text
        feature = response.json()["top_features"][0]
        assert feature["feature_name"] == "header[9]"  # 식별자는 그대로
        assert feature["display_name"] == expected
    listed = client.get("/analyses").json()["analyses"][0]["top_features"][0]
    assert listed["display_name"] == expected


def test_openapi_documents_display_name_as_optional(api):
    schema = api[0].get("/openapi.json").json()
    top_feature = schema["components"]["schemas"]["TopFeature"]
    assert "display_name" in top_feature["properties"]
    assert "display_name" not in top_feature.get("required", [])
    assert "feature_name" in top_feature["required"]


@pytest.mark.parametrize(
    "route",
    [
        "/analyses/missing",
        "/analyses/missing/status",
        "/analyses/missing/triage",
        "/analyses/missing/deep-analysis",
        "/analyses/missing/xai",
        "/analyses/missing/reviews",
        "/batches/missing",
    ],
)
def test_unknown_ids_return_consistent_errors(api, route):
    client, _ = api
    response = client.get(route)
    assert response.status_code == 404
    assert set(response.json()) == {"error"}


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"sha256": "bad"},
        {"status": "NOT_REQUIRED"},
    ],
)
def test_list_validation(api, params):
    response = api[0].get("/analyses", params=params)
    assert (
        response.status_code == 422
        and response.json()["error"]["code"] == "INVALID_REQUEST"
    )


@pytest.mark.parametrize(
    "files,expected",
    [
        ({"file": ("a.txt", header_bytes())}, 422),
        ({"file": ("a.exe", b"not PE")}, 422),
        ({"file": ("a.exe", b"")}, 422),
        ({"file": ("a.exe", header_bytes() + bytes(512))}, 413),
        ({"wrong": ("a.exe", header_bytes())}, 422),
        (
            [("file", ("a.exe", header_bytes())), ("file", ("b.exe", header_bytes()))],
            400,
        ),
    ],
)
def test_rejected_uploads_leave_no_jobs_or_files(api, files, expected):
    client, service = api
    response = client.post("/analyses", files=files)
    assert response.status_code == expected, response.text
    assert not service.repository.rows
    assert not list(service.config.storage_root.glob("**/sample.bin"))


def test_unauthorized_request_rejected_before_body_or_storage(api):
    _, service = api
    config = replace(service.config, api_token="a" * 24, reviewer_token="r" * 24)
    with TestClient(
        create_app(service, config), raise_server_exceptions=False
    ) as client:
        assert upload(client).status_code == 401
        assert client.get("/analyses").status_code == 401
        assert client.get("/health").status_code == 200
        assert client.get("/docs").status_code == 200
        accepted = upload(client, headers={"X-API-Key": "a" * 24})
        assert accepted.status_code == 202
        response = client.patch(
            f"/analyses/{accepted.json()['analysis_id']}/verdict",
            headers={"X-API-Key": "a" * 24},
            json={
                "analyst_final_verdict": "BENIGN",
                "reviewer_id": "tester",
                "expected_revision": 0,
            },
        )
        assert response.status_code == 403


def test_review_preserves_system_verdict_and_detects_conflict(api):
    client, service = api
    identity = upload(client).json()["analysis_id"]
    claim = service.repository.claim(identity, 900)
    service.repository.finish(
        identity,
        claim.token,
        {
            "final_verdict": "UNCERTAIN",
            "disposition": "ANALYSIS_FAILED",
            "requires_human_review": True,
            "reason": "test failure",
            "policy_version": "test",
        },
        error={"code": "TEST_FAILURE", "message": "test"},
    )
    payload = {
        "analyst_final_verdict": "BENIGN",
        "reviewer_id": "tester",
        "analyst_notes": "검토 결과",
        "expected_revision": 0,
    }
    response = client.patch(f"/analyses/{identity}/verdict", json=payload)
    assert response.status_code == 200 and response.json()["revision"] == 1
    assert (
        client.patch(f"/analyses/{identity}/verdict", json=payload).status_code == 409
    )
    result = client.get(f"/analyses/{identity}").json()
    assert result["status"] == "FAILED"
    assert (
        result["final_verdict"] == "INCONCLUSIVE"
        and result["analyst_final_verdict"] == "BENIGN"
    )
    assert result["approval_status"] == "MODIFIED"
    assert len(client.get(f"/analyses/{identity}/reviews").json()["items"]) == 1
    reviewed = client.get("/analyses", params={"reviewed_only": True}).json()
    assert reviewed["total_count"] == 1
    assert reviewed["analyses"][0]["analysis_id"] == identity


def test_openapi_has_uploads_contract_and_error_models(api):
    schema = api[0].get("/openapi.json").json()
    for path, field in (("/analyses", "file"), ("/batches", "files")):
        operation = schema["paths"][path]["post"]
        assert "202" in operation["responses"]
        assert (
            field
            in operation["requestBody"]["content"]["multipart/form-data"]["schema"][
                "properties"
            ]
        )
    security = schema["components"]["securitySchemes"]
    assert security["ApiKeyAuth"]["name"] == "X-API-Key"
    assert security["ReviewerKeyAuth"]["name"] == "X-Reviewer-Key"
    assert schema["paths"]["/analyses/{analysis_id}/verdict"]["patch"]["security"] == [
        {"ApiKeyAuth": [], "ReviewerKeyAuth": []}
    ]
    assert "file_location" not in json.dumps(schema)


@pytest.mark.parametrize(
    "length,expected", [("-1", 400), ("bad", 400), (str(2 * 1024 * 1024), 413)]
)
def test_content_length_boundary(api, length, expected):
    response = api[0].post(
        "/analyses", content=b"x", headers={"Content-Length": length}
    )
    assert response.status_code == expected


def test_chunked_body_actual_size_limit_and_idle_timeout():
    async def exercise(timeout):
        output, calls = [], 0
        config = BackendConfig(
            max_file_bytes=1, upload_timeout_seconds=0.01 if timeout else 5
        )

        async def receive():
            nonlocal calls
            calls += 1
            if timeout:
                await asyncio.sleep(1)
            return {"type": "http.request", "body": bytes(600000), "more_body": True}

        async def send(value):
            output.append(value)

        async def consumer(_scope, receive, _send):
            while True:
                await receive()

        await RequestBoundary(consumer, config)(
            {"type": "http", "path": "/analyses", "headers": []}, receive, send
        )
        assert output[0]["status"] == (408 if timeout else 413)
        assert calls == (1 if timeout else 2)

    asyncio.run(exercise(False))
    asyncio.run(exercise(True))


def test_internal_errors_redacted(api, monkeypatch):
    client, service = api

    def broken(*_args, **_kwargs):
        raise RuntimeError("postgres://user:SECRET@private-host password=SECRET")

    monkeypatch.setattr(service.repository, "list_analyses", broken)
    response = client.get("/analyses")
    assert response.status_code == 500
    assert "SECRET" not in response.text and "private-host" not in response.text
    with TestClient(create_app(service), raise_server_exceptions=True) as strict:
        assert strict.get("/analyses").status_code == 500
