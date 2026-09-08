"""Swagger 예시의 정확성과 기존 API 계약 보존을 검증한다."""

import json
import re
from urllib.parse import unquote

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from trust_triage.backend_api import runtime
from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.schemas import ErrorResponse, ReviewRequest


def test_docs_are_readable_without_database_or_analysis_dependencies(monkeypatch):
    def forbidden(_config):
        raise AssertionError("Documentation must not create external connections")

    monkeypatch.setattr(runtime, "create_service", forbidden)
    with TestClient(create_app(config=BackendConfig())) as client:
        for path in ("/docs", "/redoc", "/openapi.json", "/health"):
            assert client.get(path).status_code == 200
        schema = client.get("/openapi.json").json()
        assert "표준 처리 흐름" in schema["info"]["description"]
        assert "202 Accepted" in schema["info"]["description"]
        for path in schema["paths"].values():
            for operation in path.values():
                assert re.search(r"[가-힣]", operation["summary"])
                assert len(operation["description"]) > 50
                assert "### 목적" in operation["description"]
        links = re.findall(
            r"\]\(\./docs#/([^/]+)/([^)]+)\)", schema["info"]["description"]
        )
        targets = {
            (operation["tags"][0], operation["operationId"])
            for path in schema["paths"].values()
            for operation in path.values()
        }
        assert len(links) == 4
        assert all(
            (unquote(tag), operation_id) in targets for tag, operation_id in links
        )
        assert '"defaultModelsExpandDepth": 1' in client.get("/docs").text


def test_openapi_copy_uses_professional_contract_language():
    schema = create_app(config=BackendConfig()).openapi()
    rendered = json.dumps(schema, ensure_ascii=False)
    prohibited = (
        "처음이라면",
        "언제 쓰나요",
        "따라 해보세요",
        "해보세요",
        "붙여 넣으세요",
        "복사하세요",
        "비워 두세요",
    )
    assert not any(phrase in rendered for phrase in prohibited)
    assert {tag["name"] for tag in schema["tags"]} == {
        "01. 서비스 상태",
        "02. 분석 접수",
        "03. 분석 조회",
        "04. 배치 분석",
        "05. 전문가 검토",
    }


def test_swagger_examples_follow_real_request_and_response_models():
    app = create_app(config=BackendConfig())
    schema = app.openapi()
    count = 0
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        for method in route.methods:
            operation = schema["paths"][route.path][method.lower()]
            for code, response in operation["responses"].items():
                media = response.get("content", {}).get("application/json", {})
                examples = [row["value"] for row in media.get("examples", {}).values()]
                if "example" in media:
                    examples.append(media["example"])
                model = ErrorResponse if int(code) >= 400 else route.response_model
                for example in examples:
                    if model is not None:
                        model.model_validate(example)
                    count += 1
            if route.path.endswith("/verdict"):
                examples = operation["requestBody"]["content"]["application/json"][
                    "examples"
                ]
                decisions = {
                    ReviewRequest.model_validate(example["value"]).analyst_final_verdict
                    for example in examples.values()
                }
                assert decisions == {None, "BENIGN", "MALICIOUS"}
    assert count >= 13
    with TestClient(app) as client:
        health_example = schema["paths"]["/health"]["get"]["responses"]["200"][
            "content"
        ]["application/json"]["examples"]["ok"]["value"]
        assert client.get("/health").json() == health_example


def test_all_openapi_schema_references_resolve():
    schema = create_app(config=BackendConfig()).openapi()

    def verify(value):
        if isinstance(value, list):
            for item in value:
                verify(item)
        elif isinstance(value, dict):
            if "$ref" in value:
                reference = value["$ref"]
                assert reference.startswith("#/")
                target = schema
                for part in reference[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]
            for item in value.values():
                verify(item)

    verify(schema)


def test_upload_limits_and_auth_help_match_server_configuration():
    token = "example-test-token-do-not-reuse"
    config = BackendConfig(max_file_bytes=2048, max_batch_files=3, api_token=token)
    schema = create_app(config=config).openapi()
    upload = schema["paths"]["/analyses"]["post"]["description"]
    batch = schema["paths"]["/batches"]["post"]["description"]
    assert "2,048 bytes" in upload and "2,048 bytes" in batch
    assert "**3개**" in batch
    assert "X-API-Key`를 요구합니다" in schema["info"]["description"]
    assert token not in json.dumps(schema)
    public = create_app(config=BackendConfig()).openapi()
    assert "X-API-Key` 검증이 비활성화" in public["info"]["description"]
