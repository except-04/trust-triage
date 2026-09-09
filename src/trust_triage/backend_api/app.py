"""HTTP 접수/조회 창구. 오래 걸리는 분석은 여기서 실행하지 않는다."""

import asyncio
import hmac
import logging
import time
from copy import deepcopy
from typing import Annotated, Literal

from fastapi import Body, Depends, FastAPI, Header, Path, Query, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import (
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException

from . import api_docs, views
from .config import BackendConfig
from .errors import BackendError
from .schemas import (
    AnalysisAccepted,
    AnalysisListResponse,
    AnalysisProgress,
    AnalysisResponse,
    BatchAccepted,
    BatchAnalysisListResponse,
    BatchResponse,
    DeepAnalysisResponse,
    InitialVerdict,
    ReviewHistoryResponse,
    ReviewRequest,
    ReviewResponse,
    TriageResponse,
    XAIResponse,
)
from .service import BackendService

LOGGER = logging.getLogger(__name__)
_PUBLIC_PATHS = {"/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
_API_KEY = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ApiKeyAuth",
    description="API 접근 인증에 사용하는 X-API-Key 헤더입니다. 서버의 API 키 검증이 비활성화된 환경에서는 생략할 수 있습니다.",
    auto_error=False,
)
_REVIEW_KEY = APIKeyHeader(
    name="X-Reviewer-Key",
    scheme_name="ReviewerKeyAuth",
    description="전문가 검토 등록 권한을 검증하는 X-Reviewer-Key 헤더입니다. API 키 검증도 활성화된 환경에서는 두 인증 헤더가 모두 필요합니다.",
    auto_error=False,
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9_-]{1,128}$"
Identifier = Annotated[
    str,
    Path(
        pattern=_IDENTIFIER_PATTERN,
        description=api_docs.ANALYSIS_ID_HELP,
        examples=["analysis_example_001"],
    ),
]
BatchIdentifier = Annotated[
    str,
    Path(
        pattern=_IDENTIFIER_PATTERN,
        description=api_docs.BATCH_ID_HELP,
        examples=["batch_example_001"],
    ),
]
IdempotencyKey = Annotated[
    str | None, Header(max_length=200, description=api_docs.IDEMPOTENCY_HELP)
]
BatchSort = Annotated[
    Literal["high_risk_first", "newest", "input_order"],
    Query(
        description="기본 high_risk_first는 고위험→자동 악성→자동 정상→미판정→실패 순서입니다. newest는 최신 접수순, input_order는 배치 입력순입니다. 실행 순서는 바꾸지 않습니다."
    ),
]


def _listing_filters(
    limit: Annotated[
        int,
        Query(
            ge=1, le=100, description="페이지당 결과 수입니다. 기본 20, 최대 100입니다."
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="앞에서 건너뛸 결과 수입니다. 다음 페이지는 offset + limit입니다.",
        ),
    ] = 0,
    status: Annotated[
        Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"] | None,
        Query(
            description="분석 진행 상태 필터입니다. 생략하면 모든 상태를 조회합니다."
        ),
    ] = None,
    sha256: Annotated[
        str | None,
        Query(
            pattern=r"^[0-9a-f]{64}$", description="64자리 소문자 SHA-256 필터입니다."
        ),
    ] = None,
    verdict: Annotated[
        InitialVerdict | None,
        Query(
            description="JRR 초기 판정 필터입니다. 최종 시스템 판정·전문가 판정과 별개입니다."
        ),
    ] = None,
):
    return {
        "limit": limit,
        "offset": offset,
        "status": status,
        "sha256": sha256,
        "verdict": verdict,
    }


ListingFilters = Annotated[dict, Depends(_listing_filters)]


class RequestBoundary:
    """본문을 받기 전에 인증한다. Content-Length가 없어도 실제 수신 바이트를 센다."""

    def __init__(self, app, config: BackendConfig):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        path, config = scope["path"], self.config
        if (
            config.api_token
            and path not in _PUBLIC_PATHS
            and not hmac.compare_digest(
                headers.get(b"x-api-key", b""), config.api_token.encode()
            )
        ):
            await JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "X-API-Key를 확인해주세요.",
                        "stage": None,
                        "retryable": False,
                    }
                },
            )(scope, receive, send)
            return
        max_bytes = (
            config.max_zip_bytes + 1024 * 1024
            if path == "/batches/zip"
            else (
                config.max_file_bytes
                * (config.max_batch_files if path == "/batches" else 1)
                + 1024 * 1024
                if path in {"/analyses", "/batches"}
                else 64 * 1024
            )
        )
        received, started, response_started = 0, time.monotonic(), False

        async def limited_receive():
            nonlocal received
            remaining = config.upload_timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise BackendError(
                    "UPLOAD_TIMEOUT",
                    "요청 본문 업로드 시간이 초과되었습니다.",
                    http_status=408,
                    stage="UPLOAD",
                )
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError as exc:
                raise BackendError(
                    "UPLOAD_TIMEOUT",
                    "요청 본문 업로드 시간이 초과되었습니다.",
                    http_status=408,
                    stage="UPLOAD",
                ) from exc
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    raise BackendError(
                        "REQUEST_TOO_LARGE",
                        "요청 본문이 허용 크기를 초과했습니다.",
                        http_status=413,
                        stage="UPLOAD",
                    )
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            if b"content-length" in headers:
                try:
                    length = int(headers[b"content-length"])
                    if length < 0:
                        raise ValueError
                except ValueError as exc:
                    raise BackendError(
                        "INVALID_CONTENT_LENGTH",
                        "Content-Length가 올바르지 않습니다.",
                        http_status=400,
                    ) from exc
                if length > max_bytes:
                    raise BackendError(
                        "REQUEST_TOO_LARGE",
                        "요청 본문이 허용 크기를 초과했습니다.",
                        http_status=413,
                        stage="UPLOAD",
                    )
            await self.app(scope, limited_receive, tracked_send)
        except BackendError as exc:
            if response_started:
                raise
            await JSONResponse(
                status_code=exc.http_status, content={"error": exc.to_dict()}
            )(scope, receive, send)
        except Exception:
            if response_started:
                raise
            LOGGER.error("unexpected_backend_http_error")
            await JSONResponse(
                status_code=500,
                content={
                    "error": BackendError(
                        "INTERNAL_ERROR", "서버 처리 중 오류가 발생했습니다."
                    ).to_dict()
                },
            )(scope, receive, send)


def _upload_schema(multiple: bool, *, archive: bool = False) -> dict:
    key = "files" if multiple else "file"
    value = {
        "type": "string",
        "format": "binary",
        "description": "분석할 .exe/.dll 파일이 들어 있는 ZIP 한 개입니다."
        if archive
        else "분석 대상 Windows PE 파일입니다. 지원 확장자는 .exe와 .dll입니다.",
    }
    if multiple:
        value = {
            "type": "array",
            "items": value,
            "description": "배치 분석 대상 파일 목록입니다. 파일 수와 파일별 용량은 서버 설정의 상한을 적용합니다.",
        }
    return {
        "requestBody": {
            "required": True,
            "description": "multipart/form-data 형식의 ZIP 본문입니다."
            if archive
            else "multipart/form-data 형식의 PE 파일 본문입니다. 바이너리를 JSON으로 인코딩하지 않습니다.",
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": [key],
                        "properties": {key: value},
                    }
                }
            },
        }
    }


def create_app(
    service: BackendService | None = None, config: BackendConfig | None = None
) -> FastAPI:
    config = config or (service.config if service else BackendConfig.from_env())
    docs = api_docs.operations(config)
    app = FastAPI(
        title="TRUST-TRIAGE Backend API",
        version="0.1.0",
        docs_url=None,
        description=api_docs.introduction(config),
        openapi_tags=api_docs.TAGS,
        swagger_ui_parameters=api_docs.SWAGGER_PARAMETERS,
        responses=api_docs.error_responses(500),
    )
    app.state.service = service
    app.add_middleware(RequestBoundary, config=config)

    @app.get("/docs", include_in_schema=False)
    async def swagger_docs(request: Request):
        root_path = request.scope.get("root_path", "").rstrip("/")
        html = get_swagger_ui_html(
            openapi_url=f"{root_path}{app.openapi_url}",
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=f"{root_path}/docs/oauth2-redirect",
            swagger_ui_parameters=app.swagger_ui_parameters,
        ).body.decode("utf-8")
        return HTMLResponse(
            html.replace("</body>", api_docs.NAVIGATION_SCRIPT + "</body>")
        )

    @app.get("/docs/oauth2-redirect", include_in_schema=False)
    async def swagger_oauth_redirect():
        return get_swagger_ui_oauth2_redirect_html()

    @app.exception_handler(BackendError)
    async def backend_error(_request, exc):
        return JSONResponse(
            status_code=exc.http_status, content={"error": exc.to_dict()}
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, _exc):
        return JSONResponse(
            status_code=422,
            content={
                "error": BackendError(
                    "INVALID_REQUEST",
                    "요청 필드 형식과 필수 값을 /docs에서 확인해주세요.",
                    http_status=422,
                ).to_dict()
            },
        )

    @app.exception_handler(HTTPException)
    async def http_error(_request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": BackendError(
                    "INVALID_HTTP_REQUEST",
                    "요청 경로·메서드·multipart 형식을 확인해주세요.",
                    http_status=exc.status_code,
                ).to_dict()
            },
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_request, _exc):
        LOGGER.error("unexpected_backend_http_error")
        return JSONResponse(
            status_code=500,
            content={
                "error": BackendError(
                    "INTERNAL_ERROR", "서버 처리 중 오류가 발생했습니다."
                ).to_dict()
            },
        )

    def backend() -> BackendService:
        if app.state.service is None:
            from .runtime import create_service

            app.state.service = create_service(config)
        return app.state.service

    def authorize(key: Annotated[str | None, Security(_API_KEY)] = None):
        if config.api_token and (
            key is None
            or not hmac.compare_digest(key.encode(), config.api_token.encode())
        ):
            raise BackendError(
                "UNAUTHORIZED", "X-API-Key를 확인해주세요.", http_status=401
            )

    def authorize_review(key: Annotated[str | None, Security(_REVIEW_KEY)] = None):
        expected = config.reviewer_token
        if expected and (
            key is None or not hmac.compare_digest(key.encode(), expected.encode())
        ):
            raise BackendError(
                "REVIEW_FORBIDDEN", "X-Reviewer-Key를 확인해주세요.", http_status=403
            )

    dependencies = [Depends(authorize)]

    @app.get("/health", **docs["health"])
    def health():
        return {"status": "ok", "service": "trust-triage-backend", "version": "0.1.0"}

    @app.get("/ready", dependencies=dependencies, **docs["ready"])
    def ready(svc: Annotated[BackendService, Depends(backend)]):
        svc.repository.check()
        return {"status": "ready"}

    async def submit(request: Request, svc, batch, key, *, archive=False):
        expected = "files" if batch and not archive else "file"
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "multipart/form-data"
        ):
            raise BackendError(
                "INVALID_UPLOAD_TYPE",
                "multipart/form-data로 파일을 올려주세요.",
                http_status=422,
                stage="UPLOAD",
            )
        async with request.form(
            max_files=config.max_batch_files if batch and not archive else 1,
            max_fields=0,
            max_part_size=config.max_zip_bytes if archive else config.max_file_bytes,
        ) as form:
            entries = list(form.multi_items())
            if not entries or any(
                name != expected or not isinstance(value, UploadFile)
                for name, value in entries
            ):
                raise BackendError(
                    "INVALID_UPLOAD",
                    f"multipart/form-data의 {expected} 파일 필드를 확인해주세요.",
                    http_status=422,
                    stage="UPLOAD",
                )
            uploads = [(value.file, value.filename or "") for _, value in entries]
            if archive:
                return await run_in_threadpool(
                    svc.submit_zip, uploads, idempotency_key=key
                )
            return await run_in_threadpool(
                svc.submit,
                uploads,
                batch=batch,
                idempotency_key=key,
            )

    @app.post(
        "/analyses",
        status_code=202,
        response_model=AnalysisAccepted,
        dependencies=dependencies,
        openapi_extra=_upload_schema(False),
        **docs["upload"],
    )
    async def upload(
        request: Request,
        svc: Annotated[BackendService, Depends(backend)],
        idempotency_key: IdempotencyKey = None,
    ):
        return await submit(request, svc, False, idempotency_key)

    @app.post(
        "/batches",
        status_code=202,
        response_model=BatchAccepted,
        dependencies=dependencies,
        openapi_extra=_upload_schema(True),
        **docs["upload_batch"],
    )
    async def upload_batch(
        request: Request,
        svc: Annotated[BackendService, Depends(backend)],
        idempotency_key: IdempotencyKey = None,
    ):
        return await submit(request, svc, True, idempotency_key)

    @app.post(
        "/batches/zip",
        status_code=202,
        response_model=BatchAccepted,
        dependencies=dependencies,
        openapi_extra=_upload_schema(False, archive=True),
        **docs["upload_zip"],
    )
    async def upload_zip(
        request: Request,
        svc: Annotated[BackendService, Depends(backend)],
        idempotency_key: IdempotencyKey = None,
    ):
        return await submit(request, svc, True, idempotency_key, archive=True)

    @app.get(
        "/analyses",
        response_model=AnalysisListResponse,
        dependencies=dependencies,
        **docs["list_analyses"],
    )
    def list_analyses(
        svc: Annotated[BackendService, Depends(backend)],
        filters: ListingFilters,
        batch_id: Annotated[
            str | None,
            Query(
                pattern=_IDENTIFIER_PATTERN,
                description="특정 배치에 포함된 결과만 조회합니다.",
            ),
        ] = None,
        sort: Annotated[
            Literal["high_risk_first", "newest"],
            Query(
                description="기본 high_risk_first는 고위험 우선이며 실패는 마지막입니다. newest는 최신 접수순입니다. 실행 순서는 바꾸지 않습니다."
            ),
        ] = "high_risk_first",
    ):
        return svc.list_analyses(batch_id=batch_id, sort=sort, **filters)

    @app.get(
        "/analyses/{analysis_id}",
        response_model=AnalysisResponse,
        dependencies=dependencies,
        **docs["get_analysis"],
    )
    def get_analysis(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return views.analysis(svc.get(analysis_id))

    @app.get(
        "/analyses/{analysis_id}/status",
        response_model=AnalysisProgress,
        dependencies=dependencies,
        **docs["get_status"],
    )
    def get_status(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return views.progress(svc.get(analysis_id))

    @app.get(
        "/analyses/{analysis_id}/triage",
        response_model=TriageResponse,
        dependencies=dependencies,
        **docs["get_triage"],
    )
    def get_triage(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return views.triage(svc.get(analysis_id))

    @app.get(
        "/analyses/{analysis_id}/deep-analysis",
        response_model=DeepAnalysisResponse,
        dependencies=dependencies,
        **docs["get_deep"],
    )
    def get_deep(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return views.deep_analysis(svc.get(analysis_id))

    @app.get(
        "/analyses/{analysis_id}/xai",
        response_model=XAIResponse,
        dependencies=dependencies,
        **docs["get_xai"],
    )
    def get_xai(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return views.xai(svc.get(analysis_id))

    @app.get(
        "/batches/{batch_id}",
        response_model=BatchResponse,
        dependencies=dependencies,
        **docs["get_batch"],
    )
    def get_batch(
        batch_id: BatchIdentifier,
        svc: Annotated[BackendService, Depends(backend)],
        sort: BatchSort = "high_risk_first",
    ):
        return svc.get_batch(batch_id, sort=sort)

    @app.get(
        "/batches/{batch_id}/analyses",
        response_model=BatchAnalysisListResponse,
        dependencies=dependencies,
        **docs["list_batch_analyses"],
    )
    def list_batch_analyses(
        batch_id: BatchIdentifier,
        svc: Annotated[BackendService, Depends(backend)],
        filters: ListingFilters,
        sort: BatchSort = "high_risk_first",
    ):
        return svc.list_batch_analyses(batch_id, sort=sort, **filters)

    @app.patch(
        "/analyses/{analysis_id}/verdict",
        response_model=ReviewResponse,
        dependencies=[*dependencies, Depends(authorize_review)],
        **docs["save_review"],
    )
    def save_review(
        analysis_id: Identifier,
        request: Annotated[
            ReviewRequest, Body(openapi_examples=api_docs.REVIEW_EXAMPLES)
        ],
        svc: Annotated[BackendService, Depends(backend)],
    ):
        return svc.review(analysis_id, request)

    @app.get(
        "/analyses/{analysis_id}/reviews",
        response_model=ReviewHistoryResponse,
        dependencies=dependencies,
        **docs["list_reviews"],
    )
    def list_reviews(
        analysis_id: Identifier, svc: Annotated[BackendService, Depends(backend)]
    ):
        return svc.reviews(analysis_id)

    default_openapi = app.openapi

    def openapi():
        schema = default_openapi()
        # FastAPI의 exclude_none 직렬화로 설명용 JSON의 null이 빠지지 않도록 보존한다.
        for route in app.routes:
            if route.name not in docs:
                continue
            for method in route.methods:
                operation = schema["paths"][route.path][method.lower()]
                for code, response in docs[route.name]["responses"].items():
                    media = response.get("content", {}).get("application/json", {})
                    target = operation["responses"][str(code)]["content"][
                        "application/json"
                    ]
                    for key in ("example", "examples"):
                        if key in media:
                            target[key] = deepcopy(media[key])
        review_operation = schema["paths"]["/analyses/{analysis_id}/verdict"]["patch"]
        review_operation["requestBody"]["content"]["application/json"]["examples"] = (
            deepcopy(api_docs.REVIEW_EXAMPLES)
        )
        # FastAPI의 별도 Security 의존성은 기본 OR 표현이다. 검토 저장은 두 키를 함께 확인한다.
        schema["paths"]["/analyses/{analysis_id}/verdict"]["patch"]["security"] = [
            {"ApiKeyAuth": [], "ReviewerKeyAuth": []}
        ]
        return schema

    app.openapi = openapi
    return app
