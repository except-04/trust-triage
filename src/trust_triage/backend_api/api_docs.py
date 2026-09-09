"""Swagger의 안내 문구와 설명용 예시. 분석·접수 로직은 포함하지 않는다."""

from urllib.parse import quote

from .config import BackendConfig
from .schemas import ErrorResponse

STATUS_TAG = "01. 서비스 상태"
UPLOAD_TAG = "02. 분석 접수"
RESULT_TAG = "03. 분석 조회"
BATCH_TAG = "04. 배치 분석"
REVIEW_TAG = "05. 전문가 검토"

TAGS = [
    {
        "name": STATUS_TAG,
        "description": "서비스 프로세스의 생존 상태와 데이터베이스 준비 상태를 진단합니다.",
    },
    {
        "name": UPLOAD_TAG,
        "description": "단일 Windows PE 파일을 비동기 분석 작업으로 등록합니다.",
    },
    {
        "name": RESULT_TAG,
        "description": "분석 수명주기, 모델 판정, 위험 신호, 설명 및 심층 분석 증거를 조회합니다.",
    },
    {
        "name": BATCH_TAG,
        "description": "여러 PE 파일을 하나의 배치로 등록하고 파일별 처리 결과를 집계합니다.",
    },
    {
        "name": REVIEW_TAG,
        "description": "완료된 분석에 대한 전문가 판정과 근거를 기록하고 변경 이력을 조회합니다.",
    },
]

SWAGGER_PARAMETERS = {
    "docExpansion": "list",
    "defaultModelsExpandDepth": 1,
    "defaultModelExpandDepth": 2,
    "displayRequestDuration": True,
    "filter": True,
    "showCommonExtensions": True,
}

# Swagger의 Markdown 링크가 새 탭을 열지 않도록 안내 표의 이동만 처리한다.
NAVIGATION_SCRIPT = """
<script>
document.addEventListener("click", function (event) {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const link = event.target.closest?.("a");
    if (!link || !link.getAttribute("href")?.startsWith("./docs#/")) return;
    const target = new URL(link.href, document.baseURI);
    if (target.origin !== location.origin || target.pathname !== location.pathname) return;
    const operationId = decodeURIComponent(target.hash.split("/").pop());
    const block = Array.from(document.querySelectorAll(".opblock[id]"))
        .find(item => item.id.endsWith("-" + operationId));
    const control = block?.querySelector(".opblock-summary-control");
    if (!control) return;
    event.preventDefault();
    event.stopPropagation();
    if (control.getAttribute("aria-expanded") !== "true") control.click();
    block.scrollIntoView({block: "start"});
    control.focus({preventScroll: true});
}, true);
</script>
"""

ANALYSIS_ID_HELP = (
    "분석 리소스 식별자. POST /analyses, POST /batches 또는 POST /batches/zip 응답의 analysis_id를 사용합니다. "
    "문서에 표시된 예시 식별자는 실제 조회 대상이 아닙니다."
)
BATCH_ID_HELP = "배치 리소스 식별자. POST /batches 또는 POST /batches/zip 응답의 batch_id를 사용하며, 파일별 analysis_id와 구분됩니다."
IDEMPOTENCY_HELP = (
    "선택적 멱등성 키. 동일한 업로드 요청을 재전송할 때 같은 값을 사용하면 중복 작업 생성을 방지합니다. "
    "동일한 키에 다른 파일 집합을 사용하면 409가 반환됩니다."
)


def introduction(config: BackendConfig) -> str:
    auth = (
        "**인증 정책:** 이 배포 환경은 `X-API-Key`를 요구합니다. Swagger UI의 "
        "**Authorize → ApiKeyAuth**가 해당 헤더를 설정합니다."
        if config.api_token
        else "**인증 정책:** 현재 배포 환경에서는 `X-API-Key` 검증이 비활성화되어 있습니다."
    )
    return f"""TRUST-TRIAGE Backend API는 Windows PE(`.exe`, `.dll`)를 접수하고 정적 모델 판정,
위험 신호, 선택적 심층 분석 증거, 시스템 처리 제안 및 전문가 검토 이력을 제공합니다.
파일 접수는 비동기 방식이며 `202 Accepted`는 작업 등록을 의미합니다.

### 표준 처리 흐름

| 단계 | API | 계약 |
| --- | --- | --- |
| 1. 생존 확인 | {_jump("GET /health", STATUS_TAG, "health_health_get")} | API 프로세스의 생존 상태를 반환합니다. |
| 2. 분석 접수 | {_jump("POST /analyses", UPLOAD_TAG, "upload_analyses_post")} | PE 파일을 등록하고 `analysis_id`를 반환합니다. |
| 3. 상태 조회 | {_jump("GET /analyses/{analysis_id}/status", RESULT_TAG, "get_status_analyses__analysis_id__status_get")} | 비동기 작업의 현재 상태와 단계를 반환합니다. |
| 4. 결과 조회 | {_jump("GET /analyses/{analysis_id}", RESULT_TAG, "get_analysis_analyses__analysis_id__get")} | 누적 분석 결과와 최종 처리 제안을 반환합니다. |

### 상태 및 응답 의미

`QUEUED`와 `RUNNING`은 비종료 상태이며, `COMPLETED`와 `FAILED`는 종료 상태입니다.
HTTP `200`은 조회 요청의 성공을 나타내므로 응답의 `status`가 `FAILED`일 수 있습니다.
Swagger UI의 `Example Value`는 스키마 예시이며, 실행된 요청의 실제 응답은
`Server response → Response body`에 표시됩니다. 예시의 식별자, 확률 및 판정값은 실제 분석 결과가 아닙니다.

{auth}
접수 정보 저장에는 데이터베이스가 필요하고, 비동기 분석 수행에는 별도의 분석 처리기(`run`)가 필요합니다.
"""


def _jump(label: str, tag: str, operation_id: str) -> str:
    return f"[{label}](./docs#/{quote(tag, safe='')}/{operation_id})"


def _example(summary: str, value: dict) -> dict:
    return {"summary": summary, "value": value}


def _error(code: str, message: str, *, stage=None, retryable=False) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "stage": stage,
            "retryable": retryable,
        }
    }


_ERRORS = {
    400: (
        "요청 본문을 해석할 수 없습니다. 경로, HTTP 메서드 또는 multipart 형식이 유효하지 않습니다.",
        _error(
            "INVALID_HTTP_REQUEST",
            "요청 경로, 메서드 또는 multipart 형식이 유효하지 않습니다.",
        ),
    ),
    401: (
        "인증에 실패했습니다. 유효한 X-API-Key가 필요합니다.",
        _error("UNAUTHORIZED", "유효한 X-API-Key가 필요합니다."),
    ),
    403: (
        "전문가 검토 권한이 없습니다. 유효한 X-Reviewer-Key가 필요합니다.",
        _error("REVIEW_FORBIDDEN", "유효한 X-Reviewer-Key가 필요합니다."),
    ),
    404: (
        "요청한 리소스가 존재하지 않습니다. 접수 응답에서 반환된 실제 식별자를 기준으로 조회합니다.",
        _error("ANALYSIS_NOT_FOUND", "해당 분석을 찾을 수 없습니다."),
    ),
    408: (
        "설정된 제한 시간 안에 파일 전송이 완료되지 않았습니다.",
        _error(
            "UPLOAD_TIMEOUT", "요청 본문 업로드 시간이 초과되었습니다.", stage="UPLOAD"
        ),
    ),
    409: (
        "현재 리소스 상태 또는 멱등성 키에 연결된 기존 요청과 충돌합니다. error.code가 충돌 유형을 구분합니다.",
        _error("IDEMPOTENCY_CONFLICT", "같은 접수 키에 다른 파일이 연결되어 있습니다."),
    ),
    413: (
        "파일 또는 전체 요청 본문이 서버의 업로드 제한을 초과했습니다.",
        _error("FILE_TOO_LARGE", "파일이 허용 크기를 초과했습니다.", stage="UPLOAD"),
    ),
    422: (
        "요청 값이 API 계약을 충족하지 않습니다. 필수 필드, 식별자 형식, 파일 형식 또는 숫자 범위가 유효하지 않습니다.",
        _error("INVALID_REQUEST", "요청 필드 형식 또는 필수 값이 유효하지 않습니다."),
    ),
    500: (
        "서버 내부 오류입니다. 장애 분석에는 error.code와 요청 시각이 필요합니다.",
        _error("INTERNAL_ERROR", "서버 처리 중 오류가 발생했습니다."),
    ),
    503: (
        "서비스 의존성이 준비되지 않았습니다. error.code가 데이터베이스, 저장소 등 실패한 의존성을 식별합니다.",
        _error(
            "DATABASE_NOT_CONFIGURED", "BACKEND_DATABASE_URL이 설정되지 않았습니다."
        ),
    ),
}


def error_responses(*codes: int) -> dict:
    return {
        code: {
            "model": ErrorResponse,
            "description": _ERRORS[code][0],
            "content": {"application/json": {"example": _ERRORS[code][1]}},
        }
        for code in codes
    }


REVIEW_EXAMPLES = {
    "hold": _example(
        "검토 보류",
        {
            "analyst_final_verdict": None,
            "analyst_notes": "증거 간 상충이 해소되지 않아 추가 분석 결과 검토가 필요합니다.",
            "reviewer_id": "reviewer.example",
            "expected_revision": 0,
        },
    ),
    "benign": _example(
        "정상 판정",
        {
            "analyst_final_verdict": "BENIGN",
            "analyst_notes": "정상 파일로 판단한 근거를 여기에 기록합니다.",
            "reviewer_id": "reviewer.example",
            "expected_revision": 0,
        },
    ),
    "malicious": _example(
        "악성 판정",
        {
            "analyst_final_verdict": "MALICIOUS",
            "analyst_notes": "악성 파일로 판단한 근거를 여기에 기록합니다.",
            "reviewer_id": "reviewer.example",
            "expected_revision": 0,
        },
    ),
}


def response_examples() -> dict:
    """예시는 가상의 한 파일을 기준으로 읽을 수 있도록 구성한다."""
    identity = {
        "analysis_id": "analysis_example_001",
        "batch_id": None,
        "sha256": "a" * 64,
        "created_at": "2026-09-08T09:00:00Z",
    }
    accepted = {**identity, "status": "QUEUED", "duplicate_of": None}
    waiting = {
        **identity,
        "status": "QUEUED",
        "current_stage": "UPLOAD",
        "updated_at": "2026-09-08T09:00:00Z",
        "completed_at": None,
        "error": None,
    }
    running = {**waiting, "status": "RUNNING", "current_stage": "INITIAL_ANALYSIS"}
    finished = {
        **waiting,
        "status": "COMPLETED",
        "current_stage": "FINAL_ASSESSMENT",
        "updated_at": "2026-09-08T09:00:20Z",
        "completed_at": "2026-09-08T09:00:20Z",
    }
    failed = {
        **finished,
        "status": "FAILED",
        "error": _error(
            "MODEL_NOT_CONFIGURED",
            "초기 분석 모델 경로가 설정되지 않았습니다.",
            stage="MODEL_LOADING",
        )["error"],
    }
    prediction = {
        "lgbm_raw_probability": 0.04,
        "xgb_raw_probability": 0.08,
        "calibrated_probability": 0.05,
    }
    risks = {"disagreement": 0.04, "ood_score": 0.12, "difficulty_score": 0.08}
    top_features = [
        {
            "feature_name": "general[0]",
            "feature_value": 14848.0,
            "shap_value": -0.42,
            "direction": "BENIGN",
        }
    ]
    tool_states = {
        tool: "NOT_REQUIRED" for tool in ("capa", "floss", "speakeasy", "cape")
    }
    triage = {
        **identity,
        "status": "COMPLETED",
        "prediction": prediction,
        "risk_signals": risks,
        "initial_verdict": "AUTO_BENIGN",
        "route": "FINAL",
        "reason": "설명용 예시: 추가 분석 조건에 해당하지 않아 최종 처리로 이동했습니다.",
        "feature_metadata": {},
    }
    assessment = {
        "final_verdict": "BENIGN",
        "disposition": "AUTO_ALLOW_RECOMMENDED",
        "requires_human_review": False,
        "reason": "설명용 예시: 초기 정상 경로이며 모델 설명도 완료되었습니다.",
        "policy_version": "backend-review-first-v1",
    }
    analysis = {
        **finished,
        "filename": "example.exe",
        "size_bytes": 14848,
        "duplicate_of": None,
        "prediction": prediction,
        "risk_signals": risks,
        "initial_verdict": "AUTO_BENIGN",
        "route": "FINAL",
        "reason": triage["reason"],
        "top_features": top_features,
        "deep_analysis_status": tool_states,
        "evidence": [],
        "llm_summary": None,
        "final_verdict": "BENIGN",
        "final_assessment": assessment,
        "analyst_final_verdict": None,
        "approval_status": "AUTO_POLICY",
        "review_revision": 0,
    }
    review = {
        "analysis_id": identity["analysis_id"],
        "revision": 1,
        "analyst_final_verdict": None,
        "analyst_notes": "증거 간 상충이 해소되지 않아 추가 분석 결과 검토가 필요합니다.",
        "reviewer_id": "reviewer.example",
        "reviewed_at": "2026-09-08T09:05:00Z",
    }
    receipt = {
        "input_count": 1,
        "accepted_count": 1,
        "skipped_count": 0,
        "archive_file_count": None,
        "entries": [
            {
                "input_index": 0,
                "filename": "example.exe",
                "status": "ACCEPTED",
                "analysis_id": identity["analysis_id"],
                "sha256": identity["sha256"],
                "size_bytes": 14848,
                "reason_code": None,
                "reason": None,
            }
        ],
    }
    high_risk = {
        **analysis,
        **running,
        "batch_id": "batch_example_001",
        "initial_verdict": "HIGH_RISK_UNCERTAIN",
        "route": "DEEP_ANALYSIS",
        "reason": "설명용 예시: 위험 신호로 추가 분석을 수행합니다.",
        "current_stage": "CAPA_FLOSS",
        "deep_analysis_status": {
            "capa": "RUNNING",
            "floss": "RUNNING",
            "speakeasy": "QUEUED",
            "cape": "NOT_REQUIRED",
        },
        "final_verdict": None,
        "final_assessment": None,
        "approval_status": "PENDING",
    }
    return {
        "health": {
            "ok": _example(
                "서버가 응답하는 경우",
                {"status": "ok", "service": "trust-triage-backend", "version": "0.1.0"},
            )
        },
        "ready": {
            "ready": _example("DB와 백엔드 테이블을 확인한 경우", {"status": "ready"})
        },
        "upload": {"accepted": _example("단일 분석 작업 접수", accepted)},
        "get_status": {
            "queued": _example("대기 — 분석 처리기를 기다리는 중", waiting),
            "running": _example("진행 — 초기 분석을 수행하는 중", running),
            "completed": _example("완료 — 종합 결과를 조회할 수 있음", finished),
            "failed": _example("분석 실패 — error에서 원인 확인", failed),
        },
        "get_analysis": {
            "completed": _example("정상 처리 제안으로 완료된 설명용 예시", analysis)
        },
        "list_analyses": {
            "one_result": _example(
                "저장된 분석 1건이 있는 경우",
                {"total_count": 1, "limit": 20, "offset": 0, "analyses": [analysis]},
            )
        },
        "get_triage": {
            "completed": _example("초기 판정 완료 — 전체 분석 상태와 별개", triage)
        },
        "get_xai": {
            "completed": _example(
                "모델 예측에 영향을 준 특성 예시",
                {
                    **identity,
                    "status": "COMPLETED",
                    "explained_output": "LIGHTGBM_RAW_OUTPUT",
                    "top_features": top_features,
                    "error": None,
                },
            )
        },
        "get_deep": {
            "not_required": _example(
                "심층 분석 대상이 아닌 경우",
                {
                    **identity,
                    "status": "NOT_REQUIRED",
                    "deep_analysis_status": tool_states,
                    "tool_details": {},
                    "capa": None,
                    "floss": None,
                    "speakeasy": None,
                    "evidence": [],
                    "evidence_details": [],
                    "llm_summary": None,
                    "llm_status": None,
                    "error": None,
                },
            )
        },
        "upload_batch": {
            "accepted": _example(
                "묶음 접수 — batch_id와 analysis_id가 함께 반환됨",
                {
                    "batch_id": "batch_example_001",
                    "total_count": 1,
                    **receipt,
                    "analyses": [{**accepted, "batch_id": "batch_example_001"}],
                },
            )
        },
        "upload_zip": {
            "mixed": _example(
                "ZIP의 PE 1건 접수, 텍스트 1건 제외",
                {
                    "batch_id": "batch_example_001",
                    "total_count": 1,
                    **receipt,
                    "input_count": 2,
                    "skipped_count": 1,
                    "archive_file_count": 2,
                    "entries": [
                        *receipt["entries"],
                        {
                            "input_index": 1,
                            "filename": "readme.txt",
                            "status": "SKIPPED",
                            "analysis_id": None,
                            "sha256": None,
                            "size_bytes": 30,
                            "reason_code": "UNSUPPORTED_FILE_TYPE",
                            "reason": ".exe와 .dll 파일만 분석합니다.",
                        },
                    ],
                    "analyses": [{**accepted, "batch_id": "batch_example_001"}],
                },
            ),
        },
        "get_batch": {
            "completed": _example(
                "묶음의 모든 파일이 종료된 경우",
                {
                    "batch_id": "batch_example_001",
                    "total_count": 1,
                    **receipt,
                    "status": "COMPLETED",
                    "summary": {
                        "total": 1,
                        "queued": 0,
                        "running": 0,
                        "completed": 1,
                        "failed": 0,
                        "auto_benign": 1,
                        "auto_malicious": 0,
                        "high_risk_uncertain": 0,
                        "unclassified": 0,
                    },
                    "finished_count": 1,
                    "status_counts": {
                        "QUEUED": 0,
                        "RUNNING": 0,
                        "COMPLETED": 1,
                        "FAILED": 0,
                    },
                    "analyses": [{**analysis, "batch_id": "batch_example_001"}],
                },
            )
        },
        "list_batch_analyses": {
            "high_risk": _example(
                "고위험 초기 판정으로 필터링한 목록",
                {
                    "batch_id": "batch_example_001",
                    "total_count": 1,
                    "limit": 20,
                    "offset": 0,
                    "analyses": [high_risk],
                },
            ),
        },
        "save_review": {"held": _example("전문가 검토 보류 등록", review)},
        "list_reviews": {
            "empty": _example(
                "아직 검토 의견이 없는 경우",
                {"analysis_id": identity["analysis_id"], "items": []},
            ),
            "reviewed": _example(
                "검토 이력 1건이 있는 경우",
                {"analysis_id": identity["analysis_id"], "items": [review]},
            ),
        },
    }


def operations(config: BackendConfig) -> dict:
    """각 API 작업의 목적, 요청 계약, 응답 의미 및 운영 특성을 제공한다."""
    file_limit = f"{config.max_file_bytes / (1024 * 1024):g} MiB ({config.max_file_bytes:,} bytes)"
    descriptions = {
        "health": (
            STATUS_TAG,
            "서비스 생존 상태 확인",
            """
### 목적

API 프로세스가 HTTP 요청을 수신하고 응답할 수 있는지 확인하는 liveness 엔드포인트입니다.

### 요청 및 응답

요청 매개변수와 인증이 없습니다. 정상 응답은 HTTP `200`과 `status: "ok"`를 반환합니다.

### 점검 범위

데이터베이스, 객체 저장소, 모델 및 분석 처리기의 상태는 검사하지 않습니다. 데이터베이스 준비 상태는 `GET /ready`에서 별도로 제공합니다.
""",
            (),
        ),
        "ready": (
            STATUS_TAG,
            "데이터베이스 준비 상태 확인",
            """
### 목적

분석 접수와 조회에 필요한 데이터베이스 연결 및 백엔드 테이블의 준비 상태를 확인합니다.

### 요청 및 응답

요청 매개변수는 없습니다. API 키가 활성화된 환경에서는 `X-API-Key`가 필요합니다.
HTTP `200`과 `status: "ready"`는 연결 및 필수 테이블 검사가 성공했음을 의미합니다.
HTTP `503`은 데이터베이스 설정, 접근 권한, 연결 또는 테이블 초기화 문제를 나타냅니다.

### 점검 범위

객체 저장소, 모델 로딩 및 분석 처리기 가동 여부는 이 엔드포인트의 점검 대상에 포함되지 않습니다.
""",
            (401, 503),
        ),
        "upload": (
            UPLOAD_TAG,
            "단일 PE 분석 접수",
            f"""
### 목적

단일 Windows PE 파일을 비동기 분석 작업으로 등록합니다. 지원 입력은 `.exe`와 `.dll`이며 서버는 업로드된 파일을 실행하지 않습니다.

### 요청

- Content-Type: `multipart/form-data`
- 필수 필드: `file`
- 파일 크기 상한: **{file_limit}**
- `Idempotency-Key`: 네트워크 재시도 등 동일 요청의 중복 등록을 방지하는 선택 헤더

### 응답

HTTP `202 Accepted`는 작업이 등록되었음을 의미하며 분석 완료를 보장하지 않습니다.
응답의 `analysis_id`는 상태 및 결과 조회에 사용하는 리소스 식별자이고, 초기 `status`는 일반적으로 `QUEUED`입니다.

### 처리 특성

동일한 SHA-256을 다시 접수하면 기본적으로 새 `analysis_id`가 생성되고 `duplicate_of`가 이전 분석을 참조합니다.
동일한 `Idempotency-Key`와 동일한 파일의 재전송은 기존 접수 결과를 반환하며, 같은 키에 다른 파일을 연결하면 `409`가 반환됩니다.
`QUEUED` 상태가 장시간 지속되는 경우 비동기 분석 처리기(`run`)의 가동 상태를 운영 측에서 점검해야 합니다.
""",
            (400, 401, 408, 409, 413, 422, 503),
        ),
        "get_status": (
            RESULT_TAG,
            "분석 진행 상태 조회",
            """
### 목적

비동기 분석 작업의 수명주기 상태, 현재 단계, 종료 시각 및 오류를 조회합니다.

### 요청

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.

### 응답 상태

| `status` | 의미 | 클라이언트 처리 |
| --- | --- | --- |
| `QUEUED` | 처리 대기 | 폴링 지속 |
| `RUNNING` | 분석 진행 | `current_stage` 기반 진행 표시 및 폴링 지속 |
| `COMPLETED` | 분석 정상 종료 | 폴링 종료 및 종합 결과 조회 |
| `FAILED` | 분석 실패 종료 | 폴링 종료 및 `error` 기반 장애 처리 |

### 폴링 계약

기본 권장 간격은 2~3초이며, 장기 실행 시 점진적 backoff를 적용할 수 있습니다.
`COMPLETED`와 `FAILED`는 종료 상태입니다. HTTP `200`은 조회 요청의 성공을 나타내므로 응답의 분석 상태가 `FAILED`일 수 있습니다.
""",
            (401, 404, 422, 503),
        ),
        "get_analysis": (
            RESULT_TAG,
            "종합 분석 결과 조회",
            """
### 목적

파일 메타데이터, 진행 상태, 초기 판정, 심층 분석 증거, 시스템 최종 제안 및 전문가 검토 상태를 하나의 응답으로 제공합니다.

### 요청

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.

### 주요 필드

| 필드 | 의미 |
| --- | --- |
| `status` / `current_stage` | 전체 진행 상태 / 현재 단계 |
| `initial_verdict` | 초기 JRR 판정 |
| `final_verdict` / `final_assessment` | 시스템의 최종 판정과 처리 제안 |
| `analyst_final_verdict` / `approval_status` | 전문가 의견과 승인 상태 |
| `review_revision` | 전문가 검토의 낙관적 동시성 제어에 사용하는 현재 리비전 |

### 일관성 특성

분석 도중에도 조회할 수 있으며 아직 생성되지 않은 결과는 `null` 또는 빈 목록으로 반환됩니다.
초기 모델 및 JRR 상세는 `/triage`, SHAP 설명은 `/xai`, 추가 도구 결과는 `/deep-analysis`에서 제공합니다.
전문가 검토 등록은 전체 상태가 `COMPLETED` 또는 `FAILED`인 분석에 한해 허용됩니다.
""",
            (401, 404, 422, 503),
        ),
        "list_analyses": (
            RESULT_TAG,
            "분석 목록 조회",
            """
### 목적

접수된 분석을 고위험 우선으로 조회하며 상태·초기 판정·배치·파일 해시 필터와 offset 기반 페이지네이션을 제공합니다.

### 쿼리 매개변수

| 이름 | 기본값 | 의미 |
| --- | --- | --- |
| `limit` | `20` | 페이지당 결과 수. 허용 범위는 1~100 |
| `offset` | `0` | 결과 집합에서 건너뛸 항목 수 |
| `status` | 없음 | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` 중 하나로 필터링 |
| `sha256` | 없음 | 64자리 소문자 SHA-256과 일치하는 파일로 필터링 |
| `verdict` | 없음 | 초기 JRR 판정. `HIGH_RISK_UNCERTAIN`, `AUTO_MALICIOUS`, `AUTO_BENIGN` |
| `batch_id` | 없음 | 특정 배치에 속한 분석만 조회 |
| `sort` | `high_risk_first` | 고위험 우선. `newest`를 지정하면 최신 접수순 |

### 응답 및 페이지네이션

`total_count`는 필터 조건에 일치하는 전체 건수이고 `analyses`는 현재 페이지의 결과입니다.
다음 페이지의 offset은 현재 `offset + limit`으로 계산합니다. SHA-256은 파일 내용 식별자이며 작업 식별자인 `analysis_id`와 별개입니다.
필터와 정렬은 전체 검색 결과에 적용한 다음 페이지를 자릅니다.
고위험 우선 순서는 `HIGH_RISK_UNCERTAIN` → `AUTO_MALICIOUS` → `AUTO_BENIGN` → 미판정 → `FAILED`입니다.
동순위는 최신 접수순입니다. 이 순서는 조회 표시용이며 분석 실행 순서를 변경하지 않습니다.
`verdict`는 초기 판정이므로 후속 분석 결과나 전문가 판정이 바뀌어도 해당 초기 판정으로 조회됩니다.
""",
            (401, 404, 422, 503),
        ),
        "get_triage": (
            RESULT_TAG,
            "초기 분류 및 JRR 결과 조회",
            """
### 목적

기본 모델의 원 확률, 보정 확률, 위험 신호 및 Joint Risk Router의 초기 경로 결정을 제공합니다.

### 요청 및 가용성

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.
초기 분석이 완료되기 전에는 확률과 판정 필드가 `null`일 수 있으며, 이 응답의 `status`는 초기 분석 단계의 상태를 나타냅니다.

### 결과 해석

`prediction`은 두 모델의 악성 확률과 보정 확률, `risk_signals`는 모델 불일치·OOD·분석 난이도입니다.
확률 필드는 0~1 범위이며 `0.72`는 72%에 해당합니다. OOD 원점수는 확률이 아니므로 음수가 허용됩니다.

`initial_verdict`와 `reason`은 초기 판단을, `route`는 `FINAL` 또는 `DEEP_ANALYSIS` 처리 경로를 나타냅니다.
초기 판정 생성 이후에도 후속 단계가 진행될 수 있으므로 전체 수명주기 상태는 `/status` 응답을 기준으로 판단합니다.
""",
            (401, 404, 422, 503),
        ),
        "get_xai": (
            RESULT_TAG,
            "SHAP 기반 모델 설명 조회",
            """
### 목적

LightGBM 원출력에 대한 SHAP 기여도를 영향도가 큰 특성 순으로 제공합니다.

### 요청 및 응답

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.
`top_features`의 `feature_name`은 스키마 특성명, `feature_value`는 관측값, `shap_value`는 모델 원출력에 대한 기여도입니다.
`direction`은 기여 방향을 `MALICIOUS`, `BENIGN`, `NEUTRAL`로 정규화합니다.

### 해석 범위

SHAP 값은 확률 또는 백분율이 아닙니다. 설명 대상은 `explained_output`에 명시된 LightGBM 원출력입니다.
빈 `top_features`는 미완료 또는 설명 단계 실패와 함께 발생할 수 있으며 `status`와 `error`가 그 상태를 구분합니다.
외부 분석 도구가 생성한 증거는 `/deep-analysis` 응답에 포함됩니다.
""",
            (401, 404, 422, 503),
        ),
        "get_deep": (
            RESULT_TAG,
            "심층 분석 상태 및 증거 조회",
            """
### 목적

JRR이 심층 분석 경로로 전달한 파일에 대해 CAPA, FLOSS, Speakeasy 등 도구별 실행 상태와 정규화된 증거를 제공합니다.

### 요청 및 부작용

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.
이 GET 요청은 저장된 결과만 조회하며 새로운 도구 실행을 시작하지 않습니다.

### 응답 구조

`deep_analysis_status`는 도구별 대기·진행·완료 상태입니다. `NOT_REQUIRED`는 해당 분석이 필요 없어 생략됐다는 뜻입니다.
`tool_details`는 `TIMEOUT`을 포함한 원래 도구 상태와 버전을 보존합니다.
`evidence`는 ATT&CK 기법 단위 집계, `evidence_details`는 출처와 신뢰도를 포함한 개별 증거를 제공합니다.
`llm_summary`는 생성된 경우에만 제공되는 전문가 참고 설명입니다.

### 실패 의미

도구 실패 자체는 악성 증거로 처리되지 않습니다. 전체 분석 상태와 도구별 상태는 서로 다른 수명주기를 가질 수 있으므로 함께 해석해야 합니다.
""",
            (401, 404, 422, 503),
        ),
        "upload_batch": (
            BATCH_TAG,
            "배치 분석 접수",
            f"""
### 목적

여러 Windows PE 파일을 단일 배치로 등록하고 배치 수준의 추적 식별자를 발급합니다.

### 요청

- Content-Type: `multipart/form-data`
- 필수 필드: 반복 가능한 `files`
- 파일 수 상한: **{config.max_batch_files}개**
- 파일별 크기 상한: **{file_limit}**
- `Idempotency-Key`: 동일한 파일 집합과 순서로 구성된 요청의 재전송을 식별하는 선택 헤더

### 응답

HTTP `202 Accepted`는 배치와 파일별 작업이 등록되었음을 의미합니다.
`batch_id`는 배치 집계 조회에 사용하고, `analyses[].analysis_id`는 개별 파일 조회에 사용합니다.

### 입력별 처리 및 멱등성

지원하지 않는 확장자·잘못된 PE·미지원 PE 형식은 `entries`에 `SKIPPED`와 사유를 기록하고 유효한 PE만 작업으로 등록합니다.
`input_count = accepted_count + skipped_count`이고 `total_count`는 등록한 분석 수(`accepted_count`)입니다.
모두 제외된 입력도 배치 접수 내역을 보존하며 `analyses`는 빈 목록입니다. 접수 제한 초과나 저장소·DB 장애는 요청 전체 오류입니다.
접수 후 개별 분석 실패는 다른 파일의 분석을 중단하지 않습니다.
동일한 멱등성 키에 다른 파일 집합 또는 순서를 사용하면 `409`가 반환됩니다.
""",
            (400, 401, 408, 409, 413, 422, 503),
        ),
        "upload_zip": (
            BATCH_TAG,
            "ZIP 배치 분석 접수",
            f"""
### 목적과 요청

`multipart/form-data`의 `file` 필드로 ZIP 한 개를 접수합니다. ZIP 안의 `.exe`와 `.dll`을 기존과 같은 분석 처리기로 전달합니다.
`Idempotency-Key`를 지정하면 동일한 ZIP 바이트와 이름의 재전송은 기존 배치와 접수 내역을 반환합니다.

### 입력 제한

- ZIP 크기: {config.max_zip_bytes:,} bytes
- 전체 ZIP 항목: 최대 {config.max_zip_entries}개(폴더 포함), 분석 대상 PE: 최대 {config.max_batch_files}개
- 파일별 PE 크기: {file_limit}, 선언된 해제 후 총 크기: {config.max_zip_expanded_bytes:,} bytes
- 항목별 최대 압축률: {config.max_zip_ratio:g}, ZIP 처리 제한 시간: {config.zip_timeout_seconds:g}초

STORED와 DEFLATE를 지원합니다. 중첩 ZIP, 다른 확장자, 암호화 파일, 미지원 압축·패치 데이터 기능, 크기 초과 PE 및 잘못된 PE는 `SKIPPED`로 기록합니다.
빈 ZIP, 손상된 PE 항목의 압축 데이터·체크섬, 위험 경로·링크, 압축률·총량·항목 수 제한 위반은 전체 접수를 거절합니다.
분할 ZIP과 ZIP64는 지원하지 않습니다. 지원하지 않는 항목의 본문은 해제하거나 분석하지 않습니다.

### 응답

`batch_id`, `input_count`, `accepted_count`, `skipped_count`, `archive_file_count`와 파일별 `entries`를 반환합니다.
`input_index`는 ZIP 항목 순서이며 동명 파일을 구분합니다. 폴더는 파일 수와 `entries`에서 제외됩니다.
`entries[].analysis_id`는 접수된 파일에만 발급하고, `SKIPPED`는 분석 실패 수에 포함하지 않습니다.
모두 제외돼도 배치는 저장되며 등록된 분석 수가 0이므로 조회 상태는 `COMPLETED`입니다.
""",
            (400, 401, 408, 409, 413, 422, 503),
        ),
        "get_batch": (
            BATCH_TAG,
            "배치 처리 상태 및 결과 조회",
            """
### 목적

배치에 포함된 파일별 분석 상태와 종합 결과를 집계하여 제공합니다.

### 요청

경로 매개변수 `batch_id`에는 `POST /batches` 또는 `POST /batches/zip` 응답의 배치 식별자를 사용합니다.
`batch_id`는 개별 파일의 `analysis_id`와 별개의 네임스페이스를 가집니다.

### 완료 조건

`total_count`는 등록된 분석 수, `finished_count`는 **COMPLETED와 FAILED를 합한 종료 분석 수**입니다.
두 값이 같으면 모든 파일이 종료 상태에 도달한 것이며, 모든 분석이 성공했다는 의미는 아닙니다.

`status_counts`는 상태별 파일 수를, `analyses`는 파일별 결과와 오류를 제공합니다.
개별 분석의 상세 리소스는 각 항목의 `analysis_id`로 조회할 수 있습니다.

### 요약과 입력 내역

`summary`의 `queued/running/completed/failed`는 작업 상태 집계이며 합계는 `total`입니다.
`auto_benign/auto_malicious/high_risk_uncertain/unclassified`는 초기 판정 집계이며 합계는 같은 `total`입니다. 두 집계는 서로 독립적입니다.
`entries`는 최초 접수 내역으로, 제외된 파일의 사유도 보존합니다. `SKIPPED`는 분석 작업과 실패 수에 포함하지 않습니다.

배치 `status`는 전부 대기하면 `QUEUED`, 진행 중이면 `RUNNING`, 일부 종료 후 나머지가 활성 상태면 `PARTIALLY_COMPLETED`입니다.
전부 실패하면 `FAILED`이며, 그 외 모두 종료한 경우(일부 실패 포함) 또는 전부 제외된 경우는 `COMPLETED`입니다.
기본 `sort=high_risk_first`는 고위험 우선, `newest`는 최신순, `input_order`는 입력순입니다.
이 API는 배치의 모든 등록 분석을 반환합니다. 필터·페이지 조회는 `GET /batches/{batch_id}/analyses`를 사용합니다.
""",
            (401, 404, 422, 503),
        ),
        "list_batch_analyses": (
            BATCH_TAG,
            "배치 내 분석 목록 필터 조회",
            """
### 목적과 쿼리

배치 안의 등록된 분석만 조회합니다. `verdict=HIGH_RISK_UNCERTAIN`으로 초기 고위험 파일을 모아 볼 수 있습니다.
`status`, `sha256`, `limit`(기본 20, 최대 100), `offset`(기본 0)을 함께 사용할 수 있습니다.
`sort`는 `high_risk_first`(기본), `newest`, `input_order` 중 하나입니다.
고위험 우선은 초기 고위험→자동 악성→자동 정상→미판정→실패 순서이며, 동순위는 최신순입니다.
조회 정렬은 실제 분석 실행 순서를 바꾸지 않습니다.

### 응답

`total_count`는 모든 필터에 맞는 전체 분석 수이고 `analyses`는 정렬 후 선택된 페이지입니다.
초기 판정은 시스템 최종 판정·전문가 판정과 별개로 보존됩니다.
존재하는 배치에서 일치 결과가 없거나 모든 입력이 제외된 경우 빈 목록을 반환합니다. 배치 자체가 없으면 `404`입니다.
전체 요약과 `SKIPPED` 입력 내역은 `GET /batches/{batch_id}`에서 조회합니다.
""",
            (401, 404, 422, 503),
        ),
        "save_review": (
            REVIEW_TAG,
            "전문가 검토 결과 등록",
            """
### 목적

종료된 분석에 전문가 판정 또는 보류 의견을 추가합니다. 초기 판정과 시스템 최종 제안은 변경하지 않고 별도 필드로 보존합니다.

### 선행 조건 및 인증

분석의 전체 상태가 `COMPLETED` 또는 `FAILED`여야 합니다.
검토 전용 키가 설정된 환경에서는 `X-Reviewer-Key`가 필요하며, API 키도 활성화된 경우 두 헤더가 모두 필요합니다.

### 요청 필드

| 필드 | 의미 |
| --- | --- |
| `analyst_final_verdict` | `BENIGN`, `MALICIOUS`, 또는 보류를 나타내는 `null` |
| `analyst_notes` | 판정 또는 보류의 근거 |
| `reviewer_id` | 감사 이력에 기록할 검토자 식별자 |
| `expected_revision` | 종합 결과의 최신 `review_revision` 값 |

### 동시성 및 응답

`expected_revision`은 낙관적 동시성 제어에 사용됩니다. 다른 검토가 먼저 저장된 경우 `409 / REVIEW_CONFLICT`가 반환되며 최신 리비전으로 재검토해야 합니다.
분석이 종료되지 않은 경우 `409 / ANALYSIS_NOT_FINISHED`가 반환됩니다. 성공 응답의 `revision`은 새 검토 리비전입니다.
""",
            (401, 403, 404, 409, 422, 503),
        ),
        "list_reviews": (
            REVIEW_TAG,
            "전문가 검토 이력 조회",
            """
### 목적

분석에 등록된 전문가 검토 기록을 리비전 순서의 감사 이력으로 제공합니다.

### 요청

경로 매개변수 `analysis_id`에는 접수 응답에서 반환된 분석 식별자를 사용합니다.

### 응답

`items`에는 검토자의 식별자, 판정, 메모, 저장 시각, 수정 번호가 담깁니다.
빈 `items`는 등록된 검토가 없음을 의미하며, 보류 의견의 판정값은 `null`입니다.
현재 적용된 전문가 판정, 승인 상태 및 `review_revision`은 종합 분석 결과에서 제공합니다.
""",
            (401, 404, 422, 503),
        ),
    }
    examples = response_examples()
    result = {}
    for name, (tag, summary, description, errors) in descriptions.items():
        success = 202 if name in {"upload", "upload_batch", "upload_zip"} else 200
        responses = error_responses(*errors)
        responses[success] = {
            "description": "비동기 분석 작업이 접수되었습니다. 응답 식별자로 상태와 결과를 조회할 수 있습니다."
            if success == 202
            else "요청이 정상 처리되었습니다. 예시는 응답 스키마의 대표 값을 나타냅니다.",
            "content": {"application/json": {"examples": examples[name]}},
        }
        result[name] = {
            "tags": [tag],
            "summary": summary,
            "description": description.strip(),
            "responses": responses,
        }
    for name in ("get_batch", "list_batch_analyses", "list_analyses"):
        result[name]["responses"][404]["content"]["application/json"]["example"] = (
            _error("BATCH_NOT_FOUND", "해당 일괄 분석을 찾을 수 없습니다.")
        )
    conflict = result["save_review"]["responses"][409]
    conflict["content"]["application/json"] = {
        "examples": {
            "revision": _example(
                "다른 검토가 먼저 저장됨",
                _error(
                    "REVIEW_CONFLICT",
                    "검토 리비전이 변경되었습니다. 최신 결과에 대한 재검토가 필요합니다.",
                ),
            ),
            "running": _example(
                "분석이 아직 진행 중",
                _error("ANALYSIS_NOT_FINISHED", "분석이 종료된 뒤 검토할 수 있습니다."),
            ),
        }
    }
    return result
