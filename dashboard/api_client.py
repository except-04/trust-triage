"""백엔드 API 호출 담당 모듈.

화면(app.py)은 HTTP를 몰라도 되고, 이 파일은 화면을 몰라도 된다.
주소와 토큰은 환경변수로 받는다 — 배포하면 주소가 바뀌는데
그때 코드를 고치지 않기 위해서다.
"""

import os

import requests

BASE_URL = os.getenv("TRUST_TRIAGE_API", "http://127.0.0.1:8000").rstrip("/")
API_TOKEN = os.getenv("TRUST_TRIAGE_API_TOKEN", "")
TIMEOUT_SEC = 30
# ZIP은 백엔드가 해제·항목 검증까지 수행하므로(기본 상한 60초) 더 오래 기다린다.
ZIP_TIMEOUT_SEC = 150


class ApiError(Exception):
    """백엔드가 돌려준 실패를 파이썬 예외로 옮긴 것.

    무엇이 실패했는지만 담는다. 화면에 어떻게 보여줄지는 app.py가 정한다.
    """

    def __init__(self, code, message, stage=None, retryable=False, http_status=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage
        self.retryable = retryable
        self.http_status = http_status


def _headers():
    return {"X-API-Key": API_TOKEN} if API_TOKEN else {}


def _to_api_error(response):
    """{"error": {...}} 형태의 응답을 ApiError로 바꾼다."""
    try:
        payload = response.json().get("error", {})
    except ValueError:
        payload = {}

    return ApiError(
        code=payload.get("code", "UNKNOWN_ERROR"),
        message=payload.get("message", f"HTTP {response.status_code}"),
        stage=payload.get("stage"),
        retryable=payload.get("retryable", False),
        http_status=response.status_code,
    )


def _request(method, path, *, timeout=None, **kwargs):
    try:
        response = requests.request(
            method,
            f"{BASE_URL}{path}",
            headers=_headers(),
            timeout=timeout or TIMEOUT_SEC,
            **kwargs,
        )
    except requests.RequestException as e:
        # 백엔드가 아예 안 떠 있는 경우. 화면이 두 종류의 실패를
        # 따로 처리하지 않아도 되도록 같은 예외로 감싼다.
        raise ApiError(
            "API_UNREACHABLE",
            f"백엔드에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요. ({BASE_URL})",
            retryable=True,
        ) from e

    if response.status_code >= 400:
        raise _to_api_error(response)

    return response.json()


def upload(filename, content):
    """PE 파일 하나를 접수한다.

    반환: {"analysis_id": ..., "sha256": ..., "status": "QUEUED", ...}
    """
    files = {"file": (filename, content, "application/octet-stream")}
    return _request("POST", "/analyses", files=files)


def upload_batch(files_):
    """여러 파일을 한 번에 접수한다. files_: [(filename, content), ...]"""
    payload = [("files", (name, content, "application/octet-stream")) for name, content in files_]
    return _request("POST", "/batches", files=payload)


def upload_zip(filename, content):
    """ZIP 한 개를 접수한다. 해제·내부 PE 검증·보안 검사는 백엔드가 수행한다.

    필드 이름은 files가 아니라 file 하나다 (POST /batches/zip 계약).
    반환: batch_id / entries / analyses / accepted_count / skipped_count ...
    """
    files = {"file": (filename, content, "application/zip")}
    return _request("POST", "/batches/zip", files=files, timeout=ZIP_TIMEOUT_SEC)


def get_status(analysis_id):
    """진행 상태만 가볍게 조회한다. 폴링용.

    반환: status / current_stage / error / updated_at ...
    """
    return _request("GET", f"/analyses/{analysis_id}/status")


def get_result(analysis_id):
    """현재까지 누적된 종합 결과를 가져온다.

    전체 상태가 RUNNING이어도 Initial Analysis가 저장된 뒤라면 초기 판정과
    SHAP, 심층 분석 도구별 상태가 채워져 온다.
    """
    return _request("GET", f"/analyses/{analysis_id}")


def get_deep_analysis(analysis_id):
    """심층 분석의 종합 상태와 도구별 상세 결과를 가져온다."""
    return _request("GET", f"/analyses/{analysis_id}/deep-analysis")


def get_batch(batch_id):
    """묶음 전체의 진행 상황과 결과를 한 번에 조회한다. 배치 폴링용.

    파일별 /status + /analyses 반복 조회를 이 한 번으로 대체한다.
    응답의 analyses 항목은 get_result()와 같은 종합 결과 형태다.

    반환: batch_id / status / status_counts / finished_count / summary / analyses ...
    """
    return _request("GET", f"/batches/{batch_id}")


def search_analyses(sha256, limit=20, offset=0, sort="newest"):
    """SHA-256으로 분석 이력을 조회한다.

    전용 해시 조회 엔드포인트가 아니라 목록 조회(GET /analyses)의 sha256
    필터다. 같은 파일을 여러 번 접수했으면 이력이 모두 나온다 — 백엔드는
    최신 한 건으로 줄이지 않는다.

    없는 해시는 404가 아니라 total_count 0인 빈 목록으로 온다. 호출하는 쪽은
    "결과 없음"을 예외가 아니라 건수로 판정해야 한다.

    sha256은 소문자 64자리여야 한다(백엔드 정규식). 형식이 어긋나면 422다.

    반환: {"total_count": ..., "limit": ..., "offset": ..., "analyses": [...]}
    """
    params = {"sha256": sha256, "limit": limit, "offset": offset, "sort": sort}
    return _request("GET", "/analyses", params=params)


def health():
    """서버가 살아 있는지 확인한다."""
    return _request("GET", "/health")
