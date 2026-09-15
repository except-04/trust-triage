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


def _request(method, path, **kwargs):
    try:
        response = requests.request(
            method, f"{BASE_URL}{path}", headers=_headers(), timeout=TIMEOUT_SEC, **kwargs
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


def get_status(analysis_id):
    """진행 상태만 가볍게 조회한다. 폴링용.

    반환: status / current_stage / error / updated_at ...
    """
    return _request("GET", f"/analyses/{analysis_id}/status")


def get_result(analysis_id):
    """완료된 분석의 전체 결과를 가져온다."""
    return _request("GET", f"/analyses/{analysis_id}")


def health():
    """서버가 살아 있는지 확인한다."""
    return _request("GET", "/health")
