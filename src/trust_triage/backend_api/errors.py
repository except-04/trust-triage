"""API와 작업 프로세스가 함께 사용하는, 외부에 공개해도 되는 오류."""

from __future__ import annotations


class BackendError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int = 500,
        stage: str | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.stage = stage
        self.retryable = retryable

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "code": self.code,
            "message": self.message,
            "stage": self.stage,
            "retryable": self.retryable,
        }
