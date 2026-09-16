"""로그에 자격 증명이나 원본 파일 내용을 노출하지 않는 경계 오류."""


class WorkerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class RetryableError(WorkerError):
    """연결 복구 후 같은 요청을 재시도할 수 있다."""


class PermanentError(WorkerError):
    """현재 입력/설정으로는 재시도하지 않는다."""


class LeaseLost(WorkerError):
    def __init__(self) -> None:
        super().__init__("LEASE_LOST", "Worker no longer owns this job")
