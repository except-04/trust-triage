"""Backend의 작업 등록 함수와 전송 실패 후 재전송 처리."""

from __future__ import annotations

from .models import JobRecord, SpeakeasyJob
from .queue import JobQueue
from .repository import JobRepository


class JobPublisher:
    def __init__(self, repository: JobRepository, queue: JobQueue) -> None:
        self.repository = repository
        self.queue = queue

    def submit(self, job: SpeakeasyJob) -> JobRecord:
        # 먼저 DB에 남긴다. SQS 전송 실패 시에도 run/dispatch에서 같은 요청을 복구한다.
        record = self.repository.register(job, dispatch_pending=True)
        if record.dispatch_pending and not record.status.terminal:
            self.queue.send(record.job)
            self.repository.mark_dispatched(record.job.analysis_id)
            record = self.repository.get(job.analysis_id)
        return record

    def dispatch_pending(self, limit: int = 10) -> int:
        sent = 0
        for job in self.repository.pending_jobs(limit):
            # 전송 응답이나 이 DB 갱신이 실패하면 다음 실행에서 다시 전송할 수 있다.
            # 소비자는 analysis_id 기준으로 완료/동시 처리를 검사한다.
            self.queue.send(job)
            self.repository.mark_dispatched(job.analysis_id)
            sent += 1
        return sent
