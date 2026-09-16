"""python -m trust_triage.speakeasy_worker 실행 진입점."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from botocore.exceptions import BotoCoreError
from dotenv import load_dotenv

from .config import WorkerConfig
from .errors import RetryableError, WorkerError
from .models import MAX_MESSAGE_BYTES, SpeakeasyJob
from .repository import PostgresJobRepository
from .runtime import WorkerRuntime, create_publisher, create_runtime
from .worker import log_event


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SQS Speakeasy Worker")
    parser.add_argument("--env-file", default=".env", help="환경변수 파일 (기본: .env)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db", help="Worker 전용 PostgreSQL 테이블 생성")
    commands.add_parser("check", help="DB와 SQS/DLQ 설정 확인")
    enqueue = commands.add_parser("enqueue", help="JSON 파일의 분석 요청 등록")
    enqueue.add_argument("message_file", type=Path)
    get = commands.add_parser("get", help="분석 번호로 Speakeasy 상태와 결과 조회")
    get.add_argument("analysis_id")
    commands.add_parser("dispatch", help="DB에 남은 미전송 요청을 SQS에 재전송")
    run = commands.add_parser("run", help="작업 처리, 미전송 요청 복구, DLQ 상태 정리")
    run.add_argument("--once", action="store_true", help="한 번만 확인하고 종료")
    return parser


def _run(runtime: WorkerRuntime, *, once: bool) -> int:
    stop = threading.Event()

    def request_stop(signum, frame) -> None:
        # 진행 중인 Speakeasy 자식 프로세스는 기존 timeout/정리 경로로 마무리한다.
        stop.set()

    originals = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        originals[signum] = signal.signal(signum, request_stop)
    try:
        while not stop.is_set():
            try:
                runtime.publisher.dispatch_pending()
                delivery = runtime.dlq.receive()
                if delivery is not None:
                    runtime.worker.reconcile_dead_letter(delivery, runtime.dlq)
                outcome = runtime.worker.run_once()
                if once:
                    print(json.dumps({"outcome": outcome.value}))
                    return 0
            except RetryableError as exc:
                log_event("service_retry", code=exc.code)
                if once:
                    return 1
                # DB가 끊긴 상태에서는 큐의 다른 작업을 계속 가져와 소진하지 않는다.
                stop.wait(5)
        return 0
    finally:
        for signum, original in originals.items():
            signal.signal(signum, original)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if not stream.isatty() and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = _parser().parse_args(argv)
    load_dotenv(args.env_file, override=False)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        if args.command in {"init-db", "get"}:
            repository = PostgresJobRepository(os.getenv("WORKER_DATABASE_URL", ""))
            if args.command == "init-db":
                repository.initialize()
                print("Worker DB table is ready.")
            else:
                record = repository.get(args.analysis_id)
                if record is None:
                    print(
                        json.dumps(
                            {"error": "NOT_FOUND", "analysis_id": args.analysis_id}
                        )
                    )
                    return 1
                print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            return 0

        config = WorkerConfig.from_env()
        if args.command in {"enqueue", "dispatch"}:
            publisher = create_publisher(config)
            if args.command == "enqueue":
                if args.message_file.stat().st_size > MAX_MESSAGE_BYTES:
                    raise ValueError("job JSON exceeds the 16 KiB limit")
                job = SpeakeasyJob.from_json(
                    args.message_file.read_text(encoding="utf-8-sig")
                )
                record = publisher.submit(job)
                print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            else:
                print(json.dumps({"sent_count": publisher.dispatch_pending()}))
            return 0

        runtime = create_runtime(config)
        runtime.check(config.max_receives)
        if args.command == "check":
            print(
                json.dumps(
                    {"status": "OK", "checks": ["database", "sqs_redrive_policy"]}
                )
            )
            return 0
        return _run(runtime, once=args.once)
    except (WorkerError, BotoCoreError, ValueError, OSError) as exc:
        # 예외 원본/traceback에는 접속 정보가 들어갈 수 있으므로 제한된 설명만 출력한다.
        if isinstance(exc, WorkerError):
            message = f"{exc.code}: {exc.message}"
        elif isinstance(exc, BotoCoreError):
            message = (
                "Cannot initialize AWS clients; check the region and IAM credentials."
            )
        elif isinstance(exc, OSError):
            message = "Cannot read the job/environment file or access local storage."
        else:
            message = str(exc)
        print(message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
