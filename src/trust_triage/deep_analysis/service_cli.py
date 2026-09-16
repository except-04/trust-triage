"""심층 분석 등록과 저장된 단계 재개를 위한 실행 진입점."""

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

from ..speakeasy_worker.errors import RetryableError, WorkerError
from ..speakeasy_worker.models import MAX_MESSAGE_BYTES
from ..speakeasy_worker.repository import PostgresJobRepository
from .service_models import DeepAnalysisRequest
from .service_repository import PostgresDeepAnalysisRepository
from .service_runtime import _number, create_deep_analysis_runtime


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CAPA/FLOSS → SQS Speakeasy → Evidence/LLM"
    )
    parser.add_argument("--env-file", default=".env")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db", help="심층 분석과 Worker 테이블 생성")
    commands.add_parser("check", help="DB, SQS, CAPA/FLOSS 경로 설정 확인")
    start = commands.add_parser("start", help="JSON 파일의 심층 분석 요청 시작")
    start.add_argument("request_file", type=Path)
    start.add_argument(
        "--enqueue-only",
        action="store_true",
        help="등록만 하고 run 프로세스에서 정적 분석",
    )
    get = commands.add_parser("get", help="저장된 진행 상태와 최종 결과 조회")
    get.add_argument("analysis_id")
    resume = commands.add_parser("resume", help="한 작업의 저장된 단계 재개")
    resume.add_argument("analysis_id")
    run = commands.add_parser("run", help="UI 조회와 독립적으로 대기 작업 처리·재개")
    run.add_argument("--once", action="store_true")
    run.add_argument("--limit", type=int, default=10)
    return parser


def _run(runtime, *, once: bool, limit: int) -> int:
    if not 1 <= limit <= 100:
        raise ValueError("--limit must be between 1 and 100")
    poll = _number("DEEP_POLL_SECONDS", 3)
    if not 0.1 <= poll <= 60:
        raise ValueError("DEEP_POLL_SECONDS must be between 0.1 and 60")
    stop = threading.Event()

    def request_stop(signum, frame) -> None:
        stop.set()

    originals = {
        signum: signal.signal(signum, request_stop)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        while not stop.is_set():
            try:
                records = runtime.service.resume_ready(limit, should_stop=stop.is_set)
                if once:
                    print(
                        json.dumps(
                            {"processed": [record.to_dict() for record in records]},
                            ensure_ascii=False,
                        )
                    )
                    return 0
            except RetryableError as exc:
                logging.getLogger(__name__).warning(
                    json.dumps(
                        {
                            "source": "DEEP_ANALYSIS",
                            "event": "service_retry",
                            "code": exc.code,
                        }
                    )
                )
                if once:
                    return 1
            stop.wait(poll)
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
            dsn = os.getenv("WORKER_DATABASE_URL", "")
            repository = PostgresDeepAnalysisRepository(dsn)
            if args.command == "init-db":
                PostgresJobRepository(dsn).initialize()
                repository.initialize()
                print("Deep-analysis and Worker tables are ready.")
                return 0
            record = repository.get(args.analysis_id)
            if record is None:
                print(
                    json.dumps({"error": "NOT_FOUND", "analysis_id": args.analysis_id})
                )
                return 1
            print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            return 0

        runtime = create_deep_analysis_runtime()
        if args.command in {"check", "run"}:
            runtime.check()
        if args.command == "check":
            print(
                json.dumps(
                    {"status": "OK", "checks": ["database", "sqs", "static_tool_paths"]}
                )
            )
            return 0
        if args.command == "start":
            if args.request_file.stat().st_size > MAX_MESSAGE_BYTES:
                raise ValueError("request JSON exceeds the 16 KiB limit")
            request = DeepAnalysisRequest.from_json(
                args.request_file.read_text(encoding="utf-8-sig")
            )
            method = (
                runtime.service.register if args.enqueue_only else runtime.service.start
            )
            record = method(request)
        elif args.command == "resume":
            record = runtime.service.resume(args.analysis_id)
        else:
            return _run(runtime, once=args.once, limit=args.limit)
        print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
        return 0
    except (WorkerError, BotoCoreError, ValueError, OSError) as exc:
        if isinstance(exc, WorkerError):
            message = f"{exc.code}: {exc.message}"
        elif isinstance(exc, BotoCoreError):
            message = "Cannot initialize AWS clients; check region and IAM credentials."
        elif isinstance(exc, OSError):
            message = "Cannot read the request/environment file or local storage."
        else:
            message = str(exc)
        print(message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
