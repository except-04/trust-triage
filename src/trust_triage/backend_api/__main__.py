"""python -m trust_triage.backend_api --env-file PATH serve|run|init-db|check"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import signal
import threading
from pathlib import Path

from .errors import BackendError

LOGGER = logging.getLogger(__name__)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="TRUST-TRIAGE 백엔드 API와 분석 처리자"
    )
    result.add_argument(
        "--env-file",
        type=Path,
        help="명시적으로 읽을 설정 파일. 생략하면 .env 파일을 자동으로 읽지 않습니다.",
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "init-db", help="API 테이블을 생성합니다. 기존 데이터는 유지합니다."
    )
    probe = commands.add_parser("check", help="DB와 파일 저장소 연결을 확인합니다.")
    probe.add_argument(
        "--analysis",
        action="store_true",
        help="모델 파일과 분석 패키지 존재 여부도 검사",
    )
    probe.add_argument(
        "--deep", action="store_true", help="심층 분석 도구·DB·SQS 설정도 검사"
    )
    commands.add_parser("serve", help="HTTP API 시작")
    run = commands.add_parser("run", help="DB에 접수된 분석을 처리")
    run.add_argument(
        "--once", action="store_true", help="준비된 작업을 한 단계씩 처리한 후 종료"
    )
    run.add_argument(
        "--limit", type=int, default=10, help="한 회차에 처리할 작업 수 (1~100)"
    )
    cleanup = commands.add_parser(
        "cleanup", help="보관 기간이 지난 종료 작업의 원본 정리"
    )
    cleanup.add_argument(
        "--delete",
        action="store_true",
        help="원본 삭제 실행. 생략하면 대상 번호만 조회",
    )
    cleanup.add_argument("--limit", type=int, default=100)
    export = commands.add_parser("export-openapi", help="접속 없이 API 명세 JSON 생성")
    export.add_argument(
        "--output", type=Path, default=Path("docs/backend-api/openapi.json")
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        if args.env_file is not None:
            from dotenv import load_dotenv

            if not args.env_file.is_file():
                raise ValueError("The specified environment file does not exist")
            load_dotenv(args.env_file, override=False)
        from .app import create_app
        from .config import BackendConfig
        from .runtime import check, create_processor, create_service

        config = BackendConfig.from_env()
        if args.command == "export-openapi":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(
                    create_app(config=config).openapi(), ensure_ascii=False, indent=2
                )
                + "\n",
                encoding="utf-8",
            )
            print(json.dumps({"output": str(args.output)}, ensure_ascii=False))
            return 0
        if hasattr(args, "limit") and not 1 <= args.limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        service = create_service(config)
        if args.command == "init-db":
            service.repository.initialize()
            print('{"status":"initialized"}')
        elif args.command == "check":
            print(json.dumps(check(service, analysis=args.analysis, deep=args.deep)))
        elif args.command == "cleanup":
            print(json.dumps(service.cleanup(limit=args.limit, delete=args.delete)))
        elif args.command == "serve":
            import uvicorn

            service.repository.check()
            uvicorn.run(
                create_app(service),
                host=config.host,
                port=config.port,
                log_level="info",
            )
        elif args.command == "run":
            service.repository.check()
            processor, stop = create_processor(service), threading.Event()
            previous = {}

            def request_stop(_signum, _frame):
                stop.set()

            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, request_stop)
            try:
                while not stop.is_set():
                    try:
                        rows = processor.resume_ready(
                            args.limit, should_stop=stop.is_set
                        )
                        if args.once:
                            print(
                                json.dumps(
                                    {
                                        "processed": [
                                            {
                                                "analysis_id": row.analysis_id,
                                                "status": row.status,
                                                "current_stage": row.current_stage,
                                            }
                                            for row in rows
                                        ]
                                    }
                                )
                            )
                            break
                    except BackendError as exc:
                        LOGGER.error("backend_processor_error code=%s", exc.code)
                        if args.once or not exc.retryable:
                            raise
                    stop.wait(config.poll_seconds)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
        return 0
    except BackendError as exc:
        print(json.dumps({"error": exc.to_dict()}, ensure_ascii=False))
        return 1
    except Exception:  # noqa: BLE001 - CLI must never print credentials from third-party exceptions
        print(
            json.dumps(
                {
                    "error": {
                        "code": "CONFIGURATION_OR_RUNTIME_ERROR",
                        "message": "설정·의존성·저장소 권한을 확인해주세요.",
                    }
                },
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
