"""파일 하나의 정적 Feature를 추출하는 명령줄 실행 진입점."""

from __future__ import annotations

import argparse
import sys

from .extractor import extract_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PE 파일에서 재현 가능한 정적 Feature를 추출합니다."
    )
    parser.add_argument("path", help="분석할 .exe 또는 .dll 파일 경로")
    parser.add_argument(
        "--compact", action="store_true", help="JSON을 한 줄로 출력합니다"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = extract_file(args.path)
    indent = None if args.compact else 2
    print(result.to_json(indent=indent))
    return 0 if result.status.value == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
