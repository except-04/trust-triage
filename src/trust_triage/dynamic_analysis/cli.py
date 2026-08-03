"""Speakeasy 동적 분석 CLI."""

from __future__ import annotations

import argparse
import sys

from .models import DynamicAnalysisStatus
from .speakeasy_analyzer import SpeakeasyAnalyzer


def build_parser() -> argparse.ArgumentParser:
    """CLI 인자를 정의한다."""

    parser = argparse.ArgumentParser(description="Speakeasy PE 동적 분석")
    parser.add_argument("sample", help="분석할 PE 파일 경로")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="분석 제한 시간(초), 기본값: 30",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=1_000_000,
        help="에뮬레이터 명령어 제한, 기본값: 1000000",
    )
    parser.add_argument(
        "--include-raw-report",
        action="store_true",
        help="원본 report를 artifacts 경로에 저장하고 raw_reference를 출력",
    )
    parser.add_argument(
        "--raw-report-dir",
        default="artifacts/speakeasy",
        help="원본 report 저장 폴더 (기본값: artifacts/speakeasy)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="JSON을 한 줄로 출력",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 진입점."""

    args = build_parser().parse_args(argv)
    analyzer = SpeakeasyAnalyzer(
        timeout_seconds=args.timeout,
        max_instructions=args.max_instructions,
        include_raw_report=args.include_raw_report,
        raw_report_directory=args.raw_report_dir,
    )
    result = analyzer.analyze(args.sample)
    print(result.to_json(indent=None if args.compact else 2))
    return 0 if result.status is DynamicAnalysisStatus.SUCCESS else 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
