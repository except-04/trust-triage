"""파일 하나의 정적 Feature를 추출하는 명령줄 실행 진입점."""

from __future__ import annotations

import argparse
import sys

from .ember_v3 import extract_file
from .result import FeatureExtractionResult


def format_summary(result: FeatureExtractionResult) -> str:
    """Feature 벡터 전체 대신 사람이 읽기 쉬운 핵심 정보만 포맷한다."""

    lines = [
        "[PE 정적 분석 요약]",
        f"상태: {result.status.value}",
        f"SHA-256: {result.sha256 or '-'}",
        f"파일 형식: {result.file_type}",
        f"EMBER Schema: {result.schema_version}",
        f"Feature 개수: {result.feature_count}",
    ]

    if result.api_groups is not None:
        report = result.api_groups
        lines.extend(
            [
                "Import 요약:",
                f"  이름이 있는 Import: {report.named_import_count}",
                f"  Ordinal Import: {report.ordinal_import_count}",
                "API 그룹:",
            ]
        )
        for group_name, match in report.groups.items():
            status = "발견" if match.matched else "미발견"
            api_text = ", ".join(match.apis) or "-"
            dll_text = ", ".join(match.dlls) or "-"
            lines.append(
                f"  {group_name}: {status} "
                f"(매칭 {match.match_count}개, API: {api_text}, DLL: {dll_text})"
            )

    if result.missing_features:
        lines.append(f"누락 Feature: {len(result.missing_features)}개")
    if result.warnings:
        lines.append("경고:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    if result.errors:
        lines.append("오류:")
        lines.extend(f"  - {error}" for error in result.errors)

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PE 파일에서 재현 가능한 정적 Feature를 추출합니다."
    )
    parser.add_argument("path", help="분석할 .exe 또는 .dll 파일 경로")
    parser.add_argument(
        "--features-file",
        help="EMBER Feature 그룹 선택 JSON 경로(thrember 사용 시에만 적용)",
    )
    parser.add_argument(
        "--compact", action="store_true", help="JSON을 한 줄로 출력합니다"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="JSON 대신 핵심 분석 정보와 API 그룹 결과를 요약해서 출력합니다",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = extract_file(args.path, features_file=args.features_file)
    if args.summary:
        print(format_summary(result))
        return 0 if result.status.value == "SUCCESS" else 1

    indent = None if args.compact else 2
    print(result.to_json(indent=indent))
    return 0 if result.status.value == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
