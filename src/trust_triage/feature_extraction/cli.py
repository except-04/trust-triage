"""파일 하나의 정적 Feature를 추출하는 명령줄 실행 진입점."""

from __future__ import annotations

import argparse
import json
import math
import sys

import numpy as np

from .ember_v3 import DEFAULT_TIMEOUT_SECONDS, EmberV3Extractor, extract_file
from .result import FeatureExtractionResult
from .selection import FeatureSelector


def format_summary(result: FeatureExtractionResult) -> str:
    """Feature 벡터 전체 대신 사람이 읽기 쉬운 핵심 정보만 포맷한다."""

    lines = [
        "[PE 정적 분석 요약]",
        f"상태: {result.status.value}",
        f"SHA-256: {result.sha256 or '-'}",
        f"파일 형식: {result.file_type}",
        f".NET 여부: {'예' if result.is_dotnet else '아니오'}",
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
        if report.ordinal_imports:
            lines.append("Ordinal 상세:")
            lines.extend(
                f"  - {item.dll} ordinal {item.ordinal}"
                for item in report.ordinal_imports
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


def format_selection_summary(
    selector: FeatureSelector,
    selected_feature_count: int,
) -> str:
    """선택된 모델 입력 Schema의 핵심 정보만 출력한다."""

    return "\n".join(
        [
            "[모델 입력 Feature 선택 요약]",
            f"선택 ID: {selector.selection_id}",
            f"선택 방식: {'전체' if selector.is_all else '부분집합'}",
            f"모델 입력 Schema: {selector.output_schema.version}",
            f"모델 입력 Feature 개수: {selected_feature_count}",
            f"자료형: {selector.dtype}",
        ]
    )


def build_selected_payload(
    result: FeatureExtractionResult,
    selector: FeatureSelector,
    selected_vector: np.ndarray,
) -> dict[str, object]:
    """추출 결과에서 선택된 모델 입력 벡터만 JSON으로 만든다."""

    # selected_vector는 FeatureSelector가 검증한 1차원 NumPy 배열이다.
    return {
        "source_schema_version": result.schema_version,
        "schema_version": selector.output_schema.version,
        "selection_id": selector.selection_id,
        "mode": "all" if selector.is_all else "subset",
        "dtype": selector.dtype,
        "sha256": result.sha256,
        "file_type": result.file_type,
        "is_dotnet": result.is_dotnet,
        "feature_count": selector.feature_count,
        "feature_names": list(selector.selected_feature_names),
        "features": [float(value) for value in selected_vector],
        "metadata": dict(result.metadata),
    }


def _positive_float(value: str) -> float:
    """CLI에서 0보다 큰 실수 제한 시간을 받는다."""

    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("양수인 숫자를 입력하세요.") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout은 0보다 커야 합니다.")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PE 파일에서 재현 가능한 정적 Feature를 추출합니다."
    )
    parser.add_argument("path", help="분석할 .exe 또는 .dll 파일 경로")
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"정적 Feature 추출 제한 시간(초), 기본값: {DEFAULT_TIMEOUT_SECONDS:g}",
    )
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
    parser.add_argument(
        "--selection-file",
        help="모델 입력 Feature 선택 manifest JSON 경로",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.selection_file:
            # 선택 manifest는 실제로 사용한 extractor Schema에 대해 검증해야
            # 하므로, 이 경우에는 extractor 객체를 직접 유지한다.
            extractor = EmberV3Extractor(features_file=args.features_file)
            result = extractor.extract_with_timeout(args.path, args.timeout)
        else:
            result = extract_file(
                args.path,
                features_file=args.features_file,
                timeout_seconds=args.timeout,
            )
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"Feature extraction setup error: {exc}", file=sys.stderr)
        return 2

    if args.selection_file and result.status.value == "SUCCESS":
        try:
            selector = FeatureSelector.from_json_file(
                extractor.schema,
                args.selection_file,
            )
            selected_vector = result.to_model_input(selector)
        except (OSError, ValueError) as exc:
            print(f"Feature selection error: {exc}", file=sys.stderr)
            return 2

        if args.summary:
            print(format_summary(result))
            print()
            print(format_selection_summary(selector, selector.feature_count))
            return 0

        indent = None if args.compact else 2
        print(
            json.dumps(
                build_selected_payload(result, selector, selected_vector),
                ensure_ascii=False,
                indent=indent,
                allow_nan=False,
            )
        )
        return 0
    if args.summary:
        print(format_summary(result))
        return 0 if result.status.value == "SUCCESS" else 1

    indent = None if args.compact else 2
    print(result.to_json(indent=indent))
    return 0 if result.status.value == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
