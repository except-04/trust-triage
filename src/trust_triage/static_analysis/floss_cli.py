"""Command-line entry point for the FLOSS static-analysis adapter."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from .floss_analyzer import (
    DEFAULT_FLOSS_TIMEOUT_SECONDS,
    DEFAULT_MAX_EVIDENCE_STRINGS,
    DEFAULT_MIN_STRING_LENGTH,
    FlossAnalyzer,
    FlossConfig,
    FlossStatus,
)


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run FLOSS static analysis and emit a normalized JSON result."
    )
    parser.add_argument("path", help="PE file path (.exe or .dll)")
    parser.add_argument(
        "--floss-command",
        default="floss",
        help="FLOSS executable or full path (default: floss)",
    )
    parser.add_argument(
        "--floss-executable-arg",
        action="append",
        default=[],
        help="Argument placed after --floss-command; repeatable for launchers",
    )
    parser.add_argument(
        "--min-length",
        type=_positive_int,
        default=DEFAULT_MIN_STRING_LENGTH,
        help=(
            "minimum recovered string length "
            f"(default: {DEFAULT_MIN_STRING_LENGTH})"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_FLOSS_TIMEOUT_SECONDS,
        help=(
            "FLOSS timeout in seconds "
            f"(default: {DEFAULT_FLOSS_TIMEOUT_SECONDS:g})"
        ),
    )
    parser.add_argument(
        "--max-strings",
        type=_positive_int,
        default=DEFAULT_MAX_EVIDENCE_STRINGS,
        help=(
            "maximum strings converted to Evidence "
            f"(default: {DEFAULT_MAX_EVIDENCE_STRINGS})"
        ),
    )
    parser.add_argument(
        "--raw-reference",
        help="Durable report reference to attach to generated Evidence",
    )
    parser.add_argument(
        "--include-raw-report",
        action="store_true",
        help="Include the complete FLOSS JSON report in the output",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a concise human-readable summary",
    )
    return parser


def format_summary(result) -> str:
    lines = [
        "[FLOSS static analysis]",
        f"status: {result.status.value}",
        f"sha256: {result.sha256 or '-'}",
        f"file_type: {result.file_type}",
        f"floss_version: {result.floss_version or '-'}",
        f"strings: {len(result.strings)}",
        f"elapsed_ms: {result.elapsed_ms if result.elapsed_ms is not None else '-'}",
    ]
    if result.string_counts:
        lines.append("string_counts:")
        lines.extend(
            f"  - {key}: {value}" for key, value in sorted(result.string_counts.items())
        )
    if result.strings:
        lines.append("recovered_strings:")
        for item in result.strings[:10]:
            lines.append(f"  - [{item.string_type}] {item.value}")
        if len(result.strings) > 10:
            lines.append(f"  - ... {len(result.strings) - 10} more")
    if result.warnings:
        lines.append("warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    if result.errors:
        lines.append("errors:")
        lines.extend(f"  - {error}" for error in result.errors)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyzer = FlossAnalyzer(
            FlossConfig(
                executable=args.floss_command,
                executable_args=tuple(args.floss_executable_arg),
                timeout_seconds=args.timeout,
                min_string_length=args.min_length,
            )
        )
        result = analyzer.analyze(args.path, raw_reference=args.raw_reference)
    except (OSError, ValueError) as exc:
        print(f"FLOSS setup error: {exc}", file=sys.stderr)
        return 2

    if args.summary:
        print(format_summary(result))
    else:
        indent = None if args.compact else 2
        print(result.to_json(indent=indent, include_raw_report=args.include_raw_report))
    return 0 if result.status is FlossStatus.SUCCESS else 1


if __name__ == "__main__":
    raise SystemExit(main())
