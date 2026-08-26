"""Command-line entry point for the CAPA static-analysis adapter."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from .attack_mapping import normalize_attack_labels, technique_display_name
from .capa_analyzer import DEFAULT_TIMEOUT_SECONDS, CapaAnalyzer, CapaConfig
from .models import CapaBackend, CapaStatus


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run CAPA static analysis and emit a normalized JSON result."
    )
    parser.add_argument("path", help="PE file path (.exe or .dll)")
    parser.add_argument(
        "--backend",
        choices=[backend.value for backend in CapaBackend],
        default=CapaBackend.DEFAULT.value,
        help="CAPA feature-extraction backend (default: default)",
    )
    parser.add_argument(
        "--capa-command",
        default="capa",
        help="CAPA executable or full path (default: capa)",
    )
    parser.add_argument(
        "--capa-executable-arg",
        action="append",
        default=[],
        help=(
            "Argument placed immediately after --capa-command; repeatable "
            "for launchers such as python -m capa.main"
        ),
    )
    parser.add_argument(
        "--rules",
        type=Path,
        help="CAPA rules directory or archive path",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        help="CAPA library-identification signatures directory",
    )
    parser.add_argument(
        "--rules-version",
        help="Pinned CAPA rules version to record in the result",
    )
    parser.add_argument(
        "--ghidra-install-dir",
        type=Path,
        help="Ghidra installation directory used by the ghidra backend",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"CAPA timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    parser.add_argument(
        "--raw-reference",
        help="Durable report reference to attach to generated Evidence",
    )
    parser.add_argument(
        "--include-raw-report",
        action="store_true",
        help="Include the complete CAPA JSON report in the output",
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
        "[CAPA static analysis]",
        f"status: {result.status.value}",
        f"sha256: {result.sha256 or '-'}",
        f"file_type: {result.file_type}",
        f"backend: {result.backend.value}",
        f"capabilities: {len(result.capabilities)}",
        f"capa_version: {result.capa_version or '-'}",
        f"elapsed_ms: {result.elapsed_ms if result.elapsed_ms is not None else '-'}",
    ]
    if result.capabilities:
        lines.append("matches:")
        for item in result.capabilities:
            techniques = normalize_attack_labels(item.attack)
            technique_text = ", ".join(
                technique_display_name(technique)
                for technique in techniques
                if technique.technique_id
            )
            suffix = f" ATT&CK: {technique_text}" if technique_text else ""
            lines.append(
                f"  - {item.rule_name} ({item.namespace or 'no-namespace'}){suffix}"
            )
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
        analyzer = CapaAnalyzer(
            CapaConfig(
                executable=args.capa_command,
                executable_args=tuple(args.capa_executable_arg),
                backend=CapaBackend(args.backend),
                timeout_seconds=args.timeout,
                rules_path=args.rules,
                signatures_path=args.signatures,
                rules_version=args.rules_version,
                ghidra_install_dir=args.ghidra_install_dir,
            )
        )
        result = analyzer.analyze(args.path, raw_reference=args.raw_reference)
    except (OSError, ValueError) as exc:
        print(f"CAPA setup error: {exc}", file=sys.stderr)
        return 2

    if args.summary:
        print(format_summary(result))
    else:
        indent = None if args.compact else 2
        print(result.to_json(indent=indent, include_raw_report=args.include_raw_report))
    return 0 if result.status is CapaStatus.SUCCESS else 1


if __name__ == "__main__":
    raise SystemExit(main())
