"""FLOSS command-line adapter for selective static analysis.

The adapter treats FLOSS as an external static-analysis tool. It reads the
tool's versioned JSON result, keeps string provenance, and converts bounded
string observations into the shared Evidence contract. It never executes or
loads the input PE in the TRUST-TRIAGE process.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ..evidence import Evidence, EvidenceStatus
from .capa_analyzer import sha256_file


DEFAULT_FLOSS_TIMEOUT_SECONDS = 120.0
DEFAULT_MIN_STRING_LENGTH = 4
DEFAULT_MAX_EVIDENCE_STRINGS = 64
_DIAGNOSTIC_LINE_LIMIT = 40
_MAX_STRING_LENGTH = 512
_SUSPICIOUS_STRING_PATTERN = re.compile(
    r"(?:https?://|hxxps?://|\\|\b(?:cmd|powershell|rundll32|regsvr32)\b|"
    r"\b(?:HKCU|HKLM)\\|\.(?:exe|dll|ps1|vbs|js)\b|\b(?:mutex|c2|beacon)\b)",
    re.IGNORECASE,
)


class FlossStatus(str, Enum):
    """Stable status values exposed by the FLOSS adapter."""

    SUCCESS = "SUCCESS"
    INVALID_INPUT = "INVALID_INPUT"
    TIMEOUT = "TIMEOUT"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    PARSE_ERROR = "PARSE_ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    TOOL_ERROR = "TOOL_ERROR"


@dataclass(frozen=True)
class FlossConfig:
    """Configuration for one FLOSS invocation."""

    executable: str | Path = "floss"
    timeout_seconds: float = DEFAULT_FLOSS_TIMEOUT_SECONDS
    min_string_length: int = DEFAULT_MIN_STRING_LENGTH
    working_directory: Path | None = None
    executable_args: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if self.min_string_length < 1:
            raise ValueError("min_string_length must be positive")
        if self.working_directory is not None and not isinstance(
            self.working_directory, Path
        ):
            object.__setattr__(
                self,
                "working_directory",
                Path(self.working_directory),
            )
        object.__setattr__(self, "executable_args", tuple(self.executable_args))
        object.__setattr__(self, "extra_args", tuple(self.extra_args))

    def build_command(self, sample_path: Path) -> tuple[str, ...]:
        """Build a shell-free JSON-producing FLOSS command."""

        command = [str(self.executable), *self.executable_args, "-j"]
        if self.min_string_length != DEFAULT_MIN_STRING_LENGTH:
            command.extend(("-n", str(self.min_string_length)))
        command.extend(self.extra_args)
        # End option parsing before the caller-controlled sample path.
        command.extend(("--", str(sample_path)))
        return tuple(command)


@dataclass(frozen=True)
class FlossString:
    """One string recovered by FLOSS."""

    string_type: str
    value: str
    offset: int | str | None = None
    address: int | str | None = None
    encoding: str = ""
    tags: tuple[str, ...] = ()
    decoding_routine: int | str | None = None
    decoded_at: int | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "string_type": self.string_type,
            "string": self.value,
            "offset": self.offset,
            "address": self.address,
            "encoding": self.encoding,
            "tags": list(self.tags),
            "decoding_routine": self.decoding_routine,
            "decoded_at": self.decoded_at,
        }


@dataclass(frozen=True)
class ParsedFlossReport:
    """Fields extracted from one FLOSS JSON result."""

    sha256: str
    file_type: str
    floss_version: str | None
    analysis_metadata: dict[str, Any]
    strings: tuple[FlossString, ...]
    string_counts: dict[str, int]


@dataclass
class FlossAnalysisResult:
    """Serializable result of one FLOSS invocation."""

    sha256: str
    file_type: str
    status: FlossStatus
    strings: list[FlossString] = field(default_factory=list)
    string_counts: dict[str, int] = field(default_factory=dict)
    floss_version: str | None = None
    analysis_metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    returncode: int | None = None
    elapsed_ms: float | None = None
    command: tuple[str, ...] = ()
    raw_report: dict[str, Any] | None = None
    raw_reference: str | None = None

    @property
    def is_success(self) -> bool:
        return self.status is FlossStatus.SUCCESS

    def to_evidence(
        self,
        *,
        raw_reference: str | None = None,
        reliability: float = 0.55,
        max_strings: int = DEFAULT_MAX_EVIDENCE_STRINGS,
    ) -> list[Evidence]:
        """Convert bounded FLOSS observations into shared Evidence items.

        FLOSS strings are supporting observations, not direct malware labels.
        No ATT&CK technique is inferred from a string alone. This keeps the
        deterministic ATT&CK sufficiency gate from treating a URL, command,
        or path as conclusive evidence by itself.
        """

        if not self.is_success:
            return []
        if not 0.0 <= reliability <= 1.0:
            raise ValueError("reliability must be between 0 and 1")
        if max_strings < 1:
            raise ValueError("max_strings must be positive")

        reference = (
            raw_reference
            or self.raw_reference
            or f"inline:floss/{self.sha256 or 'unknown'}"
        )
        sample_key = self.sha256[:16] if self.sha256 else "unknown"
        evidence: list[Evidence] = []

        total_strings = sum(self.string_counts.values()) or len(self.strings)
        evidence.append(
            Evidence(
                evidence_id=f"evt-floss-{sample_key}-summary",
                sha256=self.sha256,
                source="FLOSS",
                category="STRING_SUMMARY",
                severity=0.15,
                reliability=min(reliability, 0.5),
                summary=(
                    f"FLOSS recovered {total_strings} string(s): "
                    + ", ".join(
                        f"{key}={value}"
                        for key, value in sorted(self.string_counts.items())
                    )
                ),
                status=EvidenceStatus.OBSERVED,
                raw_reference=reference,
                details={
                    "floss_version": self.floss_version,
                    "string_counts": dict(self.string_counts),
                    "total_strings": total_strings,
                },
            )
        )

        selected = sorted(
            self.strings,
            key=lambda item: (
                _string_priority(item),
                item.string_type,
                item.value,
            ),
            reverse=True,
        )[:max_strings]
        for index, item in enumerate(selected, start=1):
            value = _bounded_text(item.value, _MAX_STRING_LENGTH)
            evidence.append(
                Evidence(
                    evidence_id=f"evt-floss-{sample_key}-{index:04d}",
                    sha256=self.sha256,
                    source="FLOSS",
                    category=(
                        "OBFUSCATED_STRING"
                        if item.string_type
                        in {"decoded_strings", "stack_strings", "tight_strings"}
                        else "STRING_OBSERVED"
                    ),
                    severity=_severity_for_string(item),
                    reliability=reliability,
                    summary=(
                        f"FLOSS recovered {item.string_type}: {value}"
                    ),
                    status=EvidenceStatus.OBSERVED,
                    raw_reference=reference,
                    details={
                        "string": value,
                        "string_type": item.string_type,
                        "offset": item.offset,
                        "address": item.address,
                        "encoding": item.encoding,
                        "tags": list(item.tags),
                        "decoding_routine": item.decoding_routine,
                        "decoded_at": item.decoded_at,
                    },
                )
            )
        return evidence

    def to_dict(self, *, include_raw_report: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "sha256": self.sha256,
            "file_type": self.file_type,
            "status": self.status.value,
            "strings": [item.to_dict() for item in self.strings],
            "string_counts": dict(self.string_counts),
            "floss_version": self.floss_version,
            "analysis_metadata": dict(self.analysis_metadata),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "returncode": self.returncode,
            "elapsed_ms": self.elapsed_ms,
            "command": list(self.command),
            "raw_reference": self.raw_reference,
        }
        if include_raw_report:
            payload["raw_report"] = self.raw_report
        return payload

    def to_json(
        self,
        *,
        indent: int | None = 2,
        include_raw_report: bool = False,
    ) -> str:
        return json.dumps(
            self.to_dict(include_raw_report=include_raw_report),
            ensure_ascii=False,
            indent=indent,
            allow_nan=False,
        )


class FlossAnalyzer:
    """Run FLOSS and normalize its versioned JSON result."""

    def __init__(self, config: FlossConfig | None = None) -> None:
        self.config = config or FlossConfig()

    def analyze(
        self,
        sample_path: str | Path,
        *,
        raw_reference: str | None = None,
    ) -> FlossAnalysisResult:
        path = Path(sample_path)
        if not path.is_file():
            return FlossAnalysisResult(
                sha256="",
                file_type="UNKNOWN",
                status=FlossStatus.INVALID_INPUT,
                errors=[f"input file does not exist or is not a file: {path}"],
                raw_reference=raw_reference,
            )

        try:
            sample_sha256 = sha256_file(path)
        except OSError as exc:
            return FlossAnalysisResult(
                sha256="",
                file_type="UNKNOWN",
                status=FlossStatus.TOOL_ERROR,
                errors=[f"could not read input file for hashing: {exc}"],
                raw_reference=raw_reference,
            )

        if (
            self.config.working_directory is not None
            and not self.config.working_directory.is_dir()
        ):
            return FlossAnalysisResult(
                sha256=sample_sha256,
                file_type="UNKNOWN",
                status=FlossStatus.ENVIRONMENT_MISMATCH,
                errors=[
                    "FLOSS working directory does not exist: "
                    f"{self.config.working_directory}"
                ],
                raw_reference=raw_reference,
            )

        resolved_path = path.resolve()
        command = self.config.build_command(resolved_path)
        started = time.perf_counter()
        analysis_started_at = datetime.now(timezone.utc).isoformat()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                cwd=(
                    str(self.config.working_directory)
                    if self.config.working_directory is not None
                    else None
                ),
                encoding="utf-8",
                errors="replace",
                env=os.environ.copy(),
                shell=False,
                text=True,
                timeout=self.config.timeout_seconds,
            )
        except FileNotFoundError as exc:
            return self._failure_result(
                sha256=sample_sha256,
                command=command,
                raw_reference=raw_reference,
                status=FlossStatus.ENVIRONMENT_MISMATCH,
                error=f"FLOSS executable was not found: {exc}",
                started=started,
            )
        except PermissionError as exc:
            return self._failure_result(
                sha256=sample_sha256,
                command=command,
                raw_reference=raw_reference,
                status=FlossStatus.ENVIRONMENT_MISMATCH,
                error=f"FLOSS executable cannot be executed: {exc}",
                started=started,
            )
        except subprocess.TimeoutExpired as exc:
            diagnostics = _diagnostic_lines(_decode_output(exc.stderr or exc.stdout))
            return self._failure_result(
                sha256=sample_sha256,
                command=command,
                raw_reference=raw_reference,
                status=FlossStatus.TIMEOUT,
                errors=diagnostics or ["FLOSS analysis timed out"],
                started=started,
            )
        except OSError as exc:
            return self._failure_result(
                sha256=sample_sha256,
                command=command,
                raw_reference=raw_reference,
                status=FlossStatus.TOOL_ERROR,
                error=f"FLOSS process could not be started: {exc}",
                started=started,
            )

        elapsed_ms = _elapsed_ms(started)
        stderr = _diagnostic_lines(completed.stderr)
        if completed.returncode != 0:
            status = _classify_process_failure(completed.stderr)
            return FlossAnalysisResult(
                sha256=sample_sha256,
                file_type="UNKNOWN",
                status=status,
                errors=stderr
                or [f"FLOSS exited with return code {completed.returncode}"],
                returncode=completed.returncode,
                elapsed_ms=elapsed_ms,
                command=command,
                raw_reference=raw_reference,
            )

        try:
            report = json.loads(completed.stdout)
            if not isinstance(report, Mapping):
                raise ValueError("FLOSS JSON report must be an object")
            parsed = parse_floss_report(report)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return FlossAnalysisResult(
                sha256=sample_sha256,
                file_type="UNKNOWN",
                status=FlossStatus.PARSE_ERROR,
                errors=[f"could not parse FLOSS JSON output: {exc}"],
                warnings=stderr,
                returncode=completed.returncode,
                elapsed_ms=elapsed_ms,
                command=command,
                raw_reference=raw_reference,
            )

        metadata = dict(parsed.analysis_metadata)
        metadata["execution_mode"] = "external_process"
        metadata["analysis_started_at"] = analysis_started_at
        return FlossAnalysisResult(
            sha256=sample_sha256,
            file_type=parsed.file_type,
            status=FlossStatus.SUCCESS,
            strings=list(parsed.strings),
            string_counts=dict(parsed.string_counts),
            floss_version=parsed.floss_version,
            analysis_metadata=metadata,
            warnings=stderr,
            returncode=completed.returncode,
            elapsed_ms=elapsed_ms,
            command=command,
            raw_report=dict(report),
            raw_reference=raw_reference,
        )

    def _failure_result(
        self,
        *,
        sha256: str,
        command: tuple[str, ...],
        raw_reference: str | None,
        status: FlossStatus,
        started: float,
        error: str | None = None,
        errors: list[str] | None = None,
    ) -> FlossAnalysisResult:
        diagnostics = list(errors or [])
        if error is not None:
            diagnostics.append(error)
        return FlossAnalysisResult(
            sha256=sha256,
            file_type="UNKNOWN",
            status=status,
            errors=diagnostics,
            elapsed_ms=_elapsed_ms(started),
            command=command,
            raw_reference=raw_reference,
        )


def parse_floss_report(report: Mapping[str, Any]) -> ParsedFlossReport:
    """Parse FLOSS's versioned JSON document.

    Unknown top-level and per-string fields are ignored so minor FLOSS schema
    additions do not break the integration.
    """

    metadata = _mapping(report.get("metadata"))
    analysis = _mapping(report.get("analysis"))
    raw_strings = _mapping(report.get("strings"))
    if not isinstance(report.get("strings", {}), Mapping):
        raise ValueError("FLOSS JSON field 'strings' must be an object")

    parsed_strings: list[FlossString] = []
    string_counts: dict[str, int] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for group_name, group_values in raw_strings.items():
        if group_values is None:
            string_counts[str(group_name)] = 0
            continue
        if not isinstance(group_values, Sequence) or isinstance(
            group_values, (str, bytes, bytearray)
        ):
            raise ValueError(f"FLOSS string group '{group_name}' must be a list")

        canonical_group = str(group_name)
        count = 0
        for raw_item in group_values:
            if isinstance(raw_item, Mapping):
                value = _first_text(
                    raw_item.get("string"),
                    raw_item.get("value"),
                    raw_item.get("decoded_string"),
                    raw_item.get("text"),
                )
                if not value:
                    continue
                item = FlossString(
                    string_type=canonical_group,
                    value=value,
                    offset=_scalar(raw_item.get("offset")),
                    address=_scalar(
                        raw_item.get("address"),
                        raw_item.get("decoded_at"),
                        raw_item.get("program_counter"),
                    ),
                    encoding=_first_text(raw_item.get("encoding")),
                    tags=_string_tuple(raw_item.get("tags", raw_item.get("tag"))),
                    decoding_routine=_scalar(raw_item.get("decoding_routine")),
                    decoded_at=_scalar(raw_item.get("decoded_at")),
                )
            else:
                value = _first_text(raw_item)
                if not value:
                    continue
                item = FlossString(string_type=canonical_group, value=value)

            key = (
                item.string_type,
                item.value,
                str(item.offset),
                str(item.address),
            )
            if key in seen:
                continue
            seen.add(key)
            parsed_strings.append(item)
            count += 1
        string_counts[canonical_group] = count

    file_type = _first_text(
        metadata.get("file_type"),
        metadata.get("format"),
        analysis.get("format"),
        "UNKNOWN",
    ).upper()
    floss_version = _optional_text(
        metadata.get("version"),
        report.get("version"),
    )
    analysis_metadata = dict(analysis)
    analysis_metadata["metadata"] = dict(metadata)
    return ParsedFlossReport(
        sha256=_first_text(metadata.get("sha256")),
        file_type=file_type,
        floss_version=floss_version,
        analysis_metadata=analysis_metadata,
        strings=tuple(parsed_strings),
        string_counts=string_counts,
    )


def _string_priority(item: FlossString) -> int:
    priority = {
        "decoded_strings": 40,
        "tight_strings": 35,
        "stack_strings": 30,
        "language_strings": 20,
        "static_strings": 10,
    }.get(item.string_type, 5)
    if _SUSPICIOUS_STRING_PATTERN.search(item.value):
        priority += 25
    if any(tag.casefold() in {"#common", "common"} for tag in item.tags):
        priority -= 10
    return priority


def _severity_for_string(item: FlossString) -> float:
    severity = {
        "decoded_strings": 0.45,
        "tight_strings": 0.42,
        "stack_strings": 0.38,
        "language_strings": 0.3,
        "static_strings": 0.2,
    }.get(item.string_type, 0.2)
    if _SUSPICIOUS_STRING_PATTERN.search(item.value):
        severity += 0.15
    if any(tag.casefold() in {"#common", "common"} for tag in item.tags):
        severity -= 0.1
    return max(0.05, min(0.7, round(severity, 3)))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first_text(*values: Any) -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _optional_text(*values: Any) -> str | None:
    value = _first_text(*values)
    return value or None


def _scalar(*values: Any) -> int | str | None:
    for value in values:
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            return value
    return None


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value if str(item).strip())
    return (str(value),)


def _bounded_text(value: str, limit: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1] + "…"


def _decode_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _diagnostic_lines(value: Any) -> list[str]:
    return [
        line.strip()
        for line in _decode_output(value).splitlines()
        if line.strip()
    ][:_DIAGNOSTIC_LINE_LIMIT]


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _classify_process_failure(stderr: str) -> FlossStatus:
    normalized = _decode_output(stderr).lower()
    if any(
        marker in normalized
        for marker in (
            "unsupported",
            "not a pe",
            "invalid pe",
            "could not identify",
            "unknown file format",
        )
    ):
        return FlossStatus.UNSUPPORTED
    return FlossStatus.TOOL_ERROR
