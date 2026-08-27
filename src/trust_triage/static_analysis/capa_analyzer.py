"""CAPA command-line adapter for selective static analysis.

The adapter invokes CAPA as a separate process with ``shell=False``. It never
executes or loads the input PE itself. The optional Ghidra mode is represented
as a CAPA backend, not as a second analyzer or a second analysis stage.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import (
    CapaAnalysisResult,
    CapaBackend,
    CapaCapability,
    CapaStatus,
    as_string_tuple,
)


DEFAULT_TIMEOUT_SECONDS = 120.0
_DIAGNOSTIC_LINE_LIMIT = 40


@dataclass(frozen=True)
class CapaConfig:
    """Configuration for one CAPA invocation.

    ``DEFAULT`` means the normal CAPA CLI invocation; no ``-b`` flag is
    emitted. ``GHIDRA`` emits ``-b ghidra`` and therefore requires the Ghidra
    runtime to be installed in the analysis environment.
    """

    executable: str | Path = "capa"
    backend: CapaBackend = CapaBackend.DEFAULT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    rules_path: Path | None = None
    signatures_path: Path | None = None
    rules_version: str | None = None
    ghidra_install_dir: Path | None = None
    working_directory: Path | None = None
    executable_args: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.backend, str):
            object.__setattr__(self, "backend", CapaBackend(self.backend.lower()))
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        for field_name in (
            "rules_path",
            "signatures_path",
            "ghidra_install_dir",
            "working_directory",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, Path):
                object.__setattr__(self, field_name, Path(value))
        object.__setattr__(self, "executable_args", tuple(self.executable_args))
        object.__setattr__(self, "extra_args", tuple(self.extra_args))

    def build_command(self, sample_path: Path) -> tuple[str, ...]:
        """Build a shell-free CAPA command for ``sample_path``."""

        command = [str(self.executable), *self.executable_args]
        if self.backend is CapaBackend.GHIDRA:
            command.extend(("-b", CapaBackend.GHIDRA.value))
        if self.rules_path is not None:
            command.extend(("-r", str(self.rules_path)))
        if self.signatures_path is not None:
            command.extend(("-s", str(self.signatures_path)))
        command.extend(self.extra_args)
        command.extend(("-j", str(sample_path)))
        return tuple(command)


@dataclass(frozen=True)
class ParsedCapaReport:
    """Normalized fields extracted from CAPA's JSON report."""

    file_type: str
    capa_version: str | None
    rules_version: str | None
    analysis_metadata: dict[str, Any]
    capabilities: list[CapaCapability]


class CapaAnalyzer:
    """Run CAPA and normalize its report for TRUST-TRIAGE."""

    def __init__(self, config: CapaConfig | None = None) -> None:
        self.config = config or CapaConfig()

    def analyze(
        self,
        sample_path: str | Path,
        *,
        raw_reference: str | None = None,
    ) -> CapaAnalysisResult:
        path = Path(sample_path)
        if not path.is_file():
            return CapaAnalysisResult(
                sha256="",
                file_type="UNKNOWN",
                status=CapaStatus.INVALID_INPUT,
                backend=self.config.backend,
                errors=[f"input file does not exist or is not a file: {path}"],
                raw_reference=raw_reference,
            )

        try:
            sha256 = sha256_file(path)
        except OSError as exc:
            return CapaAnalysisResult(
                sha256="",
                file_type="UNKNOWN",
                status=CapaStatus.TOOL_ERROR,
                backend=self.config.backend,
                errors=[f"could not read input file for hashing: {exc}"],
                raw_reference=raw_reference,
            )

        environment_error = self._validate_environment()
        if environment_error is not None:
            return CapaAnalysisResult(
                sha256=sha256,
                file_type="UNKNOWN",
                status=CapaStatus.ENVIRONMENT_MISMATCH,
                backend=self.config.backend,
                errors=[environment_error],
                raw_reference=raw_reference,
            )

        resolved_path = path.resolve()
        command = self.config.build_command(resolved_path)
        environment = self._build_environment()
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
                env=environment,
                shell=False,
                timeout=self.config.timeout_seconds,
                text=True,
            )
        except FileNotFoundError as exc:
            return self._failure_result(
                sha256=sha256,
                command=command,
                raw_reference=raw_reference,
                status=CapaStatus.ENVIRONMENT_MISMATCH,
                error=f"CAPA executable was not found: {exc}",
                started=started,
            )
        except PermissionError as exc:
            return self._failure_result(
                sha256=sha256,
                command=command,
                raw_reference=raw_reference,
                status=CapaStatus.ENVIRONMENT_MISMATCH,
                error=f"CAPA executable cannot be executed: {exc}",
                started=started,
            )
        except subprocess.TimeoutExpired as exc:
            diagnostics = _diagnostic_lines(
                _decode_output(exc.stderr or exc.stdout)
            )
            return self._failure_result(
                sha256=sha256,
                command=command,
                raw_reference=raw_reference,
                status=CapaStatus.TIMEOUT,
                errors=diagnostics or ["CAPA analysis timed out"],
                started=started,
            )
        except OSError as exc:
            return self._failure_result(
                sha256=sha256,
                command=command,
                raw_reference=raw_reference,
                status=CapaStatus.TOOL_ERROR,
                error=f"CAPA process could not be started: {exc}",
                started=started,
            )

        elapsed_ms = _elapsed_ms(started)
        stderr = _diagnostic_lines(completed.stderr)
        if completed.returncode != 0:
            status = _classify_process_failure(
                completed.returncode,
                completed.stderr,
            )
            return CapaAnalysisResult(
                sha256=sha256,
                file_type="UNKNOWN",
                status=status,
                backend=self.config.backend,
                errors=stderr
                or [f"CAPA exited with return code {completed.returncode}"],
                warnings=[],
                returncode=completed.returncode,
                elapsed_ms=elapsed_ms,
                command=command,
                raw_reference=raw_reference,
            )

        try:
            report = json.loads(completed.stdout)
            if not isinstance(report, Mapping):
                raise ValueError("CAPA JSON report must be an object")
            parsed = parse_capa_report(report)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return CapaAnalysisResult(
                sha256=sha256,
                file_type="UNKNOWN",
                status=CapaStatus.PARSE_ERROR,
                backend=self.config.backend,
                errors=[f"could not parse CAPA JSON output: {exc}"],
                warnings=stderr,
                returncode=completed.returncode,
                elapsed_ms=elapsed_ms,
                command=command,
                raw_reference=raw_reference,
            )

        metadata = dict(parsed.analysis_metadata)
        metadata["execution_mode"] = "external_process"
        metadata["backend"] = self.config.backend.value
        metadata["analysis_started_at"] = analysis_started_at
        metadata["rules_version"] = (
            parsed.rules_version or self.config.rules_version
        )
        return CapaAnalysisResult(
            sha256=sha256,
            file_type=parsed.file_type,
            status=CapaStatus.SUCCESS,
            backend=self.config.backend,
            capabilities=parsed.capabilities,
            capa_version=parsed.capa_version,
            rules_version=parsed.rules_version or self.config.rules_version,
            analysis_metadata=metadata,
            warnings=stderr,
            returncode=completed.returncode,
            elapsed_ms=elapsed_ms,
            command=command,
            raw_report=dict(report),
            raw_reference=raw_reference,
        )

    def _validate_environment(self) -> str | None:
        for label, path in (
            ("CAPA rules", self.config.rules_path),
            ("CAPA signatures", self.config.signatures_path),
        ):
            if path is not None and not Path(path).exists():
                return f"{label} path does not exist: {path}"
        if (
            self.config.ghidra_install_dir is not None
            and not self.config.ghidra_install_dir.is_dir()
        ):
            return (
                "Ghidra installation directory does not exist: "
                f"{self.config.ghidra_install_dir}"
            )
        return None

    def _build_environment(self) -> dict[str, str] | None:
        if self.config.ghidra_install_dir is None:
            return None
        environment = os.environ.copy()
        environment["GHIDRA_INSTALL_DIR"] = str(self.config.ghidra_install_dir)
        return environment

    def _failure_result(
        self,
        *,
        sha256: str,
        command: tuple[str, ...],
        raw_reference: str | None,
        status: CapaStatus,
        started: float,
        error: str | None = None,
        errors: list[str] | None = None,
    ) -> CapaAnalysisResult:
        diagnostics = list(errors or [])
        if error is not None:
            diagnostics.append(error)
        return CapaAnalysisResult(
            sha256=sha256,
            file_type="UNKNOWN",
            status=status,
            backend=self.config.backend,
            errors=diagnostics,
            elapsed_ms=_elapsed_ms(started),
            command=command,
            raw_reference=raw_reference,
        )


def parse_capa_report(report: Mapping[str, Any]) -> ParsedCapaReport:
    """Parse CAPA JSON while preserving capability and rule metadata."""

    meta = _mapping(report.get("meta"))
    analysis = _mapping(meta.get("analysis")) or _mapping(report.get("analysis"))
    sample = _mapping(meta.get("sample"))

    raw_rules = report.get("rules", {})
    if not isinstance(raw_rules, Mapping):
        raise ValueError("CAPA JSON field 'rules' must be an object")

    capabilities: list[CapaCapability] = []
    for rule_key, raw_rule in raw_rules.items():
        if not isinstance(raw_rule, Mapping):
            raise ValueError(f"CAPA rule '{rule_key}' must be an object")
        rule_meta = _mapping(raw_rule.get("meta"))
        matches = raw_rule.get("matches", raw_rule.get("locations"))
        match_locations = _match_locations(matches)
        if not match_locations:
            continue

        rule_name = _first_text(
            rule_meta.get("name"),
            raw_rule.get("name"),
            rule_key,
        )
        namespace = _first_text(
            rule_meta.get("namespace"),
            raw_rule.get("namespace"),
            "",
        )
        capabilities.append(
            CapaCapability(
                rule_name=rule_name,
                namespace=namespace,
                match_locations=match_locations,
                attack=as_string_tuple(
                    rule_meta.get("att&ck", rule_meta.get("attack"))
                ),
                mbc=as_string_tuple(rule_meta.get("mbc")),
                description=_first_text(rule_meta.get("description"), ""),
            )
        )

    file_type = _first_text(
        analysis.get("format"),
        sample.get("format"),
        "UNKNOWN",
    ).upper()
    capa_version = _optional_text(
        meta.get("version"),
        meta.get("capa_version"),
        report.get("version"),
    )
    rules_version = _optional_text(
        meta.get("rules_version"),
        analysis.get("rules_version"),
        report.get("rules_version"),
    )

    analysis_metadata = dict(analysis)
    if sample:
        analysis_metadata["sample"] = dict(sample)
    return ParsedCapaReport(
        file_type=file_type,
        capa_version=capa_version,
        rules_version=rules_version,
        analysis_metadata=analysis_metadata,
        capabilities=capabilities,
    )


def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Hash a sample without loading it all into memory or executing it."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _match_locations(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        return tuple(_render_match(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_render_match(item) for item in value)
    return (_render_match(value),)


def _render_match(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _first_text(*values: Any) -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _optional_text(*values: Any) -> str | None:
    value = _first_text(*values)
    return value or None


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


def _classify_process_failure(returncode: int, stderr: str) -> CapaStatus:
    del returncode  # The message is more useful than a tool-specific code.
    normalized = stderr.lower()
    if any(
        marker in normalized
        for marker in (
            "ghidra_install_dir",
            "pyghidra",
            "ghidra",
            "java_home",
            "no such file or directory",
        )
    ):
        return CapaStatus.ENVIRONMENT_MISMATCH
    if any(marker in normalized for marker in ("unsupported", "not a pe", "invalid pe")):
        return CapaStatus.UNSUPPORTED
    return CapaStatus.TOOL_ERROR
