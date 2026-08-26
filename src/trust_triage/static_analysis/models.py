"""Data contracts for CAPA-based static analysis.

The CAPA adapter deliberately keeps analysis status separate from evidence.
An unsuccessful tool invocation is an analysis event, not malicious evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from ..evidence import Evidence, EvidenceStatus


class CapaBackend(str, Enum):
    """Feature-extraction backend used by CAPA."""

    DEFAULT = "default"
    GHIDRA = "ghidra"


class CapaStatus(str, Enum):
    """Stable status values exposed to the rest of TRUST-TRIAGE."""

    SUCCESS = "SUCCESS"
    INVALID_INPUT = "INVALID_INPUT"
    TIMEOUT = "TIMEOUT"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    PARSE_ERROR = "PARSE_ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    UNSUPPORTED_API = "UNSUPPORTED_API"
    TOOL_ERROR = "TOOL_ERROR"


@dataclass(frozen=True)
class CapaCapability:
    """One top-level capability match reported by CAPA."""

    rule_name: str
    namespace: str = ""
    match_locations: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    mbc: tuple[str, ...] = ()
    description: str = ""

    @property
    def match_count(self) -> int:
        return len(self.match_locations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "match_locations": list(self.match_locations),
            "match_count": self.match_count,
            "attack": list(self.attack),
            "mbc": list(self.mbc),
            "description": self.description,
        }


@dataclass
class CapaAnalysisResult:
    """Serializable result of one CAPA invocation."""

    sha256: str
    file_type: str
    status: CapaStatus
    backend: CapaBackend
    capabilities: list[CapaCapability] = field(default_factory=list)
    capa_version: str | None = None
    rules_version: str | None = None
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
        return self.status is CapaStatus.SUCCESS

    def to_evidence(
        self,
        *,
        raw_reference: str | None = None,
        reliability: float = 0.8,
    ) -> list[Evidence]:
        """Convert matches to Evidence without turning failures into evidence."""

        if not self.is_success:
            return []
        if not 0.0 <= reliability <= 1.0:
            raise ValueError("reliability must be between 0 and 1")

        reference = (
            raw_reference
            or self.raw_reference
            or f"inline:capa/{self.sha256 or 'unknown'}"
        )
        sample_key = self.sha256[:16] if self.sha256 else "unknown"
        evidence: list[Evidence] = []
        for index, capability in enumerate(self.capabilities, start=1):
            # Keep the raw CAPA label in ``details.attack`` while adding a
            # stable ATT&CK representation for the downstream router.
            from ..attack_mapping import normalize_attack_labels

            attack_techniques = normalize_attack_labels(capability.attack)
            evidence.append(
                Evidence(
                    evidence_id=f"evt-capa-{sample_key}-{index:04d}",
                    sha256=self.sha256,
                    source="CAPA",
                    category="CAPABILITY_MATCH",
                    severity=_severity_for_namespace(capability.namespace),
                    reliability=reliability,
                    summary=f"CAPA matched capability: {capability.rule_name}",
                    raw_reference=reference,
                    details={
                        "backend": self.backend.value,
                        "rule_name": capability.rule_name,
                        "namespace": capability.namespace,
                        "match_count": capability.match_count,
                        "match_locations": list(capability.match_locations),
                        "attack": list(capability.attack),
                        "mbc": list(capability.mbc),
                        "attack_techniques": [
                            technique.to_dict() for technique in attack_techniques
                        ],
                    },
                    attack_techniques=attack_techniques,
                )
            )
        return evidence

    def to_dict(self, *, include_raw_report: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "sha256": self.sha256,
            "file_type": self.file_type,
            "status": self.status.value,
            "backend": self.backend.value,
            "capabilities": [item.to_dict() for item in self.capabilities],
            "capa_version": self.capa_version,
            "rules_version": self.rules_version,
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


def _severity_for_namespace(namespace: str) -> float:
    """Return a conservative, non-calibrated evidence weight.

    CAPA capabilities are not malware labels. This small prior only supplies
    the required Evidence field until the project-level fusion policy exists.
    """

    normalized = namespace.lower().strip()
    if normalized.startswith(
        (
            "anti-analysis",
            "communication",
            "collection",
            "exploitation",
            "impact",
            "load-code",
            "persistence",
        )
    ):
        return 0.7
    if normalized.startswith(("compiler", "executable", "linking", "runtime")):
        return 0.3
    return 0.5


def as_string_tuple(value: Any) -> tuple[str, ...]:
    """Normalize scalar/list CAPA metadata into a JSON-safe string tuple."""

    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(str(key) for key in value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value)
    return (str(value),)
