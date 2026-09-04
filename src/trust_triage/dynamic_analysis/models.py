"""동적 분석 결과를 공통 Evidence 형태로 표현한다."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


DYNAMIC_ANALYSIS_SCHEMA_VERSION = "dynamic-analysis-v1"


class DynamicAnalysisStatus(str, Enum):
    """동적 분석 모듈이 반환할 수 있는 처리 상태."""

    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED_API = "UNSUPPORTED_API"
    UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"
    TOOL_ERROR = "TOOL_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"


@dataclass(frozen=True)
class DynamicAnalysisResult:
    """Speakeasy 결과를 후속 Evidence 처리에 전달하는 객체."""

    evidence_id: str
    sha256: str
    source: str
    category: str
    status: DynamicAnalysisStatus
    summary: str
    severity: float | None = None
    reliability: float | None = None
    raw_reference: str | None = None
    observed_apis: tuple[str, ...] = ()
    api_call_counts: Mapping[str, int] = field(default_factory=dict)
    behaviors: tuple[str, ...] = ()
    events: Mapping[str, tuple[Mapping[str, Any], ...]] = field(default_factory=dict)
    analysis_time_ms: int | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    raw_report: Mapping[str, Any] | None = None
    tool_version: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    schema_version: str = DYNAMIC_ANALYSIS_SCHEMA_VERSION
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON 직렬화에 사용할 사전으로 변환한다."""

        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "source": self.source,
            "category": self.category,
            "status": self.status.value,
            "severity": self.severity,
            "reliability": self.reliability,
            "summary": self.summary,
            "raw_reference": self.raw_reference,
            "observed_apis": list(self.observed_apis),
            "api_call_counts": dict(self.api_call_counts),
            "behaviors": list(self.behaviors),
            "events": {
                str(category): [dict(event) for event in category_events]
                for category, category_events in self.events.items()
            },
            "analysis_time_ms": self.analysis_time_ms,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "raw_report": dict(self.raw_report) if self.raw_report is not None else None,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": dict(self.metadata),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """결과를 JSON 문자열로 변환한다."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            allow_nan=False,
        )
