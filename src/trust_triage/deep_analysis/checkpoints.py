"""CAPA/FLOSS 결과를 저장하고 다른 프로세스에서 복원하는 체크포인트."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..evidence import AttackTechnique, Evidence, EvidenceStatus
from .models import AnalysisTier, EvidenceAssessment

STATIC_CHECKPOINT_VERSION = "deep-static-v1"
MAX_CHECKPOINT_BYTES = 8 * 1024 * 1024


def json_snapshot(value: Any, *, max_bytes: int | None = MAX_CHECKPOINT_BYTES) -> Any:
    """JSON으로 복원 가능한 유한 값만 저장하며 내부 객체와 참조를 공유하지 않는다."""

    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
    if max_bytes is not None and len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError("Deep-analysis checkpoint exceeds the 8 MiB limit")
    return json.loads(encoded)


def tool_snapshot(result: Any, status: str) -> dict[str, Any]:
    """기존 도구의 JSON 결과를 보존한다. 원본 파일/대형 raw report는 수집하지 않는다."""

    if result is None:
        return {"status": status}
    to_dict = getattr(result, "to_dict", None)
    if isinstance(result, Mapping):
        payload = dict(result)
    elif callable(to_dict):
        payload = dict(to_dict())
    else:
        payload = {"status": status, "sha256": getattr(result, "sha256", "")}
    payload.pop("raw_report", None)
    payload.pop("command", None)
    # The service archives or explicitly omits oversized tool details before
    # constructing the bounded, durable checkpoint.
    return json_snapshot(payload, max_bytes=None)


@dataclass(frozen=True)
class StaticAnalysisCheckpoint:
    sha256: str
    initial_route: str
    initial_verdict: str | None
    config_fingerprint: str
    needs_speakeasy: bool
    last_tier: AnalysisTier
    assessment: EvidenceAssessment
    executed_tiers: tuple[AnalysisTier, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    tool_statuses: Mapping[str, str] = field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    tool_results: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_snapshot(
            {
                "schema_version": STATIC_CHECKPOINT_VERSION,
                "sha256": self.sha256,
                "initial_route": self.initial_route,
                "initial_verdict": self.initial_verdict,
                "config_fingerprint": self.config_fingerprint,
                "needs_speakeasy": self.needs_speakeasy,
                "last_tier": self.last_tier.value,
                "assessment": self.assessment.to_dict(),
                "executed_tiers": [tier.value for tier in self.executed_tiers],
                "evidence": [item.to_dict() for item in self.evidence],
                "tool_statuses": dict(self.tool_statuses),
                "reason_codes": list(self.reason_codes),
                "errors": list(self.errors),
                "tool_results": dict(self.tool_results),
            }
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StaticAnalysisCheckpoint:
        payload = json_snapshot(dict(value))
        if payload.get("schema_version") != STATIC_CHECKPOINT_VERSION:
            raise ValueError("Unsupported static checkpoint schema")
        try:
            assessment = payload["assessment"]
            if not isinstance(payload["needs_speakeasy"], bool):
                raise ValueError("needs_speakeasy must be a boolean")  # noqa: TRY004 - invalid serialized contract
            if not isinstance(assessment["sufficient"], bool):
                raise ValueError("assessment.sufficient must be a boolean")  # noqa: TRY004 - invalid serialized contract
            if not 0 <= assessment["weighted_score"] <= 1:
                raise ValueError("assessment score must be between zero and one")
            return cls(
                sha256=payload["sha256"],
                initial_route=payload["initial_route"],
                initial_verdict=payload["initial_verdict"],
                config_fingerprint=payload["config_fingerprint"],
                needs_speakeasy=payload["needs_speakeasy"],
                last_tier=AnalysisTier(payload["last_tier"]),
                assessment=EvidenceAssessment(
                    sufficient=assessment["sufficient"],
                    weighted_score=assessment["weighted_score"],
                    mapped_technique_ids=tuple(assessment["mapped_technique_ids"]),
                    reason_codes=tuple(assessment["reason_codes"]),
                ),
                executed_tiers=tuple(
                    AnalysisTier(tier) for tier in payload["executed_tiers"]
                ),
                evidence=tuple(
                    _evidence_from_dict(item) for item in payload["evidence"]
                ),
                tool_statuses=dict(payload["tool_statuses"]),
                reason_codes=tuple(payload["reason_codes"]),
                errors=tuple(payload["errors"]),
                tool_results=dict(payload["tool_results"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid static analysis checkpoint") from exc

    def validate_identity(
        self,
        *,
        sha256: str,
        initial_route: str,
        initial_verdict: str | None,
        config_fingerprint: str,
    ) -> None:
        """비동기 경계에서 다른 파일·분석 설정의 결과를 섞지 않도록 검증한다."""

        if (
            not re.fullmatch(r"[0-9a-f]{64}", self.sha256)
            or self.sha256 != sha256
            or self.initial_route != initial_route
            or self.initial_verdict != initial_verdict
            or self.config_fingerprint != config_fingerprint
        ):
            raise ValueError(
                "Checkpoint identity or configuration does not match the request"
            )
        if set(self.executed_tiers) - {AnalysisTier.CAPA, AnalysisTier.FLOSS}:
            raise ValueError("Static checkpoint contains a later analysis tier")
        if (
            self.last_tier not in {AnalysisTier.CAPA, AnalysisTier.FLOSS}
            or self.last_tier not in self.executed_tiers
            or len(set(self.executed_tiers)) != len(self.executed_tiers)
        ):
            raise ValueError(
                "Static checkpoint last tier or execution history is invalid"
            )
        if self.needs_speakeasy == self.assessment.sufficient:
            raise ValueError("Checkpoint contradicts its evidence assessment")
        seen: set[str] = set()
        for item in self.evidence:
            if (
                item.sha256 != sha256
                or not item.evidence_id
                or item.evidence_id in seen
            ):
                raise ValueError(
                    "Checkpoint evidence has a conflicting SHA-256 or duplicate ID"
                )
            if item.source not in {"CAPA", "FLOSS"}:
                raise ValueError(
                    "Static checkpoint contains evidence from another tool"
                )
            seen.add(item.evidence_id)
        for source, result in self.tool_results.items():
            if source not in {"CAPA", "FLOSS"} or not isinstance(result, Mapping):
                raise ValueError("Invalid static tool result")
            actual_hash = result.get("sha256")
            if actual_hash and actual_hash != sha256:
                raise ValueError("Static tool returned a different SHA-256")
            if result.get("status") == "SUCCESS" and not actual_hash:
                raise ValueError("Successful static tool result has no SHA-256")


def _evidence_from_dict(value: Mapping[str, Any]) -> Evidence:
    techniques = tuple(
        AttackTechnique(
            technique_id=item["technique_id"],
            technique_name=item["technique_name"],
            tactics=tuple(item["tactics"]),
            source_label=item["source_label"],
            mapping_status=item["mapping_status"],
        )
        for item in value["attack_techniques"]
    )
    return Evidence(
        evidence_id=value["evidence_id"],
        sha256=value["sha256"],
        source=value["source"],
        category=value["category"],
        severity=value["severity"],
        reliability=value["reliability"],
        summary=value["summary"],
        status=EvidenceStatus(value["status"]),
        raw_reference=value["raw_reference"],
        details=dict(value["details"]),
        attack_techniques=techniques,
    )
