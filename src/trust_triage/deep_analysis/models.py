"""Contracts for the CAPA -> Speakeasy deep-analysis pipeline."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from math import prod
from typing import Any



class EvidenceStatus(str, Enum):
    """Observation state for a deep-analysis evidence item."""

    OBSERVED = "OBSERVED"


@dataclass(frozen=True)
class AttackTechnique:
    """Canonical ATT&CK reference used by the deep-analysis policy."""

    technique_id: str | None
    technique_name: str
    tactics: tuple[str, ...] = ()
    source_label: str = ""
    mapping_status: str = "MAPPED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactics": list(self.tactics),
            "source_label": self.source_label,
            "mapping_status": self.mapping_status,
        }


@dataclass(frozen=True)
class Evidence:
    """Tool-neutral Evidence contract owned by deep analysis."""

    evidence_id: str
    sha256: str
    source: str
    category: str
    severity: float
    reliability: float
    summary: str
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    raw_reference: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    attack_techniques: tuple[AttackTechnique, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("severity", "reliability"):
            value = getattr(self, field_name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "source": self.source,
            "category": self.category,
            "severity": self.severity,
            "reliability": self.reliability,
            "summary": self.summary,
            "status": self.status.value,
            "raw_reference": self.raw_reference,
            "details": dict(self.details),
            "attack_techniques": [
                technique.to_dict() for technique in self.attack_techniques
            ],
        }


class DeepAnalysisStatus(str, Enum):
    """Lifecycle status of the complete deep-analysis flow."""

    COMPLETE = "COMPLETE"
    NOT_REQUIRED = "NOT_REQUIRED"
    FAILED = "FAILED"


class AnalysisTier(str, Enum):
    """Supported deep-analysis tiers in the MVP."""

    CAPA = "CAPA"
    SPEAKEASY = "SPEAKEASY"


class DeepAnalysisDisposition(str, Enum):
    """Routing recommendation after deep analysis."""

    AUTO_ALLOW_RECOMMENDED = "AUTO_ALLOW_RECOMMENDED"
    ALERT_RECOMMENDED = "ALERT_RECOMMENDED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    REPORT_ONLY = "REPORT_ONLY"


@dataclass(frozen=True)
class EvidenceAssessment:
    """Explain why the current evidence is or is not sufficient."""

    sufficient: bool
    weighted_score: float
    mapped_technique_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sufficient": self.sufficient,
            "weighted_score": self.weighted_score,
            "mapped_technique_ids": list(self.mapped_technique_ids),
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class EvidenceSufficiencyPolicy:
    """Configurable MVP gate for deciding whether another Tier is needed.

    The score is a routing weight, not a calibrated malware probability.  A
    technique's contribution is ``severity * reliability``; repeated evidence
    for the same technique is capped before independent techniques are
    combined.  Thresholds must be calibrated by the evaluation owner before
    production use.
    """

    minimum_weighted_score: float = 0.55
    minimum_mapped_techniques: int = 1

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_weighted_score <= 1.0:
            raise ValueError("minimum_weighted_score must be between 0 and 1")
        if self.minimum_mapped_techniques < 1:
            raise ValueError("minimum_mapped_techniques must be positive")

    def assess(self, evidence: Sequence[Evidence]) -> EvidenceAssessment:
        """Return a deterministic, explainable evidence sufficiency result."""

        contributions: dict[str, float] = {}
        for item in evidence:
            contribution = min(1.0, item.severity * item.reliability)
            for technique in item.attack_techniques:
                if not technique.technique_id:
                    continue
                contributions[technique.technique_id] = max(
                    contributions.get(technique.technique_id, 0.0),
                    contribution,
                )

        technique_ids = tuple(sorted(contributions))
        if not technique_ids:
            return EvidenceAssessment(
                sufficient=False,
                weighted_score=0.0,
                reason_codes=("NO_MAPPED_ATTACK_TECHNIQUE",),
            )

        weighted_score = round(
            1.0 - prod(1.0 - contributions[technique_id] for technique_id in technique_ids),
            6,
        )
        sufficient = (
            len(technique_ids) >= self.minimum_mapped_techniques
            and weighted_score >= self.minimum_weighted_score
        )
        reason_codes = (
            ("SUFFICIENT_ATTACK_TECHNIQUE_EVIDENCE",)
            if sufficient
            else ("ATTACK_TECHNIQUE_EVIDENCE_BELOW_THRESHOLD",)
        )
        return EvidenceAssessment(
            sufficient=sufficient,
            weighted_score=weighted_score,
            mapped_technique_ids=technique_ids,
            reason_codes=reason_codes,
        )


@dataclass(frozen=True)
class DeepAnalysisResult:
    """Serializable result of one bounded deep-analysis run."""

    sha256: str
    deep_analysis_status: DeepAnalysisStatus
    initial_route: str
    initial_verdict: str | None = None
    final_verdict: str = "UNKNOWN"
    disposition: DeepAnalysisDisposition = DeepAnalysisDisposition.MANUAL_REVIEW
    last_tier: AnalysisTier | None = None
    executed_tiers: tuple[AnalysisTier, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    tool_statuses: Mapping[str, str] = field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    requires_human_review: bool = False
    evidence_assessment: EvidenceAssessment | None = None

    @property
    def status(self) -> DeepAnalysisStatus:
        """Short alias for callers that use generic result status handling."""

        return self.deep_analysis_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "deep_analysis_status": self.deep_analysis_status.value,
            "initial_route": self.initial_route,
            "initial_verdict": self.initial_verdict,
            "final_verdict": self.final_verdict,
            "disposition": self.disposition.value,
            "last_tier": self.last_tier.value if self.last_tier else None,
            "executed_tiers": [tier.value for tier in self.executed_tiers],
            "tool_statuses": dict(self.tool_statuses),
            "reason_codes": list(self.reason_codes),
            "errors": list(self.errors),
            "requires_human_review": self.requires_human_review,
            "evidence": [item.to_dict() for item in self.evidence],
            "evidence_assessment": (
                self.evidence_assessment.to_dict()
                if self.evidence_assessment is not None
                else None
            ),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            allow_nan=False,
        )
