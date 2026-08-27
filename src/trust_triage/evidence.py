"""Shared Evidence contracts used by static and deep analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceStatus(str, Enum):
    """Observation state for an evidence item."""

    OBSERVED = "OBSERVED"
    CANDIDATE = "CANDIDATE"


@dataclass(frozen=True)
class AttackTechnique:
    """Canonical MITRE ATT&CK reference attached to Evidence."""

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
    """Tool-neutral Evidence item shared across analysis stages."""

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
