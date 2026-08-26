"""Selective static-analysis integrations for TRUST-TRIAGE."""

from .capa_analyzer import (
    DEFAULT_TIMEOUT_SECONDS,
    CapaAnalyzer,
    CapaConfig,
    ParsedCapaReport,
    parse_capa_report,
    sha256_file,
)
from .attack_mapping import (
    normalize_attack_label,
    normalize_attack_labels,
    technique_display_name,
)
from .models import (
    CapaAnalysisResult,
    CapaBackend,
    CapaCapability,
    CapaStatus,
    AttackTechnique,
    Evidence,
    EvidenceStatus,
)

__all__ = [
    "CapaAnalyzer",
    "CapaAnalysisResult",
    "AttackTechnique",
    "CapaBackend",
    "CapaCapability",
    "CapaConfig",
    "CapaStatus",
    "DEFAULT_TIMEOUT_SECONDS",
    "Evidence",
    "EvidenceStatus",
    "normalize_attack_label",
    "normalize_attack_labels",
    "ParsedCapaReport",
    "parse_capa_report",
    "sha256_file",
    "technique_display_name",
]
