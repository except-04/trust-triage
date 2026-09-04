"""Bounded CAPA + FLOSS -> Speakeasy -> Ghidra CAPA orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    AnalysisTier,
    DeepAnalysisDisposition,
    DeepAnalysisResult,
    DeepAnalysisStatus,
    EvidenceAssessment,
    EvidenceSufficiencyPolicy,
    LLMInterpretation,
    LLMInterpretationStatus,
)
from .normalizer import (
    normalize_capa_result,
    normalize_floss_result,
    normalize_speakeasy_result,
)


DEFAULT_DEEP_ROUTES = frozenset(
    {
        "HIGH_RISK_UNCERTAIN",
        "DEEP_ANALYSIS",
        "DEEP_STATIC",
        "CAPA_SCAN",
    }
)


@dataclass(frozen=True)
class DeepAnalysisConfig:
    """Policy and dependency configuration for the bounded pipeline."""

    deep_routes: frozenset[str] = field(default_factory=lambda: DEFAULT_DEEP_ROUTES)
    evidence_policy: EvidenceSufficiencyPolicy = field(
        default_factory=EvidenceSufficiencyPolicy
    )
    capa_reliability: float = 0.8
    floss_reliability: float = 0.55
    max_floss_evidence_strings: int = 64
    speakeasy_reliability: float = 0.75
    enable_ghidra_capa: bool = False

    def __post_init__(self) -> None:
        normalized_routes = frozenset(str(route).upper() for route in self.deep_routes)
        object.__setattr__(self, "deep_routes", normalized_routes)
        for field_name in (
            "capa_reliability",
            "floss_reliability",
            "speakeasy_reliability",
        ):
            value = getattr(self, field_name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be between 0 and 1")
        if self.max_floss_evidence_strings < 1:
            raise ValueError("max_floss_evidence_strings must be positive")

    def requires_deep_analysis(self, initial_route: str) -> bool:
        return str(initial_route).upper() in self.deep_routes


class DeepAnalysisOrchestrator:
    """Run each Tier at most once and preserve every decision reason.

    ``floss_analyzer``, ``speakeasy_analyzer`` and ``ghidra_capa_analyzer`` are intentionally
    dependency-injected. The dynamic-analysis branch can pass its
    ``SpeakeasyAnalyzer`` instance here, while the static-analysis branch can
    pass its ``FlossAnalyzer`` and a ``CapaAnalyzer`` configured with the Ghidra backend. The optional
    ``llm_interpreter`` receives only normalized Evidence after a successful
    terminal Tier. None of those implementations are copied into this module.
    """

    def __init__(
        self,
        *,
        capa_analyzer: Any | None = None,
        floss_analyzer: Any | None = None,
        speakeasy_analyzer: Any | None = None,
        ghidra_capa_analyzer: Any | None = None,
        llm_interpreter: Any | None = None,
        config: DeepAnalysisConfig | None = None,
    ) -> None:
        # CAPA is owned by feature/static-analysis and is injected at the
        # integration boundary.  Deep analysis must not copy that module.
        self.capa_analyzer = capa_analyzer
        self.floss_analyzer = floss_analyzer
        self.speakeasy_analyzer = speakeasy_analyzer
        self.ghidra_capa_analyzer = ghidra_capa_analyzer
        self.llm_interpreter = llm_interpreter
        self.config = config or DeepAnalysisConfig()

    def run(
        self,
        sample_path: str | Path,
        *,
        initial_route: str,
        initial_verdict: str | None = None,
        sha256: str | None = None,
    ) -> DeepAnalysisResult:
        """Run the bounded flow for one PE and return a serializable result."""

        path = Path(sample_path)
        route = str(initial_route).upper()
        verdict = _normalize_verdict(initial_verdict)
        sample_sha256 = sha256 or _safe_sha256(path)

        if not self.config.requires_deep_analysis(route):
            return DeepAnalysisResult(
                sha256=sample_sha256,
                deep_analysis_status=DeepAnalysisStatus.NOT_REQUIRED,
                initial_route=route,
                initial_verdict=verdict,
                final_verdict=verdict or "UNKNOWN",
                disposition=_disposition_for_verdict(verdict),
                reason_codes=("DEEP_ANALYSIS_NOT_REQUIRED",),
                requires_human_review=verdict not in {None, "BENIGN"},
            )

        if not path.is_file():
            return self._failed(
                sha256=sample_sha256,
                initial_route=route,
                initial_verdict=verdict,
                errors=(f"analysis target does not exist: {path}",),
                reason_codes=("INVALID_ANALYSIS_TARGET",),
            )

        evidence = []
        executed_tiers: list[AnalysisTier] = []
        tool_statuses: dict[str, str] = {}
        reason_codes = ["DEEP_ANALYSIS_REQUIRED"]
        errors: list[str] = []
        assessment: EvidenceAssessment | None = None

        # Tier 1: CAPA.  A failure is retained and the next Tier is attempted
        # when possible; the failure itself is never converted into evidence.
        executed_tiers.append(AnalysisTier.CAPA)
        capa_result: Any | None = None
        if self.capa_analyzer is None:
            capa_status = "UNAVAILABLE"
            errors.append("CAPA analyzer is not configured")
        else:
            try:
                capa_result = self.capa_analyzer.analyze(path)
                capa_status = _status_value(capa_result) or "UNKNOWN"
                evidence.extend(
                    normalize_capa_result(
                        capa_result,
                        reliability=self.config.capa_reliability,
                    )
                )
                errors.extend(_result_errors(capa_result))
            except Exception as exc:  # Boundary: preserve tool failure for review.
                capa_status = "TOOL_ERROR"
                errors.append(f"CAPA analyzer raised {type(exc).__name__}: {exc}")
        tool_statuses[AnalysisTier.CAPA.value] = capa_status

        # FLOSS is the second half of the initial static-analysis phase. It is
        # independent from CAPA, so a failure in one tool never discards the
        # observations from the other tool. FLOSS strings remain supporting
        # Evidence and do not by themselves satisfy the ATT&CK gate.
        floss_result: Any | None = None
        floss_status = "NOT_CONFIGURED"
        if self.floss_analyzer is None:
            tool_statuses[AnalysisTier.FLOSS.value] = floss_status
            reason_codes.append("FLOSS_NOT_CONFIGURED")
        else:
            executed_tiers.append(AnalysisTier.FLOSS)
            try:
                floss_result = self.floss_analyzer.analyze(path)
                floss_status = _status_value(floss_result) or "UNKNOWN"
                evidence.extend(
                    normalize_floss_result(
                        floss_result,
                        reliability=self.config.floss_reliability,
                        max_strings=self.config.max_floss_evidence_strings,
                    )
                )
                errors.extend(_result_errors(floss_result))
            except Exception as exc:  # Boundary: preserve tool failure for review.
                floss_status = "TOOL_ERROR"
                errors.append(f"FLOSS analyzer raised {type(exc).__name__}: {exc}")
            tool_statuses[AnalysisTier.FLOSS.value] = floss_status
            if floss_status != "SUCCESS":
                reason_codes.append(f"FLOSS_{floss_status}")

        static_last_tier = (
            AnalysisTier.FLOSS
            if floss_status == "SUCCESS"
            else AnalysisTier.CAPA
        )
        assessment = self.config.evidence_policy.assess(evidence)
        if assessment.sufficient:
            reason_codes.extend(assessment.reason_codes)
            return self._complete(
                sha256=sample_sha256 or _result_sha256(capa_result),
                initial_route=route,
                initial_verdict=verdict,
                last_tier=static_last_tier,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=reason_codes,
                errors=errors,
                assessment=assessment,
            )

        if capa_status != "SUCCESS":
            reason_codes.append(f"CAPA_{capa_status}")
        reason_codes.extend(assessment.reason_codes)
        reason_codes.append("ADVANCE_TO_SPEAKEASY")

        # Tier 2 is supplied by the dynamic-analysis branch.  This branch
        # only defines the contract and orchestration boundary.
        if self.speakeasy_analyzer is None:
            errors.append("Speakeasy analyzer is not configured")
            return self._failed(
                sha256=sample_sha256 or _result_sha256(capa_result),
                initial_route=route,
                initial_verdict=verdict,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=tuple(reason_codes),
                errors=tuple(errors),
                assessment=assessment,
            )

        executed_tiers.append(AnalysisTier.SPEAKEASY)
        speakeasy_result: Any | None = None
        try:
            speakeasy_result = self.speakeasy_analyzer.analyze(path)
            speakeasy_status = _status_value(speakeasy_result) or "UNKNOWN"
            evidence.extend(
                normalize_speakeasy_result(
                    speakeasy_result,
                    sha256=sample_sha256 or _result_sha256(capa_result),
                    reliability=self.config.speakeasy_reliability,
                )
            )
            errors.extend(_result_errors(speakeasy_result))
        except Exception as exc:  # Boundary: preserve tool failure for review.
            speakeasy_status = "TOOL_ERROR"
            errors.append(
                f"Speakeasy analyzer raised {type(exc).__name__}: {exc}"
            )
        tool_statuses[AnalysisTier.SPEAKEASY.value] = speakeasy_status

        assessment = self.config.evidence_policy.assess(evidence)
        reason_codes.extend(assessment.reason_codes)
        result_sha256 = (
            sample_sha256
            or _result_sha256(speakeasy_result)
            or _result_sha256(capa_result)
        )
        if speakeasy_status != "SUCCESS":
            reason_codes.append(f"SPEAKEASY_{speakeasy_status}")

        if speakeasy_status == "SUCCESS" and assessment.sufficient:
            # Tier 2 produced enough evidence; do not pay for Tier 3.
            return self._complete(
                sha256=result_sha256,
                initial_route=route,
                initial_verdict=verdict,
                last_tier=AnalysisTier.SPEAKEASY,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=reason_codes,
                errors=errors,
                assessment=assessment,
            )

        # Tier 3: Ghidra-backed CAPA is intentionally disabled by default.
        # Keep the injection point for a future environment, but do not run
        # it when the team has not enabled the optional backend.
        if not self.config.enable_ghidra_capa:
            tool_statuses[AnalysisTier.GHIDRA_CAPA.value] = "DISABLED"
            reason_codes.append("GHIDRA_CAPA_DISABLED")
            if speakeasy_status != "SUCCESS":
                return self._failed(
                    sha256=result_sha256,
                    initial_route=route,
                    initial_verdict=verdict,
                    executed_tiers=executed_tiers,
                    evidence=evidence,
                    tool_statuses=tool_statuses,
                    reason_codes=tuple(reason_codes),
                    errors=tuple(errors),
                    assessment=assessment,
                )
            return self._complete(
                sha256=result_sha256,
                initial_route=route,
                initial_verdict=verdict,
                last_tier=AnalysisTier.SPEAKEASY,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=reason_codes,
                errors=errors,
                assessment=assessment,
            )

        # Optional Tier 3: Ghidra-backed CAPA. It is injected from
        # feature/static-analysis as the same CapaAnalyzer configured with
        # CapaBackend.GHIDRA; no CAPA implementation is duplicated here.
        reason_codes.append("ADVANCE_TO_GHIDRA_CAPA")
        if self.ghidra_capa_analyzer is None:
            tool_statuses[AnalysisTier.GHIDRA_CAPA.value] = "NOT_CONFIGURED"
            errors.append("Ghidra CAPA analyzer is not configured")
            reason_codes.append("GHIDRA_CAPA_NOT_CONFIGURED")
            return self._failed(
                sha256=result_sha256,
                initial_route=route,
                initial_verdict=verdict,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=tuple(reason_codes),
                errors=tuple(errors),
                assessment=assessment,
            )

        executed_tiers.append(AnalysisTier.GHIDRA_CAPA)
        ghidra_result: Any | None = None
        try:
            ghidra_result = self.ghidra_capa_analyzer.analyze(path)
            ghidra_status = _status_value(ghidra_result) or "UNKNOWN"
            evidence.extend(
                normalize_capa_result(
                    ghidra_result,
                    reliability=self.config.capa_reliability,
                )
            )
            errors.extend(_result_errors(ghidra_result))
        except Exception as exc:  # Boundary: preserve tool failure for review.
            ghidra_status = "TOOL_ERROR"
            errors.append(f"Ghidra CAPA analyzer raised {type(exc).__name__}: {exc}")
        tool_statuses[AnalysisTier.GHIDRA_CAPA.value] = ghidra_status

        assessment = self.config.evidence_policy.assess(evidence)
        reason_codes.extend(assessment.reason_codes)
        result_sha256 = result_sha256 or _result_sha256(ghidra_result)
        if ghidra_status != "SUCCESS":
            reason_codes.append(f"GHIDRA_CAPA_{ghidra_status}")
            return self._failed(
                sha256=result_sha256,
                initial_route=route,
                initial_verdict=verdict,
                executed_tiers=executed_tiers,
                evidence=evidence,
                tool_statuses=tool_statuses,
                reason_codes=tuple(reason_codes),
                errors=tuple(errors),
                assessment=assessment,
            )

        # Ghidra is the final configured Tier.  A successful run with weak or
        # conflicting evidence is complete from the tool perspective, but it
        # must remain UNKNOWN and be sent to analyst review.
        return self._complete(
            sha256=result_sha256,
            initial_route=route,
            initial_verdict=verdict,
            last_tier=AnalysisTier.GHIDRA_CAPA,
            executed_tiers=executed_tiers,
            evidence=evidence,
            tool_statuses=tool_statuses,
            reason_codes=reason_codes,
            errors=errors,
            assessment=assessment,
        )

    def _complete(
        self,
        *,
        sha256: str,
        initial_route: str,
        initial_verdict: str | None,
        last_tier: AnalysisTier,
        executed_tiers: list[AnalysisTier],
        evidence: list[Any],
        tool_statuses: Mapping[str, str],
        reason_codes: list[str],
        errors: list[str],
        assessment: EvidenceAssessment,
    ) -> DeepAnalysisResult:
        # LLM output is an evidence-grounded interpretation for analysts. It
        # is the verdict source after analysis. EvidenceSufficiencyPolicy only
        # decides whether another analysis Tier is needed; its routing score is
        # not a malware probability and must never become MALICIOUS by itself.
        llm_interpretation: LLMInterpretation | None = None
        result_tool_statuses = dict(tool_statuses)
        result_reason_codes = list(reason_codes)
        result_errors = list(errors)
        if self.llm_interpreter is not None:
            try:
                llm_interpretation = self.llm_interpreter.interpret(
                    tuple(evidence),
                    sha256=sha256,
                    initial_verdict=initial_verdict,
                )
            except Exception as exc:  # Boundary: keep LLM failure advisory only.
                llm_interpretation = LLMInterpretation(
                    status=LLMInterpretationStatus.API_ERROR,
                    model="",
                    error=f"LLM interpreter raised {type(exc).__name__}",
                )

            llm_status = _llm_status_value(llm_interpretation)
            result_tool_statuses["LLM_INTERPRETER"] = llm_status
            result_reason_codes.append(f"LLM_{llm_status}")
            if llm_interpretation.error:
                result_errors.append(llm_interpretation.error)

        if (
            llm_interpretation is not None
            and _llm_status_value(llm_interpretation) == "SUCCESS"
        ):
            final_verdict = _normalize_verdict(llm_interpretation.verdict) or "UNKNOWN"
            result_reason_codes.append("FINAL_VERDICT_FROM_LLM")
        else:
            final_verdict = "UNKNOWN"
            result_reason_codes.append("FINAL_VERDICT_UNKNOWN_WITHOUT_LLM")

        requires_human_review = final_verdict in {"MALICIOUS", "UNKNOWN"}
        if llm_interpretation is not None:
            requires_human_review = (
                requires_human_review or llm_interpretation.manual_review_required
            )
        return DeepAnalysisResult(
            sha256=sha256,
            deep_analysis_status=DeepAnalysisStatus.COMPLETE,
            initial_route=initial_route,
            initial_verdict=initial_verdict,
            final_verdict=final_verdict,
            disposition=(
                DeepAnalysisDisposition.MANUAL_REVIEW
                if final_verdict == "UNKNOWN"
                else _disposition_for_verdict(final_verdict)
            ),
            last_tier=last_tier,
            executed_tiers=tuple(executed_tiers),
            evidence=tuple(evidence),
            tool_statuses=result_tool_statuses,
            reason_codes=tuple(dict.fromkeys(result_reason_codes)),
            errors=tuple(result_errors),
            requires_human_review=requires_human_review,
            evidence_assessment=assessment,
            llm_interpretation=llm_interpretation,
        )

    def _failed(
        self,
        *,
        sha256: str,
        initial_route: str,
        initial_verdict: str | None,
        executed_tiers: list[AnalysisTier] | None = None,
        evidence: list[Any] | None = None,
        tool_statuses: Mapping[str, str] | None = None,
        reason_codes: tuple[str, ...] = (),
        errors: tuple[str, ...] = (),
        assessment: EvidenceAssessment | None = None,
    ) -> DeepAnalysisResult:
        return DeepAnalysisResult(
            sha256=sha256,
            deep_analysis_status=DeepAnalysisStatus.FAILED,
            initial_route=initial_route,
            initial_verdict=initial_verdict,
            final_verdict="UNKNOWN",
            disposition=DeepAnalysisDisposition.ANALYSIS_FAILED,
            last_tier=(executed_tiers[-1] if executed_tiers else None),
            executed_tiers=tuple(executed_tiers or ()),
            evidence=tuple(evidence or ()),
            tool_statuses=dict(tool_statuses or {}),
            reason_codes=tuple(dict.fromkeys(reason_codes)),
            errors=tuple(errors),
            requires_human_review=True,
            evidence_assessment=assessment,
        )


def _safe_sha256(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _status_value(value: Any) -> str:
    if isinstance(value, Mapping):
        status = value.get("status")
    else:
        status = getattr(value, "status", None)
    if hasattr(status, "value"):
        status = status.value
    return str(status or "").upper()


def _result_sha256(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return str(value.get("sha256") or "")
    return str(getattr(value, "sha256", "") or "")


def _result_errors(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        errors = value.get("errors")
    else:
        errors = getattr(value, "errors", ())
    if errors is None:
        return ()
    if isinstance(errors, str):
        return (errors,)
    return tuple(str(error) for error in errors)


def _llm_status_value(value: Any) -> str:
    status = getattr(value, "status", None)
    if hasattr(status, "value"):
        status = status.value
    return str(status or "UNKNOWN").upper()


def _normalize_verdict(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).upper()
    return normalized or None


def _disposition_for_verdict(value: str | None) -> DeepAnalysisDisposition:
    if value == "BENIGN":
        return DeepAnalysisDisposition.AUTO_ALLOW_RECOMMENDED
    if value == "MALICIOUS":
        return DeepAnalysisDisposition.ALERT_RECOMMENDED
    return DeepAnalysisDisposition.REPORT_ONLY
