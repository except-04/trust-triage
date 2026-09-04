"""Opt-in integration test for the real MonoGPT Claude API."""

from __future__ import annotations

import pytest

from trust_triage.deep_analysis import (
    AttackTechnique,
    Evidence,
    EvidenceStatus,
    LLMInterpretationStatus,
    MonoGPTClaudeInterpreter,
    MonoGPTConfig,
)


def test_monogpt_claude_real_api() -> None:
    """Call MonoGPT only when all local environment values are configured."""

    config = MonoGPTConfig.from_env()
    if not config.is_configured:
        pytest.skip(
            "set LLM_ENABLED=true, MONOGPT_API_KEY, MONOGPT_BASE_URL, "
            "and MONOGPT_MODEL to run the real API test"
        )

    evidence = (
        Evidence(
            evidence_id="integration-capa-001",
            sha256="0" * 64,
            source="CAPA",
            category="CAPABILITY_MATCH",
            severity=0.8,
            reliability=0.9,
            summary="Process Injection capability was observed by CAPA.",
            status=EvidenceStatus.OBSERVED,
            attack_techniques=(
                AttackTechnique(
                    technique_id="T1055",
                    technique_name="Process Injection",
                    tactics=("Defense Evasion",),
                ),
            ),
        ),
    )

    result = MonoGPTClaudeInterpreter(config).interpret(
        evidence,
        sha256="0" * 64,
        initial_verdict="UNKNOWN",
    )

    assert result.status is LLMInterpretationStatus.SUCCESS
    assert result.verdict in {"BENIGN", "MALICIOUS", "UNKNOWN"}
    assert 0.0 <= result.confidence <= 1.0
    assert result.summary
    assert set(result.supporting_evidence_ids).issubset(
        {item.evidence_id for item in evidence}
    )
    assert set(result.contradicting_evidence_ids).issubset(
        {item.evidence_id for item in evidence}
    )
    assert set(result.attack_techniques).issubset({"T1055"})
