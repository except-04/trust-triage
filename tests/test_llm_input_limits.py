from __future__ import annotations

import json

from trust_triage.deep_analysis.llm_interpreter import (
    MonoGPTConfig,
    _select_evidence,
    _serialize_evidence,
)
from trust_triage.evidence import AttackTechnique, Evidence, EvidenceStatus


def _evidence(
    evidence_id: str,
    *,
    source: str = "FLOSS",
    category: str = "STRING_OBSERVED",
    summary: str = "ordinary string",
    details: dict | None = None,
    attack: tuple[AttackTechnique, ...] = (),
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        sha256="a" * 64,
        source=source,
        category=category,
        severity=0.2,
        reliability=0.55,
        summary=summary,
        status=EvidenceStatus.OBSERVED,
        details=details or {},
        attack_techniques=attack,
    )


def test_llm_selection_is_bounded_and_keeps_high_value_evidence() -> None:
    mapped = _evidence(
        "capa-attack",
        source="CAPA",
        category="CAPABILITY_MATCH",
        summary="Process Injection capability",
        attack=(
            AttackTechnique(
                technique_id="T1055",
                technique_name="Process Injection",
            ),
        ),
    )
    decoded = _evidence(
        "floss-decoded",
        category="OBFUSCATED_STRING",
        summary="decoded command string",
        details={
            "string": "powershell.exe -enc hidden-command",
            "string_type": "decoded_strings",
        },
    )
    ordinary = tuple(
        _evidence(f"floss-static-{index}", details={"string": "common"})
        for index in range(100)
    )

    selected = _select_evidence(
        (ordinary[0], *ordinary[1:], mapped, decoded),
        max_items=10,
        max_chars=24000,
    )
    payload = _serialize_evidence(selected)

    assert len(selected) <= 10
    assert {item.evidence_id for item in selected} >= {
        "capa-attack",
        "floss-decoded",
    }
    assert len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"))) <= 24000


def test_llm_serialization_bounds_long_text_and_context() -> None:
    item = _evidence(
        "long-floss",
        summary="x" * 5000,
        details={
            "string": "y" * 5000,
            "string_type": "static_strings",
            "tags": ["tag"] * 100,
        },
    )

    payload = _serialize_evidence((item,))[0]

    assert len(payload["summary"]) == 600
    assert len(payload["context"]["string"]) == 400
    assert len(payload["context"]["tags"]) == 8


def test_llm_config_has_safe_default_output_and_input_limits() -> None:
    config = MonoGPTConfig()

    assert config.max_tokens == 1600
    assert config.max_evidence_items == 40
    assert config.max_input_chars == 24000
