from __future__ import annotations

import json

import pytest

from trust_triage.deep_analysis.llm_interpreter import (
    MonoGPTClaudeInterpreter,
    MonoGPTConfig,
    _select_evidence,
    _serialize_evidence,
)
from trust_triage.deep_analysis.models import LLMInterpretationStatus
from trust_triage.evidence import AttackTechnique, Evidence, EvidenceStatus
from trust_triage.static_analysis.floss_analyzer import (
    FlossAnalysisResult,
    FlossStatus,
    FlossString,
)


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


def test_floss_limited_scope_survives_when_summary_is_not_selected() -> None:
    strings = [FlossString("static_strings", f"ordinary-{index:03d}") for index in range(64)]
    limited = FlossAnalysisResult(
        sha256="a" * 64, file_type="PE32", status=FlossStatus.SUCCESS,
        strings=strings, string_counts={"static_strings": 64},
        analysis_metadata={
            "limited_mode": True,
            "limited_reason": "INPUT_EXCEEDS_16_MIB",
            "skipped_string_types": [
                "stack_strings", "tight_strings", "decoded_strings", "language_strings"
            ],
        },
    )
    normal = FlossAnalysisResult(
        sha256="a" * 64, file_type="PE32", status=FlossStatus.SUCCESS,
        strings=strings, string_counts={"static_strings": 64},
    )

    selected = _select_evidence(
        limited.to_evidence(max_strings=64), max_items=40, max_chars=24000
    )
    payload = _serialize_evidence(selected)
    normal_payload = _serialize_evidence(_select_evidence(
        normal.to_evidence(max_strings=64), max_items=40, max_chars=24000
    ))

    assert len(selected) == 40
    assert all(item.category != "STRING_SUMMARY" for item in selected)
    assert all(row["context"]["limited_mode"] is True for row in payload)
    assert all(row["context"]["limited_reason"] == "INPUT_EXCEEDS_16_MIB" for row in payload)
    assert all(
        row["context"]["skipped_string_types"] == [
            "stack_strings", "tight_strings", "decoded_strings", "language_strings"
        ]
        for row in payload
    )
    assert payload != normal_payload

    mapped = _evidence(
        "capa-attack", source="CAPA", category="CAPABILITY_MATCH",
        attack=(AttackTechnique("T1055", "Process Injection"),),
    )
    mixed = _select_evidence(
        (mapped, *limited.to_evidence(max_strings=64)),
        max_items=10, max_chars=3000,
    )
    mixed_payload = _serialize_evidence(mixed)
    assert any(row["source"] == "CAPA" for row in mixed_payload)
    assert any(row["source"] == "FLOSS" for row in mixed_payload)
    assert all(
        row["context"]["limited_mode"] is True
        for row in mixed_payload if row["source"] == "FLOSS"
    )
    assert len(json.dumps(mixed_payload, ensure_ascii=False, separators=(",", ":"))) <= 3000


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


def test_first_oversized_evidence_is_omitted_from_small_budget() -> None:
    item = _evidence("large", summary="x" * 5000)

    selected = _select_evidence((item,), max_items=10, max_chars=100)

    assert selected == ()


def test_full_user_message_obeys_budget_and_records_omissions(monkeypatch) -> None:
    captured = {}

    def respond(_config, *, headers, payload):
        captured["content"] = payload["messages"][1]["content"]
        answer = {
            "verdict": "UNKNOWN",
            "confidence": 0.1,
            "supporting_evidence_ids": [],
            "contradicting_evidence_ids": [],
            "attack_techniques": [],
            "summary": "Insufficient evidence",
            "manual_review_required": True,
        }
        return ("response", 200, json.dumps({"choices": [{"message": {"content": json.dumps(answer)}}]}).encode())

    monkeypatch.setattr(
        "trust_triage.deep_analysis.llm_interpreter._bounded_http_post", respond
    )
    interpreter = MonoGPTClaudeInterpreter(
        MonoGPTConfig(
            api_key="fixture", base_url="http://127.0.0.1:1", model="fixture",
            max_input_chars=220,
        )
    )

    result = interpreter.interpret((_evidence("large", summary="x" * 5000),), sha256="a" * 64)

    assert result.status is LLMInterpretationStatus.SUCCESS
    assert len(captured["content"]) <= 220
    assert json.loads(captured["content"])["evidence"] == []
    assert json.loads(captured["content"])["evidence_omitted_count"] == 1


@pytest.mark.parametrize("missing", ["summary", "supporting_evidence_ids", "attack_techniques"])
def test_llm_response_requires_documented_fields(missing):
    interpreter = MonoGPTClaudeInterpreter(MonoGPTConfig())
    answer = {
        "verdict": "UNKNOWN", "confidence": 0.1,
        "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
        "attack_techniques": [], "summary": "Uncertain",
        "manual_review_required": True,
    }
    del answer[missing]

    with pytest.raises(ValueError, match="missing required"):
        interpreter._validated_result(answer, evidence=(), started=0.0)


def test_llm_cannot_return_benign_without_cited_evidence():
    interpreter = MonoGPTClaudeInterpreter(MonoGPTConfig())
    answer = {
        "verdict": "BENIGN", "confidence": 0.5,
        "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
        "attack_techniques": [], "summary": "Appears benign",
        "manual_review_required": False,
    }

    with pytest.raises(ValueError, match="requires supporting evidence"):
        interpreter._validated_result(answer, evidence=(), started=0.0)


def test_llm_config_has_safe_default_output_and_input_limits() -> None:
    config = MonoGPTConfig()

    assert config.max_tokens == 1600
    assert config.max_evidence_items == 40
    assert config.max_input_chars == 24000
    assert config.max_response_bytes == 1024 * 1024


def test_llm_response_limit_loads_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("MONOGPT_MAX_RESPONSE_BYTES", "2048")

    config = MonoGPTConfig.from_env(load_env_file=False)

    assert config.max_response_bytes == 2048


@pytest.mark.parametrize("value", ["invalid", "0", "127", str(8 * 1024 * 1024 + 1)])
def test_llm_response_limit_rejects_invalid_environment(monkeypatch, value) -> None:
    monkeypatch.setenv("MONOGPT_MAX_RESPONSE_BYTES", value)

    with pytest.raises(ValueError):
        MonoGPTConfig.from_env(load_env_file=False)
