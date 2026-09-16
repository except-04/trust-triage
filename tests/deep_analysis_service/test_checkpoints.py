"""Persisted static evidence and staged orchestration use no live analysis tools."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from trust_triage.deep_analysis.checkpoints import (
    StaticAnalysisCheckpoint,
    tool_snapshot,
)
from trust_triage.deep_analysis.models import (
    AnalysisTier,
    DeepAnalysisStatus,
    EvidenceSufficiencyPolicy,
    LLMInterpretation,
    LLMInterpretationStatus,
)
from trust_triage.deep_analysis.orchestrator import (
    DeepAnalysisConfig,
    DeepAnalysisOrchestrator,
)
from trust_triage.evidence import AttackTechnique, Evidence, EvidenceStatus


class _StaticResult:
    status = "SUCCESS"
    errors = ()

    def __init__(self, sha256, source, evidence):
        self.sha256 = sha256
        self.source = source
        self.evidence = evidence

    def to_evidence(self, *, reliability, max_strings=None):
        del max_strings
        return tuple(replace(item, reliability=reliability) for item in self.evidence)

    def to_dict(self):
        return {
            "sha256": self.sha256,
            "source": self.source,
            "status": self.status,
            "summary": "harmless fake static result",
            "tool_version": "fixture-v1",
            "raw_report": {"excluded": True},
            "command": ["excluded-command"],
        }


class _Analyzer:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def analyze(self, path):
        del path
        self.calls += 1
        return self.result


class _ForbiddenAnalyzer:
    def __init__(self):
        self.calls = 0

    def analyze(self, path):
        del path
        self.calls += 1
        pytest.fail("staged orchestration called an analyzer it must not run")


class _Interpreter:
    def __init__(self):
        self.calls = 0
        self.evidence = ()

    def interpret(self, evidence, *, sha256, initial_verdict):
        self.calls += 1
        self.evidence = tuple(evidence)
        assert all(item.sha256 == sha256 for item in evidence)
        assert initial_verdict == "UNKNOWN"
        return LLMInterpretation(
            status=LLMInterpretationStatus.SUCCESS,
            verdict="UNKNOWN",
            confidence=0.5,
            manual_review_required=True,
            supporting_evidence_ids=tuple(item.evidence_id for item in evidence),
            summary="Fake evidence interpretation for a unit test.",
            model="fixture-model",
        )


def _rig(tmp_path, *, mapped=True):
    sample = tmp_path / "harmless-static-input.txt"
    data = b"Unit test text. This is not an executable."
    sample.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    technique = AttackTechnique(
        technique_id="T1055",
        technique_name="Process Injection",
        tactics=("defense-evasion",),
        source_label="Process Injection",
    )
    capa_evidence = Evidence(
        evidence_id="capa-fixture-1",
        sha256=sha256,
        source="CAPA",
        category="CAPABILITY_MATCH",
        severity=0.8,
        reliability=0.8,
        summary="Fake capability observation",
        status=EvidenceStatus.CANDIDATE,
        details={
            "rule_name": "fixture",
            "attack": ["Process Injection"] if mapped else [],
        },
        attack_techniques=(technique,) if mapped else (),
    )
    floss_evidence = Evidence(
        evidence_id="floss-fixture-1",
        sha256=sha256,
        source="FLOSS",
        category="STRING_SUMMARY",
        severity=0.2,
        reliability=0.55,
        summary="테스트용 문자열",
        details={"string_counts": {"decoded_strings": 1}},
    )
    capa = _Analyzer(_StaticResult(sha256, "CAPA", (capa_evidence,)))
    floss = _Analyzer(_StaticResult(sha256, "FLOSS", (floss_evidence,)))
    speakeasy, ghidra, llm = _ForbiddenAnalyzer(), _ForbiddenAnalyzer(), _Interpreter()
    orchestrator = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        floss_analyzer=floss,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
        llm_interpreter=llm,
    )
    checkpoint = orchestrator.prepare(
        sample, initial_route="deep_analysis", initial_verdict="unknown", sha256=sha256
    )
    assert isinstance(checkpoint, StaticAnalysisCheckpoint)
    return SimpleNamespace(
        sample=sample,
        sha256=sha256,
        capa=capa,
        floss=floss,
        speakeasy=speakeasy,
        ghidra=ghidra,
        llm=llm,
        orchestrator=orchestrator,
        checkpoint=checkpoint,
    )


def _identity(rig):
    return {
        "sha256": rig.sha256,
        "initial_route": "DEEP_ANALYSIS",
        "initial_verdict": "UNKNOWN",
        "config_fingerprint": rig.orchestrator.config.fingerprint(),
    }


def test_checkpoint_json_roundtrip_restores_evidence_and_attack_objects(tmp_path):
    rig = _rig(tmp_path)
    payload = json.loads(json.dumps(rig.checkpoint.to_dict(), ensure_ascii=False))
    restored = StaticAnalysisCheckpoint.from_dict(payload)
    assert restored == rig.checkpoint
    restored.validate_identity(**_identity(rig))
    assert isinstance(restored.evidence[0], Evidence)
    assert restored.evidence[0].status is EvidenceStatus.CANDIDATE
    assert isinstance(restored.evidence[0].attack_techniques[0], AttackTechnique)
    assert restored.evidence[0].attack_techniques[0].technique_id == "T1055"
    assert restored.evidence[1].summary == "테스트용 문자열"
    assert (
        rig.orchestrator.config.evidence_policy.assess(restored.evidence)
        == restored.assessment
    )
    assert "raw_report" not in restored.tool_results["CAPA"]
    assert "command" not in restored.tool_results["CAPA"]
    payload["evidence"][0]["details"]["rule_name"] = "changed after restore"
    assert restored.evidence[0].details["rule_name"] == "fixture"


@pytest.mark.parametrize("mapped", [True, False])
def test_prepare_saves_static_phase_without_calling_later_tools_or_llm(
    tmp_path, mapped
):
    rig = _rig(tmp_path, mapped=mapped)
    assert rig.capa.calls == rig.floss.calls == 1
    assert rig.speakeasy.calls == rig.ghidra.calls == rig.llm.calls == 0
    assert rig.checkpoint.needs_speakeasy is not mapped
    assert rig.checkpoint.assessment.sufficient is mapped
    assert rig.checkpoint.executed_tiers == (AnalysisTier.CAPA, AnalysisTier.FLOSS)
    assert set(rig.checkpoint.tool_statuses) == {"CAPA", "FLOSS"}
    assert {item.source for item in rig.checkpoint.evidence} == {"CAPA", "FLOSS"}


def test_finalize_static_uses_restored_evidence_and_calls_llm_once_per_invocation(
    tmp_path,
):
    rig = _rig(tmp_path)
    restored = StaticAnalysisCheckpoint.from_dict(rig.checkpoint.to_dict())
    rig.sample.unlink()
    result = rig.orchestrator.finalize_static(restored)
    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.last_tier is AnalysisTier.FLOSS
    assert rig.llm.calls == 1
    assert rig.llm.evidence == restored.evidence
    assert rig.capa.calls == rig.floss.calls == 1
    assert rig.speakeasy.calls == rig.ghidra.calls == 0
    # The service repository owns idempotency; a direct second core call is explicit work.
    rig.orchestrator.finalize_static(restored)
    assert rig.llm.calls == 2
    assert rig.capa.calls == rig.floss.calls == 1


def test_finalize_static_refuses_checkpoint_that_requires_worker(tmp_path):
    rig = _rig(tmp_path, mapped=False)
    with pytest.raises(ValueError, match="requires a Speakeasy"):
        rig.orchestrator.finalize_static(rig.checkpoint)
    assert rig.llm.calls == 0


def test_resume_without_sample_never_reexecutes_capa_floss_or_speakeasy(tmp_path):
    rig = _rig(tmp_path, mapped=False)
    restored = StaticAnalysisCheckpoint.from_dict(rig.checkpoint.to_dict())
    rig.sample.unlink()
    never = _ForbiddenAnalyzer()
    resumed = DeepAnalysisOrchestrator(
        capa_analyzer=never,
        floss_analyzer=never,
        speakeasy_analyzer=never,
        ghidra_capa_analyzer=never,
        llm_interpreter=rig.llm,
    )
    result = resumed.resume_speakeasy(
        restored,
        {
            "status": "SUCCESS",
            "sha256": rig.sha256,
            "evidence_id": "speakeasy-fixture",
            "observed_apis": ["kernel32.CreateRemoteThread"],
            "behaviors": [],
            "events": {},
        },
    )
    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.executed_tiers == (
        AnalysisTier.CAPA,
        AnalysisTier.FLOSS,
        AnalysisTier.SPEAKEASY,
    )
    assert result.last_tier is AnalysisTier.SPEAKEASY
    assert never.calls == 0
    assert rig.capa.calls == rig.floss.calls == rig.llm.calls == 1
    assert {item.source for item in rig.llm.evidence} == {"CAPA", "FLOSS", "SPEAKEASY"}
    assert len({item.evidence_id for item in result.evidence}) == len(result.evidence)
    assert rig.checkpoint.executed_tiers == (AnalysisTier.CAPA, AnalysisTier.FLOSS)


def test_failed_worker_resume_preserves_static_evidence_without_llm_or_malicious_verdict(
    tmp_path,
):
    rig = _rig(tmp_path, mapped=False)
    result = rig.orchestrator.resume_speakeasy(
        rig.checkpoint,
        {
            "status": "TIMEOUT",
            "sha256": rig.sha256,
            "errors": ["engine limit reached"],
            "observed_apis": ["kernel32.CreateRemoteThread"],
            "behaviors": ["Process Injection"],
        },
    )
    assert result.deep_analysis_status is DeepAnalysisStatus.FAILED
    assert result.evidence == rig.checkpoint.evidence
    assert result.final_verdict == "UNKNOWN"
    assert result.requires_human_review
    assert "engine limit reached" in result.errors
    assert rig.llm.calls == rig.speakeasy.calls == rig.ghidra.calls == 0


def test_resume_refuses_static_only_checkpoint(tmp_path):
    rig = _rig(tmp_path)
    with pytest.raises(ValueError, match="does not request"):
        rig.orchestrator.resume_speakeasy(rig.checkpoint, {"status": "SUCCESS"})
    assert rig.llm.calls == 0


@pytest.mark.parametrize(
    "changed",
    [
        {"speakeasy_reliability": 0.5},
        {"capa_reliability": 0.7},
        {"max_floss_evidence_strings": 8},
        {"enable_ghidra_capa": True},
        {"deep_routes": frozenset({"DEEP_ANALYSIS"})},
        {"evidence_policy": EvidenceSufficiencyPolicy(minimum_weighted_score=0.8)},
    ],
)
def test_resume_and_static_finalization_reject_policy_changes(tmp_path, changed):
    rig = _rig(tmp_path)
    updated = DeepAnalysisOrchestrator(
        config=replace(rig.orchestrator.config, **changed), llm_interpreter=rig.llm
    )
    with pytest.raises(ValueError, match="configuration changed"):
        updated.finalize_static(rig.checkpoint)
    with pytest.raises(ValueError, match="configuration changed"):
        updated.resume_speakeasy(rig.checkpoint, {"status": "SUCCESS"})
    assert rig.llm.calls == 0


def test_config_fingerprint_is_stable_across_route_set_order():
    assert DeepAnalysisConfig(
        deep_routes=frozenset(["CAPA_SCAN", "DEEP_STATIC"])
    ).fingerprint() == (
        DeepAnalysisConfig(
            deep_routes=frozenset(["DEEP_STATIC", "CAPA_SCAN"])
        ).fingerprint()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "b" * 64),
        ("initial_route", "DEEP_STATIC"),
        ("initial_verdict", "BENIGN"),
        ("config_fingerprint", "changed"),
    ],
)
def test_checkpoint_rejects_request_identity_mismatch(tmp_path, field, value):
    rig = _rig(tmp_path)
    with pytest.raises(ValueError, match="identity or configuration"):
        rig.checkpoint.validate_identity(**{**_identity(rig), field: value})


def test_checkpoint_rejects_duplicate_evidence_or_evidence_for_another_file(tmp_path):
    rig = _rig(tmp_path)
    first = rig.checkpoint.evidence[0]
    for evidence in (
        (first, first),
        (replace(first, sha256="b" * 64),),
        (replace(first, evidence_id=""),),
    ):
        with pytest.raises(ValueError, match="conflicting SHA-256 or duplicate ID"):
            replace(rig.checkpoint, evidence=evidence).validate_identity(
                **_identity(rig)
            )


@pytest.mark.parametrize("tier", [AnalysisTier.SPEAKEASY, AnalysisTier.GHIDRA_CAPA])
def test_static_checkpoint_rejects_later_executed_tiers(tmp_path, tier):
    rig = _rig(tmp_path)
    with pytest.raises(ValueError, match="later analysis tier"):
        replace(
            rig.checkpoint, executed_tiers=(*rig.checkpoint.executed_tiers, tier)
        ).validate_identity(**_identity(rig))


@pytest.mark.parametrize("tier", [AnalysisTier.SPEAKEASY, AnalysisTier.GHIDRA_CAPA])
def test_static_checkpoint_rejects_later_last_tier(tmp_path, tier):
    rig = _rig(tmp_path)
    with pytest.raises(ValueError):
        replace(rig.checkpoint, last_tier=tier).validate_identity(**_identity(rig))


def test_static_checkpoint_rejects_duplicate_tiers_and_an_unexecuted_last_tier(
    tmp_path,
):
    rig = _rig(tmp_path)
    for checkpoint in (
        replace(
            rig.checkpoint,
            executed_tiers=(AnalysisTier.CAPA, AnalysisTier.FLOSS, AnalysisTier.FLOSS),
        ),
        replace(
            rig.checkpoint,
            executed_tiers=(AnalysisTier.CAPA,),
            last_tier=AnalysisTier.FLOSS,
        ),
    ):
        with pytest.raises(ValueError):
            checkpoint.validate_identity(**_identity(rig))


def test_static_checkpoint_rejects_another_tool_or_conflicting_tool_hash(tmp_path):
    rig = _rig(tmp_path)
    wrong_source = replace(rig.checkpoint.evidence[0], source="SPEAKEASY")
    with pytest.raises(ValueError, match="another tool"):
        replace(rig.checkpoint, evidence=(wrong_source,)).validate_identity(
            **_identity(rig)
        )
    for tool_results in (
        {"SPEAKEASY": {"sha256": rig.sha256, "status": "SUCCESS"}},
        {"CAPA": {"sha256": "b" * 64, "status": "SUCCESS"}},
        {"CAPA": {"status": "SUCCESS"}},
    ):
        with pytest.raises(ValueError):
            replace(rig.checkpoint, tool_results=tool_results).validate_identity(
                **_identity(rig)
            )


def test_checkpoint_rejects_contradictory_routing_and_invalid_serialization(tmp_path):
    rig = _rig(tmp_path)
    with pytest.raises(ValueError, match="contradicts"):
        replace(rig.checkpoint, needs_speakeasy=True).validate_identity(
            **_identity(rig)
        )
    for field, value in (
        ("schema_version", "future-schema"),
        ("needs_speakeasy", "false"),
    ):
        payload = rig.checkpoint.to_dict()
        payload[field] = value
        with pytest.raises(ValueError):
            StaticAnalysisCheckpoint.from_dict(payload)
    for value in (float("nan"), float("inf"), -0.1, 1.1):
        payload = rig.checkpoint.to_dict()
        payload["assessment"]["weighted_score"] = value
        with pytest.raises(ValueError):
            StaticAnalysisCheckpoint.from_dict(payload)


def test_tool_snapshot_removes_raw_report_and_command_without_mutating_original():
    payload = {
        "status": "TIMEOUT",
        "raw_report": {"private": True},
        "command": ["never-run"],
        "errors": ["timeout"],
    }
    result = tool_snapshot(payload, "TIMEOUT")
    assert result == {"status": "TIMEOUT", "errors": ["timeout"]}
    result["errors"].append("local change")
    assert payload["errors"] == ["timeout"]
    assert "raw_report" in payload and "command" in payload
