from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass

from trust_triage.deep_analysis import (
    AnalysisTier,
    Evidence,
    EvidenceStatus,
    DeepAnalysisConfig,
    DeepAnalysisDisposition,
    DeepAnalysisOrchestrator,
    DeepAnalysisStatus,
    LLMInterpretation,
    LLMInterpretationStatus,
)
from trust_triage.attack_mapping import normalize_attack_labels


@dataclass(frozen=True)
class _Capability:
    attack: tuple[str, ...] = ()


class _FakeCapaResult:
    sha256 = "b" * 64

    def __init__(
        self,
        capabilities: list[_Capability],
        *,
        status: str = "SUCCESS",
    ) -> None:
        self.capabilities = capabilities
        self.status = status

    def to_evidence(self, *, reliability: float = 0.8) -> tuple[Evidence, ...]:
        return tuple(
            Evidence(
                evidence_id=f"capa-{index}",
                sha256=self.sha256,
                source="CAPA",
                category="CAPABILITY_MATCH",
                severity=0.7,
                reliability=reliability,
                summary="CAPA capability match",
                status=EvidenceStatus.OBSERVED,
                details={"attack": list(capability.attack)},
                attack_techniques=normalize_attack_labels(capability.attack),
            )
            for index, capability in enumerate(self.capabilities, start=1)
        )


class _FakeCapaAnalyzer:
    def __init__(self, result: _FakeCapaResult) -> None:
        self.result = result
        self.calls = 0

    def analyze(self, sample_path: Path) -> _FakeCapaResult:
        del sample_path
        self.calls += 1
        return self.result


class _FakeFlossResult:
    sha256 = "f" * 64

    def __init__(self, evidence: tuple[Evidence, ...] = (), *, status: str = "SUCCESS") -> None:
        self.evidence = evidence
        self.status = status

    def to_evidence(
        self,
        *,
        reliability: float = 0.55,
        max_strings: int = 64,
    ) -> tuple[Evidence, ...]:
        del reliability, max_strings
        return self.evidence if self.status == "SUCCESS" else ()


class _FakeFlossAnalyzer:
    def __init__(self, result: _FakeFlossResult) -> None:
        self.result = result
        self.calls = 0

    def analyze(self, sample_path: Path) -> _FakeFlossResult:
        del sample_path
        self.calls += 1
        return self.result


class _FakeSpeakeasyAnalyzer:
    def __init__(self, result: dict) -> None:
        self.result = result
        self.calls = 0

    def analyze(self, sample_path: Path) -> dict:
        del sample_path
        self.calls += 1
        return self.result


class _FakeLLMInterpreter:
    def __init__(self) -> None:
        self.calls = 0
        self.evidence: tuple[Evidence, ...] = ()

    def interpret(
        self,
        evidence: tuple[Evidence, ...],
        *,
        sha256: str,
        initial_verdict: str | None,
    ) -> LLMInterpretation:
        del sha256, initial_verdict
        self.calls += 1
        self.evidence = tuple(evidence)
        return LLMInterpretation(
            status=LLMInterpretationStatus.SUCCESS,
            verdict="MALICIOUS",
            confidence=0.9,
            supporting_evidence_ids=(evidence[0].evidence_id,),
            attack_techniques=("T1055",),
            summary="The supplied evidence supports a malicious recommendation.",
            manual_review_required=True,
            model="test-model",
        )


def _sample(tmp_path: Path) -> Path:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00fixture")
    return sample


def _capa_result(
    *,
    capabilities: list[_Capability],
    status: str = "SUCCESS",
) -> _FakeCapaResult:
    return _FakeCapaResult(capabilities, status=status)


def _injection_capability() -> _Capability:
    return _Capability(attack=("Defense Evasion::Process Injection",))


def _floss_string_evidence() -> Evidence:
    return Evidence(
        evidence_id="floss-1",
        sha256="f" * 64,
        source="FLOSS",
        category="OBFUSCATED_STRING",
        severity=0.5,
        reliability=0.55,
        summary="FLOSS recovered decoded_strings: https://example.invalid/c2",
        status=EvidenceStatus.OBSERVED,
        details={
            "string": "https://example.invalid/c2",
            "string_type": "decoded_strings",
        },
    )


def test_low_risk_route_does_not_start_deep_analysis(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[_injection_capability()]))
    speakeasy = _FakeSpeakeasyAnalyzer({"status": "SUCCESS"})

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
    ).run(_sample(tmp_path), initial_route="AUTO_BENIGN", initial_verdict="BENIGN")

    assert result.deep_analysis_status is DeepAnalysisStatus.NOT_REQUIRED
    assert result.reason_codes == ("DEEP_ANALYSIS_NOT_REQUIRED",)
    assert capa.calls == 0
    assert speakeasy.calls == 0


def test_capa_sufficient_evidence_stops_before_speakeasy(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[_injection_capability()]))
    speakeasy = _FakeSpeakeasyAnalyzer({"status": "SUCCESS"})

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.last_tier is AnalysisTier.CAPA
    assert result.executed_tiers == (AnalysisTier.CAPA,)
    assert result.final_verdict == "UNKNOWN"
    assert result.disposition is DeepAnalysisDisposition.MANUAL_REVIEW
    assert speakeasy.calls == 0
    assert result.evidence_assessment is not None
    assert result.evidence_assessment.sufficient is True


def test_capa_and_floss_run_as_one_static_phase_and_reach_llm(
    tmp_path: Path,
) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[_injection_capability()]))
    floss = _FakeFlossAnalyzer(_FakeFlossResult((_floss_string_evidence(),)))
    speakeasy = _FakeSpeakeasyAnalyzer({"status": "SUCCESS"})
    llm = _FakeLLMInterpreter()

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        floss_analyzer=floss,
        speakeasy_analyzer=speakeasy,
        llm_interpreter=llm,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.executed_tiers == (AnalysisTier.CAPA, AnalysisTier.FLOSS)
    assert result.last_tier is AnalysisTier.FLOSS
    assert result.final_verdict == "MALICIOUS"
    assert capa.calls == 1
    assert floss.calls == 1
    assert speakeasy.calls == 0
    assert llm.calls == 1
    assert {item.source for item in llm.evidence} == {"CAPA", "FLOSS"}
    assert result.llm_interpretation is not None
    assert result.llm_interpretation.status is LLMInterpretationStatus.SUCCESS


def test_floss_failure_does_not_discard_successful_capa_evidence(
    tmp_path: Path,
) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[_injection_capability()]))
    floss = _FakeFlossAnalyzer(_FakeFlossResult(status="TIMEOUT"))

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        floss_analyzer=floss,
        speakeasy_analyzer=None,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.final_verdict == "UNKNOWN"
    assert result.tool_statuses["FLOSS"] == "TIMEOUT"
    assert result.evidence and result.evidence[0].source == "CAPA"


def test_insufficient_capa_evidence_advances_to_speakeasy(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-1",
            "sha256": "c" * 64,
            "status": "SUCCESS",
            "observed_apis": [
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
            "behaviors": [],
            "events": {},
        }
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
    ).run(_sample(tmp_path), initial_route="DEEP_ANALYSIS")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.executed_tiers == (AnalysisTier.CAPA, AnalysisTier.SPEAKEASY)
    assert result.last_tier is AnalysisTier.SPEAKEASY
    assert result.final_verdict == "UNKNOWN"
    assert speakeasy.calls == 1
    assert any(
        technique.technique_id == "T1055"
        for item in result.evidence
        for technique in item.attack_techniques
    )
    assert "ADVANCE_TO_SPEAKEASY" in result.reason_codes


def test_insufficient_speakeasy_evidence_advances_to_ghidra(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-generic",
            "sha256": "f" * 64,
            "status": "SUCCESS",
            "observed_apis": ["CreateFileW"],
            "behaviors": ["file_access"],
            "events": {},
        }
    )
    ghidra = _FakeCapaAnalyzer(
        _capa_result(capabilities=[_injection_capability()])
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
        config=DeepAnalysisConfig(enable_ghidra_capa=True),
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.executed_tiers == (
        AnalysisTier.CAPA,
        AnalysisTier.SPEAKEASY,
        AnalysisTier.GHIDRA_CAPA,
    )
    assert result.last_tier is AnalysisTier.GHIDRA_CAPA
    assert result.final_verdict == "UNKNOWN"
    assert ghidra.calls == 1
    assert "ADVANCE_TO_GHIDRA_CAPA" in result.reason_codes


def test_speakeasy_failure_uses_ghidra_fallback(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-timeout",
            "sha256": "g" * 64,
            "status": "TIMEOUT",
            "errors": ["timeout"],
        }
    )
    ghidra = _FakeCapaAnalyzer(
        _capa_result(capabilities=[_injection_capability()])
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
        config=DeepAnalysisConfig(enable_ghidra_capa=True),
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.final_verdict == "UNKNOWN"
    assert result.tool_statuses["SPEAKEASY"] == "TIMEOUT"
    assert result.tool_statuses["GHIDRA_CAPA"] == "SUCCESS"
    assert "SPEAKEASY_TIMEOUT" in result.reason_codes
    assert ghidra.calls == 1


def test_ghidra_failure_returns_failed_status(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-generic",
            "sha256": "h" * 64,
            "status": "SUCCESS",
            "observed_apis": ["CreateFileW"],
            "behaviors": ["file_access"],
        }
    )
    ghidra = _FakeCapaAnalyzer(
        _capa_result(capabilities=[], status="ENVIRONMENT_MISMATCH")
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
        config=DeepAnalysisConfig(enable_ghidra_capa=True),
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.FAILED
    assert result.final_verdict == "UNKNOWN"
    assert result.disposition is DeepAnalysisDisposition.ANALYSIS_FAILED
    assert result.tool_statuses["GHIDRA_CAPA"] == "ENVIRONMENT_MISMATCH"
    assert "GHIDRA_CAPA_ENVIRONMENT_MISMATCH" in result.reason_codes


def test_ghidra_is_disabled_by_default_and_not_executed(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-generic",
            "sha256": "i" * 64,
            "status": "SUCCESS",
            "observed_apis": ["CreateFileW"],
            "behaviors": ["file_access"],
        }
    )
    ghidra = _FakeCapaAnalyzer(
        _capa_result(capabilities=[_injection_capability()])
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.executed_tiers == (AnalysisTier.CAPA, AnalysisTier.SPEAKEASY)
    assert result.last_tier is AnalysisTier.SPEAKEASY
    assert result.final_verdict == "UNKNOWN"
    assert result.disposition is DeepAnalysisDisposition.MANUAL_REVIEW
    assert result.tool_statuses["GHIDRA_CAPA"] == "DISABLED"
    assert "GHIDRA_CAPA_DISABLED" in result.reason_codes
    assert ghidra.calls == 0


def test_speakeasy_failure_is_not_malicious_evidence(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-timeout",
            "sha256": "d" * 64,
            "status": "TIMEOUT",
            "observed_apis": ["VirtualAllocEx"],
            "behaviors": [],
            "errors": ["timeout"],
        }
    )

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.FAILED
    assert result.disposition is DeepAnalysisDisposition.ANALYSIS_FAILED
    assert result.final_verdict == "UNKNOWN"
    assert result.evidence == ()
    assert result.requires_human_review is True
    assert "SPEAKEASY_TIMEOUT" in result.reason_codes


def test_completed_but_uncertain_flow_requires_review(tmp_path: Path) -> None:
    capa = _FakeCapaAnalyzer(_capa_result(capabilities=[]))
    speakeasy = _FakeSpeakeasyAnalyzer(
        {
            "evidence_id": "speakeasy-benign-looking",
            "sha256": "e" * 64,
            "status": "SUCCESS",
            "observed_apis": ["CreateFileW"],
            "behaviors": ["file_access"],
            "events": {"file_access": [{"path": "C:\\temp\\x.bin"}]},
        }
    )
    ghidra = _FakeCapaAnalyzer(_capa_result(capabilities=[]))

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
        ghidra_capa_analyzer=ghidra,
        config=DeepAnalysisConfig(),
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    assert result.deep_analysis_status is DeepAnalysisStatus.COMPLETE
    assert result.final_verdict == "UNKNOWN"
    assert result.disposition is DeepAnalysisDisposition.MANUAL_REVIEW
    assert result.requires_human_review is True
    assert result.evidence_assessment is not None
    assert result.evidence_assessment.sufficient is False


def test_result_serializes_deep_analysis_status(tmp_path: Path) -> None:
    result = DeepAnalysisOrchestrator(
        capa_analyzer=_FakeCapaAnalyzer(_capa_result(capabilities=[])),
        speakeasy_analyzer=None,
    ).run(_sample(tmp_path), initial_route="HIGH_RISK_UNCERTAIN")

    payload = result.to_dict()
    assert payload["deep_analysis_status"] == "FAILED"
    assert payload["disposition"] == "ANALYSIS_FAILED"
