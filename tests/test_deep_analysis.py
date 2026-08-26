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
)
from trust_triage.attack_mapping import normalize_attack_labels


@dataclass(frozen=True)
class _Capability:
    attack: tuple[str, ...] = ()


class _FakeCapaResult:
    status = "SUCCESS"
    sha256 = "b" * 64

    def __init__(self, capabilities: list[_Capability]) -> None:
        self.capabilities = capabilities

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


class _FakeSpeakeasyAnalyzer:
    def __init__(self, result: dict) -> None:
        self.result = result
        self.calls = 0

    def analyze(self, sample_path: Path) -> dict:
        del sample_path
        self.calls += 1
        return self.result


def _sample(tmp_path: Path) -> Path:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00fixture")
    return sample


def _capa_result(*, capabilities: list[_Capability]) -> _FakeCapaResult:
    return _FakeCapaResult(capabilities)


def _injection_capability() -> _Capability:
    return _Capability(attack=("Defense Evasion::Process Injection",))


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
    assert result.final_verdict == "MALICIOUS"
    assert result.disposition is DeepAnalysisDisposition.ALERT_RECOMMENDED
    assert speakeasy.calls == 0
    assert result.evidence_assessment is not None
    assert result.evidence_assessment.sufficient is True


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
    assert result.final_verdict == "MALICIOUS"
    assert speakeasy.calls == 1
    assert any(
        technique.technique_id == "T1055"
        for item in result.evidence
        for technique in item.attack_techniques
    )
    assert "ADVANCE_TO_SPEAKEASY" in result.reason_codes


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

    result = DeepAnalysisOrchestrator(
        capa_analyzer=capa,
        speakeasy_analyzer=speakeasy,
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
