from __future__ import annotations

from trust_triage.attack_mapping import technique_display_name
from trust_triage.deep_analysis import (
    Evidence,
    EvidenceStatus,
    normalize_attack_label,
    normalize_speakeasy_result,
)


def test_human_readable_attack_label_is_normalized() -> None:
    technique = normalize_attack_label("Defense Evasion::Process Injection")

    assert technique.technique_id == "T1055"
    assert technique.technique_name == "Process Injection"
    assert technique.mapping_status == "MAPPED"
    assert technique.source_label == "Defense Evasion::Process Injection"


def test_subtechnique_id_is_preserved() -> None:
    technique = normalize_attack_label("T1055.012: Process Hollowing")

    assert technique.technique_id == "T1055.012"
    assert technique.technique_name == "Process Hollowing"


def test_unknown_label_is_not_silently_dropped() -> None:
    technique = normalize_attack_label("Future CAPA behavior")

    assert technique.technique_id is None
    assert technique.mapping_status == "UNMAPPED"
    assert technique.source_label == "Future CAPA behavior"


def test_capa_evidence_contains_raw_and_normalized_attack_values() -> None:
    technique = normalize_attack_label("Persistence::Create or Modify System Process")
    evidence = Evidence(
        evidence_id="evt-1",
        sha256="a" * 64,
        source="CAPA",
        category="CAPABILITY_MATCH",
        severity=0.7,
        reliability=0.8,
        summary="CAPA match",
        status=EvidenceStatus.OBSERVED,
        details={"attack": ["Persistence::Create or Modify System Process"]},
        attack_techniques=(technique,),
    )

    payload = evidence.to_dict()

    assert payload["status"] == "OBSERVED"
    assert payload["details"]["attack"] == [
        "Persistence::Create or Modify System Process"
    ]
    assert payload["attack_techniques"][0]["technique_id"] == "T1543"
    assert payload["attack_techniques"][0]["technique_name"] == (
        "Create or Modify System Process"
    )


def test_capa_summary_shows_analyst_facing_attack_label() -> None:
    technique = normalize_attack_label("Process Injection")

    assert technique_display_name(technique) == "[T1055] Process Injection"


def _speakeasy_payload(*, observed_apis, events=None):
    return {
        "evidence_id": "dynamic-1",
        "sha256": "a" * 64,
        "status": "SUCCESS",
        "observed_apis": observed_apis,
        "behaviors": [],
        "events": events or {},
    }


def test_open_scm_manager_alone_is_not_service_creation() -> None:
    evidence = normalize_speakeasy_result(
        _speakeasy_payload(observed_apis=["advapi32.OpenSCManagerW"])
    )

    assert all(
        technique.technique_id != "T1543.003"
        for item in evidence
        for technique in item.attack_techniques
    )


def test_successful_create_service_maps_windows_service() -> None:
    evidence = normalize_speakeasy_result(
        _speakeasy_payload(
            observed_apis=["advapi32.CreateServiceW"],
            events={
                "api_calls": [
                    {"api_name": "advapi32.CreateServiceW", "ret_val": "0x1234"}
                ]
            },
        )
    )

    assert any(
        technique.technique_id == "T1543.003"
        for item in evidence
        for technique in item.attack_techniques
    )


def test_failed_create_service_call_is_not_mapped() -> None:
    evidence = normalize_speakeasy_result(
        _speakeasy_payload(
            observed_apis=["advapi32.CreateServiceW"],
            events={
                "api_calls": [{"api_name": "advapi32.CreateServiceW", "ret_val": "0x0"}]
            },
        )
    )

    assert all(
        technique.technique_id != "T1543.003"
        for item in evidence
        for technique in item.attack_techniques
    )
