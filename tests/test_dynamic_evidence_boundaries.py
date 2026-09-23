"""Dynamic observations stay meaningful and bounded at the LLM boundary."""

from __future__ import annotations

from trust_triage.deep_analysis.llm_interpreter import _serialize_evidence
from trust_triage.deep_analysis.normalizer import normalize_speakeasy_result


def _payload(apis, events=None):
    return {
        "evidence_id": "dynamic-boundary",
        "sha256": "a" * 64,
        "status": "SUCCESS",
        "observed_apis": apis,
        "behaviors": [],
        "events": events or {},
    }


def _attack_ids(payload):
    return {
        technique.technique_id
        for item in normalize_speakeasy_result(payload)
        for technique in item.attack_techniques
    }


def test_two_allocation_apis_do_not_imply_process_injection():
    assert _attack_ids(_payload(["VirtualAllocEx", "NtAllocateVirtualMemory"])) == set()
    assert _attack_ids(_payload(["VirtualAllocEx", "WriteProcessMemory"])) == {
        "T1055"
    }


def test_zero_padded_failed_service_creation_is_not_attack_evidence():
    payload = _payload(
        ["CreateServiceW"],
        {"api_calls": [{"api_name": "CreateServiceW", "ret_val": "0x00000000"}]},
    )
    assert _attack_ids(payload) == set()


def test_different_observed_paths_and_destinations_reach_llm_context():
    def serialized(path, destination):
        payload = _payload(
            ["CreateFileW"],
            {
                "file_access": [{"path": path}],
                "network_events": [{"destination": destination}],
            },
        )
        payload["metadata"] = {
            "event_counts": {"file_access": 20, "network_events": 3},
            "events_truncated": True,
        }
        evidence = normalize_speakeasy_result(payload)
        context = _serialize_evidence(evidence)[0]["context"]
        assert context["events_truncated"] is True
        assert context["event_counts"]["file_access"] == 20
        return context["observations"]

    first = serialized("C:\\temp\\first.bin", "example.invalid:443")
    second = serialized("C:\\temp\\second.bin", "other.invalid:443")

    assert first != second
    assert any(item.get("path") == "C:\\temp\\first.bin" for item in first)
    assert any(item.get("destination") == "example.invalid:443" for item in first)
    assert len(first) <= 8
