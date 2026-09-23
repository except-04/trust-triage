"""Dynamic observations stay meaningful and bounded at the LLM boundary."""

from __future__ import annotations

from trust_triage.deep_analysis.llm_interpreter import _serialize_evidence
from trust_triage.deep_analysis.normalizer import normalize_speakeasy_result
from trust_triage.deep_analysis.service_models import DeepAnalysisRequest
from trust_triage.deep_analysis.worker_results import analysis_from_worker
from trust_triage.dynamic_analysis.models import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
)
from trust_triage.dynamic_analysis.speakeasy_analyzer import _summarize_report
from trust_triage.speakeasy_worker.models import result_from_analysis


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


def test_missing_service_call_detail_distinguishes_legacy_from_truncated_input():
    legacy = _payload(["CreateServiceW"], {"api_calls": []})
    truncated = {
        **legacy,
        "metadata": {"events_truncated": True},
    }

    assert _attack_ids(legacy) == {"T1543.003"}
    assert _attack_ids(truncated) == set()


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


def test_speakeasy_1511_report_fields_survive_worker_and_llm_boundaries():
    request = DeepAnalysisRequest(
        "v1511-observations", "a" * 64,
        "s3://worker-test-bucket/raw/fixture.bin", "DEEP_ANALYSIS",
    )

    def context(domain, command, operation):
        summary = _summarize_report({
            "entry_points": [{
                "apis": [{
                    "api_name": "kernel32.CreateProcessW",
                    "args": ["0x0", command, "0x0"],
                    "ret_val": "0x1",
                }],
                "network_events": {
                    "dns": [{"query": domain, "response": "192.0.2.1"}],
                    "traffic": [{"server": domain, "port": 443, "proto": "tcp.https"}],
                },
                "file_access": [{"event": operation, "path": "C:\\temp\\fixture.bin"}],
            }]
        })
        analysis = DynamicAnalysisResult(
            evidence_id="v1511-evidence", sha256=request.sha256,
            source="SPEAKEASY", category="DYNAMIC_ANALYSIS",
            status=DynamicAnalysisStatus.SUCCESS, summary="synthetic observations",
            observed_apis=summary.observed_apis,
            behaviors=summary.behaviors,
            events=summary.events,
        )
        worker = result_from_analysis(request.worker_job, analysis)
        restored = analysis_from_worker(request, worker)
        evidence = normalize_speakeasy_result(restored)
        return _serialize_evidence(evidence)[0]["context"]["observations"]

    first = context("first.invalid", "tool.exe --mode=one", "read")
    second = context("second.invalid", "tool.exe --mode=two", "write")

    assert first != second
    assert any(item.get("query") == "first.invalid" for item in first)
    assert any(item.get("server") == "first.invalid" for item in first)
    assert any("arg[1]=tool.exe --mode=one" in item.get("arguments", "") for item in first)
    assert any(item.get("event") == "read" for item in first)
    assert any(item.get("event") == "write" for item in second)
