"""Public projections of the real static/deep/worker serialization contracts.

Fixtures follow the sibling deep-analysis service's get()/LLMInterpretation and
speakeasy_worker.models.result_from_analysis shapes, reviewed read-only. Static
results use their real dataclass serializers; no analyzer, PE, or API is invoked.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from trust_triage.backend_api import views
from trust_triage.backend_api.repository import AnalysisRecord
from trust_triage.backend_api.schemas import InitialResult
from trust_triage.evidence import AttackTechnique, Evidence
from trust_triage.static_analysis import (
    CapaAnalysisResult,
    CapaBackend,
    CapaCapability,
    CapaStatus,
    FlossAnalysisResult,
    FlossStatus,
    FlossString,
)

SHA256 = "a" * 64
PRIVATE_PATH = "C:/private-backend-only/work/sample.bin"
STAMP = "2026-09-08T03:00:00+00:00"


def initial(verdict="HIGH_RISK_UNCERTAIN"):
    return {
        "prediction": {
            "lgbm_raw_probability": 0.75,
            "xgb_raw_probability": 0.75,
            "calibrated_probability": 0.75,
        },
        "risk_signals": {"disagreement": 0, "ood_score": -0.1, "difficulty_score": 0},
        "initial_verdict": verdict,
        "route": "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL",
        "reason": "Synthetic static result.",
        "feature_metadata": {"source_schema_version": "synthetic-v1"},
        "top_features": [],
        "xai_status": "SUCCESS",
        "xai_error": None,
    }


def record(**overrides):
    value = AnalysisRecord(
        analysis_id="analysis-view",
        sha256=SHA256,
        file_location="s3://private-backend-only/raw/sample.bin",
        filename="header-only.exe",
        size_bytes=224,
        status="RUNNING",
        current_stage="SPEAKEASY",
        phase="WAITING_DEEP",
        initial_result=initial(),
        created_at=STAMP,
        updated_at=STAMP,
    )
    return replace(value, **overrides)


@pytest.fixture
def snapshot():
    capa = CapaAnalysisResult(
        sha256=SHA256,
        file_type="PE32",
        status=CapaStatus.SUCCESS,
        backend=CapaBackend.DEFAULT,
        capabilities=[
            CapaCapability(
                "create process",
                "host-interaction/process",
                attack=("Execution::Command and Scripting Interpreter [T1059]",),
            )
        ],
        capa_version="9.3.0",
        rules_version="test-rules",
        elapsed_ms=120,
        analysis_metadata={"sample_path": PRIVATE_PATH},
        raw_reference=PRIVATE_PATH,
        command=("capa", "-j", PRIVATE_PATH),
    ).to_dict()
    floss = FlossAnalysisResult(
        sha256=SHA256,
        file_type="PE32",
        status=FlossStatus.SUCCESS,
        strings=[
            FlossString(f"{kind}_strings", f"{kind} observation", offset=10)
            for kind in ("static", "stack", "tight", "decoded")
        ],
        floss_version="3.1.1",
        elapsed_ms=240,
        raw_reference=PRIVATE_PATH,
        analysis_metadata={"sample_path": PRIVATE_PATH},
        command=("floss", "-j", PRIVATE_PATH),
    ).to_dict()
    technique = AttackTechnique(
        "T1059",
        "Command and Scripting Interpreter",
        ("Execution",),
        "Execution::Command and Scripting Interpreter [T1059]",
    )
    evidence = [
        Evidence(
            "evt-capa",
            SHA256,
            "CAPA",
            "CAPABILITY_MATCH",
            0.7,
            0.8,
            "Observed a process capability.",
            raw_reference=PRIVATE_PATH,
            details={"input_path": PRIVATE_PATH},
            attack_techniques=(technique,),
        ).to_dict(),
        Evidence(
            "evt-worker",
            SHA256,
            "SPEAKEASY",
            "BEHAVIOR_OBSERVED",
            0.6,
            0.7,
            "Observed a process API call.",
            raw_reference=PRIVATE_PATH,
            attack_techniques=(technique,),
        ).to_dict(),
        Evidence(
            "evt-unmapped",
            SHA256,
            "FLOSS",
            "STRING_OBSERVED",
            0.2,
            0.5,
            "Observed an unrelated static string.",
            attack_techniques=(
                AttackTechnique(None, "Unmapped label", mapping_status="UNMAPPED"),
            ),
        ).to_dict(),
    ]
    # This is the actual worker result envelope; raw analysis is internal, while
    # behavior contains observations from the emulated guest rather than host IO.
    worker = {
        "schema_version": "speakeasy-result-v1",
        "analysis_id": "analysis-view",
        "sha256": SHA256,
        "tool": "SPEAKEASY",
        "status": "FAILED",
        "tool_status": "TIMEOUT",
        "behavior": {
            "processes": [{"name": "guest-child"}],
            "api_calls": [{"api_name": "CreateProcessW"}],
            "files": [{"path": "C:/ProgramData/observed-guest-file.dat"}],
            "registry": [],
            "network": [],
        },
        "error": {"code": "TIMEOUT", "message": f"Tool failed at {PRIVATE_PATH}"},
        "started_at": STAMP,
        "completed_at": STAMP,
        "analysis": {
            "tool_version": "1.5.0",
            "analysis_time_ms": 1250,
            "raw_reference": PRIVATE_PATH,
            "metadata": {"input_path": PRIVATE_PATH},
            "raw_report": None,
        },
    }
    # LLMInterpretation.to_dict() has these fields, not key_findings/limitations.
    llm = {
        "status": "SUCCESS",
        "verdict": "UNKNOWN",
        "confidence": 0.6,
        "supporting_evidence_ids": ["evt-worker", "evt-capa"],
        "contradicting_evidence_ids": ["evt-unmapped"],
        "attack_techniques": ["T1059"],
        "summary": "Evidence needs analyst review.",
        "manual_review_required": True,
        "model": "test-model",
        "analysis_time_ms": 300,
        "error": "",
    }
    return {
        "analysis_id": "analysis-view",
        "sha256": SHA256,
        "initial_route": "DEEP_ANALYSIS",
        "initial_verdict": "UNKNOWN",
        "status": "COMPLETED",
        "phase": "COMPLETED",
        "updated_at": STAMP,
        "attempt_count": 3,
        "last_error": None,
        "tool_statuses": {
            "CAPA": "SUCCESS",
            "FLOSS": "SUCCESS",
            "SPEAKEASY": "TIMEOUT",
            "GHIDRA_CAPA": "DISABLED",
            "LLM_INTERPRETER": "SUCCESS",
        },
        "evidence": evidence,
        "static_results": {"CAPA": capa, "FLOSS": floss},
        "speakeasy_result": worker,
        "result": {
            "sha256": SHA256,
            "deep_analysis_status": "COMPLETE",
            "final_verdict": "UNKNOWN",
            "tool_statuses": {"SPEAKEASY": "TIMEOUT"},
            "llm_interpretation": llm,
            "errors": [f"Internal diagnostic: {PRIVATE_PATH}"],
        },
    }


def test_floss_uses_real_string_type_categories(snapshot):
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.floss["strings"] == {
        kind: [f"{kind} observation"]
        for kind in ("static", "stack", "tight", "decoded")
    }
    assert value.floss["status"] == "COMPLETED"
    assert value.capa["capabilities"] == [
        {"name": "create process", "namespace": "host-interaction/process"}
    ]


def test_grouped_floss_report_projects_only_known_string_fields(snapshot):
    snapshot["static_results"]["FLOSS"]["strings"] = {
        "static_strings": [
            {"string": "visible observation", "input_path": PRIVATE_PATH}
        ],
        "decoded": ["decoded observation"],
        "raw_reference": PRIVATE_PATH,
        "metadata": {"input_path": PRIVATE_PATH},
    }
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.floss["strings"] == {
        "static": ["visible observation"],
        "stack": [],
        "tight": [],
        "decoded": ["decoded observation"],
    }
    assert "private-backend-only" not in value.model_dump_json()


def test_llm_summary_is_grounded_in_supporting_evidence_ids(snapshot):
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.llm_status == "SUCCESS"
    assert value.llm_summary.summary == "Evidence needs analyst review."
    assert value.llm_summary.suspicious_behaviors == [
        "Observed a process capability.",
        "Observed a process API call.",
    ]
    assert (
        "Observed an unrelated static string."
        not in value.llm_summary.suspicious_behaviors
    )
    assert value.llm_summary.analyst_notes
    assert "key_findings" not in snapshot["result"]["llm_interpretation"]


@pytest.mark.parametrize(
    "status", ["DISABLED", "NOT_CONFIGURED", "TIMEOUT", "API_ERROR", "INVALID_RESPONSE"]
)
def test_llm_failure_or_disabled_state_does_not_invent_a_summary(snapshot, status):
    snapshot["result"]["llm_interpretation"].update(
        status=status, error=f"Internal diagnostic at {PRIVATE_PATH}"
    )
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.llm_status == status and value.llm_summary is None
    assert "private-backend-only" not in value.model_dump_json()


def test_attack_evidence_aggregates_sources_and_preserves_unmapped_details(snapshot):
    value = views.deep_analysis(record(deep_result=snapshot))
    assert len(value.evidence) == 1
    technique = value.evidence[0]
    assert technique.technique_id == "T1059"
    assert technique.sources == ["CAPA", "SPEAKEASY"]
    assert technique.evidence_ids == ["evt-capa", "evt-worker"]
    assert len(value.evidence_details) == 3
    assert (
        value.evidence_details[2]["attack_techniques"][0]["mapping_status"]
        == "UNMAPPED"
    )
    assert all(
        "raw_reference" not in item and "details" not in item
        for item in value.evidence_details
    )


def test_tool_failure_retains_partial_behavior_and_version_without_internal_paths(
    snapshot,
):
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.status == "COMPLETED"
    assert value.deep_analysis_status == {
        "capa": "COMPLETED",
        "floss": "COMPLETED",
        "speakeasy": "FAILED",
        "cape": "NOT_REQUIRED",
    }
    assert value.speakeasy["tool_status"] == "TIMEOUT"
    assert value.speakeasy["behavior"]["files"] == [
        {"path": "C:/ProgramData/observed-guest-file.dat"}
    ]
    assert value.tool_details["speakeasy"] == {
        "tool_status": "TIMEOUT",
        "version": "1.5.0",
        "elapsed_ms": 1250,
    }
    assert value.tool_details["capa"]["version"] == "9.3.0"
    assert value.tool_details["floss"]["elapsed_ms"] == 240
    encoded = value.model_dump_json()
    assert "private-backend-only" not in encoded
    assert "raw_report" not in encoded and "file_location" not in encoded
    assert "command" not in encoded and "analysis_metadata" not in encoded
    assert value.speakeasy["error"]["code"] == "TIMEOUT"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("SUCCESS", "COMPLETED"),
        ("TIMEOUT", "FAILED"),
        ("ENVIRONMENT_MISMATCH", "FAILED"),
        ("UNSUPPORTED_API", "FAILED"),
        ("NOT_CONFIGURED", "FAILED"),
        ("QUEUED", "QUEUED"),
        ("RUNNING", "RUNNING"),
    ],
)
def test_actual_tool_status_is_preserved_separately_from_public_lifecycle(
    snapshot, status, expected
):
    snapshot.update(status="RUNNING", phase="WAITING_SPEAKEASY", result=None)
    snapshot["tool_statuses"]["SPEAKEASY"] = status
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.status == "RUNNING"
    assert value.deep_analysis_status["speakeasy"] == expected
    assert value.tool_details["speakeasy"]["tool_status"] == status


def test_selected_deep_analysis_is_running_while_worker_holds_first_claim():
    value = views.deep_analysis(
        record(deep_result=None, current_stage="CAPA_FLOSS", claimed=True)
    )
    assert value.status == "RUNNING"


def test_terminal_initial_failure_does_not_leave_deep_tools_queued():
    value = views.deep_analysis(
        record(
            initial_result=None,
            status="FAILED",
            phase="DONE",
            current_stage="FINAL_ASSESSMENT",
            completed_at=STAMP,
        )
    )
    assert value.status == "FAILED"
    assert set(value.deep_analysis_status.values()) == {"NOT_REQUIRED"}


def test_terminal_backend_failure_overrides_stale_running_deep_snapshot(snapshot):
    snapshot.update(status="RUNNING", phase="WAITING_SPEAKEASY", result=None)
    snapshot["tool_statuses"]["SPEAKEASY"] = "RUNNING"
    failure = {
        "code": "DEEP_WAIT_TIMEOUT",
        "message": "Waiting expired.",
        "stage": "SPEAKEASY",
        "retryable": False,
        "retry_count": 3,
        "next_retry_at": STAMP,
    }
    value = views.deep_analysis(
        record(
            deep_result=snapshot,
            status="FAILED",
            phase="DONE",
            current_stage="FINAL_ASSESSMENT",
            error=failure,
            completed_at=STAMP,
        )
    )
    assert value.status == "FAILED" and value.error.code == "DEEP_WAIT_TIMEOUT"
    assert value.deep_analysis_status["capa"] == "COMPLETED"
    assert value.deep_analysis_status["speakeasy"] == "RUNNING"
    assert value.tool_details["speakeasy"]["tool_status"] == "RUNNING"
    assert "retry_count" not in value.model_dump_json()


def test_completed_deep_result_is_preserved_if_later_backend_finalization_fails(
    snapshot,
):
    value = views.deep_analysis(
        record(
            deep_result=snapshot,
            status="FAILED",
            phase="DONE",
            error={"code": "DATABASE_ERROR", "message": "Finalization failed."},
            completed_at=STAMP,
        )
    )
    assert value.status == "COMPLETED"
    assert value.llm_summary is not None
    assert value.error is None


def test_static_sufficiency_marks_unselected_speakeasy_not_required(snapshot):
    snapshot["tool_statuses"].pop("SPEAKEASY")
    snapshot["speakeasy_result"] = None
    value = views.deep_analysis(record(deep_result=snapshot))
    assert value.deep_analysis_status["speakeasy"] == "NOT_REQUIRED"
    assert value.speakeasy is None


def test_xai_uses_initial_schema_default_instead_of_reporting_false_failure():
    result = initial("AUTO_BENIGN")
    result.pop("xai_status")
    assert InitialResult.model_validate(result).xai_status == "NOT_REQUIRED"
    value = views.xai(
        record(
            initial_result=result, status="COMPLETED", phase="DONE", completed_at=STAMP
        )
    )
    assert value.status == "NOT_REQUIRED"
    assert value.explained_output == "LIGHTGBM_RAW_OUTPUT"


def test_xai_failure_does_not_hide_successful_triage_or_publish_internal_retry_fields():
    result = initial("AUTO_BENIGN")
    result.update(
        xai_status="FAILED",
        xai_error={
            "code": "XAI_FAILED",
            "message": "Explanation unavailable.",
            "stage": "XAI",
            "retryable": False,
            "retry_count": 3,
        },
    )
    row = record(
        initial_result=result, status="COMPLETED", phase="DONE", completed_at=STAMP
    )
    assert views.triage(row).status == "COMPLETED"
    assert views.triage(row).initial_verdict == "AUTO_BENIGN"
    assert views.xai(row).status == "FAILED"
    assert "retry_count" not in views.xai(row).model_dump_json()


def test_read_only_projections_do_not_mutate_durable_state(snapshot):
    original = deepcopy(snapshot)
    row = record(deep_result=snapshot)
    views.deep_analysis(row)
    views.analysis(row)
    views.xai(row)
    assert snapshot == original


def test_review_projection_drops_internal_review_id_and_keeps_revision():
    value = views.review(
        {
            "review_id": "internal-id",
            "analysis_id": "analysis-view",
            "revision": 2,
            "analyst_final_verdict": "BENIGN",
            "analyst_notes": "Synthetic review.",
            "reviewer_id": "reviewer-1",
            "reviewed_at": STAMP,
            "review_status": "COMPLETED",
        }
    )
    assert value.revision == 2
    assert "review_id" not in value.model_dump()
