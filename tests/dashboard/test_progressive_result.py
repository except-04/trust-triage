"""HIGH_RISK_UNCERTAIN Progressive Result UI와 기존 polling의 결합 계약."""

from __future__ import annotations

import pytest


def combined_response(
    analysis_id="A1",
    *,
    verdict="HIGH_RISK_UNCERTAIN",
    status="RUNNING",
    deep_statuses=None,
):
    return {
        "analysis_id": analysis_id,
        "status": status,
        "current_stage": "CAPA_FLOSS",
        "error": None,
        "prediction": {
            "lgbm_raw_probability": 0.73,
            "xgb_raw_probability": 0.65,
            "calibrated_probability": 0.69,
        },
        "risk_signals": {
            "disagreement": 0.08,
            "ood_score": -0.12,
            "difficulty_score": 7.0,
        },
        "initial_verdict": verdict,
        "route": "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL",
        "reason": "추가 위험 신호가 탐지되었습니다.",
        "triggered_signals": ["OOD", "DIFFICULTY"]
        if verdict == "HIGH_RISK_UNCERTAIN"
        else [],
        "top_features": [],
        "deep_analysis_status": deep_statuses
        or {
            "capa": "QUEUED",
            "floss": "QUEUED",
            "speakeasy": "QUEUED",
            "cape": "NOT_REQUIRED",
        },
        "evidence": [],
        "llm_summary": None,
        "final_verdict": None,
        "final_assessment": None,
    }


def view(app, response):
    base = app.entry_view(
        {
            "analysis_id": response["analysis_id"],
            "filename": f"{response['analysis_id']}.exe",
            "sha256": response["analysis_id"].lower().ljust(64, "a"),
            "size_bytes": 1024,
        },
        response["status"],
    )
    return app.to_view(response, base)


def deep_response(status="COMPLETED", *, missing=False):
    value = {
        "status": status,
        "deep_analysis_status": {
            "capa": "COMPLETED",
            "floss": "COMPLETED",
            "speakeasy": "FAILED" if status == "FAILED" else "COMPLETED",
            "cape": "NOT_REQUIRED",
        },
        "tool_details": {"capa": {"version": "9.3.0", "elapsed_ms": 120}},
        "capa": {
            "status": "COMPLETED",
            "capabilities": [
                {"name": "create process", "namespace": "host-interaction/process"}
            ],
        },
        "floss": {
            "status": "COMPLETED",
            "strings": {"decoded": ["powershell.exe"], "static": []},
        },
        "speakeasy": {
            "status": "COMPLETED",
            "behavior": {"api_calls": [{"api_name": "CreateProcessW"}]},
        },
        "evidence": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "sources": ["CAPA", "SPEAKEASY"],
                "summary": "Process execution was observed.",
                "evidence_ids": ["evt-1"],
            }
        ],
        "evidence_details": [],
        "llm_summary": {
            "summary": "분석가 검토가 필요합니다.",
            "suspicious_behaviors": ["Process execution was observed."],
            "analyst_notes": "참고 자료",
        },
        "llm_status": "SUCCESS",
        "error": None,
    }
    if status == "FAILED":
        value["error"] = {
            "code": "DEEP_WAIT_TIMEOUT",
            "message": "심층 분석 대기 시간을 초과했습니다.",
            "stage": "SPEAKEASY",
        }
    if missing:
        for key in ("capa", "floss", "speakeasy", "evidence", "llm_summary"):
            value.pop(key)
    return value


@pytest.mark.parametrize("verdict", ["AUTO_BENIGN", "AUTO_MALICIOUS"])
def test_automatic_verdicts_keep_existing_completed_detail_path(app, verdict):
    result = view(app, combined_response(verdict=verdict, status="COMPLETED"))

    assert app.detail_blocker(result) is None
    assert app.is_progressive_result(result) is False
    assert app.deep_analysis_state(result) == "NOT_REQUIRED"


def test_queued_deep_analysis_exposes_initial_result_immediately(app):
    result = view(app, combined_response())

    assert app.is_progressive_result(result) is True
    assert result["status"] == "RUNNING"
    assert result["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
    assert result["calibrated_probability"] == pytest.approx(0.69)
    assert result["triggered_signals"] == ["OOD", "DIFFICULTY"]
    assert app.deep_analysis_state(result) == "QUEUED"


def test_running_deep_analysis_keeps_initial_result(app):
    result = view(
        app,
        combined_response(
            deep_statuses={
                "capa": "COMPLETED",
                "floss": "RUNNING",
                "speakeasy": "QUEUED",
                "cape": "NOT_REQUIRED",
            }
        ),
    )

    assert app.deep_analysis_state(result) == "RUNNING"
    assert result["reason"] and result["raw_probability"] == pytest.approx(0.73)


def test_completed_deep_analysis_merges_actual_tool_results(app):
    initial = view(app, combined_response(status="COMPLETED"))
    initial["final_assessment"] = {
        "final_verdict": "UNCERTAIN",
        "disposition": "MANUAL_REVIEW",
        "reason": "심층 근거를 검토해야 합니다.",
    }

    result = app.merge_deep_result(initial, deep_response())

    assert app.deep_analysis_state(result) == "COMPLETED"
    assert result["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
    assert result["capa"]["capabilities"][0]["name"] == "create process"
    assert result["floss"]["strings"]["decoded"] == ["powershell.exe"]
    assert result["speakeasy"]["behavior"]["api_calls"]
    assert result["evidence"][0]["technique_id"] == "T1059"
    assert result["llm_summary"]["summary"]
    assert result["final_assessment"]["disposition"] == "MANUAL_REVIEW"


def test_failed_deep_analysis_does_not_replace_initial_result(app):
    initial = view(app, combined_response(status="FAILED"))
    result = app.merge_deep_result(initial, deep_response("FAILED"))

    assert app.is_progressive_result(result) is True
    assert app.detail_blocker(result) is None
    assert app.deep_analysis_state(result) == "FAILED"
    assert result["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
    assert result["deep_error"]["code"] == "DEEP_WAIT_TIMEOUT"


def test_missing_optional_deep_fields_render_without_key_error(app):
    initial = view(app, combined_response(status="COMPLETED"))
    result = app.merge_deep_result(initial, deep_response(missing=True))

    app.render_progressive_result(result)

    assert result["capa"] is None
    assert result["floss"] is None
    assert result["speakeasy"] is None
    assert result["evidence"] == []


def test_batch_polling_promotes_partial_initial_result_without_second_loop(
    app, monkeypatch
):
    batch_data = {
        "batch_ids": ["B1"],
        "analyses": [
            app.entry_view(
                {
                    "analysis_id": "A1",
                    "filename": "sample.exe",
                    "sha256": "a" * 64,
                    "size_bytes": 1024,
                },
                "QUEUED",
            )
        ],
    }
    calls = {"batch": 0, "deep": 0}

    def get_batch(batch_id):
        calls["batch"] += 1
        return {"batch_id": batch_id, "analyses": [combined_response()]}

    def get_deep(_analysis_id):
        calls["deep"] += 1
        return deep_response()

    monkeypatch.setattr(app.api_client, "get_batch", get_batch)
    monkeypatch.setattr(app.api_client, "get_deep_analysis", get_deep)

    assert app.refresh_batch(batch_data) is True
    assert batch_data["analyses"][0]["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
    assert calls == {"batch": 1, "deep": 0}


def test_terminal_transition_loads_deep_detail_once(app, monkeypatch):
    pending = view(app, combined_response())
    batch_data = {"batch_ids": ["B1"], "analyses": [pending]}
    calls = []
    monkeypatch.setattr(
        app.api_client,
        "get_batch",
        lambda _batch_id: {
            "analyses": [combined_response(status="COMPLETED")]
        },
    )
    monkeypatch.setattr(
        app.api_client,
        "get_deep_analysis",
        lambda analysis_id: calls.append(analysis_id) or deep_response(),
    )

    assert app.refresh_batch(batch_data) is False
    assert app.refresh_batch(batch_data) is False

    assert calls == ["A1"]
    assert batch_data["analyses"][0]["deep_detail_loaded"] is True


def test_deep_completion_loads_detail_before_overall_finalization(app, monkeypatch):
    pending = view(app, combined_response())
    batch_data = {"batch_ids": ["B1"], "analyses": [pending]}
    finished_tools = {
        "capa": "COMPLETED",
        "floss": "COMPLETED",
        "speakeasy": "COMPLETED",
        "cape": "NOT_REQUIRED",
    }
    calls = []
    monkeypatch.setattr(
        app.api_client,
        "get_batch",
        lambda _batch_id: {
            "analyses": [combined_response(deep_statuses=finished_tools)]
        },
    )
    monkeypatch.setattr(
        app.api_client,
        "get_deep_analysis",
        lambda analysis_id: calls.append(analysis_id) or deep_response(),
    )

    assert app.refresh_batch(batch_data) is True

    result = batch_data["analyses"][0]
    assert result["status"] == "RUNNING"
    assert result["deep_status"] == "COMPLETED"
    assert result["capa"]["capabilities"]
    assert calls == ["A1"]


def test_switching_analysis_does_not_leave_previous_deep_result(app):
    first = app.merge_deep_result(
        view(app, combined_response("A1", status="COMPLETED")), deep_response()
    )
    second = view(app, combined_response("A2"))
    app.st.session_state.selected_analysis_id = "A2"
    app.st.session_state.analysis_result = first

    app.sync_selected_analysis({"analyses": [first, second]})

    selected = app.st.session_state.analysis_result
    assert selected["analysis_id"] == "A2"
    assert selected.get("deep_detail_loaded") is not True
    assert selected.get("capa") is None
