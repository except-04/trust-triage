"""Common detail shell, per-file batch results and Speakeasy presentation."""
from copy import deepcopy
from pathlib import Path

import pytest
from test_evidence_rendering import Tree
from test_progressive_result import combined_response, deep_response, view

SCENARIOS = [
    ("AUTO_BENIGN", "COMPLETED"), ("AUTO_MALICIOUS", "COMPLETED"),
    ("HIGH_RISK_UNCERTAIN", "QUEUED"), ("HIGH_RISK_UNCERTAIN", "RUNNING"),
    ("HIGH_RISK_UNCERTAIN", "COMPLETED"), ("HIGH_RISK_UNCERTAIN", "FAILED"),
]
SECTIONS = ["분석 요약", "라우팅 결정", "분석 파이프라인", "설명 가능성", "Deep Analysis"]


def sample(app, verdict, state):
    response = combined_response(
        verdict=verdict, status=state if state in ("COMPLETED", "FAILED") else "RUNNING"
    )
    response["deep_analysis_status"] = dict.fromkeys(("capa", "floss", "speakeasy"), state)
    response["deep_analysis_status"]["cape"] = "NOT_REQUIRED"
    result = view(app, response)
    result["top_features"] = [
        {"feature_name": f"feature[{index}]", "shap_value": value}
        for index, value in enumerate([0.3, -0.2, 0.1, -0.05, 0.01])
    ]
    if verdict != "HIGH_RISK_UNCERTAIN":
        result["final_verdict"] = "BENIGN" if verdict == "AUTO_BENIGN" else "MALICIOUS"
    elif state in ("COMPLETED", "FAILED"):
        result = app.merge_deep_result(result, deep_response(state))
        if state == "COMPLETED":
            result["final_assessment"] = {"final_verdict": "UNCERTAIN", "reason": "Review evidence"}
    return result


@pytest.mark.parametrize("verdict,state", SCENARIOS)
def test_every_route_uses_same_sections_and_spacing(app, verdict, state):
    result = sample(app, verdict, state)
    original = deepcopy(result)
    target = Tree()
    app.render_result_detail(result, target)
    assert [args[0] for args in target.named("subheader")] == SECTIONS
    cards = [kw for name, _, kw in target.walk() if name == "container" and kw.get("border")]
    assert {kw["key"] for kw in cards} == {
        f"detail_{key}_card" for key in ("summary", "routing", "pipeline", "shap", "deep")
    }
    assert all(kw["height"] == "stretch" and kw["gap"] == app.DETAIL_CARD_GAP for kw in cards)
    shell = target.children[0]
    # Summary, SHAP and Deep remain full-width siblings for every route.
    assert len([name for name, _, _ in shell.calls if name == "container"]) == 3
    assert [args for name, args, _ in shell.calls if name == "columns"] == [([6, 1],), (2,)]
    assert all(kw["gap"] == app.DETAIL_COLUMN_GAP for name, _, kw in shell.calls if name == "columns")
    routing, pipeline = [kw for kw in cards if kw["key"] in {"detail_routing_card", "detail_pipeline_card"}]
    assert {k: v for k, v in routing.items() if k != "key"} == {
        k: v for k, v in pipeline.items() if k != "key"
    }
    assert len(target.named("pyplot")) == 1
    assert result == original
    if verdict != "HIGH_RISK_UNCERTAIN":
        assert set(app.result_detail_state(result)["tools"].values()) == {"NOT_REQUIRED"}
        assert not set(target.expanders()) & {"Speakeasy", "MITRE Evidence", "LLM Summary"}
    elif state in ("QUEUED", "RUNNING"):
        assert any(f"Status: {state}" in args[0] for args in target.named("markdown"))
        assert not target.named("json")
    elif state == "FAILED":
        assert target.named("error")
        assert result["evidence"] in [args[0] for args in target.named("dataframe")]
    else:
        assert {"LLM Summary", "Final Assessment"} <= set(target.expanders())


@pytest.mark.parametrize("verdict,state", SCENARIOS)
def test_running_batch_renders_file_in_existing_fragment(app, monkeypatch, verdict, state):
    result = sample(app, verdict, state)
    batch = {"batch_ids": ["B1"], "analyses": [result, view(app, combined_response("A2"))]}
    app.st.session_state.batch_data = batch
    app.st.session_state.selected_analysis_id = result["analysis_id"]
    app.st.session_state.poll_started_at = app.time.monotonic()
    calls = []
    monkeypatch.setattr(app, "refresh_batch", lambda data: calls.append("refresh") or True)
    monkeypatch.setattr(app, "render_polling_panel", lambda *a, **kw: calls.append("panel"))
    monkeypatch.setattr(app, "render_batch_triage", lambda data: calls.append("selector"))
    target = Tree()
    real_render = app.render_result_detail
    monkeypatch.setattr(app, "render_result_detail", lambda value: real_render(value, target))
    app.polling_fragment()
    assert calls == ["refresh", "panel", "selector"]
    assert [args[0] for args in target.named("subheader")] == SECTIONS
    assert app.st.session_state.analysis_result == result


def test_empty_group_hides_stale_detail(app, monkeypatch, stop_signal):
    result = sample(app, "AUTO_BENIGN", "COMPLETED")
    batch = {"analyses": [result], "summary": app.derive_batch_summary([result])}
    app.st.session_state.analysis_result = result
    monkeypatch.setattr(app.st, "segmented_control", lambda *a, **kw: "needs_review", raising=False)
    monkeypatch.setattr(app.st, "text_input", lambda *a, **kw: "")
    with pytest.raises(stop_signal):
        app.render_progressive_batch_result(batch)
    assert app.st.session_state.analysis_result == result


def test_speakeasy_groups_limits_and_collapsed_raw(app):
    payload = {"behavior": {
        "api_calls": [{"api_name": "CreateFileW"}] * 3 + [
            {"api_name": f"API{index}"} for index in range(15)
        ],
        "files": [{"path": f"file{index}.bin", "operation": "open"} for index in range(15)],
        "network": [{"dns": ["example.test"], "entry_point": 0}],
        "registry": [{"key": "test-key"}],
    }}
    original = deepcopy(payload)
    target = Tree()
    app.render_speakeasy(target, payload)
    assert target.named("metric") == [("API Calls", 18), ("Unique APIs", 16)]
    tables = [args[0] for args in target.named("dataframe")]
    assert [len(rows) for rows in tables] == [10, 10, 1, 1]
    assert tables[0][0] == {"API": "CreateFileW", "Calls": 3}
    assert tables[1][0]["path"] == "file0.bin"
    assert "example.test" in tables[2][0]["dns"]
    assert tables[3][0]["key"] == "test-key"
    assert not any(name == "json" for name, _, _ in target.calls)
    assert target.calls[-1] == ("expander", ("Raw details",), {"expanded": False})
    assert target.children[-1].named("json") == [(payload,)]
    assert payload == original


def test_truncated_worker_and_static_detail_notices_are_visible(app):
    target = Tree()
    app.render_speakeasy(target, {
        "behavior": {"api_calls": [{"api_name": "CreateFileW"}] * 8},
        "behavior_truncated": True,
        "events_truncated": True,
        "event_counts": {"api_calls": 100},
    })
    captions = [args[0] for args in target.named("caption")]
    assert any("100개 중 8개" in caption for caption in captions)
    assert any("일부 상세 이벤트" in caption for caption in captions)

    static = Tree()
    app.render_static_detail_notice(static, {
        "details_status": "OMITTED_TOO_LARGE",
        "details_error": {"actual_bytes": 9_000_000, "limit_bytes": 8_388_608},
    })
    app.render_static_detail_notice(static, {
        "details_status": "ARCHIVE_FAILED",
        "details_error": {"code": "S3_WRITE_FAILED"},
    })
    messages = [args[0] for args in static.named("caption")]
    assert any("상한을 넘어 생략" in message for message in messages)
    assert any("보관에 실패" in message for message in messages)


def test_adapter_and_worker_truncation_stages_are_explained(app):
    target = Tree()
    app.render_speakeasy(target, {
        "behavior": {"api_calls": [{"api_name": "CreateFileW"}] * 8},
        "behavior_truncated": True,
        "events_truncated": True,
        "adapter_events_truncated": True,
        "worker_events_truncated": True,
        "event_counts": {"api_calls": 110},
    })

    captions = [args[0] for args in target.named("caption")]
    assert any("110개 중 8개" in caption for caption in captions)
    assert any("100개를 넘는" in caption for caption in captions)
    assert any("결과 크기 제한" in caption for caption in captions)


def test_floss_static_only_mode_is_visible_in_detail(app):
    result = sample(app, "HIGH_RISK_UNCERTAIN", "COMPLETED")
    result["floss"]["limited_mode"] = True
    target = Tree()

    app.render_result_detail(result, target)

    captions = [args[0] for args in target.named("caption")]
    assert any("FLOSS 제한 모드" in caption for caption in captions)
    assert any("정적 문자열 중심" in caption for caption in captions)


@pytest.mark.parametrize("payload", [{}, {"behavior": None}, {"behavior": {
    "api_calls": [], "files": None, "network": [], "registry": []
}}])
def test_empty_speakeasy_is_explicit(app, payload):
    target = Tree()
    app.render_speakeasy(target, payload)
    assert target.named("metric") == [("API Calls", 0), ("Unique APIs", 0)]
    captions = [args[0] for args in target.named("caption")]
    for category in ("file", "network", "registry"):
        assert f"No {category} activity detected" in captions
    assert not target.named("dataframe")


@pytest.mark.parametrize("verdict,state", SCENARIOS)
def test_real_streamlit_renders_common_detail(app, verdict, state):
    from streamlit.testing.v1 import AppTest

    result = sample(app, verdict, state)
    dashboard = Path(__file__).parents[2] / "dashboard"
    script = f'''
import sys
import runpy
import streamlit as st
sys.path.insert(0, {str(dashboard)!r})
st.session_state.analysis_result = {result!r}
runpy.run_path({str(dashboard / "app.py")!r}, run_name="__main__")
'''
    screen = AppTest.from_string(script).run(timeout=30)
    assert not screen.exception
    assert [heading.value for heading in screen.subheader] == SECTIONS
    assert all(element.label != "Raw details" or not element.proto.expanded for element in screen.expander)


@pytest.mark.parametrize("verdict,state", [
    ("AUTO_BENIGN", "COMPLETED"), ("AUTO_MALICIOUS", "COMPLETED"),
    ("HIGH_RISK_UNCERTAIN", "RUNNING"), ("HIGH_RISK_UNCERTAIN", "COMPLETED"),
])
def test_real_streamlit_opens_selected_result_before_batch_finishes(app, verdict, state):
    from streamlit.testing.v1 import AppTest

    result = sample(app, verdict, state)
    response = combined_response("A2")
    batch = {"batch_ids": ["B1"], "analyses": [result, view(app, response)]}
    group = {
        "AUTO_BENIGN": "auto_benign", "AUTO_MALICIOUS": "auto_malicious",
        "HIGH_RISK_UNCERTAIN": "needs_review",
    }[verdict]
    dashboard = Path(__file__).parents[2] / "dashboard"
    # Exercise the real fragment and selector, with all HTTP transport prohibited.
    script = f'''
import sys
import runpy
import streamlit as st
from unittest.mock import patch
sys.path.insert(0, {str(dashboard)!r})
import api_client
st.session_state.update(
    analysis_result={result!r}, batch_data={batch!r},
    selected_analysis_id="A1", group_analysis_selector="A1", batch_group={group!r},
)
with patch.object(api_client, "_request", side_effect=AssertionError("Unexpected HTTP")), \\
     patch.object(api_client, "get_batch", return_value={{"analyses": [{response!r}]}}):
    runpy.run_path({str(dashboard / "app.py")!r}, run_name="__main__")
'''
    screen = AppTest.from_string(script).run(timeout=30)
    assert not screen.exception
    assert [heading.value for heading in screen.subheader] == SECTIONS
    assert screen.session_state.analysis_result["analysis_id"] == "A1"
    assert screen.session_state.batch_data["analyses"][1]["status"] == "RUNNING"
