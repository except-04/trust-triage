"""위협 근거(MITRE ATT&CK) 영역의 표시 시점과 마크업.

두 가지를 고정한다. (1) 심층 분석이 끝나기 전이나 필요 없는 판정에서는 근거
영역을 그리지 않는다 — 백엔드는 진행 중 스냅샷에도 evidence를 실어 보낼 수 있으므로
표시 시점은 프론트가 정한다. (2) 카드 HTML은 줄바꿈 없는 한 줄이어야 한다 —
st.markdown이 dedent 후 CommonMark로 파싱하므로 빈 줄 하나에 <div> 블록이 끊기고
뒤가 코드 블록으로 찍히던 결함의 회귀 가드다.
"""

from __future__ import annotations

import pytest

from test_progressive_result import combined_response, deep_response, view


class Tree:
    """자식 컨테이너까지 붙잡아 두는 st 대역. 재귀적으로 호출을 모은다."""

    _LAYOUT = ("container", "expander", "empty", "form", "popover", "status", "spinner")

    def __init__(self, name="root"):
        self.name = name
        self.calls = []
        self.children = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name in self._LAYOUT:
                child = Tree(f"{name}:{args[0] if args else ''}")
                self.children.append(child)
                return child
            if name in ("columns", "tabs"):
                spec = args[0] if args else 1
                count = spec if isinstance(spec, int) else len(spec)
                kids = [Tree(f"{name}[{i}]") for i in range(count)]
                self.children.extend(kids)
                return kids
            return None

        return record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def walk(self):
        yield from self.calls
        for child in self.children:
            yield from child.walk()

    def named(self, call_name):
        return [args for name, args, _ in self.walk() if name == call_name]

    def expanders(self):
        return [args[0] for args in self.named("expander") if args]

    def html(self):
        return [
            args[0]
            for name, args, kwargs in self.walk()
            if name == "markdown" and kwargs.get("unsafe_allow_html") and args
        ]


EVIDENCE = [
    {
        "technique_id": "T1055",
        "technique_name": "Process <Injection>",
        "sources": ["CAPA", "SPEAKEASY"],
        "summary": "Injection observed.",
        "evidence_ids": ["evt-1"],
    }
]


# --- 표시 시점 -------------------------------------------------------------------


@pytest.mark.parametrize("verdict", ["AUTO_BENIGN", "AUTO_MALICIOUS"])
def test_not_required_deep_analysis_hides_evidence(app, verdict):
    result = view(app, combined_response(verdict=verdict, status="COMPLETED"))
    assert app.deep_analysis_state(result) == "NOT_REQUIRED"
    assert app.evidence_visible(result) is False
    # 백엔드가 어떤 이유로 evidence 를 실어 보내도 자동 판정에서는 그리지 않는다
    result["evidence"] = list(EVIDENCE)
    assert app.evidence_visible(result) is False


@pytest.mark.parametrize("status", ["QUEUED", "RUNNING"])
def test_pending_deep_analysis_hides_evidence_even_with_partial_snapshot(app, status):
    statuses = {"capa": status, "floss": status, "speakeasy": status, "cape": "NOT_REQUIRED"}
    result = view(app, combined_response(status="RUNNING", deep_statuses=statuses))
    result["evidence"] = list(EVIDENCE)  # 진행 중 스냅샷에 부분 근거가 실린 경우
    assert app.deep_analysis_state(result) == status
    assert app.evidence_visible(result) is False


def test_completed_deep_analysis_shows_evidence_even_when_empty(app):
    initial = view(app, combined_response(status="COMPLETED"))
    result = app.merge_deep_result(initial, deep_response(missing=True))
    assert result["evidence"] == []
    assert app.evidence_visible(result) is True


def test_failed_deep_analysis_shows_evidence_only_if_any_was_collected(app):
    initial = view(app, combined_response(status="FAILED"))
    with_partial = app.merge_deep_result(initial, deep_response("FAILED"))
    assert app.deep_analysis_state(with_partial) == "FAILED"
    assert with_partial["evidence"]
    assert app.evidence_visible(with_partial) is True

    without = app.merge_deep_result(initial, deep_response("FAILED", missing=True))
    assert without["evidence"] == []
    assert app.evidence_visible(without) is False


# --- Progressive 화면 ----------------------------------------------------------


def _render(app, result):
    target = Tree()
    app.render_progressive_result(result, target=target)
    return target


@pytest.mark.parametrize("status", ["QUEUED", "RUNNING"])
def test_pending_progressive_view_keeps_initial_and_shap_but_no_deep_results(
    app, status
):
    statuses = {"capa": status, "floss": status, "speakeasy": status, "cape": "NOT_REQUIRED"}
    result = view(app, combined_response(status="RUNNING", deep_statuses=statuses))
    result["top_features"] = [
        {"feature_name": "header[9]", "display_name": "Major Linker Version",
         "feature_value": 14.0, "shap_value": 0.3, "direction": "MALICIOUS"}
    ]
    result["evidence"] = list(EVIDENCE)
    target = _render(app, result)

    subheaders = [args[0] for args in target.named("subheader")]
    assert subheaders == ["분석 요약", "라우팅 결정", "분석 파이프라인", "설명 가능성", "Deep Analysis"]
    assert target.named("pyplot")  # SHAP 차트는 그대로
    expanders = target.expanders()
    assert "MITRE Evidence" not in expanders
    assert "LLM Summary" not in expanders
    assert "Final Assessment" not in expanders
    assert not target.named("dataframe")  # 부분 근거 표도 없다
    assert any("완료되면" in args[0] for args in target.named("info"))


def test_completed_progressive_view_shows_evidence_llm_and_assessment(app):
    initial = view(app, combined_response(status="COMPLETED"))
    initial["final_assessment"] = {
        "final_verdict": "UNCERTAIN",
        "disposition": "MANUAL_REVIEW",
        "reason": "심층 근거를 검토해야 합니다.",
    }
    result = app.merge_deep_result(initial, deep_response())
    target = _render(app, result)

    expanders = target.expanders()
    assert all(name in expanders for name in ("MITRE Evidence", "LLM Summary", "Final Assessment"))
    frames = [args[0] for args in target.named("dataframe")]
    assert result["evidence"] in frames


def test_failed_progressive_view_shows_partial_evidence_but_no_llm_or_assessment(app):
    initial = view(app, combined_response(status="FAILED"))
    result = app.merge_deep_result(initial, deep_response("FAILED"))
    target = _render(app, result)

    expanders = target.expanders()
    assert "MITRE Evidence" in expanders
    assert "LLM Summary" not in expanders
    assert "Final Assessment" not in expanders
    assert any("실패" in args[0] for args in target.named("error"))


def test_failed_progressive_view_without_evidence_shows_nothing_extra(app):
    initial = view(app, combined_response(status="FAILED"))
    result = app.merge_deep_result(initial, deep_response("FAILED", missing=True))
    target = _render(app, result)

    expanders = target.expanders()
    assert "MITRE Evidence" not in expanders
    assert "LLM Summary" not in expanders
    assert "Final Assessment" not in expanders


# --- 카드 마크업 -----------------------------------------------------------------


def _no_markdown_breaks(markup):
    assert "\n" not in markup, "줄바꿈이 있으면 빈 줄/들여쓰기로 HTML 블록이 쪼개질 수 있다"
    assert not markup.startswith(" ")


def test_empty_card_is_a_single_line_with_placeholders(app):
    markup = app.evidence_card_markup([], [])
    _no_markdown_breaks(markup)
    assert markup.startswith('<div class="evidence-grid">') and markup.endswith("</div>")
    assert "표시할 MITRE ATT&amp;CK 근거가 없습니다." in markup
    assert "표시할 CAPA 행위가 없습니다." in markup
    assert markup.count("<div") == markup.count("</div>")


def test_card_escapes_values_and_stays_single_line(app):
    markup = app.evidence_card_markup(EVIDENCE, ["create process", "<b>bold</b>"])
    _no_markdown_breaks(markup)
    assert '<span class="technique-id">T1055</span>' in markup
    assert "Process &lt;Injection&gt;" in markup  # 값은 escape 된다
    assert "<Injection>" not in markup
    assert "CAPA, SPEAKEASY" in markup  # tactic 이 없으면 sources 로 표기
    assert "· create process" in markup
    assert "&lt;b&gt;bold&lt;/b&gt;" in markup and "<b>bold</b>" not in markup
    assert "표시할 MITRE" not in markup and "표시할 CAPA" not in markup


def test_card_accepts_legacy_mock_keys(app):
    markup = app.evidence_card_markup(
        [{"id": "T1000", "name": "Legacy", "tactic": "Execution"}], []
    )
    _no_markdown_breaks(markup)
    assert "T1000" in markup and "Legacy · Execution" in markup


@pytest.mark.parametrize("verdict", ["AUTO_BENIGN", "AUTO_MALICIOUS"])
def test_completed_layout_hides_the_card_for_automatic_verdicts(app, verdict):
    result = view(app, combined_response(verdict=verdict, status="COMPLETED"))
    target = Tree()
    shap_area = app.evidence_layout(target, result)

    assert not target.named("columns")  # 2열로 나누지 않고
    assert "위협 근거" not in [args[0] for args in target.named("subheader")]
    assert not target.html()
    assert shap_area is target.children[0]  # SHAP 은 전체 폭 컨테이너에


def test_completed_layout_shows_the_card_when_deep_analysis_finished(app):
    initial = view(app, combined_response(status="COMPLETED"))
    result = app.merge_deep_result(initial, deep_response())
    target = Tree()
    shap_area = app.evidence_layout(target, result)

    assert target.named("columns") == [(2,)]
    left, right = target.children
    assert shap_area is right
    assert [args[0] for args in left.named("subheader")] == ["위협 근거"]
    html = left.html()
    assert len(html) == 1 and "T1059" in html[0]
    _no_markdown_breaks(html[0])


def test_render_evidence_card_uses_the_single_line_markup(app):
    result = {"evidence": list(EVIDENCE), "capa_behaviors": []}
    target = Tree()
    app.render_evidence_card(target, result)

    assert [args[0] for args in target.named("subheader")] == ["위협 근거"]
    html = target.html()
    assert len(html) == 1
    _no_markdown_breaks(html[0])
    assert html[0] == app.evidence_card_markup(EVIDENCE, [])
