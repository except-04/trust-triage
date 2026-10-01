"""Deep Analysis 결과 검색: 검색창 하나로 CAPA/FLOSS/Speakeasy/MITRE 표를 거른다."""

from __future__ import annotations

from test_evidence_rendering import Tree


class SearchTree(Tree):
    """text_input 이 정해진 검색어를 돌려주는 Tree."""

    def __init__(self, query, name="root"):
        super().__init__(name)
        self.query = query

    def text_input(self, *args, **kwargs):
        self.calls.append(("text_input", args, kwargs))
        return self.query


def completed_analysis():
    return {
        "capa": {
            "status": "COMPLETED",
            "capabilities": [
                {"name": "create process", "namespace": "host-interaction/process"},
                {"name": "run PowerShell expression", "namespace": "load-code/powershell"},
            ],
        },
        "floss": {
            "status": "COMPLETED",
            "strings": {"decoded": ["powershell.exe"], "static": ["kernel32.dll", "cmd.exe"]},
        },
        "speakeasy": {
            "status": "COMPLETED",
            "behavior": {
                "api_calls": [{"api_name": "CreateProcessW"}, {"api_name": "RegSetValueExW"}],
                "registry": [{"key": "HKCU\\Software\\Run", "access": "set"}],
            },
        },
        "evidence": [
            {"technique_id": "T1059.001", "technique_name": "PowerShell",
             "sources": ["CAPA"], "summary": "run PowerShell", "evidence_ids": ["evt-1"]},
            {"technique_id": "T1518", "technique_name": "Software Discovery",
             "sources": ["CAPA"], "summary": "query software", "evidence_ids": ["evt-2"]},
        ],
        "deep_status": "COMPLETED",
        "status": "COMPLETED",
    }


def state():
    return {"deep": "COMPLETED", "tools": {"capa": "COMPLETED", "floss": "COMPLETED", "speakeasy": "COMPLETED"}}


def expander_titles(tree):
    return [args[0] for name, args, _ in tree.walk() if name == "expander"]


def tables(tree):
    return [args[0] for name, args, _ in tree.walk() if name == "dataframe"]


def render(app, monkeypatch, query):
    monkeypatch.setattr(app, "evidence_visible", lambda analysis: True)
    deep = SearchTree(query)
    app.render_deep_analysis(completed_analysis(), deep, state())
    return deep


def test_needle_is_trimmed_lowercase_or_none(app):
    assert app.deep_search_needle("  PowerShell ") == "powershell"
    assert app.deep_search_needle("   ") is None
    assert app.deep_search_needle(None) is None


def test_rows_match_any_cell_including_list_values(app):
    rows = completed_analysis()["evidence"]
    assert app.deep_search_rows(rows, "capa") == rows  # sources 리스트 안의 값
    assert app.deep_search_rows(rows, "t1518") == [rows[1]]
    assert app.deep_search_rows(rows, None) is rows


def test_without_query_tables_and_titles_are_unchanged(app, monkeypatch):
    deep = render(app, monkeypatch, "")

    titles = expander_titles(deep)
    for title in ("CAPA", "FLOSS", "Speakeasy", "MITRE Evidence"):
        assert title in titles
    # 검색하지 않으면 원래처럼 list 를 그대로 넘긴다
    assert all(isinstance(table, list) for table in tables(deep))


def test_query_filters_every_table_and_counts_in_titles(app, monkeypatch):
    deep = render(app, monkeypatch, "PowerShell")

    titles = expander_titles(deep)
    assert "CAPA · 1 / 2건" in titles
    assert "FLOSS · 1 / 3건" in titles
    assert "Speakeasy · 0 / 3건" in titles
    assert "MITRE Evidence · 1 / 2건" in titles

    # 검색 중인 표는 일치한 행만 담은 Styler 로 그리고, 일치한 칸에 색을 입힌다
    styled = [table for table in tables(deep) if not isinstance(table, list)]
    assert [len(table.data) for table in styled] == [1, 1, 1]
    html = styled[0].to_html()
    assert app.DEEP_SEARCH_HIGHLIGHT.split(";")[0] in html


def test_tables_without_matches_say_so(app, monkeypatch):
    deep = render(app, monkeypatch, "no-such-thing")

    captions = [args[0] for name, args, _ in deep.walk() if name == "caption"]
    assert "CAPA 0 · FLOSS 0 · Speakeasy 0 · MITRE 0" in captions
    assert captions.count("검색어와 일치하는 항목이 없습니다.") >= 4


def test_new_intake_clears_the_deep_query(app):
    app.st.session_state.deep_filter_query = "powershell"
    app.reset_analysis_result()
    assert "deep_filter_query" not in app.st.session_state
