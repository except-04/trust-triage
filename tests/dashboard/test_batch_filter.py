"""배치 결과 안에서 파일명/SHA-256으로 찾기.

백엔드를 부르지 않고 session 의 batch_data["analyses"] 만 거른다. 거른 목록이
기존 4그룹·선택·상세 연결에 그대로 흘러가는지, 그리고 결과가 없을 때 직전에
고른 파일의 상세 화면이 남지 않는지가 관심사다.
"""

from __future__ import annotations

import pytest


# 앞 12자리와 뒤 8자리가 다르게 만들어 prefix 검색과 substring 검색을 구분한다
HASH_A = "a1b2c3d4" + "e5f60718" * 7
HASH_B = "f0e1d2c3" * 8
HASH_C = "0123456789abcdef" * 4


def analysis(analysis_id, filename, sha256, verdict="AUTO_BENIGN", status="COMPLETED"):
    """배치 결과 항목. entry_view() 가 만든 뷰에 완료 결과가 얹힌 형태."""
    return {
        "analysis_id": analysis_id,
        "filename": filename,
        "sha256": sha256,
        "file_size": 1024,
        "status": status,
        "initial_verdict": verdict,
        "route": "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL",
        "reason": "test",
        "final_verdict": None,
        "calibrated_probability": 0.5,
        "raw_probability": 0.5,
        "disagreement": 0.1,
        "ood_score": 0.2,
        "difficulty_score": 1.0,
        "top_features": [],
        "deep_analysis_status": {
            "capa": "NOT_REQUIRED",
            "floss": "NOT_REQUIRED",
            "speakeasy": "NOT_REQUIRED",
            "cape": "NOT_REQUIRED",
        },
        "evidence": [],
        "llm_summary": None,
        "error": None,
    }


ANALYSES = [
    analysis("A1", "Dropper.exe", HASH_A, "HIGH_RISK_UNCERTAIN"),
    analysis("A2", "helper.dll", HASH_B, "AUTO_MALICIOUS"),
    analysis("A3", "setup_helper.EXE", HASH_C, "AUTO_BENIGN"),
    analysis("A4", "broken.exe", "9" * 64, None, status="FAILED"),
]


def seed_batch(app, selected="A1"):
    """완료된 배치가 떠 있고 selected 가 상세로 열려 있는 상태."""
    batch_data = {
        "batch_ids": ["B1"],
        "analyses": [dict(item) for item in ANALYSES],
        "skipped": [],
        "errors": [],
    }
    chosen = next(a for a in batch_data["analyses"] if a["analysis_id"] == selected)
    app.st.session_state.update(
        analysis_result=chosen,
        batch_data=batch_data,
        batch_results=batch_data["analyses"],
        batch_ids=["B1"],
        selected_analysis_id=selected,
        group_analysis_selector=selected,
        poll_started_at=1.0,
        poll_timed_out=False,
    )
    return batch_data


@pytest.fixture
def typed(app, monkeypatch):
    """검색창에 값이 들어 있는 상태로 만든다."""

    def set_query(value):
        monkeypatch.setattr(app.st, "text_input", lambda *a, **k: value)
        app.st.session_state.batch_filter_query = value

    return set_query


# --- 필터 규칙 ------------------------------------------------------------


@pytest.mark.parametrize("query", ["", "   ", None])
def test_empty_query_returns_everything(app, query):
    assert app.filter_batch_analyses(ANALYSES, query) is ANALYSES


@pytest.mark.parametrize(
    "query,expected",
    [
        ("helper", ["A2", "A3"]),
        ("HELPER", ["A2", "A3"]),
        (".exe", ["A1", "A3", "A4"]),
        ("  dropper  ", ["A1"]),
        ("nothing-like-this", []),
    ],
)
def test_filename_matches_case_insensitive_substring(app, query, expected):
    hits = app.filter_batch_analyses(ANALYSES, query)
    assert [a["analysis_id"] for a in hits] == expected


@pytest.mark.parametrize(
    "query,expected",
    [
        (HASH_A, ["A1"]),
        (HASH_A[:12], ["A1"]),
        (HASH_A[-8:], ["A1"]),
        (HASH_A.upper(), ["A1"]),
        ("0123456789abcdef", ["A3"]),
        ("999", ["A4"]),
        ("zzzz", []),
    ],
)
def test_sha256_matches_full_prefix_and_suffix(app, query, expected):
    hits = app.filter_batch_analyses(ANALYSES, query)
    assert [a["analysis_id"] for a in hits] == expected


def test_items_without_sha256_or_filename_do_not_crash(app):
    items = [{"analysis_id": "X", "filename": None}, {"analysis_id": "Y"}]
    assert app.filter_batch_analyses(items, "abc") == []
    items = [{"analysis_id": "X", "filename": "abc.exe"}]
    assert app.filter_batch_analyses(items, "abc") == items


def test_filtered_list_keeps_all_four_groups(app):
    groups = app.group_batch_analyses(app.filter_batch_analyses(ANALYSES, "helper"))
    assert list(groups) == ["needs_review", "auto_malicious", "auto_benign", "failed"]
    assert {k: len(v) for k, v in groups.items()} == {
        "needs_review": 0,
        "auto_malicious": 1,
        "auto_benign": 1,
        "failed": 0,
    }


# --- 결과 화면에서의 동작 --------------------------------------------------


@pytest.fixture
def screen(app, monkeypatch):
    """render_batch_triage 가 st 에 직접 그리는 안내와 그룹 위젯 호출을 기록한다."""
    log = {"info": [], "caption": [], "group_calls": []}
    monkeypatch.setattr(app.st, "info", lambda text, *a, **k: log["info"].append(text))
    monkeypatch.setattr(
        app.st, "caption", lambda text, *a, **k: log["caption"].append(text)
    )

    def segmented_control(*args, **kwargs):
        log["group_calls"].append(kwargs)
        return log.get("group")

    monkeypatch.setattr(app.st, "segmented_control", segmented_control)
    return log


@pytest.fixture
def no_backend(app, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("배치 검색은 백엔드를 부르면 안 된다")

    for name in ("get_batch", "get_status", "get_result", "search_analyses"):
        monkeypatch.setattr(app.api_client, name, forbidden)


def test_no_match_hides_the_detail_view_but_keeps_the_selection(
    app, typed, screen, no_backend, stop_signal
):
    batch_data = seed_batch(app, selected="A1")
    before = dict(app.st.session_state)
    typed("no-such-file")

    with pytest.raises(stop_signal):
        app.render_batch_triage(batch_data)

    assert screen["info"] == ["검색 조건에 맞는 파일이 없습니다."]
    assert screen["caption"] == ["검색 결과 0건 / 전체 4건"]
    # 그룹 위젯까지 가지 않는다
    assert screen["group_calls"] == []
    # 직전 선택은 지우지 않는다 — 검색어를 지우면 그대로 돌아오기 위해서
    for key in ("analysis_result", "selected_analysis_id", "batch_data", "batch_ids",
                "poll_started_at", "poll_timed_out"):
        assert app.st.session_state[key] == before[key], key


def test_clearing_the_query_restores_the_previous_view(
    app, typed, screen, no_backend, stop_signal
):
    batch_data = seed_batch(app, selected="A1")
    typed("no-such-file")
    with pytest.raises(stop_signal):
        app.render_batch_triage(batch_data)

    typed("")
    app.render_batch_triage(batch_data)  # st.stop 없이 끝까지 그린다

    assert app.st.session_state.analysis_result["analysis_id"] == "A1"
    assert screen["info"] == ["검색 조건에 맞는 파일이 없습니다."]  # 새 안내는 없음
    assert screen["caption"] == ["검색 결과 0건 / 전체 4건"]  # 빈 검색어엔 건수 표시 없음


def test_results_reappearing_restores_the_view(
    app, typed, screen, no_backend, stop_signal
):
    batch_data = seed_batch(app, selected="A1")
    typed("no-such-file")
    with pytest.raises(stop_signal):
        app.render_batch_triage(batch_data)

    typed("dropper")
    app.render_batch_triage(batch_data)
    assert app.st.session_state.analysis_result["analysis_id"] == "A1"
    assert screen["caption"][-1] == "검색 결과 1건 / 전체 4건"


def test_group_counts_follow_the_query(app, typed, screen, no_backend):
    batch_data = seed_batch(app)
    typed("helper")
    app.render_batch_triage(batch_data)

    format_group = screen["group_calls"][0]["format_func"]
    assert [format_group(key) for key in ("needs_review", "auto_malicious", "auto_benign", "failed")] == [
        "Needs Review (0)",
        "Auto Malicious (1)",
        "Auto Benign (1)",
        "Failed (0)",
    ]
    assert screen["caption"] == ["검색 결과 2건 / 전체 4건"]


def test_selecting_a_match_in_a_group_opens_its_detail(app, typed, screen, no_backend):
    batch_data = seed_batch(app, selected="A1")
    screen["group"] = "auto_malicious"
    typed("helper")
    app.render_batch_triage(batch_data)

    # 직전 선택(A1)은 걸러진 그룹에 없으므로 첫 매칭 파일로 상세가 바뀐다
    assert app.st.session_state.selected_analysis_id == "A2"
    assert app.st.session_state.analysis_result["analysis_id"] == "A2"
    assert app.st.session_state.group_analysis_selector == "A2"


def test_sha256_fragment_reaches_the_detail_view(app, typed, screen, no_backend):
    batch_data = seed_batch(app, selected="A1")
    screen["group"] = "auto_benign"
    typed(HASH_C[:16].upper())
    app.render_batch_triage(batch_data)
    assert app.st.session_state.analysis_result["analysis_id"] == "A3"


def test_a_still_matching_selection_is_kept(app, typed, screen, no_backend):
    batch_data = seed_batch(app, selected="A1")
    typed("DROPPER")
    app.render_batch_triage(batch_data)
    assert app.st.session_state.selected_analysis_id == "A1"
    assert app.st.session_state.analysis_result["analysis_id"] == "A1"


def test_summary_card_keeps_whole_batch_counts(app, typed, screen, no_backend):
    batch_data = seed_batch(app)
    typed("helper")
    app.render_batch_triage(batch_data)
    assert batch_data["summary"]["total"] == 4


def test_search_leaves_hash_search_and_polling_state_alone(app, typed, screen, no_backend):
    batch_data = seed_batch(app)
    app.st.session_state.hash_search = {"query": HASH_A, "total_count": 1, "analyses": []}
    app.st.session_state.hash_search_error = None
    typed("helper")
    app.render_batch_triage(batch_data)

    assert app.st.session_state.hash_search == {"query": HASH_A, "total_count": 1, "analyses": []}
    assert app.st.session_state.batch_data is batch_data
    assert app.st.session_state.batch_ids == ["B1"]
    assert app.st.session_state.poll_started_at == 1.0
    assert [a["analysis_id"] for a in batch_data["analyses"]] == ["A1", "A2", "A3", "A4"]


def test_new_intake_clears_the_query(app):
    app.st.session_state.batch_filter_query = "helper"
    app.reset_analysis_result()
    assert "batch_filter_query" not in app.st.session_state
