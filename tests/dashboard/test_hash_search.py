"""SHA-256 분석 이력 검색.

검색은 기존 접수(unified upload)/폴링과 상태를 공유하지 않는다는 점, 그리고
상세 화면으로 넘길 수 있는 이력과 목록에만 남겨야 하는 이력을 가르는 기준이
이 파일의 관심사다. HTTP는 타지 않고 api_client.search_analyses만 대역으로 바꾼다.
"""

from __future__ import annotations

import pytest

from api_client import ApiError


HASH = "a" * 64


def response_item(analysis_id, status="COMPLETED", complete=True, **overrides):
    """GET /analyses 가 돌려주는 AnalysisResponse 한 건.

    complete=False 는 초기 분석 결과가 아직/영영 없는 경우다. 백엔드 스키마상
    prediction/risk_signals 는 null 이 될 수 있으므로 상태와 별개로 표현한다.
    """
    item = {
        "analysis_id": analysis_id,
        "batch_id": "B1",
        "sha256": HASH,
        "created_at": "2026-09-16T10:00:00+00:00",
        "status": status,
        "current_stage": "FINAL",
        "updated_at": "2026-09-16T10:01:00+00:00",
        "completed_at": None,
        "error": None,
        "filename": "sample.exe",
        "size_bytes": 2048,
        "duplicate_of": None,
        "prediction": None,
        "risk_signals": None,
        "initial_verdict": None,
        "route": None,
        "reason": None,
        "triggered_signals": None,
        "top_features": [],
        "deep_analysis_status": {
            "capa": "NOT_REQUIRED",
            "floss": "NOT_REQUIRED",
            "speakeasy": "NOT_REQUIRED",
            "cape": "NOT_REQUIRED",
        },
        "evidence": [],
        "llm_summary": None,
        "final_verdict": None,
        "final_assessment": None,
        "analyst_final_verdict": None,
        "approval_status": None,
        "review_revision": 0,
    }
    if complete:
        item.update(
            prediction={
                "lgbm_raw_probability": 0.91,
                "xgb_raw_probability": 0.88,
                "calibrated_probability": 0.87,
            },
            risk_signals={
                "disagreement": 0.03,
                "ood_score": 0.42,
                "difficulty_score": 2.0,
            },
            initial_verdict="AUTO_MALICIOUS",
            route="FINAL",
            reason="보정 확률이 임계값을 넘었습니다.",
            final_verdict="MALICIOUS",
        )
    item.update(overrides)
    return item


def listing(items, total=None):
    return {
        "total_count": len(items) if total is None else total,
        "limit": 20,
        "offset": 0,
        "analyses": list(items),
    }


class FakeSearch:
    """api_client.search_analyses 대역. 호출 인자를 남긴다."""

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def __call__(self, sha256, **kwargs):
        self.calls.append((sha256, kwargs))
        if self.error is not None:
            raise self.error
        return self.result


class Forbidden:
    """호출되면 안 되는 자리에 둔다."""

    def __call__(self, *args, **kwargs):
        raise AssertionError("형식 검증 전에 백엔드 요청이 나갔다")


class Panel:
    """검색 패널이 그리는 대상 대역.

    위젯 호출을 기록하고, 버튼/셀렉트박스만 지정한 값을 돌려준다.
    """

    def __init__(self, button_labels=(), selected=None):
        self.calls = []
        self.button_labels = set(button_labels)
        self.selected = selected

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name == "button":
                return bool(args) and args[0] in self.button_labels
            if name == "selectbox":
                return self.selected
            return None

        return record

    def texts(self, name):
        return [args[0] for called, args, _ in self.calls if called == name and args]

    def rows(self):
        for called, args, _ in self.calls:
            if called == "dataframe" and args:
                return args[0]
        return []


@pytest.fixture
def search(app, monkeypatch):
    """기본 대역을 끼우고 (app, 대역 교체기) 를 돌려준다."""

    def install(result=None, error=None, fake=None):
        fake = fake or FakeSearch(result=result, error=error)
        monkeypatch.setattr(app.api_client, "search_analyses", fake)
        return fake

    return install


def seeded_batch_state(app):
    """접수/폴링이 진행 중인 화면 상태."""
    pending = {"analysis_id": "P1", "status": "RUNNING", "filename": "pending.exe"}
    batch_data = {"batch_ids": ["B9"], "analyses": [pending], "skipped": [], "errors": []}
    app.st.session_state.update(
        analysis_result=pending,
        batch_data=batch_data,
        batch_results=batch_data["analyses"],
        batch_ids=["B9"],
        selected_analysis_id="P1",
        batch_group="needs_review",
        poll_started_at=123.0,
        poll_timed_out=False,
        intake_receipt=batch_data,
    )
    return dict(app.st.session_state)


# --- 입력 검증 ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "abc",
        "a" * 63,
        "a" * 65,
        "z" * 64,
        "a" * 32 + " " + "a" * 31,
        "0x" + "a" * 62,
    ],
)
def test_invalid_hash_never_reaches_the_backend(app, search, raw):
    search(fake=Forbidden())
    app.run_hash_search(app.normalize_hash_query(raw))

    assert "hash_search" not in app.st.session_state
    assert "64" in app.st.session_state["hash_search_error"]


def test_uppercase_and_whitespace_are_normalized_before_the_request(app, search):
    fake = search(listing([response_item("A1")]))
    app.run_hash_search(app.normalize_hash_query("  " + "A" * 64 + "\n"))

    assert [sent for sent, _ in fake.calls] == [HASH]
    assert fake.calls[0][1] == {"limit": app.HASH_SEARCH_LIMIT, "sort": "newest"}
    assert "hash_search_error" not in app.st.session_state


def test_a_new_search_clears_the_previous_error(app, search):
    search(fake=Forbidden())
    app.run_hash_search("bad")
    assert app.st.session_state["hash_search_error"]

    search(listing([]))
    app.run_hash_search(HASH)
    assert "hash_search_error" not in app.st.session_state


# --- 조회 결과 ------------------------------------------------------------


def test_no_result_is_decided_by_total_count_not_by_an_error(app, search):
    search(listing([], total=0))
    app.run_hash_search(HASH)

    stored = app.st.session_state["hash_search"]
    assert stored["total_count"] == 0 and stored["analyses"] == []
    assert "hash_search_error" not in app.st.session_state
    assert app.st.session_state.analysis_result is None

    panel = Panel()
    app.render_hash_search_results(panel)
    assert panel.texts("info") and not panel.rows()


def test_single_result_lists_only_backend_provided_columns(app, search):
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)

    panel = Panel(selected="A1")
    app.render_hash_search_results(panel)
    rows = panel.rows()

    assert len(rows) == 1
    assert list(rows[0]) == [
        "Created At",
        "Analysis ID",
        "File",
        "Status",
        "Initial Verdict",
        "Final Verdict",
    ]
    assert rows[0]["Analysis ID"] == "A1"
    assert rows[0]["Created At"] == "2026-09-16T10:00:00+00:00"
    assert rows[0]["Initial Verdict"] == "AUTO_MALICIOUS"
    assert rows[0]["Final Verdict"] == "MALICIOUS"


def test_one_hash_with_several_analyses_lists_every_record(app, search):
    items = [
        response_item("A3", created_at="2026-09-16T12:00:00+00:00"),
        response_item("A2", created_at="2026-09-15T12:00:00+00:00"),
        response_item("A1", status="FAILED", complete=False),
    ]
    search(listing(items))
    app.run_hash_search(HASH)

    panel = Panel(selected="A3")
    app.render_hash_search_results(panel)

    assert [row["Analysis ID"] for row in panel.rows()] == ["A3", "A2", "A1"]
    assert app.st.session_state["hash_search"]["total_count"] == 3


def test_history_beyond_the_page_is_announced_without_pagination(app, search):
    items = [response_item(f"A{index}") for index in range(app.HASH_SEARCH_LIMIT)]
    search(listing(items, total=42))
    app.run_hash_search(HASH)

    panel = Panel(selected="A0")
    app.render_hash_search_results(panel)

    notice = " ".join(panel.texts("info"))
    assert "42" in notice and str(app.HASH_SEARCH_LIMIT) in notice
    assert len(panel.rows()) == app.HASH_SEARCH_LIMIT


# --- 상세 전환 ------------------------------------------------------------


def test_detail_transition_hands_the_selected_record_to_the_detail_view(app, search):
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)

    assert app.open_search_result("A1") is True

    result = app.st.session_state.analysis_result
    assert result["analysis_id"] == "A1"
    assert result["filename"] == "sample.exe" and result["sha256"] == HASH
    # 상세 화면이 서식에 직접 넣는 값이 모두 채워져 있어야 한다
    assert all(result[key] is not None for key in app.DETAIL_REQUIRED_FIELDS)
    assert result["raw_probability"] == 0.91
    assert result["calibrated_probability"] == 0.87
    assert result["disagreement"] == 0.03


def test_detail_transition_clears_batch_polling_and_search_state(app, search):
    seeded_batch_state(app)
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)

    assert app.open_search_result("A1") is True

    for key in (
        "batch_data",
        "batch_id",
        "batch_ids",
        "selected_analysis_id",
        "batch_group",
        "group_analysis_selector",
        "poll_started_at",
        "poll_timed_out",
        "intake_receipt",
        "hash_search",
        "hash_search_selector",
    ):
        assert key not in app.st.session_state, key
    # batch_results 도 함께 비워진다. 다음 실행에서 app 본문이 [] 로 다시 세우므로
    # 남아 있던 목록으로 batch_data 가 되살아나지 않는다.
    assert "batch_results" not in app.st.session_state
    assert app.st.session_state.analysis_result["analysis_id"] == "A1"


def test_detail_transition_does_not_pin_the_next_batch_selection(app, search):
    """selected_analysis_id 가 남으면 다음 접수에서 첫 분석이 자동 선택되지 않는다."""
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)
    app.open_search_result("A1")

    promoted = app.commit_receipt(
        {
            "batch_ids": ["B1"],
            "analyses": [dict(app.entry_view({"analysis_id": "N1"}, "QUEUED"))],
            "skipped": [],
            "errors": [],
        }
    )
    assert promoted is True
    assert app.st.session_state.selected_analysis_id == "N1"


def test_unknown_analysis_id_is_not_promoted(app, search):
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)

    assert app.open_search_result("does-not-exist") is False
    assert app.st.session_state.analysis_result is None


def test_the_detail_button_switches_screens(app, search, rerun_signal):
    search(listing([response_item("A1")]))
    app.run_hash_search(HASH)

    panel = Panel(button_labels={"상세 보기"}, selected="A1")
    with pytest.raises(rerun_signal):
        app.render_hash_search_results(panel)
    assert app.st.session_state.analysis_result["analysis_id"] == "A1"


# --- 상세로 보낼 수 없는 이력 ---------------------------------------------


@pytest.mark.parametrize(
    "item",
    [
        response_item("A1", status="QUEUED", complete=False),
        response_item("A1", status="RUNNING", complete=False),
        response_item("A1", status="FAILED", complete=False),
        # COMPLETED 라도 모델 결과가 비어 있으면 상세 화면이 렌더 중 터진다
        response_item("A1", status="COMPLETED", complete=False),
        response_item("A1", risk_signals=None),
        response_item("A1", prediction=None),
        response_item("A1", route=None),
        # 심층 분석 중: 초기 결과는 다 있지만 아직 끝나지 않았다.
        # 값이 있다는 이유로 완료 화면을 띄우면 미완결 결과를 완료로 보여 준다.
        response_item(
            "A1", status="RUNNING", route="DEEP_ANALYSIS", final_verdict=None
        ),
        # 초기 분석은 됐고 심층 분석이 실패한 경우
        response_item(
            "A1",
            status="FAILED",
            route="DEEP_ANALYSIS",
            final_verdict=None,
            error={"code": "TOOL_ERROR", "message": "capa 실행 실패"},
        ),
    ],
    ids=[
        "queued",
        "running",
        "failed",
        "completed-without-model-result",
        "no-risk-signals",
        "no-prediction",
        "no-route",
        "deep-analysis-running-with-initial-result",
        "deep-analysis-failed-with-initial-result",
    ],
)
def test_records_that_cannot_render_stay_in_the_list_only(app, search, item):
    search(listing([item]))
    app.run_hash_search(HASH)

    panel = Panel(button_labels={"상세 보기"}, selected="A1")
    app.render_hash_search_results(panel)

    # 목록에는 남고, 상세 버튼은 아예 그려지지 않는다
    assert len(panel.rows()) == 1
    assert "button" not in [called for called, _, _ in panel.calls]
    assert panel.texts("info")
    assert app.open_search_result("A1") is False
    assert app.st.session_state.analysis_result is None


def test_failed_record_keeps_its_error_in_the_view(app, search):
    error = {"code": "TOOL_ERROR", "message": "capa 실행 실패", "stage": "DEEP"}
    search(listing([response_item("A1", status="FAILED", complete=False, error=error)]))
    app.run_hash_search(HASH)

    stored = app.st.session_state["hash_search"]["analyses"][0]
    assert stored["error"] == error
    assert app.detail_blocker(stored)


# --- 실패와 격리 ----------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ApiError("API_UNREACHABLE", "백엔드에 연결할 수 없습니다.", retryable=True),
        ApiError("UNAUTHORIZED", "인증에 실패했습니다.", http_status=401),
    ],
)
def test_api_error_is_shown_without_producing_results(app, search, error):
    search(error=error)
    app.run_hash_search(HASH)

    message = app.st.session_state["hash_search_error"]
    assert error.message in message and error.code in message
    assert "hash_search" not in app.st.session_state
    assert app.st.session_state.analysis_result is None


def test_api_error_keeps_the_previous_batch_state(app, search):
    before = seeded_batch_state(app)
    search(error=ApiError("UNAUTHORIZED", "인증에 실패했습니다.", http_status=401))
    app.run_hash_search(HASH)

    for key, value in before.items():
        assert app.st.session_state[key] == value, key


def test_searching_alone_leaves_batch_and_polling_state_untouched(app, search):
    before = seeded_batch_state(app)
    search(listing([response_item("A1"), response_item("A2")]))
    app.run_hash_search(HASH)

    # 조회 결과만 새로 생기고, 접수/폴링 쪽 키는 값까지 그대로여야 한다
    assert app.st.session_state["hash_search"]["total_count"] == 2
    for key, value in before.items():
        assert app.st.session_state[key] == value, key
    assert app.st.session_state.analysis_result["analysis_id"] == "P1"


def test_search_results_do_not_enter_the_polling_path(app, search):
    """batch_data 를 만들지 않으므로 검색 결과가 폴링 대상이 되지 않는다."""
    search(listing([response_item("A1", status="QUEUED", complete=False)]))
    app.run_hash_search(HASH)
    assert "batch_data" not in app.st.session_state
    assert app.st.session_state.batch_results == []


def test_clearing_the_search_leaves_the_typed_hash_alone(app, search):
    search(listing([response_item("A1")]))
    app.st.session_state.hash_search_input = HASH
    app.run_hash_search(HASH)

    app.clear_hash_search()
    assert not any(key in app.st.session_state for key in app.HASH_SEARCH_KEYS)
    assert app.st.session_state.hash_search_input == HASH


# --- 패널 렌더 ------------------------------------------------------------


def test_panel_renders_before_any_search(app, search):
    search(fake=Forbidden())
    app.render_hash_search()
    assert "hash_search" not in app.st.session_state


def test_panel_shows_the_error_from_the_last_search(app, search):
    search(fake=Forbidden())
    app.run_hash_search("bad")
    app.render_hash_search()
    assert app.st.session_state["hash_search_error"]
